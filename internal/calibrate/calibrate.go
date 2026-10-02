// Package calibrate captures, persists, and reloads the host baseline that
// deviation-based signals are measured against.
//
// There is no training step and no model artifact: a baseline is a set of
// distributions measured on the host it will be used on. Until one exists,
// GRIMA runs in uncalibrated mode and deviation signals are suppressed.
package calibrate

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/prateekpurohit13/grima/internal/bus"
	"github.com/prateekpurohit13/grima/internal/config"
	"github.com/prateekpurohit13/grima/internal/event"
)

// Version is the baseline schema version. A baseline whose version does not
// match is ignored rather than fatal.
const Version = 3

// Dist is a measured distribution.
type Dist struct {
	Mean   float64 `json:"mean"`
	StdDev float64 `json:"std_dev"`
	N      int     `json:"n"`
}

// Baseline is the host-specific measurement set.
type Baseline struct {
	Version         int                `json:"version"`
	Host            string             `json:"host"`
	CapturedAt      time.Time          `json:"captured_at"`
	WarmupSeconds   float64            `json:"warmup_seconds"`
	MinSamples      int                `json:"min_samples"`
	SigmaFloor      float64            `json:"sigma_floor"`
	EntropyByExt    map[string]Dist    `json:"entropy_by_ext"`
	WriteRateByProc map[string]float64 `json:"write_rate_by_proc"`

	// Per-second rates for file events, split by kind so the burst signals
	// compare like with like. An earlier version kept one all-event rate and
	// compared subset rates against it; on a host with 400 processes the
	// baseline was dominated by process events, so write_burst and its siblings
	// could never reach their threshold.
	//
	// Each rate counts one event kind and only that kind. WriteRate counts
	// writes, not writes-plus-creates: the signal numerator counts writes, and
	// a subset rate compared against a superset baseline is the same defect in
	// the other direction — it halves the apparent deviation of a create-heavy
	// workload and makes host and audit attribution disagree about it.
	WriteRate     Dist `json:"write_rate"`
	CreateRate    Dist `json:"create_rate"`
	RenameRate    Dist `json:"rename_rate"`
	DeleteRate    Dist `json:"delete_rate"`
	FileEventRate Dist `json:"file_event_rate"`

	DirFanout Dist     `json:"dir_fanout"`
	KnownExt  []string `json:"known_ext"`
}

// Ready reports whether the baseline has enough samples for deviation signals to
// be meaningful. A baseline that is not ready puts GRIMA in uncalibrated mode.
func (b *Baseline) Ready() bool {
	if b == nil {
		return false
	}
	total := 0
	for _, d := range b.EntropyByExt {
		total += d.N
	}
	return total >= b.MinSamples
}

// Coverage reports how many samples each distribution in the baseline was
// measured from.
//
// Ready is a single gate over the whole baseline; it does not say that every
// deviation signal has something to compare against. A zero here means the
// signal reading that distribution is omitted — unknown, not quiet — so an
// operator reading "calibrated" can see which of them those are.
func (b *Baseline) Coverage() map[string]int {
	if b == nil {
		return nil
	}
	entropy := 0
	for _, d := range b.EntropyByExt {
		entropy += d.N
	}
	return map[string]int{
		"entropy":     entropy,
		"write_rate":  b.WriteRate.N,
		"create_rate": b.CreateRate.N,
		"rename_rate": b.RenameRate.N,
		"delete_rate": b.DeleteRate.N,
		"dir_fanout":  b.DirFanout.N,
	}
}

// Sigma returns the standard deviation to use for an extension, applying the
// configured floor so that a degenerate distribution never divides by zero.
func (b *Baseline) Sigma(ext string) (Dist, bool) {
	d, ok := b.EntropyByExt[ext]
	if !ok || d.N < 2 {
		return Dist{}, false
	}
	if d.StdDev < b.SigmaFloor {
		d.StdDev = b.SigmaFloor
	}
	return d, true
}

// KnowsExt reports whether the host had seen this extension before calibration.
// Renames to an extension the host has never seen are a primary signal.
func (b *Baseline) KnowsExt(ext string) bool {
	if b == nil || ext == "" {
		return true
	}
	for _, e := range b.KnownExt {
		if e == ext {
			return true
		}
	}
	return false
}

// secondCounts is one second of file events, split by kind.
type secondCounts struct {
	file   int
	write  int
	create int
	rename int
	delete int
}

// Observations accumulates the measurements a baseline is assembled from.
// Capture and Recalibrate both measure through it, so a recalibration window and
// a first capture reduce to comparable numbers.
type Observations struct {
	entropyByExt map[string][]float64
	writeCounts  map[string]int
	dirSets      map[string]map[string]struct{}
	perSecond    map[int64]secondCounts
	extSeen      map[string]struct{}
}

// NewObservations returns an empty measurement set.
func NewObservations() *Observations {
	return &Observations{
		entropyByExt: make(map[string][]float64),
		writeCounts:  make(map[string]int),
		dirSets:      make(map[string]map[string]struct{}),
		perSecond:    make(map[int64]secondCounts),
		extSeen:      make(map[string]struct{}),
	}
}

// Observe folds one bus event into the measurement set.
func (o *Observations) Observe(ev event.Event) {
	if o.entropyByExt == nil {
		*o = *NewObservations()
	}

	// Process events are deliberately excluded: these rates are the baseline
	// for file-derived burst signals, and a busy host emits far more process
	// events than file events.
	if ev.Kind.IsFile() {
		second := ev.Time.Unix()
		counts := o.perSecond[second]
		counts.file++
		switch ev.Kind {
		case event.KindFileWrite:
			counts.write++
		case event.KindFileCreate:
			counts.create++
		case event.KindFileRename:
			counts.rename++
		case event.KindFileDelete:
			counts.delete++
		}
		o.perSecond[second] = counts
	}

	if ext := ev.Extension(); ext != "" {
		o.extSeen[ext] = struct{}{}
	}
	if ev.Kind != event.KindFileWrite {
		return
	}
	if ev.Entropy > 0 {
		if ext := ev.Extension(); ext != "" {
			o.entropyByExt[ext] = append(o.entropyByExt[ext], ev.Entropy)
		}
	}
	// An unattributed write still carries entropy and an extension, but it
	// cannot be charged to a process name.
	if ev.PID == 0 || ev.ProcName == "" {
		return
	}
	o.writeCounts[ev.ProcName]++
	dirs := o.dirSets[ev.ProcName]
	if dirs == nil {
		dirs = make(map[string]struct{})
		o.dirSets[ev.ProcName] = dirs
	}
	if d := event.ParentDir(ev.Path); d != "" {
		dirs[d] = struct{}{}
	}
}

// Baseline assembles the measured distributions. elapsed is the observation
// window the counts were gathered over; a non-positive window falls back to the
// configured warm-up so that a rate is never divided by zero.
func (o *Observations) Baseline(cfg config.Config, elapsed time.Duration) *Baseline {
	seconds := elapsed.Seconds()
	if seconds <= 0 {
		seconds = cfg.Calibration.Warmup.Std().Seconds()
	}
	if seconds <= 0 {
		seconds = 1
	}

	bl := &Baseline{
		Version:         Version,
		CapturedAt:      time.Now(),
		WarmupSeconds:   seconds,
		MinSamples:      cfg.Calibration.MinSamples,
		SigmaFloor:      cfg.Calibration.EntropySigmaFloor,
		EntropyByExt:    make(map[string]Dist, len(o.entropyByExt)),
		WriteRateByProc: make(map[string]float64, len(o.writeCounts)),
	}
	if host, err := os.Hostname(); err == nil {
		bl.Host = host
	}

	for ext, samples := range o.entropyByExt {
		bl.EntropyByExt[ext] = distOf(samples)
	}

	for name, n := range o.writeCounts {
		bl.WriteRateByProc[name] = float64(n) / seconds
	}

	fanouts := make([]float64, 0, len(o.dirSets))
	for _, dirs := range o.dirSets {
		fanouts = append(fanouts, float64(len(dirs)))
	}
	bl.DirFanout = distOf(fanouts)

	rates := make([]float64, 0, len(o.perSecond))
	writes := make([]float64, 0, len(o.perSecond))
	creates := make([]float64, 0, len(o.perSecond))
	renames := make([]float64, 0, len(o.perSecond))
	deletes := make([]float64, 0, len(o.perSecond))
	for _, counts := range o.perSecond {
		rates = append(rates, float64(counts.file))
		writes = append(writes, float64(counts.write))
		creates = append(creates, float64(counts.create))
		renames = append(renames, float64(counts.rename))
		deletes = append(deletes, float64(counts.delete))
	}
	bl.FileEventRate = distOf(rates)
	bl.WriteRate = distOf(writes)
	bl.CreateRate = distOf(creates)
	bl.RenameRate = distOf(renames)
	bl.DeleteRate = distOf(deletes)

	known := make(map[string]struct{}, len(o.extSeen))
	for ext := range o.extSeen {
		known[ext] = struct{}{}
	}
	// Extensions that already exist under the monitored paths are "known" even
	// if nothing wrote to them during the observation window.
	for _, ext := range scanExtensions(cfg.General.MonitorPaths) {
		known[ext] = struct{}{}
	}
	for ext := range known {
		bl.KnownExt = append(bl.KnownExt, ext)
	}
	sort.Strings(bl.KnownExt)

	return bl
}

// distOf reduces raw samples to a distribution.
func distOf(xs []float64) Dist {
	mean, sd := meanStdDev(xs)
	return Dist{Mean: mean, StdDev: sd, N: len(xs)}
}

// Capture observes the host for the configured warm-up period and returns the
// measured baseline.
func Capture(ctx context.Context, cfg config.Config, b *bus.Bus) (*Baseline, error) {
	ch := b.Subscribe("calibration", 16384)
	obs := NewObservations()

	start := time.Now()
	timer := time.NewTimer(cfg.Calibration.Warmup.Std())
	defer timer.Stop()

collect:
	for {
		select {
		case <-ctx.Done():
			break collect
		case <-timer.C:
			break collect
		case ev, ok := <-ch:
			if !ok {
				break collect
			}
			obs.Observe(ev)
		}
	}

	return obs.Baseline(cfg, time.Since(start)), nil
}

// Save writes the baseline as JSON.
func (b *Baseline) Save(path string) error {
	if path == "" {
		return fmt.Errorf("calibration.baseline_path is empty")
	}
	data, err := json.MarshalIndent(b, "", "  ")
	if err != nil {
		return fmt.Errorf("encode baseline: %w", err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return fmt.Errorf("write baseline %s: %w", path, err)
	}
	return nil
}

// Load reads a baseline. A missing, unreadable, or version-mismatched file
// yields (nil, nil): the caller falls back to uncalibrated mode rather than
// refusing to start.
func Load(path string) (*Baseline, error) {
	if path == "" {
		return nil, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("read baseline %s: %w", path, err)
	}

	var b Baseline
	if err := json.Unmarshal(data, &b); err != nil {
		return nil, nil
	}
	if b.Version != Version {
		return nil, nil
	}
	return &b, nil
}

// Merge folds a fresh measurement set into b and returns the number of
// extensions that were not previously known. This is the recalibration edge:
// the confirmed-benign observations become part of the distributions the
// signals are measured against, so a workload the operator has marked benign
// stops registering as a deviation.
//
// b keeps its own settings — MinSamples and SigmaFloor describe the deployment,
// not the measurements — while CapturedAt becomes the time of this refresh, so
// the dashboard's calibration age tracks the newest data.
func (b *Baseline) Merge(fresh *Baseline) (int, error) {
	if b == nil || fresh == nil {
		return 0, fmt.Errorf("merge needs two baselines")
	}
	// The baseline is host-specific by construction; folding another host's
	// measurements in would silently describe a machine that does not exist.
	if b.Host != "" && fresh.Host != "" && b.Host != fresh.Host {
		return 0, fmt.Errorf("baseline describes host %s, observations come from %s", b.Host, fresh.Host)
	}
	if b.EntropyByExt == nil {
		b.EntropyByExt = make(map[string]Dist)
	}
	if b.WriteRateByProc == nil {
		b.WriteRateByProc = make(map[string]float64)
	}

	for ext, d := range fresh.EntropyByExt {
		b.EntropyByExt[ext] = poolDist(b.EntropyByExt[ext], d)
	}

	// A rate is counts over time, so a known process is re-averaged over the
	// total observation time: neither window may be dropped, or the baseline
	// would drift toward whichever was measured last. A process the baseline
	// has never recorded has no prior rate to average with — it is new, and
	// treating its absence as a zero rate would understate it permanently.
	total := b.WarmupSeconds + fresh.WarmupSeconds
	for name, rate := range fresh.WriteRateByProc {
		prior, known := b.WriteRateByProc[name]
		if !known || b.WarmupSeconds <= 0 || fresh.WarmupSeconds <= 0 {
			b.WriteRateByProc[name] = rate
			continue
		}
		b.WriteRateByProc[name] = (prior*b.WarmupSeconds + rate*fresh.WarmupSeconds) / total
	}
	b.WarmupSeconds = total

	b.FileEventRate = poolDist(b.FileEventRate, fresh.FileEventRate)
	b.WriteRate = poolDist(b.WriteRate, fresh.WriteRate)
	b.CreateRate = poolDist(b.CreateRate, fresh.CreateRate)
	b.RenameRate = poolDist(b.RenameRate, fresh.RenameRate)
	b.DeleteRate = poolDist(b.DeleteRate, fresh.DeleteRate)
	b.DirFanout = poolDist(b.DirFanout, fresh.DirFanout)

	known := make(map[string]struct{}, len(b.KnownExt))
	for _, ext := range b.KnownExt {
		known[ext] = struct{}{}
	}
	promoted := 0
	for _, ext := range fresh.KnownExt {
		if _, ok := known[ext]; ok {
			continue
		}
		known[ext] = struct{}{}
		b.KnownExt = append(b.KnownExt, ext)
		promoted++
	}
	sort.Strings(b.KnownExt)

	if b.Host == "" {
		b.Host = fresh.Host
	}
	b.CapturedAt = time.Now()
	return promoted, nil
}

// poolDist combines two measured distributions, weighting each by its sample
// count and adding the variance the two means differ by.
func poolDist(a, c Dist) Dist {
	if a.N <= 0 {
		return c
	}
	if c.N <= 0 {
		return a
	}

	n := a.N + c.N
	mean := (a.Mean*float64(a.N) + c.Mean*float64(c.N)) / float64(n)

	// Sum of squared deviations: each group's own scatter, plus the scatter
	// their means introduce around the pooled mean.
	sq := a.StdDev * a.StdDev * float64(a.N-1)
	sq += c.StdDev * c.StdDev * float64(c.N-1)
	sq += (a.Mean - c.Mean) * (a.Mean - c.Mean) * float64(a.N) * float64(c.N) / float64(n)

	sd := 0.0
	if n > 1 {
		sd = math.Sqrt(sq / float64(n-1))
	}
	return Dist{Mean: mean, StdDev: sd, N: n}
}

// Recalibrate observes the host for the configured warm-up, folds what it sees
// into base, and saves the result. A nil base becomes the new baseline, so the
// same call also serves a first capture that was never persisted.
//
// Everything observed during the window is treated as confirmed benign: the
// operator runs this while a workload they have judged harmless is active. It is
// an explicit action rather than an automatic one for exactly that reason.
func Recalibrate(ctx context.Context, cfg config.Config, b *bus.Bus, base *Baseline) (*Baseline, error) {
	fresh, err := Capture(ctx, cfg, b)
	if err != nil {
		return nil, err
	}

	if base == nil {
		base = fresh
	} else if _, err := base.Merge(fresh); err != nil {
		return nil, err
	}

	if err := base.Save(cfg.Calibration.BaselinePath); err != nil {
		return nil, err
	}
	return base, nil
}

func meanStdDev(xs []float64) (float64, float64) {
	if len(xs) == 0 {
		return 0, 0
	}
	var sum float64
	for _, x := range xs {
		sum += x
	}
	mean := sum / float64(len(xs))

	if len(xs) < 2 {
		return mean, 0
	}
	var sq float64
	for _, x := range xs {
		d := x - mean
		sq += d * d
	}
	return mean, math.Sqrt(sq / float64(len(xs)-1))
}

// scanExtensions walks the monitored paths, bounded in both depth and entry
// count, and returns the set of extensions present.
func scanExtensions(roots []string) []string {
	const (
		maxEntries = 20000
		maxDepth   = 4
	)

	seen := make(map[string]struct{})
	entries := 0

	var walk func(dir string, depth int)
	walk = func(dir string, depth int) {
		if depth > maxDepth || entries >= maxEntries {
			return
		}
		items, err := os.ReadDir(dir)
		if err != nil {
			return
		}
		for _, it := range items {
			if entries >= maxEntries {
				return
			}
			entries++
			name := it.Name()
			if it.IsDir() {
				if strings.HasPrefix(name, ".") {
					continue
				}
				walk(filepath.Join(dir, name), depth+1)
				continue
			}
			if ext := event.Extension(name); ext != "" {
				seen[ext] = struct{}{}
			}
		}
	}

	for _, root := range roots {
		walk(root, 0)
	}

	out := make([]string, 0, len(seen))
	for ext := range seen {
		out = append(out, ext)
	}
	return out
}
