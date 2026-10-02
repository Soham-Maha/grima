package calibrate

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/prateekpurohit13/grima/internal/bus"
	"github.com/prateekpurohit13/grima/internal/config"
	"github.com/prateekpurohit13/grima/internal/event"
)

func sampleBaseline() *Baseline {
	return &Baseline{
		Version:         Version,
		Host:            "testhost",
		CapturedAt:      time.Now().Truncate(time.Second),
		WarmupSeconds:   600,
		MinSamples:      2,
		SigmaFloor:      0.05,
		EntropyByExt:    map[string]Dist{".docx": {Mean: 4.2, StdDev: 0.3, N: 50}},
		WriteRateByProc: map[string]float64{"code": 12.5},
		KnownExt:        []string{".docx", ".txt"},
	}
}

func TestSaveLoadRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "baseline.json")

	if err := sampleBaseline().Save(path); err != nil {
		t.Fatalf("save: %v", err)
	}

	loaded, err := Load(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if loaded == nil {
		t.Fatal("baseline did not load")
	}
	if loaded.Host != "testhost" {
		t.Fatalf("host = %q", loaded.Host)
	}
	if got := loaded.EntropyByExt[".docx"].Mean; got != 4.2 {
		t.Fatalf("mean = %v, want 4.2", got)
	}
	if got := loaded.WriteRateByProc["code"]; got != 12.5 {
		t.Fatalf("write rate = %v, want 12.5", got)
	}
	if !loaded.Ready() {
		t.Fatal("a baseline with samples should be ready")
	}
}

// Sad path: a baseline from a different schema version is ignored, not fatal.
func TestLoadIgnoresVersionMismatch(t *testing.T) {
	path := filepath.Join(t.TempDir(), "baseline.json")
	body := `{"version": 999, "min_samples": 1, "entropy_by_ext": {".txt": {"mean":1,"std_dev":0.1,"n":10}}}`

	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}

	loaded, err := Load(path)
	if err != nil {
		t.Fatalf("version mismatch must not be an error: %v", err)
	}
	if loaded != nil {
		t.Fatal("expected a version mismatch to yield nil")
	}
}

// Sad path: a missing baseline means uncalibrated mode, not a failure to start.
func TestLoadMissingFileReturnsNil(t *testing.T) {
	loaded, err := Load(filepath.Join(t.TempDir(), "absent.json"))
	if err != nil {
		t.Fatalf("missing file must not be an error: %v", err)
	}
	if loaded != nil {
		t.Fatal("expected nil for a missing baseline")
	}
}

// Sad path: a corrupt baseline is ignored rather than crashing the detector.
func TestLoadCorruptFileReturnsNil(t *testing.T) {
	path := filepath.Join(t.TempDir(), "baseline.json")
	if err := os.WriteFile(path, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}

	loaded, err := Load(path)
	if err != nil {
		t.Fatalf("corrupt file must not be an error: %v", err)
	}
	if loaded != nil {
		t.Fatal("expected nil for a corrupt baseline")
	}
}

func TestLoadEmptyPathReturnsNil(t *testing.T) {
	loaded, err := Load("")
	if err != nil || loaded != nil {
		t.Fatalf("Load(\"\") = (%v, %v), want (nil, nil)", loaded, err)
	}
}

func TestSaveRejectsEmptyPath(t *testing.T) {
	if err := sampleBaseline().Save(""); err == nil {
		t.Fatal("saving to an empty path should fail")
	}
}

func TestReadyRequiresSamples(t *testing.T) {
	baseline := sampleBaseline()
	baseline.MinSamples = 1000
	if baseline.Ready() {
		t.Fatal("baseline should not be ready with too few samples")
	}

	var absent *Baseline
	if absent.Ready() {
		t.Fatal("a nil baseline is never ready")
	}
}

func TestSigmaAppliesFloor(t *testing.T) {
	baseline := sampleBaseline()
	baseline.EntropyByExt[".flat"] = Dist{Mean: 7.9, StdDev: 0, N: 10}

	dist, ok := baseline.Sigma(".flat")
	if !ok {
		t.Fatal("expected a usable distribution")
	}
	if dist.StdDev != baseline.SigmaFloor {
		t.Fatalf("stddev = %v, want the floor %v", dist.StdDev, baseline.SigmaFloor)
	}
}

func TestSigmaRejectsUnknownExtension(t *testing.T) {
	if _, ok := sampleBaseline().Sigma(".nope"); ok {
		t.Fatal("an extension with no samples has no usable distribution")
	}
}

func TestKnowsExt(t *testing.T) {
	baseline := sampleBaseline()

	if !baseline.KnowsExt(".docx") {
		t.Fatal(".docx is known")
	}
	if baseline.KnowsExt(".locked") {
		t.Fatal(".locked should be unknown")
	}
	if !baseline.KnowsExt("") {
		t.Fatal("an empty extension is not evidence of anything")
	}

	var absent *Baseline
	if !absent.KnowsExt(".locked") {
		t.Fatal("with no baseline, nothing can be called unknown")
	}
}

// --- observations -----------------------------------------------------------

func writeEvent(at time.Time, proc, path string, entropy float64, pid int32) event.Event {
	return event.Event{
		Time:     at,
		Kind:     event.KindFileWrite,
		PID:      pid,
		ProcName: proc,
		Path:     path,
		Entropy:  entropy,
		Bytes:    4096,
	}
}

// A measurement set built from events is what a capture measures: per-extension
// entropy, per-process write rates, and the extensions the host has seen.
func TestObservationsMeasureWhatCaptureRecords(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "legacy.bak"), []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg := config.Default()
	cfg.General.MonitorPaths = []string{dir}
	cfg.Calibration.MinSamples = 5

	obs := NewObservations()
	start := time.Unix(1_700_000_000, 0)
	for i := range 10 {
		obs.Observe(writeEvent(start.Add(time.Duration(i)*time.Second), "writer.exe",
			filepath.Join(dir, fmt.Sprintf("doc_%d.txt", i)), 4.0, 4242))
	}

	baseline := obs.Baseline(cfg, 10*time.Second)

	dist, ok := baseline.Sigma(".txt")
	if !ok {
		t.Fatal("the writes produced no .txt entropy distribution")
	}
	if dist.Mean != 4.0 {
		t.Fatalf("mean entropy = %v, want 4.0", dist.Mean)
	}
	if rate := baseline.WriteRateByProc["writer.exe"]; rate != 1.0 {
		t.Fatalf("write rate = %v, want 1 write/s over 10s", rate)
	}
	if !baseline.KnowsExt(".txt") {
		t.Fatal("an extension the host wrote to is known")
	}
	// Extensions already on disk count as known even with no event for them.
	if !baseline.KnowsExt(".bak") {
		t.Fatal("an extension present under the monitored path is known")
	}
	if !baseline.Ready() {
		t.Fatal("ten samples against a minimum of five is ready")
	}

	// An unattributed write carries content evidence but no process rate.
	obs.Observe(writeEvent(start, "", filepath.Join(dir, "host.dat"), 7.9, 0))
	obs.Observe(writeEvent(start.Add(time.Second), "", filepath.Join(dir, "host2.dat"), 7.8, 0))
	baseline = obs.Baseline(cfg, 10*time.Second)
	if _, ok := baseline.Sigma(".dat"); !ok {
		t.Fatal("an unattributed write still produces an entropy distribution")
	}
	if len(baseline.WriteRateByProc) != 1 {
		t.Fatalf("process rates = %v, want only the attributed writer", baseline.WriteRateByProc)
	}
}

// --- recalibration ----------------------------------------------------------

// Pooling keeps both windows' evidence: the samples add up, and the uncertainty
// grows to cover the fact that the host has been measured in two regimes.
func TestMergePoolsDistributions(t *testing.T) {
	base := sampleBaseline()
	fresh := &Baseline{
		Version:       Version,
		Host:          base.Host,
		WarmupSeconds: 50,
		EntropyByExt:  map[string]Dist{".docx": {Mean: 6.2, StdDev: 0.3, N: 50}},
	}

	if _, err := base.Merge(fresh); err != nil {
		t.Fatalf("merge: %v", err)
	}

	dist, ok := base.Sigma(".docx")
	if !ok {
		t.Fatal("the pooled distribution is not usable")
	}
	if dist.N != 100 {
		t.Fatalf("samples = %d, want the two windows' 50 + 50", dist.N)
	}
	if dist.Mean != 5.2 {
		t.Fatalf("mean = %v, want the weighted 5.2", dist.Mean)
	}
	if dist.StdDev <= 0.3 {
		t.Fatalf("stddev = %v, want the between-window spread folded in", dist.StdDev)
	}
}

// The feedback edge: an extension the operator has confirmed benign stops
// counting as unknown, which is what retires the novelty signal.
func TestMergePromotesObservedExtensions(t *testing.T) {
	base := sampleBaseline()
	fresh := &Baseline{
		Version:       Version,
		Host:          base.Host,
		WarmupSeconds: 30,
		EntropyByExt:  map[string]Dist{".obj": {Mean: 7.2, StdDev: 0.1, N: 200}},
		KnownExt:      []string{".obj", ".txt"},
	}

	promoted, err := base.Merge(fresh)
	if err != nil {
		t.Fatalf("merge: %v", err)
	}
	if promoted != 1 {
		t.Fatalf("promoted = %d, want the one extension the baseline did not know", promoted)
	}
	if !base.KnowsExt(".obj") {
		t.Fatal(".obj is known after recalibration")
	}
	if len(base.KnownExt) != 3 {
		t.Fatalf("known extensions = %v, want no duplicate of .txt", base.KnownExt)
	}
}

// Rates are counts over time, so the merge is total counts over total time:
// a short burst must not displace a long baseline, or the reverse.
func TestMergeAveragesWriteRateAcrossWindows(t *testing.T) {
	base := sampleBaseline()
	base.WriteRateByProc["code"] = 2
	base.WarmupSeconds = 600

	fresh := &Baseline{
		Version:         Version,
		Host:            base.Host,
		WarmupSeconds:   200,
		WriteRateByProc: map[string]float64{"code": 10},
	}

	if _, err := base.Merge(fresh); err != nil {
		t.Fatalf("merge: %v", err)
	}

	if got := base.WriteRateByProc["code"]; got != 4 {
		t.Fatalf("rate = %v, want (2*600 + 10*200)/800", got)
	}
	if base.WarmupSeconds != 800 {
		t.Fatalf("window = %v, want 800s of observations represented", base.WarmupSeconds)
	}
}

// A baseline too thin for deviation signals becomes usable once recalibration
// has added samples, without any second capture.
func TestMergeCanMakeABaselineReady(t *testing.T) {
	base := sampleBaseline()
	base.MinSamples = 500
	if base.Ready() {
		t.Fatal("a baseline with 50 samples is not ready against a minimum of 500")
	}

	fresh := &Baseline{
		Version:       Version,
		Host:          base.Host,
		WarmupSeconds: 60,
		EntropyByExt:  map[string]Dist{".txt": {Mean: 4.1, StdDev: 0.4, N: 460}},
	}

	if _, err := base.Merge(fresh); err != nil {
		t.Fatalf("merge: %v", err)
	}
	if !base.Ready() {
		t.Fatal("510 samples against a minimum of 500 is ready")
	}
}

// Sad path: another host's measurements describe a machine that does not exist.
func TestMergeRejectsAnotherHostsObservations(t *testing.T) {
	base := sampleBaseline()
	fresh := &Baseline{
		Version:       Version,
		Host:          "elsewhere",
		WarmupSeconds: 10,
		EntropyByExt:  map[string]Dist{".obj": {Mean: 7.2, StdDev: 0.1, N: 10}},
		KnownExt:      []string{".obj"},
	}

	if _, err := base.Merge(fresh); err == nil {
		t.Fatal("merging another host's measurements must fail")
	}
	if base.KnowsExt(".obj") {
		t.Fatal("a refused merge must leave the baseline unchanged")
	}
	if len(base.EntropyByExt) != 1 {
		t.Fatalf("entropy distributions = %v, want only the original", base.EntropyByExt)
	}
}

// Sad path: nothing to merge into, nothing to merge from.
func TestMergeRejectsNil(t *testing.T) {
	if _, err := (*Baseline)(nil).Merge(sampleBaseline()); err == nil {
		t.Fatal("merging into a nil baseline must fail")
	}
	if _, err := sampleBaseline().Merge(nil); err == nil {
		t.Fatal("merging nil observations must fail")
	}
}

// Recalibrate is the operator-facing edge: observe the warm-up, fold it in, and
// persist the result where the next run will load it.
func TestRecalibrateMergesIntoTheStoredBaseline(t *testing.T) {
	dir := t.TempDir()
	cfg := config.Default()
	cfg.General.MonitorPaths = []string{dir}
	cfg.Calibration.Warmup = config.Duration(80 * time.Millisecond)
	cfg.Calibration.MinSamples = 5
	cfg.Calibration.BaselinePath = filepath.Join(dir, "baseline.json")

	// The baseline as captured earlier, before this workload existed.
	seen := NewObservations()
	seen.Observe(writeEvent(time.Now(), "explorer.exe", filepath.Join(dir, "notes.txt"), 4.0, 11))
	base := seen.Baseline(cfg, time.Second)
	if err := base.Save(cfg.Calibration.BaselinePath); err != nil {
		t.Fatalf("save: %v", err)
	}

	events := bus.New(256, bus.DropOldest)
	defer events.Close()

	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		tick := time.NewTicker(5 * time.Millisecond)
		defer tick.Stop()
		for {
			select {
			case <-stop:
				return
			case <-tick.C:
				events.Publish(writeEvent(time.Now(), "cc1.exe",
					filepath.Join(dir, "obj", "unit.o"), 7.2, 99))
			}
		}
	}()

	merged, err := Recalibrate(context.Background(), cfg, events, base)
	close(stop)
	wg.Wait()

	if err != nil {
		t.Fatalf("recalibrate: %v", err)
	}
	if !merged.KnowsExt(".o") {
		t.Fatal("recalibration did not promote the extension the workload wrote")
	}
	if merged.WriteRateByProc["cc1.exe"] <= 0 {
		t.Fatal("recalibration did not record the workload's write rate")
	}

	stored, err := Load(cfg.Calibration.BaselinePath)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if stored == nil {
		t.Fatal("the recalibrated baseline was not saved")
	}
	if !stored.KnowsExt(".o") {
		t.Fatal("the stored baseline does not carry the recalibration")
	}
}

// Sad path: recalibration is not a way to lose a baseline, and an unwritable
// path is reported rather than silently dropped.
func TestRecalibrateReportsUnwritableBaseline(t *testing.T) {
	dir := t.TempDir()
	cfg := config.Default()
	cfg.General.MonitorPaths = []string{dir}
	cfg.Calibration.Warmup = config.Duration(20 * time.Millisecond)
	cfg.Calibration.BaselinePath = filepath.Join(dir, "missing", "nested", "baseline.json")

	events := bus.New(64, bus.DropOldest)
	defer events.Close()

	if _, err := Recalibrate(context.Background(), cfg, events, nil); err == nil {
		t.Fatal("saving to a path whose directory does not exist must fail")
	}
}

// A first recalibration with no stored baseline behaves as a capture.
func TestRecalibrateWithoutABaselineCaptures(t *testing.T) {
	dir := t.TempDir()
	cfg := config.Default()
	cfg.General.MonitorPaths = []string{dir}
	cfg.Calibration.Warmup = config.Duration(20 * time.Millisecond)
	cfg.Calibration.BaselinePath = filepath.Join(dir, "baseline.json")

	events := bus.New(64, bus.DropOldest)
	defer events.Close()

	baseline, err := Recalibrate(context.Background(), cfg, events, nil)
	if err != nil {
		t.Fatalf("recalibrate: %v", err)
	}
	if baseline == nil {
		t.Fatal("recalibration with no stored baseline must produce one")
	}
	if baseline.Version != Version {
		t.Fatalf("version = %d, want %d", baseline.Version, Version)
	}

	stored, err := Load(cfg.Calibration.BaselinePath)
	if err != nil || stored == nil {
		t.Fatalf("Load = (%v, %v), want the saved baseline", stored, err)
	}
}

// Ready is one gate over the whole baseline, so it cannot say which deviation
// signals have a distribution behind them. Coverage reports the sample counts
// that answer that question, and a zero must read as "unavailable", not "quiet".
func TestCoverageReportsSamplesPerDistribution(t *testing.T) {
	baseline := sampleBaseline()
	baseline.RenameRate = Dist{Mean: 0, StdDev: 0, N: 7}
	baseline.DeleteRate = Dist{Mean: 0, StdDev: 0, N: 7}
	baseline.WriteRate = Dist{Mean: 3, StdDev: 1, N: 9}
	// DirFanout is left at its zero value: nothing measured it.

	cov := baseline.Coverage()

	for name, want := range map[string]int{
		"entropy":     50,
		"write_rate":  9,
		"rename_rate": 7,
		"delete_rate": 7,
		"dir_fanout":  0,
	} {
		if got := cov[name]; got != want {
			t.Errorf("coverage[%s] = %d, want %d", name, got, want)
		}
	}

	// A zero sample count is the signal saying it cannot be computed, so it must
	// be present in the map rather than missing from it.
	if _, ok := cov["dir_fanout"]; !ok {
		t.Error("an unmeasured distribution is absent from coverage, not reported as zero")
	}
}

func TestNilBaselineHasNoCoverage(t *testing.T) {
	var baseline *Baseline
	if cov := baseline.Coverage(); cov != nil {
		t.Fatalf("nil baseline coverage = %v, want nil", cov)
	}
}
