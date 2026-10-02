package score

import (
	"fmt"
	"sort"

	"github.com/prateekpurohit13/grima/internal/calibrate"
	"github.com/prateekpurohit13/grima/internal/config"
	"github.com/prateekpurohit13/grima/internal/fingerprint"
)

// minSignalValue is the floor below which a normalized signal is noise rather
// than evidence.
const minSignalValue = 0.05

// The n-gram signal needs enough k-grams to be a share of something: below these
// counts a window is too short for the ratio to mean anything.
const (
	minNGramWindows = 8
	minRenameChains = 4
)

// computeSignals derives every available signal. Signals whose baseline input is
// missing are omitted rather than zeroed: zero means "benign", not "unknown".
func (s *Scorer) computeSignals(in Inputs, calibrated bool) []Signal {
	tv := in.Tree
	b := in.Baseline
	out := make([]Signal, 0, 8)

	windowSeconds := tv.WindowDuration.Seconds()
	if windowSeconds <= 0 {
		windowSeconds = 1
	}

	if calibrated {
		if sg, ok := entropySignal(tv, b); ok {
			out = append(out, sg)
		}
		if sg, ok := writeBurstSignal(tv, b, windowSeconds, s.trustPerProcessBaseline()); ok {
			out = append(out, sg)
		}
		if sg, ok := renameBurstSignal(tv, b, windowSeconds); ok {
			out = append(out, sg)
		}
		if sg, ok := unknownExtensionSignal(tv, b); ok {
			out = append(out, sg)
		}
		if sg, ok := deleteRateSignal(tv, b, windowSeconds); ok {
			out = append(out, sg)
		}
		if sg, ok := dirFanoutSignal(tv, b); ok {
			out = append(out, sg)
		}
	}
	if sg, ok := magicSignal(tv); ok {
		out = append(out, sg)
	}
	if sg, ok := ngramRenameChainSignal(tv); ok {
		out = append(out, sg)
	}
	if sg, ok := bytesRewrittenSignal(tv); ok {
		out = append(out, sg)
	}
	if sg, ok := busDropSignal(in.BusDropped); ok {
		out = append(out, sg)
	}

	// Without a baseline there is nothing to deviate from, so a fixed
	// bulk-modification threshold stands in. Crude, but it is what makes
	// uncalibrated mode useful rather than merely safe.
	if !calibrated {
		if sg, ok := absoluteWriteRateSignal(tv, windowSeconds, s.cfg.Scoring.AbsoluteWriteRate); ok {
			out = append(out, sg)
		}
	}

	return dropNoise(out)
}

// dropNoise removes signals below the floor at which they stop being evidence.
// Without this, any process that wrote a few kilobytes produces a verdict.
func dropNoise(signals []Signal) []Signal {
	kept := signals[:0]
	for _, sg := range signals {
		if sg.Value >= minSignalValue {
			kept = append(kept, sg)
		}
	}
	return kept
}

func absoluteWriteRateSignal(tv fingerprint.TreeVector, windowSeconds, base float64) (Signal, bool) {
	if base <= 0 {
		base = 20
	}
	rate := float64(tv.Writes) / windowSeconds
	excess := rate / base
	value := clamp01((excess - 1) / 7)
	if value <= 0 {
		return Signal{}, false
	}
	return Signal{
		Name:   "write_rate_absolute",
		Class:  ClassPrimary,
		Value:  value,
		Detail: fmt.Sprintf("%.1f writes/s exceeds the uncalibrated threshold of %.0f/s", rate, base),
	}, true
}

func entropySignal(tv fingerprint.TreeVector, b *calibrate.Baseline) (Signal, bool) {
	var sum, worst float64
	var n int
	for _, es := range tv.Entropy {
		d, ok := b.Sigma(es.Ext)
		if !ok {
			continue
		}
		z := (es.H - d.Mean) / d.StdDev
		if z < 0 {
			z = 0
		}
		sum += z
		if z > worst {
			worst = z
		}
		n++
	}
	if n == 0 {
		return Signal{}, false
	}
	mean := sum / float64(n)
	return Signal{
		Name:  "entropy_deviation",
		Class: ClassPrimary,
		Value: clamp01(mean / 6),
		Detail: fmt.Sprintf("entropy +%.1fσ mean across %d samples (worst +%.1fσ)",
			mean, n, worst),
	}, true
}

func magicSignal(tv fingerprint.TreeVector) (Signal, bool) {
	if tv.MagicTotal == 0 || tv.MagicMismatch == 0 {
		return Signal{}, false
	}
	return Signal{
		Name:  "magic_mismatch",
		Class: ClassPrimary,
		Value: clamp01(float64(tv.MagicMismatch) / float64(tv.MagicTotal) * 2),
		Detail: fmt.Sprintf("magic bytes disagree with extension on %d of %d writes",
			tv.MagicMismatch, tv.MagicTotal),
	}, true
}

// ngramRenameChainSignal reads the fingerprint's sequence feature. An encryptor
// overwrites a file and then renames it to a new extension, so a window whose
// k-grams hold write-then-rename chains is encryption-like. Measured on Windows,
// an atomic save over an existing file produces no chain at all — the sensor
// reports the temp file's removal as a delete between the write and the rename —
// but an extraction that renames a new file into place produces the same
// sequence, because the two cycles are rotations of one another. That is why it
// ships at a low weight: it corroborates the content signals rather than
// alerting on its own.
func ngramRenameChainSignal(tv fingerprint.TreeVector) (Signal, bool) {
	ng := tv.NGram
	if ng.Total < minNGramWindows || ng.RenameChains < minRenameChains {
		return Signal{}, false
	}
	// A quarter of the window being chains is ordinary file management; eight in
	// ten saturates.
	value := clamp01((ng.ChainShare - 0.25) / 0.55)
	if value <= 0 {
		return Signal{}, false
	}
	return Signal{
		Name:  "ngram_rename_chain",
		Class: ClassSecondary,
		Value: value,
		Detail: fmt.Sprintf("%d of %d %d-grams hold a write>rename chain; dominant %s x%d",
			ng.RenameChains, ng.Total, ng.K, ng.Sequence, ng.Count),
	}, true
}

func writeBurstSignal(tv fingerprint.TreeVector, b *calibrate.Baseline, windowSeconds float64, trustPerProcess bool) (Signal, bool) {
	rate := float64(tv.Writes) / windowSeconds
	base, sigma, ok := rateBaseline(b, tv.ProcName, trustPerProcess)
	if !ok || base <= 0 {
		return Signal{}, false
	}
	excess := rate / base
	value := clamp01((excess - 1) / 7) // 8x baseline saturates
	if value <= 0 {
		return Signal{}, false
	}
	return Signal{
		Name:  "write_burst",
		Class: ClassPrimary,
		Value: value,
		Detail: fmt.Sprintf("%.1f writes/s vs baseline %.1f/s (%.1fx, σ=%.1f)",
			rate, base, excess, sigma),
	}, true
}

func renameBurstSignal(tv fingerprint.TreeVector, b *calibrate.Baseline, windowSeconds float64) (Signal, bool) {
	if b.RenameRate.Mean <= 0 {
		return Signal{}, false
	}
	rate := float64(tv.Renames) / windowSeconds
	base := b.RenameRate.Mean
	excess := rate / base
	value := clamp01((excess - 1) / 7)
	if value <= 0 {
		return Signal{}, false
	}
	return Signal{
		Name:   "rename_burst",
		Class:  ClassPrimary,
		Value:  value,
		Detail: fmt.Sprintf("%.1f renames/s vs host baseline %.1f/s (%.1fx)", rate, base, excess),
	}, true
}

// unknownExtensionSignal counts writes to extensions this host has never seen,
// which is how a mass rename to a new suffix (".locked") shows up. It is
// cumulative, so it survives the decaying window.
//
// Decision (Sprint 4, item 4.10): the alert is accepted, not floored.
//
// Measured with the shipped weights and bands (internal/score/alertability_test.go):
// 10 novel-extension writes score 20.0 info, 20 score 40.0 low, 30 score 60.0
// medium, 50 score 100.0 critical. So the medium band is crossed at 23 novel
// writes and a first-time workload whose extensions calibration never learned can
// page an operator with no burst. That is the accepted cost: at most one alert
// per genuinely new extension set, until recalibration promotes the extensions
// (promotion is absolute, so the second run is silent).
//
// A minimum-novelty floor was rejected because it breaks the design's answer to
// Gap 4 instead of the benign case. The quiet drip (item 2.2) writes 24 files of
// an unseen extension in a window with no other evidence and carries the verdict
// as this signal at 0.480 plus cum_bytes_rewritten at 0.094 — measured at 49.96
// medium, i.e. it crosses by 5 points. Moving the alert point above 30 files
// needs the saturation count to exceed 30/0.45 = 66.7; at 67 the same pair fuses
// to 0.382 (38.2 low) and quiet drip stops alerting. The floor and the
// capability are the same constant, so the constant stays at 50.
func unknownExtensionSignal(tv fingerprint.TreeVector, b *calibrate.Baseline) (Signal, bool) {
	var unknown int64
	for ext, n := range tv.ExtActivity {
		if !b.KnowsExt(ext) {
			unknown += n
		}
	}
	if unknown == 0 {
		return Signal{}, false
	}
	return Signal{
		Name:  "unknown_extension_activity",
		Class: ClassPrimary,
		Value: clamp01(float64(unknown) / 50),
		Detail: fmt.Sprintf("%d writes to extensions never seen on this host (%s)",
			unknown, topUnknownExts(tv.ExtActivity, b, 3)),
	}, true
}

func deleteRateSignal(tv fingerprint.TreeVector, b *calibrate.Baseline, windowSeconds float64) (Signal, bool) {
	if b.DeleteRate.Mean <= 0 {
		return Signal{}, false
	}
	rate := float64(tv.Deletes) / windowSeconds
	base := b.DeleteRate.Mean
	excess := rate / base
	value := clamp01((excess - 1) / 7)
	if value <= 0 {
		return Signal{}, false
	}
	return Signal{
		Name:   "delete_rate",
		Class:  ClassSecondary,
		Value:  value,
		Detail: fmt.Sprintf("%.1f deletes/s vs host baseline %.1f/s (%.1fx)", rate, base, excess),
	}, true
}

func dirFanoutSignal(tv fingerprint.TreeVector, b *calibrate.Baseline) (Signal, bool) {
	if b.DirFanout.Mean <= 0 {
		return Signal{}, false
	}
	dirs := tv.DirCount()
	excess := float64(dirs) / b.DirFanout.Mean
	value := clamp01((excess - 1) / 7)
	if value <= 0 {
		return Signal{}, false
	}
	return Signal{
		Name:   "dir_fanout",
		Class:  ClassSecondary,
		Value:  value,
		Detail: fmt.Sprintf("touched %d directories vs baseline %.1f", dirs, b.DirFanout.Mean),
	}, true
}

func bytesRewrittenSignal(tv fingerprint.TreeVector) (Signal, bool) {
	const saturate = 1 << 30 // 1 GiB
	if tv.CumBytesRewritten <= 0 {
		return Signal{}, false
	}
	value := clamp01(float64(tv.CumBytesRewritten) / saturate)
	if value <= 0 {
		return Signal{}, false
	}
	return Signal{
		Name:  "cum_bytes_rewritten",
		Class: ClassSecondary,
		Value: value,
		Detail: fmt.Sprintf("%s rewritten across %d files since process start",
			humanBytes(tv.CumBytesRewritten), tv.CumFilesRewritten),
	}, true
}

// busDropSignal treats overload as evidence: a storm that saturates the bus also
// means the window under-counted.
func busDropSignal(dropped uint64) (Signal, bool) {
	if dropped == 0 {
		return Signal{}, false
	}
	return Signal{
		Name:   "bus_drops",
		Class:  ClassSecondary,
		Value:  clamp01(float64(dropped) / 1000),
		Detail: fmt.Sprintf("%d events dropped by the bus (window under-counts)", dropped),
	}, true
}

// trustPerProcessBaseline reports whether a blamed process can be believed
// enough to measure it against its own baseline. Only causal attribution can
// name the writer; correlative attribution cannot, and using its guess as a
// denominator turns a benign burst into a deviation from an unrelated process.
func (s *Scorer) trustPerProcessBaseline() bool {
	return s.cfg.Attribution.Mode == config.AttributionAudit
}

// rateBaseline returns the rate a write burst is measured against.
//
// A per-process baseline is only meaningful when the blamed process really is
// the writer. Under correlative attribution it is not — that mode was measured
// at 0% accuracy — so normalizing against it compares a workload's writes to an
// arbitrary process's rate. Measured consequence: a benign 480-save atomic-save
// workload was blamed on firefox.exe, whose 1.67 writes/s baseline made the
// burst look 5-10x over and produced a medium false positive, where the host
// baseline of 130.3 writes/s would not have fired at all.
func rateBaseline(b *calibrate.Baseline, procName string, trustPerProcess bool) (base, sigma float64, ok bool) {
	if trustPerProcess && procName != "" {
		if v, found := b.WriteRateByProc[procName]; found && v > 0 {
			return v, b.WriteRate.StdDev, true
		}
	}
	if b.WriteRate.Mean > 0 {
		return b.WriteRate.Mean, b.WriteRate.StdDev, true
	}
	return 0, 0, false
}

func topUnknownExts(m map[string]int64, b *calibrate.Baseline, n int) string {
	type pair struct {
		ext string
		n   int64
	}
	items := make([]pair, 0, len(m))
	for ext, c := range m {
		if !b.KnowsExt(ext) {
			items = append(items, pair{ext, c})
		}
	}
	if len(items) == 0 {
		return "none"
	}
	sort.Slice(items, func(i, j int) bool { return items[i].n > items[j].n })
	if len(items) > n {
		items = items[:n]
	}
	out := ""
	for i, it := range items {
		if i > 0 {
			out += ", "
		}
		out += fmt.Sprintf("%s x%d", it.ext, it.n)
	}
	return out
}

func clamp01(x float64) float64 {
	switch {
	case x < 0:
		return 0
	case x > 1:
		return 1
	default:
		return x
	}
}

func humanBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for v := n / unit; v >= unit; v /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(n)/float64(div), "KMGT"[exp])
}
