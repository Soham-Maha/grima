package score

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/prateekpurohit13/grima/internal/calibrate"
	"github.com/prateekpurohit13/grima/internal/config"
	"github.com/prateekpurohit13/grima/internal/event"
	"github.com/prateekpurohit13/grima/internal/fingerprint"
)

func testBaseline() *calibrate.Baseline {
	return &calibrate.Baseline{
		Version:    calibrate.Version,
		MinSamples: 1,
		SigmaFloor: 0.05,
		EntropyByExt: map[string]calibrate.Dist{
			".docx": {Mean: 4.0, StdDev: 0.5, N: 100},
		},
		WriteRateByProc: map[string]float64{},
		WriteRate:       calibrate.Dist{Mean: 5, StdDev: 1, N: 100},
		RenameRate:      calibrate.Dist{Mean: 2, StdDev: 1, N: 100},
		DeleteRate:      calibrate.Dist{Mean: 2, StdDev: 1, N: 100},
		FileEventRate:   calibrate.Dist{Mean: 12, StdDev: 2, N: 100},
		DirFanout:       calibrate.Dist{Mean: 2, StdDev: 1, N: 100},
		KnownExt:        []string{".docx", ".txt"},
	}
}

func encryptedTree() fingerprint.TreeVector {
	return fingerprint.TreeVector{
		Root:           1,
		ProcName:       "cryptor",
		PIDs:           []int32{1},
		Writes:         500,
		Renames:        200,
		WindowDuration: time.Second,
		Entropy:        []fingerprint.EntropySample{{Ext: ".docx", H: 7.9}},
		MagicTotal:     500,
		MagicMismatch:  500,
		Dirs:           map[string]struct{}{"/data/a": {}, "/data/b": {}},
		ExtActivity:    map[string]int64{".locked": 500},
	}
}

func TestEncryptionLikeActivityScoresHigh(t *testing.T) {
	scorer := NewScorer(config.Default())

	verdict := scorer.Evaluate(Inputs{Tree: encryptedTree(), Baseline: testBaseline()})

	if verdict.Level < LevelHigh {
		t.Fatalf("level = %v, want at least high (score %.1f)", verdict.Level, verdict.Score)
	}
	if len(verdict.Signals) == 0 {
		t.Fatal("a high verdict must carry evidence")
	}

	names := map[string]bool{}
	for _, sg := range verdict.Signals {
		names[sg.Name] = true
		if sg.Detail == "" {
			t.Fatalf("signal %q has no detail", sg.Name)
		}
	}
	for _, want := range []string{"entropy_deviation", "magic_mismatch", "write_burst", "unknown_extension_activity"} {
		if !names[want] {
			t.Fatalf("missing expected signal %q; got %v", want, names)
		}
	}
}

func TestQuietActivityScoresLow(t *testing.T) {
	scorer := NewScorer(config.Default())

	verdict := scorer.Evaluate(Inputs{
		Tree:     fingerprint.TreeVector{Root: 2, ProcName: "editor", WindowDuration: time.Second},
		Baseline: testBaseline(),
	})

	if verdict.Level > LevelLow {
		t.Fatalf("level = %v, want low or below for quiet activity", verdict.Level)
	}
}

// Sad path: with no baseline, deviation signals are unknown, not zero.
func TestUncalibratedOmitsDeviationSignals(t *testing.T) {
	scorer := NewScorer(config.Default())

	verdict := scorer.Evaluate(Inputs{Tree: encryptedTree(), Baseline: nil})

	if verdict.Calibrated {
		t.Fatal("verdict claims to be calibrated with no baseline")
	}
	for _, sg := range verdict.Signals {
		switch sg.Name {
		case "entropy_deviation", "write_burst", "rename_burst", "unknown_extension_activity", "dir_fanout", "delete_rate":
			t.Fatalf("deviation signal %q present while uncalibrated", sg.Name)
		}
	}
}

// Sad path: an unready baseline is treated as absent.
func TestUnreadyBaselineIsNotCalibrated(t *testing.T) {
	scorer := NewScorer(config.Default())
	baseline := testBaseline()
	baseline.MinSamples = 10_000

	verdict := scorer.Evaluate(Inputs{Tree: encryptedTree(), Baseline: baseline})
	if verdict.Calibrated {
		t.Fatal("a baseline without enough samples must not count as calibrated")
	}
}

func TestOverrideSetsFloorAndIsNotAveragedAway(t *testing.T) {
	scorer := NewScorer(config.Default())

	verdict := scorer.Evaluate(Inputs{
		Tree:     fingerprint.TreeVector{Root: 3, WindowDuration: time.Second},
		Baseline: testBaseline(),
		Overrides: []Override{{
			ID:     "R-DECOY-TOUCH",
			Level:  LevelCritical,
			Detail: "decoy touched",
		}},
	})

	if verdict.Level != LevelCritical {
		t.Fatalf("level = %v, want critical from the override floor", verdict.Level)
	}
	if verdict.Override != "R-DECOY-TOUCH" {
		t.Fatalf("override = %q, want R-DECOY-TOUCH", verdict.Override)
	}
}

func TestSigmaFloorPreventsDivideByZero(t *testing.T) {
	baseline := testBaseline()
	baseline.EntropyByExt[".dat"] = calibrate.Dist{Mean: 7.9, StdDev: 0, N: 50}

	dist, ok := baseline.Sigma(".dat")
	if !ok {
		t.Fatal("expected a usable distribution")
	}
	if dist.StdDev <= 0 {
		t.Fatalf("stddev = %v, want the configured floor applied", dist.StdDev)
	}
}

func TestSigmaRejectsThinDistributions(t *testing.T) {
	baseline := testBaseline()
	baseline.EntropyByExt[".thin"] = calibrate.Dist{Mean: 1, StdDev: 1, N: 1}

	if _, ok := baseline.Sigma(".thin"); ok {
		t.Fatal("a single-sample distribution is not usable")
	}
}

func TestParseLevelRoundTrip(t *testing.T) {
	for _, name := range []string{"info", "low", "medium", "high", "critical"} {
		lvl, ok := ParseLevel(name)
		if !ok || lvl.String() != name {
			t.Fatalf("ParseLevel(%q) = (%v, %v)", name, lvl, ok)
		}
	}
	if _, ok := ParseLevel("apocalyptic"); ok {
		t.Fatal("unknown level name should not parse")
	}
}

func TestKnowsExtTreatsUnknownAsUnknown(t *testing.T) {
	baseline := testBaseline()
	if !baseline.KnowsExt(".docx") {
		t.Fatal(".docx is in the known set")
	}
	if baseline.KnowsExt(".locked") {
		t.Fatal(".locked is not in the known set")
	}
	if !baseline.KnowsExt("") {
		t.Fatal("an empty extension should not be reported as unknown")
	}
}

// The burst signals compare a per-kind rate against the same per-kind baseline.
//
// An earlier baseline kept a single all-event rate, and on a busy host that was
// dominated by process events — 92.5/s measured with 404 processes. A 65-file
// burst over a 30s window is 2.2 writes/s, so against that baseline the ratio
// was 0.02 and write_burst could never fire. This test gives the baseline a
// realistic all-event rate as well, so it fails if the signal ever goes back to
// comparing against it.
func TestWriteBurstComparesLikeWithLike(t *testing.T) {
	baseline := testBaseline()
	baseline.WriteRate = calibrate.Dist{Mean: 0.2, StdDev: 0.1, N: 100}
	baseline.FileEventRate = calibrate.Dist{Mean: 92.5, StdDev: 119.45, N: 10}

	scorer := NewScorer(config.Default())
	tree := fingerprint.TreeVector{
		Root:           1,
		ProcName:       "cryptor",
		Writes:         65,
		WindowDuration: 30 * time.Second,
	}

	verdict := scorer.Evaluate(Inputs{Tree: tree, Baseline: baseline})

	for _, sg := range verdict.Signals {
		if sg.Name == "write_burst" {
			if sg.Detail == "" {
				t.Fatal("write_burst fired with no detail")
			}
			return
		}
	}
	t.Fatalf("write_burst did not fire for 2.2 writes/s against a 0.2/s baseline; signals = %v",
		signalNames(verdict))
}

// A per-process baseline is only meaningful when the blamed process really is
// the writer. Correlative attribution was measured at 0% accuracy, so
// normalizing a burst against its guess compares the workload to an arbitrary
// process. Measured consequence: a benign 480-save atomic-save workload blamed
// on firefox.exe, whose 1.67 writes/s baseline made the burst look 5-10x over
// and produced a medium false positive, where the host baseline of 130.3
// writes/s would not have fired at all.
func TestWriteBurstIgnoresPerProcessBaselineUnderCorrelativeAttribution(t *testing.T) {
	cfg := config.Default()
	cfg.Attribution.Mode = config.AttributionCorrelate

	baseline := testBaseline()
	baseline.WriteRate = calibrate.Dist{Mean: 130.3, StdDev: 20, N: 100}
	baseline.WriteRateByProc = map[string]float64{"firefox.exe": 1.67}

	tree := fingerprint.TreeVector{
		Root:           1,
		ProcName:       "firefox.exe",
		Writes:         480,
		WindowDuration: 27 * time.Second, // ~17.8 writes/s
	}

	verdict := NewScorer(cfg).Evaluate(Inputs{Tree: tree, Baseline: baseline})

	for _, sg := range verdict.Signals {
		if sg.Name == "write_burst" {
			t.Fatalf("write_burst fired against an arbitrary process's baseline: %s", sg.Detail)
		}
	}
}

// With causal attribution the blamed process can be believed, so its own
// baseline is the right comparison and the signal is allowed to fire.
func TestWriteBurstUsesPerProcessBaselineUnderCausalAttribution(t *testing.T) {
	cfg := config.Default()
	cfg.Attribution.Mode = config.AttributionAudit

	baseline := testBaseline()
	baseline.WriteRate = calibrate.Dist{Mean: 130.3, StdDev: 20, N: 100}
	baseline.WriteRateByProc = map[string]float64{"cryptor": 1.67}

	tree := fingerprint.TreeVector{
		Root:           1,
		ProcName:       "cryptor",
		Writes:         480,
		WindowDuration: 27 * time.Second,
	}

	verdict := NewScorer(cfg).Evaluate(Inputs{Tree: tree, Baseline: baseline})

	for _, sg := range verdict.Signals {
		if sg.Name == "write_burst" {
			return
		}
	}
	t.Fatalf("write_burst did not fire against a known writer's own baseline; signals = %v",
		signalNames(verdict))
}

func signalNames(v Verdict) []string {
	names := make([]string, 0, len(v.Signals))
	for _, sg := range v.Signals {
		names = append(names, sg.Name)
	}
	return names
}

// Adding evidence must never lower the score.
//
// A weighted mean fails this, and that is not hypothetical: the same encryption
// burst scored 100 (critical) on a local run where one signal fired, and 56.4
// (medium) in CI where four fired, because the saturated signal was averaged
// against three weaker ones. More evidence of the same attack read as less
// severe.
func TestAddingEvidenceNeverLowersTheScore(t *testing.T) {
	scorer := NewScorer(config.Default())
	baseline := testBaseline()

	base := fingerprint.TreeVector{
		Root:           1,
		ProcName:       "cryptor",
		WindowDuration: time.Second,
		ExtActivity:    map[string]int64{".locked": 60},
	}
	more := base
	more.Writes = 500
	more.Entropy = []fingerprint.EntropySample{{Ext: ".docx", H: 7.9}}
	more.MagicTotal = 500
	more.MagicMismatch = 500

	fewer := scorer.Evaluate(Inputs{Tree: base, Baseline: baseline})
	extra := scorer.Evaluate(Inputs{Tree: more, Baseline: baseline})

	if len(extra.Signals) <= len(fewer.Signals) {
		t.Fatalf("the second verdict should carry more signals: %d then %d",
			len(fewer.Signals), len(extra.Signals))
	}
	if extra.Score < fewer.Score {
		t.Fatalf("more evidence scored lower: %.1f with %d signals, %.1f with %d",
			fewer.Score, len(fewer.Signals), extra.Score, len(extra.Signals))
	}
}

// 2.1 end to end: the configured n-gram length is read from the ring, becomes a
// feature, and arrives in a verdict as evidence with a readable detail. The
// happy path encrypts and renames; the sad path rewrites the same volume of
// files and renames nothing.
func TestNGramRenameChainReachesTheVerdict(t *testing.T) {
	cfg := config.Default()
	cfg.Window.DecayHalfLife = config.Duration(time.Hour)
	cfg.Window.NGramLength = 4
	scorer := NewScorer(cfg)

	drive := func(procName string, rename bool) fingerprint.TreeVector {
		engine := fingerprint.NewEngine(cfg)
		now := time.Now()
		engine.Apply(event.Event{Kind: event.KindProcessStart, PID: 7, ProcName: procName, Time: now})
		for i := range 12 {
			path := fmt.Sprintf("/data/report%d.docx", i)
			engine.Apply(event.Event{Kind: event.KindFileWrite, PID: 7, Path: path, Bytes: 4096, Time: now})
			if rename {
				engine.Apply(event.Event{Kind: event.KindFileRename, PID: 7, Path: path, Time: now})
			}
		}
		return engine.Aggregate(7)
	}

	find := func(signals []Signal, name string) (Signal, bool) {
		for _, sg := range signals {
			if sg.Name == name {
				return sg, true
			}
		}
		return Signal{}, false
	}

	encrypting := scorer.Evaluate(Inputs{Tree: drive("cryptor", true)})
	sg, ok := find(encrypting.Signals, "ngram_rename_chain")
	if !ok {
		t.Fatalf("write-then-rename activity produced no n-gram signal: %v", encrypting.Signals)
	}
	t.Logf("detail: %s", sg.Detail)
	if sg.Value != 1 {
		t.Fatalf("signal value = %.2f, want 1 for a window that is all chains", sg.Value)
	}
	if !strings.Contains(sg.Detail, "4-grams") {
		t.Fatalf("detail %q does not report the configured n-gram length", sg.Detail)
	}
	if encrypting.Score <= 0 {
		t.Fatalf("score = %.1f, want above zero from the n-gram signal alone", encrypting.Score)
	}

	benign := scorer.Evaluate(Inputs{Tree: drive("bulk-rewriter", false)})
	if sg, ok := find(benign.Signals, "ngram_rename_chain"); ok {
		t.Fatalf("write-only activity produced an n-gram signal: %s", sg.Detail)
	}
}

// Bus drops are their own signal rather than a silent loss: a storm that outran
// the bus must show up in the verdict it corrupted, not only in a log line.
func TestBusDropsSurfaceAsTheirOwnSignal(t *testing.T) {
	scorer := NewScorer(config.Default())

	verdict := scorer.Evaluate(Inputs{Tree: encryptedTree(), Baseline: testBaseline(), BusDropped: 500})

	var seen bool
	for _, sg := range verdict.Signals {
		if sg.Name != "bus_drops" {
			continue
		}
		seen = true
		if sg.Class != ClassSecondary {
			t.Errorf("bus_drops class = %v, want secondary", sg.Class)
		}
		if sg.Value < 0.49 || sg.Value > 0.51 {
			t.Errorf("bus_drops value = %v, want 500/1000", sg.Value)
		}
		if !strings.Contains(sg.Detail, "500") {
			t.Errorf("bus_drops detail = %q, want the count", sg.Detail)
		}
	}
	if !seen {
		t.Fatalf("no bus_drops signal for 500 dropped events; got %v", verdict.Signals)
	}
}

// Sad path: no drops must not produce the signal, and a handful of drops is
// below the noise floor rather than evidence of a storm.
func TestBusDropsBelowTheNoiseFloorAreNotEvidence(t *testing.T) {
	scorer := NewScorer(config.Default())

	for _, dropped := range []uint64{0, 10} {
		verdict := scorer.Evaluate(Inputs{Tree: encryptedTree(), Baseline: testBaseline(), BusDropped: dropped})
		for _, sg := range verdict.Signals {
			if sg.Name == "bus_drops" {
				t.Fatalf("bus_drops present with %d drops (value %v)", dropped, sg.Value)
			}
		}
	}
}
