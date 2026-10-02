package score

import (
	"fmt"
	"math"
	"testing"
	"time"

	"github.com/prateekpurohit13/grima/internal/calibrate"
	"github.com/prateekpurohit13/grima/internal/config"
	"github.com/prateekpurohit13/grima/internal/fingerprint"
)

// Solo-signal alertability and the novel-extension alert point. These are the
// measurements behind Sprint 4 items 4.9 and 4.10; they are not scenario tests.
//
// The question here is arithmetic — "given the shipped weights and bands, what
// does one signal at full value produce on its own?" — so the fixtures are
// hand-built vectors chosen to saturate exactly one signal and leave the rest
// quiet. The scorer under test is the real one; nothing is re-implemented.

// alertabilityBaseline uses round means so "8x baseline" is an exact fact in the
// fixtures below, which keeps the saturation table readable.
func alertabilityBaseline() *calibrate.Baseline {
	return &calibrate.Baseline{
		Version:    calibrate.Version,
		MinSamples: 10,
		SigmaFloor: 0.05,
		EntropyByExt: map[string]calibrate.Dist{
			".txt": {Mean: 4.0, StdDev: 0.5, N: 100},
		},
		WriteRateByProc: map[string]float64{},
		WriteRate:       calibrate.Dist{Mean: 5, StdDev: 1, N: 100},
		CreateRate:      calibrate.Dist{Mean: 5, StdDev: 1, N: 100},
		RenameRate:      calibrate.Dist{Mean: 5, StdDev: 1, N: 100},
		DeleteRate:      calibrate.Dist{Mean: 5, StdDev: 1, N: 100},
		FileEventRate:   calibrate.Dist{Mean: 20, StdDev: 2, N: 100},
		DirFanout:       calibrate.Dist{Mean: 2, StdDev: 1, N: 100},
		KnownExt:        []string{".txt"},
	}
}

func alertabilityBase() fingerprint.TreeVector {
	return fingerprint.TreeVector{
		Root:           1,
		ProcName:       "solo",
		WindowDuration: 30 * time.Second,
		Dirs:           map[string]struct{}{"/data": {}},
		ExtActivity:    map[string]int64{".txt": 1},
	}
}

// soloCase saturates exactly one signal.
type soloCase struct {
	signal       string
	class        Class
	weight       float64
	dropped      uint64
	uncalibrated bool // measured against the no-baseline fallback
	mutate       func(*fingerprint.TreeVector)
}

// Every emitted signal in config.DefaultSignalWeights, saturated on its own at
// an exactly-known value of 1.0.
func soloCases() []soloCase {
	return []soloCase{
		{
			signal: "entropy_deviation", class: ClassPrimary, weight: 1.0,
			// Entropy +6σ (7.0 against mean 4.0, σ 0.5) saturates the z>=6 ceiling.
			mutate: func(tv *fingerprint.TreeVector) {
				tv.Entropy = []fingerprint.EntropySample{{Ext: ".txt", H: 7.0}}
			},
		},
		{
			signal: "magic_mismatch", class: ClassPrimary, weight: 1.0,
			mutate: func(tv *fingerprint.TreeVector) {
				tv.Writes, tv.MagicTotal, tv.MagicMismatch = 10, 10, 10
			},
		},
		{
			signal: "write_burst", class: ClassPrimary, weight: 1.0,
			mutate: func(tv *fingerprint.TreeVector) { tv.Writes = 1200 }, // 40/s vs 5/s
		},
		{
			signal: "create_burst", class: ClassPrimary, weight: 0.6,
			mutate: func(tv *fingerprint.TreeVector) { tv.Creates = 1200 }, // 40/s vs 5/s
		},
		{
			signal: "write_rate_absolute", class: ClassPrimary, weight: 1.0,
			uncalibrated: true,
			mutate:       func(tv *fingerprint.TreeVector) { tv.Writes = 4800 }, // 160/s vs 20/s
		},
		{
			signal: "rename_burst", class: ClassPrimary, weight: 0.8,
			mutate: func(tv *fingerprint.TreeVector) { tv.Renames = 1200 },
		},
		{
			signal: "unknown_extension_activity", class: ClassPrimary, weight: 1.0,
			mutate: func(tv *fingerprint.TreeVector) {
				tv.Writes = 50
				tv.ExtActivity = map[string]int64{".newext": 50}
			},
		},
		{
			signal: "delete_rate", class: ClassSecondary, weight: 0.4,
			mutate: func(tv *fingerprint.TreeVector) { tv.Deletes = 1200 },
		},
		{
			signal: "dir_fanout", class: ClassSecondary, weight: 0.4,
			mutate: func(tv *fingerprint.TreeVector) {
				tv.Dirs = map[string]struct{}{}
				for i := range 100 {
					tv.Dirs[fmt.Sprintf("/data/d%d", i)] = struct{}{}
				}
			},
		},
		{
			signal: "cum_bytes_rewritten", class: ClassSecondary, weight: 0.4,
			mutate: func(tv *fingerprint.TreeVector) {
				tv.CumBytesRewritten = 1 << 30 // the signal's own 1 GiB ceiling
				tv.CumFilesRewritten = 100
			},
		},
		{
			signal: "ngram_rename_chain", class: ClassSecondary, weight: 0.2,
			mutate: func(tv *fingerprint.TreeVector) {
				tv.NGram = fingerprint.NGram{
					K: 32, Total: 89, Count: 89, Sequence: "file_write>file_rename",
					RenameChains: 89, ChainShare: 1,
				}
			},
		},
		{
			signal: "bus_drops", class: ClassSecondary, weight: 0.2,
			dropped: 1000,
		},
	}
}

func evaluateSolo(t *testing.T, tc soloCase) Verdict {
	t.Helper()
	cfg := config.Default()
	scorer := NewScorer(cfg)

	tv := alertabilityBase()
	if tc.mutate != nil {
		tc.mutate(&tv)
	}
	in := Inputs{Tree: tv, BusDropped: tc.dropped}
	if !tc.uncalibrated {
		in.Baseline = alertabilityBaseline()
	}
	return scorer.Evaluate(in)
}

// The per-signal saturation table for item 4.9, measured with the real scorer.
//
// A signal is solo-alertable when its fused score reaches the medium band with
// no other evidence. The table is printed so the number behind a weight change
// is reproducible rather than asserted by memory.
func TestSoloSignalSaturationTable(t *testing.T) {
	cfg := config.Default()
	medium := cfg.Scoring.LevelBands.Medium

	t.Logf("%-28s %-9s %6s %6s %6s %s", "signal", "class", "weight", "raw", "fused", "level")
	for _, tc := range soloCases() {
		v := evaluateSolo(t, tc)

		// The fixture must saturate exactly the intended signal; a second signal
		// present would make the row measure a combination, not the signal.
		if len(v.Signals) != 1 || v.Signals[0].Name != tc.signal {
			t.Fatalf("%s: fixture produced %v, want only %s",
				tc.signal, signalNames(v), tc.signal)
		}
		if got := v.Signals[0].Value; math.Abs(got-1.0) > 1e-9 {
			t.Fatalf("%s: value = %v, want the fixture to saturate it to 1.0", tc.signal, got)
		}
		if got := v.Signals[0].Class; got != tc.class {
			t.Fatalf("%s: class = %v, want %v", tc.signal, got, tc.class)
		}
		if got := cfg.WeightFor(tc.signal); got != tc.weight {
			t.Fatalf("%s: shipped weight = %v, want %v", tc.signal, got, tc.weight)
		}

		t.Logf("%-28s %-9s %6.2f %6.1f %6.1f %s",
			tc.signal, tc.class, tc.weight, 100*tc.weight, v.Score, v.Level)

		// A Secondary must never page an operator on its own, at any band value:
		// score is zero because its weight only applies alongside a Primary.
		if tc.class == ClassSecondary {
			if v.Level >= LevelMedium {
				t.Errorf("%s alone = %s (%.1f), want below medium", tc.signal, v.Level, v.Score)
			}
			if v.Score >= medium {
				t.Errorf("%s alone scored %.1f, want below the medium band %.0f",
					tc.signal, v.Score, medium)
			}
			continue
		}

		// A Primary at full value still carries its own weight.
		if want := 100 * tc.weight; math.Abs(v.Score-want) > 1e-9 {
			t.Errorf("%s alone = %.4f, want %.4f (100 x weight)", tc.signal, v.Score, want)
		}
		if v.Level < LevelMedium {
			t.Errorf("%s alone = %s, want at least medium", tc.signal, v.Level)
		}
	}
}

// No Secondary signal in the table escapes pricing.
//
// The weight table is the thing being priced, so a new entry that is never
// measured here would silently reintroduce the arithmetic accident item 4.9
// exists to remove. static_reputation is the only documented exception: it is a
// Secondary in design.md §5 but Phase 7 work, so the scorer never emits it.
func TestEveryWeightedSignalIsPriced(t *testing.T) {
	measured := map[string]bool{}
	for _, tc := range soloCases() {
		measured[tc.signal] = true
	}

	for _, w := range config.DefaultSignalWeights {
		if measured[w.Name] {
			continue
		}
		if w.Name == "static_reputation" {
			continue
		}
		t.Errorf("weight table prices %q at %.2f but no saturation case measures it",
			w.Name, w.Weight)
	}
}

// Secondary signals corroborating one another is still a verdict with no
// Primary companion, and the weights cannot bound the combination: three
// saturated Secondaries fuse well above the band even at weight 0.4. The rule
// is structural, so the whole tier saturated together must still stay silent.
func TestSecondariesTogetherCannotCarryAVerdictAlone(t *testing.T) {
	cfg := config.Default()
	medium := cfg.Scoring.LevelBands.Medium

	tv := alertabilityBase()
	tv.Deletes = 1200
	tv.Dirs = map[string]struct{}{}
	for i := range 100 {
		tv.Dirs[fmt.Sprintf("/data/d%d", i)] = struct{}{}
	}
	tv.CumBytesRewritten = 1 << 30
	tv.CumFilesRewritten = 100
	tv.NGram = fingerprint.NGram{
		K: 32, Total: 89, Count: 89, Sequence: "file_write>file_rename",
		RenameChains: 89, ChainShare: 1,
	}

	v := NewScorer(cfg).Evaluate(Inputs{Tree: tv, Baseline: alertabilityBaseline(), BusDropped: 1000})

	want := map[string]bool{
		"delete_rate": true, "dir_fanout": true, "cum_bytes_rewritten": true,
		"ngram_rename_chain": true, "bus_drops": true,
	}
	for _, sg := range v.Signals {
		if sg.Class == ClassPrimary {
			t.Fatalf("fixture produced a Primary signal %q; it must have none", sg.Name)
		}
		delete(want, sg.Name)
	}
	for name := range want {
		t.Errorf("secondary signal %q did not fire; the fixture is not measuring the whole tier", name)
	}

	t.Logf("every Secondary saturated together: score %.1f level %s", v.Score, v.Level)
	if v.Score >= medium {
		t.Errorf("five saturated Secondaries scored %.1f (medium band %.0f); a Secondary-only verdict must stay below the band",
			v.Score, medium)
	}
	if v.Level >= LevelMedium {
		t.Errorf("five saturated Secondaries reached %s with no Primary present", v.Level)
	}
}

// The structural rule must not discard corroboration: with one Primary present,
// the Secondary tier adds to the score again.
func TestSecondaryCorroboratesOnceAPrimaryIsPresent(t *testing.T) {
	scorer := NewScorer(config.Default())

	// Entropy +3σ (H 5.5 against mean 4.0, σ 0.5) is half-saturated, so the
	// Secondary's own contribution is visible rather than hidden by a ceiling.
	primary := alertabilityBase()
	primary.Entropy = []fingerprint.EntropySample{{Ext: ".txt", H: 5.5}}

	withSecondary := primary
	withSecondary.Deletes = 1200

	alone := scorer.Evaluate(Inputs{Tree: primary, Baseline: alertabilityBaseline()})
	corroborated := scorer.Evaluate(Inputs{Tree: withSecondary, Baseline: alertabilityBaseline()})

	t.Logf("primary alone %.2f (%s); with delete_rate %.2f (%s)",
		alone.Score, alone.Level, corroborated.Score, corroborated.Level)
	if corroborated.Score <= alone.Score {
		t.Fatalf("delete_rate added nothing to a Primary verdict: %.1f alone, %.1f corroborated",
			alone.Score, corroborated.Score)
	}
}

// Item 4.10, decided: the novel-extension alert point is accepted, not floored.
//
// The levels are pinned so the cost of the decision cannot drift unnoticed, and
// the quiet-drip pair is pinned from the other side: it is the capability a
// minimum-novelty floor large enough to move 30 files below the band would
// break (see the comment on unknownExtensionSignal).
func TestNovelExtensionAlertPointIsAccepted(t *testing.T) {
	scorer := NewScorer(config.Default())

	novel := func(files int64) Verdict {
		tv := alertabilityBase()
		tv.Writes = int(files)
		tv.ExtActivity = map[string]int64{".newext": files}
		return scorer.Evaluate(Inputs{Tree: tv, Baseline: alertabilityBaseline()})
	}

	wantLevel := []struct {
		files int64
		level Level
		score float64
	}{
		{10, LevelInfo, 20.0},
		{20, LevelLow, 40.0},
		{30, LevelMedium, 60.0}, // the accepted medium alert
		{50, LevelCritical, 100.0},
	}
	for _, want := range wantLevel {
		v := novel(want.files)
		if v.Level != want.level || math.Abs(v.Score-want.score) > 1e-9 {
			t.Errorf("%d novel files = %s (%.1f), want %s (%.1f)",
				want.files, v.Level, v.Score, want.level, want.score)
		}
	}

	// The quiet drip (Sprint 2 item 2.2): 24 files of an unseen extension in a
	// window with no other evidence, carried by this signal at 0.480 and
	// cum_bytes_rewritten at 0.094. It must keep reaching the band.
	quiet := alertabilityBase()
	quiet.Writes = 24
	quiet.ExtActivity = map[string]int64{".newext": 24}
	quiet.CumFilesRewritten = 24
	cumFraction := 0.094
	quiet.CumBytesRewritten = int64(cumFraction * float64(int64(1)<<30))

	v := scorer.Evaluate(Inputs{Tree: quiet, Baseline: alertabilityBaseline()})
	t.Logf("quiet drip at 24 novel files: score %.2f level %s", v.Score, v.Level)
	if v.Level < LevelMedium {
		t.Errorf("the quiet-drip pair reached only %s (%.2f); a floor that raises the alert point has broken item 2.2",
			v.Level, v.Score)
	}
}

// The corroboration gate is structural, so it has to read "a Primary
// contributed", not "a Primary was present". An operator muting a noisy Primary
// by removing its weight entry must not silently restore Secondary-only fusion —
// which is the 86.2 high verdict the gate exists to make impossible.
func TestMutedPrimaryDoesNotOpenTheCorroborationGate(t *testing.T) {
	saturatedSecondaries := func() fingerprint.TreeVector {
		tv := alertabilityBase()
		tv.Entropy = []fingerprint.EntropySample{{Ext: ".txt", H: 7.0}} // entropy_deviation
		tv.Deletes = 1200
		tv.CumBytesRewritten = 1 << 30
		tv.CumFilesRewritten = 100
		tv.Dirs = map[string]struct{}{}
		for i := range 100 {
			tv.Dirs[fmt.Sprintf("/data/d%d", i)] = struct{}{}
		}
		tv.NGram = fingerprint.NGram{
			K: 32, Total: 89, Count: 89, Sequence: "file_write>file_rename",
			RenameChains: 89, ChainShare: 1,
		}
		return tv
	}

	// The Primary is present in both runs; only its weight differs.
	withWeight := config.Default()
	muted := config.Default()
	kept := make([]config.Weight, 0, len(muted.Scoring.Weights))
	for _, w := range muted.Scoring.Weights {
		if w.Name == "entropy_deviation" {
			continue // the operator removed the entry to silence it
		}
		kept = append(kept, w)
	}
	muted.Scoring.Weights = kept

	t.Run("muted Primary does not gate", func(t *testing.T) {
		v := NewScorer(muted).Evaluate(Inputs{Tree: saturatedSecondaries(), Baseline: alertabilityBaseline()})

		var primaryPresent bool
		for _, sg := range v.Signals {
			if sg.Class == ClassPrimary {
				primaryPresent = true
			}
		}
		if !primaryPresent {
			t.Fatal("the fixture has no Primary; it is not measuring the gate")
		}
		if v.Score != 0 {
			t.Fatalf("score = %.1f from Secondary signals alone; a muted Primary must not gate", v.Score)
		}
		if v.Level >= LevelLow {
			t.Fatalf("level = %v, want info for Secondary-only evidence", v.Level)
		}
	})

	t.Run("a contributing Primary does gate", func(t *testing.T) {
		v := NewScorer(withWeight).Evaluate(Inputs{Tree: saturatedSecondaries(), Baseline: alertabilityBaseline()})

		if v.Score <= 0 {
			t.Fatalf("score = %.1f with a weighted Primary present; the gate should admit corroboration", v.Score)
		}
	})
}
