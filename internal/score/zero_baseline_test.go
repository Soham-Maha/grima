package score

import (
	"testing"
	"time"

	"github.com/prateekpurohit13/grima/internal/calibrate"
	"github.com/prateekpurohit13/grima/internal/config"
	"github.com/prateekpurohit13/grima/internal/fingerprint"
)

// window is the production window length: the decay half-life the engine
// reports as a tree vector's duration.
const window = 30 * time.Second

func signalsByName(v Verdict) map[string]Signal {
	out := make(map[string]Signal, len(v.Signals))
	for _, sg := range v.Signals {
		out[sg.Name] = sg
	}
	return out
}

// A warm-up on a quiet host measures a rate of zero for the actions the host
// never performed. That is a measurement, not an absence of one: the signal has
// to stay available and read the burst as a large deviation. Comparing against
// the zero instead disabled it for the life of the deployment, while health went
// on reporting the baseline as ready.
func TestZeroRateBaselineStillSeesABurst(t *testing.T) {
	cases := []struct {
		name   string
		signal string
		zero   func(*calibrate.Baseline)
		tree   fingerprint.TreeVector
	}{
		{
			name:   "rename burst on a host that never renames",
			signal: "rename_burst",
			zero:   func(b *calibrate.Baseline) { b.RenameRate = calibrate.Dist{Mean: 0, StdDev: 0, N: 7} },
			tree:   fingerprint.TreeVector{Root: 1, ProcName: "locker", Renames: 80, WindowDuration: window},
		},
		{
			name:   "delete rate on a host that never deletes",
			signal: "delete_rate",
			zero:   func(b *calibrate.Baseline) { b.DeleteRate = calibrate.Dist{Mean: 0, StdDev: 0, N: 7} },
			tree:   fingerprint.TreeVector{Root: 1, ProcName: "wiper", Deletes: 80, WindowDuration: window},
		},
		{
			name:   "write burst on a host that never wrote",
			signal: "write_burst",
			zero:   func(b *calibrate.Baseline) { b.WriteRate = calibrate.Dist{Mean: 0, StdDev: 0, N: 7} },
			tree:   fingerprint.TreeVector{Root: 1, ProcName: "cryptor", Writes: 900, WindowDuration: window},
		},
		{
			name:   "directory fan-out on a host with no fan-out samples",
			signal: "dir_fanout",
			zero:   func(b *calibrate.Baseline) { b.DirFanout = calibrate.Dist{Mean: 0, StdDev: 0, N: 3} },
			tree: fingerprint.TreeVector{
				Root: 1, ProcName: "cryptor", WindowDuration: window,
				Dirs: manyDirs(200),
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			baseline := testBaseline()
			tc.zero(baseline)

			verdict := NewScorer(config.Default()).Evaluate(Inputs{Tree: tc.tree, Baseline: baseline})

			sg, ok := signalsByName(verdict)[tc.signal]
			if !ok {
				t.Fatalf("%s absent on a zero baseline; got %v", tc.signal, verdict.Signals)
			}
			if sg.Value <= 0 {
				t.Fatalf("%s value = %v, want a positive deviation", tc.signal, sg.Value)
			}
			if sg.Detail == "" {
				t.Fatalf("%s has no detail", tc.signal)
			}
		})
	}
}

// The floor exists so that a host which never renames does not page an operator
// the first time a program performs an ordinary atomic save. A handful of events
// is not a burst.
func TestZeroRateBaselineIgnoresAnOrdinaryEvent(t *testing.T) {
	baseline := testBaseline()
	baseline.RenameRate = calibrate.Dist{Mean: 0, StdDev: 0, N: 7}

	verdict := NewScorer(config.Default()).Evaluate(Inputs{
		Tree:     fingerprint.TreeVector{Root: 1, ProcName: "editor", Renames: 3, WindowDuration: window},
		Baseline: baseline,
	})

	if sg, ok := signalsByName(verdict)["rename_burst"]; ok {
		t.Fatalf("three renames produced rename_burst = %v on a zero baseline", sg.Value)
	}
}

// Unknown and zero are different. A distribution with no samples behind it says
// nothing about the host, so the signal stays omitted even when the activity is
// enormous — reporting it would present an unmeasured quantity as a deviation.
func TestUnmeasuredRateOmitsTheSignal(t *testing.T) {
	baseline := testBaseline()
	baseline.RenameRate = calibrate.Dist{}

	verdict := NewScorer(config.Default()).Evaluate(Inputs{
		Tree:     fingerprint.TreeVector{Root: 1, ProcName: "locker", Renames: 5000, WindowDuration: window},
		Baseline: baseline,
	})

	if sg, ok := signalsByName(verdict)["rename_burst"]; ok {
		t.Fatalf("rename_burst = %v from a distribution with no samples", sg.Value)
	}
}

// The floor is a threshold, not a switch: raising it must raise the burst a
// zero-baseline host needs before the signal contributes.
func TestZeroBaselineBurstRaisesTheBurstNeeded(t *testing.T) {
	tree := fingerprint.TreeVector{Root: 1, ProcName: "locker", Renames: 80, WindowDuration: window}

	low := config.Default()
	low.Scoring.ZeroBaselineBurst = 10
	high := config.Default()
	high.Scoring.ZeroBaselineBurst = 1000

	baseline := func() *calibrate.Baseline {
		b := testBaseline()
		b.RenameRate = calibrate.Dist{Mean: 0, StdDev: 0, N: 7}
		return b
	}

	got := signalsByName(NewScorer(low).Evaluate(Inputs{Tree: tree, Baseline: baseline()}))["rename_burst"]
	want := signalsByName(NewScorer(high).Evaluate(Inputs{Tree: tree, Baseline: baseline()}))["rename_burst"]

	if got.Value <= 0 {
		t.Fatalf("a low floor produced no signal (value %v)", got.Value)
	}
	if want.Value != 0 {
		t.Fatalf("a floor above the observed burst still produced %v", want.Value)
	}
}

func manyDirs(n int) map[string]struct{} {
	out := make(map[string]struct{}, n)
	for i := range n {
		out[string(rune('a'+i%26))+string(rune('a'+(i/26)%26))] = struct{}{}
	}
	return out
}
