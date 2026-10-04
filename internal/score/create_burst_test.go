package score

import (
	"testing"
	"time"

	"github.com/prateekpurohit13/grima/internal/calibrate"
	"github.com/prateekpurohit13/grima/internal/config"
	"github.com/prateekpurohit13/grima/internal/fingerprint"
)

// Creates are counted in the fingerprint, so they have to be scored. A process
// that only creates files — an unpacker, a restore, a locker writing a note per
// directory — writes nothing the write counter records, and before create_burst
// existed it produced no verdict at all: 12,026 create events in one second
// scored nothing in either mode.
func TestCreateOnlyStormIsScored(t *testing.T) {
	verdict := NewScorer(config.Default()).Evaluate(Inputs{
		Tree: fingerprint.TreeVector{
			Root: 1, ProcName: "unpacker", Creates: 1200, WindowDuration: window,
		},
		Baseline: testBaseline(),
	})

	sg, ok := signalsByName(verdict)["create_burst"]
	if !ok {
		t.Fatalf("create_burst absent on a create-only storm; got %v", verdict.Signals)
	}
	if sg.Value != 1 {
		t.Fatalf("create_burst value = %v, want saturation at 8x the baseline", sg.Value)
	}
	if sg.Class != ClassPrimary {
		t.Fatalf("create_burst class = %v, want primary", sg.Class)
	}
	if sg.Detail == "" {
		t.Fatal("create_burst has no detail")
	}
}

// A create rate that was never measured is unknown, so the signal stays omitted
// rather than reporting the host as quiet.
func TestCreateBurstOmittedWithoutSamples(t *testing.T) {
	baseline := testBaseline()
	baseline.CreateRate = calibrate.Dist{}

	verdict := NewScorer(config.Default()).Evaluate(Inputs{
		Tree: fingerprint.TreeVector{
			Root: 1, ProcName: "unpacker", Creates: 5000, WindowDuration: window,
		},
		Baseline: baseline,
	})

	if sg, ok := signalsByName(verdict)["create_burst"]; ok {
		t.Fatalf("create_burst = %v from a distribution with no samples", sg.Value)
	}
}

// Uncalibrated mode has no create rate to compare against, so the absolute
// fallback is the only thing that can see a create-only storm. It thresholds
// bulk modification, and a create is bulk modification.
func TestUncalibratedCreateStormTripsTheAbsoluteFallback(t *testing.T) {
	cfg := config.Default()
	cfg.Scoring.AbsoluteWriteRate = 20

	// 12,026 creates over the window: the storm that scored nothing before.
	verdict := NewScorer(cfg).Evaluate(Inputs{
		Tree: fingerprint.TreeVector{
			Root: 1, ProcName: "unpacker", Creates: 12026, WindowDuration: window,
		},
		Baseline: nil,
	})

	sg, ok := signalsByName(verdict)["write_rate_absolute"]
	if !ok {
		t.Fatalf("create-only storm produced no absolute signal; got %v", verdict.Signals)
	}
	if sg.Value != 1 {
		t.Fatalf("write_rate_absolute value = %v, want saturation", sg.Value)
	}
	if verdict.Level < LevelMedium {
		t.Fatalf("level = %v, want medium or above for a 400 creates/s storm", verdict.Level)
	}
}

// The absolute fallback still has to leave a quiet host alone.
func TestUncalibratedFewCreatesStaySilent(t *testing.T) {
	verdict := NewScorer(config.Default()).Evaluate(Inputs{
		Tree: fingerprint.TreeVector{
			Root: 1, ProcName: "editor", Creates: 20, Writes: 20, WindowDuration: time.Minute,
		},
		Baseline: nil,
	})

	if sg, ok := signalsByName(verdict)["write_rate_absolute"]; ok {
		t.Fatalf("40 modifications over a minute produced %v", sg.Value)
	}
}
