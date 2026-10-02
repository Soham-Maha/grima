package attrib

import (
	"errors"
	"testing"
	"time"

	"github.com/prateekpurohit13/grima/internal/config"
	"github.com/prateekpurohit13/grima/internal/event"
)

var errSourceUnavailable = errors.New("source unavailable")

func TestConfigureCorrelateAttachesNothing(t *testing.T) {
	a := New(time.Second)
	a.Configure(config.AttributionConfig{Mode: config.AttributionCorrelate}, []string{`C:\data`}, testLogger())

	if a.causal != nil || a.source != nil || a.pending != nil {
		t.Fatal("correlate mode must not attach a causal source")
	}
	if got := a.Stats().Mode; got != modeCorrelate {
		t.Fatalf("mode = %q, want %q", got, modeCorrelate)
	}
}

// Sad path: a mode the platform cannot run leaves the detector correlating and
// reports why, rather than failing to start or starting blind.
func TestConfigureUnknownModeFallsBackToCorrelation(t *testing.T) {
	a := New(time.Second)
	a.Configure(config.AttributionConfig{Mode: "telepathy"}, []string{`C:\data`}, testLogger())

	if a.causal != nil {
		t.Fatal("an unknown mode must not attach a causal source")
	}
	if got := a.Stats().Mode; got != modeCorrelate {
		t.Fatalf("mode = %q, want the fallback %q", got, modeCorrelate)
	}

	a.Observe(8, "crypt", 0, "", 4096)
	if pid, _, _, _, _ := a.Suspect(time.Now(), `C:\a.txt`); pid != 8 {
		t.Fatalf("pid = %d, want correlation to still work", pid)
	}
}

// Sad path: a delay that is missing or nonsensical is replaced by the default
// rather than trusted, so a file event cannot be held indefinitely.
func TestResolveDelayReplacesUnusableValues(t *testing.T) {
	cases := []struct {
		name string
		in   config.Duration
		want time.Duration
	}{
		{"unset", 0, defaultMaxDelay},
		{"negative", config.Duration(-time.Second), defaultMaxDelay},
		{"configured", config.Duration(75 * time.Millisecond), 75 * time.Millisecond},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := resolveDelay(config.AttributionConfig{MaxDelay: tc.in})
			if got != tc.want {
				t.Fatalf("delay = %s, want %s", got, tc.want)
			}
		})
	}
}

func TestConfigureWithNoLoggerDoesNotPanic(t *testing.T) {
	a := New(time.Second)
	a.Configure(config.AttributionConfig{Mode: config.AttributionCorrelate}, nil, nil)

	if a.log == nil {
		t.Fatal("want a usable logger even when none is supplied")
	}
}

func TestConfigureNilAttributorIsSafe(t *testing.T) {
	var a *Attributor
	a.Configure(config.AttributionConfig{Mode: config.AttributionAudit}, nil, testLogger())
}

// The shipped default for the failure table's ambiguous-attribution row: host
// mode makes no per-process claim, so two competing writers cannot put a wrong
// PID on the event. The evidence aggregates on the host (PID 0) fingerprint
// instead of being split across a guess.
func TestHostModeFilesAgainstTheHostFingerprint(t *testing.T) {
	a := New(time.Second)
	a.Configure(config.AttributionConfig{Mode: config.AttributionHost}, []string{`C:\data`}, testLogger())

	a.Observe(11, "heavy", 0, `C:\Tools\heavy.exe`, 9000)
	a.Observe(22, "light", 0, `C:\Tools\light.exe`, 1000)

	recorder := newEmitRecorder(1)
	a.Resolve(event.Event{Kind: event.KindFileWrite, Path: `C:\data\a.txt`, Time: time.Now()}, recorder.emit)

	emitted := recorder.wait(t)
	if emitted[0].PID != 0 {
		t.Fatalf("pid = %d, want 0: host mode must not blame a process", emitted[0].PID)
	}
}

func TestCausalWindowIsWiderThanTheDelay(t *testing.T) {
	if got := causalWindow(time.Second); got <= time.Second {
		t.Fatalf("window = %s, want it to outlast the wait", got)
	}
	if got := causalWindow(time.Millisecond); got < 2*time.Second {
		t.Fatalf("window = %s, want a floor so a short delay still matches", got)
	}
}
