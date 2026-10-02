package response

import (
	"bytes"
	"errors"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/prateekpurohit13/grima/internal/config"
	"github.com/prateekpurohit13/grima/internal/score"
)

func testHandler(t *testing.T, cooldown time.Duration) (*Handler, *bytes.Buffer) {
	t.Helper()

	cfg := config.Default()
	cfg.Response.AlertCooldown = config.Duration(cooldown)

	var buf bytes.Buffer
	log := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	return NewHandler(cfg, log), &buf
}

func verdict(pid int32, level score.Level) score.Verdict {
	return score.Verdict{
		PID:      pid,
		ProcName: "encryptor",
		Score:    95,
		Level:    level,
		Signals:  []score.Signal{{Name: "R-DECOY-TOUCH", Class: score.ClassOverride, Level: level}},
	}
}

func countAlerts(buf *bytes.Buffer) int {
	return strings.Count(buf.String(), "ransomware risk detected")
}

func TestDecideGatesSuspendOnOptInAndCritical(t *testing.T) {
	off, _ := testHandler(t, 0)
	if got := off.Decide(verdict(1, score.LevelCritical)); got != Alert {
		t.Errorf("suspend off, critical: action = %s, want alert", got)
	}
	if got := off.Decide(verdict(1, score.LevelLow)); got != Observe {
		t.Errorf("suspend off, low: action = %s, want observe", got)
	}

	cfg := config.Default()
	cfg.Response.EnableSuspend = true
	on := NewHandler(cfg, slog.New(slog.DiscardHandler))
	if got := on.Decide(verdict(1, score.LevelCritical)); got != Suspend {
		t.Errorf("suspend on, critical: action = %s, want suspend", got)
	}
	if got := on.Decide(verdict(1, score.LevelHigh)); got != Alert {
		t.Errorf("suspend on, high: action = %s, want alert", got)
	}
}

func TestActionStringCoversAllActions(t *testing.T) {
	for action, want := range map[Action]string{Observe: "observe", Alert: "alert", Suspend: "suspend"} {
		if got := action.String(); got != want {
			t.Errorf("Action(%d).String() = %q, want %q", action, got, want)
		}
	}
	if got := Action(99).String(); got != "action(?)" {
		t.Errorf("unknown action = %q, want %q", got, "action(?)")
	}
}

func TestApplyObservesWithoutAlerting(t *testing.T) {
	h, buf := testHandler(t, 0)

	if err := h.Apply(verdict(1, score.LevelLow)); err != nil {
		t.Fatalf("apply: %v", err)
	}
	if got := countAlerts(buf); got != 0 {
		t.Fatalf("alerts = %d, want none below the alert band", got)
	}
}

// The default has no cooldown, so behaviour is unchanged: every tick over the
// alert band is logged.
func TestApplyAlertsOnEveryTickWithoutCooldown(t *testing.T) {
	h, buf := testHandler(t, 0)

	for range 5 {
		if err := h.Apply(verdict(1, score.LevelCritical)); err != nil {
			t.Fatalf("apply: %v", err)
		}
	}
	if got := countAlerts(buf); got != 5 {
		t.Fatalf("alerts = %d, want 5 with no cooldown", got)
	}
}

// One persistent condition is one incident, identified by the tree root, so a
// second process still alerts on its own.
func TestApplyAlertsOncePerIncidentWhenCooldownSet(t *testing.T) {
	h, buf := testHandler(t, 30*time.Second)

	for range 5 {
		if err := h.Apply(verdict(1, score.LevelCritical)); err != nil {
			t.Fatalf("apply: %v", err)
		}
	}
	if got := countAlerts(buf); got != 1 {
		t.Fatalf("alerts = %d, want 1 for a persistent condition", got)
	}

	if err := h.Apply(verdict(2, score.LevelCritical)); err != nil {
		t.Fatalf("apply: %v", err)
	}
	if got := countAlerts(buf); got != 2 {
		t.Fatalf("alerts = %d, want 2 once a second process alerts", got)
	}
}

func TestCooldownExpiryAndSeverityDropReArmTheIncident(t *testing.T) {
	h, buf := testHandler(t, 10*time.Second)
	now := time.Unix(1000, 0)
	h.now = func() time.Time { return now }

	v := verdict(7, score.LevelCritical)
	if err := h.Apply(v); err != nil {
		t.Fatalf("apply: %v", err)
	}
	if err := h.Apply(v); err != nil {
		t.Fatalf("apply: %v", err)
	}
	if got := countAlerts(buf); got != 1 {
		t.Fatalf("alerts = %d, want 1 while the cooldown holds", got)
	}

	now = now.Add(11 * time.Second)
	if err := h.Apply(v); err != nil {
		t.Fatalf("apply: %v", err)
	}
	if got := countAlerts(buf); got != 2 {
		t.Fatalf("alerts = %d, want 2 once the cooldown expires", got)
	}

	// Dropping below the alert band ends the incident, so the next rise alerts
	// even though the cooldown has not elapsed.
	now = now.Add(time.Second)
	if err := h.Apply(verdict(7, score.LevelInfo)); err != nil {
		t.Fatalf("apply: %v", err)
	}
	if err := h.Apply(v); err != nil {
		t.Fatalf("apply: %v", err)
	}
	if got := countAlerts(buf); got != 3 {
		t.Fatalf("alerts = %d, want 3 after the severity dropped and rose again", got)
	}
}

// Sad path: a suspend that fails must reach the caller, so the pipeline logs it
// rather than reporting a process stopped that is still running. This is also
// the shape of an unsupported platform: there is no suspend primitive, and the
// handler surfaces the error instead of silently doing nothing.
func TestApplyReportsSuspendFailure(t *testing.T) {
	cfg := config.Default()
	cfg.Response.EnableSuspend = true
	h := NewHandler(cfg, slog.New(slog.DiscardHandler))
	h.suspend = func(int32) error { return errors.New("no suspend primitive on this platform") }

	err := h.Apply(verdict(4242, score.LevelCritical))
	if err == nil {
		t.Fatal("a failed suspend must be reported")
	}
	if !strings.Contains(err.Error(), "suspend pid 4242") {
		t.Fatalf("error = %v, want it to name the pid", err)
	}
}

func TestSignalSummary(t *testing.T) {
	if got := signalSummary(score.Verdict{}); got != "none" {
		t.Fatalf("empty summary = %q, want none", got)
	}

	many := score.Verdict{Signals: []score.Signal{
		{Name: "a"}, {Name: "b"}, {Name: "c"}, {Name: "d"}, {Name: "e"}, {Name: "f"},
	}}
	if got, want := signalSummary(many), "a; b; c; d; e; ..."; got != want {
		t.Fatalf("summary = %q, want %q", got, want)
	}
}
