// Package response applies actions to verdicts.
//
// The default is Observe. Terminating or suspending a process on a heuristic
// score is a denial-of-service primitive: a false positive against a database
// process is worse than a missed detection that alerts. Suspension is opt-in and
// gated on Critical.
package response

import (
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/prateekpurohit13/grima/internal/config"
	"github.com/prateekpurohit13/grima/internal/score"
)

// Action is what the handler does with a verdict.
type Action uint8

const (
	// Observe records the verdict with no side effect. Default.
	Observe Action = iota
	// Alert emits the verdict to the configured sink.
	Alert
	// Suspend stops the process from being scheduled.
	Suspend
)

var actionNames = [...]string{"observe", "alert", "suspend"}

// String returns the stable lowercase name of the action.
func (a Action) String() string {
	if int(a) < len(actionNames) {
		return actionNames[a]
	}
	return "action(?)"
}

// maxOpenIncidents bounds the throttle table. A process that alerts and then
// disappears without a below-band verdict would otherwise leak an entry.
const maxOpenIncidents = 4096

// Handler applies response policy to verdicts.
type Handler struct {
	cfg        config.Config
	alertMin   score.Level
	suspendMin score.Level
	log        *slog.Logger

	// suspend is the platform primitive, held as a field so a test can exercise
	// the failure path without a suspendable target.
	suspend func(int32) error
	// now is the clock, held as a field so a test can advance past a cooldown.
	now func() time.Time

	mu sync.Mutex
	// alerts maps a verdict's tree root to the last alert it produced while its
	// incident is open.
	alerts map[int32]time.Time
}

// NewHandler builds a handler from configuration.
func NewHandler(cfg config.Config, log *slog.Logger) *Handler {
	alertMin, _ := score.ParseLevel(cfg.Response.AlertMinLevel)
	suspendMin, _ := score.ParseLevel(cfg.Response.SuspendMinLevel)

	return &Handler{
		cfg:        cfg,
		alertMin:   alertMin,
		suspendMin: suspendMin,
		log:        log,
		suspend:    suspendProcess,
		now:        time.Now,
		alerts:     make(map[int32]time.Time),
	}
}

// Decide returns the action this verdict warrants, without performing it.
func (h *Handler) Decide(v score.Verdict) Action {
	if h.cfg.Response.EnableSuspend && v.Level >= h.suspendMin && v.Level >= score.LevelCritical {
		return Suspend
	}
	if v.Level >= h.alertMin {
		return Alert
	}
	return Observe
}

// Apply performs the action for a verdict.
//
// An alert throttles per incident: the incident is identified by the verdict's
// tree root, so one persistent condition produces one alert rather than one per
// scoring tick. A verdict below the alert band ends the incident, and the
// cooldown expiring re-arms the next alert.
func (h *Handler) Apply(v score.Verdict) error {
	switch h.Decide(v) {
	case Observe:
		h.clearIncident(v.PID)
		return nil

	case Alert:
		if !h.alertDue(v.PID) {
			return nil
		}
		h.log.Warn("ransomware risk detected",
			"pid", v.PID,
			"process", v.ProcName,
			"score", fmt.Sprintf("%.1f", v.Score),
			"level", v.Level.String(),
			"override", v.Override,
			"signals", signalSummary(v),
		)
		return nil

	case Suspend:
		if err := h.suspend(v.PID); err != nil {
			return fmt.Errorf("suspend pid %d: %w", v.PID, err)
		}
		h.log.Warn("process suspended",
			"pid", v.PID,
			"process", v.ProcName,
			"score", fmt.Sprintf("%.1f", v.Score),
			"level", v.Level.String(),
			"signals", signalSummary(v),
		)
		return nil
	}
	return nil
}

// alertDue reports whether an alert for a tree root is due, and records it when
// it is. Without a cooldown every verdict alerts; otherwise the first alert
// opens the incident and repeats are held until the cooldown elapses.
func (h *Handler) alertDue(root int32) bool {
	cooldown := h.cfg.Response.AlertCooldown.Std()
	if cooldown <= 0 {
		return true
	}

	now := h.now()

	h.mu.Lock()
	defer h.mu.Unlock()

	if last, open := h.alerts[root]; open && now.Sub(last) < cooldown {
		h.log.Debug("alert suppressed by cooldown", "pid", root, "since", now.Sub(last).Round(time.Second))
		return false
	}
	if len(h.alerts) >= maxOpenIncidents {
		h.prune(now, cooldown)
	}
	h.alerts[root] = now
	return true
}

// clearIncident ends the incident for a tree root, so its next alert is due
// immediately instead of waiting out the cooldown.
func (h *Handler) clearIncident(root int32) {
	h.mu.Lock()
	delete(h.alerts, root)
	h.mu.Unlock()
}

// prune forgets incidents whose cooldown has elapsed. Forgetting one is
// harmless: the next alert after a cooldown is emitted anyway.
func (h *Handler) prune(now time.Time, cooldown time.Duration) {
	for root, last := range h.alerts {
		if now.Sub(last) >= cooldown {
			delete(h.alerts, root)
		}
	}
}

func signalSummary(v score.Verdict) string {
	if len(v.Signals) == 0 {
		return "none"
	}
	out := ""
	for i, s := range v.Signals {
		if i > 0 {
			out += "; "
		}
		out += s.Name
		if i >= 4 {
			out += "; ..."
			break
		}
	}
	return out
}
