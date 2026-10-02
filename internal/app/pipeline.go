package app

import (
	"context"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/prateekpurohit13/grima/internal/bus"
	"github.com/prateekpurohit13/grima/internal/calibrate"
	"github.com/prateekpurohit13/grima/internal/config"
	"github.com/prateekpurohit13/grima/internal/event"
	"github.com/prateekpurohit13/grima/internal/fingerprint"
	"github.com/prateekpurohit13/grima/internal/response"
	"github.com/prateekpurohit13/grima/internal/rules"
	"github.com/prateekpurohit13/grima/internal/score"
	"github.com/prateekpurohit13/grima/internal/sensor"
	"github.com/prateekpurohit13/grima/internal/web"
)

const (
	scoreInterval     = time.Second
	maxHitsPerProcess = 8
)

// overrideTracker keeps recent rule hits so a hit still raises the floor on the
// next scoring tick rather than only at the instant it fired.
type overrideTracker struct {
	mu   sync.Mutex
	hits map[int32][]overrideHit
	ttl  time.Duration
}

type overrideHit struct {
	override score.Override
	at       time.Time
}

func newOverrideTracker(ttl time.Duration) *overrideTracker {
	if ttl <= 0 {
		ttl = 30 * time.Second
	}
	return &overrideTracker{
		hits: make(map[int32][]overrideHit),
		ttl:  ttl,
	}
}

func (t *overrideTracker) Record(pid int32, override score.Override) {
	t.mu.Lock()
	defer t.mu.Unlock()

	list := append(t.hits[pid], overrideHit{override: override, at: time.Now()})
	if len(list) > maxHitsPerProcess {
		list = list[len(list)-maxHitsPerProcess:]
	}
	t.hits[pid] = list
}

func (t *overrideTracker) For(pid int32) []score.Override {
	t.mu.Lock()
	defer t.mu.Unlock()

	list := t.hits[pid]
	if len(list) == 0 {
		return nil
	}

	now := time.Now()
	kept := list[:0]
	var out []score.Override
	for _, hit := range list {
		if now.Sub(hit.at) > t.ttl {
			continue
		}
		kept = append(kept, hit)
		out = append(out, hit.override)
	}

	if len(kept) == 0 {
		delete(t.hits, pid)
	} else {
		t.hits[pid] = kept
	}
	return out
}

// engineLoop owns the fingerprint engine. Every read and every write of window
// state happens on the goroutine that runs it: events arrive on in and scoring
// ticks arrive on the ticker, so the scoring pass reads state that the same
// goroutine wrote. The single-writer invariant (docs/architecture.md §12) is a
// property of this wiring, not a comment — the engine must never be handed to a
// second goroutine, which is why its liveness count is published here rather
// than read by the health handler directly.
type engineLoop struct {
	scoreLoop
	in   <-chan event.Event
	live *atomic.Int64

	// interval is the scoring cadence. Zero means scoreInterval; tests set it
	// lower so a loop does not have to run for a second to be observed.
	interval time.Duration
}

func (l engineLoop) cadence() time.Duration {
	if l.interval <= 0 {
		return scoreInterval
	}
	return l.interval
}

// run blocks until ctx is cancelled or the event channel closes.
func (l engineLoop) run(ctx context.Context) {
	ticker := time.NewTicker(l.cadence())
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case ev, ok := <-l.in:
			if !ok {
				return
			}
			l.engine.Apply(ev)
		case <-ticker.C:
			l.live.Store(int64(l.engine.Live()))
			l.evaluate()
		}
	}
}

// startRuleLoop evaluates rules on raw events, so an override is recorded the
// instant it happens rather than at the next scoring tick.
func startRuleLoop(ctx context.Context, engine *rules.Engine, tracker *overrideTracker, in <-chan event.Event) {
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case ev, ok := <-in:
				if !ok {
					return
				}
				if override, hit := engine.Evaluate(ev); hit {
					tracker.Record(ev.PID, override)
				}
			}
		}
	}()
}

type scoreLoop struct {
	cfg       config.Config
	events    *bus.Bus
	engine    *fingerprint.Engine
	scorer    *score.Scorer
	overrides *overrideTracker
	responder *response.Handler
	hub       *web.Hub
	baseline  *calibrate.Baseline
	log       *slog.Logger

	// lastDropped is the bus drop counter as of the previous tick. The signal
	// reports the drops that happened during the window being scored, not every
	// drop the process has ever seen: with a lifetime counter, one overload
	// episode marked every verdict for the rest of the run, and because a verdict
	// with any signal is published, it also filled the history ring with
	// info-level noise.
	lastDropped uint64
}

func (l *scoreLoop) evaluate() {
	// The drop count is a delta over the window being scored, so an overload that
	// has passed stops marking new verdicts.
	total := l.events.Stats().Dropped
	dropped := total - l.lastDropped
	l.lastDropped = total

	roots := l.engine.Roots()
	// A verdict is the current assessment of a process, so one for a process that
	// has exited is a ghost: it would sit at the top of the dashboard forever.
	// The history ring keeps the incident.
	defer l.hub.Retain(roots)

	hostScored := false
	for _, root := range roots {
		if root == 0 {
			hostScored = true
		}
		verdict := l.scorer.Evaluate(score.Inputs{
			Tree:       l.engine.Aggregate(root),
			Baseline:   l.baseline,
			BusDropped: dropped,
			Overrides:  l.overrides.For(root),
		})
		if !worthReporting(verdict) {
			continue
		}
		l.publish(verdict)
	}

	// A rule hit with no process behind it (a persistence install, say) belongs
	// to the host. Score it only if the host fingerprint did not already cover
	// it, so the same evidence is not reported twice.
	if hostScored {
		return
	}
	if hostOverrides := l.overrides.For(0); len(hostOverrides) > 0 {
		l.publish(l.scorer.Evaluate(score.Inputs{
			Tree:       fingerprint.TreeVector{Root: 0, ProcName: fingerprint.HostName},
			Baseline:   l.baseline,
			BusDropped: dropped,
			Overrides:  hostOverrides,
		}))
	}
}

func (l scoreLoop) publish(verdict score.Verdict) {
	l.hub.Publish(verdict)
	if err := l.responder.Apply(verdict); err != nil {
		l.log.Warn("response action failed", "pid", verdict.PID, "error", err)
	}
}

// worthReporting filters the per-second stream down to verdicts with evidence.
func worthReporting(v score.Verdict) bool {
	return len(v.Signals) > 0 || v.Level >= score.LevelLow
}

func healthSnapshot(startedAt time.Time, events *bus.Bus, sources []sensor.Source, live int, baseline *calibrate.Baseline) web.Health {
	stats := events.Stats()

	// Only sources that started are in this map, so a source that failed to
	// start is absent rather than present with zeroed counters.
	sensors := make(map[string]sensor.Stats, len(sources))
	for _, src := range sources {
		reporter, ok := src.(sensor.Reporter)
		if !ok {
			// The source has no counters: mark them unknown, not zero.
			sensors[src.Name()] = sensor.Stats{Name: src.Name()}
			continue
		}
		reported := reporter.Stats()
		reported.Reporting = true
		sensors[src.Name()] = reported
	}

	health := web.Health{
		CalibrationReady: baseline != nil && baseline.Ready(),
		BusPublished:     stats.Published,
		BusDropped:       stats.Dropped,
		LiveProcesses:    live,
		Sensors:          sensors,
		Uptime:           time.Since(startedAt).Seconds(),
	}
	if baseline != nil {
		health.CalibrationAge = time.Since(baseline.CapturedAt).Seconds()

		// Ready is one gate over the whole baseline, so it cannot say which
		// signals actually have a distribution behind them. Publish the sample
		// counts: a zero is an unavailable signal, not a quiet host.
		if health.Extra == nil {
			health.Extra = make(map[string]uint64, 5)
		}
		for name, n := range baseline.Coverage() {
			health.Extra["baseline_samples_"+name] = uint64(n)
		}
	}
	return health
}
