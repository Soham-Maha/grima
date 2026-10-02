// Package app wires the sensors, bus, fingerprint engine, scorer, rules, and
// dashboard together and runs the detection loop.
package app

import (
	"context"
	"fmt"
	"log/slog"
	"sync/atomic"
	"time"

	"github.com/prateekpurohit13/grima/internal/bus"
	"github.com/prateekpurohit13/grima/internal/calibrate"
	"github.com/prateekpurohit13/grima/internal/config"
	"github.com/prateekpurohit13/grima/internal/decoy"
	"github.com/prateekpurohit13/grima/internal/event"
	"github.com/prateekpurohit13/grima/internal/fingerprint"
	"github.com/prateekpurohit13/grima/internal/platform"
	"github.com/prateekpurohit13/grima/internal/response"
	"github.com/prateekpurohit13/grima/internal/rules"
	"github.com/prateekpurohit13/grima/internal/score"
	"github.com/prateekpurohit13/grima/internal/sensor"
	"github.com/prateekpurohit13/grima/internal/web"
)

// Options are the runtime knobs that come from the command line.
type Options struct {
	Duration     time.Duration
	Calibrate    bool
	Recalibrate  bool
	RemoveDecoys bool
}

const sensorBuffer = 4096

// Run starts the detector and blocks until ctx is cancelled.
func Run(ctx context.Context, cfg config.Config, opts Options, log *slog.Logger) error {
	if opts.Duration > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, opts.Duration)
		defer cancel()
	}

	// Removing decoys is a maintenance action, not a run: it touches the files
	// this tool wrote and nothing else, so it happens before any sensor or bus
	// exists.
	if opts.RemoveDecoys {
		return runRemoveDecoys(cfg, log)
	}

	policy, _ := bus.ParseDropPolicy(cfg.Bus.DropPolicy)
	events := bus.New(cfg.Bus.Capacity, policy)
	defer events.Close()

	host := platform.Detect(cfg, log)
	log.Info("platform detected", "os", host.OS)

	defer func() {
		if err := host.Attrib.Close(); err != nil {
			log.Warn("closing attribution trace", "error", err)
		}
	}()

	if cfg.Decoy.Enabled {
		planted, err := decoy.Plant(cfg, host.Decoys)
		if err != nil {
			log.Warn("decoy planting partially failed", "error", err)
		}
		log.Info("decoys planted",
			"count", planted,
			"manifest", cfg.Decoy.ManifestPath,
			"max_depth", cfg.Decoy.MaxDepth,
		)
	}

	sources, err := startSensors(ctx, cfg, host, events, log)
	if err != nil {
		return err
	}
	defer closeSensors(sources)

	if opts.Calibrate {
		return runCalibration(ctx, cfg, events, log)
	}
	if opts.Recalibrate {
		return runRecalibration(ctx, cfg, events, log)
	}

	baseline, err := calibrate.Load(cfg.Calibration.BaselinePath)
	if err != nil {
		log.Warn("baseline unreadable, running uncalibrated", "error", err)
	}
	if baseline == nil || !baseline.Ready() {
		log.Warn("no usable baseline: deviation signals are inactive until one is captured",
			"path", cfg.Calibration.BaselinePath)
	}

	engine := fingerprint.NewEngine(cfg)
	scorer := score.NewScorer(cfg)
	ruleEngine := rules.NewEngine(cfg)
	responder := response.NewHandler(cfg, log)
	overrides := newOverrideTracker(cfg.Window.DecayHalfLife.Std())

	startedAt := time.Now()

	// The engine is owned by the loop below, so anything outside it reads this
	// published count rather than the engine itself. Staleness is bounded by the
	// scoring interval.
	var live atomic.Int64
	hub := web.NewHub(func() web.Health {
		return healthSnapshot(startedAt, events, sources, int(live.Load()), baseline)
	})

	startRuleLoop(ctx, ruleEngine, overrides, events.Subscribe("rules", cfg.Bus.Capacity))

	if cfg.Web.Enabled {
		server, err := web.NewServer(cfg, hub, log)
		if err != nil {
			return err
		}
		go func() {
			if err := server.Start(ctx); err != nil {
				log.Warn("dashboard stopped", "error", err)
			}
		}()
	}

	loop := engineLoop{
		scoreLoop: scoreLoop{
			cfg:       cfg,
			events:    events,
			engine:    engine,
			scorer:    scorer,
			overrides: overrides,
			responder: responder,
			hub:       hub,
			baseline:  baseline,
			log:       log,
		},
		in:   events.Subscribe("fingerprint", cfg.Bus.Capacity/2),
		live: &live,
	}
	// Seed the published count on this goroutine: the loop has not started, so
	// there is no writer to race with yet.
	live.Store(int64(engine.Live()))
	loop.run(ctx)

	log.Info("grima stopped",
		"published", events.Stats().Published,
		"dropped", events.Stats().Dropped,
	)
	return nil
}

func startSensors(ctx context.Context, cfg config.Config, host platform.Set, events *bus.Bus, log *slog.Logger) ([]sensor.Source, error) {
	var started []sensor.Source

	for _, src := range host.Sources {
		out := make(chan event.Event, sensorBuffer)
		if err := src.Start(ctx, out); err != nil {
			log.Warn("sensor unavailable", "source", src.Name(), "error", err)
			continue
		}
		started = append(started, src)
		go pumpToBus(ctx, out, events)
	}

	// Running with no sensors would look healthy while being blind.
	if len(started) == 0 {
		return nil, fmt.Errorf("no sensor could start on %s", host.OS)
	}
	return started, nil
}

func closeSensors(sources []sensor.Source) {
	for _, src := range sources {
		_ = src.Close()
	}
}

func pumpToBus(ctx context.Context, out <-chan event.Event, events *bus.Bus) {
	for {
		select {
		case <-ctx.Done():
			return
		case ev, ok := <-out:
			if !ok {
				return
			}
			events.Publish(ev)
		}
	}
}

// runRemoveDecoys deletes the canary files a previous run planted, using the
// manifest that run wrote. It is the undo for a tool that writes into the user's
// directories.
func runRemoveDecoys(cfg config.Config, log *slog.Logger) error {
	removed, skipped, err := decoy.Remove(cfg.Decoy.ManifestPath)
	if err != nil {
		return fmt.Errorf("remove decoys: %w", err)
	}

	log.Info("decoys removed", "removed", removed, "manifest", cfg.Decoy.ManifestPath)
	if skipped > 0 {
		// A skipped path held something that is not the canary body any more.
		// Deleting it would delete the user's file, so it is left and reported.
		log.Warn("some recorded decoys were left in place: their contents are no longer the canary body",
			"skipped", skipped)
	}
	return nil
}

func runCalibration(ctx context.Context, cfg config.Config, events *bus.Bus, log *slog.Logger) error {
	log.Info("capturing host baseline", "warmup", cfg.Calibration.Warmup.Std().String())

	baseline, err := calibrate.Capture(ctx, cfg, events)
	if err != nil {
		return fmt.Errorf("capture baseline: %w", err)
	}
	if err := baseline.Save(cfg.Calibration.BaselinePath); err != nil {
		return fmt.Errorf("save baseline: %w", err)
	}

	log.Info("baseline written",
		"path", cfg.Calibration.BaselinePath,
		"extensions", len(baseline.EntropyByExt),
		"processes", len(baseline.WriteRateByProc),
	)
	return nil
}

// runRecalibration folds a fresh observation window into the existing baseline,
// so a workload the operator has confirmed as benign stops alerting.
func runRecalibration(ctx context.Context, cfg config.Config, events *bus.Bus, log *slog.Logger) error {
	existing, err := calibrate.Load(cfg.Calibration.BaselinePath)
	if err != nil {
		return fmt.Errorf("load baseline: %w", err)
	}
	if existing == nil {
		return fmt.Errorf("no usable baseline at %s; run --calibrate first", cfg.Calibration.BaselinePath)
	}

	log.Info("recalibrating host baseline", "warmup", cfg.Calibration.Warmup.Std().String())

	// Recalibrate merges into the stored baseline and persists it; saving again
	// here would write the same bytes twice.
	merged, err := calibrate.Recalibrate(ctx, cfg, events, existing)
	if err != nil {
		return fmt.Errorf("recalibrate: %w", err)
	}

	log.Info("baseline recalibrated",
		"path", cfg.Calibration.BaselinePath,
		"extensions", len(merged.EntropyByExt),
		"processes", len(merged.WriteRateByProc),
	)
	return nil
}
