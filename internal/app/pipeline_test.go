package app

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/prateekpurohit13/grima/internal/bus"
	"github.com/prateekpurohit13/grima/internal/calibrate"
	"github.com/prateekpurohit13/grima/internal/config"
	"github.com/prateekpurohit13/grima/internal/decoy"
	"github.com/prateekpurohit13/grima/internal/event"
	"github.com/prateekpurohit13/grima/internal/fingerprint"
	"github.com/prateekpurohit13/grima/internal/platform"
	"github.com/prateekpurohit13/grima/internal/response"
	"github.com/prateekpurohit13/grima/internal/score"
	"github.com/prateekpurohit13/grima/internal/sensor"
	"github.com/prateekpurohit13/grima/internal/web"
)

// countingSource is a sensor that exposes health counters.
type countingSource struct {
	name     string
	events   uint64
	errors   uint64
	dropped  uint64
	startErr error
}

func (s *countingSource) Name() string { return s.name }

func (s *countingSource) Start(ctx context.Context, out chan<- event.Event) error {
	return s.startErr
}

func (s *countingSource) Close() error { return nil }

func (s *countingSource) Stats() sensor.Stats {
	return sensor.Stats{Name: s.name, Events: s.events, Errors: s.errors, Dropped: s.dropped}
}

// quietSource is a sensor that only implements Source, so it has no counters.
type quietSource struct{ name string }

func (s *quietSource) Name() string                                            { return s.name }
func (s *quietSource) Start(ctx context.Context, out chan<- event.Event) error { return nil }
func (s *quietSource) Close() error                                            { return nil }

// healthPayload is the /healthz JSON as a consumer parses it.
type healthPayload struct {
	CalibrationReady bool    `json:"calibration_ready"`
	BusPublished     uint64  `json:"bus_published"`
	BusDropped       uint64  `json:"bus_dropped"`
	LiveProcesses    int     `json:"live_processes"`
	UptimeSeconds    float64 `json:"uptime_seconds"`
	Sensors          map[string]struct {
		Name      string            `json:"Name"`
		Events    uint64            `json:"Events"`
		Errors    uint64            `json:"Errors"`
		Dropped   uint64            `json:"Dropped"`
		Extra     map[string]uint64 `json:"Extra"`
		Reporting bool              `json:"Reporting"`
	} `json:"sensors"`
}

func parseHealth(t *testing.T, events *bus.Bus, sources []sensor.Source) healthPayload {
	t.Helper()

	// The liveness count is published by the engine loop, which these tests do
	// not run; they exercise the health encoding, so it is zero here.
	snapshot := healthSnapshot(time.Now(), events, sources, 0, nil)
	raw, err := json.Marshal(snapshot)
	if err != nil {
		t.Fatalf("marshal health: %v", err)
	}

	var payload healthPayload
	if err := json.Unmarshal(raw, &payload); err != nil {
		t.Fatalf("unmarshal health: %v\n%s", err, raw)
	}
	return payload
}

func testBus(t *testing.T) *bus.Bus {
	t.Helper()
	events := bus.New(64, bus.DropOldest)
	t.Cleanup(events.Close)
	return events
}

func TestHealthShowsCountersFromReportingSource(t *testing.T) {
	src := &countingSource{name: "procwatch", events: 42, errors: 2, dropped: 3}

	payload := parseHealth(t, testBus(t), []sensor.Source{src})

	seen, ok := payload.Sensors["procwatch"]
	if !ok {
		t.Fatalf("sensor missing from health output: %v", payload.Sensors)
	}
	if !seen.Reporting {
		t.Error("a source that exposes counters must be marked as reporting")
	}
	if seen.Events != src.events || seen.Errors != src.errors || seen.Dropped != src.dropped {
		t.Errorf("counters = events %d errors %d dropped %d, want %d/%d/%d",
			seen.Events, seen.Errors, seen.Dropped, src.events, src.errors, src.dropped)
	}
}

func TestHealthMarksSourceWithoutCounters(t *testing.T) {
	src := &quietSource{name: "no-counters"}

	payload := parseHealth(t, testBus(t), []sensor.Source{src})

	seen, ok := payload.Sensors["no-counters"]
	if !ok {
		t.Fatalf("sensor missing from health output: %v", payload.Sensors)
	}
	if seen.Reporting {
		t.Error("a source with no counters must not be marked as reporting")
	}
}

func TestHealthShowsReportingAndSilentSourcesTogether(t *testing.T) {
	reporting := &countingSource{name: "procwatch", events: 17}
	silent := &quietSource{name: "no-counters"}

	payload := parseHealth(t, testBus(t), []sensor.Source{reporting, silent})

	if len(payload.Sensors) != 2 {
		t.Fatalf("sensors = %v, want one entry per started source", payload.Sensors)
	}
	if got := payload.Sensors["procwatch"]; !got.Reporting || got.Events != 17 {
		t.Errorf("procwatch = %+v, want reporting with 17 events", got)
	}
	if got := payload.Sensors["no-counters"]; got.Reporting {
		t.Errorf("no-counters = %+v, want reporting false", got)
	}
}

// A sensor that failed to start must be absent from health, not present with a
// row of zeros that reads like a healthy idle sensor.
func TestSensorThatFailedToStartIsAbsentFromHealth(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	good := &countingSource{name: "procwatch", events: 5}
	broken := &countingSource{name: "filewatch", startErr: errors.New("no permission")}
	events := testBus(t)
	host := platform.Set{OS: "test", Sources: []sensor.Source{good, broken}}

	started, err := startSensors(ctx, config.Default(), host, events, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatalf("startSensors: %v", err)
	}
	if len(started) != 1 || started[0].Name() != "procwatch" {
		t.Fatalf("started = %v, want only procwatch", started)
	}

	payload := parseHealth(t, events, started)
	if _, ok := payload.Sensors["filewatch"]; ok {
		t.Errorf("failed sensor appears in health output: %v", payload.Sensors)
	}
	if got, ok := payload.Sensors["procwatch"]; !ok || !got.Reporting {
		t.Errorf("procwatch = %+v (present %v), want a reporting entry", got, ok)
	}
}

// Running with no sensors at all must fail loudly rather than report health
// while blind.
func TestAllSensorsFailingIsAnError(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	host := platform.Set{OS: "test", Sources: []sensor.Source{
		&countingSource{name: "filewatch", startErr: errors.New("no permission")},
	}}

	if _, err := startSensors(ctx, config.Default(), host, testBus(t), slog.New(slog.DiscardHandler)); err == nil {
		t.Fatal("startSensors succeeded with no usable sensor")
	}
}

// The score loop publishes on every tick, so the response handler is what
// collapses a persistent condition into one alert per incident when the
// cooldown is configured. This drives the real app-to-response call path.
func TestPublishThrottlesAlertsPerIncident(t *testing.T) {
	cases := []struct {
		name     string
		cooldown time.Duration
		want     int
	}{
		{"cooldown off alerts every tick", 0, 5},
		{"cooldown on alerts once", 30 * time.Second, 1},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := config.Default()
			cfg.Response.AlertCooldown = config.Duration(tc.cooldown)

			var buf bytes.Buffer
			log := slog.New(slog.NewTextHandler(&buf, nil))
			hub := web.NewHub(func() web.Health { return web.Health{} })
			loop := scoreLoop{
				responder: response.NewHandler(cfg, log),
				hub:       hub,
				log:       log,
			}

			v := score.Verdict{
				PID:      4242,
				ProcName: "encryptor",
				Score:    95,
				Level:    score.LevelCritical,
				Signals:  []score.Signal{{Name: "R-DECOY-TOUCH", Class: score.ClassOverride, Level: score.LevelCritical}},
			}
			for range 5 {
				loop.publish(v)
			}

			if got := strings.Count(buf.String(), "ransomware risk detected"); got != tc.want {
				t.Fatalf("alerts = %d, want %d\n%s", got, tc.want, buf.String())
			}
		})
	}
}

// A write storm that outruns the bus must be visible where an operator looks:
// the drop counter in health, and the verdict the lost events would have shaped.
// This drives a real bus, a real engine and the real score loop.
func TestWriteStormSurfacesDropsInHealthAndVerdicts(t *testing.T) {
	cfg := config.Default()
	cfg.Bus.Capacity = 8
	cfg.Scoring.AbsoluteWriteRate = 1
	log := slog.New(slog.DiscardHandler)

	events := bus.New(cfg.Bus.Capacity, bus.DropOldest)
	defer events.Close()

	// Nothing consumes this bus, so it fills and the rest is dropped.
	for range 500 {
		events.Publish(event.Event{Kind: event.KindFileWrite, Path: "/data/a.txt", Time: time.Now()})
	}
	dropped := events.Stats().Dropped
	if dropped == 0 {
		t.Fatal("the storm dropped nothing; the test measured nothing")
	}

	engine := fingerprint.NewEngine(cfg)
	for range 50 {
		engine.Apply(event.Event{
			Kind: event.KindFileWrite, Path: "/data/a.txt", Time: time.Now(),
			PID: 4242, ProcName: "cryptor",
		})
	}

	hub := web.NewHub(func() web.Health { return web.Health{} })
	loop := scoreLoop{
		cfg:       cfg,
		events:    events,
		engine:    engine,
		scorer:    score.NewScorer(cfg),
		overrides: newOverrideTracker(cfg.Window.DecayHalfLife.Std()),
		responder: response.NewHandler(cfg, log),
		hub:       hub,
		log:       log,
	}
	loop.evaluate()

	var found bool
	for _, v := range hub.Latest() {
		for _, sg := range v.Signals {
			if sg.Name == "bus_drops" {
				found = true
				if !strings.Contains(sg.Detail, strconv.FormatUint(dropped, 10)) {
					t.Errorf("bus_drops detail = %q, want the count %d", sg.Detail, dropped)
				}
			}
		}
	}
	if !found {
		t.Fatalf("no verdict carried the drop count (%d dropped); verdicts: %v", dropped, hub.Latest())
	}

	health := healthSnapshot(time.Now(), events, nil, engine.Live(), nil)
	if health.BusDropped != dropped {
		t.Errorf("health bus_dropped = %d, want %d", health.BusDropped, dropped)
	}
}

// newTestEngineLoop builds the real loop over a real bus and hub, ticking fast
// enough to observe without a second of wall clock.
func newTestEngineLoop(t *testing.T, cfg config.Config, events *bus.Bus, hub *web.Hub, live *atomic.Int64) engineLoop {
	t.Helper()

	return engineLoop{
		scoreLoop: scoreLoop{
			cfg:       cfg,
			events:    events,
			engine:    fingerprint.NewEngine(cfg),
			scorer:    score.NewScorer(cfg),
			overrides: newOverrideTracker(cfg.Window.DecayHalfLife.Std()),
			responder: response.NewHandler(cfg, slog.New(slog.DiscardHandler)),
			hub:       hub,
			log:       slog.New(slog.DiscardHandler),
		},
		in:       events.Subscribe("fingerprint", cfg.Bus.Capacity/2),
		live:     live,
		interval: time.Millisecond,
	}
}

// The engine is owned by one goroutine, and the scoring pass runs there too, so
// an event written by the ingest path is read by the scorer without a lock.
// Health is asked for the same state from another goroutine, and it must get a
// published value rather than reaching into the engine: if it ever reads window
// state directly again, this test fails under -race.
func TestEngineLoopScoresWhileHealthIsReadConcurrently(t *testing.T) {
	cfg := config.Default()
	cfg.Scoring.AbsoluteWriteRate = 1

	events := bus.New(cfg.Bus.Capacity, bus.DropOldest)
	defer events.Close()

	var live atomic.Int64
	// health is exactly the callback the hub hands to the /healthz handler, so
	// calling it from another goroutine is the read path an operator triggers.
	health := func() web.Health {
		return healthSnapshot(time.Now(), events, nil, int(live.Load()), nil)
	}
	hub := web.NewHub(health)
	loop := newTestEngineLoop(t, cfg, events, hub, &live)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan struct{})
	go func() {
		defer close(done)
		loop.run(ctx)
	}()

	// A sensor's worth of events, published while the loop is draining them.
	go func() {
		for range 400 {
			events.Publish(event.Event{
				Kind: event.KindFileWrite, Path: "/data/secret.docx", Time: time.Now(),
				PID: 4242, ProcName: "encryptor", Bytes: 4096,
			})
		}
	}()

	// An HTTP handler's worth of health reads, concurrent with the loop.
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if health().LiveProcesses > 0 && len(hub.Latest()) > 0 {
			return // the loop published both a liveness count and a verdict
		}
		time.Sleep(time.Millisecond)
	}

	t.Fatalf("loop published no verdict or liveness count: live=%d verdicts=%d",
		health().LiveProcesses, len(hub.Latest()))
}

// A loop stops on cancellation and on a closed input channel, so shutting the
// detector down cannot leave it ticking against a dead bus.
func TestEngineLoopStopsOnCancelAndOnClosedInput(t *testing.T) {
	cases := []struct {
		name  string
		stop  func(cancel context.CancelFunc, in chan event.Event)
		check func(t *testing.T)
	}{
		{
			name: "cancelled context",
			stop: func(cancel context.CancelFunc, in chan event.Event) { cancel() },
		},
		{
			name: "closed input channel",
			stop: func(cancel context.CancelFunc, in chan event.Event) { close(in) },
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := config.Default()
			events := bus.New(cfg.Bus.Capacity, bus.DropOldest)
			defer events.Close()

			var live atomic.Int64
			hub := web.NewHub(func() web.Health { return web.Health{} })
			loop := newTestEngineLoop(t, cfg, events, hub, &live)

			in := make(chan event.Event, 1)
			loop.in = in

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			done := make(chan struct{})
			go func() {
				defer close(done)
				loop.run(ctx)
			}()

			tc.stop(cancel, in)

			select {
			case <-done:
			case <-time.After(5 * time.Second):
				t.Fatal("loop did not stop")
			}
		})
	}
}

// "Calibrated" is one gate over the whole baseline, so on its own it can read as
// full coverage when a deviation signal has no distribution behind it. Health
// publishes the sample count per distribution, and a zero there means the signal
// is unavailable rather than that the host is quiet.
func TestHealthPublishesBaselineSampleCounts(t *testing.T) {
	baseline := &calibrate.Baseline{
		CapturedAt:   time.Now(),
		MinSamples:   1,
		EntropyByExt: map[string]calibrate.Dist{".txt": {Mean: 5, StdDev: 1, N: 40}},
		WriteRate:    calibrate.Dist{Mean: 3, StdDev: 1, N: 9},
		RenameRate:   calibrate.Dist{Mean: 0, StdDev: 0, N: 7},
	}

	health := healthSnapshot(time.Now(), testBus(t), nil, 0, baseline)

	if !health.CalibrationReady {
		t.Fatal("baseline with enough entropy samples should be ready")
	}
	for name, want := range map[string]uint64{
		"baseline_samples_entropy":     40,
		"baseline_samples_write_rate":  9,
		"baseline_samples_rename_rate": 7,
		"baseline_samples_dir_fanout":  0,
	} {
		if got := health.Extra[name]; got != want {
			t.Errorf("health %s = %d, want %d", name, got, want)
		}
	}
}

// Decoys are written into the user's own directories, so the run has to have an
// undo that works from the manifest alone — after a restart, with nothing in
// memory. This drives the real planting and the real removal.
func TestRemoveDecoysUndoesAPreviousRun(t *testing.T) {
	dir := t.TempDir()
	cfg := config.Default()
	cfg.General.MonitorPaths = []string{dir}
	cfg.Decoy.Enabled = true
	cfg.Decoy.ManifestPath = filepath.Join(t.TempDir(), "grima-decoys.json")

	reg := decoy.NewRegistry()
	planted, err := decoy.Plant(cfg, reg)
	if err != nil {
		t.Fatalf("Plant: %v", err)
	}
	if planted == 0 {
		t.Fatal("nothing was planted; the test would measure nothing")
	}

	if err := runRemoveDecoys(cfg, slog.New(slog.DiscardHandler)); err != nil {
		t.Fatalf("runRemoveDecoys: %v", err)
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read %s: %v", dir, err)
	}
	if len(entries) != 0 {
		t.Fatalf("%d files survived removal", len(entries))
	}
	if _, err := os.Stat(cfg.Decoy.ManifestPath); !os.IsNotExist(err) {
		t.Fatalf("manifest survived removal: %v", err)
	}
}

func anyVerdictHasSignal(verdicts []score.Verdict, name string) bool {
	for _, v := range verdicts {
		for _, sg := range v.Signals {
			if sg.Name == name {
				return true
			}
		}
	}
	return false
}

// The drop signal describes the window being scored, not the run. A lifetime
// counter kept marking every verdict long after the overload had passed — and
// because a verdict carrying any signal is published, it also filled the bounded
// history ring with info-level noise and buried real findings.
func TestBusDropsSignalCoversOnlyTheWindowThatDropped(t *testing.T) {
	cfg := config.Default()
	cfg.Bus.Capacity = 8
	cfg.Scoring.AbsoluteWriteRate = 1
	log := slog.New(slog.DiscardHandler)

	events := bus.New(cfg.Bus.Capacity, bus.DropOldest)
	defer events.Close()

	// Nothing consumes this bus, so it fills and the rest is dropped.
	for range 500 {
		events.Publish(event.Event{Kind: event.KindFileWrite, Path: "/data/a.txt", Time: time.Now()})
	}
	if events.Stats().Dropped == 0 {
		t.Fatal("the storm dropped nothing; the test measured nothing")
	}

	engine := fingerprint.NewEngine(cfg)
	for range 200 {
		engine.Apply(event.Event{
			Kind: event.KindFileWrite, Path: "/data/a.txt", Time: time.Now(),
			PID: 4242, ProcName: "cryptor",
		})
	}

	hub := web.NewHub(func() web.Health { return web.Health{} })
	loop := &scoreLoop{
		cfg:       cfg,
		events:    events,
		engine:    engine,
		scorer:    score.NewScorer(cfg),
		overrides: newOverrideTracker(cfg.Window.DecayHalfLife.Std()),
		responder: response.NewHandler(cfg, log),
		hub:       hub,
		log:       log,
	}

	loop.evaluate()
	if !anyVerdictHasSignal(hub.Latest(), "bus_drops") {
		t.Fatalf("the window that dropped events carried no bus_drops: %v", hub.Latest())
	}

	// The next window drops nothing, so nothing should still be reporting drops.
	loop.evaluate()
	if anyVerdictHasSignal(hub.Latest(), "bus_drops") {
		t.Fatalf("bus_drops survived into a window that dropped nothing: %v", hub.Latest())
	}
}
