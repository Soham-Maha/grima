package app

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/prateekpurohit13/grima/internal/bus"
	"github.com/prateekpurohit13/grima/internal/config"
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

	snapshot := healthSnapshot(time.Now(), events, sources, fingerprint.NewEngine(config.Default()), nil)
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

	health := healthSnapshot(time.Now(), events, nil, engine, nil)
	if health.BusDropped != dropped {
		t.Errorf("health bus_dropped = %d, want %d", health.BusDropped, dropped)
	}
}
