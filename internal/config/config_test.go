package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestDefaultsAreValid(t *testing.T) {
	cfg := Default()
	if err := cfg.Validate(); err != nil {
		t.Fatalf("default configuration is invalid: %v", err)
	}
}

func TestLoadWithNoPathReturnsDefaults(t *testing.T) {
	cfg, err := Load("")
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if cfg.Bus.Capacity != Default().Bus.Capacity {
		t.Fatal("expected the default capacity")
	}
}

func writeConfig(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "grima.toml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLoadOverridesDefaults(t *testing.T) {
	path := writeConfig(t, `
[bus]
capacity = 128
drop_policy = "drop_newest"
`)

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if cfg.Bus.Capacity != 128 {
		t.Fatalf("capacity = %d, want 128", cfg.Bus.Capacity)
	}
	if cfg.Bus.DropPolicy != "drop_newest" {
		t.Fatalf("drop_policy = %q", cfg.Bus.DropPolicy)
	}
}

// Sad path: a typo must surface at startup, not silently disable a setting.
func TestLoadRejectsUnknownKeys(t *testing.T) {
	path := writeConfig(t, `
[bus]
capcity = 128
`)

	if _, err := Load(path); err == nil {
		t.Fatal("an unknown key should be rejected")
	}
}

func TestLoadRejectsMalformedTOML(t *testing.T) {
	if _, err := Load(writeConfig(t, "this is not toml ===")); err == nil {
		t.Fatal("malformed TOML should be rejected")
	}
}

func TestLoadRejectsMissingFile(t *testing.T) {
	if _, err := Load(filepath.Join(t.TempDir(), "absent.toml")); err == nil {
		t.Fatal("a missing config file should be an error")
	}
}

func TestValidateRejectsBadValues(t *testing.T) {
	cases := map[string]func(*Config){
		"zero bus capacity": func(c *Config) { c.Bus.Capacity = 0 },
		"unknown drop policy": func(c *Config) {
			c.Bus.DropPolicy = "drop_sideways"
		},
		"zero entropy sample": func(c *Config) { c.FileWatch.EntropySampleBytes = 0 },
		"zero ngram length":   func(c *Config) { c.Window.NGramLength = 0 },
		"zero decay":          func(c *Config) { c.Window.DecayHalfLife = 0 },
		"zero sigma floor":    func(c *Config) { c.Calibration.EntropySigmaFloor = 0 },
		"zero min samples":    func(c *Config) { c.Calibration.MinSamples = 0 },
		"unknown alert level": func(c *Config) { c.Response.AlertMinLevel = "loud" },
		"unknown suspend level": func(c *Config) {
			c.Response.SuspendMinLevel = "loud"
		},
		"relative monitor path": func(c *Config) {
			c.General.MonitorPaths = []string{"relative/dir"}
		},
		"no monitor paths": func(c *Config) { c.General.MonitorPaths = nil },
		"negative weight": func(c *Config) {
			c.Scoring.Weights = []Weight{{Name: "entropy_deviation", Weight: -1}}
		},
		"negative decoy depth": func(c *Config) { c.Decoy.MaxDepth = -1 },
		"planting without a manifest": func(c *Config) {
			// Without a manifest there is no record of what was written, so the
			// decoys could never be removed.
			c.Decoy.ManifestPath = ""
		},
	}

	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			cfg := Default()
			mutate(&cfg)
			if err := cfg.Validate(); err == nil {
				t.Fatal("expected a validation error")
			}
		})
	}
}

// Sad path: suspension below critical would let a heuristic score stop a
// legitimate process, so the combination is rejected outright.
func TestValidateRejectsSuspendBelowCritical(t *testing.T) {
	cfg := Default()
	cfg.Response.EnableSuspend = true
	cfg.Response.SuspendMinLevel = "high"

	if err := cfg.Validate(); err == nil {
		t.Fatal("enabling suspend below critical should be rejected")
	}
}

// Happy path: opting in with the required critical level is accepted, with or
// without an alert cooldown.
func TestValidateAcceptsSuspendAtCritical(t *testing.T) {
	cfg := Default()
	cfg.Response.EnableSuspend = true

	if err := cfg.Validate(); err != nil {
		t.Fatalf("enable_suspend with the default critical level: %v", err)
	}
	cfg.Response.AlertCooldown = Duration(30 * time.Second)
	if err := cfg.Validate(); err != nil {
		t.Fatalf("alert_cooldown alongside suspend: %v", err)
	}
}

// Throttling is off by default so nothing regresses to a quieter alert stream.
func TestAlertCooldownDefaultsOff(t *testing.T) {
	if got := Default().Response.AlertCooldown.Std(); got != 0 {
		t.Fatalf("alert_cooldown = %s, want 0 (off)", got)
	}
}

func TestLoadAlertCooldown(t *testing.T) {
	path := writeConfig(t, `
[response]
alert_cooldown = "45s"
`)

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if got := cfg.Response.AlertCooldown.Std(); got != 45*time.Second {
		t.Fatalf("alert_cooldown = %s, want 45s", got)
	}
}

// Sad path: a negative cooldown would re-arm every alert, which reads like
// throttling is on while it does nothing.
func TestValidateRejectsNegativeAlertCooldown(t *testing.T) {
	cfg := Default()
	cfg.Response.AlertCooldown = Duration(-time.Second)

	if err := cfg.Validate(); err == nil {
		t.Fatal("a negative alert_cooldown should be rejected")
	}
}

func TestDurationUnmarshalRejectsGarbage(t *testing.T) {
	var d Duration
	if err := d.UnmarshalText([]byte("soon")); err == nil {
		t.Fatal("a non-duration string should be rejected")
	}
	if err := d.UnmarshalText([]byte("90s")); err != nil {
		t.Fatalf("valid duration rejected: %v", err)
	}
	if d.Std().Seconds() != 90 {
		t.Fatalf("duration = %v, want 90s", d.Std())
	}
}

func TestWeightFor(t *testing.T) {
	cfg := Default()

	if got := cfg.WeightFor("entropy_deviation"); got != 1.0 {
		t.Fatalf("weight = %v, want 1.0", got)
	}
	if got := cfg.WeightFor("no_such_signal"); got != 0 {
		t.Fatalf("weight = %v, want 0 for an unknown signal", got)
	}
}

// The default makes no per-process attribution claim.
//
// It was `correlate` until Sprint 2 measured that mode at 0% accuracy and found
// it actively harmful: filing cumulative evidence against a guessed process
// fragments a slow drip across unrelated ones, so the cumulative track — the
// design's answer to drip encryption — never accumulated and a 1-file-per-5s
// drip reached no alert at all. `host` files every event against the host
// fingerprint instead, which is what unelevated detection can honestly claim.
func TestAttributionDefaultsToHost(t *testing.T) {
	cfg := Default()
	if cfg.Attribution.Mode != AttributionHost {
		t.Fatalf("mode = %q, want %q: per-process attribution requires a causal mechanism",
			cfg.Attribution.Mode, AttributionHost)
	}
	if cfg.Attribution.MaxDelay.Std() <= 0 {
		t.Fatalf("max_delay = %s, want a positive wait", cfg.Attribution.MaxDelay.Std())
	}
}

func TestAttributionModes(t *testing.T) {
	cases := []struct {
		name    string
		mode    string
		wantErr bool
	}{
		{"default", AttributionHost, false},
		{"host", AttributionHost, false},
		{"correlate", AttributionCorrelate, false},
		{"audit", AttributionAudit, false},
		{"empty means host", "", false},
		{"etw is named but not implemented", AttributionETW, true},
		{"typo", "correlte", true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := Default()
			cfg.Attribution.Mode = tc.mode
			err := cfg.Validate()
			if tc.wantErr && err == nil {
				t.Fatalf("mode %q was accepted", tc.mode)
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("mode %q was rejected: %v", tc.mode, err)
			}
		})
	}
}

// Sad path: a delay of zero would hold a file event forever, or not at all.
func TestAttributionMaxDelayMustBePositive(t *testing.T) {
	cfg := Default()
	cfg.Attribution.MaxDelay = 0
	if err := cfg.Validate(); err == nil {
		t.Fatal("want an error for a non-positive max_delay")
	}
}

func TestLoadAttributionSection(t *testing.T) {
	// A genuinely absolute path for the platform under test: "C:\data" is not
	// absolute on Linux, where a backslash is not a separator, so a hardcoded
	// Windows path makes this test fail on the Linux runner for a reason that
	// has nothing to do with the attribution section it is meant to cover.
	monitor := filepath.ToSlash(t.TempDir())

	path := writeConfig(t, `
[general]
monitor_paths = ["`+monitor+`"]

[attribution]
mode = "audit"
max_delay = "150ms"
audit_setup = false
`)

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if cfg.Attribution.Mode != AttributionAudit {
		t.Fatalf("mode = %q", cfg.Attribution.Mode)
	}
	if cfg.Attribution.MaxDelay.Std() != 150*time.Millisecond {
		t.Fatalf("max_delay = %s", cfg.Attribution.MaxDelay.Std())
	}
	if cfg.Attribution.AuditSetup {
		t.Fatal("audit_setup = true, want the configured false")
	}
}
