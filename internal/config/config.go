// Package config loads and validates GRIMA's TOML configuration.
//
// Every setting has a default, so the binary runs with no configuration file at
// all, in observe-only mode.
package config

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"github.com/BurntSushi/toml"
)

// Duration is a time.Duration that unmarshals from a TOML string such as "30s".
type Duration time.Duration

// UnmarshalText implements encoding.TextUnmarshaler.
func (d *Duration) UnmarshalText(text []byte) error {
	v, err := time.ParseDuration(string(text))
	if err != nil {
		return fmt.Errorf("invalid duration %q: %w", string(text), err)
	}
	*d = Duration(v)
	return nil
}

// Std returns the value as a time.Duration.
func (d Duration) Std() time.Duration { return time.Duration(d) }

// General holds top-level settings.
type General struct {
	MonitorPaths []string `toml:"monitor_paths"`
	LogLevel     string   `toml:"log_level"`
}

// BusConfig holds event-bus settings.
type BusConfig struct {
	Capacity   int    `toml:"capacity"`
	DropPolicy string `toml:"drop_policy"`
}

// FileWatchConfig holds filesystem sensor settings.
type FileWatchConfig struct {
	EntropySampleBytes int      `toml:"entropy_sample_bytes"`
	RescanOnOverflow   bool     `toml:"rescan_on_overflow"`
	SampleInterval     Duration `toml:"sample_interval"`
	// StartupDeadline bounds how long Start spends registering watches on the
	// initial tree. Directories not reached in time are handed to the background
	// worker, so a large tree under load cannot delay the whole detector. Zero
	// means unbounded: register everything before returning.
	StartupDeadline Duration `toml:"startup_deadline"`
}

// ProcWatchConfig holds process sensor settings.
type ProcWatchConfig struct {
	SampleInterval Duration `toml:"sample_interval"`
}

// AttributionConfig holds settings for matching a file event to the process
// that caused it.
type AttributionConfig struct {
	Mode string `toml:"mode"`
	// MaxDelay bounds how long a file event waits for a causal record before it
	// is attributed by correlation instead.
	MaxDelay Duration `toml:"max_delay"`
	// AuditSetup lets GRIMA enable the File System audit subcategory and set the
	// audit ACE on every monitored directory. It needs an elevated process.
	AuditSetup bool `toml:"audit_setup"`
}

// Attribution modes.
const (
	// AttributionHost files every event against the host fingerprint. It claims
	// no per-process attribution, which is the honest default: correlation was
	// measured at 0% accuracy, and filing cumulative evidence against a guess
	// fragments it across unrelated processes — which is how a 1-file-per-5s
	// drip reached no alert at all.
	AttributionHost = "host"
	// AttributionCorrelate blames the largest recent writer. No privileges. Kept
	// because it is the measured baseline the causal path is compared against,
	// not because it is fit to deploy.
	AttributionCorrelate = "correlate"
	// AttributionAudit takes the writer from Windows file-system auditing.
	AttributionAudit = "audit"
	// AttributionETW is named by the sprint plan but not implemented yet.
	AttributionETW = "etw"
)

// DecoyConfig holds canary-file settings.
type DecoyConfig struct {
	Enabled     bool     `toml:"enabled"`
	Names       []string `toml:"names"`
	CountPerDir int      `toml:"count_per_dir"`
}

// WindowConfig holds fingerprint window settings.
type WindowConfig struct {
	DecayHalfLife Duration `toml:"decay_half_life"`
	NGramLength   int      `toml:"ngram_length"`
}

// CalibrationConfig holds host-baseline settings.
type CalibrationConfig struct {
	Warmup            Duration `toml:"warmup"`
	MinSamples        int      `toml:"min_samples"`
	BaselinePath      string   `toml:"baseline_path"`
	EntropySigmaFloor float64  `toml:"entropy_sigma_floor"`
}

// Bands maps risk scores to levels.
type Bands struct {
	Low      float64 `toml:"low"`
	Medium   float64 `toml:"medium"`
	High     float64 `toml:"high"`
	Critical float64 `toml:"critical"`
}

// Weight assigns a fusion weight to one signal by name.
type Weight struct {
	Name   string  `toml:"name"`
	Weight float64 `toml:"weight"`
}

// ScoringConfig holds fusion settings.
type ScoringConfig struct {
	LevelBands Bands `toml:"level_bands"`
	// AbsoluteWriteRate is the writes-per-second threshold used when no host
	// baseline exists. It is replaced by the calibrated write_burst signal as
	// soon as a baseline is available.
	AbsoluteWriteRate float64 `toml:"absolute_write_rate"`
	// ZeroBaselineBurst is the smallest number of events in a window that
	// counts as a burst when the host's measured rate for that event kind is
	// zero. A zero rate is a measurement, not an absence of one: it says the
	// host never did this during warm-up, so there is no multiple to express
	// tolerance in. The floor keeps the deviation signal available instead of
	// disabling it, while stopping one ordinary event from saturating it.
	ZeroBaselineBurst float64  `toml:"zero_baseline_burst"`
	Weights           []Weight `toml:"weights"`
}

// RulesConfig holds hard-rule settings. Patterns are matched case-insensitively
// against a process command line.
type RulesConfig struct {
	Enabled          bool     `toml:"enabled"`
	ShadowCommands   []string `toml:"shadow_commands"`
	EventLogCommands []string `toml:"eventlog_commands"`
	USNCommands      []string `toml:"usn_commands"`
	Terminators      []string `toml:"terminators"`
	BackupProcesses  []string `toml:"backup_processes"`
}

// ResponseConfig holds action settings.
type ResponseConfig struct {
	EnableSuspend   bool   `toml:"enable_suspend"`
	SuspendMinLevel string `toml:"suspend_min_level"`
	AlertMinLevel   string `toml:"alert_min_level"`
	// AlertCooldown holds repeat alerts for one process this long. Zero disables
	// throttling, so every scoring tick over the alert band logs an alert.
	AlertCooldown Duration `toml:"alert_cooldown"`
}

// WebConfig holds dashboard settings.
type WebConfig struct {
	Enabled bool   `toml:"enabled"`
	Listen  string `toml:"listen"`
}

// Config is the root configuration.
type Config struct {
	General     General           `toml:"general"`
	Bus         BusConfig         `toml:"bus"`
	FileWatch   FileWatchConfig   `toml:"filewatch"`
	ProcWatch   ProcWatchConfig   `toml:"procwatch"`
	Attribution AttributionConfig `toml:"attribution"`
	Decoy       DecoyConfig       `toml:"decoy"`
	Window      WindowConfig      `toml:"window"`
	Calibration CalibrationConfig `toml:"calibration"`
	Scoring     ScoringConfig     `toml:"scoring"`
	Rules       RulesConfig       `toml:"rules"`
	Response    ResponseConfig    `toml:"response"`
	Web         WebConfig         `toml:"web"`
}

// LevelNames are the risk levels a configuration may name.
var LevelNames = []string{"info", "low", "medium", "high", "critical"}

// DefaultSignalWeights is the starting fusion weight for each signal. Phase 6
// replaces these with values from a grid search over the scenario corpus.
var DefaultSignalWeights = []Weight{
	{Name: "entropy_deviation", Weight: 1.0},
	{Name: "magic_mismatch", Weight: 1.0},
	{Name: "write_burst", Weight: 1.0},
	{Name: "write_rate_absolute", Weight: 1.0},
	{Name: "rename_burst", Weight: 0.8},
	{Name: "ngram_rename_chain", Weight: 0.2},
	{Name: "unknown_extension_activity", Weight: 1.0},
	// Secondary signals corroborate; none may carry a verdict alone. That is
	// enforced structurally in score's fusion — a Secondary contributes only
	// while a Primary signal is present (Sprint 4, item 4.9) — so these weights
	// are corroboration strength rather than the guard, and the guard no longer
	// depends on where the medium band sits. They sit at 0.4 because at 0.5 each
	// solo-scored exactly 50 against a 45 band: measured on a benign atomic-save
	// workload, which alerted at medium on delete_rate alone. Do not read 0.4 as
	// a safety margin — the fusion rule is what makes the tier safe.
	{Name: "delete_rate", Weight: 0.4},
	{Name: "dir_fanout", Weight: 0.4},
	{Name: "cum_bytes_rewritten", Weight: 0.4},
	// static_reputation is a Secondary (design.md §5) that the scorer does not
	// emit yet; Phase 7. Its weight is deliberately not bounded by the medium
	// band because it cannot carry a verdict without a Primary either way.
	{Name: "static_reputation", Weight: 0.6},
	{Name: "bus_drops", Weight: 0.2},
}

// Default returns a configuration that is usable as-is.
func Default() Config {
	home, err := os.UserHomeDir()
	if err != nil {
		home = "."
	}

	return Config{
		General: General{
			MonitorPaths: []string{home},
			LogLevel:     "info",
		},
		Bus: BusConfig{
			Capacity:   8192,
			DropPolicy: "drop_oldest",
		},
		FileWatch: FileWatchConfig{
			EntropySampleBytes: 4096,
			RescanOnOverflow:   true,
			SampleInterval:     Duration(2 * time.Second),
			StartupDeadline:    Duration(10 * time.Second),
		},
		ProcWatch: ProcWatchConfig{
			SampleInterval: Duration(500 * time.Millisecond),
		},
		Attribution: AttributionConfig{
			Mode:       AttributionHost,
			MaxDelay:   Duration(300 * time.Millisecond),
			AuditSetup: true,
		},
		Decoy: DecoyConfig{
			Enabled:     true,
			Names:       []string{"_grima_canary.doc", "quarterly_report_2019.xlsx", "invoices_backup.pdf"},
			CountPerDir: 2,
		},
		Window: WindowConfig{
			DecayHalfLife: Duration(30 * time.Second),
			NGramLength:   32,
		},
		Calibration: CalibrationConfig{
			Warmup:            Duration(10 * time.Minute),
			MinSamples:        200,
			BaselinePath:      "grima-baseline.json",
			EntropySigmaFloor: 0.05,
		},
		Scoring: ScoringConfig{
			LevelBands:        Bands{Low: 20, Medium: 45, High: 70, Critical: 88},
			AbsoluteWriteRate: 20,
			ZeroBaselineBurst: 25,
			Weights:           DefaultSignalWeights,
		},
		Rules: RulesConfig{
			Enabled: true,
			ShadowCommands: []string{
				"vssadmin delete shadows",
				"vssadmin.exe delete shadows",
				"wmic shadowcopy delete",
				"wbadmin delete catalog",
				"wbadmin delete systemstatebackup",
				"bcdedit /set recoveryenabled no",
				"bcdedit /set {default} recoveryenabled no",
			},
			EventLogCommands: []string{"wevtutil cl", "wevtutil.exe cl", "Clear-EventLog"},
			USNCommands:      []string{"fsutil usn deletejournal"},
			Terminators:      []string{"taskkill", "pkill", "killall", "Stop-Process", "net stop"},
			BackupProcesses: []string{
				"sqlservr", "veeam", "backup exec", "beserver",
				"wbengine", "msexchange", "postgres", "mysqld", "mongod",
			},
		},
		Response: ResponseConfig{
			EnableSuspend:   false,
			SuspendMinLevel: "critical",
			AlertMinLevel:   "medium",
			AlertCooldown:   0,
		},
		Web: WebConfig{
			Enabled: true,
			Listen:  "127.0.0.1:8787",
		},
	}
}

// Load reads a TOML file over the defaults. An empty path returns the defaults.
func Load(path string) (Config, error) {
	cfg := Default()
	if path == "" {
		return cfg, cfg.Validate()
	}

	md, err := toml.DecodeFile(path, &cfg)
	if err != nil {
		return Config{}, fmt.Errorf("read config %s: %w", path, err)
	}
	if undecoded := md.Undecoded(); len(undecoded) > 0 {
		return Config{}, fmt.Errorf("config %s has unknown keys: %v", path, undecoded)
	}

	return cfg, cfg.Validate()
}

// Validate reports configuration errors that would otherwise surface as
// confusing runtime behavior.
func (c Config) Validate() error {
	if c.Bus.Capacity <= 0 {
		return fmt.Errorf("bus.capacity must be positive, got %d", c.Bus.Capacity)
	}
	if _, ok := ParseDropPolicyName(c.Bus.DropPolicy); !ok {
		return fmt.Errorf("bus.drop_policy %q is not one of drop_oldest, drop_newest, block", c.Bus.DropPolicy)
	}
	if c.FileWatch.EntropySampleBytes <= 0 {
		return fmt.Errorf("filewatch.entropy_sample_bytes must be positive, got %d", c.FileWatch.EntropySampleBytes)
	}
	if c.FileWatch.StartupDeadline.Std() < 0 {
		return fmt.Errorf("filewatch.startup_deadline must not be negative, got %s", c.FileWatch.StartupDeadline.Std())
	}
	if c.Window.NGramLength <= 0 {
		return fmt.Errorf("window.ngram_length must be positive, got %d", c.Window.NGramLength)
	}
	if c.Window.DecayHalfLife.Std() <= 0 {
		return fmt.Errorf("window.decay_half_life must be positive, got %s", c.Window.DecayHalfLife.Std())
	}
	if c.Calibration.EntropySigmaFloor <= 0 {
		return fmt.Errorf("calibration.entropy_sigma_floor must be positive, got %v", c.Calibration.EntropySigmaFloor)
	}
	if c.Calibration.MinSamples <= 0 {
		return fmt.Errorf("calibration.min_samples must be positive, got %d", c.Calibration.MinSamples)
	}
	if c.Scoring.AbsoluteWriteRate <= 0 {
		return fmt.Errorf("scoring.absolute_write_rate must be positive, got %v", c.Scoring.AbsoluteWriteRate)
	}
	if c.Scoring.ZeroBaselineBurst <= 0 {
		return fmt.Errorf("scoring.zero_baseline_burst must be positive, got %v", c.Scoring.ZeroBaselineBurst)
	}
	if err := c.validateAttribution(); err != nil {
		return err
	}
	if !validLevel(c.Response.AlertMinLevel) {
		return fmt.Errorf("response.alert_min_level %q is not one of %v", c.Response.AlertMinLevel, LevelNames)
	}
	if !validLevel(c.Response.SuspendMinLevel) {
		return fmt.Errorf("response.suspend_min_level %q is not one of %v", c.Response.SuspendMinLevel, LevelNames)
	}
	if c.Response.EnableSuspend && c.Response.SuspendMinLevel != "critical" {
		return fmt.Errorf("response.enable_suspend requires suspend_min_level = \"critical\", got %q", c.Response.SuspendMinLevel)
	}
	if c.Response.AlertCooldown.Std() < 0 {
		return fmt.Errorf("response.alert_cooldown must not be negative, got %s", c.Response.AlertCooldown.Std())
	}
	for _, w := range c.Scoring.Weights {
		if w.Weight < 0 {
			return fmt.Errorf("scoring weight for %q must not be negative, got %v", w.Name, w.Weight)
		}
	}
	if len(c.General.MonitorPaths) == 0 {
		return fmt.Errorf("general.monitor_paths must list at least one directory")
	}
	for _, p := range c.General.MonitorPaths {
		if !filepath.IsAbs(p) {
			// The shipped example uses POSIX paths, and on Windows those are not
			// absolute — `/home` resolves against the current drive. Say what the
			// platform wants rather than leaving the operator to work it out.
			hint := `e.g. "/home/you" or "/srv/data"`
			if runtime.GOOS == "windows" {
				hint = `on Windows that means a drive letter, e.g. "C:/Users/you/Documents"`
			}
			return fmt.Errorf("general.monitor_paths entry %q must be an absolute path (%s)", p, hint)
		}
	}
	return nil
}

// validateAttribution rejects an attribution mode GRIMA cannot run, so a typo
// fails at startup instead of silently correlating.
func (c Config) validateAttribution() error {
	mode := c.Attribution.Mode
	if mode == "" {
		mode = AttributionHost
	}
	switch mode {
	case AttributionHost, AttributionCorrelate, AttributionAudit:
	case AttributionETW:
		return fmt.Errorf("attribution.mode %q is not implemented: kernel file events carry a thread id and no path, so ETW needs both a thread-to-process map and a file-object-to-name map; use %q", mode, AttributionAudit)
	default:
		return fmt.Errorf("attribution.mode %q is not one of %s, %s, %s", mode, AttributionHost, AttributionCorrelate, AttributionAudit)
	}
	if c.Attribution.MaxDelay.Std() <= 0 {
		return fmt.Errorf("attribution.max_delay must be positive, got %s", c.Attribution.MaxDelay.Std())
	}
	return nil
}

// ParseDropPolicyName reports whether name is a known drop policy.
func ParseDropPolicyName(name string) (string, bool) {
	switch name {
	case "drop_oldest", "drop_newest", "block":
		return name, true
	}
	return "", false
}

// WeightFor returns the configured fusion weight for a signal, or 0 when the
// signal has no weight entry.
func (c Config) WeightFor(signal string) float64 {
	for _, w := range c.Scoring.Weights {
		if w.Name == signal {
			return w.Weight
		}
	}
	return 0
}

func validLevel(s string) bool {
	for _, n := range LevelNames {
		if n == s {
			return true
		}
	}
	return false
}
