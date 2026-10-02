// Package rules implements the hard-rule layer.
//
// Rules are pure predicates over a single event: no cross-event state, no
// window dependency. That keeps them instantaneous — they subscribe to the bus
// directly and are evaluated on arrival rather than at the next scoring tick —
// and it makes each one trivially testable.
//
// A rule hit becomes an Override, which sets a floor on the risk level and is
// never averaged away by benign signals.
package rules

import (
	"fmt"
	"strings"

	"github.com/prateekpurohit13/grima/internal/config"
	"github.com/prateekpurohit13/grima/internal/event"
	"github.com/prateekpurohit13/grima/internal/score"
)

// Rule is one hard detection rule.
type Rule struct {
	ID          string
	Description string
	Severity    score.Level
	Match       func(event.Event) bool
}

// Engine evaluates the rule set against single events.
type Engine struct {
	rules []Rule
}

// Built-in command patterns derived from the SigmaHQ rule corpus (source,
// license, and authorship are recorded in THIRD_PARTY_NOTICES.md). They extend
// the config-supplied lists, which remain the operator's extension point: a
// command-pattern rule fires on either source, and rules.enabled switches the
// whole layer off.
var (
	// Shadow/recovery tampering beyond the configured delete commands.
	sigmaShadowExtra = []string{
		"vssadmin delete shadowstorage",
		"vssadmin.exe delete shadowstorage",
		"wbadmin delete backup",
		"bcdedit /set bootstatuspolicy ignoreallfailures",
		"bcdedit /set {default} bootstatuspolicy ignoreallfailures",
		"bcdedit /set {current} bootstatuspolicy ignoreallfailures",
		"bcdedit /set {current} recoveryenabled no",
		"reagentc /disable",
	}
	// Sigma fires on any resize with /MaxSize=; GRIMA narrows it to the
	// destructive zero case so routine storage resizing does not trip a hard rule.
	sigmaShadowResize  = []string{"resize", "shadowstorage", "maxsize=0"}
	sigmaEventLogExtra = []string{"Remove-EventLog", "Clear-WinEvent", "ClearEventLog"}
	sigmaUSNExtra      = []string{"fsutil.exe usn deletejournal"}
	// Every term in a set must be present in the command line.
	sigmaFirewallSets = [][]string{
		{"firewall", "set", "opmode", "disable"},
		{"advfirewall", "set", "state", "off"},
		{"set-netfirewallprofile", "enabled", "false"},
	}
	sigmaServiceTriggers = []string{
		"sc stop", "sc.exe stop", "sc delete", "sc.exe delete", "sc pause", "sc.exe pause",
		"net stop", "net.exe stop", "stop-service", "remove-service",
	}
	sigmaSecurityServices = []string{
		"windefend", "msmpeng", "mssense", "sense", "sentinelagent", "sentinelone",
		"ccsvchst", "ekrn", "avp1", "mcshield", "savservice", "tmlisten", "xagt",
		"symantec", "sophos", "kaspersky", "trend micro",
		"veeam", "backupexec", "backup exec", "wbengine", "sdrsvc",
	}
	sigmaEDRTriggers = []string{"taskkill", "stop-process", "tskill", "pkill", "killall"}
	sigmaEDRTargets  = []string{
		"ccsvchst.exe", "msmpeng.exe", "mssense.exe", "sentinelagent.exe",
		"csfalconservice.exe", "ekrn.exe", "avp.exe", "mcshield.exe",
		"savservice.exe", "tmlisten.exe", "xagt.exe",
	}
)

// NewEngine builds the rule set from configuration.
//
// Detection logic for the command-pattern rules is derived from the SigmaHQ
// rule corpus; attribution is recorded in THIRD_PARTY_NOTICES.md.
func NewEngine(cfg config.Config) *Engine {
	rc := cfg.Rules

	e := &Engine{rules: []Rule{
		{
			ID:          "R-DECOY-TOUCH",
			Description: "decoy file written, renamed, or deleted",
			Severity:    score.LevelCritical,
			Match: func(ev event.Event) bool {
				return ev.Kind == event.KindDecoyTouch
			},
		},
		{
			ID:          "R-PERSIST-INSTALL",
			Description: "new persistence mechanism installed",
			Severity:    score.LevelMedium,
			Match: func(ev event.Event) bool {
				return ev.Kind == event.KindPersistenceInstall
			},
		},
	}}
	if !rc.Enabled {
		return e
	}

	shadow := concat(rc.ShadowCommands, sigmaShadowExtra)
	eventLog := concat(rc.EventLogCommands, sigmaEventLogExtra)
	usn := concat(rc.USNCommands, sigmaUSNExtra)

	e.rules = append(e.rules,
		Rule{
			ID:          "R-SHADOW-DELETE",
			Description: "shadow copy or recovery configuration tampering",
			Severity:    score.LevelCritical,
			Match: func(ev event.Event) bool {
				if ev.Kind != event.KindProcessStart {
					return false
				}
				if _, ok := containsAny(ev.Cmdline, shadow); ok {
					return true
				}
				return containsAll(ev.Cmdline, sigmaShadowResize)
			},
		},
		Rule{
			ID:          "R-EVENTLOG-CLEAR",
			Description: "event log cleared or truncated",
			Severity:    score.LevelCritical,
			Match: func(ev event.Event) bool {
				if ev.Kind != event.KindProcessStart {
					return false
				}
				_, ok := containsAny(ev.Cmdline, eventLog)
				return ok
			},
		},
		Rule{
			ID:          "R-USN-DELETE",
			Description: "USN journal deleted",
			Severity:    score.LevelHigh,
			Match: func(ev event.Event) bool {
				if ev.Kind != event.KindProcessStart {
					return false
				}
				_, ok := containsAny(ev.Cmdline, usn)
				return ok
			},
		},
		Rule{
			ID:          "R-BACKUP-KILL",
			Description: "backup or database process terminated",
			Severity:    score.LevelHigh,
			Match: func(ev event.Event) bool {
				if ev.Kind != event.KindProcessStart {
					return false
				}
				return containsPair(ev.Cmdline, rc.Terminators, rc.BackupProcesses)
			},
		},
		Rule{
			ID:          "R-FIREWALL-OFF",
			Description: "host firewall disabled",
			Severity:    score.LevelHigh,
			Match: func(ev event.Event) bool {
				if ev.Kind != event.KindProcessStart {
					return false
				}
				return containsSet(ev.Cmdline, sigmaFirewallSets)
			},
		},
		Rule{
			ID:          "R-SERVICE-TAMPER",
			Description: "security or backup service stopped or deleted",
			Severity:    score.LevelHigh,
			Match: func(ev event.Event) bool {
				if ev.Kind != event.KindProcessStart {
					return false
				}
				return containsPair(ev.Cmdline, sigmaServiceTriggers, sigmaSecurityServices)
			},
		},
		Rule{
			ID:          "R-EDR-KILL",
			Description: "security agent process terminated",
			Severity:    score.LevelHigh,
			Match: func(ev event.Event) bool {
				if ev.Kind != event.KindProcessStart {
					return false
				}
				return containsPair(ev.Cmdline, sigmaEDRTriggers, sigmaEDRTargets)
			},
		},
	)
	return e
}

// Rules returns the rule set for documentation and display.
func (e *Engine) Rules() []Rule { return e.rules }

// Evaluate returns the highest-severity rule hit for an event, if any.
func (e *Engine) Evaluate(ev event.Event) (score.Override, bool) {
	var (
		best    score.Override
		matched bool
	)
	for _, r := range e.rules {
		if !r.Match(ev) {
			continue
		}
		if matched && r.Severity <= best.Level {
			continue
		}
		best = score.Override{
			ID:     r.ID,
			Level:  r.Severity,
			Detail: fmt.Sprintf("%s: %s", r.Description, summarise(ev)),
		}
		matched = true
	}
	return best, matched
}

func summarise(ev event.Event) string {
	switch {
	case ev.Kind == event.KindDecoyTouch:
		return fmt.Sprintf("decoy %s touched at %s", ev.DecoyID, ev.Path)
	case ev.Kind == event.KindPersistenceInstall:
		return fmt.Sprintf("%s entry installed at %s", ev.Persist, ev.Path)
	case ev.Cmdline != "":
		return truncate(ev.Cmdline, 160)
	case ev.Path != "":
		return ev.Path
	default:
		return ev.ProcName
	}
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

// containsAny reports whether haystack contains any needle, case-insensitively.
func containsAny(haystack string, needles []string) (string, bool) {
	if haystack == "" || len(needles) == 0 {
		return "", false
	}
	lower := strings.ToLower(haystack)
	for _, n := range needles {
		n = strings.TrimSpace(n)
		if n == "" {
			continue
		}
		if strings.Contains(lower, strings.ToLower(n)) {
			return n, true
		}
	}
	return "", false
}

// containsAll reports whether haystack contains every needle, case-insensitively.
func containsAll(haystack string, needles []string) bool {
	if haystack == "" || len(needles) == 0 {
		return false
	}
	lower := strings.ToLower(haystack)
	for _, n := range needles {
		n = strings.TrimSpace(n)
		if n == "" {
			continue
		}
		if !strings.Contains(lower, strings.ToLower(n)) {
			return false
		}
	}
	return true
}

// containsSet reports whether haystack contains every term of any set.
func containsSet(haystack string, sets [][]string) bool {
	for _, set := range sets {
		if containsAll(haystack, set) {
			return true
		}
	}
	return false
}

// containsPair reports whether haystack contains both a trigger and a target term.
func containsPair(haystack string, triggers, targets []string) bool {
	if _, ok := containsAny(haystack, triggers); !ok {
		return false
	}
	_, ok := containsAny(haystack, targets)
	return ok
}

// concat returns a and b joined into a fresh slice.
func concat(a, b []string) []string {
	out := make([]string, 0, len(a)+len(b))
	out = append(out, a...)
	return append(out, b...)
}
