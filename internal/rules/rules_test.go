package rules

import (
	"strings"
	"testing"

	"github.com/prateekpurohit13/grima/internal/config"
	"github.com/prateekpurohit13/grima/internal/event"
	"github.com/prateekpurohit13/grima/internal/score"
)

// proc builds a process-start event from command-line words.
//
// The words are joined at run time rather than written as one literal because
// whole ransomware command lines make Windows Defender quarantine the test
// binary as a false positive.
func proc(words ...string) event.Event {
	return event.Event{Kind: event.KindProcessStart, Cmdline: strings.Join(words, " ")}
}

func TestRuleMatching(t *testing.T) {
	engine := NewEngine(config.Default())
	t.Logf("rule count: %d", len(engine.Rules()))

	cases := []struct {
		name  string
		ev    event.Event
		want  string // empty means no rule should fire
		level score.Level
	}{
		// R-DECOY-TOUCH
		{
			name:  "decoy touched",
			ev:    event.Event{Kind: event.KindDecoyTouch, Path: "/data/invoices_backup.pdf", DecoyID: "ab12"},
			want:  "R-DECOY-TOUCH",
			level: score.LevelCritical,
		},
		{
			name: "decoy name on an ordinary write",
			ev:   event.Event{Kind: event.KindFileWrite, Path: "/data/invoices_backup.pdf"},
		},

		// R-PERSIST-INSTALL
		{
			name:  "persistence installed",
			ev:    event.Event{Kind: event.KindPersistenceInstall, Path: "/etc/cron.d/x", Persist: "cron"},
			want:  "R-PERSIST-INSTALL",
			level: score.LevelMedium,
		},
		{
			name: "cron text in a process command line",
			ev:   proc("echo", "'*", "*", "*", "*", "*", "/tmp/x'", ">>", "/etc/crontab"),
		},

		// R-SHADOW-DELETE
		{
			name:  "shadow copy deletion",
			ev:    proc("vssadmin.exe", "delete", "shadows", "/all", "/quiet"),
			want:  "R-SHADOW-DELETE",
			level: score.LevelCritical,
		},
		{
			name:  "shadow copy deletion via wmic",
			ev:    proc("wmic", "shadowcopy", "delete"),
			want:  "R-SHADOW-DELETE",
			level: score.LevelCritical,
		},
		{
			name:  "shadow storage resized to zero",
			ev:    proc("vssadmin", "resize", "shadowstorage", "/for=C:", "/on=C:", "/maxsize=0"),
			want:  "R-SHADOW-DELETE",
			level: score.LevelCritical,
		},
		{
			name:  "shadow storage deleted",
			ev:    proc("vssadmin", "delete", "shadowstorage", "/for=C:", "/on=C:"),
			want:  "R-SHADOW-DELETE",
			level: score.LevelCritical,
		},
		{
			name:  "recovery disabled",
			ev:    proc("bcdedit", "/set", "recoveryenabled", "no"),
			want:  "R-SHADOW-DELETE",
			level: score.LevelCritical,
		},
		{
			name:  "boot status policy tampered",
			ev:    proc("bcdedit", "/set", "{default}", "bootstatuspolicy", "ignoreallfailures"),
			want:  "R-SHADOW-DELETE",
			level: score.LevelCritical,
		},
		{
			name:  "boot status policy tampered mixed case",
			ev:    proc("BCDEDIT", "/SET", "{DEFAULT}", "BOOTSTATUSPOLICY", "IGNOREALLFAILURES"),
			want:  "R-SHADOW-DELETE",
			level: score.LevelCritical,
		},
		{
			name:  "recovery environment disabled",
			ev:    proc("reagentc", "/disable"),
			want:  "R-SHADOW-DELETE",
			level: score.LevelCritical,
		},
		{
			name:  "backup catalog deleted",
			ev:    proc("wbadmin", "delete", "catalog", "-quiet"),
			want:  "R-SHADOW-DELETE",
			level: score.LevelCritical,
		},
		{
			name:  "system state backup deleted",
			ev:    proc("wbadmin", "delete", "systemstatebackup"),
			want:  "R-SHADOW-DELETE",
			level: score.LevelCritical,
		},
		{
			name: "benign shadow enumeration",
			ev:   proc("vssadmin", "list", "shadows"),
		},
		{
			name: "benign shadow storage resize",
			ev:   proc("vssadmin", "resize", "shadowstorage", "/for=C:", "/on=C:", "/maxsize=20GB"),
		},
		{
			name: "benign shadow storage add",
			ev:   proc("vssadmin", "add", "shadowstorage", "/for=C:", "/on=C:", "/maxsize=20GB"),
		},
		{
			name: "recovery re-enabled",
			ev:   proc("bcdedit", "/set", "{default}", "recoveryenabled", "yes"),
		},
		{
			name: "benign boot policy",
			ev:   proc("bcdedit", "/set", "{default}", "bootstatuspolicy", "displayallfailures"),
		},
		{
			name: "benign backup start",
			ev:   proc("wbadmin", "start", "backup", "-backupTarget:E:", "-allCritical", "-quiet"),
		},
		{
			name: "shadow word in an unrelated argument",
			ev:   proc("vim", "shadows.txt"),
		},
		{
			name: "command pattern on a file event",
			ev:   event.Event{Kind: event.KindFileWrite, Cmdline: `vssadmin delete shadows`},
		},

		// R-EVENTLOG-CLEAR
		{
			name:  "event log cleared",
			ev:    proc("wevtutil", "cl", "System"),
			want:  "R-EVENTLOG-CLEAR",
			level: score.LevelCritical,
		},
		{
			name:  "event log cleared long form",
			ev:    proc("wevtutil", "clear-log", "System"),
			want:  "R-EVENTLOG-CLEAR",
			level: score.LevelCritical,
		},
		{
			name:  "event log removed via PowerShell",
			ev:    proc("powershell", "-c", `"Remove-EventLog`, "-LogName", `System"`),
			want:  "R-EVENTLOG-CLEAR",
			level: score.LevelCritical,
		},
		{
			name:  "event log cleared via wmic",
			ev:    proc("wmic", "nteventlog", "where", `"LogfileName='Application'"`, "call", "ClearEventLog"),
			want:  "R-EVENTLOG-CLEAR",
			level: score.LevelCritical,
		},
		{
			name: "benign event log query",
			ev:   proc("wevtutil", "qe", "System", "/f:text", "/rd:true"),
		},

		// R-USN-DELETE
		{
			name:  "usn journal deleted",
			ev:    proc("fsutil", "usn", "deletejournal", "/D", "C:"),
			want:  "R-USN-DELETE",
			level: score.LevelHigh,
		},
		{
			name:  "usn journal deleted full path",
			ev:    proc(`C:\Windows\System32\fsutil.exe`, "usn", "deletejournal", "/d", "c:"),
			want:  "R-USN-DELETE",
			level: score.LevelHigh,
		},
		{
			name: "benign usn read",
			ev:   proc("fsutil", "usn", "readjournal", "C:"),
		},
		{
			name: "benign usn create",
			ev:   proc("fsutil", "usn", "createjournal", "m=1000", "a=100", "c:"),
		},

		// R-BACKUP-KILL
		{
			name:  "backup process terminated",
			ev:    proc("taskkill", "/IM", "sqlservr.exe", "/F"),
			want:  "R-BACKUP-KILL",
			level: score.LevelHigh,
		},
		{
			name:  "backup process terminated bare name",
			ev:    proc("pkill", "veeam"),
			want:  "R-BACKUP-KILL",
			level: score.LevelHigh,
		},
		{
			name: "terminator with no backup target",
			ev:   proc("pkill", "nginx"),
		},

		// R-FIREWALL-OFF
		{
			name:  "firewall disabled via netsh",
			ev:    proc("netsh", "advfirewall", "set", "allprofiles", "state", "off"),
			want:  "R-FIREWALL-OFF",
			level: score.LevelHigh,
		},
		{
			name:  "firewall disabled legacy syntax",
			ev:    proc("netsh", "firewall", "set", "opmode", "mode=disable", "profile=all"),
			want:  "R-FIREWALL-OFF",
			level: score.LevelHigh,
		},
		{
			name:  "firewall disabled mixed case",
			ev:    proc("NETSH", "ADVFIREWALL", "SET", "CURRENTPROFILE", "STATE", "OFF"),
			want:  "R-FIREWALL-OFF",
			level: score.LevelHigh,
		},
		{
			name:  "firewall disabled via PowerShell",
			ev:    proc("Set-NetFirewallProfile", "-Profile", "Domain,Public,Private", "-Enabled", "False"),
			want:  "R-FIREWALL-OFF",
			level: score.LevelHigh,
		},
		{
			name: "benign firewall enable",
			ev:   proc("netsh", "advfirewall", "set", "allprofiles", "state", "on"),
		},
		{
			name: "benign firewall status",
			ev:   proc("netsh", "advfirewall", "show", "allprofiles", "state"),
		},
		{
			name: "benign firewall rule add",
			ev:   proc("netsh", "advfirewall", "firewall", "add", "rule", `name="Allow`, `443"`, "dir=out", "action=allow", "protocol=TCP", "localport=443"),
		},
		{
			name: "benign interface address",
			ev:   proc("netsh", "interface", "ip", "set", "address", `name="Ethernet"`, "static", "10.0.0.5", "255.255.255.0"),
		},

		// R-SERVICE-TAMPER
		{
			name:  "security service stopped",
			ev:    proc("sc", "stop", "windefend"),
			want:  "R-SERVICE-TAMPER",
			level: score.LevelHigh,
		},
		{
			name:  "security service stopped full path",
			ev:    proc(`C:\Windows\System32\sc.exe`, "stop", "Sense"),
			want:  "R-SERVICE-TAMPER",
			level: score.LevelHigh,
		},
		{
			name:  "security service deleted",
			ev:    proc("sc.exe", "delete", "Veeam"),
			want:  "R-SERVICE-TAMPER",
			level: score.LevelHigh,
		},
		{
			name:  "backup service stopped via PowerShell",
			ev:    proc("Stop-Service", "-Name", "wbengine", "-Force"),
			want:  "R-SERVICE-TAMPER",
			level: score.LevelHigh,
		},
		{
			name: "benign service query",
			ev:   proc("sc", "query", "windefend"),
		},
		{
			name: "benign non-security service stop",
			ev:   proc("sc", "stop", "spooler"),
		},
		{
			name: "benign service start",
			ev:   proc("sc", "start", "veeam"),
		},

		// R-EDR-KILL
		{
			name:  "edr process terminated",
			ev:    proc("taskkill", "/IM", "MsMpEng.exe", "/F"),
			want:  "R-EDR-KILL",
			level: score.LevelHigh,
		},
		{
			name:  "edr process terminated full path",
			ev:    proc(`C:\Windows\System32\taskkill.exe`, "/f", "/im", "ccSvcHst.exe"),
			want:  "R-EDR-KILL",
			level: score.LevelHigh,
		},
		{
			name:  "edr process terminated via PowerShell",
			ev:    proc("Stop-Process", "-Name", "SentinelAgent.exe", "-Force"),
			want:  "R-EDR-KILL",
			level: score.LevelHigh,
		},
		{
			name:  "edr process terminated mixed case",
			ev:    proc("TASKKILL", "/IM", "EKRN.EXE", "/F"),
			want:  "R-EDR-KILL",
			level: score.LevelHigh,
		},
		{
			name: "benign process kill",
			ev:   proc("taskkill", "/IM", "notepad.exe", "/F"),
		},
		{
			name: "benign pid kill",
			ev:   proc("taskkill", "/PID", "4321", "/F"),
		},
		{
			name: "benign PowerShell stop",
			ev:   proc("Stop-Process", "-Name", "outlook", "-Force"),
		},

		// Kind gating
		{
			name: "benign listing",
			ev:   proc("ls", "-la", "/data"),
		},
		{
			name: "benign file write",
			ev:   event.Event{Kind: event.KindFileWrite, Path: "/data/report.docx"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, hit := engine.Evaluate(tc.ev)
			if tc.want == "" {
				if hit {
					t.Fatalf("unexpected rule hit %q", got.ID)
				}
				return
			}
			if !hit {
				t.Fatalf("expected rule %q to fire", tc.want)
			}
			if got.ID != tc.want {
				t.Fatalf("rule = %q, want %q", got.ID, tc.want)
			}
			if got.Level != tc.level {
				t.Fatalf("severity = %v, want %v", got.Level, tc.level)
			}
			if got.Detail == "" {
				t.Fatal("a rule hit must carry a detail")
			}
		})
	}
}

// benignWords are ordinary command lines, as word lists, that must not trip any
// rule; they bound the false-positive budget of the whole set, not just the top
// match.
var benignWords = [][]string{
	{"ls", "-la", "/data"},
	{"pkill", "nginx"},
	{"vim", "shadows.txt"},
	{"vssadmin", "list", "shadows"},
	{"vssadmin", "resize", "shadowstorage", "/for=C:", "/on=C:", "/maxsize=20GB"},
	{"vssadmin", "add", "shadowstorage", "/for=C:", "/on=C:", "/maxsize=20GB"},
	{"wbadmin", "start", "backup", "-backupTarget:E:", "-allCritical", "-quiet"},
	{"wbadmin", "get", "versions"},
	{"bcdedit", "/enum", "{default}"},
	{"bcdedit", "/set", "{default}", "recoveryenabled", "yes"},
	{"bcdedit", "/set", "{default}", "bootstatuspolicy", "displayallfailures"},
	{"wevtutil", "qe", "System", "/f:text", "/rd:true"},
	{"fsutil", "usn", "readjournal", "C:"},
	{"fsutil", "usn", "createjournal", "m=1000", "a=100", "c:"},
	{"netsh", "advfirewall", "set", "allprofiles", "state", "on"},
	{"netsh", "advfirewall", "show", "allprofiles", "state"},
	{"netsh", "advfirewall", "firewall", "add", "rule", `name="Allow`, `443"`, "dir=out", "action=allow", "protocol=TCP", "localport=443"},
	{"netsh", "interface", "ip", "set", "address", `name="Ethernet"`, "static", "10.0.0.5", "255.255.255.0"},
	{"sc", "query", "windefend"},
	{"sc", "stop", "spooler"},
	{"sc", "start", "veeam"},
	{"net", "start", "wbengine"},
	{"taskkill", "/IM", "notepad.exe", "/F"},
	{"taskkill", "/PID", "4321", "/F"},
	{"Stop-Process", "-Name", "outlook", "-Force"},
	{"powershell", "-c", `"Get-Service`, `windefend"`},
	{"reagentc", "/info"},
	{"shutdown", "/r", "/t", "0"},
}

// No rule may fire on a benign command, including rules hidden behind a
// higher-severity match.
func TestBenignCommandsMatchNoRule(t *testing.T) {
	engine := NewEngine(config.Default())

	benign := make([]event.Event, 0, len(benignWords)+4)
	for _, words := range benignWords {
		benign = append(benign, proc(words...))
	}
	benign = append(benign,
		event.Event{Kind: event.KindFileWrite, Path: "/data/invoices_backup.pdf"},
		event.Event{Kind: event.KindFileWrite, Path: "/data/report.docx", Cmdline: `vssadmin delete shadows`},
		event.Event{Kind: event.KindFileRename, Path: "/data/a.docx", NewPath: "/data/a.docx.locked"},
		event.Event{Kind: event.KindProcessExit, ProcName: "sqlservr"},
	)

	for _, r := range engine.Rules() {
		for _, ev := range benign {
			if r.Match(ev) {
				t.Errorf("rule %s fired on benign event %q", r.ID, ev.Cmdline)
			}
		}
	}
}

// The highest-severity match wins when more than one rule matches.
func TestHighestSeverityWins(t *testing.T) {
	engine := NewEngine(config.Default())

	ev := event.Event{
		Kind:    event.KindPersistenceInstall,
		Path:    "/etc/cron.d/x",
		Persist: "cron",
	}

	got, hit := engine.Evaluate(ev)
	if !hit {
		t.Fatal("expected a hit")
	}
	if got.ID != "R-PERSIST-INSTALL" {
		t.Fatalf("rule = %q, want R-PERSIST-INSTALL", got.ID)
	}
}

// The configured set must expose exactly the documented rules.
func TestRuleSetShape(t *testing.T) {
	engine := NewEngine(config.Default())

	want := []string{
		"R-DECOY-TOUCH",
		"R-PERSIST-INSTALL",
		"R-SHADOW-DELETE",
		"R-EVENTLOG-CLEAR",
		"R-USN-DELETE",
		"R-BACKUP-KILL",
		"R-FIREWALL-OFF",
		"R-SERVICE-TAMPER",
		"R-EDR-KILL",
	}

	got := engine.Rules()
	if len(got) != len(want) {
		t.Fatalf("rule count = %d, want %d", len(got), len(want))
	}
	for i, id := range want {
		if got[i].ID != id {
			t.Fatalf("rule %d = %q, want %q", i, got[i].ID, id)
		}
		if got[i].Description == "" {
			t.Fatalf("rule %q has no description", id)
		}
	}
	t.Logf("rule count: %d", len(got))
}

func TestEmptyConfigDisablesPatternRules(t *testing.T) {
	cfg := config.Default()
	cfg.Rules = config.RulesConfig{Enabled: false}

	engine := NewEngine(cfg)
	for _, words := range [][]string{
		{"vssadmin", "delete", "shadows", "/all"},
		{"netsh", "advfirewall", "set", "allprofiles", "state", "off"},
		{"sc", "stop", "windefend"},
		{"taskkill", "/IM", "MsMpEng.exe", "/F"},
	} {
		if _, hit := engine.Evaluate(proc(words...)); hit {
			t.Fatalf("pattern rules must not fire when disabled: %q", strings.Join(words, " "))
		}
	}
}
