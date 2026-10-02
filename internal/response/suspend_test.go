//go:build windows || linux || darwin

package response

import (
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/prateekpurohit13/grima/internal/config"
	"github.com/prateekpurohit13/grima/internal/score"
)

// childEnv makes the test binary run as a progress-making child instead of a
// test suite, so the suspend path can be measured against a real process.
const childEnv = "GRIMA_SUSPEND_CHILD_FILE"

func TestMain(m *testing.M) {
	if path := os.Getenv(childEnv); path != "" {
		runProgressChild(path)
		return
	}
	os.Exit(m.Run())
}

// runProgressChild appends a line on a short interval until it is killed. Its
// file growth is the observable progress the parent suspends and resumes by
// measuring.
func runProgressChild(path string) {
	file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		fmt.Fprintln(os.Stderr, "progress child:", err)
		os.Exit(1)
	}
	defer file.Close()

	for {
		if _, err := file.WriteString("tick\n"); err != nil {
			os.Exit(1)
		}
		_ = file.Sync()
		time.Sleep(10 * time.Millisecond)
	}
}

func startProgressChild(t *testing.T) (pid int32, file string) {
	t.Helper()

	file = filepath.Join(t.TempDir(), "progress.txt")
	cmd := exec.Command(os.Args[0])
	cmd.Env = append(os.Environ(), childEnv+"="+file)
	cmd.Stdout, cmd.Stderr = io.Discard, io.Discard
	if err := cmd.Start(); err != nil {
		t.Fatalf("start progress child: %v", err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
	})

	waitForBytes(t, file, 1)
	return int32(cmd.Process.Pid), file
}

func waitForBytes(t *testing.T, path string, atLeast int64) {
	t.Helper()

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if info, err := os.Stat(path); err == nil && info.Size() >= atLeast {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("child made no progress at %s within 5s", path)
}

func fileSize(t *testing.T, path string) int64 {
	t.Helper()

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat %s: %v", path, err)
	}
	return info.Size()
}

// The child writes every 10ms; 250ms is long enough that a running child could
// not coincidentally leave the file unchanged. The first sample waits for the
// suspension to settle: a thread already inside a write completes it after the
// suspend call returns, so sampling at the instant of the call can catch a byte
// that was already in flight.
func assertStopped(t *testing.T, file string) {
	t.Helper()

	time.Sleep(100 * time.Millisecond)
	stopped := fileSize(t, file)
	time.Sleep(250 * time.Millisecond)
	if grew := fileSize(t, file); grew != stopped {
		t.Fatalf("child kept writing while suspended: %d -> %d bytes", stopped, grew)
	}
}

func assertRunning(t *testing.T, file string) {
	t.Helper()

	before := fileSize(t, file)
	time.Sleep(250 * time.Millisecond)
	if after := fileSize(t, file); after <= before {
		t.Fatalf("child stopped writing while it should be running: %d -> %d bytes", before, after)
	}
}

func TestSuspendProcessStopsARealChildProcess(t *testing.T) {
	pid, file := startProgressChild(t)

	if err := suspendProcess(pid); err != nil {
		t.Fatalf("suspend child: %v", err)
	}
	assertStopped(t, file)
}

func TestApplySuspendsCriticalTargetWhenEnabled(t *testing.T) {
	pid, file := startProgressChild(t)

	cfg := config.Default()
	cfg.Response.EnableSuspend = true
	h := NewHandler(cfg, slog.New(slog.DiscardHandler))

	if err := h.Apply(verdict(pid, score.LevelCritical)); err != nil {
		t.Fatalf("apply: %v", err)
	}
	assertStopped(t, file)
}

func TestApplyLeavesTargetRunningWhenSuspendDisabled(t *testing.T) {
	pid, file := startProgressChild(t)

	// The default configuration keeps enable_suspend false.
	h := NewHandler(config.Default(), slog.New(slog.DiscardHandler))

	if err := h.Apply(verdict(pid, score.LevelCritical)); err != nil {
		t.Fatalf("apply: %v", err)
	}
	assertRunning(t, file)
}

func TestApplyAlertsRatherThanSuspendsBelowCritical(t *testing.T) {
	pid, file := startProgressChild(t)

	cfg := config.Default()
	cfg.Response.EnableSuspend = true
	h := NewHandler(cfg, slog.New(slog.DiscardHandler))

	// Suspend is gated on critical, so a high verdict must alert only.
	if err := h.Apply(verdict(pid, score.LevelHigh)); err != nil {
		t.Fatalf("apply: %v", err)
	}
	assertRunning(t, file)
}

// Sad path: the process is gone, so there is nothing to suspend.
func TestSuspendProcessRejectsAPIDThatNoLongerExists(t *testing.T) {
	dead := exec.Command(os.Args[0], "-test.run=^$")
	dead.Stdout, dead.Stderr = io.Discard, io.Discard
	if err := dead.Run(); err != nil {
		t.Fatalf("run placeholder process: %v", err)
	}

	if err := suspendProcess(int32(dead.Process.Pid)); err == nil {
		t.Fatal("suspending a PID that has exited should fail")
	}
}

// Sad path: a process the user does not own cannot be opened for suspension.
// The unix equivalent would be PID 1, which must never be touched from a test.
func TestSuspendProcessRefusesAProcessWeDoNotOwn(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("unownable target is Windows-specific; PID 1 must not be touched on unix")
	}

	// PID 4 is System on Windows; a user token cannot open it for suspension.
	if err := suspendProcess(4); err == nil {
		t.Fatal("suspending the System process should be denied")
	}
}
