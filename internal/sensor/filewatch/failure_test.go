package filewatch

import (
	"bytes"
	"context"
	"log/slog"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/fsnotify/fsnotify"

	"github.com/prateekpurohit13/grima/internal/attrib"
	"github.com/prateekpurohit13/grima/internal/decoy"
	"github.com/prateekpurohit13/grima/internal/event"
)

// Failure table row 1, filesystem event overflow: the overflow is delivered the
// way the kernel delivers it — on the watcher's own error channel carrying
// fsnotify's ErrEventOverflow — so the real loop, not a direct call, drives the
// rescan. The observables are the synthetic event and the counters.
func TestOverflowOnTheWatcherErrorChannelRescansAndCounts(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "one.txt")
	writeTestFile(t, path, bytes.Repeat([]byte("abcdefgh"), 512))

	s := testSource(t, dir)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	out := make(chan event.Event, 64)
	if err := s.Start(ctx, out); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer s.Close()
	drain(out)

	s.watcher.Errors <- fsnotify.ErrEventOverflow

	ev := waitForEvent(t, out, "no synthetic event after an overflow on the watcher error channel")
	if ev.Kind != event.KindFileWrite || ev.Path != path {
		t.Fatalf("event = %s %s, want a synthetic file write for %s", ev.Kind, ev.Path, path)
	}

	stats := s.Stats()
	if n := stats.Extra["overflow"]; n != 1 {
		t.Fatalf("overflow = %d, want 1", n)
	}
	if n := stats.Extra["rescans"]; n != 1 {
		t.Fatalf("rescans = %d, want 1", n)
	}
	if n := stats.Extra["watch_failures"]; n != 1 {
		t.Fatalf("watch_failures = %d, want 1 for a lost-notification overflow", n)
	}
	if stats.Errors != 1 {
		t.Fatalf("errors = %d, want 1", stats.Errors)
	}
}

// Failure table row 2, watch exhaustion: a monitored root that cannot be watched
// (here it no longer exists; on Linux this is also the Add ENOSPC/ENOSPC-style
// exhaustion path) must be logged, counted, and therefore visible in the health
// entry. One watchable root keeps Start from failing outright.
func TestUnwatchedDirectoryIsLoggedCountedAndSurfaced(t *testing.T) {
	good := t.TempDir()
	missing := filepath.Join(good, "gone")

	var buf bytes.Buffer
	cfg := sensorConfig(good)
	cfg.General.MonitorPaths = []string{good, missing}
	s := New(cfg, attrib.New(time.Second), decoy.NewRegistry(), slog.New(slog.NewTextHandler(&buf, nil)))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	out := make(chan event.Event, 8)
	if err := s.Start(ctx, out); err != nil {
		t.Fatalf("Start with one watchable root: %v", err)
	}
	defer s.Close()

	if !strings.Contains(buf.String(), "partial watch") {
		t.Fatalf("the unwatched directory was not logged: %q", buf.String())
	}
	if n := s.Stats().Extra["watch_failures"]; n != 1 {
		t.Fatalf("watch_failures = %d, want 1 in the sensor's health counters", n)
	}
}

// Row 2's kernel half: an Add the backend refuses is counted, rather than only
// logged. A closed watcher refuses every Add with fsnotify.ErrClosed, which is
// the same code path an exhausted inotify watch table takes.
func TestRefusedWatchIsCounted(t *testing.T) {
	dir := t.TempDir()
	s := testSource(t, dir)

	w, err := fsnotify.NewWatcher()
	if err != nil {
		t.Fatalf("new watcher: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("close watcher: %v", err)
	}

	added, err := s.addTree(w, dir)
	if err == nil {
		t.Fatal("adding to a watch table that refuses the watch must report an error")
	}
	if added != 0 {
		t.Fatalf("added = %d, want 0 when the watch was refused", added)
	}
	if n := s.Stats().Extra["watch_failures"]; n == 0 {
		t.Fatal("a refused watch was not counted")
	}
}

// Row 2's bounded-queue half: the add queue never drops silently. A full queue
// is counted, because the directory it carried stays invisible until the next
// rescan.
func TestFullAddQueueIsCounted(t *testing.T) {
	dir := t.TempDir()
	s := testSource(t, dir)
	s.addQueue = make(chan string, 1)

	s.enqueueAdd(filepath.Join(dir, "a"))
	s.enqueueAdd(filepath.Join(dir, "b"))

	if n := s.Stats().Extra["add_dropped"]; n != 1 {
		t.Fatalf("add_dropped = %d, want 1 for the directory the full queue dropped", n)
	}
}

// Failure table row 4, no baseline yet: the magic-byte check is the part of
// uncalibrated mode the file sensor owns. It reads the file's own content, so it
// works with no host baseline at all.
func TestMagicMismatchIsReportedWithoutABaseline(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "report.docx")
	writeTestFile(t, path, bytes.Repeat([]byte{0x91, 0xab, 0xcd, 0xef}, 2048))

	s := testSource(t, dir)
	out := make(chan event.Event, 8)
	s.rescan(out)

	got := drain(out)
	if len(got) != 1 {
		t.Fatalf("events = %d, want 1", len(got))
	}
	if !got[0].MagicMismatch {
		t.Fatalf("a .docx holding ciphertext was not flagged (entropy %.2f)", got[0].Entropy)
	}
}
