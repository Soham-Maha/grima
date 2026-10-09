package filewatch

import (
	"bytes"
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/fsnotify/fsnotify"

	"github.com/prateekpurohit13/grima/internal/attrib"
	"github.com/prateekpurohit13/grima/internal/decoy"
	"github.com/prateekpurohit13/grima/internal/event"
)

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

// Row 2's bounded-queue half: the add queue never drops silently. A directory
// discovered while the queue is full is a counted drop on the event-loop path,
// because that goroutine must keep consuming events rather than block on a
// registration. (The startup walk makes the opposite choice on purpose: it
// registers inline instead, since a directory left unwatched at startup stays
// blind until something rescans it.)
func TestFullAddQueueIsCounted(t *testing.T) {
	dir := t.TempDir()
	s := testSource(t, dir)
	s.addQueue = make(chan string, 1)

	if !s.enqueueAdd(filepath.Join(dir, "a")) {
		t.Fatal("the queue was empty and refused an entry")
	}
	if s.enqueueAdd(filepath.Join(dir, "b")) {
		t.Fatal("a full queue accepted an entry")
	}

	created := filepath.Join(dir, "b")
	if err := os.Mkdir(created, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	out := make(chan event.Event, 4)
	s.handle(fsnotify.Event{Name: created, Op: fsnotify.Create}, out)

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
