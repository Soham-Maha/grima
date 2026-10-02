package filewatch

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/fsnotify/fsnotify"

	"github.com/prateekpurohit13/grima/internal/attrib"
	"github.com/prateekpurohit13/grima/internal/config"
	"github.com/prateekpurohit13/grima/internal/decoy"
	"github.com/prateekpurohit13/grima/internal/event"
)

// writeTree creates a tree of dirs directories with a file in each.
func writeTree(t *testing.T, root string, dirs int) {
	t.Helper()
	for i := range dirs {
		dir := filepath.Join(root, fmt.Sprintf("pkg-%03d", i), "lib")
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", dir, err)
		}
		writeTestFile(t, filepath.Join(dir, "index.js"), []byte("module.exports = 1\n"))
	}
}

// A tree being written to while the watches are registered used to deadlock
// Start: fsnotify's Add waits for its backend reader, and that reader waits for
// a consumer that Start had not started yet. Once the reader's event buffer
// fills, every remaining Add waits forever.
//
// Two details make this deterministic rather than flaky. The writes must arrive
// *while* the walk runs — a burst made before Start can be coalesced by the OS
// into fewer events than the buffer holds, and then nothing blocks. And the
// writes must be bounded: with an unbounded writer the walk advances only as
// fast as the consumer drains, which is correct but slow enough under -race to
// look like the bug this test exists to catch.
func TestStartReturnsWhileTheTreeIsBeingWritten(t *testing.T) {
	dir := t.TempDir()
	writeTree(t, dir, 300)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	writing := make(chan struct{})
	go func() {
		defer close(writing)
		for i := range 4000 {
			_ = os.WriteFile(filepath.Join(dir, fmt.Sprintf("pkg-%03d", i%300), "lib", "index.js"),
				[]byte(fmt.Sprintf("module.exports = %d\n", i)), 0o644)
		}
	}()

	src := testSource(t, dir)
	out := make(chan event.Event, 4096)
	done := make(chan error, 1)
	go func() { done <- src.Start(ctx, out) }()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Start: %v", err)
		}
	case <-time.After(60 * time.Second):
		t.Fatal("Start did not return while the tree was being written: the watch registration deadlocked")
	}
	defer src.Close()
	<-writing

	waitForEvent(t, out, "no event after Start returned")
}

// A directory created under a running sensor must still get a watch, and the
// event that announces it must not be the one that blocks the consumer: the
// watch is registered off the event loop for that reason.
func TestNewDirectoryIsWatchedWhileEventsArePending(t *testing.T) {
	dir := t.TempDir()
	writeTree(t, dir, 20)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	src := testSource(t, dir)
	out := make(chan event.Event, 4096)
	if err := src.Start(ctx, out); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer src.Close()

	newDir := filepath.Join(dir, "created-later")
	if err := os.MkdirAll(newDir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	// Events for the new directory can only arrive once its watch is
	// registered, so a write inside it proves the queued add happened.
	deadline := time.Now().Add(20 * time.Second)
	written := filepath.Join(newDir, "inside.js")
	for time.Now().Before(deadline) {
		writeTestFile(t, written, []byte("module.exports = 2\n"))
		for _, ev := range drain(out) {
			if ev.Path == written {
				return
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("no event for %s: the created directory never got a watch", written)
}

// waitForEvent fails the test unless one event arrives promptly.
func waitForEvent(t *testing.T, out chan event.Event, msg string) event.Event {
	t.Helper()
	select {
	case ev := <-out:
		return ev
	case <-time.After(20 * time.Second):
		t.Fatal(msg)
		return event.Event{}
	}
}

// A deadline that has already passed must still leave the sensor observing
// something: the root is registered inline whatever the clock says, and the rest
// of the tree is queued rather than dropped. Deterministic — no reliance on how
// fast this machine walks.
func TestAddTreeUntilQueuesTheRestOnceTheDeadlineHasPassed(t *testing.T) {
	dir := t.TempDir()
	writeTree(t, dir, 5)

	src := testSource(t, dir)
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		t.Fatalf("watcher: %v", err)
	}
	defer watcher.Close()
	src.watcher = watcher
	src.addQueue = make(chan string, addQueueDepth)

	added, queued, err := src.addTreeUntil(watcher, dir, time.Now().Add(-time.Second))
	if err != nil {
		t.Fatalf("addTreeUntil: %v", err)
	}
	if added != 1 {
		t.Errorf("added = %d, want the root registered inline", added)
	}
	// One queue entry per top-level subtree: the worker walks each subtree it is
	// handed, so queueing the subtree root is what covers everything under it.
	if queued != 5 {
		t.Errorf("queued = %d, want one entry per subtree past the deadline", queued)
	}
	if len(src.addQueue) != 5 {
		t.Fatalf("queue holds %d entries, want 5", len(src.addQueue))
	}
	if pending := src.addPending.Load(); pending != 5 {
		t.Errorf("addPending = %d, want 5 while the queued directories are unregistered", pending)
	}
}

// A startup deadline short enough to bite must not stop the sensor from starting
// or from covering the whole tree: Start returns early, the remainder is counted
// as pending, and every directory ends up watched.
func TestStartWithADeadlineCoversTheRestInTheBackground(t *testing.T) {
	dir := t.TempDir()
	writeTree(t, dir, 600)

	cfg := sensorConfig(dir)
	cfg.FileWatch.StartupDeadline = config.Duration(time.Nanosecond)
	src := New(cfg, attrib.New(time.Second), decoy.NewRegistry(), slog.New(slog.DiscardHandler))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	out := make(chan event.Event, 4096)
	if err := src.Start(ctx, out); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer src.Close()

	if pending := src.addPending.Load(); pending <= 0 {
		t.Fatalf("addPending = %d immediately after Start, want the rest of the tree queued", pending)
	}

	// The worker must drain it and leave the tree fully covered.
	deadline := time.Now().Add(60 * time.Second)
	for src.addPending.Load() > 0 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if pending := src.addPending.Load(); pending != 0 {
		t.Fatalf("addPending = %d after waiting, want the queued directories registered", pending)
	}

	// A directory the deadline skipped is only watched if the worker registered
	// it: an event from inside one proves the coverage completed.
	deep := filepath.Join(dir, "pkg-599", "lib")
	written := filepath.Join(deep, "late.js")
	writeTestFile(t, written, []byte("module.exports = 3\n"))
	for _, ev := range drain(out) {
		if ev.Path == written {
			return
		}
	}
	waitForEvent(t, out, "no event for a directory the startup deadline skipped")
}

// Zero means unbounded: the old behaviour, where Start registers the whole tree
// before returning and nothing is left pending.
func TestStartWithoutADeadlineRegistersEverythingInline(t *testing.T) {
	dir := t.TempDir()
	writeTree(t, dir, 40)

	cfg := sensorConfig(dir)
	cfg.FileWatch.StartupDeadline = 0
	src := New(cfg, attrib.New(time.Second), decoy.NewRegistry(), slog.New(slog.DiscardHandler))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	out := make(chan event.Event, 4096)
	if err := src.Start(ctx, out); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer src.Close()

	if pending := src.addPending.Load(); pending != 0 {
		t.Fatalf("addPending = %d with no deadline, want everything registered inline", pending)
	}

	written := filepath.Join(dir, "pkg-039", "lib", "inline.js")
	writeTestFile(t, written, []byte("module.exports = 4\n"))
	for _, ev := range drain(out) {
		if ev.Path == written {
			return
		}
	}
	waitForEvent(t, out, "no event from a directory the inline walk registered")
}
