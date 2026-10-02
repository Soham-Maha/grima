package filewatch

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

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
