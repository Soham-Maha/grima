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

// A tree that is being written to while the watches are registered used to
// deadlock Start: fsnotify's Add waits for its backend reader, and that reader
// waits for the event channel to be drained by the consumer, which had not
// started yet. The sensor stalled for minutes instead of failing.
func TestStartReturnsWhileTheTreeIsBeingWritten(t *testing.T) {
	dir := t.TempDir()
	writeTree(t, dir, 300)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	stop := make(chan struct{})
	defer close(stop)
	go func() {
		for i := 0; ; i++ {
			select {
			case <-stop:
				return
			default:
			}
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
	case <-time.After(30 * time.Second):
		t.Fatal("Start did not return while the tree was being written: the watch registration deadlocked")
	}
	defer src.Close()

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
