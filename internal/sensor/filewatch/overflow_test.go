//go:build !darwin

package filewatch

import (
	"bytes"
	"context"
	"path/filepath"
	"testing"

	"github.com/fsnotify/fsnotify"

	"github.com/prateekpurohit13/grima/internal/event"
)

// Failure table row 1, filesystem event overflow: the overflow is delivered the
// way the kernel delivers it — on the watcher's own error channel carrying
// fsnotify's ErrEventOverflow — so the real loop, not a direct call, drives the
// rescan. The observables are the synthetic event and the counters.
//
// Darwin is excluded. The kqueue backend never produces ErrEventOverflow (the
// upstream documentation lists it as "not used" on kqueue and fen), and that
// backend's teardown closes the Errors channel from a goroutine that
// Watcher.Close does not join — the wake travels through a kernel pipe, so a
// send on watcher.Errors from another goroutine has no happens-before edge to
// that close and the race detector reports it. Reproduced with fsnotify v1.10.1
// alone, no grima code. Overflow is an inotify and Windows condition, and those
// backends synchronise their teardown, so CI exercises this test on both.
// Production never sends on watcher.Errors, so the sensor itself is race-free
// on darwin; see overflow_darwin_test.go for what darwin can test.
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
