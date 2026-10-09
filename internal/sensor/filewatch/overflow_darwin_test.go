//go:build darwin

package filewatch

import (
	"bytes"
	"path/filepath"
	"testing"

	"github.com/fsnotify/fsnotify"

	"github.com/prateekpurohit13/grima/internal/event"
)

// Darwin half of the overflow test. The kqueue backend cannot deliver an
// overflow error at all (fsnotify: "kqueue, fen: not used" for
// ErrEventOverflow), and injecting one on watcher.Errors races that backend's
// asynchronous teardown close under the race detector — see overflow_test.go
// for the full-path test CI runs on Windows and Linux. So the decision the
// loop makes is driven directly: the same handler, the same observables, with
// only fsnotify's delivery in between.
func TestOverflowErrorCountsAndRescans(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "one.txt")
	writeTestFile(t, path, bytes.Repeat([]byte("abcdefgh"), 512))

	s := testSource(t, dir)
	out := make(chan event.Event, 64)

	s.handleWatchError(fsnotify.ErrEventOverflow, out)

	ev := waitForEvent(t, out, "no synthetic event after an overflow")
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
