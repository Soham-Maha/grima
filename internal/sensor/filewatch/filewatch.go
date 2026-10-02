// Package filewatch watches directories for file changes and samples changed
// files for entropy and content-vs-extension mismatches.
package filewatch

import (
	"context"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"math"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/fsnotify/fsnotify"

	"github.com/prateekpurohit13/grima/internal/attrib"
	"github.com/prateekpurohit13/grima/internal/config"
	"github.com/prateekpurohit13/grima/internal/decoy"
	"github.com/prateekpurohit13/grima/internal/event"
	"github.com/prateekpurohit13/grima/internal/sensor"
)

const name = "filewatch"

// addQueueDepth bounds directories waiting for a watch. A full queue drops and
// counts, rather than blocking the event loop.
const addQueueDepth = 256

// Source watches the configured directories.
type Source struct {
	cfg    config.Config
	log    *slog.Logger
	attrib *attrib.Attributor
	decoys *decoy.Registry

	watcher *fsnotify.Watcher
	done    chan struct{}
	closeMu sync.Once
	wg      sync.WaitGroup

	// addQueue carries directories that need a watch. They are added by
	// addWorker rather than by whoever saw them, because fsnotify's Add
	// handshakes with the backend reader and that reader blocks while an event
	// is waiting to be consumed.
	addQueue   chan string
	addDropped atomic.Uint64
	// addPending counts directories queued for a watch that has not been
	// registered yet, whether queued at startup or by a directory created later.
	addPending atomic.Int64

	events   atomic.Uint64
	errors   atomic.Uint64
	dropped  atomic.Uint64
	overflow atomic.Uint64
	rescans  atomic.Uint64

	// watchFailures counts directories that ended up unmonitored: an Add the
	// kernel refused (inotify watch exhaustion), an unreadable subtree, or an
	// overflow that lost notifications. It is the number behind the failure
	// table's "count and surface watch exhaustion".
	watchFailures atomic.Uint64
}

// New returns a file sensor.
func New(cfg config.Config, at *attrib.Attributor, decoys *decoy.Registry, log *slog.Logger) *Source {
	return &Source{
		cfg:    cfg,
		log:    log,
		attrib: at,
		decoys: decoys,
		done:   make(chan struct{}),
	}
}

func (s *Source) Name() string { return name }

// Start watches every monitored directory. It fails rather than starting blind
// if no directory can be watched at all.
func (s *Source) Start(ctx context.Context, out chan<- event.Event) error {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return fmt.Errorf("%s: create watcher: %w", name, err)
	}
	s.watcher = watcher

	// The consumer starts before the first watch is added. fsnotify's Add
	// handshakes with its backend reader, and that reader blocks while an event
	// is waiting to be consumed — so adding watches with no consumer running
	// deadlocks both sides. Measured as a multi-minute startup stall on a
	// 403-directory tree that was being written to (sprints.md §23).
	s.addQueue = make(chan string, addQueueDepth)
	s.wg.Add(2)
	go s.loop(ctx, out)
	go s.addWorker(ctx)

	// The initial walk is bounded. Registering every watch before returning
	// means the walk advances only as fast as the event consumer drains — on a
	// large tree under load that took seconds, and every other sensor and the
	// score loop wait behind Start (sprints.md §25). Past the deadline the rest
	// of the tree goes to the worker, which walks those subtrees itself.
	deadline := time.Time{}
	if d := s.cfg.FileWatch.StartupDeadline.Std(); d > 0 {
		deadline = time.Now().Add(d)
	}

	watched, queued := 0, 0
	for _, root := range s.cfg.General.MonitorPaths {
		n, q, err := s.addTreeUntil(watcher, root, deadline)
		if err != nil {
			s.log.Warn("partial watch", "path", root, "error", err)
		}
		watched += n
		queued += q
	}
	if watched == 0 {
		watcher.Close()
		s.closeMu.Do(func() { close(s.done) })
		return fmt.Errorf("%s: no directory under %v could be watched", name, s.cfg.General.MonitorPaths)
	}

	s.log.Info("watching directories", "source", name, "count", watched)
	if queued > 0 {
		s.log.Warn("startup deadline reached; the rest of the tree is being watched in the background",
			"source", name, "watched", watched, "queued", queued,
			"deadline", s.cfg.FileWatch.StartupDeadline.Std().String())
	}

	return nil
}

// Close stops watching. Idempotent.
func (s *Source) Close() error {
	s.closeMu.Do(func() {
		close(s.done)
		if s.watcher != nil {
			s.watcher.Close()
		}
		s.wg.Wait()
	})
	return nil
}

// Stats reports sensor health.
func (s *Source) Stats() sensor.Stats {
	attribution := s.attrib.Stats()
	return sensor.Stats{
		Name:    name,
		Events:  s.events.Load(),
		Errors:  s.errors.Load(),
		Dropped: s.dropped.Load(),
		Extra: map[string]uint64{
			"overflow":            s.overflow.Load(),
			"rescans":             s.rescans.Load(),
			"watch_failures":      s.watchFailures.Load(),
			"add_dropped":         s.addDropped.Load(),
			"add_pending":         uint64(max(0, s.addPending.Load())),
			"attrib_causal_hits":  attribution.CausalHits,
			"attrib_correlate":    attribution.CausalMisses,
			"attrib_pending_drop": attribution.PendingDrops,
			"attrib_source_error": attribution.Source.Errors,
		},
	}
}

// enqueueAdd offers a directory to the watch queue, reporting whether it was
// taken. The queue is bounded, so the caller decides what a full queue means:
// the event loop counts the loss (it must not block), while the startup walk
// registers the directory inline instead, because a directory that is never
// watched is blind until something else rescans it.
func (s *Source) enqueueAdd(path string) bool {
	select {
	case s.addQueue <- path:
		s.addPending.Add(1)
		return true
	default:
		return false
	}
}

// addWorker registers queued directories, off the event loop.
func (s *Source) addWorker(ctx context.Context) {
	defer s.wg.Done()

	for {
		select {
		case <-ctx.Done():
			return
		case <-s.done:
			return
		case path := <-s.addQueue:
			if _, err := s.addTree(s.watcher, path); err != nil {
				s.log.Warn("partial watch", "path", path, "error", err)
			}
			s.addPending.Add(-1)
		}
	}
}

func (s *Source) loop(ctx context.Context, out chan<- event.Event) {
	defer s.wg.Done()

	for {
		select {
		case <-ctx.Done():
			return
		case <-s.done:
			return
		case fsEv, ok := <-s.watcher.Events:
			if !ok {
				return
			}
			s.handle(fsEv, out)
		case err, ok := <-s.watcher.Errors:
			if !ok {
				return
			}
			s.handleWatchError(err, out)
		}
	}
}

// handleWatchError counts a watch error and rescans after an overflow, because
// notifications lost to the overflow would otherwise never be seen.
func (s *Source) handleWatchError(err error, out chan<- event.Event) {
	s.errors.Add(1)
	s.log.Warn("watch error", "source", name, "error", err)

	if !isOverflow(err) {
		return
	}
	// An overflow lost notifications whether or not the compensating rescan is
	// enabled, so it is both an overflow and a watch failure either way.
	s.overflow.Add(1)
	s.watchFailures.Add(1)
	if s.cfg.FileWatch.RescanOnOverflow {
		s.rescan(out)
	}
}

func (s *Source) handle(fsEv fsnotify.Event, out chan<- event.Event) {
	path := fsEv.Name

	// A new directory needs its own watch, or everything created inside it is
	// invisible from here on. The watch is queued, not added here: this
	// goroutine is the only consumer of the events that fsnotify's Add waits
	// behind, so adding inline would stall the sensor under load.
	if fsEv.Op&fsnotify.Create != 0 {
		if info, err := os.Stat(path); err == nil && info.IsDir() {
			// This goroutine must keep consuming events, so a full queue is a
			// counted drop here rather than a blocking registration.
			if !s.enqueueAdd(path) {
				s.addDropped.Add(1)
			}
			return
		}
	}

	kind, ok := kindFor(fsEv.Op)
	if !ok {
		return
	}

	ev := event.Event{Kind: kind, Path: path, Time: time.Now()}
	if kind == event.KindFileWrite || kind == event.KindFileCreate {
		s.readContent(&ev, path)
	}

	if id, isDecoy := s.decoys.Lookup(path); isDecoy {
		ev.Kind = event.KindDecoyTouch
		ev.DecoyID = id
	}

	s.attrib.Resolve(ev, func(ev event.Event) { s.emit(out, ev) })
}

// rescan re-reads recently modified files after an event overflow, so a storm
// that outran the notification buffer still reaches the fingerprint window.
func (s *Source) rescan(out chan<- event.Event) {
	const window = 5 * time.Second

	s.rescans.Add(1)
	seen := make(map[string]struct{})
	cutoff := time.Now().Add(-window)

	for _, root := range s.cfg.General.MonitorPaths {
		_ = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() {
				return nil
			}
			info, err := d.Info()
			if err != nil || info.ModTime().Before(cutoff) {
				return nil
			}
			if _, dup := seen[path]; dup {
				return nil
			}
			seen[path] = struct{}{}

			ev := event.Event{Kind: event.KindFileWrite, Path: path, Time: time.Now()}
			s.readContent(&ev, path)
			s.attrib.Resolve(ev, func(ev event.Event) { s.emit(out, ev) })
			return nil
		})
	}
}

func (s *Source) readContent(ev *event.Event, path string) {
	head, tail, total, err := readSample(path, s.cfg.FileWatch.EntropySampleBytes)
	if err != nil {
		return // unreadable: entropy stays zero, which means unknown
	}
	ev.Bytes = total
	if len(head)+len(tail) > 0 {
		ev.Entropy = shannon(head, tail)
	}
	ev.MagicMismatch = looksWrong(path, head)
}

func (s *Source) emit(out chan<- event.Event, ev event.Event) {
	ev.Source = name
	s.events.Add(1)

	select {
	case out <- ev:
	default:
		s.dropped.Add(1)
	}
}

func kindFor(op fsnotify.Op) (event.Kind, bool) {
	switch {
	case op&fsnotify.Create != 0:
		return event.KindFileCreate, true
	case op&fsnotify.Write != 0:
		return event.KindFileWrite, true
	case op&fsnotify.Remove != 0:
		return event.KindFileDelete, true
	case op&fsnotify.Rename != 0:
		return event.KindFileRename, true
	}
	return event.KindUnknown, false
}

func isOverflow(err error) bool {
	return strings.Contains(strings.ToLower(err.Error()), "overflow")
}

// addTreeUntil watches root and its subdirectories, stopping at the deadline:
// the directory it stops on is queued for the background worker, which walks
// that subtree itself. The first directory is always registered inline, so a
// deadline that has already passed still leaves the sensor observing something
// rather than returning the "nothing could be watched" error.
func (s *Source) addTreeUntil(watcher *fsnotify.Watcher, root string, deadline time.Time) (added, queued int, firstErr error) {
	expired := !deadline.IsZero() && time.Now().After(deadline)

	_ = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			s.watchFailures.Add(1)
			return nil
		}
		if !d.IsDir() {
			return nil
		}
		if added > 0 && expired {
			// Past the deadline the subtree goes to the worker — unless the
			// queue is full, in which case registering it here is slower but
			// leaves it watched rather than blind.
			if s.enqueueAdd(path) {
				queued++
				return filepath.SkipDir
			}
		}
		if err := watcher.Add(path); err != nil {
			if firstErr == nil {
				firstErr = err
			}
			s.watchFailures.Add(1)
			return nil
		}
		added++
		expired = !deadline.IsZero() && time.Now().After(deadline)
		return nil
	})

	return added, queued, firstErr
}

// addTree watches root and every subdirectory under it, skipping subtrees it
// cannot read rather than failing the whole watch. Every directory that ends up
// unwatched is counted, so inotify watch exhaustion shows up as a number on
// /healthz rather than only as a log line.
func (s *Source) addTree(watcher *fsnotify.Watcher, root string) (int, error) {
	added := 0
	var firstErr error

	_ = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			s.watchFailures.Add(1)
			if firstErr == nil {
				firstErr = err
			}
			return nil
		}
		if !d.IsDir() {
			return nil
		}
		if err := watcher.Add(path); err != nil {
			s.watchFailures.Add(1)
			if firstErr == nil {
				firstErr = err
			}
			return nil
		}
		added++
		return nil
	})

	return added, firstErr
}

// readSample reads the head and tail of a file. Sampling rather than reading the
// whole file bounds I/O under an encryption storm and still catches partial
// encryption that leaves the middle untouched.
//
// The open shares delete, so sampling never blocks an application from renaming
// or deleting a file it is reading — see openShared.
func readSample(path string, size int) (head, tail []byte, total int64, err error) {
	f, err := openShared(path)
	if err != nil {
		return nil, nil, 0, err
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		return nil, nil, 0, err
	}
	total = info.Size()

	head = make([]byte, size)
	n, err := io.ReadFull(f, head)
	if err != nil && err != io.EOF && err != io.ErrUnexpectedEOF {
		return nil, nil, total, err
	}
	head = head[:n]

	if total > int64(size)*2 {
		tail = make([]byte, size)
		if _, err := f.ReadAt(tail, total-int64(size)); err != nil {
			tail = nil
		}
	}
	return head, tail, total, nil
}

// shannon returns the Shannon entropy in bits per byte across the sampled parts.
func shannon(parts ...[]byte) float64 {
	var counts [256]int
	total := 0
	for _, p := range parts {
		for _, b := range p {
			counts[b]++
			total++
		}
	}
	if total == 0 {
		return 0
	}

	var h float64
	for _, c := range counts {
		if c == 0 {
			continue
		}
		p := float64(c) / float64(total)
		h -= p * math.Log2(p)
	}
	return h
}
