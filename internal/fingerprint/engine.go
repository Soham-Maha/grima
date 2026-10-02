package fingerprint

import (
	"time"

	"github.com/prateekpurohit13/grima/internal/config"
	"github.com/prateekpurohit13/grima/internal/event"
)

// Engine owns all fingerprint state. Single-writer: Apply is called from exactly
// one goroutine, so there is no locking on the hot path.
type Engine struct {
	cfg      config.Config
	procs    map[int32]*procState
	children map[int32]map[int32]struct{}
}

// NewEngine returns an empty engine.
func NewEngine(cfg config.Config) *Engine {
	return &Engine{
		cfg:      cfg,
		procs:    make(map[int32]*procState),
		children: make(map[int32]map[int32]struct{}),
	}
}

// Apply folds one event into the fingerprint state.
func (e *Engine) Apply(ev event.Event) {
	switch ev.Kind {
	case event.KindProcessStart:
		e.ensure(ev.PID, ev.ProcName, ev.PPID, ev.Time)
		e.linkChild(ev.PPID, ev.PID)
		return
	case event.KindProcessExit:
		e.Reap(ev.PID)
		return
	}

	// Unattributed file events still carry evidence — entropy, magic bytes,
	// extension novelty — that is a property of the file, not the process. They
	// go into a host-level fingerprint rather than being discarded, so detection
	// does not depend on attribution succeeding.
	if !ev.Kind.IsFile() {
		return
	}

	name := ev.ProcName
	if ev.PID == 0 && name == "" {
		name = HostName
	}
	p := e.ensure(ev.PID, name, ev.PPID, ev.Time)
	p.push(sample{
		at:      ev.Time,
		kind:    ev.Kind,
		bytes:   ev.Bytes,
		dir:     event.ParentDir(ev.Path),
		ext:     ev.Extension(),
		entropy: ev.Entropy,
		magic:   ev.MagicMismatch,
	})

	switch ev.Kind {
	case event.KindFileWrite:
		p.cumFilesRewritten++
		p.cumBytesRewritten += ev.Bytes
		if ext := ev.Extension(); ext != "" {
			p.extActivity[ext]++
		}
	case event.KindFileCreate:
		// A create reports the file's whole size, and a rename emits one for its
		// destination, so adding bytes here counts every renamed file twice —
		// measured at roughly 2x the bytes actually written. A create is still
		// activity; it is just not bytes written.
		p.cumFilesRewritten++
		if ext := ev.Extension(); ext != "" {
			p.extActivity[ext]++
		}
	}
}

// Window returns a snapshot of one process fingerprint.
func (e *Engine) Window(pid int32) (Window, bool) {
	p, ok := e.procs[pid]
	if !ok {
		return Window{}, false
	}
	return e.snapshot(p, time.Now()), true
}

// Snapshot returns a window for every live process.
func (e *Engine) Snapshot() map[int32]Window {
	now := time.Now()
	out := make(map[int32]Window, len(e.procs))
	for pid, p := range e.procs {
		out[pid] = e.snapshot(p, now)
	}
	return out
}

// Roots returns the PIDs that head a process tree.
func (e *Engine) Roots() []int32 {
	out := make([]int32, 0, len(e.procs))
	for pid, p := range e.procs {
		if p.ppid == 0 {
			out = append(out, pid)
			continue
		}
		if _, tracked := e.procs[p.ppid]; !tracked {
			out = append(out, pid)
		}
	}
	return out
}

// Aggregate sums the fingerprint of root and every tracked descendant.
func (e *Engine) Aggregate(root int32) TreeVector {
	cutoff := time.Now().Add(-e.cfg.Window.DecayHalfLife.Std())

	tv := TreeVector{
		Root:           root,
		ExtActivity:    make(map[string]int64),
		WindowDuration: e.cfg.Window.DecayHalfLife.Std(),
	}

	// One accumulator for the whole tree: the members' in-window samples form a
	// single sequence, so the n-gram feature sees the tree's behavior rather
	// than one process's.
	c := newCounts()
	e.walk(root, func(pid int32, p *procState) {
		tv.PIDs = append(tv.PIDs, pid)
		if tv.ProcName == "" {
			tv.ProcName = p.name
		}
		tv.CumFilesRewritten += p.cumFilesRewritten
		tv.CumBytesRewritten += p.cumBytesRewritten
		for ext, n := range p.extActivity {
			tv.ExtActivity[ext] += n
		}

		p.each(func(s sample) bool {
			if s.at.Before(cutoff) {
				return false // newest-first, so everything after this is older
			}
			c.add(s)
			return true
		})
	})
	c.finish()

	tv.Writes = c.writes
	tv.Creates = c.creates
	tv.Renames = c.renames
	tv.Deletes = c.deletes
	tv.Bytes = c.bytes
	tv.Dirs = c.dirs
	tv.Entropy = c.entropy
	tv.MagicTotal = c.magicAll
	tv.MagicMismatch = c.magicBad
	tv.NGram = c.ngram(e.cfg.Window.NGramLength)

	return tv
}

// Reap releases state for an exited process so memory tracks live processes
// rather than every process ever seen.
func (e *Engine) Reap(pid int32) {
	p, ok := e.procs[pid]
	if !ok {
		return
	}
	delete(e.procs, pid)

	// Unlink from the parent's child set. Leaving the dead PID there kept it a
	// child of a live parent forever, which had two consequences: the set grew
	// with every process ever spawned under a long-lived parent (the opposite of
	// what this function promises), and a reused PID was walked into the old
	// tree, so a stranger's writes landed in that parent's score and dashboard
	// member list while the stranger was also scored as its own root.
	if siblings, ok := e.children[p.ppid]; ok {
		delete(siblings, pid)
		if len(siblings) == 0 {
			delete(e.children, p.ppid)
		}
	}

	if kids, ok := e.children[pid]; ok {
		for child := range kids {
			if c, alive := e.procs[child]; alive {
				c.ppid = 0 // orphan becomes a root rather than vanishing from the tree
			}
		}
		delete(e.children, pid)
	}
}

// Live reports how many processes currently hold fingerprint state.
func (e *Engine) Live() int { return len(e.procs) }

func (e *Engine) ensure(pid int32, name string, ppid int32, at time.Time) *procState {
	if p, ok := e.procs[pid]; ok {
		if name != "" {
			p.name = name
		}
		return p
	}
	p := newProcState(name, ppid, at)
	e.procs[pid] = p
	return p
}

func (e *Engine) linkChild(parent, child int32) {
	if parent == 0 {
		return
	}
	set := e.children[parent]
	if set == nil {
		set = make(map[int32]struct{})
		e.children[parent] = set
	}
	set[child] = struct{}{}
}

func (e *Engine) walk(root int32, fn func(pid int32, p *procState)) {
	seen := make(map[int32]struct{})
	queue := []int32{root}

	for len(queue) > 0 {
		pid := queue[0]
		queue = queue[1:]
		if _, done := seen[pid]; done {
			continue
		}
		seen[pid] = struct{}{}

		p, ok := e.procs[pid]
		if !ok {
			continue
		}
		fn(pid, p)

		for child := range e.children[pid] {
			queue = append(queue, child)
		}
	}
}

func (e *Engine) snapshot(p *procState, now time.Time) Window {
	cutoff := now.Add(-e.cfg.Window.DecayHalfLife.Std())

	c := newCounts()
	p.each(func(s sample) bool {
		if s.at.Before(cutoff) {
			return false
		}
		c.add(s)
		return true
	})
	c.finish()

	w := Window{
		Writes:            c.writes,
		Creates:           c.creates,
		Renames:           c.renames,
		Deletes:           c.deletes,
		Bytes:             c.bytes,
		Dirs:              c.dirs,
		Entropy:           c.entropy,
		MagicTotal:        c.magicAll,
		MagicMismatch:     c.magicBad,
		NGram:             c.ngram(e.cfg.Window.NGramLength),
		CumFilesRewritten: p.cumFilesRewritten,
		CumBytesRewritten: p.cumBytesRewritten,
		ExtActivity:       make(map[string]int64, len(p.extActivity)),
		FirstSeen:         p.firstSeen,
		LastSeen:          p.lastSeen,
	}
	for ext, n := range p.extActivity {
		w.ExtActivity[ext] = n
	}
	return w
}
