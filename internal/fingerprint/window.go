// Package fingerprint folds raw events into per-process behavioral fingerprints
// and aggregates them over process trees.
package fingerprint

import (
	"slices"
	"strings"
	"time"

	"github.com/prateekpurohit13/grima/internal/event"
)

// ringCapacity bounds retained samples per process, capping memory at
// (live processes x ringCapacity) regardless of uptime.
const ringCapacity = 4096

// seqCap bounds the kind sequence an n-gram is read from, so the aggregate over
// a large process tree costs no more than a single process's ring.
const seqCap = ringCapacity

// kindHashBase is the multiplier of the rolling k-gram hash. Any odd constant
// works: the alphabet is the event-kind vocabulary, which is small.
const kindHashBase uint64 = 131

// HostName labels the fingerprint that collects file events no process could be
// blamed for, so their evidence still reaches scoring.
const HostName = "(host)"

type sample struct {
	at      time.Time
	kind    event.Kind
	bytes   int64
	dir     string
	ext     string
	entropy float64
	magic   bool
}

type procState struct {
	name      string
	ppid      int32
	firstSeen time.Time
	lastSeen  time.Time

	ring  []sample
	head  int
	count int

	// Non-decaying counters. These never age out, which is what catches drip
	// encryption that no single window would ever see.
	cumFilesRewritten int64
	cumBytesRewritten int64
	extActivity       map[string]int64
}

func newProcState(name string, ppid int32, at time.Time) *procState {
	return &procState{
		name:        name,
		ppid:        ppid,
		firstSeen:   at,
		lastSeen:    at,
		ring:        make([]sample, ringCapacity),
		extActivity: make(map[string]int64),
	}
}

func (p *procState) push(s sample) {
	p.ring[p.head] = s
	p.head = (p.head + 1) % len(p.ring)
	if p.count < len(p.ring) {
		p.count++
	}
	p.lastSeen = s.at
}

// each iterates newest-first and stops when fn returns false.
func (p *procState) each(fn func(sample) bool) {
	n := len(p.ring)
	for i := range p.count {
		idx := (p.head - 1 - i + n) % n
		if !fn(p.ring[idx]) {
			return
		}
	}
}

// EntropySample is one observed entropy value tagged with its extension, so the
// scorer can compare it against the matching per-extension baseline.
type EntropySample struct {
	Ext string
	H   float64
}

// TreeVector is the summed fingerprint of a process and all its descendants.
// Scoring the tree rather than the process is what defeats workload splitting.
type TreeVector struct {
	Root     int32
	ProcName string
	PIDs     []int32

	Writes        int
	Creates       int
	Renames       int
	Deletes       int
	Bytes         int64
	Dirs          map[string]struct{}
	Entropy       []EntropySample
	MagicTotal    int
	MagicMismatch int
	NGram         NGram

	CumFilesRewritten int64
	CumBytesRewritten int64
	ExtActivity       map[string]int64

	WindowDuration time.Duration
}

// DirCount returns the number of distinct directories touched in the window.
func (t TreeVector) DirCount() int { return len(t.Dirs) }

// Window is a read-only snapshot of one process fingerprint.
type Window struct {
	Writes        int
	Creates       int
	Renames       int
	Deletes       int
	Bytes         int64
	Dirs          map[string]struct{}
	Entropy       []EntropySample
	MagicTotal    int
	MagicMismatch int
	NGram         NGram

	CumFilesRewritten int64
	CumBytesRewritten int64
	ExtActivity       map[string]int64

	FirstSeen time.Time
	LastSeen  time.Time
}

// counts accumulates window counters. Shared by Aggregate and snapshot so the
// two can never drift apart.
type counts struct {
	writes   int
	creates  int
	renames  int
	deletes  int
	bytes    int64
	dirs     map[string]struct{}
	entropy  []EntropySample
	magicBad int
	magicAll int
	kinds    []event.Kind // newest-first until finish orders it
}

func newCounts() *counts {
	return &counts{dirs: make(map[string]struct{})}
}

func (c *counts) add(s sample) {
	switch s.kind {
	case event.KindFileWrite:
		c.writes++
	case event.KindFileCreate:
		c.creates++
	case event.KindFileRename:
		c.renames++
	case event.KindFileDelete:
		c.deletes++
	}
	c.bytes += s.bytes
	if s.dir != "" {
		c.dirs[s.dir] = struct{}{}
	}
	c.kinds = append(c.kinds, s.kind)
	if s.kind != event.KindFileWrite {
		return
	}
	c.magicAll++
	if s.magic {
		c.magicBad++
	}
	if s.entropy > 0 {
		c.entropy = append(c.entropy, EntropySample{Ext: s.ext, H: s.entropy})
	}
}

// finish orders the kind sequence chronologically and trims it to the most
// recent seqCap events, ready for the n-gram feature.
func (c *counts) finish() {
	slices.Reverse(c.kinds)
	if len(c.kinds) > seqCap {
		c.kinds = c.kinds[len(c.kinds)-seqCap:]
	}
}

// ngram reads the sequence feature off the accumulated window.
func (c *counts) ngram(k int) NGram { return ngramOf(c.kinds, k) }

// NGram is the sequence feature of a window. Ransomware overwrites a file and
// then renames it to a new extension, so a write immediately followed by a
// rename is the transition that separates encryption from ordinary
// modification; a bulk build, archive or backup writes without renaming.
type NGram struct {
	K            int     // k, from window.ngram_length
	Total        int     // k-grams observed in the window
	Sequence     string  // the most frequent k-gram, reduced to its cycle when it repeats
	Count        int     // occurrences of Sequence
	Pairs        int     // adjacent event pairs in the window
	RenameChains int     // adjacent pairs that are a write followed by a rename
	ChainShare   float64 // RenameChains / Pairs
}

// ngramOf derives the feature from a window's kinds in chronological order.
// k-grams are counted by rolling hash, so a busy window builds no string key per
// k-gram. It returns the zero value when the window holds fewer than k events,
// which is not the same as "no chains observed".
//
// The chain share is measured over adjacent pairs, not over k-grams. A k-gram
// spans k-1 pairs, so counting k-grams that contain a chain made the share a
// step function rather than a density: at the default k=32 a single
// write-then-rename adjacency lies inside up to 31 overlapping k-grams, so one
// ordinary rename in a short window read as a saturated pattern. Pairs are what
// the claim "a quarter of the window is chains" is actually about.
func ngramOf(kinds []event.Kind, k int) NGram {
	out := NGram{K: k}
	if k <= 0 || len(kinds) < k {
		return out
	}
	out.Total = len(kinds) - k + 1

	// A transition needs two events, so a 1-gram window has no transitions to
	// measure and reports no chains rather than reporting every adjacency.
	if k >= 2 {
		out.Pairs = len(kinds) - 1
		for i := 0; i+1 < len(kinds); i++ {
			if isRenameChain(kinds[i], kinds[i+1]) {
				out.RenameChains++
			}
		}
		if out.Pairs > 0 {
			out.ChainShare = float64(out.RenameChains) / float64(out.Pairs)
		}
	}

	pow := uint64(1)
	for range k {
		pow *= kindHashBase
	}

	seen := make(map[uint64]int, out.Total)
	var hash uint64
	best, bestAt := 0, 0

	for i, kind := range kinds {
		hash = hash*kindHashBase + uint64(kind)
		if i >= k {
			hash -= uint64(kinds[i-k]) * pow
		}
		if i < k-1 {
			continue
		}

		n := seen[hash] + 1
		seen[hash] = n
		if n > best {
			best, bestAt = n, i
		}
	}

	out.Count = best
	out.Sequence = renderKinds(kinds[bestAt-k+1 : bestAt+1])
	return out
}

// isRenameChain reports whether an event kind is followed by the rename an
// encryptor performs after overwriting a file.
func isRenameChain(prev, next event.Kind) bool {
	return prev == event.KindFileWrite && next == event.KindFileRename
}

// renderKinds renders a k-gram compactly: a periodic k-gram becomes the cycle it
// repeats ("file_write>file_rename"), which is the shape a loop has, and a
// non-repeating one is truncated so a signal Detail stays readable.
func renderKinds(kinds []event.Kind) string {
	const limit = 48
	for p := 1; p < len(kinds); p++ {
		if len(kinds)%p == 0 && periodic(kinds, p) {
			return joinKinds(kinds[:p], limit)
		}
	}
	return joinKinds(kinds, limit)
}

// periodic reports whether the whole sequence repeats with period p.
func periodic(kinds []event.Kind, p int) bool {
	for i := p; i < len(kinds); i++ {
		if kinds[i] != kinds[i%p] {
			return false
		}
	}
	return true
}

func joinKinds(kinds []event.Kind, limit int) string {
	var b strings.Builder
	for _, kind := range kinds {
		if b.Len() > 0 {
			b.WriteByte('>')
		}
		b.WriteString(kind.String())
		if b.Len() > limit {
			return b.String()[:limit] + "..."
		}
	}
	return b.String()
}
