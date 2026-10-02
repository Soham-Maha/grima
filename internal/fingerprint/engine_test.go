package fingerprint

import (
	"fmt"
	"math"
	"testing"
	"time"

	"github.com/prateekpurohit13/grima/internal/config"
	"github.com/prateekpurohit13/grima/internal/event"
)

func testEngine(t *testing.T, halfLife time.Duration) *Engine {
	t.Helper()
	cfg := config.Default()
	cfg.Window.DecayHalfLife = config.Duration(halfLife)
	return NewEngine(cfg)
}

func write(pid int32, path string, bytes int64, at time.Time) event.Event {
	return event.Event{Kind: event.KindFileWrite, PID: pid, Path: path, Bytes: bytes, Time: at}
}

func TestAggregateSumsOverProcessTree(t *testing.T) {
	e := testEngine(t, time.Minute)
	now := time.Now()

	e.Apply(event.Event{Kind: event.KindProcessStart, PID: 10, ProcName: "parent", Time: now})
	e.Apply(event.Event{Kind: event.KindProcessStart, PID: 11, PPID: 10, ProcName: "child", Time: now})
	e.Apply(write(10, "/data/a.txt", 100, now))
	e.Apply(write(11, "/data/b.txt", 200, now))

	tv := e.Aggregate(10)

	if tv.Writes != 2 {
		t.Fatalf("writes = %d, want 2", tv.Writes)
	}
	if tv.Bytes != 300 {
		t.Fatalf("bytes = %d, want 300", tv.Bytes)
	}
	if len(tv.PIDs) != 2 {
		t.Fatalf("pids = %v, want parent and child", tv.PIDs)
	}
	if tv.DirCount() != 1 {
		t.Fatalf("directories = %d, want 1", tv.DirCount())
	}
}

// The point of the dual-track design: the window ages out, the counters do not.
func TestCumulativeCountersSurviveDecay(t *testing.T) {
	e := testEngine(t, 40*time.Millisecond)
	e.Apply(event.Event{Kind: event.KindProcessStart, PID: 5, ProcName: "dripper", Time: time.Now()})

	for i := range 10 {
		e.Apply(write(5, fmt.Sprintf("/data/f%d.txt", i), 10, time.Now()))
	}
	time.Sleep(120 * time.Millisecond)

	tv := e.Aggregate(5)
	if tv.Writes != 0 {
		t.Fatalf("window writes = %d, want 0 after decay", tv.Writes)
	}
	if tv.CumFilesRewritten != 10 {
		t.Fatalf("cumulative files = %d, want 10 (must not decay)", tv.CumFilesRewritten)
	}
	if tv.CumBytesRewritten != 100 {
		t.Fatalf("cumulative bytes = %d, want 100", tv.CumBytesRewritten)
	}
}

// A rename emits a create for its destination carrying the whole file size, so
// counting bytes on creates reported roughly twice what was actually written.
// Measured against a fixture that wrote 96 MiB and was reported at ~193 MiB.
func TestCumulativeBytesAreNotDoubleCountedOnRename(t *testing.T) {
	e := testEngine(t, time.Minute)
	now := time.Now()
	e.Apply(event.Event{Kind: event.KindProcessStart, PID: 7, ProcName: "crypt", Time: now})

	// The write that put the bytes on disk, then the rename's destination create.
	e.Apply(event.Event{Kind: event.KindFileWrite, PID: 7, Path: "/d/a.txt", Bytes: 4096, Time: now})
	e.Apply(event.Event{Kind: event.KindFileRename, PID: 7, Path: "/d/a.txt", NewPath: "/d/a.txt.locked", Time: now})
	e.Apply(event.Event{Kind: event.KindFileCreate, PID: 7, Path: "/d/a.txt.locked", Bytes: 4096, Time: now})

	tv := e.Aggregate(7)
	if tv.CumBytesRewritten != 4096 {
		t.Fatalf("cumulative bytes = %d, want 4096: a rename must not re-count the file it moved",
			tv.CumBytesRewritten)
	}
}

func TestExtensionActivityIsCumulative(t *testing.T) {
	e := testEngine(t, time.Minute)
	now := time.Now()
	e.Apply(event.Event{Kind: event.KindProcessStart, PID: 7, ProcName: "crypt", Time: now})

	for i := range 4 {
		ev := write(7, fmt.Sprintf("/data/doc%d.docx", i), 10, now)
		ev.Kind = event.KindFileCreate
		e.Apply(ev)
	}

	tv := e.Aggregate(7)
	if tv.ExtActivity[".docx"] != 4 {
		t.Fatalf("docx activity = %d, want 4", tv.ExtActivity[".docx"])
	}
}

// Unattributed file events must still reach scoring: entropy, magic bytes, and
// extension novelty are properties of the file, not the process. Discarding
// them made detection depend on attribution succeeding — which is exactly what
// the design claims it does not, and it made the detector blind on Linux where
// nothing gets attributed.
func TestUnattributedFileEventsFormAHostFingerprint(t *testing.T) {
	e := testEngine(t, time.Minute)

	e.Apply(event.Event{
		Kind:          event.KindFileWrite,
		PID:           0,
		Path:          "/data/report.docx",
		Bytes:         4096,
		Entropy:       7.9,
		MagicMismatch: true,
		Time:          time.Now(),
	})

	tv := e.Aggregate(0)
	if tv.Writes != 1 {
		t.Fatalf("host writes = %d, want 1", tv.Writes)
	}
	if tv.ProcName != HostName {
		t.Fatalf("host name = %q, want %q", tv.ProcName, HostName)
	}
	if tv.MagicMismatch != 1 || len(tv.Entropy) != 1 {
		t.Fatalf("host evidence lost: mismatches=%d, entropy samples=%d",
			tv.MagicMismatch, len(tv.Entropy))
	}

	roots := e.Roots()
	if len(roots) != 1 || roots[0] != 0 {
		t.Fatalf("roots = %v, want [0] so the host fingerprint is scored", roots)
	}
}

// The host fingerprint must not absorb process trees: a process whose parent is
// PID 0 is a root in its own right, not a child of the host bucket.
func TestHostFingerprintDoesNotAbsorbProcessTrees(t *testing.T) {
	e := testEngine(t, time.Minute)
	now := time.Now()

	e.Apply(event.Event{Kind: event.KindProcessStart, PID: 1, PPID: 0, ProcName: "init", Time: now})
	e.Apply(write(1, "/data/a.txt", 10, now))
	e.Apply(event.Event{Kind: event.KindFileWrite, PID: 0, Path: "/data/b.txt", Time: now})

	host := e.Aggregate(0)
	if len(host.PIDs) != 1 || host.PIDs[0] != 0 {
		t.Fatalf("host tree = %v, want just the host bucket", host.PIDs)
	}

	initTree := e.Aggregate(1)
	if initTree.Writes != 1 {
		t.Fatalf("init writes = %d, want 1 (its own, not the host's)", initTree.Writes)
	}
}

func TestReapReleasesStateAndOrphansChild(t *testing.T) {
	e := testEngine(t, time.Minute)
	now := time.Now()
	e.Apply(event.Event{Kind: event.KindProcessStart, PID: 20, ProcName: "parent", Time: now})
	e.Apply(event.Event{Kind: event.KindProcessStart, PID: 21, PPID: 20, ProcName: "child", Time: now})

	e.Reap(20)

	if e.Live() != 1 {
		t.Fatalf("live processes = %d, want 1", e.Live())
	}
	roots := e.Roots()
	if len(roots) != 1 || roots[0] != 21 {
		t.Fatalf("roots = %v, want [21] (orphan becomes a root)", roots)
	}
}

func TestReapUnknownProcessIsHarmless(t *testing.T) {
	e := testEngine(t, time.Minute)
	e.Reap(9999)
}

func TestWindowSnapshotMatchesAggregate(t *testing.T) {
	e := testEngine(t, time.Minute)
	now := time.Now()
	e.Apply(event.Event{Kind: event.KindProcessStart, PID: 3, ProcName: "solo", Time: now})
	e.Apply(write(3, "/data/a.bin", 42, now))

	win, ok := e.Window(3)
	if !ok {
		t.Fatal("window not found for a live process")
	}
	tv := e.Aggregate(3)

	if win.Writes != tv.Writes || win.Bytes != tv.Bytes {
		t.Fatalf("snapshot (%d writes, %d bytes) disagrees with aggregate (%d, %d)",
			win.Writes, win.Bytes, tv.Writes, tv.Bytes)
	}
}

func TestWindowMissingProcessReportsNotOK(t *testing.T) {
	e := testEngine(t, time.Minute)
	if _, ok := e.Window(1234); ok {
		t.Fatal("expected not-ok for an unknown process")
	}
}

func rename(pid int32, path string, at time.Time) event.Event {
	return event.Event{Kind: event.KindFileRename, PID: pid, Path: path, Time: at}
}

// An encryptor overwrites a file and renames it to a new extension, so its
// window is a run of write-then-rename chains. That is what the n-gram feature
// has to see, and what the signal reads.
func TestNGramReadsWriteToRenameChains(t *testing.T) {
	cfg := config.Default()
	cfg.Window.DecayHalfLife = config.Duration(time.Hour)
	cfg.Window.NGramLength = 4
	e := NewEngine(cfg)
	now := time.Now()

	e.Apply(event.Event{Kind: event.KindProcessStart, PID: 8, ProcName: "cryptor", Time: now})
	for i := range 10 {
		e.Apply(write(8, fmt.Sprintf("/data/doc%d.txt", i), 100, now))
		e.Apply(rename(8, fmt.Sprintf("/data/doc%d.txt", i), now))
	}

	ng := e.Aggregate(8).NGram
	if ng.K != 4 {
		t.Fatalf("k = %d, want 4 from window.ngram_length", ng.K)
	}
	if ng.Total != 17 {
		t.Fatalf("k-grams = %d, want 17 from 20 events", ng.Total)
	}
	// Ten write>rename pairs among nineteen adjacent transitions: every file's
	// write is followed by its rename, and each rename by the next write. The
	// share is a density over transitions, so it is a little over a half — not
	// one, which is what counting k-grams that merely contain a chain reported.
	if ng.RenameChains != 10 || ng.Pairs != 19 {
		t.Fatalf("chains = %d of %d adjacent transitions, want 10 of 19", ng.RenameChains, ng.Pairs)
	}
	if want := 10.0 / 19.0; math.Abs(ng.ChainShare-want) > 1e-9 {
		t.Fatalf("chain share = %.4f, want %.4f", ng.ChainShare, want)
	}
	if ng.Count != 9 {
		t.Fatalf("dominant k-gram count = %d, want 9", ng.Count)
	}
	if ng.Sequence != "file_write>file_rename" {
		t.Fatalf("dominant k-gram = %q, want %q", ng.Sequence, "file_write>file_rename")
	}

	win, ok := e.Window(8)
	if !ok || win.NGram != ng {
		t.Fatalf("window n-gram %+v disagrees with aggregate %+v", win.NGram, ng)
	}
}

// Sad path: a rename that no write precedes is not an encrypt-then-rename chain.
// Compilers, archive tools and installers create and rename files constantly;
// counting those would make the signal noise.
func TestNGramCountsOnlyRenamesThatFollowAWrite(t *testing.T) {
	cfg := config.Default()
	cfg.Window.DecayHalfLife = config.Duration(time.Hour)
	cfg.Window.NGramLength = 4
	e := NewEngine(cfg)
	now := time.Now()

	e.Apply(event.Event{Kind: event.KindProcessStart, PID: 9, ProcName: "installer", Time: now})
	for i := range 10 {
		e.Apply(event.Event{Kind: event.KindFileCreate, PID: 9, Path: fmt.Sprintf("/data/tmp%d", i), Time: now})
		e.Apply(rename(9, fmt.Sprintf("/data/tmp%d", i), now))
	}
	if ng := e.Aggregate(9).NGram; ng.RenameChains != 0 || ng.ChainShare != 0 {
		t.Fatalf("create-then-rename counted as a chain: %d of %d", ng.RenameChains, ng.Total)
	}

	// A plain bulk writer is one repeated kind, and no chain at all.
	e2 := NewEngine(cfg)
	e2.Apply(event.Event{Kind: event.KindProcessStart, PID: 10, ProcName: "backup", Time: now})
	for i := range 10 {
		e2.Apply(write(10, fmt.Sprintf("/data/f%d.txt", i), 10, now))
	}
	ng := e2.Aggregate(10).NGram
	if ng.RenameChains != 0 {
		t.Fatalf("write-only window reported %d chains", ng.RenameChains)
	}
	if ng.Sequence != "file_write" {
		t.Fatalf("dominant k-gram = %q, want %q", ng.Sequence, "file_write")
	}
}

// A k of 1 is a legal configuration, and a one-event sequence holds no
// transition, so no chain can be counted.
func TestNGramOneGramHoldsNoTransition(t *testing.T) {
	cfg := config.Default()
	cfg.Window.DecayHalfLife = config.Duration(time.Hour)
	cfg.Window.NGramLength = 1
	e := NewEngine(cfg)
	now := time.Now()

	e.Apply(event.Event{Kind: event.KindProcessStart, PID: 12, ProcName: "pair", Time: now})
	for i := range 10 {
		e.Apply(write(12, fmt.Sprintf("/data/f%d.txt", i), 10, now))
		e.Apply(rename(12, fmt.Sprintf("/data/f%d.txt", i), now))
	}

	ng := e.Aggregate(12).NGram
	if ng.Total != 20 {
		t.Fatalf("1-grams = %d, want 20", ng.Total)
	}
	if ng.RenameChains != 0 || ng.ChainShare != 0 {
		t.Fatalf("1-grams reported %d chains", ng.RenameChains)
	}
}

// Sad path: fewer events than k is not an observation of zero chains, it is no
// observation at all. The two must be distinguishable, or a quiet process looks
// like a benign one.
func TestNGramIsAbsentWhenTheWindowIsShorterThanK(t *testing.T) {
	e := testEngine(t, time.Hour)
	now := time.Now()
	e.Apply(event.Event{Kind: event.KindProcessStart, PID: 11, ProcName: "quiet", Time: now})
	for i := range 3 {
		e.Apply(write(11, fmt.Sprintf("/data/f%d.txt", i), 10, now))
	}

	ng := e.Aggregate(11).NGram
	if ng.Total != 0 || ng.RenameChains != 0 || ng.Sequence != "" {
		t.Fatalf("3 events produced an n-gram: %+v", ng)
	}
	if ng.K != 32 {
		t.Fatalf("k = %d, want the configured 32 so an unobserved window is explainable", ng.K)
	}
}

// A split workload has no chain in any one process, but its members' sequences
// concatenate at tree level — the same reasoning that makes the summed counters
// catch a split.
func TestTreeNGramSpansChildren(t *testing.T) {
	e := testEngine(t, time.Hour)
	now := time.Now()

	e.Apply(event.Event{Kind: event.KindProcessStart, PID: 30, ProcName: "parent", Time: now})
	e.Apply(write(30, "/data/parent.txt", 10, now))
	for pid := int32(31); pid <= 32; pid++ {
		e.Apply(event.Event{Kind: event.KindProcessStart, PID: pid, PPID: 30, ProcName: "worker", Time: now})
		for i := range 20 {
			e.Apply(write(pid, fmt.Sprintf("/data/child%d_%d.txt", pid, i), 10, now))
			e.Apply(rename(pid, fmt.Sprintf("/data/child%d_%d.txt", pid, i), now))
		}
	}

	// Each child alternates write, rename: twenty chains among thirty-nine
	// transitions. The tree reads one sequence over all members, so its chains
	// are the sum rather than the average — a split workload cannot hide its
	// shape by splitting it.
	child := e.Aggregate(31).NGram
	if child.RenameChains != 20 || child.Pairs != 39 {
		t.Fatalf("child chains = %d of %d adjacent transitions, want 20 of 39", child.RenameChains, child.Pairs)
	}
	tree := e.Aggregate(30).NGram
	if tree.RenameChains != 40 || tree.Pairs != 80 {
		t.Fatalf("tree chains = %d of %d, want the children's chains to survive aggregation",
			tree.RenameChains, tree.Pairs)
	}
}

// 2.7: samples live in a fixed-capacity ring, so a long-running process retains
// the newest ringCapacity events and nothing older. The oldest samples must be
// gone, and the counters must stop growing at the cap.
func TestRingWrapDropsOldestSamples(t *testing.T) {
	cfg := config.Default()
	cfg.Window.DecayHalfLife = config.Duration(time.Hour)
	e := NewEngine(cfg)
	now := time.Now()
	e.Apply(event.Event{Kind: event.KindProcessStart, PID: 42, ProcName: "looper", Time: now})

	for range 64 { // oldest: these slots get overwritten
		e.Apply(event.Event{Kind: event.KindFileDelete, PID: 42, Path: "/data/ancient/old.txt", Time: now})
	}
	for i := range ringCapacity {
		e.Apply(write(42, fmt.Sprintf("/data/bulk/f%d.txt", i), 10, now))
	}

	win, ok := e.Window(42)
	if !ok {
		t.Fatal("process vanished while it was still live")
	}
	if win.Deletes != 0 {
		t.Fatalf("deletes = %d, want 0: the 64 oldest samples must be gone", win.Deletes)
	}
	if win.Writes != ringCapacity {
		t.Fatalf("writes = %d, want the ring capped at %d, not %d",
			win.Writes, ringCapacity, ringCapacity+64)
	}
	if len(win.Dirs) != 1 {
		t.Fatalf("directories = %d, want 1 (/data/bulk only)", len(win.Dirs))
	}
	if want := ringCapacity - cfg.Window.NGramLength + 1; win.NGram.Total != want {
		t.Fatalf("n-gram input = %d events, want %d: the sequence must be bounded by the ring too",
			win.NGram.Total, want)
	}
	if e.Live() != 1 {
		t.Fatalf("live = %d, want 1", e.Live())
	}
}

// 2.7: memory tracks live processes. Reaping on exit has to return the count to
// zero across many start/exit cycles, including when the operating system reuses
// the same PID.
func TestProcessExitReleasesStateAcrossManyCycles(t *testing.T) {
	e := testEngine(t, time.Hour)
	now := time.Now()

	for cycle := range 500 {
		for pid := int32(1); pid <= 20; pid++ {
			e.Apply(event.Event{Kind: event.KindProcessStart, PID: pid, ProcName: "worker", Time: now})
			e.Apply(write(pid, fmt.Sprintf("/data/f%d.txt", pid), 4096, now))
			e.Apply(event.Event{Kind: event.KindProcessExit, PID: pid, Time: now})
		}
		if e.Live() != 0 {
			t.Fatalf("cycle %d: live = %d, want 0 once every process has exited", cycle, e.Live())
		}
	}
	if e.Live() != 0 || len(e.Roots()) != 0 {
		t.Fatalf("live = %d, roots = %v, want both empty", e.Live(), e.Roots())
	}
}

// A re-created PID starts from empty state: the old fingerprint was released,
// not accumulated.
func TestRecreatedProcessStartsFromEmpty(t *testing.T) {
	e := testEngine(t, time.Hour)
	now := time.Now()

	e.Apply(event.Event{Kind: event.KindProcessStart, PID: 77, ProcName: "first", Time: now})
	for i := range 3 {
		e.Apply(write(77, fmt.Sprintf("/data/old%d.txt", i), 100, now))
	}
	e.Apply(event.Event{Kind: event.KindProcessExit, PID: 77, Time: now})
	if e.Live() != 0 {
		t.Fatalf("live = %d after exit, want 0", e.Live())
	}

	e.Apply(event.Event{Kind: event.KindProcessStart, PID: 77, ProcName: "second", Time: now})
	e.Apply(write(77, "/data/new.txt", 7, now))

	tv := e.Aggregate(77)
	if tv.Writes != 1 || tv.Bytes != 7 {
		t.Fatalf("re-created process carries %d writes / %d bytes, want 1 / 7",
			tv.Writes, tv.Bytes)
	}
	if tv.CumFilesRewritten != 1 {
		t.Fatalf("cumulative files = %d, want 1: the previous incarnation's counters must be gone",
			tv.CumFilesRewritten)
	}
	if tv.ProcName != "second" {
		t.Fatalf("name = %q, want the new incarnation's name", tv.ProcName)
	}
}

// One write followed by one rename is a single transition, not a pattern.
// Counting k-grams that merely contain a chain made it saturate: at the default
// k=32 one adjacency lies inside up to 31 overlapping k-grams, so an editor's
// occasional atomic save read as a fully saturated encryption shape.
func TestNGramOneChainIsNotAPattern(t *testing.T) {
	cfg := config.Default() // k = 32
	cfg.Window.DecayHalfLife = config.Duration(time.Hour)
	e := NewEngine(cfg)
	now := time.Now()

	e.Apply(event.Event{Kind: event.KindProcessStart, PID: 13, ProcName: "editor", Time: now})
	for i := range 38 {
		e.Apply(write(13, fmt.Sprintf("/data/f%d.txt", i), 10, now))
	}
	e.Apply(rename(13, "/data/f37.txt", now)) // the one chain

	ng := e.Aggregate(13).NGram
	if ng.RenameChains != 1 {
		t.Fatalf("chains = %d, want the single adjacency", ng.RenameChains)
	}
	if ng.Pairs != 38 {
		t.Fatalf("pairs = %d, want 38 transitions from 39 events", ng.Pairs)
	}
	if ng.ChainShare > 0.05 {
		t.Fatalf("chain share = %.3f from one adjacency of %d transitions", ng.ChainShare, ng.Pairs)
	}
}

// A child that exits must leave its parent's child set. Leaving the dead PID
// there made a reused PID a member of the old tree, so an unrelated process's
// writes were charged to a parent that never spawned it.
func TestReapUnlinksTheDeadProcessFromItsParent(t *testing.T) {
	e := testEngine(t, time.Hour)
	now := time.Now()

	e.Apply(event.Event{Kind: event.KindProcessStart, PID: 20, ProcName: "explorer", Time: now})
	e.Apply(event.Event{Kind: event.KindProcessStart, PID: 21, PPID: 20, ProcName: "worker", Time: now})
	e.Apply(write(21, "/data/a.txt", 10, now))
	e.Apply(event.Event{Kind: event.KindProcessExit, PID: 21, Time: now})

	if kids := e.children[20]; len(kids) != 0 {
		t.Fatalf("parent still claims %d children after the child exited: %v", len(kids), kids)
	}
	if tree := e.Aggregate(20); len(tree.PIDs) != 1 || tree.PIDs[0] != 20 {
		t.Fatalf("parent tree = %v, want just the parent", tree.PIDs)
	}

	// The operating system hands the PID to an unrelated process.
	e.Apply(event.Event{Kind: event.KindProcessStart, PID: 21, PPID: 9999, ProcName: "stranger", Time: now})
	e.Apply(write(21, "/data/stranger.txt", 10, now))

	if tree := e.Aggregate(20); len(tree.PIDs) != 1 {
		t.Fatalf("a reused PID was walked into the old tree: %v", tree.PIDs)
	}
	roots := e.Roots()
	if len(roots) != 2 {
		t.Fatalf("roots = %v, want the parent and the stranger scored separately", roots)
	}
}

// The child index is the tree's index, so it has to shrink on exit. A
// long-lived parent — explorer, a shell, a service manager — otherwise keeps one
// entry per process it ever spawned.
func TestReapKeepsTheChildIndexBounded(t *testing.T) {
	e := testEngine(t, time.Hour)
	now := time.Now()
	e.Apply(event.Event{Kind: event.KindProcessStart, PID: 100, ProcName: "explorer", Time: now})

	for cycle := range 200 {
		for pid := int32(1000); pid < 1020; pid++ {
			e.Apply(event.Event{Kind: event.KindProcessStart, PID: pid, PPID: 100, ProcName: "worker", Time: now})
			e.Apply(event.Event{Kind: event.KindProcessExit, PID: pid, Time: now})
		}
		if kids := e.children[100]; len(kids) != 0 {
			t.Fatalf("cycle %d: parent holds %d child entries, want none", cycle, len(kids))
		}
	}
}
