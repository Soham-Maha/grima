package attrib

import (
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/prateekpurohit13/grima/internal/event"
)

// In correlation mode Resolve is the synchronous path the detector has always
// used: the event is attributed before the sensor moves on.
func TestResolveCorrelatesWithoutACausalSource(t *testing.T) {
	a := New(time.Second)
	a.Observe(77, "crypt", 4, `C:\Tools\crypt.exe`, 4096)

	recorder := newEmitRecorder(1)
	a.Resolve(event.Event{Kind: event.KindFileWrite, Path: `C:\data\a.txt`, Time: time.Now()}, recorder.emit)

	emitted := recorder.wait(t)
	if emitted[0].PID != 77 {
		t.Fatalf("pid = %d, want the correlated writer 77", emitted[0].PID)
	}
	if emitted[0].AttribConfidence != 1 {
		t.Fatalf("confidence = %v, want 1 for a single writer", emitted[0].AttribConfidence)
	}
	if got := a.Stats().Mode; got != modeCorrelate {
		t.Fatalf("mode = %q, want %q", got, modeCorrelate)
	}
}

// The failure table's ambiguous-attribution row, correlate half: when several
// processes are writing, the emitted event carries the top writer's share of
// recent bytes as its confidence rather than a claim of certainty. The event is
// still attributed and emitted; the confidence is what says the per-process
// blame is weak.
func TestResolveReportsLowConfidenceWhenWritersAreAmbiguous(t *testing.T) {
	a := New(time.Second)
	a.Observe(11, "heavy", 0, `C:\Tools\heavy.exe`, 9000)
	a.Observe(22, "light", 0, `C:\Tools\light.exe`, 1000)

	recorder := newEmitRecorder(1)
	a.Resolve(event.Event{Kind: event.KindFileWrite, Path: `C:\data\a.txt`, Time: time.Now()}, recorder.emit)

	emitted := recorder.wait(t)
	if emitted[0].PID != 11 {
		t.Fatalf("pid = %d, want the top writer 11", emitted[0].PID)
	}
	if c := emitted[0].AttribConfidence; c <= 0 || c >= 1 {
		t.Fatalf("confidence = %v, want strictly between 0 and 1 for two writers", c)
	}
}

// The point of the mechanism: a file event is blamed on the process the OS
// reported, even when another process was writing more bytes.
func TestResolveUsesTheCausalWriter(t *testing.T) {
	a, src := causalAttributor(t, 2*time.Second)
	a.Observe(1, "browser", 0, `C:\browser.exe`, 50_000_000)

	path := `C:\data\report.txt`
	observedAt := time.Now()
	recorder := newEmitRecorder(1)

	// The OS reports the writer after the sensor has already seen the change.
	go func() {
		time.Sleep(30 * time.Millisecond)
		src.deliver(Writer{Path: path, PID: 4242, Name: "crypt.exe", Exe: `C:\Tools\crypt.exe`, At: observedAt})
	}()

	a.Resolve(event.Event{Kind: event.KindFileWrite, Path: path, Time: observedAt}, recorder.emit)

	emitted := recorder.wait(t)
	if emitted[0].PID != 4242 {
		t.Fatalf("pid = %d, want the causally reported writer 4242", emitted[0].PID)
	}
	if emitted[0].ProcName != "crypt.exe" {
		t.Fatalf("name = %q, want crypt.exe", emitted[0].ProcName)
	}
	if emitted[0].AttribConfidence != 1 {
		t.Fatalf("confidence = %v, want 1 for an OS-reported writer", emitted[0].AttribConfidence)
	}
	if stats := a.Stats(); stats.CausalHits != 1 || stats.CausalMisses != 0 {
		t.Fatalf("stats = %+v, want one causal hit and no miss", stats)
	}
}

// Sad path: when the OS never reports a writer, the event is still attributed by
// correlation rather than dropped or left unattributed.
func TestResolveFallsBackWhenNoCausalRecordArrives(t *testing.T) {
	a, _ := causalAttributor(t, 50*time.Millisecond)
	a.Observe(31, "crypt", 0, `C:\Tools\crypt.exe`, 4096)

	recorder := newEmitRecorder(1)
	a.Resolve(event.Event{Kind: event.KindFileWrite, Path: `C:\data\a.txt`, Time: time.Now()}, recorder.emit)

	emitted := recorder.wait(t)
	if emitted[0].PID != 31 {
		t.Fatalf("pid = %d, want the correlated writer 31", emitted[0].PID)
	}
	if stats := a.Stats(); stats.CausalMisses != 1 {
		t.Fatalf("causal misses = %d, want 1", stats.CausalMisses)
	}
}

// Sad path: waiting must happen off the sensor's goroutine, or one slow report
// would stall every later event.
func TestResolveDoesNotBlockTheSensor(t *testing.T) {
	a, _ := causalAttributor(t, 3*time.Second)

	recorder := newEmitRecorder(1)
	start := time.Now()
	a.Resolve(event.Event{Kind: event.KindFileWrite, Path: `C:\data\a.txt`, Time: time.Now()}, recorder.emit)
	elapsed := time.Since(start)

	if elapsed > 100*time.Millisecond {
		t.Fatalf("Resolve took %s, want it to return immediately", elapsed)
	}
}

// Sad path: a full queue falls back to correlation and counts the drop, because
// stalling the sensor or growing without bound would both be worse.
func TestResolveFallsBackWhenTheQueueIsFull(t *testing.T) {
	a, _ := causalAttributor(t, 20*time.Millisecond)
	a.Observe(9, "crypt", 0, `C:\Tools\crypt.exe`, 4096)

	want := pendingCapacity * 4
	recorder := newEmitRecorder(want)
	for i := 0; i < want; i++ {
		a.Resolve(event.Event{Kind: event.KindFileWrite, Path: `C:\data\a.txt`, Time: time.Now()}, recorder.emit)
	}

	emitted := recorder.wait(t)
	if len(emitted) != want {
		t.Fatalf("emitted %d events, want %d", len(emitted), want)
	}
	if stats := a.Stats(); stats.PendingDrops == 0 {
		t.Fatal("want the overflow to be counted, not silently absorbed")
	}
}

// A source that never delivers must not slow every event for the rest of the
// run, and a record arriving later must switch the wait back on.
func TestResolveDegradesAndRecovers(t *testing.T) {
	a, src := causalAttributor(t, 5*time.Millisecond)

	recorder := newEmitRecorder(causalMissStreak + 1)
	for i := 0; i < causalMissStreak+1; i++ {
		a.Resolve(event.Event{Kind: event.KindFileWrite, Path: `C:\data\a.txt`, Time: time.Now()}, recorder.emit)
	}
	recorder.wait(t)

	if !a.Stats().Degraded {
		t.Fatal("want the attributor to stop waiting after a run of misses")
	}

	path := `C:\data\report.txt`
	at := time.Now()
	src.deliver(Writer{Path: path, PID: 5150, Name: "crypt.exe", At: at})

	recovered := newEmitRecorder(1)
	a.Resolve(event.Event{Kind: event.KindFileWrite, Path: path, Time: at}, recovered.emit)

	emitted := recovered.wait(t)
	if emitted[0].PID != 5150 {
		t.Fatalf("pid = %d, want the causally reported writer 5150", emitted[0].PID)
	}
	if a.Stats().Degraded {
		t.Fatal("want the attributor to resume waiting once records arrive again")
	}
}

// Sad path: shutting down must count the events it never resolved.
func TestCloseCountsQueuedEvents(t *testing.T) {
	a, src := causalAttributor(t, 3*time.Second)

	recorder := newEmitRecorder(1)
	for i := 0; i < 32; i++ {
		a.Resolve(event.Event{Kind: event.KindFileWrite, Path: `C:\data\a.txt`, Time: time.Now()}, recorder.emit)
	}

	if err := a.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	if stats := a.Stats(); stats.PendingDrops == 0 {
		t.Fatal("want the events left in the queue to be counted")
	}
	if !src.closed {
		t.Fatal("want the causal source to be closed with the attributor")
	}
	if a.Stats().Source.Errors != 0 {
		t.Fatalf("source errors = %d, want 0", a.Stats().Source.Errors)
	}
}

// Sad path: an event that arrives while the detector is shutting down is still
// attributed and emitted, and counted as one the causal path did not cover.
func TestResolveAfterCloseStillEmits(t *testing.T) {
	a, _ := causalAttributor(t, time.Second)
	a.Observe(9, "crypt", 0, `C:\Tools\crypt.exe`, 4096)
	if err := a.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	recorder := newEmitRecorder(1)
	a.Resolve(event.Event{Kind: event.KindFileWrite, Path: `C:\a.txt`, Time: time.Now()}, recorder.emit)

	emitted := recorder.wait(t)
	if emitted[0].PID != 9 {
		t.Fatalf("pid = %d, want the correlated writer 9", emitted[0].PID)
	}
	if a.Stats().PendingDrops == 0 {
		t.Fatal("want the event counted as unattributed")
	}
}

// Sad path: a source that cannot start leaves the attributor correlating rather
// than failing or looking healthy.
func TestAttachFailureKeepsCorrelation(t *testing.T) {
	a := New(time.Second)
	a.log = testLogger()
	src := &fakeSource{start: errSourceUnavailable}

	if err := a.attachSource(src, time.Second); err == nil {
		t.Fatal("want an error when the source cannot start")
	}
	if a.causal != nil || a.pending != nil {
		t.Fatal("want no causal state after a failed start")
	}

	a.Observe(5, "crypt", 0, "", 4096)
	recorder := newEmitRecorder(1)
	a.Resolve(event.Event{Kind: event.KindFileWrite, Path: `C:\a.txt`, Time: time.Now()}, recorder.emit)
	if pid := recorder.wait(t)[0].PID; pid != 5 {
		t.Fatalf("pid = %d, want the correlated writer 5", pid)
	}
}

// The trace names the mechanism behind each decision, so a run can be split into
// causal and correlated ones without re-running it.
func TestTraceNamesTheMechanism(t *testing.T) {
	a, path := traced(t, 10)
	a.log = testLogger()
	src := &fakeSource{}
	if err := a.attachSource(src, time.Second); err != nil {
		t.Fatalf("attach fake source: %v", err)
	}
	t.Cleanup(func() { _ = a.Close() })

	at := time.Now()
	watched := `C:\data\report.txt`
	src.deliver(Writer{Path: watched, PID: 77, Name: "crypt.exe", At: at})

	recorder := newEmitRecorder(1)
	a.Resolve(event.Event{Kind: event.KindFileWrite, Path: watched, Time: at}, recorder.emit)
	recorder.wait(t)

	lines := traceLines(t, path)
	if len(lines) != 1 {
		t.Fatalf("trace lines = %d, want 1", len(lines))
	}
	for _, want := range []string{`"pid":77`, `"source":"causal"`} {
		if !strings.Contains(lines[0], want) {
			t.Fatalf("trace line %s does not contain %s", lines[0], want)
		}
	}
}

// A correlated decision says so, so a causal run cannot be mistaken for a
// measured one.
func TestTraceMarksCorrelatedDecisions(t *testing.T) {
	a, path := traced(t, 10)
	a.Observe(9, "crypt", 0, "", 4096)

	recorder := newEmitRecorder(1)
	a.Resolve(event.Event{Kind: event.KindFileWrite, Path: `C:\a.txt`, Time: time.Now()}, recorder.emit)
	recorder.wait(t)

	lines := traceLines(t, path)
	if len(lines) != 1 || !strings.Contains(lines[0], `"source":"correlate"`) {
		t.Fatalf("trace line = %v, want the correlate source", lines)
	}
}

// Concurrency: the sensor keeps producing events while the detector shuts down
// and the health endpoint reads attribution state. Run under -race.
func TestConcurrentResolveCloseAndStats(t *testing.T) {
	a, _ := causalAttributor(t, 20*time.Millisecond)
	a.Observe(9, "crypt", 0, `C:\Tools\crypt.exe`, 4096)

	var wg sync.WaitGroup
	var emitted atomic.Uint64
	stop := make(chan struct{})

	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
					a.Resolve(event.Event{Kind: event.KindFileWrite, Path: `C:\a.txt`, Time: time.Now()},
						func(event.Event) { emitted.Add(1) })
				}
			}
		}()
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
				_ = a.Stats()
			}
		}
	}()

	time.Sleep(100 * time.Millisecond)
	if err := a.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	close(stop)
	wg.Wait()

	if emitted.Load() == 0 {
		t.Fatal("want events emitted while the detector was shutting down")
	}
}
