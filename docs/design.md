# GRIMA: Design & Interface Reference

This is the authoritative design document for GRIMA. It defines the frozen interfaces,
signal semantics, calibration model, fusion rules, and configuration surface. Where this
document and an implementation disagree, this document is the specification and the
implementation is the bug.

---

## Table of Contents

1. [Concepts](#1-concepts)
2. [The Event Contract (Frozen)](#2-the-event-contract-frozen)
3. [The Source Interface](#3-the-source-interface)
4. [The Event Bus](#4-the-event-bus)
5. [Signal Reference](#5-signal-reference)
6. [Fingerprint Engine Reference](#6-fingerprint-engine-reference)
7. [Calibration Reference](#7-calibration-reference)
8. [Scoring & Fusion Reference](#8-scoring--fusion-reference)
9. [Rule Reference](#9-rule-reference)
10. [Response Reference](#10-response-reference)
11. [Configuration Reference](#11-configuration-reference)
12. [Observability & Health](#12-observability--health)
13. [Error Handling](#13-error-handling)
14. [Testing Contract](#14-testing-contract)
15. [Non-Goals](#15-non-goals)

Architecture & layer mechanics: **`docs/architecture.md`**. Goals, roadmap, risks:
**`docs/plan.md`**.

---

## 1. Concepts

| Term | Meaning |
|---|---|
| **Event** | One observable system action: a file write, a process start, a persistence install. The single currency of the pipeline. |
| **Source** | A sensor that produces events. One implementation per OS capability. |
| **Bus** | Bounded, fan-out event queue with an explicit drop policy and drop counter. |
| **Window** | The decaying half of a process fingerprint: bounded counts over recent events. |
| **Cumulative counter** | The non-decaying half: totals of irreversible actions since process start. |
| **Fingerprint** | One process's `Window` plus its non-decaying cumulative counters. |
| **Tree vector** | The sum of fingerprints across an ancestor/process group. This is what gets scored. |
| **Baseline** | Host-specific measured distributions (entropy per extension, write-rate EWMA, host percentiles). |
| **Signal** | One named, normalized piece of evidence derived from a tree vector and a baseline. |
| **Override** | A signal class that sets a floor on the risk level rather than contributing to a weighted average. |
| **Verdict** | The scored output for one process or tree: score, level, contributing signals. |
| **Uncalibrated mode** | State before a baseline exists: overrides and absolute fallbacks only. |

---

## 2. The Event Contract (Frozen)

`internal/event` is the contract between collectors and everything above them. It is
**frozen**: adding a `Kind` is a compatible change; changing an existing field's meaning
is not.

```go
package event

type Kind uint8

const (
    KindUnknown Kind = iota
    KindProcessStart
    KindProcessExit
    KindFileCreate
    KindFileWrite
    KindFileRename
    KindFileDelete
    KindPersistenceInstall
    KindDecoyTouch
)

func (k Kind) String() string
```

```go
type Event struct {
    Seq      uint64    // assigned by the bus, monotonic per process
    Time     time.Time // wall clock at observation
    Kind     Kind
    Source   string    // emitting source name, for attribution and debugging

    // Actor
    PID      int32
    PPID     int32
    ProcName string
    Exe      string
    UID      uint32

    // Path
    Path     string    // primary path
    NewPath  string    // rename destination; empty unless KindFileRename

    // Content evidence (populated by FileWatch on write/create)
    Bytes         int64
    Entropy       float64 // Shannon entropy of sampled bytes, bits/byte
    MagicMismatch bool    // file magic disagrees with extension

    // Typed payloads
    DecoyID string    // set when Kind == KindDecoyTouch
    Persist string    // "cron" | "systemd" | "runkey" | "task" | "service"
}
```

### Field semantics

| Field | Semantics | Required for |
|---|---|---|
| `Seq` | Monotonic, assigned by the bus at publish. Used for ordering and dedup. | All |
| `Time` | Observation time, not event time. OS notification APIs do not supply the latter. | All |
| `PID` | The actor. Zero means unattributed. | All |
| `PPID` | Parent PID at observation time. Enables tree aggregation. | Process/file |
| `Path` | Absolute path where possible. | File kinds |
| `NewPath` | Rename destination. A rename to a previously-unseen extension is a primary signal. | `KindFileRename` |
| `Bytes` | Bytes written, when the OS reports it. Zero is legitimate (unknown), not an error. | `KindFileWrite` |
| `Entropy` | Shannon entropy $H = -\sum_i p_i \log_2 p_i$ over the head+tail sample. | `KindFileWrite` |
| `MagicMismatch` | True when the file's magic bytes contradict its extension. | `KindFileWrite` |
| `DecoyID` | Identifier of the touched canary, for post-incident attribution. | `KindDecoyTouch` |
| `Persist` | Which persistence mechanism was installed. | `KindPersistenceInstall` |

### Entropy sampling contract

`FileWatch` computes `Entropy` over a **head sample and a tail sample** (default 4 KiB
each), never the whole file. This is a specification, not an optimization:

- whole-file reads are unbounded I/O under an encryption storm and cause the sensor to
  fall behind the attack;
- head+tail also catches partial/intermittent encryption, which deliberately leaves the
  file's middle region in plaintext to depress whole-file entropy.

`Entropy` is `0` when the sample is empty or the file is unreadable. Consumers must
treat `0` as *unknown*, not as *low entropy*.

---

## 3. The Source Interface

```go
package sensor

type Source interface {
    Name() string
    Start(ctx context.Context, out chan<- event.Event) error
    Close() error
}
```

### Contract

1. `Start` returns once the source is observing, not when it finishes. It must not block
   for the lifetime of the process. For a source that must enumerate something before it can
   observe — FileWatch's directory tree — *observing* means at least one monitored root is
   watched: the remainder may be registered after `Start` returns, bounded by
   `filewatch.startup_deadline`, with the number still queued surfaced as `add_pending` in
   `/healthz`. A directory whose watch has not landed yet is covered by the overflow rescan
   until it does.
2. The source writes to `out` until `ctx` is cancelled or `Close` is called.
3. `Start` and `Close` are idempotent with respect to a second `Close` — closing twice
   must not panic.
4. A source that cannot observe on this host must return an error from `Start` and be
   skipped; it must not silently produce nothing. Silent no-op sensors are the failure
   mode that makes a detector look healthy while blind.
5. Sources must not block indefinitely on `out`. If the bus is saturated, apply the
   source's own bounded policy and count the loss.

---

## 4. The Event Bus

```go
package bus

type DropPolicy uint8

const (
    DropOldest DropPolicy = iota // default
    DropNewest
    Block                        // never used on the hot path
)

type Stats struct {
    Published uint64
    Dropped   uint64
    Subscribers map[string]uint64 // per-subscriber delivery counts
}

func New(capacity int, policy DropPolicy) *Bus
func (b *Bus) Publish(ev event.Event)
func (b *Bus) Subscribe(name string, capacity int) <-chan event.Event
func (b *Bus) Stats() Stats
func (b *Bus) Close()
```

### Semantics

- `Publish` **never blocks** under `DropOldest`/`DropNewest`. Under `Block` it blocks,
  which is provided for tests only.
- Every drop increments `Stats().Dropped`. Drops are never silent.
- `Subscribe` returns a receive-only channel. A slow subscriber does not stall other
  subscribers — each has its own buffer.
- The rule layer subscribes with a larger capacity than the fingerprint layer, because a
  dropped override is more costly than a dropped window sample.
- `Publish` assigns `Seq`.

**Rationale for bounded queues:** an encryption storm is an overload condition. An
unbounded queue converts overload into unbounded memory growth, which converts a
detection problem into an availability problem.

---

## 5. Signal Reference

Each signal is computed from a `TreeVector` and a `Baseline`, normalized to `0..1`, and
carries a human-readable `Detail` string. Every alert must be reconstructible from its
signals.

```go
package score

type Class uint8

const (
    ClassPrimary   Class = iota // carries a verdict on its own
    ClassSecondary              // corroborates: fuses only alongside a Primary
    ClassOverride               // sets a floor, never averaged
)

type Signal struct {
    Name   string
    Class  Class
    Value  float64 // normalized 0..1
    Detail string  // e.g. "entropy +4.1σ on 37 .docx files"
}
```

| # | Name | Class | Baseline input | Status |
|---|---|---|---|---|
| 1 | `entropy_deviation` | Primary | `EntropyByExt[ext]` | Implemented |
| 2 | `magic_mismatch` | Primary | none | Implemented |
| 3 | `write_burst` | Primary | `WriteRateByProc[name]`, falling back to `WriteRate` | Implemented |
| 4 | `create_burst` | Primary | `CreateRate` | Implemented |
| 5 | `rename_burst` | Primary | `RenameRate` | Implemented |
| 6 | `unknown_extension_activity` | Primary | `KnownExt` | Implemented |
| 7 | `delete_rate` | Secondary | `DeleteRate` | Implemented |
| 8 | `dir_fanout` | Secondary | `DirFanout` | Implemented |
| 9 | `cum_bytes_rewritten` | Secondary | none | Implemented |
| 10 | `write_rate_absolute` | Primary | none — uncalibrated fallback only | Implemented |
| 11 | `persistence_install` | Override | none | Implemented (rule `R-PERSIST-INSTALL`) |
| 12 | `static_reputation` | Secondary | none | **Phase 7** — not yet emitted |
| 13 | `decoy_touch` | Override | none | Implemented (rule `R-DECOY-TOUCH`) |
| 14 | `bus_drops` | Secondary | none | Implemented |
| 15 | `ngram_rename_chain` | Secondary | none — the window's own sequence | Implemented |

### Normalization rules

- Deviation signals clamp to `[0,1]` at a documented ceiling ($z \ge 6$ for entropy,
  $8\times$ baseline for rates). Unbounded normalization lets one runaway signal
  dominate fusion.
- **Signals below a noise floor of 0.05 are dropped.** Without this, a process that
  wrote a few kilobytes produces a verdict and every writing process looks like a
  detection.
- Deviation signals (`entropy_deviation`, `write_burst`, `rename_burst`,
  `unknown_extension_activity`, `delete_rate`, `dir_fanout`) compare against the baseline,
  so while the host is uncalibrated they are **unavailable** and are omitted from the
  signal list rather than reported as `0`. Reporting `0` would misrepresent *unknown* as
  *benign*. Signals that read the window's own contents — `magic_mismatch`,
  `cum_bytes_rewritten`, `bus_drops`, `ngram_rename_chain` — are available either way.
- `write_rate_absolute` exists precisely because omitting deviation signals leaves
  uncalibrated mode thin. It is a fixed bulk-modification threshold
  (`scoring.absolute_write_rate`, default 20/s) counting **writes and creates**, because bulk
  modification is what it thresholds and a create-only storm is bulk modification. It is
  superseded by `write_burst` and `create_burst` the moment a baseline exists.
- `Detail` strings must state the measured value and the comparison, never just a score.
- **Rates compare like with like.** Each burst signal is measured against a baseline of the
  same kind — writes against `WriteRate`, creates against `CreateRate`, renames against
  `RenameRate` — and each rate counts one event kind and only that kind. An earlier version
  kept one all-event rate; on a host with 404 processes that was dominated by process events
  (92.5/s measured), so a 65-file burst at 2.2 writes/s could never reach its threshold and
  `write_burst` was unreachable on a real machine. A subset rate must never be compared
  against a superset baseline, and the converse holds too: counting creates as writes made
  the write denominator a superset of the write numerator, which halved the apparent
  deviation of a create-heavy workload and made host and audit attribution disagree about
  the same one. `CreateRate` is what `create_burst` reads; `WriteRate` counts writes alone.
- **Creates are counted, so they are scored.** A process that only creates files — an
  unpacker, a restore, a locker writing a note in every directory — writes nothing the write
  counter records. `TreeVector.Creates` was populated and read by no signal, so a create-only
  storm was invisible in both modes: measured, **12,026 create events in one second produced
  no verdict at all**. `create_burst` closes that, and the uncalibrated fallback counts
  creates because with no baseline there is no create rate to compare against.
- **A measured zero rate is not an absent one.** A warm-up on a quiet host records
  `rename_rate = 0` and `delete_rate = 0`, which is a measurement: the host never performed
  the action. Comparing a burst against that zero disables the signal — division by zero if
  taken literally, and in the shipped code an early return — so the one signal that could
  see a rename storm on a quiet host stayed dead for the life of the deployment while
  `/healthz` reported `calibration_ready: true`. Measured consequence: **80 renames in one
  second produced no verdict at all** on a host calibrated during a quiet window.
  A zero-mean distribution is therefore floored at the smallest burst that counts as
  evidence (`scoring.zero_baseline_burst`, default 25 events per window), which keeps the
  ratio finite and the signal available while stopping one ordinary event from saturating
  it: the same host stays silent through an editor's occasional atomic save and still sees
  a mass rename.
- **No samples is different from zero.** A distribution with `N == 0` was never measured,
  so the signal reading it is omitted even when the activity is enormous. `Ready()` is a
  single gate over the whole baseline and cannot express this; `Baseline.Coverage()` reports
  the sample count behind each distribution, and `/healthz` publishes them as
  `baseline_samples_*` so that "calibrated" is not read as "every signal is live".

### Why `unknown_extension_activity` rather than a rename signal

`fsnotify` reports a rename's *source* path, not its destination — the destination
arrives as a separate create event. A signal keyed on rename destinations would therefore
never fire. Counting writes and creates per extension captures the same evidence (a mass
rename to `.locked` shows up as a burst of creates on an extension the host has never
seen) using data that is actually available. The n-gram signal (#14) is unaffected by
this: it reads the *kind* of each event, not its destination.

---

## 6. Fingerprint Engine Reference

```go
package fingerprint

// TreeVector is the summed fingerprint of a process and all its descendants.
type TreeVector struct {
    Root     int32
    ProcName string
    PIDs     []int32

    // Decaying track: bounded by the ring and aged out by decay_half_life.
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

    // Non-decaying track.
    CumFilesRewritten int64
    CumBytesRewritten int64
    ExtActivity       map[string]int64

    WindowDuration time.Duration
}

type EntropySample struct{ Ext string; H float64 }

type Engine struct { /* single-writer; see docs/architecture.md §12 */ }

func NewEngine(cfg config.Config) *Engine
func (e *Engine) Apply(ev event.Event)
func (e *Engine) Window(pid int32) (Window, bool)
func (e *Engine) Snapshot() map[int32]Window
func (e *Engine) Roots() []int32
func (e *Engine) Aggregate(root int32) TreeVector
func (e *Engine) Reap(pid int32)
func (e *Engine) Live() int
```

### Semantics

- `Apply` is called from exactly one goroutine. No internal locking.
- The decaying track ages out entries older than `window.decay_half_life`. Samples live in
  a fixed-capacity ring (`ringCapacity`, 4096), so memory is bounded by live process count
  rather than uptime: once the ring is full the oldest sample is overwritten and no longer
  counted, and the kind sequence the n-gram reads is bounded by the same cap.
- The cumulative track **never decays**. This is the mechanism that answers Gap 4.
- `ExtActivity` counts writes and creates per extension, cumulatively. It is what
  `unknown_extension_activity` reads, and it needs no file content — so it survives the
  race where a file is renamed before the sensor can read it.
- `Aggregate(root)` sums the fingerprint of `root` and every descendant, and is what
  scoring consumes.
- `Reap(pid)` releases state on `KindProcessExit`, re-parenting orphans to root rather
  than dropping them from the tree.
- Events with `PID == 0` are **not discarded**: they go into a host-level fingerprint
  (`HostName`, PID 0) so their file-derived evidence still reaches scoring. Detection must
  not depend on attribution succeeding — see `sprints.md` §13.

### Event-kind n-grams

The ring records the `Kind` of every sample, so a window is also a short sequence of event
kinds (`file_write, file_rename, file_write, …`). `Window` and `TreeVector` expose it as
`NGram`, computed over the samples still inside the decay window with
$k = \texttt{window.ngram\_length}$:

```go
type NGram struct {
    K            int     // k, from window.ngram_length
    Total        int     // k-grams observed in the window
    Sequence     string  // the most frequent k-gram, reduced to its cycle when it repeats
    Count        int     // occurrences of Sequence
    RenameChains int     // k-grams containing a write followed by a rename
    ChainShare   float64 // RenameChains / Total
}
```

- The feature separates encryption from ordinary modification by *shape*. An encryptor
  overwrites a file and then renames it to a new extension, so its window is dense in
  `file_write → file_rename` transitions; a compiler, archiver or backup writes and
  renames nothing, so its share is zero.
- Only a **write** followed by a **rename** counts. A `file_create → file_rename` pair is
  not a chain: installers, editors and compilers do that constantly.
- `Total == 0` means the window held fewer than `k` events — no observation, which is not
  the same as "no chains". The scorer emits the signal only when `Total` and
  `RenameChains` both clear a floor.
- The tree aggregate reads one sequence over the whole tree (each member's in-window
  samples in walk order), so a split workload's shape survives aggregation rather than
  being averaged across children.
- k-grams are counted by rolling hash over a sequence bounded by `ringCapacity`, and the
  ring is the only storage, so the feature adds no retained state.
- Measured on Windows with the real sensor, the shape is narrower than it looks. An
  atomic save over an existing file arrives as `create, write, delete, rename` — the temp
  file's removal is reported as a delete between the write and the rename — so it produces
  **no chain at all**, and editors and config managers stay silent. An extractor,
  installer or release script that renames a new file to a new name arrives as
  `create, write, rename`, which reaches the same value an encryptor reaches
  (`write, rename, create`): the two cycles are *rotations* of one another, so this
  feature cannot separate extraction from encryption. That separation is left to the
  content signals — hence the deliberately low weight below.
- Because of that overlap the signal ships with a **weight of 0.2**, where `bus_drops`
  sits: at full value a benign extraction scores 20 — under the medium alert band — so it
  corroborates the content signals on a real encryptor instead of raising an alert by
  itself. Weight is not safety, only margin: measured against the fusion, the signal still
  lifts a companion score of 31–45 (below the medium band on its own) over it, so a benign
  extraction that also shows a mild content deviation reaches medium, and the signal is
  what carries it there. Sprint 4's ablation has to price that per scenario before the
  paper cites it.

`score` turns it into signal #14, `ngram_rename_chain`; whether it earns its weight is
Sprint 4's ablation. Item 2.1 is closed by this — the gap it recorded (a parsed-but-unread
`window.ngram_length`) no longer exists.

---

## 7. Calibration Reference

```go
package calibrate

type Dist struct {
    Mean   float64
    StdDev float64
    N      int
}

type Baseline struct {
    Version         int
    Host            string
    CapturedAt      time.Time
    WarmupSeconds   float64
    MinSamples      int
    SigmaFloor      float64
    EntropyByExt    map[string]Dist
    WriteRateByProc map[string]float64

    // Per-second rates for file events, split by kind so each burst signal
    // compares like with like. Process events are excluded: they outnumber file
    // events on a busy host and would mask every file-derived burst.
    WriteRate     Dist
    RenameRate    Dist
    DeleteRate    Dist
    FileEventRate Dist

    DirFanout Dist
    KnownExt  []string
}

func Capture(ctx context.Context, cfg config.Config, bus *bus.Bus) (*Baseline, error)
func Recalibrate(ctx context.Context, cfg config.Config, bus *bus.Bus, base *Baseline) (*Baseline, error)
func (b *Baseline) Merge(fresh *Baseline) (int, error)
func Load(path string) (*Baseline, error)
func (b *Baseline) Save(path string) error
func (b *Baseline) Ready() bool
```

### Semantics

- `Capture` observes the host for `calibration.warmup` and records distributions. It
  runs before scoring is enabled.
- `Ready()` reports whether the baseline has enough samples to be used
  (`N >= calibration.min_samples`). Before that, GRIMA runs in uncalibrated mode.
- `StdDev` of `0` is replaced with a floor (`calibration.entropy_sigma_floor`, default
  `0.05`) to avoid division by zero on extensions that are always identical.
- Persisted as JSON at `calibration.baseline_path`. **Schema version 3.** A version
  mismatch is ignored rather than fatal, so a v2 baseline captured before `create_rate`
  existed puts the detector in uncalibrated mode and is re-captured by running
  `--calibrate`. The bump is required rather than cosmetic: v2 counted creates as writes in
  `WriteRate`, so an old file's write distribution is a superset of what `write_burst` now
  measures against it.
- `Recalibrate` observes a fresh window, merges it into an existing baseline with
  `Merge`, and returns the result. Reachable from the command line as `--recalibrate`;
  the detector exits after saving. This is the feedback edge in the architecture diagram.

### Known limitation: recalibration does not fix `dir_fanout`

Recalibration silences novelty and rate deviations. It does **not** silence fan-out.

`dir_fanout` compares a tree's distinct-directory count against the pooled host mean:
$\text{value} = \mathrm{clamp}_{[0,1]}\left(\frac{dirs/mean - 1}{7}\right)$ at weight 0.5, so
alone it reaches the 45 medium threshold at roughly **7×** the pooled host mean. In a
measured v2 run the pooled mean after recalibration was 5.44 (n=9), so a confirmed-benign
workload touching about 40 directories still alerts at medium *after* recalibration.

The exit criterion therefore holds only below that ratio — the honest boundary, rather than
one measured pair. The fix is per-process directory-fanout profiles instead of a single
pooled host distribution: Sprint 4 work, and it should be measured before `dir_fanout` is
relied on.

---

## 8. Scoring & Fusion Reference

```go
package score

type Level uint8

const (
    LevelInfo Level = iota
    LevelLow
    LevelMedium
    LevelHigh
    LevelCritical
)

type Verdict struct {
    PID         int32
    ProcName    string
    Score       float64 // 0..100
    Level       Level
    Signals     []Signal
    Override    string // rule ID that set the floor; empty if none
    Calibrated  bool
    EvaluatedAt time.Time
}

func (s *Scorer) Evaluate(tv fingerprint.TreeVector, b *calibrate.Baseline) Verdict
```

### Fusion algorithm

1. **Independent evidence, not an average.** Signals combine as
   $\text{score} = 100 \left(1 - \prod_i \left(1 - \mathrm{clamp}_{[0,1]}(w_i \cdot v_i)\right)\right)$
   over Primary and Secondary signals, where $w_i$ comes from configuration. The product
   is taken over every Primary signal, and over Secondary signals **only while at least one
   Primary is present**; Secondary-only evidence is reported in `Signals` but does not fuse.

   This is noisy-OR, and the choice is deliberate. A weighted mean is **not monotonic**:
   adding a weak signal lowers the score, so a saturated signal alone scored 100 while the
   same signal alongside three weaker ones scored 56.4 — more evidence of the same attack
   reading as less severe. That is not a hypothetical: it is the difference between a local
   run and CI on an identical scenario (`sprints.md` §15). A risk score must be monotonic in
   its evidence, so evidence can only add.

   The corroboration gate is structural, not arithmetic (`sprints.md` §18, Sprint 4 item
   4.9). A Secondary may not carry a verdict: bounding each Secondary's weight below the band
   leaves combinations unbounded and ties the tier's meaning to the band value. Measured with
   the shipped weights, all five Secondary signals saturated with no Primary present fused to
   86.2 high before the gate.
2. **Override floor.** For each Override signal present, `level = max(level, rule_severity)`
   and `Override` is set to the rule ID. Overrides are **never** combined; they set a
   minimum.
3. **Decay.** The decaying track's contribution is reduced by
   `exp(-Δt / decay_half_life)` when no further suspicious activity follows. The
   cumulative track is exempt.
4. **Level mapping.** Score bands map to levels via configuration
   (`scoring.level_bands`), and the override floor may raise the final level above the
   band implied by score alone.

### Invariants

- A verdict with a non-empty `Override` has `Level >= rule_severity`.
- A verdict in uncalibrated mode has `Calibrated == false` and contains no
  deviation-based signals.
- `Signals` is never empty for `Level >= LevelMedium`. A medium-or-higher alert without
  stated evidence is a bug, not a detection.
- `Level >= LevelMedium` implies at least one Primary signal contributed, or an Override set
  the floor. Secondary signals never carry a verdict on their own, in any combination.

---

## 9. Rule Reference

```go
package rules

type Hit struct {
    RuleID   string
    Severity score.Level
    Detail   string
}

type Rule struct {
    ID          string
    Description string
    Severity    score.Level
    Match       func(event.Event) bool
}

type Engine struct { /* ... */ }

func NewEngine(cfg config.Config) *Engine
func (e *Engine) Evaluate(ev event.Event) (Hit, bool)
```

### Semantics

- Rules are **pure predicates over a single event**. No cross-event state, no window
  dependency. This keeps them instantaneous and trivially testable.
- Rules subscribe to the bus directly, so they are evaluated on arrival rather than at
  the next scoring tick.
- A rule hit produces an Override-class signal. It sets a floor; it does not add.
- Rules are data-driven where possible (`configs/grima.example.toml` lists process names
  and command patterns) so operators can extend them without a rebuild.

### Initial rule set

| Rule ID | Severity | Trigger |
|---|---|---|
| `R-SHADOW-DELETE` | Critical | `vssadmin delete shadows`, `wmic shadowcopy delete`, `wbadmin delete catalog`, `bcdedit /set recoveryenabled no` |
| `R-EVENTLOG-CLEAR` | Critical | `wevtutil cl` |
| `R-USN-DELETE` | High | `fsutil usn deletejournal` |
| `R-BACKUP-KILL` | High | Termination of configured backup/database process names |
| `R-DECOY-TOUCH` | Critical | `KindDecoyTouch` |
| `R-PERSIST-INSTALL` | Medium | `KindPersistenceInstall` |
| `R-MASS-RENAME` | High | Rename burst to a previously-unseen extension |

Detection logic for the first four is derived from published rule corpora; attribution
is recorded in `THIRD_PARTY_NOTICES.md`.

---

## 10. Response Reference

```go
package response

type Action uint8

const (
    Observe Action = iota
    Alert
    Suspend
)

type Handler struct { /* ... */ }

func NewHandler(cfg config.Config) *Handler
func (h *Handler) Apply(v score.Verdict) error
```

| Action | Effect | Default |
|---|---|---|
| `Observe` | Record the verdict; no side effect | **Yes** |
| `Alert` | Emit to the configured sink (log, file, webhook) | On `>= alert_min_level` |
| `Suspend` | `SIGSTOP` (POSIX) / `NtSuspendProcess` (Windows) | Opt-in only |

**Suspension is opt-in and gated.** Terminating or suspending a process on a heuristic
score is a denial-of-service primitive; a false positive against a database process is
worse than a missed detection that alerts. `response.suspend_min_level` must be
`Critical` and `response.enable_suspend` must be explicitly set.

**Alerts throttle per incident.** The score loop emits a verdict on every tick, so a
persistent condition would otherwise log an alert every second. An *incident* is
identified by the verdict's tree root — the process, or the host when no process is
claimed — and `response.alert_cooldown` holds further alerts for that root until it
elapses. An incident ends when a verdict below `alert_min_level` reaches the responder
(its next rise then alerts immediately), or, if the root stops carrying evidence
entirely, when the cooldown elapses. A zero cooldown disables throttling and is the
default, so alert emission is unchanged unless opted into. Throttling gates only the
alert log; the verdict stream and the dashboard are unaffected.

---

## 11. Configuration Reference

TOML, loaded from `--config`. An annotated example lives at
`configs/grima.example.toml`. Defaults are chosen so the binary runs with no config file
at all, in observe-only mode.

```toml
[general]
monitor_paths  = ["/home", "/srv"]     # directories to watch
log_level      = "info"

[bus]
capacity       = 8192
drop_policy    = "drop_oldest"

[filewatch]
entropy_sample_bytes = 4096            # per head/tail sample
rescan_on_overflow   = true

[decoy]
enabled        = true
names          = ["_grima_canary.doc", "quarterly_report.xlsx"]
count_per_dir  = 2
max_depth      = 0                     # 0 plants in the monitored roots only
manifest_path  = "grima-decoys.json"   # records what was planted, for --remove-decoys

[window]
decay_half_life = "30s"
ngram_length    = 32

[calibration]
warmup         = "10m"
min_samples    = 200
baseline_path  = "grima-baseline.json"
entropy_sigma_floor = 0.05

[scoring]
level_bands        = { low = 20, medium = 45, high = 70, critical = 88 }
absolute_write_rate = 20               # used only while uncalibrated
[[scoring.weights]]
name = "entropy_deviation"
weight = 1.0
# ... one entry per signal

[response]
enable_suspend    = false
suspend_min_level = "critical"
alert_min_level   = "medium"
alert_cooldown    = "0s"               # 0 disables per-incident alert throttling

[web]
enabled = true
listen  = "127.0.0.1:8787"
```

### Decoy planting is bounded and recorded

Planting decoys writes real files into directories the operator monitors. That is a side
effect on the filesystem, not only on the detector, so two rules apply:

- **Depth is bounded and defaults to zero.** Decoys go in the monitored roots and nowhere
  else unless `decoy.max_depth` asks for more. Recursing to depth 3 with `count_per_dir = 2`
  writes two plausible-looking documents into *every* directory of the tree — measured at
  **66 files across 33 directories from a three-second run** over a small tree — and on a
  real home directory that is thousands of files appearing in the user's folders, their
  version control and their backups, under names designed to look like the user's own work.
- **Every planted path is recorded, and the run has an undo.** `decoy.manifest_path` is a
  union across runs, so `grima --remove-decoys` removes decoys planted earlier, or under a
  different depth, and works after a restart or a crash. Removal only deletes a file whose
  contents are still the canary body: a path the user has since replaced with a real
  document is left in place and reported as skipped. The manifest says where the tool wrote,
  not that whatever is there now belongs to it.

`decoy.manifest_path` is required while decoys are enabled — planting without a record is
planting files that can never be removed.

---

## 12. Observability & Health

GRIMA reports on itself, because a detector that is silently blind is worse than no
detector.

| Metric | Meaning | Surfaced where |
|---|---|---|
| `bus.published` | Events published | `/healthz`, dashboard |
| `bus.dropped` | Events dropped (overload evidence) | `/healthz`, dashboard, signal #13 |
| `sensor.<name>.events` | Per-source event count | `/healthz` |
| `sensor.<name>.errors` | Per-source error count | `/healthz` |
| `watch.failures` | inotify watch exhaustion / RDCW overflow | `/healthz` |
| `history.size` / `history.depth` | Verdicts held on the timeline | `/healthz`, dashboard |
| `history.dropped` | Verdicts overwritten because the ring is full | `/healthz`, dashboard |
| `calibration.ready` | Whether deviation signals are active | dashboard banner |
| `calibration.age` | Time since baseline capture | dashboard |
| `baseline.samples.<dist>` | Samples behind each baseline distribution | `/healthz` |

`/healthz` returns JSON. The dashboard shows a persistent banner while in uncalibrated
mode, so an operator never mistakes "no alerts" for "calibrated and quiet."

`calibration.ready` answers "is there a baseline?", not "is every signal live?". A baseline
captured on a quiet host has no samples for some distributions, and the signals reading
them are omitted — `baseline.samples.<dist>` is what distinguishes that from a quiet host.
A zero there is an unavailable signal, not a silent one.

### The verdict history

The dashboard is not a current-state view only: an incident that has already scrolled past
must remain readable, or the operator sees a decaying score and no record of what happened.

| Endpoint | Returns |
|---|---|
| `/api/verdicts` | The latest verdict per root, highest score first |
| `/api/trees` | The same, grouped into trees with their contributing processes |
| `/api/history` | `{entries, size, dropped, depth}` — recorded verdicts **oldest first**, each with its timestamp, level, score and signals |
| `/events` | Server-sent events, one tree per message, for live updates |

The history is a **bounded in-memory ring** (`historyDepth`, 4096 entries — tens of minutes
at the default scoring cadence). It is deliberately not a database: this is a proof of
concept, and a detector that grows without bound under a storm is the failure it exists to
catch. When the ring wraps, the overwritten count is incremented and surfaced through
`/healthz` and the payload, so a dashboard says "showing the last N, M overwritten" rather
than implying the record is complete. This is the same rule as every other bounded queue in
the system: **drops are counted, never silent.**

It records the verdicts the detector **reports** — those with evidence or a level at or above
`low` — not every scoring tick. A quiet host therefore contributes no points, and the timeline
is a record of findings rather than a continuous score trace: an incident appears as a run of
points and then stops, which is the moment the evidence left the window. Recording every tick
instead would fill the ring in about an hour of idleness and bury the findings in noise.

---

## 13. Error Handling

- Sensor failures are **non-fatal and loud**. One failing source degrades coverage; it
  does not stop the pipeline. The failure is counted and surfaced.
- A malformed or version-mismatched baseline is ignored with a warning; GRIMA falls back
  to uncalibrated mode rather than refusing to start.
- Rule predicate panics are recovered and counted. A broken rule must not take down the
  detector.
- All errors carry the source name and the event sequence number when an event is
  involved.

---

## 14. Testing Contract

- The event schema is frozen; tests assert on `Event` values, not on sensor internals.
- The fingerprint engine is single-writer, so tests drive it directly with synthetic
  events and assert on window state — no timing, no sleeps, deterministic.
- Rules are pure predicates; each rule gets a table-driven test over events that should
  and should not match.
- Scoring is tested against synthetic baselines with known distributions, asserting that
  $z$-score normalization and clamping behave at the boundaries ($z=0$, $z=6$, $\sigma=0$
  floor).
- A bus test asserts that drops are counted rather than lost silently.

Tests must assert **observable contract**: window counts, verdict levels, signal
presence, drop counters. They must not assert implementation details such as internal
map identities or log wording.

---

## 15. Non-Goals

- Kernel drivers, minifilters, or eBPF programs. User space only.
- Machine learning of any kind. No training, no pretrained artifacts, no inference
  runtime.
- Pre-execution blocking. GRIMA observes; it does not gate execution.
- Decryption, key recovery, or file restoration.
- Network traffic inspection or C2 detection.
- Multi-host correlation or a central management server. Single host, single binary.
