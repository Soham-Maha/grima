# SKILLS — GRIMA Operational Runbook

Concrete procedures for building, running, calibrating, and evaluating GRIMA. Each entry
is a self-contained task with the exact commands and the observable result that confirms
it worked.

Interfaces and semantics live in `docs/design.md`. Layer structure lives in
`docs/architecture.md`. This file is *how to operate the thing*.

---

## Table of Contents

1. [Build and run](#1-build-and-run)
2. [Cross-compile for another platform](#2-cross-compile-for-another-platform)
3. [Capture a host baseline](#3-capture-a-host-baseline)
4. [Run a detection scenario](#4-run-a-detection-scenario)
5. [Read the dashboard and health endpoint](#5-read-the-dashboard-and-health-endpoint)
6. [Add a sensor](#6-add-a-sensor)
7. [Add a rule](#7-add-a-rule)
8. [Add a signal](#8-add-a-signal)
9. [Tune fusion weights](#9-tune-fusion-weights)
10. [Reproduce a detection](#10-reproduce-a-detection)
11. [Diagnose "no alerts"](#11-diagnose-no-alerts)
12. [Measure false positives on a benign workload](#12-measure-false-positives-on-a-benign-workload)
13. [Run the ablation](#13-run-the-ablation)
14. [Debug a wedged pipeline](#14-debug-a-wedged-pipeline)
15. [Coding conventions](#15-coding-conventions)
16. [Measure attribution accuracy](#16-measure-attribution-accuracy)

---

## 1. Build and run

```sh
make build
./grima --version
./grima --config configs/grima.example.toml
```

**Expected:** binary builds with no cgo; on start it logs the detected platform, the
sources it started, calibration status, and the web listen address. Verdicts at
`medium` or above print to stdout.

Run for a bounded time (useful for smoke tests and CI):

```sh
./grima --config configs/grima.example.toml --duration 30s
```

**Expected:** exits cleanly after 30s with a summary line: events published, events
dropped, verdicts emitted.

---

## 2. Cross-compile for another platform

**Cross-compiling is not verification.** It proves the code builds for that platform, not
that the sensors observe anything there. Windows and Linux are verified by the CI workflow;
**macOS is not** — see `docs/sprints.md` §10.

```sh
make cross
ls -la dist/
```

**Expected:** four binaries — `grima-linux-amd64`, `grima-linux-arm64`,
`grima-windows-amd64.exe`, `grima-darwin-arm64`. Verify the static-link claim:

```sh
file dist/grima-linux-amd64        # "statically linked"
```

If `file` reports dynamic linking, something pulled in cgo. Find it:

```sh
CGO_ENABLED=0 go build -x ./cmd/grima 2>&1 | grep -i cgo
```

---

## 3. Capture a host baseline

Calibration must run on the host that will be monitored, during representative activity.
A baseline captured on an idle machine will flag everything.

```sh
# Capture for 10 minutes and write the baseline
./grima --config configs/grima.example.toml --calibrate --duration 10m

# Inspect what was learned
cat grima-baseline.json | jq '.EntropyByExt | to_entries | sort_by(.value.N) | .[-10:]'
```

**Expected:** `grima-baseline.json` contains `EntropyByExt` with a `(Mean, StdDev, N)`
triple per extension, `WriteRateByProc` with an EWMA per process name, and host-wide
percentiles. Extensions with low `N` are unreliable — raise `calibration.min_samples`
rather than trusting them.

**Calibrate against activity, not an idle machine.** A warm-up over a quiet host records
nothing and produces a baseline that is silently useless. Confirm the capture produced
samples before trusting it:

```sh
jq '[.entropy_by_ext[].n] | add' grima-baseline.json   # must be > 0
```

If that prints `0`, the host was idle. Drive ordinary work during the warm-up — or for a
test fixture, write to the monitored directory in a loop — and capture again. Verified
symptom: calibrating a static fixture directory logs
`baseline written ... extensions=0 processes=0`, and every deviation signal is then
permanently unavailable.

**Verify it loaded on the next run:** the dashboard must *not* show the uncalibrated
banner, and `/healthz` must report `"calibration_ready": true`.

**Do not commit the baseline.** It is host-specific and `.gitignore` excludes it.

### Recalibrating

When a legitimate workload keeps alerting, fold a window of it into the existing baseline
rather than re-capturing from scratch — re-capturing discards everything learned:

```sh
# Confirm the workload is benign, then let it run during the warm-up
./grima --config configs/grima.example.toml --recalibrate
```

It loads the current baseline, observes for `calibration.warmup`, merges the new
observations, saves, and exits. Running it with no baseline present is an error, not a
silent capture — run `--calibrate` first.

**Recalibration does not fix everything.** It promotes observed extensions and re-averages
per-process write rates, but a workload touching far more directories than any other process
still moves `dir_fanout` against the pooled host mean. See `docs/design.md` §7.

---

## 4. Run a detection scenario

**Run the whole thing end to end first.** `testdata/scenarios/smoke.sh` builds the
fixture, captures a baseline against it, runs a benign workload that must not alert, then
runs the encryptor and checks that it does:

```sh
make build
bash testdata/scenarios/smoke.sh
```

It exits non-zero on any violated expectation, so it is the fastest way to tell whether a
change broke detection.

To drive it by hand instead, use two halves: a benign workload (must not alert) and a
controlled encryptor (must alert).

```sh
# Terminal 1 — monitor
./grima --config configs/grima.example.toml --duration 5m

# Terminal 2 — benign bulk I/O (must NOT alert)
mkdir -p /tmp/grima-scratch && cd /tmp/grima-scratch
for i in $(seq 1 500); do head -c 200000 /dev/urandom > f$i.bin; done
tar czf archive.tgz f*.bin

# Terminal 3 — controlled encryptor (MUST alert)
python3 testdata/scenarios/encryptor.py --path /tmp/grima-scratch --rate burst
```

**Expected:**
- The benign burst produces no `medium`-or-higher verdict.
- The encryptor produces a `high`/`critical` verdict within the configured window, with
  signals naming entropy deviation, write burst, and (if it renames) rename-to-unknown
  extension.

Rates to test — all three must be detected, which is the whole point of the dual-track
design:

```sh
python3 testdata/scenarios/encryptor.py --path /tmp/grima-scratch --rate burst        # ~500 files/s
python3 testdata/scenarios/encryptor.py --path /tmp/grima-scratch --rate drip         # 1 file / 5s
python3 testdata/scenarios/encryptor.py --path /tmp/grima-scratch --rate intermittent # partial-region encryption
```

**`drip` is the critical case.** If burst is caught and drip is not, the cumulative track
is broken — see §8.

---

## 5. Read the dashboard and health endpoint

```sh
./grima --config configs/grima.example.toml
# then, in a browser:
#   http://127.0.0.1:8787

curl -s http://127.0.0.1:8787/healthz | jq
```

**Expected `healthz` shape:**

```json
{
  "calibration_ready": true,
  "calibration_age_seconds": 412,
  "bus": { "published": 128441, "dropped": 0 },
  "sensors": { "filewatch": { "events": 128100, "errors": 0 } },
  "watch_failures": 0
}
```

A rising `bus.dropped` during a write storm is **expected and meaningful** — it is
overload evidence, and signal #13 consumes it. A rising `bus.dropped` while idle is a
bug in a sensor's pacing.

---

## 6. Add a sensor

1. Create `internal/sensor/<name>/<name>.go`.
2. Implement the three-method interface from `docs/design.md` §3:

```go
type Source interface {
    Name() string
    Start(ctx context.Context, out chan<- event.Event) error
    Close() error
}
```

3. Register it in `internal/platform/platform.go` for the relevant OS.
4. Emit only `event.Kind` values that already exist. If you need a new one, add it to
   `internal/event` **and** update `docs/design.md` §2 in the same commit.
5. Add a counter so `/healthz` reports the source's event and error counts.

**A sensor that cannot observe on this host must return an error from `Start`.** Never
return `nil` and produce nothing — that is the failure mode where the detector looks
healthy while blind.

**Verify:** run with `--duration 20s` and confirm `/healthz` shows a non-zero event count
for the new source, and that the count rises when you exercise the underlying activity.

---

## 7. Add a rule

Rules are pure predicates over a single event — no cross-event state, no window
dependency.

1. Add the rule to `internal/rules/rules.go` with a unique `R-` prefixed ID.
2. If it matches on process names or command strings, put those in
   `configs/grima.example.toml` rather than hardcoding them.
3. Set severity per `docs/design.md` §9.
4. Add a table-driven test asserting both a matching and a non-matching event.
5. If the detection logic is derived from a published rule corpus, record the source in
   `THIRD_PARTY_NOTICES.md` in the same commit.

**Verify:** the rule must raise the verdict level **immediately**, not at the next
scoring tick. Trigger the underlying action and confirm the verdict appears within one
second, with `Override` set to the rule ID.

---

## 8. Add a signal

1. Compute it in `internal/score/signals.go` from a `TreeVector` and a `Baseline`.
2. Choose a `Class`: `Primary`, `Secondary`, or `Override`. Use `Override` only for
   signals that must set a floor rather than contribute to the average.
3. Normalize to `[0,1]` with a documented ceiling. Unbounded normalization lets one
   runaway signal dominate fusion.
4. Populate `Detail` with the measured value **and** the comparison — never just a score.
5. Add a weight entry to `configs/grima.example.toml`.
6. Update the signal table in `docs/design.md` §5.

**If the signal needs a baseline input that does not exist yet**, add the distribution to
`calibrate.Baseline`, capture it in `calibrate.Capture`, and document it in
`docs/design.md` §7.

**Verify:** in uncalibrated mode the signal must be **absent** from the verdict, not
present with value `0`. Reporting `0` misrepresents *unknown* as *benign*.

---

## 9. Tune fusion weights

Weights are empirical, not learned. Grid search over the calibration corpus.

```sh
python3 testdata/scenarios/tune_weights.py \
    --benign testdata/corpus/benign/ \
    --malicious testdata/corpus/encryptor/ \
    --objective ttd_bytes \
    --out configs/grima.tuned.toml
```

**Objective order of preference:**

1. `ttd_bytes` — bytes encrypted before the first alert. This is the metric that matters
   for ransomware; a detector that alerts after the disk is encrypted has failed.
2. False positives per 24h of benign activity, at a fixed detection rate.
3. ROC/PR-AUC over the scenario corpus, for the paper's figure.

Do not tune weights against the same scenarios used for the reported results — hold out a
split, or the numbers are meaningless.

---

## 10. Reproduce a detection

Every verdict carries its contributing signals and their measured values. To replay:

```sh
# Capture the verdict with full signal detail
./grima --config configs/grima.example.toml --duration 5m | tee run.log

# Re-run the identical scenario
python3 testdata/scenarios/encryptor.py --path /tmp/grima-scratch --rate burst --seed 12345
```

**Expected:** the same rule IDs and the same signal names fire. Numeric values will
differ (real wall-clock timing, real I/O), but the *set* of firing signals and the final
level must be stable. If the level flickers between runs on the same scenario, a weight
is sitting on a boundary — widen the band or fix the normalization.

The fingerprint engine is single-writer and takes synthetic events directly, so unit
tests can reproduce window state exactly without timing. Prefer that over wall-clock
reproduction when asserting on behavior.

---

## 11. Diagnose "no alerts"

Work down this list in order. The first three explain almost every case.

1. **Is it calibrated?** `curl -s localhost:8787/healthz | jq .calibration_ready`.
   If `false`, deviation signals are suppressed by design. Capture a baseline (§3).
2. **Are events arriving?** `jq .bus.published`. Zero means a sensor failed to start —
   check the startup log for a source that returned an error.
3. **Are the monitor paths actually being written?** Confirm `general.monitor_paths`
   covers the directory the workload touches. A path outside the watch set is invisible.
4. **Is the level threshold above what the scenario produces?** Check
   `scoring.level_bands`. A `medium` verdict will not print if `alert_min_level = "high"`.
5. **Is the process attributed?** `PID == 0` means the event was observed but not
   attributed to an actor; it will never produce a per-process verdict. Check the
   attribution-confidence path.
6. **Did the bus drop?** `jq .bus.dropped`. Heavy drops during the scenario mean the
   window under-counted and may never have crossed threshold. Raise `bus.capacity`.

---

## 12. Measure false positives on a benign workload

The number the paper needs. Run representative legitimate bulk I/O against a calibrated
host and count alerts.

```sh
./grima --config configs/grima.example.toml --duration 1h | tee benign-1h.log

# concurrently, a representative workload:
npm install                      # thousands of small writes
git clone <large-repo>           # many files, many renames
tar czf /tmp/a.tgz <big-tree>    # high-entropy output — the 7-Zip problem
ffmpeg -i in.mp4 -c:v libx264 out.mp4
```

### Running the scripted corpus

`testdata/scenarios/benign-fp-check.sh <scenario>` captures a baseline against one workload,
runs that workload again as the measured pass, and prints the verdict with its signals. It
exits non-zero when the workload alerted, so it composes:

```sh
testdata/scenarios/benign-fp-spread.sh -n 3 testdata/scenarios/benign-npm-install.sh
```

The calibration window is sized from a timed pass (one extra workload run) rather than a
constant. A window shorter than one pass leaves that pass's own late writes — and therefore
their extensions — outside the baseline, and the measured pass then reports them as
first-seen novelty, which is a harness defect that reads exactly like a detector false
positive. `GRIMA_FP_WARMUP` overrides the window; the script header lists the rest.

On Windows, run these under **Git Bash**, not WSL. The detector is a Windows binary and the
fixtures are handed Windows paths, so a WSL work root (`//wsl.localhost/...`) is not a
directory it can watch. Both scripts fail fast when the work root is not drive-lettered
rather than reporting an empty baseline after two minutes.

**Expected:** zero `high`/`critical` verdicts. `medium` verdicts on `tar`/`ffmpeg` output
are the known hard case — high entropy from a legitimate compressor. If they fire, the
fix is a per-extension entropy prior plus a magic-byte check, **not** raising the global
threshold, which would also hide drip encryption.

Report as **false positives per 24h of benign activity**, not as a percentage.

---

## 13. Run the ablation

This table is the paper's results section. Run each signal subset over the same corpus:

```sh
python3 testdata/scenarios/ablate.py \
    --corpus testdata/corpus/ \
    --subsets rules_only,entropy,entropy+rename,all_signals \
    --out results/ablation.json
```

**Expected output columns:** subset, detection rate, false positives/24h, TTD in bytes
(median and 95th percentile), per-family generalization (train on family A, test on
family B).

An ablation row that does not move the numbers is a signal that is not earning its
complexity. Say so in the paper rather than keeping it.

---

## 14. Debug a wedged pipeline

Symptoms and first checks:

| Symptom | Likely cause | Check |
|---|---|---|
| `published` frozen, `dropped` rising | A subscriber stopped draining | Per-subscriber counts in `/healthz` |
| `published` frozen, `dropped` flat | A sensor died | Startup log; per-source error counts |
| Verdicts stop but events continue | Scoring goroutine tick stopped | Scoring tick counter in `/healthz` |
| CPU pinned at 100% | Entropy sampling on every byte of huge files | `filewatch.entropy_sample_bytes`; confirm head+tail sampling is in effect |
| Memory climbing without bound | Fingerprint state not reaped on process exit | `fingerprint.Reap` wired to `KindProcessExit`; live process count |

The fingerprint engine is single-writer, so a wedge there is a blocked call inside
`Apply`, not a lock deadlock. Profile with:

```sh
go test -run XXX -bench . -cpuprofile cpu.out ./internal/fingerprint
go tool pprof -top cpu.out
```

---

## 15. Coding conventions

Non-negotiable for this repository. Code review rejects violations.

### Structure

- Keep the codebase **modular** and follow standard Go practice.
- **`main.go` stays thin.** It parses flags, wires components together, and calls
  them. No business logic, no loops over data, no signal math, no string building.
  Every function it calls is defined in another file.
- One concern per file. If a file covers two jobs, split it.

### Naming

- Names must be **plain and easy to understand**: `writeRate`, `decoyFiles`,
  `isSuspicious`, `droppedEvents`. Not `exponentialBackoffAggregator`.
- **Strictly avoid jargon or "rocket science" names.** If a name needs a comment to
  explain it, the name is wrong — rename it.
- Files get plain descriptive names too: `filewatch.go`, `bus.go`, `score.go`,
  `rules.go`. A reader should guess a file's job from its name.

### Comments

- **One line, and only where the logic is not obvious.**
- No block comments restating what the code already says. No essays. No
  restating a function signature in prose.
- If you feel the need to explain *why*, first try a better name or a simpler
  structure. Comment only when the reason genuinely is not visible in the code.

### Size

- **Hard ceiling: 700 lines per file. Target under 500.**
- Over the limit → split by concern into multiple files in the same package.
- The same applies to functions: if a function needs scrolling to read, split it.

### Reliability

- **Fail-safe by default.** A component failure degrades coverage; it never takes
  down the detector. One dead sensor must not stop the pipeline.
- **No silent failures.** Count and surface every drop, error, and skip. A detector
  that is quietly blind is worse than no detector.
- **Never panic in a hot path.** Recover where operator-supplied or third-party code
  runs (rule predicates, templates).
- **Bounded everything.** Queues, rings, buffers, directory scans, per-process state —
  all fixed-size. Nothing grows with uptime.
- **Single writer per mutable state.** Prefer ownership over locking; add a mutex
  only when a value is genuinely shared.

### Testing

- Every component gets **both paths**: happy path and sad path.
- Sad path means the failure is actually exercised — a full queue that drops, a
  missing file, malformed input, an unreadable or version-mismatched baseline, a
  host that cannot be observed. Not a bare "it does not throw".
- Table-driven tests where the cases are data.
- Assert on observable behavior: window counts, verdict levels, drop counters,
  error returns. Never on log wording or internal field identity.

---

## 16. Measure attribution accuracy

User-space file notifications report *that* a file changed, not *who* changed it. GRIMA has
two ways to answer "who": correlation against per-process write-volume counters, which needs
no privileges and has a measured, severe failure mode, and causal attribution from the
operating system, which needs an elevated process. `attribution.mode` selects one:

| Mode | What it does | Needs |
|---|---|---|
| `correlate` (default) | blames the largest recent writer | nothing |
| `audit` | reads the writer from Windows file-system auditing (Security event 4663) | elevation, and it sets an audit ACE on each monitored directory |
| `etw` | rejected at startup with the reason — not implemented, see `docs/sprints.md` §14 | — |

A mode that cannot start logs `causal attribution unavailable, correlating instead` with the
reason and keeps detecting. **If that line is in the log, you are measuring correlation, not
the causal mechanism.**

### The trace

Set `GRIMA_ATTRIB_TRACE` to a file path and the detector writes one JSON line per blame
decision — PID, process name, candidate count, byte totals, confidence, and which mechanism
answered (`source`, `causal` or `correlate`):

```sh
GRIMA_ATTRIB_TRACE=/tmp/attrib.jsonl ./grima --config grima.toml --duration 30s
```

The trace is bounded at 200,000 lines. If it drops decisions it says so on stderr when the
detector closes, because a trace that silently under-counts would skew the accuracy figure.

### The procedure

```sh
# Terminal 1 — detector with tracing on
GRIMA_ATTRIB_TRACE=$PWD/trace.jsonl ./grima --config grima.toml --duration 25s

# Terminal 2 — a known writer
python testdata/scenarios/attribution.py --role writer --path /tmp/target \
       --files 65 --size 4096 --interval 0 --suffix ""

# Score it (the writer prints its own pid on the first line)
python testdata/scenarios/score_attribution.py --trace trace.jsonl --writer-pid <PID>
```

Run **at least five rounds** and report the aggregate. A single run is an anecdote.

### What to expect

Measured on a Windows host, solo writer, 65 x 4 KiB files, no deliberate background load:

| Rounds | Decisions | Correct | Accuracy | Confidence |
|---|---|---|---|---|
| 5 | 1,255 | **0** | **0.0%** | mean 0.40–0.92 |

Every decision blamed `firefox.exe`, which was writing more *bytes* to its cache than the
writer was writing in small files. The writer was never even a candidate.

**The confidence figure is the important part.** It was 0.92 in one round while being
entirely wrong. `confidence` is the top writer's share of recent write volume, so it
measures *byte dominance*, not attribution correctness. Treat it as a measure of how
concentrated the byte volume was, never as a probability that the blamed process is right.

### Measuring the causal mechanism (elevated)

`mode = "audit"` needs elevation, so the measurement is one command in an elevated PowerShell
at the repository root:

```powershell
.\testdata\scenarios\verify_attribution.ps1
```

It builds the detector, runs the known-writer scenario for five rounds, scores each trace, and
prints the aggregate and the pass/fail against the 90% gate. Traces, logs and configs land in
`%TEMP%\grima-attrib-verify`. Expect `accuracy >= 90%` with `source":"causal"` on nearly every
decision. If it says the mechanism never started, read the reason it prints — it is the line
the detector logged, and the mechanism cannot be measured until it is gone.

Use `-AllowUnelevated` to rehearse the harness itself; it will report 0% and say why.

### Consequences

- **Do not** report per-process attribution as a working feature. The measured bound is 0%
  for small-file workloads, and the causal mechanism's number has not been taken yet
  (`docs/sprints.md` §14).
- **Detection still works.** Evidence like entropy deviation and magic-byte mismatch is a
  property of the *file*, so it lands in whichever fingerprint received the events. Verdicts
  reach critical on the correct evidence, attributed to the wrong PID.
- **The fix is causal attribution**, not a better heuristic: an OS event that names the
  writer. Windows file-system auditing does, and is implemented behind
  `attribution.mode = "audit"`; ETW's write event carries no path, which is why it was not
  the one built (`docs/sprints.md` §14).
- **Tree aggregation partially compensates.** The true writer often appears inside the
  blamed process's tree, so tree-level scoring reaches it even when per-process scoring
  does not. Prefer tree-level claims in the paper.
