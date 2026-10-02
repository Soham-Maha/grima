# GRIMA — Sprint Plan

Timeboxed implementation plan. The roadmap in [`plan.md`](plan.md) §7 says *what* the
phases are; this says *who does what, in what order, and how we know it is finished*.

---

## Table of Contents

1. [Assumptions](#1-assumptions)
2. [Team and Workstreams](#2-team-and-workstreams)
3. [Definition of Done](#3-definition-of-done)
4. [Sprint Overview](#4-sprint-overview)
5. [Sprint Detail](#5-sprint-detail)
6. [Parallel Paper Track](#6-parallel-paper-track)
7. [Critical Path](#7-critical-path)
8. [Cut List](#8-cut-list)
9. [Known Gaps Carried Into Sprint 1](#9-known-gaps-carried-into-sprint-1)
10. [Platform Verification](#10-platform-verification)
11. [Attribution: The Measured Result](#11-attribution-the-measured-result)
12. [Why ETW Was Rejected](#12-why-etw-was-rejected)
13. [Detection No Longer Depends On Attribution](#13-detection-no-longer-depends-on-attribution)
14. [Causal Attribution: What Landed](#14-causal-attribution-what-landed)
15. [Fusion Was Not Monotonic](#15-fusion-was-not-monotonic)
16. [Calibration Units Were Mismatched](#16-calibration-units-were-mismatched)
17. [`ngram_rename_chain` Cannot Tell Extraction From Encryption](#17-ngram_rename_chain-cannot-tell-extraction-from-encryption)
18. [Two Weight-Table Problems The Ablation Must Price](#18-two-weight-table-problems-the-ablation-must-price)
19. [The Atomic-Save False Positive](#19-the-atomic-save-false-positive)
20. [Host Mode: Where Evidence Is Filed](#20-host-mode-where-evidence-is-filed)
21. [The npm False Positive, and One Claim That Reproduced Later](#21-the-npm-false-positive-and-one-claim-that-reproduced-later)
22. [The `max_delay` Curve, and a Coupling It Exposed](#22-the-max_delay-curve-and-a-coupling-it-exposed)
23. [Sprint 2 Close-Out: An Amended Criterion, Four Harness Defects, One Deadlock](#23-sprint-2-close-out-an-amended-criterion-four-harness-defects-one-deadlock)
24. [The Cerberus Split: What Is Asserted, and What Is Only Measured](#24-the-cerberus-split-what-is-asserted-and-what-is-only-measured)
25. [Startup Has No Bound Under Load — Proposed Design Change](#25-startup-has-no-bound-under-load--proposed-design-change)
26. [Corroboration Is Structural, Not Arithmetic](#26-corroboration-is-structural-not-arithmetic)

---

## 1. Assumptions

| Assumption | Value | Adjust if wrong |
|---|---|---|
| Sprint length | 2 weeks | — |
| Team size | 3 | — |
| Working capacity | ~10 h/person/sprint | Course load varies |
| Phase 0 (docs + scaffolding) | **Complete** | Verified: builds, tests, smoke test passes |
| Sprint 1 start | 2026-09-28 | Maps to the real deadline |
| Remaining sprints | 5 + 1 buffer = 12 weeks | Cut from the bottom of §8 |

Dates are deliberately expressed as *sprint numbers* rather than calendar dates, because
the submission deadline drives how many sprints exist, not the other way round. Map
sprint *n* to `start + (n-1) × 2 weeks` once the deadline is known.

**If fewer than 5 sprints are available**, apply the cut list in §8 in order. Sprint 4 is
never cut — it is the paper's contribution.

---

## 2. Team and Workstreams

Three workstreams, deliberately non-overlapping so nobody blocks anyone:

| Workstream | Scope | Packages |
|---|---|---|
| **W1 — Sensing** | Sensors, platform dispatch, attribution, decoys | `internal/sensor/*`, `internal/platform`, `internal/attrib`, `internal/decoy` |
| **W2 — Detection** | Fingerprint engine, calibration, scoring, rules | `internal/fingerprint`, `internal/calibrate`, `internal/score`, `internal/rules` |
| **W3 — Evaluation & Paper** | Harness, scenarios, metrics, writing, figures | `testdata/`, `docs/`, paper |

**Proposed ownership** (reassign freely — this is a starting split, not a decision):

| Person | Reg. No. | Primary | Secondary |
|---|---|---|---|
| Soham Mahapatra | 23BCI0074 | W1 | Paper §IV |
| Vaibhav Sijaria | 23BCI0063 | W2 | Paper §II–III |
| Prateek Purohit | 23BCI0066 | W3 | Paper §V–VI |

Every person reviews at least one sprint deliverable outside their own workstream. The
paper is not one person's job.

**Interface discipline.** W2 depends on the frozen `event` contract and the `Source`
interface, both of which are already fixed in [`design.md`](design.md) §2–§3. W1 must not
change them without updating `design.md` in the same commit — that is what keeps the two
workstreams parallel instead of serial.

---

## 3. Definition of Done

A sprint item is done when **all** of these hold. This mirrors `SKILLS.md` §15 and
`AGENTS.md`; it is the same bar every time.

1. Code builds, `go vet` clean, `gofmt` clean.
2. Happy path **and** sad path tested, asserting observable behaviour (counts, levels,
   error returns) — not log wording or internal fields.
3. No new dead configuration. A config key that is parsed but never read is a bug, not a
   placeholder.
4. Docs updated in the same commit if behaviour or an interface changed.
5. Evidence recorded: the command run and its output, not a claim that it works.
6. `THIRD_PARTY_NOTICES.md` updated if code or rule logic came from elsewhere.
7. Demoable at sprint review: someone other than the author runs it and sees it work.

---

## 4. Sprint Overview

| Sprint | Goal | Workstreams | Exit criterion |
|---|---|---|---|
| **1** | Trustworthy sensing | W1 (lead), W2, W3 | Sensors verified on Windows; attribution accuracy measured; decoy touch demonstrably fires |
| **2** | Fingerprint and calibration complete | W2 (lead), W1, W3 | Drip encryption caught by cumulative track; n-gram either implemented or removed; calibration reloads and recalibrates |
| **3** | Rules, response, multi-process | W2 (lead), W1, W3 | Cerberus-style split workload detected; suspend path exercised under its gate |
| **4** | **Evaluation harness** | W3 (lead), all | Ablation table with DR, FPR/24h, TTD-in-bytes across signal subsets |
| **5** | Results and paper | all | Results section written from real numbers; system frozen |
| **Buffer** | Slip absorption, macOS or scope statement, packaging | all | Submission-ready |

---

## 5. Sprint Detail

### Sprint 1 — Trustworthy sensing

**Goal.** The detector must be demonstrably correct about *what happened* before anyone
trusts it about *what it means*. Phase 0 proved the pipeline moves data; it did not prove
the sensors are accurate.

| # | Item | WS | Exit criterion |
|---|---|---|---|
| 1.1 | Exercise the FileWatch overflow rescan path | W1 | Overflow induced (buffer size reduced in a test), subtree re-scanned, synthetic events counted |
| 1.2 | Verify PersistWatch on real hosts | W1 | Windows: Run key + Scheduled Task + Startup file each produce `persistence_install`. Linux: cron + systemd unit each do |
| 1.3 | Measure ProcWatch cost | W1 | CPU and wall time of one process scan on a 300+ process host, recorded; interval tuned from the number |
| 1.4 | **Measure attribution accuracy** | W1 | Known-writer scenario: a named process writes N files; detector identifies it correctly for ≥90% of events |
| 1.5 | Attribution upgrade if 1.4 fails | W1 | ETW (`Microsoft-Windows-Kernel-File`) on Windows, auditd on Linux; no custom driver |
| 1.6 | Verify decoy touch fires | W1 | A write to a planted decoy raises `R-DECOY-TOUCH` at critical |
| 1.7 | Sensor health honesty | W2 | Every sensor reports non-zero events when exercised; a sensor that cannot start is absent from `/healthz`, not silently zero |

### Sprint 1 outcome

| # | Item | Result |
|---|---|---|
| 1.1 | Overflow rescan | **Done.** Extracted `handleWatchError` so the branch is reachable; 6 tests. Revert-checked: removing the `rescan` call makes the test fail. |
| 1.2 | PersistWatch verified | **Done.** 9 tests; 17 baseline entries catalogued on this host; a new Startup-folder entry detected at runtime; pre-existing entries correctly silent. |
| 1.3 | ProcWatch cost | **Done.** 14–49 ms per sample pass, ≈1.4–4.9% of one core at the 1 s default — the default is justified. 167 processes return empty `Exe()`/`Cmdline()` on this host, with no error, which bounds what attribution can rely on. |
| 1.4 | **Attribution accuracy** | ✅ **PASSED — 96.9%.** Correlation measured 0%; causal attribution measured 945 of 975 decisions over 5 rounds on an elevated host. Gate was ≥90%. Every causal decision was correct — the residual 3.1% is the correlation fallback, which fails at the same 0% rate as before. See §11. |
| 1.5 | Attribution upgrade | ✅ **Complete.** Windows file-system auditing (Security event 4663) implemented behind `attribution.mode`, verified on an elevated host. ETW was evaluated and rejected on evidence. See §14. |
| 1.6 | Decoy touch fires | **Done.** `KindDecoyTouch` + `DecoyID` verified in unit tests and end to end at critical. |
| 1.7 | Sensor health honesty | **Done.** `Reporting` on `sensor.Stats`; 5 tests over the `/healthz` shape a consumer parses. |
| 1.8 | Linux smoke test | ✅ **Done, via CI instead of WSL.** The ubuntu job runs `smoke-linux.sh`: all three sensors report, `filewatch` produces events, `persistwatch` scans real locations, the benign workload stays silent, and the encryptor is detected with content-derived signals. Reproducible by anyone — see §10. |

**Audit result.** An independent review of the sprint found two blocker-class defects, both
now fixed:

1. **A data race in `procwatch`** — the sample loop wrote the process map while `/healthz`
   read its length, with no synchronisation. `go test -race` caught it. In Go a concurrent
   map read and write is a *fatal* error, not a recoverable one, so any health scrape could
   have crashed the detector. Fixed with an atomic counter; `persistwatch` had the same
   latent defect and is fixed the same way. A regression test now exercises concurrent
   `Stats` reads against a running sampler.
2. **A test that did not test what it claimed** — the decoy path-spelling test could not
   fail, because `filepath.Join` cleans paths, so both sides were always clean. Rebuilt
   with a genuinely unclean path.

Two further findings were fixed: the attribution trace silently under-counted when it hit
its line cap (now reported on stderr at close), and the trace's off-by-default test asserted
an internal field rather than observable behaviour.

**Why 1.4 matters most.** The Phase 0 smoke test blamed `firefox.exe` for the encryptor's
writes. Detection was correct; the blamed process was not. Sprint 1 measured this properly,
and the result is worse than the anecdote suggested — see §11.

**Sprint review demo:** run the encryptor while a background bulk writer runs; show the
alert names the right process, or show the measured accuracy number that explains why not.

---

### Sprint 2 — Fingerprint and calibration complete

**Goal.** Make the dual-track design provable and resolve the n-gram gap.

| # | Item | WS | Exit criterion |
|---|---|---|---|
| 2.1 | **Resolve the n-gram gap** | W2 | Either an n-gram signal is computed from the ring and appears in verdicts, or the claim and `window.ngram_length` are deleted. No third option |
| 2.2 | Drip-encryption validation | W2 | `encryptor.py --rate drip` (1 file / 5s) crosses threshold. **Amended at close** — the original second clause ("while the decaying window stays flat") assumed per-process filing. Under the shipped `host` aggregation the window sees every event, so the clause is unmeetable as written, and re-measuring it under `audit` would only demonstrate a configuration we do not deploy. The cumulative track's ability to carry a verdict *alone* is demonstrated instead by `rates.sh quiet-drip`, where every window signal is absent |
| 2.3 | Intermittent-encryption validation | W2 | `--rate intermittent` detected; confirm the tail sample is what catches it |
| 2.4 | Calibration round-trip | W2 | Baseline saved, reloaded, `calibration_ready: true`; a stale baseline is rejected |
| 2.5 | Recalibration feedback | W2 | An operator-confirmed benign workload stops alerting after recalibration |
| 2.6 | Tree aggregation under a real split | W1 | A parent that forks N children each below threshold is scored as one actor above threshold |
| 2.7 | Fingerprint memory bound | W2 | Live process count × ring capacity verified bounded over a long run; `Reap` confirmed on exit |
| 2.8 | Scenario corpus, first cut | W3 | Benign workloads scripted and repeatable: compile, `npm install`, archive, video encode |
| 2.9 | **Tune `attribution.max_delay`** | W1 | The causal path is 100% accurate and the correlation fallback 0%, so the 3.1% miss is entirely events whose audited record arrived late. Measure the accuracy/latency curve and pick a default from it. Needs an elevated run — §14 |
| 2.10 | **Report variance, not a single figure** | W3 | Two runs of one scenario scored 100 and 56.4 for a purely environmental reason (§15). The harness must report per-round spread for TTD and detection rate, not one number |
| 2.11 | **Re-baseline the smoke tests on the new fusion** | W3 | The noisy-OR change (§15) raises scores, so the level thresholds in `smoke.sh` and `smoke-linux.sh` were calibrated against a different formula. Confirm the thresholds still assert what they should |

**Sprint review demo:** drip encryption caught live — the case that defeats every
fixed-window detector.

**Carried in from Sprint 1.** Items 2.9–2.11 were not in the original plan; they come from
what Sprint 1 measured. 2.9 and 2.10 exist because the measurements were taken and the
results were surprising, not because the sprint finished short.

### Sprint 2 outcome

| # | Item | Result |
|---|---|---|
| 2.1 | n-gram gap | ✅ **Done.** Implemented rather than deleted: `ngram_rename_chain` is signal #14 and appears in live verdicts. Its limits are measured in §17. |
| 2.2 | Drip validation | ✅ **Done, criterion amended.** Drip is detected at critical where it previously produced no alert (§20). The amended clause's demonstration is `rates.sh quiet-drip` on `6329324`: the same 1-file-per-5s rate, fixtures carrying no window-visible content, first verdict `info 6.0` below the band, later verdict **45.9 medium** on `(host)` — the only signals present are the cumulative pair `unknown_extension_activity=0.480` and `cum_bytes_rewritten=0.094`, with `write_burst`, `entropy_deviation`, `magic_mismatch`, `rename_burst`, `delete_rate` and `dir_fanout` absent from every verdict. The cumulative track carries a verdict alone. See §23. |
| 2.3 | Intermittent validation | ✅ **Done.** Both halves measured on `6329324` with `rates.sh intermittent tail`, all checks passing. Intermittent: **100.0 critical** on `(host)`, `entropy_deviation=1.000`, `magic_mismatch=1.000`, `ngram_rename_chain=1.000`, 36 alerts. Tail: the fixture reports head entropy 4.16 (z=1.22 → signal 0.204, below the band) against head+tail 6.84 (z=7.51 → saturated), and the detector reaches **94.1 critical** with `entropy_deviation=0.941` and `magic_mismatch` **absent** — the untouched head is why magic still matches, so the tail half is the carrier. See §23. |
| 2.4 | Calibration round-trip | ✅ **Done.** Verified both directions through a real detector, including the stale-baseline path. |
| 2.5 | Recalibration feedback | ✅ **Done.** Implemented, `--recalibrate` wired, before/after proven through the real scorer. |
| 2.6 | Tree aggregation under a real split | ✅ **Done, under per-process attribution** — the only configuration where it can be met. Split workload measured: tree 63.2 medium while each child stays silent. See §20. |
| 2.7 | Fingerprint memory bound | ✅ **Done.** Ring wrap and 500×20 start/exit cycles pinned. |
| 2.8 | Benign corpus | ✅ **Met.** npm now runs at its scripted default of **200 packages** — the configuration that previously could not be measured at all — and is **silent** (peak 21.7 low, zero alerts) once the calibration window covers a whole pass; the other four workloads were already silent. The extension-novelty behaviour behind the earlier npm alert is unchanged and belongs to 4.10. See §21 and §23. |
| 2.9 | `max_delay` tuning | ✅ **Done.** Curve measured on an elevated host; default set to 500 ms, the best point, and the delay/window coupling bounded. See §22. |
| 2.10 | Report spread, not one figure | ✅ **Done.** `benign-fp-spread.sh` reports N-round spread. |
| 2.11 | Re-baseline smoke thresholds | ✅ **Done.** Assertions tightened in both smoke scripts. |

**All eleven met, one against an amended criterion.** 2.2's original second clause could not
be satisfied by any configuration we ship (§23), so the criterion was rewritten to say what
the detector actually does rather than re-measuring a mode we retired.

**Two things this table records that the sprint would otherwise have hidden.** 2.2's criterion
was met in outcome and not in mechanism, and the honest reading is in §20 and §23 rather than a
tick. 2.8 met its criterion while finding a false positive, which is the corpus doing its job — a
benign-corpus item that reports no false positives has probably not been run.

---

### Sprint 3 — Rules, response, multi-process

**Goal.** Close the remaining literature gaps in the implementation and make the response
path real.

| # | Item | WS | Exit criterion |
|---|---|---|---|
| 3.1 | Expand and cross-check the rule set | W2 | Each rule has a table-driven test with matching and non-matching cases; patterns cross-checked against the Sigma corpus, attribution recorded |
| 3.2 | Exercise the suspend path | W2 | With `enable_suspend = true` and a critical verdict, the target is suspended; with the flag off, it is not |
| 3.3 | Cerberus-style split scenario | W3 | A workload splitting encryption across cooperating children is built and detected |
| 3.4 | Alert throttling option | W2 | A persistent condition produces one alert per incident, not one per second, when enabled |
| 3.5 | Dashboard per-tree view | W2 | Tree aggregate visible with its contributing process list |
| 3.6 | Bus saturation behaviour | W1 | Under a write storm, drops are counted and surfaced as signal 13, not silently lost |
| 3.7 | Failure-injection pass | W3 | Each row of `architecture.md` §13 failure table exercised at least once |

**Sprint review demo:** the split-process attack, which per-process classifiers miss.

### Sprint 3 outcome

| # | Item | Result |
|---|---|---|
| 3.1 | Rule set | ✅ **Done.** Six rules became nine — `R-FIREWALL-OFF`, `R-SERVICE-TAMPER`, `R-EDR-KILL` — and the existing pattern rules widened to the rest of the anti-recovery surface (`vssadmin resize/delete shadowstorage`, `bcdedit bootstatuspolicy` and `recoveryenabled`, `wbadmin delete backup`, `reagentc /disable`, `Remove-EventLog`, `Clear-WinEvent`, the `fsutil.exe` path variant). 58 sub-cases, each rule with several matching spellings and a non-matching case; a second test asserts no rule at all fires on 32 benign command lines. The Sigma rule identifiers and authors are recorded in `THIRD_PARTY_NOTICES.md`. **Found while doing it:** `rules.enabled` was declared in configuration and never read, so the pattern layer could not be switched off — now honoured. |
| 3.2 | Suspend path | ✅ **Done.** `internal/response` had no tests at all; the path is now exercised against a real child process — suspended with the flag on, still running with it off, and a pid that no longer exists or is not ours reported rather than ignored. The Windows path runs on this host and the `SIGSTOP` path was run on real Linux under WSL. |
| 3.3 | Cerberus-style split | ✅ **Done, with the live measurement bounded by attribution.** The workload is cooperative: children contend for one pool and claim each file with an exclusive marker, so nothing assigns work and no process owns a partition (verified: 480 files, 480 claims, uneven split). Detection is measured in the shipped default, and the aggregation claim is pinned deterministically by `internal/fingerprint/split_test.go`. The live per-process measurement is a characterisation, not a check — see §24. |
| 3.4 | Alert throttling | ✅ **Done.** `response.alert_cooldown` holds repeat alerts for one incident, keyed by the tree root, cleared by a below-band verdict, bounded and pruned. Zero disables it and is the default, so alert emission is unchanged unless opted into; proven end to end (11 alerts off, 1 on) and by a test that drives the real app-to-response path. |
| 3.5 | Dashboard per-tree view | ✅ **Done.** A new `/api/trees` groups verdicts by tree root with their contributing processes; a member with its own verdict keeps it, one without inherits the aggregate and is marked. A single-member tree renders exactly as the old flat row. Verified in a live browser against a real split workload. `/api/verdicts` is unchanged, because the smoke, rates and false-positive harnesses parse it. |
| 3.6 | Bus saturation | ✅ **Done.** Drops are counted on the bus, surfaced as `bus_dropped` in `/healthz`, and reach the verdict as the `bus_drops` diagnostic signal. Two tests: the signal's presence at 500 drops and its absence at 0 and 10 (below the noise floor), and a storm through a real bus, real engine and real score loop asserting both the health counter and the signal. |
| 3.7 | Failure-injection pass | ✅ **Done.** Rows 1, 2, 4, 5 and 6 of `architecture.md` §13 exercised; row 3 (bus saturation) is 3.6. Row 2 required a real fix: an unaddable directory was logged and never counted, so `watch_failures` could not move — it is now counted and surfaced through `/healthz`. Three stale claims in the document were corrected: the alert-dedupe advice (the cooldown exists now), the attribution narrative (host mode is the default; ETW was rejected, not "Phase 1 work"), and the overflow row (the error carries no path, so the rescan covers every root). |

**All seven met.** Two of them were not what the plan assumed: 3.1 found a configuration
switch that did nothing, and 3.3 found that the live per-process measurement cannot be
asserted on this host at all.

**Also landed, unplanned.** §23's `filewatch` deadlock fix is the largest single change in
this sprint: a startup that could hang for minutes on a tree that was being written to is now
gone, covered by a regression test that fails on the pre-fix code. It is not the whole story —
§25 records what the fix left behind, a startup whose *rate* is still coupled to the event
drain, and proposes the change that would bound it.

---

### Sprint 4 — Evaluation harness *(the paper's contribution)*

**Goal.** Produce the numbers. Everything before this is infrastructure.

| # | Item | WS | Exit criterion |
|---|---|---|---|
| 4.1 | Benign corpus, expanded | W3 | ≥6 representative workloads with recorded activity profiles |
| 4.2 | Attack corpus | W3 | Controlled encryptor at 3 rates + real families in an isolated snapshot VM |
| 4.3 | **Ablation runner** | W3 | Signal subsets (`rules_only`, `+entropy`, `+rename`, `+calibration`, `all`) each produce a full metric row |
| 4.4 | Metrics | W3 | DR @ 1% FPR, **TTD in bytes encrypted before alert**, FPR per 24h benign, CPU/RSS overhead |
| 4.5 | Generalization split | W3 | Train/tune on family A, test on family B |
| 4.6 | Weight tuning | W2 | Weights from grid search on a held-out split, not on the reported scenarios |
| 4.7 | Figures | W3 | Ablation table + TTD distribution + ROC/PR curve |
| 4.8 | Overhead measurement | W1 | Idle and under-load CPU/RSS, compared against no detector |
| 4.9 | **Price solo alertability** | W2 | Three Secondary signals sit at 0.5, which is five points above the medium band, so each pages an operator alone. Either weights below 0.45 or a rule that a Secondary needs a Primary companion. Price per signal — §18 |
| 4.10 | **Price first-seen-extension novelty** | W3 | 30 files of a never-seen extension is a medium alert and it accumulates without a burst. Decide between a minimum-novelty floor and accepting the alert — §18 |
| 4.11 | **Re-run the signal measurements** | W3 | §17 and §18 rest on scratch programs under `.sprint2/FingerprintWork/`. Re-run them from the ablation harness so the numbers are reproducible from the repo, not from one agent's scratch dir |
| 4.12 | **Report per-round spread** | W3 | Carried from 2.10. One scenario scored 100 and 56.4 for a purely environmental reason — no single-run figure is trustworthy |
| 4.13 | **Measure the split under causal attribution** | W3 | Carried from 3.3. The live per-process half of the split claim cannot be asserted while the writer is a guess: two runs under `correlate` landed the evidence in `explorer.exe`'s tree (§24). Re-run `cerberus.sh correlate` with `attribution.mode = "audit"` on an elevated host, where the writer is OS-reported, and record the tree-versus-children numbers there |
| 4.14 | **Bound `FileWatch` startup** | W1 | Carried from 3.6/§25. `Start` walks every directory before returning, so a large tree under load delays every other sensor and the score loop, and `design.md` §3.1 already promises `Start` returns once the source is *observing*. Add `filewatch.startup_deadline` (default 10 s), queue the remainder to the worker, count it as `add_pending`, and update `design.md` §3.1 and §13 in the same change. Blocked on the `plan.md` §11 decision |

**Safety, non-negotiable for 4.2:** isolated VM, snapshots, host-only network, no shared
folders, Defender exclusions inside the test VM only. Prefer the simulator for the demo.

**Exit criterion for the sprint:** a table where every row is a real measurement from a
reproducible command. If a row does not move the numbers, say so in the paper — a signal
that earns nothing is worth reporting as such.

**Carried in from Sprint 2.** Items 4.9–4.12 come from measuring the signal set rather than
from the original plan. Three of them are about signals that are currently alerting on their
own without corroboration; leaving them to weight-tuning in 4.6 would mean tuning a table
whose arithmetic is wrong.

**Carried in from Sprint 3.** Item 4.13 is the live half of the split claim, which cannot be
measured while the writer is a guess (§24).

---

### Sprint 5 — Results and paper

| # | Item | WS | Exit criterion |
|---|---|---|---|
| 5.1 | Results section from real output | all | Every number traceable to a command in `testdata/` |
| 5.2 | Fix all citations | all | Every reference resolves to a DOI or URL; the five unverifiable ones replaced or removed |
| 5.3 | Rewrite §II.E and §IV for the ML-free design | W2 | No claim of a pretrained classifier or unsupervised model remains |
| 5.4 | Threats to validity | all | Attribution limits, decoy detectability, single-host scope, monitor killability |
| 5.5 | System freeze | all | No feature changes after this point; bug fixes only |

---

### Buffer sprint

Slip absorption first. Then, in order: macOS sensor set, packaging, reproduction
instructions, `README` polish. Nothing here is load-bearing.

---

## 6. Parallel Paper Track

The paper is graded, so it runs alongside the code rather than after it. One section per
sprint, written from what that sprint actually produced:

| Sprint | Paper section | Source of truth |
|---|---|---|
| 1 | §II Background — sensing approaches | Sprint 1 measurements |
| 2 | §III gaps, restated against what the implementation showed | Sprint 2 evidence |
| 3 | §IV design — final architecture | Frozen `architecture.md` |
| 4 | §V evaluation, §VI results | Sprint 4 numbers |
| 5 | Abstract, intro, threats to validity, conclusion | All of the above |

**Do not write results before Sprint 4.** A design section written before the numbers
exist tends to promise things the numbers then contradict — which is exactly how the
current draft ended up claiming ML it is not using.

---

## 7. Critical Path

```mermaid
flowchart LR
    S1["Sprint 1<br/>Sensing verified"] --> S2["Sprint 2<br/>Fingerprint + calibration"]
    S2 --> S4["Sprint 4<br/>Evaluation harness"]
    S3["Sprint 3<br/>Rules + multi-process"] --> S4
    S4 --> S5["Sprint 5<br/>Results + paper"]

    P["Paper track<br/>one section per sprint"] -.-> S5
```

- **Sprint 4 is the critical path.** It cannot start before 2 and 3 produce a stable
  detector, and Sprint 5 cannot start before it.
- **Sprint 1 gates Sprint 2's tree work.** If attribution is unreliable, tree-level
  scoring degrades to host-level scoring, which changes what the paper can claim.
- **Sprints 1 and 3 can partially overlap** — rules work (3.1, 3.2) does not depend on
  sensor accuracy.

---

## 8. Cut List

Cut from the top when time is short. **Sprint 4 is never cut.**

| Order | Cut | Cost of cutting |
|---|---|---|
| 1 | Dashboard features beyond the current view | None — the demo still works |
| 2 | macOS sensor verification | Scope statement required: verified on Windows and Linux; macOS coverage not claimed |
| 3 | Alert throttling (3.4) | Log noise during an incident |
| 4 | Suspend path (3.2) | Observe-only; defensible, since suspend is opt-in anyway |
| 5 | Generalization split (4.5) | Weakens the headline claim — cut only under real pressure |
| 6 | Real-family testing (4.2 second half) | Falls back to the simulator; weaker but honest |

---

## 9. Known Gaps Carried Into Sprint 1

Verified against the code, not assumed:

| Gap | Evidence | Where it lands |
|---|---|---|
| ~~`window.ngram_length` is dead config~~ | **Resolved in Sprint 2** — the ring's event-kind sequence is scored as signal #14 `ngram_rename_chain` (Secondary, weight 0.5) | Done; see `design.md` §6 |
| ~~Attribution unreliable~~ | **Resolved in Sprint 1** — correlation measured 0%, causal attribution measured 96.9%. Elevation is now a deployment requirement, not a gap | Done; see §11 |
| ~~Decoy touch never observed firing~~ | **Resolved in Sprint 1** — verified in unit tests and end to end at critical | Done |
| **Suspend path untested** | Implemented for Windows and POSIX, never executed | Sprint 3 item 3.2 |
| ~~Overflow rescan untested~~ | **Resolved in Sprint 1** — 6 tests, revert-checked so the test fails if the rescan call is removed | Done |
| **macOS unverified** | The adapter compiles but no macOS host has produced an event through it | Scope statement in the paper; see §10 |
| **`static_reputation` signal absent** | Documented as Phase 7; correctly marked "not yet emitted" in `design.md` §5 | Buffer or never |

---

## 10. Platform Verification

**Superseded — Linux is verified.** This section originally recorded the cost of cutting
Linux verification: cross-platform would be a design property rather than a measured one, and
Gap 1 could not be claimed as closed. That position no longer holds.

Linux verification was reinstated through a different mechanism than the one originally
planned. Rather than WSL or a container, the project uses **GitHub Actions on
`ubuntu-latest`** — a real Ubuntu VM with a real kernel. The `linux` job runs
`smoke-linux.sh`, which asserts:

- all three sensors register and report counters;
- `filewatch` produces real `inotify` events;
- `persistwatch` scans real cron and systemd locations;
- the benign workload stays silent;
- the encryptor is detected with content-derived signals;
- the binary is statically linked.

**Linux is now measured, not asserted.** The claim the paper can make is correspondingly
stronger:

> The architecture avoids OS lock-in by construction, and is verified on Windows and Linux.
> macOS adapters ship but remain unverified.

The value of this is not only the second data point. The first CI run **failed on Linux and
passed on Windows on the same commit**, exposing a design defect that would have gone
unnoticed: `fingerprint.Apply` discarded every file event it could not attribute to a
process, so the detector went blind wherever attribution returned zero. A single-platform
evaluation cannot find that class of bug. See §13.

**What remains unverified: macOS.** The `darwin` adapter compiles and ships, but no macOS
host has produced an event through it. `architecture.md` §3 marks it accordingly, and the
paper's Threats to Validity must say so.

**Still true from the original reasoning:**

1. `README.md` must not describe the system as cross-platform without naming which platforms
   are verified.
2. The paper's Threats to Validity section carries macOS as a first-class limitation.
3. Do not claim macOS coverage from compilation alone.

---

## 11. Attribution: The Measured Result

Sprint 1 item 1.4 asked whether the detector can name the process that wrote a file. Two
mechanisms were measured, and they differ by 97 points.

### Result

| Mechanism | Decisions | Correct | Accuracy | Gate (≥90%) |
|---|---|---|---|---|
| Correlation on write volume | 1,255 | 0 | **0.0%** | ❌ failed |
| Causal (Windows file-system auditing) | 975 | 945 | **96.9%** | ✅ **met** |

The causal run: solo writer, 65 files of 4 KiB, five rounds on an elevated host.

| Round | Writer PID | Decisions | Correct | Accuracy | Causal | Correlate |
|---|---|---|---|---|---|---|
| 1 | 20440 | 195 | 189 | 96.9% | 189 | 6 |
| 2 | 6020 | 195 | 189 | 96.9% | 189 | 6 |
| 3 | 10700 | 195 | 189 | 96.9% | 189 | 6 |
| 4 | 18068 | 195 | 189 | 96.9% | 189 | 6 |
| 5 | 7264 | 195 | 189 | 96.9% | 189 | 6 |
| **Total** | — | **975** | **945** | **96.9%** | 945 | 30 |

**The breakdown matters more than the headline.** `correct` equals `causal` in every round:
**every decision the causal mechanism resolved was correct.** The residual 3.1% is the
correlation fallback — the six events per round whose audited record did not arrive inside
`max_delay` — and those fail at the same 0% rate the correlation path always had.

So the honest reading is not "96.9% accurate attribution". It is: **causal attribution was
100% accurate; correlation remains 0%; the blend is 96.9% and is tunable by raising
`max_delay`.**

### The correlation number

Correlation against write volume, measured first and kept here because it is the baseline the
causal result is compared against. Condition: solo writer, 65 files of 4 KiB, no deliberate
background load — the *easiest* case, with exactly one process doing the writing.

| Round | Writer PID | Decisions | Correct | Accuracy | Blamed instead |
|---|---|---|---|---|---|
| 1 | 27160 | 215 | 0 | 0.0% | `firefox.exe` ×215 |
| 2 | 33128 | 260 | 0 | 0.0% | `firefox.exe` ×260 |
| 3 | 37612 | 260 | 0 | 0.0% | `firefox.exe` ×260 |
| 4 | 44636 | 260 | 0 | 0.0% | `firefox.exe` ×260 |
| 5 | 15584 | 260 | 0 | 0.0% | `firefox.exe` ×260 |
| **Total** | — | **1,255** | **0** | **0.0%** | — |

Across every other condition tested (paced writes, 4 MiB files, with and without a deliberate
background writer) the best observed rate was **19.1%**.

### Why correlation fails

`Suspect` picks the process with the largest recent write-*byte* delta. A browser writing
hundreds of kilobytes to its cache in the same sample interval beats a process writing 65
small files, every time — and the writer is not even a candidate. Writing 4 MiB files
instead of 4 KiB files does not help, so this is not a file-size problem; byte volume is
simply the wrong discriminator for small-file workloads, which is exactly the ransomware
workload.

### The confidence figure is actively misleading

Confidence reached **0.92** in a round where every single decision was wrong. It is defined
as the top writer's share of recent write volume, so it measures *byte dominance* — how
concentrated the volume was — and not the probability that the blamed process is correct.
Reporting it as a confidence would be worse than reporting nothing.

### What survives

**Detection is unaffected.** The signals that matter — entropy deviation, magic-byte
mismatch, extension novelty — are properties of the *file*, not the process, so they land
in whichever fingerprint received the events. In the same runs that scored 0% attribution,
verdicts reached **critical (100.0)** on correct evidence. The detector knows what happened
and is wrong about who did it.

**Tree aggregation partially compensates.** The true writer frequently appears inside the
blamed process's tree, so tree-level scoring reaches it even when per-process scoring does
not. The paper should make tree-level claims, not per-process ones.

### What to do

1. **State the measured bound.** "Per-process attribution via write-volume correlation
   achieved 0% on the solo-writer case; detection was unaffected." That is a legitimate,
   useful result — it quantifies a limitation of the entire user-space correlation approach,
   which the literature generally does not.
2. **Adopt causal attribution** in Sprint 2 if per-process claims are wanted: ETW
   (`Microsoft-Windows-Kernel-File`) on Windows, auditd on Linux. Both report the writing
   PID directly, are OS-provided, and require no custom driver. *(Corrected in §14: the
   Kernel-File write event carries no file path, so ETW needs a second correlation on top of
   the thread-to-process map. Windows file-system auditing gives the path and the PID in one
   record, and is what was implemented.)*
3. **Reframe if not.** If Sprint 2 cannot absorb that work, the honest framing is
   host-level and tree-level detection with an explicit statement that per-process blame is
   not reliable. This is defensible and does not weaken the dual-track or calibration
   contributions.

### Reproducing it

`SKILLS.md` §16 documents the trace facility (`GRIMA_ATTRIB_TRACE`),
`testdata/scenarios/attribution.py` provides the known writer, and
`testdata/scenarios/score_attribution.py` scores a trace against a writer PID.

---

## 12. Why ETW Was Rejected

**Resolved.** Item 1.5 is complete: causal attribution was implemented via Windows file-system
auditing and measured at 96.9% (§11). This section is kept because the reasoning is the
justification for choosing auditing over ETW, and because the constraint it identified —
elevation — still governs how the feature is deployed.

Item 1.5's exit criterion named a mechanism: *ETW (`Microsoft-Windows-Kernel-File`) on
Windows; no custom driver*. Three facts, each verified on this host, put ETW out of reach.

### 1. The named mechanism requires elevation

`Microsoft-Windows-Kernel-File` is a **kernel** ETW provider. Enabling it requires
`SeSystemProfilePrivilege`, which means an elevated process. This host is not elevated:

```
$ net session
NOT admin
```

The design intent behind item 1.5 was that ETW is OS-provided and therefore needs no custom
driver — which is true. It was not accounted for that ETW is also **privileged**. "No driver"
and "no elevation" are different claims, and only the first one holds.

### 2. The only non-admin alternative is too slow

The one causal signal available without elevation is enumerating system handles and asking
which process holds the file. Measured on this host, one system-wide pass:

```
enumeration took 5.595s, denied=174
```

**5.6 seconds per pass.** File events arrive at hundreds per second during an encryption
burst, so this cannot run on the event path at all. It is three orders of magnitude too slow.

### 3. And it would not work even if it were fast

A real encryptor opens, writes, and closes each file. The handle is gone by the time a
detector could look for it. Probe: a writer creates 20 files, each closed immediately,
then handles are enumerated at once.

```
writer pid=9960 wrote 20 files, each closed immediately
written files still held open by anyone: 0 of 20
attributable to the writer: 0 of 20
```

**Zero of twenty.** The workload that defeats the correlation heuristic defeats handle
enumeration for the same underlying reason: the evidence does not exist at observation time.

### What this means

Per-process attribution for fast small-file workloads requires **an elevated deployment**.
That is a deployment requirement, not a capability the detector has — and it should be
stated as one.

This is not a dead end; it changes what the claim is:

- **Wrong:** "GRIMA attributes file writes to the process responsible."
- **Right:** "GRIMA attributes file writes to the process responsible **when deployed with
  the privileges ETW requires**; unelevated, it detects the same activity but cannot name
  the actor."

The second is defensible, testable, and honest. It also explains why the detector is
designed so that detection does not *depend* on attribution — the file-derived signals
(entropy, magic bytes, extension novelty) carry the verdict regardless.

### How it was resolved

Option 1 was taken: the mechanism was implemented behind `attribution.mode`, and the
measurement was taken on an elevated host. **96.9% — the gate is met (§11).**

The second option was not needed, and should not be reached for now that the first has
worked. Recording it here only so the reasoning is not re-derived:

- Re-scoping the gate to "attribution unavailable unelevated" would have been legitimate
  **only** as an explicit decision, not as a quiet lowering of the bar. It is moot.

The elevation constraint has not gone away. It is now a **deployment requirement**: causal
attribution needs `SeSecurityPrivilege` plus an audit ACE per monitored directory, so a
default install runs on correlation and is blind to the actor. That belongs in the paper as
a deployment note, not buried here.

---

## 13. Detection No Longer Depends On Attribution

§11 claimed detection was unaffected by the attribution failure. That claim was **false on
Linux**, and the first CI run proved it.

### The bug

`fingerprint.Apply` discarded any file event it could not blame on a process:

```go
if !ev.Kind.IsFile() || ev.PID == 0 {
    return
}
```

On Windows this never bit, because a background browser always had a non-zero write delta,
so `Suspect` always returned *some* PID — the wrong one, but a non-zero one, so events
flowed. On Linux nothing was attributed, every file event was thrown away, and the detector
went **completely blind**. CI reported:

```
  filewatch reporting: 0 events
FAIL: encryption workload was not detected on Linux
```

The Windows job passed on the same commit. Only a second platform exposed it — which is
precisely the argument for verifying on more than one.

### Why it mattered beyond Linux

The design says detection must not depend on attribution succeeding. It did. Every signal
that makes GRIMA work — entropy deviation, magic-byte mismatch, extension novelty — is a
property of the *file*, not the process, and all of them were being gated behind a
correlation heuristic that is known to fail 100% of the time.

That is a design-level defect, not a Linux porting bug. It would have surfaced on Windows
too, the moment attribution returned zero candidates.

### The fix

Unattributed file events are folded into a **host-level fingerprint** (`HostName`, PID 0)
instead of being dropped, and that fingerprint is scored like any other root. The evidence
reaches scoring whether or not a process could be named.

Two properties are pinned by tests:

- an unattributed write still produces host-level entropy and magic-mismatch evidence, and
  the host bucket appears in `Roots()` so it is scored;
- the host bucket does **not** absorb process trees — a process whose parent is PID 0 (init,
  or any orphan) is a root in its own right, not a child of the host.

The second matters because `linkChild` already refuses to attach children to PID 0, and that
behaviour is now load-bearing rather than incidental.

### What it changes for the paper

The claim in §11 is now true rather than aspirational: **detection is independent of
attribution.** Verdicts carry file-derived evidence at host level when no process can be
blamed, and at process level when one can. That is a stronger and more honest architecture
than one whose detection silently depends on a heuristic that fails.

---

## 14. Causal Attribution: What Landed

Item 1.4's gate is still failed: nobody has measured a causal mechanism on an elevated host.
This section records what was built, why it is auditing rather than ETW, what is verified, and
the single command that takes the missing measurement.

### The two mechanisms, evaluated

| | ETW `Microsoft-Windows-Kernel-File` | Windows file-system auditing (SACL) |
|---|---|---|
| Writer PID | `IssuingThreadId` — a *thread* id, so it needs a thread→process map | `ProcessId`, in the event |
| File path | **Not in the write event.** Event 16 (Write) carries `FileObject`/`FileKey`; the path needs a second map built from the `Name` events (10/11) | `ObjectName`, in the same event |
| Process image | not in the event | `ProcessName`, in the same event |
| Latency | microseconds | tens of milliseconds (event-log delivery) |
| Privilege needed | `SeSystemProfilePrivilege` | `SeSecurityPrivilege`, plus an audit ACE per directory |
| Work to build | TDH property parsing, or a third-party consumer, plus two correlation maps | four documented API calls and one XML shape |

Evidence gathered on this host, which is not elevated:

- **Enabling a session is admin-gated**, for kernel and non-kernel providers alike:
  `logman start grima-probe -p "{EDD08927-9CC4-4E65-B970-C2560FB5C289}" -o probe.etl -ets` →
  `Access is denied. Try running this command as an administrator.`
- **The provider's write event has no path.** `wevtutil gp Microsoft-Windows-Kernel-File
  /ge:true /f:xml` confirms Write = event 16 with `KERNEL_FILE_KEYWORD_WRITE` = 0x200. The
  templates are not in that dump; the Win10 18990 manifest mirror shows event 16 (both
  versions) using `ReadArgs`/`ReadArgs_V1`, whose fields are ByteOffset, Irp, FileObject,
  FileKey, IssuingThreadId, IOSize, IOFlags — no FileName. `NameCreate` (10) carries
  `FileKey` + `FileName`, so the path can be recovered, but only by a second correlation that
  has its own miss window.
- **Reading the Security log is admin-gated too:** `wevtutil qe Security /c:1` →
  `Access is denied.`, and `auditpol /get /subcategory:"File System"` →
  `A required privilege is not held by the client. (0x522)`.
- **Neither Go ETW library is a good fit.** `github.com/bi-zone/etw` is MIT but cgo, which
  would make a pure-Go repository require a C toolchain for Windows builds;
  `github.com/0xrawsec/golang-etw` is pure Go but GPL-3.0, which cannot be linked into this
  MIT repository. A hand-written TDH consumer cannot be exercised at all unelevated, and a
  wrong `EVENT_TRACE_LOGFILEW` layout fails by crashing an elevated process, not by erroring.

**Recommendation: auditing.** One 4663 record carries the path, the PID and the image name.
The ETW alternative needs two independent correlation maps — one of them thread→process, with
the same "the evidence is gone by observation time" failure mode that sank the volume
heuristic — and its latency advantage buys nothing when the detector's windows are seconds
wide. The audit path is also the one that can be largely verified without elevation.

### What was implemented

`attribution.mode` selects the mechanism. The default is `correlate`, which is exactly the
behaviour measured in §11, so nothing regresses.

| Mode | Mechanism |
|---|---|
| `correlate` | the write-volume heuristic, unchanged |
| `audit` | Windows file-system auditing: `SeSecurityPrivilege`, a success-audit ACE for `Everyone` covering write and delete rights on each monitored directory (inherited), the File System audit subcategory enabled for successes, and a push subscription (`EvtSubscribe`) to Security event 4663 |
| `etw` | **rejected at startup** with the reason, rather than shipped unverified |

How a file event gets its writer:

1. The 4663 record's `ObjectName` is an NT device path (`\Device\HarddiskVolume4\...`); it is
   translated to the DOS path the file sensor reports, using `QueryDosDevice` for each drive.
2. Records go into a bounded, time-windowed index keyed by path. Records older than the
   window, records without a path or PID, and the detector's own writes are dropped and
   counted.
3. The file sensor hands each event to a resolver goroutine instead of attributing inline.
   The resolver waits up to `attribution.max_delay` (default 300 ms) for a matching record and
   emits the event either way, so the sensor's goroutine never blocks.
4. A run of `causalMissStreak` (20) events with no record marks the mechanism degraded: the
   resolver stops waiting, logs it, and still looks. One arriving record clears it and logs
   the recovery. A source that dies mid-run cannot quietly slow the detector down.
5. If the mechanism cannot start — not elevated, no `SeSecurityPrivilege`, no subscription —
   the reason is logged at warn and the detector continues in correlation mode. It never fails
   to start and never looks healthy while blind.

Health counters (`attrib_causal_hits`, `attrib_correlate`, `attrib_pending_drop`,
`attrib_source_error`) are on the file sensor's `/healthz` entry, and the trace gained a
`source` field (`causal` or `correlate`) per decision.

### Verified without elevation

- **The fallback.** Running the detector with `mode = "audit"` on this host logs
  `causal attribution unavailable, correlating instead ... reason="file-system auditing needs
  an elevated process, and this one is not elevated"`, keeps detecting (critical verdict on the
  writer's files), and traces every decision with `source":"correlate"`. Scored 0% — the same
  measured failure as §11, which is the point: the fallback is the old behaviour.
- **4663 parsing** against the provider's own field names, including reads, non-file objects,
  other event ids, unmapped volumes, missing process ids, malformed XML and unreadable
  timestamps.
- **Device-path translation** against this host: the system drive's `QueryDosDevice` name
  round-trips back to `C:\`.
- **The audit ACE** is built and inspected without installing it: one `SYSTEM_AUDIT_ACE_TYPE`
  entry, the write mask, inheritance flags, correct SID.
- **Privilege detection** is read back from the token, so an unelevated process gets
  `enable SeSecurityPrivilege: the process does not hold the privilege` rather than a silent
  success — `AdjustTokenPrivileges` reports success even when it changes nothing.
- **Thread→PID, index bounds, degradation, queue overflow and shutdown drops** with synthetic
  records.

Two bugs were caught this way and fixed before any elevated run: `AddAuditAccessAceEx` takes
the access mask *before* the SID (the swapped call produced `ERROR_INVALID_SID`, which would
have made the SACL silently absent), and `EvtSubscribeActionDeliver` is **1**, not 0 — with
the wrong constant the callback would have discarded every delivered event.

### Not verified, and why

- **The subscription and the render path** (`EvtSubscribe` → callback → `EvtRender` → parse).
  Both need an elevated process to open the Security channel; nothing about them can be
  exercised here. They are written against the documented signatures, and the dispatch
  constants are pinned by a test, but they have never run.
- **The audit policy and the ACE against a live directory**, and therefore whether the
  Security log actually delivers 4663 records for the monitored tree.
- **The ≥90% number itself.** It needs an elevated run.

### The measurement

From an elevated PowerShell, at the repository root:

```powershell
.\testdata\scenarios\verify_attribution.ps1
```

It builds the detector, runs 5 rounds of the known-writer scenario against a temporary
directory with `mode = "audit"`, scores each trace with `score_attribution.py`, and prints the
aggregate plus a pass/fail against the 90% gate. It leaves the traces, logs and configs in
`%TEMP%\grima-attrib-verify` for inspection, and it leaves the audit ACE and audit policy in
place. Use `-Rounds 1 -Files 20` for a quick check, and `-AllowUnelevated` to rehearse the
harness (which will report 0% and say why).

Two things to know before running it. The ACE covers write and delete rights only, so the
Security log sees one record per write under the monitored directories and nothing for reads;
on a large monitored tree, raise the log size first (`wevtutil sl Security /ms:268435456`). And
the policy can be confirmed by hand with `auditpol /get /subcategory:"File System"`, which
should report Success once the detector has started in audit mode.

What to expect if the mechanism works: `accuracy ≥ 90%`, with `causal` on nearly every
decision and only a handful attributed by correlation (the ones whose audited record did not
arrive inside `max_delay`). If the script reports that the mechanism never started, read the
reason it prints — it is the same line the detector logged.

**Until that number exists, 1.4 stays failed.** A mechanism that is implemented, unit-tested
and unelevated-verified is not a measurement.

### First elevated run: the mechanism did not start

Run on 2026-09-24 on an elevated host. All five rounds reported:

```
causal attribution unavailable, correlating instead
mode=audit reason="enable file-system auditing: AuditQuerySystemPolicy: Incorrect function."
decisions 975, correct 0, causal 0 (0.0% of decisions)
```

**The failure was in the code, not the environment.** `AuditQuerySystemPolicy` is declared as
returning a `BOOLEAN` — zero for failure, non-zero for success — but the call site read the
return value as an error code:

```go
ret, _, _ := procAuditQueryPolicy.Call(...)
if status := uint32(ret); status != 0 {
    return 0, fmt.Errorf("AuditQuerySystemPolicy: %w", syscall.Errno(status))
}
```

So a **successful** call returning `TRUE` (1) was reported as `errno 1`, `ERROR_INVALID_FUNCTION`
— "Incorrect function". The auditing API worked and the code called it a failure. The sibling
`setSystemAuditPolicy` gets this right (`if ok == 0`), so the two were inconsistent.

Two fixes: the return value is now treated as a boolean, with the real error taken from
`GetLastError`; and the structure the system allocates is released with `AuditFree` rather than
`LocalFree`, which is what the API documents.

A test now resolves all three function pointers by name, because a mistyped symbol does not fail
a build — it panics on an elevated host, in the one run that is expensive to repeat.

**What this run did prove.** The graceful-degradation path works: the detector logged a precise
reason, fell back to correlation, and kept running rather than failing to start. The harness
also correctly refused to report a number it had not measured, printing "the audit mechanism
never started, so this run does not measure it" instead of a misleading 0%.

**The measurement was then taken.** Re-running the same command on an elevated host started
`mode=audit` cleanly and produced:

| Round | Decisions | Correct | Accuracy | Causal | Correlate |
|---|---|---|---|---|---|
| 1–5 (each) | 195 | 189 | 96.9% | 189 | 6 |
| **Total** | **975** | **945** | **96.9%** | **945** | 30 |

**Gate met.** Every causal decision was correct; the residual 3.1% is the correlation
fallback. The full breakdown is in §11.

**One tuning note for later.** The 30 correlated decisions are events whose audited record
did not arrive inside `max_delay` (default 150 ms). Since the causal path is 100% accurate and
the fallback is 0%, raising `max_delay` should raise the blended figure toward 100% at the
cost of added latency. Worth measuring in Sprint 2 alongside the other calibration work,
rather than assuming the current 96.9% is the ceiling.

---

## 15. Fusion Was Not Monotonic

CI failed the Windows smoke test after the attribution fix. The log showed the detector had
worked:

```
level=WARN msg="ransomware risk detected" pid=5872 process=bash.exe
score=56.4 level=medium signals="unknown_extension_activity; entropy_deviation; magic_mismatch; write_burst"
```

Detection was correct — the right signals, on the right activity. The **level** was the
problem: 56.4 (medium) where the same scenario had scored **100 (critical)** locally.

### Why

Fusion combined signals as a weighted **mean**:

$$\text{score} = 100 \cdot \frac{\sum_i w_i v_i}{\sum_i w_i}$$

A mean is not monotonic. Adding a weak signal *lowers* the score, because it enlarges the
denominator without adding much to the numerator. So:

| Run | Signals present | Score | Level |
|---|---|---|---|
| Local | `unknown_extension_activity` alone (saturated, 1.0) | **100.0** | critical |
| CI | the same signal + `entropy_deviation` + `magic_mismatch` + `write_burst` | **56.4** | medium |

**More evidence of the same attack produced a lower severity.** The local run was *less*
informed — its content signals had raced against the rename and found nothing — and scored
*higher* for it.

That is a correctness defect in the core scorer, not a test threshold. A risk score whose
value falls as evidence accumulates cannot be reasoned about, and it would have distorted
every number in the Sprint 4 ablation.

### The fix

Signals now combine as independent evidence:

$$\text{score} = 100 \left(1 - \prod_i \left(1 - \mathrm{clamp}_{[0,1]}(w_i v_i)\right)\right)$$

This is noisy-OR, and monotonicity is the property being bought: adding a signal can only
raise the score. A saturated signal alone still reaches 100; the same signal with three
weaker companions now reaches 100 as well rather than being averaged down to 56.

`TestAddingEvidenceNeverLowersTheScore` pins the invariant, asserting both that the second
verdict carries more signals and that its score is not lower.

### What it says about the evaluation

Two runs of one scenario disagreed by 44 points, and the disagreement was **environmental** —
whether the detector read a file before or after it was renamed. That is a reminder for
Sprint 4: TTD and detection-rate numbers taken from a single run are not trustworthy, and the
harness has to report variance across rounds rather than one figure.

---

## 16. Calibration Units Were Mismatched

Sprint 2 item 2.4 verified calibration end to end, and in doing so surfaced a bug that made
three signals unreachable on a real machine.

### The bug

`Observations.Observe` counted **every** bus event into one per-second series:

```go
o.perSecond[ev.Time.Unix()]++
```

`HostEventRate` was built from that series, and three signals compared their own subset rate
against it:

| Signal | Compared | Against |
|---|---|---|
| `write_burst` | writes/s | all events/s |
| `rename_burst` | renames/s | all events/s |
| `delete_rate` | deletes/s | all events/s |

On the test host — 404 processes, `procwatch` at 500 ms — the baseline measured **92.5
events/s**, dominated by process lifecycle events. A 71-file encryption burst over the 30 s
decay window is **2.4 writes/s**. The ratio is 0.03, so `write_burst` could never reach its
threshold. It was not weak; it was dead.

This also explains an inconsistency from Sprint 1: `write_burst` appeared in the CI verdict
but never fired on a real desktop. CI calibrates against a quiet runner, so its all-event
baseline was small enough for the ratio to work by accident.

### The fix

Rates are now measured per kind, and count **file events only**:

```go
type Baseline struct {
    WriteRate     Dist  // writes per second
    RenameRate    Dist
    DeleteRate    Dist
    FileEventRate Dist  // all file events, for context
    ...
}
```

Each signal compares against its own kind, and `rateBaseline`'s fallback uses `WriteRate`
rather than the all-event rate. Baseline schema version bumped to 2; a v1 baseline is ignored
and the detector runs uncalibrated until re-captured, which is the documented behaviour for a
version mismatch.

`TestWriteBurstComparesLikeWithLike` pins it: a 65-write burst over 30 s against a 0.2/s write
baseline must fire, and the fixture also carries a realistic 92.5/s `FileEventRate` so the
test fails if the signal ever compares against it again.

### The general rule

**A subset rate must never be compared against a superset baseline.** This was not a typo —
it was a units error that survived because no test exercised the signals against a baseline
measured on a busy host. Worth remembering for Sprint 4: a signal is not validated by firing
in a quiet test harness.

---

## 17. `ngram_rename_chain` Cannot Tell Extraction From Encryption

Sprint 2 item 2.1 closed the n-gram gap by implementing it rather than deleting the claim.
The implementation is sound and the docs now match the code. But measuring it produced a
result that limits what the signal can be trusted for.

### What it measures

The share of k-grams in the window holding a **write immediately followed by a rename**
(k = `window.ngram_length`, default 32). It is signal #14, Secondary, weight **0.2** — lowered
from 0.5 after the measurement below.

### Measured against three workloads

Real `filewatch` on Windows, real engine, 30 s window, k=32:

| Workload | Adjacent transitions | Chains / k-grams | Value |
|---|---|---|---|
| Atomic save over an existing file (118 saves, 40 files) | `write→delete=78`, `delete→rename=78`, **`write→rename`=0** | 0 / 363 | **absent** |
| Extractor / installer (118 writes to new names) | `write→rename=118` | 445 / 445 | **1.0** |
| Encryption fixture (40 `.docx` → `.locked`) | `write→rename=39` | 87 / 87 | **1.0** |

**It does not fire on atomic saves.** The intuitive worry — that every editor's save looks
like encryption — is wrong, and empirically so: when the destination exists, the temp file's
removal arrives as a `delete` *between* the write and the rename, so no `write→rename`
transition occurs. Measured, not modelled.

### The limit

**It cannot distinguish an extractor from an encryptor.** The extraction cycle is
`create→write→rename`; the encryptor's is `write→rename→create`. Those are **rotations of the
same 3-cycle**, so over a dense burst the two windows hold the same multiset of k-grams, and
no rotation-invariant measure over event kinds can separate them.

Discriminator candidates were tested against the real sequences and all fail:

- "chain not preceded by a create" excludes the encryptor too — its `create→write` belongs to
  the *previous* file's destination create;
- "create-light window" fails because the encryptor's renames also emit destination creates
  (`create=39` vs `rename=39`);
- create/rename and rename/write ratios are ≈1 for all three workloads.

At the originally shipped weight of 0.5 the extraction shape **alerted on its own**:

```
level=WARN msg="ransomware risk detected" pid=28012 process=chrome.exe
score=50.0 level=medium override="" signals=ngram_rename_chain
```

Lowering the weight to 0.2 stops it alerting alone (≈20, below the 45 medium band). That is
**masking the false positive, not fixing it** — the signal still contributes to any fusion it
joins, and it contributes identically for a benign extractor and a real encryptor.

### What to do

1. **Sprint 4's ablation decides.** The signal was implemented specifically so it could be
   measured rather than assumed. If it does not move the detection rate and does add false
   positives on extraction workloads, delete it — and cite this section as the reason.
2. **Do not cite it as evidence of encryption** in the paper. It is evidence of *bulk
   write-then-rename activity*, which extraction, installation, and deployment share with
   encryption.
3. **The weight is not a tuning question.** No weight makes a non-discriminating signal
   discriminating; a lower weight only makes it quieter.

This is the useful outcome of implementing rather than deleting: the gap is closed, and what
the signal actually buys is now known instead of assumed.

### The weight narrows the margin; it does not remove the false positive

Measured against the real scorer with noisy-OR fusion, extraction shape, calibrated baseline
with per-kind rates high enough that no burst signal fires:

| Workload | w=0.2 (shipped) | w=0.5 (previous) | w=0 |
|---|---|---|---|
| Extraction, no companion | 20.0 info | 50.0 medium | 0.0 info |
| Extraction + magic on 10% of writes | 36.0 low | 60.0 medium | 20.0 info |
| Extraction + magic on 25% of writes | **60.0 medium** | 75.0 high | 50.0 medium |
| Extraction + entropy +2σ | **46.7 medium** | 66.7 medium | 33.3 low |
| Extraction + entropy +3σ | **60.0 medium** | 75.0 high | 50.0 medium |
| Extraction + unknown extension | 100.0 critical | 100.0 critical | 100.0 critical |

The band rule, derivable from noisy-OR and matching the table: at weight $w$ the signal lifts
a companion score in $\left[\left(1 - \frac{0.55}{1-w}\right) \cdot 100,\ 45\right)$ from low
over the medium band. At $w = 0.2$ that is **31.25 to <45**; at $w = 0.5$ it was **0 to <45** —
any companion at all, which is why a benign extraction alerted alone at 50.0 live.

So 0.2 is a real improvement, not a fix. A benign extraction whose only other evidence is a
mild entropy deviation scores **33.3 (low, no alert) without the signal and 46.7 (medium,
alert) with it**. `ngram_rename_chain` is not what alerts in that case — it is what carries the
combination over the band.

**The argument for deleting it.** The signal carries no information beyond "this process
renamed a file it wrote", which the content signals already measure, and noisy-OR treats the
two as independent evidence, so it **over-counts**. That is the real case for weight 0 or
deletion. The counter-argument, and why the weight stays at 0.2 for now: a zero-weight signal
makes the Sprint 4 ablation vacuous for it — a subset comparison cannot show a change if the
signal cannot change anything.

A test pins the invariant the shipped weight encodes: a benign extraction scored with the
signal alone must stay below the medium band. Raising the weight back to 0.5 would fail a
test rather than pass silently.

### Extraction is a false-positive class with or without this signal

The more consequential finding, and it is not about `ngram_rename_chain`: **`extraction +
unknown extension` scores 100 (critical) with the signal contributing nothing.** A host whose
baseline has never seen the extracted extension alerts on `unknown_extension_activity`
(weight 1.0) alone.

That is inherent to novelty detection — a first-seen extension genuinely is novel — and
recalibration is the mitigation: a recurring benign workload has its extensions promoted and
stops alerting, which was verified end to end (§16). But a **first-time** benign extraction
of an unfamiliar file type alerts, and no weight tuning changes that.

When Sprint 4 prices the extraction workload, `ngram_rename_chain` is neither the only nor the
largest contributor. Attributing that FP class to it would be wrong.

---

## 18. Two Weight-Table Problems The Ablation Must Price

Both found while characterising signal #14, both wider than that signal.

### A Secondary signal can page an operator on its own

Measured with shipped weights, default bands (low 20, medium 45), one signal saturated and
nothing else present:

| Signal | Weight | Score alone | Level |
|---|---|---|---|
| `entropy_deviation` | 1.0 | 100.0 | critical |
| `magic_mismatch` | 1.0 | 100.0 | critical |
| `write_burst` | 1.0 | 100.0 | critical |
| `write_rate_absolute` | 1.0 | 100.0 | critical |
| `rename_burst` | 0.8 | 80.0 | high |
| **`delete_rate`** | **0.5** | **50.0** | **medium** |
| **`dir_fanout`** | **0.5** | **50.0** | **medium** |
| **`cum_bytes_rewritten`** | **0.5** | **50.0** | **medium** |
| `bus_drops` | 0.2 | 20.0 | info |
| `ngram_rename_chain` | 0.2 | 20.0 | info |

A signal is solo-alertable iff $w \cdot v \ge$ the medium band, so with the default bands **any
weight ≥ 0.45 alerts alone at full value.** Three Secondary signals therefore sit exactly five
points above the alert threshold, and one saturated `dir_fanout` or `delete_rate` pages an
operator with no second opinion — which is the opposite of what "Secondary" is supposed to
mean.

**This is a coincidence of the $(0.5, 45)$ pair, not a property of the tier.** Move medium to
55 and all three go silent; move it to 50 and they sit on the edge. That fragility is the real
finding: the weight table and the level bands were chosen independently and happen to
interact.

Two candidate fixes, and they are not equivalent:

- **weight < 0.45** for signals meant to corroborate — simple, but leaves the interaction
  implicit;
- **a Secondary signal cannot carry a verdict without a Primary companion** — encodes
  "corroborating" structurally instead of by arithmetic accident.

Price per signal rather than in bulk: `cum_bytes_rewritten` at 1 GiB is plausibly a genuine
bulk event, while `dir_fanout` at 8× baseline is plausibly just a build.

### `unknown_extension_activity` accumulates to an alert with no burst

Cumulative, benign content, no rename, files of a never-seen extension:

| Files | Score | Level |
|---|---|---|
| 10 | 20.0 | info |
| 20 | 40.0 | low |
| **30** | **60.0** | **medium — alerts** |
| 50 | 100.0 | critical |
| 200 | 100.0 | critical |

**30 files of a first-seen extension is a medium alert, 50 is critical.** Because
`ExtActivity` never decays — by design, that is what answers Gap 4 — a long-running benign
process accumulates its way there with no burst at all.

This is a lower bar than expected, and it makes the signal the ablation's flagship candidate:
it carries weight 1.0 and is the single largest contributor to the extraction false-positive
class (§17).

**Recalibration only helps the second time.** A recurring workload has its extensions promoted
and stops alerting. A first-time workload has no baseline to recalibrate from, so the answer
must be either a minimum-novelty floor — do not alert below N files of an unseen extension —
or accepting the alert as "unknown file type, watch this". That is a product decision, not a
tuning one, and it should be made deliberately rather than by leaving the threshold where it
landed.

---

## 19. The Atomic-Save False Positive

Sprint 2's benign corpus found a genuine false positive on the workload most likely to trip
it, and fixing it took three passes because each fix exposed the next contributor.

### The workload and the result

A dense batch of atomic saves — write a temp file, rename it over the target — which is what
editors, config managers and archive extractors do. Measured on a host calibrated *with* the
workload running, as the corpus intends:

| Stage | Score | Level | Signals |
|---|---|---|---|
| As found | 56.6 | medium | `dir_fanout; write_burst` |
| After the baseline fix | 50.7 | medium | `delete_rate; ngram_rename_chain` |
| After the weight fix | **45.1** | **medium** | `delete_rate; dir_fanout; entropy_deviation` |

**It still alerts, at 45.1 against a 45 band.** Each fix removed a contributor; the
combination still crosses by 0.1. Recorded as an open false positive rather than declared
fixed.

### Contributor 1: a burst measured against an arbitrary process

`write_burst` normalised against `WriteRateByProc[procName]`, and under correlative
attribution — the default, measured at **0% accuracy** — the blamed process is a guess. The
workload was blamed on `firefox.exe`, whose 1.67 writes/s baseline made a legitimate burst
look 5–10× over, where the host's 130.3 writes/s would not have fired at all.

**Fixed:** a per-process baseline is only used when attribution is causal
(`attribution.mode = "audit"`). Using a guess as a denominator is the bug, not the weight.

### Contributor 2: Secondary signals that alert alone

With the burst signal gone, `delete_rate` carried the verdict by itself. It sits at weight
0.5, and §18 established that any weight ≥ 0.45 is solo-alertable — so it scored exactly 50
against a 45 band, paging an operator with no corroboration.

**Fixed:** `delete_rate`, `dir_fanout` and `cum_bytes_rewritten` moved to 0.4, below the
solo-alertable line. A Secondary signal now corroborates rather than carrying a verdict.

### Contributor 3: noisy-OR over-counts non-independent evidence

After both fixes the score is 45.1 — three legitimate observations (`delete_rate`,
`dir_fanout`, a mild entropy shift) combining to just cross the band.

This is the residue of treating non-independent evidence as independent, which §17 identified
as the case for deleting `ngram_rename_chain` and which applies to the fusion itself. **Not
fixed**, and it should not be fixed by nudging the band: the question is whether a workload
that genuinely writes, deletes and spreads across eight directories at 53 operations/s should
alert at the *lowest* band. That is a product decision for Sprint 4 (items 4.9, 4.10).

### A limitation this exposed in recalibration

Merging pools distributions, so one recalibration lowers a large rate deviation sharply
without erasing it: `write_burst` fell from 0.81 to 0.19 in one pass, and repeated passes
converge rather than one pass settling it. The extension signal *is* fully absorbed, because
promotion is absolute. Worth knowing before telling an operator "recalibrate once and it goes
away".

### Provenance: some Sprint 2 measurements predate these fixes

The figures in §17, §18 and the drip-fragmentation finding were taken **before** the
`FILE_SHARE_DELETE`, per-kind-rate, `rateBaseline` and weight changes landed, against the
binary in `.sprint2/RateScenarios/`. Re-running the corpus against the current build will not
reproduce them:

- `cum_bytes_rewritten` now reads about **half** what was reported, because the rename
  double-count is gone;
- the quiet-drip attribution split across four fingerprints was sensitive to the 2 s
  attribution window, and attribution behaviour changed;
- the atomic-save figure moved 56.6 → 45.1 as contributors were removed.

The *conclusions* hold — each was a real defect with a mechanism — but the numbers are
pinned to a specific build. Anyone re-running for the ablation should re-measure rather than
quote these. That is Sprint 4 item 4.11, and it now covers more than the scratch programs.

### Framing for 4.9 and 4.10

The residual 45.1 is not a weight question. The workload is 480 saves across 8 directories in
27 s, with no deletes of the *targets* — the deletes are the temp files each save replaces —
and only a mild entropy shift because the payload is small config text.

So the question is not "is 53 operations/s too low a bar" but **"should a batch config-manager
save look like bulk I/O at all?"** The direction of the fix may be a workload-shape signal
rather than a weight: distinguishing a save pattern from an encryption pattern needs something
that sees the *shape*, which no current signal does. Worth deciding before spending a sprint
tuning numbers.

---

## 20. Host Mode: Where Evidence Is Filed

Sprint 2 item 2.2 failed: a 1-file-per-5s drip produced **no alert**, because the cumulative
evidence fragmented across four fingerprints (0.480 total, max 20.9). The counters were
right; the filing was wrong.

### The decision

**Attribution decides where evidence is filed, and a guess is not a filing destination.**

Correlation was measured at 0% accuracy (§11). Filing cumulative evidence against a guessed
process spreads one slow attack across whichever processes happened to be busy, and the
cumulative track — the design's answer to Gap 4 — never accumulates. The same guessed process
was also used as a rate denominator, which is what produced the atomic-save false positive
(§19).

So a third mode, `host`, is now the default:

| Mode | Attribution | Privileges | Filing |
|---|---|---|---|
| **`host`** (default) | none claimed | none | host fingerprint |
| `correlate` | largest recent writer | none | per-process — **0% accurate, kept only as the measured baseline** |
| `audit` | OS-reported writer | elevation | per-process |

`correlate` is retained deliberately: it is the comparison the causal path is measured
against, not something fit to deploy.

### Result

Drip encryption, 20 files at one per 5 seconds, host mode:

| | Before | After |
|---|---|---|
| Alerts | **0** | **85**, `score=100.0 level=critical` |
| Signals | — | `entropy_deviation; magic_mismatch; unknown_extension_activity` |

**Detection works where it previously did not.** But the exit criterion is only half met, and
saying otherwise would be dishonest:

- ✅ "crosses threshold" — yes, at critical;
- ❌ "while the decaying window stays flat" — **no.** `entropy_deviation` fired from the
  window, so the window was not flat.

The criterion's second clause assumed per-process filing, where a slow drip spreads thin
across a window. Under host aggregation the window sees every event, so it catches a drip on
its own and the cumulative track is not *necessary* to the result — it contributed
(`unknown_extension_activity`) but is no longer load-bearing.

**What this means for the paper:** the dual-track claim should be restated as it actually
behaves. The honest version is "host-level aggregation is what makes a slow drip detectable;
the cumulative track survives decay and contributes, but the window is not flat in this
mode." The claim that decay alone would miss a drip is true of per-process filing and is no
longer the configuration we ship.

### Why this is the long-term choice

The alternative — keep per-process filing and accept that drip detection requires elevation —
would make the design's answer to Gap 4 a privileged feature. Host mode makes it the default
and keeps per-process attribution as the upgrade it actually is.

This also removes the class of defect rather than instances of it: `write_burst` no longer
has an arbitrary denominator (§19), cumulative counters no longer fragment (§20), and no
verdict names a process the detector cannot identify. Verdicts now read `pid=0 process=(host)`,
which is true.

### The cost: Gap 2 requires elevation

Host mode has a consequence that was not obvious until item 2.6 exercised it, and it is worth
stating plainly rather than discovering later.

**With every file event filed at the host, there are no per-process fingerprints to aggregate,
so tree aggregation is never exercised.** Measured: the same split workload that scores a tree
at 63.2 (medium) under per-process filing produced exactly one verdict under host mode —
`root=0 process=(host) score=21.0` — and an empty attribution trace.

So the design's answer to **Gap 2 (multi-process workload splitting) does not function in the
default configuration.** Working it through, this is not a reason to change the default:

| Mode | File events land in | Tree aggregate correct? | Drip detected? |
|---|---|---|---|
| `host` | the host fingerprint | no — there is one tree, the host | **yes** |
| `correlate` | a **guessed** process | **no** — the tree structure is right (PPID is known) but the events are in the wrong branches | no (§20) |
| `audit` | the **actual** process | **yes** | yes |

`correlate` does not rescue Gap 2 either: the process tree is knowable from PPID, but a tree
that sums events filed against a guessed process is wrong. So **Gap 2 requires causal
attribution in every configuration**, and host mode is strictly better than correlate on
everything else.

**The honest mapping, which the paper must carry:**

| Gap | Unelevated (`host`) | Elevated (`audit`) |
|---|---|---|
| 1 — cross-platform | verified on Windows and Linux; macOS unverified | same |
| 2 — multi-process splitting | **not addressed** | addressed |
| 3 — single threshold | addressed | addressed |
| 4 — rigid time windows | addressed | addressed |
| 5 — host-calibrated baselines | addressed | addressed |

**Four of five gaps unelevated, five of five elevated.** That is a defensible claim and a
truthful one. The alternative — keeping `correlate` as the default so the architecture diagram
looks fully exercised — would be shipping a mode measured at 0% accuracy to make a gap appear
closed, which is exactly the kind of claim this project's own §11 exists to prevent.

Item 2.6's exit criterion is therefore met **under per-process attribution**, which is the
only configuration in which it can be met, and the sprint plan should say so rather than
implying it holds by default.

---

## 21. The npm False Positive, and One Claim That Reproduced Later

### npm alerts at critical on a benign install

The benign corpus found a second false positive, and it was reproducible: **3 of 3 spread
rounds at 100.0 critical**, 12–13 alert lines each.

```
signals="delete_rate=1.000; unknown_extension_activity=1.000; entropy_deviation=0.051"
```

**The root cause is a harness artifact, and it is worth being precise about which part is
which.** The harness calibrated for 15 s, but one npm pass takes 22 s. npm's temp-file rename
loop runs at the *end* of the pass — outside the window — so that run's baseline recorded
`known_ext = [.js, .json, .md]` with no `.tmp` and no `.log`. The measured pass then writes
~60 files with those extensions, and `unknown_extension_activity` counts them as novel and
saturates at 100 on its own.

Compare atomic-save, whose `known_ext` *does* include `.tmp` and `.log` because its writes and
renames interleave from t=0 and fall inside the window. Same signal, opposite outcome, and the
difference is whether calibration saw the workload.

**So this is two findings at once:**

1. **A harness defect:** a calibration window shorter than one workload pass leaves the
   workload's own extensions unlearned. Fixed by calibrating until a full pass has completed
   rather than for a fixed duration.
2. **A real behaviour, already recorded:** a first-seen extension alerts at 100 on its own
   (§18). This is that behaviour showing up in a benign context, which is precisely the
   false-positive class item 4.10 exists to price.

Reporting it as "npm is a false positive, cause unknown" would have been wrong, and so would
treating it as purely a harness bug. It is both, and the split matters.

**Resolution (§23).** The harness half is fixed: the calibration window is now sized from a
timed pass, and the same workload at its scripted default — **200 packages, which previously
"could not be measured at all"** — is silent.

```
baseline written ... extensions=4 processes=0
observed: calibration_ready=True filewatch_events=9234 filewatch_reporting=True
score=21.7 level=low pid=0 proc=(host) signals=rename_burst=0.186; entropy_deviation=0.081
alerts=0
```

The baseline now carries four extensions instead of three — `.tmp` and `.log` are learned —
and the workload peaks at **21.7 low with zero alerts**. The behaviour half is unchanged and
still belongs to item 4.10: a first-seen extension can still alert on its own, and a workload
that writes an extension calibration never saw is still the class that prices it.

### Atomic-save is now silent

The same run measured the workload from §19 at **peak 20 (info), zero alerts** — down from
56.6 medium, then 45.1 medium. Host mode plus the weight fixes removed it. The open defect in
§19 is closed by the §20 change, not by tuning the band.

### A claim that was not reproduced here, and later was

The agent reported that `filewatch.Start` "never returns" on a 403-directory tree. I tested
**401 directories** and **1041 directories**:

```
watching directories source=filewatch count=401     (34 ms to start)
watching directories source=filewatch count=1041    (clean run, exit 0)
```

Both start in well under a second. **Not reproduced.** It may have been specific to that
tree's shape — `node_modules` contains symlinks and deep nesting — or a misreading of a slow
run. Recorded as unreproduced rather than dismissed, because a sensor that can hang is a
fail-safe violation and worth a targeted test if anyone sees it again.

**Resolution (§23): the report was right.** It reproduced on a 403-directory tree that was
being written to while the detector started, and it is a deadlock in `filewatch`'s watch
registration — fsnotify's `Add` waits for its backend reader, and that reader waits for a
consumer that `Start` had not started yet. The two tests here passed because nothing was
writing to those trees. Fixed, with a regression test that fails on the pre-fix code.

---

## 22. The `max_delay` Curve, and a Coupling It Exposed

Item 2.9 asked for the accuracy/latency curve rather than a value that landed somewhere.
Measured on an elevated host, 3 rounds per delay, 195 decisions per round:

| `max_delay` | Accuracy | Correct | Causal | Fallback | Causal correct? |
|---|---|---|---|---|---|
| 100 ms | 90.4% | 529 / 585 | 529 | 56 | **100%** |
| 300 ms | 96.9% | 567 / 585 | 567 | 18 | **100%** |
| **500 ms** | **98.5%** | **576 / 585** | **576** | 9 | **100%** |
| 1 s | 84.6% | 495 / 585 | 583 | 2 | **84.9%** ❌ |

**The curve is not monotonic, and the reason is a coupling, not noise.**

Up to 500 ms the shape is what was expected: a longer wait captures more of the late
records, so fewer events fall back to correlation, and accuracy rises 90.4% → 96.9% → 98.5%.
Causal attribution is 100% correct at all three.

At 1 s it inverts. `causal` rises to 583 — nearly every event is now attributed causally — but
`correct` *falls* to 495. **88 causal decisions were wrong.** Two of the three rounds scored
150/195 while the first scored 195/195, so it degraded after the first round at that setting.

### The cause

`causalWindow` was `4 × delay`, floored at 2 s:

| `max_delay` | Window | Outcome |
|---|---|---|
| 100 ms | 2 s (floor) | 100% causal correct |
| 300 ms | 2 s (floor) | 100% causal correct |
| 500 ms | 2 s | 100% causal correct |
| **1 s** | **4 s** | **84.9% causal correct** |

The matcher returns the newest record for a path within the window. A 4 s window is long
enough to **span two rounds of the same workload**, and rounds reuse the same paths in a fresh
directory. So a late event that timed out found a **stale record from the previous round** and
was blamed on the previous round's writer — a real match, to the wrong write.

Every setting whose window stayed at 2 s avoided this because the previous round's records had
expired before the next began.

**So the delay and the matching window were coupled by a multiplier, and raising one silently
raised misattribution risk in the other.** Nothing about `max_delay = 1s` is unreasonable on
its face; it was the window that made it bad.

### The decisions

**1. Default is now 500 ms**, the best measured point: 98.5% with causal attribution 100%
correct. It captures 9 of the 10 late events that 300 ms missed, and the cost is 200 ms of
additional detection latency on the events that need it — small against a metric measured in
files encrypted.

**2. The coupling is bounded.** `causalWindow` is now `max(2 s, delay + 250 ms)` rather than
`4 × delay`. At 500 ms that is 2 s — **identical to the configuration measured above**, so the
result stands. At 1 s it is 2 s rather than 4 s, which removes the stale-match path.

**1 s has not been re-measured with the fix**, and the honest statement is that 500 ms is the
best *measured* point, not that it is provably optimal. If a longer delay is ever wanted, the
sweep should be re-run — it is one command.

### What this says about the method

The value that shipped before this run — 300 ms — was chosen by the agent that implemented the
mechanism. It happened to be reasonable, but it was not chosen from a measurement, and the
measurement shows it leaves 1.6 points on the table while a value one step further would have
been actively harmful. **A parameter that looks like a latency knob was also a correctness
knob**, and only a sweep showed that.

---

## 23. Sprint 2 Close-Out: An Amended Criterion, Four Harness Defects, One Deadlock

Closing 2.2 and 2.3 took one amended exit criterion, four defects in the measurement
harness, and one observation that belongs in the record. All figures below were taken on
`6329324`, the commit the sprint closed on.

### 2.2 — the clause assumed a configuration we no longer ship

The original criterion required the drip to cross the threshold "on the cumulative track
while the decaying window stays flat". That was written for per-process filing, where a slow
drip spreads thin across a window. Under the `host` filing default that shipped in §20 the
window sees every event, so the clause is unmeetable as written — and re-measuring it under
`attribution.mode = "audit"` would only demonstrate a configuration the detector does not
deploy. The criterion was amended to say what the shipped detector does, and the property the
old clause was reaching for is demonstrated separately by `rates.sh quiet-drip`.

That phase runs the same 1-file-per-5s rate with fixtures that carry no window-visible
content, so the cumulative track is the only track that can fire:

| | Value |
|---|---|
| First verdict | `info`, 6.0 — below the band |
| Later verdict | **45.9 medium** on `(host)` |
| Signals present | `unknown_extension_activity=0.480`, `cum_bytes_rewritten=0.094` |
| Signals absent from every verdict | `write_burst`, `entropy_deviation`, `magic_mismatch`, `rename_burst`, `delete_rate`, `dir_fanout` |

**The cumulative track carries a verdict alone.** That is a stronger statement than the
original clause, which only asked that the window not be the carrier.

### 2.3 — the tail half is the carrier

`rates.sh intermittent tail` measures both halves, and both now pass:

| Phase | Result |
|---|---|
| intermittent | **100.0 critical** on `(host)`; `entropy_deviation=1.000`, `magic_mismatch=1.000`, `ngram_rename_chain=1.000`, `unknown_extension_activity=0.800`; 36 alerts |
| tail | fixture: head 4.16 → z=1.22 → signal **0.204** (below the band); head+tail 6.84 → z=7.51 → **saturated** |

The tail phase's detector verdict is **94.1 critical** with `entropy_deviation=0.941` and
`magic_mismatch` **absent**. The absence is the proof: the fixture overwrites only the last
4 KiB, so the head still carries the `%PDF-1.7` magic while the sensor's head+tail sample
reads 6.84 bits/byte against a baseline of 3.639. The head half alone would not have crossed
the band (0.204), so the sample's tail half is what catches it.

### A startup stall, reproduced and root-caused

§21 recorded, as unreproduced, a report that `filewatch.Start` "never returns" on a
403-directory tree; it was tested against 401 and 1041 directories and started in under a
second both times. **It happened again during this close-out, at 403 directories, and this
time it reproduced on demand.**

The false-positive harness's calibration detector sat for **4 m 43 s** after
`platform detected` with no further log line — `watching directories` never appeared, which
places the stall inside `filewatch.Start`'s tree walk. It was killed by hand. The identical
tree, immediately afterwards and with the host idle, started in **32 ms**. Then the harness
was re-run, and the same tree hung again — this time the harness's new bounded wait caught
it, and a standalone run reproduced the hang with nothing else on the host:

```
time=... level=INFO msg="platform detected" os=windows
(no further output; killed at 45 s)
```

**The cause is a deadlock in the watch registration, not a slow machine.** A probe that
times `watcher.Add` per directory produced the runtime's own verdict:

```
... 150 dirs, 14.05ms elapsed
fatal error: all goroutines are asleep - deadlock!

goroutine 1 [chan receive]:
  fsnotify.(*readDirChangesW).AddWith(...)   backend_windows.go:145
  main.main.func1(...)                        probe-addtree/main.go:29
goroutine 8 [select, locked to thread]:
  fsnotify.(*readDirChangesW).sendEvent(...)  backend_windows.go:76
  fsnotify.(*readDirChangesW).readEvents(...) backend_windows.go:642
```

fsnotify's Windows `Add` sends the request to the backend and then waits for a reply on a
channel (`<-in.reply`). The backend's reader goroutine is the one that answers — and it
blocks while an event is waiting to be consumed (`sendEvent`, on a bounded `Events` channel).
`Start` registered every watch *before* starting the goroutine that consumes events, so on a
tree that is being written to, the reader filled the event buffer and stopped answering,
while `Start` waited for an answer. Neither side could move.

That explains every observation: the idle tree starts in milliseconds (no events, nothing to
block on), the count of directories is incidental (it only sets how long the window is open),
and §21's 401- and 1041-directory tests passed because nothing was writing to those trees.

**Fixed in `internal/sensor/filewatch`:**

1. **The consumer starts before the first watch is added.** The event channel always has a
   reader, so the reader can always answer an `Add`.
2. **Directories discovered at runtime are queued, not added inline.** The event loop is the
   only consumer of the events that `Add` waits behind, so calling `Add` from inside it is the
   same deadlock one directory later. A worker goroutine owns those adds; a full queue
   (256) is counted as `add_dropped` and surfaced through `/healthz`, per the invariant that a
   bounded queue never drops silently.

**Verified three ways.** The probe above deadlocks on the old code and completes on the new
one. A regression test (`TestStartReturnsWhileTheTreeIsBeingWritten`, a 300-directory tree
written to while `Start` walks it) fails on the pre-fix code with *"Start did not return while
the tree was being written: the watch registration deadlocked"* and passes with the fix; a
second test covers the runtime-added-directory path. And the tree that hung for 45 s+ now
starts in **56 ms** (`platform detected` 14:21:32.290, `watching directories count=403`
14:21:32.346).

**What this says about the method.** The original report was correct and was recorded as
"unreproduced" — which was the right thing to write at the time, because it had been tested
twice on idle trees and started fast both times. The reproduction only became possible when
the harness began writing to the tree *while* the detector started, which is what a real
deployment does. A hang that needs load to appear will not show up in a quiet test.

### The npm false positive is gone, and the harness was half of it

§21 split npm's 100/critical alert into a harness defect (a 15 s calibration window against a
69 s workload pass) and a real behaviour (a first-seen extension alerting alone, §18). The
harness half is now fixed, and the workload is silent at its scripted default:

| | Before | After |
|---|---|---|
| Packages | 50 (200 could not be measured) | **200** |
| Baseline extensions | 3 — `.tmp` and `.log` unlearned | **4** |
| Peak verdict | 100.0 critical, 12–13 alerts | **21.7 low, 0 alerts** |

`rename_burst=0.186` and `entropy_deviation=0.081` are the only signals left. The behaviour
half is unchanged: a workload that writes an extension calibration never saw still alerts on
its own, which is exactly what item 4.10 exists to price.

### The harness defects this exposed

Measuring on a busy host found four defects in the measurement instrument itself, all fixed:

1. **A calibration window shorter than one workload pass.** The window was a fixed 15 s while
   one npm pass takes 69 s, so the pass's own late writes — the temp-file rename loop lands in
   its final seconds — fell outside the baseline and their extensions came back as first-seen
   novelty in the measured pass. This is the harness half of §21's false positive. The window
   is now sized from a timed pass (`GRIMA_FP_WARMUP` overrides it).
2. **`pick_python` proved nothing.** It accepted a candidate that satisfied `-c 'import sys'`,
   which the Windows Store `python3` stub does before failing to open any script. It now
   requires the candidate to evaluate and print a value.
3. **An unbounded wait.** The harness waited on the calibration process forever, so a stalled
   detector produced no output at all instead of a diagnosis. The wait is now bounded and the
   stall is reported with the detector's last log lines.
4. **`smoke.sh` could not run its own encryptor leg.** It resolved python with `command -v
   python3`, which on Windows finds the Store stub — a command that resolves and then fails to
   open any script. The smoke test therefore reported "encryptor fixture failed" and never
   exercised detection end to end, while CI, which runs the Linux variant on a real python3,
   stayed green. Found only because the smoke test was run here after the other harnesses were
   fixed. Both smoke scripts now require the interpreter to evaluate and print a value.

A work-root guard was added alongside them: under WSL, `/tmp` converts to a
`//wsl.localhost/...` path the detector cannot watch, and the run then reported an empty
baseline and a dead sensor instead of a misconfigured path. Both harnesses now fail fast on a
work root that is not drive-lettered. `rates.sh` also pins `attribution.mode` rather than
inheriting the default, so a future change to the default cannot silently re-point every
measurement underneath it.

### Provenance

The three-phase rates run and the false-positive run were both taken with the repository's own
scripts, under Git Bash, against `grima.exe` built from `6329324`. Raw output is in
`.sprint2/RateScenarios/rerun/` (scratch, gitignored). One caveat on the raw tail-phase output:
a concurrently running subagent's end-to-end test had a process whose command line matched
`R-EVENTLOG-CLEAR`, so the series also contains `critical score=0.0` override verdicts naming
`python.exe`. Those are that test's artifact, not the fixture's — the entropy evidence the
phase asserts is a separate verdict line and is unaffected.

---

## 24. The Cerberus Split: What Is Asserted, and What Is Only Measured

Sprint 3 item 3.3 asked for a workload that splits encryption across cooperating children,
built and detected. The workload is built and the detection is measured; the *live*
per-process half turned out not to be assertable on this host, and the reason is worth
recording rather than smoothing over.

### The workload is genuinely cooperative

`split.py --claim` gives the children one shared pool and an exclusive marker per file: a
child rewrites the files it wins the claim for, and which child that is depends on timing
rather than on a partition the parent handed out. Measured: **960 files, 960 claims**, split
**119–121 per child** across 8 workers — uneven, which is the evidence that nothing assigned
the work. No process owns a partition of the encryption.

### Detection, in the shipped default: asserted and passing

`attribution.mode = "host"` files every write against the host fingerprint, so the aggregate
rate is the workload's whole rate. Against the default uncalibrated threshold of 20 writes/s
with a 2 s window:

| | Value |
|---|---|
| Verdict | `pid=0 proc=(host)` **95.8 critical** |
| Signals | `write_rate_absolute=0.950`, `cum_bytes_rewritten=0.417` |
| Observed | 911 file events, `bus_dropped=0` |

`testdata/scenarios/cerberus.sh split` asserts exactly this and passes.

### The aggregation itself: pinned deterministically

`internal/fingerprint/split_test.go` drives the engine from the outside on synthetic events:
each of six children writes 180 times inside a ten-second window — 18 writes/s, above the
20/s threshold only in the sense that matters (no signal fires, so nothing is reported) —
and the aggregate of the root plus all six crosses into the medium band. No timing, no
attribution, no host. **That test is the reproducible evidence for the aggregation claim.**

### The live per-process measurement is a race, not a result

The same cooperative workload under `attribution.mode = "correlate"`, with a launcher holding
the tree open so the workers have one live root, produced this:

| Run | Root that carried the crossing | Members | Workload's own tree |
|---|---|---|---|
| 2.6, 2026-09-24 | `python.exe` pid 7712 — the workload's parent | 6 | ✅ 100 critical |
| §24, run 1 | `explorer.exe` | 41 | ❌ never carried it |
| §24, run 2 | `explorer.exe` | 41 | ❌ never carried it |

Correlative attribution blames the largest recent byte-writer, which was measured at **0%
accuracy** on a known-writer workload (§11). On a desktop that is doing anything else, the
workload does not reliably win that race, and when it loses, the evidence lands in the
desktop shell's tree — where it still crosses the threshold, for the wrong reason. The 2.6
run won the race; two later runs of the same shape did not.

**So the honest statement is two-part.** The aggregation is verified: deterministically by
the engine test, and in the shipped configuration by the host-filing measurement. The claim
that a *per-process* view of a split workload is what fails, while the tree view catches it,
is only measurable where the writer is known — that is, under causal attribution, which
needs elevation. It is carried into Sprint 4 as item 4.13.

`cerberus.sh correlate` is therefore a characterisation phase: it prints which root carried
the crossing and whether that root was the workload's own, and it does not fail the run.
Asserting a stable outcome there would be asserting a coin flip.

---

## 25. Startup Has No Bound Under Load — Proposed Design Change

### What the deadlock fix left behind

§23 removed a hang: the consumer now starts before the first watch is added, and directories
discovered at runtime are queued rather than registered on the event loop. What remains is a
**rate coupling**, and it only shows up under load.

| Shape | `Start` returns in |
|---|---|
| Pre-fix, 300-directory tree, writer running | never — the deadlock §23 describes |
| Post-fix, same shape, uninstrumented | **8–11 s** |
| Post-fix, same shape, under `-race` | **past 60 s** |

The goroutine dump says nothing is stuck: fsnotify's `readEvents` is blocked in `sendEvent`
on a full 128-event channel, our loop is inside `readSample` doing its work, and the walk's
`Add` is waiting behind the queue. The walk advances at the consumer's drain rate, so a
writer that outruns the consumer stretches startup for as long as it keeps writing.

### Why this is a conformance problem, not just a slow path

`docs/design.md` §3 contract 1 already says: *"`Start` returns once the source is observing,
not when it finishes. It must not block for the lifetime of the process."* The implementation
walks every directory before returning, so on a large tree under load it returns when the
**walk** finishes, not when the source is observing. The code disagrees with the
specification, and by this repo's rule that makes the code the bug.

The cost is not confined to one sensor: `app.startSensors` starts sources in sequence and the
score loop starts only after all of them, so a slow `filewatch` walk delays `procwatch`,
`persistwatch` and every verdict — the detector is blind for as long as the walk takes.

### Proposed change

Bound the walk, keep what is watched, queue the remainder.

- `filewatch.Start` walks with a deadline: `filewatch.startup_deadline`, default **10 s**,
  `0` meaning unbounded (today's behaviour).
- On expiry: log how many directories are watched and how many remain, hand the remainder to
  the existing `addWorker` queue, and return.
- Contract 4 still holds: if **nothing** is watched when the deadline expires, return the
  error and be skipped — the detector never starts blind.
- Two counters in `/healthz`: `add_pending` (queued, not yet registered) next to the existing
  `add_dropped`.
- `design.md` §3 contract 1 gains one sentence: *observing* means at least one monitored root
  is watched; the remainder may be registered after `Start` returns, and a directory whose
  watch has not landed yet is covered by the overflow rescan until it does.

**Rejected alternatives.**

- *Register watches without fsnotify's handshake.* Not possible: `Add` always handshakes with
  the backend reader, which is the mechanism §23 is about.
- *Document the bound and change nothing.* Cheapest, no interface change, but it leaves the
  worst case unbounded in principle and leaves `Start` non-conforming to its own contract.
- *Persist a watch list between runs.* The list goes stale, and a stale watch is worse than a
  late one — it looks like coverage that is not there.

**Acceptance criteria, if adopted.** A test that a tree larger than the deadline returns
within the deadline plus a margin with the remainder counted; the §23 deadlock regression
still failing on pre-fix code; a measurement that `add_pending` reaches zero once the workload
stops; `design.md` §3.1 and §13 updated in the same change.

**Cost.** Around half a day, most of it the "returns early and the tree still completes" test.

**Status.** Adopted as item 4.14. `filewatch.startup_deadline` defaults to 10 s; the walk
past the deadline is queued to the worker and counted as `add_pending`, the root is always
registered inline so a deadline that has already passed still leaves the sensor observing
something, and a full queue falls back to registering inline rather than leaving a directory
blind. Verified: the 403-directory tree registers inline in 92 ms with `add_pending` 0, a
600-directory tree with a nanosecond deadline returns immediately with the rest pending and
ends fully covered, and `Start` with no deadline behaves exactly as before.

---

## 26. Corroboration Is Structural, Not Arithmetic

Sprint 4 items 4.9 and 4.10 exist because Sprint 2 measured two arithmetic problems in the
weight table (§18). Both are now closed by measurement, and the fix for the first is not the
one the item proposed.

### The problem the weight table could not solve

§18 measured a Secondary signal paging an operator on its own, and the shipped response was to
put every Secondary at 0.4 — below the medium band, so no single one can reach it. That bounds
each signal and says nothing about a **combination**, which is the shape the arithmetic invites:

| Evidence, no Primary present | Score | Level |
|---|---|---|
| `delete_rate` + `dir_fanout` + `cum_bytes_rewritten` + `ngram_rename_chain` + `bus_drops`, all saturated | **86.2** | high |
| `static_reputation` alone at its configured 0.6 | **60.0** | medium |

The first is reachable today: five Secondary observations of the same attack, none of which may
alert, fusing to a high alert. The second is a trap waiting for Phase 7 to emit
`static_reputation` — a Secondary by design (`design.md` §5), configured above the band. Neither
is a tuning error; both are what a per-signal bound leaves open.

### The decision

**A Secondary signal corroborates; it does not carry a verdict.** Secondaries fuse only while at
least one Primary is present. They are still reported in `Verdict.Signals` — the operator sees
all the evidence — they simply cannot decide on their own, in any combination.

The alternative the item suggested — keep lowering weights — was rejected because it ties the
tier's *meaning* to the band value: a Secondary is a statement about evidence strength, and
"weight < 45" is a statement about arithmetic. Gating on a Primary makes the two impossible at
any band, and it gives `design.md` a checkable invariant: **`Level >= Medium` implies a Primary
contributed, or an Override set the floor.**

### 4.10: the first-seen-extension alert is kept, and priced

The other half of §18 is that 30 files of a never-seen extension reach the medium band and
accumulate without a burst. The decision is to **accept it and state the cost**: 23 novel writes
cross the 45 band, 30 files score 60.0.

A minimum-novelty floor was measured and rejected, and the reason is the sharper finding: the
signal that carries a first-seen extension — `unknown_extension_activity` — is also what carries
the **quiet drip** that item 2.2 rests on. Any floor low enough to be safe is high enough to
silence a 24-file drip; the floor that moves 30 novel files below the band moves the drip below
it too. The false-positive class and the detection are the same signal at different rates, so
the honest answer is the alert, with the trade recorded rather than hidden.

### What it cost, and how it was checked

`alertability_test.go` prices every signal in the table — saturated alone, through the real
scorer — and asserts that no combination of Secondaries can carry a verdict. One existing
assertion was re-pinned rather than kept: `TestNGramRenameChainReachesTheVerdict` asserted a
non-zero score *from the n-gram signal alone*, which is exactly the solo alertability this
change removes.

A fusion change is cross-cutting, so the scenarios that rest on the old arithmetic were re-run
on the shipped binary: smoke **100.0 critical**, `rates.sh quiet-drip` still crosses at **49.9
medium** (the cumulative track is a Primary, so the gate does not touch it), `cerberus.sh split`
**95.2 critical**. The benign corpus was re-measured after the change as well: all six workloads
silent, npm peaking at 23.4 low.
