#!/usr/bin/env python3
"""Ablation runner: one metric row per signal subset, over the same corpus.

This is the paper's results table. Each subset restricts which signals may move
the score — by zeroing every weight outside the subset, so a signal still appears
in the verdict as evidence but cannot contribute to the decision — and each
scenario runs against the same detector, the same corpus and the same window.

Subsets are cumulative, so a row is the *addition* of one group of signals:

    rules_only    nothing but the rule overrides; no weights at all
    +entropy      content signals: entropy deviation, magic-byte mismatch
    +rename       rename/extension shape: rename burst, n-gram rename chain,
                  first-seen extension activity
    +calibration  the baseline-dependent deviations: write burst, delete rate,
                  directory fan-out, cumulative bytes, absolute write rate
    all           the shipped weight table

`rules_only`, `+entropy` and `+rename` run uncalibrated; `+calibration` and `all`
capture a baseline first. That is deliberate: the calibration group is exactly
the set of signals that needs one, so measuring them without a baseline would
measure their absence.

Metrics per subset (docs/sprints.md item 4.4):

  DR @ 1% FPR   detection rate at the threshold where the benign corpus reaches
                a 1% false-positive rate, from a sweep over the observed scores
  TTD bytes     bytes encrypted before the first alert, median and 95th
                percentile, from the encryptor's own progress lines
  FPR / 24h     false positives per 24h of benign activity

Usage:
  ablate.py [--work DIR] [--rounds N] [--subsets a,b,...] [--attacks a,b,...]
            [--benign a,b,...] [--duration S] [--out FILE] [--port N]
            [--binary PATH] [--keep]

Exit status is 0 only if every subset produced at least one attack row and one
benign row; a subset that measured nothing is an error, not a zero.
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import signal
import subprocess
import sys
import time
import urllib.error
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(os.path.dirname(HERE))

LEVELS = ["info", "low", "medium", "high", "critical"]
MEDIUM = 2

# Signal names, in the order they appear in the shipped weight table.
ALL_SIGNALS = [
    "entropy_deviation",
    "magic_mismatch",
    "write_burst",
    "write_rate_absolute",
    "rename_burst",
    "ngram_rename_chain",
    "unknown_extension_activity",
    "delete_rate",
    "dir_fanout",
    "cum_bytes_rewritten",
    "static_reputation",
    "bus_drops",
]

SUBSETS = {
    "rules_only": {"signals": [], "calibrated": False},
    "+entropy": {
        "signals": ["entropy_deviation", "magic_mismatch"],
        "calibrated": False,
    },
    "+rename": {
        "signals": [
            "entropy_deviation",
            "magic_mismatch",
            "rename_burst",
            "ngram_rename_chain",
            "unknown_extension_activity",
        ],
        "calibrated": False,
    },
    "+calibration": {
        "signals": [
            "entropy_deviation",
            "magic_mismatch",
            "rename_burst",
            "ngram_rename_chain",
            "unknown_extension_activity",
            "write_burst",
            "write_rate_absolute",
            "delete_rate",
            "dir_fanout",
            "cum_bytes_rewritten",
        ],
        "calibrated": True,
    },
    "all": {"signals": ALL_SIGNALS, "calibrated": True},
}

DEFAULT_ATTACKS = ["burst", "drip", "intermittent"]
DEFAULT_BENIGN = [
    "benign-compile.sh",
    "benign-npm-install.sh",
    "benign-archive.sh",
    "benign-media-encode.sh",
    "benign-atomic-save.sh",
    "benign-git-objects.sh",
]

# One pool per rate, sized so the workload outlives the detector's evaluation
# latency. Time-to-detect is only informative where the attack is still running
# when the detector fires: a burst that finishes inside the first scoring tick
# reports the whole corpus as its TTD, which says nothing about the detector.
#
# drip writes one file every 5s, so it needs the smallest pool to stay bounded.
ATTACK_POOL = {
    "burst": {"files": 300, "bytes": 65536},
    "intermittent": {"files": 120, "bytes": 65536},
    "drip": {"files": 20, "bytes": 65536},
}
ATTACK_TIMEOUT = {"burst": 120.0, "drip": 240.0, "intermittent": 120.0}
BENIGN_TIMEOUT = 180.0


def parse_args() -> argparse.Namespace:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--work", default="", help="work root (default: $TEMP/grima-ablation)")
    ap.add_argument("--rounds", type=int, default=1, help="rounds per (subset, scenario)")
    ap.add_argument("--subsets", default=",".join(SUBSETS))
    ap.add_argument("--attacks", default=",".join(DEFAULT_ATTACKS))
    ap.add_argument("--benign", default=",".join(DEFAULT_BENIGN))
    ap.add_argument("--duration", type=float, default=30.0,
                    help="floor for the measured detector run, seconds; a scenario that "
                         "needs longer gets longer")
    ap.add_argument("--warmup", default="15s", help="calibration window for calibrated subsets")
    ap.add_argument("--out", default="", help="results JSON (default: <work>/ablation.json)")
    ap.add_argument("--port", type=int, default=8798)
    ap.add_argument("--binary", default="")
    ap.add_argument("--python", default=sys.executable)
    ap.add_argument("--keep", action="store_true", help="keep each run's logs")
    return ap.parse_args()


def host_path(path: str) -> str:
    """A path the detector (a native binary) can open."""
    return path.replace("\\", "/")


def find_binary(explicit: str) -> str:
    if explicit:
        return explicit
    for candidate in (os.path.join(REPO, "grima"), os.path.join(REPO, "grima.exe")):
        if os.path.isfile(candidate):
            return candidate
    sys.exit("error: no detector binary; run make build or pass --binary")


def find_bash() -> str:
    """The interpreter the benign workloads run under.

    On Windows, bare `bash` is the WSL launcher, which cannot open the
    drive-letter paths this script hands it; Git Bash is what the workloads are
    written for. GRIMA_ABLATE_BASH overrides.
    """
    explicit = os.environ.get("GRIMA_ABLATE_BASH")
    if explicit:
        return explicit
    if os.name == "nt":
        for candidate in (r"C:\Program Files\Git\bin\bash.exe",
                          r"C:\Program Files\Git\usr\bin\bash.exe"):
            if os.path.isfile(candidate):
                return candidate
    return "bash"


def write_config(path: str, monitor: str, baseline: str, subset: str, calibrated: bool, warmup: str) -> None:
    """One config per (subset, run). Every signal is listed; the ones outside the
    subset are weighted 0, so they still appear as evidence but cannot move the
    score — which is what "signal subset" has to mean if the verdict is to stay
    readable."""
    allowed = set(SUBSETS[subset]["signals"])
    lines = [
        "[general]",
        f'monitor_paths = ["{host_path(monitor)}"]',
        'log_level = "info"',
        "",
        "[web]",
        "enabled = true",
        f'listen = "127.0.0.1:{CONFIG["port"]}"',
        "",
        "[decoy]",
        "enabled = false",
        "",
        "[attribution]",
        "# Pinned: per-process filing needs elevation and would confound the",
        "# comparison between subsets.",
        'mode = "host"',
        "",
        "[procwatch]",
        'sample_interval = "500ms"',
        "",
        "[calibration]",
        f'warmup = "{warmup}"',
        "min_samples = 20",
        f'baseline_path = "{host_path(baseline)}"',
        "",
        "[window]",
        'decay_half_life = "10s"',
        "",
    ]
    for name in ALL_SIGNALS:
        lines += ["[[scoring.weights]]", f'name = "{name}"',
                  f"weight = {1.0 if name in allowed else 0.0}", ""]
    if not calibrated:
        lines += ["# Uncalibrated on purpose: this subset has no baseline-dependent signal."]
    with open(path, "w", encoding="utf-8") as handle:
        handle.write("\n".join(lines) + "\n")


CONFIG: dict = {}


class Run:
    """One detector run, with the scenario driven against it."""

    def __init__(self, work: str, config: str, binary: str, duration: float):
        self.work = work
        self.log_path = os.path.join(work, "grima.log")
        self.log = open(self.log_path, "w", encoding="utf-8", errors="replace")
        self.proc = subprocess.Popen(
            [binary, "--config", config, "--duration", f"{int(duration)}s"],
            stdout=self.log, stderr=subprocess.STDOUT,
        )
        self.first_alert_at: float | None = None
        self.alerts = 0
        self.max_score = 0.0
        self.max_level = 0
        self.best_signals: list[str] = []
        self.signal_values: dict[str, float] = {}
        self._log_pos = 0
        self._poll_at = 0.0

    def scan_log(self) -> None:
        """Count alerts and stamp the first one, from the detector's own log."""
        with open(self.log_path, "r", encoding="utf-8", errors="replace") as handle:
            handle.seek(self._log_pos)
            for line in handle:
                if "ransomware risk detected" in line:
                    self.alerts += 1
                    if self.first_alert_at is None:
                        self.first_alert_at = time.monotonic()
            self._log_pos = handle.tell()

    def poll_verdicts(self) -> None:
        url = f"http://127.0.0.1:{CONFIG['port']}/api/verdicts"
        try:
            with urllib.request.urlopen(url, timeout=3) as response:
                verdicts = json.load(response)
        except (urllib.error.URLError, OSError, ValueError):
            return
        for v in verdicts or []:
            if v.get("Score", 0) > self.max_score:
                self.max_score = v["Score"]
                self.max_level = v.get("Level", 0)
                self.best_signals = [s["Name"] for s in (v.get("Signals") or [])]
            # The highest value each signal reached, so a characterisation like
            # §17's "what does the n-gram share look like on this workload" is
            # reproducible from the harness rather than from a scratch program.
            for s in v.get("Signals") or []:
                name = s["Name"]
                if s["Value"] > self.signal_values.get(name, 0.0):
                    self.signal_values[name] = round(s["Value"], 3)

    def tick(self) -> None:
        self.scan_log()
        now = time.monotonic()
        if now - self._poll_at >= 2.0:
            self._poll_at = now
            self.poll_verdicts()

    def stop(self) -> None:
        self.scan_log()
        self.poll_verdicts()
        self.proc.terminate()
        try:
            self.proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            self.proc.kill()
        self.log.close()


def run_scenario(run: Run, argv: list[str], timeout: float) -> dict:
    """Drive one scenario against a running detector, sampling both streams.

    The encryptor's progress lines and the detector's alert lines are stamped
    with the same clock here, so time-to-detect in bytes is the byte count on the
    last progress line before the first alert — the work done before it fired.
    """
    progress_bytes = 0
    progress_at_first_alert: int | None = None
    summary_line: str | None = None
    started = time.monotonic()
    proc = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                            text=True, bufsize=1, env=scenario_env())
    assert proc.stdout is not None
    deadline = started + timeout
    for line in proc.stdout:
        run.tick()
        if line.startswith("progress "):
            fields = dict(part.split("=", 1) for part in line.split()[1:] if "=" in part)
            progress_bytes = int(fields.get("bytes", 0))
        if line.startswith("SUMMARY "):
            summary_line = line.strip()
        if run.first_alert_at is not None and progress_at_first_alert is None:
            progress_at_first_alert = progress_bytes
        if time.monotonic() > deadline:
            proc.kill()
            break
    proc.wait(timeout=30)
    elapsed = time.monotonic() - started

    # The alert can land between the last progress line and the workload's exit;
    # the loop above only samples while lines are arriving, so the log is read
    # once more before the row is closed. The byte count then is everything the
    # workload wrote, which is the honest figure for "it fired after the work was
    # finished" rather than a missing value.
    run.tick()
    if run.first_alert_at is not None and progress_at_first_alert is None:
        progress_at_first_alert = progress_bytes

    return {
        "elapsed_s": round(elapsed, 1),
        "bytes_written": progress_bytes,
        "ttd_bytes": progress_at_first_alert,
        "ttd_seconds": round(run.first_alert_at - started, 2) if run.first_alert_at else None,
        # A workload that wrote nothing also produces no alert, so a silent row
        # without this line is not a measurement of anything.
        "workload_summary": summary_line,
    }


def prepare_pool(pool: str, files: int, size: int) -> None:
    shutil.rmtree(pool, ignore_errors=True)
    os.makedirs(pool, exist_ok=True)
    payload = b"ordinary document content for the ablation pool\n" * (size // 45 + 1)
    for i in range(files):
        with open(os.path.join(pool, f"doc_{i:04d}.txt"), "wb") as handle:
            handle.write(payload[:size])


def warmup_workload(data: str, seconds: float) -> None:
    """Benign activity during calibration, so the baseline is not captured on an
    idle host — an idle baseline makes every deviation signal meaningless."""
    end = time.monotonic() + seconds
    round_no = 0
    while time.monotonic() < end:
        for i in range(40):
            with open(os.path.join(data, f"warm_{i}.txt"), "w", encoding="utf-8") as handle:
                handle.write(f"ablation warm-up round {round_no} file {i} ordinary prose\n")
        round_no += 1
        time.sleep(2)


def scenario_env() -> dict:
    """Environment for a workload.

    GNU tar reads `C:/...` as a remote `host:path` and silently produces no
    archive under Git Bash, which would make the archive workload look silent
    because it wrote nothing. benign-fp-check.sh does the same for the same
    reason.
    """
    env = dict(os.environ)
    try:
        version = subprocess.run(["tar", "--version"], capture_output=True, text=True, timeout=10).stdout
        if "GNU tar" in version:
            env["TAR_OPTIONS"] = f"--force-local {env.get('TAR_OPTIONS', '')}".strip()
    except (OSError, subprocess.SubprocessError):
        pass
    return env


def time_workload(argv: list[str]) -> float:
    """One pass, timed, before the detector exists. The calibration window has to
    cover a whole workload pass: a window shorter than the pass leaves the pass's
    own late writes — and therefore their extensions — outside the baseline, and
    the measured pass then reports them as first-seen novelty. That is the defect
    that made npm look like a false positive (sprints.md §21), and it is why this
    pass exists rather than a fixed window."""
    started = time.monotonic()
    subprocess.run(argv, stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT,
                   env=scenario_env(), timeout=BENIGN_TIMEOUT + 120)
    return time.monotonic() - started


def calibrate(binary: str, config: str, data: str, warmup_seconds: float,
              warmup_argv: list[str] | None = None) -> str:
    """Capture a baseline, returning the detector's log for the record.

    For an attack run the warm-up is synthetic text: the pool is static, and what
    the attack then does to it is the deviation. For a benign workload the
    workload itself runs during calibration, inside a window sized to cover it.
    """
    log_path = os.path.join(os.path.dirname(config), "calibrate.log")
    with open(log_path, "w", encoding="utf-8", errors="replace") as log:
        proc = subprocess.Popen([binary, "--config", config, "--calibrate"], stdout=log, stderr=subprocess.STDOUT)
        if warmup_argv is None:
            warmup_workload(data, warmup_seconds)
        else:
            subprocess.run(warmup_argv, stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT,
                           env=scenario_env(), timeout=warmup_seconds + 120)
        try:
            proc.wait(timeout=warmup_seconds + 60)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()
    return log_path


def one_run(args, binary: str, subset: str, scenario: str, kind: str, rnd: int) -> dict:
    name = f"{subset.replace('+', 'p')}-{scenario}-r{rnd}"
    work = os.path.join(args.work, name)
    shutil.rmtree(work, ignore_errors=True)
    os.makedirs(work, exist_ok=True)
    data = os.path.join(work, "data")
    os.makedirs(data, exist_ok=True)
    baseline = os.path.join(work, "baseline.json")
    config = os.path.join(work, "grima.toml")
    calibrated = SUBSETS[subset]["calibrated"]

    if kind == "attack":
        pool = ATTACK_POOL[scenario]
        prepare_pool(data, pool["files"], pool["bytes"])
        scenario_timeout = ATTACK_TIMEOUT[scenario]
        scenario_argv = [args.python, os.path.join(HERE, "encryptor.py"),
                         "--path", data, "--rate", scenario, "--seed", "7"]
    else:
        scenario_timeout = BENIGN_TIMEOUT
        scenario_argv = [find_bash(), os.path.join(HERE, scenario), data]

    write_config(config, data, baseline if calibrated else os.path.join(work, "absent.json"),
                 subset, calibrated, args.warmup)

    warmup_seconds = float(args.warmup.rstrip("s")) if args.warmup.endswith("s") else 15.0
    if calibrated:
        if kind == "benign":
            # Size the window to the workload before the detector is told how
            # long to calibrate: a fixed window shorter than the pass is the
            # §21 defect, and it shows up as a false positive on the workload
            # whose late writes fell outside it.
            warmup_seconds = max(warmup_seconds, time_workload(scenario_argv) + 5.0)
            write_config(config, data, baseline, subset, calibrated, f"{warmup_seconds:.0f}s")
        calibrate(binary, config, data, warmup_seconds,
                  warmup_argv=None if kind == "attack" else scenario_argv)

    # The detector outlives the scenario and is terminated when the scenario
    # ends, so this only has to be generous enough not to cut a workload short.
    run = Run(work, config, binary, max(args.duration, scenario_timeout) + 15)
    time.sleep(4)  # let the sensors start before the scenario begins
    run.tick()

    try:
        detail = run_scenario(run, scenario_argv, timeout=scenario_timeout)
    finally:
        run.stop()

    if kind == "benign":
        # Byte figures come from the encryptor's progress lines, so they mean
        # nothing for a workload that has none. Reporting 0 would read as
        # "detected before a single byte", which is not what happened.
        detail["bytes_written"] = None
        detail["ttd_bytes"] = None

    row = {
        "subset": subset,
        "scenario": scenario,
        "kind": kind,
        "round": rnd,
        "max_score": round(run.max_score, 1),
        "max_level": LEVELS[run.max_level],
        "alerts": run.alerts,
        "signals": run.best_signals,
        "signal_values": run.signal_values,
        **detail,
    }
    if not args.keep:
        shutil.rmtree(data, ignore_errors=True)
    print("  {kind:<6} {scenario:<22} score={max_score:>5} {max_level:<8} alerts={alerts:<3}"
          " ttd_bytes={ttd_bytes} bytes={bytes_written}".format(**row), flush=True)
    return row


def percentile(values: list[float], pct: float) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    index = min(len(ordered) - 1, int(round((pct / 100.0) * (len(ordered) - 1))))
    return ordered[index]


def dr_at_fpr(rows: list[dict], fpr_target: float = 0.01) -> tuple[float | None, float | None]:
    """Detection rate at the lowest threshold whose benign false-positive rate is
    at or below the target, from the observed score distributions."""
    attacks = [r for r in rows if r["kind"] == "attack"]
    benign = [r for r in rows if r["kind"] == "benign"]
    if not attacks or not benign:
        return None, None
    best_dr, best_threshold = None, None
    for threshold in range(101):
        fpr = sum(1 for r in benign if r["max_score"] >= threshold) / len(benign)
        if fpr > fpr_target:
            continue
        dr = sum(1 for r in attacks if r["max_score"] >= threshold) / len(attacks)
        if best_dr is None or dr > best_dr:
            best_dr, best_threshold = dr, threshold
    return best_dr, best_threshold


def summarise(rows: list[dict]) -> list[dict]:
    """Per-subset metrics, computed per round and then reported as a spread.

    Item 4.12 is explicit that one run of one scenario is not a figure: two runs
    of the same scenario disagreed by 44 points for a purely environmental reason
    (§15). So every headline number here is a range over rounds, with the round
    count beside it, and a single-round run says so rather than pretending to a
    spread it does not have.
    """
    out = []
    for subset in dict.fromkeys(r["subset"] for r in rows):
        group = [r for r in rows if r["subset"] == subset]
        rounds = sorted({r["round"] for r in group})
        per_round = []
        for rnd in rounds:
            in_round = [r for r in group if r["round"] == rnd]
            attacks = [r for r in in_round if r["kind"] == "attack"]
            benign = [r for r in in_round if r["kind"] == "benign"]
            ttd = [r["ttd_bytes"] for r in attacks if r.get("ttd_bytes") is not None]
            minutes = sum(r["elapsed_s"] for r in benign) / 60.0
            dr, threshold = dr_at_fpr(in_round)
            per_round.append({
                "round": rnd,
                "attack_runs": len(attacks),
                "benign_runs": len(benign),
                "detected": sum(1 for r in attacks if LEVELS.index(r["max_level"]) >= MEDIUM),
                "dr_at_1pct_fpr": round(dr, 3) if dr is not None else None,
                "threshold_at_1pct_fpr": threshold,
                "ttd_bytes_median": percentile(ttd, 50),
                "ttd_bytes_p95": percentile(ttd, 95),
                "benign_alerts": sum(r["alerts"] for r in benign),
                "fpr_per_24h": round(sum(r["alerts"] for r in benign) / minutes * 1440, 1) if minutes > 0 else None,
                "unmeasured_workloads": sum(1 for r in benign if not r.get("workload_summary")),
            })
        attacks = [r for r in group if r["kind"] == "attack"]
        benign = [r for r in group if r["kind"] == "benign"]
        out.append({
            "subset": subset,
            "rounds": len(rounds),
            "attack_runs": len(attacks),
            "benign_runs": len(benign),
            "detected": sum(1 for r in attacks if LEVELS.index(r["max_level"]) >= MEDIUM),
            "dr_at_1pct_fpr": spread([r["dr_at_1pct_fpr"] for r in per_round]),
            "ttd_bytes_median": spread([r["ttd_bytes_median"] for r in per_round]),
            "ttd_bytes_p95": spread([r["ttd_bytes_p95"] for r in per_round]),
            "fpr_per_24h": spread([r["fpr_per_24h"] for r in per_round]),
            "benign_alerts": sum(r["alerts"] for r in benign),
            "unmeasured_workloads": sum(1 for r in benign if not r.get("workload_summary")),
            "per_round": per_round,
        })
    return out


def spread(values: list) -> dict | None:
    """min/median/max over rounds. A single round is reported as itself, with the
    count, so a one-round run cannot be mistaken for a stable figure."""
    present = [v for v in values if v is not None]
    if not present:
        return None
    return {
        "n": len(present),
        "min": min(present),
        "median": percentile(present, 50),
        "max": max(present),
    }


def fmt(value) -> str:
    if value is None:
        return "-"
    if isinstance(value, dict):
        if value["n"] == 1:
            return f"{value['min']}"
        return f"{value['min']}..{value['max']}"
    return str(value)


def print_summary(summary: list[dict]) -> None:
    print()
    print(f"{'subset':<14}{'rounds':>7}{'attacks':>8}{'detected':>9}{'DR@1%FPR':>13}"
          f"{'TTD bytes med':>15}{'p95':>13}{'FPR/24h':>13}")
    for row in summary:
        print(f"{row['subset']:<14}{row['rounds']:>7}{row['attack_runs']:>8}{row['detected']:>9}"
              f"{fmt(row['dr_at_1pct_fpr']):>13}{fmt(row['ttd_bytes_median']):>15}"
              f"{fmt(row['ttd_bytes_p95']):>13}{fmt(row['fpr_per_24h']):>13}")
    if any(row["rounds"] < 2 for row in summary):
        print("\nnote: a range needs at least two rounds; entries with one round are a "
              "single observation, not a spread.")
    print("note: TTD is read from the workload's own progress lines, so a workload that "
          "finishes inside the detector's first evaluation tick reports its whole corpus "
          "— that is a late detection, not a missing measurement.")


def main() -> int:
    args = parse_args()
    if not args.work:
        temp = os.environ.get("TEMP") or os.environ.get("TMPDIR") or "/tmp"
        args.work = os.path.join(temp, "grima-ablation")
    os.makedirs(args.work, exist_ok=True)
    binary = find_binary(args.binary)
    subsets = [s for s in args.subsets.split(",") if s]
    attacks = [a for a in args.attacks.split(",") if a]
    benign = [b for b in args.benign.split(",") if b]
    unknown = [s for s in subsets if s not in SUBSETS]
    if unknown:
        sys.exit(f"error: unknown subset(s) {unknown}; known: {list(SUBSETS)}")

    CONFIG["port"] = args.port
    print(f"detector: {binary}")
    print(f"work root: {args.work}")
    print(f"subsets: {', '.join(subsets)}")
    print(f"corpus: {len(attacks)} attack rate(s) x {len(benign)} benign workload(s), "
          f"{args.rounds} round(s), {int(args.duration)}s measured run each")

    rows: list[dict] = []
    for subset in subsets:
        for rnd in range(1, args.rounds + 1):
            print(f"\n=== {subset} (round {rnd}) ===", flush=True)
            for rate in attacks:
                rows.append(one_run(args, binary, subset, rate, "attack", rnd))
            for workload in benign:
                rows.append(one_run(args, binary, subset, workload, "benign", rnd))

    summary = summarise(rows)
    print_summary(summary)

    out = args.out or os.path.join(args.work, "ablation.json")
    with open(out, "w", encoding="utf-8") as handle:
        json.dump({"args": vars(args), "rows": rows, "summary": summary}, handle, indent=2)
    print(f"\nresults: {out}")

    incomplete = [s["subset"] for s in summary
                  if s["attack_runs"] == 0 or s["benign_runs"] == 0]
    unmeasured = [f"{r['subset']}/{r['scenario']}" for r in rows
                  if r["kind"] == "benign" and not r.get("workload_summary")]
    if incomplete:
        print(f"error: subset(s) measured nothing: {incomplete}", file=sys.stderr)
    if unmeasured:
        print(f"error: workload(s) produced no SUMMARY line, so a silent verdict from them "
              f"is not a measurement: {unmeasured}", file=sys.stderr)
    if incomplete or unmeasured:
        return 1
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(130)
