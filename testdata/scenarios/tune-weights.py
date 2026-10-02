#!/usr/bin/env python3
"""Offline weight tuning (Sprint 4 item 4.6) and the honest generalization split
(Sprint 4 item 4.5) over a recorded ablation run.

Nothing here runs the detector. The input is `ablation.json` as written by
`ablate.py`: per row it carries `kind`, `scenario`, `round`, `subset` and
`signal_values` — the highest value each signal reached during that run, 0..1.
Every candidate weight table is scored by *re-fusing those recorded values*
with the shipped rule (docs/design.md §8):

    score = 100 * (1 - prod_i (1 - clamp01(w_i * v_i)))

over the Primary signals always, over the Secondary signals only while at least
one Primary is present, and with Override signals setting a level floor and
never fusing. Levels come from the shipped bands: low 20, medium 45, high 70,
critical 88. Detector runs are deliberately absent: a weight table must be
reproducible from a recorded run, not from a fresh one.

Item 4.6: a grid search over the weight table maximising detection rate subject
to a false-positive budget, tuned on a held-out split and reported on the rest.

Item 4.5: the corpus contains one attack family — the controlled encryptor at
three rates — so cross-family generalization is not measurable and is reported
as such. What is measurable is tuning bias: leave-one-scenario-out (attack
rates) and leave-one-workload-out (benign). The held-out/in-sample gap bounds
how much the tuning leans on the split it saw; it says nothing about a second
attack family.

Usage:
  tune-weights.py --help
  tune-weights.py --selftest
  tune-weights.py --ablation ablation.json [--mode all|split|loso|lowo]
  tune-weights.py --write-synthetic /tmp/synth.json   # a dev fixture, no detector
"""
from __future__ import annotations

import argparse
import itertools
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))

LEVELS = ["info", "low", "medium", "high", "critical"]
L_INFO, L_LOW, L_MEDIUM, L_HIGH, L_CRITICAL = range(5)
BAND_LEVEL = {"info": L_INFO, "low": L_LOW, "medium": L_MEDIUM,
              "high": L_HIGH, "critical": L_CRITICAL}

# docs/design.md §8, configs/grima.example.toml [scoring] level_bands
BANDS = {"low": 20.0, "medium": 45.0, "high": 70.0, "critical": 88.0}

# internal/score/signals.go: minSignalValue
MIN_SIGNAL_VALUE = 0.05

# docs/design.md §5 and internal/config/config.go DefaultSignalWeights. The
# shipped table is the thing this tool tunes against, so it is a literal copy:
# an in-binary default that drifts from this file is a bug in this file.
SIGNAL_CLASS = {
    "entropy_deviation": "primary",
    "magic_mismatch": "primary",
    "write_burst": "primary",
    "write_rate_absolute": "primary",
    "rename_burst": "primary",
    "unknown_extension_activity": "primary",
    "delete_rate": "secondary",
    "dir_fanout": "secondary",
    "cum_bytes_rewritten": "secondary",
    "ngram_rename_chain": "secondary",
    "static_reputation": "secondary",
    "bus_drops": "secondary",
}
SHIPPED_WEIGHTS = {
    "entropy_deviation": 1.0,
    "magic_mismatch": 1.0,
    "write_burst": 1.0,
    "write_rate_absolute": 1.0,
    "rename_burst": 0.8,
    "ngram_rename_chain": 0.2,
    "unknown_extension_activity": 1.0,
    "delete_rate": 0.4,
    "dir_fanout": 0.4,
    "cum_bytes_rewritten": 0.4,
    "static_reputation": 0.6,
    "bus_drops": 0.2,
}

# internal/rules/rules.go: the rule IDs the scorer records as Override signals,
# with the severity that floors the verdict. Every other unknown name is treated
# as an override too (it cannot fuse), but with an unknown floor.
OVERRIDE_FLOOR = {
    "R-DECOY-TOUCH": L_CRITICAL,
    "R-PERSIST-INSTALL": L_MEDIUM,
    "R-SHADOW-DELETE": L_CRITICAL,
    "R-EVENTLOG-CLEAR": L_CRITICAL,
    "R-USN-DELETE": L_HIGH,
    "R-BACKUP-KILL": L_HIGH,
    "R-FIREWALL-OFF": L_HIGH,
    "R-SERVICE-TAMPER": L_HIGH,
    "R-EDR-KILL": L_HIGH,
    "decoy_touch": L_CRITICAL,
    "persistence_install": L_MEDIUM,
}


# --------------------------------------------------------------------------
# The fusion arithmetic, a faithful port of internal/score/score.go Evaluate.

def clamp01(x: float) -> float:
    if x < 0.0:
        return 0.0
    if x > 1.0:
        return 1.0
    return x


def level_for(score: float) -> int:
    if score >= BANDS["critical"]:
        return L_CRITICAL
    if score >= BANDS["high"]:
        return L_HIGH
    if score >= BANDS["medium"]:
        return L_MEDIUM
    if score >= BANDS["low"]:
        return L_LOW
    return L_INFO


def fuse(signal_values: dict, weights: dict, gate: bool = True,
         floor: float = MIN_SIGNAL_VALUE) -> tuple:
    """Re-fuse one recorded signal set. Returns (score, level, overrides).

    `gate=False` disables the structural Secondary rule and reproduces the
    pre-§26 arithmetic, which the selftest uses to pin the noisy-OR product
    against the 86.2 figure design.md §26 records.
    """
    primaries, secondaries, overrides = [], [], []
    for name, value in signal_values.items():
        cls = SIGNAL_CLASS.get(name)
        if cls is None:
            overrides.append(name)  # a rule ID: an Override, never fused
            continue
        if value < floor:
            continue  # dropNoise
        if cls == "primary":
            primaries.append((name, value))
        elif cls == "secondary":
            secondaries.append((name, value))
        else:
            overrides.append(name)

    combined = 1.0
    for name, value in primaries:
        w = weights.get(name, 0.0)
        if w > 0:
            combined *= 1.0 - clamp01(w * value)
    if primaries or not gate:
        for name, value in secondaries:
            w = weights.get(name, 0.0)
            if w > 0:
                combined *= 1.0 - clamp01(w * value)
    score = (1.0 - combined) * 100.0
    level = level_for(score)
    for name in overrides:
        level = max(level, OVERRIDE_FLOOR.get(name, L_INFO))
    return score, level, overrides


# --------------------------------------------------------------------------
# Metrics over a row set.

def metrics(rows: list, weights: dict, alert_band: int = L_MEDIUM) -> dict:
    attack_scores, benign_scores = [], []
    attack_hits = benign_hits = 0
    for row in rows:
        score, level, _ = fuse(row.get("signal_values") or {}, weights)
        if row["kind"] == "attack":
            attack_scores.append(score)
            attack_hits += level >= alert_band
        elif row["kind"] == "benign":
            benign_scores.append(score)
            benign_hits += level >= alert_band
    n_attack, n_benign = len(attack_scores), len(benign_scores)
    min_attack = min(attack_scores) if attack_scores else None
    max_benign = max(benign_scores) if benign_scores else None
    if min_attack is None:
        separation = None
    elif max_benign is None:
        separation = min_attack
    else:
        separation = min_attack - max_benign
    return {
        "n_attack": n_attack,
        "n_benign": n_benign,
        "dr": (attack_hits / n_attack) if n_attack else None,
        "fpr": (benign_hits / n_benign) if n_benign else 0.0,
        "attack_hits": attack_hits,
        "benign_hits": benign_hits,
        "min_attack": min_attack,
        "max_benign": max_benign,
        "separation": separation,
    }


# --------------------------------------------------------------------------
# Grid search.

def grid_search(rows: list, axes: list, budget: float, grid: list, coarse: list,
                cap: int, alert_band: int, max_passes: int,
                shipped: dict = SHIPPED_WEIGHTS) -> dict:
    """Search the weight table on `rows`.

    Objective (lexicographic, maximised): detection rate at the alert band over
    attack rows; then the fewest changed weights; then the largest in-sample
    separation (min attack score - max benign score). Feasible means the benign
    false-positive rate is at or below `budget`. The churn tie-break means a
    search that cannot improve DR returns the shipped table rather than an
    arbitrary equally-good one.
    """
    def key(weights: dict, m: dict) -> tuple:
        churn = sum(abs(weights[n] - shipped.get(n, 0.0)) for n in axes)
        sep = m["separation"] if m["separation"] is not None else float("-inf")
        dr = m["dr"] if m["dr"] is not None else -1.0
        return (dr, -churn, sep)

    base = dict(shipped)

    def feasible(m: dict) -> bool:
        return m["fpr"] <= budget + 1e-12

    best = None
    base_m = metrics(rows, base, alert_band)
    if feasible(base_m):
        best = (base, base_m)

    combos = len(coarse) ** len(axes)
    evaluated = 0
    pruned = combos > cap
    if not pruned:
        for vec in itertools.product(coarse, repeat=len(axes)):
            weights = dict(base)
            weights.update(zip(axes, vec))
            m = metrics(rows, weights, alert_band)
            evaluated += 1
            if not feasible(m):
                continue
            if best is None or key(weights, m) > key(*best):
                best = (weights, m)

    if best is None:
        # Shipped is infeasible and the coarse pass found nothing feasible.
        # Report the shipped table and its metrics rather than inventing one.
        best = (base, base_m)
        infeasible_shipped = True
    else:
        infeasible_shipped = not feasible(base_m)

    weights, m = best
    if not infeasible_shipped:
        for _ in range(max_passes):
            improved = False
            for name in axes:
                for value in grid:
                    if value == weights[name]:
                        continue
                    cand = dict(weights)
                    cand[name] = value
                    cm = metrics(rows, cand, alert_band)
                    evaluated += 1
                    if not feasible(cm):
                        continue
                    if key(cand, cm) > key(weights, m):
                        weights, m, improved = cand, cm, True
            if not improved:
                break

    return {"weights": weights, "metrics": m, "evaluated": evaluated,
            "combos": combos, "pruned": pruned, "infeasible_shipped": infeasible_shipped}


# --------------------------------------------------------------------------
# Splits.

def rows_of(rows: list, kind: str) -> list:
    return [r for r in rows if r["kind"] == kind]


def scenarios_of(rows: list, kind: str) -> list:
    seen = []
    for r in rows:
        if r["kind"] == kind and r["scenario"] not in seen:
            seen.append(r["scenario"])
    return sorted(seen)


def split_rows(rows: list, holdout_attack: str, holdout_benign: str) -> tuple:
    """Tuning rows are everything except the held-out scenario/workload; the
    held-out rows are reported but never seen by the search."""
    def held(r: dict) -> bool:
        if holdout_attack and r["kind"] == "attack" and r["scenario"] == holdout_attack:
            return True
        if holdout_benign and r["kind"] == "benign" and r["scenario"] == holdout_benign:
            return True
        return False
    tune = [r for r in rows if not held(r)]
    hold = [r for r in rows if held(r)]
    return tune, hold


def loso_folds(rows: list) -> list:
    folds = []
    for scenario in scenarios_of(rows, "attack"):
        tune = [r for r in rows if not (r["kind"] == "attack" and r["scenario"] == scenario)]
        hold = [r for r in rows if r["kind"] == "attack" and r["scenario"] == scenario]
        folds.append((scenario, tune, hold))
    return folds


def lowo_folds(rows: list) -> list:
    folds = []
    for scenario in scenarios_of(rows, "benign"):
        tune = [r for r in rows if not (r["kind"] == "benign" and r["scenario"] == scenario)]
        hold = [r for r in rows if r["kind"] == "benign" and r["scenario"] == scenario]
        folds.append((scenario, tune, hold))
    return folds


# --------------------------------------------------------------------------
# Reporting.

def fmt(value, digits: int = 1) -> str:
    if value is None:
        return "  n/a"
    if isinstance(value, float):
        return f"{value:.{digits}f}"
    return str(value)


def weight_table(tuned: dict) -> list:
    lines = [f"  {'signal':<29} {'class':<10} {'shipped':>7} {'tuned':>7}  changed",
             "  " + "-" * 66]
    for name in SHIPPED_WEIGHTS:
        shipped = SHIPPED_WEIGHTS[name]
        value = tuned.get(name, shipped)
        mark = "yes" if abs(value - shipped) > 1e-9 else ""
        lines.append(f"  {name:<29} {SIGNAL_CLASS[name]:<10} {shipped:>7.2f} {value:>7.2f}  {mark}")
    return lines


def metrics_table(label_rows: list) -> list:
    lines = [f"  {'split':<22} {'table':<9} {'DR':>7} {'FPR':>7} {'minAtk':>8} "
             f"{'maxBen':>8} {'sep':>7}",
             "  " + "-" * 76]
    for label, table, m in label_rows:
        lines.append(f"  {label:<22} {table:<9} {fmt(m['dr'], 3):>7} {fmt(m['fpr'], 3):>7} "
                     f"{fmt(m['min_attack']):>8} {fmt(m['max_benign']):>8} "
                     f"{fmt(m['separation']):>7}")
    return lines


def parse_grid(text: str, flag: str) -> list:
    try:
        values = [float(part) for part in text.split(",") if part.strip() != ""]
    except ValueError:
        sys.exit(f"error: {flag} expects comma-separated numbers, got {text!r}")
    if not values:
        sys.exit(f"error: {flag} is empty")
    for value in values:
        if not 0.0 <= value <= 1.0:
            sys.exit(f"error: {flag}: weight {value} outside [0,1]")
    return values


def load_rows(path: str, subset: str) -> tuple:
    if not os.path.isfile(path):
        sys.exit(f"error: no ablation JSON at {path}; "
                 f"run ablate.py, or use --write-synthetic for a dev fixture")
    with open(path, "r", encoding="utf-8") as handle:
        data = json.load(handle)
    rows = data.get("rows")
    if not isinstance(rows, list):
        sys.exit(f"error: {path} has no 'rows' list")
    subsets = sorted({r.get("subset", "?") for r in rows})
    if subset != "any":
        selected = [r for r in rows if r.get("subset") == subset]
        if not selected:
            sys.exit(f"error: no rows for subset {subset!r}; present: {', '.join(subsets)}")
    else:
        selected = list(rows)
    clean = []
    for row in selected:
        if row.get("kind") not in ("attack", "benign"):
            continue
        row = dict(row)
        row.setdefault("signal_values", {})
        row.setdefault("scenario", "?")
        row.setdefault("round", 0)
        clean.append(row)
    if not clean:
        sys.exit(f"error: subset {subset!r} has no attack/benign rows")
    carriers = sum(1 for row in clean if row["signal_values"])
    if carriers == 0:
        named = sum(1 for row in clean if row.get("signals"))
        sys.exit(
            "error: no row in this ablation run carries `signal_values`; offline weight "
            "tuning needs the per-row signal maxima.\n"
            f"       ({named} rows list `signals` but none list `signal_values` — the run "
            "was written by an ablate.py older than the signal_values capture.)\n"
            "       Re-run ablate.py, or point --ablation at a run that recorded it. "
            "Nothing is tuned from scores alone.")
    return clean, subsets


def run_split(rows: list, args, out: dict) -> dict:
    """Item 4.6: tune on the tuning split, report held-out and in-sample."""
    attacks = scenarios_of(rows, "attack")
    benigns = scenarios_of(rows, "benign")
    holdout_attack = args.holdout_attack or (attacks[-1] if attacks else "")
    holdout_benign = args.holdout_benign or (benigns[-1] if benigns else "")
    tune, hold = split_rows(rows, holdout_attack, holdout_benign)
    if not tune or not hold:
        sys.exit("error: split produced an empty side; check --holdout-*-scenario")
    if not rows_of(tune, "attack"):
        sys.exit("error: tuning split has no attack rows")

    axes = sorted({name for r in tune for name in (r.get("signal_values") or {})
                   if name in SHIPPED_WEIGHTS})
    print(f"\n== 4.6 Weight tuning ==")
    print(f"  ablation : {args.ablation}  (subset {args.subset})")
    print(f"  rows     : attack {len(rows_of(rows,'attack'))}, "
          f"benign {len(rows_of(rows,'benign'))}"
          f"  [tune {len(tune)} / held-out {len(hold)}]")
    print(f"  split    : hold out attack={holdout_attack or '(none)'} "
          f"benign={holdout_benign or '(none)'}")
    print(f"  objective: maximise DR at the {args.alert_band} band "
          f"(level >= {BAND_LEVEL[args.alert_band]}, score >= {BANDS[args.alert_band]}); "
          f"tie-break fewest changed weights, then widest separation")
    print(f"  budget   : benign FPR <= {args.budget:.3f} "
          f"({int(args.budget * len(rows_of(tune,'benign')))} of "
          f"{len(rows_of(tune,'benign'))} in-sample benign rows may alert)")
    print(f"  axes     : {len(axes)} tunable signals present in the tuning split "
          f"(others fixed at shipped: never emitted in this corpus)")
    combos = len(args.coarse_grid) ** len(axes)
    print(f"  search   : exhaustive {'x'.join([str(len(args.coarse_grid))]*len(axes))}"
          f" = {combos} coarse vectors over the {len(axes)} signal axes, "
          f"then coordinate refinement over {args.grid} ({args.max_passes} passes max)")
    if combos > args.cap:
        print(f"  pruned   : {combos} > --cap {args.cap}; the coarse pass is skipped and the "
              f"search starts from the shipped table and descends coordinate-wise. Weights "
              f"enter fusion only as clamp01(w*v), clamp01 is piecewise linear, and noisy-OR "
              f"is monotone in every weight, so the reachable score set changes only at the "
              f"grid points — the pruning loses resolution, not the objective's direction.")

    if not rows_of(tune, "benign"):
        print("  note     : tuning split has no benign rows; FPR is unconstrained")

    result = grid_search(tune, axes, args.budget, args.grid, args.coarse_grid,
                         args.cap, BAND_LEVEL[args.alert_band], args.max_passes)
    tuned = result["weights"]

    print(f"\n  evaluated {result['evaluated']} weight vectors "
          f"(combos {result['combos']}, pruned={result['pruned']})")
    if result["infeasible_shipped"]:
        print("  WARNING  : the shipped table violates the budget on the tuning split")

    print("\n  tuned table vs shipped:")
    print("\n".join(weight_table(tuned)))

    shipped_m_in = metrics(tune, SHIPPED_WEIGHTS, BAND_LEVEL[args.alert_band])
    tuned_m_in = metrics(tune, tuned, BAND_LEVEL[args.alert_band])
    shipped_m_hold = metrics(hold, SHIPPED_WEIGHTS, BAND_LEVEL[args.alert_band])
    tuned_m_hold = metrics(hold, tuned, BAND_LEVEL[args.alert_band])

    print("\n  metrics:")
    print("\n".join(metrics_table([
        ("in-sample (tuned on)", "shipped", shipped_m_in),
        ("in-sample (tuned on)", "tuned", tuned_m_in),
        ("held-out", "shipped", shipped_m_hold),
        ("held-out", "tuned", tuned_m_hold),
    ])))

    changed = [n for n in SHIPPED_WEIGHTS if abs(tuned[n] - SHIPPED_WEIGHTS[n]) > 1e-9]
    if changed:
        print(f"\n  tuning changed {len(changed)} weight(s): "
              + ", ".join(f"{n} {SHIPPED_WEIGHTS[n]:.2f}->{tuned[n]:.2f}" for n in changed))
    else:
        print("\n  tuning changed nothing: the shipped table already maximises the "
              "objective on the tuning split")

    in_delta = (tuned_m_in["dr"] or 0.0) - (shipped_m_in["dr"] or 0.0)
    hold_delta = (tuned_m_hold["dr"] or 0.0) - (shipped_m_hold["dr"] or 0.0)
    print("\n  finding  : ", end="")
    if in_delta > 1e-9 and hold_delta <= 1e-9:
        print(f"the tuned table beats the shipped one in-sample (DR {in_delta:+.3f}) "
              f"but not on the held-out split (DR {hold_delta:+.3f}). That is tuning bias "
              f"on a single-family corpus, reported rather than hidden.")
    elif in_delta > 1e-9:
        print(f"the tuned table improves DR in-sample ({in_delta:+.3f}) and holds "
              f"held-out ({hold_delta:+.3f}).")
    else:
        print("the shipped table is already optimal for this objective on the tuning "
              "split; the corpus does not separate it from the alternatives.")

    out["split"] = {
        "holdout_attack": holdout_attack,
        "holdout_benign": holdout_benign,
        "axes": axes,
        "tuned_weights": {n: round(tuned[n], 4) for n in SHIPPED_WEIGHTS},
        "changed": changed,
        "in_sample": {"shipped": shipped_m_in, "tuned": tuned_m_in},
        "held_out": {"shipped": shipped_m_hold, "tuned": tuned_m_hold},
        "search": {k: result[k] for k in ("evaluated", "combos", "pruned",
                                          "infeasible_shipped")},
    }
    return out["split"]


def run_loso(rows: list, args, out: dict) -> dict:
    print("\n== 4.5 Leave-one-scenario-out (attack rates) ==")
    print(f"  {'held-out scenario':<22} {'in-DR':>7} {'held-DR':>8} {'gap':>7}  changed")
    print("  " + "-" * 62)
    folds = loso_folds(rows)
    gaps, records = [], []
    for scenario, tune, hold in folds:
        axes = sorted({name for r in tune for name in (r.get("signal_values") or {})
                       if name in SHIPPED_WEIGHTS})
        result = grid_search(tune, axes, args.budget, args.grid, args.coarse_grid,
                             args.cap, BAND_LEVEL[args.alert_band], args.max_passes)
        in_dr = metrics(tune, result["weights"], BAND_LEVEL[args.alert_band])["dr"]
        hold_dr = metrics(hold, result["weights"], BAND_LEVEL[args.alert_band])["dr"]
        gap = (hold_dr - in_dr) if (hold_dr is not None and in_dr is not None) else None
        if gap is not None:
            gaps.append(gap)
        changed = [n for n in SHIPPED_WEIGHTS
                   if abs(result["weights"][n] - SHIPPED_WEIGHTS[n]) > 1e-9]
        print(f"  {scenario:<22} {fmt(in_dr,3):>7} {fmt(hold_dr,3):>8} {fmt(gap,3):>7}  "
              + (f"{len(changed)}" if changed else "none"))
        records.append({"scenario": scenario, "in_dr": in_dr, "held_dr": hold_dr,
                        "gap": gap, "changed": changed})
    if gaps:
        print(f"  mean gap (held-out - in-sample): {sum(gaps)/len(gaps):+.3f}")
    out["loso"] = {"folds": records,
                   "mean_gap": (sum(gaps) / len(gaps)) if gaps else None}
    return out["loso"]


def run_lowo(rows: list, args, out: dict) -> dict:
    print("\n== 4.5 Leave-one-workload-out (benign) ==")
    print(f"  {'held-out workload':<24} {'in-FPR':>7} {'held-FPR':>9} {'gap':>7}  changed")
    print("  " + "-" * 64)
    folds = lowo_folds(rows)
    gaps, records = [], []
    for scenario, tune, hold in folds:
        axes = sorted({name for r in tune for name in (r.get("signal_values") or {})
                       if name in SHIPPED_WEIGHTS})
        result = grid_search(tune, axes, args.budget, args.grid, args.coarse_grid,
                             args.cap, BAND_LEVEL[args.alert_band], args.max_passes)
        in_fpr = metrics(tune, result["weights"], BAND_LEVEL[args.alert_band])["fpr"]
        hold_m = metrics(hold, result["weights"], BAND_LEVEL[args.alert_band])
        hold_fpr = hold_m["fpr"]
        gap = hold_fpr - in_fpr
        gaps.append(gap)
        changed = [n for n in SHIPPED_WEIGHTS
                   if abs(result["weights"][n] - SHIPPED_WEIGHTS[n]) > 1e-9]
        print(f"  {scenario:<24} {fmt(in_fpr,3):>7} {fmt(hold_fpr,3):>9} {fmt(gap,3):>7}  "
              + (f"{len(changed)}" if changed else "none"))
        records.append({"scenario": scenario, "in_fpr": in_fpr, "held_fpr": hold_fpr,
                        "gap": gap, "changed": changed})
    if gaps:
        print(f"  mean gap (held-out - in-sample): {sum(gaps)/len(gaps):+.3f}")
    out["lowo"] = {"folds": records,
                   "mean_gap": (sum(gaps) / len(gaps)) if gaps else None}
    return out["lowo"]


def report_generalization(out: dict, rows: list) -> None:
    print("\n== 4.5 Generalization, stated honestly ==")
    print("  The attack corpus is a single family: the controlled encryptor at three")
    print("  rates (burst, intermittent, drip). Cross-family generalization therefore")
    print("  has no second family to measure and is NOT reported here. What the split")
    print("  above bounds is tuning bias — how much a weight table selected on the")
    print("  scenarios it saw changes behaviour on the scenarios it did not — and")
    print("  nothing more. A table that generalizes across these three rates may still")
    print("  fail on a family with a different signal profile.")
    loso = out.get("loso") or {}
    lowo = out.get("lowo") or {}
    if loso.get("mean_gap") is not None:
        print(f"  Leave-one-rate-out: mean held-out minus in-sample DR "
              f"{loso['mean_gap']:+.3f}.")
    if lowo.get("mean_gap") is not None:
        print(f"  Leave-one-workload-out: mean held-out minus in-sample FPR "
              f"{lowo['mean_gap']:+.3f}.")


# --------------------------------------------------------------------------
# Selftest: the re-fusion against the Go scorer's own arithmetic.

def selftest() -> int:
    """Golden numbers are the Go scorer's, read from internal/score: the solo
    saturation table in alertability_test.go, the 86.2 ungated Secondary
    combination in docs/design.md §26, and the 49.96 quiet-drip pair."""
    failures = []
    cases = [
        # docs/design.md §8: a Primary at full value carries exactly its weight.
        ("primary entropy saturated", {"entropy_deviation": 1.0}, 100.0, "critical"),
        ("primary rename_burst saturated", {"rename_burst": 1.0}, 80.0, "high"),
        # alertability_test.go: entropy +3σ is half-saturated.
        ("entropy half", {"entropy_deviation": 0.5}, 50.0, "medium"),
        ("entropy half + delete_rate full",
         {"entropy_deviation": 0.5, "delete_rate": 1.0}, 70.0, "high"),
        # §26: a Secondary alone is gated out entirely.
        ("delete_rate alone", {"delete_rate": 1.0}, 0.0, "info"),
        ("five secondaries alone",
         {"delete_rate": 1.0, "dir_fanout": 1.0, "cum_bytes_rewritten": 1.0,
          "ngram_rename_chain": 1.0, "bus_drops": 1.0}, 0.0, "info"),
        # signals.go: novel-extension saturation count is 50.
        ("novel extension 30 files", {"unknown_extension_activity": 0.6}, 60.0, "medium"),
        ("novel extension 20 files", {"unknown_extension_activity": 0.4}, 40.0, "low"),
        # The float knife-edge: 10/50 rounds down, so it stays info.
        ("novel extension 10 files", {"unknown_extension_activity": 0.2}, 20.0, "info"),
        # alertability_test.go: quiet drip = novel 0.480 + cum 0.094 = 49.96.
        ("quiet drip pair",
         {"unknown_extension_activity": 0.480, "cum_bytes_rewritten": 0.094},
         49.9552, "medium"),
        # An Override sets a floor without fusing (R-PERSIST-INSTALL is medium).
        ("persistence override floor", {"R-PERSIST-INSTALL": 1.0}, 0.0, "medium"),
        ("decoy override floor", {"R-DECOY-TOUCH": 1.0}, 0.0, "critical"),
        # The noise floor drops sub-0.05 evidence before it can gate.
        ("below noise floor", {"delete_rate": 0.04, "dir_fanout": 1.0}, 0.0, "info"),
    ]
    for name, values, want_score, want_level in cases:
        score, level, _ = fuse(values, SHIPPED_WEIGHTS)
        if abs(score - want_score) > 1e-9:
            failures.append(f"{name}: score {score!r}, want {want_score}")
        elif LEVELS[level] != want_level:
            failures.append(f"{name}: level {LEVELS[level]}, want {want_level}")

    # §26 pre-gate arithmetic: an ungated product of five saturated Secondaries.
    score, _, _ = fuse({"delete_rate": 1.0, "dir_fanout": 1.0, "cum_bytes_rewritten": 1.0,
                        "ngram_rename_chain": 1.0, "bus_drops": 1.0},
                       SHIPPED_WEIGHTS, gate=False)
    if abs(score - 86.176) > 1e-3:
        failures.append(f"ungated secondaries: score {score!r}, want 86.176 (design.md §26)")

    # Weights above 1 clamp at saturation rather than over-driving the product.
    score, _, _ = fuse({"entropy_deviation": 0.5}, {"entropy_deviation": 3.0})
    if abs(score - 100.0) > 1e-9:
        failures.append(f"weight clamp: score {score!r}, want 100.0")

    # A single Primary at 0.5 with weight 0.3 is 15.0, and a Secondary beside it
    # is corroboration, not a verdict on its own.
    score, level, _ = fuse({"magic_mismatch": 0.5}, {"magic_mismatch": 0.3})
    if abs(score - 15.0) > 1e-9 or LEVELS[level] != "info":
        failures.append(f"weak primary: {score!r} {LEVELS[level]}, want 15.0 info")

    if failures:
        print("selftest FAILED:")
        for failure in failures:
            print(f"  - {failure}")
        return 1
    print(f"selftest OK: {len(cases)} golden cases + ungated product + clamp "
          f"match the Go scorer (internal/score)")
    return 0


# --------------------------------------------------------------------------
# A synthetic fixture, for development when no measured ablation.json exists.

def synthetic_rows() -> list:
    """A plausible corpus, not a measurement: it exists so the tuner can be
    exercised end to end before a real ablation run lands. The signal values
    are drawn from the shapes recorded in docs/sprints.md §17/§18/§26."""
    def attack(scenario, values, round_no):
        return {"subset": "all", "scenario": scenario, "kind": "attack",
                "round": round_no, "max_score": None, "max_level": None,
                "alerts": 1, "signals": sorted(values), "signal_values": values,
                "ttd_bytes": 65536, "elapsed_s": 30.0}

    def benign(scenario, values, round_no):
        return {"subset": "all", "scenario": scenario, "kind": "benign",
                "round": round_no, "max_score": None, "max_level": None,
                "alerts": 0, "signals": sorted(values), "signal_values": values,
                "ttd_bytes": None, "elapsed_s": 180.0, "bytes_written": None}

    attack_shapes = {
        "burst": {"entropy_deviation": 1.0, "magic_mismatch": 1.0, "rename_burst": 1.0,
                  "ngram_rename_chain": 1.0, "unknown_extension_activity": 1.0,
                  "write_burst": 1.0, "delete_rate": 0.9, "dir_fanout": 1.0,
                  "cum_bytes_rewritten": 1.0},
        "intermittent": {"entropy_deviation": 0.941, "magic_mismatch": 1.0,
                         "rename_burst": 0.9, "ngram_rename_chain": 1.0,
                         "unknown_extension_activity": 1.0, "write_burst": 1.0,
                         "delete_rate": 0.6, "dir_fanout": 0.8,
                         "cum_bytes_rewritten": 1.0},
        "drip": {"unknown_extension_activity": 0.48, "cum_bytes_rewritten": 0.094,
                 "entropy_deviation": 0.204, "ngram_rename_chain": 0.15},
    }
    benign_shapes = {
        "benign-compile.sh": {},
        "benign-npm-install.sh": {"unknown_extension_activity": 0.234},
        "benign-archive.sh": {},
        "benign-media-encode.sh": {},
        "benign-atomic-save.sh": {"delete_rate": 0.08},
        "benign-git-objects.sh": {"entropy_deviation": 0.07},
    }
    rows = []
    for round_no in range(1, 4):
        for scenario, values in attack_shapes.items():
            jitter = {k: max(0.0, min(1.0, round(v - 0.02 * (round_no - 1), 3)))
                      for k, v in values.items()}
            rows.append(attack(scenario, jitter, round_no))
        rows.append(benign("benign-npm-install.sh",
                           {"unknown_extension_activity": round(0.234 - 0.02 * (round_no - 1), 3)},
                           round_no))
        for scenario in ("benign-compile.sh", "benign-archive.sh", "benign-media-encode.sh"):
            rows.append(benign(scenario, {}, round_no))
        rows.append(benign("benign-atomic-save.sh", {"delete_rate": 0.08}, round_no))
        rows.append(benign("benign-git-objects.sh", {"entropy_deviation": 0.07}, round_no))
    return rows


def write_synthetic(path: str) -> None:
    rows = synthetic_rows()
    payload = {"args": {"synthetic": True, "note": "generated by tune-weights.py; not a measurement"},
               "rows": rows, "summary": []}
    os.makedirs(os.path.dirname(os.path.abspath(path)) or ".", exist_ok=True)
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2)
    print(f"wrote {len(rows)} synthetic rows to {path}")


# --------------------------------------------------------------------------

def parse_args(argv=None) -> argparse.Namespace:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Search space. Only signals that actually appear in the tuning rows are\n"
            "tunable; a signal the corpus never emits cannot change any score, so it\n"
            "stays at its shipped weight. Each tunable weight is searched over\n"
            "--coarse-grid exhaustively (3^k vectors for k axes) when that fits under\n"
            "--cap, then refined coordinate-wise over --grid. Above --cap the coarse\n"
            "pass is skipped and the search descends from the shipped table; the run\n"
            "prints exactly what it pruned and why.\n\n"
            "Objective. Maximise detection rate at --alert-band over attack rows,\n"
            "subject to the benign false-positive rate staying within --budget; ties\n"
            "go to the table that changes the fewest weights, then to the widest\n"
            "attack/benign separation.\n"))
    ap.add_argument("--ablation", default=os.path.join(HERE, "ablation.json"),
                    help="ablation.json written by ablate.py")
    ap.add_argument("--subset", default="all",
                    help="which ablate.py subset to tune on; 'any' merges all rows")
    ap.add_argument("--budget", type=float, default=0.01,
                    help="benign false-positive budget (fraction of benign rows)")
    ap.add_argument("--alert-band", default="medium", choices=list(BANDS),
                    help="level at or above which a row counts as detected (default medium)")
    ap.add_argument("--grid", default="0,0.2,0.4,0.6,0.8,1.0",
                    help="fine coordinate grid")
    ap.add_argument("--coarse-grid", default="0,0.5,1.0",
                    help="coarse exhaustive grid")
    ap.add_argument("--cap", type=int, default=300000,
                    help="max coarse vectors to enumerate before pruning to coordinates")
    ap.add_argument("--max-passes", type=int, default=4,
                    help="coordinate refinement passes")
    ap.add_argument("--holdout-attack", default="",
                    help="attack scenario held out of tuning (default: last, sorted)")
    ap.add_argument("--holdout-benign", default="",
                    help="benign workload held out of tuning (default: last, sorted)")
    ap.add_argument("--mode", default="all", choices=["all", "split", "loso", "lowo"],
                    help="which sections to run")
    ap.add_argument("--out", default="", help="write the result JSON here")
    ap.add_argument("--selftest", action="store_true",
                    help="check the re-fusion against the Go scorer's arithmetic")
    ap.add_argument("--write-synthetic", default="",
                    help="write a synthetic ablation.json (no detector) and exit")
    args = ap.parse_args(argv)
    args.grid = parse_grid(args.grid, "--grid")
    args.coarse_grid = parse_grid(args.coarse_grid, "--coarse-grid")
    if args.alert_band not in BAND_LEVEL:
        sys.exit(f"error: unknown band {args.alert_band!r}")
    return args


def main(argv=None) -> int:
    args = parse_args(argv)
    if args.selftest:
        return selftest()
    if args.write_synthetic:
        write_synthetic(args.write_synthetic)
        return 0

    rows, subsets = load_rows(args.ablation, args.subset)
    print(f"loaded {len(rows)} rows from {args.ablation} "
          f"(subset {args.subset}; subsets present: {', '.join(subsets)})")
    print(f"  attack scenarios : {', '.join(scenarios_of(rows, 'attack')) or '(none)'}")
    print(f"  benign workloads : {', '.join(scenarios_of(rows, 'benign')) or '(none)'}")
    coverage = {}
    for row in rows:
        for name in (row.get("signal_values") or {}):
            coverage[name] = coverage.get(name, 0) + 1
    if coverage:
        print("  signal coverage  : " + ", ".join(
            f"{name} x{coverage[name]}" for name in sorted(coverage, key=lambda n: -coverage[n])))

    out = {"ablation": args.ablation, "subset": args.subset, "args": vars(args)}
    if args.mode in ("all", "split"):
        run_split(rows, args, out)
    if args.mode in ("all", "loso"):
        run_loso(rows, args, out)
    if args.mode in ("all", "lowo"):
        run_lowo(rows, args, out)
    if args.mode == "all":
        report_generalization(out, rows)

    if args.out:
        with open(args.out, "w", encoding="utf-8") as handle:
            json.dump(out, handle, indent=2, default=str)
        print(f"\nwrote {args.out}")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(130)
