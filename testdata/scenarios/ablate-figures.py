#!/usr/bin/env python3
"""Sprint 4 item 4.7: figures for the paper, rendered from a recorded ablation.json.

Input is the JSON that `ablate.py` writes:

    {"args": {...}, "rows": [...], "summary": [...]}

`rows` carries one entry per (subset, scenario, kind, round) with the observed
`max_score`, `max_level`, `alerts`, `signals`, `signal_values`, `ttd_bytes`,
`elapsed_s` and `workload_summary`. `summary` carries one entry per subset with
`rounds` and per-subset spreads (`{n,min,median,max}`) for `dr_at_1pct_fpr`,
`ttd_bytes_median`, `ttd_bytes_p95` and `fpr_per_24h`.

Three outputs, standard library only, reproducible from the JSON alone:

1. `ablation-table.md` — one markdown row per subset, metrics from `summary`.
   Markdown rather than a PNG because the paper's numbers have to be checkable.
2. `ttd-distribution.txt` — per subset, a text histogram plus the raw sorted
   bytes-encrypted-before-alert values.
3. `roc.csv` / `pr.csv` — a threshold sweep over the observed scores, per subset,
   with the 1%-FPR operating point marked. The corpus is small, so the curve is a
   step function of a handful of points; it is not smoothed or interpolated.

Nothing here invents a number: a field that is absent from the JSON renders as
`-` and is called out.
"""
from __future__ import annotations

import argparse
import json
import os
import sys


FPR_BUDGET = 0.01
CURVE_PREVIEW_LINES = 12


def parse_args() -> argparse.Namespace:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("ablation", help="path to ablation.json")
    ap.add_argument("--out", default="",
                    help="output directory (default: <ablation dir>/figures)")
    return ap.parse_args()


def load_json(path: str) -> dict:
    try:
        with open(path, "r", encoding="utf-8") as handle:
            data = json.load(handle)
    except OSError as err:
        sys.exit(f"error: cannot read {path}: {err}")
    except json.JSONDecodeError as err:
        sys.exit(f"error: {path} is not valid JSON: {err}")
    if not isinstance(data, dict):
        sys.exit(f"error: {path} is not a JSON object")
    return data


def human_bytes(value) -> str:
    if value is None:
        return "-"
    try:
        n = float(value)
    except (TypeError, ValueError):
        return "-"
    for unit in ("B", "KiB", "MiB", "GiB"):
        if abs(n) < 1024.0 or unit == "GiB":
            if unit == "B":
                return f"{int(n)} B"
            return f"{n:.1f} {unit}"
        n /= 1024.0
    return f"{n:.1f} GiB"


def is_spread(value) -> bool:
    return isinstance(value, dict) and {"n", "min", "median", "max"} <= set(value)


def fmt_spread(value) -> str:
    """A summary spread as `min..max (n=k)`; a one-round spread says so."""
    if not is_spread(value):
        # None, or a dict that is not a spread: both render as absent, not as a
        # Python repr that a reader would mistake for a measurement.
        if value is None or isinstance(value, dict):
            return "-"
        return str(value)
    n = value["n"]
    if n == 1:
        return f"{value['min']} (n=1)"
    return f"{value['min']}..{value['max']} (n={n})"


def fmt_scalar(value) -> str:
    if value is None:
        return "-"
    if isinstance(value, float):
        return f"{value:.3f}".rstrip("0").rstrip(".")
    return str(value)


def subsets_in_order(data: dict) -> list[str]:
    """Preserve the JSON's own order so a figure is stable run to run."""
    names: list[str] = []
    for entry in data.get("summary") or []:
        name = entry.get("subset")
        if name and name not in names:
            names.append(name)
    for row in data.get("rows") or []:
        name = row.get("subset")
        if name and name not in names:
            names.append(name)
    return names


def rows_for(data: dict, subset: str, kind: str) -> list[dict]:
    return [r for r in (data.get("rows") or [])
            if r.get("subset") == subset and r.get("kind") == kind]


# ---------------------------------------------------------------------------
# 1. The ablation table
# ---------------------------------------------------------------------------

TABLE_COLUMNS = [
    "subset", "rounds", "attack runs", "benign runs", "detected",
    "DR @ 1% FPR", "TTD bytes median", "TTD bytes p95", "FPR / 24h",
    "benign alerts", "unmeasured",
]


def render_table(data: dict) -> str:
    summary = data.get("summary") or []
    lines = ["# Ablation table", ""]
    if not summary:
        lines.append("_No `summary` array in the input: nothing to tabulate. Metrics below "
                     "render as `-`._")
        lines.append("")
    lines.append("| " + " | ".join(TABLE_COLUMNS) + " |")
    lines.append("|" + "|".join(["---"] * len(TABLE_COLUMNS)) + "|")

    entries: list[dict] = []
    if summary:
        entries = list(summary)
    else:
        for subset in subsets_in_order(data):
            entry = {"subset": subset}
            entry["attack_runs"] = len(rows_for(data, subset, "attack"))
            entry["benign_runs"] = len(rows_for(data, subset, "benign"))
            entries.append(entry)

    for entry in entries:
        detected = entry.get("detected")
        attack_runs = entry.get("attack_runs")
        if detected is not None and attack_runs:
            detected_cell = f"{detected}/{attack_runs}"
        else:
            detected_cell = fmt_scalar(detected)
        cells = [
            str(entry.get("subset", "-")),
            fmt_scalar(entry.get("rounds")),
            fmt_scalar(entry.get("attack_runs")),
            fmt_scalar(entry.get("benign_runs")),
            detected_cell,
            fmt_spread(entry.get("dr_at_1pct_fpr")),
            fmt_spread(entry.get("ttd_bytes_median")),
            fmt_spread(entry.get("ttd_bytes_p95")),
            fmt_spread(entry.get("fpr_per_24h")),
            fmt_scalar(entry.get("benign_alerts")),
            fmt_scalar(entry.get("unmeasured_workloads")),
        ]
        lines.append("| " + " | ".join(cells) + " |")

    lines.append("")
    lines.append("Detected counts attack runs whose `max_level` reached `medium` or above. "
                 "Every spread is over rounds, not over scenarios; `(n=k)` is the number of "
                 "rounds the spread was computed from, so a single-round entry is one "
                 "observation and not a range.")
    if any((e.get("rounds") or 0) < 2 for e in entries):
        lines.append("")
        lines.append("**Note:** at least one subset was run for a single round; its figures "
                     "are a single observation, not a spread (Sprint 2 item 2.10).")
    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------------------
# 2. TTD distribution
# ---------------------------------------------------------------------------

TTD_CAVEAT = (
    "Caveat: TTD is only meaningful where the attack outlived the detector's first\n"
    "evaluation tick. A workload that finished inside the first tick reports its whole\n"
    "corpus as its TTD, which is a late detection, not a missing measurement. A null\n"
    "TTD below means no alert was observed for that run, or the workload produced no\n"
    "progress line."
)


def histogram(values: list[int], width: int = 40) -> list[str]:
    """Equal-width bins over [min, max]. No smoothing, no interpolation."""
    if not values:
        return []
    if len(values) == 1 or values[0] == values[-1]:
        return [f"  [ {human_bytes(values[0])} ]  {len(values):>3} |{'#' * width}"]
    lo, hi = min(values), max(values)
    nbins = min(10, max(1, len(values)))
    span = hi - lo
    counts = [0] * nbins
    for value in values:
        index = min(nbins - 1, int((value - lo) / span * nbins))
        counts[index] += 1
    top = max(counts)
    out = []
    for i, count in enumerate(counts):
        start = lo + span * i / nbins
        end = lo + span * (i + 1) / nbins
        bar = "#" * round(width * count / top) if top else ""
        out.append(f"  [ {human_bytes(start):>10} .. {human_bytes(end):>10} )"
                   f" {count:>3} |{bar}")
    return out


def render_ttd(data: dict) -> str:
    lines = ["# TTD distribution (bytes encrypted before alert)", "", TTD_CAVEAT, "",
             "Raw values are bytes written on the last workload progress line before the",
             "detector's first alert; sorting them does not change their meaning.", ""]
    subsets = subsets_in_order(data)
    if not subsets:
        lines.append("_No rows in the input._")
        return "\n".join(lines) + "\n"
    for subset in subsets:
        attacks = rows_for(data, subset, "attack")
        values = [r["ttd_bytes"] for r in attacks if r.get("ttd_bytes") is not None]
        missing = len(attacks) - len(values)
        lines.append(f"## {subset}")
        lines.append("")
        if not attacks:
            lines.append("_No attack runs for this subset._")
            lines.append("")
            continue
        lines.append(f"attack runs: {len(attacks)}   TTD values: {len(values)}   "
                     f"no TTD: {missing}")
        lines.append("")
        if not values:
            lines.append("histogram: - (no finite TTD value)")
            lines.append("values:    -")
            lines.append("")
            continue
        ordered = sorted(values)
        lines.append("histogram (equal-width bins, no smoothing):")
        lines.extend(histogram(ordered))
        lines.append("")
        lines.append("values (sorted bytes):")
        for value in ordered:
            lines.append(f"  {value}  ({human_bytes(value)})")
        if missing:
            lines.append("")
            lines.append(f"note: {missing} attack run(s) contributed no TTD value (`-`).")
        lines.append("")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# 3. ROC / PR over observed scores
# ---------------------------------------------------------------------------

def curve_points(attack_scores: list[float], benign_scores: list[float]) -> list[dict]:
    """One point per distinct observed score used as a threshold.

    Prediction is `max_score >= threshold`. Consecutive thresholds that yield the
    same confusion matrix are collapsed to a single point, so the row count equals
    the number of distinct (tp, fp) observations and the step function is visible
    rather than padded.
    """
    n_attack, n_benign = len(attack_scores), len(benign_scores)
    thresholds = {0.0}
    thresholds.update(attack_scores)
    thresholds.update(benign_scores)
    if attack_scores or benign_scores:
        thresholds.add(max(attack_scores + benign_scores) + 1.0)
    thresholds = sorted(thresholds, reverse=True)

    points: list[dict] = []
    seen: set[tuple[int, int]] = set()
    for threshold in thresholds:
        tp = sum(1 for s in attack_scores if s >= threshold)
        fp = sum(1 for s in benign_scores if s >= threshold)
        if (tp, fp) in seen:
            continue
        seen.add((tp, fp))
        fn = n_attack - tp
        recall = tp / n_attack if n_attack else None
        dr = recall
        fpr = fp / n_benign if n_benign else None
        precision = tp / (tp + fp) if (tp + fp) else None
        points.append({
            "threshold": threshold,
            "n_attack": n_attack,
            "n_benign": n_benign,
            "tp": tp,
            "fp": fp,
            "fn": fn,
            "tn": n_benign - fp,
            "recall": recall,
            "dr": dr,
            "fpr": fpr,
            "precision": precision,
            "operating_point_1pct": 0,
        })
    return points


def mark_operating_point(points: list[dict]) -> dict | None:
    """The 1%-FPR operating point, chosen as `ablate.py`'s dr_at_fpr does it:
    among thresholds whose benign FPR is at or below the budget, the lowest
    threshold that attains the best detection rate."""
    eligible = [p for p in points
                if p["fpr"] is not None and p["fpr"] <= FPR_BUDGET]
    if not eligible:
        return None
    best_dr = max(p["dr"] for p in eligible if p["dr"] is not None)
    chosen = None
    for point in sorted(eligible, key=lambda p: p["threshold"]):
        if point["dr"] == best_dr:
            chosen = point
            break
    if chosen is not None:
        chosen["operating_point_1pct"] = 1
    return chosen


def write_curves(data: dict, out_dir: str) -> dict:
    subsets = subsets_in_order(data)
    roc_lines = [
        "# subset,threshold,n_attack,n_benign,tp,fp,fn,tn,fpr,dr,operating_point_1pct"]
    pr_lines = [
        "# subset,threshold,n_attack,tp,fp,recall,precision,operating_point_1pct"]
    stats = {"roc_rows": 0, "pr_rows": 0, "subsets": 0, "skipped": [],
             "points": {}, "dropped": []}

    for subset in subsets:
        attacks = rows_for(data, subset, "attack")
        benign = rows_for(data, subset, "benign")
        for kind, group in (("attack", attacks), ("benign", benign)):
            for r in group:
                if r.get("max_score") is None:
                    stats["dropped"].append(
                        f"{subset}/{r.get('scenario', '?')}/{kind}/round {r.get('round', '?')}")
        attack_scores = [r["max_score"] for r in attacks if r.get("max_score") is not None]
        benign_scores = [r["max_score"] for r in benign if r.get("max_score") is not None]
        if not attack_scores or not benign_scores:
            stats["skipped"].append(subset)
            continue
        stats["subsets"] += 1
        points = curve_points(attack_scores, benign_scores)
        mark_operating_point(points)
        stats["points"][subset] = len(points)
        for point in points:
            roc_lines.append(",".join([
                subset, fmt_csv_num(point["threshold"]),
                str(point["n_attack"]), str(point["n_benign"]),
                str(point["tp"]), str(point["fp"]), str(point["fn"]), str(point["tn"]),
                fmt_csv_num(point["fpr"]), fmt_csv_num(point["dr"]),
                str(point["operating_point_1pct"]),
            ]))
            pr_lines.append(",".join([
                subset, fmt_csv_num(point["threshold"]),
                str(point["n_attack"]), str(point["tp"]), str(point["fp"]),
                fmt_csv_num(point["recall"]), fmt_csv_num(point["precision"]),
                str(point["operating_point_1pct"]),
            ]))
        stats["roc_rows"] += len(points)
        stats["pr_rows"] += len(points)

    write_text(os.path.join(out_dir, "roc.csv"), "\n".join(roc_lines) + "\n")
    write_text(os.path.join(out_dir, "pr.csv"), "\n".join(pr_lines) + "\n")
    return stats


def fmt_csv_num(value) -> str:
    if value is None:
        return "-"
    if isinstance(value, float):
        return f"{value:.4f}".rstrip("0").rstrip(".")
    return str(value)


CURVE_CAVEAT = (
    "The sweep is over the observed scores of a small corpus, so each curve is a step\n"
    "function of a handful of points -- the row count equals the number of distinct\n"
    "confusion matrices actually observed. It is not smoothed and not interpolated. The\n"
    "operating_point_1pct column is 1 on the lowest threshold whose benign FPR is within\n"
    "the 1% budget that attains the best detection rate; with this few benign runs a 1%\n"
    "budget usually permits zero false positives, so that point can sit above the highest\n"
    "benign score."
)


def write_text(path: str, text: str) -> None:
    with open(path, "w", encoding="utf-8", newline="\n") as handle:
        handle.write(text)


def preview_csv(path: str, lines: int = CURVE_PREVIEW_LINES) -> str:
    with open(path, "r", encoding="utf-8") as handle:
        content = handle.read().splitlines()
    return "\n".join(content[:lines])


def main() -> int:
    args = parse_args()
    data = load_json(args.ablation)
    out_dir = args.out or os.path.join(os.path.dirname(os.path.abspath(args.ablation)), "figures")
    os.makedirs(out_dir, exist_ok=True)

    table = render_table(data)
    ttd = render_ttd(data)
    curve_stats = write_curves(data, out_dir)
    write_text(os.path.join(out_dir, "ablation-table.md"), table)
    write_text(os.path.join(out_dir, "ttd-distribution.txt"), ttd)
    write_text(os.path.join(out_dir, "roc-pr-notes.txt"),
               CURVE_CAVEAT + "\n\n"
               f"subsets with a curve: {curve_stats['subsets']}\n"
               f"curve points per subset: {curve_stats['points']}\n"
               f"ROC rows: {curve_stats['roc_rows']}   PR rows: {curve_stats['pr_rows']}\n"
               + (f"subsets skipped (no attack or no benign scores): "
                  f"{', '.join(curve_stats['skipped'])}\n" if curve_stats["skipped"] else "")
               + (f"rows dropped for a missing max_score: "
                  f"{', '.join(curve_stats['dropped'])}\n" if curve_stats["dropped"] else ""))

    print(table)
    print(ttd)

    roc_path = os.path.join(out_dir, "roc.csv")
    pr_path = os.path.join(out_dir, "pr.csv")
    print("# roc.csv (first "
          f"{CURVE_PREVIEW_LINES} lines of {curve_stats['roc_rows'] + 1}; "
          "full file beside the table)")
    print(preview_csv(roc_path))
    print()
    print("# pr.csv (first "
          f"{CURVE_PREVIEW_LINES} lines of {curve_stats['pr_rows'] + 1}; "
          "full file beside the table)")
    print(preview_csv(pr_path))
    print()
    print(CURVE_CAVEAT)
    print()
    print(f"curve points per subset: {curve_stats['points']}   "
          f"ROC rows: {curve_stats['roc_rows']}   PR rows: {curve_stats['pr_rows']}")
    if curve_stats["skipped"]:
        print(f"subsets skipped (no attack or no benign scores): "
              f"{', '.join(curve_stats['skipped'])}")
    if curve_stats["dropped"]:
        print(f"rows dropped for a missing max_score: "
              f"{', '.join(curve_stats['dropped'])}")
    print(f"wrote: {out_dir}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
