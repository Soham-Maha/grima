#!/usr/bin/env bash
# Run every benign workload through the false-positive harness and report one
# row per workload: the activity profile the workload recorded plus the
# detector's verdict and whether it stayed below response.alert_min_level.
#
# The corpus exists to measure false positives, so the interesting rows are the
# ones that alert: a workload that writes high-entropy data, renames into place,
# deletes in bursts or writes files a baseline has never seen is exactly where a
# detector is allowed to be wrong, and this driver makes that visible instead of
# hiding it behind a single "CORPUS OK" line.
#
# Each workload is run as its own full benign-fp-check.sh pass — fresh
# calibration with the workload running, then the measured pass — because that
# is the harness the corpus is defined against, and because a workload measured
# without a baseline of its own shape is measuring the wrong thing.
#
# A single round is not a measurement. The same scenario has scored 100 and 56.4
# for a purely environmental reason (sprints.md §15), so each workload reports a
# per-round spread and how many rounds alerted, not one number. The default of
# one round is a runtime budget, not a claim that one figure is trustworthy: a
# round costs a full harness pass (timing + calibration + measured), and
# benign-npm-install at its 200-package default spends ~73 s in each, so two
# rounds over the whole corpus measured at ~19 minutes. Run with -n 2 (or more)
# whenever the spread matters; benign-fp-spread.sh does the same for one
# workload with a default of five rounds.
#
# A workload with no SUMMARY line did not complete, and a workload that did not
# complete also produces no alert, so it is reported as ERROR and never as a
# silent pass.
#
# Usage: benign-corpus.sh [-n rounds] [scenario-script ...]
#   with no scenarios, every benign-*.sh workload in this directory is run
#
# Environment overrides:
#   GRIMA_CORPUS_ROUNDS   rounds per workload (default 1; the full default
#                         sweep runs in ~10 minutes, and each extra round adds
#                         roughly that again because npm dominates)
#   GRIMA_CORPUS_WORK     work root (default $TMPDIR/grima-corpus)
#   GRIMA_CORPUS_PORT     dashboard port handed to the harness (default 8795)
#   GRIMA_CORPUS_DURATION detector window per harness pass (default 30s; the
#                         harness still extends it to outlive a slower workload)
#   GRIMA_CORPUS_ALERT_MIN_LEVEL  level the pass/fail compares against (default
#                         the detector's own default, "medium")
#   GRIMA_CORPUS_HARNESS  harness to drive (default the sibling
#                         benign-fp-check.sh; overridable so the driver's own
#                         parsing can be exercised without a detector run)
#   plus everything benign-fp-check.sh honours: GRIMA_BINARY, GRIMA_FP_PYTHON
#
# Exits 0 when every workload stayed silent, 1 when any workload alerted, 2 when
# a workload could not be measured.
set -uo pipefail

DIR_C="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
HARNESS="${GRIMA_CORPUS_HARNESS:-$DIR_C/benign-fp-check.sh}"
[ -f "$HARNESS" ] || { echo "error: $HARNESS is missing" >&2; exit 2; }

ROUNDS="${GRIMA_CORPUS_ROUNDS:-1}"
WORK="${GRIMA_CORPUS_WORK:-${TMPDIR:-${TEMP:-${TMP:-/tmp}}}/grima-corpus}"
PORT="${GRIMA_CORPUS_PORT:-8795}"
DURATION="${GRIMA_CORPUS_DURATION:-30s}"
ALERT_MIN="${GRIMA_CORPUS_ALERT_MIN_LEVEL:-medium}"

usage() {
  echo "usage: benign-corpus.sh [-n rounds] [scenario-script ...]" >&2
  exit 2
}

SCENARIOS=()
while [ "$#" -gt 0 ]; do
  case "$1" in
    -n)
      [ "$#" -ge 2 ] || usage
      ROUNDS="$2"; shift 2 ;;
    -n*)
      ROUNDS="${1#-n}"; shift ;;
    -h|--help)
      usage ;;
    -*)
      echo "error: unknown option: $1" >&2; usage ;;
    *)
      SCENARIOS+=("$1"); shift ;;
  esac
done

case "$ROUNDS" in
  ''|*[!0-9]*) echo "error: round count must be a positive integer: '$ROUNDS'" >&2; exit 2 ;;
esac
[ "$ROUNDS" -ge 1 ] || { echo "error: round count must be at least 1" >&2; exit 2; }

if [ "${#SCENARIOS[@]}" -eq 0 ]; then
  for f in "$DIR_C"/benign-*.sh; do
    b="$(basename "$f")"
    case "$b" in
      benign-fp-check.sh|benign-fp-spread.sh|benign-corpus.sh) continue ;;
    esac
    SCENARIOS+=("$f")
  done
fi
[ "${#SCENARIOS[@]}" -gt 0 ] || { echo "error: no benign-*.sh workloads found in $DIR_C" >&2; exit 2; }

level_rank() {
  case "$1" in
    info) echo 0 ;;
    low) echo 1 ;;
    medium) echo 2 ;;
    high) echo 3 ;;
    critical) echo 4 ;;
    *) echo -1 ;;
  esac
}
ALERT_MIN_RANK="$(level_rank "$ALERT_MIN")"
[ "$ALERT_MIN_RANK" -ge 0 ] || { echo "error: unknown alert_min_level: '$ALERT_MIN'" >&2; exit 2; }

mkdir -p "$WORK"

echo "corpus sweep: ${#SCENARIOS[@]} workload(s) x $ROUNDS round(s)"
echo "harness: $HARNESS"
echo "work root: $WORK"
echo "dashboard port: $PORT, detector window: $DURATION, alert_min_level: $ALERT_MIN"
if [ "$ROUNDS" -eq 1 ]; then
  echo "note: one round per workload, so no spread is shown; re-run with -n 2 (or more)"
  echo "      when the per-round variance matters."
fi
echo

overall=0        # 0 ok, 1 alert, 2 error

# spread_of <values...> — min/median/max, so a lone figure never stands in for a
# distribution.
spread_of() {
  [ "$#" -gt 0 ] || { printf '%s' '-'; return; }
  local sorted n min max med
  sorted="$(printf '%s\n' "$@" | sort -g)"
  n="$(printf '%s\n' "$sorted" | wc -l | tr -d ' ')"
  min="$(printf '%s\n' "$sorted" | sed -n '1p')"
  max="$(printf '%s\n' "$sorted" | sed -n "${n}p")"
  if [ $((n % 2)) -eq 1 ]; then
    med="$(printf '%s\n' "$sorted" | sed -n "$(( (n + 1) / 2 ))p")"
  else
    med="$(printf '%s\n' "$sorted" | awk -v n="$n" 'NR==n/2 || NR==n/2+1 { s+=$1; c++ } END { printf "%.1f", s/c }')"
  fi
  printf '%s/%s/%s' "$min" "$med" "$max"
}

# ext_mix <workdir> — top three extensions in the measured work tree, used for
# workloads whose SUMMARY predates the extension field.
ext_mix() {
  local dir="$1"
  [ -d "$dir" ] || { printf '%s' '-'; return; }
  find "$dir" -type f -printf '%f\n' 2>/dev/null \
    | awk '{ if ($0 ~ /\./) { n = split($0, a, "."); print a[n] } else print "none" }' \
    | sort | uniq -c | sort -rn \
    | awk 'NR <= 3 { printf "%s%s:%s", (NR > 1 ? "," : ""), $2, $1 }'
}

error_rounds=0
quiet_rounds=0
table_rows=()

for SCRIPT in "${SCENARIOS[@]}"; do
  [ -f "$SCRIPT" ] || { echo "error: no such scenario: $SCRIPT" >&2; overall=2; error_rounds=$((error_rounds + 1)); continue; }
  NAME="$(basename "$SCRIPT" .sh)"

  echo "== $NAME =="

  r_scores=()
  r_alerts=()
  r_levels=()
  r_ttds=()
  profile_raw="-"
  profile_files="-"; profile_bytes="-"; profile_renames="-"; profile_deletes="-"; profile_elapsed="-"
  profile_ext="-"
  profile_signals="-"
  failed=0
  bare=0
  alerted_here=0

  round=0
  while [ "$round" -lt "$ROUNDS" ]; do
    round=$((round + 1))
    round_work="$WORK/$NAME/round-$round"
    log="$WORK/$NAME/round-$round.out"
    mkdir -p "$WORK/$NAME"

    GRIMA_FP_WORK="$round_work" GRIMA_FP_PORT="$PORT" GRIMA_FP_DURATION="$DURATION" \
      "${BASH:-bash}" "$HARNESS" "$SCRIPT" > "$log" 2>&1
    rc=$?

    result="$(grep '^RESULT ' "$log" | tail -1)"
    summary_log="$round_work/$NAME/workload.log"
    summary_line="$(grep '^SUMMARY ' "$summary_log" 2>/dev/null | tail -1)"

    # No SUMMARY means the workload did not complete; a silent verdict from a
    # workload that wrote nothing is not a pass, it is a missing measurement.
    if [ -z "$summary_line" ]; then
      echo "  round $round: ERROR — no SUMMARY line (harness exit $rc), see $log" >&2
      tail -3 "$log" | sed 's/^/    /' >&2
      failed=$((failed + 1))
      continue
    fi
    if [ "$rc" = "2" ] || [ -z "$result" ]; then
      echo "  round $round: ERROR — harness exit $rc, see $log" >&2
      tail -3 "$log" | sed 's/^/    /' >&2
      failed=$((failed + 1))
      continue
    fi

    score="$(printf '%s' "$result" | sed -n 's/.*max_score=\([^ ]*\).*/\1/p')"
    level="$(printf '%s' "$result" | sed -n 's/.*max_level=\([^ ]*\).*/\1/p')"
    n_alerts="$(printf '%s' "$result" | sed -n 's/.*alerts=\([0-9]*\).*/\1/p')"
    ttd="$(printf '%s' "$result" | sed -n 's/.*ttd=\([^ ]*\).*/\1/p')"
    signals="$(printf '%s' "$result" | sed -n 's/.*max_signals=\([^ ]*\).*/\1/p')"
    [ -n "$n_alerts" ] || n_alerts=0
    [ -n "$ttd" ] || ttd=-
    [ -n "$signals" ] || signals="-"
    if [ "$score" = "none" ] || [ "$score" = "unavailable" ]; then
      score="0.0"
      level="none"
      bare=$((bare + 1))
    fi

    r_scores+=("$score")
    r_alerts+=("$n_alerts")
    r_levels+=("$level")
    [ "$ttd" != "-" ] && r_ttds+=("$ttd")
    [ "$n_alerts" -gt 0 ] && alerted_here=$((alerted_here + 1))

    echo "  round $round: score=$score level=$level alerts=$n_alerts ttd=$ttd signals=$signals"

    # Keep the profile and the peak signals from the most recent completed
    # round, and prefer the workload's own extension list over the one scanned
    # from disk.
    profile_raw="$summary_line"
    profile_signals="$signals"
    profile_files="$(printf '%s' "$summary_line" | sed -n 's/.*files_written=\([0-9]*\).*/\1/p')"
    profile_bytes="$(printf '%s' "$summary_line" | sed -n 's/.*bytes_written=\([0-9]*\).*/\1/p')"
    profile_renames="$(printf '%s' "$summary_line" | sed -n 's/.*renames=\([0-9]*\).*/\1/p')"
    profile_deletes="$(printf '%s' "$summary_line" | sed -n 's/.*deletes=\([0-9]*\).*/\1/p')"
    profile_elapsed="$(printf '%s' "$summary_line" | sed -n 's/.*elapsed_s=\([0-9]*\).*/\1/p')"
    profile_ext="$(printf '%s' "$summary_line" | sed -n 's/.*extensions=\([^ ]*\).*/\1/p')"
    [ -n "$profile_ext" ] || profile_ext="$(ext_mix "$round_work/$NAME/monitored/data")"
    [ -n "$profile_files" ] || profile_files="-"
    [ -n "$profile_bytes" ] || profile_bytes="-"
    [ -n "$profile_renames" ] || profile_renames="-"
    [ -n "$profile_deletes" ] || profile_deletes="-"
    [ -n "$profile_elapsed" ] || profile_elapsed="-"
    [ -n "$profile_ext" ] || profile_ext="-"
  done

  completed="${#r_scores[@]}"
  echo "  profile: $profile_raw"

  if [ "$completed" -eq 0 ]; then
    echo "  spread: no completed round" >&2
    table_rows+=("$(printf '%-24s | %6s | %9s | %4s | %4s | %4s | %-24s | %-16s | %-10s | %-6s | %-28s | %s' \
      "$NAME" "$profile_files" "$profile_bytes" "$profile_renames" "$profile_deletes" "$profile_elapsed" "$profile_ext" \
      "ERROR" "-" "-" "-" "ERROR")")
    overall=2
    error_rounds=$((error_rounds + 1))
    echo
    continue
  fi

  scores_spread="$(spread_of "${r_scores[@]}")"
  levels="$(printf '%s\n' "${r_levels[@]}" | sort -u | tr '\n' ',' | sed 's/,$//')"
  total_alerts=0
  for n in "${r_alerts[@]}"; do total_alerts=$((total_alerts + n)); done

  worst_rank=0
  for l in "${r_levels[@]}"; do
    r="$(level_rank "$l")"
    [ "$r" -gt "$worst_rank" ] && worst_rank="$r"
  done

  verdict="PASS"
  if [ "$worst_rank" -ge "$ALERT_MIN_RANK" ] || [ "$total_alerts" -gt 0 ]; then
    verdict="ALERT"
    overall=1
  fi
  if [ "$failed" -gt 0 ]; then
    verdict="$verdict ($failed round(s) failed)"
    [ "$overall" -lt 2 ] && overall=2
    error_rounds=$((error_rounds + 1))
  fi

  ttd_note=""
  [ "${#r_ttds[@]}" -gt 0 ] && ttd_note=" ttd(s) $(spread_of "${r_ttds[@]}")"
  echo "  spread: score(min/med/max)=$scores_spread alerted $alerted_here/$completed round(s)$ttd_note"
  [ "$bare" -gt 0 ] && echo "  note: $bare/$completed round(s) published no verdict at all (counted as score 0)"
  quiet_rounds=$((quiet_rounds + bare))

  table_rows+=("$(printf '%-24s | %6s | %9s | %4s | %4s | %4s | %-24s | %-16s | %-10s | %-6s | %-28s | %s' \
    "$NAME" "$profile_files" "$profile_bytes" "$profile_renames" "$profile_deletes" "$profile_elapsed" "$profile_ext" \
    "$scores_spread" "$levels" "$total_alerts" "$profile_signals" "$verdict")")
  echo
done

echo "-------------------------------------------------------------------------------"
printf '%-24s | %6s | %9s | %4s | %4s | %4s | %-24s | %-16s | %-10s | %-6s | %-28s | %s\n' \
  "workload" "files" "bytes" "ren" "del" "dur" "extensions" "score(min/med/max)" "levels" "alerts" "peak signals" "verdict"
echo "-------------------------------------------------------------------------------"
[ "${#table_rows[@]}" -gt 0 ] && printf '%s\n' "${table_rows[@]}"
echo "-------------------------------------------------------------------------------"

if [ "$quiet_rounds" -gt 0 ]; then
  echo "corpus: $quiet_rounds round(s) published no verdict and were counted as score 0"
fi

if [ "$error_rounds" -gt 0 ]; then
  echo "corpus: $error_rounds workload(s) could not be fully measured"
fi
if [ "$overall" = "0" ]; then
  echo "corpus: all workloads stayed below alert_min_level=$ALERT_MIN over $ROUNDS round(s)"
elif [ "$overall" = "1" ]; then
  echo "corpus: at least one workload alerted at or above alert_min_level=$ALERT_MIN"
else
  echo "corpus: at least one workload could not be measured; no verdict is reported for it"
fi
exit "$overall"
