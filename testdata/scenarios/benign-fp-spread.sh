#!/usr/bin/env bash
# Run one benign workload N times and report the spread of its peak score.
#
# A single run is not a measurement: the same scenario has scored 100 and 56.4
# for a purely environmental reason (whether the detector read a file before or
# after it was renamed), so this reports min, median, max and how many rounds
# alerted rather than one number. Each round's time to first alert is reported
# too, with its own spread over the rounds that alerted — a false positive that
# takes twenty seconds to appear is a different problem from one that fires on
# the first write.
#
# Each round is a full benign-fp-check.sh pass — fresh calibration with the
# workload running, then the measured pass — so the spread covers calibration
# variance as well as detector variance. Rounds are independent; a round that
# cannot complete is reported as an error and excluded from the spread rather
# than being averaged in as a zero.
#
# Usage: benign-fp-spread.sh [-n rounds] <scenario-script> [extra scenario args...]
#
# Environment overrides:
#   GRIMA_FP_SPREAD_ROUNDS  rounds to run (default 5)
#   GRIMA_FP_SPREAD_WORK    work root (default $TMPDIR/grima-fp-spread)
#   plus everything benign-fp-check.sh honours: GRIMA_BINARY, GRIMA_FP_PORT,
#   GRIMA_FP_DURATION, GRIMA_FP_WARMUP, GRIMA_FP_PYTHON
#
# Exits 0 when every round stayed silent, 1 when any round alerted, 2 when a
# round could not complete.
#
# A round in which no verdict carried evidence is counted as a score of 0, and
# the summary says how many rounds were like that, so "quiet" is never confused
# with "the detector produced nothing at all".
set -uo pipefail

ROOT_SP="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
HARNESS="$ROOT_SP/benign-fp-check.sh"
[ -f "$HARNESS" ] || { echo "error: $HARNESS is missing" >&2; exit 2; }

ROUNDS="${GRIMA_FP_SPREAD_ROUNDS:-5}"
while [ "$#" -gt 0 ]; do
  case "$1" in
    -n) ROUNDS="${2:-}"; shift 2 ;;
    -n*) ROUNDS="${1#-n}"; shift ;;
    *) break ;;
  esac
done

case "$ROUNDS" in
  ''|*[!0-9]*) echo "error: round count must be a positive integer: '$ROUNDS'" >&2; exit 2 ;;
esac
[ "$ROUNDS" -ge 1 ] || { echo "error: round count must be at least 1" >&2; exit 2; }

if [ "$#" -lt 1 ]; then
  echo "usage: benign-fp-spread.sh [-n rounds] <scenario-script> [extra args...]" >&2
  exit 2
fi

SCRIPT="$1"
[ -f "$SCRIPT" ] || { echo "error: no such scenario: $SCRIPT" >&2; exit 2; }
NAME="$(basename "$SCRIPT" .sh)"

WORK="${GRIMA_FP_SPREAD_WORK:-${TMPDIR:-${TEMP:-${TMP:-/tmp}}}/grima-fp-spread}/$NAME"
mkdir -p "$WORK"

echo "spread report: $NAME over $ROUNDS round(s)"
echo "rounds: $WORK"
echo

scores=()
alerts=()
ttds=()
failed=0
bare=0

round=0
while [ "$round" -lt "$ROUNDS" ]; do
  round=$((round + 1))
  log="$WORK/round-$round.out"
  # Each round gets its own work root so a stale baseline from an earlier round
  # cannot be loaded by a later one.
  GRIMA_FP_WORK="$WORK/round-$round" \
    "${BASH:-bash}" "$HARNESS" "$@" > "$log" 2>&1
  rc=$?

  result="$(grep '^RESULT ' "$log" | tail -1)"
  if [ "$rc" = "2" ] || [ -z "$result" ]; then
    echo "round $round: ERROR (harness exit $rc) — see $log"
    tail -3 "$log" | sed 's/^/  /'
    failed=$((failed + 1))
    continue
  fi

  score="$(printf '%s' "$result" | sed -n 's/.*max_score=\([^ ]*\).*/\1/p')"
  level="$(printf '%s' "$result" | sed -n 's/.*max_level=\([^ ]*\).*/\1/p')"
  sig="$(printf '%s' "$result" | sed -n 's/.*max_signals=\([^ ]*\).*/\1/p')"
  n_alerts="$(printf '%s' "$result" | sed -n 's/.*alerts=\([0-9]*\).*/\1/p')"
  round_ttd="$(printf '%s' "$result" | sed -n 's/.*ttd=\([^ ]*\).*/\1/p')"
  [ -n "$n_alerts" ] || n_alerts=0
  [ -n "$round_ttd" ] || round_ttd=-

  if [ "$score" = "none" ]; then
    echo "round $round: no verdict carried evidence, alerts=$n_alerts ttd=$round_ttd — see $log"
    scores+=("0.0")
    bare=$((bare + 1))
  else
    echo "round $round: score=$score level=$level alerts=$n_alerts ttd=$round_ttd signals=${sig:--}"
    scores+=("$score")
  fi
  alerts+=("$n_alerts")
  if [ "$n_alerts" -gt 0 ] && [ "$round_ttd" != "-" ]; then
    ttds+=("$round_ttd")
  fi
done

completed=${#scores[@]}
if [ "$completed" -eq 0 ]; then
  echo
  echo "error: no round completed; nothing to report" >&2
  exit 2
fi

# spread_of <label> <value>... — prints min, median and max of the values.
spread_of() {
  local label="$1"; shift
  local count=$# min max median lo hi sorted
  [ "$count" -gt 0 ] || return 0
  sorted="$(printf '%s\n' "$@" | sort -n)"
  min="$(printf '%s\n' "$sorted" | sed -n '1p')"
  max="$(printf '%s\n' "$sorted" | sed -n "${count}p")"
  if [ $((count % 2)) -eq 1 ]; then
    median="$(printf '%s\n' "$sorted" | sed -n "$(( (count + 1) / 2 ))p")"
  else
    lo="$(printf '%s\n' "$sorted" | sed -n "$(( count / 2 ))p")"
    hi="$(printf '%s\n' "$sorted" | sed -n "$(( count / 2 + 1 ))p")"
    median="$(awk -v a="$lo" -v b="$hi" 'BEGIN { printf "%.1f", (a + b) / 2 }')"
  fi
  echo "$label min=$min median=$median max=$max"
}

alerted_rounds=0
for n in "${alerts[@]}"; do
  [ "$n" -gt 0 ] && alerted_rounds=$((alerted_rounds + 1))
done

echo
echo "--- spread over $completed completed round(s) ---"
spread_of "score  " "${scores[@]}"
# Time to first alert is only defined for rounds that alerted, so its spread is
# over those rounds alone.
[ "${#ttds[@]}" -gt 0 ] && spread_of "ttd(s) " "${ttds[@]}"
echo "alerted $alerted_rounds/$completed round(s)"
[ "$bare" -gt 0 ] && echo "quiet   $bare/$completed round(s) published no verdict at all (counted as 0)"
[ "$failed" -gt 0 ] && echo "failed  $failed/$ROUNDS round(s) did not complete"

echo
if [ "$failed" -gt 0 ]; then
  exit 2
fi
if [ "$alerted_rounds" -gt 0 ]; then
  exit 1
fi
exit 0
