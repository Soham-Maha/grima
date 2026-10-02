#!/usr/bin/env bash
# Sprint 3 item 3.3 — the Cerberus-style cooperative split.
#
# The workload claims files cooperatively (`split.py --claim`): nothing assigns
# work, and each file is taken by whichever child creates its exclusive marker
# first, so no process owns a partition of the encryption. That is the shape the
# item is named after — cooperating children, not a statically partitioned batch.
#
# Two phases:
#
#   split      the workload against the shipped default, `attribution.mode =
#              "host"`. Asserts the split is detected: every write lands in the
#              host fingerprint, so the tree's rate crosses the threshold. This
#              is the phase that can be asserted, because it does not depend on
#              who the writes are blamed on.
#
#   correlate  the same workload with a launcher holding the tree open, under
#              `attribution.mode = "correlate"`. **Characterisation, not a
#              check**: it prints which root carried the crossing and whether
#              that root was the workload's own tree. Correlative attribution is
#              a byte-volume guess, so which tree receives the evidence is a race
#              with every other writer on the host — this phase records the
#              outcome rather than pretending it is stable.
#
# The "N children each below the threshold are scored as one actor above it"
# property itself is pinned deterministically, without timing or attribution, by
# `internal/fingerprint/split_test.go` — that test drives the engine from the
# outside and is the reproducible evidence for the aggregation. This script is
# the live counterpart.
#
# Both phases run uncalibrated on purpose: the claim is about an explicit
# threshold, and an uncalibrated detector is the configuration in which the
# threshold is a number this script chooses rather than one learned from the
# host. The window's decay half-life is shortened so the in-window count reflects
# the workload's current rate.
#
# Usage: cerberus.sh [split|correlate|all]
#
# Environment overrides:
#   GRIMA_BINARY           detector binary (default: <repo>/grima[.exe])
#   GRIMA_CERBERUS_PORT    dashboard port (default 8797)
#   GRIMA_CERBERUS_WORK    work root (default $TEMP/grima-cerberus)
#   GRIMA_CERBERUS_PYTHON  interpreter for the fixtures
#   GRIMA_CERBERUS_WORKERS / GRIMA_CERBERUS_FILES / GRIMA_CERBERUS_SIZE /
#   GRIMA_CERBERUS_INTERVAL   workload shape (8 x 60 x 512 KiB every 20 ms)
#
# Evidence: each phase prints its verdicts and its checks; raw polls are kept
# under the phase directory. Exits non-zero when a checked phase fails.
set -uo pipefail

ROOT_SH="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

to_host_path() {
  local path="$1" converted=""
  case "$path" in
    [A-Za-z]:[\\/]*) printf '%s' "$path" | tr '\\' '/' ; return ;;
  esac
  if command -v cygpath >/dev/null 2>&1; then
    converted="$(cygpath -w "$path" 2>/dev/null)"
  elif command -v wslpath >/dev/null 2>&1; then
    converted="$(wslpath -w "$path" 2>/dev/null)"
  fi
  if [ -n "$converted" ]; then
    printf '%s' "$converted" | tr '\\' '/'
  else
    printf '%s' "$path"
  fi
}

BINARY="${GRIMA_BINARY:-$ROOT_SH/grima}"
[ -x "$BINARY" ] || BINARY="$ROOT_SH/grima.exe"
[ -x "$BINARY" ] || { echo "error: build grima first (make build), or set GRIMA_BINARY" >&2; exit 2; }

# A `python3` on PATH may be a Windows Store stub that prints an install message
# and exits 0, so each candidate has to prove it evaluates code and prints the
# answer.
pick_python() {
  local candidate got
  for candidate in "$@"; do
    [ -n "$candidate" ] || continue
    got="$("$candidate" -c 'print(4**2)' 2>/dev/null | tr -d '\r')"
    if [ "$got" = "16" ]; then
      printf '%s' "$candidate"
      return 0
    fi
  done
  return 1
}

PYTHON="$(pick_python "${GRIMA_CERBERUS_PYTHON:-}" python3 python)" \
  || { echo "error: python is required for the fixtures" >&2; exit 2; }

PORT="${GRIMA_CERBERUS_PORT:-8797}"
WORK="${GRIMA_CERBERUS_WORK:-${TMPDIR:-${TEMP:-${TMP:-/tmp}}}/grima-cerberus}"
WORKERS="${GRIMA_CERBERUS_WORKERS:-8}"
FILES="${GRIMA_CERBERUS_FILES:-120}"
SIZE="${GRIMA_CERBERUS_SIZE:-524288}"
INTERVAL="${GRIMA_CERBERUS_INTERVAL:-0.02}"

# The uncalibrated write-rate threshold, left at the shipped default. The split's
# aggregate rate is many times this, which is what the host-filing phase asserts;
# the number is written down rather than inherited so a change to the default
# cannot silently move the measurement.
THRESHOLD=20

# The detector is a native binary: a work root that only exists in the shell's
# own namespace produces an empty baseline and a dead sensor, which reads like a
# detector failure rather than a misconfigured path.
if command -v cygpath >/dev/null 2>&1 || command -v wslpath >/dev/null 2>&1; then
  case "$(to_host_path "$WORK")" in
    [A-Za-z]:*) ;;
    *)
      echo "error: work root $WORK is not a drive-letter path the detector can watch" >&2
      echo "       set GRIMA_CERBERUS_WORK=\"\$TEMP/grima-cerberus\" (or fix TMPDIR)" >&2
      exit 2
      ;;
  esac
fi

SCENARIOS="$ROOT_SH/testdata/scenarios"
SPLIT_PY="$SCENARIOS/split.py"
LAUNCH_PY="$SCENARIOS/launch.py"
DATA="$WORK/data"
CLAIMS="$WORK/claims"

failures=0
DETECTOR_PID=""
POLLER_PID=""
fail() { echo "FAIL: $*" >&2; failures=$((failures + 1)); }

cleanup() {
  [ -n "$POLLER_PID" ] && kill "$POLLER_PID" 2>/dev/null
  [ -n "$DETECTOR_PID" ] && kill "$DETECTOR_PID" 2>/dev/null
  return 0
}
trap cleanup EXIT

write_config() { # $1 phase dir, $2 attribution mode
  local dir="$1" mode="$2"
  cat > "$dir/grima.toml" <<EOF
[general]
monitor_paths = ["$(to_host_path "$DATA")"]
log_level = "info"

[web]
enabled = true
listen = "127.0.0.1:$PORT"

[decoy]
enabled = false

[calibration]
# Deliberately no baseline: the claim is about an explicit threshold, and an
# uncalibrated detector is the configuration in which that threshold is a number
# this script chooses rather than one learned from the host.
baseline_path = "$(to_host_path "$dir/no-baseline.json")"

[window]
# Short enough that the in-window write count reflects what the workload is
# doing now, not what it did over the last half-minute.
decay_half_life = "2s"

[scoring]
absolute_write_rate = ${THRESHOLD}

[procwatch]
sample_interval = "500ms"

[attribution]
# Pinned, not defaulted: each phase's meaning depends on where evidence is filed.
mode = "$mode"
EOF
}

poll_verdicts() { # $1 out file, $2 duration seconds
  local out="$1" duration="$2" end
  end=$(( $(date +%s) + duration ))
  : > "$out"
  while [ "$(date +%s)" -lt "$end" ]; do
    curl -fsS --max-time 3 "http://127.0.0.1:$PORT/api/verdicts" 2>/dev/null \
      | tr -d '\n' >> "$out" 2>/dev/null
    printf '\n' >> "$out"
    sleep 2
  done
}

start_detector() { # $1 phase dir, $2 duration
  "$BINARY" --config "$(to_host_path "$1/grima.toml")" --duration "$2" > "$1/grima.log" 2>&1 &
  DETECTOR_PID=$!
  sleep 5
  if ! grep -q 'no usable baseline' "$1/grima.log"; then
    fail "the detector did not start uncalibrated; the threshold would not be the one this script set"
  fi
}

capture_health() { # $1 phase dir
  curl -fsS --max-time 5 "http://127.0.0.1:$PORT/healthz" > "$1/healthz.json" 2>/dev/null
  [ -s "$1/healthz.json" ] || return 0
  "$PYTHON" - "$1/healthz.json" <<'PY'
import json, sys
h = json.load(open(sys.argv[1]))
fw = h["sensors"].get("filewatch", {})
print("observed: calibration_ready=%s filewatch_events=%s bus_published=%s bus_dropped=%s"
      % (h["calibration_ready"], fw.get("Events"), h["bus_published"], h["bus_dropped"]))
PY
}

run_workload() { # $1 phase, $2 summary log
  local phase="$1" summary="$2"
  rm -rf "$CLAIMS"
  mkdir -p "$CLAIMS"
  if [ "$phase" = "split" ]; then
    "$PYTHON" "$SPLIT_PY" --path "$(to_host_path "$DATA")" --workers "$WORKERS" \
      --files-per-worker "$FILES" --size "$SIZE" --interval "$INTERVAL" --hold 5 \
      --claim --claim-dir "$(to_host_path "$CLAIMS")" --detach > "$summary" 2>&1
  else
    "$PYTHON" "$LAUNCH_PY" --out "$summary" --linger 45 -- \
      "$PYTHON" "$SPLIT_PY" --path "$(to_host_path "$DATA")" --workers "$WORKERS" \
      --files-per-worker "$FILES" --size "$SIZE" --interval "$INTERVAL" --hold 5 \
      --claim --claim-dir "$(to_host_path "$CLAIMS")"
  fi
  cat "$summary"
}

# workload_pids writes the workload's pids and its tree-root candidates to
# $1-pids.txt, one line each.
workload_pids() { # $1 summary log, $2 out file
  "$PYTHON" - "$1" > "$2" <<'PY'
import re, sys
all_pids, roots = [], []
for line in open(sys.argv[1], errors="replace"):
    for m in re.finditer(r"launch\.py pid=(\d+)", line):
        roots.append(m.group(1))
    for m in re.finditer(r"parent_pid=(\d+)", line):
        roots.append(m.group(1))
    for m in re.finditer(r"child_pids=([0-9,]+)", line):
        all_pids += m.group(1).split(",")
    for m in re.finditer(r"spawned pid=(\d+)", line):
        all_pids.append(m.group(1))
all_pids += roots
print(",".join(dict.fromkeys(all_pids)))
print(",".join(dict.fromkeys(roots)))
PY
}

# check_host_detection asserts the shipped default detects the split: the host
# fingerprint crosses the threshold. $1 polls file.
check_host_detection() {
  echo
  echo "--- split: verdicts ---"
  "$PYTHON" - "$1" <<'PY'
import json, sys
levels = ["info", "low", "medium", "high", "critical"]
best = None
for line in open(sys.argv[1]):
    line = line.strip()
    if not line:
        continue
    try:
        verdicts = json.loads(line)
    except ValueError:
        continue
    for v in verdicts or []:
        if v.get("PID") != 0:
            continue
        if best is None or v.get("Score", 0) > best.get("Score", 0):
            best = v
if best is None:
    print("no host verdict was produced")
    sys.exit(1)
signals = ", ".join("%s=%.3f" % (s["Name"], s["Value"]) for s in (best.get("Signals") or []))
print("pid=0 proc=%s score=%.1f level=%s signals=%s"
      % (best.get("ProcName"), best.get("Score", 0.0), levels[best.get("Level", 0)], signals or "-"))
if best.get("Level", 0) < 2:
    print("FAIL: the split was not detected (level %s, below medium)" % levels[best.get("Level", 0)])
    sys.exit(1)
if not any(s.get("Name") == "write_rate_absolute" for s in (best.get("Signals") or [])):
    print("FAIL: the verdict does not carry the write-rate signal the threshold produces")
    sys.exit(1)
print("PASS: the cooperative split was detected at %s" % levels[best.get("Level", 0)])
PY
  [ "$?" -eq 0 ] || failures=$((failures + 1))
}

# characterise_attribution prints which root carried the crossing. It never
# fails the run: the phase exists to record a race, not to assert a stable
# property.
characterise_attribution() { # $1 polls file, $2 roots csv, $3 pids csv
  echo
  echo "--- correlate: which root carried the crossing ---"
  "$PYTHON" - "$1" "$2" "$3" <<'PY'
import json, sys
polls, roots_csv, pids_csv = sys.argv[1:4]
roots = {int(p) for p in roots_csv.split(",") if p}
workload = {int(p) for p in pids_csv.split(",") if p}
levels = ["info", "low", "medium", "high", "critical"]
best = {}
for line in open(polls):
    line = line.strip()
    if not line:
        continue
    try:
        verdicts = json.loads(line)
    except ValueError:
        continue
    for v in verdicts or []:
        if not (set(v.get("PIDs") or []) & workload):
            continue
        key = v.get("PID")
        if key not in best or v.get("Score", 0) > best[key].get("Score", 0):
            best[key] = v
crossed = [v for v in best.values()
           if any(s.get("Name") == "write_rate_absolute" for s in (v.get("Signals") or []))]
if not crossed:
    print("no root crossed the threshold in this run")
    sys.exit(0)
for v in sorted(crossed, key=lambda v: -v.get("Score", 0)):
    signals = ", ".join("%s=%.3f" % (s["Name"], s["Value"]) for s in (v.get("Signals") or []))
    print("pid=%s proc=%s score=%.1f level=%s members=%d %s signals=%s"
          % (v.get("PID"), v.get("ProcName"), v.get("Score", 0.0), levels[v.get("Level", 0)],
             len(v.get("PIDs") or []),
             "ROOTED AT THE WORKLOAD" if v.get("PID") in roots else "rooted elsewhere",
             signals))
print("characterisation: correlative attribution is a byte-volume guess, so which tree "
      "receives the evidence is a race with every other writer on the host. The aggregation "
      "itself is pinned deterministically by internal/fingerprint/split_test.go.")
PY
}

run_phase() { # $1 phase name, $2 attribution mode
  local phase="$1" mode="$2" dir="$WORK/$1"
  rm -rf "$dir"
  mkdir -p "$dir"
  echo
  echo "=== 3.3 $phase: cooperative split, ${WORKERS} workers x ${FILES} files, threshold ${THRESHOLD}/s, mode=$mode ==="
  write_config "$dir" "$mode"
  start_detector "$dir" 75s
  poll_verdicts "$dir/polls.jsonl" 65 &
  POLLER_PID=$!
  sleep 2

  local summary="$dir/workload.log"
  run_workload "$phase" "$summary"
  sleep 6
  capture_health "$dir"
  sleep 2

  wait "$POLLER_PID" 2>/dev/null
  POLLER_PID=""
  wait "$DETECTOR_PID" 2>/dev/null
  DETECTOR_PID=""

  workload_pids "$summary" "$dir/workload-pids.txt"
  local pids roots
  pids="$(sed -n 1p "$dir/workload-pids.txt")"
  roots="$(sed -n 2p "$dir/workload-pids.txt")"
  echo "workload pids: $pids"
  echo "root pids: $roots"
  if [ -z "$pids" ]; then
    fail "the workload summary named no pid; the phase measured nothing"
    return 1
  fi

  if [ "$phase" = "split" ]; then
    check_host_detection "$dir/polls.jsonl"
  else
    characterise_attribution "$dir/polls.jsonl" "$roots" "$pids"
  fi
  echo "logs: $dir"
}

phases=("$@")
[ "${#phases[@]}" -eq 0 ] && phases=(split correlate)

mkdir -p "$WORK"
echo "detector: $BINARY"
echo "work root: $WORK"

rm -rf "$DATA"
mkdir -p "$DATA"
"$PYTHON" "$SPLIT_PY" --path "$(to_host_path "$DATA")" --prepare \
  --workers "$WORKERS" --files-per-worker "$FILES" --size "$SIZE" --claim || exit 2

for phase in "${phases[@]}"; do
  case "$phase" in
    split) run_phase split host ;;
    correlate) run_phase correlate correlate ;;
    *) fail "unknown phase $phase (expected split or correlate)" ;;
  esac
done

echo
if [ "$failures" -eq 0 ]; then
  echo "cerberus: all checks passed"
  exit 0
fi
echo "cerberus: $failures check(s) failed" >&2
exit 1
