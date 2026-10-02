#!/usr/bin/env bash
# End-to-end smoke test.
#
# Builds a fixture tree, captures a host baseline against it, then runs a benign
# workload that must not alert and a controlled encryptor that must alert. Exits
# non-zero if either expectation is violated.
#
# The binary must already be built (`make build`); this script does not need a
# Go toolchain on PATH.
#
# Usage: testdata/scenarios/smoke.sh
set -uo pipefail

# --- paths -------------------------------------------------------------------
#
# The detector may be a native binary or a Windows .exe driven from WSL or
# Git-Bash, and the fixture script may run under either interpreter. So the same
# directory is addressed in two forms and each tool gets the one it understands.

ROOT_SH="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"   # for this shell

to_host_path() {
  local path="$1" converted=""
  case "$path" in
    [A-Za-z]:[\\/]*) printf '%s' "$path" | tr '\\' '/'; return ;;
  esac
  if command -v wslpath >/dev/null 2>&1; then
    converted="$(wslpath -w "$path" 2>/dev/null)"
  fi
  if [ -z "$converted" ] && command -v cygpath >/dev/null 2>&1; then
    converted="$(cygpath -w "$path" 2>/dev/null)"
  fi
  if [ -n "$converted" ]; then
    printf '%s' "$converted" | tr '\\' '/'
  else
    printf '%s' "$path"
  fi
}

ROOT_HOST="$(to_host_path "$ROOT_SH")"

WORK_SH="$ROOT_SH/.smoke";   DATA_SH="$WORK_SH/data"
WORK_HOST="$ROOT_HOST/.smoke"; DATA_HOST="$WORK_HOST/data"
CONFIG_SH="$WORK_SH/grima.toml"; CONFIG_HOST="$WORK_HOST/grima.toml"
BASELINE_SH="$WORK_SH/baseline.json"; BASELINE_HOST="$WORK_HOST/baseline.json"

PORT="${GRIMA_SMOKE_PORT:-8791}"

BINARY="${GRIMA_BINARY:-$ROOT_SH/grima}"
[ -x "$BINARY" ] || BINARY="$ROOT_SH/grima.exe"
[ -x "$BINARY" ] || { echo "error: build grima first (make build), or set GRIMA_BINARY" >&2; exit 2; }

# A `python3` on PATH may be a Windows Store stub that prints an install message
# and exits 0, so `command -v` proves nothing: the stub resolves, then fails to
# open any script. Each candidate has to prove it evaluates code and prints the
# answer, or the encryptor leg reports a fixture failure that is really a broken
# interpreter.
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

PYTHON="$(pick_python "${GRIMA_SMOKE_PYTHON:-}" python3 python)" \
  || { echo "error: python is required for the encryptor fixture" >&2; exit 2; }

# A Windows detector driven by a POSIX interpreter over a DrvFs mount cannot
# rename files the detector is reading: the rename is denied. Prefer a matching
# interpreter, and say so plainly when there is not one.
CAN_RUN_ENCRYPTOR=1
if [ "${BINARY##*.}" = "exe" ] && [ "${PYTHON#/}" != "$PYTHON" ]; then
  if WINDOWS_PYTHON="$(command -v python.exe 2>/dev/null)" && [ -n "$WINDOWS_PYTHON" ]; then
    PYTHON="$WINDOWS_PYTHON"
  else
    CAN_RUN_ENCRYPTOR=0
  fi
fi

ENCRYPTOR_SH="$ROOT_SH/testdata/scenarios/encryptor.py"
ENCRYPTOR_HOST="$ROOT_HOST/testdata/scenarios/encryptor.py"

# A POSIX interpreter needs the POSIX form of the path; a Windows one — including
# one reached through WSL interop at /mnt/c/... — needs the host form.
case "$PYTHON" in
  /mnt/*|[A-Za-z]:*) PY_DATA="$DATA_HOST"; PY_BASELINE="$BASELINE_HOST"; PY_ENCRYPTOR="$ENCRYPTOR_HOST" ;;
  /*)                PY_DATA="$DATA_SH";   PY_BASELINE="$BASELINE_SH";   PY_ENCRYPTOR="$ENCRYPTOR_SH" ;;
  *)                 PY_DATA="$DATA_HOST"; PY_BASELINE="$BASELINE_HOST"; PY_ENCRYPTOR="$ENCRYPTOR_HOST" ;;
esac

fail() { echo "FAIL: $*" >&2; exit 1; }
pass() { echo "PASS: $*"; }

# Prints the highest-scoring verdict the dashboard is holding. Every assertion
# below is level-based, and the level is a band, so the margin above or below a
# band is what says whether an assertion is tight — the log alone only shows the
# verdicts that alerted. Best-effort: no dashboard, no line.
report_peak() { # $1 label
  curl -fsS --max-time 5 "http://127.0.0.1:$PORT/api/verdicts" > "$WORK_SH/verdicts.json" 2>/dev/null || return 0
  "$PYTHON" -c 'pass' >/dev/null 2>&1 || return 0
  "$PYTHON" - "$WORK_SH/verdicts.json" "$1" <<'PY'
import json, sys
levels = ["info", "low", "medium", "high", "critical"]
try:
    verdicts = json.load(open(sys.argv[1]))
except ValueError:
    verdicts = []
if not verdicts:
    print("peak verdict (%s): none carried evidence" % sys.argv[2])
else:
    v = max(verdicts, key=lambda x: x["Score"])
    names = "; ".join(s["Name"] for s in (v.get("Signals") or [])) or "-"
    print("peak verdict (%s): score=%.1f level=%s proc=%s signals=%s"
          % (sys.argv[2], v["Score"], levels[v["Level"]], v["ProcName"], names))
PY
}

rm -rf "$WORK_SH"
mkdir -p "$DATA_SH"

# --- fixture -----------------------------------------------------------------

for i in $(seq 1 40); do
  printf 'plain text report line %s\nsecond line of the report\n' "$i" > "$DATA_SH/report_$i.txt"
done
for i in $(seq 1 15); do
  { printf 'PK\003\004'; printf 'office payload %s with ordinary content\n' "$i"; } > "$DATA_SH/doc_$i.docx"
done
for i in $(seq 1 10); do
  { printf '%%PDF-1.7\n'; printf 'pdf body %s\n' "$i"; } > "$DATA_SH/scan_$i.pdf"
done

cat > "$CONFIG_SH" <<EOF
[general]
monitor_paths = ["$DATA_HOST"]
log_level = "info"

[web]
enabled = true
listen = "127.0.0.1:$PORT"

[decoy]
enabled = true
count_per_dir = 2

[calibration]
warmup = "15s"
min_samples = 20
baseline_path = "$BASELINE_HOST"

[procwatch]
sample_interval = "500ms"
EOF

# --- calibration -------------------------------------------------------------
# A baseline captured against an idle directory is useless, so drive ordinary
# writes while the warm-up runs.

echo "--- capturing baseline (15s) ---"
"$BINARY" --config "$CONFIG_HOST" --calibrate > "$WORK_SH/calibrate.log" 2>&1 &
CALIB_PID=$!

for round in 1 2 3 4 5 6; do
  for i in $(seq 1 40); do
    printf 'benign rewrite round %s file %s with ordinary prose\n' "$round" "$i" > "$DATA_SH/report_$i.txt"
  done
  sleep 2
done
wait "$CALIB_PID"

grep -q 'baseline written' "$WORK_SH/calibrate.log" \
  || { cat "$WORK_SH/calibrate.log"; fail "calibration"; }

# Validated from the detector's own log rather than by reading the file back:
# a Windows writer and a POSIX reader can disagree about a fresh file for long
# enough to make a direct read flaky.
if grep -qE 'baseline written.*extensions=0' "$WORK_SH/calibrate.log"; then
  cat "$WORK_SH/calibrate.log"
  fail "baseline has no entropy samples: the host was idle during warm-up"
fi
pass "baseline captured"

# --- detection run -----------------------------------------------------------

"$BINARY" --config "$CONFIG_HOST" --duration 40s > "$WORK_SH/grima.log" 2>&1 &
GRIMA_PID=$!
# A failing assertion exits without waiting for the detector, which would leave
# it holding the port for the next run.
trap 'kill "$GRIMA_PID" 2>/dev/null' EXIT
sleep 4

# Calibration is asserted from the log rather than only over HTTP, so this works
# even where the shell cannot reach the detector's loopback address.
if grep -q 'no usable baseline' "$WORK_SH/grima.log"; then
  cat "$WORK_SH/grima.log"
  fail "detector ran uncalibrated despite a captured baseline"
fi
pass "detector loaded the baseline"

if curl -fsS --max-time 5 "http://127.0.0.1:$PORT/healthz" > "$WORK_SH/healthz.json" 2>/dev/null; then
  grep -q '"calibration_ready": true' "$WORK_SH/healthz.json" \
    && pass "health endpoint reports a calibrated host" \
    || fail "health endpoint disagrees with the log about calibration"
else
  echo "NOTE: dashboard not reachable from this shell (127.0.0.1 may not cross a"
  echo "      WSL/Windows boundary); skipping the HTTP check"
fi

# --- benign workload: must not alert ----------------------------------------

for round in 1 2 3; do
  for i in $(seq 1 40); do
    printf 'benign rewrite round %s file %s ordinary prose content\n' "$round" "$i" > "$DATA_SH/report_$i.txt"
  done
done
sleep 4

report_peak "benign rewrite"

# response.alert_min_level is medium, so any alert line at all is a false
# positive. Asserting only "not high|critical" accepts the whole medium band —
# the first band a benign workload can alert in, and the band §19 recorded a
# benign atomic-save batch alerting in.
if grep -q 'ransomware risk detected' "$WORK_SH/grima.log"; then
  cat "$WORK_SH/grima.log"
  fail "benign rewrite alerted"
fi
pass "benign rewrite did not alert"

# --- malicious workload: must alert -----------------------------------------

if [ "$CAN_RUN_ENCRYPTOR" = "0" ]; then
  echo "SKIP: encryptor scenario needs a Windows Python to drive a Windows binary"
  echo "      (a POSIX interpreter cannot rename files the detector is reading)."
  echo "      Set GRIMA_BINARY to a native build, or run under a matching interpreter."
  wait "$GRIMA_PID" 2>/dev/null
  echo
  echo "smoke test incomplete: benign path verified, detection path not exercised"
  exit 3
fi

"$PYTHON" "$PY_ENCRYPTOR" --path "$PY_DATA" --rate burst --seed 7 \
  > "$WORK_SH/encryptor.log" 2>&1 || fail "encryptor fixture failed"

sleep 6

report_peak "burst encryption"

# The burst encryptor reaches critical on both platforms, so demanding critical
# rather than high|critical closes the 30-point slack a high threshold leaves:
# with noisy-OR fusion a run that has gone partly blind still lands in the high
# band, which is exactly what the old threshold let through (docs/sprints.md §15).
if ! grep -q 'level=critical' "$WORK_SH/grima.log"; then
  echo "--- grima log ---"; cat "$WORK_SH/grima.log"
  echo "--- encryptor log ---"; cat "$WORK_SH/encryptor.log"
  fail "encryption workload was not detected at critical"
fi
pass "encryption workload detected at critical"

# --- in-place encryption: the content signals must fire ----------------------

for i in $(seq 1 30); do
  printf 'plain text report line %s\nsecond line of the report\n' "$i" > "$DATA_SH/inplace_$i.txt"
done
"$PYTHON" "$PY_ENCRYPTOR" --path "$PY_DATA" --rate burst --seed 11 --suffix "" \
  > "$WORK_SH/encryptor-inplace.log" 2>&1 || fail "in-place encryptor fixture failed"
sleep 5

grep -q 'entropy_deviation' "$WORK_SH/grima.log" && pass "entropy deviation fired" \
  || fail "in-place encryption produced no entropy deviation"
grep -q 'magic_mismatch' "$WORK_SH/grima.log" && pass "magic-byte mismatch fired" \
  || fail "in-place encryption produced no magic-byte mismatch"

wait "$GRIMA_PID" 2>/dev/null
trap - EXIT

echo
echo "--- detected verdicts ---"
grep -E 'level=critical' "$WORK_SH/grima.log" | sed -n '1,3p'

echo
echo "smoke test complete"
