#!/usr/bin/env bash
# Run one benign scenario against a calibrated detector and report whether the
# detector alerted on it.
#
# This is the false-positive half of the corpus: the workload is legitimate bulk
# I/O, so any verdict at or above response.alert_min_level is a false positive
# and the script prints the verdict with its signals instead of hiding it.
#
# The workload is run once to time it, once during the detector's calibration,
# and again for the measured pass, so the host being watched has the shape of a
# machine that has used that tool before: the extensions it writes and the
# entropy ranges it produces are baseline data, not novelty.
#
# The timing pass exists because a calibration window shorter than one workload
# pass is a measurement defect, not a conservative default: a pass whose late
# writes fall outside the window (npm-install spends its last seconds in a
# temp-file rename loop) leaves those extensions unlearned, and the measured
# pass then reports them as first-seen novelty. The window is sized from the
# measured pass instead of being a constant.
#
# Usage: benign-fp-check.sh <scenario-script> [extra scenario args...]
#   the scenario must accept its work directory as its first argument
#
# Environment overrides:
#   GRIMA_BINARY        detector binary (default: <repo>/grima[.exe])
#   GRIMA_FP_PORT       dashboard port (default 8794)
#   GRIMA_FP_WORK       work root (default $TMPDIR/grima-fp)
#   GRIMA_FP_DURATION   minimum detector run length (default 90s; raised when
#                       the workload takes longer, so the detector outlives it)
#   GRIMA_FP_WARMUP     calibration window in seconds. Default: the measured
#                       workload pass plus 5s, floored at 15s. Raise it only if
#                       a workload writes in more than one distinct phase.
#   GRIMA_FP_PYTHON     interpreter for the end-of-run verdict dump
#
# Exits 0 when the workload stayed silent, 1 when it produced an alert.
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

if [ "$#" -lt 1 ]; then
  echo "usage: benign-fp-check.sh <scenario-script> [extra args...]" >&2
  exit 2
fi

SCRIPT="$1"; shift
[ -f "$SCRIPT" ] || { echo "error: no such scenario: $SCRIPT" >&2; exit 2; }
NAME="$(basename "$SCRIPT" .sh)"

BINARY="${GRIMA_BINARY:-$ROOT_SH/grima}"
[ -x "$BINARY" ] || BINARY="$ROOT_SH/grima.exe"
[ -x "$BINARY" ] || { echo "error: build grima first (make build), or set GRIMA_BINARY" >&2; exit 2; }

# A `python3` on PATH may be a Windows Store stub that prints an install message
# and exits 0, so `-c 'import sys'` proves nothing: the stub satisfies it and
# then fails to open any script. Each candidate has to prove it evaluates code
# and prints the answer, which the stub does not.
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

PYTHON="$(pick_python "${GRIMA_FP_PYTHON:-}" python3 python)" \
  || { echo "error: python is required for the verdict dump" >&2; exit 2; }

PORT="${GRIMA_FP_PORT:-8794}"
DURATION="${GRIMA_FP_DURATION:-90s}"
WORK="${GRIMA_FP_WORK:-${TMPDIR:-${TEMP:-${TMP:-/tmp}}}/grima-fp}/$NAME"

# A work root the detector cannot address produces an empty baseline and a
# sensor reporting "no directory could be watched", which reads like a detector
# failure rather than a misconfigured path. Under Git-Bash, /tmp has been seen
# to resolve to a WSL share (//wsl.localhost/...), which filewatch cannot open.
# Fail before anything is measured rather than after the run reports nothing.
# Git-Bash converts through cygpath and WSL through wslpath; both are checked,
# because the WSL route yields a //wsl.localhost path the detector cannot open.
if command -v cygpath >/dev/null 2>&1 || command -v wslpath >/dev/null 2>&1; then
  case "$(to_host_path "$WORK")" in
    [A-Za-z]:*) ;;
    *)
      echo "error: work root $WORK is not a drive-letter path the detector can watch" >&2
      echo "       set GRIMA_FP_WORK=\"\$TEMP/grima-fp\" (or fix TMPDIR)" >&2
      exit 2
      ;;
  esac
fi
# The workload works inside a monitored tree rather than being the tree: most of
# these scripts reset their own work directory at the start, and deleting the
# directory the sensor is watching removes the watch, after which nothing is
# seen and the baseline comes out empty.
MONITOR="$WORK/monitored"
DATA="$MONITOR/data"
mkdir -p "$WORK"
rm -rf "$MONITOR"
mkdir -p "$DATA"

echo "false-positive check: $NAME"
echo "work directory: $DATA"
echo "detector: $BINARY on port $PORT"

run_scenario() { # $1 log file, rest: extra scenario args
  local log="$1"; shift
  "${BASH:-bash}" "$SCRIPT" "$DATA" "$@" > "$log" 2>&1
}

# GNU tar reads `C:/...` as a remote `host:path` and fails, so a workload that
# archives by absolute path silently produces no archive under Git-Bash or WSL
# even though the detector run itself is fine. `--force-local` is the documented
# GNU answer; bsdtar has no such rule and no such flag, so it is only added when
# the tar on PATH is GNU. (benign-archive.sh's archiver choice is not
# drive-letter safe; this keeps the corpus runnable, it does not fix that.)
if tar --version 2>/dev/null | grep -q 'GNU tar'; then
  export TAR_OPTIONS="--force-local ${TAR_OPTIONS:-}"
fi

# --- sizing: how long is one workload pass? ---------------------------------

# The detector's calibration window has to cover a whole pass. Measuring the
# pass costs one extra workload run; guessing costs a false positive that is
# indistinguishable from a detection failure, which is worse.
echo "timing pass: $NAME"
pass_start="$(date +%s)"
run_scenario "$WORK/timing.log" "$@" || true
slowest_pass=$(( $(date +%s) - pass_start ))
echo "workload pass: ${slowest_pass}s"
tail -1 "$WORK/timing.log" 2>/dev/null | sed 's/^/  /'

WARMUP_SECS="${GRIMA_FP_WARMUP:-0}"
case "$WARMUP_SECS" in
  ''|*[!0-9]*) WARMUP_SECS=0 ;;
esac
if [ "$WARMUP_SECS" -le 0 ]; then
  WARMUP_SECS=$(( slowest_pass + 5 ))
  [ "$WARMUP_SECS" -lt 15 ] && WARMUP_SECS=15
fi
echo "calibration window: ${WARMUP_SECS}s"

cat > "$WORK/grima.toml" <<EOF
[general]
monitor_paths = ["$(to_host_path "$MONITOR")"]
log_level = "info"

[web]
enabled = true
listen = "127.0.0.1:$PORT"

[decoy]
enabled = false

[calibration]
warmup = "${WARMUP_SECS}s"
min_samples = 20
baseline_path = "$(to_host_path "$WORK/baseline.json")"

[procwatch]
sample_interval = "500ms"
EOF

# --- calibration: the workload runs while the baseline is captured -----------

"$BINARY" --config "$(to_host_path "$WORK/grima.toml")" --calibrate > "$WORK/calibrate.log" 2>&1 &
CAL_PID=$!

calibration_passes=0
cal_deadline=$(( $(date +%s) + WARMUP_SECS + 3 ))
while [ "$(date +%s)" -lt "$cal_deadline" ]; do
  pass_start="$(date +%s)"
  run_scenario "$WORK/warmup.log" "$@" || true
  pass_elapsed=$(( $(date +%s) - pass_start ))
  [ "$pass_elapsed" -gt "$slowest_pass" ] && slowest_pass="$pass_elapsed"
  calibration_passes=$((calibration_passes + 1))
done

# The detector is not waited on forever. filewatch.Start has been observed to
# stall for minutes on a ~400-directory tree while the host was busy — the same
# observation recorded as unreproduced in sprints.md §21 — and a harness that
# waits without a bound reports nothing at all, which reads as a detector that
# never started rather than one that hung.
cal_wait_deadline=$(( $(date +%s) + WARMUP_SECS + 120 ))
while kill -0 "$CAL_PID" 2>/dev/null && [ "$(date +%s)" -lt "$cal_wait_deadline" ]; do
  sleep 2
done
if kill -0 "$CAL_PID" 2>/dev/null; then
  kill "$CAL_PID" 2>/dev/null
  echo "error: calibration did not finish within $((WARMUP_SECS + 120))s" >&2
  echo "       the detector stalled during startup; last lines of its log:" >&2
  tail -5 "$WORK/calibrate.log" >&2
  exit 2
fi
wait "$CAL_PID" 2>/dev/null

if ! grep -q 'baseline written' "$WORK/calibrate.log"; then
  cat "$WORK/calibrate.log" >&2
  echo "error: calibration produced no baseline" >&2
  exit 2
fi
echo "baseline captured after $calibration_passes workload pass(es)"
grep 'baseline written' "$WORK/calibrate.log" | tail -1 | sed 's/^/  /'

# The detector has to outlive the workload. A detector that reaches --duration
# mid-workload closes its dashboard, so the run ends with no verdicts to read
# and a workload that was only half watched looks like a silent one. The
# warm-up passes just timed the workload, so size the measured run from the
# slowest of them. Only a plain seconds value can be resized; anything else
# (e.g. "1m30s") is left exactly as the operator set it.
DURATION_SECS="${DURATION%s}"
case "$DURATION_SECS" in
  ''|*[!0-9]*) DURATION_SECS=0 ;;
esac
if [ "$DURATION_SECS" -gt 0 ]; then
  needed=$(( slowest_pass + 30 ))
  if [ "$needed" -gt "$DURATION_SECS" ]; then
    echo "detector run extended to ${needed}s: the workload took ${slowest_pass}s in warm-up"
    DURATION="${needed}s"
  fi
fi

# --- measured run -----------------------------------------------------------

"$BINARY" --config "$(to_host_path "$WORK/grima.toml")" --duration "$DURATION" > "$WORK/grima.log" 2>&1 &
DET_PID=$!
trap 'kill "$DET_PID" 2>/dev/null' EXIT

# The detector is ready once the dashboard is listening, which happens after
# every sensor has started. Poll for that instead of guessing a sleep: a
# detector that never gets there — filewatch has been seen to stall on a large
# monitor tree (§23) — would otherwise be measured as a workload that stayed
# silent. The first polls race the shell creating the log file, so a missing
# file is not reported.
ready_deadline=$(( $(date +%s) + 30 ))
while [ "$(date +%s)" -lt "$ready_deadline" ]; do
  grep -q 'dashboard listening' "$WORK/grima.log" 2>/dev/null && break
  kill -0 "$DET_PID" 2>/dev/null || break
  sleep 1
done
if ! grep -q 'dashboard listening' "$WORK/grima.log"; then
  echo "error: the detector did not finish starting within 30s:" >&2
  cat "$WORK/grima.log" >&2
  kill "$DET_PID" 2>/dev/null
  wait "$DET_PID" 2>/dev/null
  trap - EXIT
  exit 2
fi

if grep -q 'no usable baseline' "$WORK/grima.log"; then
  echo "error: detector ran uncalibrated despite a captured baseline" >&2
  exit 2
fi

start="$(date +%s)"
run_scenario "$WORK/workload.log" "$@"
elapsed=$(( $(date +%s) - start ))

# A workload that aborted writes little or nothing, and "little" also produces
# no alert — so a silent verdict from a failed workload is not a measurement.
# Every benign workload ends with a SUMMARY line; without one, say so.
if ! grep -q '^SUMMARY ' "$WORK/workload.log"; then
  echo "error: the workload did not complete (no SUMMARY line), so a silent" >&2
  echo "       verdict would be meaningless:" >&2
  tail -5 "$WORK/workload.log" >&2
  kill "$DET_PID" 2>/dev/null
  wait "$DET_PID" 2>/dev/null
  trap - EXIT
  exit 2
fi
tail -1 "$WORK/workload.log"
echo "measured pass: ${elapsed}s"

# The sizing above is an estimate from the warm-up passes; if the measured pass
# still outran it, the detector is gone and so are its verdicts. Say so rather
# than reporting a workload nobody was watching.
if ! kill -0 "$DET_PID" 2>/dev/null; then
  echo "error: the detector exited before the workload finished (--duration $DURATION)," >&2
  echo "       so its verdicts were never collected; raise GRIMA_FP_DURATION" >&2
  tail -3 "$WORK/grima.log" >&2
  trap - EXIT
  exit 2
fi

sleep 8
curl -fsS --max-time 5 "http://127.0.0.1:$PORT/api/verdicts" > "$WORK/verdicts.json" 2>/dev/null

# A silent verdict only means something if the detector saw the workload, so the
# sensor counters are recorded next to the verdict they justify.
if curl -fsS --max-time 5 "http://127.0.0.1:$PORT/healthz" > "$WORK/healthz.json" 2>/dev/null; then
  "$PYTHON" - "$WORK/healthz.json" <<'PY'
import json, sys
h = json.load(open(sys.argv[1]))
fw = (h.get("sensors") or {}).get("filewatch") or {}
print("observed: calibration_ready=%s filewatch_events=%s filewatch_reporting=%s"
      % (h.get("calibration_ready"), fw.get("Events"), fw.get("Reporting")))
PY
else
  echo "observed: health endpoint unreachable from this shell"
fi

kill "$DET_PID" 2>/dev/null
wait "$DET_PID" 2>/dev/null
trap - EXIT

# --- verdict ----------------------------------------------------------------

echo
echo "--- verdicts at the end of the run ---"
if [ -s "$WORK/verdicts.json" ]; then
  "$PYTHON" - "$WORK/verdicts.json" <<'PY'
import json, sys
levels = ["info", "low", "medium", "high", "critical"]
for v in json.load(open(sys.argv[1])):
    signals = "; ".join("%s=%.3f" % (s["Name"], s["Value"]) for s in (v.get("Signals") or []))
    print("score=%.1f level=%s pid=%s proc=%s signals=%s"
          % (v["Score"], levels[v["Level"]], v["PID"], v["ProcName"], signals or "-"))
PY
else
  echo "(no verdict carried evidence)"
fi

alerts="$(grep -c 'ransomware risk detected' "$WORK/grima.log")"

# Time from the start of the measured workload to the first alert. A false
# positive that takes twenty seconds to appear is a different problem from one
# that fires on the first write, and a spread over rounds needs both numbers.
ttd="-"
first_alert="$(grep -m1 'ransomware risk detected' "$WORK/grima.log" || true)"
if [ -n "$first_alert" ]; then
  alert_at="$(printf '%s' "$first_alert" | sed -n 's/^time=\([^ ]*\).*/\1/p')"
  alert_epoch="$(date -d "$alert_at" +%s 2>/dev/null || true)"
  [ -n "$alert_epoch" ] && ttd=$(( alert_epoch - start ))
fi
echo
echo "--- detector alerts during the measured pass ---"
if [ "$alerts" = "0" ]; then
  echo "none"
else
  grep 'ransomware risk detected' "$WORK/grima.log" | sed -n '1p;$p'
fi
echo "logs: $WORK"

# One machine-readable line, so a spread report or any other consumer reads a
# parsed result instead of re-parsing the human-readable verdict dump above.
"$PYTHON" - "$WORK/verdicts.json" "$NAME" "$alerts" "$ttd" <<'PY' || \
  echo "RESULT scenario=$NAME max_score=unavailable max_level=unavailable max_signals=- alerts=$alerts ttd=$ttd"
import json, os, sys

path, name, alerts, ttd = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]
levels = ["info", "low", "medium", "high", "critical"]
verdicts = []
if os.path.exists(path) and os.path.getsize(path):
    try:
        verdicts = json.load(open(path))
    except ValueError:
        verdicts = []
if not verdicts:
    print("RESULT scenario=%s max_score=none max_level=none max_signals=- alerts=%s ttd=%s" % (name, alerts, ttd))
else:
    peak = max(verdicts, key=lambda v: v["Score"])
    names = ",".join(s["Name"] for s in (peak.get("Signals") or [])) or "-"
    print("RESULT scenario=%s max_score=%.1f max_level=%s max_signals=%s alerts=%s ttd=%s"
          % (name, peak["Score"], levels[peak["Level"]], names, alerts, ttd))
PY

echo
if [ "$alerts" = "0" ]; then
  echo "PASS: $NAME stayed below response.alert_min_level"
  exit 0
fi
echo "FALSE POSITIVE: $NAME produced $alerts alert line(s)"
exit 1
