#!/usr/bin/env bash
# Linux end-to-end smoke test.
#
# Runs on a native Linux host, so unlike the Windows script there is no path
# juggling and no cross-filesystem boundary: inotify works on the fixture tree,
# and the detector's own loopback is reachable.
#
# Usage: testdata/scenarios/smoke-linux.sh
#   GRIMA_BINARY  detector to run (default: ./grima in the repo root)
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
WORK="${GRIMA_SMOKE_WORK:-$(mktemp -d -t grima-smoke-XXXXXX)}"
DATA="$WORK/data"
PORT="${GRIMA_SMOKE_PORT:-8791}"
CONFIG="$WORK/grima.toml"
BASELINE="$WORK/baseline.json"
LOG="$WORK/grima.log"

BINARY="${GRIMA_BINARY:-$ROOT/grima}"
[ -x "$BINARY" ] || { echo "error: no binary at $BINARY; run 'make build' or set GRIMA_BINARY" >&2; exit 2; }

# A python on PATH has to prove it evaluates code and prints the answer: a
# resolver that only checks the command exists accepts a shim that then fails to
# open any script.
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

PYTHON="$(pick_python python3 python)" \
  || { echo "error: python3 is required for the fixtures" >&2; exit 2; }

fail() { echo "FAIL: $*" >&2; [ -n "${KEEP_WORK:-}" ] || rm -rf "$WORK"; exit 1; }
pass() { echo "PASS: $*"; }

mkdir -p "$DATA"
GRIMA_PID=""
trap 'kill "$GRIMA_PID" 2>/dev/null; [ -n "${KEEP_WORK:-}" ] || rm -rf "$WORK"' EXIT

# Prints the highest-scoring verdict the dashboard is holding. Every assertion
# below is level-based, and the level is a band, so the margin above or below a
# band is what says whether an assertion is tight — the log alone only shows the
# verdicts that alerted.
report_peak() { # $1 label
  curl -fsS --max-time 5 "http://127.0.0.1:$PORT/api/verdicts" > "$WORK/verdicts.json" 2>/dev/null || return 0
  "$PYTHON" - "$WORK/verdicts.json" "$1" <<'PY'
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

# --- fixture -----------------------------------------------------------------

for i in $(seq 1 40); do
  printf 'plain text report line %s\nsecond line of the report\n' "$i" > "$DATA/report_$i.txt"
done
for i in $(seq 1 15); do
  { printf 'PK\003\004'; printf 'office payload %s with ordinary content\n' "$i"; } > "$DATA/doc_$i.docx"
done

cat > "$CONFIG" <<EOF
[general]
monitor_paths = ["$DATA"]
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
baseline_path = "$BASELINE"

[procwatch]
sample_interval = "500ms"
EOF

# --- calibration -------------------------------------------------------------
# A baseline captured against an idle directory is useless, so drive ordinary
# writes while the warm-up runs.

echo "--- capturing baseline (15s) ---"
"$BINARY" --config "$CONFIG" --calibrate > "$WORK/calibrate.log" 2>&1 &
CALIB_PID=$!

for round in 1 2 3 4 5 6; do
  for i in $(seq 1 40); do
    printf 'benign rewrite round %s file %s with ordinary prose\n' "$round" "$i" > "$DATA/report_$i.txt"
  done
  sleep 2
done
wait "$CALIB_PID"

grep -q 'baseline written' "$WORK/calibrate.log" \
  || { cat "$WORK/calibrate.log"; fail "calibration"; }
grep -qE 'baseline written.*extensions=0' "$WORK/calibrate.log" \
  && { cat "$WORK/calibrate.log"; fail "baseline has no samples: the host was idle"; }
pass "baseline captured"

# --- detection run -----------------------------------------------------------

"$BINARY" --config "$CONFIG" --duration 45s > "$LOG" 2>&1 &
GRIMA_PID=$!
sleep 4

curl -fsS "http://127.0.0.1:$PORT/healthz" > "$WORK/healthz.json" \
  || fail "health endpoint did not answer on Linux loopback"
pass "health endpoint answered"

"$PYTHON" - "$WORK/healthz.json" <<'PY' || fail "Linux sensors did not report"
import json, sys
h = json.load(open(sys.argv[1]))
if not h.get("calibration_ready"):
    sys.exit("detector did not load the baseline")
sensors = h.get("sensors", {})
for name in ("filewatch", "procwatch", "persistwatch"):
    if name not in sensors:
        sys.exit(f"sensor {name} missing from health")
print("  sensors:", ", ".join(sorted(sensors)))
fw = sensors["filewatch"]
if not fw.get("Reporting"):
    sys.exit("filewatch does not report counters")
print("  filewatch reporting:", fw.get("Events"), "events")
pw = sensors["persistwatch"].get("Extra", {}).get("tracked")
if not pw:
    sys.exit("persistwatch scanned no persistence locations on this host")
print("  persistwatch tracked:", pw, "locations")
PY
pass "Linux sensors registered and reporting"

# --- benign workload: must not alert ----------------------------------------

for round in 1 2 3; do
  for i in $(seq 1 40); do
    printf 'benign rewrite round %s file %s ordinary prose content\n' "$round" "$i" > "$DATA/report_$i.txt"
  done
done
sleep 4

report_peak "benign rewrite"

# response.alert_min_level is medium, so any alert line at all is a false
# positive. Asserting only "not high|critical" accepts the whole medium band —
# the first band a benign workload can alert in, and the band §19 recorded a
# benign atomic-save batch alerting in.
if grep -q 'ransomware risk detected' "$LOG"; then
  cat "$LOG"; fail "benign rewrite alerted"
fi
pass "benign rewrite did not alert"

# --- malicious workload: must alert -----------------------------------------

dump_diagnostics() {
  echo "--- healthz after the workload ---"
  curl -fsS "http://127.0.0.1:$PORT/healthz" 2>/dev/null | "$PYTHON" -m json.tool 2>/dev/null || echo "(unavailable)"
  echo "--- verdicts ---"
  curl -fsS "http://127.0.0.1:$PORT/api/verdicts" 2>/dev/null | head -c 2000 || echo "(unavailable)"
  echo
  echo "--- grima log ---"
  cat "$LOG"
  echo "--- encryptor log ---"
  cat "$WORK/encryptor.log"
}

"$PYTHON" "$ROOT/testdata/scenarios/encryptor.py" --path "$DATA" --rate burst --seed 7 \
  > "$WORK/encryptor.log" 2>&1 || fail "encryptor fixture failed"
sleep 6

report_peak "burst encryption"

# The burst encryptor reaches critical on both platforms, so demanding critical
# rather than high|critical closes the 30-point slack a high threshold leaves:
# with noisy-OR fusion a run that has gone partly blind still lands in the high
# band, which is exactly what the old threshold let through (docs/sprints.md §15).
if ! grep -q 'level=critical' "$LOG"; then
  dump_diagnostics
  fail "encryption workload was not detected at critical on Linux"
fi
pass "encryption workload detected at critical"

grep -q 'entropy_deviation\|magic_mismatch\|unknown_extension_activity' "$LOG" \
  && pass "content-derived signals fired" \
  || fail "detection carried no content-derived signal"

wait "$GRIMA_PID" 2>/dev/null

echo
echo "--- detected verdicts ---"
grep -E 'level=critical' "$LOG" | sed -n '1,3p'

echo
echo "smoke test complete (Linux)"
