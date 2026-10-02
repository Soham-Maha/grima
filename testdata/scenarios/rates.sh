#!/usr/bin/env bash
# Sprint 2 items 2.2 and 2.3 — validate the dual-track design and the head+tail
# entropy sample against the controlled encryptor.
#
# Phases (default: all):
#   drip          `encryptor.py --rate drip`, the case the sprint names.
#   quiet-drip    the same 1-file-per-5s rate with fixtures that carry no
#                 window-visible content evidence, so the cumulative track is
#                 the only track that can fire. This is the crisp dual-track
#                 demonstration: every decaying-window signal absent, the
#                 cumulative counters climbing until they cross the band.
#                 GRIMA_RATES_QUIET_WRITE_MS (default 2500) spreads each file's
#                 write over that many milliseconds. The default was chosen when
#                 the detector defaulted to correlation attribution, which only
#                 considered processes seen writing in the last 2 s, so a
#                 single-shot write was blamed on whichever process happened to
#                 be busy and the evidence fragmented across four fingerprints
#                 (0.18 + 0.16 + 0.08 + 0.06) with no fingerprint crossing the
#                 band. Under the host-filing default that mechanism is gone and
#                 the default's effect is not re-measured — see §23.
#   intermittent  `encryptor.py --rate intermittent`, which overwrites only the
#                 first 4 KiB of each file.
#   tail          a file whose head is untouched and whose last 4 KiB is
#                 overwritten: detection can only come from the tail half of the
#                 sensor's head+tail sample.
#
# The decoy is disabled: a decoy planted inside the fixture tree can be collected
# by the encryptor, and a decoy touch is a rule override at critical, which would
# contaminate the signal evidence these phases exist to collect.
#
# Usage: rates.sh [phase ...]
#
# Environment overrides:
#   GRIMA_BINARY      detector binary (default: <repo>/grima[.exe])
#   GRIMA_RATES_PORT  dashboard port (default 8794)
#   GRIMA_RATES_WORK  work root (default $TMPDIR/grima-rates)
#   GRIMA_RATES_PYTHON  interpreter for the fixtures
#   GRIMA_RATES_FILES   files for the paced drip phases (default 20)
#   GRIMA_RATES_QUIET_WRITE_MS  milliseconds to spread each quiet-drip write over
#
# Evidence: every phase prints its full verdict series, the check list, and the
# path of its logs. Exits non-zero if any check fails.
set -uo pipefail

ROOT_SH="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

# The detector may be a native binary or a Windows .exe driven from WSL or
# Git-Bash, and the fixtures may run under either interpreter, so paths are
# carried in the form each tool understands.
to_host_path() {
  local path="$1" converted=""
  case "$path" in
    [A-Za-z]:[\\/]*) printf '%s' "$path" | tr '\\' '/'; return ;;
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

PYTHON="$(pick_python "${GRIMA_RATES_PYTHON:-}" python3 python)" \
  || { echo "error: python is required for the fixtures" >&2; exit 2; }

PORT="${GRIMA_RATES_PORT:-8794}"
WORK="${GRIMA_RATES_WORK:-${TMPDIR:-${TEMP:-${TMP:-/tmp}}}/grima-rates}"

# A work root the detector cannot address produces an empty baseline and a
# sensor reporting "no directory could be watched", which reads like a detector
# failure rather than a misconfigured path. Under Git-Bash, /tmp has been seen
# to resolve to a WSL share (//wsl.localhost/...), which filewatch cannot open.
# Fail before anything is measured rather than after the phase reports nothing.
# Git-Bash converts through cygpath and WSL through wslpath; both are checked,
# because the WSL route yields a //wsl.localhost path the detector cannot open.
if command -v cygpath >/dev/null 2>&1 || command -v wslpath >/dev/null 2>&1; then
  case "$(to_host_path "$WORK")" in
    [A-Za-z]:*) ;;
    *)
      echo "error: work root $WORK is not a drive-letter path the detector can watch" >&2
      echo "       set GRIMA_RATES_WORK=\"\$TEMP/grima-rates\" (or fix TMPDIR)" >&2
      exit 2
      ;;
  esac
fi
FILES="${GRIMA_RATES_FILES:-20}"
QUIET_FILES="${GRIMA_RATES_QUIET_FILES:-24}"
QUIET_WRITE_MS="${GRIMA_RATES_QUIET_WRITE_MS:-2500}"
QUIET_INTERVAL="${GRIMA_RATES_QUIET_INTERVAL:-2.5}"
PDF_FILES="${GRIMA_RATES_PDF_FILES:-40}"

SCENARIOS="$ROOT_SH/testdata/scenarios"
ENCRYPTOR_PY="$SCENARIOS/encryptor.py"
QUIET_DRIP_PY="$SCENARIOS/quiet_drip.py"
HEAD_TAIL_PY="$SCENARIOS/head_tail_fixture.py"

failures=0
DETECTOR_PID=""
POLLER_PID=""

fail() { echo "FAIL: $*" >&2; failures=$((failures + 1)); }
pass() { echo "PASS: $*"; }

cleanup() {
  [ -n "$POLLER_PID" ] && kill "$POLLER_PID" 2>/dev/null
  [ -n "$DETECTOR_PID" ] && kill "$DETECTOR_PID" 2>/dev/null
  return 0
}
trap cleanup EXIT

# --- shared helpers ----------------------------------------------------------

write_config() { # $1 phase dir
  local dir="$1"
  cat > "$dir/grima.toml" <<EOF
[general]
monitor_paths = ["$(to_host_path "$dir/data")"]
log_level = "info"

[web]
enabled = true
listen = "127.0.0.1:$PORT"

[decoy]
enabled = false

[calibration]
warmup = "15s"
min_samples = 20
baseline_path = "$(to_host_path "$dir/baseline.json")"

[procwatch]
sample_interval = "500ms"

[attribution]
# Pinned rather than defaulted. Every check in this script describes how the
# detector behaves when evidence is filed at the host, so a change to the
# default must not silently re-point the measurements underneath it.
mode = "host"
EOF
}

capture_baseline() { # $1 phase dir, $2 warmup function, rest: workdir for it
  local dir="$1" warmup="$2" data="$3"
  "$BINARY" --config "$(to_host_path "$dir/grima.toml")" --calibrate > "$dir/calibrate.log" 2>&1 &
  local cal=$!
  "$warmup" "$data" "$dir/warmup.log"
  wait "$cal"
  if ! grep -q 'baseline written' "$dir/calibrate.log"; then
    cat "$dir/calibrate.log" >&2
    fail "calibration wrote no baseline"
    return 1
  fi
  if grep -qE 'baseline written.*extensions=0' "$dir/calibrate.log"; then
    cat "$dir/calibrate.log" >&2
    fail "baseline has no entropy samples: the host was idle during warm-up"
    return 1
  fi
  pass "baseline captured ($(grep -o 'extensions=[0-9]*' "$dir/calibrate.log" | tail -1))"
}

start_detector() { # $1 phase dir, $2 duration
  "$BINARY" --config "$(to_host_path "$1/grima.toml")" --duration "$2" > "$1/grima.log" 2>&1 &
  DETECTOR_PID=$!
  sleep 3
  if grep -q 'no usable baseline' "$1/grima.log"; then
    fail "detector ran uncalibrated despite a captured baseline"
  fi
}

# poll_verdicts records one line per verdict for every poll, so the file is both
# the evidence and the input to the checks.
poll_verdicts() { # $1 out file, $2 duration seconds
  local out="$1"
  local duration="$2"
  local end
  end=$(( $(date +%s) + duration ))
  : > "$out"
  while [ "$(date +%s)" -lt "$end" ]; do
    curl -fsS --max-time 3 "http://127.0.0.1:$PORT/api/verdicts" 2>/dev/null \
      | "$PYTHON" -c "$VERDICT_PY" >> "$out" 2>/dev/null
    sleep 5
  done
}

read -r -d '' VERDICT_PY <<'PY' || true
import datetime, json, sys
levels = ["info", "low", "medium", "high", "critical"]
try:
    verdicts = json.load(sys.stdin)
except Exception:
    sys.exit(0)
stamp = datetime.datetime.now().strftime("%H:%M:%S")
if not verdicts:
    print("%s (no verdicts)" % stamp)
    sys.exit(0)
for v in verdicts:
    signals = ", ".join("%s=%.3f" % (s["Name"], s["Value"]) for s in (v.get("Signals") or []))
    print("%s score=%.1f level=%s pid=%s proc=%s signals=%s"
          % (stamp, v["Score"], levels[v["Level"]], v["PID"], v["ProcName"], signals or "-"))
PY

# check_series prints the series and asserts what the phase is supposed to show.
# $1 file, $2 phase label, $3 present signals (csv or -), $4 absent signals (csv
# or -), $5 extra check: alert | early-below-medium, $6 signals of which at
# least one must be present (csv or -, default -)
check_series() {
  local file="$1"
  local label="$2"
  local present="$3"
  local absent="$4"
  local extra="$5"
  local any="${6:--}"
  echo
  echo "--- $label: verdict series ---"
  cat "$file"
  echo "--- $label: checks ---"
  "$PYTHON" -c "$CHECK_PY" "$file" "$label" "$present" "$absent" "$extra" "$any"
  local rc=$?
  [ "$rc" -eq 0 ] || failures=$((failures + 1))
}

read -r -d '' CHECK_PY <<'PY' || true
import re
import sys

path, label, present, absent, extra = sys.argv[1:6]
any_of = sys.argv[6] if len(sys.argv) > 6 else "-"
levels = ["info", "low", "medium", "high", "critical"]
groups = []
seen = set()
worst = {}
line = re.compile(r"^(\d\d:\d\d:\d\d) score=([\d.]+) level=(\w+) pid=(-?\d+) proc=(\S+) signals=(.*)$")
for row in open(path, encoding="utf-8", errors="replace"):
    row = row.rstrip("\n")
    m = line.match(row)
    if not m:
        continue
    stamp, score, level, pid, proc, sigs = m.groups()
    names = [] if sigs == "-" else [s.split("=")[0] for s in sigs.split(", ")]
    for name in names:
        seen.add(name)
    for s in ([] if sigs == "-" else sigs.split(", ")):
        name, value = s.split("=")
        worst[name] = max(worst.get(name, 0.0), float(value))
    groups.append((stamp, float(score), level, pid, proc, names))

failures = []

def check(ok, message):
    print(("PASS " if ok else "FAIL ") + message)
    if not ok:
        failures.append(message)

if not groups:
    check(False, "no verdict was ever produced")
else:
    if extra == "alert":
        top = max(groups, key=lambda g: levels.index(g[2]))
        check(levels.index(top[2]) >= 2,
              "a verdict reached the alert band (highest %s, score %.1f on %s)" % (top[2], top[1], top[4]))
    elif extra == "early-below-medium":
        first = groups[0]
        check(levels.index(first[2]) < 2,
              "first verdict was below the alert band (%s, score %.1f on %s)" % (first[2], first[1], first[4]))
        top = max(groups, key=lambda g: levels.index(g[2]))
        check(levels.index(top[2]) >= 2,
              "a later verdict reached the alert band (highest %s, score %.1f on %s)" % (top[2], top[1], top[4]))
    for name in [n for n in present.split(",") if n and n != "-"]:
        shown = " (max value %.3f)" % worst[name] if name in worst else ""
        check(name in seen, "signal %s was present%s" % (name, shown))
    wanted = [n for n in any_of.split(",") if n and n != "-"]
    if wanted:
        hit = [n for n in wanted if n in seen]
        check(bool(hit), "at least one cumulative signal fired (%s)"
              % ("; ".join("%s=max %.3f" % (n, worst.get(n, 0.0)) for n in hit) or "none"))
    for name in [n for n in absent.split(",") if n and n != "-"]:
        check(name not in seen, "signal %s was absent from every verdict" % name)
    stamps = []
    for g in groups:
        if not stamps or stamps[-1] != g[0]:
            stamps.append(g[0])
    print("INFO %d polls with verdicts, first %s, last %s" % (len(stamps), stamps[0], stamps[-1]))

sys.exit(1 if failures else 0)
PY

# --- warm-up workloads -------------------------------------------------------

warmup_text() { # $1 data dir, $2 log
  local data="$1" log="$2" round i
  for round in 1 2 3 4 5 6 7 8; do
    for i in $(seq 1 "$FILES"); do
      printf 'benign rewrite round %s file %s with ordinary prose\n' "$round" "$i" > "$data/report_$i.txt"
    done
    sleep 2
  done > "$log" 2>&1
}

warmup_pdf() { # $1 data dir, $2 log
  local data="$1" log="$2" round i
  for round in 1 2 3 4 5 6 7 8; do
    for i in $(seq 1 "$PDF_FILES"); do
      write_plain_pdf "$data/scan_$i.pdf" "$round" "$i"
    done
    sleep 2
  done > "$log" 2>&1
}

write_plain_pdf() { # $1 path, $2 round, $3 index
  {
    printf '%%PDF-1.7\n'
    yes "pdf body round $2 index $3 ordinary document text for the fixture" | head -n 600
  } > "$1"
}

warmup_quiet() { # $1 data dir, $2 log
  local data="$1" log="$2" round
  for round in $(seq 1 4); do
    "$PYTHON" "$(to_host_path "$QUIET_DRIP_PY")" --path "$(to_host_path "$data")" \
      --files "$QUIET_FILES" --prepare --size-bytes 1048576 --seed "$round" >> "$log" 2>&1
    sleep 2
  done
}

# --- phases ------------------------------------------------------------------

phase_drip() {
  local dir="$WORK/drip"
  local data="$dir/data"
  local i
  rm -rf "$dir"
  mkdir -p "$data"
  for i in $(seq 1 "$FILES"); do
    printf 'plain text report line %s\nsecond line of the report\n' "$i" > "$data/report_$i.txt"
  done

  echo
  echo "=== 2.2 drip: encryptor.py --rate drip, 1 file / 5s ==="
  write_config "$dir"
  capture_baseline "$dir" warmup_text "$data"
  start_detector "$dir" 130s
  poll_verdicts "$dir/verdicts.txt" 135 &
  POLLER_PID=$!
  sleep 6

  "$PYTHON" "$(to_host_path "$ENCRYPTOR_PY")" --path "$(to_host_path "$data")" \
    --rate drip --max-files "$FILES" --seed 5 > "$dir/encryptor.log" 2>&1
  cat "$dir/encryptor.log"

  wait "$POLLER_PID" 2>/dev/null
  POLLER_PID=""
  wait "$DETECTOR_PID" 2>/dev/null
  DETECTOR_PID=""

  echo "detector alerts: $(grep -c 'ransomware risk detected' "$dir/grima.log")"
  check_series "$dir/verdicts.txt" "drip" "-" "write_burst" "alert" \
    "unknown_extension_activity,cum_bytes_rewritten"
  grep -qE 'level=(high|critical)' "$dir/grima.log" && pass "detector logged an alert for drip" \
    || fail "no high/critical alert logged for drip"
  echo "logs: $dir"
}

phase_quiet_drip() {
  local dir="$WORK/quiet-drip"
  local data="$dir/data"
  rm -rf "$dir"
  mkdir -p "$data"

  echo
  echo "=== 2.2 quiet drip: same rate, fixtures with no window-visible content ==="
  "$PYTHON" "$(to_host_path "$QUIET_DRIP_PY")" --path "$(to_host_path "$data")" \
    --files "$QUIET_FILES" --prepare --size-bytes 1048576 --seed 1
  write_config "$dir"
  capture_baseline "$dir" warmup_quiet "$data"
  print_baseline_entropy "$dir/baseline.json" ".dat"

  start_detector "$dir" 150s
  poll_verdicts "$dir/verdicts.txt" 155 &
  POLLER_PID=$!
  sleep 5

  "$PYTHON" "$(to_host_path "$QUIET_DRIP_PY")" --path "$(to_host_path "$data")" \
    --files "$QUIET_FILES" --interval "$QUIET_INTERVAL" --write-ms "$QUIET_WRITE_MS" \
    --seed 7 > "$dir/drip.log" 2>&1
  cat "$dir/drip.log"

  wait "$POLLER_PID" 2>/dev/null
  POLLER_PID=""
  wait "$DETECTOR_PID" 2>/dev/null
  DETECTOR_PID=""

  echo "detector alerts: $(grep -c 'ransomware risk detected' "$dir/grima.log")"
  check_series "$dir/verdicts.txt" "quiet-drip" \
    "unknown_extension_activity,cum_bytes_rewritten" \
    "write_burst,entropy_deviation,magic_mismatch,rename_burst,delete_rate,dir_fanout" \
    "early-below-medium"
  grep -qE 'level=(medium|high|critical)' "$dir/grima.log" && pass "detector logged an alert for quiet drip" \
    || fail "no alert logged for quiet drip"
  echo "logs: $dir"
}

print_baseline_entropy() { # $1 baseline json, $2 extension
  "$PYTHON" - "$1" "$2" <<'PY'
import json, sys
try:
    bl = json.load(open(sys.argv[1]))
except Exception as exc:
    print("baseline unreadable: %s" % exc)
    sys.exit(0)
d = bl.get("entropy_by_ext", {}).get(sys.argv[2])
if not d:
    print("baseline has no entropy samples for %s" % sys.argv[2])
else:
    print("baseline %s entropy: mean=%.3f std_dev=%.3f sigma_floor=%.3f n=%d"
          % (sys.argv[2], d["mean"], d["std_dev"], bl.get("sigma_floor", 0), d["n"]))
PY
}

# sample_z turns the fixture's measured head and head+tail entropies into the
# per-sample deviation the entropy signal would see, so "the tail sample is what
# caught it" is a number rather than an assertion.
sample_z() { # $1 baseline json, $2 extension, $3 fixture log
  local head sampled
  head="$(grep -o 'head_mean=[0-9.]*' "$3" | cut -d= -f2)"
  sampled="$(grep -o 'sampled_mean=[0-9.]*' "$3" | cut -d= -f2)"
  if [ -z "$head" ] || [ -z "$sampled" ]; then
    fail "fixture log does not report head/sampled entropy"
    return 1
  fi
  "$PYTHON" - "$1" "$2" "$head" "$sampled" <<'PY'
import json, sys
bl = json.load(open(sys.argv[1]))
ext, head, sampled = sys.argv[2], float(sys.argv[3]), float(sys.argv[4])
d = bl["entropy_by_ext"][ext]
sigma = max(d["std_dev"], bl.get("sigma_floor", 0.0))
for label, value in (("head sample alone", head), ("head+tail sample", sampled)):
    z = (value - d["mean"]) / sigma if sigma else 0.0
    print("%s: entropy %.2f vs baseline %.3f sigma %.3f -> z=%.2f, signal value %.3f"
          % (label, value, d["mean"], sigma, z, max(0.0, min(1.0, z / 6)) if z > 0 else 0.0))
PY
}

phase_intermittent() {
  local dir="$WORK/intermittent"
  local data="$dir/data"
  local i
  rm -rf "$dir"
  mkdir -p "$data"
  for i in $(seq 1 "$PDF_FILES"); do
    write_plain_pdf "$data/scan_$i.pdf" 0 "$i"
  done

  echo
  echo "=== 2.3 intermittent: encryptor.py --rate intermittent, first 4 KiB only ==="
  write_config "$dir"
  capture_baseline "$dir" warmup_pdf "$data"
  print_baseline_entropy "$dir/baseline.json" ".pdf"
  start_detector "$dir" 45s
  poll_verdicts "$dir/verdicts.txt" 50 &
  POLLER_PID=$!
  sleep 5

  "$PYTHON" "$(to_host_path "$ENCRYPTOR_PY")" --path "$(to_host_path "$data")" \
    --rate intermittent --max-files "$PDF_FILES" --seed 9 > "$dir/encryptor.log" 2>&1
  cat "$dir/encryptor.log"

  wait "$POLLER_PID" 2>/dev/null
  POLLER_PID=""
  wait "$DETECTOR_PID" 2>/dev/null
  DETECTOR_PID=""

  echo "detector alerts: $(grep -c 'ransomware risk detected' "$dir/grima.log")"
  check_series "$dir/verdicts.txt" "intermittent" \
    "entropy_deviation,unknown_extension_activity" "-" "alert"
  echo "signals named in the detector's own alert lines:"
  grep 'ransomware risk detected' "$dir/grima.log" | sed -n '1p;$p' \
    | sed 's/.*signals=/  signals=/'
  echo "logs: $dir"
}

phase_tail() {
  local dir="$WORK/tail"
  local data="$dir/data"
  rm -rf "$dir"
  mkdir -p "$data"
  write_plain_pdf "$data/plain.pdf" 0 0

  echo
  echo "=== 2.3 tail sample: head untouched, last 4 KiB overwritten ==="
  write_config "$dir"
  capture_baseline "$dir" warmup_pdf "$data"
  print_baseline_entropy "$dir/baseline.json" ".pdf"
  start_detector "$dir" 40s
  poll_verdicts "$dir/verdicts.txt" 45 &
  POLLER_PID=$!
  sleep 5

  "$PYTHON" "$(to_host_path "$HEAD_TAIL_PY")" --path "$(to_host_path "$data")" \
    --region tail --files 5 --size-bytes 65536 --extension .pdf --seed 3 > "$dir/fixture.log" 2>&1
  cat "$dir/fixture.log"
  sample_z "$dir/baseline.json" ".pdf" "$dir/fixture.log"

  wait "$POLLER_PID" 2>/dev/null
  POLLER_PID=""
  wait "$DETECTOR_PID" 2>/dev/null
  DETECTOR_PID=""

  echo "detector alerts: $(grep -c 'ransomware risk detected' "$dir/grima.log")"
  check_series "$dir/verdicts.txt" "tail" "entropy_deviation" "magic_mismatch" "alert"
  echo "logs: $dir"
}

# --- main --------------------------------------------------------------------

phases=("$@")
[ "${#phases[@]}" -eq 0 ] && phases=(drip quiet-drip intermittent tail)

mkdir -p "$WORK"
echo "detector: $BINARY"
echo "work root: $WORK"

for phase in "${phases[@]}"; do
  case "$phase" in
    drip) phase_drip ;;
    quiet-drip) phase_quiet_drip ;;
    intermittent) phase_intermittent ;;
    tail) phase_tail ;;
    *) fail "unknown phase $phase (expected drip, quiet-drip, intermittent, tail)" ;;
  esac
done

echo
if [ "$failures" -eq 0 ]; then
  echo "rates: all checks passed"
else
  echo "rates: $failures check(s) failed"
fi
exit $(( failures > 0 ? 1 : 0 ))
