#!/usr/bin/env bash
# overhead.sh — Sprint 4 item 4.8: what the detector costs the host it watches.
#
# Three phases, one measurement method (testdata/scenarios/overhead-sample.ps1,
# which reads per-process CPU time and working set out of Win32_Process):
#
#   idle      detector running over a monitored tree, no workload
#   load      the same detector, while a benign workload writes inside the tree
#   control   the same workload with no detector at all
#
# The control is the point: a CPU figure with nothing to compare it against is
# not an overhead, it is a number. The table reports each phase's mean and peak
# CPU (as a percentage of one core and of the machine's logical processors) and
# its mean and peak RSS, then the differences.
#
# Why a user-space process's idle cost matters at all is docs/plan.md §8 risk 3;
# a process that is expensive while doing nothing is a process that gets killed.
#
# Usage: overhead.sh
#
# Environment overrides:
#   GRIMA_OVERHEAD_BINARY    detector binary (default: <repo>/grima[.exe])
#   GRIMA_OVERHEAD_SCENARIO  workload script (default: benign-atomic-save.sh)
#   GRIMA_OVERHEAD_PORT      dashboard port (default: 8811)
#   GRIMA_OVERHEAD_IDLE_SECS idle phase length (default: 30)
#   GRIMA_OVERHEAD_CAP_SECS  cap on a workload phase (default: 180; the phase
#                            ends when the workload exits, whichever is first)
#   GRIMA_OVERHEAD_INTERVAL  sample interval in seconds (default: 1.0)
#   GRIMA_OVERHEAD_WORK      work root (default: $TMP/grima-overhead)
#
# Runs unattended. Exits non-zero if any phase produced no sample, if the
# workload printed no SUMMARY, or if the detector failed to start. Never leaves
# a detector process or a listener behind.
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

PS="powershell.exe"
command -v "$PS" >/dev/null 2>&1 || { echo "error: powershell.exe is required (this is a Windows measurement)" >&2; exit 2; }
command -v cygpath >/dev/null 2>&1 || { echo "error: run this under Git Bash (cygpath not found)" >&2; exit 2; }

BINARY="${GRIMA_OVERHEAD_BINARY:-${GRIMA_BINARY:-$ROOT_SH/grima}}"
[ -x "$BINARY" ] || BINARY="$ROOT_SH/grima.exe"
[ -x "$BINARY" ] || { echo "error: build grima first (make build), or set GRIMA_OVERHEAD_BINARY" >&2; exit 2; }

SCENARIO="${GRIMA_OVERHEAD_SCENARIO:-$ROOT_SH/testdata/scenarios/benign-atomic-save.sh}"
[ -f "$SCENARIO" ] || { echo "error: no such workload: $SCENARIO" >&2; exit 2; }

SAMPLER="$ROOT_SH/testdata/scenarios/overhead-sample.ps1"
[ -f "$SAMPLER" ] || { echo "error: missing $SAMPLER" >&2; exit 2; }

PORT="${GRIMA_OVERHEAD_PORT:-8811}"
IDLE_SECS="${GRIMA_OVERHEAD_IDLE_SECS:-30}"
CAP_SECS="${GRIMA_OVERHEAD_CAP_SECS:-180}"
INTERVAL="${GRIMA_OVERHEAD_INTERVAL:-1.0}"
GRACE=2
STARTUP_GRACE="${GRIMA_OVERHEAD_STARTUP_GRACE:-25}"
WBASH="${BASH:-bash}"
# The sampler stops the run when its first subject disappears, so the two
# workload phases are bounded by the workload, not by the cap.
RUN_SECS=$((IDLE_SECS + CAP_SECS + 60))

WORK="${GRIMA_OVERHEAD_WORK:-${TMPDIR:-${TEMP:-${TMP:-/tmp}}}/grima-overhead}/$$"
MONITOR="$WORK/monitored"
UNIQ="ovh$$x$(date +%s)"
TOKD="$UNIQ"
TOKL="${UNIQ}L"
TOKC="${UNIQ}C"

case "$(to_host_path "$WORK")" in
  [A-Za-z]:*) ;;
  *) echo "error: work root $WORK is not a drive-letter path; set GRIMA_OVERHEAD_WORK=\"\$TEMP/grima-overhead\"" >&2; exit 2 ;;
esac

# --- host context ------------------------------------------------------------

NCORES="$("$PS" -NoProfile -NonInteractive -Command '(Get-CimInstance Win32_ComputerSystem).NumberOfLogicalProcessors' 2>/dev/null | tr -d '\r' | head -1)"
case "$NCORES" in ''|*[!0-9]*) NCORES="${NUMBER_OF_PROCESSORS:-1}" ;; esac
[ "$NCORES" -ge 1 ] 2>/dev/null || NCORES=1
NCORES_PHYS="$("$PS" -NoProfile -NonInteractive -Command '(Get-CimInstance Win32_Processor | Measure-Object -Property NumberOfCores -Sum).Sum' 2>/dev/null | tr -d '\r' | head -1)"
case "$NCORES_PHYS" in ''|*[!0-9]*) NCORES_PHYS="$NCORES" ;; esac

cpu_name="$("$PS" -NoProfile -NonInteractive -Command '(Get-CimInstance Win32_Processor | Select-Object -First 1 -ExpandProperty Name)' 2>/dev/null | tr -d '\r' | head -1)"

# --- cleanup -----------------------------------------------------------------

DET_PID=""
WL_PIDS=()

port_owner() {
  "$PS" -NoProfile -NonInteractive -Command \
    "(Get-NetTCPConnection -LocalPort $PORT -State Listen -ErrorAction SilentlyContinue | Select-Object -First 1 -ExpandProperty OwningProcess)" \
    2>/dev/null | tr -d '\r' | head -1
}

cleanup() {
  local rc=$? p owner cmdline
  trap - EXIT INT TERM
  for p in "${WL_PIDS[@]:-}"; do
    [ -n "$p" ] && kill "$p" 2>/dev/null
  done
  if [ -n "$DET_PID" ]; then
    kill "$DET_PID" 2>/dev/null
  fi
  wait 2>/dev/null
  DET_PID=""
  # Fail-safe: a detector that ignored the kill, or a listener left by it. Only
  # a process whose command line carries this run's unique token is ours.
  owner="$(port_owner)"
  if [ -n "$owner" ] && [ "$owner" != "0" ]; then
    cmdline="$("$PS" -NoProfile -NonInteractive -Command \
      "(Get-CimInstance Win32_Process -Filter \"ProcessId=$owner\").CommandLine" 2>/dev/null | tr -d '\r')"
    case "$cmdline" in
      *"$UNIQ"*)
        "$PS" -NoProfile -NonInteractive -Command "Stop-Process -Id $owner -Force" >/dev/null 2>&1
        echo "cleanup: stopped leftover detector pid $owner on port $PORT" >&2
        ;;
      *)
        echo "warning: port $PORT still has a listener (pid $owner) that is not this run's detector" >&2
        ;;
    esac
  fi
  exit "$rc"
}
trap cleanup EXIT INT TERM

# A port already in use is someone else's measurement; refuse rather than
# sample against it or kill it.
busy="$(port_owner)"
if [ -n "$busy" ] && [ "$busy" != "0" ]; then
  echo "error: port $PORT is already in use (pid $busy); set GRIMA_OVERHEAD_PORT" >&2
  exit 2
fi

# --- work tree and detector config -------------------------------------------

mkdir -p "$MONITOR"
cat > "$WORK/grima-ovh-$TOKD.toml" <<EOF
[general]
monitor_paths = ["$(to_host_path "$MONITOR")"]
log_level = "info"

[web]
enabled = true
listen = "127.0.0.1:$PORT"

[decoy]
enabled = false
EOF

run_sampler() { # $1 subjects, $2 max seconds, $3 out csv, $4 log
  "$PS" -NoProfile -NonInteractive -ExecutionPolicy Bypass \
    -File "$(to_host_path "$SAMPLER")" \
    -Subjects "$1" -Seconds "$2" -IntervalSec "$INTERVAL" -GraceSec "$GRACE" \
    -StartupGraceSec "$STARTUP_GRACE" \
    -Out "$(to_host_path "$3")" > "$4" 2>&1
}

field() { # $1 summary line, $2 key
  printf '%s\n' "$1" | awk -v k="$2" '{ for (i=1;i<=NF;i++) { n=index($i,"="); if (n>0 && substr($i,1,n-1)==k) { print substr($i,n+1); exit } } }'
}

FAILED=0
samples_of() { grep -c '^SAMPLE ' "$1" 2>/dev/null || true; }

echo "overhead measurement — Sprint 4 item 4.8"
echo "host: ${NCORES} logical processors (${NCORES_PHYS} physical cores)${cpu_name:+ — $cpu_name}"
echo "workload: $(basename "$SCENARIO")   detector: $BINARY   port: $PORT"
echo "work dir: $WORK"
echo

# --- phase: idle -------------------------------------------------------------

"$BINARY" --config "$(to_host_path "$WORK/grima-ovh-$TOKD.toml")" --duration "${RUN_SECS}s" > "$WORK/grima.log" 2>&1 &
DET_PID=$!

ready_deadline=$(( $(date +%s) + 30 ))
while [ "$(date +%s)" -lt "$ready_deadline" ]; do
  grep -q 'dashboard listening' "$WORK/grima.log" 2>/dev/null && break
  kill -0 "$DET_PID" 2>/dev/null || break
  sleep 1
done
if ! grep -q 'dashboard listening' "$WORK/grima.log"; then
  echo "error: detector did not start within 30s; log:" >&2
  tail -20 "$WORK/grima.log" >&2
  exit 1
fi
echo "detector ready; sampling idle for ${IDLE_SECS}s"
run_sampler "det|cmd|$TOKD|grima|" "$IDLE_SECS" "$WORK/idle.csv" "$WORK/idle.sample.log"

# --- phase: load -------------------------------------------------------------

LOADDIR="$MONITOR/load"
echo "sampling under load: $(basename "$SCENARIO") -> $LOADDIR"
"$WBASH" "$SCENARIO" "$LOADDIR" "$TOKL" > "$WORK/load.work.log" 2>&1 &
WL_PIDS+=($!)
run_sampler "workload|cmd|$TOKL|bash|tree;det|cmd|$TOKD|grima|" "$CAP_SECS" "$WORK/load.csv" "$WORK/load.sample.log"
if kill -0 "${WL_PIDS[-1]}" 2>/dev/null; then kill "${WL_PIDS[-1]}" 2>/dev/null; fi
wait "${WL_PIDS[-1]}" 2>/dev/null

# --- stop detector, before the control ---------------------------------------

kill "$DET_PID" 2>/dev/null
wait "$DET_PID" 2>/dev/null
DET_PID=""
release_deadline=$(( $(date +%s) + 10 ))
while [ "$(date +%s)" -lt "$release_deadline" ]; do
  busy="$(port_owner)"
  [ -z "$busy" ] || [ "$busy" = "0" ] && break
  sleep 1
done

# --- phase: control ----------------------------------------------------------

CTRLDIR="$MONITOR/control"
echo "sampling control: $(basename "$SCENARIO") with no detector -> $CTRLDIR"
"$WBASH" "$SCENARIO" "$CTRLDIR" "$TOKC" > "$WORK/control.work.log" 2>&1 &
WL_PIDS+=($!)
run_sampler "workload|cmd|$TOKC|bash|tree" "$CAP_SECS" "$WORK/control.csv" "$WORK/control.sample.log"
if kill -0 "${WL_PIDS[-1]}" 2>/dev/null; then kill "${WL_PIDS[-1]}" 2>/dev/null; fi
wait "${WL_PIDS[-1]}" 2>/dev/null

# --- aggregate ---------------------------------------------------------------

declare -A V=()
add_row() { # phase, subject, csv, label
  local phase="$1" subject="$2" csv="$3" label="$4" line samples present
  line="$(grep -m1 "^SUMMARY label=$label " "$csv" 2>/dev/null || true)"
  if [ -z "$line" ]; then
    echo "error: phase '$phase' ($subject) produced no SUMMARY — expected label '$label' in $csv" >&2
    echo "       $(samples_of "$csv") sample line(s); sampler log:" >&2
    sed 's/^/       /' "$WORK/$phase.sample.log" >&2 2>/dev/null || true
    FAILED=1
    return
  fi
  samples="$(field "$line" samples)"
  present="$(field "$line" present)"
  case "$samples" in ''|*[!0-9]*) samples=0 ;; esac
  case "$present" in ''|*[!0-9]*) present=0 ;; esac
  if [ "$samples" -le 0 ] || [ "$present" -le 0 ]; then
    echo "error: phase '$phase' ($subject) produced no sample (samples=$samples, present=$present)" >&2
    FAILED=1
  fi
  V["${phase}_${subject}_samples"]="$samples"
  V["${phase}_${subject}_present"]="$present"
  V["${phase}_${subject}_cmean"]="$(field "$line" cpu_pct1_mean)"
  V["${phase}_${subject}_cpeak"]="$(field "$line" cpu_pct1_peak)"
  V["${phase}_${subject}_rmean"]="$(field "$line" rss_mean_mib)"
  V["${phase}_${subject}_rpeak"]="$(field "$line" rss_peak_mib)"
  V["${phase}_${subject}_procs"]="$(field "$line" procs_mean)"
}

phase_row() { # phase, subject — prints one table row, blank cells if absent
  local phase="$1" subject="$2"
  local cmean="${V[${phase}_${subject}_cmean]:-}"
  local mach="-"
  if [ -n "$cmean" ]; then
    mach="$(awk -v m="$cmean" -v n="$NCORES" 'BEGIN { printf "%.3f", m/n }')"
  fi
  printf '%-8s %-9s %8s %15s %15s %15s %12s %12s\n' \
    "$phase" "$subject" \
    "${V[${phase}_${subject}_samples]:--}" \
    "${cmean:--}" \
    "${V[${phase}_${subject}_cpeak]:--}" \
    "$mach" \
    "${V[${phase}_${subject}_rmean]:--}" \
    "${V[${phase}_${subject}_rpeak]:--}"
}

add_row idle    det      "$WORK/idle.csv"    det
add_row load    det      "$WORK/load.csv"    det
add_row load    workload "$WORK/load.csv"    workload
add_row control workload "$WORK/control.csv" workload

echo
echo "--- per-phase measurements (CPU as % of one core / of $NCORES logical processors) ---"
printf '%-8s %-9s %8s %15s %15s %15s %12s %12s\n' \
  phase subject samples "cpu_mean" "cpu_peak" "cpu_mean" "rss_MiB" "rss_MiB"
printf '%-8s %-9s %8s %15s %15s %15s %12s %12s\n' \
  "" "" "" "%1_core" "%1_core" "%machine" "mean" "peak"
phase_row idle    det
phase_row load    det
phase_row load    workload
phase_row control workload

echo
echo "--- differences ---"
idle_c="${V[idle_det_cmean]:-0}"; load_c="${V[load_det_cmean]:-0}"
idle_cp="${V[idle_det_cpeak]:-0}"; load_cp="${V[load_det_cpeak]:-0}"
idle_r="${V[idle_det_rmean]:-0}"; load_r="${V[load_det_rmean]:-0}"
lw_c="${V[load_workload_cmean]:-0}"; cw_c="${V[control_workload_cmean]:-0}"
lw_r="${V[load_workload_rmean]:-0}"; cw_r="${V[control_workload_rmean]:-0}"

awk -v nc="$NCORES" -v ic="$idle_c" -v lc="$load_c" -v icp="$idle_cp" -v lcp="$load_cp" \
    -v ir="$idle_r" -v lr="$load_r" -v lwc="$lw_c" -v cwc="$cw_c" -v lwr="$lw_r" -v cwr="$cw_r" 'BEGIN {
  printf "detector under load minus idle:  cpu mean %+.3f %%1core (%+.3f %%machine), peak %+.3f %%1core, rss mean %+.1f MiB\n", lc-ic, (lc-ic)/nc, lcp-icp, lr-ir
  printf "workload under detector minus control:  cpu mean %+.3f %%1core (%+.3f %%machine), rss mean %+.1f MiB\n", lwc-cwc, (lwc-cwc)/nc, lwr-cwr
}'

wl_time() { grep -m1 '^SUMMARY ' "$1" 2>/dev/null | sed -n 's/.*elapsed_s=\([0-9][0-9]*\).*/\1/p'; }
lt="$(wl_time "$WORK/load.work.log")"; ct="$(wl_time "$WORK/control.work.log")"
if [ -z "$lt" ] || [ -z "$ct" ]; then
  echo "error: workload printed no SUMMARY (load=${lt:-none}s control=${ct:-none}s); the workload did not complete" >&2
  FAILED=1
else
  awk -v l="$lt" -v c="$ct" 'BEGIN { printf "workload wall time: load %ds, control %ds (%+ds)\n", l, c, l-c }'
fi

if [ "$FAILED" -ne 0 ]; then
  echo
  echo "FAILED: at least one phase produced no sample" >&2
  exit 1
fi

echo
echo "logs and samples: $WORK"
