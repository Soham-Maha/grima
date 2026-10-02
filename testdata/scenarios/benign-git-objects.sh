#!/usr/bin/env bash
# Benign workload: a git-shaped object/tree write pattern.
#
# Sprint 4 uses this to measure false positives. Every machine that checks out
# or commits code writes this shape: hundreds of small files under
# `.git/objects/<ab>/<38 hex>`, most of them extensionless, each one a
# zlib-deflated blob whose stored bytes look like ciphertext; an `index` and a
# `refs/heads/<branch>` rewritten temp-then-rename on every commit; and, on a
# repack, one large pack written and every loose object deleted in a burst.
#
# It is the workload in the corpus that stresses the widest set of scoring
# signals at once, which is why it is the most likely of the six to trip one:
#   entropy_deviation          zlib streams sample high, like encrypted output
#   unknown_extension_activity extensionless hex object names, plus a novel .pack
#   ngram_rename_chain         index and ref temp-then-rename per commit
#   delete_rate                a repack deletes every loose object at once
#   dir_fanout                 `.git/objects/<ab>` spreads writes over directories
#   cum_bytes_rewritten        objects written once, then re-read to build the pack
#
# The generator is a python program rather than shell loops for a measured
# reason: hashing and deflating each of ~160 objects from bash costs one process
# spawn per object per step, which measured at 39 s on this Windows host. The
# corpus driver runs this workload for every round, so that cost is multiplied.
# `benign-git-objects.py` does the same shape in-process in well under a second.
#
# Usage: benign-git-objects.sh [workdir]
#   workdir defaults to $TMPDIR/grima-benign-git-objects
#
# Runs unattended and is idempotent (fresh workdir, deterministic content), and
# prints exactly one SUMMARY line: files, bytes, renames, deletes, seconds,
# deflate mode and the extension mix.
set -uo pipefail

WORK="${1:-${TMPDIR:-${TEMP:-${TMP:-/tmp}}}/grima-benign-git-objects}"
COMMITS="${GRIMA_GIT_COMMITS:-2}"
FILES_PER_COMMIT="${GRIMA_GIT_FILES:-80}"
SRC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# A `python3` on PATH may be a Windows Store stub that prints an install message
# and exits 0, so it has to prove it evaluates code and prints the answer.
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

PYTHON="$(pick_python "${GRIMA_PYTHON:-}" python3 python)" \
  || { echo "error: git-objects workload needs a working python" >&2; exit 2; }

# The generator opens the workdir by name, so a Git-Bash `/c/...` path has to be
# converted to the drive-letter form Windows Python understands.
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

echo "git-objects workload: $COMMITS commits x $FILES_PER_COMMIT files, deflate=zlib"
echo "work directory: $WORK"

"$PYTHON" "$SRC_DIR/benign-git-objects.py" "$(to_host_path "$WORK")" "$COMMITS" "$FILES_PER_COMMIT"
