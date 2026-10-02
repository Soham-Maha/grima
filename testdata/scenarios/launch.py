#!/usr/bin/env python3
"""Run a workload from a short-lived parent, so it has a process-tree root.

procwatch samples this launcher, and it lingers a few sample ticks so the
detector sees it; the workload it spawns is then a descendant of a process the
detector knows about, instead of a leaf of the desktop shell's tree. That is what
lets a verdict be matched to the workload's own tree rather than to
`explorer.exe`, whose members include every other application on the host.

Keep --linger longer than the workload: while the launcher is alive the workload
is aggregated under it, and when it exits the workload's own parent becomes the
root instead.

Usage: launch.py --out FILE [--linger S] -- CMD [ARG...]
"""
from __future__ import annotations

import argparse
import os
import subprocess
import sys
import time

ap = argparse.ArgumentParser()
ap.add_argument("--out", required=True)
ap.add_argument("--linger", type=float, default=2.5,
                help="seconds to stay alive after spawning the workload")
ap.add_argument("cmd", nargs=argparse.REMAINDER)
args = ap.parse_args()

cmd = args.cmd[1:] if args.cmd and args.cmd[0] == "--" else args.cmd
if not cmd:
    print("usage: launch.py --out FILE [--linger S] -- CMD [ARG...]", file=sys.stderr)
    sys.exit(2)

with open(args.out, "wb") as out:
    proc = subprocess.Popen(cmd, stdout=out, stderr=subprocess.STDOUT)

print(f"launch.py pid={os.getpid()} spawned pid={proc.pid}", flush=True)
time.sleep(args.linger)
