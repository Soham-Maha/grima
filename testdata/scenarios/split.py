#!/usr/bin/env python3
"""Controlled split workload for testing GRIMA's tree aggregation.

This is a test fixture, not malware. It uses no key material, refuses to touch
anything outside --path, and does not delete or rename anything.

A per-process classifier sees N quiet children; the tree aggregate sees one
actor. This fixture produces that shape so the claim can be measured against a
real detector: a parent forks --workers children, each of which overwrites
--files-per-worker files in place. Every child's own share is small enough to
stay below the alert band on its own; the tree total is not.

Two shapes are available, and they are not equivalent:

  * the default, where the parent partitions the files statically and each child
    owns its share;
  * --claim, where the children contend for one shared pool and each file is
    taken by whichever child creates its exclusive marker first. Nothing assigns
    work: the split emerges from the children. That is the Cerberus-style shape,
    and it is the one a per-process classifier cannot even describe, because no
    process owns a partition.

Files are overwritten in place rather than created, so the detector reads one
write per file and no create. Run --prepare once to lay the files down, then run
the workload against them; preparing and writing in the same pass would measure
creates, not writes.

Usage:
  split.py --path DIR --prepare --workers N --files-per-worker M [--claim]
  split.py --path DIR --workers N --files-per-worker M [--claim]
           [--interval S] [--stagger S] [--hold S] [--size BYTES]

The parent prints one parseable summary line naming its own pid and every child
pid, so a detector's verdict can be matched against the processes that produced
it:

  split.py summary parent_pid=1234 child_pids=1235,1236 workers=2 ...
"""

from __future__ import annotations

import argparse
import os
import random
import subprocess
import sys
import time

DEFAULT_SIZE = 65536


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Controlled split workload for GRIMA testing.")
    parser.add_argument("--path", required=True, help="directory to operate inside")
    parser.add_argument("--workers", type=int, default=5, help="children the parent forks")
    parser.add_argument("--files-per-worker", type=int, default=90, help="files each child rewrites")
    parser.add_argument("--size", type=int, default=DEFAULT_SIZE, help="bytes per file")
    parser.add_argument("--interval", type=float, default=0.02,
                        help="seconds between writes inside one child")
    parser.add_argument("--stagger", type=float, default=0.0,
                        help="seconds between child starts")
    parser.add_argument("--hold", type=float, default=10.0,
                        help="seconds a child stays alive after its last write")
    parser.add_argument("--ext", default=".txt", help="extension of the files to rewrite")
    parser.add_argument("--claim", action="store_true",
                        help="cooperative split: children contend for a shared pool of files, "
                             "claiming each by creating an exclusive marker, so no child owns a "
                             "partition of the work")
    parser.add_argument("--claim-dir", default="",
                        help="directory for claim markers (default: a sibling of --path, so the "
                             "markers are not themselves watched)")
    parser.add_argument("--detach", action="store_true",
                        help="exit as soon as the children are spawned, so each child becomes its "
                             "own process-tree root — the control for the aggregate")
    parser.add_argument("--prepare", action="store_true",
                        help="lay down the fixture files and exit")
    parser.add_argument("--worker", type=int, default=-1, help=argparse.SUPPRESS)
    return parser.parse_args()


def target_path(root: str, ext: str, worker: int, index: int) -> str:
    return os.path.join(root, f"split_w{worker}_{index:04d}{ext}")


def shared_path(root: str, ext: str, index: int) -> str:
    """A file in the shared pool: no worker owns it until one claims it."""
    return os.path.join(root, f"shared_{index:04d}{ext}")


def payload(size: int, worker: int, index: int) -> bytes:
    """Ordinary low-entropy text, so content signals stay quiet.

    The same generator is used to prepare the fixture and to rewrite it, so a
    baseline captured against this content matches the workload's entropy
    distribution instead of deviating from it.
    """
    line = f"split fixture line worker {worker} file {index} ordinary prose content\n"
    return (line * (size // len(line) + 1)).encode()[:size]


def rewrite(path: str, data: bytes) -> None:
    """Overwrite a file in place. The size does not change, so this is one write."""
    with open(path, "r+b") as handle:
        handle.write(data)
        handle.flush()
        os.fsync(handle.fileno())


def claim_dir(args: argparse.Namespace, root: str) -> str:
    """Where claim markers live. A sibling of the data directory by default, so
    the detector's own watch does not see the markers as file activity."""
    return args.claim_dir or os.path.join(os.path.dirname(root), "claims")


def claim_pool(args: argparse.Namespace) -> int:
    return args.workers * args.files_per_worker


def prepare(args: argparse.Namespace, root: str) -> int:
    written = 0
    if args.claim:
        os.makedirs(claim_dir(args, root), exist_ok=True)
    for index in range(claim_pool(args)):
        if args.claim:
            path = shared_path(root, args.ext, index)
        else:
            path = target_path(root, args.ext, index // args.files_per_worker, index % args.files_per_worker)
        try:
            with open(path, "wb") as handle:
                handle.write(payload(args.size, index % args.files_per_worker, index))
        except OSError as exc:
            print(f"skip {path}: {exc}", file=sys.stderr)
            continue
        written += 1
    print(f"split.py prepared files={written} workers={args.workers} "
          f"files_per_worker={args.files_per_worker} bytes={args.size} "
          f"claim={int(args.claim)} path={root}")
    return 0 if written else 2


def run_worker(args: argparse.Namespace, root: str) -> int:
    if args.claim:
        return run_claiming_worker(args, root)

    for index in range(args.files_per_worker):
        path = target_path(root, args.ext, args.worker, index)
        try:
            rewrite(path, payload(args.size, args.worker, index))
        except OSError as exc:
            print(f"skip {path}: {exc}", file=sys.stderr)
            continue
        if args.interval:
            time.sleep(args.interval)
    time.sleep(args.hold)
    return 0


def run_claiming_worker(args: argparse.Namespace, root: str) -> int:
    """Claim files from the shared pool and rewrite the ones this worker wins.

    The claim is an exclusive create, which is atomic across processes: exactly
    one child wins each file, and which child that is depends on timing rather
    than on a partition handed out by the parent. That is the shape a per-process
    classifier cannot see and a tree aggregate can.
    """
    rng = random.Random(args.worker)
    order = list(range(claim_pool(args)))
    rng.shuffle(order)

    claims = claim_dir(args, root)
    claimed = 0
    for index in order:
        marker = os.path.join(claims, f"shared_{index:04d}.claim")
        try:
            handle = os.open(marker, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o644)
        except FileExistsError:
            continue
        except OSError as exc:
            print(f"skip {marker}: {exc}", file=sys.stderr)
            continue
        os.close(handle)

        path = shared_path(root, args.ext, index)
        try:
            rewrite(path, payload(args.size, args.worker, index))
        except OSError as exc:
            print(f"skip {path}: {exc}", file=sys.stderr)
            continue
        claimed += 1
        if args.interval:
            time.sleep(args.interval)

    print(f"split.py worker={args.worker} pid={os.getpid()} claimed={claimed}", flush=True)
    time.sleep(args.hold)
    return 0


def missing_files(args: argparse.Namespace, root: str) -> list[str]:
    if args.claim:
        return [shared_path(root, args.ext, i)
                for i in range(claim_pool(args))
                if not os.path.exists(shared_path(root, args.ext, i))]
    paths = (target_path(root, args.ext, w, i)
             for w in range(args.workers)
             for i in range(args.files_per_worker))
    return [path for path in paths if not os.path.exists(path)]


def child_argv(args: argparse.Namespace, root: str, worker: int) -> list[str]:
    argv = [sys.executable, os.path.abspath(__file__),
            "--path", root,
            "--workers", str(args.workers),
            "--files-per-worker", str(args.files_per_worker),
            "--size", str(args.size),
            "--interval", str(args.interval),
            "--hold", str(args.hold),
            "--ext", args.ext,
            "--worker", str(worker)]
    if args.claim:
        argv += ["--claim", "--claim-dir", claim_dir(args, root)]
    return argv


def main() -> int:
    args = parse_args()

    root = os.path.abspath(args.path)
    if not os.path.isdir(root):
        print(f"error: {root} is not a directory", file=sys.stderr)
        return 2
    if args.workers < 1 or args.files_per_worker < 1 or args.size < 1:
        print("error: --workers, --files-per-worker and --size must be positive", file=sys.stderr)
        return 2

    if args.prepare:
        return prepare(args, root)

    if args.worker >= 0:
        return run_worker(args, root)

    missing = missing_files(args, root)
    if missing:
        print(f"error: {len(missing)} fixture files are missing, e.g. {missing[0]}; "
              f"run with --prepare first", file=sys.stderr)
        return 2

    children = []
    for worker in range(args.workers):
        children.append(subprocess.Popen(child_argv(args, root, worker)))
        if args.stagger:
            time.sleep(args.stagger)

    child_pids = [proc.pid for proc in children]
    print(f"split.py summary parent_pid={os.getpid()} "
          f"child_pids={','.join(str(pid) for pid in child_pids)} "
          f"workers={args.workers} files_per_child={args.files_per_worker} "
          f"total_files={args.workers * args.files_per_worker} "
          f"bytes_per_file={args.size} ext={args.ext} claim={int(args.claim)} "
          f"path={root}", flush=True)

    codes = [] if args.detach else [proc.wait() for proc in children]
    if args.detach:
        print(f"split.py detached parent_pid={os.getpid()} children={len(children)} "
              f"child_pids={','.join(str(pid) for pid in child_pids)}", flush=True)
        return 0
    failed = [pid for pid, code in zip(child_pids, codes) if code != 0]
    print(f"split.py done parent_pid={os.getpid()} children={len(children)} "
          f"failed={len(failed)}", flush=True)
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
