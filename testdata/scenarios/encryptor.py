#!/usr/bin/env python3
"""Controlled encryptor for testing GRIMA.

This is a test fixture, not malware. It uses no key material, cannot decrypt
anything, refuses to touch anything outside --path, and does not delete files.

It exists so the detector can be exercised against known encryption-like I/O at
a chosen rate, which is what the burst / drip / intermittent cases in SKILLS.md
section 4 require.

Usage:
  encryptor.py --path DIR --rate burst [--seed N] [--suffix .locked]
  encryptor.py --path DIR --rate drip
  encryptor.py --path DIR --rate intermittent
"""

from __future__ import annotations

import argparse
import os
import random
import sys
import time

RATE_DELAYS = {
    "burst": 0.0,
    "drip": 5.0,
    "intermittent": 0.02,
}

TARGET_EXTENSIONS = {".txt", ".md", ".csv", ".docx", ".pdf", ".jpg", ".log", ".json"}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Controlled encryptor for GRIMA testing.")
    parser.add_argument("--path", required=True, help="directory to operate inside")
    parser.add_argument("--rate", choices=sorted(RATE_DELAYS), default="burst")
    parser.add_argument("--seed", type=int, default=0, help="0 means use the clock")
    parser.add_argument("--suffix", default=".locked", help="extension to rename to (empty to skip)")
    parser.add_argument("--max-files", type=int, default=0, help="0 means no limit")
    parser.add_argument("--partial-bytes", type=int, default=4096,
                        help="bytes to overwrite per file in intermittent mode")
    return parser.parse_args()


def collect(target: str, max_files: int) -> list[str]:
    found = []
    for root, _dirs, files in os.walk(target):
        for name in files:
            if os.path.splitext(name)[1].lower() not in TARGET_EXTENSIONS:
                continue
            found.append(os.path.join(root, name))
            if max_files and len(found) >= max_files:
                return found
    return found


def overwrite(path: str, partial_bytes: int, rng: random.Random) -> int:
    """Overwrite a file with high-entropy bytes, and report how many it wrote."""
    size = os.path.getsize(path)
    if partial_bytes and size > partial_bytes:
        payload = rng.randbytes(partial_bytes)  # intermittent: leave the rest in place
    else:
        payload = rng.randbytes(size or 1)

    with open(path, "r+b") as handle:
        handle.write(payload)
        handle.flush()
        os.fsync(handle.fileno())
    return len(payload)


def rename_to_suffix(path: str, suffix: str) -> str:
    if not suffix:
        return path
    target = path + suffix
    os.replace(path, target)
    return target


def main() -> int:
    args = parse_args()

    target = os.path.abspath(args.path)
    if not os.path.isdir(target):
        print(f"error: {target} is not a directory", file=sys.stderr)
        return 2

    rng = random.Random(args.seed or None)
    files = collect(target, args.max_files)
    if not files:
        print(f"error: no target files found under {target}", file=sys.stderr)
        return 2

    delay = RATE_DELAYS[args.rate]
    print(f"{len(files)} files, rate={args.rate}, suffix={args.suffix or '(none)'}")

    # One progress line per file, with a running byte count, so a harness can
    # report time-to-detect in bytes encrypted rather than in seconds: the line
    # that precedes the detector's alert is the amount of work done before it.
    # Parsed by testdata/scenarios/ablate.py; harmless to everything else, which
    # only reads the summary lines.
    done_files = 0
    done_bytes = 0
    for path in files:
        try:
            written = overwrite(path, args.partial_bytes if args.rate == "intermittent" else 0, rng)
            rename_to_suffix(path, args.suffix)
        except OSError as exc:
            print(f"skip {path}: {exc}", file=sys.stderr)
            continue
        done_files += 1
        done_bytes += written
        print(f"progress files={done_files} bytes={done_bytes}", flush=True)
        if delay:
            time.sleep(delay)

    print("done")
    return 0


if __name__ == "__main__":
    sys.exit(main())
