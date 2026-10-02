#!/usr/bin/env python3
"""Generate a git-shaped object/tree write pattern for the benign corpus.

This is the generator behind benign-git-objects.sh; see that file for why the
corpus carries a git-shaped workload and which detection signals it stresses.

The shape is synthesized rather than produced by the real `git` binary so that
every write, rename and delete is counted at the point it happens: a real git
run hides most of its object churn behind a child process, and the recorded
profile would be a guess. Nothing here touches the network or reads outside the
work directory.

Usage: benign-git-objects.py <workdir> <commits> <files-per-commit>

Prints exactly one SUMMARY line.
"""
from __future__ import annotations

import hashlib
import os
import random
import shutil
import sys
import time
import zlib
from collections import Counter
from pathlib import Path


def blob_body(n: int, commit: int) -> bytes:
    """A compressible source-like body, deterministic in both arguments."""
    rng = random.Random(n * 2654435761 + commit * 40503)
    lines = [f"package pkg_{commit}", ""]
    for r in range(10):
        lines.append(
            "func F%d_%d(x int) int { return (x*%d + %d) %% %d }"
            % (n, r, r * 7 + 3, n * 13 + r * 29, commit + r + 17)
        )
    # A little entropy so the deflated object samples high, the way real source
    # with string literals does.
    lines.append("const banner = %r" % "".join(rng.choice("abcdefghijklmnop") for _ in range(48)))
    return ("\n".join(lines) + "\n").encode()


class Run:
    def __init__(self, work: Path) -> None:
        self.work = work
        self.files = 0
        self.bytes = 0
        self.renames = 0
        self.deletes = 0
        self.ext: Counter[str] = Counter()
        self.loose: list[Path] = []

    def note(self, path: Path, size: int) -> None:
        self.files += 1
        self.bytes += size
        self.ext[path.suffix[1:] or "none"] += 1

    def write(self, path: Path, data: bytes) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        self.note(path, len(data))

    def atomic_write(self, path: Path, data: bytes) -> None:
        """temp-then-rename, the way git rewrites index and refs."""
        tmp = path.with_name(path.name + ".tmp")
        tmp.write_bytes(data)
        os.replace(tmp, path)
        self.renames += 1
        self.note(path, len(data))

    def append(self, path: Path, data: bytes) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "ab") as fh:
            fh.write(data)
        self.note(path, len(data))

    def object(self, obj_type: str, body: bytes) -> str:
        content = b"%s %d\0" % (obj_type.encode(), len(body)) + body
        sha = hashlib.sha1(content).hexdigest()
        path = self.work / "repo" / ".git" / "objects" / sha[:2] / sha[2:]
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(zlib.compress(content, 9))
        self.note(path, path.stat().st_size)
        self.loose.append(path)
        return sha


def main(argv: list[str]) -> int:
    work = Path(argv[1])
    commits = int(argv[2])
    per_commit = int(argv[3])

    shutil.rmtree(work, ignore_errors=True)
    run = Run(work)
    repo = work / "repo"
    (repo / ".git" / "objects" / "pack").mkdir(parents=True)
    (repo / ".git" / "refs" / "heads").mkdir(parents=True)
    (repo / ".git" / "logs").mkdir(parents=True)

    start = time.monotonic()
    for c in range(1, commits + 1):
        pkg = repo / "src" / ("pkg_%d" % c)
        entries: list[tuple[str, str]] = []
        for n in range(1, per_commit + 1):
            name = "f%d.go" % n
            body = blob_body(n, c)
            run.write(pkg / name, body)
            entries.append((name, run.object("blob", body)))

        tree_body = b"".join(
            b"100644 %s\0%s" % (name.encode(), bytes.fromhex(sha)) for name, sha in entries
        )
        tree_sha = run.object("tree", tree_body)
        commit_body = (
            "tree %s\n"
            "author benign <benign@example.invalid> 1700000000 +0000\n"
            "committer benign <benign@example.invalid> 1700000000 +0000\n"
            "\n"
            "commit %d\n" % (tree_sha, c)
        ).encode()
        commit_sha = run.object("commit", commit_body)

        run.atomic_write(repo / ".git" / "index", ("\n".join(s for _, s in entries) + "\n").encode())
        run.atomic_write(repo / ".git" / "refs" / "heads" / "main", (commit_sha + "\n").encode())
        run.append(
            repo / ".git" / "logs" / "HEAD",
            ("0000000 %s benign <benign@example.invalid> 1700000000 +0000\tcommit: c%d\n" % (commit_sha, c)).encode(),
        )

    # A repack: one large pack written, then every loose object deleted in a
    # burst. This is the legitimate-mass-delete / bulk-write shape a detector
    # must not confuse with a ransomware pass.
    pack = b"".join(p.read_bytes() for p in run.loose)
    pack_name = "pack-%s" % hashlib.sha1(b"%d" % os.getpid() + pack[:64]).hexdigest()
    run.atomic_write(repo / ".git" / "objects" / "pack" / (pack_name + ".pack"), pack)
    run.write(repo / ".git" / "objects" / "pack" / (pack_name + ".idx"), ("\n".join(str(p) for p in run.loose) + "\n").encode())
    for p in run.loose:
        p.unlink()
        run.deletes += 1

    elapsed = int(time.monotonic() - start)
    mix = ",".join("%s:%d" % (k, v) for k, v in run.ext.most_common())
    print(
        "SUMMARY scenario=git_objects files_written=%d bytes_written=%d renames=%d "
        "deletes=%d elapsed_s=%d deflate=zlib commits=%d extensions=%s"
        % (run.files, run.bytes, run.renames, run.deletes, elapsed, commits, mix)
    )
    return 0


if __name__ == "__main__":
    if len(sys.argv) != 4:
        print("usage: benign-git-objects.py <workdir> <commits> <files-per-commit>", file=sys.stderr)
        sys.exit(2)
    sys.exit(main(sys.argv))
