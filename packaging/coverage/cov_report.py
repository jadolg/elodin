#!/usr/bin/env python3
"""Turn the raw files cov_rt.c leaves in $ELODIN_COV_DIR into lcov.

Inputs (per server process, PID in the name):
  cov.<pid>.pcs    uint64 count, then that many instrumented PCs (identical
                   across processes, since they share one binary).
  cov.<pid>.hits   one byte per point, non-zero where that point ran.

The point at index i in .hits is the PC at index i in .pcs. Every .hits file is
OR-merged, each PC is symbolized with addr2line, the points under src/ are kept,
and lcov is emitted: a line is DA:<line>,1 if any point on it ran, else 0.
"""
import glob
import os
import struct
import subprocess  # nosec B404 - fixed argv (addr2line), no shell, no external input
import sys


def read_pcs(path):
    """Read the PC table written by cov_rt.c: a count then that many uint64 PCs."""
    with open(path, "rb") as f:
        (count,) = struct.unpack("<Q", f.read(8))
        return list(struct.unpack(f"<{count}Q", f.read(8 * count)))


def merge_hits(paths, count):
    """OR-merge every per-process hit bitmap into one list of `count` flags."""
    merged = bytearray(count)
    for path in paths:
        with open(path, "rb") as f:
            data = f.read()
        for i in range(min(count, len(data))):
            if data[i]:
                merged[i] = 1
    return merged


def symbolize(binary, pcs, addr2line):
    """Run addr2line once over all PCs, returning its line-oriented output."""
    addrs = "\n".join(f"0x{pc:x}" for pc in pcs)
    proc = subprocess.run(  # nosec B603 - fixed argv, no shell, tool path from env only
        [addr2line, "-e", binary, "-a", "-f", "-i"],
        input=addrs, capture_output=True, text=True, check=False,
    )
    if proc.returncode != 0:
        sys.exit(f"coverage: addr2line failed: {proc.stderr}")
    return proc.stdout.splitlines()


def collect(lines, merged, repo, src_prefix):
    """Fold addr2line output into {relative_path: {lineno: covered}} for src/.

    addr2line emits, per address, a line "0x..", then function/file:line pairs
    (several when a PC is inlined). A point is attributed to every src/ frame it
    names, covered if that point's merged hit bit is set.
    """
    cov = {}

    def add(path, lineno, covered):
        real = os.path.realpath(path)
        if not real.startswith(src_prefix):
            return
        rel = real[len(repo):]
        per_line = cov.setdefault(rel, {})
        per_line[lineno] = per_line.get(lineno, False) or covered

    idx = -1
    i = 0
    while i < len(lines):
        if lines[i].startswith("0x"):
            idx += 1
            i += 1
            continue
        # A function name line, then its file:line line.
        if i + 1 < len(lines):
            path, _, lno = lines[i + 1].rpartition(":")
            lno = lno.split(" ")[0]
            if lno.isdigit() and path not in ("??", ""):
                add(path, int(lno), bool(merged[idx]) if 0 <= idx < len(merged) else False)
            i += 2
            continue
        i += 1
    return cov


def write_lcov(cov, out):
    """Write the coverage map as lcov and return (hit_lines, total_lines)."""
    total = hits = 0
    with open(out, "w", encoding="utf-8") as w:
        for rel in sorted(cov):
            per_line = cov[rel]
            w.write(f"SF:{rel}\n")
            for lno in sorted(per_line):
                covered = 1 if per_line[lno] else 0
                w.write(f"DA:{lno},{covered}\n")
                total += 1
                hits += covered
            w.write(f"LF:{len(per_line)}\n")
            w.write(f"LH:{sum(1 for v in per_line.values() if v)}\n")
            w.write("end_of_record\n")
    return hits, total


def main():
    """Merge the raw coverage files named on argv into an lcov report."""
    cov_dir, binary, out = sys.argv[1], sys.argv[2], sys.argv[3]
    addr2line = os.environ.get("ADDR2LINE", "addr2line")
    here = os.path.abspath(__file__)
    repo = os.path.realpath(os.path.dirname(os.path.dirname(os.path.dirname(here)))) + "/"
    src_prefix = repo + "src/"

    pcs_files = sorted(glob.glob(os.path.join(cov_dir, "cov.*.pcs")))
    hits_files = sorted(glob.glob(os.path.join(cov_dir, "cov.*.hits")))
    if not pcs_files or not hits_files:
        sys.exit(f"coverage: no cov.*.pcs / cov.*.hits files in {cov_dir}")

    pcs = read_pcs(pcs_files[0])
    merged = merge_hits(hits_files, len(pcs))
    cov = collect(symbolize(binary, pcs, addr2line), merged, repo, src_prefix)
    hits, total = write_lcov(cov, out)

    pct = (100.0 * hits / total) if total else 0.0
    print(f"coverage: {hits}/{total} lines, {pct:.1f}% across {len(cov)} files -> {out}")


if __name__ == "__main__":
    main()
