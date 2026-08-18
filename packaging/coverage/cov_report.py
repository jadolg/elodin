#!/usr/bin/env python3
"""
Turn the raw coverage files that cov_rt.c leaves in $ELODIN_COV_DIR into an
lcov report for the elodin sources.

Inputs (per server process, PID in the name):
  cov.<pid>.pcs    uint64 count, then that many instrumented PCs (identical
                   across processes, since they share one binary).
  cov.<pid>.hits   one byte per point, non-zero where that point ran.

The point at index i in .hits corresponds to the PC at index i in .pcs. We
OR-merge every .hits file, symbolize each PC with addr2line, keep the ones under
src/, and emit lcov: a line is DA:<line>,1 if any point on it ran, else
DA:<line>,0.
"""
import glob, os, struct, subprocess, sys

def main():
    cov_dir = sys.argv[1]
    binary = sys.argv[2]
    out = sys.argv[3]
    addr2line = os.environ.get("ADDR2LINE", "addr2line")
    repo = os.path.realpath(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))) + "/"
    src_prefix = repo + "src/"

    pcs_files = sorted(glob.glob(os.path.join(cov_dir, "cov.*.pcs")))
    hits_files = sorted(glob.glob(os.path.join(cov_dir, "cov.*.hits")))
    if not pcs_files or not hits_files:
        sys.exit("coverage: no cov.*.pcs / cov.*.hits files in %s" % cov_dir)

    with open(pcs_files[0], "rb") as f:
        (n,) = struct.unpack("<Q", f.read(8))
        pcs = list(struct.unpack("<%dQ" % n, f.read(8 * n)))

    merged = bytearray(n)
    for hf in hits_files:
        with open(hf, "rb") as f:
            data = f.read()
        for i in range(min(n, len(data))):
            if data[i]:
                merged[i] = 1

    # Symbolize every PC once. addr2line reads a list of addresses on stdin.
    addrs = "\n".join("0x%x" % pc for pc in pcs)
    proc = subprocess.run([addr2line, "-e", binary, "-a", "-f", "-i"],
                          input=addrs, capture_output=True, text=True)
    if proc.returncode != 0:
        sys.exit("coverage: addr2line failed: %s" % proc.stderr)

    # Output groups per address: a line "0x..", then function/file:line pairs
    # (several when a PC is inlined). We attribute the point to its innermost
    # frame that falls under src/.
    idx = -1
    lines = proc.stdout.splitlines()
    # file -> {lineno -> covered(bool)}
    cov = {}
    i = 0
    cur_locs = []
    def flush(point_idx, locs):
        hit = merged[point_idx] if 0 <= point_idx < n else 0
        for path, ln in locs:
            rp = os.path.realpath(path)
            if not rp.startswith(src_prefix):
                continue
            rel = rp[len(repo):]
            d = cov.setdefault(rel, {})
            d[ln] = d.get(ln, False) or bool(hit)
    while i < len(lines):
        ln = lines[i]
        if ln.startswith("0x"):
            if idx >= 0:
                flush(idx, cur_locs)
            idx += 1
            cur_locs = []
            i += 1
            continue
        # function name line, then file:line line
        if i + 1 < len(lines):
            floc = lines[i + 1]
            if ":" in floc:
                path, _, lno = floc.rpartition(":")
                lno = lno.split(" ")[0]
                if lno.isdigit() and path not in ("??", ""):
                    cur_locs.append((path, int(lno)))
            i += 2
            continue
        i += 1
    if idx >= 0:
        flush(idx, cur_locs)

    total = hitc = 0
    with open(out, "w") as w:
        for rel in sorted(cov):
            w.write("SF:%s\n" % rel)
            d = cov[rel]
            for lno in sorted(d):
                c = 1 if d[lno] else 0
                w.write("DA:%d,%d\n" % (lno, c))
                total += 1
                hitc += c
            w.write("LF:%d\n" % len(d))
            w.write("LH:%d\n" % sum(1 for v in d.values() if v))
            w.write("end_of_record\n")
    pct = (100.0 * hitc / total) if total else 0.0
    print("coverage: %d/%d lines, %.1f%% across %d files -> %s" %
          (hitc, total, pct, len(cov), out))

if __name__ == "__main__":
    main()
