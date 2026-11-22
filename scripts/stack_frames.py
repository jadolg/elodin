#!/usr/bin/env python3
"""Fail a build whose stack frames could step over a fiber's guard.

usage: scripts/stack_frames.py BINARY

The compiler emits no stack probes, so a frame moves the stack pointer down in
one step and its first stores land wherever that is. A fiber stack has
`loop.STACK_GUARD` of PROT_NONE below it: a frame at least that large could step
past it into the mapping below, another fiber's stack, instead of faulting.
This reads every procedure's frame allocation from `objdump -d` (amd64
`sub $N,%rsp`; arm64 `sub sp, sp, #N[, lsl #12]`, summed) and fails on any at
the guard or past it, outside `MAIN_THREAD`, the procedures that run on the
process's own stack, which the kernel guards with a gap far larger than any
frame.
"""

import pathlib
import re
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent

# Procedures that run only on the main thread's stack, never on a fiber.
MAIN_THREAD = {"main::run"}

AMD64 = re.compile(r"\bsub[q]?\s+\$0x([0-9a-f]+),%rsp\b")
ARM64 = re.compile(r"\bsub\s+sp,\s*sp,\s*#0x([0-9a-f]+)(?:,\s*lsl\s+#12)?")
ARM64_LSL = re.compile(r"lsl\s+#12")
SYMBOL = re.compile(r"^[0-9a-f]+ <(.+)>:$")


def guard() -> int:
    src = (ROOT / "src/loop/fiber.odin").read_text()
    m = re.search(r"^STACK_GUARD :: (\d+) \* 1024$", src, re.M)
    if not m:
        sys.exit("stack_frames: STACK_GUARD not found in src/loop/fiber.odin")
    return int(m.group(1)) * 1024


def frames(binary: str) -> dict[str, int]:
    out = subprocess.run(
        ["objdump", "-d", "--no-show-raw-insn", binary],
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    sizes: dict[str, int] = {}
    current = None
    for line in out.splitlines():
        sym = SYMBOL.match(line)
        if sym:
            current = sym.group(1)
            continue
        if current is None:
            continue
        m = AMD64.search(line)
        if m:
            sizes[current] = max(sizes.get(current, 0), int(m.group(1), 16))
            continue
        m = ARM64.search(line)
        if m:
            n = int(m.group(1), 16) << (12 if ARM64_LSL.search(line) else 0)
            # A large arm64 frame is two subtractions, the shifted one first.
            sizes[current] = sizes.get(current, 0) + n
    return sizes


def main() -> int:
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    limit = guard()
    sizes = frames(sys.argv[1])
    if not sizes:
        sys.exit(f"stack_frames: no frames read from {sys.argv[1]}")
    over = sorted(
        ((n, name) for name, n in sizes.items() if n >= limit and name not in MAIN_THREAD),
        reverse=True,
    )
    for n, name in over:
        print(f"stack_frames: {name} has a {n}-byte frame, past the {limit}-byte fiber stack guard")
    if over:
        print("stack_frames: shrink the frame (move the large local to the scratch arena), or raise loop.STACK_GUARD")
        return 1
    largest = max((n, name) for name, n in sizes.items() if name not in MAIN_THREAD)
    print(f"stack_frames: largest frame {largest[0]} bytes ({largest[1]}), under the {limit}-byte guard")
    return 0


if __name__ == "__main__":
    sys.exit(main())
