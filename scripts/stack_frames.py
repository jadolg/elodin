#!/usr/bin/env python3
"""Fail a build whose stack frames could step over a fiber's guard.

usage: scripts/stack_frames.py BINARY

The compiler emits no stack probes, so a frame moves the stack pointer down in
one step and its first stores land wherever that is. A fiber stack has
`loop.STACK_GUARD` of PROT_NONE below it, and two frames can step over it
together: a caller whose stack pointer ends inside the guard without writing
there, and a callee whose own writes land below it - on arm64 a call writes
nothing to the stack, and a leaf saves no frame record. So the two largest
frames together must fit in the guard, outside `MAIN_THREAD`, the procedures
that run on the process's own stack, which the kernel guards with a gap far
larger than any frame.

Frames are read from `objdump -d`: amd64 `sub $N,%rsp`, arm64 `sub sp, sp, #N`
(a `lsl #12` one and the one after it are one frame) and the `sub xN, sp, #N`
an over-aligned frame starts from. A stack allocation of a size only known at
run time is refused outright, since no guard bounds it. Only the binary's own
code is read: a library linked at run time is not in it.
"""

import pathlib
import re
import shutil
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent

# Procedures that run only on the main thread's stack, never on a fiber. See
# the note on `run` in src/main/main.odin.
MAIN_THREAD = {"main::run"}

IMM = r"#(?:0x([0-9a-f]+)|(\d+))"
AMD64 = re.compile(r"\bsub[q]?\s+\$0x([0-9a-f]+),%rsp\b")
AMD64_VARIABLE = re.compile(r"\bsub[q]?\s+%r[a-z0-9]+,%rsp\b")
ARM64 = re.compile(r"\bsub\s+(?:sp|x\d+),\s*sp,\s*" + IMM + r"(,\s*lsl\s+#12)?")
ARM64_VARIABLE = re.compile(r"\bsub\s+sp,\s*sp,\s*x\d+")
SYMBOL = re.compile(r"^[0-9a-f]+ <(.+)>:$")


def guard() -> int:
    src = (ROOT / "src/loop/fiber.odin").read_text()
    # The figure outside AddressSanitizer, which is what these builds are.
    m = re.search(r"^STACK_GUARD :: .*?(\d+) \* 1024$", src, re.M)
    if not m:
        sys.exit("stack_frames: STACK_GUARD not found in src/loop/fiber.odin")
    return int(m.group(1)) * 1024


def immediate(m: re.Match) -> int:
    return int(m.group(1), 16) if m.group(1) is not None else int(m.group(2))


def frames(binary: str) -> tuple[dict[str, int], list[str]]:
    if shutil.which("objdump") is None:
        sys.exit("stack_frames: objdump not found; install binutils")
    out = subprocess.run(
        ["objdump", "-d", "--no-show-raw-insn", binary],
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    sizes: dict[str, int] = {}
    variable: list[str] = []
    current = None
    shifted = 0  # an arm64 `lsl #12` subtraction waiting for the one after it
    for line in out.splitlines():
        sym = SYMBOL.match(line)
        if sym:
            current, shifted = sym.group(1), 0
            continue
        if current is None:
            continue
        if AMD64_VARIABLE.search(line) or ARM64_VARIABLE.search(line):
            variable.append(current)
            continue
        m = AMD64.search(line)
        if m:
            sizes[current] = max(sizes.get(current, 0), int(m.group(1), 16))
            continue
        m = ARM64.search(line)
        if m:
            n = immediate(m)
            if m.group(3):
                shifted = n << 12
                n = shifted
            else:
                n += shifted
                shifted = 0
            sizes[current] = max(sizes.get(current, 0), n)
            continue
        shifted = 0
    return sizes, variable


def main() -> int:
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    limit = guard()
    sizes, variable = frames(sys.argv[1])
    if not sizes:
        sys.exit(f"stack_frames: no frames read from {sys.argv[1]}")
    failed = False
    for name in sorted(set(variable) - MAIN_THREAD):
        print(f"stack_frames: {name} makes a stack allocation of a size known only at run time, which no guard bounds")
        failed = True
    fiber = sorted(((n, name) for name, n in sizes.items() if name not in MAIN_THREAD), reverse=True)
    top = fiber[:2]
    pair = sum(n for n, _ in top)
    if pair >= limit:
        names = " and ".join(f"{name} ({n} bytes)" for n, name in top)
        print(f"stack_frames: {names} come to {pair} bytes together, past the {limit}-byte fiber stack guard")
        print("stack_frames: shrink the frame (move the large local to the scratch arena), or raise loop.STACK_GUARD")
        failed = True
    if failed:
        return 1
    print(f"stack_frames: the two largest frames come to {pair} bytes ({', '.join(name for _, name in top)}), under the {limit}-byte guard")
    return 0


if __name__ == "__main__":
    sys.exit(main())
