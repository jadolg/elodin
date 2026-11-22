#!/usr/bin/env python3
"""usage: scripts/stack_frames.py BINARY - fail a build whose stack frames could step over a fiber's guard."""
# The compiler emits no stack probes, so a frame moves the stack pointer down in
# one step and its first stores land wherever that is. A fiber stack has
# `loop.STACK_GUARD` of PROT_NONE below it, and two frames can step over it
# together: a caller whose stack pointer ends inside the guard without writing
# there, and a callee whose own writes land below it - on arm64 a call writes
# nothing to the stack, and a leaf saves no frame record. So the two largest
# frames together must fit in the guard, outside `MAIN_THREAD`, the procedures
# that run on the process's own stack, which the kernel guards with a gap far
# larger than any frame.
#
# Frames are read from `objdump -d`: amd64 `sub $N,%rsp`, arm64 `sub sp, sp, #N`
# (a `lsl #12` one and the one after it are one frame) and the `sub xN, sp, #N`
# an over-aligned frame starts from, followed through the register it writes.
# Each procedure's largest such subtraction is its frame, which leaves out pushes,
# saved registers and call-argument space: `SLACK` is held back from the guard
# for them. A stack allocation of a size only known at run time - a register
# moved into the stack pointer, outside an epilogue's frame pointer and the fiber
# switch - is refused outright, since no guard bounds it. Only the binary's own
# code is read: a library linked at run time is not in it.

import pathlib
import re
import shutil
import subprocess  # nosec B404: a fixed argument list, no shell
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent

# Procedures that run only on the main thread's stack, never on a fiber. See
# the note on `run` in src/main/main.odin.
MAIN_THREAD = {"main::run"}

# Held back from the guard for what a frame's largest subtraction leaves out:
# pushes, the arm64 callee-save area (at most 512 bytes), alignment padding and
# call-argument space.
SLACK = 4096

# The fiber switch moves the stack pointer between stacks by design.
SWITCH = "elodin_fiber_switch"

IMM = r"#(?:0x([0-9a-f]+)|(\d+))"
AMD64 = re.compile(r"\bsub[q]?\s+\$0x([0-9a-f]+),%rsp\b")
# A register moved into the stack pointer, other than the frame pointer; and the
# subtraction of a register from it.
AMD64_VARIABLE = re.compile(r"\b(?:mov[q]?\s+%r(?!bp\b)[a-z0-9]+,%rsp|sub[q]?\s+%r[a-z0-9]+,%rsp)\b")
ARM64 = re.compile(r"\bsub\s+(sp|x\d+),\s*(sp|x\d+),\s*" + IMM + r"(,\s*lsl\s+#12)?")
ARM64_VARIABLE = re.compile(r"\b(?:mov\s+sp,\s*x(?!29\b)\d+|sub\s+sp,\s*sp,\s*x\d+)\b")
SYMBOL = re.compile(r"^[0-9a-f]+ <(.+)>:$")


def guard() -> int:
    src = (ROOT / "src/loop/fiber.odin").read_text()
    # The figure outside AddressSanitizer, which is what these builds are.
    m = re.search(r"^STACK_GUARD :: \d+ \* 1024 when ASAN else (\d+) \* 1024$", src, re.M)
    if not m:
        sys.exit("stack_frames: STACK_GUARD in src/loop/fiber.odin is not `N * 1024 when ASAN else M * 1024`")
    return int(m.group(1)) * 1024


def frames(binary: str) -> tuple[dict[str, int], list[str]]:
    if shutil.which("objdump") is None:
        sys.exit("stack_frames: objdump not found; install binutils")
    out = subprocess.run(  # nosec B603 B607: objdump on the binary the build just made
        ["objdump", "-d", "--no-show-raw-insn", binary],
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    return parse(out)


def parse(out: str) -> tuple[dict[str, int], list[str]]:
    """Each procedure's frame, and the procedures that allocate at run time, from `objdump -d` text."""
    sizes: dict[str, int] = {}
    variable: list[str] = []
    current = None
    # An arm64 frame being built across subtractions: its size so far, and the
    # register it is in.
    shifted, into = 0, None
    for line in out.splitlines():
        sym = SYMBOL.match(line)
        if sym:
            current, shifted, into = sym.group(1), 0, None
            continue
        if current is None:
            continue
        if (AMD64_VARIABLE.search(line) or ARM64_VARIABLE.search(line)) and current != SWITCH:
            variable.append(current)
            continue
        m = AMD64.search(line)
        if m:
            sizes[current] = max(sizes.get(current, 0), int(m.group(1), 16))
            continue
        step = arm64_step(line, shifted, into)
        if step:
            shifted, into = step
            sizes[current] = max(sizes.get(current, 0), shifted)
            continue
        shifted, into = 0, None
    return sizes, variable


def arm64_step(line: str, shifted: int, into):
    """The frame so far and the register it is in, after an arm64 subtraction that builds one; None for any other line."""
    m = ARM64.search(line)
    if not m:
        return None
    dst, src = m.group(1), m.group(2)
    # A subtraction from the stack pointer starts a frame; one from the
    # register the last wrote carries it on.
    if src != "sp" and src != into:
        return None
    n = int(m.group(3), 16) if m.group(3) is not None else int(m.group(4))
    base = shifted if src == into else 0
    return base + (n << 12 if m.group(5) else n), dst


def main() -> int:
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    limit = guard()
    sizes, variable = frames(sys.argv[1])
    if not sizes:
        sys.exit(f"stack_frames: no frames read from {sys.argv[1]}")
    unbounded = sorted(set(variable) - MAIN_THREAD)
    for name in unbounded:
        print(f"stack_frames: {name} makes a stack allocation of a size known only at run time, which no guard bounds")
    fits = pair_fits(sizes, limit)
    return 0 if fits and not unbounded else 1


def pair_fits(sizes: dict[str, int], limit: int) -> bool:
    """Whether the two largest fiber frames, with `SLACK`, stay under `limit`; says which either way."""
    fiber = sorted(((n, name) for name, n in sizes.items() if name not in MAIN_THREAD), reverse=True)
    top = fiber[:2]
    pair = sum(n for n, _ in top)
    if pair + SLACK >= limit:
        names = " and ".join(f"{name} ({n} bytes)" for n, name in top)
        print(f"stack_frames: {names} come to {pair} bytes together, "
              f"with {SLACK} held back past the {limit}-byte fiber stack guard")
        print("stack_frames: shrink the frame (move the large local to the scratch arena), or raise loop.STACK_GUARD")
        return False
    print(f"stack_frames: the two largest frames come to {pair} bytes ({', '.join(name for _, name in top)}), "
          f"with {SLACK} held back under the {limit}-byte guard")
    return True


if __name__ == "__main__":
    sys.exit(main())
