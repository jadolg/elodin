#!/usr/bin/env python3
"""scripts/stack_frames.py reads each frame shape it names. Run by `mise run check`."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import stack_frames  # noqa: E402

# (disassembly, frame sizes wanted, procedures that allocate at run time)
CASES = [
    # amd64: one frame, and a later call-frame adjustment that is smaller.
    ("0000 <a::f>:\n  sub    $0x648,%rsp\n  sub    $0x40,%rsp\n", {"a::f": 0x648}, []),
    # amd64: alloca as LLVM emits it, through a register.
    ("0000 <a::g>:\n  mov    %rsp,%rax\n  sub    %rdi,%rax\n  mov    %rax,%rsp\n", {}, ["a::g"]),
    # amd64: an epilogue restoring from the frame pointer is no allocation.
    ("0000 <a::h>:\n  sub    $0x20,%rsp\n  mov    %rbp,%rsp\n", {"a::h": 0x20}, []),
    # arm64: a large frame in two steps.
    ("0000 <a::i>:\n  sub\tsp, sp, #0x8, lsl #12\n  sub\tsp, sp, #0x590\n", {"a::i": 0x8590}, []),
    # arm64: an over-aligned frame through a scratch register, decimal too.
    ("0000 <a::j>:\n  sub\tx9, sp, #0x7, lsl #12\n  sub\tx9, x9, #4095\n  and\tsp, x9, #0xffffffffffffffc0\n", {"a::j": 0x7FFF}, []),
    # arm64: alloca, and an epilogue from x29.
    ("0000 <a::k>:\n  mov\tx8, sp\n  sub\tx8, x8, x9\n  mov\tsp, x8\n  mov\tsp, x29\n", {}, ["a::k"]),
    # The fiber switch moves the stack pointer by design.
    ("0000 <elodin_fiber_switch>:\n  mov\tsp, x1\n", {}, []),
]

failures = []
for text, want_sizes, want_variable in CASES:
    sizes, variable = stack_frames.parse(text)
    if sizes != want_sizes or sorted(set(variable)) != sorted(want_variable):
        failures.append(f"{text!r}: got {sizes} {variable}, want {want_sizes} {want_variable}")
for f in failures:
    print(f, file=sys.stderr)
sys.exit(1 if failures else 0)
