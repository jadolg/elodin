package harness

import "base:runtime"
import "core:mem"

/*
Shared per-input scratch arena for libFuzzer targets.

Parsers under fuzzing allocate freely and none of the targets need what they
produce past the call, so a single arena dropped whole at the end of each
input is cheaper than tracking individual frees — and it means a target never
needs a matching `destroy` for whatever the parser under test allocated.
*/

ARENA_SIZE :: 4 * 1024 * 1024

Fuzz_Arena :: struct {
	arena:     mem.Arena,
	buf:       []u8,
	// The allocator `buf` itself was made with, so teardown can free it
	// regardless of what `context.allocator` has been swapped to by then.
	allocator: mem.Allocator,
}

setup :: proc(f: ^Fuzz_Arena) -> runtime.Context {
	context = runtime.default_context()
	f.allocator = context.allocator
	f.buf = make([]u8, ARENA_SIZE, f.allocator)
	mem.arena_init(&f.arena, f.buf)
	ctx := context
	ctx.allocator = mem.arena_allocator(&f.arena)
	return ctx
}

teardown :: proc(f: ^Fuzz_Arena) {
	delete(f.buf, f.allocator)
}
