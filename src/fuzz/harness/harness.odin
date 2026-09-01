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

/*
Drop everything this input allocated: the arena above, and the temp arena with it.

`setup` swaps `context.allocator` but leaves `context.temp_allocator` as the
thread's default one, and code under test reaches for it on its own - the EDNS
writers take their scratch from there whenever an option cannot be spliced in
place and the message has to go back through the decoder. Nothing in a fuzz
target ever returns to a caller that would reset it, and Odin's default temp
allocator chains a fresh heap block rather than reusing the last one once its
backing is full, so a target that touched it grew by a few hundred bytes per
input for as long as the run lasted. Left out, `fuzz_dns` climbed from 70 MB to
libFuzzer's 2 GB ceiling in around 600k inputs and reported an out-of-memory
whose reproducer replays clean - which is the one finding a fuzz target must not
invent, because it stops the run that would have found a real one.
*/
teardown :: proc(f: ^Fuzz_Arena) {
	free_all(context.temp_allocator)
	delete(f.buf, f.allocator)
}
