#+build linux
package loop

import "base:runtime"
import "core:sys/linux"
import "core:sys/posix"
import "core:testing"
import "core:thread"

@(private = "file")
Scratch_Probe :: struct {
	// What the thread found its arena backed by, before it allocated.
	backed:   bool,
	// The arena's first block, and a second one a request past it took.
	blocks:   [2][]u8,
	resident: [2]int,
	mincore:  [2]linux.Errno,
	// Blocks taken from and given back to `mapped_allocator`, counted by
	// `counting_proc`; the thread's exit is what gives them back.
	allocs:   int,
	frees:    int,
}

/*
See `run_with_mapped_scratch`: a thread's scratch blocks are mappings of their
own, resident as far as they are used, and given back once the thread exits -
for a thread started with a context (a rebuild) as much as without one (a
connection). Residency is read with mincore(2) while the block is live; the
release is counted rather than read off the address afterwards, which another
test's thread may have mapped again by then.
*/
@(test)
test_a_spawned_threads_scratch_is_unmapped_when_it_exits :: proc(t: ^testing.T) {
	// As the server does: with transparent huge pages on, the kernel merges
	// neighbouring blocks of parallel tests' threads into one mapping and may
	// back a 2 MB span of it, this block's included.
	disable_huge_pages()
	for with_context in ([]bool{false, true}) {
		probe: Scratch_Probe
		th := spawn_thread(&probe, use_scratch, context) if with_context else spawn_thread(&probe, use_scratch)
		if !testing.expect(t, th != nil, "no thread") {
			return
		}
		thread.join(th)
		thread.destroy(th)
		if !testing.expectf(t, probe.backed, "the arena was not backed by mapped_allocator (context %v)", with_context) {
			continue
		}
		for b, i in probe.blocks {
			if !testing.expectf(t, len(b) > 0, "block %d was not seen (context %v)", i, with_context) {
				return
			}
			if !testing.expectf(t, probe.mincore[i] == .NONE, "block %d: mincore: %v (context %v)", i, probe.mincore[i], with_context) {
				return
			}
			// A calloc'd block is resident throughout; this one, where touched.
			testing.expectf(t, probe.resident[i] <= 2, "block %d: %d pages resident of %d (context %v)", i, probe.resident[i], len(b) / int(page_size()), with_context)
		}
		testing.expectf(t, probe.allocs == 2 && probe.frees == 2, "%d blocks mapped, %d given back (context %v)", probe.allocs, probe.frees, with_context)
	}
}

@(private = "file")
use_scratch :: proc(p: ^Scratch_Probe) {
	arena := &runtime.global_default_temp_allocator_data.arena
	p.backed = arena.curr_block == nil && arena.backing_allocator.procedure == mapped_allocator_proc
	if !p.backed {
		return
	}
	arena.backing_allocator = runtime.Allocator{counting_proc, p}
	_ = make([]u8, 64, context.temp_allocator)
	first := arena.curr_block
	// Past the first block, so the arena takes a second.
	_ = make([]u8, runtime.DEFAULT_TEMP_ALLOCATOR_BACKING_SIZE + 1, context.temp_allocator)
	for b, i in ([]^runtime.Memory_Block{first, arena.curr_block}) {
		if b == nil || (i == 1 && b == first) {
			return
		}
		p.blocks[i] = b.base[:b.capacity]
		p.resident[i], p.mincore[i] = residency(p.blocks[i])
	}
}

// `mapped_allocator`, counting into the probe what it maps and gives back.
@(private = "file")
counting_proc :: proc(
	data: rawptr,
	mode: runtime.Allocator_Mode,
	size, alignment: int,
	old_memory: rawptr,
	old_size: int,
	loc := #caller_location,
) -> (
	[]byte,
	runtime.Allocator_Error,
) {
	p := (^Scratch_Probe)(data)
	b, err := mapped_allocator_proc(nil, mode, size, alignment, old_memory, old_size, loc)
	#partial switch mode {
	case .Alloc, .Alloc_Non_Zeroed:
		p.allocs += 1 if err == nil else 0
	case .Free:
		p.frees += 1
	}
	return b, err
}

// The kernel's page, which mincore(2) wants its start aligned to: 16 KiB or
// 64 KiB on some arm64 kernels.
@(private = "file")
page_size :: proc() -> uintptr {
	return uintptr(posix.sysconf(._PAGESIZE))
}

// Pages of `b` resident, by mincore(2) over the pages it spans.
@(private = "file")
residency :: proc(b: []u8) -> (pages: int, err: linux.Errno) {
	page := page_size()
	start := uintptr(raw_data(b)) &~ (page - 1)
	end := (uintptr(raw_data(b)) + uintptr(len(b)) + page - 1) &~ (page - 1)
	vec := make([]b8, (end - start) / page)
	defer delete(vec)
	err = linux.mincore(rawptr(start), uint(end - start), vec)
	for r in vec {
		pages += int(transmute(u8)r & 1)
	}
	return
}
