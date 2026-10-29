package loop

import "base:runtime"
import "core:sys/posix"
import "core:thread"

/*
Start a thread - a loop's, or one of the few that are not - that never takes the signals `main` acts on: SIGTERM, SIGINT and
SIGHUP (#416), and whose scratch arena is mapped pages it gives back when it
exits (#526).

A handler only sets a flag, but the kernel hands a process-directed signal to
any thread that has it unblocked - the main thread first, another when the main
thread already has it pending. A thread that takes one in a timed socket read
has the read fail with EINTR, which signal(7) says is never restarted however
the handler was installed: a list download fails, or an upstream read and the
query behind it. Every thread is started here, so the main thread is the only
one that takes them.
*/
spawn_thread :: proc(
	data: $T,
	fn: proc(data: T),
	init_context: Maybe(runtime.Context) = nil,
	self_cleanup := false,
) -> ^thread.Thread {
	set, old: posix.sigset_t
	posix.sigemptyset(&set)
	for sig in ([]posix.Signal{.SIGTERM, .SIGINT, .SIGHUP}) {
		posix.sigaddset(&set, sig)
	}
	// The thread inherits the mask. One of these arriving meanwhile is held,
	// and delivered on the restore.
	posix.pthread_sigmask(.BLOCK, &set, &old)
	defer posix.pthread_sigmask(.SETMASK, &old, nil)
	return thread.create_and_start_with_poly_data2(
		data,
		fn,
		run_with_mapped_scratch,
		init_context,
		self_cleanup = self_cleanup,
	)
}

/*
Run `fn` with the thread's scratch arena backed by `mapped_allocator`, and unmap
the arena when `fn` returns.

Left to itself the arena takes its blocks from libc `calloc`. A new thread's
first large request is served from a glibc arena heap rather than `mmap`,
whatever `MALLOC_MMAP_THRESHOLD_` says, so `calloc` memsets all 256 KiB of it,
and the block freed at exit stays in that heap: ~275 KB resident for good for
every TCP, DoT and DoH/1.1 connection that answers a query. Anonymous pages are
zeroed by the kernel and resident only once touched, so a thread holds what its
queries used, and nothing once it exits.

Destroyed here rather than by `core:thread`, which does it only for a thread
started without a context.
*/
@(private)
run_with_mapped_scratch :: proc(data: $T, fn: proc(data: T)) {
	scratch := &runtime.global_default_temp_allocator_data
	if context.temp_allocator.data != scratch {
		fn(data)
		return
	}
	runtime.default_temp_allocator_destroy(scratch)
	scratch.arena.backing_allocator = mapped_allocator
	defer runtime.default_temp_allocator_destroy(scratch)
	fn(data)
}

/*
Whole pages, each allocation a mapping of its own. For a scratch arena's blocks
only, which come and go a few times a thread: a `munmap` per free costs nothing
there and would anywhere busier.

`runtime.Arena` frees a block without its size, so the mapping's base and
length sit just below the pointer handed out. That pointer is at least the
alignment asked for into a page-aligned mapping, so it is aligned for anything
up to a page.

The kernel merges neighbouring blocks into one mapping - 29 of them, 7.5 MB,
with 200 connections held - so where transparent huge pages are on, a touch in
a 2 MB span would fault in all of it; `disable_huge_pages` turns them off for
the process.
*/
@(private)
mapped_allocator := runtime.Allocator{mapped_allocator_proc, nil}

@(private)
Mapping :: struct {
	base:   rawptr,
	length: uint,
}

@(private)
MAPPING_ALIGN_MAX :: 4096

@(private)
mapped_allocator_proc :: proc(
	allocator_data: rawptr,
	mode: runtime.Allocator_Mode,
	size, alignment: int,
	old_memory: rawptr,
	old_size: int,
	loc := #caller_location,
) -> (
	[]byte,
	runtime.Allocator_Error,
) {
	#partial switch mode {
	case .Alloc, .Alloc_Non_Zeroed:
		if size < 0 || alignment > MAPPING_ALIGN_MAX {
			return nil, .Invalid_Argument
		}
		offset := uint(max(alignment, size_of(Mapping)))
		length := offset + uint(size)
		// Readable and writable from the start: one call, nothing to undo when it
		// fails.
		base := posix.mmap(nil, length, {.READ, .WRITE}, {.PRIVATE, .ANONYMOUS})
		if base == posix.MAP_FAILED || base == nil {
			return nil, .Out_Of_Memory
		}
		ptr := ([^]u8)(base)[offset:]
		(^Mapping)(ptr[-size_of(Mapping):])^ = {base, length}
		return ptr[:size], nil
	case .Free:
		if old_memory != nil {
			m := (^Mapping)(([^]u8)(old_memory)[-size_of(Mapping):])^
			posix.munmap(m.base, m.length)
		}
		return nil, nil
	case .Query_Features:
		if set := (^runtime.Allocator_Mode_Set)(old_memory); set != nil {
			set^ = {.Alloc, .Alloc_Non_Zeroed, .Free, .Query_Features}
		}
		return nil, nil
	}
	return nil, .Mode_Not_Implemented
}
