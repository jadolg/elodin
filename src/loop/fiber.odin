package loop

import "base:runtime"
import "core:mem"
import "core:sys/linux"

/*
A fiber: a stack of its own, run by one loop thread at a time and never by two.

Everything this server does while it waits on the network runs on one of these:
a query, a connection, a UDP reader, an accept loop, a racer. A wait parks the
fiber - its registers saved on its own stack - and the loop runs another; the
loop thread itself never sleeps anywhere but `epoll_wait`. That is what lets a
handful of threads carry tens of thousands of queries in flight and connections
held, where a thread per wait capped both at the thread count (#547).

A fiber stays on the loop it was spawned on for its whole life. Code that runs on
one can therefore keep using everything that is per thread - OpenSSL's error
queue, errno, `core:net`'s last error - between two calls that do not park, and
the few thread-locals that must survive a park are swapped with the fiber (see
`register_local`).

**Lifetime.** The `Fiber` struct is never freed while its loop exists: a finished
fiber goes on the loop's free list and is handed out again, with `incarnation`
moved on. A timer, an epoll registration or a wake posted from another thread
names a fiber by pointer and token, and a pointer that outlives the work it was
taken for therefore points at a struct that is still there, whose token no longer
matches - the wake is dropped, never delivered to freed memory. See `Handle` and
`wake`.
*/
Fiber :: struct {
	loop:         ^Loop,
	// The stack pointer this fiber switched out with; meaningless while it runs.
	sp:           rawptr,
	stack:        Stack,
	fn:           proc(data: rawptr),
	data:         rawptr,
	// Socket calls completed in a row without giving the loop up; see `take_turn`.
	turns:        int,
	state:        Fiber_State,
	/*
	Moved on every time a park ends, so a wake meant for one park cannot end a
	later one. Everything that may wake a parked fiber - a timer, an fd, a cond, a
	post from another thread - records the token it saw when it signed up and
	presents it back; see `wake_local`.
	*/
	token:        u64,
	// Moved on each time the struct is handed out again; see `Handle`.
	incarnation:  u64,
	wake_reason:  Wake_Reason,
	// Whether `cancel` has reached this fiber. Read and written on its loop only.
	cancelled:    bool,
	// Whether `cancel` may end the park in progress; see `park`.
	cancellable:  bool,
	deadline:     Tick,
	// Where this fiber sits in its loop's timer heap, or -1.
	heap_index:   int,
	// The fiber's scratch, which is its `context.temp_allocator`; see `fiber_entry`.
	scratch:      Scratch,
	// The thread-locals registered with `register_local`, while the fiber is parked.
	locals:       [LOCALS_MAX]u8,
	// Live fibers of the loop, for `cancel_all`; the free list reuses `next`.
	next, prev:   ^Fiber,
	asan_fake:    rawptr,
}

Fiber_State :: enum u8 {
	Free,
	// Spawned and waiting for its first turn.
	New,
	Ready,
	Running,
	Parked,
	// Gave up its turn in `yield`, and is already on the ready list.
	Yielded,
	// `fn` returned; the scheduler puts it back on the free list.
	Done,
}

Wake_Reason :: enum u8 {
	None,
	// What it was waiting for happened, or may have: every wait re-checks.
	Ready,
	Timeout,
	Cancelled,
}

/*
A fiber as somebody else holds it: the struct and which use of it is meant.

The struct is recycled, so a pointer alone could cancel whatever fiber the free
list handed it to next. `incarnation` is compared on the fiber's own loop before
anything is done to it.
*/
Handle :: struct {
	fiber:       ^Fiber,
	incarnation: u64,
}

/*
How much stack a fiber may use, and how much of it the kernel actually backs.

Virtual: the mapping is reserved whole and a page is resident only once touched.
Measured with the release build, a query uses 7 KB of stack on a cache hit and at
most 21 KB on a miss that walks a DNSSEC chain over UDP, including the signature
checks; a DoT or DoH upstream adds an OpenSSL handshake on the same stack. 256 KiB
is an order of magnitude over the deepest of those. Under AddressSanitizer every
frame carries redzones, so the figure is four times that there.

A fiber that runs past the end hits the guard page below it and the process stops
with SIGSEGV - a crash, never a write into a neighbour.
*/
STACK_SIZE :: #config(ELODIN_FIBER_STACK, 1024 * 1024 when ASAN else 256 * 1024)

@(private)
PAGE :: 4096

/*
How many stacks a loop keeps for reuse once their fibers are done.

A stack handed back is still mapped and its touched pages still resident, so the
next fiber starts warm and no `mmap` is paid per query. Past this many the rest
are unmapped, which is what returns a burst's memory: 64 stacks at the ~20 KB a
query touches is about a megabyte per loop kept for the next burst.
*/
@(private)
STACK_CACHE :: 64

/*
How much a recycled fiber's scratch may keep.

`arena_free_all` keeps the first block, and that block is as large as the first
allocation it served - a 64 KiB message buffer, say. A fiber whose first block is
past this is given a fresh arena when it is recycled, so one large query does not
leave its high-water mark resident on a stack that goes on to answer small ones.
*/
@(private)
SCRATCH_KEEP :: 64 * 1024

// The first block of a fresh fiber's scratch. Most queries need a few kilobytes.
@(private)
SCRATCH_FIRST_BLOCK :: 16 * 1024

@(private)
ASAN :: .Address in ODIN_SANITIZER_FLAGS

@(private)
Stack :: struct {
	// The whole mapping, guard page included.
	base: rawptr,
	size: uint,
}

/*
Assembled by `mise run prepare` from `switch_arm64.S` or `switch_amd64.S`, with
the C compiler that links every build anyway, rather than imported as source:
for x86-64 source Odin runs `nasm`, which reads Intel syntax and is one more
thing every machine building elodin would have to install.
*/
when ODIN_ARCH != .arm64 && ODIN_ARCH != .amd64 {
	#panic("elodin's fiber switch is written for arm64 and amd64 only")
}
foreign import fiber_switch "../../bin/elodin_switch.o"

@(private, default_calling_convention = "c")
foreign fiber_switch {
	elodin_fiber_switch :: proc(from_sp: ^rawptr, to_sp: rawptr) ---
}

when ASAN {
	/*
	AddressSanitizer keeps per-thread stack bounds and a fake stack for
	use-after-return detection, and has to be told when the stack changes under
	it; without these it reports every frame on a fiber as a stack overflow or
	worse, silently misses the bugs on them.
	*/
	@(private, default_calling_convention = "c")
	foreign _ {
		__sanitizer_start_switch_fiber :: proc(fake_stack_save: ^rawptr, bottom: rawptr, size: uint) ---
		__sanitizer_finish_switch_fiber :: proc(fake_stack_save: rawptr, bottom_old: ^rawptr, size_old: ^uint) ---
		__asan_unpoison_memory_region :: proc(addr: rawptr, size: uint) ---
	}
}

@(private)
stack_map :: proc() -> (s: Stack, ok: bool) {
	size := uint(STACK_SIZE) + PAGE
	base, err := linux.mmap(0, size, {.READ, .WRITE}, {.PRIVATE, .ANONYMOUS, .NORESERVE, .STACK})
	if err != .NONE {
		return {}, false
	}
	// The guard: the lowest page, since the stack grows down into it.
	if linux.mprotect(base, PAGE, {}) != .NONE {
		linux.munmap(base, size)
		return {}, false
	}
	return Stack{base, size}, true
}

@(private)
stack_unmap :: proc(s: Stack) {
	if s.base != nil {
		/*
		The frame a fiber leaves on its stack for good - `fiber_entry`'s, which
		never returns - leaves its redzones poisoned, and a raw `munmap` is one
		AddressSanitizer never sees. The next stack of this size is mapped at the
		same addresses, and its locals would sit on that stale poison.
		*/
		when ASAN {
			__asan_unpoison_memory_region(rawptr(uintptr(s.base) + PAGE), s.size - PAGE)
		}
		linux.munmap(s.base, s.size)
	}
}

@(private)
stack_top :: proc(s: Stack) -> uintptr {
	return uintptr(s.base) + uintptr(s.size)
}

/*
Lay out a fresh stack so that switching to it runs `fiber_entry(f)`.

The frame is exactly what `elodin_fiber_switch` pops: the callee-saved registers,
with the fiber in the one the switch copies into the first argument register, and
the entry's address where the switch returns to. 16-byte aligned as both ABIs
require at a call, which on amd64 means the return address sits at 16n-8 once
popped.
*/
@(private)
fiber_prepare :: proc(f: ^Fiber) {
	top := stack_top(f.stack) - 64
	entry := uintptr(rawptr(fiber_entry))
	when ODIN_ARCH == .arm64 {
		frame := ([^]uintptr)(rawptr(top - 160))
		mem.zero(frame, 160)
		frame[0] = uintptr(f) // x19
		frame[11] = entry // x30
		f.sp = frame
	} else {
		// r15 r14 r13 r12 rbx rbp, then the address `ret` pops, then padding so
		// the entry starts with the stack the ABI promises.
		frame := ([^]uintptr)(rawptr(top - 8 * 8))
		mem.zero(frame, 8 * 8)
		frame[4] = uintptr(f) // rbx
		frame[6] = entry
		f.sp = frame
	}
}

/*
The bottom of every fiber's stack.

Runs jobs rather than one job: a stack handed back to the cache keeps this frame
parked at the end of the loop below, and the next fiber to get it is started by
switching in, without laying the stack out again.

`context` is built here, on the fiber's own stack, from the loop's; a fiber can
change its own context freely and nothing it does reaches another fiber. The
scratch is the one thing set per fiber: `context.temp_allocator` is the fiber's
own arena, freed when the job returns, so every allocation a query makes through
it - and the resolver makes most of its allocations that way - lives exactly as
long as the query and not as long as the thread, which under a loop would be
forever.
*/
@(private)
fiber_entry :: proc "c" (arg: rawptr) {
	f := (^Fiber)(arg)
	when ASAN {
		// Entered for the first time: there is no fake stack of ours to restore,
		// and the stack we came from is the loop thread's own, which every later
		// switch back to the scheduler names.
		__sanitizer_finish_switch_fiber(nil, &f.loop.thread_stack_bottom, &f.loop.thread_stack_size)
	}
	for {
		l := f.loop
		context = l.ctx
		context.temp_allocator = scratch_allocator(&f.scratch)
		if f.fn == nil {
			break
		}
		f.fn(f.data)
		scratch_free_all(&f.scratch)
		f.state = .Done
		switch_to_scheduler(f)
	}
	// Told to exit, because the stack is about to be unmapped: the last switch out
	// of it lets AddressSanitizer release the fake stack that belonged to it.
	f.state = .Done
	when ASAN {
		__sanitizer_start_switch_fiber(nil, f.loop.thread_stack_bottom, f.loop.thread_stack_size)
	}
	elodin_fiber_switch(&f.sp, f.loop.sched_sp)
	unreachable()
}

// From the scheduler into `f`, until it parks or finishes.
@(private)
switch_to_fiber :: proc(l: ^Loop, f: ^Fiber) {
	locals_restore(l, f)
	f.state = .Running
	l.current = f
	when ASAN {
		fake: rawptr
		__sanitizer_start_switch_fiber(&fake, f.stack.base, f.stack.size)
		elodin_fiber_switch(&l.sched_sp, f.sp)
		__sanitizer_finish_switch_fiber(fake, nil, nil)
	} else {
		elodin_fiber_switch(&l.sched_sp, f.sp)
	}
	l.current = nil
	locals_save(l, f)
}

// From `f`, which is running, back to its loop's scheduler.
@(private)
switch_to_scheduler :: proc "contextless" (f: ^Fiber) {
	l := f.loop
	// Giving the loop up is what `take_turn` counts towards.
	f.turns = 0
	when ASAN {
		__sanitizer_start_switch_fiber(&f.asan_fake, l.thread_stack_bottom, l.thread_stack_size)
		elodin_fiber_switch(&f.sp, l.sched_sp)
		__sanitizer_finish_switch_fiber(f.asan_fake, nil, nil)
	} else {
		elodin_fiber_switch(&f.sp, l.sched_sp)
	}
}

// --- Thread-locals carried by the fiber --------------------------------------

/*
At most this many bytes of registered thread-locals, in all.

Three are registered today - the generation a query has pinned, whether it is a
prefetch, and the errno of the last failed handshake - for a few dozen bytes.
Copied on every switch, so the figure stays small on purpose.
*/
LOCALS_MAX :: 64

@(private)
Local :: struct {
	address: proc "contextless" () -> rawptr,
	size:    int,
	offset:  int,
}

@(private)
locals: [8]Local

@(private)
locals_count: int

@(private)
locals_used: int

/*
Make a thread-local per fiber instead.

Some state is per request and is kept in a thread-local rather than passed down
through every call that reads it: the generation a query pinned (`server.pin`),
whether it is a prefetch. On a loop thread many requests take turns, so each fiber keeps its own copy: the value is saved when the fiber parks
and put back when it runs, and the loop thread sees zero in between.

`address` returns the calling thread's instance of the variable - an `@(thread_local)`
read through `&` - and is asked once per loop thread. Registered from an `@(init)`
procedure, before any loop starts; a registration after that would be missed by a
loop already running, so it panics instead.
*/
register_local :: proc(address: proc "contextless" () -> rawptr, size: int) {
	assert(loops_started == 0, "thread-locals are registered before any loop starts")
	assert(locals_count < len(locals) && locals_used + size <= LOCALS_MAX, "too many fiber-local bytes")
	locals[locals_count] = Local{address, size, locals_used}
	locals_count += 1
	locals_used += size
}

@(private)
locals_restore :: proc "contextless" (l: ^Loop, f: ^Fiber) {
	for i in 0 ..< locals_count {
		mem.copy_non_overlapping(l.local_addresses[i], &f.locals[locals[i].offset], locals[i].size)
	}
}

@(private)
locals_save :: proc "contextless" (l: ^Loop, f: ^Fiber) {
	for i in 0 ..< locals_count {
		mem.copy_non_overlapping(&f.locals[locals[i].offset], l.local_addresses[i], locals[i].size)
		mem.zero(l.local_addresses[i], locals[i].size)
	}
}

// --- Scratch ----------------------------------------------------------------

/*
A fiber's `context.temp_allocator`.

An arena in the ordinary build, backed by mapped pages so a block given back is
memory given back to the kernel rather than to a glibc heap that keeps it.

With `-define:ELODIN_SCRATCH_DEBUG=true` every allocation is a heap allocation of
its own, freed at `free_all`. An arena that is freed and refilled hands out the
same addresses again, so a pointer kept past the arena's reset reads plausible
data and AddressSanitizer sees nothing; separate allocations are poisoned when
freed, so the same mistake is reported where it happens. `mise run leakcheck`
and the fuzz targets build with it.
*/
SCRATCH_DEBUG :: #config(ELODIN_SCRATCH_DEBUG, false)

when SCRATCH_DEBUG {
	Scratch :: struct {
		blocks: [dynamic]rawptr,
	}
} else {
	Scratch :: struct {
		arena: runtime.Arena,
	}
}

scratch_allocator :: proc(s: ^Scratch) -> runtime.Allocator {
	return runtime.Allocator{scratch_allocator_proc, s}
}

@(private)
scratch_allocator_proc :: proc(
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
	s := (^Scratch)(data)
	when SCRATCH_DEBUG {
		#partial switch mode {
		case .Alloc, .Alloc_Non_Zeroed:
			p, err := runtime.mem_alloc(size, alignment, runtime.heap_allocator(), loc)
			if err == nil && p != nil {
				if s.blocks == nil {
					s.blocks = make([dynamic]rawptr, runtime.heap_allocator())
				}
				append(&s.blocks, raw_data(p))
			}
			return p, err
		case .Resize, .Resize_Non_Zeroed:
			// Never in place, so a pointer to the old copy is a pointer into memory
			// that is freed at `free_all` with the rest - the same lifetime an
			// arena gives it, and no longer.
			p, err := scratch_allocator_proc(data, .Alloc, size, alignment, nil, 0, loc)
			if err == nil && old_memory != nil {
				mem.copy(raw_data(p), old_memory, min(size, old_size))
			}
			return p, err
		case .Free:
			return nil, nil
		case .Free_All:
			scratch_free_all(s)
			return nil, nil
		case .Query_Features:
			if set := (^runtime.Allocator_Mode_Set)(old_memory); set != nil {
				set^ = {.Alloc, .Alloc_Non_Zeroed, .Resize, .Resize_Non_Zeroed, .Free, .Free_All, .Query_Features}
			}
			return nil, nil
		}
		return nil, .Mode_Not_Implemented
	} else {
		if s.arena.backing_allocator.procedure == nil {
			s.arena.backing_allocator = mapped_allocator
			s.arena.minimum_block_size = SCRATCH_FIRST_BLOCK
		}
		return runtime.arena_allocator_proc(&s.arena, mode, size, alignment, old_memory, old_size, loc)
	}
}

scratch_free_all :: proc(s: ^Scratch) {
	when SCRATCH_DEBUG {
		for p in s.blocks {
			runtime.mem_free(p, runtime.heap_allocator())
		}
		clear(&s.blocks)
	} else {
		if s.arena.curr_block != nil {
			runtime.arena_free_all(&s.arena)
		}
	}
}

@(private)
scratch_destroy :: proc(s: ^Scratch) {
	when SCRATCH_DEBUG {
		scratch_free_all(s)
		delete(s.blocks)
		s.blocks = nil
	} else {
		runtime.arena_destroy(&s.arena)
		s^ = {}
	}
}

// Whether the scratch is holding more than a recycled fiber should keep.
@(private)
scratch_oversized :: proc(s: ^Scratch) -> bool {
	when SCRATCH_DEBUG {
		return false
	} else {
		return s.arena.total_capacity > SCRATCH_KEEP
	}
}
