#+build linux
package loop

import "base:runtime"
import "core:mem"
import "core:sync"
import "core:testing"
import "core:time"

// Under `SCRATCH_DEBUG` every allocation is the heap's: an empty scratch maps
// nothing, and there is no arena to look at.
when !SCRATCH_DEBUG {
	// The loop's clock in this file's test, moved by hand on the loop's own thread.
	@(private = "file")
	idle_now: Tick

	@(private = "file")
	idle_clock :: proc "contextless" () -> Tick {
		return idle_now
	}

	@(private = "file")
	Scratch_Hold :: enum {
		// Everything the fiber allocated is freed before it waits: a connection
		// between queries.
		Nothing,
		// One allocation is still live across the wait.
		Allocation,
		// A temp region is open across the wait, with nothing allocated in it yet.
		Temp_Region,
	}

	@(private = "file")
	Scratch_Probe :: struct {
		done:     sync.Sema,
		hold:     Scratch_Hold,
		idle:     bool,
		parked:   ^Fiber,
		token:    u64,
		// Whether the scratch had a block resident before the trim, and still has
		// one mapped after it.
		resident: bool,
		kept:     bool,
		// Whether the live allocation read back what was written into it, and the
		// scratch served a new one, once the fiber ran again.
		intact:   bool,
		served:   bool,
	}

	/*
	An idle park that lasts unmaps the fiber's scratch along with its stack when
	nothing in the scratch is live (#613). The first block `arena_free_all` keeps
	mapped is 4 KiB of every held connection otherwise. A live allocation or an
	open temp region keeps the arena whole, and a park that is not idle keeps it
	too. Either way the fiber can allocate again once it runs.
	*/
	@(test)
	test_an_idle_fiber_gives_its_empty_scratch_back_with_its_stack :: proc(t: ^testing.T) {
		idle_now = time.tick_now()
		r, started := start(t, idle_clock)
		if !started {
			return
		}
		defer finish(r)
		l := r.l
		Case :: struct {
			hold: Scratch_Hold,
			idle: bool,
		}
		for c in ([]Case{{.Nothing, true}, {.Nothing, false}, {.Allocation, true}, {.Temp_Region, true}}) {
			p := Scratch_Probe {
				hold = c.hold,
				idle = c.idle,
			}
			_, ok := spawn(l, use_scratch_then_park, &p)
			if !testing.expect(t, ok) || !testing.expect(t, sync.sema_wait_with_timeout(&p.done, 5 * time.Second)) {
				return
			}
			// The premise: the query's scratch is resident while the fiber waits.
			testing.expectf(t, p.resident, "%v: no scratch block resident before the trim", c)
			testing.expectf(t, p.kept == (c.hold != .Nothing || !c.idle), "%v: a block still mapped after the trim is %v", c, p.kept)
			testing.expectf(t, p.served, "%v: the scratch served nothing once the fiber ran again", c)
			if c.hold == .Allocation {
				testing.expectf(t, p.intact, "%v: the live allocation lost what was written into it", c)
			}
		}
	}

	@(private = "file")
	use_scratch_then_park :: proc(data: rawptr) {
		p := (^Scratch_Probe)(data)
		f := current()
		// What a query leaves: its message and answer, freed when it is answered.
		scratch := make([]u8, 1024, context.temp_allocator)
		mem.set(raw_data(scratch), 0xa5, len(scratch))
		temp: runtime.Arena_Temp
		switch p.hold {
		case .Nothing:
			free_all(context.temp_allocator)
		case .Allocation:
		case .Temp_Region:
			free_all(context.temp_allocator)
			temp = runtime.arena_temp_begin(&f.scratch.arena)
		}
		set_idle(p.idle)
		p.parked = f
		p.token = f.token
		_, _ = spawn(current_loop(), trim_scratch, p)
		_ = park(time.tick_add(idle_now, 10 * IDLE_TRIM_AFTER))
		set_idle(false)
		// Read only what the trim left mapped: an arena unmapped under a live
		// allocation is the failure the expectations report, not a fault to take.
		if p.hold == .Allocation && p.kept {
			p.intact = true
			for b in scratch {
				p.intact &&= b == 0xa5
			}
		}
		if p.hold == .Temp_Region {
			if p.kept {
				runtime.arena_temp_end(temp)
			} else {
				f.scratch.arena.temp_count = 0
			}
		}
		again := make([]u8, 1024, context.temp_allocator)
		p.served = len(again) == 1024
		sync.sema_post(&p.done)
	}

	@(private = "file")
	trim_scratch :: proc(data: rawptr) {
		p := (^Scratch_Probe)(data)
		f := p.parked
		if b := f.scratch.arena.curr_block; b != nil {
			pages, _ := residency(([^]u8)(b)[:size_of(b^)])
			p.resident = pages > 0
		}
		idle_now = time.tick_add(idle_now, IDLE_TRIM_AFTER)
		expire_timers(f.loop, idle_now)
		p.kept = f.scratch.arena.curr_block != nil
		wake(f, p.token)
	}
}
