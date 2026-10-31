package brlock

import "core:sync"
import "core:thread"

/*
A reader-writer lock for something read on every query and written on a reload.

`core:sync`'s `RW_Mutex` keeps its readers in one word, so every reader on every
loop thread writes the same cache line twice - in and out - and the line moves
between cores on each query. With four threads matching against the block
lists, that lock and two shared counters beside it cut the matches done per
second to under half of what one thread did alone, and to about an eighth of
what the same four did with neither (#415).

Here each thread counts itself in on a stripe of its own, a cache line nothing
else is written to, so a reader shares no written line with a reader on another
thread. The writer pays for it: it raises `writing` and then waits for every
stripe to drain. A reader that finds `writing` raised steps back out and waits
for it to fall, so once the writer has seen every stripe at zero no reader is
inside, and none gets in until `write_unlock`.

What makes the two halves agree is that both sides write their own word and then
read the other's, each a sequentially consistent operation: either the reader's
load sees `writing`, or the writer's load sees the reader's count. Both missing
each other would need the two loads to be ordered before both stores, which a
single total order of those four operations does not allow.

Readers must not wait on anything inside: the writer waits for them, spinning,
and a reader that parks holds every writer up for as long as it is parked.
*/

// More than any loop count (`listeners.udp.readers` is at most 8), so the loop
// threads each have one. A thread past them shares, which is still correct.
STRIPES :: 16

// A count on a cache line of its own. Also what a structure holding a count per
// stripe - `server.Generation`'s references - is made of.
Count :: struct #align(64) {
	n: int,
}

Lock :: struct {
	readers: [STRIPES]Count,
	// Read by every reader on every entry, written only by a writer, so the line
	// it is on stays shared between cores until a reload.
	writing: bool,
	// One writer at a time.
	writers: sync.Mutex,
}

@(private, thread_local)
mine: int

@(private)
assigned: int

/*
This thread's stripe, the same one every time it asks.

Handed out in order of first use, so the loop threads, started together, take
the first few. A thread rather than a fiber: a reader cannot park inside, so a
fiber never carries a read lock from one thread to another.
*/
stripe :: proc "contextless" () -> int {
	if mine == 0 {
		mine = sync.atomic_add(&assigned, 1) % STRIPES + 1
	}
	return mine - 1
}

// Returns the stripe to hand back to `read_unlock`.
read_lock :: proc "contextless" (l: ^Lock) -> (stripe_index: int) {
	stripe_index = stripe()
	r := &l.readers[stripe_index].n
	for {
		sync.atomic_add(r, 1)
		if !sync.atomic_load(&l.writing) {
			return
		}
		sync.atomic_sub(r, 1)
		for spins := 0; sync.atomic_load(&l.writing); spins += 1 {
			relax(spins)
		}
	}
}

read_unlock :: proc "contextless" (l: ^Lock, stripe_index: int) {
	sync.atomic_sub(&l.readers[stripe_index].n, 1)
}

write_lock :: proc(l: ^Lock) {
	sync.mutex_lock(&l.writers)
	sync.atomic_store(&l.writing, true)
	for &r in l.readers {
		for spins := 0; sync.atomic_load(&r.n) != 0; spins += 1 {
			relax(spins)
		}
	}
}

write_unlock :: proc(l: ^Lock) {
	sync.atomic_store(&l.writing, false)
	sync.mutex_unlock(&l.writers)
}

// Every stripe's count added up. Exact only while nothing can raise any of them.
total :: proc "contextless" (counts: []Count) -> (n: int) {
	for &c in counts {
		n += sync.atomic_load(&c.n)
	}
	return
}

/*
A wait on the other side, which lasts as long as one match or one pin on the
reader's side, and as long as a pointer swap on the writer's. Spun briefly, then
given up to the scheduler, so a side that was descheduled mid-way is let back
on rather than spun against for its whole time slice.
*/
@(private)
relax :: proc "contextless" (spins: int) {
	if spins < 64 {
		sync.cpu_relax()
	} else {
		context = {}
		thread.yield()
	}
}
