package brlock

import "core:sync"
import "core:testing"
import "core:thread"

// Long enough for a thread that is free to run to have run, without being a
// measure of time: a passing run never depends on it.
@(private = "file")
YIELDS :: 2000

@(private = "file")
Probe :: struct {
	l:    ^Lock,
	done: bool,
}

@(test)
test_a_writer_waits_for_a_reader :: proc(t: ^testing.T) {
	p := new(Probe)
	defer free(p)
	p.l = new(Lock)
	defer free(p.l)

	i := read_lock(p.l)
	w := thread.create_and_start_with_data(p, proc(data: rawptr) {
		p := (^Probe)(data)
		write_lock(p.l)
		sync.atomic_store(&p.done, true)
		write_unlock(p.l)
	})
	defer thread.destroy(w)

	// Until the writer is at the lock, or past it already, which is the failure.
	for !sync.atomic_load(&p.l.writing) && !sync.atomic_load(&p.done) {
		thread.yield()
	}
	for _ in 0 ..< YIELDS {
		thread.yield()
	}
	testing.expect(t, !sync.atomic_load(&p.done), "the writer went in past a reader")
	read_unlock(p.l, i)
	thread.join(w)
	testing.expect(t, sync.atomic_load(&p.done), "the writer never went in")
}

@(test)
test_a_reader_waits_for_a_writer :: proc(t: ^testing.T) {
	p := new(Probe)
	defer free(p)
	p.l = new(Lock)
	defer free(p.l)

	write_lock(p.l)
	r := thread.create_and_start_with_data(p, proc(data: rawptr) {
		p := (^Probe)(data)
		i := read_lock(p.l)
		sync.atomic_store(&p.done, true)
		read_unlock(p.l, i)
	})
	defer thread.destroy(r)

	for _ in 0 ..< YIELDS {
		thread.yield()
	}
	testing.expect(t, !sync.atomic_load(&p.done), "a reader went in past the writer")
	write_unlock(p.l)
	thread.join(r)
	testing.expect(t, sync.atomic_load(&p.done), "the reader never went in")
}

// What the lock is for: two threads reading count on two different lines.
@(test)
test_threads_read_on_their_own_lines :: proc(t: ^testing.T) {
	got: [2]int
	ts: [2]^thread.Thread
	for &g, k in got {
		ts[k] = thread.create_and_start_with_data(&g, proc(data: rawptr) {
			(^int)(data)^ = stripe()
		})
	}
	for th in ts {
		thread.join(th)
		thread.destroy(th)
	}
	testing.expect(t, got[0] != got[1], "two threads were given one stripe")

	l := new(Lock)
	defer free(l)
	testing.expect_value(t, uintptr(&l.readers[0]) % 64, 0)
	testing.expect_value(t, uintptr(&l.readers[1]) - uintptr(&l.readers[0]), 64)
}
