package pool

import "core:mem"
import "core:sync"
import "core:thread"

/*
A fixed-size worker pool over a FIFO job queue.

The server runs two of these. Query handling gets one; racing upstreams gets a
second, separate one. Keeping them apart matters: a race job is submitted *by* a
handler and waited on by it, so sharing a single pool could deadlock once every
worker is blocked waiting for jobs that no one is left to run.
*/

Job :: struct {
	fn:   proc(data: rawptr),
	data: rawptr,
}

Pool :: struct {
	mu:        sync.Mutex,
	cond:      sync.Cond,
	queue:     [dynamic]Job,
	head:      int,
	threads:   []^thread.Thread,
	running:   bool,
	allocator: mem.Allocator,
	pending:   int,
}

make_pool :: proc(workers: int, allocator := context.allocator) -> ^Pool {
	p := new(Pool, allocator)
	p.allocator = allocator
	p.queue = make([dynamic]Job, 0, 64, allocator)
	p.running = true
	p.threads = make([]^thread.Thread, max(workers, 1), allocator)

	for i in 0 ..< len(p.threads) {
		p.threads[i] = thread.create_and_start_with_poly_data(p, worker_loop)
	}
	return p
}

@(private)
worker_loop :: proc(p: ^Pool) {
	for {
		sync.mutex_lock(&p.mu)
		for p.running && p.head >= len(p.queue) {
			sync.cond_wait(&p.cond, &p.mu)
		}
		if !p.running && p.head >= len(p.queue) {
			sync.mutex_unlock(&p.mu)
			return
		}
		job := p.queue[p.head]
		p.head += 1
		// Reclaim the consumed prefix once it dominates the buffer.
		if p.head > 64 && p.head * 2 > len(p.queue) {
			remaining := len(p.queue) - p.head
			copy(p.queue[:remaining], p.queue[p.head:])
			resize(&p.queue, remaining)
			p.head = 0
		}
		sync.mutex_unlock(&p.mu)

		job.fn(job.data)

		sync.mutex_lock(&p.mu)
		p.pending -= 1
		sync.mutex_unlock(&p.mu)
	}
}

submit :: proc(p: ^Pool, fn: proc(data: rawptr), data: rawptr) -> bool {
	return try_submit(p, fn, data, 0) == .Accepted
}

Submit_Result :: enum {
	Accepted,
	// The backlog was already at `limit`.
	Full,
	// The pool is shutting down and takes no more work.
	Stopped,
}

/*
Submit unless the backlog is already at `limit`, deciding and appending under
one hold of the lock. A limit of zero or less is no limit.

Asking `pending` and then calling `submit` is not the same thing: the gap
between them is one every caller can pass through at once, and the callers are
not one thread. DoH over HTTP/2 runs a reader thread per connection, so a
synchronised burst can have `max_connections` of them each read a backlog one
short of the limit and each add to it - a queue past the limit by as many
threads as happened to be looking, which is the shape of load the limit is
there for.
*/
try_submit :: proc(p: ^Pool, fn: proc(data: rawptr), data: rawptr, limit: int) -> Submit_Result {
	sync.mutex_lock(&p.mu)
	defer sync.mutex_unlock(&p.mu)
	if !p.running {
		return .Stopped
	}
	if limit > 0 && p.pending >= limit {
		return .Full
	}
	append(&p.queue, Job{fn = fn, data = data})
	p.pending += 1
	sync.cond_signal(&p.cond)
	return .Accepted
}

// Jobs queued or in flight. Used to shed load before the queue grows unbounded.
pending :: proc(p: ^Pool) -> int {
	sync.mutex_lock(&p.mu)
	defer sync.mutex_unlock(&p.mu)
	return p.pending
}

worker_count :: proc(p: ^Pool) -> int {
	return len(p.threads)
}

// Stop accepting work, drain what is queued, and join every worker.
destroy :: proc(p: ^Pool) {
	if p == nil {
		return
	}
	sync.mutex_lock(&p.mu)
	p.running = false
	sync.cond_broadcast(&p.cond)
	sync.mutex_unlock(&p.mu)

	for t in p.threads {
		thread.join(t)
		thread.destroy(t)
	}
	delete(p.threads, p.allocator)
	delete(p.queue)
	free(p, p.allocator)
}
