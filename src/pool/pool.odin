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
	sync.mutex_lock(&p.mu)
	defer sync.mutex_unlock(&p.mu)
	if !p.running {
		return false
	}
	append(&p.queue, Job{fn = fn, data = data})
	p.pending += 1
	sync.cond_signal(&p.cond)
	return true
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
