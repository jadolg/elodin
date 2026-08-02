package server

import "core:sync"
import "core:thread"

VERSION :: "0.1.0"

/*
Bookkeeping for connection-handling threads.

TCP, DoT and DoH connections are long-lived and mostly idle, so each gets its
own thread rather than a slot in the query worker pool — a handful of open
connections would otherwise starve every UDP query. Finished threads are joined
lazily on the next spawn, which keeps the accept loop free of a reaper thread.
*/
Conn_Manager :: struct {
	mu:        sync.Mutex,
	threads:   [dynamic]^thread.Thread,
	limit:     int,
	// Accept and read loops live here too, but must not eat into the limit the
	// operator set for client connections.
	permanent: int,
}

conn_manager_init :: proc(cm: ^Conn_Manager, limit: int) {
	cm.limit = max(limit, 1)
	cm.threads = make([dynamic]^thread.Thread, 0, 16)
}

/*
Start `fn` on its own thread, unless the connection limit has been reached.

Returns false when the caller should refuse the connection instead. Pass
`counted = false` for the server's own listener loops, which run for the
process's lifetime and are not client connections.
*/
conn_spawn :: proc(cm: ^Conn_Manager, data: rawptr, fn: proc(data: rawptr), counted := true) -> bool {
	sync.mutex_lock(&cm.mu)
	defer sync.mutex_unlock(&cm.mu)

	reap_locked(cm)
	if counted && len(cm.threads) - cm.permanent >= cm.limit {
		return false
	}
	t := thread.create_and_start_with_poly_data(data, fn)
	if t == nil {
		return false
	}
	append(&cm.threads, t)
	if !counted {
		cm.permanent += 1
	}
	return true
}

@(private)
reap_locked :: proc(cm: ^Conn_Manager) {
	i := 0
	for i < len(cm.threads) {
		t := cm.threads[i]
		if thread.is_done(t) {
			thread.join(t)
			thread.destroy(t)
			unordered_remove(&cm.threads, i)
			continue
		}
		i += 1
	}
}

active_connections :: proc(cm: ^Conn_Manager) -> int {
	sync.mutex_lock(&cm.mu)
	defer sync.mutex_unlock(&cm.mu)
	reap_locked(cm)
	return len(cm.threads) - cm.permanent
}

// Wait for every connection thread to finish. Callers close the listening
// sockets first so the handlers see EOF and return.
conn_manager_shutdown :: proc(cm: ^Conn_Manager) {
	sync.mutex_lock(&cm.mu)
	threads := cm.threads
	cm.threads = nil
	sync.mutex_unlock(&cm.mu)

	for t in threads {
		thread.join(t)
		thread.destroy(t)
	}
	delete(threads)
}
