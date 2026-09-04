package server

import "core:sync"
import "core:thread"

// Stamped at build time from the git tag; see ELODIN_VERSION in mise.toml. A
// build that bypasses mise reports "dev" rather than claiming a release number.
VERSION :: #config(ELODIN_VERSION, "dev")

/*
Bookkeeping for connection-handling threads.

TCP, DoT and DoH connections are long-lived and mostly idle, so each gets its
own thread rather than a slot in the query worker pool — a handful of open
connections would otherwise starve every UDP query. Finished threads are joined
lazily on the next spawn, which keeps the accept loop free of a reaper thread.
*/
Conn_Manager :: struct {
	mu:           sync.Mutex,
	threads:      [dynamic]Conn_Thread,
	limit:        int,
	/*
	The most of `limit` any one client prefix may hold, or 0 for no such cap.

	`limit` on its own is a budget with no share-out, and nothing else in this
	server bounds how long a client keeps what it was given: the rate limiter
	charges opening a connection and charges the queries asked over it, both of
	which are rates a client inside its budget goes on paying while holding every
	connection it opened. So without this one prefix may hold every slot and lock
	everybody else out.

	Occupancy against arrival, in other words - two bounds that need each other.
	A share alone does not bound arrivals: a flood that holds each connection for
	the length of a handshake never reaches a share of 256 out of 512, which is
	measured in `bench/results/2026-09-03-handshake-floods.md`. An arrival budget
	alone does not bound occupancy: a client that opens connections slowly and
	never closes them fills the table inside any rate.

	Kept per /24 and /64 rather than per address, because that is the granularity
	an attacker picks addresses within, and the granularity the limiter's budgets
	are already kept at. See `client_prefix`.
	*/
	prefix_limit: int,
	// Accept and read loops live here too, but must not eat into the limit the
	// operator set for client connections. Adjusted as threads are reaped as
	// well as as they are added: the limit is `len(threads) - permanent`, so a
	// figure that only ever grows stops describing anything once a loop ends.
	permanent:    int,
}

@(private)
Conn_Thread :: struct {
	handle:    ^thread.Thread,
	permanent: bool,
	// Which client's share this thread is occupying. Zero for the permanent
	// loops, which are nobody's client.
	prefix:    Client_Prefix,
}

conn_manager_init :: proc(cm: ^Conn_Manager, limit: int, prefix_limit: int) {
	cm.limit = max(limit, 1)
	cm.prefix_limit = max(prefix_limit, 0)
	cm.threads = make([dynamic]Conn_Thread, 0, 16)
}

/*
Why a spawn did not happen.

Three things stop one, and they do not ask for the same response from an
operator. `Limit_Reached` is `server.max_connections` doing its job, and raising
it is the fix. `Prefix_Limit_Reached` is one client's share of that table being
full while the table itself is not, so raising `max_connections` would only hand
the same client more; `server.max_connections_per_prefix` is the figure that
decides it. `Thread_Failed` is the OS refusing a thread - `RLIMIT_NPROC`, or
memory - and it can happen far below either limit, where raising anything cannot
help and the number in the log would send somebody the wrong way.
*/
Spawn_Result :: enum u8 {
	Started,
	Limit_Reached,
	Prefix_Limit_Reached,
	Thread_Failed,
}

/*
Start `fn` on its own thread, unless a connection limit has been reached.

Anything but `.Started` means the caller should refuse the connection. `prefix`
is the client the connection belongs to, which is what its share of the table is
counted against; the zero value is a connection that is nobody's, and is not
counted against a share. Pass `counted = false` for the server's own listener
loops, which run for the process's lifetime and are not client connections.
*/
conn_spawn :: proc(
	cm: ^Conn_Manager,
	data: rawptr,
	fn: proc(data: rawptr),
	prefix := Client_Prefix{},
	counted := true,
) -> Spawn_Result {
	sync.mutex_lock(&cm.mu)
	defer sync.mutex_unlock(&cm.mu)

	reap_locked(cm)
	if counted {
		if len(cm.threads) - cm.permanent >= cm.limit {
			return .Limit_Reached
		}
		/*
		The client's share, asked after the table's total.

		Both can be true at once - a full table whose last slot this prefix was
		not entitled to either - and the total is the one to report there. It is
		a fact about the server rather than about the client, and it is what
		would have to be raised before the next connection from anywhere could
		be served.
		*/
		if cm.prefix_limit > 0 && prefix.n != 0 && prefix_conns_locked(cm, prefix) >= cm.prefix_limit {
			return .Prefix_Limit_Reached
		}
	}
	t := thread.create_and_start_with_poly_data(data, fn)
	if t == nil {
		return .Thread_Failed
	}
	append(&cm.threads, Conn_Thread{handle = t, permanent = !counted, prefix = prefix})
	if !counted {
		cm.permanent += 1
	}
	return .Started
}

/*
How many slots `prefix` is holding, counted off the thread list itself.

Walked rather than kept in a table beside the list. It costs nothing that was
not already being spent: `reap_locked` walks the same list on every spawn and
asks the OS about each entry, so the accept path was linear in the table before
this and the added pass is a comparison of nine bytes per entry. What it buys is
that a count taken from the connections cannot drift from the connections, which
a counter incremented on accept and decremented at the far end of a connection
handler can. There is nothing to release: a connection that ends gives up its
share in the same `reap_locked` that gives up its slot, and one that is refused
never took either.
*/
@(private)
prefix_conns_locked :: proc(cm: ^Conn_Manager, prefix: Client_Prefix) -> int {
	n := 0
	for entry in cm.threads {
		if !entry.permanent && entry.prefix == prefix {
			n += 1
		}
	}
	return n
}

@(private)
reap_locked :: proc(cm: ^Conn_Manager) {
	i := 0
	for i < len(cm.threads) {
		entry := cm.threads[i]
		if thread.is_done(entry.handle) {
			thread.join(entry.handle)
			thread.destroy(entry.handle)
			if entry.permanent {
				cm.permanent -= 1
			}
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

	for entry in threads {
		thread.join(entry.handle)
		thread.destroy(entry.handle)
	}
	delete(threads)
}
