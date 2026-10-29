package server

import "base:runtime"
import "core:mem/virtual"
import "core:strings"
import "core:thread"
import "elodin:config"
import "elodin:loop"

/*
A rebuild of the rule sets, on a thread of its own (#416).

A rebuild downloads each list that is due, each for up to `FETCH_DEADLINE`. On
the maintenance thread, where signals are acted on and housekeeping runs, that
would hold a SIGTERM past an init system's stop timeout, which then kills the
process undrained; and a signal the kernel handed that thread would cut the
download it is in short, as a failed one. So the loop starts a rebuild here and
goes on. One runs at a time, from a copy of what it reads of the configuration
taken as it starts, so it pins no generation: a reload meanwhile goes ahead, the
generations it replaces are released as ever, and the rebuild it asks for
follows.

Like every thread, it starts with the signals `main` acts on blocked, so the
kernel hands them to a thread that is not downloading; see `loop.spawn_thread`.
*/
Rebuild :: struct {
	s:       ^Server,
	network: bool,
	thread:  ^thread.Thread,
	// Read once the thread is joined.
	current: bool,
	// The copy the rebuild reads, and the arena it lives in.
	arena:   virtual.Arena,
	cfg:     config.Config,
}

// Start a rebuild; the caller has checked none is running. False when no
// thread can be had, and nothing is started: run on the caller's thread, it
// would hold the signals that thread acts on.
rebuild_start :: proc(r: ^Rebuild, s: ^Server, network: bool) -> (started: bool) {
	// A second start would overwrite what the running thread still writes to.
	assert(!rebuild_busy(r), "a rebuild is already running")
	r^ = Rebuild {
		s       = s,
		network = network,
	}
	if virtual.arena_init_growing(&r.arena) != nil {
		r^ = {}
		return false
	}
	r.cfg = rebuild_snapshot(live_config(s), virtual.arena_allocator(&r.arena))
	// The caller's allocators, as the sets and `lists_loaded` built there are
	// freed by the caller's thread; `loop.spawn_thread` gives it a temp allocator of its own.
	r.thread = loop.spawn_thread(r, rebuild_thread, context)
	if r.thread == nil {
		virtual.arena_destroy(&r.arena)
		r^ = {}
		return false
	}
	return true
}

@(private = "file")
rebuild_thread :: proc(r: ^Rebuild) {
	r.current = rebuild_rules(r.s, &r.cfg, r.network)
}

// Started and not yet collected.
rebuild_busy :: proc(r: ^Rebuild) -> bool {
	return r.s != nil
}

// Over, and not yet collected.
rebuild_done :: proc(r: ^Rebuild) -> bool {
	return r.s != nil && thread.is_done(r.thread)
}

// A rebuild that is over, joined and forgotten; `over` is false while one runs,
// or when none was started.
rebuild_collect :: proc(r: ^Rebuild) -> (current, over: bool) {
	if !rebuild_done(r) {
		return
	}
	thread.join(r.thread)
	thread.destroy(r.thread)
	virtual.arena_destroy(&r.arena)
	current = r.current
	r^ = {}
	return current, true
}

/*
What `rebuild_rules` reads of `from` - the blocking section and the bootstrap
servers - copied into `allocator`, and nothing else: the rest is left zero.
*/
rebuild_snapshot :: proc(from: ^config.Config, allocator := context.allocator) -> (cfg: config.Config) {
	clone_lists :: proc(lists: []config.Block_List, allocator: runtime.Allocator) -> []config.Block_List {
		out := make([]config.Block_List, len(lists), allocator)
		for list, i in lists {
			out[i] = list
			out[i].name = strings.clone(list.name, allocator)
			out[i].url = strings.clone(list.url, allocator)
			out[i].file = strings.clone(list.file, allocator)
		}
		return out
	}
	clone_strings :: proc(texts: []string, allocator: runtime.Allocator) -> []string {
		out := make([]string, len(texts), allocator)
		for text, i in texts {
			out[i] = strings.clone(text, allocator)
		}
		return out
	}
	cfg.blocking = from.blocking
	cfg.blocking.lists = clone_lists(from.blocking.lists, allocator)
	cfg.blocking.allow_lists = clone_lists(from.blocking.allow_lists, allocator)
	cfg.blocking.rules = clone_strings(from.blocking.rules, allocator)
	cfg.blocking.allow_rules = clone_strings(from.blocking.allow_rules, allocator)
	cfg.blocking.cache_dir = strings.clone(from.blocking.cache_dir, allocator)
	cfg.upstream.bootstrap = clone_strings(from.upstream.bootstrap, allocator)
	return
}
