package server

import "core:mem/virtual"
import "core:reflect"
import "core:strings"
import "elodin:cache"
import "elodin:config"
import "elodin:filter"
import "elodin:logx"

/*
What a configuration reload did, for the caller's bookkeeping.
*/
Reload_Outcome :: struct {
	// A new configuration is in effect.
	applied:  bool,
	// The rule sets are to be built again, by the caller through
	// `rebuild_rules`: the blocking section changed, or it names `file:` lists,
	// which every SIGHUP reads again (`reads_list_files`).
	blocking: bool,
}

/*
Read the configuration file again and put into effect what it changes.

Everything is validated and built before anything is swapped: the file goes
through the loader `--check` runs, and every part a change needs - upstream
groups, the validator and its anchors, the cookie secret - is built before the
generation is swapped in. A file that fails any of that leaves the running
configuration exactly as it was and says why. A reload that half-applies would
be worse than one that does not happen: the operator would be running a
configuration nobody wrote.

The keys that need a restart are named in a warning and held at the value the
process started with, and everything else in the file is applied: refusing a
whole reload over a listener address would leave an operator choosing between
their rewrites and a restart they did not want yet. See `keep_restart_only`.

Runs on the maintenance thread, which is the only one that swaps or releases a
generation, and must not be called with a generation pinned. The rules are not
rebuilt here, as a rebuild may download for minutes and the maintenance thread
is where signals are acted on (#416); nor are they or their history touched, so
it runs beside a rebuild, which reads its own copy of the configuration and pins
no generation (see `Rebuild`).
*/
reload_config :: proc(s: ^Server, path: string) -> (out: Reload_Outcome) {
	assert(pinned.server == nil, "reload_config runs with no generation pinned")
	cur := s.gens.current

	arena := new(virtual.Arena)
	if err := virtual.arena_init_growing(arena); err != nil {
		free(arena)
		logx.errorf("reload: cannot reserve memory for the configuration (%v); keeping the configuration already in effect", err)
		return
	}
	g := new(Generation)
	g.arena = arena
	keep := false
	defer if !keep {
		destroy_generation(g)
	}

	// Without the certificate files: the listeners are held at what the process
	// started with, and `reload_tls` reads their certificates and says what it
	// could not.
	loaded, load_err := config.load_file(path, virtual.arena_allocator(arena), tls_files = false)
	if e, has := load_err.?; has {
		for msg in e.messages {
			logx.errorf("reload: %s: %s", path, msg)
		}
		logx.warnf("reload: %s is not usable; keeping the configuration already in effect", path)
		return
	}
	g.config = loaded
	g.cfg = &g.config

	for key in g.cfg.retired {
		logx.warnf("reload: %s", config.retired_warning(key))
	}
	for key in keep_restart_only(s.gens.boot, g.cfg, context.temp_allocator) {
		logx.warnf("reload: %s changed, which takes a restart; it keeps the value the process started with until then", key)
	}
	if !differs(cur.cfg^, g.config) {
		if !reads_list_files(cur.cfg) {
			logx.infof("reload: nothing a reload puts into effect has changed")
			return
		}
		// The file is the same, and the lists it names on disk may not be.
		logx.infof("reload: the configuration is unchanged; reading the blocklist files again")
		out.blocking = true
		return
	}

	built, carried, ok := build_live(s, &g.live, &cur.live)
	if !ok {
		logx.warnf("reload: %s could not be put into effect; keeping the configuration already in effect", path)
		return
	}
	g.owns = built

	// The cache is shared with the generation it came from, so it is brought in
	// line only now that nothing can fail.
	answers := "off"
	flush := false
	if g.answers != nil {
		answers = "new" if .Answers in built else "kept"
		if .Answers in carried && differs(cur.cfg.cache, g.cfg.cache) {
			cache.reconfigure(g.answers, cache_options(g.cfg.cache))
		}
		flush = .Answers in carried && g.policy != cur.policy
		if flush {
			answers = "flushed"
		}
	}

	changed := changed_sections(cur.cfg, g.cfg, context.temp_allocator)
	out.blocking = rules_changed(cur.cfg.blocking, g.cfg.blocking) || reads_list_files(g.cfg)
	log_file_moved := g.cfg.log.file != cur.cfg.log.file

	swap_generation(s, g, carried)
	keep = true
	out.applied = true
	// After the swap: a query that pinned the old generation in between would
	// otherwise refill the emptied cache under a number no query asks for again.
	if flush {
		cache.clear_all(g.answers)
	}

	logx.set_level(logx.Level(g.cfg.log.level))
	if log_file_moved && !logx.reopen(g.cfg.log.file) {
		logx.warnf("reload: cannot open the log file %q; logging where it was", g.cfg.log.file)
	}

	rebuilt := parts_text(built, context.temp_allocator)
	logx.eventf(.Info, "reloaded", "changed=%s rebuilt=%s cache=%s", logx.quote(changed), logx.quote(rebuilt), answers)
	return
}

/*
Whether a SIGHUP reads blocklists off the disk: a `file:` list is the operator's
own, edited in place, and a SIGHUP is how dnsmasq is told to read its hosts files
again - the habit an operator brings. A downloaded list is not fetched for it,
unless its cached copy is older than `refresh` anyway; see `fetch_list`.
*/
@(private)
reads_list_files :: proc(cfg: ^config.Config) -> bool {
	if !cfg.blocking.enabled {
		return false
	}
	for list in cfg.blocking.lists {
		if list.file != "" {
			return true
		}
	}
	for list in cfg.blocking.allow_lists {
		if list.file != "" {
			return true
		}
	}
	return false
}

/*
Build the rule sets `cfg` asks for, or take them away. It reads the blocking
section and the bootstrap servers, and no other part (see `rebuild_snapshot`).

`lists_current` is `reload_filters`'s. A list that loaded before and cannot be
had now leaves the rules already in effect, and the retry it schedules applies
the change once the list is back.

On any thread, one at a time.
*/
rebuild_rules :: proc(s: ^Server, cfg: ^config.Config, allow_network: bool) -> (lists_current: bool) {
	if !cfg.blocking.enabled {
		clear_filters(s)
		// The line a rebuild ends with, as `reload_filters` logs its own.
		logx.infof("filter: blocking is off; no rules in effect")
		return true
	}
	return reload_filters_from(s, cfg, allow_network)
}

/*
Hold every key that needs a restart at the value the process started with, and
name the ones the file changed.

The listeners and the metrics endpoint, because their sockets were bound before
privileges were dropped: a port below 1024 cannot be bound again, and the event
loops that serve them are started once. The loop count and the connection
table, because neither is resized in place. And the
account, because root, once given up, cannot be had back - nor, with it, the
handover of the blocklist cache directory to that account. The certificates under
`listeners.dot` and `listeners.doh` are still read again on every SIGHUP, from
the paths the process started with.

Held at the starting value rather than at the previous reload's, which is the
same value for every key here - none of them has ever changed while running -
and is the one whose strings live as long as the process.
*/
@(private)
keep_restart_only :: proc(boot, cfg: ^config.Config, allocator := context.allocator) -> []string {
	changed := make([dynamic]string, allocator)
	// A reader count both files leave to the machine moves with the CPUs it can
	// see, and nothing the operator wrote changed. It is the loop count, which is
	// fixed for the life of the process.
	if boot.server.sizing.derived_udp_readers && cfg.server.sizing.derived_udp_readers {
		cfg.listeners.udp.readers = boot.listeners.udp.readers
	}
	hold(&changed, "listeners.udp", boot.listeners.udp, &cfg.listeners.udp)
	hold(&changed, "listeners.tcp", boot.listeners.tcp, &cfg.listeners.tcp)
	hold(&changed, "listeners.dot", boot.listeners.dot, &cfg.listeners.dot)
	hold(&changed, "listeners.doh", boot.listeners.doh, &cfg.listeners.doh)
	hold(&changed, "metrics", boot.metrics, &cfg.metrics)
	/*
	Not keys, and nothing a reload changes: the heavy decode slots are set once,
	process-wide, and the retired keys do nothing whatever the file says about
	them - `reload_config` has already said what this file names.
	*/
	cfg.server.heavy_decodes = boot.server.heavy_decodes
	cfg.retired = boot.retired
	hold(&changed, "server.max_connections", boot.server.max_connections, &cfg.server.max_connections)
	// Unnamed when both files leave it to be derived: it moves with
	// `max_connections`, which is already the key to name.
	hold(
		&changed,
		"server.max_connections_per_prefix",
		boot.server.max_connections_per_prefix,
		&cfg.server.max_connections_per_prefix,
		boot.server.sizing.derived_per_prefix && cfg.server.sizing.derived_per_prefix,
	)
	hold(&changed, "server.user", boot.server.user, &cfg.server.user)
	hold(&changed, "server.group", boot.server.group, &cfg.server.group)
	// Handed to `server.user` at startup, as root; a directory named afterwards
	// would be one the process cannot write its cached lists into.
	hold(&changed, "blocking.cache_dir", boot.blocking.cache_dir, &cfg.blocking.cache_dir)

	/*
	What the loader derives where the file leaves a figure unset is derived again
	from the machine the process started on, so that a memory limit moved since
	does not move a figure nobody wrote; where the file names it, it is the
	operator's and it reloads. The chain-walk bound then follows whichever
	`max_pending` is in effect, since it is a share of it.

	The record of what was derived is the starting one for the keys held above,
	and the new file's for the figures derived here.
	*/
	derived := cfg.server.sizing
	cfg.server.sizing = boot.server.sizing
	cfg.server.sizing.derived_chain_walks = derived.derived_chain_walks
	cfg.server.sizing.derived_connection_walks = derived.derived_connection_walks
	cfg.server.sizing.derived_max_pending = derived.derived_max_pending
	if derived.derived_max_pending {
		cfg.server.max_pending = config.derive_max_pending(boot.server.sizing.machine)
	}
	if derived.derived_chain_walks {
		cfg.dnssec.max_chain_walks = config.derive_chain_walks(cfg.server.max_pending)
	}
	if derived.derived_connection_walks {
		cfg.dnssec.max_connection_walks = config.derive_chain_walks(cfg.server.max_connections)
	}
	return changed[:]
}

/*
Whether the rule sets have to be built again: everything in `blocking` but the
keys read per query or per tick - the response a block is answered with, the
addresses a `custom` one carries, its TTL and the refresh interval - which take
effect without one. A rebuild holds
two sets of every list in memory at once and may download them, which is not a
price a new `block_ttl` should pay. Read off the type the other way round, so a
key added to the section later rebuilds until it is listed here. With blocking
off on both sides there are no sets to build or take away, as `policy_changed`
reads `dnssec` and `rebind`.
*/
@(private)
rules_changed :: proc(a, b: config.Blocking_Config) -> bool {
	if !a.enabled && !b.enabled {
		return false
	}
	x, y := a, b
	x.response, x.block_ttl, x.refresh = y.response, y.block_ttl, y.refresh
	x.custom_ipv4, x.custom_ipv6 = y.custom_ipv4, y.custom_ipv6
	return differs(x, y)
}

@(private)
hold :: proc(changed: ^[dynamic]string, name: string, running: $T, loaded: ^T, derived := false) {
	if differs(running, loaded^) {
		if !derived {
			append(changed, name)
		}
		loaded^ = running
	}
}

/*
The top-level sections that differ, by the name they have in the file.

Read off the type rather than listed, so a section added later is reported
without anybody remembering to add it here.
*/
@(private)
changed_sections :: proc(a, b: ^config.Config, allocator := context.allocator) -> string {
	names := make([dynamic]string, context.temp_allocator)
	for field in reflect.struct_fields_zipped(config.Config) {
		x := reflect.struct_field_value(a^, field)
		y := reflect.struct_field_value(b^, field)
		if !reflect.equal(x, y, including_indirect_array_recursion = true) {
			append(&names, field.name)
		}
	}
	return strings.join(names[:], ",", allocator)
}

@(private)
parts_text :: proc(parts: Parts, allocator := context.allocator) -> string {
	names := make([dynamic]string, context.temp_allocator)
	for part in Part {
		if part in parts {
			name, _ := reflect.enum_name_from_value(part)
			append(&names, strings.to_lower(name, context.temp_allocator))
		}
	}
	if len(names) == 0 {
		return "none"
	}
	return strings.join(names[:], ",", allocator)
}

/*
Take every rule out of effect, for a reload that turns blocking off.

What is checked per query is `blocking.enabled`, so this is about the memory:
the sets would otherwise sit there unread until the process ended.
*/
@(private)
clear_filters :: proc(s: ^Server) {
	old_block, old_allow := filter.engine_swap(s.filters, nil, nil)
	filter.set_destroy(old_block)
	filter.set_destroy(old_allow)
	delete(s.lists_loaded)
	s.lists_loaded = nil
}
