package main

import "core:fmt"
import "core:mem/virtual"
import "core:os"
import "core:strings"
import "core:sync"
import "core:sys/posix"
import "core:thread"
import "core:time"
import "elodin:cache"
import "elodin:config"
import "elodin:dns"
import "elodin:filter"
import "elodin:logx"
import "elodin:loop"
import "elodin:privdrop"
import "elodin:server"

USAGE :: `elodin - a filtering DNS forwarder

usage:
  elodin [--config <path>] [--check] [--no-fetch] [--version]

options:
  -c, --config <path>  configuration file (default: /etc/elodin/elodin.yaml)
      --check          load and validate the configuration, then exit
      --no-fetch       do not download remote blocklists at startup
  -v, --version        print the version and exit
  -h, --help           print this message
`

Options :: struct {
	config_path: string,
	check_only:  bool,
	no_fetch:    bool,
}

/*
Set by the signal handler, read by the maintenance loop.

A handler may not do much - it interrupts a thread wherever it happened to be,
so anything taking a lock or allocating can deadlock the process it was meant
to stop. Setting a flag is safe, and the loop is what turns that into an
orderly shutdown.
*/
@(private)
stop_requested: bool

/*
Set by the SIGHUP handler, consumed by the maintenance loop.

Unlike `stop_requested` this never needs to be reset by the handler: the loop
clears it the moment it acts on it, so a second SIGHUP arriving before that
just asks for the same thing again rather than escalating to anything.
*/
@(private)
reload_requested: bool

@(private)
on_reload_signal :: proc "c" (sig: posix.Signal) {
	sync.atomic_store(&reload_requested, true)
}

@(private)
on_stop_signal :: proc "c" (sig: posix.Signal) {
	if !sync.atomic_exchange(&stop_requested, true) {
		return
	}
	/*
	A second signal is an operator saying the first is taking too long. Put the
	default disposition back and let this one through, so nobody is ever held
	by a shutdown that has stopped making progress - a connection waiting out a
	client timeout, most likely.

	Both calls are on the short list of what a handler may do.
	*/
	act: posix.sigaction_t
	act.sa_handler = nil // SIG_DFL
	_ = posix.sigaction(sig, &act, nil)
	_ = posix.kill(posix.getpid(), sig)
}

/*
Ask for an orderly shutdown on the signals that mean one.

SIGTERM is what an init system sends; SIGINT is Ctrl-C. Without these the
default disposition applies and the process is simply terminated, which means
nothing is put away: connections are cut mid-answer, and the teardown that
drains the queries in flight before releasing what they are using never runs
at all.
*/
install_stop_handlers :: proc() {
	act: posix.sigaction_t
	act.sa_handler = on_stop_signal
	for sig in ([]posix.Signal{.SIGTERM, .SIGINT}) {
		if posix.sigaction(sig, &act, nil) != .OK {
			fmt.eprintfln("elodin: cannot install a handler for %v; it will terminate the process instead", sig)
		}
	}
}

/*
SIGHUP asks the maintenance loop to reload the DoT/DoH certificates from the
paths already in the configuration, without restarting the process.

Nothing else about the configuration is reloaded - listener addresses, the
upstream set, blocking, all of that still needs a restart - but a certificate
renewed in place by certbot or its equivalent is the one thing that otherwise
forces a resolver to bounce on a schedule it does not control.
*/
install_reload_handler :: proc() {
	act: posix.sigaction_t
	act.sa_handler = on_reload_signal
	if posix.sigaction(.SIGHUP, &act, nil) != .OK {
		fmt.eprintfln("elodin: cannot install a handler for SIGHUP; it will terminate the process instead")
	}
}

@(private)
Wait_Outcome :: enum u8 {
	Tick,
	Stop,
	Reload,
	// The rebuild of the rule sets is over, and waits to be collected.
	Rebuilt,
}

/*
Sleep until the next tick, or until a signal asks for something sooner.

Sliced rather than left as one long sleep: a handler can only set a flag, so
the loop has to come back and look. Anything less often than this and an
operator waits on a service that has already been told to go - or, for
`Reload`, on a certificate that is already sitting on disk waiting to be
picked up. `Reload` cuts the wait short rather than sitting out the rest of
the tick, which otherwise could be the better part of `TICK`, and so does
`Rebuilt`, as a reload may have asked for another. Neither moves `deadline`,
so the housekeeping on the tick keeps its pace. `Rebuilt` comes before
`Reload`, so a SIGHUP that lands as a rebuild ends finds it collected and starts
its own at once.
*/
@(private)
wait_for_tick :: proc(deadline: time.Tick, rebuild: ^server.Rebuild) -> Wait_Outcome {
	SLICE :: 200 * time.Millisecond
	for {
		if sync.atomic_load(&stop_requested) {
			return .Stop
		}
		if server.rebuild_done(rebuild) {
			return .Rebuilt
		}
		if sync.atomic_exchange(&reload_requested, false) {
			return .Reload
		}
		remaining := time.tick_diff(time.tick_now(), deadline)
		if remaining <= 0 {
			return .Tick
		}
		time.sleep(min(SLICE, remaining))
	}
}

/*
One line saying how large this instance is and why.

Worth printing on every start, not only when something was derived: a loop
count or an in-flight bound that came from the machine is one an operator has
never seen in a file, so
leaving it out of the log would make the first question about memory or
throughput unanswerable from anything but the source. `--check` prints the same
line, and derives it the same way, so it answers the question on the machine the
config is bound for rather than in the abstract.
*/
// "1 usable CPU" rather than "1 usable CPUs", which is a machine small enough
// that this line is exactly the one an operator reads twice.
@(private)
usable_cpus :: proc(cpus: int) -> string {
	if cpus == 1 {
		return "1 usable CPU"
	}
	return fmt.tprintf("%d usable CPUs", cpus)
}

/*
What the figures in the sizing line came from: the loops from the CPUs and the
in-flight bound from the memory, each named only when it was derived, and "from
the configuration" when neither was. The heavy decode slots always come from the
memory, but they are not a key, so they credit no machine on their own.
*/
@(private)
sizing_origin :: proc(s: config.Server_Config) -> string {
	m := s.sizing.machine
	cpus, memory: string
	if s.sizing.derived_udp_readers {
		cpus = usable_cpus(m.cpus) if m.cpus > 0 else "one loop, as this machine's CPUs could not be counted"
	}
	if s.sizing.derived_max_pending {
		memory = fmt.tprintf("%#.1M", m.memory) if m.memory > 0 else "the default max_pending, as this machine's memory could not be measured"
	}
	switch {
	case cpus != "" && memory != "":
		return fmt.tprintf("derived from %s and %s", cpus, memory)
	case cpus != "":
		return fmt.tprintf("derived from %s", cpus)
	case memory != "":
		return fmt.tprintf("derived from %s", memory)
	}
	return "from the configuration"
}

/*
Where the reader count came from, when the machine is what decided it.

Empty for a figure an operator wrote, for the same reason `sizing_origin`
returns "from the configuration" rather than naming a machine it never
consulted: crediting the hardware with somebody's own number sends them looking
for a setting they already have.
*/
@(private)
udp_readers_origin :: proc(s: config.Server_Config) -> string {
	if !s.sizing.derived_udp_readers {
		return ""
	}
	if s.sizing.machine.cpus > 0 {
		return fmt.tprintf(" (derived from %s)", usable_cpus(s.sizing.machine.cpus))
	}
	return " (derived; this machine's CPUs could not be counted)"
}

/*
`chain_walks` rides along with `max_pending` because it is derived from it and
spent out of it: it is how many of the queries in flight may be waiting on a DS
or DNSKEY lookup at once, the rest being reserved for what needs no chain walk.
Printed only where validation is on, and printed at all because this is the one
place `--check` can show a number an operator is otherwise told to raise without
being told what it is. See `config.derive_chain_walks`.

`loops` is `listeners.udp.readers`, which names it under that key: one event loop
per reader, each a thread. `heavy_decodes` is how many requests may decode past
the ordinary allowance at once (`dns.REQUEST_ORDINARY_DECODE`), which is not a
key and is said here so it can be read.
*/
@(private)
sizing_line :: proc(s: config.Server_Config, loops: int, chain_walks := 0, connection_walks := 0) -> string {
	walks := fmt.tprintf(" chain_walks=%d connection_walks=%d", chain_walks, connection_walks) if chain_walks > 0 else ""
	return fmt.tprintf(
		"loops=%d max_pending=%d heavy_decodes=%d%s (%s)",
		loops,
		s.max_pending,
		s.heavy_decodes,
		walks,
		sizing_origin(s),
	)
}

/*
One line saying who may ask.

Printed on every start and under `--check`, for the same reason as the sizing
line: the default was never written in anybody's file, so an operator debugging
a client that gets no answer has nowhere else to read it. The empty list gets a
warning rather than a line, because a resolver reachable from the internet that
answers all of it is the condition every open-resolver scanner is looking for,
and an operator who meant it should still see it said out loud once a start.
*/
@(private)
allow_from_line :: proc(s: config.Server_Config) -> string {
	if len(s.allow_from) == 0 {
		return "server.allow_from is empty: queries are answered from any source, including the internet"
	}
	texts := make([]string, len(s.allow_from), context.temp_allocator)
	for p, i in s.allow_from {
		texts[i] = config.format_prefix(p, context.temp_allocator)
	}
	return fmt.tprintf(
		"answering queries from %s; every other source is refused",
		strings.join(texts, ", ", context.temp_allocator),
	)
}

/*
Inline `blocking.rules` entries written in the shape of a dnsmasq route.

`server=/corp.example/10.0.0.1` is dnsmasq for "send this zone to that server",
and it is the exact string an operator migrating from dnsmasq reaches for when
they want `upstream.zones`. Pasted into `blocking.rules` it does nothing:
`parse_adblock_line` skips a `server=` line that names a server, because only
`server=/d/` - no server, so dnsmasq answers d locally - means a blackhole in a
downloaded list. So the zone the operator meant to route goes on being resolved
by `upstream.servers`, which looks exactly like the route not working. Written
without a server, it blackholes the zone instead.

Neither is what the operator meant, and both are a long way from "the rule you
wrote is not a route", so it is worth its own line.
*/
route_shaped_rules :: proc(cfg: ^config.Config, allocator := context.allocator) -> []string {
	out := make([dynamic]string, 0, 0, allocator)
	for rule in cfg.blocking.rules {
		if strings.has_prefix(strings.trim_space(rule), "server=/") {
			append(&out, rule)
		}
	}
	for rule in cfg.blocking.allow_rules {
		if strings.has_prefix(strings.trim_space(rule), "server=/") {
			append(&out, rule)
		}
	}
	return out[:]
}

/*
What each route gives up, said once per route rather than left to be noticed.

A route does three things and only the first is what the operator wrote it for:
the zone goes to its own servers, its names stop being validated, and its
answers stop being checked for private addresses. The last two follow from what
a route asserts - that a local authority answers this zone - and for the zone
`upstream.zones` was built for they are what makes it work at all. A network's
own `corp.example` is unsigned under a parent that delegates nothing to it, and
its addresses are RFC 1918 by definition.

They are the wrong two for a zone that is public and signed, which a route can
equally be pointed at: sending one domain to a filtering resolver or down a VPN
is ordinary conditional forwarding, and there the route silently turns off a
check that was working. Nothing at load can tell the two apart - whether a zone
is signed is a question only the DNS can answer - so this says what happened and
leaves the judgement where the knowledge is.

Only what is actually given up. With `dnssec.enabled` off there is no validation
to lose and with `rebind.enabled` off there is no guard to be exempt from, so a
configuration with both off gets no line: a warning that names a protection the
file already turned off is noise standing where a real one should be. A trust
anchor over the routed zone is the third way to have given nothing up, and the
one that is easiest to get wrong here: the anchor stands the bypass down, so the
zone is validated like any other and `config.route_is_anchored` takes the first
half of the line back. Telling a site that anchored its own zone that routing it
turned validation off would be the warning misfiring at the most careful file
there is.
*/
route_implication_warning :: proc(
	cfg: ^config.Config,
	route: config.Zone_Route,
	allocator := context.allocator,
) -> (
	text: string,
	worth_saying: bool,
) {
	if len(route.domains) == 0 {
		return "", false
	}
	// Validation is given up only where it was being done: with `dnssec.enabled`
	// off there is nothing to lose, and with an anchor over every name the route
	// claims the bypass never applies to them in the first place.
	insecure := cfg.dnssec.enabled && !config.route_is_anchored(cfg, route)
	if !insecure && !cfg.rebind.enabled {
		return "", false
	}

	zones := strings.join(route.domains, ", ", allocator)
	switch {
	case insecure && cfg.rebind.enabled:
		return fmt.aprintf(
			"the route for %s serves that zone insecure (DNSSEC validation off for it) and exempt from rebind protection, which is what a route asserts about a zone a local authority answers; if it is a public signed zone, those are two checks you are giving up",
			zones,
			allocator = allocator,
		), true
	case insecure:
		return fmt.aprintf(
			"the route for %s serves that zone insecure (DNSSEC validation off for it), which is what a route asserts about a zone a local authority answers; if it is a public signed zone, that is a check you are giving up",
			zones,
			allocator = allocator,
		), true
	case cfg.rebind.enabled:
		return fmt.aprintf(
			"the route for %s exempts that zone from rebind protection, which is what a route asserts about a zone a local authority answers; if it is a public zone, that is a check you are giving up",
			zones,
			allocator = allocator,
		), true
	}
	// Unreachable: the guard above has already left for the file that gives up
	// neither, so one of the three arms holds. Odin wants the terminator.
	return "", false
}

/*
One line per rule found, worded for both lists.

`blocking.allow` (`cfg.blocking.allow_rules`) is scanned as well as
`blocking.rules`. There `build_filter_sets` prefixes the entry with `@@` before
parsing it, which puts the string past `parse_adblock_line`'s dnsmasq branch and
into the generic one, where the `/` still in it is refused by `set_add`. So under
`blocking.allow` the rule adds nothing, and under `blocking.rules` it adds
nothing or blackholes the zone, as above. Both lists are named by the key an operator writes rather
than by the field they land in, so the line can be searched for in the file it
is about.
*/
route_rule_warning :: proc(rule: string, allocator := context.allocator) -> string {
	return fmt.aprintf(
		"blocking rule %q is a list rule, not a route: it does not send the zone anywhere - under blocking.rules it is discarded if it names a server and blackholes the zone if not, and under blocking.allow it is discarded; to send a zone to its own server use upstream.zones",
		strings.trim_space(rule),
		allocator = allocator,
	)
}

main :: proc() {
	// Writing to a socket whose peer has gone away raises SIGPIPE, whose
	// default disposition kills the process. A client hanging up mid-answer is
	// completely routine, so the signal is ignored and the write reports EPIPE
	// through the normal error path instead.
	posix.sigignore(.SIGPIPE)
	// Before the first thread or large allocation, so no mapping predates it.
	loop.disable_huge_pages()
	install_stop_handlers()
	install_reload_handler()

	opts, ok := parse_args()
	if !ok {
		os.exit(2)
	}

	/*
	The configuration gets an arena, and is released as one thing at the end.

	`Config` is a tree of strings that are not the tree's to free one by one: a
	YAML scalar is usually a view into the file text, and sometimes - a block
	scalar, a quoted one carrying an escape - a buffer the parser built instead,
	so a field's bytes may live in either and nothing records which. Freeing the
	document would strand the fields pointing into it, and freeing the file text
	would strand the rest; there is no order that works, which is why `yaml` has
	no destroy at all.

	An arena sidesteps the question by making the lifetime one decision instead
	of hundreds, and it is what every other caller of the loader already does -
	the tests all hand it a scratch arena. This was the one that handed it the
	heap and never came back, so a `--check` run, and every run of the server,
	ended holding the whole parse.

	Registered before `logx.shutdown` so it is released after it: defers run in
	reverse, and the log's own file name is one of these strings.
	*/
	config_arena: virtual.Arena
	if arena_err := virtual.arena_init_growing(&config_arena); arena_err != nil {
		fmt.eprintfln("elodin: cannot reserve memory for the configuration: %v", arena_err)
		os.exit(1)
	}
	defer virtual.arena_destroy(&config_arena)

	cfg, load_err := config.load_file(opts.config_path, virtual.arena_allocator(&config_arena))
	if e, has := load_err.?; has {
		fmt.eprintfln("elodin: %s is not usable:", opts.config_path)
		for msg in e.messages {
			fmt.eprintfln("  - %s", msg)
		}
		os.exit(1)
	}

	if !logx.init(logx.Level(cfg.log.level), cfg.log.file) {
		fmt.eprintfln("elodin: cannot open the log file %q, logging to stderr instead", cfg.log.file)
	}
	defer logx.shutdown()

	/*
	Resolved here rather than where it is used, so a name nobody has an account
	for is a startup error instead of a process that comes up, takes port 53 and
	only then finds it has nowhere to go. It also puts the account under
	`--check`, which is where an operator looks before restarting a resolver.
	*/
	service: privdrop.Identity
	if cfg.server.user != "" {
		err: privdrop.Error
		service, err = privdrop.resolve(cfg.server.user, cfg.server.group)
		if err != .None {
			fmt.eprintfln(
				"elodin: server.user %q / server.group %q is not usable: %s",
				cfg.server.user,
				cfg.server.group,
				privdrop.explain(err),
			)
			os.exit(1)
		}
	}

	misrouted := route_shaped_rules(&cfg, context.temp_allocator)

	if opts.check_only {
		fmt.printfln("%s is valid: %d upstreams, %d zone routes, %d blocklists, %d rewrites",
			opts.config_path,
			len(cfg.upstream.servers),
			len(cfg.upstream.zones),
			len(cfg.blocking.lists),
			len(cfg.rewrites))
		fmt.printfln(
			"  %s",
			sizing_line(
				cfg.server,
				max(cfg.listeners.udp.readers, 1),
				cfg.dnssec.max_chain_walks if cfg.dnssec.enabled else 0,
				cfg.dnssec.max_connection_walks if cfg.dnssec.enabled else 0,
			),
		)
		fmt.printfln("  %s", allow_from_line(cfg.server))
		// Only where it applies, and without a granted figure: nothing here has
		// bound a socket, so what the kernel would allow each reader is not
		// known yet. Startup prints the same line with that filled in.
		if cfg.listeners.udp.enabled {
			fmt.printfln(
				"  udp: %s%s",
				server.udp_readers_line(cfg.listeners.udp.readers, cfg.listeners.udp.receive_buffer, 0),
				udp_readers_origin(cfg.server),
			)
		}
		// Only where it applies, as at startup: with no stream listener there is
		// no connection table for either figure to bound.
		if config.stream_listeners_enabled(cfg.listeners) {
			fmt.printfln(
				"  %s",
				server.connection_limits_line(cfg.server.max_connections, cfg.server.max_connections_per_prefix),
			)
			/*
			The descriptor limit is deliberately *not* said here, though it bounds
			this same table and startup warns about it.

			Every other figure in these lines is read from the file being checked.
			That one would be read from whichever process runs the check - an
			interactive shell with the distribution's 1024, where the service has
			the unit's `LimitNOFILE` - so it would warn about a server that is
			fine and stay silent about one that is not, and an operator would
			reasonably read it as a statement about the server. See
			`server.descriptor_limit_line`.
			*/
		}
		/*
		The networks with budgets of their own, in the words the startup log uses.

		Here because this is where a wrong entry is cheapest to find. Nothing else
		says which prefix a client will be accounted on - the counters are not
		labelled per prefix, deliberately - so an entry that does not match the
		clients it was written for shows up in these lines and in no number
		anywhere. An operator reads `--check` before restarting, which is before
		the mistake is serving anybody.
		*/
		if cfg.server.rate_limit.enabled {
			// What the two rate-limit figures multiply out to, which is the
			// quantity being chosen, and - where the estimate is one no answer
			// can reach - that it charges nothing and is reported nowhere else.
			if text, say := server.rate_limit_denomination_line(
				cfg.server.rate_limit.responses_per_second,
				cfg.server.rate_limit.response_size_estimate,
				cfg.server.max_udp_response,
				context.temp_allocator,
			); say {
				fmt.printfln("  %s", text)
			}
			if text, say := server.response_size_estimate_warning(
				cfg.server.rate_limit.response_size_estimate,
				cfg.server.max_udp_response,
				context.temp_allocator,
			); say {
				fmt.printfln("  warning: %s", text)
			}
			for line in server.rate_limit_override_lines(
				cfg.server.rate_limit.overrides,
				cfg.server.rate_limit.response_size_estimate,
				cfg.server.max_udp_response,
				context.temp_allocator,
			) {
				fmt.printfln("  %s", line)
			}
		}
		for rule in misrouted {
			fmt.printfln("  warning: %s", route_rule_warning(rule, context.temp_allocator))
		}
		for route in cfg.upstream.zones {
			if text, say := route_implication_warning(&cfg, route, context.temp_allocator); say {
				fmt.printfln("  warning: %s", text)
			}
		}
		if text, say := mixed_validation_warning(&cfg); say {
			fmt.printfln("  warning: %s", text)
		}
		if text, say := connection_memory_warning(&cfg); say {
			fmt.printfln("  warning: %s", text)
		}
		for key in cfg.retired {
			fmt.printfln("  warning: %s", config.retired_warning(key))
		}
		return
	}

	logx.eventf(.Info, "starting", "version=%s", logx.quote(server.VERSION))
	logx.eventf(
		.Info,
		"sizing",
		"loops=%d max_pending=%d heavy_decodes=%d origin=%s",
		max(cfg.listeners.udp.readers, 1),
		cfg.server.max_pending,
		cfg.server.heavy_decodes,
		logx.quote(sizing_origin(cfg.server)),
	)
	for key in cfg.retired {
		logx.warnf("%s", config.retired_warning(key))
	}
	log_config_warnings(&cfg)
	// Before anything decodes on behalf of a request, and once: the slots are
	// process-wide and a reload does not move them.
	dns.set_heavy_decodes(cfg.server.heavy_decodes)
	run(&cfg, opts, service)
}

/*
What the configuration gives up or leaves open, said at startup and again after
every reload that puts a new one into effect, where an operator who has just
edited the file is reading. `--check` prints the same lines from the same
procedures, so the readings cannot drift apart.
*/
@(private)
log_config_warnings :: proc(cfg: ^config.Config) {
	misrouted := route_shaped_rules(cfg, context.temp_allocator)
	if len(cfg.server.allow_from) == 0 {
		logx.warnf("%s", allow_from_line(cfg.server))
	} else {
		logx.infof("%s", allow_from_line(cfg.server))
	}
	// Said under `--check` as well, which is where an operator looks before
	// restarting; both readings go through the same procedure so the two can
	// not drift apart.
	for rule in misrouted {
		logx.warnf("%s", route_rule_warning(rule, context.temp_allocator))
	}
	for route in cfg.upstream.zones {
		if text, say := route_implication_warning(cfg, route, context.temp_allocator); say {
			logx.warnf("%s", text)
		}
	}
	/*
	Said out loud for the same reason an empty allow list is: with the table
	off, a .onion query is forwarded, which tells the upstream operator that
	somebody here is reaching for one specific hidden service (RFC 7686 section
	2). Nothing is logged when it is on - that is the default.

	`onion` alone gets its own line, since that setting is a claim about the
	upstream rather than about this table: it says the upstream is a Tor-aware
	resolver, which is the one deployment where forwarding is right, and it is
	worth reading back to an operator who set it for some other reason.

	There is no second line under `enabled: false` telling an operator with a
	local tor to write `onion: false` as well: `special_use_deferred` takes a
	forwarded `.onion` name out of the chain whichever key forwarded it, so the
	two keys do not have to be written together to work, and a line telling an
	operator to write both would be telling them to do something that changes
	nothing.
	*/
	if text, say := mixed_validation_warning(cfg); say {
		logx.warnf("%s", text)
	}
	if text, say := connection_memory_warning(cfg); say {
		logx.warnf("%s", text)
	}

	switch {
	case !cfg.special_use.enabled:
		logx.warnf("special_use.enabled is off: localhost., onion., invalid. and the private reverse zones are forwarded to the upstream")
		// The second half of what this key does. `special_use_deferred` fires
		// on this key as well as on `onion`, so an operator who set it for a
		// reason having nothing to do with tor - wanting their own hosts file to
		// own `localhost.`, say - is also giving up the root's signed
		// nonexistence proof for `.onion`, and this line is the only place they
		// will see that. The warning it replaced said the opposite, that they
		// had to write `onion: false` to get here.
		if cfg.dnssec.enabled {
			logx.warnf("special_use.enabled is off: .onion answers are served insecure, as nothing under a zone the root proves is not delegated can be signed")
		}
	case !cfg.special_use.onion:
		logx.warnf("special_use.onion is off: .onion queries are forwarded, which is only safe to a Tor-aware upstream")
	}
}

/*
Validation off and a group with somewhere else to go: the one arrangement where
the sweep in `upstream.resolve_insisting` can turn a rejected answer into a
served one.

A member that validates answers SERVFAIL for a zone it found bogus. The sweep
asks the next member, and if that one does not validate, what comes back is the
forgery - cached, and served to every client behind this server. `usable_rcode`
keeps the SERVFAIL where the member says why in an RFC 8914 extended error, but
most do not by default: Unbound needs `ede: yes` and dnsmasq has none, so the
check cannot be relied on and this says so once rather than pretending
otherwise.

Said as a condition rather than as a verdict, because from here the two cannot
be told apart: a group of two upstreams that both validate is in no danger from
this, a group where one does and one does not is, and nothing in the
configuration says which. The line names the arrangement and what would follow
from it, and an operator who knows their upstreams reads it in one go.

One procedure for the startup log and for `--check`, which is where an operator
looks before restarting, so the two readings cannot drift apart.
*/
@(private)
mixed_validation_warning :: proc(cfg: ^config.Config) -> (text: string, say: bool) {
	if cfg.dnssec.enabled {
		return "", false
	}
	several := len(cfg.upstream.servers) > 1
	for route in cfg.upstream.zones {
		if len(route.upstream.servers) > 1 {
			several = true
		}
	}
	if !several {
		return "", false
	}
	return "dnssec.enabled is off and an upstream group has more than one server: if its members do not all validate, a SERVFAIL from one that does is asked of one that does not - see elodin_upstream_swept_rcode_total",
		true
}

// Only with a stream listener, as the connection table is theirs. The machine is
// measured here if no derivation needed it, and not stored: `sizing` reports a
// machine only where a number came from it.
@(private)
connection_memory_warning :: proc(cfg: ^config.Config) -> (text: string, say: bool) {
	if !config.stream_listeners_enabled(cfg.listeners) {
		return "", false
	}
	m := cfg.server.sizing.machine
	if m.memory == 0 {
		m = config.probe_machine()
	}
	return config.connection_memory_warning(cfg.server.max_connections, m)
}

run :: proc(cfg: ^config.Config, opts: Options, service: privdrop.Identity) {
	/*
	The event loops, one thread each, as many as `listeners.udp.readers` says:
	the usable CPUs, at most eight, unless the file names a figure. Everything
	that waits on the network runs on them - see `loop` - and each takes one UDP
	reader. Started before anything that could spawn on one.
	*/
	loops, loop_threads := start_loops(max(cfg.listeners.udp.readers, 1))

	filters := filter.engine_make()
	defer filter.engine_destroy(filters)

	s := server.Server {
		filters      = filters,
		loops        = loops,
		started      = time.now(),
		running      = true,
	}

	/*
	Everything a reload can change - the upstream groups, the cache, the
	validator, the cookie secret, the rate limiter - is built as the first
	generation, by the same procedure a SIGHUP builds the next one with. What it
	cannot build is said by the part that failed; this only ends the process.
	*/
	if !server.boot_generation(&s, cfg) {
		logx.errorf("the configuration could not be put into effect, giving up")
		os.exit(1)
	}
	// Released last of all, once nothing can be using any generation: the
	// block below drains the queries and stops the loops before this runs.
	defer server.destroy_generations(&s)

	// The main thread reads the configuration through `server.live` like any
	// other until the maintenance loop takes over, which pins per tick.
	server.pin(&s)

	defer delete(s.lists_loaded)
	lists_current := true
	// Here rather than in the loop, as a rebuild a stop leaves running writes
	// to it until the process ends; see the deferred stop below.
	rebuild: server.Rebuild
	if cfg.blocking.enabled {
		/*
		On the rebuild thread, as at every refresh, so a SIGTERM is not held by
		the downloads and no signal cuts one short (#416). Nothing listens yet,
		so a stop has nothing to drain. A SIGHUP waits for the loop.
		*/
		if !server.rebuild_start(&rebuild, &s, !opts.no_fetch) {
			// Here, then: nothing listens yet for a stop to drain.
			logx.warnf("blocklists: cannot start a thread to build the rules; building them here")
			lists_current = server.rebuild_rules(&s, server.live_config(&s), !opts.no_fetch)
		}
		for server.rebuild_busy(&rebuild) {
			if current, over := server.rebuild_collect(&rebuild); over {
				lists_current = current
				break
			}
			if sync.atomic_load(&stop_requested) {
				logx.infof("signal received, shutting down")
				os.exit(0)
			}
			// Short, as the listeners wait on it: lists loaded from the cache are
			// over in a moment.
			time.sleep(10 * time.Millisecond)
		}
	}

	/*
	A rebuild still downloading at a stop is not waited for: it is held by the
	network, for up to `FETCH_DEADLINE` a list, and what the drain below
	protects is the clients. Its thread reads the engine and `lists_loaded`, and
	allocates from this thread's allocator, so once the drain is over the process
	ends before the defers above free them. A cached copy it was writing is replaced by a rename, whole
	or not at all.
	*/
	defer if server.rebuild_busy(&rebuild) {
		// One that ended by the end of the drain is joined, and the defers above run.
		if _, over := server.rebuild_collect(&rebuild); !over {
			logx.infof("blocklists: not waiting for the rebuild in progress")
			os.exit(0)
		}
	}

	listeners: server.Listeners
	if !server.start_listeners(&s, &listeners) {
		logx.errorf("could not start every listener, shutting down")
		os.exit(1)
	}
	/*
	Shutdown, in the one order that works, which is why it is a block rather
	than separate defers.

	Deferred last so it runs first. Stopping the listeners stops the read and
	accept loops, closes their sockets and waits on every connection, but a
	query a reader admitted a moment earlier is still in flight on a fiber of
	its own. Those reach for the validator, the filters, the cache, the upstream
	group and the rate limiter - `udp_job` charges the answer it just packed to
	the prefix it is addressed to - so they are drained before any of that is
	torn down by the defers written above this one, which run after it.

	Metrics is stopped right after `stop_listeners`, not merged into it and not
	left running past the loops. `stop_listeners` is the slow, client-facing
	part: a DoT or DoH connection can hold out for `server.client_timeout`, and
	an operator scraping through that wait wants to see it happening rather than
	find the port already closed. The loops are a different hazard: the endpoint
	reads them, and `stop_loops` frees them.

	What is left on the loops after the drain is detached work nobody answers to
	- a racer still waiting out its timeout, the reader of an upstream's HTTP/2
	connection - and it is cancelled rather than waited for, since a reader lives
	as long as its connection and the connection as long as the generation,
	which is released after this.
	*/
	defer {
		server.stop_listeners(&listeners)
		server.stop_metrics(&listeners)
		server.drain_queries(&s)
		stop_loops(loops, loop_threads)
		// Freed with them: nothing after this may find a loop to start work on.
		s.loops = nil
		server.destroy_listeners(&listeners)
		// Last: a draining query can be a DoH request still building a profile,
		// and this is what it signs with.
		server.stop_profile_signer(&s)
	}

	drop_privileges(cfg, service)

	logx.eventf(
		.Info,
		"ready",
		"strategy=%v upstreams=%d cache=%v blocking=%v dnssec=%v rebind=%v",
		cfg.upstream.strategy,
		len(cfg.upstream.servers),
		cfg.cache.enabled,
		cfg.blocking.enabled,
		cfg.dnssec.enabled,
		// Named here because it is off by default and can make a name stop
		// resolving once it is not. An operator working out why an internal host
		// went missing should be able to see, in the first line the server
		// wrote, whether the thing that refuses such answers is running.
		cfg.rebind.enabled,
	)
	server.unpin(&s)

	maintenance_loop(&s, &listeners, &rebuild, opts, lists_current)
}

/*
Put root down now that the listeners hold their ports.

This is the last moment a privilege is needed and the first moment it can go:
binding below 1024 is the only thing on the way up that root was for, and
everything from here on is parsing whatever arrives on those sockets. The
sockets themselves are already open, so the process keeps serving on them
whoever it becomes.

The blocklist cache goes over first. It is the one path still opened by name
afterwards - the lists were downloaded above, as root, and a refresh some hours
later reopens them - so without this the cache would silently stop being
written the moment its owner changed. Only with blocking on, so a directory
that is not elodin's - a shared one, named but unused - is not taken over for
nothing. A reload that turns blocking on later finds it as it is; see
`docs/install.md`.

A drop that was asked for and did not happen ends the process. Carrying on
would leave it as root while the log said otherwise, which is worse than not
starting.
*/
@(private)
drop_privileges :: proc(cfg: ^config.Config, service: privdrop.Identity) {
	if cfg.server.user == "" {
		if privdrop.is_root() {
			logx.warnf(
				"running as root and server.user is not set, so every query is parsed with full privileges;",
			)
			logx.warnf(
				"set server.user, or bind the port with 'setcap cap_net_bind_service=+ep' and start unprivileged",
			)
		}
		return
	}

	if cfg.blocking.enabled && cfg.blocking.cache_dir != "" {
		if !privdrop.hand_over(cfg.blocking.cache_dir, service) {
			logx.warnf(
				"could not give %q to %s; the lists are in effect but will be re-downloaded on each start",
				cfg.blocking.cache_dir,
				cfg.server.user,
			)
		}
	}

	if err := privdrop.apply(service); err != .None {
		logx.errorf("cannot drop privileges to %s: %s", cfg.server.user, privdrop.explain(err))
		os.exit(1)
	}
	logx.infof("running as %s (uid=%d gid=%d)", cfg.server.user, service.uid, service.gid)
}

/*
Periodic housekeeping.

Runs on the main thread, which otherwise has nothing to do once the listeners
are up: expire cache entries, close idle upstream connections, start a rebuild
of the blocklists when their interval comes round and collect it when it is
over, release the configurations a reload has replaced once nothing uses them,
and reload when SIGHUP asks for it.

A rebuild still running at the stop is left to `run`.
*/
maintenance_loop :: proc(
	s: ^server.Server,
	listeners: ^server.Listeners,
	rebuild: ^server.Rebuild,
	opts: Options,
	lists_current: bool,
) {
	TICK :: 30 * time.Second
	m := Maintenance {
		rebuild      = rebuild,
		next_tick    = time.tick_add(time.tick_now(), TICK),
		last_refresh = time.now(),
		last_report  = time.tick_now(),
	}
	refresh := server.live_config(s).blocking.refresh
	if !lists_current && !opts.no_fetch && refresh > 0 {
		m.retry = server.refresh_retry(0, refresh)
		logx.warnf("blocklists: not every list is current; trying again in %v", m.retry)
	}

	for sync.atomic_load(&s.running) {
		switch wait_for_tick(m.next_tick, m.rebuild) {
		case .Stop:
			logx.infof("signal received, shutting down")
			sync.atomic_store(&s.running, false)
			continue
		case .Reload:
			reload(s, listeners, opts, &m)
		case .Rebuilt:
			collect(s, opts, &m)
		case .Tick:
			m.next_tick = time.tick_add(time.tick_now(), TICK)
			tick(s, listeners, opts, &m)
		}
		if released := server.reap_generations(s); released > 0 {
			logx.debugf("reload: released %d replaced configuration(s)", released)
		}
		free_all(context.temp_allocator)
	}
}

// What the maintenance loop carries from one turn to the next.
@(private)
Maintenance :: struct {
	rebuild:        ^server.Rebuild,
	// Monotonic, so a step of the wall clock neither stalls nor rushes the tick.
	next_tick:      time.Tick,
	// The running rebuild is the one a reload asked for, which starts the
	// retries afresh; a refresh's goes on from `retry`.
	after_reload:   bool,
	// A reload changed the rules while a rebuild ran under the configuration
	// before it, or when no thread could be had: another follows once that one
	// is over, or at the next tick.
	rebuild_again:  bool,
	// On the wall clock, as the cached copies' ages are by their mtime: a
	// monotonic clock stops while the machine is suspended, and a day's
	// refresh would wait for a day awake.
	last_refresh:   time.Time,
	// Zero while the lists are current; otherwise the wait before the next
	// attempt, which `refresh_retry` stretches on each failure (#411).
	retry:          time.Duration,
	// Monotonic, as `next_tick` is, so a step of the wall clock neither holds
	// nor hurries the report.
	last_report:    time.Tick,
	// What the kernel had dropped at the last report, so the line below is
	// about the interval rather than about the whole run. A counter that only
	// grows says nothing about whether it is still growing.
	last_udp_drops: u64,
}

/*
What SIGHUP asks for, in the order an operator would want it.

The log first, so everything the reload says lands where logrotate expects it:
`logrotate` renames the file and sends the signal, and this is what opens the
name again. Then the configuration, which may move the log somewhere else and
says so. The certificates last, read from the paths the process started with -
whether or not the rest of the file was usable, since a renewal that happens to
coincide with a typo in the file is still a renewal.

None of it waits for a rebuild of the rules in progress. One the configuration
asks for starts once that is over; see `collect`.
*/
@(private)
reload :: proc(s: ^server.Server, listeners: ^server.Listeners, opts: Options, m: ^Maintenance) {
	file := server.live_config(s).log.file
	reopened := logx.reopen(file)
	logx.infof("SIGHUP received, reloading the configuration and the TLS certificates")
	if !reopened {
		logx.warnf("cannot open the log file %q again; logging where it was", file)
	}

	out := server.reload_config(s, opts.config_path)
	if out.applied {
		server.pin(s)
		log_config_warnings(server.live(s).cfg)
		server.unpin(s)
	}
	if out.blocking {
		// One over and not yet collected is not in progress.
		if server.rebuild_done(m.rebuild) {
			collect(s, opts, m)
		}
		if server.rebuild_busy(m.rebuild) {
			logx.infof("reload: the rules are rebuilt once the rebuild in progress is over")
			m.rebuild_again = true
		} else {
			start_rebuild(s, opts, m, after_reload = true)
		}
	}

	// From the paths the process started with, which need no pin.
	server.reload_tls(s, listeners)
}

// Take in a rebuild that is over, and start the one a reload asked for
// meanwhile.
@(private)
collect :: proc(s: ^server.Server, opts: Options, m: ^Maintenance) {
	current, over := server.rebuild_collect(m.rebuild)
	if !over {
		return
	}
	// Built under the configuration a reload has since replaced: the rebuild it
	// asked for decides what is current, and starts the retries afresh.
	if m.rebuild_again {
		start_rebuild(s, opts, m, after_reload = true)
		return
	}
	m.last_refresh = time.now()
	refresh := server.live_config(s).blocking.refresh
	switch {
	case current || opts.no_fetch || refresh <= 0:
		m.retry = 0
	case:
		m.retry = server.refresh_retry(0 if m.after_reload else m.retry, refresh)
		logx.warnf("blocklists: not every list is current; trying again in %v", m.retry)
	}
	m.after_reload = false
}

/*
Start the rebuild a refresh or a reload asks for. With no thread to be had it
stays wanted, and the next tick tries again: run on this thread, it would hold
the signals the loop acts on (#416). A refresh that cannot start is still due.
*/
@(private)
start_rebuild :: proc(s: ^server.Server, opts: Options, m: ^Maintenance, after_reload: bool) {
	if server.rebuild_start(m.rebuild, s, !opts.no_fetch) {
		m.after_reload = after_reload
		m.rebuild_again = false
		return
	}
	m.rebuild_again = m.rebuild_again || after_reload
	logx.warnf("blocklists: cannot start a thread to rebuild the rules; trying again at the next tick")
}

// Everything the maintenance loop does on an ordinary tick, under the
// generation current at its start.
@(private)
tick :: proc(s: ^server.Server, listeners: ^server.Listeners, opts: Options, m: ^Maintenance) {
	server.pin(s)
	defer server.unpin(s)
	cfg := server.live(s).cfg
	answers := server.live(s).answers

	if answers != nil {
		if removed := cache.sweep(answers); removed > 0 {
			logx.debugf("cache: swept %d expired entries", removed)
		}
	}
	if closed := server.groom_upstreams(s); closed > 0 {
		logx.debugf("upstream: closed %d idle connections", closed)
	}
	if dropped := server.sweep_validator(s); dropped > 0 {
		logx.debugf("dnssec: dropped %d expired zone keys", dropped)
	}

	refreshing := cfg.blocking.enabled && !opts.no_fetch && cfg.blocking.refresh > 0
	if !server.rebuild_busy(m.rebuild) {
		switch {
		case m.rebuild_again:
			start_rebuild(s, opts, m, after_reload = true)
		case refreshing && time.since(m.last_refresh) >= server.refresh_wait(m.retry, cfg.blocking.refresh):
			logx.infof("refreshing blocklists")
			start_rebuild(s, opts, m, after_reload = false)
		}
	}

	if time.tick_since(m.last_report) >= 5 * time.Minute {
		report(s, answers)
		report_udp_drops(listeners, &m.last_udp_drops)
		m.last_report = time.tick_now()
	}
}

/*
Say when the kernel is throwing datagrams away before this server can read them.

The one loss nothing else in this process can report. A datagram that overflows
a reader's receive queue never reaches a read, so it is charged to no counter on
the query path and its absence is indistinguishable from a client that did not
ask - which is why the condition is normally learned from complaints rather than
from the server. `elodin_udp_receive_drops_total` carries the same number per
reader for anybody scraping; this line is for the operator who is not.

A `warn` because it is the point past which this server's fairness properties
stop applying: the thing deciding whose queries are served is the kernel's queue
rather than the rate limiter's budget, and no setting in the file can reach it.
Bounded to one line per five-minute report, and only when the figure has moved,
so a server that dropped datagrams once at three in the morning says so once.

What the line does not do is name the cause. `sk_drops` is the socket's whole
count of datagrams the kernel would not deliver, and a full receive queue is the
usual reason but not the only one - a bad UDP checksum is charged here too. A
handful over five minutes on a busy interface is corruption on the wire; a
figure that climbs with the load is the queue. The line says which number moved
and leaves the reader to tell those apart, rather than sending somebody to raise
`readers` over a bad cable.
*/
@(private)
report_udp_drops :: proc(l: ^server.Listeners, last: ^u64) {
	total, ok := server.udp_receive_drops(l)
	if !ok {
		return
	}
	defer last^ = total
	// Counters that only grow, so anything but growth is the kernel having
	// nothing new to report - or, if a figure ever went backwards, a socket
	// this process no longer owns, which is not something to raise an alarm over.
	if total <= last^ {
		return
	}
	logx.warnf(
		"udp: the kernel dropped %d datagrams before any reader could take them (%d since start, across %d reader(s)). A figure that climbs with the load is more traffic than the readers can drain: raise listeners.udp.readers, raise listeners.udp.receive_buffer with net.core.rmem_max to match, or put a packet filter in front of this server. A few at a time is more likely to be corrupt datagrams, which are counted here too",
		total - last^,
		total,
		len(l.udp),
	)
}

report :: proc(s: ^server.Server, answers: ^cache.Cache) {
	st := server.stats_of(s)
	cs := cache.stats(answers)
	limited, slipped, conn_limited := server.rate_limit_stats(server.live(s).limiter)
	// Built by `server.stats_line`, for the reason every other reported line in
	// this server is: a counter left out of it is a failing test there rather
	// than a figure that reads zero forever here.
	logx.eventf(
		.Info,
		"stats",
		"%s",
		server.stats_line(
			st,
			cs,
			cache.len_entries(answers),
			cache.bytes_used(answers),
			limited,
			slipped,
			conn_limited,
		),
	)
}

parse_args :: proc() -> (opts: Options, ok: bool) {
	opts.config_path = "/etc/elodin/elodin.yaml"

	args := os.args[1:]
	i := 0
	for i < len(args) {
		arg := args[i]
		switch {
		case arg == "-h" || arg == "--help":
			fmt.print(USAGE)
			os.exit(0)
		case arg == "-v" || arg == "--version":
			fmt.printfln("elodin %s", server.VERSION)
			os.exit(0)
		case arg == "--check":
			opts.check_only = true
		case arg == "--no-fetch":
			opts.no_fetch = true
		case arg == "-c" || arg == "--config":
			if i + 1 >= len(args) {
				fmt.eprintfln("elodin: %s needs a path", arg)
				return opts, false
			}
			i += 1
			opts.config_path = args[i]
		case strings.has_prefix(arg, "--config="):
			opts.config_path = arg[len("--config="):]
		case:
			fmt.eprintfln("elodin: unknown option %q", arg)
			fmt.eprint(USAGE)
			return opts, false
		}
		i += 1
	}
	return opts, true
}

/*
Start `n` event loops, each on a thread that never takes the signals `main` acts
on (#416). A loop that cannot be made is fatal: the server would run with fewer
than it reported, and on a machine that refuses an epoll descriptor nothing
else would work either.
*/
@(private)
start_loops :: proc(n: int) -> (loops: []^loop.Loop, threads: []^thread.Thread) {
	loops = make([]^loop.Loop, n)
	threads = make([]^thread.Thread, n)
	for i in 0 ..< n {
		l, ok := loop.make_loop()
		if !ok {
			logx.errorf("cannot create event loop %d of %d", i + 1, n)
			os.exit(1)
		}
		loops[i] = l
		threads[i] = loop.spawn_thread(l, loop.run, context)
		if threads[i] == nil {
			logx.errorf("cannot start a thread for event loop %d of %d", i + 1, n)
			os.exit(1)
		}
	}
	return
}

/*
Cancel what is still running on the loops, wait for each to finish, and free them.

Stopped before cancelled: a loop that is stopping starts nothing more, so a
cancelled fiber cannot start one the cancel has already gone past - an upstream
connection's reader, say, which would then keep its loop running for good.
*/
@(private)
stop_loops :: proc(loops: []^loop.Loop, threads: []^thread.Thread) {
	for l in loops {
		loop.stop(l)
		loop.cancel_all(l)
	}
	for t, i in threads {
		thread.join(t)
		thread.destroy(t)
		loop.destroy(loops[i])
	}
	delete(threads)
	delete(loops)
}
