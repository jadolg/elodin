package main

import "core:fmt"
import "core:mem/virtual"
import "core:os"
import "core:strings"
import "core:sync"
import "core:sys/posix"
import "core:time"
import "elodin:cache"
import "elodin:config"
import "elodin:filter"
import "elodin:logx"
import "elodin:pool"
import "elodin:privdrop"
import "elodin:server"
import "elodin:upstream"

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
	by a shutdown that has stopped making progress - a connection thread waiting
	out a client timeout, most likely.

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
drains the worker pools before releasing what their jobs are using never runs
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
}

/*
Sleep until the next tick, or until a signal asks for something sooner.

Sliced rather than left as one long sleep: a handler can only set a flag, so
the loop has to come back and look. Anything less often than this and an
operator waits on a service that has already been told to go - or, for
`Reload`, on a certificate that is already sitting on disk waiting to be
picked up. `Reload` cuts the wait short rather than sitting out the rest of
the tick, which otherwise could be the better part of `TICK`.
*/
@(private)
wait_for_tick :: proc(tick: time.Duration) -> Wait_Outcome {
	SLICE :: 200 * time.Millisecond
	deadline := time.time_add(time.now(), tick)
	for {
		if sync.atomic_load(&stop_requested) {
			return .Stop
		}
		if sync.atomic_exchange(&reload_requested, false) {
			return .Reload
		}
		remaining := time.diff(time.now(), deadline)
		if remaining <= 0 {
			return .Tick
		}
		time.sleep(min(SLICE, remaining))
	}
}

/*
One line saying how large this instance is and why.

Worth printing on every start, not only when something was derived: a worker
count that came from the machine is one an operator has never seen in a file, so
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

@(private)
sizing_origin :: proc(s: config.Server_Config) -> string {
	switch {
	case s.sizing.derived_workers:
		m := s.sizing.machine
		switch {
		case m.cpus > 0 && m.memory > 0:
			return fmt.tprintf("derived from %s and %#.1M", usable_cpus(m.cpus), m.memory)
		case m.cpus > 0:
			return fmt.tprintf("derived from %s", usable_cpus(m.cpus))
		case m.memory > 0:
			return fmt.tprintf("derived from %#.1M of memory", m.memory)
		case:
			return "derived from defaults; this machine could not be measured"
		}
	// Nothing was measured: half of a number the file named is still that
	// number's doing, and naming the machine here would credit it with a
	// choice an operator made.
	case s.sizing.derived_upstream_workers:
		return "upstream_workers derived from the configured workers"
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

@(private)
sizing_line :: proc(s: config.Server_Config) -> string {
	return fmt.tprintf(
		"workers=%d upstream_workers=%d max_pending=%d (%s)",
		s.workers,
		s.upstream_workers,
		s.max_pending,
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
they want `upstream.zones`. Pasted into `blocking.rules` it does the opposite:
`parse_adblock_line` reads the form, discards the target and adds the domain to
the *block* set with `{.Apex, .Subdomains}`, so the zone the operator meant to
route is blackholed instead. That is right where the form actually turns up -
in a downloaded list of otherwise adblock syntax, where it does mean a
blackhole - and wrong here, so the warning is scoped to rules written by hand in
the configuration file rather than to anything a list contains.

It fails closed and the query log says `outcome=blocked detail=list`, so it is
diagnosable. It is still worth one line at startup, because "I configured the
route and now the zone answers NXDOMAIN" is a long way from "the rule you wrote
is a block rule".
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
`blocking.rules`, and the form does a different nothing in each. In
`blocking.rules` it blackholes the zone, as above. In `blocking.allow` it does
not exempt it either: `build_filter_sets` prefixes those entries with `@@`
before parsing them, which puts the string past `parse_adblock_line`'s dnsmasq
branch and into the generic one, where the `/` still in it is read as a
path-scoped rule and the whole entry is discarded. So the rule adds nothing to
either set and the zone goes on being resolved by `upstream.servers`, which
looks exactly like the route not working.

The warning therefore says what the rule is and what it is not, and leaves what
it does to the list it is in - claiming either "blocks that domain" or "exempts
that domain" would be untrue of one of the two files. Both lists are named by
the key an operator writes rather than by the field they land in, so the line
can be searched for in the file it is about.
*/
route_rule_warning :: proc(rule: string, allocator := context.allocator) -> string {
	return fmt.aprintf(
		"blocking rule %q is a list rule, not a route: it does not send the zone anywhere - under blocking.rules that form blackholes the zone, and under blocking.allow it is discarded; to send a zone to its own server use upstream.zones",
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
		fmt.printfln("  %s", sizing_line(cfg.server))
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
			for line in server.rate_limit_override_lines(cfg.server.rate_limit.overrides, context.temp_allocator) {
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
		return
	}

	logx.eventf(.Info, "starting", "version=%s", logx.quote(server.VERSION))
	logx.eventf(
		.Info,
		"sizing",
		"workers=%d upstream_workers=%d max_pending=%d origin=%s",
		cfg.server.workers,
		cfg.server.upstream_workers,
		cfg.server.max_pending,
		logx.quote(sizing_origin(cfg.server)),
	)
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
		if text, say := route_implication_warning(&cfg, route, context.temp_allocator); say {
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

	There used to be a second line under `enabled: false`, telling an operator
	with a local tor that they needed `onion: false` as well or their `.onion`
	answers would be held to the public chain of trust and become SERVFAIL. That
	was a warning standing in for a fix. `special_use_deferred` now takes a
	forwarded `.onion` name out of the chain whichever key forwarded it, so there
	is nothing left to warn about: the two keys no longer have to be written
	together to work, and a line telling an operator to write both would now be
	telling them to do something that changes nothing.
	*/
	switch {
	case !cfg.special_use.enabled:
		logx.warnf("special_use.enabled is off: localhost., onion. and invalid. are forwarded to the upstream")
		// The second half of what this key now does. `special_use_deferred` fires
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
	run(&cfg, opts, service)
}

run :: proc(cfg: ^config.Config, opts: Options, service: privdrop.Identity) {
	handler_pool := pool.make_pool(cfg.server.workers)
	race_pool := pool.make_pool(cfg.server.upstream_workers)

	group, gerr := upstream.make_group(cfg.upstream, race_pool, cookies = cfg.cookies.upstream)
	if gerr != .None {
		logx.errorf("no usable upstream servers, giving up")
		os.exit(1)
	}
	defer upstream.destroy_group(group)

	/*
	One group per `upstream.zones` entry, built the same way the default is.

	A route whose servers are all unusable is fatal rather than dropped. The
	names it claims are the ones an operator added the route to keep resolving,
	and a server that quietly carried on without it would send them to the
	public upstream instead - which is both the leak the route was written to
	stop and the answer least likely to be noticed, since the public resolver
	replies rather than failing. Refusing to start says so at the one moment
	somebody is watching.
	*/
	routes := make([]server.Zone_Route, len(cfg.upstream.zones))
	defer delete(routes)
	defer for route in routes {
		upstream.destroy_group(route.group)
	}
	for zone, i in cfg.upstream.zones {
		zg, zerr := upstream.make_group(zone.upstream, race_pool, cookies = cfg.cookies.upstream)
		if zerr != .None {
			logx.errorf("upstream.zones[%d]: no usable servers for %s, giving up", i, zone.domains[0])
			os.exit(1)
		}
		routes[i] = server.Zone_Route {
			domains = zone.domains,
			group   = zg,
		}
		logx.infof("routing %s to its own upstream", strings.join(zone.domains, ", ", context.temp_allocator))
	}

	answers: ^cache.Cache
	if cfg.cache.enabled {
		answers = cache.make_cache(
			cache.Options {
				max_entries = cfg.cache.max_entries,
				max_bytes = cfg.cache.max_bytes,
				min_ttl = cfg.cache.min_ttl,
				max_ttl = cfg.cache.max_ttl,
				negative_ttl = cfg.cache.negative_ttl,
				serve_stale = cfg.cache.serve_stale,
			},
		)
	}
	defer cache.destroy(answers)

	filters := filter.engine_make()
	defer filter.engine_destroy(filters)

	s := server.Server {
		cfg          = cfg,
		group        = group,
		routes       = routes,
		answers      = answers,
		filters      = filters,
		handler_pool = handler_pool,
		race_pool    = race_pool,
		started      = time.now(),
		running      = true,
	}

	if !server.start_validator(&s) {
		logx.errorf("dnssec is enabled but the trust anchors are not usable, shutting down")
		os.exit(1)
	}
	defer server.stop_validator(&s)

	if !server.start_rate_limiter(&s) {
		logx.errorf("the rate limiter could not be created, shutting down")
		os.exit(1)
	}
	defer server.stop_rate_limiter(&s)

	if !server.start_cookies(&s) {
		logx.errorf("the configured cookie secret is not usable, shutting down")
		os.exit(1)
	}
	defer server.stop_cookies(&s)

	if cfg.blocking.enabled {
		server.reload_filters(&s, !opts.no_fetch)
	}

	listeners: server.Listeners
	if !server.start_listeners(&s, &listeners) {
		logx.errorf("could not start every listener, shutting down")
		os.exit(1)
	}
	/*
	Shutdown, in the one order that works, which is why it is a block rather
	than four separate defers.

	Deferred last so it runs first. Stopping the listeners closes the sockets
	and joins every connection thread, but it does not empty the pools: a query
	accepted a moment earlier is still queued, and `pool.destroy` runs what is
	queued before it joins its workers. Those jobs reach for the validator, the
	filters, the cache and the upstream group, so the pools have to be drained
	before any of that is torn down - the defers below this one - and the
	listener contexts released only once nothing is left that could hold one.

	The pools are handled here rather than at the point they are created, where
	a `defer` of their own would put them last in the unwind and hand every
	draining job a set of freed dependencies.
	*/
	defer {
		server.stop_listeners(&listeners)
		pool.destroy(handler_pool)
		pool.destroy(race_pool)
		server.destroy_listeners(&listeners)
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

	maintenance_loop(&s, &listeners, answers, cfg, opts)
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
written the moment its owner changed.

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
are up: expire cache entries, close idle upstream connections, refresh the
blocklists when their interval comes round, and reload the TLS certificates
when SIGHUP asks for it.
*/
maintenance_loop :: proc(
	s: ^server.Server,
	listeners: ^server.Listeners,
	answers: ^cache.Cache,
	cfg: ^config.Config,
	opts: Options,
) {
	TICK :: 30 * time.Second
	last_refresh := time.now()
	last_report := time.now()
	// What the kernel had dropped at the last report, so the line below is
	// about the interval rather than about the whole run. A counter that only
	// grows says nothing about whether it is still growing.
	last_udp_drops: u64

	for sync.atomic_load(&s.running) {
		switch wait_for_tick(TICK) {
		case .Stop:
			logx.infof("signal received, shutting down")
			sync.atomic_store(&s.running, false)
			continue
		case .Reload:
			logx.infof("SIGHUP received, reloading TLS certificates")
			server.reload_tls(s, listeners)
			free_all(context.temp_allocator)
			continue
		case .Tick:
		}

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

		if cfg.blocking.enabled && !opts.no_fetch && cfg.blocking.refresh > 0 {
			if time.diff(last_refresh, time.now()) >= cfg.blocking.refresh {
				logx.infof("refreshing blocklists")
				server.reload_filters(s, true)
				last_refresh = time.now()
			}
		}

		if time.diff(last_report, time.now()) >= 5 * time.Minute {
			report(s, answers)
			report_udp_drops(listeners, &last_udp_drops)
			last_report = time.now()
		}
		free_all(context.temp_allocator)
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
	limited, slipped, conn_limited := server.rate_limit_stats(s.limiter)
	logx.eventf(
		.Info,
		"stats",
		"queries=%d blocked=%d cached=%d forwarded=%d failed=%d dropped=%d refused=%d conn_refused=%d conn_rate_limited=%d conn_failed=%d handshakes=%d limited=%d truncated=%d secure=%d bogus=%d rebind=%d special_use=%d cache_entries=%d cache_bytes=%d cache_hits=%d cache_withheld=%d cache_misses=%d cache_stale=%d cache_evictions=%d",
		st.queries,
		st.blocked,
		st.cached,
		st.forwarded,
		st.failed,
		st.dropped,
		st.refused,
		st.conn_refused,
		// Beside `conn_refused` because the pair is the diagnosis: a table that
		// is full and a client arriving too fast are different problems with
		// different settings behind them, and the second used to show up in
		// neither figure.
		conn_limited,
		st.conn_failed,
		st.handshakes,
		limited,
		slipped,
		st.secure,
		st.bogus,
		st.rebind,
		st.special_use,
		cache.len_entries(answers),
		cache.bytes_used(answers),
		cs.hits,
		// Beside `cache_hits` because it qualifies it: `get` counts a hit when it
		// hands the bytes over, and the resolver may then refuse them. Without
		// this the line shows `cache_hits` and `cached=` drifting apart with
		// nothing to account for the gap, which is the drift the counter exists
		// to close - the metrics endpoint got it and this line did not.
		cs.withheld,
		cs.misses,
		cs.stale,
		cs.evictions,
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
