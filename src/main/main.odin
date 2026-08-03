package main

import "core:fmt"
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
  elodin [--config <path>] [--check] [--version]

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
Sleep until the next tick, or until a signal asks us to stop.

Sliced rather than left as one long sleep: a handler can only set a flag, so
the loop has to come back and look. Anything less often than this and an
operator waits on a service that has already been told to go.
*/
@(private)
wait_for_tick :: proc(tick: time.Duration) -> (carry_on: bool) {
	SLICE :: 200 * time.Millisecond
	deadline := time.time_add(time.now(), tick)
	for {
		if sync.atomic_load(&stop_requested) {
			return false
		}
		remaining := time.diff(time.now(), deadline)
		if remaining <= 0 {
			return true
		}
		time.sleep(min(SLICE, remaining))
	}
}

main :: proc() {
	// Writing to a socket whose peer has gone away raises SIGPIPE, whose
	// default disposition kills the process. A client hanging up mid-answer is
	// completely routine, so the signal is ignored and the write reports EPIPE
	// through the normal error path instead.
	posix.sigignore(.SIGPIPE)
	install_stop_handlers()

	opts, ok := parse_args()
	if !ok {
		os.exit(2)
	}

	cfg, load_err := config.load_file(opts.config_path, context.allocator)
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

	if opts.check_only {
		fmt.printfln("%s is valid: %d upstreams, %d blocklists, %d rewrites",
			opts.config_path, len(cfg.upstream.servers), len(cfg.blocking.lists), len(cfg.rewrites))
		return
	}

	logx.infof("elodin %s starting", server.VERSION)
	run(&cfg, opts, service)
}

run :: proc(cfg: ^config.Config, opts: Options, service: privdrop.Identity) {
	handler_pool := pool.make_pool(cfg.server.workers)
	race_pool := pool.make_pool(cfg.server.upstream_workers)

	group, gerr := upstream.make_group(cfg.upstream, race_pool)
	if gerr != .None {
		logx.errorf("no usable upstream servers, giving up")
		os.exit(1)
	}
	defer upstream.destroy_group(group)

	answers: ^cache.Cache
	if cfg.cache.enabled {
		answers = cache.make_cache(
			cache.Options {
				max_entries = cfg.cache.max_entries,
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
		answers      = answers,
		filters      = filters,
		handler_pool = handler_pool,
		race_pool    = race_pool,
		running      = true,
	}

	if !server.start_validator(&s) {
		logx.errorf("dnssec is enabled but the trust anchors are not usable, shutting down")
		os.exit(1)
	}
	defer server.stop_validator(&s)

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

	logx.infof(
		"ready: strategy=%v upstreams=%d cache=%v blocking=%v dnssec=%v",
		cfg.upstream.strategy,
		len(cfg.upstream.servers),
		cfg.cache.enabled,
		cfg.blocking.enabled,
		cfg.dnssec.enabled,
	)

	maintenance_loop(&s, group, answers, cfg, opts)
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
				"  set server.user, or bind the port with 'setcap cap_net_bind_service=+ep' and start unprivileged",
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
are up: expire cache entries, close idle upstream connections, and refresh the
blocklists when their interval comes round.
*/
maintenance_loop :: proc(
	s: ^server.Server,
	group: ^upstream.Group,
	answers: ^cache.Cache,
	cfg: ^config.Config,
	opts: Options,
) {
	TICK :: 30 * time.Second
	last_refresh := time.now()
	last_report := time.now()

	for sync.atomic_load(&s.running) {
		if !wait_for_tick(TICK) {
			logx.infof("signal received, shutting down")
			sync.atomic_store(&s.running, false)
			break
		}

		if answers != nil {
			if removed := cache.sweep(answers); removed > 0 {
				logx.debugf("cache: swept %d expired entries", removed)
			}
		}
		if closed := upstream.groom(group); closed > 0 {
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
			last_report = time.now()
		}
		free_all(context.temp_allocator)
	}
}

report :: proc(s: ^server.Server, answers: ^cache.Cache) {
	st := server.stats_of(s)
	cs := cache.stats(answers)
	logx.infof(
		"stats: queries=%d blocked=%d cached=%d forwarded=%d failed=%d dropped=%d secure=%d bogus=%d | cache entries=%d hits=%d misses=%d evictions=%d",
		st.queries,
		st.blocked,
		st.cached,
		st.forwarded,
		st.failed,
		st.dropped,
		st.secure,
		st.bogus,
		cache.len_entries(answers),
		cs.hits,
		cs.misses,
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
