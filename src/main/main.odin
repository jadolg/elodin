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

main :: proc() {
	// Writing to a socket whose peer has gone away raises SIGPIPE, whose
	// default disposition kills the process. A client hanging up mid-answer is
	// completely routine, so the signal is ignored and the write reports EPIPE
	// through the normal error path instead.
	posix.sigignore(.SIGPIPE)

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

	if opts.check_only {
		fmt.printfln("%s is valid: %d upstreams, %d blocklists, %d rewrites",
			opts.config_path, len(cfg.upstream.servers), len(cfg.blocking.lists), len(cfg.rewrites))
		return
	}

	logx.infof("elodin %s starting", server.VERSION)
	run(&cfg, opts)
}

run :: proc(cfg: ^config.Config, opts: Options) {
	handler_pool := pool.make_pool(cfg.server.workers)
	race_pool := pool.make_pool(cfg.server.upstream_workers)
	defer pool.destroy(handler_pool)
	defer pool.destroy(race_pool)

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

	if cfg.blocking.enabled {
		server.reload_filters(&s, !opts.no_fetch)
	}

	listeners: server.Listeners
	if !server.start_listeners(&s, &listeners) {
		logx.errorf("could not start every listener, shutting down")
		os.exit(1)
	}
	defer server.stop_listeners(&listeners)

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
		time.sleep(TICK)

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
