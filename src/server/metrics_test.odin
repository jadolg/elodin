package server

import "core:fmt"
import "core:reflect"
import "core:strings"
import "core:testing"
import "core:time"
import "elodin:cache"
import "elodin:config"

/*
A `Server` with counters and nothing else behind them.

`render_metrics` reaches for the cache, the filter engine, the upstream group
and the two pools, and every one of those is absent here: what is being tested
is what the endpoint says about the numbers, and the components have tests of
their own. The renderer leaves out the families it has no component for, which
is why this builds.
*/
@(private)
metrics_fixture :: proc(stats: Stats) -> (Server, config.Config) {
	cfg := config.default_config()
	cfg.server.max_connections = 512
	cfg.metrics.enabled = true
	s := Server {
		stats   = stats,
		started = time.now(),
	}
	return s, cfg
}

// `limiter` defaults to none, which is what every case about `Stats` wants: the
// endpoint reads the limiter's counters through `rate_limit_stats`, which answers
// zeroes for a nil one. A case about those counters passes one in.
@(private)
render_fixture :: proc(stats: Stats, limiter: ^Rate_Limiter = nil) -> string {
	s, cfg := metrics_fixture(stats)
	s.cfg = &cfg
	s.limiter = limiter
	listeners: Listeners
	return render_metrics(&s, &listeners, context.temp_allocator)
}

/*
Every counter the log line reports has a series here.

The failure this guards against is the one `test_stats_of_carries_every_counter`
guards against a field further up: a counter the query path maintains, that the
endpoint never publishes, is a number an operator cannot alert on and has no way
of knowing is missing - the scrape looks complete either way.

Distinct values, so a series reading the wrong field fails rather than passing
on a coincidence.
*/
@(test)
test_every_counter_reaches_the_endpoint :: proc(t: ^testing.T) {
	page := render_fixture(
		Stats {
			queries = 1,
			blocked = 2,
			cached = 3,
			forwarded = 4,
			failed = 5,
			rewritten = 6,
			dropped = 7,
			refused = 8,
			conn_refused = 9,
			conn_failed = 10,
			handshakes = 11,
			secure = 12,
			bogus = 13,
			rebind = 14,
			special_use = 15,
			accept_backoff = 16,
		},
	)

	expect_line(t, page, "elodin_queries_total 1")
	expect_line(t, page, `elodin_answers_total{outcome="blocked"} 2`)
	expect_line(t, page, `elodin_answers_total{outcome="cached"} 3`)
	expect_line(t, page, `elodin_answers_total{outcome="forwarded"} 4`)
	expect_line(t, page, `elodin_answers_total{outcome="failed"} 5`)
	expect_line(t, page, `elodin_answers_total{outcome="rewritten"} 6`)
	expect_line(t, page, "elodin_queries_dropped_total 7")
	expect_line(t, page, "elodin_accept_backoffs_total 16")
	expect_line(t, page, "elodin_queries_refused_total 8")
	expect_line(t, page, "elodin_connections_refused_total 9")
	expect_line(t, page, "elodin_connections_failed_total 10")
	expect_line(t, page, "elodin_tls_handshakes_total 11")
	expect_line(t, page, `elodin_dnssec_answers_total{result="secure"} 12`)
	expect_line(t, page, `elodin_dnssec_answers_total{result="bogus"} 13`)
	expect_line(t, page, "elodin_rebind_refused_total 14")
	expect_line(t, page, "elodin_special_use_total 15")
	free_all(context.temp_allocator)
}

/*
The limiter's own counters reach the endpoint too, including the connections it
refused.

Separate from the test above because these do not come off `Stats`: the endpoint
reads them through `rate_limit_stats`, so a counter added to the limiter and not
added there publishes a zero for as long as nobody checks. `conn_rate_limited` is
the one that matters most here - `elodin_connections_refused_total` reading zero
through a handshake flood is the blindness issue #247 was filed about, and a
series that reported the new bound as a flat zero would be the same blindness with
a metric name on it.
*/
@(test)
test_the_limiters_counters_reach_the_endpoint :: proc(t: ^testing.T) {
	// Distinct values, so a series reading the wrong counter fails.
	limiter := make_rate_limiter(500, 2)
	defer destroy_rate_limiter(limiter)
	limiter.limited = 3
	limiter.slipped = 5
	limiter.conn_limited = 7

	page := render_fixture(Stats{}, limiter)
	expect_line(t, page, "elodin_rate_limited_total 3")
	expect_line(t, page, "elodin_rate_limit_slipped_total 5")
	expect_line(t, page, "elodin_connections_rate_limited_total 7")
	free_all(context.temp_allocator)
}

/*
A family is declared once, whatever it holds.

Two `# TYPE` lines for one metric name are a duplicate, and a scraper rejects
the whole response over it rather than the line - so a page that is merely
noisy in this respect is a page that reports nothing at all.
*/
@(test)
test_no_family_is_declared_twice :: proc(t: ^testing.T) {
	page := render_fixture(Stats{})
	seen := make(map[string]bool, 64, context.temp_allocator)
	for line in strings.split_lines_iterator(&page) {
		if !strings.has_prefix(line, "# TYPE ") {
			continue
		}
		name := line[len("# TYPE "):]
		if space := strings.index_byte(name, ' '); space > 0 {
			name = name[:space]
		}
		testing.expectf(t, !seen[name], "%s was declared more than once", name)
		seen[name] = true
	}
	testing.expect(t, len(seen) > 0, "nothing was declared at all")
	free_all(context.temp_allocator)
}

/*
Every sample belongs to a family declared before it.

A bare sample is legal in the format and is what a scraper stores when the
declaration is missing: the number arrives untyped, so `rate()` over what is
really a counter is left to whoever writes the query. A metric renamed in one
place and not the other lands exactly here.
*/
@(test)
test_every_sample_belongs_to_a_declared_family :: proc(t: ^testing.T) {
	page := render_fixture(Stats{})
	declared := make(map[string]bool, 64, context.temp_allocator)
	for line in strings.split_lines_iterator(&page) {
		if line == "" {
			continue
		}
		if strings.has_prefix(line, "# TYPE ") {
			name := line[len("# TYPE "):]
			if space := strings.index_byte(name, ' '); space > 0 {
				declared[name[:space]] = true
			}
			continue
		}
		if strings.has_prefix(line, "#") {
			continue
		}
		name := line
		if cut := strings.index_any(name, "{ "); cut > 0 {
			name = name[:cut]
		}
		testing.expectf(t, declared[name], "%q was sampled without a # TYPE line", name)
	}
	free_all(context.temp_allocator)
}

/*
The process family is the part of this the issue asked for by name, and it is
the part that cannot be faked from a counter.
*/
@(test)
test_the_process_family_is_published :: proc(t: ^testing.T) {
	page := render_fixture(Stats{})
	for name in ([]string {
			"process_cpu_seconds_total",
			"process_resident_memory_bytes",
			"process_virtual_memory_bytes",
			"process_threads",
			"process_start_time_seconds",
		}) {
		testing.expectf(t, strings.contains(page, name), "%s was not published", name)
	}
	free_all(context.temp_allocator)
}

@(private)
expect_line :: proc(t: ^testing.T, page: string, line: string, loc := #caller_location) {
	// With the newline, so that a shorter name is not matched by a longer one
	// that happens to start with it.
	wanted := strings.concatenate({line, "\n"}, context.temp_allocator)
	testing.expectf(t, strings.contains(page, wanted), "%q is not on the page", line, loc = loc)
}

/*
Every counter in `Stats` appears in the line, with its own value.

Read off the struct rather than off a list kept here by hand, which is the
difference between a guard and a note. The first version of this test carried the
list, and so had exactly the failure it was written to close: it checked the
counters somebody remembered, and `Stats.rewritten` - published by the endpoint
since it existed, absent from the line since it existed - passed it.

`reflect.struct_field_names` cannot forget. A counter added to `Stats` and left
out of `stats_line` fails here on the day it is added, which is what the other
two guards do for the snapshot and the endpoint.

Distinct values, and the value is asserted with the name, so a field printed from
the wrong counter fails rather than passing on the presence of its key. Every
field of `Stats` is a `u64` and every one belongs in the line, so there is no
exception list - and if either ever stops being true, this test is where it has
to be argued.
*/
@(test)
test_the_stats_line_carries_every_counter :: proc(t: ^testing.T) {
	st := Stats {
		queries        = 1,
		blocked        = 2,
		cached         = 3,
		forwarded      = 4,
		failed         = 5,
		rewritten      = 6,
		dropped        = 7,
		refused        = 8,
		conn_refused   = 9,
		conn_failed    = 10,
		handshakes     = 11,
		secure         = 12,
		bogus          = 13,
		rebind         = 14,
		special_use    = 15,
		accept_backoff = 16,
	}
	cs := cache.Stats {
		hits      = 20,
		misses    = 21,
		stale     = 22,
		withheld  = 23,
		evictions = 24,
	}
	line := stats_line(st, cs, 30, 31, 40, 41, 42)

	for name in reflect.struct_field_names(Stats) {
		value := reflect.struct_field_value_by_name(st, name)
		count, ok := value.(u64)
		testing.expectf(t, ok, "Stats.%s is not a u64; this guard assumes every counter is one", name)
		if !ok {
			continue
		}
		want := fmt.tprintf("%s=%d", name, count)
		testing.expectf(t, strings.contains(line, want), "the stats line is missing %q: %s", want, line)
	}

	// The figures that do not live in `Stats` - the limiter's and the cache's -
	// which the walk above cannot see.
	for want in ([]string {
			"conn_rate_limited=42",
			"limited=40",
			"truncated=41",
			"cache_entries=30",
			"cache_bytes=31",
			"cache_hits=20",
			"cache_withheld=23",
			"cache_misses=21",
			"cache_stale=22",
			"cache_evictions=24",
		}) {
		testing.expectf(t, strings.contains(line, want), "the stats line is missing %q: %s", want, line)
	}
}
