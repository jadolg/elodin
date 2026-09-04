package server

import "core:strings"
import "core:testing"
import "core:time"
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

@(private)
render_fixture :: proc(stats: Stats) -> string {
	s, cfg := metrics_fixture(stats)
	s.cfg = &cfg
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
		},
	)

	expect_line(t, page, "elodin_queries_total 1")
	expect_line(t, page, `elodin_answers_total{outcome="blocked"} 2`)
	expect_line(t, page, `elodin_answers_total{outcome="cached"} 3`)
	expect_line(t, page, `elodin_answers_total{outcome="forwarded"} 4`)
	expect_line(t, page, `elodin_answers_total{outcome="failed"} 5`)
	expect_line(t, page, `elodin_answers_total{outcome="rewritten"} 6`)
	expect_line(t, page, "elodin_queries_dropped_total 7")
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
	s, cfg := metrics_fixture(Stats{})
	s.cfg = &cfg
	// Distinct values, so a series reading the wrong counter fails.
	s.limiter = make_rate_limiter(500, 2)
	defer destroy_rate_limiter(s.limiter)
	s.limiter.limited = 3
	s.limiter.slipped = 5
	s.limiter.conn_limited = 7

	listeners: Listeners
	page := render_metrics(&s, &listeners, context.temp_allocator)
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
