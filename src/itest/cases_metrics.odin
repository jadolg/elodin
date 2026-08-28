package itest

import "core:fmt"
import "core:strconv"
import "core:strings"
import "core:time"
import "elodin:dns"

/*
The Prometheus endpoint, against the running binary.

Two things are worth establishing from outside the process. That the port is not
open unless the configuration asks for it - the default an operator inherits on
upgrade. And that what a scrape returns is derived from the queries that
actually went through the resolver, rather than from counters the endpoint keeps
for itself: the cases below query the server first and then read the numbers
back.
*/

@(private = "file")
config_metrics :: proc(udp_port, upstream_port: int, metrics: string) -> string {
	return fmt.tprintf(
		`log: {{ level: warn }}
listeners:
  udp: {{ enabled: true, address: "127.0.0.1", port: %d }}
  tcp: {{ enabled: false }}
upstream:
  timeout: 3s
  servers: ["127.0.0.1:%d"]
cache: {{ enabled: true, max_entries: 100 }}
blocking: {{ enabled: false }}
%s`,
		udp_port,
		upstream_port,
		metrics,
	)
}

run_metrics_cases :: proc(r: ^Runner) {
	upstream_port := next_port(r)
	mock := mock_make("metrics", upstream_port)
	mock_synth_all(mock, {203, 0, 113, 21})
	if !mock_start(mock) {
		skip_case(r, "metrics", "cannot start the mock upstream")
		return
	}
	defer mock_stop(mock)

	/*
	Nothing is listening unless it was asked for.

	The whole of the argument for shipping this on by default is that it costs
	nothing; the argument against is that a resolver which opens a port an
	operator never wrote in a file has widened their exposure on their behalf.
	This is the case that keeps the second one true.
	*/
	start_case(r, "metrics: no endpoint unless the configuration asks for one")
	{
		udp_port := next_port(r)
		metrics_port := next_port(r)
		srv, ok := start_server(
			r,
			Server_Options{config = config_metrics(udp_port, upstream_port, ""), udp_port = udp_port},
		)
		if check(r, ok, "server did not start") {
			defer stop_server(&srv)
			check(r, !tcp_port_open(9153), "something is listening on the default metrics port with metrics off")
			check(r, !tcp_port_open(metrics_port), "the metrics port is open with metrics off")
		}
	}
	end_case(r)

	start_case(r, "metrics: a scrape reports the queries that went through")
	{
		udp_port := next_port(r)
		metrics_port := next_port(r)
		srv, ok := start_server(
			r,
			Server_Options {
				config = config_metrics(
					udp_port,
					upstream_port,
					fmt.tprintf("metrics: {{ enabled: true, address: \"127.0.0.1\", port: %d }}\n", metrics_port),
				),
				udp_port = udp_port,
			},
		)
		if check(r, ok, "server did not start") {
			defer stop_server(&srv)
			if check(r, wait_http(metrics_port, "/metrics"), "the metrics endpoint never answered") {
				QUERIES :: 4
				// A baseline, because the harness establishes readiness by
				// asking a question of its own and that question is a query
				// like any other. What is being checked is the difference the
				// four below make.
				before := metric_value(
					string(http_request(metrics_port, "GET", "/metrics", context.temp_allocator).body),
					"elodin_queries_total",
				)
				for i in 0 ..< QUERIES {
					// The same name every time, so all but the first are cache
					// hits and both counters below have something to say.
					q := build_query("counted.example.", u16(dns.Type.A), id = u16(100 + i), allocator = context.temp_allocator)
					query_udp(udp_port, q, context.temp_allocator)
				}

				res := http_request(metrics_port, "GET", "/metrics", context.temp_allocator)
				if check(r, res.status == 200, "a scrape returned %d", res.status) {
					check(
						r,
						header_contains(res.headers, "text/plain; version=0.0.4"),
						"the response is not the exposition format:\n%s",
						res.headers,
					)
					page := string(res.body)
					check_eq_int(
						r,
						metric_value(page, "elodin_queries_total") - before,
						QUERIES,
						"the rise in elodin_queries_total",
					)
					check_metric(r, page, `elodin_answers_total{outcome="forwarded"}`, 1)
					check_metric(r, page, `elodin_answers_total{outcome="cached"}`, QUERIES - 1)
					check_metric(r, page, "elodin_cache_hits_total", QUERIES - 1)
					check_metric(r, page, "elodin_cache_entries", 1)

					// The families that cannot be derived from a counter, which
					// is the half of the issue a log line could not have covered.
					for name in ([]string{"process_cpu_seconds_total", "process_resident_memory_bytes", "process_threads"}) {
						check(r, strings.contains(page, name), "%s is missing from the scrape", name)
					}
					check(
						r,
						strings.contains(page, "elodin_upstream_queries_total{upstream="),
						"the upstream family is missing from the scrape",
					)
				}

				// Anything but the configured path is a 404, and anything that
				// would change state is refused: this endpoint only reads.
				check_eq_int(
					r,
					http_request(metrics_port, "GET", "/", context.temp_allocator).status,
					404,
					"a request off the metrics path",
				)
				check_eq_int(
					r,
					http_request(metrics_port, "POST", "/metrics", context.temp_allocator).status,
					405,
					"a POST to the metrics path",
				)
			}
		}
	}
	end_case(r)

	start_case(r, "metrics: the configured path is the only one served")
	{
		udp_port := next_port(r)
		metrics_port := next_port(r)
		srv, ok := start_server(
			r,
			Server_Options {
				config = config_metrics(
					udp_port,
					upstream_port,
					fmt.tprintf(
						"metrics: {{ enabled: true, address: \"127.0.0.1\", port: %d, path: /internal/prom }}\n",
						metrics_port,
					),
				),
				udp_port = udp_port,
			},
		)
		if check(r, ok, "server did not start") {
			defer stop_server(&srv)
			if check(r, wait_http(metrics_port, "/internal/prom"), "the metrics endpoint never answered") {
				check_eq_int(
					r,
					http_request(metrics_port, "GET", "/metrics", context.temp_allocator).status,
					404,
					"the default path with another one configured",
				)
			}
		}
	}
	end_case(r)
}

/*
Wait for the endpoint rather than for the resolver.

`start_server` establishes readiness by asking a DNS question, and the metrics
listener binds after the ones that answer those - so a scrape sent the moment
the probe succeeds can arrive before there is anything to accept it.

Shared with `cases_special_use.odin`, which scrapes the endpoint for a counter of
its own; the waiting is the same and the reason for it is the same.
*/
wait_http :: proc(port: int, path: string) -> bool {
	deadline := time.time_add(time.now(), 5 * time.Second)
	for time.diff(deadline, time.now()) < 0 {
		if http_request(port, "GET", path, context.temp_allocator).status == 200 {
			return true
		}
		time.sleep(50 * time.Millisecond)
	}
	return false
}

// A sample is the metric, a space, and the value, on a line of its own.
@(private = "file")
check_metric :: proc(r: ^Runner, page: string, name: string, want: int) {
	wanted := fmt.tprintf("\n%s %d\n", name, want)
	check(r, strings.contains(page, wanted), "%s is not %d in the scrape", name, want)
}

// -1 when the sample is not there, which no counter on the page can be. Shared
// with `cases_special_use.odin` for the same reason `wait_http` is.
metric_value :: proc(page: string, name: string) -> int {
	prefix := fmt.tprintf("\n%s ", name)
	at := strings.index(page, prefix)
	if at < 0 {
		return -1
	}
	rest := page[at + len(prefix):]
	line_end := strings.index_byte(rest, '\n')
	if line_end < 0 {
		return -1
	}
	return strconv.parse_int(rest[:line_end]) or_else -1
}
