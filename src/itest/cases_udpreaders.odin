package itest

import "core:fmt"
import "core:os"
import "core:path/filepath"
import "core:strings"
import "elodin:dns"

/*
Several UDP readers, against the running binary.

Everything a datagram costs before the rate limiter sees it is spent on the
thread that read it, so one reader is one core's worth of drain rate for the
whole server and past it the kernel drops datagrams in the receive queue, where
no budget in this server can reach them. `listeners.udp.readers` gives each
reader a socket of its own on the same port, and these cases are the parts of
that an operator can see: the port is shared rather than split, every reader
answers, the count is reported before a restart and refused when it is
impossible, and what the kernel dropped is published.
*/

@(private = "file")
config_readers :: proc(udp_port, upstream_port: int, extra: string) -> string {
	return fmt.tprintf(
		`log: {{ level: info }}
listeners:
  udp: {{ enabled: true, address: "127.0.0.1", port: %d, readers: 4 }}
  tcp: {{ enabled: false }}
upstream:
  timeout: 3s
  servers: ["127.0.0.1:%d"]
cache: {{ enabled: false }}
blocking: {{ enabled: false }}
%s`,
		udp_port,
		upstream_port,
		extra,
	)
}

run_udp_reader_cases :: proc(r: ^Runner) {
	upstream_port := next_port(r)
	mock := mock_make("udpreaders", upstream_port)
	mock_synth_all(mock, {203, 0, 113, 44})
	if !mock_start(mock) {
		skip_case(r, "listeners.udp.readers", "cannot start the mock upstream")
		return
	}
	defer mock_stop(mock)

	start_case(r, "listeners.udp.readers: four readers share one port and every query is answered")
	{
		udp_port := next_port(r)
		metrics_port := next_port(r)
		srv, ok := start_server(
			r,
			Server_Options {
				config = config_readers(
					udp_port,
					upstream_port,
					fmt.tprintf("metrics: {{ enabled: true, address: \"127.0.0.1\", port: %d }}\n", metrics_port),
				),
				udp_port = udp_port,
			},
		)
		if check(r, ok, "server did not start") {
			defer stop_server(&srv)
			check(
				r,
				log_contains(&srv, "4 readers"),
				"the startup line does not say how many readers there are; log:\n%s",
				read_log(&srv),
			)

			/*
			A question each, from a source port each.

			`query_udp` opens a socket per call, so every query arrives on a
			4-tuple of its own - which is what the kernel hashes to pick a
			reader. Sent to one address and one port throughout: the whole
			claim is that these are one listener rather than four.
			*/
			QUERIES :: 32
			answered := 0
			for i in 0 ..< QUERIES {
				q := build_query(
					fmt.tprintf("r%d.example.", i),
					u16(dns.Type.A),
					id = u16(0x700 + i),
					allocator = context.temp_allocator,
				)
				if query_udp(udp_port, q, context.temp_allocator).ok {
					answered += 1
				}
			}
			check_eq_int(r, answered, QUERIES, "queries answered across the readers")

			if check(r, wait_http(metrics_port, "/metrics"), "the metrics endpoint never answered") {
				page := string(http_request(metrics_port, "GET", "/metrics", context.temp_allocator).body)
				total := 0
				busy := 0
				for i in 0 ..< 4 {
					name := fmt.tprintf("elodin_udp_datagrams_total{{reader=\"%d\"}}", i)
					n := metric_value(page, name)
					if !check(r, n >= 0, "%s is missing from the scrape", name) {
						continue
					}
					total += n
					if n > 0 {
						busy += 1
					}
				}
				check(r, total >= QUERIES, "the readers counted %d datagrams of at least %d", total, QUERIES)
				/*
				More than one reader received. This is the property, and it is
				what a single socket could not have done: before `SO_REUSEPORT`
				the second reader's bind was refused outright.

				The kernel could in principle hash all 32 onto one reader; at
				four readers that is (3/4)^32 per reader, about one run in ten
				thousand for any of them. Retried nowhere, because a failure
				here is far more likely to be the sharing having stopped
				working.
				*/
				check(r, busy >= 2, "%d of 4 readers received anything: the port is not being shared", busy)

				// What the kernel dropped before any of them could read: the
				// one loss no counter on the query path can see.
				check(
					r,
					strings.contains(page, "elodin_udp_receive_drops_total{reader=\"0\"}"),
					"the drop counter is missing from the scrape, so the receive queue is unmeasured",
				)
			}
		}
	}
	end_case(r)

	start_case(r, "listeners.udp.readers: --check reports the count and where it came from")
	{
		path := filepath.join({r.work_dir, "readers-derived.yaml"}, context.temp_allocator) or_else ""
		_ = os.write_entire_file(path, transmute([]u8)string("upstream:\n  servers: [1.1.1.1]\n"))
		res := run_binary(r, []string{"--config", path, "--check"}, "readers-derived")
		if check(r, res.ok, "could not run the binary") {
			check_eq_int(r, res.exit_code, 0, "exit code")
			// The shipped file names no reader count, so this is the only place
			// an operator can read the number the next start will use.
			check(
				r,
				strings.contains(res.output, "udp: ") && strings.contains(res.output, "reader"),
				"the reader count was not reported: %q",
				res.output,
			)
			check(
				r,
				strings.contains(res.output, "receive buffer"),
				"the receive buffer was not reported: %q",
				res.output,
			)
		}
	}
	end_case(r)

	start_case(r, "listeners.udp.readers: --check refuses a count this server will not honour")
	{
		path := filepath.join({r.work_dir, "readers-absurd.yaml"}, context.temp_allocator) or_else ""
		_ = os.write_entire_file(
			path,
			transmute([]u8)string("upstream:\n  servers: [1.1.1.1]\nlisteners:\n  udp:\n    readers: 4096\n"),
		)
		res := run_binary(r, []string{"--config", path, "--check"}, "readers-absurd")
		if check(r, res.ok, "could not run the binary") {
			check(r, res.exit_code != 0, "a reader count of 4096 exited 0")
			check(
				r,
				strings.contains(res.output, "listeners.udp.readers"),
				"the error does not name the setting: %q",
				res.output,
			)
		}
	}
	end_case(r)
}
