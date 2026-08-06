package itest

import "core:fmt"
import "core:time"
import "elodin:dns"

/*
The ceiling on a UDP response, against the running binary.

A client's advertised EDNS buffer is a request, not a promise: it arrives on a
datagram whose source nothing has verified, so an attacker aiming answers at
somebody else advertises the largest buffer it can and that number is its
amplification factor. `server.max_udp_response` is the ceiling on it, 1232 by
default, and the cases below are the same large answer asked for at 4096 with
the ceiling in place and lifted.

TCP is asked the same question, because the ceiling must not apply there: a
connection was established before the query arrived, so there is nothing to
reflect and no reason to make a client ask twice.
*/

@(private = "file")
config_udp_size :: proc(udp_port, tcp_port, upstream_port: int, ceiling: string) -> string {
	return fmt.tprintf(
		`log: {{ level: info }}
listeners:
  udp: {{ enabled: true, address: "127.0.0.1", port: %d }}
  tcp: {{ enabled: true, address: "127.0.0.1", port: %d }}
server:
  workers: 8
  upstream_workers: 4
  %s
upstream:
  timeout: 3s
  # TCP, so the mock's oversized answer reaches us whole rather than being
  # clipped on the way in by the thing under test.
  servers: ["tcp://127.0.0.1:%d"]
cache: {{ enabled: false }}
blocking: {{ enabled: false }}
`,
		udp_port,
		tcp_port,
		ceiling,
		upstream_port,
	)
}

// A response of roughly `count * 260` bytes, built as TXT records so it is the
// answer section rather than anything the server would strip that makes it big.
@(private = "file")
big_txt_answer :: proc(name: string, count: int, allocator := context.allocator) -> []u8 {
	answers := make([]dns.Record, count, context.temp_allocator)
	for i in 0 ..< count {
		chunk := make([]u8, 255, context.temp_allocator)
		for j in 0 ..< len(chunk) {
			chunk[j] = u8('a' + (i + j) % 26)
		}
		strs := make([]string, 1, context.temp_allocator)
		strs[0] = string(chunk)
		answers[i] = dns.Record {
			name  = name,
			type  = .TXT,
			class = .IN,
			ttl   = 300,
			data  = dns.Rdata_TXT{strings = strs},
		}
	}
	m := dns.Message {
		question   = []dns.Question{{name = name, type = .TXT, class = .IN}},
		answer     = answers,
		additional = []dns.Record{dns.make_opt(4096, false)},
	}
	m.flags.qr = true
	m.flags.ra = true
	wire, _, err := dns.encode_message(m, allocator, dns.MAX_MESSAGE)
	if err != .None {
		return nil
	}
	return wire
}

run_udp_size_cases :: proc(r: ^Runner) {
	upstream_port := next_port(r)
	mock := mock_make("udpsize", upstream_port)
	// About 2600 bytes: over the 1232 default, under the 4096 the client asks
	// for, so the two configurations below give visibly different answers.
	big := big_txt_answer("big.example.", 10, context.allocator)
	defer delete(big)
	mock_reply(mock, "big.example.", u16(dns.Type.TXT), big)
	if !mock_start(mock) {
		skip_case(r, "max_udp_response", "cannot start the mock upstream")
		return
	}
	defer mock_stop(mock)

	query := build_query("big.example.", u16(dns.Type.TXT), id = 0x60, edns_size = 4096, allocator = context.allocator)
	defer delete(query)

	start_case(r, "max_udp_response: the default holds a client that asks for 4096 to 1232")
	{
		udp_port, tcp_port := next_port(r), next_port(r)
		srv, ok := start_server(
			r,
			Server_Options{config = config_udp_size(udp_port, tcp_port, upstream_port, ""), port = udp_port},
		)
		if check(r, ok, "server did not start") {
			defer stop_server(&srv)
			res := query_udp(udp_port, query, context.temp_allocator)
			if check(r, res.ok, "no answer came back") {
				check(
					r,
					len(res.wire) <= 1232,
					"the answer is %d bytes, past the 1232 default ceiling",
					len(res.wire),
				)
				h, hok := parse_header(res.wire)
				check(r, hok, "the answer does not parse")
				check(r, h.tc, "the truncated answer does not carry TC, so no client would retry")
			}

			// And the message an operator needs in order to know which setting
			// did it, and that it is theirs to change.
			check(r, log_contains(&srv, "max_udp_response"), "the log does not name the setting; log:\n%s", read_log(&srv))
			check(
				r,
				log_contains(&srv, "retry over TCP"),
				"the log does not say what happened to the answer; log:\n%s",
				read_log(&srv),
			)
			check(
				r,
				log_contains(&srv, "raise server.max_udp_response"),
				"the log does not say what to change; log:\n%s",
				read_log(&srv),
			)
		}
	}
	end_case(r)

	// The ceiling is a setting, so raising it has to actually deliver the answer
	// the client asked for rather than only silence the message.
	start_case(r, "max_udp_response: raising it to 4096 sends the whole answer over UDP")
	{
		udp_port, tcp_port := next_port(r), next_port(r)
		srv, ok := start_server(
			r,
			Server_Options {
				config = config_udp_size(udp_port, tcp_port, upstream_port, "max_udp_response: 4096"),
				port = udp_port,
			},
		)
		if check(r, ok, "server did not start") {
			defer stop_server(&srv)
			res := query_udp(udp_port, query, context.temp_allocator)
			if check(r, res.ok, "no answer came back") {
				check(r, len(res.wire) > 1232, "the answer is only %d bytes; the ceiling was not lifted", len(res.wire))
				h, hok := parse_header(res.wire)
				check(r, hok, "the answer does not parse")
				check(r, !h.tc, "the answer carries TC even though it fits")
				check_eq_int(r, h.ancount, 10, "answer count")
			}
			check(
				r,
				!log_contains(&srv, "raise server.max_udp_response"),
				"an answer that fit still asked the operator to raise the ceiling; log:\n%s",
				read_log(&srv),
			)
		}
	}
	end_case(r)

	// TCP proves the address before a query arrives, so there is nothing to
	// reflect and the ceiling does not belong there.
	start_case(r, "max_udp_response: the ceiling does not apply over tcp")
	{
		udp_port, tcp_port := next_port(r), next_port(r)
		srv, ok := start_server(
			r,
			Server_Options{config = config_udp_size(udp_port, tcp_port, upstream_port, ""), port = udp_port},
		)
		if check(r, ok, "server did not start") {
			defer stop_server(&srv)
			res := query_tcp(tcp_port, query, context.temp_allocator)
			if check(r, res.ok, "no answer came back over tcp") {
				check(r, len(res.wire) > 1232, "tcp answered only %d bytes; the UDP ceiling leaked", len(res.wire))
				h, hok := parse_header(res.wire)
				check(r, hok, "the answer does not parse")
				check(r, !h.tc, "a tcp answer was truncated")
			}
		}
	}
	end_case(r)

	// A client that asked for less than the ceiling gets what it asked for, and
	// nothing is said about a setting that had no part in it.
	start_case(r, "max_udp_response: a client's own small buffer is not blamed on the setting")
	{
		udp_port, tcp_port := next_port(r), next_port(r)
		srv, ok := start_server(
			r,
			Server_Options{config = config_udp_size(udp_port, tcp_port, upstream_port, ""), port = udp_port},
		)
		if check(r, ok, "server did not start") {
			defer stop_server(&srv)
			small := build_query(
				"big.example.",
				u16(dns.Type.TXT),
				id = 0x61,
				edns_size = 512,
				allocator = context.temp_allocator,
			)
			res := query_udp(udp_port, small, context.temp_allocator)
			if check(r, res.ok, "no answer came back") {
				check(r, len(res.wire) <= 512, "the answer is %d bytes, past what the client asked for", len(res.wire))
			}
			// Give the line a moment to reach the file before concluding it is
			// not there.
			time.sleep(200 * time.Millisecond)
			check(
				r,
				!log_contains(&srv, "raise server.max_udp_response"),
				"a client's own 512-byte buffer was reported as the server's ceiling; log:\n%s",
				read_log(&srv),
			)
		}
	}
	end_case(r)
}
