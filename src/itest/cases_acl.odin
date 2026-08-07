package itest

import "core:fmt"
import "core:net"
import "core:os"
import "core:path/filepath"
import "core:strings"
import "core:time"
import "elodin:dns"

/*
Who may ask, against the running binary.

A resolver that answers every source on the internet is an open resolver, and
the rate limiter does not change that: it bounds how much one victim can be made
to receive, not whether this server takes part. `server.allow_from` is the
bound on the other side of the exchange - a list of networks queries are
accepted from, checked before the message is parsed and before it is queued.

The cases below run the server with an allow list that deliberately excludes
loopback, because loopback is where the suite asks from. A source outside the
list is the thing being tested, and this is the only way to be one.
*/

@(private = "file")
config_acl :: proc(udp_port, tcp_port, upstream_port: int, allow_from: string) -> string {
	return fmt.tprintf(
		// info, not warn: the denied cases establish readiness from the line the
		// listeners print when they bind, since they cannot ask a question.
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
  servers: ["127.0.0.1:%d"]
cache: {{ enabled: false }}
blocking: {{ enabled: false }}
`,
		udp_port,
		tcp_port,
		allow_from,
		upstream_port,
	)
}

/*
Whether a TCP connection is refused, or closed before an answer.

`query_tcp` cannot tell "the server hung up" from "the server never listened",
and for this case the difference matters: a listener that failed to bind would
pass a test written only on the absence of an answer. So the connection is made
and the write attempted first, and only the read is expected to come back empty.
*/
@(private = "file")
tcp_closed_without_answer :: proc(port: int) -> (connected: bool, answered: bool) {
	socket, err := net.dial_tcp_from_endpoint(net.Endpoint{address = net.IP4_Loopback, port = port})
	if err != nil {
		return false, false
	}
	defer net.close(socket)
	_ = net.set_option(socket, .Receive_Timeout, 2 * time.Second)
	_ = net.set_option(socket, .Send_Timeout, 2 * time.Second)

	query := build_query("acl.example.", u16(dns.Type.A), id = 0x51, allocator = context.temp_allocator)
	framed := make([]u8, 2 + len(query), context.temp_allocator)
	framed[0] = u8(len(query) >> 8)
	framed[1] = u8(len(query))
	copy(framed[2:], query)
	// A closed connection may take the write rather than the read, so a failure
	// here is still the server having refused us.
	if _, werr := net.send_tcp(socket, framed); werr != nil {
		return true, false
	}

	buf: [2]u8
	n, rerr := net.recv_tcp(socket, buf[:])
	return true, rerr == nil && n > 0
}

/*
A server whose allow list excludes the address this suite asks from.

Started without the usual readiness probe, because the probe is a query and the
whole point of this configuration is that our queries go unanswered. Readiness
comes off the log line the listeners print once they are bound.
*/
@(private = "file")
start_denying_server :: proc(r: ^Runner, upstream_port: int) -> (srv: Server, tcp_port: int, ok: bool) {
	udp_port := next_port(r)
	tcp_port = next_port(r)
	cfg := config_acl(udp_port, tcp_port, upstream_port, `allow_from: ["10.0.0.0/8"]`)
	srv, ok = start_server_raw(r, without_dnssec(cfg), udp_port)
	if !ok {
		return srv, tcp_port, false
	}
	// Both listeners, so a TCP case cannot race the bind and read the closed
	// connection it was hoping for out of a socket nothing is listening on yet.
	if !wait_listening(&srv, fmt.tprintf("%d/tcp", tcp_port), 5 * time.Second) {
		fail(r, "server never bound its listeners; log:\n%s", read_log(&srv))
		stop_server(&srv)
		return srv, tcp_port, false
	}
	return srv, tcp_port, true
}

run_acl_cases :: proc(r: ^Runner) {
	upstream_port := next_port(r)
	mock := mock_make("acl", upstream_port)
	mock_synth_all(mock, {203, 0, 113, 20})
	if !mock_start(mock) {
		skip_case(r, "allow_from", "cannot start the mock upstream")
		return
	}
	defer mock_stop(mock)

	query := build_query("acl.example.", u16(dns.Type.A), id = 0x50, allocator = context.allocator)
	defer delete(query)

	/*
	A source outside the list is not answered over UDP.

	Dropped rather than refused: a REFUSED sent to a UDP source is itself a
	reflection, small but free to the sender, and the source on a datagram is
	whatever it says it is.
	*/
	start_case(r, "allow_from: a source outside the list gets no answer over udp")
	{
		srv, _, ok := start_denying_server(r, upstream_port)
		if check(r, ok, "server did not start") {
			defer stop_server(&srv)
			check(r, expect_no_udp_reply(srv.port, query), "the server answered a source outside allow_from")
		}
	}
	end_case(r)

	// The same source over TCP, where the connection is closed on accept rather
	// than given a thread, a read and an answer to write into.
	start_case(r, "allow_from: a source outside the list gets no answer over tcp")
	{
		srv, tcp_port, ok := start_denying_server(r, upstream_port)
		if check(r, ok, "server did not start") {
			defer stop_server(&srv)
			connected, answered := tcp_closed_without_answer(tcp_port)
			check(r, connected, "the tcp listener is not accepting at all, so the case proves nothing")
			check(r, !answered, "the server answered a tcp source outside allow_from")
		}
	}
	end_case(r)

	/*
	A refused client is told nothing, so the log has to say something.

	This is the other half of a default that denies: over UDP nothing is sent
	back and over TCP the connection just goes, so an operator whose network is
	not on the list sees clients stop working and has nowhere to read why. One
	line, at `warn` so it shows at the default level, naming the source and the
	setting.

	Once, though. The caller is whatever is sending the refused datagrams, and a
	line per datagram would be a way for it to write to the disk this server
	logs to.
	*/
	start_case(r, "allow_from: a refusal names the source and the setting, once")
	{
		srv, _, ok := start_denying_server(r, upstream_port)
		if check(r, ok, "server did not start") {
			defer stop_server(&srv)
			check(r, expect_no_udp_reply(srv.port, query), "the server answered a source outside allow_from")
			// A second refusal, which must not produce a second line.
			check(r, expect_no_udp_reply(srv.port, query), "the server answered a source outside allow_from")
			// The line is written on the read loop, so give it the moment
			// between the datagram being refused and the file being flushed.
			time.sleep(200 * time.Millisecond)

			check(
				r,
				log_contains(&srv, "udp: refused a query from"),
				"the log does not say a query was refused over udp; log:\n%s",
				read_log(&srv),
			)
			// The address, not just the fact: "127.0.0.1" alone would also match
			// the line the listener printed when it bound.
			check(
				r,
				log_contains(&srv, "refused a query from 127.0.0.1:"),
				"the log does not name the refused source; log:\n%s",
				read_log(&srv),
			)
			check(
				r,
				log_contains(&srv, "server.allow_from"),
				"the log does not name the setting to change; log:\n%s",
				read_log(&srv),
			)
			check_eq_int(r, log_count(&srv, "refused a query from"), 1, "refusal lines after two refusals")
		}
	}
	end_case(r)

	/*
	The stream listeners refuse on accept, where there is even less for the
	client to go on - so the same line, naming the transport it happened on.
	A fresh server, because the line above is printed once per process.

	And naming a connection rather than a query: the check runs before a byte
	has been read, so there never was a query to refuse. The `refused=` counter
	is a sum of the two units, and the wording is what says which one a line is.
	*/
	start_case(r, "allow_from: a refused tcp connection is logged as a connection")
	{
		srv, tcp_port, ok := start_denying_server(r, upstream_port)
		if check(r, ok, "server did not start") {
			defer stop_server(&srv)
			connected, answered := tcp_closed_without_answer(tcp_port)
			check(r, connected, "the tcp listener is not accepting at all, so the case proves nothing")
			check(r, !answered, "the server answered a tcp source outside allow_from")
			time.sleep(200 * time.Millisecond)
			check(
				r,
				log_contains(&srv, "tcp: refused a connection from"),
				"a refused tcp connection left nothing in the log; log:\n%s",
				read_log(&srv),
			)
			check(
				r,
				!log_contains(&srv, "tcp: refused a query from"),
				"a tcp connection refused on accept was logged as a refused query; log:\n%s",
				read_log(&srv),
			)
		}
	}
	end_case(r)

	// The same server with loopback in the list, so the cases above are about
	// the list and not about anything else being broken.
	start_case(r, "allow_from: a source inside the list is answered")
	{
		udp_port, tcp_port := next_port(r), next_port(r)
		srv, ok := start_server(
			r,
			Server_Options {
				config = config_acl(
					udp_port,
					tcp_port,
					upstream_port,
					`allow_from: ["10.0.0.0/8", "127.0.0.1/32"]`,
				),
				port = udp_port,
			},
		)
		if check(r, ok, "server did not start") {
			defer stop_server(&srv)
			res := query_udp(udp_port, query, context.temp_allocator)
			check(r, res.ok, "a source inside allow_from was not answered over udp")
			tcp := query_tcp(tcp_port, query, context.temp_allocator)
			check(r, tcp.ok, "a source inside allow_from was not answered over tcp")
		}
	}
	end_case(r)

	// An empty list is how an operator asks for a public resolver, and it has to
	// mean exactly that rather than "nothing may ask".
	start_case(r, "allow_from: an empty list serves everybody")
	{
		udp_port, tcp_port := next_port(r), next_port(r)
		srv, ok := start_server(
			r,
			Server_Options{config = config_acl(udp_port, tcp_port, upstream_port, `allow_from: []`), port = udp_port},
		)
		if check(r, ok, "server did not start") {
			defer stop_server(&srv)
			res := query_udp(udp_port, query, context.temp_allocator)
			check(r, res.ok, "an empty allow_from refused a query instead of allowing everything")
		}
	}
	end_case(r)

	// The shipped default has to leave a loopback client working, since that is
	// every desktop install and the first thing anybody tries.
	start_case(r, "allow_from: the default list answers loopback")
	{
		udp_port, tcp_port := next_port(r), next_port(r)
		srv, ok := start_server(
			r,
			Server_Options{config = config_acl(udp_port, tcp_port, upstream_port, ""), port = udp_port},
		)
		if check(r, ok, "server did not start") {
			defer stop_server(&srv)
			res := query_udp(udp_port, query, context.temp_allocator)
			check(r, res.ok, "the default allow_from refused a query from loopback")
		}
	}
	end_case(r)

	// A CIDR that is not one should stop `--check`, not come up as a resolver
	// that quietly serves a network nobody named.
	start_case(r, "allow_from: an unparseable entry is a configuration error")
	{
		udp_port, tcp_port := next_port(r), next_port(r)
		cfg := config_acl(udp_port, tcp_port, upstream_port, `allow_from: ["192.168.0.0/33"]`)
		path := filepath.join({r.work_dir, "acl-bad.yaml"}, context.temp_allocator) or_else ""
		_ = os.write_entire_file(path, transmute([]u8)cfg)
		res := run_binary(r, []string{"--config", path, "--check"}, "acl-bad")
		if check(r, res.ok, "could not run the binary") {
			check(r, res.exit_code != 0, "--check accepted an impossible prefix length")
			check(
				r,
				strings.contains(res.output, "allow_from"),
				"the error does not name the setting: %s",
				res.output,
			)
		}
	}
	end_case(r)
}
