package itest

import "core:fmt"
import "core:net"
import "core:time"
import "elodin:dns"
import "elodin:h2"
import "elodin:tlsx"

/*
A client that trickles its message a byte at a time is reclaimed, against the
running binary.

`server.client_timeout` reaches an accepted socket as SO_RCVTIMEO, which bounds
one read and is restarted by every byte that arrives. It is also the only thing
that reclaims a connection already accepted - `max_connections` and the per-prefix
share bound how many exist, `conn_rate_check` bounds how fast they are opened, and
every query budget is charged per message - so a client sending one byte inside
every wait was never given up on at all, and held a connection, a thread and one of
the table's slots for as long as it cared to while no message ever completed. RFC
7766 6.2.3 names the attack and says the idle timeout should be reset "on the
receipt of a full DNS message, rather than on receipt of any part of a DNS
message".

Here rather than only in the unit tests because the property is about the binary
an operator runs: each transport reaches the wire through its own reader, and a
bound that was fixed in one of them says nothing about the next. TCP and the
HTTP/2 preface are the two ends of the range - the plainest reader and the one
behind a TLS handshake and a protocol of its own - and the DoH/1.1 and handshake
readers are held by `src/server/doh_test.odin` and `src/tlsx/tlsx_test.odin`.

`client_timeout` is a second so the cases cost about that; the drip is under it,
which is what makes it a drip rather than a client that has simply stopped.
*/

@(private = "file")
DRIP :: 400 * time.Millisecond
@(private = "file")
BUDGET :: 1 * time.Second
// Comfortably past `BUDGET` and short enough that a case that fails does not hold
// the suite up: a connection still open after this many drips is one nothing
// reclaimed.
@(private = "file")
DRIP_LIMIT :: 8
// What a reclaimed connection costs the client: the budget is a second and a
// drip is 400ms, so the close lands on the third, and the room above that is for
// a loaded box rather than for a server that took its time about it. Asserted
// because `closed` alone would pass on a connection that went away for any
// reason at all, including the last drip of a run that hit `DRIP_LIMIT`.
@(private = "file")
DRIPS_ALLOWED :: 5

@(private = "file")
config_drip :: proc(r: ^Runner, udp_port, tcp_port, doh_port, upstream_port: int) -> string {
	return fmt.tprintf(
		`log: {{ level: info }}
listeners:
  udp: {{ enabled: true, address: "127.0.0.1", port: %d }}
  tcp: {{ enabled: true, address: "127.0.0.1", port: %d }}
  doh: {{ enabled: true, address: "127.0.0.1", port: %d, path: /dns-query, cert_file: %s, key_file: %s }}
server:
  client_timeout: 1s
upstream:
  timeout: 3s
  servers: ["127.0.0.1:%d"]
cache: {{ enabled: false }}
blocking: {{ enabled: false }}
`,
		udp_port,
		tcp_port,
		doh_port,
		r.cert_file,
		r.key_file,
		upstream_port,
	)
}

/*
Trickle `message` a byte at a time and say how many landed before the server let
go of the connection.

The read between the bytes is both how the close is noticed and what paces the
drip. Its wait is a whole drip, so a read that comes back having used all of it
found nothing and the connection is still open, and one that comes back at once
found the end of the connection - a graceful close or a reset, which this client
has no reason to tell apart. Elapsed time is what separates the two, because the
transports underneath report "nothing yet" and "nothing ever again" the same way.
*/
@(private = "file")
drip_until_closed :: proc(conn: ^Test_Conn, message: []u8) -> (sent: int, closed: bool) {
	for sent < len(message) && sent < DRIP_LIMIT {
		if !conn_write(conn, message[sent:][:1]) {
			return sent, true
		}
		sent += 1

		reply: [1]u8
		start := time.tick_now()
		if _, ok := conn_read(conn, reply[:]); !ok && time.tick_since(start) < DRIP / 2 {
			return sent, true
		}
	}
	return sent, false
}

run_slow_drip_cases :: proc(r: ^Runner) {
	upstream_port := next_port(r)
	mock := mock_make("drip", upstream_port)
	mock_synth_all(mock, {203, 0, 113, 9})
	if !mock_start(mock) {
		skip_case(r, "slow drip", "cannot start the mock upstream")
		return
	}
	defer mock_stop(mock)

	udp_port := next_port(r)
	tcp_port := next_port(r)
	doh_port := next_port(r)
	srv, ok := start_server(
		r,
		Server_Options {
			config = config_drip(r, udp_port, tcp_port, doh_port, upstream_port),
			udp_port = udp_port,
			tcp_port = tcp_port,
			doh_port = doh_port,
		},
	)
	if !ok {
		skip_case(r, "slow drip", "server did not start")
		return
	}
	defer stop_server(&srv)

	start_case(r, "drip: a trickled TCP message is given up on at client_timeout")
	{
		socket, derr := net.dial_tcp_from_endpoint(net.Endpoint{address = net.IP4_Loopback, port = tcp_port})
		if check(r, derr == nil, "cannot open a TCP connection: %v", derr) {
			defer net.close(socket)
			// The read between the drips waits one drip - see `drip_until_closed`.
			_ = net.set_option(socket, .Receive_Timeout, DRIP)
			conn := Test_Conn {
				socket = socket,
			}
			// A bare DNS header behind its length prefix. Nothing parses a message
			// that never finishes arriving, so what it asks does not matter.
			message: [2 + dns.HEADER_SIZE]u8
			message[1] = u8(dns.HEADER_SIZE)
			sent, closed := drip_until_closed(&conn, message[:])
			check(r, closed, "a byte every %v held the connection for all %d bytes", DRIP, sent)
			check(r, sent <= DRIPS_ALLOWED, "the connection was held for %d drips of a %v budget", sent, BUDGET)
		}
	}
	end_case(r)

	/*
	And the same on the endpoint a browser reaches, where the trickle is the
	HTTP/2 connection preface: 24 bytes before a stream exists, before a request
	has been made, and before anything this server counts per query has seen the
	client at all. It is the same reader for every frame header behind it - see
	`h2.read_exact`.
	*/
	start_case(r, "drip: a trickled HTTP/2 preface is given up on at client_timeout")
	{
		conn, dialed := dial_tls(doh_port, []string{"h2"})
		if check(r, dialed, "cannot open an h2 connection") {
			defer close_tls(&conn)
			// `dial_tls` carries the suite's own timeout over to the TLS connection;
			// the read between the drips wants one drip, as the TCP case sets.
			tlsx.set_read_timeout(conn.tls, DRIP)
			sent, closed := drip_until_closed(&conn, transmute([]u8)string(h2.PREFACE))
			check(r, closed, "a byte every %v held the connection for all %d bytes", DRIP, sent)
			check(r, sent <= DRIPS_ALLOWED, "the connection was held for %d drips of a %v budget", sent, BUDGET)
		}
	}
	end_case(r)
}
