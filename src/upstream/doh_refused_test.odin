package upstream

import "core:net"
import "core:sync"
import "core:testing"
import "core:thread"
import "core:time"
import "elodin:config"
import "elodin:dns"
import "elodin:h2"

/*
RST_STREAM(REFUSED_STREAM) says the server never processed the request - RFC
9113 8.7 names it safe to retry - and it is what a server at its
SETTINGS_MAX_CONCURRENT_STREAMS sends. It surfaced as `.HTTP_Error`, which
`exchange` charges to the upstream's health, so a concurrency spike benched a
resolver that was answering fine (#326).

The peer here is scripted over plain TCP, handed to the upstream as its shared
connection the way `get_h2_conn` would after ALPN: it refuses the first
`refuse` streams and answers the next.
*/
@(private = "file")
Refusing_Peer :: struct {
	listener: net.TCP_Socket,
	refuse:   int,
	headers:  int,
}

@(private = "file")
peer_send :: proc(socket: net.TCP_Socket, out: [dynamic]u8) {
	_, _ = net.send_tcp(socket, out[:])
}

@(private = "file")
refusing_peer_run :: proc(p: ^Refusing_Peer) {
	client, _, err := net.accept_tcp(p.listener)
	if err != nil {
		return
	}
	defer net.close(client)
	_ = net.set_option(client, .Receive_Timeout, 3 * time.Second)

	preface: [len(h2.PREFACE)]u8
	if read_full_tcp(client, preface[:]) != .None {
		return
	}
	out := make([dynamic]u8, 0, 64, context.temp_allocator)
	h2.write_frame_header(&out, 0, .Settings, 0, 0)
	peer_send(client, out)

	refused: [dynamic]u32
	defer delete(refused)
	for {
		hdr: [h2.FRAME_HEADER_SIZE]u8
		if read_full_tcp(client, hdr[:]) != .None {
			return
		}
		h, ok := h2.parse_frame_header(hdr[:])
		if !ok {
			return
		}
		payload := make([]u8, h.length, context.temp_allocator)
		if read_full_tcp(client, payload) != .None {
			return
		}
		#partial switch h.type {
		case .Headers:
			sync.atomic_add(&p.headers, 1)
			if len(refused) < p.refuse {
				append(&refused, h.stream_id)
				clear(&out)
				h2.write_frame_header(&out, 4, .Rst_Stream, 0, h.stream_id)
				h2.append_u32(&out, u32(h2.Error_Code.Refused_Stream))
				peer_send(client, out)
			}
		case .Data:
			was_refused := false
			for id in refused {
				was_refused ||= id == h.stream_id
			}
			if was_refused || h.flags & h2.FLAG_END_STREAM == 0 || len(payload) < dns.HEADER_SIZE {
				continue
			}
			// The query as its own answer, QR set: all `response_matches` asks.
			payload[2] |= 0x80
			clear(&out)
			h2.write_frame_header(&out, 1, .Headers, h2.FLAG_END_HEADERS, h.stream_id)
			append(&out, 0x88) // :status 200, HPACK static table entry 8
			h2.write_frame_header(&out, len(payload), .Data, h2.FLAG_END_STREAM, h.stream_id)
			append(&out, ..payload)
			peer_send(client, out)
		}
	}
}

@(private = "file")
exchange_with_refusals :: proc(t: ^testing.T, refuse: int) -> (err: Error, headers: int) {
	listener, lerr := net.listen_tcp(net.Endpoint{address = net.IP4_Loopback, port = 0})
	if !testing.expectf(t, lerr == nil, "cannot listen: %v", lerr) {
		return .IO_Error, 0
	}
	defer net.close(listener)
	bound, berr := net.bound_endpoint(listener)
	if !testing.expectf(t, berr == nil, "cannot read the port: %v", berr) {
		return .IO_Error, 0
	}
	p := Refusing_Peer {
		listener = listener,
		refuse   = refuse,
	}
	peer := thread.create_and_start_with_poly_data(&p, refusing_peer_run)

	u, uerr := make_upstream(
		config.Upstream_Spec {
			name = "refusing",
			kind = .TCP,
			address = "127.0.0.1",
			port = bound.port,
			hostname = "doh.invalid",
			path = "/dns-query",
		},
		8,
		30 * time.Second,
	)
	if !testing.expectf(t, uerr == .None, "cannot make the upstream: %v", uerr) {
		thread.join(peer)
		thread.destroy(peer)
		return .IO_Error, 0
	}

	socket, derr := dial_tcp_timeout(bound, time.Second)
	if !testing.expectf(t, derr == .None, "cannot dial the peer: %v", derr) {
		destroy(u)
		thread.join(peer)
		thread.destroy(peer)
		return .IO_Error, 0
	}
	// What `get_h2_conn` builds once ALPN says h2, minus the TLS.
	_ = net.set_option(socket, .Receive_Timeout, 100 * time.Millisecond)
	hc := start_h2_conn(Stream{socket = socket}, u.allocator)
	sync.mutex_lock(&u.mu)
	u.proto = .H2
	u.h2 = hc
	sync.mutex_unlock(&u.mu)

	query := dns.Message {
		id       = 0x3260,
		question = []dns.Question{{name = "example.com.", type = .A, class = .IN}},
	}
	query.flags.rd = true
	wire, _, enc := dns.encode_message(query, context.temp_allocator)
	testing.expect_value(t, enc, dns.Encode_Error.None)
	body := make([]u8, len(wire), context.temp_allocator)
	copy(body, wire)
	dns.set_id_in_place(body, 0)

	resp: []u8
	resp, err = exchange_doh_h2(u, wire, body, 3 * time.Second, time.tick_add(time.tick_now(), 3 * time.Second), context.temp_allocator)
	if err == .None {
		testing.expect_value(t, u16(resp[0]) << 8 | u16(resp[1]), query.id)
	}

	// Tears the connection down, which ends the peer's read loop.
	destroy(u)
	thread.join(peer)
	thread.destroy(peer)
	free_all(context.temp_allocator)
	return err, sync.atomic_load(&p.headers)
}

@(test)
test_a_refused_doh_stream_is_asked_again :: proc(t: ^testing.T) {
	err, headers := exchange_with_refusals(t, 1)
	testing.expect_value(t, err, Error.None)
	testing.expect_value(t, headers, 2)
}

@(test)
test_a_doh_stream_refused_twice_is_not_charged_as_a_failing_server :: proc(t: ^testing.T) {
	// Not asked a third time, and reported as the peer turning the query away -
	// which `record_failure` exempts until it is all the server ever does.
	err, headers := exchange_with_refusals(t, 2)
	testing.expect_value(t, err, Error.Peer_Closed)
	testing.expect_value(t, headers, 2)
}
