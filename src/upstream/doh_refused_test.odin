package upstream

import "core:mem"
import "core:net"
import "core:sync"
import "core:testing"
import "core:thread"
import "core:time"
import "elodin:config"
import "elodin:dns"
import "elodin:h2"
import "elodin:loop"

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
	// When set, the answer is this header block with no body, after `interim`'s
	// block when that is set too, rather than the query echoed with a 200.
	interim:  []u8,
	head:     []u8,
	// Bytes of zeros sent as the body after `head`.
	body:     int,
	// Instead of ending the stream after `head`, reset it with INTERNAL_ERROR,
	// or leave it open and send nothing more.
	reset:    bool,
	stall:    bool,
	// Or close the connection after `head`, without ending the stream.
	hang_up:  bool,
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
			if p.head != nil {
				clear(&out)
				if p.interim != nil {
					h2.write_frame_header(&out, len(p.interim), .Headers, h2.FLAG_END_HEADERS, h.stream_id)
					append(&out, ..p.interim)
				}
				ends := p.body == 0 && !p.reset && !p.stall && !p.hang_up
				h2.write_frame_header(&out, len(p.head), .Headers, h2.FLAG_END_HEADERS | (h2.FLAG_END_STREAM if ends else 0), h.stream_id)
				append(&out, ..p.head)
				if p.reset {
					h2.write_frame_header(&out, 4, .Rst_Stream, 0, h.stream_id)
					h2.append_u32(&out, u32(h2.Error_Code.Internal_Error))
				}
				// In frames no larger than the default SETTINGS_MAX_FRAME_SIZE.
				for sent := 0; sent < p.body; {
					n := min(p.body - sent, h2.DEFAULT_MAX_FRAME)
					sent += n
					h2.write_frame_header(&out, n, .Data, h2.FLAG_END_STREAM if sent == p.body else 0, h.stream_id)
					resize(&out, len(out) + n)
				}
				peer_send(client, out)
				if p.hang_up {
					return
				}
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
exchange_with_refusals :: proc(t: ^testing.T, refuse: int, allocator := context.temp_allocator) -> (err: Error, headers: int) {
	err, headers, _ = exchange_with_peer(t, refuse, nil, nil, 0, allocator) // lint:allow a wait, not an error: only the throttling cases read it
	return
}

/*
One exchange answered by the header block `head`, after the interim block
`interim` when that is not nil, and how long a `Retry-After` it carried asks
the upstream to wait, or zero.
*/
@(private)
exchange_with_head :: proc(t: ^testing.T, interim, head: []u8, body: int, reset := false, stall := false, hang_up := false) -> (err: Error, wait: time.Duration) {
	err, _, wait = exchange_with_peer(t, 0, interim, head, body, context.temp_allocator, reset = reset, stall = stall, hang_up = hang_up)
	return
}

@(private = "file")
exchange_with_peer :: proc(
	t: ^testing.T,
	refuse: int,
	interim, head: []u8,
	body: int,
	allocator: mem.Allocator,
	reset := false,
	stall := false,
	hang_up := false,
) -> (
	err: Error,
	headers: int,
	wait: time.Duration,
) {
	listener, lerr := net.listen_tcp(net.Endpoint{address = net.IP4_Loopback, port = 0})
	if !testing.expectf(t, lerr == nil, "cannot listen: %v", lerr) {
		return .IO_Error, 0, 0
	}
	defer net.close(listener)
	bound, berr := net.bound_endpoint(listener)
	if !testing.expectf(t, berr == nil, "cannot read the port: %v", berr) {
		return .IO_Error, 0, 0
	}
	p := Refusing_Peer {
		listener = listener,
		refuse   = refuse,
		interim  = interim,
		head     = head,
		body     = body,
		reset    = reset,
		stall    = stall,
		hang_up  = hang_up,
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
		return .IO_Error, 0, 0
	}

	socket, derr := dial_tcp_timeout(bound, time.Second)
	if !testing.expectf(t, derr == .None, "cannot dial the peer: %v", derr) {
		destroy(u)
		thread.join(peer)
		thread.destroy(peer)
		return .IO_Error, 0, 0
	}
	// What `get_h2_conn` builds once ALPN says h2, minus the TLS.
	_ = net.set_option(socket, .Receive_Timeout, 100 * time.Millisecond)
	sync.mutex_lock(&u.mu)
	u.proto = .H2
	u.h2 = start_h2_conn(u, Stream{socket = socket})
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
	resp, err = exchange_doh_h2(u, wire, body, 3 * time.Second, time.tick_add(time.tick_now(), 3 * time.Second), allocator)
	if err == .None {
		testing.expect_value(t, u16(resp[0]) << 8 | u16(resp[1]), query.id)
	}

	wait = max(-loop.moment_since(u.throttled_until), 0)

	// Tears the connection down, which ends the peer's read loop.
	destroy(u)
	thread.join(peer)
	thread.destroy(peer)
	free_all(context.temp_allocator)
	return err, sync.atomic_load(&p.headers), wait
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

/*
An answer there is no room to hand the caller is `Out_Of_Memory`, as over
HTTP/1.1: this server's failing, which `charges_member` does not hold against
the upstream, and not an empty answer.
*/
@(test)
test_a_doh_answer_without_room_is_this_servers :: proc(t: ^testing.T) {
	f := Fail_Nth {
		backing  = context.temp_allocator,
		fail_at  = 1,
		fail_for = 1,
	}
	err, headers := exchange_with_refusals(t, 0, fail_nth(&f))
	testing.expect_value(t, err, Error.Out_Of_Memory)
	testing.expect_value(t, headers, 1)
	testing.expect_value(t, f.seen, 1)
}

/*
A member that answered this query 429 is not asked it again in the query's
second round, with a `Retry-After` (RFC 9110 10.2.3) or without: the group's
other member timing out is no reason to go back to a server that has just said
it will refuse. The DoH member goes through `exchange` and a real group, on the
scripted peer; the other is a silent UDP mock.
*/
@(test)
test_a_member_that_refused_is_not_asked_again_in_the_same_query :: proc(t: ^testing.T) {
	for retry_after in ([]string{"120", ""}) {
		asked := ask_a_refusing_member_and_a_silent_one(t, retry_after)
		testing.expectf(t, asked == 1, "a member that answered 429 (Retry-After %q) in this query was asked %d times in it", retry_after, asked)
	}
}

@(private = "file")
ask_a_refusing_member_and_a_silent_one :: proc(t: ^testing.T, retry_after: string) -> (asked: int) {
	listener, lerr := net.listen_tcp(net.Endpoint{address = net.IP4_Loopback, port = 0})
	if !testing.expectf(t, lerr == nil, "cannot listen: %v", lerr) {
		return
	}
	defer net.close(listener)
	bound, berr := net.bound_endpoint(listener)
	if !testing.expectf(t, berr == nil, "cannot read the port: %v", berr) {
		return
	}
	head := make([dynamic]u8, 0, 64, context.temp_allocator)
	h2.encode_header(&head, ":status", "429")
	if retry_after != "" {
		h2.encode_header(&head, "retry-after", retry_after)
	}
	p := Refusing_Peer{listener = listener, head = head[:]}
	peer := thread.create_and_start_with_poly_data(&p, refusing_peer_run)
	a, aerr := make_upstream(config.Upstream_Spec{name = "refusing", kind = .HTTPS, address = "127.0.0.1", port = bound.port, hostname = "doh.invalid", path = "/dns-query", url = "https://doh.invalid/dns-query"}, 8, 30 * time.Second)
	if !testing.expectf(t, aerr == .None, "cannot make the upstream: %v", aerr) {
		thread.join(peer)
		thread.destroy(peer)
		return
	}
	socket, derr := dial_tcp_timeout(bound, time.Second)
	if !testing.expectf(t, derr == .None, "cannot dial the peer: %v", derr) {
		destroy(a)
		thread.join(peer)
		thread.destroy(peer)
		return
	}
	if serr := net.set_option(socket, .Receive_Timeout, 100 * time.Millisecond); !testing.expectf(t, serr == nil, "cannot bound the reader: %v", serr) {
		net.close(socket)
		destroy(a)
		thread.join(peer)
		thread.destroy(peer)
		return
	}
	sync.mutex_lock(&a.mu)
	a.proto = .H2
	a.h2 = start_h2_conn(a, Stream{socket = socket})
	sync.mutex_unlock(&a.mu)

	m: Echo_Mock
	m.mute = true
	b, worker, ok := start_udp_mock(t, &m, echo_mock_loop, "silent", 300 * time.Millisecond)
	if ok {
		msg := dns.Message{id = 0x3272, question = []dns.Question{{name = "r5.example.test.", type = .A, class = .IN}}}
		msg.flags.rd = true
		query, _, enc := dns.encode_message(msg, context.temp_allocator)
		testing.expect_value(t, enc, dns.Encode_Error.None)
		ups := []^Upstream{a, b}
		g := failover_group(ups, 300 * time.Millisecond, attempts = 2)
		resp, _, rerr := resolve(&g, query, context.allocator)
		delete(resp, context.allocator)
		testing.expectf(t, rerr != .None, "a group of a refusing and a silent member answered")
		asked = sync.atomic_load(&p.headers)
		stop_udp_mock(&m, worker, b)
	}
	destroy(a)
	thread.join(peer)
	thread.destroy(peer)
	free_all(context.temp_allocator)
	return
}
