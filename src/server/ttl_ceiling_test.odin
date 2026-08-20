package server

import "core:net"
import "core:testing"
import "core:thread"
import "core:time"
import "elodin:cache"
import "elodin:config"
import "elodin:dns"
import "elodin:upstream"

/*
What a forwarded answer tells the client to hold the record for.

The cache bounds the copies it serves by bounding what it stores, which leaves
the copy handed to the client on the miss that filled the entry - the upstream's
own bytes, on their way past. That is the client the ceiling has to reach most:
it is the one whose query fetched the record, so a name that is looked up once
is pinned in the only cache that ever sees it. Driven against a real socket
because the whole point is a response that came from off this machine.
*/

@(private = "file")
HOSTILE_NAME :: "hostile.example."

@(private = "file")
Ttl_Exchange :: struct {
	socket: net.UDP_Socket,
	reply:  []u8,
	got:    bool,
}

// One query, then done; joined by the caller before `got` is read. The socket
// carries a receive timeout, so a query that never arrives ends the thread
// rather than the run.
@(private = "file")
serve_one_ttl :: proc(x: ^Ttl_Exchange) {
	buf: [4096]u8
	n, remote, err := net.recv_udp(x.socket, buf[:])
	if err != nil || n < dns.HEADER_SIZE || len(x.reply) > len(buf) {
		return
	}
	x.got = true

	out: [4096]u8
	copy(out[:], x.reply)
	// The resolver draws a fresh ID for every query it forwards, so the reply
	// has to echo what arrived rather than carry an ID fixed in advance.
	out[0], out[1] = buf[0], buf[1]
	_, _ = net.send_udp(x.socket, out[:len(x.reply)], remote)
}

@(private = "file")
hostile_query :: proc() -> []u8 {
	questions := make([]dns.Question, 1, context.temp_allocator)
	questions[0] = dns.Question {
		name  = HOSTILE_NAME,
		type  = .A,
		class = .IN,
	}
	msg := dns.Message {
		id       = 0x2468,
		question = questions,
	}
	msg.flags.rd = true
	wire, _, err := dns.encode_message(msg, context.temp_allocator)
	if err != .None {
		return nil
	}
	return wire
}

@(private = "file")
upstream_reply :: proc(ttl: u32) -> []u8 {
	answer := make([]dns.Record, 1, context.temp_allocator)
	answer[0] = dns.Record {
		name  = HOSTILE_NAME,
		type  = .A,
		class = .IN,
		ttl   = ttl,
		data  = dns.Rdata_A{addr = {192, 0, 2, 7}},
	}
	question := make([]dns.Question, 1, context.temp_allocator)
	question[0] = dns.Question {
		name  = HOSTILE_NAME,
		type  = .A,
		class = .IN,
	}
	msg := dns.Message {
		question = question,
		answer   = answer,
	}
	msg.flags.qr = true
	msg.flags.rd = true
	msg.flags.ra = true
	wire, _, err := dns.encode_message(msg, context.temp_allocator)
	if err != .None {
		return nil
	}
	return wire
}

/*
Forward one query to a mock upstream that answers with `ttl`, and report the TTL
the client is handed.

`ok` false means the exchange itself did not happen, which the caller reports
rather than reading a TTL out of nothing.
*/
@(private = "file")
forwarded_ttl :: proc(t: ^testing.T, ttl: u32, max_ttl: u32) -> (served: u32, ok: bool) {
	socket, serr := net.make_bound_udp_socket(net.IP4_Loopback, 0)
	if !testing.expectf(t, serr == nil, "cannot bind the mock upstream: %v", serr) {
		return 0, false
	}
	defer net.close(socket)
	_ = net.set_option(socket, .Receive_Timeout, 2 * time.Second)
	bound, berr := net.bound_endpoint(socket)
	if !testing.expectf(t, berr == nil, "cannot read the mock's port: %v", berr) {
		return 0, false
	}

	answers := cache.make_cache(cache.Options{max_entries = 8, max_ttl = max_ttl})
	defer cache.destroy(answers)

	cfg := config.default_config()
	cfg.log.queries = false
	cfg.blocking.enabled = false
	cfg.cache.max_ttl = max_ttl
	cfg.upstream.strategy = .Failover
	// One try, so a case that is going wrong says so instead of retrying.
	cfg.upstream.attempts = 1
	cfg.upstream.timeout = 5 * time.Second
	servers := make([]config.Upstream_Spec, 1, context.temp_allocator)
	servers[0] = config.Upstream_Spec {
		name    = "mock",
		kind    = .UDP,
		address = "127.0.0.1",
		port    = bound.port,
	}
	cfg.upstream.servers = servers

	group, gerr := upstream.make_group(cfg.upstream, nil, context.allocator, false)
	if !testing.expectf(t, gerr == .None, "cannot build the upstream group: %v", gerr) {
		return 0, false
	}
	defer upstream.destroy_group(group)

	s := Server {
		cfg     = &cfg,
		answers = answers,
		group   = group,
	}

	x := Ttl_Exchange {
		socket = socket,
		reply  = upstream_reply(ttl),
	}
	mock := thread.create_and_start_with_poly_data(&x, serve_one_ttl)
	out, outcome, done := handle_query(&s, hostile_query(), .UDP, "127.0.0.1:5555", context.temp_allocator)
	thread.join(mock)
	thread.destroy(mock)

	if !testing.expect(t, x.got, "the upstream was never asked") {
		return 0, false
	}
	if !testing.expect(t, done, "nothing came back at all") {
		return 0, false
	}
	testing.expect_value(t, outcome, Outcome.Forwarded)

	served_msg, derr := dns.decode_message(out, context.temp_allocator)
	if !testing.expect(t, derr == .None, "the forwarded copy did not decode") {
		return 0, false
	}
	if !testing.expect(t, len(served_msg.answer) == 1, "the forwarded copy carried no record") {
		return 0, false
	}
	return served_msg.answer[0].ttl, true
}

/*
RFC 2181 section 8, on the path that does not go through the cache:

	Implementations should treat TTL values received with the most significant
	bit set as if the entire value received was zero.

`cache.put` refuses such an answer, which is section 8 as far as this server's
own storage goes, but refusing to keep it is not the same as refusing to pass it
on: the client that caused the fetch still gets the response, and 2^31 seconds
is sixty-eight years in whatever holds it next. One answer, no follow-up
traffic, and nothing in the operator's logs to say it happened.
*/
@(test)
test_a_forwarded_high_bit_ttl_reaches_the_client_as_zero :: proc(t: ^testing.T) {
	ttl, ok := forwarded_ttl(t, 0x8000_0000, 86400)
	if !ok {
		return
	}
	testing.expect_value(t, ttl, u32(0))
	free_all(context.temp_allocator)
}

/*
And `cache.max_ttl` bounds the forwarded copy as well as the cached one.

The answer a miss forwards is the same answer the next client is handed out of
the entry it just filled. Bounding one and not the other would leave the setting
skipping exactly one client per fetch - the one that asked first - which is the
reading dnsmasq's `--max-ttl` has never had: the maximum TTL handed out to
clients.
*/
@(test)
test_max_ttl_bounds_a_forwarded_answer :: proc(t: ^testing.T) {
	ttl, ok := forwarded_ttl(t, 86400, 60)
	if !ok {
		return
	}
	testing.expect_value(t, ttl, u32(60))
	free_all(context.temp_allocator)
}
