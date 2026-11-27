package server

import "core:net"
import "core:strings"
import "core:testing"
import "elodin:config"
import "elodin:testkit"

/*
A datagram that proves its source with a server cookie is charged to a pool of
its own once the datagram pool turns it away, so a flood spoofing its prefix cannot
have it dropped (issue #296).
*/


// The datagram pool's rate, and so its burst, in every case here.
@(private = "file")
RATE :: 10

@(private = "file")
BURST :: RATE * RRL_BURST_SECONDS

// A query for `example.` carrying `cookie` in its OPT record, or no OPT record
// when `cookie` is nil.
@(private = "file")
cookie_query :: proc(cookie: []u8) -> []u8 {
	if cookie == nil {
		return test_query("example.", id = 0x2960, rd = false)
	}
	return test_query("example.", id = 0x2960, rd = false, opt = opt_with(.Cookie, cookie))
}

// The cookie this server would hand `client`, minted through the string path
// `handle_query` takes, so a test that verifies it through the endpoint path is
// also a test that the two read an address the same way.
@(private = "file")
issued_to :: proc(k: ^Cookie_Keeper, client: net.Endpoint) -> [COOKIE_REPLY_LEN]u8 {
	req: Cookie_Request
	copy(req.client[:], testkit.unhex(RFC9018_CLIENT_COOKIE))
	ok: bool
	req.ip_len, ok = cookie_client_ip(net.endpoint_to_string(client, context.temp_allocator), req.ip[:])
	if !ok {
		panic("the client's address does not bind a cookie")
	}
	return make_cookie(k, req, cookie_now())
}

@(test)
test_a_cookie_client_is_not_dropped_with_a_flood_naming_its_prefix :: proc(t: ^testing.T) {
	r := make_rate_limiter(RATE, 0)
	defer destroy_rate_limiter(r)
	k := secret_keeper(RFC9018_SECRET_KEY)

	client := net.Endpoint{address = net.IP4_Address{203, 0, 113, 7}, port = 30000}
	spoofed := net.Endpoint{address = net.IP4_Address{203, 0, 113, 99}, port = 40000}
	cookie := issued_to(&k, client)
	with_cookie := cookie_query(cookie[:])

	// The flood empties the prefix's datagram pool.
	plain := cookie_query(nil)
	for _ in 0 ..< BURST * 4 {
		datagram_rate_check(r, &k, plain, spoofed, limiter_tick(0))
	}
	v, proven := datagram_rate_check(r, &k, plain, client, limiter_tick(0))
	testing.expect_value(t, v, Rate_Verdict.Drop)
	testing.expect(t, !proven, "a query with no cookie was taken as proven")

	// The same client with its cookie is answered, out of the rescue pool.
	v, proven = datagram_rate_check(r, &k, with_cookie, client, limiter_tick(0))
	testing.expect_value(t, v, Rate_Verdict.Allow)
	testing.expect(t, proven, "a valid server cookie was not taken as proof of the source")

	// The cookie is bound to the address: a spoofer replaying it from another
	// address in the prefix is metered like the rest of the flood.
	v, proven = datagram_rate_check(r, &k, with_cookie, spoofed, limiter_tick(0))
	testing.expect_value(t, v, Rate_Verdict.Drop)
	testing.expect(t, !proven, "a cookie was accepted from an address it was not issued to")

	// A forged hash proves nothing.
	forged := cookie
	forged[COOKIE_REPLY_LEN - 1] ~= 1
	v, proven = datagram_rate_check(r, &k, cookie_query(forged[:]), client, limiter_tick(0))
	testing.expect_value(t, v, Rate_Verdict.Drop)
	testing.expect(t, !proven, "a forged server cookie was taken as proof")

	// Nor does a cookie when this server is not issuing them.
	_, proven = datagram_rate_check(r, nil, with_cookie, client, limiter_tick(0))
	testing.expect(t, !proven, "a cookie was judged with cookies off")
	free_all(context.temp_allocator)
}

/*
A cookie costs a client nothing it had: the datagram pool pays first and keeps
the slip, the `Proven` pool is spent only on what it turned away, and with both
empty the slip's verdict stands.
*/
@(test)
test_a_cookie_client_spends_the_datagram_pool_first :: proc(t: ^testing.T) {
	r := make_rate_limiter(RATE, 2)
	defer destroy_rate_limiter(r)
	k := secret_keeper(RFC9018_SECRET_KEY)

	client := net.Endpoint{address = net.IP4_Address{198, 51, 100, 5}, port = 30000}
	cookie := issued_to(&k, client)
	query := cookie_query(cookie[:])

	on_datagram, on_proven := 0, 0
	for _ in 0 ..< BURST * 2 {
		v, proven := datagram_rate_check(r, &k, query, client, limiter_tick(0))
		testing.expect_value(t, v, Rate_Verdict.Allow)
		if proven {
			on_proven += 1
		} else {
			testing.expect(t, on_proven == 0, "the datagram pool paid after the proven pool had")
			on_datagram += 1
		}
	}
	testing.expect_value(t, on_datagram, BURST)
	testing.expect_value(t, on_proven, BURST)
	// Never the stream pool, which a replayed cookie must not reach.
	streamed := 0
	for _ in 0 ..< BURST {
		if stream_rate_check(r, client, limiter_tick(0)) {
			streamed += 1
		}
	}
	testing.expect_value(t, streamed, BURST)

	// Both empty: the datagram pool's slip still offers TCP.
	truncated := 0
	for _ in 0 ..< 4 {
		if v, proven := datagram_rate_check(r, &k, query, client, limiter_tick(0)); v == .Truncate {
			truncated += 1
			testing.expect(t, !proven, "a slip was reported as paid by the proven pool")
		}
	}
	testing.expect_value(t, truncated, 2)
	free_all(context.temp_allocator)
}

// What a rescued answer weighs is billed to the pool that admitted it, so a
// cookie that outlived its address aims no more bytes at it than a datagram.
@(test)
test_a_rescued_answer_is_billed_to_the_proven_pool :: proc(t: ^testing.T) {
	r := make_rate_limiter(RATE, 0, response_size_estimate = 100)
	defer destroy_rate_limiter(r)
	client := net.Endpoint{address = net.IP4_Address{192, 0, 2, 5}, port = 30000}

	// Ten tokens' worth, nine beyond the one the admission took.
	rate_charge_response(r, client, 1000, limiter_tick(0), .Proven)
	rescued, streamed, datagrams := 0, 0, 0
	for _ in 0 ..< BURST {
		if spend_token(r, client, limiter_tick(0), .Proven) {
			rescued += 1
		}
		if stream_rate_check(r, client, limiter_tick(0)) {
			streamed += 1
		}
		if rate_check(r, client, limiter_tick(0)) == .Allow {
			datagrams += 1
		}
	}
	testing.expect_value(t, rescued, BURST - 9)
	testing.expect_value(t, streamed, BURST)
	testing.expect_value(t, datagrams, BURST)
}

// `::ffff:a.b.c.d` hashes as the sixteen bytes it arrived as on both paths, so
// a cookie issued with an answer verifies in the read loop.
@(test)
test_a_mapped_cookie_client_proves_its_source :: proc(t: ^testing.T) {
	k := secret_keeper(RFC9018_SECRET_KEY)
	addr: net.IP6_Address
	addr[5] = 0xffff
	addr[6] = u16be(0xc633)
	addr[7] = u16be(0x6405)
	client := net.Endpoint{address = addr, port = 30000}
	cookie := issued_to(&k, client)
	testing.expect(t, cookie_proves_source(&k, cookie_query(cookie[:]), client), "a mapped client's cookie did not verify")
	free_all(context.temp_allocator)
}

/*
A cookie replayed by whoever saw it - on the path, or as the address's previous
holder - spends the rescue pool and nothing more: the prefix's connections keep
the stream pool a datagram cannot reach.
*/
@(test)
test_a_replayed_cookie_cannot_refuse_the_prefix_connections :: proc(t: ^testing.T) {
	r := make_rate_limiter(RATE, 0)
	defer destroy_rate_limiter(r)
	k := secret_keeper(RFC9018_SECRET_KEY)

	victim := net.Endpoint{address = net.IP4_Address{203, 0, 113, 7}, port = 30000}
	cookie := issued_to(&k, victim)
	replay := cookie_query(cookie[:])
	for _ in 0 ..< BURST * 10 {
		datagram_rate_check(r, &k, replay, victim, limiter_tick(0))
	}

	neighbour := net.Endpoint{address = net.IP4_Address{203, 0, 113, 50}, port = 443}
	streamed := 0
	for _ in 0 ..< BURST {
		if stream_rate_check(r, neighbour, limiter_tick(0)) {
			streamed += 1
		}
	}
	testing.expect_value(t, streamed, BURST)
	testing.expect(t, conn_rate_check(r, neighbour, limiter_tick(0)), "the replay spent the connection pool")
	free_all(context.temp_allocator)
}

// With cookies on, the byte figure an operator is shown holds twice over, since
// rescued answers are weighed against a pool of their own; the lines say so.
@(test)
test_the_byte_figure_says_a_cookie_doubles_it :: proc(t: ^testing.T) {
	line, said := rate_limit_denomination_line(500, 128, 1232, context.temp_allocator, cookies = true)
	testing.expect(t, said && strings.contains(line, COOKIE_RESCUE_BYTES), "the startup line hides the rescue pool's bytes")
	line, said = rate_limit_denomination_line(500, 128, 1232, context.temp_allocator)
	testing.expect(t, said && !strings.contains(line, COOKIE_RESCUE_BYTES), "the rescue pool was named with cookies off")

	prefix, parsed := config.parse_prefix("198.51.100.0/24")
	if !testing.expect(t, parsed, "the override's prefix does not parse") {
		return
	}
	overrides := []config.Rate_Limit_Override{{prefix = prefix, responses_per_second = 4000, slip = 2}}
	lines := rate_limit_override_lines(overrides, 128, 1232, context.temp_allocator, cookies = true)
	testing.expect(t, len(lines) == 2 && strings.contains(lines[1], COOKIE_RESCUE_BYTES), "an override's line hides the rescue pool's bytes")
	free_all(context.temp_allocator)
}
