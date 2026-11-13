package itest

import "core:time"
import "elodin:dns"

/*
Issue #165: a cached answer is not served past its signatures, fresh or stale.

RFC 4034 section 3.1.5: an RRSIG "MUST NOT be used for authentication after the
expiration date". The mock answers with an A record and an RRSIG over it that
expires three seconds from now. Validation is off, so nothing here has checked the
signature and the cache is the only thing that can hold to it. The answer must
go out telling the client no more than the signature has left. Once the clock is
past the expiration, with the upstream silent, `serve_stale` must not hand the
day-long stale copy out; the client is answered SERVFAIL instead.
*/
@(private = "file")
RX_QNAME :: "signed.stale.example."

// The answer the mock serves, its RRSIG lapsing at `expiration`; nil when it
// cannot be encoded.
@(private = "file")
rx_answer :: proc(expiration: u32) -> []u8 {
	sig := make([]u8, 31, context.temp_allocator)
	copy(sig, []u8{0, 1, 13, 3, 0, 0, 0x0e, 0x10})
	dns.write_ttl_at(sig, 8, expiration)
	dns.write_ttl_at(sig, 12, expiration - 86400) // inception
	copy(sig[16:], []u8{0x12, 0x34, 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0, 0xde, 0xad, 0xbe, 0xef})
	answer := make([]dns.Record, 2, context.temp_allocator)
	answer[0] = {name = RX_QNAME, type = .A, class = .IN, ttl = 3600, data = dns.Rdata_A{addr = {203, 0, 113, 65}}}
	answer[1] = {name = RX_QNAME, type = .RRSIG, class = .IN, ttl = 3600, data = dns.Rdata_Raw{data = sig}}
	return encode_reply(RX_QNAME, .A, {id = 0x1650, answer = answer})
}

run_rrsig_expiry_cases :: proc(r: ^Runner) {
	upstream_port := next_port(r)
	udp_port := next_port(r)
	config := base_config(
		udp_port,
		upstream_at(upstream_port),
		timeout = "1s",
		upstream_extra = "  attempts: 1",
		cache = "{ enabled: true, max_entries: 100, serve_stale: true, stale_timeout: 300ms }",
		extra = "dnssec: { enabled: false }",
	)
	srv, ok := start_server(r, Server_Options{config = config, udp_port = udp_port})
	if !ok {
		return
	}
	defer stop_server(&srv)

	// The clock is read once the server is up, so a slow start cannot spend the
	// signature before the first query and leave both cases nothing to test.
	expiration := u32(time.time_to_unix(time.now())) + 3
	answer := rx_answer(expiration)
	if answer == nil {
		fail(r, "cannot encode the signed answer for %s", RX_QNAME)
		return
	}
	mock := mock_make("rrsig-expiry", upstream_port)
	mock_reply(mock, RX_QNAME, u16(dns.Type.A), answer)
	if !mock_start_or_skip(r, mock, "cache: rrsig expiry") {
		return
	}
	defer mock_stop(mock)

	start_case(r, "cache: a signed answer is told no more ttl than its rrsig has left")
	{
		before := u32(time.time_to_unix(time.now()))
		res := query_udp(udp_port, build_query(RX_QNAME, u16(dns.Type.A), id = 1, edns_size = 1232, dnssec_ok = true))
		after := u32(time.time_to_unix(time.now()))
		if check(r, res.ok, "no response to the query that filled the cache") {
			ttl, has := min_answer_ttl(r, res.wire)
			// Exactly what the signature had left when elodin read the clock,
			// somewhere between `before` and `after`; and at least one, so the
			// answer was live enough to be cached for the case below.
			check(
				r,
				has && ttl >= 1 && ttl + after >= expiration && ttl + before <= expiration,
				"the answer went out with ttl %d; its rrsig had %d-%d s left",
				ttl,
				expiration - min(after, expiration),
				expiration - before,
			)
		}
	}
	end_case(r)

	start_case(r, "cache: serve_stale does not serve an answer past its rrsig")
	{
		// Wait for the clock, not a duration: the case is about the expiration
		// second having passed. Bounded on the tick clock, so a wall clock
		// stepped back fails the case rather than hanging the run.
		deadline := time.tick_add(time.tick_now(), 10 * time.Second)
		for u32(time.time_to_unix(time.now())) <= expiration && time.tick_diff(time.tick_now(), deadline) > 0 {
			time.sleep(100 * time.Millisecond)
		}
		if !check(r, u32(time.time_to_unix(time.now())) > expiration, "the wall clock never passed the rrsig's expiration") {
			end_case(r)
			return
		}
		mock_go_silent(mock)
		res := query_udp(udp_port, build_query(RX_QNAME, u16(dns.Type.A), id = 2, edns_size = 1232, dnssec_ok = true))
		if check(r, res.ok, "no response once the upstream went silent") {
			h := parse_header(r, res.wire)
			check_eq_int(r, h.rcode, int(dns.Rcode.Serv_Fail), "rcode once the only copy's rrsig has expired")
		}
	}
	end_case(r)
}
