package upstream

import "core:mem"
import "core:testing"
import "elodin:dns"

/*
RFC 8484 section 5.1: a DoH client "MUST account for the Age response header
field's value [RFC7234] when calculating the DNS TTL of a response".
*/

// The final response's `Age`, the first of them; not an interim response's, and
// not one that does not parse.
@(test)
test_age_is_read_from_the_final_response :: proc(t: ^testing.T) {
	Row :: struct {
		reply: string,
		want:  u32,
	}
	rows := []Row {
		{reply = "HTTP/1.1 200 OK\r\nAge: 250\r\nContent-Length: 0\r\nConnection: close\r\n\r\n", want = 250},
		{reply = "HTTP/1.1 200 OK\r\nage: 250\r\nAge: 10\r\nContent-Length: 0\r\nConnection: close\r\n\r\n", want = 250},
		{reply = "HTTP/1.1 200 OK\r\nAge: soon\r\nAge: 10\r\nContent-Length: 0\r\nConnection: close\r\n\r\n", want = 0},
		{reply = "HTTP/1.1 103 Early Hints\r\nAge: 250\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n", want = 0},
		{reply = "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n", want = 0},
	}
	for row in rows {
		track: mem.Tracking_Allocator
		mem.tracking_allocator_init(&track, context.allocator)
		defer mem.tracking_allocator_destroy(&track)
		resp, err, ok := exchange_against(t, row.reply, &track)
		if !ok {
			continue
		}
		testing.expectf(t, err == .None, "%q: %v", row.reply, err)
		testing.expectf(t, resp.age == row.want, "%q: Age read as %d, want %d", row.reply, resp.age, row.want)
		if len(resp.body) > 0 {
			delete(resp.body, mem.tracking_allocator(&track))
		}
	}
}

// Every TTL loses the age, floored at zero; the OPT record's flags do not.
@(test)
test_age_ttls_takes_the_age_off_every_ttl :: proc(t: ^testing.T) {
	m := dns.Message {
		question   = []dns.Question{{name = "age.example.", type = .A, class = .IN}},
		answer     = []dns.Record{{name = "age.example.", type = .A, class = .IN, ttl = 600, data = dns.Rdata_A{addr = {10, 9, 9, 9}}}},
		authority  = []dns.Record{{name = "example.", type = .NS, class = .IN, ttl = 100, data = dns.Rdata_Name{name = "ns.example."}}},
		additional = []dns.Record{dns.make_opt(1232, true)},
	}
	m.flags.qr = true
	wire, _, err := dns.encode_message(m, context.temp_allocator)
	if !testing.expectf(t, err == .None, "the reply does not encode: %v", err) {
		return
	}
	age_ttls(wire, 250, context.allocator)
	got, derr := dns.decode_message(wire, context.temp_allocator)
	if !testing.expectf(t, derr == .None && len(got.answer) == 1 && len(got.authority) == 1, "the aged reply does not decode: %v", derr) {
		return
	}
	testing.expect_value(t, got.answer[0].ttl, u32(350))
	testing.expect_value(t, got.authority[0].ttl, u32(0))
	testing.expect(t, dns.edns_do(got), "the OPT record's DO bit was taken as a TTL")
	free_all(context.temp_allocator)
}
