package server

import "core:slice"
import "core:strings"
import "core:testing"
import "elodin:config"
import "elodin:dns"

/*
RFC 8145 4.1: a DNSKEY lookup for a trust anchor's zone carries the anchors' key
tags as an `edns-key-tag` option, two bytes each in network order, beside the DO
bit 4.2 asks for; a lookup given none carries no option.
*/
@(test)
test_an_upstream_query_carries_the_key_tags_it_is_given :: proc(t: ^testing.T) {
	tags := []u16{0x4f66, 0x9728}
	wire, built := upstream_query({name = ".", type = .DNSKEY, class = .IN}, true, true, context.temp_allocator, key_tags = tags)
	if !testing.expect(t, built, "the query was not built") {
		return
	}
	m, derr := dns.decode_message(wire, context.temp_allocator)
	if !testing.expectf(t, derr == .None, "the query does not decode: %v", derr) {
		return
	}
	data, found := dns.find_edns_option(m, .Key_Tag)
	testing.expect(t, found, "no edns-key-tag option")
	testing.expectf(t, slice.equal(data, []u8{0x4f, 0x66, 0x97, 0x28}), "the option holds %x, want 4f669728", data)
	testing.expect(t, dns.edns_do(m), "the DO bit is not set")

	plain, plain_built := upstream_query({name = ".", type = .DNSKEY, class = .IN}, true, true, context.temp_allocator)
	if testing.expect(t, plain_built, "the query without tags was not built") {
		pm, perr := dns.decode_message(plain, context.temp_allocator)
		if testing.expectf(t, perr == .None, "the query without tags does not decode: %v", perr) {
			_, has := dns.find_edns_option(pm, .Key_Tag)
			testing.expect(t, !has, "a query given no tags carries an edns-key-tag option")
		}
	}
	free_all(context.temp_allocator)
}

/*
A Key Tag query takes a place among the upstream waits before it is started
and gives it back when it cannot be: with every place taken it is not started
at all, and one turned away by `submit_query` (here a server with no loop to
run it on) leaves both counts as it found them.
*/
@(test)
test_a_key_tag_query_holds_an_upstream_wait_place :: proc(t: ^testing.T) {
	cfg: config.Config
	s := local_server(&cfg)
	cfg.server.max_pending = 8
	ceiling := upstream_wait_ceiling(&s)
	if !testing.expect(t, ceiling > 0, "the premise: max_pending sets a ceiling") {
		return
	}
	tags := []u16{20326}

	s.upstream_waits = ceiling
	send_key_tag_query(&s, ".", tags)
	testing.expect_value(t, s.upstream_waits, ceiling)
	testing.expect_value(t, s.pending, 0)

	s.upstream_waits = 0
	send_key_tag_query(&s, ".", tags)
	testing.expect_value(t, s.upstream_waits, 0)
	testing.expect_value(t, s.pending, 0)
}

/*
A Key Tag query that was started gives back its upstream-wait place and its
place among `max_pending` however it ends - here at once, on a zone no `_ta-`
name fits under - and frees what it was handed.
*/
@(test)
test_a_key_tag_query_job_gives_its_places_back :: proc(t: ^testing.T) {
	cfg: config.Config
	s := local_server(&cfg)
	label := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa."
	q := new(Key_Tag_Query)
	q.server = &s
	q.zone = strings.concatenate({label, label, label, label[:56]})
	q.tags = slice.clone([]u16{1})
	// As `send_key_tag_query` and `submit_query` leave them for the job.
	s.upstream_waits, s.pending = 1, 1
	key_tag_query_job(q)
	testing.expect_value(t, s.upstream_waits, 0)
	testing.expect_value(t, s.pending, 0)
}
