package server

import "core:mem"
import "core:slice"
import "core:strings"
import "core:testing"
import "elodin:config"
import "elodin:dns"
import "elodin:dnssec"

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
run it on) leaves both counts as it found them. What it allocates says which
happened: nothing for the one never started, and the query built and freed
again for the one turned away.
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

	track: mem.Tracking_Allocator
	mem.tracking_allocator_init(&track, context.allocator)
	defer mem.tracking_allocator_destroy(&track)

	s.upstream_waits = ceiling
	{
		context.allocator = mem.tracking_allocator(&track)
		send_key_tag_query(&s, ".", tags)
	}
	testing.expect_value(t, s.upstream_waits, ceiling)
	testing.expect_value(t, s.pending, 0)
	testing.expectf(t, track.total_allocation_count == 0, "a query with no place to wait in was built: %d allocations", track.total_allocation_count)

	s.upstream_waits = 0
	{
		context.allocator = mem.tracking_allocator(&track)
		send_key_tag_query(&s, ".", tags)
	}
	testing.expect_value(t, s.upstream_waits, 0)
	testing.expect_value(t, s.pending, 0)
	testing.expect(t, track.total_allocation_count > 0, "a query with a place to wait in was never built")
	testing.expectf(t, len(track.allocation_map) == 0, "the query turned away kept %d allocations", len(track.allocation_map))
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

// The data of every `edns-key-tag` option in `wire`'s OPT record, in order.
@(private = "file")
sent_key_tags :: proc(t: ^testing.T, wire: []u8, loc := #caller_location) -> (lists: [dynamic][]u8, msg: dns.Message, ok: bool) {
	m, derr := dns.decode_message(wire, context.temp_allocator)
	if !testing.expectf(t, derr == .None, "the query does not decode: %v", derr, loc = loc) {
		return nil, {}, false
	}
	opt, has_opt := dns.find_opt(m)
	if !testing.expect(t, has_opt, "the query carries no OPT record", loc = loc) {
		return nil, {}, false
	}
	lists = make([dynamic][]u8, context.temp_allocator)
	for o in opt.data.(dns.Rdata_OPT).options {
		if o.code == u16(dns.EDNS_Option_Code.Key_Tag) {
			append(&lists, o.data)
		}
	}
	return lists, m, true
}

@(private = "file")
key_tag_option :: proc(data: ..u8) -> dns.EDNS_Option {
	return {code = u16(dns.EDNS_Option_Code.Key_Tag), data = slice.clone(data, context.temp_allocator)}
}

/*
RFC 8145 section 4.2.2.1: a client's Key Tag list that differs from this
server's goes upstream beside it, each in an `edns-key-tag` option of its own,
and section 4.2.2.2 has a non-validating server copy the client's. A client
list holding the same tags as this server's is not sent twice, nor one the
client repeated; one that is empty or not whole two-byte tags (section 4.1) is
not sent at all, and nor is any other option of the client's.
*/
@(test)
test_a_dnskey_query_carries_the_clients_key_tags_beside_this_servers :: proc(t: ^testing.T) {
	defer free_all(context.temp_allocator)
	client := []dns.EDNS_Option {
		key_tag_option(0x12, 0x34),
		{code = u16(dns.EDNS_Option_Code.Cookie), data = []u8{1, 2, 3, 4, 5, 6, 7, 8}},
		key_tag_option(0x46, 0xbd),
		key_tag_option(0x01, 0x02, 0x03),
		key_tag_option(),
		key_tag_option(0xab, 0xcd, 0x12, 0x34),
		// As long as a two-tag list of this server's, and inside it, but not all of it.
		key_tag_option(0x12, 0x34, 0x12, 0x34),
		key_tag_option(0x12, 0x34),
	}
	cases := []struct {
		own:  []u16,
		want: [][]u8,
	} {
		{own = {0x46bd}, want = {{0x46, 0xbd}, {0x12, 0x34}, {0xab, 0xcd, 0x12, 0x34}, {0x12, 0x34, 0x12, 0x34}}},
		{own = nil, want = {{0x12, 0x34}, {0x46, 0xbd}, {0xab, 0xcd, 0x12, 0x34}, {0x12, 0x34, 0x12, 0x34}}},
		// The same set in another order is the same list.
		{own = {0x1234, 0xabcd}, want = {{0x12, 0x34, 0xab, 0xcd}, {0x12, 0x34}, {0x46, 0xbd}, {0x12, 0x34, 0x12, 0x34}}},
		// A list that shares tags with this server's but is not the same set.
		{
			own = {0x3412, 0x1234, 0xabcd},
			want = {{0x34, 0x12, 0x12, 0x34, 0xab, 0xcd}, {0x12, 0x34}, {0x46, 0xbd}, {0xab, 0xcd, 0x12, 0x34}, {0x12, 0x34, 0x12, 0x34}},
		},
	}
	for c in cases {
		wire, built := upstream_query({name = "example.", type = .DNSKEY, class = .IN}, true, false, context.temp_allocator, key_tags = c.own, client_options = client)
		if !testing.expectf(t, built, "own %x: the query was not built", c.own) {
			continue
		}
		got, m, ok := sent_key_tags(t, wire)
		if !ok {
			continue
		}
		testing.expectf(t, len(got) == len(c.want), "own %x: %d edns-key-tag options sent (%x), want %d (%x)", c.own, len(got), got[:], len(c.want), c.want)
		for want, i in c.want {
			if i < len(got) {
				testing.expectf(t, slice.equal(got[i], want), "own %x: option %d holds %x, want %x", c.own, i, got[i], want)
			}
		}
		_, cookie := dns.find_edns_option(m, .Cookie)
		testing.expectf(t, !cookie, "own %x: the client's cookie went upstream", c.own)
	}
}

// RFC 8145 section 4.2: a client MUST NOT send `edns-key-tag` on a question
// for any other type, so a client's that came on one is not forwarded.
@(test)
test_a_clients_key_tags_go_only_on_a_dnskey_query :: proc(t: ^testing.T) {
	defer free_all(context.temp_allocator)
	client := []dns.EDNS_Option{key_tag_option(0x12, 0x34)}
	for type in ([]dns.Type{.DNSKEY, .A, .DS}) {
		wire, built := upstream_query({name = "example.", type = type, class = .IN}, true, false, context.temp_allocator, client_options = client)
		if !testing.expectf(t, built, "%v: the query was not built", type) {
			continue
		}
		if got, _, ok := sent_key_tags(t, wire); ok {
			testing.expectf(t, len(got) == (1 if type == .DNSKEY else 0), "%v: %d edns-key-tag options sent", type, len(got))
		}
	}
}

/*
The client's lists carry `dnssec.MAX_KEY_TAGS` tags between them at most, the
limit RFC 8145 section 4.2.2.1 recommends: the list that crosses it is cut
there, and the ones after it are not sent. This server's own list is held to
the same number apart from them.
*/
@(test)
test_a_clients_key_tags_are_capped :: proc(t: ^testing.T) {
	defer free_all(context.temp_allocator)
	tags :: proc(n: int, first: u8) -> dns.EDNS_Option {
		data := make([]u8, 2 * n, context.temp_allocator)
		for i in 0 ..< n {
			data[2 * i + 1] = first + u8(i)
		}
		return {code = u16(dns.EDNS_Option_Code.Key_Tag), data = data}
	}
	client := []dns.EDNS_Option{tags(dnssec.MAX_KEY_TAGS - 1, 1), tags(3, 100), tags(1, 200)}
	own := make([]u16, dnssec.MAX_KEY_TAGS + 2, context.temp_allocator)
	for &tag, i in own {
		tag = u16(0x4000 + i)
	}
	wire, built := upstream_query({name = "example.", type = .DNSKEY, class = .IN}, true, false, context.temp_allocator, key_tags = own, client_options = client)
	if !testing.expect(t, built, "the query was not built") {
		return
	}
	got, _, ok := sent_key_tags(t, wire)
	if !ok || !testing.expectf(t, len(got) == 3, "%d edns-key-tag options sent, want this server's and two of the client's", len(got)) {
		return
	}
	testing.expect_value(t, len(got[0]), 2 * dnssec.MAX_KEY_TAGS)
	testing.expect(t, slice.equal(got[1], client[0].data), "the client's first list was not sent whole")
	testing.expectf(t, slice.equal(got[2], client[1].data[:2]), "the list crossing the cap is %x, want its first tag %x", got[2], client[1].data[:2])
}

/*
`shape_forwarded` hands the client's own `edns-key-tag` option on with its
DNSKEY question while `dnssec.trust_anchor_signaling` is on, and not while it
is off: the switch is for an upstream that answers FORMERR to the option. With
no validator, as here, there is no list of this server's beside it (RFC 8145
section 4.2.2.2).
*/
@(test)
test_a_forwarded_dnskey_query_carries_the_clients_key_tags :: proc(t: ^testing.T) {
	defer free_all(context.temp_allocator)
	wire := test_query("example.", .DNSKEY, opt = opt_with(.Key_Tag, []u8{0x12, 0x34}, do_bit = true))
	msg, derr := dns.decode_message(wire, context.temp_allocator)
	if !testing.expectf(t, derr == .None, "the client's query does not decode: %v", derr) {
		return
	}
	for signalling in ([]bool{true, false}) {
		cfg: config.Config
		s := local_server(&cfg)
		cfg.dnssec.trust_anchor_signaling = signalling
		spent: int
		st := stage_state(&s, msg, &spent, context.temp_allocator)
		if !testing.expectf(t, !shape_forwarded(&st), "signalling %v: the query was answered rather than forwarded", signalling) {
			continue
		}
		got, _, ok := sent_key_tags(t, st.forwarded)
		if !ok {
			continue
		}
		if !signalling {
			testing.expectf(t, len(got) == 0, "signalling off: %d edns-key-tag options went upstream (%x)", len(got), got[:])
		} else if testing.expectf(t, len(got) == 1, "%d edns-key-tag options went upstream, want the client's", len(got)) {
			testing.expectf(t, slice.equal(got[0], []u8{0x12, 0x34}), "the option holds %x, want 1234", got[0])
		}
	}
}
