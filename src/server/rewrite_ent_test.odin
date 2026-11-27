package server

import "core:fmt"
import "core:sync"
import "core:testing"
import "elodin:config"
import "elodin:dns"

/*
An upstream NXDOMAIN for a name a rewrite answers at or below goes out as
NODATA: the name exists here (RFC 1034 section 3.1), and an RFC 8020 cache
would take a name error for it as denying the rewrite's names too.
*/

@(private = "file")
ent_rules :: proc() -> []config.Rewrite {
	rules := make([]config.Rewrite, 4, context.temp_allocator)
	rules[0] = {domain = "a.b.rw.example.", ttl = 300, ptr = true, answers = answers_of({kind = .A, v4 = {192, 168, 1, 50}})}
	rules[1] = {domain = "wild.example.", wildcard = true, ttl = 300, answers = answers_of({kind = .A, v4 = {10, 0, 0, 1}})}
	rules[2] = {domain = "mx.example.", ttl = 300, answers = answers_of({kind = .MX, preference = 10, name = "mail.example."})}
	rules[3] = {domain = "mxw.example.", wildcard = true, ttl = 300, answers = answers_of({kind = .MX, preference = 10, name = "mail.example."})}
	return rules
}

// An upstream's NXDOMAIN for `name`, with the zone's SOA, an NSEC after it when
// `signed`, and before it the records in `chain`.
@(private = "file")
nx_reply :: proc(name: string, chain: ..dns.Record, signed := false) -> []u8 {
	soa := [2]dns.Record {
		{
			name = "example.",
			type = .SOA,
			class = .IN,
			ttl = 3600,
			data = dns.Rdata_SOA{ns = "ns.example.", mbox = "h.example.", serial = 1, refresh = 2, retry = 3, expire = 4, minimum = 3600},
		},
		// Next name the root, a bitmap of window 0 holding A.
		{name = "example.", type = .NSEC, class = .IN, ttl = 3600, data = dns.Rdata_Raw{data = []u8{0, 0, 1, 0x40}}},
	}
	return test_reply(name, .A, ..chain, rcode = .NX_Domain, authority = soa[:2 if signed else 1])
}

@(test)
test_an_nxdomain_above_a_rewrite_goes_out_as_nodata :: proc(t: ^testing.T) {
	Row :: struct {
		name:   string,
		chain:  []dns.Record,
		signed: bool,
		want:   dns.Rcode,
		reason: string,
	}
	// One link past `dns.MAX_ALIAS_REFERRAL_RECORDS`, ending above a rule.
	long := make([]dns.Record, dns.MAX_ALIAS_REFERRAL_RECORDS + 1, context.temp_allocator)
	for &rec, i in long {
		owner := "long.example." if i == 0 else fmt.tprintf("l%d.example.", i)
		target := "b.rw.example." if i == len(long) - 1 else fmt.tprintf("l%d.example.", i + 1)
		rec = cname_record(owner, target)
	}
	rows := []Row {
		{name = "b.rw.example.", want = .No_Error, reason = "an empty non-terminal above a rule"},
		{name = "rw.example.", want = .No_Error, reason = "two labels above a rule"},
		{name = "wild.example.", want = .No_Error, reason = "a wildcard rule's own domain"},
		{name = "mx.example.", want = .No_Error, reason = "a type an additive rule leaves to the upstream"},
		{name = "x.mxw.example.", want = .No_Error, reason = "a name an additive wildcard rule matches"},
		{name = "1.168.192.in-addr.arpa.", want = .No_Error, reason = "above a rule's synthesised PTR"},
		{
			name = "alias.example.",
			chain = []dns.Record{cname_record("alias.example.", "b.rw.example.")},
			want = .No_Error,
			reason = "a CNAME chain that ends above a rule",
		},
		{name = "nx.example.", want = .NX_Domain, reason = "a name no rule is at or below"},
		{name = "c.rw.example.", want = .NX_Domain, reason = "a sibling of a rule's ancestor"},
		{name = "x.a.b.rw.example.", want = .NX_Domain, reason = "below a rule that is not a wildcard"},
		{
			name = "b.rw.example.",
			chain = []dns.Record{cname_record("b.rw.example.", "gone.example.")},
			want = .NX_Domain,
			reason = "a chain from above a rule to a name that is not",
		},
		{name = "b.rw.example.", signed = true, want = .NX_Domain, reason = "a signed denial: its NSEC proves a name error"},
		{name = "long.example.", chain = long, want = .NX_Domain, reason = "a chain past the bound it is followed to"},
		{
			name = "b.rw.example.",
			chain = []dns.Record{cname_record("b.rw.example.", "x.example."), cname_record("x.example.", "b.rw.example.")},
			want = .NX_Domain,
			reason = "a chain that loops, so has no end",
		},
		{
			name = "alias.example.",
			chain = []dns.Record {
				cname_record("alias.example.", "b.rw.example."),
				cname_record("b.rw.example.", "x.example."),
				cname_record("x.example.", "b.rw.example."),
			},
			want = .NX_Domain,
			reason = "a chain that loops past the question's name",
		},
	}
	h: Harness
	if !harness_start(t, &h) {
		return
	}
	defer harness_stop(&h)
	h.cfg.rewrites = ent_rules()
	// So the reverse name is forwarded rather than answered from the RFC 6303 zone.
	h.cfg.special_use.private_reverse = false

	for row, i in rows {
		reply := nx_reply(row.name, ..row.chain, signed = row.signed)
		// EDNS, so the long chain fits a datagram.
		out, outcome, served, asked := harness_ask(&h, test_query(row.name, id = u16(0x7020 + i), opt = dns.make_opt(4096, false)), reply)
		if !testing.expectf(t, served && asked, "%s (%s): served %v, upstream asked %v", row.name, row.reason, served, asked) {
			continue
		}
		testing.expectf(t, outcome == .Forwarded, "%s (%s): outcome %v", row.name, row.reason, outcome)
		m, err := dns.decode_message(out, context.temp_allocator)
		if !testing.expectf(t, err == .None, "%s: the answer does not decode: %v", row.name, err) {
			continue
		}
		testing.expectf(t, dns.rcode_of(m) == row.want, "%s (%s): rcode %v, want %v", row.name, row.reason, dns.rcode_of(m), row.want)
		testing.expectf(t, len(m.authority) >= 1 && m.authority[0].type == .SOA, "%s (%s): authority %v, want the SOA", row.name, row.reason, m.authority)
		testing.expectf(t, len(m.answer) == len(row.chain), "%s (%s): %d answers, want %d", row.name, row.reason, len(m.answer), len(row.chain))
	}
	free_all(context.temp_allocator)
}

/*
The answer the client is sent is the one the cache keeps: a second query is
served NODATA from the entry, with the upstream not asked.
*/
@(test)
test_the_nodata_over_a_rewrite_is_what_is_cached :: proc(t: ^testing.T) {
	h: Harness
	if !harness_start(t, &h, caching = true) {
		return
	}
	defer harness_stop(&h)
	h.cfg.rewrites = ent_rules()

	for i in 0 ..< 2 {
		out, _, served, asked := harness_ask(&h, test_query("b.rw.example.", id = u16(0x7040 + i)), nx_reply("b.rw.example."))
		if !testing.expectf(t, served, "query %d: nothing served", i) {
			return
		}
		testing.expectf(t, asked == (i == 0), "query %d: upstream asked %v", i, asked)
		testing.expectf(t, dns.peek_rcode(out) == .No_Error, "query %d: rcode %v, want NOERROR", i, dns.peek_rcode(out))
	}
	free_all(context.temp_allocator)
}

/*
A NXDOMAIN this server proved Secure keeps its rcode, AD or not; an upstream's
own AD on an answer nothing here checked is not a proof of anything.
*/
@(test)
test_a_validated_nxdomain_above_a_rewrite_is_left_alone :: proc(t: ^testing.T) {
	Row :: struct {
		proven: bool,
		ad:     bool,
		want:   dns.Rcode,
	}
	rows := []Row {
		{proven = true, ad = true, want = .NX_Domain},
		// Proved, but AD cleared for an answer that could not be rebuilt, and
		// the NSEC stripped for a DO=0 client: still proved.
		{proven = true, ad = false, want = .NX_Domain},
		// An upstream's AD on an answer nothing here checked proves nothing.
		{proven = false, ad = true, want = .No_Error},
	}
	cfg: config.Config
	cfg.rewrites = ent_rules()
	s := Server {
		cfg = &cfg,
	}
	for row in rows {
		resp := nx_reply("b.rw.example.")
		set_ad_bit(resp, row.ad)
		st := Query_State {
			s          = &s,
			q          = {name = "b.rw.example.", type = .A, class = .IN},
			proven     = row.proven,
			resp       = resp,
			allocator  = context.temp_allocator,
		}
		nodata_over_rewrite(&st)
		testing.expectf(t, dns.peek_rcode(resp) == row.want, "%v: rcode %v, want %v", row, dns.peek_rcode(resp), row.want)
	}
	free_all(context.temp_allocator)
}

/*
Inside a zone this server answers itself, the same holds without an upstream: a
name above a rule exists, and so does an additive rule's own name for the types
it leaves out. NODATA, not NXDOMAIN, in every zone that denies names.
*/
@(test)
test_a_rewrite_makes_its_names_exist_in_the_special_use_zones :: proc(t: ^testing.T) {
	cfg: config.Config
	s := local_server(&cfg)
	cfg.dnssec.enabled = false
	cfg.special_use.home_arpa = true
	cfg.special_use.test = true
	cfg.special_use.local = true
	mx := answers_of({kind = .MX, preference = 10, name = "mx.example."})
	addr := answers_of({kind = .A, v4 = {192, 168, 1, 9}})
	cfg.rewrites = []config.Rewrite {
		{domain = "mail.lan.home.arpa.", ttl = 300, answers = mx},
		{domain = "app.dev.test.", ttl = 300, answers = addr},
		{domain = "nas.local.", ttl = 300, answers = mx},
		{domain = "x.y.invalid.", ttl = 300, answers = addr},
	}
	Row :: struct {
		name: string,
		want: dns.Rcode,
	}
	rows := []Row {
		{name = "mail.lan.home.arpa.", want = .No_Error},
		{name = "lan.home.arpa.", want = .No_Error},
		{name = "other.lan.home.arpa.", want = .NX_Domain},
		{name = "dev.test.", want = .No_Error},
		{name = "test.", want = .No_Error},
		{name = "prod.test.", want = .NX_Domain},
		{name = "nas.local.", want = .No_Error},
		{name = "other.local.", want = .NX_Domain},
		{name = "y.invalid.", want = .No_Error},
		{name = "z.invalid.", want = .NX_Domain},
	}
	before := sync.atomic_load(&s.stats.special_use)
	for row in rows {
		m := ask_message(t, &s, row.name, .AAAA)
		testing.expectf(t, dns.rcode_of(m) == row.want, "%s AAAA: rcode %v, want %v", row.name, dns.rcode_of(m), row.want)
		testing.expectf(t, len(m.answer) == 0, "%s AAAA: %d answers", row.name, len(m.answer))
		testing.expectf(t, len(m.authority) == 1 && m.authority[0].type == .SOA, "%s AAAA: authority %v, want the SOA", row.name, m.authority)
	}
	// Every one is a special-use answer, logged and counted as one, not as a
	// private reverse zone's.
	counted := sync.atomic_load(&s.stats.special_use) - before
	testing.expectf(t, counted == u64(len(rows)), "special_use counted %d of %d", counted, len(rows))
	// The premise: the rules answer their own types.
	for q in ([]struct {
			name: string,
			type: dns.Type,
		}{{"mail.lan.home.arpa.", .MX}, {"app.dev.test.", .A}, {"nas.local.", .MX}, {"x.y.invalid.", .A}}) {
		m := ask_message(t, &s, q.name, q.type)
		testing.expectf(t, len(m.answer) == 1, "%s %v: %d answers, want the rule's", q.name, q.type, len(m.answer))
	}
	free_all(context.temp_allocator)
}

