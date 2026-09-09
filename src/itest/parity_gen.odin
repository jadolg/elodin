package itest

import "core:fmt"
import "core:mem"
import "core:strings"

/*
The query side of the parity check: a seeded generator of DNS queries, built
byte by byte rather than with `elodin:dns` for the reason `parity_wire.odin`
gives.

Every query a run sends comes from one 64-bit seed, printed on both the passing
and the failing path, so a divergence found on CI at three in the morning is
reproduced with `--parity-seed`. That is the whole reason the generator carries
its own PRNG instead of calling `core:math/rand`: a seed has to mean the same
sequence next year as it did tonight, and only an algorithm written down here
can promise that.
*/

Pg_Rand :: struct {
	state: u64,
}

// SplitMix64. Chosen for being short enough to read and fixed forever, which is
// what a reproducible seed needs; nothing here wants a better generator.
pg_next :: proc(r: ^Pg_Rand) -> u64 {
	r.state += 0x9e3779b97f4a7c15
	z := r.state
	z = (z ~ (z >> 30)) * 0xbf58476d1ce4e5b9
	z = (z ~ (z >> 27)) * 0x94d049bb133111eb
	return z ~ (z >> 31)
}

pg_int :: proc(r: ^Pg_Rand, n: int) -> int {
	if n <= 0 {
		return 0
	}
	return int(pg_next(r) % u64(n))
}

// True `percent` times in a hundred.
pg_chance :: proc(r: ^Pg_Rand, percent: int) -> bool {
	return pg_int(r, 100) < percent
}

pg_pick :: proc(r: ^Pg_Rand, options: []$T) -> T {
	return options[pg_int(r, len(options))]
}

Parity_Transport :: enum u8 {
	UDP,
	TCP,
	DoT,
	DoH,
}

pg_transport_name :: proc(t: Parity_Transport) -> string {
	switch t {
	case .UDP:
		return "udp"
	case .TCP:
		return "tcp"
	case .DoT:
		return "dot"
	case .DoH:
		return "doh"
	}
	return "?"
}

Parity_Query :: struct {
	wire:      []u8,
	id:        u16,
	// The question as sent, in wire form and with the case as sent, so the
	// echo can be checked byte for byte.
	name:      []u8,
	qtype:     u16,
	qclass:    u16,
	rd:        bool,
	cd:        bool,
	ad:        bool,
	edns:      bool,
	udp_size:  u16,
	version:   u8,
	do_bit:    bool,
	// The EDNS options the query carried, in order.
	options:   []Pw_Option,
	transport: Parity_Transport,
	/*
	The server answers this one out of its own mouth rather than forwarding it,
	so there is no upstream answer to hold it against.

	Set for the two shapes that are defined to be refused at the edge: an EDNS
	version this server does not implement, which RFC 6891 section 6.1.3 says to
	answer with BADVERS rather than pass on, and a class the resolver serves
	locally. Those are checked, just not for parity - see
	`parity_check_local_answer`.
	*/
	local:     bool,
	desc:      string,
}

Parity_Gen :: struct {
	rand: Pg_Rand,
	// Names to ask about. Mock mode supplies synthetic ones its upstream can
	// answer for; live mode supplies real ones.
	pool: []string,
	// Transports this run may use. DoT and DoH are only in it when the suite
	// has a certificate.
	transports: []Parity_Transport,
	// Include the shapes the server answers itself. Off for a run whose whole
	// business is comparing against an upstream.
	include_local: bool,
}

pg_make :: proc(seed: u64, pool: []string, transports: []Parity_Transport) -> Parity_Gen {
	return Parity_Gen {
		rand = Pg_Rand{state = seed},
		pool = pool,
		transports = transports,
		include_local = true,
	}
}

/*
Query types worth asking for, weighted by how much of the codec they reach
rather than by how often the internet asks for them.

The unmodelled ones carry the most risk and so appear the most: a type this
server has no structure for travels as opaque RDATA, and opaque RDATA is exactly
what a re-encode drops or truncates without anything noticing. TYPE64000 and
TYPE65534 are unassigned, which is the point - nothing in the path may need to
recognise a type to carry it (RFC 3597 section 2).
*/
@(private = "file")
PG_QTYPES := []u16 {
	1, // A
	28, // AAAA
	5, // CNAME
	15, // MX
	16, // TXT
	2, // NS
	6, // SOA
	12, // PTR
	33, // SRV
	35, // NAPTR
	257, // CAA
	64, // SVCB
	65, // HTTPS
	52, // TLSA
	44, // SSHFP
	43, // DS
	48, // DNSKEY
	46, // RRSIG
	47, // NSEC
	50, // NSEC3
	13, // HINFO
	17, // RP
	18, // AFSDB
	21, // RT
	26, // PX
	24, // SIG
	29, // LOC
	39, // DNAME
	61, // OPENPGPKEY
	256, // URI
	99, // SPF
	108, // EUI48
	255, // ANY
	64000, // unassigned
	65534, // unassigned, private use
}

@(private = "file")
PG_UDP_SIZES := []u16{512, 1232, 1400, 4096, 65535}

// EDNS option codes the generator sends. The unassigned one is deliberate: a
// resolver must carry an option it does not know or drop it, and which of those
// it does is a thing to see rather than to assume.
@(private = "file")
PG_OPTION_CODES := []u16 {
	3, // NSID
	8, // EDNS Client Subnet
	10, // COOKIE
	11, // TCP keepalive
	12, // padding
	15, // extended DNS error
	65001, // unassigned, local use
}

pg_query :: proc(g: ^Parity_Gen, allocator := context.temp_allocator) -> Parity_Query {
	q: Parity_Query
	r := &g.rand

	q.id = u16(pg_next(r) & 0xffff)
	q.name = pg_name(g, allocator)
	q.qtype = pg_pick(r, PG_QTYPES)
	q.qclass = 1
	// A handful of queries in a class the resolver does not forward. CHAOS is
	// answered locally (version.bind and friends); the rest should be refused.
	if g.include_local && pg_chance(r, 3) {
		q.qclass = pg_pick(r, []u16{3, 4, 254, 255})
		q.local = true
	}

	// A query without RD is not forwarded anywhere: this server refuses it
	// itself, so it belongs with the other shapes that never reach an upstream.
	q.rd = true
	if g.include_local && pg_chance(r, 3) {
		q.rd = false
		q.local = true
	}
	q.cd = pg_chance(r, 15)
	q.ad = pg_chance(r, 10)

	q.edns = !pg_chance(r, 15)
	if q.edns {
		q.udp_size = pg_pick(r, PG_UDP_SIZES)
		q.do_bit = pg_chance(r, 50)
		if g.include_local && pg_chance(r, 3) {
			// An EDNS version this server does not implement. RFC 6891 section
			// 6.1.3 has it answered with BADVERS at the edge, not forwarded.
			q.version = u8(1 + pg_int(r, 3))
			q.local = true
		}
		q.options = pg_options(g, allocator)
	}

	q.transport = pg_pick(r, g.transports)
	q.wire = pg_encode(q, allocator)
	q.desc = pg_describe(q, allocator)
	return q
}

@(private = "file")
pg_options :: proc(g: ^Parity_Gen, allocator: mem.Allocator) -> []Pw_Option {
	r := &g.rand
	if pg_chance(r, 55) {
		return nil
	}
	count := 1 + pg_int(r, 3)
	out := make([dynamic]Pw_Option, 0, count, allocator)
	for _ in 0 ..< count {
		code := pg_pick(r, PG_OPTION_CODES)
		already := false
		for o in out {
			if o.code == code {
				already = true
			}
		}
		// One option per code: a second is a defect of its own and belongs in a
		// case that says so, not scattered through a parity run where it would
		// read as the resolver mishandling the first.
		if !already {
			append(&out, Pw_Option{code = code, data = pg_option_data(g, code, allocator)})
		}
	}
	return out[:]
}

/*
Build the option's payload.

Each is a shape a real client sends, because the question is whether the
resolver carries or strips what it was given, and an option it can tell is
nonsense is a weaker test than one it cannot.
*/
@(private = "file")
pg_option_data :: proc(g: ^Parity_Gen, code: u16, allocator: mem.Allocator) -> []u8 {
	r := &g.rand
	switch code {
	case 3:
		// NSID is empty in a query; the server fills it in a response.
		return nil
	case 8:
		// A /24 of 192.0.2.0, source-only, as a stub resolver sends it.
		out := make([]u8, 7, allocator)
		out[0], out[1] = 0, 1 // IPv4
		out[2], out[3] = 24, 0 // source prefix, scope
		out[4], out[5], out[6] = 192, 0, 2
		return out
	case 10:
		// An eight-byte client cookie and nothing else, which is what a client
		// with no server cookie yet sends (RFC 7873 section 5.2.1).
		out := make([]u8, 8, allocator)
		for i in 0 ..< 8 {
			out[i] = u8(pg_next(r) & 0xff)
		}
		return out
	case 11:
		// A client's keepalive request carries no timeout.
		return nil
	case 12:
		n := pg_int(r, 64)
		return make([]u8, n, allocator)
	case 15:
		// Extended DNS Error, which a query has no business carrying. Sent
		// anyway: an option a resolver has an opinion about is where a strip
		// that should not happen happens.
		out := make([]u8, 2, allocator)
		return out
	}
	n := pg_int(r, 8)
	out := make([]u8, n, allocator)
	for i in 0 ..< n {
		out[i] = u8(pg_next(r) & 0xff)
	}
	return out
}

// --- names -----------------------------------------------------------------

@(private = "file")
PG_LABEL_ALPHABET := "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_"

/*
A question name in wire form.

Mostly names from the pool, so most of a run asks things the upstream has real
answers for. The rest are the shapes that are legal and rarely sent: the root,
a maximum-length label, a name close to the 255-byte ceiling, and labels holding
bytes outside the letter-digit-hyphen convention, which the wire permits and a
resolver must carry unaltered.
*/
@(private = "file")
pg_name :: proc(g: ^Parity_Gen, allocator: mem.Allocator) -> []u8 {
	r := &g.rand

	switch {
	case pg_chance(r, 2):
		out := make([]u8, 1, allocator)
		return out

	case pg_chance(r, 3):
		// One label of the full 63 bytes, under a pool zone.
		label := make([]u8, 63, allocator)
		for i in 0 ..< 63 {
			label[i] = PG_LABEL_ALPHABET[pg_int(r, len(PG_LABEL_ALPHABET))]
		}
		return pg_join(g, [][]u8{label}, allocator)

	case pg_chance(r, 3):
		// A name near the 255-byte ceiling: four 60-byte labels leave room for
		// a short zone and the root.
		labels := make([][]u8, 3, allocator)
		for j in 0 ..< 3 {
			label := make([]u8, 60, allocator)
			for i in 0 ..< 60 {
				label[i] = PG_LABEL_ALPHABET[pg_int(r, len(PG_LABEL_ALPHABET))]
			}
			labels[j] = label
		}
		return pg_join(g, labels, allocator)

	case pg_chance(r, 4):
		// Bytes a hostname would never hold. Legal on the wire, and a resolver
		// that normalises them has changed the question it was asked.
		n := 1 + pg_int(r, 12)
		label := make([]u8, n, allocator)
		for i in 0 ..< n {
			label[i] = u8(pg_next(r) & 0xff)
		}
		return pg_join(g, [][]u8{label}, allocator)

	case pg_chance(r, 35):
		// A fresh subdomain, which in mock mode is answered from the synthetic
		// zone and in live mode is an NXDOMAIN both sides should agree on.
		depth := 1 + pg_int(r, 3)
		labels := make([][]u8, depth, allocator)
		for j in 0 ..< depth {
			n := 1 + pg_int(r, 12)
			label := make([]u8, n, allocator)
			for i in 0 ..< n {
				label[i] = PG_LABEL_ALPHABET[pg_int(r, len(PG_LABEL_ALPHABET))]
			}
			labels[j] = label
		}
		return pg_join(g, labels, allocator)
	}

	name := pg_encode_name(pg_pick(r, g.pool), allocator)
	if pg_chance(r, 40) {
		pg_randomise_case(r, name)
	}
	return name
}

// Put labels in front of a randomly chosen pool zone.
@(private = "file")
pg_join :: proc(g: ^Parity_Gen, labels: [][]u8, allocator: mem.Allocator) -> []u8 {
	zone := pg_encode_name(pg_pick(&g.rand, g.pool), allocator)
	total := len(zone)
	for l in labels {
		total += 1 + len(l)
	}
	if total > PW_MAX_NAME {
		return zone
	}
	out := make([]u8, total, allocator)
	pos := 0
	for l in labels {
		out[pos] = u8(len(l))
		copy(out[pos + 1:], l)
		pos += 1 + len(l)
	}
	copy(out[pos:], zone)
	return out
}

@(private = "file")
pg_encode_name :: proc(text: string, allocator: mem.Allocator) -> []u8 {
	trimmed := strings.trim_suffix(text, ".")
	if trimmed == "" {
		out := make([]u8, 1, allocator)
		return out
	}
	// One length byte per label plus the root's zero: the dots become length
	// bytes one for one, so the wire form is the text plus two.
	out := make([]u8, len(trimmed) + 2, allocator)
	pos := 0
	rest := trimmed
	for label in strings.split_iterator(&rest, ".") {
		out[pos] = u8(len(label))
		copy(out[pos + 1:], label)
		pos += 1 + len(label)
	}
	out[pos] = 0
	return out
}

/*
Flip the case of a name's letters at random.

This is the 0x20 encoding a stub uses to make an off-path forgery guess a bit
per letter as well as the transaction ID. A resolver has to echo the question
back exactly as it arrived, or the client throws away its own answer, so the
echo is checked byte for byte rather than case-insensitively.
*/
@(private = "file")
pg_randomise_case :: proc(r: ^Pg_Rand, name: []u8) {
	pos := 0
	for pos < len(name) {
		n := int(name[pos])
		if n == 0 || pos + 1 + n > len(name) {
			return
		}
		for i in pos + 1 ..< pos + 1 + n {
			c := name[i]
			if c >= 'a' && c <= 'z' && pg_chance(r, 50) {
				name[i] = c - 32
			} else if c >= 'A' && c <= 'Z' && pg_chance(r, 50) {
				name[i] = c + 32
			}
		}
		pos += 1 + n
	}
}

// --- encoding --------------------------------------------------------------

@(private = "file")
pg_encode :: proc(q: Parity_Query, allocator: mem.Allocator) -> []u8 {
	buf := make([dynamic]u8, 0, 128, allocator)

	flags := u16(0)
	if q.rd {
		flags |= 0x0100
	}
	if q.ad {
		flags |= 0x0020
	}
	if q.cd {
		flags |= 0x0010
	}

	pg_put16(&buf, q.id)
	pg_put16(&buf, flags)
	pg_put16(&buf, 1)
	pg_put16(&buf, 0)
	pg_put16(&buf, 0)
	pg_put16(&buf, q.edns ? 1 : 0)

	append(&buf, ..q.name)
	pg_put16(&buf, q.qtype)
	pg_put16(&buf, q.qclass)

	if q.edns {
		append(&buf, 0) // root owner name
		pg_put16(&buf, 41)
		pg_put16(&buf, q.udp_size)
		append(&buf, 0) // extended rcode: a query never carries one
		append(&buf, q.version)
		pg_put16(&buf, q.do_bit ? PW_DO : 0)

		rdata := make([dynamic]u8, 0, 32, allocator)
		for o in q.options {
			pg_put16(&rdata, o.code)
			pg_put16(&rdata, u16(len(o.data)))
			append(&rdata, ..o.data)
		}
		pg_put16(&buf, u16(len(rdata)))
		append(&buf, ..rdata[:])
	}
	return buf[:]
}

@(private = "file")
pg_put16 :: proc(buf: ^[dynamic]u8, v: u16) {
	append(buf, u8(v >> 8), u8(v))
}

@(private = "file")
pg_describe :: proc(q: Parity_Query, allocator: mem.Allocator) -> string {
	sb := strings.builder_make(allocator)
	fmt.sbprintf(
		&sb,
		"%s TYPE%d CLASS%d over %s",
		pw_name_text(q.name, allocator),
		q.qtype,
		q.qclass,
		pg_transport_name(q.transport),
	)
	if q.rd {
		strings.write_string(&sb, " rd")
	}
	if q.ad {
		strings.write_string(&sb, " ad")
	}
	if q.cd {
		strings.write_string(&sb, " cd")
	}
	if q.edns {
		fmt.sbprintf(&sb, " edns%d/%d", q.version, q.udp_size)
		if q.do_bit {
			strings.write_string(&sb, "+do")
		}
		for o in q.options {
			fmt.sbprintf(&sb, " opt%d", o.code)
		}
	} else {
		strings.write_string(&sb, " no-edns")
	}
	return strings.to_string(sb)
}
