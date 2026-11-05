package server

import "core:mem"
import "elodin:config"
import "elodin:dns"

/*
The bytes `encode_block_response` writes for a blocked name, written directly.

A blocked name is answered at whatever rate a client asks, and building that
answer as a `dns.Message` for the general encoder - its compression map, its
dynamic arrays, a fold and a hash per suffix - costs a quarter more than a
cache hit, which is a copy. Every block answer has one shape: the question,
then one A or AAAA record owned by it or the SOA `synth_soa` makes for its
parent, then the client's OPT record echoed, so it is written here as that.

Byte for byte the encoder's, which `blockwire_test.odin` checks against the
encoder itself rather than a model of it. The encoder compresses the record's
owner against the question, which is the pointer written here: to the question
for an address record, to its second label for the SOA (`dns.name_parent`
splits at the same unescaped dot `dns.encode_name` does). The SOA's own names
are compressed only against a question that ends in them, under `localhost.`
or `invalid.`, and such a question is left to the encoder, as is the root and
anything that will not fit `limit`.
*/
@(private)
block_wire :: proc(
	s: ^Server,
	query: dns.Message,
	q: dns.Question,
	allocator: mem.Allocator,
	limit: int,
	typed_only: bool,
) -> (
	out: []u8,
	ok: bool,
) {
	b := &live(s).cfg.blocking
	// Every byte up to `p` is written before it is read or copied out.
	buf: [512]u8 = ---
	n, err := dns.encode_name(q.name, buf[dns.HEADER_SIZE:])
	if err != .None || n <= 1 || ends_in_soa_name(buf[dns.HEADER_SIZE:][:n]) {
		return nil, false
	}
	p := dns.HEADER_SIZE + n
	wire_u16(buf[:], &p, u16(q.type))
	wire_u16(buf[:], &p, u16(q.class))

	rcode := block_rcode(b.response, typed_only)
	answers, authority, additional: u16
	if addr := block_address(b, q.type); len(addr) > 0 {
		// Owned by the question's name, at the start of the question.
		answers = 1
		wire_u16(buf[:], &p, 0xc000 | dns.HEADER_SIZE)
		wire_u16(buf[:], &p, u16(q.type))
		wire_u16(buf[:], &p, u16(dns.Class.IN))
		wire_u32(buf[:], &p, b.block_ttl)
		wire_u16(buf[:], &p, u16(len(addr)))
		p += copy(buf[p:], addr)
	} else if rcode != .Refused {
		authority = 1
		put_soa(buf[:], &p, buf[dns.HEADER_SIZE], b.block_ttl)
	}
	if _, found := dns.find_opt(query); found {
		// `dns.make_opt` with no extended rcode: none of these reach 16.
		additional = 1
		p += copy(buf[p:], []u8{0, 0, u8(dns.Type.OPT)})
		wire_u16(buf[:], &p, dns.edns_udp_size(query))
		wire_u32(buf[:], &p, 0x8000 if dns.edns_do(query) else 0)
		wire_u16(buf[:], &p, 0)
	}
	if p > limit {
		return nil, false
	}

	// `dns.make_response`'s flags.
	flags := dns.Flags {
		qr     = true,
		opcode = query.flags.opcode,
		rd     = query.flags.rd,
		ra     = true,
		cd     = query.flags.cd,
		rcode  = u8(rcode),
	}
	h := 0
	header := [6]u16{query.id, transmute(u16)flags, 1, answers, authority, additional}
	for v in header {
		wire_u16(buf[:], &h, v)
	}
	out = make([]u8, p, allocator)
	copy(out, buf[:p])
	return out, true
}

// The rcode `encode_block_response` answers with; see there for why.
@(private)
block_rcode :: proc(response: config.Block_Response, typed_only: bool) -> dns.Rcode {
	#partial switch response {
	case .NX_Domain:
		return .No_Error if typed_only else .NX_Domain
	case .Refused:
		return .Refused
	}
	return .No_Error
}

// The address a `zeroip` or `custom` block answers `qtype` with, if any.
@(private)
block_address :: proc(b: ^config.Blocking_Config, qtype: dns.Type) -> []u8 {
	#partial switch b.response {
	case .Zero_IP:
		@(static) zero: [16]u8
		#partial switch qtype {
		case .A:
			return zero[:4]
		case .AAAA:
			return zero[:]
		}
	case .Custom_IP:
		#partial switch qtype {
		case .A:
			return b.custom_ipv4[:]
		case .AAAA:
			return b.custom_ipv6[:]
		}
	}
	return nil
}

/*
`synth_soa_for_zone`'s record, owned by the question's parent: the label after
the first, `first_label` bytes in, or the question itself where it has one label.
*/
@(private)
put_soa :: proc(buf: []u8, p: ^int, first_label: u8, ttl: u32) {
	owner := dns.HEADER_SIZE + 1 + int(first_label)
	if buf[owner] == 0 {
		owner = dns.HEADER_SIZE
	}
	wire_u16(buf, p, 0xc000 | u16(owner))
	wire_u16(buf, p, u16(dns.Type.SOA))
	wire_u16(buf, p, u16(dns.Class.IN))
	wire_u32(buf, p, ttl)
	rdata := "\x09localhost\x00\x0ahostmaster\x07invalid\x00"
	wire_u16(buf, p, u16(len(rdata) + 20))
	p^ += copy(buf[p^:], rdata)
	fields := [5]u32{1, 3600, 900, 604800, ttl}
	for v in fields {
		wire_u32(buf, p, v)
	}
}

// Whether a wire name's last label is one the SOA's names end in.
@(private)
ends_in_soa_name :: proc(wire: []u8) -> bool {
	last, i := 0, 0
	for wire[i] != 0 {
		last = i
		i += 1 + int(wire[i])
	}
	label := string(wire[last + 1:][:wire[last]])
	return dns.name_equal_fold(label, "localhost") || dns.name_equal_fold(label, "invalid")
}

@(private)
wire_u16 :: proc(buf: []u8, p: ^int, v: u16) {
	buf[p^], buf[p^ + 1] = u8(v >> 8), u8(v)
	p^ += 2
}

@(private)
wire_u32 :: proc(buf: []u8, p: ^int, v: u32) {
	wire_u16(buf, p, u16(v >> 16))
	wire_u16(buf, p, u16(v))
}
