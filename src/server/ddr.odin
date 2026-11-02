package server

import "core:fmt"
import "core:mem"
import "core:net"
import "core:strings"
import "core:sync"
import "elodin:config"
import "elodin:dns"
import "elodin:netx"
import "elodin:tlsx"

/*
Discovery of Designated Resolvers, answered here rather than forwarded.

RFC 9462 gives a client one question to ask before it commits to plain Do53: the
SVCB record at `_dns.resolver.arpa`, which the resolver it is already talking to
answers with its own encrypted endpoints. The name is special-use (RFC 9462
section 8.1) and locally served - no authoritative server on the Internet holds
it, and every answer is minted by whoever the client asked.

Which is the problem with forwarding it. The answer that comes back is the
*upstream's* designation - Quad9's DoT and DoH endpoints, say - and the client
takes it as this server's own and moves its traffic there. It stops asking us:
the block lists, the rewrites, the query log and the local zones all leave with
it, and the LAN sees a resolver silently swapped out from under it. The
certificate would not check out either, since this server's address is not in
the upstream's SAN list, so the client is as likely to end up with nothing that
works. RFC 9462 section 6.1 says it plainly: a DNS forwarder SHOULD NOT forward
queries for `resolver.arpa` (or any subdomains) upstream.

Forwarding it has a second cost that is what brought this to notice. The `arpa`
zone is signed and `resolver.arpa` is not in it - a query for the DS lands on
NXDOMAIN with an NSEC proving the name does not exist - so an upstream's
synthesised, unsigned SVCB answer under a signed parent is, to a validator,
exactly what a forged answer looks like. The verdict is Bogus, the client is
handed SERVFAIL, and an operator gets a `dnssec: SVCB _dns.resolver.arpa ... did
not validate` line for every client that probes. Both problems have the same
answer: the question never leaves.

What it is answered with is this server's own designation, when `ddr.name` names
one, and NODATA otherwise - NOERROR, no records, an SOA to say how long to
remember that, which RFC 9462 section 4 asks of a resolver with no Designated
Resolver. The client then stays on Do53 and keeps talking to us.

The designation is one SVCB record per encrypted listener, minted here from the
listener settings (RFC 9461): `alpn` for what the listener negotiates, `port`
only where it is not the protocol's default - the key is automatically
mandatory, so a client that does not support it drops the record - and, for DoH,
`dohpath`. It is unsigned under a signed `arpa`, the same shape as the NODATA, and
is never cached or forwarded. A listener is designated only while its
certificate covers `ddr.name`: the listener refuses to start on one that does
not, and a renewal that drops the name stops that listener's designation rather
than send clients to a certificate they cannot verify. See `ddr_designate`.

`rewrites` are applied ahead of all this, and a rule for the name wins, in the
same spirit as a trust anchor overriding the locally-served bypass.
*/

// Which encrypted listeners have a certificate that covers `ddr.name`, as of
// their last (re)load. Written by the listeners and read by every query, hence
// atomic. Zero, as a `Server` built as a literal has it, designates nothing.
DDR_Designation :: struct {
	dot: bool,
	doh: bool,
}

// The SVCB owner name a DDR client asks (RFC 9462 section 4).
@(private)
DDR_QNAME :: "_dns.resolver.arpa."

// SvcParamKeys (RFC 9460 section 14.3.2, RFC 9461 section 5).
@(private)
SVC_KEY_ALPN :: u16(1)
@(private)
SVC_KEY_PORT :: u16(3)
@(private)
SVC_KEY_DOHPATH :: u16(7)

/*
Record whether `ctx`, the certificate `listener` now serves, covers `ddr.name`.

Called when a DoT or DoH listener loads its certificate, at startup and on every
reload. Returns false when a name is set and not covered, for the caller to say
so; nothing is designated through that listener until a certificate that covers
it is loaded.
*/
ddr_designate :: proc(s: ^Server, listener: Protocol, ctx: ^tlsx.Context) -> bool {
	name := strings.trim_suffix(startup_config(s).ddr.name, ".")
	covered := name != "" && ctx != nil && tlsx.signer_covers_host(ctx.signer, name)
	#partial switch listener {
	case .DoT:
		sync.atomic_store(&s.ddr.dot, covered)
	case .DoH:
		sync.atomic_store(&s.ddr.doh, covered)
	}
	return name == "" || covered
}
@(private)
RESOLVER_ARPA :: "resolver.arpa."

// How long a client is asked to remember that there is nothing here. Short
// enough that turning designation on later is noticed the same day, long enough
// that a client probing on every lookup is not asking us again each time.
@(private)
RESOLVER_ARPA_TTL :: u32(300)

// Whether `name` is the DDR zone or a name inside it. Same label-boundary and
// case-folding rules as the locally-served zones next door.
//
// Named a second time in `config.check_route_reachable`, which refuses an
// `upstream.zones` route into this zone: it is answered here before anything is
// forwarded and no key turns that off, so such a route could only ever sit in
// the file looking configured. The config package cannot import this one, hence
// the second copy of the name.
@(private)
is_resolver_arpa :: proc(name: string) -> bool {
	return name_at_or_below(name, RESOLVER_ARPA)
}

/*
The answer for a name in `resolver.arpa`: the designation for an SVCB question
at `_dns.resolver.arpa` when there is one, and NODATA for everything else.

The SOA names the zone itself rather than the question's parent - `synth_soa`
would hand back `arpa.` for a query at the apex, which is not a zone this server
has any business claiming.
*/
@(private)
build_resolver_arpa_response :: proc(
	s: ^Server,
	query: dns.Message,
	q: dns.Question,
	allocator: mem.Allocator,
	limit: int,
) -> []u8 {
	resp := dns.make_response(query, .No_Error, allocator)
	if q.type == .SVCB && dns.name_equal_fold(q.name, DDR_QNAME) {
		resp.answer = ddr_records(s, q.name, allocator)
	}
	if len(resp.answer) == 0 {
		resp.authority = synth_soa_for_zone(RESOLVER_ARPA, RESOLVER_ARPA_TTL, allocator)
	} else {
		resp.additional = ddr_addresses(live(s).cfg, allocator)
	}

	// Addresses that do not fit are dropped by the encoder without TC: they only
	// save the client a lookup (RFC 9462 section 4).
	out, _, err := dns.encode_message(resp, allocator, limit)
	if err != .None {
		fallback, _ := dns.error_response(nil, query, .No_Error, allocator, limit)
		return fallback
	}
	return out
}

// One SVCB record per designated listener, in ServiceMode with priority 1:
// neither transport is preferred over the other, and the client picks.
@(private)
ddr_records :: proc(s: ^Server, owner: string, allocator: mem.Allocator) -> []dns.Record {
	cfg := live(s).cfg
	if cfg.ddr.name == "" {
		return nil
	}
	records := make([dynamic]dns.Record, 0, 2, allocator)
	if sync.atomic_load(&s.ddr.dot) {
		params := svc_params(DOT_ALPN, cfg.listeners.dot.port, 853, "", allocator)
		append(&records, ddr_record(owner, cfg.ddr.name, params))
	}
	if sync.atomic_load(&s.ddr.doh) {
		dohpath := strings.concatenate({cfg.listeners.doh.path, "{?dns}"}, allocator)
		params := svc_params(DOH_ALPN, cfg.listeners.doh.port, 443, dohpath, allocator)
		append(&records, ddr_record(owner, cfg.ddr.name, params))
	}
	return records[:]
}

@(private)
ddr_record :: proc(owner, target: string, params: []u8) -> dns.Record {
	return dns.Record {
		name = owner,
		type = .SVCB,
		class = .IN,
		ttl = RESOLVER_ARPA_TTL,
		data = dns.Rdata_SVCB{priority = 1, target = target, params = params},
	}
}

// SvcParams in wire form, keys in increasing order (RFC 9460 section 2.2).
@(private)
svc_params :: proc(alpn: []string, port, default_port: int, dohpath: string, allocator: mem.Allocator) -> []u8 {
	b := make([dynamic]u8, 0, 64, allocator)
	put_u16 :: proc(b: ^[dynamic]u8, v: u16) {
		append(b, u8(v >> 8), u8(v))
	}
	// The ALPN list as TLS writes it, each protocol behind its length.
	alpn_len := 0
	for p in alpn {
		alpn_len += 1 + len(p)
	}
	put_u16(&b, SVC_KEY_ALPN)
	put_u16(&b, u16(alpn_len))
	for p in alpn {
		append(&b, u8(len(p)))
		append(&b, ..transmute([]u8)p)
	}
	if port != default_port {
		put_u16(&b, SVC_KEY_PORT)
		put_u16(&b, 2)
		put_u16(&b, u16(port))
	}
	if dohpath != "" {
		put_u16(&b, SVC_KEY_DOHPATH)
		put_u16(&b, u16(len(dohpath)))
		append(&b, ..transmute([]u8)dohpath)
	}
	return b[:]
}

/*
The A and AAAA records for the designated name, for the Additional section,
which RFC 9462 section 4 says the answer SHOULD carry.

Only what this server answers for the name itself without forwarding - the
`rewrites` rule that claims it, with the precedence `apply_rewrite` gives it -
since that is where an operator writes the local address of a name whose public
one is elsewhere, and so the address that lets a client on the LAN use the
designation opportunistically (RFC 9462 section 4.3). With no such rule there
is nothing local to say, and the client asks for the name the ordinary way.
*/
@(private)
ddr_addresses :: proc(cfg: ^config.Config, allocator: mem.Allocator) -> []dns.Record {
	from := 0
	for {
		i, found := find_rewrite_index(cfg.rewrites, cfg.ddr.name, from)
		if !found {
			return nil
		}
		rule := cfg.rewrites[i]
		if !rule_claims_name(rule) {
			from = i + 1
			continue
		}
		records := make([dynamic]dns.Record, 0, len(rule.answers), allocator)
		for a in rule.answers {
			#partial switch a.kind {
			case .A:
				append(&records, dns.Record{name = cfg.ddr.name, type = .A, class = .IN, ttl = rule.ttl, data = dns.Rdata_A{addr = a.v4}})
			case .AAAA:
				append(&records, dns.Record{name = cfg.ddr.name, type = .AAAA, class = .IN, ttl = rule.ttl, data = dns.Rdata_AAAA{addr = a.v6}})
			}
		}
		return records[:]
	}
}

/*
What `--check` says about `ddr.name`, which the loader cannot: it does not open
the certificates, and it does not look names up.

`problems` are what the listeners would refuse to start on - a certificate that
does not cover the name, or does not load. `warnings` are about where the name
leads: the addresses a client is handed for it - the `rewrites` rule that claims
it, as `ddr_addresses` puts in the answer, or else what it resolves to from here
- should include one an encrypted listener on this machine is bound to. One that
does not is not refused, since a port forwarded from elsewhere is a reason it
may be right, but a client following it reaches some other host.
*/
ddr_check :: proc(cfg: ^config.Config, allocator := context.allocator) -> (problems: []string, warnings: []string) {
	if cfg.ddr.name == "" {
		return nil, nil
	}
	bad := make([dynamic]string, allocator)
	warn := make([dynamic]string, allocator)
	host := strings.trim_suffix(cfg.ddr.name, ".")

	listeners := [2]struct {
		key: string,
		ln:  config.Listener,
	}{{"dot", cfg.listeners.dot}, {"doh", cfg.listeners.doh}}
	for l in listeners {
		if !l.ln.enabled {
			continue
		}
		ctx, err := tlsx.server_context(l.ln.cert_file, l.ln.key_file, nil)
		if err != .None {
			append(&bad, fmt.aprintf("listeners.%s: %s", l.key, tlsx.describe_error(err, context.temp_allocator), allocator = allocator))
			continue
		}
		if !tlsx.signer_covers_host(ctx.signer, host) {
			append(
				&bad,
				fmt.aprintf(
					"ddr.name: the certificate of listeners.%s (%s) does not cover %s, so it cannot be designated",
					l.key,
					l.ln.cert_file,
					host,
					allocator = allocator,
				),
			)
		}
		tlsx.context_destroy(ctx)
	}

	addresses := make([dynamic]net.Address, context.temp_allocator)
	for r in ddr_addresses(cfg, context.temp_allocator) {
		#partial switch d in r.data {
		case dns.Rdata_A:
			append(&addresses, net.IP4_Address(d.addr))
		case dns.Rdata_AAAA:
			append(&addresses, transmute(net.IP6_Address)d.addr)
		}
	}
	if len(addresses) == 0 {
		ep4, ep6, _ := netx.resolve(host)
		for ep in ([2]net.Endpoint{ep4, ep6}) {
			if ep.address != nil {
				append(&addresses, ep.address)
			}
		}
	}
	if len(addresses) == 0 {
		append(&warn, fmt.aprintf("ddr.name: %s does not resolve from here, and no rewrite gives it an address, so a client cannot reach the designation", host, allocator = allocator))
	} else if !ddr_reaches_listener(cfg, addresses[:]) {
		list := make([dynamic]string, context.temp_allocator)
		for a in addresses {
			append(&list, net.address_to_string(a, context.temp_allocator))
		}
		append(
			&warn,
			fmt.aprintf(
				"ddr.name: %s leads to %s, which no DoT or DoH listener on this machine is bound to; unless it is forwarded here, a client following the designation reaches some other host",
				host,
				strings.join(list[:], ", ", context.temp_allocator),
				allocator = allocator,
			),
		)
	}
	return bad[:], warn[:]
}

// Whether any of `addresses` is one of this machine's own that an enabled DoT or
// DoH listener is bound to, directly or through the wildcard of its family.
@(private)
ddr_reaches_listener :: proc(cfg: ^config.Config, addresses: []net.Address) -> bool {
	interfaces, err := net.enumerate_interfaces(context.temp_allocator)
	if err != nil {
		return true // nothing to judge by, so nothing to warn about
	}
	defer net.destroy_interfaces(interfaces, context.temp_allocator)
	for a in addresses {
		local := false
		for iface in interfaces {
			for lease in iface.unicast {
				local ||= lease.address == a
			}
		}
		if !local {
			continue
		}
		for ln in ([2]config.Listener{cfg.listeners.dot, cfg.listeners.doh}) {
			if !ln.enabled {
				continue
			}
			bound := netx.parse_address(ln.address)
			switch b in bound {
			case net.IP4_Address:
				if _, v4 := a.(net.IP4_Address); v4 && (b == net.IP4_Any || bound == a) {
					return true
				}
			case net.IP6_Address:
				// `::` takes IPv4 too: the sockets leave IPV6_V6ONLY at the
				// kernel's default, which is off.
				if b == net.IP6_Any || bound == a {
					return true
				}
			}
		}
	}
	return false
}
