package server

import "core:fmt"
import "core:mem"
import "core:net"
import "core:os"
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
`rewrites` rule `rewrite_rule_for` picks for an A and for an AAAA question, which
is the one `apply_rewrite` answers from - since that is where an operator writes
the local address of a name whose public one is elsewhere, and so the address
that lets a client on the LAN use the designation opportunistically (RFC 9462
section 4.3). A rule that sinks the name or aliases it has no address of the
designated resolver to give, and with no rule there is nothing local to say:
either way the client asks for the name the ordinary way.
*/
@(private)
ddr_addresses :: proc(cfg: ^config.Config, allocator: mem.Allocator) -> []dns.Record {
	records := make([dynamic]dns.Record, 0, 4, allocator)
	for qtype in ([2]dns.Type{.A, .AAAA}) {
		i, found := rewrite_rule_for(cfg.rewrites, cfg.ddr.name, qtype)
		if !found || rule_blocks(cfg.rewrites[i]) || rule_holds_alias(cfg.rewrites[i]) {
			continue
		}
		rule := cfg.rewrites[i]
		for a in rule.answers {
			if a.kind == .A && qtype == .A {
				append(&records, dns.Record{name = cfg.ddr.name, type = .A, class = .IN, ttl = rule.ttl, data = dns.Rdata_A{addr = a.v4}})
			} else if a.kind == .AAAA && qtype == .AAAA {
				append(&records, dns.Record{name = cfg.ddr.name, type = .AAAA, class = .IN, ttl = rule.ttl, data = dns.Rdata_AAAA{addr = a.v6}})
			}
		}
	}
	return records[:]
}

/*
What `--check` says about `ddr.name`, which the loader cannot, since it does not
open the certificates.

Offline, like the rest of `--check`, which a package install runs while the
machine's resolver may be this server, stopped: the certificates are read, the
keys are not - a key only the service account can read is no fault of the file -
and no name is looked up.

`problems` are what the listeners would refuse to start on: a certificate that
does not cover the name, or cannot be read. `warnings` are about the addresses
this server hands a client for the name, which are those of its `rewrites` rule
(`ddr_addresses`): a rule that sinks the name, or addresses none of which an
encrypted listener on this machine is bound to. The second is not refused, since
a port forwarded from elsewhere is a reason it may be right, but a client
following it reaches some other host. A name with no rule resolves wherever its
public DNS says, which nothing offline can judge.
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
		covered, read := tlsx.cert_file_covers_host(l.ln.cert_file, host)
		if !read {
			append(&bad, fmt.aprintf("listeners.%s.cert_file: %q holds no certificate that can be read", l.key, l.ln.cert_file, allocator = allocator))
		} else if !covered {
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
	}

	if i, found := rewrite_rule_for(cfg.rewrites, cfg.ddr.name, .A); found && rule_blocks(cfg.rewrites[i]) {
		append(&warn, fmt.aprintf("ddr.name: a rewrite sinks %s, so a client that looks it up here cannot reach the designation", host, allocator = allocator))
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
	if len(addresses) > 0 && !ddr_reaches_listener(cfg, addresses[:], bindv6only()) {
		list := make([dynamic]string, context.temp_allocator)
		for a in addresses {
			append(&list, net.address_to_string(a, context.temp_allocator))
		}
		append(
			&warn,
			fmt.aprintf(
				"ddr.name: the rewrite for %s gives %s, which no DoT or DoH listener on this machine is bound to; unless it is forwarded here, a client following the designation reaches some other host",
				host,
				strings.join(list[:], ", ", context.temp_allocator),
				allocator = allocator,
			),
		)
	}
	return bad[:], warn[:]
}

// Whether any of `addresses` is one of this machine's own that an enabled DoT or
// DoH listener is bound to, directly or through the wildcard of its family. `::`
// takes IPv4 too unless `v6only`: the sockets leave IPV6_V6ONLY at the kernel's
// default, which is `net.ipv6.bindv6only`.
@(private)
ddr_reaches_listener :: proc(cfg: ^config.Config, addresses: []net.Address, v6only: bool) -> bool {
	for a in addresses {
		if is_local_address(a) && ddr_bound_to(cfg, a, v6only) {
			return true
		}
	}
	return false
}

/*
Whether `a` is one of this machine's own addresses: the kernel binds a socket only
to those. Asked of the kernel rather than read from an interface listing, which
`core:net` returns empty on Linux.
*/
@(private)
is_local_address :: proc(a: net.Address) -> bool {
	socket, err := net.make_bound_udp_socket(a, 0)
	if err != nil {
		return false
	}
	net.close(socket)
	return true
}

// Whether an enabled DoT or DoH listener accepts connections to `a`, as bound.
@(private)
ddr_bound_to :: proc(cfg: ^config.Config, a: net.Address, v6only: bool) -> bool {
	_, is_v4 := a.(net.IP4_Address)
	for ln in ([2]config.Listener{cfg.listeners.dot, cfg.listeners.doh}) {
		if !ln.enabled {
			continue
		}
		bound := netx.parse_address(ln.address)
		switch b in bound {
		case net.IP4_Address:
			if is_v4 && (b == net.IP4_Any || bound == a) {
				return true
			}
		case net.IP6_Address:
			if b == net.IP6_Any && (!is_v4 || !v6only) || bound == a {
				return true
			}
		}
	}
	return false
}

// The kernel's default for IPV6_V6ONLY. Unreadable is the usual default, off.
@(private)
bindv6only :: proc() -> bool {
	data, err := os.read_entire_file("/proc/sys/net/ipv6/bindv6only", context.temp_allocator)
	return err == nil && len(data) > 0 && data[0] == '1'
}
