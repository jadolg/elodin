package server

import "core:fmt"
import "core:mem"
import "core:net"
import "core:os"
import "core:strings"
import "core:sync"
import "elodin:config"
import "elodin:dns"
import "elodin:logx"
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
certificate covers `ddr.name`, rather than send clients to a certificate they
cannot verify. See `ddr_designate`.

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
reload. Returns false, and logs why, when a name is set and not covered; nothing
is designated through that listener until a certificate that covers it is
loaded.

The listener serves the certificate either way, at startup as on a reload. A
renewal that drops the name is kept by a reload, since refusing it would leave
an expiring certificate serving every client; a startup that refused the same
certificate would turn the next restart after that renewal into a resolver that
does not come up at all, Do53 included. Losing the designation costs only the
upgrade; `--check` warns about the mismatch before a restart.
*/
ddr_designate :: proc(s: ^Server, listener: Protocol, ctx: ^tlsx.Context, reloaded := false) -> bool {
	name := strings.trim_suffix(startup_config(s).ddr.name, ".")
	covered := name != "" && ctx != nil && tlsx.signer_covers_host(ctx.signer, name)
	key := "dot"
	#partial switch listener {
	case .DoT:
		sync.atomic_store(&s.ddr.dot, covered)
	case .DoH:
		sync.atomic_store(&s.ddr.doh, covered)
		key = "doh"
	}
	if name == "" || covered {
		return true
	}
	if reloaded {
		logx.errorf("ddr.name: the certificate of listeners.%s no longer covers %s, so _dns.resolver.arpa stops designating it", key, name)
	} else {
		logx.errorf("ddr.name: the certificate of listeners.%s does not cover %s, so _dns.resolver.arpa does not designate it", key, name)
	}
	return false
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
		// Nothing where the designation could not be built whole: a lost record
		// would go out as a NODATA the client caches, and lost params as a
		// designation it cannot use.
		answer, built := ddr_records(s, q.name, allocator)
		if !built {
			return nil
		}
		resp.answer = answer
	}
	soa: [1]dns.Record
	if len(resp.answer) == 0 {
		soa[0] = synth_soa_for_zone(RESOLVER_ARPA, RESOLVER_ARPA_TTL)
		resp.authority = soa[:]
	} else {
		// Behind the client's OPT record rather than over it, so the encoder keeps
		// that record's room as the addresses fill the section.
		// Kept as it was where the allocator ran dry, so the client's OPT record
		// stays: the addresses are the part RFC 9462 section 4 makes optional.
		addresses := ddr_addresses(live(s).cfg, allocator)
		if joined, built := dns.alloc_slice([]dns.Record, len(resp.additional) + len(addresses), allocator); built {
			copy(joined, resp.additional)
			copy(joined[len(resp.additional):], addresses)
			resp.additional = joined
		}
	}

	// Addresses that do not fit are dropped by the encoder without TC: they only
	// save the client a lookup (RFC 9462 section 4).
	out, _, err := dns.encode_message(resp, allocator, limit)
	// Nor the empty NOERROR below where the allocator ran dry, which reads as
	// no designation.
	if err == .Out_Of_Memory {
		return nil
	}
	if err != .None {
		fallback, _ := dns.error_response(nil, query, .No_Error, allocator, limit)
		return fallback
	}
	return out
}

// One SVCB record per designated listener, in ServiceMode with priority 1:
// neither transport is preferred over the other, and the client picks.
@(private)
ddr_records :: proc(s: ^Server, owner: string, allocator: mem.Allocator) -> (records: []dns.Record, ok: bool) {
	cfg := live(s).cfg
	if cfg.ddr.name == "" {
		return nil, true
	}
	dot, doh := sync.atomic_load(&s.ddr.dot), sync.atomic_load(&s.ddr.doh)
	dot_params, doh_params: []u8
	if dot {
		dot_params = svc_params(DOT_ALPN, cfg.listeners.dot.port, 853, "", allocator) or_return
	}
	if doh {
		dohpath, derr := strings.concatenate({cfg.listeners.doh.path, "{?dns}"}, allocator)
		if derr != nil || len(dohpath) != len(cfg.listeners.doh.path) + len("{?dns}") {
			return nil, false
		}
		doh_params = svc_params(DOH_ALPN, cfg.listeners.doh.port, 443, dohpath, allocator) or_return
	}
	// Reserved whole, so neither append below can drop a record.
	list := dns.alloc_list([dynamic]dns.Record, 2, allocator) or_return
	if dot {
		append(&list, ddr_record(owner, cfg.ddr.name, dot_params))
	}
	if doh {
		append(&list, ddr_record(owner, cfg.ddr.name, doh_params))
	}
	return list[:], true
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
svc_params :: proc(alpn: []string, port, default_port: int, dohpath: string, allocator: mem.Allocator) -> (params: []u8, ok: bool) {
	put_u16 :: proc(b: ^[dynamic]u8, v: u16) {
		append(b, u8(v >> 8), u8(v))
	}
	// The ALPN list as TLS writes it, each protocol behind its length.
	alpn_len := 0
	for p in alpn {
		alpn_len += 1 + len(p)
	}
	// Reserved whole - each key's four-byte header and its value - so no
	// append below can leave a key without its value.
	b := dns.alloc_list([dynamic]u8, 4 + alpn_len + 6 + 4 + len(dohpath), allocator) or_return
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
	return b[:], true
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

`problems` are what the server would not start on: a certificate that cannot be
read. Everything else is a warning, since the server starts on it:

- a certificate that does not cover the name, whose listener the server serves
  but does not designate (see `ddr_designate`);
- a rewrite that sinks the name;
- a rewrite address on loopback, which only clients on this machine can reach;
- rewrite addresses none of which a listener is bound to, judged per listener.
  A port forwarded from elsewhere can make that right, but otherwise a client
  following the designation reaches some other host.

The addresses are those this server hands a client for the name: its `rewrites`
rule (`ddr_addresses`). A name with no rule resolves wherever its public DNS
says, which nothing offline can judge.
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
				&warn,
				fmt.aprintf(
					"ddr.name: the certificate of listeners.%s (%s) does not cover %s, so it is not designated",
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
	if len(addresses) == 0 {
		return bad[:], warn[:]
	}
	// Asked of the kernel once per address, not once per listener as well.
	local := make([dynamic]net.Address, context.temp_allocator)
	list := make([dynamic]string, context.temp_allocator)
	loopback := make([dynamic]string, context.temp_allocator)
	for a in addresses {
		text := net.address_to_string(a, context.temp_allocator)
		append(&list, text)
		if is_loopback(a) {
			append(&loopback, text)
		}
		if is_local_address(a) {
			append(&local, a)
		}
	}
	if len(loopback) > 0 {
		append(
			&warn,
			fmt.aprintf(
				"ddr.name: the rewrite for %s gives %s, on loopback, which only clients on this machine can reach",
				host,
				strings.join(loopback[:], ", ", context.temp_allocator),
				allocator = allocator,
			),
		)
	}
	v6only := bindv6only()
	// Each listener is designated on its own, so each is judged on its own.
	for l in listeners {
		if !l.ln.enabled || ddr_reaches_listener(l.ln, local[:], v6only) {
			continue
		}
		append(
			&warn,
			fmt.aprintf(
				"ddr.name: the rewrite for %s gives %s, none of which listeners.%s on this machine is bound to; unless it is forwarded here, a client following that designation reaches some other host",
				host,
				strings.join(list[:], ", ", context.temp_allocator),
				l.key,
				allocator = allocator,
			),
		)
	}
	return bad[:], warn[:]
}

// Whether `ln` is bound to any of `local`, this machine's own addresses,
// directly or through the wildcard of its family. `::` takes IPv4 too unless
// `v6only`: the sockets leave IPV6_V6ONLY at the kernel's default, which is
// `net.ipv6.bindv6only`.
@(private)
ddr_reaches_listener :: proc(ln: config.Listener, local: []net.Address, v6only: bool) -> bool {
	for a in local {
		if ddr_bound_to(ln, a, v6only) {
			return true
		}
	}
	return false
}

/*
Whether `a` is one of this machine's own addresses: the kernel binds a socket only
to those. Asked of the kernel rather than read from an interface listing, which
`core:net` returns empty on Linux. The unspecified address binds too, but it is
no address of this machine: a client sent to it connects to itself.
*/
@(private)
is_local_address :: proc(a: net.Address) -> bool {
	if a == net.IP4_Any || a == net.IP6_Any {
		return false
	}
	// Created and bound in two steps: `make_bound_udp_socket` hands back the
	// socket it could not bind still open, and that is the usual case here.
	socket, err := net.make_unbound_udp_socket(net.family_from_address(a))
	if err != nil {
		return false
	}
	defer net.close(socket)
	return net.bind(socket, {a, 0}) == .None
}

// Whether the listener `ln` accepts connections to `a`, as bound.
@(private)
ddr_bound_to :: proc(ln: config.Listener, a: net.Address, v6only: bool) -> bool {
	_, is_v4 := a.(net.IP4_Address)
	bound := netx.parse_address(ln.address)
	switch b in bound {
	case net.IP4_Address:
		return is_v4 && (b == net.IP4_Any || bound == a)
	case net.IP6_Address:
		return b == net.IP6_Any && (!is_v4 || !v6only) || bound == a
	}
	return false
}

// The kernel's default for IPV6_V6ONLY. Unreadable is the usual default, off.
@(private)
bindv6only :: proc() -> bool {
	data, err := os.read_entire_file("/proc/sys/net/ipv6/bindv6only", context.temp_allocator)
	return err == nil && len(data) > 0 && data[0] == '1'
}
