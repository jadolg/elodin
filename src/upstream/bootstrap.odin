package upstream

import "core:net"
import "core:strings"
import "core:sync"
import "core:time"
import "elodin:dns"
import "elodin:logx"

/*
Hostname resolution that does not go through the system resolver.

On a machine where elodin is the system resolver, asking libc to resolve an
upstream's hostname during startup would come straight back to a server that is
not listening yet. Bootstrap addresses are queried directly over plain UDP
instead, and results are cached for BOOTSTRAP_TTL.
*/

BOOTSTRAP_TTL :: 1 * time.Hour

@(private)
BOOTSTRAP_TIMEOUT :: 3 * time.Second

@(private)
Bootstrap_Entry :: struct {
	address: net.Address,
	expires: time.Time,
}

@(private)
bootstrap_cache: struct {
	mu:      sync.Mutex,
	entries: map[string]Bootstrap_Entry,
}

/*
Resolve `hostname` using `servers` (plain "IP" or "IP:port" strings).

A and AAAA are tried in that order; the first usable address wins.
*/
bootstrap_resolve :: proc(servers: []string, hostname: string) -> (addr: net.Address, ok: bool) {
	if literal := net.parse_address(hostname); literal != nil {
		return literal, true
	}

	sync.mutex_lock(&bootstrap_cache.mu)
	if entry, found := bootstrap_cache.entries[hostname]; found {
		if time.diff(entry.expires, time.now()) < 0 {
			sync.mutex_unlock(&bootstrap_cache.mu)
			return entry.address, true
		}
	}
	sync.mutex_unlock(&bootstrap_cache.mu)

	if len(servers) == 0 {
		return nil, false
	}

	for server in servers {
		for qtype in ([]dns.Type{.A, .AAAA}) {
			result, found := bootstrap_query(server, hostname, qtype)
			if !found {
				continue
			}
			entry := Bootstrap_Entry {
				address = result,
				expires = time.time_add(time.now(), BOOTSTRAP_TTL),
			}
			sync.mutex_lock(&bootstrap_cache.mu)
			if bootstrap_cache.entries == nil {
				bootstrap_cache.entries = make(map[string]Bootstrap_Entry)
			}
			// Storing under a key the map already holds keeps the key it has, so
			// cloning unconditionally would orphan a string every time an expired
			// entry is refreshed.
			if hostname in bootstrap_cache.entries {
				bootstrap_cache.entries[hostname] = entry
			} else {
				bootstrap_cache.entries[strings.clone(hostname)] = entry
			}
			sync.mutex_unlock(&bootstrap_cache.mu)
			return result, true
		}
	}
	return nil, false
}

// Resolve a host that may already be an IP literal, for the HTTP fetcher.
resolve_address :: proc(host: string, bootstrap: []string) -> (addr: net.Address, ok: bool) {
	if literal := net.parse_address(host); literal != nil {
		return literal, true
	}
	if resolved, found := bootstrap_resolve(bootstrap, host); found {
		return resolved, true
	}
	// Nothing configured to bootstrap with: fall back to the system resolver,
	// which is fine for a blocklist download once the server is already up.
	ip4, ip6, err := net.resolve(host)
	if err != nil {
		return nil, false
	}
	if ip4.address != nil {
		return ip4.address, true
	}
	if ip6.address != nil {
		return ip6.address, true
	}
	return nil, false
}

@(private)
bootstrap_query :: proc(
	server: string,
	hostname: string,
	qtype: dns.Type,
	timeout := BOOTSTRAP_TIMEOUT,
) -> (
	addr: net.Address,
	ok: bool,
) {
	host, port, split_ok := net.split_port(server)
	if !split_ok {
		return nil, false
	}
	server_addr := net.parse_address(host)
	if server_addr == nil {
		logx.warnf("bootstrap resolver %q is not an IP address", server)
		return nil, false
	}
	endpoint := net.Endpoint {
		address = server_addr,
		port    = port if port != 0 else 53,
	}

	name := dns.name_canonical(hostname, context.temp_allocator)
	query := dns.Message {
		// From the entropy source rather than from the clock: the low bits of a
		// timestamp carry only as much unpredictability as the platform's clock
		// resolution puts there, and what this query's answer decides - the
		// address every later query to this upstream is sent to, cached for
		// BOOTSTRAP_TTL - is worth more than that.
		id       = dns.random_id(),
		question = []dns.Question{{name = name, type = qtype, class = .IN}},
	}
	query.flags.rd = true

	wire, _, enc_err := dns.encode_message(query, context.temp_allocator)
	if enc_err != .None {
		return nil, false
	}

	socket, serr := net.make_unbound_udp_socket(net.family_from_endpoint(endpoint))
	if serr != nil {
		return nil, false
	}
	defer net.close(socket)
	set_socket_timeouts(socket, timeout)

	if _, send_err := net.send_udp(socket, wire, endpoint); send_err != nil {
		return nil, false
	}

	/*
	Same checks the main exchange path applies in `exchange_udp`: the datagram
	has to come from the server that was asked and answer the question that was
	sent. The ID on its own is 16 bits an off-path attacker can guess inside the
	receive window, and what it would land in is cached for BOOTSTRAP_TTL and
	consulted for blocklist hosts as well as upstream addresses.

	A datagram that fails them is dropped and the wait resumes, so a forgery
	arriving first does not deny the real answer the rest of the window.
	*/
	buf := make([]u8, 4096, context.temp_allocator)
	deadline := time.time_add(time.now(), timeout)

	for time.diff(deadline, time.now()) < 0 {
		n, remote, recv_err := net.recv_udp(socket, buf)
		if recv_err != nil {
			return nil, false
		}
		if n < dns.HEADER_SIZE {
			continue
		}
		if remote.port != endpoint.port || !addresses_equal(remote.address, endpoint.address) {
			continue
		}
		if !response_matches(wire, buf[:n]) {
			continue
		}

		msg, dec_err := dns.decode_message(buf[:n], context.temp_allocator)
		if dec_err != .None {
			return nil, false
		}
		for rec in msg.answer {
			#partial switch d in rec.data {
			case dns.Rdata_A:
				return net.IP4_Address(d.addr), true
			case dns.Rdata_AAAA:
				v6: net.IP6_Address
				for i in 0 ..< 8 {
					v6[i] = u16be(u16(d.addr[i * 2]) << 8 | u16(d.addr[i * 2 + 1]))
				}
				return v6, true
			}
		}
		return nil, false
	}
	return nil, false
}

// Split an http(s) URL into the pieces the fetcher needs.
@(private)
split_http_url :: proc(url: string) -> (scheme, host, path: string, port: int, host_only: string, ok: bool) {
	s, h, p, _, _ := net.split_url(url, context.temp_allocator)
	if s != "http" && s != "https" {
		return "", "", "", 0, "", false
	}
	name, explicit_port, split_ok := net.split_port(h)
	if !split_ok {
		return "", "", "", 0, "", false
	}
	resolved_port := explicit_port
	if resolved_port == 0 {
		resolved_port = 443 if s == "https" else 80
	}
	return s, h, (p if p != "" else "/"), resolved_port, name, true
}
