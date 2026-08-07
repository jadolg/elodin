package server

import "core:crypto"
import "core:crypto/siphash"
import "core:mem"
import "core:net"
import "core:time"
import "elodin:config"
import "elodin:dns"
import "elodin:logx"

/*
DNS cookies, on the side facing the clients (RFC 7873, RFC 9018).

The transaction ID and a randomised source port give an off-path attacker about
32 bits to guess before it can pass a forged answer off as ours. A cookie adds
64 bits it cannot see at all: a client that has talked to us once holds a token
only this server could have produced, and an answer that comes back without it
is not from here.

The token is not stored. It is recomputed from the client's own cookie, its
address and a timestamp, keyed by a secret this process holds, so remembering
clients costs nothing and there is no table for a flood of them to fill. The
timestamp bounds how long a cookie stays usable if it does leak.

Cookies on the upstream side are a separate matter and are not done here; a
client's cookie is stripped before its query is forwarded, since it belongs to
the client and this server, and would fail against anyone else's secret.
*/

// Defined with the setting it is read from, so `--check` and startup cannot
// disagree about what a usable secret looks like.
COOKIE_SECRET_LEN :: config.COOKIE_SECRET_LEN
COOKIE_CLIENT_LEN :: 8
// Version, three reserved bytes, a four-byte timestamp and an eight-byte hash.
COOKIE_SERVER_LEN :: 16
COOKIE_REPLY_LEN :: COOKIE_CLIENT_LEN + COOKIE_SERVER_LEN
COOKIE_VERSION :: 1

// Shortest and longest a COOKIE option may legally be (RFC 7873 section 5.2.2).
COOKIE_MIN_LEN :: 16
COOKIE_MAX_LEN :: 40

/*
How far either side of now a timestamp may sit, in seconds (RFC 9018 section
4.3). An hour of history keeps a client that asks something once an hour from
paying for a fresh handshake every time; five minutes ahead covers the clock
skew between machines in an anycast set.
*/
COOKIE_MAX_AGE :: 3600
COOKIE_MAX_SKEW :: 300

Cookie_Keeper :: struct {
	secret:  [COOKIE_SECRET_LEN]u8,
	// Answer a UDP query that cannot show a valid server cookie with BADCOOKIE
	// instead of an answer.
	require: bool,
}

Cookie_Verdict :: enum u8 {
	// No COOKIE option, so none goes back either.
	Absent,
	// A COOKIE option of a length no client should have sent.
	Malformed,
	/*
	A COOKIE option from an address the hash cannot be taken over, so there is
	nothing to bind a cookie to and nothing to check one against.

	Kept apart from `Absent` because the client did send one. Both mean no
	cookie goes back, but only one of them means `require` has nothing to
	enforce, and folding them together made that setting fail open on the single
	input it cannot verify.
	*/
	Unbindable,
	// A client cookie with nothing behind it, or one we cannot vouch for.
	Unproven,
	// Ours, for this address, and not yet stale.
	Valid,
}

Cookie_Request :: struct {
	verdict: Cookie_Verdict,
	/*
	Whether the query carried a COOKIE option at all.

	Separate from `verdict`, because it is answered even with the client-facing
	side turned off, where there is no secret to judge one against and every
	verdict is `.Absent`. What it decides is not whether to give the client a
	cookie but whether to take one off the query before forwarding it, and that
	has to happen either way: the client's cookie is no more the upstream's
	business when this server is not issuing cookies than when it is.
	*/
	sent:    bool,
	client:  [COOKIE_CLIENT_LEN]u8,
	// The client address, in the 4 or 16 bytes the hash is taken over.
	ip:      [16]u8,
	ip_len:  int,
}

/*
Set the server's cookie secret up.

Returns false when a configured secret cannot be read, which is worth refusing
to start over: silently falling back to a random one would leave the members of
an anycast set handing out cookies none of the others would accept.
*/
start_cookies :: proc(s: ^Server) -> bool {
	if !s.cfg.cookies.enabled {
		return true
	}
	k := new(Cookie_Keeper)
	k.require = s.cfg.cookies.require

	if s.cfg.cookies.secret != "" {
		if !config.parse_cookie_secret(s.cfg.cookies.secret, &k.secret) {
			logx.errorf("cookies.secret must be %d hex characters", COOKIE_SECRET_LEN * 2)
			free(k)
			return false
		}
	} else {
		crypto.rand_bytes(k.secret[:])
	}

	s.cookies = k
	logx.infof("cookies: enabled (require=%v)", k.require)
	return true
}

stop_cookies :: proc(s: ^Server) {
	if s.cookies == nil {
		return
	}
	mem.zero_explicit(&s.cookies.secret, COOKIE_SECRET_LEN)
	free(s.cookies)
	s.cookies = nil
}

/*
Read the client's COOKIE option and decide what it is worth.

`client` is the peer's address as the listener wrote it, "host:port". The port
changes from one query to the next, so only the host goes into the hash.
*/
inspect_cookie :: proc(k: ^Cookie_Keeper, m: dns.Message, client: string) -> (req: Cookie_Request) {
	raw, found := dns.find_edns_option(m, .Cookie)
	if !found {
		return {}
	}
	// Recorded before anything else, since the forwarding path needs it whatever
	// the verdict turns out to be - including with the keeper off, where there is
	// no verdict to reach.
	req.sent = true
	if k == nil {
		return req
	}
	if len(raw) != COOKIE_CLIENT_LEN && (len(raw) < COOKIE_MIN_LEN || len(raw) > COOKIE_MAX_LEN) {
		return Cookie_Request{verdict = .Malformed, sent = true}
	}

	n, parsed := cookie_client_ip(client, req.ip[:])
	if !parsed {
		// Nothing to bind a cookie to, so there is no cookie to give - but the
		// client did send one, and `require` has to turn that away rather than
		// wave it through for want of an address to check it against.
		logx.debugf("cookies: %q is not an address a cookie can be bound to", client)
		return Cookie_Request{verdict = .Unbindable, sent = true}
	}
	req.ip_len = n
	copy(req.client[:], raw[:COOKIE_CLIENT_LEN])

	req.verdict = .Unproven
	if len(raw) > COOKIE_CLIENT_LEN && verify_cookie(k, raw, req, cookie_now()) {
		req.verdict = .Valid
	}
	return req
}

/*
Whether a query has to be turned away with BADCOOKIE before the name is looked
up at all.

Asked as "the client sent a cookie and it is not one of ours", rather than as a
list of the verdicts that fail. A verdict this server cannot vouch for is one it
should refuse, and enumerating them the other way round is what let an address
the hash cannot be taken over walk straight past `require`.

Only UDP is checked; the stream transports already made the client prove it can
receive at the address it claims.
*/
cookie_must_be_refused :: proc(k: ^Cookie_Keeper, req: Cookie_Request, proto: Protocol) -> bool {
	if k == nil || !k.require || proto != .UDP {
		return false
	}
	return req.verdict != .Absent && req.verdict != .Valid
}

/*
Put this server's cookie into an answer that is already encoded.

Every response to a client that sent a cookie carries a fresh one. RFC 9018
section 4.3 only asks for a new one once the old is half an hour old, but
minting one costs a single hash and it keeps the timestamp a client holds as
young as its last query.
*/
attach_cookie :: proc(
	k: ^Cookie_Keeper,
	wire: []u8,
	req: Cookie_Request,
	query: dns.Message,
	limit: int,
	advertise: u16,
	allocator: mem.Allocator,
) -> []u8 {
	// Named as the two verdicts that earn a cookie rather than the ones that do
	// not, so a verdict added later gets none until someone says otherwise.
	if k == nil || (req.verdict != .Unproven && req.verdict != .Valid) {
		return wire
	}
	cookie := make_cookie(k, req, cookie_now())
	/*
	`advertise` is whatever the answer is going out reporting, worked out once by
	the caller.

	Only a record minted here can be affected: `ensure_edns_option` passes this
	to `make_opt` for an answer from an upstream that dropped EDNS, and leaves an
	existing OPT record's class alone. On UDP that is the ceiling, and
	`handle_query` writes it again over the top a moment later, so the value is
	belt and braces there. On the stream transports nothing writes it again, and
	it is the client's own figure - the same number this passed before, and the
	only one available on a transport where this server has no payload size to
	report.
	*/
	out, ok := dns.ensure_edns_option(wire, .Cookie, cookie[:], advertise, allocator)
	if !ok {
		// Nothing to do but send the answer as it is; a client that gets no
		// cookie back reads it as a server that does not do them.
		return wire
	}
	/*
	An answer the cookie pushes past the ceiling is truncated rather than sent
	without one.

	The other way round is available - drop the cookie, send the whole answer -
	and it is the wrong trade here. `encode_message` re-adds the OPT record
	after truncating, so the cookie survives this and the client is told to ask
	again over TCP; dropping it instead would cost the client its cookie on
	exactly the answers `cookies.require` is meant to protect, and a client that
	gets no cookie back reads it as a server that does not do them.
	*/
	if len(out) > limit {
		return fit_response(out, limit, query, allocator)
	}
	return out
}

@(private)
make_cookie :: proc(k: ^Cookie_Keeper, req: Cookie_Request, now: u32) -> (out: [COOKIE_REPLY_LEN]u8) {
	// A local copy because a parameter's array fields cannot be sliced: they are
	// not addressable. Not a defensive copy, and not one to tidy away.
	binding := req
	copy(out[:COOKIE_CLIENT_LEN], binding.client[:])
	out[8] = COOKIE_VERSION
	// out[9..11] are the reserved bytes, and this version sends them zeroed.
	out[12] = u8(now >> 24)
	out[13] = u8(now >> 16)
	out[14] = u8(now >> 8)
	out[15] = u8(now)

	hash := cookie_hash(k.secret, out[:16], binding.ip[:binding.ip_len])
	copy(out[16:], hash[:])
	return out
}

@(private)
verify_cookie :: proc(k: ^Cookie_Keeper, raw: []u8, req: Cookie_Request, now: u32) -> bool {
	/*
	Exactly 24 bytes, or nothing is checked at all (RFC 9018 section 4.4). The
	length is what makes the hash input an injective function of its parts: a
	longer cookie from an IPv4 client could otherwise be hashed to the same 32
	bytes as a shorter one from an IPv6 client, and each would verify as the
	other.
	*/
	if len(raw) != COOKIE_REPLY_LEN {
		return false
	}
	if raw[8] != COOKIE_VERSION {
		return false
	}
	ts := u32(raw[12]) << 24 | u32(raw[13]) << 16 | u32(raw[14]) << 8 | u32(raw[15])
	// Serial arithmetic, so the window still works either side of 2106.
	age := i32(now - ts)
	if age > COOKIE_MAX_AGE || age < -COOKIE_MAX_SKEW {
		return false
	}
	// The reserved bytes go in as they arrived; another server in the set may
	// have set them, and this one is not the judge of that.
	binding := req // As in `make_cookie`: the parameter's arrays are not sliceable.
	hash := cookie_hash(k.secret, raw[:16], binding.ip[:binding.ip_len])
	return crypto.compare_constant_time(hash[:], raw[16:]) == 1
}

/*
SipHash-2-4 over the client cookie, the server cookie's header and the client's
address, keyed by the server secret (RFC 9018 section 4.4). `head` is the first
sixteen bytes of the cookie: the client cookie, the version, the reserved bytes
and the timestamp.
*/
@(private)
cookie_hash :: proc(secret: [COOKIE_SECRET_LEN]u8, head: []u8, ip: []u8) -> (out: [8]u8) {
	buf: [16 + 16]u8
	n := copy(buf[:], head)
	n += copy(buf[n:], ip)

	key := secret
	siphash.sum_bytes_to_buffer_2_4(buf[:n], key[:], out[:])
	return out
}

/*
The client's address as the bytes the hash covers.

Four for IPv4, sixteen for IPv6, which is also what fixes the length of the
hash input at 20 or 32 bytes.
*/
@(private)
cookie_client_ip :: proc(client: string, out: []u8) -> (n: int, ok: bool) {
	endpoint := net.parse_endpoint(client) or_return
	switch addr in endpoint.address {
	case net.IP4_Address:
		bytes := addr
		copy(out[:4], bytes[:])
		return 4, true
	case net.IP6_Address:
		for group, i in addr {
			v := u16(group)
			out[i * 2] = u8(v >> 8)
			out[i * 2 + 1] = u8(v)
		}
		return 16, true
	}
	return 0, false
}

@(private)
cookie_now :: proc() -> u32 {
	return u32(time.time_to_unix(time.now()))
}
