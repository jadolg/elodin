package upstream

import "core:crypto"
import "core:mem"
import "core:sync"
import "core:time"
import "elodin:dns"
import "elodin:logx"

/*
DNS cookies, from the asking side (RFC 7873 section 5.3).

The same protection as the client-facing path, pointed the other way. A reply to
one of our UDP queries is accepted on a 16-bit transaction ID, a randomised
source port and an echoed question; an off-path attacker who can guess those can
have an answer of its choosing cached here and served to every client behind it.
Once the upstream has issued a cookie, forging a reply also means reproducing 64
bits that were never on a path the attacker can see.

The check happens where the reply is being matched, so a datagram that fails it
is passed over and the loop keeps waiting for the genuine one. Answering a
spoofing attempt with a failure would hand the attacker most of what it wanted.

Held per upstream: a different server learns a different client cookie, so the
cookie cannot be used to correlate this resolver across the servers it asks.
*/

COOKIE_CLIENT_LEN :: 8
COOKIE_SERVER_MIN :: 8
COOKIE_SERVER_MAX :: 32

@(private)
Cookie :: struct {
	client:     [COOKIE_CLIENT_LEN]u8,
	// What the server last gave us, empty until it has.
	server:     [COOKIE_SERVER_MAX]u8,
	server_len: int,
}

/*
Whether this upstream is one to send cookies to.

DoT and DoH are left out. Both authenticate the server with a certificate, which
settles the question a cookie only makes harder to get wrong, and a DoH resolver
answers over a connection nothing off-path can inject into anyway.
*/
@(private)
cookies_wanted :: proc(u: ^Upstream) -> bool {
	if !u.cookies {
		return false
	}
	#partial switch u.spec.kind {
	case .UDP, .TCP:
		return true
	}
	return false
}

/*
Put our cookie for this upstream into a copy of the query.

`ok` is false when the query has no OPT record to carry it. Adding one would
start an EDNS negotiation on behalf of a client that did not ask for it, and
change what may come back; the query goes out as it is instead.
*/
@(private)
attach_cookie :: proc(u: ^Upstream, query: []u8, allocator: mem.Allocator) -> (out: []u8, ok: bool) {
	option: [COOKIE_CLIENT_LEN + COOKIE_SERVER_MAX]u8
	n := 0

	sync.mutex_lock(&u.mu)
	n += copy(option[:], u.cookie.client[:])
	n += copy(option[n:], u.cookie.server[:u.cookie.server_len])
	sync.mutex_unlock(&u.mu)

	return dns.set_edns_option(query, .Cookie, option[:n], allocator)
}

/*
Whether a reply may be ours.

Three ways a reply fails (RFC 7873 section 5.3): it echoes a client cookie that
is not the one we sent, its COOKIE option is not a legal length, or it carries no
cookie at all when this server has already shown it does cookies.

That last one is the whole mechanism. A server we have never had a cookie from is
one that does not implement them, and RFC 7873 has the exchange carry on without
— but once it has issued one, accepting a reply with the option left off would
make the check something an attacker opts out of at no cost: it would be back to
guessing only the transaction ID and the source port, which is what the cookie
was added to put out of reach.
*/
@(private)
cookie_matches :: proc(u: ^Upstream, response: []u8) -> bool {
	if u == nil || !cookies_wanted(u) {
		return true
	}
	msg, err := dns.decode_message(response, context.temp_allocator)
	if err != .None {
		// Not something to judge here; `response_matches` has already accepted
		// the header, and the caller decodes it properly further along.
		return true
	}
	sync.mutex_lock(&u.mu)
	echoed := u.cookie.client
	// Having issued a cookie is what makes one owed on every reply after it.
	expected := u.cookie.server_len > 0
	sync.mutex_unlock(&u.mu)

	raw, found := dns.find_edns_option(msg, .Cookie)
	if !found {
		return !expected
	}
	if len(raw) != COOKIE_CLIENT_LEN &&
	   (len(raw) < COOKIE_CLIENT_LEN + COOKIE_SERVER_MIN || len(raw) > COOKIE_CLIENT_LEN + COOKIE_SERVER_MAX) {
		return false
	}
	for i in 0 ..< COOKIE_CLIENT_LEN {
		if raw[i] != echoed[i] {
			return false
		}
	}
	return true
}

/*
Forget the server cookie held for this upstream.

Called when it is parked for a cooldown, which is where a server that has stopped
answering ends up - including one that stopped because it no longer sends cookies
and every reply is now being discarded for the want of one. Dropping what we hold
puts it back to being a server we have never had a cookie from, so the next round
of queries is judged on what it does now rather than on what it did before.

The caller holds `u.mu`.
*/
@(private)
forget_cookie :: proc(u: ^Upstream) {
	u.cookie.server_len = 0
}

// The COOKIE option a reply carries, if it carries one.
@(private)
reply_cookie :: proc(response: []u8) -> (raw: []u8, found: bool) {
	msg, err := dns.decode_message(response, context.temp_allocator)
	if err != .None {
		return nil, false
	}
	return dns.find_edns_option(msg, .Cookie)
}

// Keep the server cookie a reply carried, for the next query to this upstream.
@(private)
learn_cookie :: proc(u: ^Upstream, response: []u8) {
	raw, found := reply_cookie(response)
	if !found {
		return
	}
	server := raw[min(COOKIE_CLIENT_LEN, len(raw)):]
	if len(server) < COOKIE_SERVER_MIN || len(server) > COOKIE_SERVER_MAX {
		return
	}

	sync.mutex_lock(&u.mu)
	defer sync.mutex_unlock(&u.mu)
	u.cookie.server_len = copy(u.cookie.server[:], server)
}

/*
Send one query with a cookie on it, and deal with what comes back.

BADCOOKIE means the server cookie we held is no longer one this server accepts —
it has rotated its secret, or we have never had one and it insists. The reply
carries a fresh one, so the question is asked again with it. Once: a server that
refuses twice is not going to answer, and the group is better off trying the
next one than looping here (RFC 7873 section 5.3).
*/
@(private)
exchange_with_cookie :: proc(
	u: ^Upstream,
	query: []u8,
	timeout: time.Duration,
	allocator: mem.Allocator,
) -> (
	response: []u8,
	err: Error,
) {
	asked, attached := attach_cookie(u, query, context.temp_allocator)
	if !attached {
		return send(u, query, timeout, allocator)
	}

	response = send(u, asked, timeout, allocator) or_return
	learn_cookie(u, response)

	if dns.peek_rcode(response) == .Bad_Cookie {
		// Unreachable in practice: the same `query` carried a cookie a moment ago
		// at the top of this proc, and nothing about it has changed since. Kept as
		// a refusal rather than an assertion because the alternative is sending
		// the query on without the cookie the server has just insisted on.
		retry, retried := attach_cookie(u, query, context.temp_allocator)
		if !retried {
			// `response` came out of `allocator`, which on the race path is the
			// process heap: dropping it here would leak it for the life of the
			// process, so free it before turning the reply away.
			delete(response, allocator)
			return nil, .Bad_Response
		}
		// The retry supersedes this reply; free it before it is overwritten.
		delete(response, allocator)
		response = send(u, retry, timeout, allocator) or_return
		learn_cookie(u, response)
		if dns.peek_rcode(response) == .Bad_Cookie {
			logx.debugf("upstream %s: still BADCOOKIE after a fresh cookie", u.spec.name)
			delete(response, allocator)
			return nil, .Bad_Response
		}
	}

	/*
	The cookie goes no further than this.

	It belongs to the conversation between this server and that upstream. Left
	in, it would reach a client that never asked for one and, worse, be stored
	in the cache and handed to every client that asks the same question later.
	*/
	if _, carried := reply_cookie(response); !carried {
		/*
		Nothing to take out, which is where a server that does not do cookies
		leaves every reply. Asked before the removal rather than inferred from it
		failing: `remove_edns_option` needs an OPT record to walk, and a reply
		without one cannot be told apart from a removal that went wrong.
		*/
		return response, .None
	}
	/*
	`stripped` is a fresh buffer with the cookie taken out, so the reply `send`
	returned is now superseded and has to be freed before we leave — the option
	is present on this path (the guard above returned otherwise), so the strip
	always produces a distinct buffer rather than handing back the input.

	On the arena paths freeing it is a no-op — the per-request scratch arena
	reclaims it on `free_all` regardless. But on the race path `allocator` is the
	process heap (a race worker can outlive the caller's arena), and there
	nothing else ever frees it: left behind, it leaks one buffer per forwarded
	query for the life of the process. Deleted before `return`, not on a defer:
	`response` is a named result, so `return stripped` would rebind it and a
	deferred delete would free the buffer we just handed back.
	*/
	stripped, ok := dns.remove_edns_option(response, .Cookie, allocator)
	if !ok {
		// Failing closed, the way the client-facing side does when it cannot take
		// the client's cookie back out. Handing the answer over as it stands is
		// the one outcome the paragraph above exists to prevent, and losing it is
		// the cheaper mistake: the group still has other servers to ask.
		logx.warnf("upstream %s: could not strip the server cookie from a reply", u.spec.name)
		delete(response, allocator)
		return nil, .Bad_Response
	}
	delete(response, allocator)
	return stripped, .None
}

@(private)
init_cookie :: proc(u: ^Upstream) {
	if !cookies_wanted(u) {
		return
	}
	// Unpredictable, and different for every upstream: RFC 9018 section 3 asks
	// for a client cookie that cannot be used to recognise this resolver from
	// one server to the next.
	crypto.rand_bytes(u.cookie.client[:])
}
