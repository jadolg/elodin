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

@(private)
COOKIE_CLIENT_LEN :: 8
@(private)
COOKIE_SERVER_MIN :: 8
@(private)
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

`ok` is false when the query has no OPT record to carry it, and the query goes
out as it is. Every query the server forwards carries one
(`server.upstream_query`); this is for one built by hand. `dry` is true where
the copy failed for want of memory instead, and the query must not go out
without the cookie for that.
*/
@(private)
attach_cookie :: proc(u: ^Upstream, query: []u8, allocator: mem.Allocator) -> (out: []u8, ok: bool, dry: bool) {
	option: [COOKIE_CLIENT_LEN + COOKIE_SERVER_MAX]u8
	n := 0

	sync.mutex_lock(&u.mu)
	n += copy(option[:], u.cookie.client[:])
	n += copy(option[n:], u.cookie.server[:u.cookie.server_len])
	sync.mutex_unlock(&u.mu)

	watched := dns.Dry_Watch{backing = allocator, dry = &dry}
	scratch := dns.Dry_Watch{backing = context.temp_allocator, dry = &dry}
	context.temp_allocator = dns.dry_watch_allocator(&scratch)
	out, ok = dns.set_edns_option(query, .Cookie, option[:n], dns.dry_watch_allocator(&watched))
	return out, ok, dry
}

/*
Whether a reply may be ours.

Three ways a reply fails (RFC 7873 section 5.3): it echoes a client cookie that
is not the one we sent, its COOKIE option is not a legal length, or it carries no
cookie at all when one was sent to a server that has already shown it does
cookies.

That last one is the whole mechanism. A server we have never had a cookie from is
one that does not implement them, and RFC 7873 has the exchange carry on without
— but once it has issued one, accepting a reply with the option left off would
make the check something an attacker opts out of at no cost: it would be back to
guessing only the transaction ID and the source port, which is what the cookie
exists to put out of reach. It is asked of the query as well as of the
upstream, though; see the comment on `expected` below.

The option is read off the wire rather than off a decoded message, because a
decode is a second, stricter test than the one the reply had to pass to get here.
`response_matches` reads the header and the first question and stops, so a
message that is well formed that far and rubbish after it is a reply this server
accepts — and treating "it does not decode" as "not mine to judge" would hand the
attacker the same opt-out by another route: truncate the body after the question
and the cookie is never looked for. Walking to the OPT record judges exactly the
set of messages `response_matches` is willing to accept, so the two cannot
disagree about which replies get judged at all. A message that cannot even be
walked that far carries no cookie as far as this is concerned, which is the
answer that fails closed.
*/
@(private)
cookie_matches :: proc(u: ^Upstream, query, response: []u8) -> bool {
	if u == nil || !cookies_wanted(u) {
		return true
	}
	sync.mutex_lock(&u.mu)
	echoed := u.cookie.client
	held := u.cookie.server_len > 0
	sync.mutex_unlock(&u.mu)

	/*
	A cookie is owed on a reply to a query that carried one, and only then.

	Having been issued a server cookie is not enough on its own, because not
	every query sent through here carries a cookie. `attach_cookie` declines
	when the query has no OPT record to carry one, and a cookie-aware server
	answering a query that carried no cookie correctly answers with no cookie of
	its own (RFC 7873 section 5.2.1). Demanding one there rejects the only reply
	that could ever have arrived, and the caller gets a timeout for a name that
	resolves.

	On the exchange itself this costs nothing. The cookie's value is that an
	off-path attacker has to guess 64 bits it never saw, and that only ever
	applies to exchanges where those bits were sent. On one carrying no cookie
	there is nothing to guess and nothing to opt out of: forging a reply is
	exactly as hard as it is without cookies, which is where every reply from a
	cookie-less upstream already sits. What must not happen is the reverse - a
	reply to a query that did carry a cookie being accepted without one - and
	that is what `held` still governs.

	Every query the server forwards carries an OPT record
	(`server.upstream_query`), so this only lets a hand-built query without one
	go out uncookied, with its reply not held to a cookie.
	*/
	// Behind `held`, so the walk happens only where its answer can change the
	// outcome. `response_accepted` runs per received datagram, so on an
	// upstream this server holds no cookie for - every cookie-less one - this
	// would otherwise re-walk the query for each datagram of a spoofing flood
	// to reach a verdict `held` had already settled.
	expected := false
	if held {
		_, asked_with_cookie := dns.peek_edns_option(query, .Cookie)
		expected = asked_with_cookie
	}

	raw, found := reply_cookie(response)
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

/*
The COOKIE option a reply carries, if it carries one.

The same wire walk `cookie_matches` judges the reply with, and for the same
reason: a reply that got past the matcher without decoding is one this server is
about to hand to a client, and the cookie in it has to be found to be taken back
out.
*/
@(private)
reply_cookie :: proc(response: []u8) -> (raw: []u8, found: bool) {
	return dns.peek_edns_option(response, .Cookie)
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
	// Shared by the retry, which is part of the same exchange (issue #449).
	deadline: time.Tick,
	allocator: mem.Allocator,
) -> (
	response: []u8,
	err: Error,
) {
	asked, attached, dry := attach_cookie(u, query, context.temp_allocator)
	if dry && !attached {
		return nil, .Out_Of_Memory
	}
	if !attached {
		return send(u, query, timeout, deadline, allocator)
	}

	response = send(u, asked, timeout, deadline, allocator) or_return
	learn_cookie(u, response)

	if dns.peek_rcode(response) == .Bad_Cookie {
		// Reached only for want of memory: the same `query` carried a cookie a
		// moment ago at the top of this proc, and nothing about it has changed
		// since. A refusal rather than an assertion because the alternative is
		// sending the query on without the cookie the server has just insisted on.
		retry, retried, retry_dry := attach_cookie(u, query, context.temp_allocator)
		if !retried {
			// `response` came out of `allocator`, which on the race path is the
			// process heap: dropping it here would leak it for the life of the
			// process, so free it before turning the reply away.
			delete(response, allocator)
			return nil, .Out_Of_Memory if retry_dry else .Bad_Response
		}
		// The retry supersedes this reply; free it before it is overwritten. Null
		// the named result in between: `send` can bail through `or_return`, and a
		// result still pointing at the freed buffer would be one the caller could
		// read back rather than one it is guaranteed to discard on the error.
		delete(response, allocator)
		response = nil
		response = send(u, retry, timeout, deadline, allocator) or_return
		learn_cookie(u, response)
		if dns.peek_rcode(response) == .Bad_Cookie {
			logx.debugf("upstream %s: still BADCOOKIE after a fresh cookie", u.spec.name)
			delete(response, allocator)
			return nil, .Bad_Response
		}
	}

	return strip_cookie(u, response, allocator)
}

/*
The cookie goes no further than this.

It belongs to the conversation between this server and that upstream. Left
in, it would reach a client that never asked for one and, worse, be stored
in the cache and handed to every client that asks the same question later.

Takes `response`, which came out of `allocator`, and hands back the reply to
use. `Bad_Response` where the cookie cannot be taken out, and `Out_Of_Memory`
where that was for want of memory: neither hands the reply on as it stands.
*/
@(private)
strip_cookie :: proc(u: ^Upstream, response: []u8, allocator: mem.Allocator) -> (out: []u8, err: Error) {
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
	returned is now superseded and has to be freed before we leave.

	On the arena paths freeing it is a no-op — the per-request scratch arena
	reclaims it on `free_all` regardless. But on the race path `allocator` is the
	process heap (a racer can outlive the caller's arena), and there
	nothing else ever frees it: left behind, it leaks one buffer per forwarded
	query for the life of the process.
	*/
	strip_dry := false
	stripped: []u8
	ok: bool
	{
		watched := dns.Dry_Watch{backing = allocator, dry = &strip_dry}
		scratch := dns.Dry_Watch{backing = context.temp_allocator, dry = &strip_dry}
		context.temp_allocator = dns.dry_watch_allocator(&scratch)
		stripped, ok = dns.remove_edns_option(response, .Cookie, dns.dry_watch_allocator(&watched))
	}
	if !ok {
		// Failing closed, the way the client-facing side does when it cannot take
		// the client's cookie back out. Handing the answer over as it stands is
		// the one outcome the paragraph above exists to prevent, and losing it is
		// the cheaper mistake: the group still has other servers to ask. A strip
		// this server had no memory for is not the upstream's doing.
		delete(response, allocator)
		if strip_dry {
			return nil, .Out_Of_Memory
		}
		logx.warnf("upstream %s: could not strip the server cookie from a reply", u.spec.name)
		return nil, .Bad_Response
	}
	/*
	Free the superseded reply only once it is a different buffer. The cookie is
	present here (the `reply_cookie` guard returned otherwise) and the guard
	walks the same OPT record `remove_edns_option` does, so the strip always
	makes a fresh buffer and this is always the case. The comparison stays
	because `remove_edns_option` hands the input straight back when it finds no
	option to take out: if the two ever stop agreeing on "is the cookie
	present", that is a free of the very buffer we return rather than a missing
	strip, and this is what keeps it from being one.
	*/
	if raw_data(stripped) != raw_data(response) {
		delete(response, allocator)
	}
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
