package upstream

import "core:mem"
import "core:time"
import "elodin:dns"
import "elodin:logx"

/*
EDNS(0) padding, from the asking side (RFC 8467 section 4.1).

The other half of what `server.pad_answer` does for clients. A network observer
sitting between this resolver and Cloudflare or Quad9 cannot read the queries,
but it can measure them, and what it is measuring is not one household's
browsing - it is every client behind this server, aggregated. Stubby and Unbound
both pad by default, so without this elodin is the one unpadded hop in a path
whose other hops were all chosen for privacy.

128 octets, which is the block RFC 8467 section 4.1 names for a requestor and
the one the recommended responder block of 468 was chosen to complement.

DoT and DoH only, for the reasons in `dns/padding.odin`: on UDP and plain TCP
the message is readable anyway, and on UDP the padding would enlarge exactly the
datagrams an amplifier wants enlarged.
*/

/*
Whether queries to this upstream go out padded.

The mirror image of `cookies_wanted`, and deliberately so: a cookie protects the
transports that have no encryption to authenticate the peer, and padding buys
something only on the transports that do. Nothing is both, which is what lets
`exchange` pick one of the two.
*/
@(private)
padding_wanted :: proc(u: ^Upstream) -> bool {
	#partial switch u.spec.kind {
	case .TLS, .HTTPS:
		return true
	}
	return false
}

/*
Send one query padded, and take the padding back off whatever comes home.

A query with no OPT record goes as it is - see `dns.pad_query`, which will not
mint one - and this is still the path that runs, because the strip on the way
back is worth doing either way.

Nothing about the reply's own padding is this server's to pass on. A padded
response is padded for the hop it arrived on, and the copy kept here outlives
that hop: it goes into the cache, where it would be served to every later client
asking the same question, over UDP included. That is two costs for no privacy -
cache entries a few hundred bytes larger than the answers in them, and UDP
answers inflated toward `server.max_udp_response` and the truncation that waits
past it. The client-facing side pads what it sends, on its own transport, with
its own block size, from the answer as it actually is.
*/
@(private)
exchange_padded :: proc(
	u: ^Upstream,
	query: []u8,
	timeout: time.Duration,
	allocator: mem.Allocator,
) -> (
	response: []u8,
	err: Error,
) {
	/*
	Working memory, from the scratch arena rather than from `allocator`: on the
	race path `allocator` is the process heap and nothing there would ever
	reclaim a padded copy of a query. The arena is reset per job by the worker
	that owns it, the same way `exchange_with_cookie` builds its query.
	*/
	asked, padded := dns.pad_query(query, dns.PAD_QUERY_BLOCK, dns.MAX_MESSAGE, context.temp_allocator)
	if !padded {
		asked = query
	}

	response = send(u, asked, timeout, allocator) or_return
	return strip_padding(u, response, allocator)
}

/*
Take the padding option out of a reply, if it brought one.

Asked with `peek_edns_option` first rather than inferred from the removal
failing, as the cookie strip is: `remove_edns_option` needs an OPT record to
walk, so a reply that has none cannot be told apart from a removal that went
wrong.

Fails open, where the cookie strip fails closed. The two are not the same kind
of leftover: a server cookie handed to a client is a secret escaping the
conversation it belongs to, and losing the answer is the cheaper mistake. Padding
that survives is only bytes - the client-facing side replaces it on the paths
that pad and the cache holds a larger entry than it needed to - and throwing away
a good answer to avoid them would be the more expensive one.
*/
@(private)
strip_padding :: proc(u: ^Upstream, response: []u8, allocator: mem.Allocator) -> (out: []u8, err: Error) {
	if _, carried := dns.peek_edns_option(response, .Padding); !carried {
		return response, .None
	}

	stripped, ok := dns.remove_edns_option(response, .Padding, allocator)
	if !ok {
		logx.debugf("upstream %s: could not strip the padding from a reply", u.spec.name)
		return response, .None
	}
	/*
	Free the superseded reply, but only once it is a different buffer.

	`remove_edns_option` hands its input straight back when it finds nothing to
	remove, and the guard above says there was something - so this is always a
	fresh buffer and the delete always has something of its own to free. The
	comparison stays for the same reason it does in `exchange_with_cookie`: if
	the two ever stop agreeing about whether the option is there, that is a free
	of the buffer being returned rather than a strip that did not happen.
	*/
	if raw_data(stripped) != raw_data(response) {
		delete(response, allocator)
	}
	return stripped, .None
}
