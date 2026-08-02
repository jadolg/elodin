package upstream

import "core:mem"
import "core:net"
import "core:time"
import "elodin:dns"
import "elodin:h2"
import "elodin:tlsx"

/*
DNS over HTTPS (RFC 8484).

The query is POSTed as application/dns-message. The transaction ID is zeroed on
the way out, as the RFC recommends, so that intermediaries can cache by body;
the caller restores the client's ID from the response afterwards.

Which transport carries it — HTTP/2, multiplexed onto one shared connection, or
pooled HTTP/1.1 connections — is decided by get_h2_conn from what ALPN showed
on this upstream's first connection; see h2client.odin.
*/
@(private)
exchange_doh :: proc(
	u: ^Upstream,
	query: []u8,
	timeout: time.Duration,
	allocator: mem.Allocator,
) -> (
	response: []u8,
	err: Error,
) {
	if len(query) < dns.HEADER_SIZE {
		return nil, .Bad_Response
	}
	body := make([]u8, len(query), context.temp_allocator)
	copy(body, query)
	dns.set_id_in_place(body, 0)

	return exchange_doh_h2(u, query, body, timeout, allocator)
}

@(private)
exchange_doh_h2 :: proc(
	u: ^Upstream,
	query: []u8,
	body: []u8,
	timeout: time.Duration,
	allocator: mem.Allocator,
) -> (
	response: []u8,
	err: Error,
) {
	// A stale shared connection dying between get_h2_conn handing it out and
	// this call reaching the server is retried once, on a fresh one; see
	// exchange_tcp for why that must not count as an upstream failure.
	for attempt in 0 ..< 2 {
		conn, is_h2, cerr := get_h2_conn(u, timeout)
		if cerr != .None {
			return nil, cerr
		}
		if !is_h2 {
			return exchange_doh_h1(u, query, body, timeout, allocator)
		}

		resp, herr := h2.client_request(
			conn,
			h2.Client_Request {
				method = "POST",
				scheme = "https",
				authority = u.spec.hostname,
				path = u.spec.path,
				content_type = "application/dns-message",
				accept = "application/dns-message",
				body = body,
			},
			timeout,
			allocator,
		)
		h2.client_unref(conn)

		switch herr {
		case .None:
			if resp.status != 200 || len(resp.body) < dns.HEADER_SIZE {
				if len(resp.body) > 0 {
					delete(resp.body, allocator)
				}
				return nil, .HTTP_Error
			}
			dns.set_id_in_place(resp.body, u16(query[0]) << 8 | u16(query[1]))
			if !response_matches(query, resp.body) {
				delete(resp.body, allocator)
				return nil, .Bad_Response
			}
			return resp.body, .None
		case .Closed:
			if attempt == 0 {
				continue
			}
			return nil, .IO_Error
		case .Reset:
			return nil, .HTTP_Error
		case .Timeout:
			return nil, .Timeout
		}
	}
	return nil, .IO_Error
}

@(private)
exchange_doh_h1 :: proc(
	u: ^Upstream,
	query: []u8,
	body: []u8,
	timeout: time.Duration,
	allocator: mem.Allocator,
) -> (
	response: []u8,
	err: Error,
) {
	// Pooled connection first, then a fresh one; see exchange_tcp for why a
	// dead pooled connection must not count as an upstream failure.
	for attempt in 0 ..< 2 {
		conn: Idle_Conn
		reused := false
		if attempt == 0 {
			conn, reused = take_idle(u)
		}
		stream: Stream
		if reused {
			stream = Stream {
				socket = conn.socket,
				tls    = conn.tls,
			}
		} else {
			s, oerr := open_stream(u.endpoint, u.tls_ctx, u.spec.hostname, timeout)
			if oerr != .None {
				return nil, oerr
			}
			stream = s
		}

		resp, herr := http_exchange(
			&stream,
			Http_Request {
				method = "POST",
				path = u.spec.path,
				host = u.spec.hostname,
				body = body,
				content_type = "application/dns-message",
				accept = "application/dns-message",
			},
			allocator,
		)

		if herr == .None && resp.status == 200 && len(resp.body) >= dns.HEADER_SIZE {
			// Restore the ID the caller sent so the usual matching applies.
			dns.set_id_in_place(resp.body, u16(query[0]) << 8 | u16(query[1]))
			if !response_matches(query, resp.body) {
				delete(resp.body, allocator)
				stream_close(&stream)
				return nil, .Bad_Response
			}
			if resp.keep_alive {
				put_idle(u, Idle_Conn{socket = stream.socket, tls = stream.tls})
			} else {
				stream_close(&stream)
			}
			return resp.body, .None
		}

		if herr == .None && resp.status != 200 {
			stream_close(&stream)
			return nil, .HTTP_Error
		}

		stream_close(&stream)
		if !reused {
			return nil, herr if herr != .None else .Bad_Response
		}
	}
	return nil, .IO_Error
}

/*
Fetch a URL over HTTP or HTTPS, following redirects.

Used to download blocklists. Kept here rather than in the filter package so the
HTTP and TLS machinery has exactly one implementation.
*/
fetch_url :: proc(
	url: string,
	bootstrap: []string,
	timeout: time.Duration,
	allocator := context.allocator,
) -> (
	body: []u8,
	err: Error,
) {
	current := url
	for _ in 0 ..< 5 {
		scheme, host, path, port, host_only, purl_ok := split_http_url(current)
		if !purl_ok {
			return nil, .HTTP_Error
		}

		addr, resolved := resolve_address(host_only, bootstrap)
		if !resolved {
			return nil, .Not_Resolved
		}
		endpoint := net.Endpoint {
			address = addr,
			port    = port,
		}

		tls_ctx: ^tlsx.Context
		if scheme == "https" {
			ctx, terr := tlsx.client_context(true, "", []string{"http/1.1"}, context.temp_allocator)
			if terr != .None {
				return nil, .TLS_Failed
			}
			tls_ctx = ctx
		}
		defer if tls_ctx != nil {
			tlsx.context_destroy(tls_ctx)
		}

		stream := open_stream(endpoint, tls_ctx, host_only, timeout) or_return
		defer stream_close(&stream)

		resp, herr := http_exchange(
			&stream,
			Http_Request{method = "GET", path = path, host = host, accept = "text/plain, */*"},
			allocator,
		)
		if herr != .None {
			return nil, herr
		}

		switch resp.status {
		case 200:
			return resp.body, .None
		case 301, 302, 303, 307, 308:
			if resp.location == "" {
				return nil, .HTTP_Error
			}
			if len(resp.body) > 0 {
				delete(resp.body, allocator)
			}
			current = resp.location
			continue
		case:
			if len(resp.body) > 0 {
				delete(resp.body, allocator)
			}
			return nil, .HTTP_Error
		}
	}
	return nil, .HTTP_Error
}
