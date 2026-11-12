package h2

import "core:strings"
import "elodin:dns"

/*
HTTP field and message grammar (RFC 9110, RFC 9112), shared by both versions of
the protocol: the HTTP/1.1 DoH server and client and the configuration loader
use it as well as this package.
*/

/*
RFC 9110 5.6.2: a token, which is what a field name is on either version of the
protocol. ASCII only, so a name outside it cannot be one a Unicode case fold in
some other hop reads as a field this one knows by another spelling.
*/
is_token :: proc(s: string) -> bool {
	for i in 0 ..< len(s) {
		switch s[i] {
		case 'a' ..= 'z', 'A' ..= 'Z', '0' ..= '9':
			continue
		case '!', '#', '$', '%', '&', '\'', '*', '+', '-', '.', '^', '_', '`', '|', '~':
			continue
		}
		return false
	}
	// 1*tchar: nothing at all is not a token.
	return len(s) > 0
}

/*
RFC 9112 3.2 and RFC 3986 2: a request target is visible ASCII and nothing
else. No SP, HTAB, VT or FF, which a lenient hop is entitled to split a request
line on (RFC 9112 3), no other control, and no byte outside ASCII, which a URI
cannot hold unencoded. Emptiness is left to the caller, which knows what an
empty target means on its version.
*/
target_is_valid :: proc(s: string) -> bool {
	for i in 0 ..< len(s) {
		if s[i] <= ' ' || s[i] >= 0x7f {
			return false
		}
	}
	return true
}

/*
RFC 9110 7.2 and RFC 3986 3.2: a host, `uri-host [":" port]`, is a target that
holds no userinfo (which RFC 9113 8.3.1 forbids in `:authority` by name), no
path, query or fragment, and no backslash, which WHATWG parsers read as a `/`.
Each of those is a Host that a hop routing by it parses its own way:
`a.example@b.example` is `b.example` to one reader and `a.example` to another.
Empty is left to the caller, as for `target_is_valid`.
*/
authority_is_valid :: proc(s: string) -> bool {
	return target_is_valid(s) && strings.index_any(s, "@/\\?#") < 0
}

/*
RFC 9110 5.6.1: whether the comma-separated list `value` holds `token`, compared
without regard to ASCII case. `Connection: keep-alive, close` is a close, which
a single-token compare missed (#437); each element loses its OWS and nothing
more, and empty elements match nothing. For lists of tokens only, such as
`Connection`: a comma inside a quoted-string is split on like any other.
*/
list_has_token :: proc(value, token: string) -> bool {
	rest := value
	for element in strings.split_iterator(&rest, ",") {
		if dns.name_equal_fold(trim_ows(element), token) {
			return true
		}
	}
	return false
}

/*
`value` with `OWS` taken off either end and nothing else.

`OWS` is spaces and tabs (RFC 9110 5.6.3), which is all a recipient may take off
a field value. `strings.trim_space` takes more: it is Unicode-aware, so it also
takes a non-breaking space off the end, which would make `close\u00a0` a close. A hop
in front reads the field as the grammar writes it and refuses the message rather
than trimming it, so trimming one here is this hop reading a value the front end
never saw.
*/
trim_ows :: proc(value: string) -> string {
	return strings.trim(value, " \t")
}

/*
An HTTP/1 `Content-Length` value, which is `1*DIGIT` (RFC 9110 8.6) and nothing
else, with `OWS` around it. One parser for the DoH server and the HTTP client,
since both carry the same request-smuggling hardening and two that disagree are
the bug.

`strconv.parse_int` with its default base reads a good deal more: the base comes
from a prefix, so `0x10` is 16 and `0b1010` is 10; `_` between digits is
skipped; a leading sign is allowed; and the accumulator wraps in silence, so
`18446744073709551620` comes back as 4 and a range check downstream sees nothing
wrong. On the server that is CL.CL request smuggling behind a front end that
reads the field as the RFC writes it; on the client it leaves a kept-alive
connection reading from the middle of a body.

A value past `limit` comes back as `limit + 1`, so nothing wraps on the way to
the caller's range check, and its digits are still all checked: too large and
not a length at all are different refusals.
*/
parse_content_length :: proc(value: string, limit: int) -> (length: int, ok: bool) {
	// A step is taken only from `length <= limit`, so it stays under
	// `limit * 10 + 9`, which this keeps inside an int.
	assert(limit >= 0 && limit < max(int) / 10)
	digits := trim_ows(value)
	if len(digits) == 0 {
		return 0, false
	}
	for i in 0 ..< len(digits) {
		c := digits[i]
		if c < '0' || c > '9' {
			return 0, false
		}
		if length <= limit {
			length = min(length * 10 + int(c - '0'), limit + 1)
		}
	}
	return length, true
}

/*
An HTTP/1 `HTTP-version`: `HTTP/` `DIGIT` `.` `DIGIT`, case-sensitively, and
nothing on either side of it (RFC 9112 2.3) - the request line's third token, or
the first eight bytes of a status line.
*/
http1_version :: proc(s: string) -> (major, minor: u8, ok: bool) {
	if len(s) != 8 || !strings.has_prefix(s, "HTTP/") || s[6] != '.' {
		return
	}
	if s[5] < '0' || s[5] > '9' || s[7] < '0' || s[7] > '9' {
		return
	}
	return s[5] - '0', s[7] - '0', true
}

/*
RFC 9113 8.2.1: a field name is an RFC 9110 token, and lowercase. Uppercase is
not folded on receipt but malformed, so that two hops cannot disagree about
which of `Transfer-Encoding` and `transfer-encoding` they were sent.
*/
@(private)
field_name_is_valid :: proc(name: string) -> bool {
	for i in 0 ..< len(name) {
		if name[i] >= 'A' && name[i] <= 'Z' {
			return false
		}
	}
	return is_token(name)
}

/*
RFC 9113 8.2.1 again: a field value holds no NUL, CR or LF, and neither begins
nor ends with whitespace. The three characters are what an HTTP/1.1 hop would
read as the end of the field, or of the message, so a value carrying one is how
a request smuggled through this end would be written.
*/
field_value_is_valid :: proc(value: string) -> bool {
	if len(value) > 0 {
		first, last := value[0], value[len(value) - 1]
		if first == ' ' || first == '\t' || last == ' ' || last == '\t' {
			return false
		}
	}
	for i in 0 ..< len(value) {
		switch value[i] {
		case 0, '\n', '\r':
			return false
		}
	}
	return true
}
