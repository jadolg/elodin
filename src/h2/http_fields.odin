package h2

import "core:strings"
import "elodin:dns"
import "elodin:netx"

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
The name and value of an HTTP/1 field line, `ok` false for one whose shape is
to be refused rather than read. The name is not checked to be a token, which
each end decides for itself.
*/
split_field_line :: proc(header: string) -> (name, value: string, ok: bool) {
	/*
	A field line this end cannot read is a field line it must not skip.

	Both of these are ways to write a Content-Length that this end does not see
	and another hop might: a line beginning with whitespace is an obs-fold
	continuation of the one before it (RFC 9112 5.2), and whitespace before
	the colon is not a field name (RFC 9112 5.1). Read here as "no header of
	that name", either one leaves the body unread while the hop that unfolded
	or trimmed it framed the message by a length this end never applied - the
	remainder becomes the next message on the connection. Both sections have
	a server answer them with a 400, and nothing that speaks DoH sends either.
	*/
	if header == "" || header[0] == ' ' || header[0] == '\t' {
		return "", "", false
	}
	colon := strings.index_byte(header, ':')
	if colon <= 0 {
		return "", "", false
	}
	if header[colon - 1] == ' ' || header[colon - 1] == '\t' {
		return "", "", false
	}
	name = header[:colon]
	// `OWS` off it and nothing more: see `h2.trim_ows`.
	value = trim_ows(header[colon + 1:])
	return name, value, true
}

/*
An HTTP/1.1 chunk line (RFC 9112 7.1): `chunk-size [ chunk-ext ]`, the size one
or more hex digits and the extensions held to the 7.1.1 grammar, then ignored.

A size past `limit` comes back as `limit + 1`, so nothing wraps on the way to
the caller's range check, and the rest of the line is still checked: too large
and not a chunk line at all are different refusals, as `parse_content_length`'s
are. `ok` is false for a line that is not a chunk line.
*/
parse_chunk_line :: proc(line: string, limit: int) -> (size: int, ok: bool) {
	// A step is taken only from `size <= limit`, so it stays under
	// `limit * 16 + 15`, which this keeps inside an int.
	assert(limit >= 0 && limit < max(int) / 16)
	digits := 0
	for digits < len(line) {
		v, hex := netx.hex_digit(line[digits])
		if !hex {
			break
		}
		if size <= limit {
			size = min(size * 16 + int(v), limit + 1)
		}
		digits += 1
	}
	// `chunk-ext = *( BWS ";" BWS chunk-ext-name [ BWS "=" BWS chunk-ext-val ] )`
	if digits == 0 || !params_are_valid(line[digits:], value_optional = true) {
		return 0, false
	}
	return size, true
}

/*
Whether `s` is empty or a list of `;` parameters, each `name [ "=" value ]` with
whitespace allowed around the `;` and the `=`: a name is a token and a value a
token or a quoted-string. RFC 9112 7 writes a transfer-coding's parameters this
way with the value required, and 7.1.1 a chunk extension's with it optional.
Whitespace with no parameter after it is in neither grammar and is refused.
*/
params_are_valid :: proc(s: string, value_optional: bool) -> bool {
	if len(s) > 0 && (s[len(s) - 1] == ' ' || s[len(s) - 1] == '\t') {
		return false
	}
	rest := s
	for {
		rest = strings.trim_left(rest, " \t")
		if rest == "" {
			return true
		}
		if rest[0] != ';' {
			return false
		}
		rest = strings.trim_left(rest[1:], " \t")
		n := token_prefix(rest)
		if n == 0 {
			return false
		}
		rest = strings.trim_left(rest[n:], " \t")
		if value_optional && (rest == "" || rest[0] == ';') {
			continue
		}
		if rest == "" || rest[0] != '=' {
			return false
		}
		rest = strings.trim_left(rest[1:], " \t")
		if v := token_prefix(rest); v > 0 {
			rest = rest[v:]
		} else if q := quoted_string_prefix(rest); q > 0 {
			rest = rest[q:]
		} else {
			return false
		}
	}
}

// How many bytes at the start of `s` are a quoted-string (RFC 9110 5.6.4), 0 if
// it does not start with one.
quoted_string_prefix :: proc(s: string) -> int {
	if len(s) == 0 || s[0] != '"' {
		return 0
	}
	for i := 1; i < len(s); i += 1 {
		switch c := s[i]; {
		case c == '"':
			return i + 1
		case c == '\\':
			// A quoted-pair: HTAB, SP or a visible character after the backslash.
			if i + 1 >= len(s) || (s[i + 1] < ' ' && s[i + 1] != '\t') || s[i + 1] == 0x7f {
				return 0
			}
			i += 1
		case c < ' ' && c != '\t', c == 0x7f:
			return 0
		}
	}
	return 0
}

// How many bytes at the start of `s` are a token (RFC 9110 5.6.2).
@(private)
token_prefix :: proc(s: string) -> int {
	for i in 0 ..< len(s) {
		if !is_token(s[i:i + 1]) {
			return i
		}
	}
	return len(s)
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
