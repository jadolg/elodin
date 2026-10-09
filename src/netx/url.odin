package netx

import "core:strings"

// RFC 3986 3.1: scheme = ALPHA *( ALPHA / DIGIT / "+" / "-" / "." ).
is_scheme :: proc(scheme: string) -> bool {
	for i in 0 ..< len(scheme) {
		switch scheme[i] {
		case 'a' ..= 'z', 'A' ..= 'Z':
			continue
		case '0' ..= '9', '+', '-', '.':
			if i > 0 {
				continue
			}
		}
		return false
	}
	return len(scheme) > 0
}

/*
An absolute url's scheme, its authority, and its path and query, which are the
request target (RFC 9112 3.2.1). The fragment is the client's alone and is left
out. `core:net`'s `split_url` drops the query, which is part of what a request
names; the target here is the url's from the authority's end, as written, and is
empty when the url has neither path nor query.

RFC 3986 3.2: the authority ends at the first `/`, `?` or `#`.
*/
split_url :: proc(url: string) -> (scheme, authority, target: string, ok: bool) {
	sep := strings.index(url, "://")
	if sep < 0 || !is_scheme(url[:sep]) {
		return "", "", "", false
	}
	rest := url[sep + 3:]
	end := strings.index_any(rest, "/?#")
	if end < 0 {
		end = len(rest)
	}
	target = rest[end:]
	if i := strings.index_byte(target, '#'); i >= 0 {
		target = target[:i]
	}
	return url[:sep], rest[:end], target, true
}

/*
RFC 9112 3.2.1: a request target in origin-form is rooted, and a url with no path
names `/` (RFC 3986 6.2.3), so `?q` is `/?q`.
*/
origin_form :: proc(target: string, allocator := context.temp_allocator) -> string {
	if target == "" || target[0] == '?' {
		return strings.concatenate({"/", target}, allocator)
	}
	return target
}

/*
RFC 3986 5.2: the url a reference names, read against `base`, the absolute url
it was found at. RFC 9110 10.2.2 lets a redirect's `Location` be relative -
`/v2/hosts.txt`, `hosts.txt`, `?page=2` or `//cdn.example/hosts.txt` - and
servers send all four. A reference with a scheme and no authority (`g:h`) comes
back as it is, as does any reference when `base` is not an absolute url. What
comes back is held to no rule here: the caller checks it as it checks any url.

The result is at most `len(base) + len(ref) + 1` bytes, in the temp allocator.
*/
resolve_reference :: proc(base, ref: string) -> string {
	scheme, authority, rest := "", "", ref
	// 5.2.2: a scheme is a run of scheme characters ending in the first `:`.
	if colon := strings.index_byte(ref, ':'); colon >= 0 && is_scheme(ref[:colon]) {
		scheme, rest = ref[:colon], ref[colon + 1:]
		if !strings.has_prefix(rest, "//") {
			return ref
		}
	}
	base_target := ""
	if scheme == "" {
		ok: bool
		scheme, authority, base_target, ok = split_url(base)
		if !ok {
			return ref
		}
	}
	// An authority of its own, whose path loses its dot segments as any other.
	own_authority := strings.has_prefix(rest, "//")
	if own_authority {
		rest = rest[2:]
		end := strings.index_any(rest, "/?#")
		if end < 0 {
			end = len(rest)
		}
		authority, rest = rest[:end], rest[end:]
	}

	// The fragment, then the query: either may hold a `/`, a `?` or a dot segment.
	path, fragment := rest, ""
	if i := strings.index_byte(path, '#'); i >= 0 {
		path, fragment = path[:i], path[i:]
	}
	query := ""
	has_query := false
	if i := strings.index_byte(path, '?'); i >= 0 {
		path, query, has_query = path[:i], path[i:], true
	}
	base_path, base_query := base_target, ""
	if i := strings.index_byte(base_path, '?'); i >= 0 {
		base_path, base_query = base_path[:i], base_path[i:]
	}

	switch {
	case own_authority:
		if path != "" {
			path = remove_dot_segments(path)
		}
	case path == "":
		path = base_path
		if !has_query {
			query = base_query
		}
	case path[0] == '/':
		path = remove_dot_segments(path)
	case:
		// 5.2.3: merged with the base path up to its last `/`, which for a base
		// with an authority and no path is the root.
		dir := base_path[:strings.last_index_byte(base_path, '/') + 1]
		if dir == "" {
			dir = "/"
		}
		path = remove_dot_segments(strings.concatenate({dir, path}, context.temp_allocator))
	}
	return strings.concatenate({scheme, "://", authority, path, query, fragment}, context.temp_allocator)
}

/*
RFC 3986 5.2.4, for a path that begins with `/`: `.` segments go, and `..` takes
the segment before it with it, never past the root. One pass into one buffer the
size of the input, so a long run of `/./` or `/..` costs what its bytes do.
*/
@(private)
remove_dot_segments :: proc(path: string) -> string {
	b := strings.builder_make(0, len(path), context.temp_allocator)
	rest := path[1:]
	for {
		end := strings.index_byte(rest, '/')
		last := end < 0
		seg := rest if last else rest[:end]
		switch seg {
		case ".":
		case "..":
			// Back to the `/` that began the segment before.
			if i := strings.last_index_byte(strings.to_string(b), '/'); i >= 0 {
				resize(&b.buf, i)
			}
		case:
			strings.write_byte(&b, '/')
			strings.write_string(&b, seg)
		}
		if last {
			// A path that ends in a dot segment names a directory: `/a/b/..` is `/a/`.
			if seg == "." || seg == ".." {
				strings.write_byte(&b, '/')
			}
			break
		}
		rest = rest[end + 1:]
	}
	return strings.to_string(b)
}
