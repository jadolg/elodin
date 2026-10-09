package netx

import "core:strings"
import "core:testing"

// RFC 3986 5.4.1 and 5.4.2: every example the RFC works through, against its base.
@(test)
test_a_reference_resolves_as_rfc_3986_reads_it :: proc(t: ^testing.T) {
	Case :: struct {
		ref, want: string,
	}
	base := "http://a/b/c/d;p?q"
	cases := []Case {
		// 5.4.1, normal examples.
		{"g:h", "g:h"},
		{"g", "http://a/b/c/g"},
		{"./g", "http://a/b/c/g"},
		{"g/", "http://a/b/c/g/"},
		{"/g", "http://a/g"},
		{"//g", "http://g"},
		{"?y", "http://a/b/c/d;p?y"},
		{"g?y", "http://a/b/c/g?y"},
		{"#s", "http://a/b/c/d;p?q#s"},
		{"g#s", "http://a/b/c/g#s"},
		{"g?y#s", "http://a/b/c/g?y#s"},
		{";x", "http://a/b/c/;x"},
		{"g;x", "http://a/b/c/g;x"},
		{"g;x?y#s", "http://a/b/c/g;x?y#s"},
		{"", "http://a/b/c/d;p?q"},
		{".", "http://a/b/c/"},
		{"./", "http://a/b/c/"},
		{"..", "http://a/b/"},
		{"../", "http://a/b/"},
		{"../g", "http://a/b/g"},
		{"../..", "http://a/"},
		{"../../", "http://a/"},
		{"../../g", "http://a/g"},
		// 5.4.2, abnormal examples, read strictly.
		{"../../../g", "http://a/g"},
		{"../../../../g", "http://a/g"},
		{"/./g", "http://a/g"},
		{"/../g", "http://a/g"},
		{"g.", "http://a/b/c/g."},
		{".g", "http://a/b/c/.g"},
		{"g..", "http://a/b/c/g.."},
		{"..g", "http://a/b/c/..g"},
		{"./../g", "http://a/b/g"},
		{"./g/.", "http://a/b/c/g/"},
		{"g/./h", "http://a/b/c/g/h"},
		{"g/../h", "http://a/b/c/h"},
		{"g;x=1/./y", "http://a/b/c/g;x=1/y"},
		{"g;x=1/../y", "http://a/b/c/y"},
		{"g?y/./x", "http://a/b/c/g?y/./x"},
		{"g?y/../x", "http://a/b/c/g?y/../x"},
		{"g#s/./x", "http://a/b/c/g#s/./x"},
		{"g#s/../x", "http://a/b/c/g#s/../x"},
		{"http:g", "http:g"},
	}
	for c in cases {
		got := resolve_reference(base, c.ref)
		testing.expectf(t, got == c.want, "%q resolved to %q, want %q", c.ref, got, c.want)
	}
	// 5.2.3: a base with an authority and no path merges from the root, and
	// an empty segment is a segment that `..` takes like any other.
	testing.expect_value(t, resolve_reference("https://a:8443", "g"), "https://a:8443/g")
	testing.expect_value(t, resolve_reference("https://a?q", "g"), "https://a/g")
	testing.expect_value(t, resolve_reference("http://a/b//c/d", "../g"), "http://a/b//g")
	// 5.2.2: a scheme is checked as a scheme, so a colon in a later segment, or
	// behind something no scheme holds, is a relative path.
	testing.expect_value(t, resolve_reference(base, "g/h:i"), "http://a/b/c/g/h:i")
	testing.expect_value(t, resolve_reference(base, "1g:h"), "http://a/b/c/1g:h")
	// 5.2.2: a reference with its own authority has its dot segments removed
	// too, and its query and fragment kept as written.
	testing.expect_value(t, resolve_reference(base, "//g/x/../y/./z?q/../r#s"), "http://g/y/z?q/../r#s")
	testing.expect_value(t, resolve_reference(base, "https://g/x/../y/."), "https://g/y/")
	free_all(context.temp_allocator)
}

// The target is the path and the query, as written; the fragment is never sent.
@(test)
test_a_url_splits_with_its_query :: proc(t: ^testing.T) {
	Case :: struct {
		url, scheme, authority, target: string,
	}
	cases := []Case {
		{"http://a/list?format=hosts", "http", "a", "/list?format=hosts"},
		{"https://a:8443?x=/y#z", "https", "a:8443", "?x=/y"},
		{"https://[::1]#/p", "https", "[::1]", ""},
		{"HTTP://a/p?q#f?g", "HTTP", "a", "/p?q"},
	}
	for c in cases {
		scheme, authority, target, ok := split_url(c.url)
		testing.expectf(t, ok, "%q did not split", c.url)
		testing.expectf(
			t,
			scheme == c.scheme && authority == c.authority && target == c.target,
			"%q split to %q %q %q",
			c.url,
			scheme,
			authority,
			target,
		)
	}
	for url in ([]string{"/relative", "a/b", "://a/", "1http://a/", "ht tp://a/"}) {
		_, _, _, ok := split_url(url)
		testing.expectf(t, !ok, "%q split", url)
	}
}

/*
A Location is the list host's to write, up to the HTTP reader's 64 KB line. A
run of dot segments must cost what its bytes do: a buffer per segment, or an
output that grew past the input, would let one header ask for many times its
size.
*/
@(test)
test_dot_segments_cost_their_own_bytes :: proc(t: ^testing.T) {
	for unit in ([]string{"./", "../", "a/../", "/"}) {
		// After `g/`, so that a run of `/` is a path and not a network path.
		ref := strings.concatenate({"g/", strings.repeat(unit, 16 * 1024, context.temp_allocator)}, context.temp_allocator)
		got := resolve_reference("http://a/b/c", ref)
		testing.expectf(t, len(got) <= len("http://a/b/c") + len(ref) + 1, "%q x16k resolved to %d bytes", unit, len(got))
	}
	testing.expect_value(t, resolve_reference("http://a/b/c", strings.repeat("../", 1000, context.temp_allocator)), "http://a/")
	free_all(context.temp_allocator)
}
