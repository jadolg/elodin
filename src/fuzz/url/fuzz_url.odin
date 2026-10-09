package fuzz_url

import "core:strings"
import "elodin:fuzz/harness"
import "elodin:netx"

/*
The url splitter and the RFC 3986 5.2 resolver a redirect's Location goes
through, which a list host writes. The input is the base url, a newline, and the
reference. What is checked is what `fetch_url` leans on: the result costs no more
than its inputs, and a reference with no scheme and no authority of its own
keeps the base's scheme and authority, whatever its dot segments say.
*/
@(export, link_name = "LLVMFuzzerTestOneInput")
fuzz_one :: proc "c" (data: [^]u8, size: uint) -> i32 {
	f: harness.Fuzz_Arena
	context = harness.setup(&f)
	defer harness.teardown(&f)

	text := string(data[:size])
	nl := strings.index_byte(text, '\n')
	if nl < 0 {
		_, _, _, _ = netx.split_url(text)
		return 0
	}
	base, ref := text[:nl], text[nl + 1:]
	got := netx.resolve_reference(base, ref)
	if len(got) > len(base) + len(ref) + 1 {
		panic("a resolved reference outgrew its inputs")
	}
	scheme, authority, _, ok := netx.split_url(base)
	colon := strings.index_byte(ref, ':')
	has_scheme := colon >= 0 && netx.is_scheme(ref[:colon])
	if ok && !has_scheme && !strings.has_prefix(ref, "//") {
		if !strings.has_prefix(got, strings.concatenate({scheme, "://", authority})) {
			panic("a relative reference moved the authority")
		}
		g_scheme, g_authority, _, g_ok := netx.split_url(got)
		if !g_ok || g_scheme != scheme || g_authority != authority {
			panic("a relative reference split to another authority")
		}
	}
	return 0
}
