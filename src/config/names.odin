package config

import "core:strings"

/*
The name a server or list goes by when the file gives it none: its url up to the
query. A query can carry a key or a per-user profile, and the name is what the
log shows and what every `upstream` label on /metrics carries; RFC 9110 17.9 has
a target logged and displayed where third parties see it. The fragment is never
sent at all (RFC 3986 3.5). The authority ends before either (RFC 3986 3.2), and
a url with userinfo is refused at load, so what is left is scheme, host, port and
path.
*/
url_name :: proc(url: string) -> string {
	if i := strings.index_any(url, "?#"); i >= 0 {
		return url[:i]
	}
	return url
}

/*
The file a downloaded list is cached under in `blocking.cache_dir`: its name,
which holds no query unless the file gave one. A query changed in the file is
told apart by the fingerprint the server keeps beside the copy, not by the
file name, which is logged.
*/
list_cache_file :: proc(bl: Block_List, allocator := context.temp_allocator) -> string {
	return list_cache_name(bl.name, allocator)
}

// A name as a file name: `_` for anything but ASCII letters, digits, `-`, `_` and `.`.
list_cache_name :: proc(name: string, allocator := context.temp_allocator) -> string {
	b := strings.builder_make(allocator)
	for i in 0 ..< len(name) {
		c := name[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '-', c == '_', c == '.':
			strings.write_byte(&b, c)
		case:
			strings.write_byte(&b, '_')
		}
	}
	strings.write_string(&b, ".list")
	return strings.to_string(b)
}

/*
A default name stops at the url's query, so two DoH servers whose urls differ
only there would come to share one: they would sum into one series on /metrics
and read as one in the log, with nothing in the file to tell them apart. That is
refused, as is a name the file gives that is another server's url up to its
query, and the same for a fragment, which is cut too. Every other shared name is
one the file spells itself, and is allowed: one url listed twice or pinned to two
addresses, two DoT servers on one address, a name the file gives to several
servers. Those sum by the operator's own spelling of the file.
*/
@(private)
check_default_upstream_names :: proc(l: ^Loader, cfg: ^Config) {
	all := make([dynamic]Upstream_Spec, context.temp_allocator)
	append(&all, ..cfg.upstream.servers)
	for route in cfg.upstream.zones {
		append(&all, ..route.upstream.servers)
	}
	// Each server against every one before it of its name: "one url" holds
	// only between https servers, so the first of a name cannot stand for all.
	for s, i in all {
		for prev in all[:i] {
			if prev.name != s.name {
				continue
			}
			// One url, the fragment aside: a given name can equal the cut url of
			// a server on another host, so the path alone does not tell.
			one_url := prev.kind == .HTTPS && s.kind == .HTTPS && url_sent(prev.url) == url_sent(s.url)
			if !one_url && (cut_a_query(prev) || cut_a_query(s)) {
				errorf(l, "upstream: two different servers both go by %q, a url cut at its query or fragment; give one a 'name:' (in the map form of a server)", s.name)
				break
			}
		}
	}

	// A default name shorter than the url it came from: a query or a fragment
	// was cut. A name the file gives is its own, whatever it spells.
	cut_a_query :: proc(s: Upstream_Spec) -> bool {
		return s.kind == .HTTPS && !s.named && s.name != s.url
	}
}

// What of a url is sent: all of it up to the fragment (RFC 3986 3.5).
url_sent :: proc(url: string) -> string {
	return strings.truncate_to_byte(url, '#')
}

/*
A downloaded list is cached under its name, so two lists with different urls
that come to one cache file - one name, or two names that differ only where the
file name cannot hold them - would read each other's copy whenever a download
fails. Refused at load, by the name that would be shared. A disabled list, or
any list while blocking is off, is never downloaded, nor is one with a `file:`,
which is read in place of its url. Two entries for one url are one list, the
fragment aside, which is never sent.
*/
@(private)
check_list_cache_names :: proc(l: ^Loader, cfg: ^Config) {
	if !cfg.blocking.enabled {
		return
	}
	seen := make(map[string]Block_List, context.temp_allocator)
	for lists in ([][]Block_List{cfg.blocking.lists, cfg.blocking.allow_lists}) {
		for bl in lists {
			if bl.url == "" || bl.file != "" || !bl.enabled {
				continue
			}
			file := list_cache_file(bl)
			prev, found := seen[file]
			if !found {
				seen[file] = bl
			} else if url_sent(prev.url) != url_sent(bl.url) {
				errorf(l, "blocking: the lists named %q and %q would share the cache file %s; give one a different 'name:'", prev.name, bl.name, file)
			}
		}
	}
}
