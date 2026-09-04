package config

import "core:fmt"
import "core:mem"
import "core:net"
import "core:os"
import "core:strings"
import "core:time"
import "elodin:dns"
import "elodin:dnssec"
import "elodin:yaml"

Load_Error :: struct {
	messages: []string,
}

@(private)
Loader :: struct {
	root:      ^yaml.Node,
	errors:    [dynamic]string,
	allocator: mem.Allocator,
}

@(private)
errorf :: proc(l: ^Loader, format: string, args: ..any) {
	append(&l.errors, fmt.aprintf(format, ..args, allocator = l.allocator))
}

load_file :: proc(path: string, allocator := context.allocator) -> (cfg: Config, err: Maybe(Load_Error)) {
	data, read_err := os.read_entire_file(path, allocator)
	if read_err != nil {
		msgs := make([]string, 1, allocator)
		msgs[0] = fmt.aprintf("cannot read config file %q: %v", path, read_err, allocator = allocator)
		return {}, Load_Error{msgs}
	}
	return load_string(string(data), allocator)
}

load_string :: proc(src: string, allocator := context.allocator) -> (cfg: Config, err: Maybe(Load_Error)) {
	root, perr := yaml.parse(src, allocator)
	if e, has := perr.?; has {
		msgs := make([]string, 1, allocator)
		msgs[0] = fmt.aprintf("line %d: %s", e.line, e.msg, allocator = allocator)
		return {}, Load_Error{msgs}
	}

	l := Loader {
		root      = root,
		errors    = make([dynamic]string, 0, 4, allocator),
		allocator = allocator,
	}
	cfg = default_config()

	load_log(&l, &cfg)
	load_server(&l, &cfg)
	load_listeners(&l, &cfg)
	load_upstream(&l, &cfg)
	load_cache(&l, &cfg)
	load_blocking(&l, &cfg)
	load_dnssec(&l, &cfg)
	load_cookies(&l, &cfg)
	load_rebind(&l, &cfg)
	load_special_use(&l, &cfg)
	load_metrics(&l, &cfg)
	load_rewrites(&l, &cfg)
	validate(&l, &cfg)

	if len(l.errors) > 0 {
		return cfg, Load_Error{l.errors[:]}
	}
	delete(l.errors)
	return cfg, nil
}

@(private)
opt_string :: proc(l: ^Loader, n: ^yaml.Node, key: string, dst: ^string, path: string) {
	child := yaml.get(n, key)
	if yaml.is_null(child) {
		return
	}
	if v, ok := yaml.as_string(child); ok {
		dst^ = v
	} else {
		errorf(l, "%s.%s: expected a string", path, key)
	}
}

@(private)
opt_bool :: proc(l: ^Loader, n: ^yaml.Node, key: string, dst: ^bool, path: string) {
	child := yaml.get(n, key)
	if yaml.is_null(child) {
		return
	}
	if v, ok := yaml.as_bool(child); ok {
		dst^ = v
	} else {
		errorf(l, "%s.%s: expected true or false", path, key)
	}
}

@(private)
opt_int :: proc(l: ^Loader, n: ^yaml.Node, key: string, dst: ^int, path: string) {
	child := yaml.get(n, key)
	if yaml.is_null(child) {
		return
	}
	if v, ok := yaml.as_int(child); ok {
		dst^ = int(v)
	} else {
		errorf(l, "%s.%s: expected an integer", path, key)
	}
}

@(private)
opt_u32 :: proc(l: ^Loader, n: ^yaml.Node, key: string, dst: ^u32, path: string) {
	child := yaml.get(n, key)
	if yaml.is_null(child) {
		return
	}
	// Accept both a bare number of seconds and a duration such as "5m".
	if d, ok := yaml.as_duration(child); ok {
		secs := i64(d / time.Second)
		if secs < 0 || secs > i64(max(u32)) {
			errorf(l, "%s.%s: value out of range", path, key)
			return
		}
		dst^ = u32(secs)
		return
	}
	errorf(l, "%s.%s: expected a duration or a number of seconds", path, key)
}

@(private)
opt_bytes :: proc(l: ^Loader, n: ^yaml.Node, key: string, dst: ^int, path: string) {
	child := yaml.get(n, key)
	if yaml.is_null(child) {
		return
	}
	// Accept both a plain count of bytes and a suffixed size such as "64MiB".
	v, ok := yaml.as_bytes(child)
	if !ok {
		errorf(l, "%s.%s: expected a size such as 64MiB, or a number of bytes", path, key)
		return
	}
	if v > i64(max(int)) {
		errorf(l, "%s.%s: size out of range", path, key)
		return
	}
	dst^ = int(v)
}

@(private)
opt_duration :: proc(l: ^Loader, n: ^yaml.Node, key: string, dst: ^time.Duration, path: string) {
	child := yaml.get(n, key)
	if yaml.is_null(child) {
		return
	}
	if v, ok := yaml.as_duration(child); ok {
		dst^ = v
	} else {
		errorf(l, "%s.%s: expected a duration such as 30s, 5m or 24h", path, key)
	}
}

@(private)
load_log :: proc(l: ^Loader, cfg: ^Config) {
	n := yaml.get(l.root, "log")
	if n == nil {
		return
	}
	if s, ok := yaml.as_string(yaml.get(n, "level")); ok {
		switch strings.to_lower(s, l.allocator) {
		case "debug":
			cfg.log.level = .Debug
		case "info":
			cfg.log.level = .Info
		case "warn", "warning":
			cfg.log.level = .Warn
		case "error":
			cfg.log.level = .Error
		case:
			errorf(l, "log.level: unknown level %q (want debug, info, warn or error)", s)
		}
	}
	opt_bool(l, n, "queries", &cfg.log.queries, "log")
	opt_string(l, n, "file", &cfg.log.file, "log")
}

@(private)
load_server :: proc(l: ^Loader, cfg: ^Config) {
	n := yaml.get(l.root, "server")
	if n == nil {
		return
	}
	opt_int(l, n, "workers", &cfg.server.workers, "server")
	opt_int(l, n, "upstream_workers", &cfg.server.upstream_workers, "server")
	opt_int(l, n, "max_connections", &cfg.server.max_connections, "server")
	opt_int(l, n, "max_connections_per_prefix", &cfg.server.max_connections_per_prefix, "server")
	opt_int(l, n, "max_pending", &cfg.server.max_pending, "server")
	// A size, so "1232" and "1232B" and "4KiB" all read, the same as the cache
	// sizes do.
	opt_bytes(l, n, "max_udp_response", &cfg.server.max_udp_response, "server")
	opt_duration(l, n, "client_timeout", &cfg.server.client_timeout, "server")
	opt_string(l, n, "user", &cfg.server.user, "server")
	opt_string(l, n, "group", &cfg.server.group, "server")
	load_allow_from(l, n, cfg)

	if rl := yaml.get(n, "rate_limit"); rl != nil {
		opt_bool(l, rl, "enabled", &cfg.server.rate_limit.enabled, "server.rate_limit")
		opt_int(l, rl, "responses_per_second", &cfg.server.rate_limit.responses_per_second, "server.rate_limit")
		opt_int(l, rl, "slip", &cfg.server.rate_limit.slip, "server.rate_limit")
		load_rate_limit_overrides(l, rl, cfg)
	}
}

/*
The most specific network a rate-limit override may name, by family.

The budgets are accounted per /24 and per /64, so an entry finer than that could
only ever be applied to the whole prefix containing it. See
`Rate_Limit_Override`.
*/
@(private)
OVERRIDE_MAX_BITS_V4 :: 24

@(private)
OVERRIDE_MAX_BITS_V6 :: 64

/*
Read `server.rate_limit.overrides` into the networks it names.

Parsed at load, with the parser `allow_from` uses, so a network that will not
parse fails `--check` rather than coming up as a server quietly applying the
default to a prefix the operator thought they had configured. The figures are
checked here too: the loader is the only thing that sees an entry beside the line
it was written on, and a limiter built out of a bad figure has nothing left to
complain with.

An entry that names no `slip` carries -1 out of here, and `validate` fills it in
from the top-level figure once that is known to be final. Reading it during this
pass would inherit whatever had been parsed so far, which depends on the order
the keys happen to appear in the file.
*/
@(private)
load_rate_limit_overrides :: proc(l: ^Loader, rl: ^yaml.Node, cfg: ^Config) {
	child := yaml.get(rl, "overrides")
	if child == nil {
		return
	}
	if yaml.is_null(child) {
		errorf(
			l,
			"server.rate_limit.overrides: expected a list of networks with figures of their own, such as [{prefix: 198.51.100.0/24, responses_per_second: 5000}]; it has no value",
		)
		return
	}
	entries := yaml.items(child)
	if len(entries) == 0 {
		return
	}
	if len(entries) > MAX_RATE_LIMIT_OVERRIDES {
		errorf(
			l,
			"server.rate_limit.overrides names %d networks, which is more than the %d the limiter can account for; this setting is for the handful of prefixes whose meaning of \"a client\" differs from the rest",
			len(entries),
			MAX_RATE_LIMIT_OVERRIDES,
		)
		return
	}
	out := make([dynamic]Rate_Limit_Override, 0, len(entries), l.allocator)

	for e, i in entries {
		path := fmt.tprintf("server.rate_limit.overrides[%d]", i)
		text := ""
		opt_string(l, e, "prefix", &text, path)
		if text == "" {
			errorf(l, "%s: missing prefix, which is the network this entry is about", path)
			continue
		}
		p, pok := parse_prefix(text)
		if !pok {
			errorf(l, "%s: %q is not a network in CIDR form such as 198.51.100.0/24 or 2001:db8::/32", path, text)
			continue
		}
		/*
		Finer than the accounting is refused rather than quietly widened.

		Every address in a /24 shares one bucket, so a /28 entry could only be
		applied to the /24 around it - sixteen times the network the operator
		named. The error says what to write instead, because the fix is
		mechanical and the mistake is an easy one to make: somebody thinking
		about one client reaches for /32.
		*/
		limit := u8(OVERRIDE_MAX_BITS_V6) if p.v6 else u8(OVERRIDE_MAX_BITS_V4)
		if p.bits > limit {
			errorf(
				l,
				"%s: %q is finer than the /%d these budgets are accounted per, so it could only ever be applied to the whole /%d around it; name that network instead",
				path,
				text,
				limit,
				limit,
			)
			continue
		}
		/*
		The same network twice is refused. `prefix_match` takes the most specific
		entry, so two of equal length would leave the figure decided by the order
		they happen to be written in - which is the one thing that procedure's
		contract promises does not decide anything.
		*/
		duplicate := false
		for existing in out {
			if existing.prefix == p {
				errorf(l, "%s: %q already has figures of its own from an earlier entry", path, text)
				duplicate = true
				break
			}
		}
		if duplicate {
			continue
		}

		// -1 is "the entry did not say", which `validate` fills in. 0 is a value
		// `slip` can be given on purpose, so it cannot stand for absence.
		o := Rate_Limit_Override {
			prefix = p,
			slip   = -1,
		}
		opt_int(l, e, "responses_per_second", &o.responses_per_second, path)
		opt_int(l, e, "slip", &o.slip, path)
		if o.responses_per_second == 0 {
			errorf(
				l,
				"%s: missing responses_per_second; an entry with no figure of its own is the default, which is what leaving the network out already means",
				path,
			)
			continue
		}
		append(&out, o)
	}
	cfg.server.rate_limit.overrides = out[:]
}

/*
Read `server.allow_from` into the prefixes it names.

Parsed at load rather than at startup, and with the parser the listeners
themselves use, so a network that will not parse fails `--check` instead of
coming up as a resolver that refuses every client. An entry that is absent
leaves the default list alone; an entry that is present and empty is an
operator asking for a public resolver, which is a different thing and is taken
as one.
*/
@(private)
load_allow_from :: proc(l: ^Loader, n: ^yaml.Node, cfg: ^Config) {
	child := yaml.get(n, "allow_from")
	if child == nil {
		return
	}
	/*
	Present with nothing after it is refused rather than guessed at.

	`allow_from:` on its own reads as null, and the two things it could have
	meant - "serve everybody" and "I started writing this and stopped" - are the
	shipped default and its exact opposite. `[]` says the first unambiguously
	and is two characters away, so there is nothing to be gained by picking one
	on the operator's behalf and an open resolver to be lost by picking wrong.
	*/
	if yaml.is_null(child) {
		errorf(
			l,
			"server.allow_from: expected a list of networks such as [192.168.0.0/16], or [] for no restriction at all; it has no value",
		)
		return
	}
	list, ok := yaml.as_string_list(child, l.allocator)
	if !ok {
		errorf(l, "server.allow_from: expected a list of networks in CIDR form, such as [192.168.0.0/16]")
		return
	}

	out := make([]Prefix, len(list), l.allocator)
	kept := 0
	for entry, i in list {
		p, pok := parse_prefix(entry)
		if !pok {
			errorf(
				l,
				"server.allow_from[%d]: %q is not a network in CIDR form such as 192.168.0.0/16 or ::1/128",
				i,
				entry,
			)
			continue
		}
		out[kept] = p
		kept += 1
	}
	cfg.server.allow_from = out[:kept]
}

@(private)
load_listener :: proc(l: ^Loader, parent: ^yaml.Node, key: string, dst: ^Listener, needs_tls: bool) {
	n := yaml.get(parent, key)
	if n == nil {
		return
	}
	path := fmt.tprintf("listeners.%s", key)
	opt_bool(l, n, "enabled", &dst.enabled, path)
	opt_string(l, n, "address", &dst.address, path)
	opt_int(l, n, "port", &dst.port, path)
	if needs_tls {
		opt_string(l, n, "cert_file", &dst.cert_file, path)
		opt_string(l, n, "key_file", &dst.key_file, path)
	}
	if key == "udp" {
		opt_int(l, n, "readers", &dst.readers, path)
		// A size, so "1MiB" and "1048576" both read, the same as the cache
		// sizes and `server.max_udp_response` do.
		opt_bytes(l, n, "receive_buffer", &dst.receive_buffer, path)
	}
	if key == "doh" {
		opt_string(l, n, "path", &dst.path, path)
		opt_string(l, n, "mobileconfig_path", &dst.mobileconfig_path, path)
	}
}

@(private)
load_listeners :: proc(l: ^Loader, cfg: ^Config) {
	n := yaml.get(l.root, "listeners")
	if n == nil {
		return
	}
	load_listener(l, n, "udp", &cfg.listeners.udp, false)
	load_listener(l, n, "tcp", &cfg.listeners.tcp, false)
	load_listener(l, n, "dot", &cfg.listeners.dot, true)
	load_listener(l, n, "doh", &cfg.listeners.doh, true)
}

// `strategy`, wherever it appears: once for `upstream` itself and once for every
// route under `upstream.zones`, which chooses between its own servers the same
// way the default group chooses between its.
@(private)
load_strategy :: proc(l: ^Loader, n: ^yaml.Node, dst: ^Strategy, path: string) {
	s, ok := yaml.as_string(yaml.get(n, "strategy"))
	if !ok {
		return
	}
	switch strings.to_lower(s, l.allocator) {
	case "failover", "first":
		dst^ = .Failover
	case "round_robin", "round-robin", "rr":
		dst^ = .Round_Robin
	case "race", "fastest", "prefer_first_answer":
		dst^ = .Race
	case:
		errorf(l, "%s.strategy: unknown strategy %q (want failover, round_robin or race)", path, s)
	}
}

@(private)
load_upstream :: proc(l: ^Loader, cfg: ^Config) {
	n := yaml.get(l.root, "upstream")
	if n == nil {
		return
	}
	load_strategy(l, n, &cfg.upstream.strategy, "upstream")
	opt_duration(l, n, "timeout", &cfg.upstream.timeout, "upstream")
	opt_int(l, n, "attempts", &cfg.upstream.attempts, "upstream")
	opt_int(l, n, "max_idle", &cfg.upstream.max_idle, "upstream")
	opt_duration(l, n, "idle_timeout", &cfg.upstream.idle_timeout, "upstream")

	if b := yaml.get(n, "bootstrap"); !yaml.is_null(b) {
		if list, ok := yaml.as_string_list(b, l.allocator); ok {
			cfg.upstream.bootstrap = list
		} else {
			errorf(l, "upstream.bootstrap: expected a list of addresses")
		}
	}

	if servers := yaml.items(yaml.get(n, "servers")); len(servers) > 0 {
		out := make([dynamic]Upstream_Spec, 0, len(servers), l.allocator)
		for sn, i in servers {
			spec, ok := load_upstream_spec(l, sn, fmt.tprintf("upstream.servers[%d]", i), cfg.upstream.bootstrap)
			if ok {
				append(&out, spec)
			}
		}
		cfg.upstream.servers = out[:]
	}

	load_upstream_zones(l, cfg, n)
}

/*
Read `upstream.zones`: the per-domain routes.

Each entry is a whole upstream configuration in its own right - its own
servers, and its own strategy, timeout, attempts and connection reuse - so it
begins as a copy of the defaults read above and overrides whatever it names.
`bootstrap` is inherited along with the rest: a route that names a DoT server
by hostname needs one exactly as the default group does, and an operator who
wrote one at the top of the section meant it for the file.

Two fields are dropped from that copy rather than inherited. `servers` is the
one thing a route has to state for itself, and inheriting it would turn a route
that forgot to name any into one silently pointing at the public upstream -
which is the leak the route was written to stop. `zones` is dropped because
routes do not nest; a `zones` key inside a route is refused below rather than
read and ignored.

Read after `servers` so the section can be written in either order and mean the
same thing, and so a route inherits the timeout an operator set beside it
rather than the built-in default.
*/
@(private)
load_upstream_zones :: proc(l: ^Loader, cfg: ^Config, n: ^yaml.Node) {
	zn := yaml.get(n, "zones")
	if yaml.is_null(zn) {
		return
	}
	// On the node's own kind rather than on whether `items` came back empty: an
	// explicit `zones: []` is a list with nothing in it, which is a file saying
	// there are no routes, and a mapping written where a list belongs is a
	// mistake. The two must not produce the same answer.
	if zn.kind != .Sequence {
		errorf(l, "upstream.zones: expected a list of routes, each with domains and servers")
		return
	}
	entries := yaml.items(zn)

	routes := make([dynamic]Zone_Route, 0, len(entries), l.allocator)
	/*
	Which route claimed a domain first. Two routes naming the same zone is not
	a longest-match question - they are the same length - so the answer would
	be whichever the file happened to list first, and the other would sit there
	looking configured while nothing ever reached it. Refused by name instead.
	*/
	claimed := make(map[string]int, l.allocator)
	defer delete(claimed)

	for entry, i in entries {
		path := fmt.tprintf("upstream.zones[%d]", i)
		if entry == nil || entry.kind != .Mapping {
			errorf(l, "%s: expected a mapping with domains and servers", path)
			continue
		}
		if !yaml.is_null(yaml.get(entry, "zones")) {
			errorf(l, "%s.zones: routes do not nest; write another entry in upstream.zones instead", path)
			continue
		}

		route: Zone_Route
		route.upstream = cfg.upstream
		route.upstream.servers = nil
		route.upstream.zones = nil

		load_strategy(l, entry, &route.upstream.strategy, path)
		opt_duration(l, entry, "timeout", &route.upstream.timeout, path)
		opt_int(l, entry, "attempts", &route.upstream.attempts, path)
		opt_int(l, entry, "max_idle", &route.upstream.max_idle, path)
		opt_duration(l, entry, "idle_timeout", &route.upstream.idle_timeout, path)
		if b := yaml.get(entry, "bootstrap"); !yaml.is_null(b) {
			if list, ok := yaml.as_string_list(b, l.allocator); ok {
				route.upstream.bootstrap = list
			} else {
				errorf(l, "%s.bootstrap: expected a list of addresses", path)
			}
		}

		route.domains = load_route_domains(l, entry, path, i, &claimed)

		if servers := yaml.items(yaml.get(entry, "servers")); len(servers) > 0 {
			out := make([dynamic]Upstream_Spec, 0, len(servers), l.allocator)
			for sn, j in servers {
				spec, ok := load_upstream_spec(
					l,
					sn,
					fmt.tprintf("%s.servers[%d]", path, j),
					route.upstream.bootstrap,
				)
				if ok {
					append(&out, spec)
				}
			}
			route.upstream.servers = out[:]
		}

		append(&routes, route)
	}
	cfg.upstream.zones = routes[:]
}

/*
One entry of a zone list, canonicalised and held to the three refusals.

`rebind.allow_domains` and every `upstream.zones[].domains` take a list of the
same thing - a plain zone name, covering itself and everything below it - and
refuse the same three ways of writing one that matches nothing a client can ask
for. An operator arrives with `*.corp.example` from the `rewrites` section, or
`.corp.example` from `no_proxy`, or with the root; kept as written, each would
sit in the file looking like the fix while nothing about the deployment changed.

The failures the two lists are guarding are different - there an exemption that
never fires and every internal name still answering NODATA, here a zone that
goes on being resolved by the public upstream - and the root is the one refusal
whose wording has to say which, so it comes in as `root_reason`. The other two
name only the entry and what to write instead, which is the same sentence
either way. `path` is the list without its index: `rebind.allow_domains`, or
`upstream.zones[0].domains`.
*/
@(private)
canonical_zone_entry :: proc(
	l: ^Loader,
	written: string,
	path: string,
	index: int,
	root_reason: string,
) -> (
	domain: string,
	ok: bool,
) {
	domain = canonical_domain(written, l.allocator)

	/*
	`rewrites` further down does take a `*.` prefix, so an operator who has
	written one there writes one here too, and `canonical_domain` keeps the
	star. Neither of these lists has a use for one - an entry already covers
	everything below itself - so `*.corp.example.` would sit in it matching
	nothing any client can ask for, with no line anywhere saying why.

	`zone` is what the entry meant; a bare `*` leaves nothing of it and is the
	root, which the next check refuses for what it is.
	*/
	wildcard := strings.has_prefix(domain, "*.")
	zone := domain
	if wildcard {
		zone = domain[2:]
		if zone == "" {
			zone = "."
		}
	}

	// The root is always the whole setting written in a way nothing about the
	// file admits to, and there is always a plainer way to say that; what it is
	// differs per list, so the caller says.
	if zone == "." {
		errorf(l, "%s[%d]: %q %s", path, index, written, root_reason)
		return "", false
	}
	/*
	Named rather than quietly stripped: `*.corp.example` means "below" in the
	section that does take it and these lists mean "at or below", so obeying it
	would widen what was written past what it says.
	*/
	if wildcard {
		errorf(
			l,
			"%s[%d]: %q takes no wildcard; write %q, which already covers everything below it",
			path,
			index,
			written,
			strings.trim_suffix(zone, "."),
		)
		return "", false
	}
	/*
	An empty label - a leading dot, or two of them in a row - is the other way to
	write an entry that matches nothing, and `.corp.example` is a form operators
	arrive with because `no_proxy` takes it and means by it what these lists
	write plain.
	*/
	if strings.has_prefix(zone, ".") || strings.contains(zone, "..") {
		errorf(
			l,
			"%s[%d]: %q has an empty label; write the zone as a plain name, such as corp.example",
			path,
			index,
			written,
		)
		return "", false
	}
	return domain, true
}

/*
The `domains` of one route, canonicalised and checked.

The three refusals are `canonical_zone_entry`'s, shared with
`rebind.allow_domains`; the fourth is this list's own, since two routes claiming
one zone is not a question the other list can be asked.
*/
@(private)
load_route_domains :: proc(
	l: ^Loader,
	entry: ^yaml.Node,
	path: string,
	index: int,
	claimed: ^map[string]int,
) -> []string {
	d := yaml.get(entry, "domains")
	if yaml.is_null(d) {
		errorf(l, "%s.domains: a route has to say which names it takes, such as [corp.example]", path)
		return nil
	}
	list, ok := yaml.as_string_list(d, l.allocator)
	if !ok {
		errorf(l, "%s.domains: expected a list of domains, such as [corp.example]", path)
		return nil
	}
	if len(list) == 0 {
		errorf(l, "%s.domains: a route has to say which names it takes, such as [corp.example]", path)
		return nil
	}

	// The root would route every name there is, which is `upstream.servers`
	// written in a way nothing about the file makes obvious - and it would take
	// the DNSSEC bypass and the rebinding exemption a route implies with it,
	// across the whole name space.
	ROOT :: "routes every name; put those servers in upstream.servers if that is what you mean"

	domains_path := fmt.tprintf("%s.domains", path)
	out := make([]string, len(list), l.allocator)
	kept := 0
	for written, j in list {
		domain, good := canonical_zone_entry(l, written, domains_path, j, ROOT)
		if !good {
			continue
		}
		if first, seen := claimed[domain]; seen {
			// Two spellings of one zone in one route - `corp.example` and
			// `CORP.example.` - is the same refusal, but "already routed by
			// upstream.zones[0]" read while looking at upstream.zones[0] names
			// the entry as its own culprit, which sends an operator looking for
			// a second route that is not there.
			if first == index {
				errorf(
					l,
					"%s[%d]: %q is already listed in this route; one zone goes in one place",
					domains_path,
					j,
					written,
				)
			} else {
				errorf(
					l,
					"%s[%d]: %q is already routed by upstream.zones[%d]; one zone goes to one place",
					domains_path,
					j,
					written,
					first,
				)
			}
			continue
		}
		claimed[domain] = index

		out[kept] = domain
		kept += 1
	}
	return out[:kept]
}

/*
Whether `name` is `zone` or sits under it, both already canonical.

The resolver's own `name_at_or_below` folds case because the names reaching it
are whatever the client spelled. Nothing here is: both sides have been through
`canonical_domain` or are written lowercase in this file, so the comparison is
bytes and the fold would only hide a name that failed to be canonicalised.
*/
@(private)
domain_at_or_below :: proc(name, zone: string) -> bool {
	if len(name) < len(zone) {
		return false
	}
	if len(name) == len(zone) {
		return name == zone
	}
	// The zone has to begin right after a label break, or it is a bare string
	// suffix of some other name rather than a subtree of it.
	if name[len(name) - len(zone) - 1] != '.' {
		return false
	}
	return name[len(name) - len(zone):] == zone
}

/*
A route into a zone the special-use table already answers never fires.

`special_use_zone` runs in `resolve_query` before anything is forwarded, so a
name inside an enabled entry is answered from the table and the route below it
is never consulted. Written together they are the exact mistake the rest of this
section is shaped against: a route sitting in the file looking like the fix
while the names it claims go on being answered somewhere else - and the one that
costs the most is `home.arpa`, since an operator who turned the key on to stop
the leak and then added the route to send the names to their router keeps the
key's NXDOMAIN and never sees the router.

Refused by name, the way `special_use.local` without `special_use.enabled` is,
rather than left to be discovered from the outside.

`resolver.arpa.` is the same refusal with no key attached, and so is checked
first and outside the guard below. See `server.is_resolver_arpa`.
*/
@(private)
check_route_reachable :: proc(l: ^Loader, cfg: ^Config, route: Zone_Route) {
	/*
	The DDR zone, which no configuration can bring within reach of a route.

	`is_resolver_arpa` runs in `resolve_query` ahead of the special-use table
	and ahead of everything that forwards, and no key turns it off - RFC 9462
	has the resolver answer for its own designation rather than fetch somebody
	else's. So a route here is the same trap as one under an enabled key, minus
	the key: there is nothing to turn off, and nothing to say about the route
	but that it will never fire.
	*/
	for domain in route.domains {
		if domain_at_or_below(domain, "resolver.arpa.") {
			errorf(
				l,
				"upstream.zones: the route for %s would never be used: this server answers resolver.arpa. itself, for DDR (RFC 9462), before a query is forwarded",
				domain,
			)
		}
	}

	if !cfg.special_use.enabled {
		return
	}
	Shadow :: struct {
		zone:   string,
		on:     bool,
		reason: string,
	}
	/*
	A copy of `server.special_use_zone`'s own list, and it has to stay one.

	This package cannot import `server` - `server` imports this one - so the
	zones are written out again here rather than read from the single place that
	decides them. A key added there and not here does not break anything loudly:
	it leaves a route under the new zone loading cleanly and then never firing,
	which is the exact failure this check exists to catch. Add the entry in both.

	`localhost.` and `invalid.` have no key of their own: with the table on at
	all they are answered there, which is what RFC 6761 asks for.
	*/
	table := [?]Shadow {
		{"localhost.", true, "special_use.enabled answers localhost. here (RFC 6761)"},
		{"invalid.", true, "special_use.enabled answers invalid. here (RFC 6761)"},
		{"onion.", cfg.special_use.onion, "special_use.onion answers onion. here"},
		{"local.", cfg.special_use.local, "special_use.local answers local. here"},
		{"test.", cfg.special_use.test, "special_use.test answers test. here"},
		{"home.arpa.", cfg.special_use.home_arpa, "special_use.home_arpa answers home.arpa. here"},
	}
	for domain in route.domains {
		for entry in table {
			if !entry.on || !domain_at_or_below(domain, entry.zone) {
				continue
			}
			errorf(
				l,
				"upstream.zones: the route for %s would never be used: %s, before a query is forwarded; turn that key off to route the zone instead",
				domain,
				entry.reason,
			)
		}
	}
}

/*
Whether every name a route claims is already covered by a trust anchor.

A route serves its zone insecure by default, and that is the first of the two
things `--check` says a route gives up - but `covered_by_local_anchor` in the
server stands the bypass down for a name an anchor covers, so a site that signed
its own zone and anchored it gives up no validation at all by routing it. Saying
otherwise would be the warning being wrong at exactly the configuration that was
most careful, which is worse than not printing it.

Every domain rather than any: the warning is one line about the whole route, and
a route claiming an anchored zone alongside an unanchored one still serves the
second insecure.

The root anchor does not count, which is `start_validator` leaving it out of
`anchor_zones`: it covers every name and can validate none of the zones the
bypass exists for. Neither does an anchor that will not parse - `validate`
refuses the file over one of those, so no operator ever sees what this answered
for such a file.

Read by `main` for the `--check` line and nothing else, so the parse is scratch:
the anchors it builds are thrown at the temporary allocator rather than freed
one by one, the caller's own line being built there too.
*/
route_is_anchored :: proc(cfg: ^Config, route: Zone_Route) -> bool {
	if !cfg.dnssec.enabled || len(cfg.dnssec.trust_anchors) == 0 || len(route.domains) == 0 {
		return false
	}
	for domain in route.domains {
		covered := false
		for line in cfg.dnssec.trust_anchors {
			anchor, ok := dnssec.parse_trust_anchor(line, context.temp_allocator)
			if !ok || anchor.zone == "." {
				continue
			}
			// Both sides canonical: `canonical_domain` made the route's, and
			// `parse_trust_anchor` runs the anchor's through
			// `dns.name_canonical`.
			if domain_at_or_below(domain, anchor.zone) {
				covered = true
				break
			}
		}
		if !covered {
			return false
		}
	}
	return true
}

@(private)
load_upstream_spec :: proc(
	l: ^Loader,
	n: ^yaml.Node,
	path: string,
	default_bootstrap: []string,
) -> (
	spec: Upstream_Spec,
	ok: bool,
) {
	spec.verify = true
	spec.bootstrap = default_bootstrap

	// A bare string entry is shorthand: "1.1.1.1", "tls://1.1.1.1:853#name",
	// "https://dns.google/dns-query".
	if n != nil && n.kind == .Scalar {
		s, sok := yaml.as_string(n)
		if !sok {
			errorf(l, "%s: expected a server definition", path)
			return {}, false
		}
		return parse_upstream_shorthand(l, s, path, default_bootstrap)
	}

	opt_string(l, n, "name", &spec.name, path)
	opt_string(l, n, "address", &spec.address, path)
	opt_string(l, n, "hostname", &spec.hostname, path)
	opt_string(l, n, "url", &spec.url, path)
	opt_int(l, n, "port", &spec.port, path)
	opt_bool(l, n, "verify", &spec.verify, path)
	if b := yaml.get(n, "bootstrap"); !yaml.is_null(b) {
		if list, lok := yaml.as_string_list(b, l.allocator); lok {
			spec.bootstrap = list
		} else {
			errorf(l, "%s.bootstrap: expected a list of addresses", path)
		}
	}

	kind_str, has_kind := yaml.as_string(yaml.get(n, "type"))
	if has_kind {
		switch strings.to_lower(kind_str, l.allocator) {
		case "udp", "plain", "dns":
			spec.kind = .UDP
		case "tcp":
			spec.kind = .TCP
		case "tls", "dot", "dns-over-tls":
			spec.kind = .TLS
		case "https", "doh", "dns-over-https":
			spec.kind = .HTTPS
		case:
			errorf(l, "%s.type: unknown type %q (want udp, tcp, tls or https)", path, kind_str)
			return {}, false
		}
	} else if spec.url != "" {
		spec.kind = .HTTPS
	} else {
		spec.kind = .UDP
	}

	if spec.kind == .HTTPS {
		if spec.url == "" {
			errorf(l, "%s: an https upstream needs a url", path)
			return {}, false
		}
		scheme, host, url_path, _, _ := net.split_url(spec.url, l.allocator)
		if scheme != "https" {
			errorf(l, "%s.url: expected an https:// url", path)
			return {}, false
		}
		host_only, url_port, split_ok := net.split_port(host)
		if !split_ok {
			errorf(l, "%s.url: cannot parse host %q", path, host)
			return {}, false
		}
		if spec.hostname == "" {
			spec.hostname = host_only
		}
		if spec.address == "" {
			spec.address = host_only
		}
		if spec.port == 0 {
			spec.port = url_port if url_port != 0 else 443
		}
		spec.path = url_path if url_path != "" else "/dns-query"
	} else {
		if spec.address == "" {
			errorf(l, "%s: missing address", path)
			return {}, false
		}
		if spec.port == 0 {
			spec.port = 853 if spec.kind == .TLS else 53
		}
		if spec.hostname == "" && net.parse_address(spec.address) == nil {
			spec.hostname = spec.address
		}
	}

	if !check_verify_has_a_name(l, spec, path) {
		return {}, false
	}
	if spec.name == "" {
		spec.name = describe_upstream(spec, l.allocator)
	}
	return spec, true
}

/*
An upstream that verifies certificates has to say which name to verify.

Checking a certificate is checking the chain *and* the name; with no name it is
the chain alone, which accepts anything a trusted CA has ever signed for anyone.
An address written as an IP literal leaves nothing to fall back on, so this is
refused at load rather than at the first query — an operator who meant to pin a
name gets told, and one who meant not to check says so with `verify: false`.
*/
@(private)
check_verify_has_a_name :: proc(l: ^Loader, spec: Upstream_Spec, path: string) -> bool {
	if spec.kind != .TLS && spec.kind != .HTTPS {
		return true
	}
	if !spec.verify || spec.hostname != "" {
		return true
	}
	errorf(
		l,
		"%s: verify is on but there is no hostname to check the certificate against; " +
		"add '#name' after the address, set 'hostname:', or set 'verify: false'",
		path,
	)
	return false
}

// "1.1.1.1", "8.8.8.8:53", "tcp://9.9.9.9", "tls://1.1.1.1:853#cloudflare-dns.com",
// "https://dns.google/dns-query".
@(private)
parse_upstream_shorthand :: proc(
	l: ^Loader,
	raw: string,
	path: string,
	default_bootstrap: []string,
) -> (
	spec: Upstream_Spec,
	ok: bool,
) {
	spec.verify = true
	spec.bootstrap = default_bootstrap
	s := strings.trim_space(raw)

	if strings.has_prefix(s, "https://") {
		spec.kind = .HTTPS
		spec.url = s
		scheme, host, url_path, _, _ := net.split_url(s, l.allocator)
		_ = scheme
		host_only, url_port, split_ok := net.split_port(host)
		if !split_ok {
			errorf(l, "%s: cannot parse %q", path, raw)
			return {}, false
		}
		spec.address = host_only
		spec.hostname = host_only
		spec.port = url_port if url_port != 0 else 443
		spec.path = url_path if url_path != "" else "/dns-query"
		spec.name = s
		return spec, true
	}

	spec.kind = .UDP
	Scheme :: struct {
		prefix: string,
		kind:   Upstream_Kind,
	}
	for sch in ([]Scheme{{"udp://", .UDP}, {"tcp://", .TCP}, {"tls://", .TLS}}) {
		if strings.has_prefix(s, sch.prefix) {
			spec.kind = sch.kind
			s = s[len(sch.prefix):]
			break
		}
	}

	// A trailing #hostname pins the certificate name for DoT.
	if idx := strings.index_byte(s, '#'); idx >= 0 {
		spec.hostname = s[idx + 1:]
		s = s[:idx]
	}

	host, port, split_ok := net.split_port(s)
	if !split_ok {
		errorf(l, "%s: cannot parse %q", path, raw)
		return {}, false
	}
	spec.address = host
	spec.port = port if port != 0 else (853 if spec.kind == .TLS else 53)
	if spec.hostname == "" && net.parse_address(host) == nil {
		spec.hostname = host
	}
	if !check_verify_has_a_name(l, spec, path) {
		return {}, false
	}
	spec.name = describe_upstream(spec, l.allocator)
	return spec, true
}

describe_upstream :: proc(spec: Upstream_Spec, allocator := context.allocator) -> string {
	if spec.kind == .HTTPS {
		return strings.clone(spec.url, allocator)
	}
	scheme := "udp"
	switch spec.kind {
	case .UDP:
		scheme = "udp"
	case .TCP:
		scheme = "tcp"
	case .TLS:
		scheme = "tls"
	case .HTTPS:
		scheme = "https"
	}
	return fmt.aprintf("%s://%s:%d", scheme, spec.address, spec.port, allocator = allocator)
}

@(private)
load_cache :: proc(l: ^Loader, cfg: ^Config) {
	n := yaml.get(l.root, "cache")
	if n == nil {
		return
	}
	opt_bool(l, n, "enabled", &cfg.cache.enabled, "cache")
	opt_int(l, n, "max_entries", &cfg.cache.max_entries, "cache")
	opt_bytes(l, n, "max_bytes", &cfg.cache.max_bytes, "cache")
	opt_u32(l, n, "min_ttl", &cfg.cache.min_ttl, "cache")
	opt_u32(l, n, "max_ttl", &cfg.cache.max_ttl, "cache")
	opt_u32(l, n, "negative_ttl", &cfg.cache.negative_ttl, "cache")
	opt_bool(l, n, "serve_stale", &cfg.cache.serve_stale, "cache")
}

@(private)
parse_v4 :: proc(l: ^Loader, s: string, path: string, dst: ^[4]u8) {
	addr := net.parse_address(s)
	if v4, is_v4 := addr.(net.IP4_Address); is_v4 {
		dst^ = cast([4]u8)v4
		return
	}
	errorf(l, "%s: %q is not an IPv4 address", path, s)
}

@(private)
parse_v6 :: proc(l: ^Loader, s: string, path: string, dst: ^[16]u8) {
	addr := net.parse_address(s)
	if v6, is_v6 := addr.(net.IP6_Address); is_v6 {
		for group, i in v6 {
			v := u16(group)
			dst[i * 2] = u8(v >> 8)
			dst[i * 2 + 1] = u8(v)
		}
		return
	}
	errorf(l, "%s: %q is not an IPv6 address", path, s)
}

@(private)
load_block_lists :: proc(l: ^Loader, n: ^yaml.Node, path: string) -> []Block_List {
	entries := yaml.items(n)
	if len(entries) == 0 {
		return nil
	}
	out := make([dynamic]Block_List, 0, len(entries), l.allocator)
	for e, i in entries {
		bl := Block_List {
			enabled = true,
		}
		if e != nil && e.kind == .Scalar {
			s, _ := yaml.as_string(e)
			if strings.has_prefix(s, "http://") || strings.has_prefix(s, "https://") {
				bl.url = s
			} else {
				bl.file = s
			}
			bl.name = s
			append(&out, bl)
			continue
		}
		item_path := fmt.tprintf("%s[%d]", path, i)
		opt_string(l, e, "name", &bl.name, item_path)
		opt_string(l, e, "url", &bl.url, item_path)
		opt_string(l, e, "file", &bl.file, item_path)
		opt_bool(l, e, "enabled", &bl.enabled, item_path)
		if f, ok := yaml.as_string(yaml.get(e, "format")); ok {
			switch strings.to_lower(f, l.allocator) {
			case "auto":
				bl.format = .Auto
			case "hosts":
				bl.format = .Hosts
			case "domains", "domain", "plain":
				bl.format = .Domains
			case "adblock", "abp":
				bl.format = .Adblock
			case:
				errorf(l, "%s.format: unknown format %q (want auto, hosts, domains or adblock)", item_path, f)
			}
		}
		if bl.url == "" && bl.file == "" {
			errorf(l, "%s: needs either a url or a file", item_path)
			continue
		}
		if bl.name == "" {
			bl.name = bl.url if bl.url != "" else bl.file
		}
		append(&out, bl)
	}
	return out[:]
}

@(private)
load_blocking :: proc(l: ^Loader, cfg: ^Config) {
	n := yaml.get(l.root, "blocking")
	if n == nil {
		return
	}
	opt_bool(l, n, "enabled", &cfg.blocking.enabled, "blocking")
	opt_u32(l, n, "block_ttl", &cfg.blocking.block_ttl, "blocking")
	opt_duration(l, n, "refresh", &cfg.blocking.refresh, "blocking")
	opt_string(l, n, "cache_dir", &cfg.blocking.cache_dir, "blocking")

	if s, ok := yaml.as_string(yaml.get(n, "response")); ok {
		switch strings.to_lower(s, l.allocator) {
		case "nxdomain", "nx_domain":
			cfg.blocking.response = .NX_Domain
		case "nodata", "no_data", "empty":
			cfg.blocking.response = .No_Data
		case "zeroip", "zero_ip", "null":
			cfg.blocking.response = .Zero_IP
		case "custom", "custom_ip":
			cfg.blocking.response = .Custom_IP
		case "refused":
			cfg.blocking.response = .Refused
		case:
			errorf(l, "blocking.response: unknown mode %q (want nxdomain, nodata, zeroip, custom or refused)", s)
		}
	}
	if s, ok := yaml.as_string(yaml.get(n, "custom_ipv4")); ok {
		parse_v4(l, s, "blocking.custom_ipv4", &cfg.blocking.custom_ipv4)
	}
	if s, ok := yaml.as_string(yaml.get(n, "custom_ipv6")); ok {
		parse_v6(l, s, "blocking.custom_ipv6", &cfg.blocking.custom_ipv6)
	}

	cfg.blocking.lists = load_block_lists(l, yaml.get(n, "lists"), "blocking.lists")
	cfg.blocking.allow_lists = load_block_lists(l, yaml.get(n, "allowlists"), "blocking.allowlists")

	if r := yaml.get(n, "rules"); !yaml.is_null(r) {
		if list, ok := yaml.as_string_list(r, l.allocator); ok {
			cfg.blocking.rules = list
		} else {
			errorf(l, "blocking.rules: expected a list of rules")
		}
	}
	if r := yaml.get(n, "allow"); !yaml.is_null(r) {
		if list, ok := yaml.as_string_list(r, l.allocator); ok {
			cfg.blocking.allow_rules = list
		} else {
			errorf(l, "blocking.allow: expected a list of rules")
		}
	}
}

@(private)
load_dnssec :: proc(l: ^Loader, cfg: ^Config) {
	n := yaml.get(l.root, "dnssec")
	if n == nil {
		return
	}
	opt_bool(l, n, "enabled", &cfg.dnssec.enabled, "dnssec")
	opt_int(l, n, "max_nsec3_iterations", &cfg.dnssec.max_nsec3_iterations, "dnssec")

	if a := yaml.get(n, "trust_anchors"); !yaml.is_null(a) {
		if list, ok := yaml.as_string_list(a, l.allocator); ok {
			cfg.dnssec.trust_anchors = list
		} else {
			errorf(l, "dnssec.trust_anchors: expected a list of DS records")
		}
	}
}

@(private)
load_cookies :: proc(l: ^Loader, cfg: ^Config) {
	n := yaml.get(l.root, "cookies")
	if n == nil {
		return
	}
	opt_bool(l, n, "enabled", &cfg.cookies.enabled, "cookies")
	opt_bool(l, n, "require", &cfg.cookies.require, "cookies")
	opt_bool(l, n, "upstream", &cfg.cookies.upstream, "cookies")
	opt_string(l, n, "secret", &cfg.cookies.secret, "cookies")
}

/*
Read the `rebind` section.

`allow_domains` is canonicalised here, with the same procedure `rewrites` uses,
so the resolver compares two names that were written the same way. An operator
who put a trailing dot on one and not the other gets the same behaviour from
both, which is the sort of difference that is otherwise only found by the name
that would not resolve.
*/
@(private)
load_rebind :: proc(l: ^Loader, cfg: ^Config) {
	n := yaml.get(l.root, "rebind")
	if n == nil {
		return
	}
	opt_bool(l, n, "enabled", &cfg.rebind.enabled, "rebind")
	opt_bool(l, n, "allow_loopback", &cfg.rebind.allow_loopback, "rebind")

	if d := yaml.get(n, "allow_domains"); !yaml.is_null(d) {
		list, ok := yaml.as_string_list(d, l.allocator)
		if !ok {
			errorf(l, "rebind.allow_domains: expected a list of domains, such as [home.example]")
			return
		}
		/*
		The root would exempt every name there is, which is `rebind.enabled:
		false` written in a way nothing about the file makes obvious. Refused
		rather than obeyed, on the same reasoning that `allow_from:` with no
		value is refused: the two readings are a setting and its opposite.
		*/
		ROOT :: "exempts every name; set rebind.enabled to false if that is what you mean"

		out := make([]string, len(list), l.allocator)
		kept := 0
		for entry, i in list {
			// The wildcard and empty-label refusals with it, shared with
			// `upstream.zones[].domains`, which takes the same shape of list
			// against the same mistakes. See `canonical_zone_entry`.
			domain, good := canonical_zone_entry(l, entry, "rebind.allow_domains", i, ROOT)
			if !good {
				continue
			}
			out[kept] = domain
			kept += 1
		}
		cfg.rebind.allow_domains = out[:kept]
	}
}

@(private)
load_special_use :: proc(l: ^Loader, cfg: ^Config) {
	n := yaml.get(l.root, "special_use")
	if n == nil {
		return
	}
	opt_bool(l, n, "enabled", &cfg.special_use.enabled, "special_use")
	opt_bool(l, n, "onion", &cfg.special_use.onion, "special_use")
	opt_bool(l, n, "local", &cfg.special_use.local, "special_use")
	opt_bool(l, n, "test", &cfg.special_use.test, "special_use")
	opt_bool(l, n, "home_arpa", &cfg.special_use.home_arpa, "special_use")
}

@(private)
load_metrics :: proc(l: ^Loader, cfg: ^Config) {
	n := yaml.get(l.root, "metrics")
	if n == nil {
		return
	}
	opt_bool(l, n, "enabled", &cfg.metrics.enabled, "metrics")
	opt_string(l, n, "address", &cfg.metrics.address, "metrics")
	opt_int(l, n, "port", &cfg.metrics.port, "metrics")
	opt_string(l, n, "path", &cfg.metrics.path, "metrics")
}

@(private)
load_rewrites :: proc(l: ^Loader, cfg: ^Config) {
	entries := yaml.items(yaml.get(l.root, "rewrites"))
	if len(entries) == 0 {
		return
	}
	out := make([dynamic]Rewrite, 0, len(entries), l.allocator)

	rules: for e, i in entries {
		path := fmt.tprintf("rewrites[%d]", i)
		rw := Rewrite {
			ttl = 300,
			ptr = true,
		}
		domain := ""
		opt_string(l, e, "domain", &domain, path)
		if domain == "" {
			errorf(l, "%s: missing domain", path)
			continue
		}
		ttl_i := int(rw.ttl)
		opt_int(l, e, "ttl", &ttl_i, path)
		rw.ttl = u32(ttl_i)
		opt_bool(l, e, "ptr", &rw.ptr, path)

		if strings.has_prefix(domain, "*.") {
			rw.wildcard = true
			domain = domain[2:]
		}
		/*
		The name the rule is for, held to the same limits as the names in its
		answers.

		A rule is matched against the question name off the wire, which a
		decoder has already held to those limits - so a domain with a 64-byte
		label in it is a rule no query can ever equal, sitting in a
		configuration that `--check` passed and quietly matching nothing. Same
		outcome the answer-side check exists to prevent, and the same one line
		to prevent it.
		*/
		rw.domain = canonical_domain(domain, l.allocator)
		if !name_fits_the_wire(l, rw.domain, fmt.tprintf("%s.domain", path)) {
			continue
		}

		/*
		Whichever of the two spellings the rule used is the one its errors are
		reported against: being pointed at `answers[0]` by a file that says
		`answer:` is being pointed at a key that is not there.

		Both at once is refused rather than resolved. `answer:` would win and
		`answers:` would be dropped in silence, and with rules that can now hold
		several records the obvious way to add an MX to a rule that already has
		an address is to write the second key underneath the first - which would
		have thrown the MX away and passed `--check` while doing it.
		*/
		answers_node := yaml.get(e, "answer")
		key := "answer"
		if answers_node == nil {
			answers_node = yaml.get(e, "answers")
			key = "answers"
		} else if yaml.get(e, "answers") != nil {
			errorf(
				l,
				"%s: has both `answer` and `answers`; put every record under one of them",
				path,
			)
			continue
		}
		raw, ok := yaml.as_string_list(answers_node, l.allocator)
		if !ok || len(raw) == 0 {
			errorf(l, "%s: missing answer", path)
			continue
		}
		// A single value written as a scalar has no index to name, while a list
		// does however long it is.
		listed := len(yaml.items(answers_node)) > 0

		answers := make([dynamic]Rewrite_Answer, 0, len(raw), l.allocator)
		for a, ai in raw {
			apath := fmt.tprintf("%s.%s", path, key)
			if listed {
				apath = fmt.tprintf("%s.%s[%d]", path, key, ai)
			}
			ans, parsed := parse_rewrite_answer(l, a, apath)
			if !parsed {
				// The whole rule goes, the way every other failure in here
				// treats one. Keeping a rule that lost an answer left the
				// resolver relying on these errors being fatal to `load_string`
				// - true today, and a rule with an empty `answers` reads to the
				// server as a record-only rule with nothing to say, which it
				// would step over in silence.
				continue rules
			}
			append(&answers, ans)
		}
		apath := fmt.tprintf("%s.%s", path, key)
		if !answers_agree(l, answers[:], apath) {
			continue rules
		}
		if !answers_fit_a_message(l, answers[:], apath) {
			continue rules
		}
		rw.answers = answers[:]
		append(&out, rw)
	}
	cfg.rewrites = out[:]
}

/*
Whether one rule's answers can all be true of the same name at once.

A CNAME says that this name is another name, so nothing else may sit beside it:
RFC 2181 section 10.1 states the rule and RFC 1034 section 3.6.2 is where it
comes from, and a resolver that meets a CNAME with an MX or a TXT at the same
owner has met a malformed answer - some stubs take the first record and some
refuse the lot. One CNAME per name for the same reason: two aliases for one name
is not a thing a name can be.

This could not be written before, near enough - a rule was an address, an alias
or the sink - and the list form that could was rare enough to go unnoticed. The
new kinds make a mixed list the natural thing to write, so the check goes in
beside them. `block` is exempt because it is not a record: it says to answer as
though the name were on a list, which `apply_rewrite` does before it looks at
anything else in the rule.
*/
@(private)
answers_agree :: proc(l: ^Loader, answers: []Rewrite_Answer, path: string) -> bool {
	aliases := 0
	records := 0
	for a in answers {
		switch a.kind {
		case .CNAME:
			aliases += 1
		case .A, .AAAA, .MX, .TXT, .SRV:
			records += 1
		case .Block:
		}
	}
	if aliases > 1 {
		errorf(l, "%s: a name can have only one CNAME", path)
		return false
	}
	if aliases == 1 && records > 0 {
		errorf(
			l,
			"%s: a CNAME cannot sit beside other records at the same name (RFC 2181 section 10.1) - it already answers every type, so put the other records on the name it points at",
			path,
		)
		return false
	}
	return true
}

/*
Whether every record a rule holds can be sent in one message.

The per-record limits in `parse_txt_strings` are not the whole of it: a rule
answers with all of its records of the queried type at once, so a rule can be
made of records that each fit and together do not. The encoder does not report
that either - it fills the message, sets the truncated flag and leaves the rest
out - and the ceiling it is filling to is 65535 whether the query arrived over
UDP or TCP, so there is no larger transport for the client to retry on. The
answer is simply short, for as long as the rule stands.

The estimate is deliberately pessimistic. The owner name is the name the client
asked for, which is not known here, so every record is charged the longest one
there can be (255 bytes) plus its ten-byte header; in a real message that name
is written once and pointed at thereafter. A rule that this refuses is a rule
with hundreds of records at one name, which is not an answer any client can use.
*/
@(private)
answers_fit_a_message :: proc(l: ^Loader, answers: []Rewrite_Answer, path: string) -> bool {
	total := 0
	for a in answers {
		rdata := 0
		switch a.kind {
		case .A:
			rdata = 4
		case .AAAA:
			rdata = 16
		case .CNAME, .SRV, .MX:
			// The name, plus a length octet for its first label and the root's
			// zero, and the fixed fields of an MX or an SRV in front of it.
			rdata = len(a.name) + 2 + 6
		case .TXT:
			for s in a.strings {
				rdata += 1 + len(s)
			}
		case .Block:
		}
		total += 255 + 10 + rdata
	}
	if total > MAX_RECORD_RDATA {
		errorf(
			l,
			"%s: these %d records come to about %d bytes, and one answer may be at most %d",
			path,
			len(answers),
			total,
			MAX_RECORD_RDATA,
		)
		return false
	}
	return true
}

/*
One entry of `answer:` / `answers:`, in either of the two forms.

The short form is what the file has always taken and is what most rules are: a
bare address is an A or a AAAA, a bare name is a CNAME, and `block` is the name
sunk as though a list had named it. It stays exactly as it was, spaces and all -
a value this cannot make sense of is a CNAME to whatever was written, which is
how a typo has always been read here.

The long form is a type token and then that type's RDATA, spelled the way a zone
file spells it:

    "A 192.168.1.50"
    "MX 10 mail.example.com"
    "SRV 0 5 5060 sip.example.com"
    'TXT "v=spf1 -all"'

Zone-file syntax rather than a shape of this file's own because the fields are
not this file's to name: an operator reaching for `MX` knows a preference comes
first from RFC 1035, and one reaching for `SRV` knows priority, weight and port
from RFC 2782, and every document they will consult while writing the rule -
their registrar's, their mail provider's, the RFC - prints it in that order. A
`{preference: 10, exchange: ...}` mapping would be this file asking to be
learned separately in order to say the same thing.

The type token has to be followed by something, which is what keeps the two
forms from colliding. `answer: mx` is a CNAME to the host called `mx`, because a
host really can be called that and a bare token cannot be an MX record - it
carries no preference and no exchange. Only `MX <something>` is read as a type.

An answer this cannot parse is an error rather than a fallback. That is the
difference the type token buys and the reason it is worth having: `MX ten
mail.example.com` is a mistake with one reading, and `--check` says so with the
rule and the field named, where the short form has no choice but to accept
whatever it is given.
*/
@(private)
parse_rewrite_answer :: proc(
	l: ^Loader,
	text: string,
	path: string,
) -> (
	ans: Rewrite_Answer,
	ok: bool,
) {
	trimmed := strings.trim_space(text)
	if trimmed == "" {
		errorf(l, "%s: empty answer", path)
		return {}, false
	}
	// Case-folded like the type tokens below, and for the same reason: `Block`
	// read as a name is a CNAME to the host `block`, which is the opposite of
	// what the word was written to ask for.
	if strings.equal_fold(trimmed, "block") || strings.equal_fold(trimmed, "deny") {
		return Rewrite_Answer{kind = .Block}, true
	}

	head, rest, typed := split_first_field(trimmed)
	if typed {
		switch {
		case strings.equal_fold(head, "a"):
			addr, is4 := net.parse_address(rest).(net.IP4_Address)
			if !is4 {
				errorf(l, "%s: A needs an IPv4 address, got %q", path, rest)
				return {}, false
			}
			return Rewrite_Answer{kind = .A, v4 = cast([4]u8)addr}, true

		case strings.equal_fold(head, "aaaa"):
			addr, is6 := net.parse_address(rest).(net.IP6_Address)
			if !is6 {
				errorf(l, "%s: AAAA needs an IPv6 address, got %q", path, rest)
				return {}, false
			}
			return v6_rewrite_answer(addr), true

		case strings.equal_fold(head, "cname"):
			name := rdata_name(l, rest, path, "CNAME") or_return
			return Rewrite_Answer{kind = .CNAME, name = name}, true

		case strings.equal_fold(head, "mx"):
			return parse_mx_answer(l, rest, path)

		case strings.equal_fold(head, "srv"):
			return parse_srv_answer(l, rest, path)

		case strings.equal_fold(head, "txt"):
			strs := parse_txt_strings(l, rest, path) or_return
			return Rewrite_Answer{kind = .TXT, strings = strs}, true
		}

		/*
		Several fields and no type this understands, which is a mistake with no
		second reading.

		The short form below would take it: `PTR nas.home` becomes a CNAME to
		the name `ptr nas.home`, which `encode_name` will put on the wire
		without complaint - it checks lengths, not characters - so every client
		asking for that name is handed an alias to a label with a space in it,
		whatever type it asked for. The type token was added on the promise that
		an answer naming a type and getting it wrong is an error, and this was
		the shape where the promise was still broken.

		Every multi-field answer is caught, not only the RR types this does not
		implement, because a typo is the same mistake as an unsupported type and
		has the same non-reading. No legal short form has ever had a space in it:
		an address does not, `block` does not, and a name that really contains
		one would have to spell it `\032` to mean anything. TXT is the single
		answer whose text may hold spaces, and it says so first.
		*/
		errorf(
			l,
			"%s: %q is not an answer this understands - name a record type first (A, AAAA, CNAME, MX, TXT, SRV), or write one address, one name, or `block`",
			path,
			trimmed,
		)
		return {}, false
	}

	// The short form, unchanged: an address is what it looks like, and anything
	// else is a name to point at.
	switch v in net.parse_address(trimmed) {
	case net.IP4_Address:
		return Rewrite_Answer{kind = .A, v4 = cast([4]u8)v}, true
	case net.IP6_Address:
		return v6_rewrite_answer(v), true
	}
	name := rdata_name(l, trimmed, path, "an answer") or_return
	return Rewrite_Answer{kind = .CNAME, name = name}, true
}

/*
`MX <preference> <exchange>`, RFC 1035 section 3.3.9.

RFC 7505's "null MX" - `MX 0 .` - is a legal and useful thing to write here: it
is how a domain says it accepts no mail at all, and `canonical_domain` holds the
root as ".", which the encoder writes as the single zero byte the RFC asks for.
*/
@(private)
parse_mx_answer :: proc(l: ^Loader, rest, path: string) -> (ans: Rewrite_Answer, ok: bool) {
	fields: [2]string
	if rdata_fields(rest, fields[:]) != 2 {
		errorf(l, "%s: MX takes a preference and a host, as \"MX 10 mail.example.com\"", path)
		return {}, false
	}
	pref, pref_ok := parse_rdata_u16(fields[0])
	if !pref_ok {
		errorf(l, "%s: MX preference %q is not a number from 0 to 65535", path, fields[0])
		return {}, false
	}
	name := rdata_name(l, fields[1], path, "MX") or_return
	return Rewrite_Answer{kind = .MX, preference = pref, name = name}, true
}

/*
`SRV <priority> <weight> <port> <target>`, RFC 2782.

A target of "." is that RFC's way of saying the service is decidedly not
available at this domain, and goes through for the same reason the null MX does.
*/
@(private)
parse_srv_answer :: proc(l: ^Loader, rest, path: string) -> (ans: Rewrite_Answer, ok: bool) {
	fields: [4]string
	if rdata_fields(rest, fields[:]) != 4 {
		errorf(
			l,
			"%s: SRV takes a priority, weight, port and target, as \"SRV 0 5 5060 sip.example.com\"",
			path,
		)
		return {}, false
	}
	names := [3]string{"priority", "weight", "port"}
	numbers: [3]u16
	for i in 0 ..< 3 {
		v, v_ok := parse_rdata_u16(fields[i])
		if !v_ok {
			errorf(l, "%s: SRV %s %q is not a number from 0 to 65535", path, names[i], fields[i])
			return {}, false
		}
		numbers[i] = v
	}
	name := rdata_name(l, fields[3], path, "SRV") or_return
	return Rewrite_Answer {
			kind = .SRV,
			priority = numbers[0],
			weight = numbers[1],
			port = numbers[2],
			name = name,
		},
		true
}

/*
The <character-string>s of a TXT record, quoted as a zone file quotes them.

Unquoted, the whole of the rest is one string, which is what makes the common
case short: `TXT hello` needs no ceremony to say one word. Quoted, it is a
sequence - `TXT "part one" "part two"` - because that is what a TXT record
actually is (RFC 1035 section 3.3.14) and what a long DKIM key has to be written
as. Inside the quotes `\"` is a quote and `\\` a backslash; any other backslash
stands for the character after it, which is the zone-file rule minus the `\DDD`
decimal escapes, and those are left out because nothing an operator pastes from
a provider's console contains one.

255 bytes is the limit on each string, from the length octet that precedes it,
and going over is an error here rather than a truncation later: a DKIM key
silently cut in half is a mail domain that fails to verify with nothing in the
logs to say why. Splitting it for the operator was the alternative, and it would
change what the record says - concatenation is the client's business, and where
the pieces join is the client's business too.
*/
@(private)
parse_txt_strings :: proc(l: ^Loader, rest, path: string) -> (out: []string, ok: bool) {
	if rest == "" {
		errorf(l, "%s: TXT needs some text, as 'TXT \"v=spf1 -all\"'", path)
		return nil, false
	}
	strs := make([dynamic]string, 0, 1, l.allocator)

	if rest[0] != '"' {
		if len(rest) > 255 {
			errorf(l, "%s: TXT string is %d bytes, and each may be at most 255", path, len(rest))
			return nil, false
		}
		append(&strs, strings.clone(rest, l.allocator))
		return strs[:], true
	}

	i := 0
	for i < len(rest) {
		// Whitespace between strings, and nothing else may sit there.
		if rest[i] == ' ' || rest[i] == '\t' {
			i += 1
			continue
		}
		if rest[i] != '"' {
			errorf(l, "%s: TXT has %q outside a quoted string", path, rest[i:])
			return nil, false
		}
		i += 1

		b := strings.builder_make(l.allocator)
		closed := false
		for i < len(rest) {
			c := rest[i]
			if c == '"' {
				i += 1
				closed = true
				break
			}
			if c == '\\' && i + 1 < len(rest) {
				i += 1
				c = rest[i]
			}
			strings.write_byte(&b, c)
			i += 1
		}
		if !closed {
			errorf(l, "%s: TXT has a quoted string that is never closed", path)
			return nil, false
		}
		s := strings.to_string(b)
		if len(s) > 255 {
			errorf(l, "%s: TXT string is %d bytes, and each may be at most 255", path, len(s))
			return nil, false
		}
		append(&strs, s)
	}

	/*
	And the record has to leave room for the message it will be sent in.

	It takes 256 strings to reach even the 16-bit RDLENGTH, so nobody types
	this - but the failure if they did is worse than the one every other check
	here prevents. `encode_message` does not report a record that will not fit:
	it sets the truncated flag and leaves the record out (see `encode.odin`), so
	the client gets TC=1 and an empty answer, retries over TCP where the ceiling
	is the same 65535, and gets the same empty answer for as long as the rule
	stands.

	MAX_RECORD_RDATA is what always fits: 65535 for the whole message, less the
	12-byte header, less a question of the longest name there can be (255 + 4),
	less this record's own header at the same worst-case name (255 + 10). Name
	compression makes that pessimistic by up to a few hundred bytes, which is
	the right direction to be wrong in for a limit nothing legitimate
	approaches.
	*/
	total := 0
	for s in strs {
		total += 1 + len(s)
	}
	if total > MAX_RECORD_RDATA {
		errorf(
			l,
			"%s: TXT record is %d bytes, and one record may be at most %d",
			path,
			total,
			MAX_RECORD_RDATA,
		)
		return nil, false
	}
	return strs[:], true
}

// See `parse_txt_strings`: the largest RDATA that always leaves room for the
// header, the question and the record's own header in a 65535-byte message.
@(private)
MAX_RECORD_RDATA :: dns.MAX_MESSAGE - 12 - (255 + 4) - (255 + 10)

// The bytes of an IPv6 literal, in the order the wire wants them.
@(private)
v6_rewrite_answer :: proc(v: net.IP6_Address) -> (ans: Rewrite_Answer) {
	ans.kind = .AAAA
	for group, gi in v {
		x := u16(group)
		ans.v6[gi * 2] = u8(x >> 8)
		ans.v6[gi * 2 + 1] = u8(x)
	}
	return ans
}

/*
A domain name out of an RDATA field, checked for being one.

`canonical_domain` takes anything at all, so both checks are here. A field with
a space in it is two fields that were meant to be one, and the message says
which record was being written rather than leaving the operator to find it.

The second check is that the wire can carry it, and it is here because of what
happens when it cannot: `encode_message` fails on the record, `apply_rewrite`
gives up and returns no answer, and the query carries on down the pipeline to
the upstream. So a label of 64 bytes, or a name over 255, turns a rule that
`--check` passed into a rule that silently does nothing - and worse than
nothing, since the internal name it was written for now leaves the building and
the public answer comes back. `encode_name` is asked here, at load time, so the
name that cannot be sent is a startup error instead.
*/
@(private)
rdata_name :: proc(l: ^Loader, text, path, type: string) -> (name: string, ok: bool) {
	trimmed := strings.trim_space(text)
	if trimmed == "" || strings.index_any(trimmed, " \t") >= 0 {
		errorf(l, "%s: %s needs one host name, got %q", path, type, text)
		return "", false
	}
	canonical := canonical_domain(trimmed, l.allocator)
	if !name_fits_the_wire(l, canonical, fmt.tprintf("%s: %s host %q", path, type, trimmed)) {
		return "", false
	}
	return canonical, true
}

// Whether `name` is one the wire can carry: 63 bytes to a label, 255 to the
// whole of it, no empty labels, and every escape a real escape. `dns` owns all
// four rules, so it is asked rather than copied.
@(private)
name_fits_the_wire :: proc(l: ^Loader, name: string, what: string) -> bool {
	// A name is at most 255 bytes encoded, so nothing longer fits in here and
	// nothing shorter needs more.
	buf: [256]u8
	if _, err := dns.encode_name(name, buf[:]); err != .None {
		errorf(l, "%s cannot be put on the wire: %v", what, err)
		return false
	}
	return true
}

/*
Splits `s` at the first run of spaces or tabs.

`ok` is false when there is no split to make, which the caller reads as "this is
one token and so cannot be a type followed by its RDATA".
*/
@(private)
split_first_field :: proc(s: string) -> (head, rest: string, ok: bool) {
	i := strings.index_any(s, " \t")
	if i < 0 {
		return s, "", false
	}
	return s[:i], strings.trim_space(s[i:]), true
}

/*
Fills `out` with the whitespace-separated fields of `s` and reports how many
there were, `len(out) + 1` standing for "more than that".

Every caller wants an exact count, so the overflow value only has to be wrong in
a way that fails the comparison, and stopping at that point keeps a rule with a
hundred trailing words from being walked to the end.
*/
@(private)
rdata_fields :: proc(s: string, out: []string) -> int {
	n := 0
	rest := strings.trim_space(s)
	for rest != "" {
		field := rest
		if i := strings.index_any(rest, " \t"); i >= 0 {
			field = rest[:i]
			rest = strings.trim_space(rest[i:])
		} else {
			rest = ""
		}
		if n == len(out) {
			return n + 1
		}
		out[n] = field
		n += 1
	}
	return n
}

/*
A decimal number that fits in the 16 bits an MX preference or an SRV field has.

Deliberately stricter than `strconv`: this is a configuration file, and `0x1f`,
`+5`, `1_000` and a leading space are all shapes that would be accepted
somewhere and mean something else here. A number is digits.

Leading zeros are digits too. `MX 000010` is ten however it is padded, and
refusing it while saying it "is not a number from 0 to 65535" was a message
arguing with itself - the value is in range and the reader is left looking for
the part that is not. The bound is on what the digits come to rather than on how
many there are, which also stops a thousand of them from being counted before
being rejected.

The reverse-name parser next door refuses a padded octet on purpose, and the
two are not in disagreement: `050` there is a second spelling of a *name*, and
one address answering to two names is a thing worth refusing. A preference is a
number, and a number has one value.
*/
@(private)
parse_rdata_u16 :: proc(s: string) -> (v: u16, ok: bool) {
	if len(s) == 0 {
		return 0, false
	}
	n := 0
	for i in 0 ..< len(s) {
		c := s[i]
		if c < '0' || c > '9' {
			return 0, false
		}
		n = n * 10 + int(c - '0')
		if n > 65535 {
			return 0, false
		}
	}
	return u16(n), true
}

// Lowercase with a trailing dot, matching the form the resolver compares against.
canonical_domain :: proc(s: string, allocator := context.allocator) -> string {
	trimmed := strings.trim_space(s)
	trimmed = strings.trim_suffix(trimmed, ".")
	lowered := strings.to_lower(trimmed, allocator)
	if lowered == "" {
		return strings.clone(".", allocator)
	}
	return strings.concatenate({lowered, "."}, allocator)
}

@(private)
validate :: proc(l: ^Loader, cfg: ^Config) {
	if len(cfg.upstream.servers) == 0 {
		errorf(l, "upstream.servers: at least one upstream server is required")
	}
	any_listener :=
		cfg.listeners.udp.enabled ||
		cfg.listeners.tcp.enabled ||
		cfg.listeners.dot.enabled ||
		cfg.listeners.doh.enabled
	if !any_listener {
		errorf(l, "listeners: every listener is disabled, so nothing would be served")
	}

	check_tls :: proc(l: ^Loader, ln: Listener, name: string) {
		if !ln.enabled {
			return
		}
		if ln.cert_file == "" || ln.key_file == "" {
			errorf(l, "listeners.%s: cert_file and key_file are required", name)
			return
		}
		if !os.exists(ln.cert_file) {
			errorf(l, "listeners.%s.cert_file: %q does not exist", name, ln.cert_file)
		}
		if !os.exists(ln.key_file) {
			errorf(l, "listeners.%s.key_file: %q does not exist", name, ln.key_file)
		}
	}
	check_tls(l, cfg.listeners.dot, "dot")
	check_tls(l, cfg.listeners.doh, "doh")

	if cfg.listeners.doh.enabled && !strings.has_prefix(cfg.listeners.doh.path, "/") {
		errorf(l, "listeners.doh.path: must start with '/'")
	}
	// The profile endpoint shares the DoH listener, so it has to be a path of its
	// own: absolute, and not the one that answers queries — a request cannot be
	// both a DNS message and a download of the profile that points at it.
	if cfg.listeners.doh.enabled && cfg.listeners.doh.mobileconfig_path != "" {
		if !strings.has_prefix(cfg.listeners.doh.mobileconfig_path, "/") {
			errorf(l, "listeners.doh.mobileconfig_path: must start with '/'")
		}
		if cfg.listeners.doh.mobileconfig_path == cfg.listeners.doh.path {
			errorf(l, "listeners.doh.mobileconfig_path: must not be the same as listeners.doh.path")
		}
	}

	if cfg.metrics.enabled {
		if !strings.has_prefix(cfg.metrics.path, "/") {
			errorf(l, "metrics.path: must start with '/'")
		}
		// Port 0 binds and works, on whichever port the kernel picked - which
		// nothing can be told to scrape. Refused here rather than left as an
		// endpoint that comes up and is never reached.
		if cfg.metrics.port < 1 || cfg.metrics.port > 65535 {
			errorf(l, "metrics.port: must be between 1 and 65535")
		}
		if net.parse_address(cfg.metrics.address) == nil {
			errorf(l, "metrics.address: %q is not an IP address", cfg.metrics.address)
		}
	}

	check_bootstrap :: proc(l: ^Loader, specs: []Upstream_Spec) {
		for spec in specs {
			needs_resolution := spec.hostname != "" && net.parse_address(spec.address) == nil
			if needs_resolution && len(spec.bootstrap) == 0 {
				errorf(
					l,
					"upstream server %q uses hostname %q but no bootstrap resolver is configured",
					spec.name,
					spec.hostname,
				)
			}
		}
	}
	check_bootstrap(l, cfg.upstream.servers)

	/*
	Each route held to what the default group is held to: servers it can
	actually reach, and an attempt count that lets it try.

	A route with no usable server is worse than no route at all. The name it
	claims would fall through to nothing - `make_group` refuses an empty group -
	so it has to be caught here, where the file can be pointed at, rather than
	at startup where it reads as "no usable upstream servers" about a resolver
	whose default upstream is fine.
	*/
	/*
	Named by their zone rather than by their index. An entry the loader refused
	outright - a route that is not a mapping, or one with a `zones` key of its
	own - is never appended, so the position of a route in this slice is not its
	position in the file once anything ahead of it has gone wrong, and an index
	that points at the wrong route is worse than no index at all.
	*/
	for route in cfg.upstream.zones {
		if len(route.domains) == 0 {
			// Already reported by the loader, which refused every domain it was
			// given; a second line saying the route is empty adds nothing.
			continue
		}
		if len(route.upstream.servers) == 0 {
			errorf(l, "upstream.zones: the route for %s needs at least one server", route.domains[0])
		}
		// Only where the route is the one that said so. `attempts` is inherited,
		// so `upstream.attempts: 0` would otherwise name every route in the file
		// for a number none of them wrote, beside the one line about the key
		// that did - and an operator fixing the routes would find the error
		// still there.
		if route.upstream.attempts < 1 && cfg.upstream.attempts >= 1 {
			errorf(l, "upstream.zones: the route for %s needs attempts of at least 1", route.domains[0])
		}
		check_bootstrap(l, route.upstream.servers)
		check_route_reachable(l, cfg, route)
	}

	// Only when there is a cache to size. A setting left over in a file that
	// switched caching off should not be what stops the server starting.
	if cfg.cache.enabled {
		if cfg.cache.max_entries < 1 {
			errorf(l, "cache.max_entries must be at least 1")
		}
		// A cache too small to hold one maximal answer would refuse every large
		// one while still answering, which is a cache that has quietly stopped
		// working on the records that most want caching.
		if cfg.cache.max_bytes < MIN_CACHE_BYTES {
			errorf(l, "cache.max_bytes must be at least %d bytes", MIN_CACHE_BYTES)
		}
	}
	if cfg.cache.max_ttl < cfg.cache.min_ttl {
		errorf(l, "cache.max_ttl must not be smaller than cache.min_ttl")
	}
	if cfg.server.workers < 0 {
		errorf(l, "server.workers must not be negative")
	}
	if cfg.server.upstream_workers < 0 {
		errorf(l, "server.upstream_workers must not be negative")
	}
	/*
	Sized before `max_pending` is derived, since that is a multiple of the
	worker count and would otherwise be derived from a zero.

	Done here rather than at startup so that `--check` and the run that follows
	it agree by construction, and so an operator can see on the machine itself
	what the file leaves unsaid.

	The machine is measured only when `workers` is the number that needs it. A
	racer count derived from a configured `workers` owes nothing to the CPUs or
	the RAM, and reporting a machine it never consulted would tell an operator
	their own number came from the hardware.
	*/
	if cfg.server.workers == 0 {
		cfg.server.sizing.machine = probe_machine()
		cfg.server.workers = derive_workers(cfg.server.sizing.machine)
		cfg.server.sizing.derived_workers = true
	}
	if cfg.server.upstream_workers == 0 {
		cfg.server.upstream_workers = derive_upstream_workers(cfg.server.workers)
		cfg.server.sizing.derived_upstream_workers = true
	}
	/*
	The UDP readers, sized the same way and reported the same way.

	Refused rather than clamped, for the reason `max_udp_response` is: the
	number decides how much traffic this server can hear at all, so a file
	naming one it will not get is a file whose author should be told rather
	than quietly given something else. Checked whether or not UDP is enabled -
	a mistyped figure under a listener that is off is still a mistake, and one
	that would surface only when somebody turned the listener on.

	Derived only when it is going to be used, and it measures the machine only
	if the worker derivation above has not already: a probe whose answer nothing
	reads would show up in the sizing line as a machine that was consulted about
	numbers an operator wrote themselves.
	*/
	if cfg.listeners.udp.readers < 0 {
		errorf(l, "listeners.udp.readers must not be negative")
	}
	if cfg.listeners.udp.readers > MAX_UDP_READERS {
		errorf(
			l,
			"listeners.udp.readers must be at most %d (it is %d); 0 derives one per usable CPU, to %d",
			MAX_UDP_READERS,
			cfg.listeners.udp.readers,
			MAX_DERIVED_UDP_READERS,
		)
	}
	if cfg.listeners.udp.receive_buffer < MIN_UDP_RECEIVE_BUFFER ||
	   cfg.listeners.udp.receive_buffer > MAX_UDP_RECEIVE_BUFFER {
		errorf(
			l,
			"listeners.udp.receive_buffer must be between %d and %d bytes (it is %d); %d is the default",
			MIN_UDP_RECEIVE_BUFFER,
			MAX_UDP_RECEIVE_BUFFER,
			cfg.listeners.udp.receive_buffer,
			DEFAULT_UDP_RECEIVE_BUFFER,
		)
	}
	if cfg.listeners.udp.enabled && cfg.listeners.udp.readers == 0 {
		if !cfg.server.sizing.derived_workers {
			cfg.server.sizing.machine = probe_machine()
		}
		cfg.listeners.udp.readers = derive_udp_readers(cfg.server.sizing.machine)
		cfg.server.sizing.derived_udp_readers = true
	}
	if cfg.server.rate_limit.enabled {
		if cfg.server.rate_limit.responses_per_second < 1 {
			errorf(l, "server.rate_limit.responses_per_second must be at least 1")
		}
		if cfg.server.rate_limit.slip < 0 {
			errorf(l, "server.rate_limit.slip must not be negative")
		}
		/*
		The overrides' own figures, held to the same rules as the defaults they
		replace, and the inherited `slip` filled in here.

		Here rather than in the loader because the top-level figures are only
		final once the whole `rate_limit` map has been read: an entry written
		above `slip:` in the same file would otherwise inherit the value from
		before it was parsed.
		*/
		for &o in cfg.server.rate_limit.overrides {
			label := format_prefix(o.prefix, context.temp_allocator)
			if o.responses_per_second < 1 {
				errorf(l, "server.rate_limit.overrides: %s: responses_per_second must be at least 1", label)
			}
			if o.slip < 0 {
				// Not "must not be negative": -1 is this loader's own marker for
				// an entry that said nothing, so a negative figure an operator
				// actually wrote is the only way to get here with one.
				if o.slip < -1 {
					errorf(l, "server.rate_limit.overrides: %s: slip must not be negative", label)
				}
				o.slip = cfg.server.rate_limit.slip
			}
		}
	} else if len(cfg.server.rate_limit.overrides) > 0 {
		/*
		Overrides with the limiter off are refused rather than ignored.

		Every one of them is an operator saying what a named network's budget
		should be, and with `enabled: false` there is no budget at all - so
		accepting the pair silently would be this server agreeing to a
		configuration it does not implement. The two readings ("I meant to turn
		it on" and "these are notes for later") are far enough apart to be worth
		asking about.
		*/
		errorf(
			l,
			"server.rate_limit.overrides names %d network(s), but server.rate_limit.enabled is false, so there are no budgets to override",
			len(cfg.server.rate_limit.overrides),
		)
	}
	if cfg.server.max_pending < 0 {
		errorf(l, "server.max_pending must not be negative")
	}
	// Refused rather than clamped: this number is an amplification factor, and
	// a resolver that quietly served 4096 to somebody who wrote 8192 would be
	// one whose ceiling is not what its file says.
	if cfg.server.max_udp_response < MIN_UDP_RESPONSE || cfg.server.max_udp_response > MAX_UDP_RESPONSE {
		errorf(
			l,
			"server.max_udp_response must be between %d and %d bytes (it is %d); %d is the default",
			MIN_UDP_RESPONSE,
			MAX_UDP_RESPONSE,
			cfg.server.max_udp_response,
			DEFAULT_MAX_UDP_RESPONSE,
		)
	}
	if cfg.server.max_pending == 0 {
		cfg.server.max_pending = cfg.server.workers * 8
	}
	/*
	The table itself, refused rather than clamped.

	`conn_manager_init` reads anything below one as one connection, so a server
	configured with zero came up serving a single client and said "at most 0 at
	once" on the startup line and in `elodin_connections_max` - a figure that
	described neither the file nor the running server. It is also the number the
	share below is derived from and reported against, so a nonsense table makes
	a nonsense share: at or below zero the derivation and the clamp both land on
	one, which then reads as "any one client prefix may hold all of them".
	*/
	if cfg.server.max_connections < 1 {
		errorf(
			l,
			"server.max_connections must be at least 1 (it is %d); 512 is the default",
			cfg.server.max_connections,
		)
	}
	if cfg.server.max_connections_per_prefix < 0 {
		errorf(l, "server.max_connections_per_prefix must not be negative")
	}
	/*
	One client's share of the connection table, worked out here for the reason
	`max_pending` is: `--check` and the run that follows it then agree by
	construction, and a figure nobody wrote in the file is one an operator can
	still read off the server.

	Half of the table, and never more than the table. Half is what leaves the
	other half for everybody else, which is the whole property the cap exists
	for. At or above `max_connections` there is no cap left to apply - the total
	is reached first, from wherever the connections came - and storing that as
	the table's own size is what makes it inert without `conn_spawn` needing a
	special case for it. The `max(..., 1)` guards keep the arithmetic sane for a
	table the check above has already refused: the load fails, but validation
	runs to the end first and the figures it prints on the way have to mean
	something.
	*/
	if cfg.server.max_connections_per_prefix == 0 {
		cfg.server.max_connections_per_prefix = max(cfg.server.max_connections / 2, 1)
	}
	cfg.server.max_connections_per_prefix = min(
		cfg.server.max_connections_per_prefix,
		max(cfg.server.max_connections, 1),
	)
	// A group on its own would read as a privilege drop that was configured,
	// and nothing at all is what it would do.
	if cfg.server.group != "" && cfg.server.user == "" {
		errorf(l, "server.group is set without server.user, so no privileges would be dropped")
	}
	if cfg.upstream.attempts < 1 {
		errorf(l, "upstream.attempts must be at least 1")
	}

	if cfg.dnssec.max_nsec3_iterations < 0 {
		errorf(l, "dnssec.max_nsec3_iterations must not be negative")
	}
	// Parsed here rather than at startup so `--check` reports a bad anchor
	// instead of a resolver that comes up refusing every name.
	for anchor, i in cfg.dnssec.trust_anchors {
		if _, ok := dnssec.parse_trust_anchor(anchor, l.allocator); !ok {
			errorf(l, "dnssec.trust_anchors[%d]: %q is not a DS record", i, anchor)
		}
	}

	// Same reasoning: a secret that will not parse should fail `--check`, not
	// leave a machine handing out cookies its neighbours reject. Read with the
	// parser the server itself uses, so the two cannot disagree.
	if cfg.cookies.secret != "" {
		scratch: [COOKIE_SECRET_LEN]u8
		if !parse_cookie_secret(cfg.cookies.secret, &scratch) {
			errorf(l, "cookies.secret must be %d hexadecimal characters", COOKIE_SECRET_LEN * 2)
		}
	}
	/*
	`require` is enforced against cookies this server issues, and it issues none
	with `enabled` off - so the pair is a setting that quietly does nothing.

	Worth an error rather than a warning: it is turned on while an attack is
	under way, and finding out then that it was never in force is the wrong time.
	*/
	if cfg.cookies.require && !cfg.cookies.enabled {
		errorf(l, "cookies.require needs cookies.enabled: there are no cookies to demand with it off")
	}

	/*
	Same shape of mistake: `local`, `test` and `home_arpa` add names to a table
	that is not consulted at all with `special_use.enabled` off, so the pair
	reads as a leak that was stopped and is not.

	`home_arpa` is the one where that reading does the most damage, since
	stopping a leak is the whole of what it is for: an operator who wrote it
	down under `enabled: false` believes their home network's names are staying
	on the network, and they are being forwarded.

	`onion` is in the same position and cannot be caught here. It defaults on,
	so `enabled: false` with it left alone is not a contradiction anybody wrote
	- it is the ordinary way to turn the table off, and erroring on it would
	make that unsayable.
	*/
	if !cfg.special_use.enabled {
		if cfg.special_use.local {
			errorf(l, "special_use.local needs special_use.enabled: nothing consults the table with it off")
		}
		if cfg.special_use.test {
			errorf(l, "special_use.test needs special_use.enabled: nothing consults the table with it off")
		}
		if cfg.special_use.home_arpa {
			errorf(
				l,
				"special_use.home_arpa needs special_use.enabled: nothing consults the table with it off, so home.arpa is still forwarded",
			)
		}
	}
}
