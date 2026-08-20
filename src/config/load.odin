package config

import "core:fmt"
import "core:mem"
import "core:net"
import "core:os"
import "core:strings"
import "core:time"
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
	}
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

@(private)
load_upstream :: proc(l: ^Loader, cfg: ^Config) {
	n := yaml.get(l.root, "upstream")
	if n == nil {
		return
	}
	if s, ok := yaml.as_string(yaml.get(n, "strategy")); ok {
		switch strings.to_lower(s, l.allocator) {
		case "failover", "first":
			cfg.upstream.strategy = .Failover
		case "round_robin", "round-robin", "rr":
			cfg.upstream.strategy = .Round_Robin
		case "race", "fastest", "prefer_first_answer":
			cfg.upstream.strategy = .Race
		case:
			errorf(l, "upstream.strategy: unknown strategy %q (want failover, round_robin or race)", s)
		}
	}
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

	servers := yaml.items(yaml.get(n, "servers"))
	if len(servers) == 0 {
		return
	}
	out := make([dynamic]Upstream_Spec, 0, len(servers), l.allocator)
	for sn, i in servers {
		spec, ok := load_upstream_spec(l, sn, i, cfg.upstream.bootstrap)
		if ok {
			append(&out, spec)
		}
	}
	cfg.upstream.servers = out[:]
}

@(private)
load_upstream_spec :: proc(
	l: ^Loader,
	n: ^yaml.Node,
	index: int,
	default_bootstrap: []string,
) -> (
	spec: Upstream_Spec,
	ok: bool,
) {
	path := fmt.tprintf("upstream.servers[%d]", index)
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
		out := make([]string, len(list), l.allocator)
		kept := 0
		for entry, i in list {
			domain := canonical_domain(entry, l.allocator)

			/*
			`rewrites` further down does take a `*.` prefix, so an operator who
			has written one there writes one here too, and `canonical_domain`
			keeps the star. This list has no use for one - an entry already
			covers everything below itself - so `*.corp.example.` would sit in
			it matching nothing any client can ask for, and the symptom of that
			is every internal name still answering NODATA after the fix was
			applied, with no line anywhere saying why. That is the one failure
			this setting exists to prevent, so the star is named here instead of
			at three in the morning.

			`zone` is what the entry meant; a bare `*` leaves nothing of it and
			is the root, which the next check refuses for what it is.
			*/
			wildcard := strings.has_prefix(domain, "*.")
			zone := domain
			if wildcard {
				zone = domain[2:]
				if zone == "" {
					zone = "."
				}
			}

			/*
			The root would exempt every name there is, which is `rebind.enabled:
			false` written in a way nothing about the file makes obvious. Refused
			rather than obeyed, on the same reasoning that `allow_from:` with no
			value is refused: the two readings are a setting and its opposite.
			*/
			if zone == "." {
				errorf(
					l,
					"rebind.allow_domains[%d]: %q exempts every name; set rebind.enabled to false if that is what you mean",
					i,
					entry,
				)
				continue
			}
			/*
			Named rather than quietly stripped: `*.corp.example` means "below"
			in the section that does take it and this list means "at or below",
			so obeying it would widen an exemption past what was written.
			*/
			if wildcard {
				errorf(
					l,
					"rebind.allow_domains[%d]: %q takes no wildcard; write %q, which already covers everything below it",
					i,
					entry,
					strings.trim_suffix(zone, "."),
				)
				continue
			}
			/*
			An empty label - a leading dot, or two of them in a row - is the
			other way to write an entry that matches nothing, and
			`.corp.example` is a form operators arrive with because `no_proxy`
			takes it and means by it what this list writes plain. Kept as
			written it would sit in the configuration looking like the fix while
			every internal name went on answering NODATA, which is the failure
			the wildcard check above exists to prevent; refused for the same
			reason.
			*/
			if strings.has_prefix(zone, ".") || strings.contains(zone, "..") {
				errorf(
					l,
					"rebind.allow_domains[%d]: %q has an empty label; write the zone as a plain name, such as corp.example",
					i,
					entry,
				)
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

	for e, i in entries {
		path := fmt.tprintf("rewrites[%d]", i)
		rw := Rewrite {
			ttl = 300,
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

		if strings.has_prefix(domain, "*.") {
			rw.wildcard = true
			domain = domain[2:]
		}
		rw.domain = canonical_domain(domain, l.allocator)

		answers_node := yaml.get(e, "answer")
		if answers_node == nil {
			answers_node = yaml.get(e, "answers")
		}
		raw, ok := yaml.as_string_list(answers_node, l.allocator)
		if !ok || len(raw) == 0 {
			errorf(l, "%s: missing answer", path)
			continue
		}

		answers := make([dynamic]Rewrite_Answer, 0, len(raw), l.allocator)
		for a in raw {
			switch {
			case a == "block", a == "deny":
				append(&answers, Rewrite_Answer{kind = .Block})
			case:
				addr := net.parse_address(a)
				switch v in addr {
				case net.IP4_Address:
					append(&answers, Rewrite_Answer{kind = .A, v4 = cast([4]u8)v})
				case net.IP6_Address:
					ans := Rewrite_Answer {
						kind = .AAAA,
					}
					for group, gi in v {
						x := u16(group)
						ans.v6[gi * 2] = u8(x >> 8)
						ans.v6[gi * 2 + 1] = u8(x)
					}
					append(&answers, ans)
				case:
					append(&answers, Rewrite_Answer{kind = .CNAME, name = canonical_domain(a, l.allocator)})
				}
			}
		}
		rw.answers = answers[:]
		append(&out, rw)
	}
	cfg.rewrites = out[:]
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

	for spec in cfg.upstream.servers {
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
	if cfg.server.rate_limit.enabled {
		if cfg.server.rate_limit.responses_per_second < 1 {
			errorf(l, "server.rate_limit.responses_per_second must be at least 1")
		}
		if cfg.server.rate_limit.slip < 0 {
			errorf(l, "server.rate_limit.slip must not be negative")
		}
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
	Same shape of mistake: `local` and `test` add two names to a table that is
	not consulted at all with `special_use.enabled` off, so the pair reads as a
	leak that was stopped and is not.

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
	}
}
