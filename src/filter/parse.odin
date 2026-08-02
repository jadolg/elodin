package filter

import "core:strings"

Format :: enum u8 {
	Auto,
	Hosts,
	Domains,
	Adblock,
}

// Entries a hosts-format blocklist carries for its own housekeeping.
@(private)
LOCALHOST_NAMES := []string {
	"localhost",
	"localhost.localdomain",
	"local",
	"broadcasthost",
	"ip6-localhost",
	"ip6-loopback",
	"ip6-localnet",
	"ip6-mcastprefix",
	"ip6-allnodes",
	"ip6-allrouters",
	"ip6-allhosts",
	"0.0.0.0",
}

@(private)
is_housekeeping_name :: proc(s: string) -> bool {
	for n in LOCALHOST_NAMES {
		if strings.equal_fold(s, n) {
			return true
		}
	}
	return false
}

/*
Guess a list's format from its first meaningful lines.

Adblock syntax is unmistakable (`[Adblock`, `!` comments, `||` anchors). A hosts
file is recognised by lines whose first field is an IP address. Anything else is
treated as a bare domain list.
*/
detect_format :: proc(text: string) -> Format {
	inspected := 0
	hosts_like := 0
	rest := text

	for inspected < 50 {
		line: string
		idx := strings.index_byte(rest, '\n')
		if idx < 0 {
			line = rest
			rest = ""
		} else {
			line = rest[:idx]
			rest = rest[idx + 1:]
		}
		trimmed := strings.trim_space(line)

		if strings.has_prefix(trimmed, "[Adblock") || strings.has_prefix(trimmed, "!") {
			return .Adblock
		}
		if strings.contains(trimmed, "||") || strings.has_prefix(trimmed, "@@") {
			return .Adblock
		}
		if strings.has_prefix(trimmed, "address=/") || strings.has_prefix(trimmed, "server=/") {
			return .Adblock
		}
		if trimmed == "" || trimmed[0] == '#' {
			if idx < 0 {
				break
			}
			continue
		}

		inspected += 1
		if first_field_is_ip(trimmed) {
			hosts_like += 1
		}
		if idx < 0 {
			break
		}
	}

	if inspected > 0 && hosts_like * 2 > inspected {
		return .Hosts
	}
	return .Domains
}

@(private)
first_field_is_ip :: proc(line: string) -> bool {
	field := line
	if idx := strings.index_any(line, " \t"); idx >= 0 {
		field = line[:idx]
	} else {
		return false
	}
	if strings.contains(field, ":") {
		return true
	}
	dots := 0
	for i in 0 ..< len(field) {
		c := field[i]
		switch {
		case c == '.':
			dots += 1
		case c >= '0' && c <= '9':
		case:
			return false
		}
	}
	return dots == 3
}

@(private)
strip_line_comment :: proc(line: string) -> string {
	for i in 0 ..< len(line) {
		if line[i] == '#' || line[i] == '!' {
			return line[:i]
		}
	}
	return line
}

/*
Parse `text` into `block` and `allow`, returning how many rules were added.

Unparseable lines are skipped rather than failing the whole list: public
blocklists routinely contain syntax that only a full ad blocker understands, and
dropping the entire file over one such line would be worse than ignoring it.
*/
parse_list :: proc(block, allow: ^Set, text: string, format: Format) -> (added: int) {
	fmt_ := format
	if fmt_ == .Auto {
		fmt_ = detect_format(text)
	}

	rest := text
	for len(rest) > 0 {
		line: string
		if idx := strings.index_byte(rest, '\n'); idx >= 0 {
			line = rest[:idx]
			rest = rest[idx + 1:]
		} else {
			line = rest
			rest = ""
		}
		line = strings.trim_right(line, "\r \t")

		switch fmt_ {
		case .Hosts:
			added += parse_hosts_line(block, line)
		case .Domains:
			added += parse_domain_line(block, allow, line)
		case .Adblock:
			added += parse_adblock_line(block, allow, line)
		case .Auto:
		// unreachable: resolved above
		}
	}
	return
}

// Parse a single rule the way an entry under `blocking.rules` is written.
parse_rule :: proc(block, allow: ^Set, rule: string) -> int {
	return parse_adblock_line(block, allow, rule)
}

@(private)
parse_hosts_line :: proc(block: ^Set, raw: string) -> (added: int) {
	line := strings.trim_space(strip_line_comment(raw))
	if line == "" {
		return 0
	}
	// "IP host [host...]": everything after the address is a name to sink.
	space := strings.index_any(line, " \t")
	if space < 0 {
		return 0
	}
	rest := strings.trim_space(line[space:])
	for len(rest) > 0 {
		host := rest
		if idx := strings.index_any(rest, " \t"); idx >= 0 {
			host = rest[:idx]
			rest = strings.trim_space(rest[idx:])
		} else {
			rest = ""
		}
		if host == "" || is_housekeeping_name(host) {
			continue
		}
		set_add(block, host, {.Apex})
		added += 1
	}
	return
}

@(private)
parse_domain_line :: proc(block, allow: ^Set, raw: string) -> (added: int) {
	line := strings.trim_space(strip_line_comment(raw))
	if line == "" {
		return 0
	}
	// A domains list may still carry the odd adblock-style entry.
	if strings.has_prefix(line, "||") || strings.has_prefix(line, "@@") {
		return parse_adblock_line(block, allow, line)
	}
	target := block
	if strings.has_prefix(line, "-") {
		target = allow
		line = strings.trim_space(line[1:])
	}
	flags := Rule_Flags{.Apex, .Subdomains}
	if strings.has_prefix(line, "*.") {
		flags = {.Subdomains}
		line = line[2:]
	}
	if line == "" || strings.contains(line, "*") || strings.contains(line, "/") {
		return 0
	}
	set_add(target, line, flags)
	return 1
}

@(private)
parse_adblock_line :: proc(block, allow: ^Set, raw: string) -> (added: int) {
	line := strings.trim_space(raw)
	if line == "" || line[0] == '!' || line[0] == '#' || line[0] == '[' {
		return 0
	}

	// dnsmasq syntax that shows up in mixed lists.
	if strings.has_prefix(line, "address=/") || strings.has_prefix(line, "server=/") {
		body := line[strings.index_byte(line, '/') + 1:]
		slash := strings.index_byte(body, '/')
		if slash <= 0 {
			return 0
		}
		domain := body[:slash]
		set_add(block, domain, {.Apex, .Subdomains})
		return 1
	}

	target := block
	if strings.has_prefix(line, "@@") {
		target = allow
		line = line[2:]
	}
	// Modifiers ($third-party, $important, ...) do not change which name is
	// matched, and the ones that would are not expressible in DNS anyway.
	if idx := strings.index_byte(line, '$'); idx >= 0 {
		line = line[:idx]
	}

	flags := Rule_Flags{.Apex, .Subdomains}
	switch {
	case strings.has_prefix(line, "||"):
		line = line[2:]
	case strings.has_prefix(line, "|"):
		line = strings.trim_prefix(line[1:], "http://")
		line = strings.trim_prefix(line, "https://")
		flags = {.Apex}
	case strings.has_prefix(line, "*."):
		line = line[2:]
		flags = {.Subdomains}
	}

	line = strings.trim_right(line, "^|/")
	if line == "" {
		return 0
	}
	// Regex rules and path-scoped rules cannot be answered at the DNS layer.
	if line[0] == '/' || strings.contains(line, "*") || strings.contains(line, "/") {
		return 0
	}
	set_add(target, line, flags)
	return 1
}
