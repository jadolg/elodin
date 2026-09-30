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
		if set_add(block, host, {.Apex}) {
			added += 1
		}
	}
	return
}

@(private)
parse_domain_line :: proc(block, allow: ^Set, raw: string) -> (added: int) {
	kept := strip_line_comment(raw)
	line := strings.trim_space(kept)
	if line == "" {
		return 0
	}
	// A `/` is never part of a domain, so a line opening with one is a regex
	// rule, and an allow rule after a `-` or `@@`. On such a line a comment has
	// to be set off by a space: a `!` or `#` cut inside the slashes (`/a/!b/`)
	// would leave a shorter pattern that matches far more names.
	cut_inside := len(kept) < len(raw) && strings.trim_right_space(kept) == kept
	// A domains list may still carry the odd adblock-style entry.
	if strings.has_prefix(line, "||") || strings.has_prefix(line, "@@") {
		if cut_inside && strings.has_prefix(line, "@@/") {
			return 0
		}
		return parse_adblock_line(block, allow, line)
	}
	target := block
	if strings.has_prefix(line, "-") {
		target = allow
		line = strings.trim_space(line[1:])
	}
	if strings.has_prefix(line, "/") {
		if cut_inside {
			return 0
		}
		return parse_adblock_line(target, allow, line)
	}
	flags := Rule_Flags{.Apex, .Subdomains}
	if strings.has_prefix(line, "*.") {
		flags = {.Subdomains}
		line = line[2:]
	}
	if line == "" || strings.contains(line, "*") {
		return 0
	}
	return int(set_add(target, line, flags))
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
		slash := strings.last_index_byte(body, '/')
		if slash <= 0 {
			return 0
		}
		// `server=/d/1.2.3.4` forwards d to that server; only `server=/d/` keeps it local.
		if strings.has_prefix(line, "server=") && body[slash + 1:] != "" {
			return 0
		}
		domains := body[:slash]
		for domain in strings.split_iterator(&domains, "/") {
			added += int(set_add(block, domain, {.Apex, .Subdomains}))
		}
		return
	}

	target := block
	if strings.has_prefix(line, "@@") {
		target = allow
		line = line[2:]
	}
	/*
	`$important` does not change which name is matched and is dropped;
	`$badfilter` cancels the rule it names. Any other modifier narrows the rule -
	to a query type, a client, a site it is loaded from - or makes it something
	other than a block (`$elemhide`, `$removeparam`, `$csp`, ...), and dropping it
	would widen the rule to every query, so the rule is skipped. That is what
	AdGuard Home does with a modifier its DNS engine cannot honour.

	`$third-party` and `$~third-party` (`$~first-party`, `$first-party`) are
	skipped too, as AdGuard Home skips them (#464): urlfilter's `NewDNSEngine`
	loads only the rules `IsHostLevelNetworkRule` accepts, and that refuses a rule
	with any flag option but `$important` and `$badfilter` enabled, or any flag
	option negated; `third-party` is one of those flags.
	*/
	/*
	A regex rule may hold `$` itself, as an anchor. urlfilter takes a rule that
	opens and closes with `/` as a whole pattern with no options, unless it holds
	`replace=` (`isRegexRuleWithoutOptions`), and otherwise splits the options
	off at the *last* `$` not escaped with `\` (`findOptionsDelimiter`), as it
	does every rule. So `/ads?|x/$replace=/a/b/` is a `$replace` rule, skipped,
	not the regex `ads?|x/$replace=/a/b`, which matches `ad`; and in
	`||x^$important=$third-party` the options are `third-party`, not an
	`important` with a value.
	*/
	if is_cosmetic(line) {
		return 0
	}
	is_regex := strings.has_prefix(line, "/")
	whole := is_regex && strings.has_suffix(line, "/") && len(line) > 1 && !strings.contains(line, "replace=")
	options_at := -1 if whole else last_options_delimiter(line)
	badfilter := false
	if idx := options_at; idx >= 0 {
		modifiers := line[idx + 1:]
		line = line[:idx]
		for len(modifiers) > 0 {
			// As urlfilter's `splitWithEscapeCharacter`: a `\,` does not split, so
			// `important=\,badfilter` is one `important` with a value.
			end := 0
			for end < len(modifiers) && (modifiers[end] != ',' || (end > 0 && modifiers[end - 1] == '\\')) {
				end += 1
			}
			m := modifiers[:end]
			modifiers = modifiers[min(end + 1, len(modifiers)):]
			// As urlfilter's `loadOptions`: a name is not trimmed, so ` important`
			// is unknown, and `=x` has no name, so it is unknown too.
			name := m
			if eq := strings.index_byte(name, '='); eq > 0 {
				name = name[:eq]
			}
			switch name {
			case "badfilter":
				badfilter = true
			case "important", "":
			case:
				return 0
			}
		}
	}
	if is_regex {
		// `/.../`: what is between the slashes is matched against the name.
		if len(line) < 2 || !strings.has_suffix(line, "/") {
			return 0
		}
		pattern := line[1:len(line) - 1]
		if badfilter {
			regex_cancel(target, pattern)
			return 0
		}
		return int(regex_add(target, pattern))
	}
	// `##`, `#@#`, `#$#`, `#?#`: cosmetic rules, naming the site they apply on.
	// A `$` left in the pattern is never in a name either.
	if strings.contains_any(line, "#$") {
		return 0
	}

	flags := Rule_Flags{.Apex, .Subdomains}
	switch {
	case strings.has_prefix(line, "||*."):
		// The AdGuard DNS filter's spelling of `*.example`: the subtree only.
		line = line[4:]
		flags = {.Subdomains}
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
	// Wildcard rules cannot be answered by a name lookup; set_add refuses a
	// path rule.
	if strings.contains(line, "*") {
		return 0
	}
	if badfilter {
		set_cancel(target, line, flags)
		return 0
	}
	return int(set_add(target, line, flags))
}

/*
urlfilter's `isCosmetic`, which `NewRule` asks before anything else: a cosmetic
or HTML filtering rule's marker at the first `#` or the first `$` in the line,
unless a space comes before it, as in a hosts line's `## comment`. So
`/ads#?#x/` and `/a$$/` are cosmetic rules, never matched against a name, and
`/a $$/` is not one.
*/
@(private)
is_cosmetic :: proc(line: string) -> bool {
	MARKERS :: [?]string{"#@$?#", "#@?#", "#@$#", "#$?#", "#@%#", "#@#", "#?#", "#$#", "#%#", "$@$", "##", "$$"}
	for first in ([]u8{'#', '$'}) {
		i := strings.index_byte(line, first)
		if i < 0 || (i > 0 && line[i - 1] == ' ') {
			continue
		}
		for marker in MARKERS {
			if strings.has_prefix(line[i:], marker) {
				return true
			}
		}
	}
	return false
}

// urlfilter's `findOptionsDelimiter`: the last `$` that no `\` escapes.
@(private)
last_options_delimiter :: proc(line: string) -> int {
	for i := len(line) - 1; i >= 0; i -= 1 {
		if line[i] == '$' && (i == 0 || line[i - 1] != '\\') {
			return i
		}
	}
	return -1
}
