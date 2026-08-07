package itest

import "core:fmt"
import "core:strings"
import "elodin:dns"

/*
The log the binary actually writes, read back as logfmt.

The unit tests in `src/logx` pin the format one line at a time. What they cannot
see is a line that never went through `logx` - a stray `fmt.eprintln` on some
error path, or a message assembled somewhere that puts a bare newline in the
middle of itself. So this reads every line a real start-to-shutdown produced and
insists all of them parse, rather than checking the ones it went looking for.
*/

@(private = "file")
config_logfmt :: proc(udp_port, upstream_port: int) -> string {
	return fmt.tprintf(
		`log: {{ level: info, queries: true }}
listeners:
  udp: {{ enabled: true, address: "127.0.0.1", port: %d }}
  tcp: {{ enabled: false }}
upstream:
  timeout: 3s
  servers: ["127.0.0.1:%d"]
cache: {{ enabled: false }}
blocking: {{ enabled: false }}
`,
		udp_port,
		upstream_port,
	)
}

run_logfmt_cases :: proc(r: ^Runner) {
	upstream_port := next_port(r)
	mock := mock_make("logfmt", upstream_port)
	mock_synth_all(mock, {203, 0, 113, 5})
	if !mock_start(mock) {
		skip_case(r, "logfmt", "cannot start the mock upstream")
		return
	}
	defer mock_stop(mock)

	udp_port := next_port(r)
	srv, ok := start_server(r, Server_Options{config = config_logfmt(udp_port, upstream_port), udp_port = udp_port})
	if !ok {
		skip_case(r, "logfmt", "server did not start")
		return
	}
	defer stop_server(&srv)

	/*
	A label with a quote in it, which is the case the escaping is for.

	Presentation form leaves `"` alone - it is printable, and not a dot or a
	backslash - so this arrives in the log line as the byte the client sent. Left
	unquoted it would close `qname=` early and everything after it would parse as
	fields this server never wrote.
	*/
	_ = query_udp(udp_port, build_query(`we"ird.example.`, u16(dns.Type.A)))
	_ = query_udp(udp_port, build_query("plain.example.", u16(dns.Type.A)))

	start_case(r, "logfmt: every line is key=value, with a timestamp and a level")
	{
		lines := log_lines(&srv)
		if check(r, len(lines) > 0, "the server logged nothing at all") {
			for line, i in lines {
				pairs, parsed := logfmt_pairs(line)
				if !check(r, parsed, "line %d is not logfmt: %s", i + 1, line) {
					continue
				}
				check(r, "ts" in pairs, "line %d has no ts: %s", i + 1, line)
				check(r, "level" in pairs, "line %d has no level: %s", i + 1, line)
				check(r, "msg" in pairs, "line %d has no msg: %s", i + 1, line)
			}
		}
	}
	end_case(r)

	start_case(r, "logfmt: a query is fields rather than a sentence")
	{
		line, found := log_line_where(&srv, "msg=query", "qname=plain.example")
		if check(r, found, "no query line for plain.example; log:\n%s", read_log(&srv)) {
			pairs, parsed := logfmt_pairs(line)
			if check(r, parsed, "the query line is not logfmt: %s", line) {
				check_eq_str(r, pairs["proto"], "udp", "proto")
				check_eq_str(r, pairs["qtype"], "A", "qtype")
				check_eq_str(r, pairs["qname"], "plain.example", "qname")
				check_eq_str(r, pairs["outcome"], "forwarded", "outcome")
				check(r, strings.has_prefix(pairs["client"], "127.0.0.1:"), "client=%q", pairs["client"])
				check(r, pairs["ms"] != "", "the line carries no duration")
			}
		}
	}
	end_case(r)

	start_case(r, "logfmt: a name a client chose cannot forge a field")
	{
		line, found := log_line_where(&srv, "msg=query", `we\"ird`)
		if check(r, found, "no query line for the awkward name; log:\n%s", read_log(&srv)) {
			pairs, parsed := logfmt_pairs(line)
			if check(r, parsed, "the query line is not logfmt: %s", line) {
				// Unescaped, and still one value: the quote is inside `qname`
				// rather than having ended it.
				check_eq_str(r, pairs["qname"], `we"ird.example`, "qname")
				check_eq_str(r, pairs["outcome"], "forwarded", "outcome")
			}
		}
	}
	end_case(r)
}

@(private = "file")
log_lines :: proc(srv: ^Server) -> []string {
	text := strings.trim_right(read_log(srv), "\n")
	if text == "" {
		return {}
	}
	return strings.split(text, "\n", context.temp_allocator)
}

@(private = "file")
log_line_where :: proc(srv: ^Server, needles: ..string) -> (line: string, found: bool) {
	search: for candidate in log_lines(srv) {
		for needle in needles {
			if !strings.contains(candidate, needle) {
				continue search
			}
		}
		return candidate, true
	}
	return "", false
}

/*
Split a logfmt line the way a collector would.

Fields are separated by spaces, except inside a quoted value, where a `\"` is a
quote rather than the end of one. Values come back unescaped, so what the test
compares against is the string the server meant to log rather than its spelling
on disk. A token with no `=` in it, or an unterminated quote, is what "this is
not logfmt" looks like.
*/
@(private = "file")
logfmt_pairs :: proc(line: string) -> (pairs: map[string]string, ok: bool) {
	pairs = make(map[string]string, 16, context.temp_allocator)

	i := 0
	for i < len(line) {
		for i < len(line) && line[i] == ' ' {
			i += 1
		}
		if i >= len(line) {
			break
		}

		key_start := i
		for i < len(line) && line[i] != '=' && line[i] != ' ' {
			i += 1
		}
		// A token that ran to the end of the line, or to a space, without an `=`
		// in it: a word rather than a field.
		if i >= len(line) || line[i] != '=' {
			return pairs, false
		}
		key := line[key_start:i]
		i += 1 // the '='
		if key == "" {
			return pairs, false
		}

		if i < len(line) && line[i] == '"' {
			i += 1
			value := strings.builder_make(context.temp_allocator)
			closed := false
			for i < len(line) {
				c := line[i]
				if c == '\\' && i + 1 < len(line) {
					switch line[i + 1] {
					case 'n':
						strings.write_byte(&value, '\n')
					case 'r':
						strings.write_byte(&value, '\r')
					case 't':
						strings.write_byte(&value, '\t')
					case:
						strings.write_byte(&value, line[i + 1])
					}
					i += 2
					continue
				}
				if c == '"' {
					i += 1
					closed = true
					break
				}
				strings.write_byte(&value, c)
				i += 1
			}
			if !closed {
				return pairs, false
			}
			pairs[key] = strings.to_string(value)
			continue
		}

		value_start := i
		for i < len(line) && line[i] != ' ' {
			i += 1
		}
		pairs[key] = line[value_start:i]
	}
	return pairs, true
}
