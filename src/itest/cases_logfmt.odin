package itest

import "core:fmt"
import "core:os"
import "core:path/filepath"
import "core:strconv"
import "core:strings"
import "core:sys/posix"
import "core:time"
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
	return base_config(
		udp_port,
		upstream_at(upstream_port),
		log = "{ level: info, queries: true }",
		timeout = "3s",
	)
}

run_logfmt_cases :: proc(r: ^Runner) {
	mock, upstream_port, mock_ok := synth_mock(r, "logfmt", "logfmt", {203, 0, 113, 5})
	if !mock_ok {
		return
	}
	defer mock_stop(mock)

	udp_port := next_port(r)
	srv, ok := start_server(r, Server_Options{config = config_logfmt(udp_port, upstream_port), udp_port = udp_port})
	if !ok {
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
				// The address on its own, with the ephemeral port in a field of
				// its own beside it: `client` is what an operator selects on, so
				// a port left joined to it would be a port every filter has to
				// strip.
				check_eq_str(r, pairs["client"], "127.0.0.1", "client")
				check(r, port_of(pairs["port"]) > 0, "port=%q", pairs["port"])
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

	log_file_case(r, upstream_port)
}

/*
A line in `log.file` is one write(2) and nothing else.

The descriptor is unbuffered, so the write is already what `tail` and a shipper
read. A sync on top of it is a disk flush per answered query, taken under the
log's lock. Only a tracer can see one, so the server runs under strace with
`log.file` set and `log.queries` on, and the case counts the syncs.
*/
@(private = "file")
log_file_case :: proc(r: ^Runner, upstream_port: int) {
	NAME :: "logfmt: a line in log.file is a write, not a write and a sync"
	QUERIES :: 20

	trace_path := filepath.join({r.work_dir, "log-sync.strace"}, context.temp_allocator) or_else ""
	log_path := filepath.join({r.work_dir, "log-sync.log"}, context.temp_allocator) or_else ""
	_ = os.remove(log_path)
	// A tracer that cannot attach here - absent, ptrace refused, or older than
	// 6.6 and so without --kill-on-exit - is no evidence either way.
	if !runs_ok(r, {"strace", "--kill-on-exit", "-o", "/dev/null", "true"}) {
		skip_case(r, NAME, "strace 6.6 or later is not installed or cannot trace here")
		return
	}

	// LeakSanitizer cannot run under a tracer: on exit it writes a fatal-error
	// report instead of a leak check, and `mise run leakcheck` fails on any
	// report. The leak check is off for this one traced process, and only that.
	inherited, eerr := os.environ(context.temp_allocator)
	if eerr != nil {
		fail(r, "%s: cannot read the environment: %v", NAME, eerr)
		return
	}
	env := make([dynamic]string, 0, len(inherited) + 1, context.temp_allocator)
	asan_options := ""
	for kv in inherited {
		if strings.has_prefix(kv, "ASAN_OPTIONS=") {
			asan_options = kv[len("ASAN_OPTIONS="):]
		} else {
			append(&env, kv)
		}
	}
	append(&env, fmt.tprintf("ASAN_OPTIONS=%s:detect_leaks=0", asan_options))

	udp_port := next_port(r)
	config := base_config(
		udp_port,
		upstream_at(upstream_port),
		log = fmt.tprintf("{{ level: info, queries: true, file: %q }}", log_path),
		timeout = "3s",
	)
	// strace is known to work here, so a server that does not answer under it
	// is a failure, not a skip - which `start_server` has recorded.
	srv, ok := start_server(
		r,
		Server_Options {
			config = config,
			udp_port = udp_port,
			env = env[:],
			// --kill-on-exit: `stop_server` kills strace, and a tracee outlives its
			// tracer otherwise, still bound to the port. --seccomp-bpf: the server
			// stops only at the traced calls, not at every syscall of every thread.
			wrap = {"strace", "--kill-on-exit", "--seccomp-bpf", "-f", "-qq", "-e", "trace=fsync,fdatasync,sync_file_range", "-o", trace_path},
			warmup = 5 * time.Second,
		},
	)
	if !ok {
		return
	}
	defer stop_server(&srv)

	for i in 0 ..< QUERIES {
		_ = query_udp(udp_port, build_query(fmt.tprintf("sync-%d.example.", i), u16(dns.Type.A)), context.temp_allocator)
	}
	// strace's own child is the server. Stopped through it rather than through
	// strace, so the server takes its own shutdown path while traced.
	children, _ := os.read_entire_file(
		fmt.tprintf("/proc/%d/task/%d/children", srv.process.pid, srv.process.pid),
		context.temp_allocator,
	)
	child, cok := strconv.parse_int(strings.trim_space(string(children)), 10)
	if !cok {
		fail(r, "%s: cannot find the server under strace pid %d: %q", NAME, srv.process.pid, string(children))
		return
	}
	posix.kill(posix.pid_t(child), .SIGTERM)
	if state, werr := os.process_wait(srv.process, GRACEFUL_STOP_TIMEOUT); werr == nil && state.exited {
		srv.running = false
	}

	start_case(r, NAME)
	{
		logged, _ := os.read_entire_file(log_path, context.temp_allocator)
		trace, _ := os.read_entire_file(trace_path, context.temp_allocator)
		// The premise: the server ran to its end under the tracer, which saw
		// the SIGTERM, and the lines went to the file, so a sync per line would
		// have been taken and seen.
		check(r, !srv.running, "the server did not exit on SIGTERM under strace; log:\n%s", read_log(&srv))
		check(r, strings.contains(string(trace), "SIGTERM"), "strace did not trace the server:\n%s", string(trace))
		// By name: wait_ready's version.bind probe is a query line too.
		lines := strings.count(string(logged), "qname=sync-")
		check(r, lines == QUERIES, "log.file has %d of the %d query lines:\n%s", lines, QUERIES, string(logged))
		// One per call: "fsync(" and "fdatasync(" end in "sync(", and a call
		// another thread interrupted adds a "<... fsync resumed>" line that
		// does not, so it is not counted twice.
		syncs := strings.count(string(trace), "sync(") + strings.count(string(trace), "sync_file_range(")
		check(r, syncs == 0, "%d syncs for %d query lines:\n%s", syncs, lines, string(trace))
	}
	end_case(r)
}

// Whether `command` runs and exits 0, its output kept out of the suite's own.
@(private = "file")
runs_ok :: proc(r: ^Runner, command: []string) -> bool {
	res := run_command(command, nil, filepath.join({r.work_dir, "runs-ok.txt"}, context.temp_allocator) or_else "")
	return res.ok && res.exit_code == 0
}

/*
The `port` field of a query line, as a number.

0 for anything `strconv.parse_int` rejects, an empty field among them, so a
caller asking for a real port asks `> 0` and a line
that lost the field fails the check rather than passing it by accident.
*/
@(private = "file")
port_of :: proc(text: string) -> int {
	if text == "" {
		return 0
	}
	value, ok := strconv.parse_int(text, 10)
	if !ok {
		return 0
	}
	return value
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
