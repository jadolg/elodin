package itest

import "core:encoding/hex"
import "core:fmt"
import "core:os"
import "core:path/filepath"
import "core:strings"
import "core:sys/posix"
import "core:time"
import "elodin:dns"

/*
Test harness.

Each case gets a fresh elodin process, started from the real binary with a
generated configuration, so the suite verifies the artefact that ships rather
than the library it was built from.
*/

Runner :: struct {
	binary:    string,
	work_dir:  string,
	cert_file: string,
	key_file:  string,
	next_port: int,
	passed:    int,
	failed:    int,
	skipped:   int,
	// Failure descriptions, reported together at the end.
	failures:  [dynamic]string,
	current:   string,
	current_failed: bool,
	verbose:   bool,
	/*
	End each case by asking the server to shut down rather than killing it.

	Off by default because it costs the suite a shutdown per case - the
	maintenance loop notices the signal on a 200ms slice, and there are two
	hundred cases - and nothing in the ordinary run needs it. What needs it is a
	binary built with `-sanitize:address`: LeakSanitizer reports at exit, and a
	process that was killed never has one. See `mise run leakcheck`.
	*/
	graceful_stop: bool,
}

// Ports are handed out from a high range unlikely to collide with anything the
// developer's machine is already running.
BASE_PORT :: 24000

/*
How long `--graceful-stop` waits for a server to go before killing it.

Generous, because the process it is waiting for is instrumented: an ASan build
walks its whole heap at exit, and a runner under load is slower again. Waiting
too long costs seconds on a job that already takes minutes; not waiting long
enough turns the leak report the mode exists to collect into a killed process
that never wrote one.
*/
GRACEFUL_STOP_TIMEOUT :: 15 * time.Second

Server :: struct {
	process:   os.Process,
	udp_port:  int,
	dot_port:  int,
	doh_port:  int,
	log_path:  string,
	running:   bool,
	// See `Runner.graceful_stop`.
	graceful:  bool,
}

next_port :: proc(r: ^Runner) -> int {
	p := r.next_port
	r.next_port += 1
	return p
}

// --- case bookkeeping ------------------------------------------------------

start_case :: proc(r: ^Runner, name: string) {
	r.current = name
	r.current_failed = false
	if r.verbose {
		fmt.printf("  %-52s ", name)
	}
}

end_case :: proc(r: ^Runner) {
	if r.current_failed {
		r.failed += 1
		if r.verbose {
			fmt.println("FAIL")
		} else {
			fmt.print("x")
		}
	} else {
		r.passed += 1
		if r.verbose {
			fmt.println("ok")
		} else {
			fmt.print(".")
		}
	}
	// stdout is block-buffered when redirected, and a stuck case would show
	// nothing at all without this.
	os.flush(os.stdout)
	free_all(context.temp_allocator)
}

skip_case :: proc(r: ^Runner, name: string, reason: string) {
	r.skipped += 1
	append(&r.failures, fmt.aprintf("SKIP %s: %s", name, reason))
	if r.verbose {
		fmt.printf("  %-52s skipped (%s)\n", name, reason)
	} else {
		fmt.print("s")
	}
}

fail :: proc(r: ^Runner, format: string, args: ..any) {
	r.current_failed = true
	append(&r.failures, fmt.aprintf("FAIL %s: %s", r.current, fmt.tprintf(format, ..args)))
}

check :: proc(r: ^Runner, condition: bool, format: string, args: ..any) -> bool {
	if !condition {
		fail(r, format, ..args)
	}
	return condition
}

check_eq_int :: proc(r: ^Runner, got, want: int, what: string) -> bool {
	return check(r, got == want, "%s: got %d, want %d", what, got, want)
}

check_eq_str :: proc(r: ^Runner, got, want: string, what: string) -> bool {
	return check(r, got == want, "%s: got %q, want %q", what, got, want)
}

// --- running the binary directly -------------------------------------------

Run_Result :: struct {
	exit_code: int,
	output:    string,
	ok:        bool,
}

// Run the binary to completion with `args` and collect what it printed. For the
// one-shot modes - `--version`, `--check` - that never bind a socket.
run_binary :: proc(r: ^Runner, args: []string, tag: string) -> Run_Result {
	out_path := filepath.join({r.work_dir, fmt.tprintf("cli-%s.txt", tag)}, context.temp_allocator) or_else ""
	out_file, oerr := os.open(out_path, {.Write, .Create, .Trunc}, os.Permissions_Read_All + {.Write_User})
	if oerr != nil {
		return {}
	}

	command := make([dynamic]string, 0, len(args) + 1, context.temp_allocator)
	append(&command, r.binary)
	append(&command, ..args)

	process, perr := os.process_start(
		os.Process_Desc{command = command[:], stdout = out_file, stderr = out_file},
	)
	if perr != nil {
		os.close(out_file)
		return {}
	}
	state, werr := os.process_wait(process)
	os.close(out_file)
	if werr != nil {
		return {}
	}

	data, rerr := os.read_entire_file(out_path, context.temp_allocator)
	text := rerr == nil ? string(data) : ""
	return Run_Result{exit_code = state.exit_code, output = text, ok = true}
}

// --- server lifecycle ------------------------------------------------------

Server_Options :: struct {
	config:    string,
	udp_port:  int,
	tcp_port:  int,
	dot_port:  int,
	doh_port:  int,
	// Extra time to allow before the readiness probe gives up.
	warmup:    time.Duration,
	// Let the server download remote blocklists. Off by default so the suite
	// stays hermetic; the list cases point it at a local HTTP mock.
	allow_fetch: bool,
}

/*
Write the configuration, start the binary, and wait until it answers.

Readiness is established by querying the server rather than by sleeping, so the
suite neither races the process nor pays for a fixed delay.
*/
start_server :: proc(r: ^Runner, opts: Server_Options) -> (srv: Server, ok: bool) {
	srv, ok = start_server_raw(r, opts.config, opts.udp_port, opts.allow_fetch)
	if !ok {
		return srv, false
	}
	srv.dot_port = opts.dot_port
	srv.doh_port = opts.doh_port

	if !wait_ready(&srv, 5 * time.Second + opts.warmup) {
		fail(r, "server on port %d never became ready; log:\n%s", opts.udp_port, read_log(&srv))
		stop_server(&srv)
		return srv, false
	}
	if opts.tcp_port > 0 && !wait_tcp(opts.tcp_port, 5 * time.Second + opts.warmup) {
		fail(r, "server on port %d never answered over tcp; log:\n%s", opts.udp_port, read_log(&srv))
		stop_server(&srv)
		return srv, false
	}
	return srv, true
}

/*
Turn DNSSEC validation off for cases that are not about it.

A shipped configuration validates, and the mock upstreams cannot produce a chain
of trust for the names they invent: leaving it on would turn every case in the
suite into a SERVFAIL about something none of them are asking. Cases that do
test validation write their own `dnssec:` block, which this leaves alone.
*/
@(private)
without_dnssec :: proc(config: string, allocator := context.temp_allocator) -> string {
	if strings.contains(config, "dnssec:") {
		return config
	}
	return strings.concatenate({config, "\ndnssec:\n  enabled: false\n"}, allocator)
}

// Start the process without probing it. Callers that cannot use the UDP probe
// establish readiness themselves.
start_server_raw :: proc(
	r: ^Runner,
	config: string,
	udp_port: int,
	allow_fetch := false,
	// Write the configuration exactly as given, so a case can observe what the
	// shipped defaults do rather than what the suite prefers.
	verbatim := false,
) -> (
	srv: Server,
	ok: bool,
) {
	cfg_path := filepath.join({r.work_dir, fmt.tprintf("elodin-%d.yaml", udp_port)}, context.temp_allocator) or_else ""
	log_path := filepath.join({r.work_dir, fmt.tprintf("elodin-%d.log", udp_port)}, context.temp_allocator) or_else ""

	written := config if verbatim else without_dnssec(config)
	if werr := os.write_entire_file(cfg_path, transmute([]u8)written); werr != nil {
		fail(r, "cannot write the config to %s: %v", cfg_path, werr)
		return {}, false
	}

	log_file, lerr := os.open(log_path, {.Write, .Create, .Trunc}, os.Permissions_Read_All + {.Write_User})
	if lerr != nil {
		fail(r, "cannot open the log file %s: %v", log_path, lerr)
		return {}, false
	}
	defer os.close(log_file)

	command := make([dynamic]string, 0, 4, context.temp_allocator)
	append(&command, r.binary, "--config", cfg_path)
	if !allow_fetch {
		append(&command, "--no-fetch")
	}

	process, perr := os.process_start(
		os.Process_Desc{command = command[:], stdout = log_file, stderr = log_file},
	)
	if perr != nil {
		fail(r, "cannot start %s: %v", r.binary, perr)
		return {}, false
	}

	srv = Server {
		process  = process,
		udp_port = udp_port,
		// Heap: a Server outlives many cases, and end_case resets the temp
		// allocator between them.
		log_path = strings.clone(log_path, context.allocator),
		running  = true,
		// Carried on the server rather than looked up at stop time, so a case
		// that keeps one past the runner's frame still ends it the same way.
		graceful = r.graceful_stop,
	}
	return srv, true
}

/*
Probe until the server answers.

The probe is a CHAOS version.bind query, which the server answers locally and so
does not depend on any upstream being reachable. Each attempt uses a short
socket timeout: a datagram sent before the listener is bound is simply lost, so
the probe has to be retried rather than waited on.
*/
@(private)
PROBE_TIMEOUT :: 250 * time.Millisecond

@(private)
wait_ready :: proc(srv: ^Server, timeout: time.Duration) -> bool {
	probe := build_query("version.bind.", u16(dns.Type.TXT), class = u16(dns.Class.CH))
	deadline := time.time_add(time.now(), timeout)

	for time.diff(deadline, time.now()) < 0 {
		res := query_udp(srv.udp_port, probe, context.temp_allocator, PROBE_TIMEOUT)
		if res.ok {
			return true
		}
	}
	return false
}

/*
Probe until the server answers over TCP.

The listeners bind in order, udp before tcp, so the UDP probe above succeeding
says nothing yet about the stream listener: a TCP dial in the gap between the
two binds is refused, and on a loaded runner the gap is more than microseconds.
A case that queries over TCP passes the udp_port in `Server_Options` and this probes
it the same way as the datagram path - a CHAOS version.bind query, answered
locally, retried until the deadline.
*/
@(private)
wait_tcp :: proc(tcp_port: int, timeout: time.Duration) -> bool {
	probe := build_query("version.bind.", u16(dns.Type.TXT), class = u16(dns.Class.CH))
	deadline := time.time_add(time.now(), timeout)
	for time.diff(deadline, time.now()) < 0 {
		res := query_tcp(tcp_port, probe, context.temp_allocator, PROBE_TIMEOUT)
		if res.ok {
			return true
		}
	}
	return false
}

/*
Poll the log until a line shows up, or give up.

The read-once counterpart, `log_contains`, is only sound when something already
establishes that the line is on the file: a query the server answered carries
its own query-log line, because `handle_query` logs before the response is
handed to the socket. Where the case learned what to expect from a *different*
observable - a receive timeout on a datagram nothing was sent back for, a
handshake that verifies against a renewed certificate - there is no such
ordering, and the line reaches the file on the server's own schedule. Reading
once then asserts that the write beat the read, which is a statement about the
machine rather than about the server.

So this re-reads until the needle appears, the same wait-until-or-give-up shape
`wait_ready` uses for the readiness probe. It is also how a server that is
configured not to answer this suite - the `allow_from` cases, which have to ask
from a source outside the list - is waited for at all: the UDP probe can never
succeed there, and the line the listeners print once they are bound says the
same thing without needing an answer.
*/
wait_for_log :: proc(srv: ^Server, needle: string, timeout: time.Duration) -> bool {
	deadline := time.time_add(time.now(), timeout)
	for time.diff(deadline, time.now()) < 0 {
		if log_contains(srv, needle) {
			return true
		}
		time.sleep(20 * time.Millisecond)
	}
	return false
}

/*
End a case's server.

SIGKILL by default, which is quick and says nothing about the process: whatever
it was doing stops where it stood. Under `--graceful-stop` it is asked first,
the way an init system would, because a binary built with a sanitizer only
reports what it found on its way out - and a killed process never gets there.
The kill stays as the fallback, so a server that will not go still cannot hang
the suite.
*/
stop_server :: proc(srv: ^Server) {
	if srv.running && srv.graceful {
		if posix.kill(posix.pid_t(srv.process.pid), .SIGTERM) == .OK {
			deadline := time.time_add(time.now(), GRACEFUL_STOP_TIMEOUT)
			for time.diff(time.now(), deadline) > 0 {
				state, werr := os.process_wait(srv.process, 100 * time.Millisecond)
				if werr == nil && state.exited {
					srv.running = false
					break
				}
			}
		}
	}
	if srv.running {
		_ = os.process_kill(srv.process)
		_, _ = os.process_wait(srv.process)
		srv.running = false
	}
	// Unconditional: a server that has already been stopped by other means
	// still left its log path behind.
	delete(srv.log_path)
	srv.log_path = ""
}

/*
Stop the server the way an init system would, and wait for it to go.

`stop_server` uses SIGKILL, which says nothing about whether the process can
shut itself down. This sends the signal systemd sends and reports what came of
it — including the case where nothing does, since a graceful shutdown that
never finishes is the failure worth catching. The log is left in place for the
caller to read.
*/
signal_shutdown :: proc(srv: ^Server, within: time.Duration) -> (state: os.Process_State, ok: bool) {
	if !srv.running {
		return {}, false
	}
	if posix.kill(posix.pid_t(srv.process.pid), .SIGTERM) != .OK {
		return {}, false
	}
	deadline := time.time_add(time.now(), within)
	for time.diff(time.now(), deadline) > 0 {
		s, err := os.process_wait(srv.process, 100 * time.Millisecond)
		if err == nil && s.exited {
			srv.running = false
			return s, true
		}
	}
	return {}, false
}

/*
Ask for a certificate reload the way an operator would.

`systemctl reload` on the shipped unit sends this, or an operator's own
`kill -HUP` does. Unlike `signal_shutdown` there is nothing here to wait for -
the process keeps running - so this only reports whether the signal was
delivered; the caller checks the effect through the log or a fresh connection.
*/
signal_reload :: proc(srv: ^Server) -> bool {
	if !srv.running {
		return false
	}
	return posix.kill(posix.pid_t(srv.process.pid), .SIGHUP) == .OK
}

read_log :: proc(srv: ^Server) -> string {
	data, err := os.read_entire_file(srv.log_path, context.temp_allocator)
	if err != nil {
		return "(log unavailable)"
	}
	return string(data)
}

// One read of the log as it stands. Sound only where the case already holds an
// ordering that puts the line on the file - see `wait_for_log`, which is what a
// case that learned what to expect from some other observable wants instead.
log_contains :: proc(srv: ^Server, needle: string) -> bool {
	return strings.contains(read_log(srv), needle)
}

// Counts how often a substring appears in the server log; used to observe which
// upstream answered.
log_count :: proc(srv: ^Server, needle: string) -> int {
	text := read_log(srv)
	count := 0
	rest := text
	for {
		idx := strings.index(rest, needle)
		if idx < 0 {
			return count
		}
		count += 1
		rest = rest[idx + len(needle):]
	}
}

// --- DNS message helpers ---------------------------------------------------

// Build a query by hand rather than through the dns package, so a codec bug
// cannot hide by being applied to both sides.
build_query :: proc(
	name: string,
	qtype: u16,
	id: u16 = 0x4242,
	class: u16 = 1,
	edns_size: u16 = 0,
	dnssec_ok := false,
	checking_disabled := false,
	// A COOKIE option to carry in the OPT record, which needs `edns_size` set.
	cookie: []u8 = nil,
	// A PADDING option, same again: the bytes a client pads its query with.
	padding: []u8 = nil,
	allocator := context.temp_allocator,
) -> []u8 {
	buf := make([dynamic]u8, 0, 64, allocator)

	arcount: u16 = 1 if edns_size > 0 else 0
	append(&buf, u8(id >> 8), u8(id))
	append(&buf, 0x01, 0x10 if checking_disabled else 0x00) // RD, and CD when asked
	append(&buf, 0, 1) // qdcount
	append(&buf, 0, 0, 0, 0) // ancount, nscount
	append(&buf, u8(arcount >> 8), u8(arcount))

	trimmed := strings.trim_suffix(name, ".")
	if trimmed != "" {
		rest := trimmed
		for len(rest) > 0 {
			label := rest
			if idx := strings.index_byte(rest, '.'); idx >= 0 {
				label = rest[:idx]
				rest = rest[idx + 1:]
			} else {
				rest = ""
			}
			append(&buf, u8(len(label)))
			append(&buf, ..transmute([]u8)label)
		}
	}
	append(&buf, 0)
	append(&buf, u8(qtype >> 8), u8(qtype))
	append(&buf, u8(class >> 8), u8(class))

	if edns_size > 0 {
		ttl: u32 = 0x0000_8000 if dnssec_ok else 0
		append(&buf, 0) // root name
		append(&buf, 0, 41) // OPT
		append(&buf, u8(edns_size >> 8), u8(edns_size))
		append(&buf, u8(ttl >> 24), u8(ttl >> 16), u8(ttl >> 8), u8(ttl))
		rdlength := 0
		if cookie != nil {
			rdlength += 4 + len(cookie)
		}
		if padding != nil {
			rdlength += 4 + len(padding)
		}
		append(&buf, u8(rdlength >> 8), u8(rdlength))
		if cookie != nil {
			append(&buf, 0, 10) // COOKIE
			append(&buf, u8(len(cookie) >> 8), u8(len(cookie)))
			append(&buf, ..cookie)
		}
		if padding != nil {
			append(&buf, 0, 12) // PADDING
			append(&buf, u8(len(padding) >> 8), u8(len(padding)))
			append(&buf, ..padding)
		}
	}
	return buf[:]
}

// The COOKIE option carried in a message, if it has one.
find_cookie :: proc(wire: []u8) -> (cookie: []u8, found: bool) {
	msg, err := dns.decode_message(wire, context.temp_allocator)
	if err != .None {
		return nil, false
	}
	return dns.find_edns_option(msg, .Cookie)
}

// The PADDING option carried in a message, if it has one.
find_padding :: proc(wire: []u8) -> (padding: []u8, found: bool) {
	msg, err := dns.decode_message(wire, context.temp_allocator)
	if err != .None {
		return nil, false
	}
	return dns.find_edns_option(msg, .Padding)
}

Header :: struct {
	id:       u16,
	qr:       bool,
	aa:       bool,
	tc:       bool,
	rd:       bool,
	ra:       bool,
	rcode:    int,
	qdcount:  int,
	ancount:  int,
	nscount:  int,
	arcount:  int,
}

// Read the header straight from the bytes, without the decoder under test.
parse_header :: proc(wire: []u8) -> (h: Header, ok: bool) {
	if len(wire) < 12 {
		return {}, false
	}
	h.id = u16(wire[0]) << 8 | u16(wire[1])
	h.qr = wire[2] & 0x80 != 0
	h.aa = wire[2] & 0x04 != 0
	h.tc = wire[2] & 0x02 != 0
	h.rd = wire[2] & 0x01 != 0
	h.ra = wire[3] & 0x80 != 0
	h.rcode = int(wire[3] & 0x0f)
	h.qdcount = int(u16(wire[4]) << 8 | u16(wire[5]))
	h.ancount = int(u16(wire[6]) << 8 | u16(wire[7]))
	h.nscount = int(u16(wire[8]) << 8 | u16(wire[9]))
	h.arcount = int(u16(wire[10]) << 8 | u16(wire[11]))
	return h, true
}

from_hex :: proc(s: string, allocator := context.temp_allocator) -> []u8 {
	out, ok := hex.decode(transmute([]u8)s, allocator)
	if !ok {
		return nil
	}
	return out
}

fixture :: proc(key: string) -> Fixture {
	for f in FIXTURES {
		if f.key == key {
			return f
		}
	}
	panic(fmt.tprintf("no fixture named %q", key))
}

// The A/AAAA addresses in a response, as dotted or colon text, for assertions
// that care about which answer came back.
answer_addresses :: proc(wire: []u8, allocator := context.temp_allocator) -> []string {
	msg, err := dns.decode_message(wire, allocator)
	if err != .None {
		return nil
	}
	out := make([dynamic]string, 0, len(msg.answer), allocator)
	for rec in msg.answer {
		#partial switch d in rec.data {
		case dns.Rdata_A:
			append(&out, fmt.aprintf("%d.%d.%d.%d", d.addr[0], d.addr[1], d.addr[2], d.addr[3], allocator = allocator))
		case dns.Rdata_AAAA:
			b := strings.builder_make(allocator)
			for i in 0 ..< 8 {
				if i > 0 {
					strings.write_byte(&b, ':')
				}
				fmt.sbprintf(&b, "%02x%02x", d.addr[i * 2], d.addr[i * 2 + 1])
			}
			append(&out, strings.to_string(b))
		}
	}
	return out[:]
}

// The smallest TTL in the answer section, for cache assertions.
min_answer_ttl :: proc(wire: []u8) -> (ttl: u32, ok: bool) {
	msg, err := dns.decode_message(wire, context.temp_allocator)
	if err != .None || len(msg.answer) == 0 {
		return 0, false
	}
	ttl = max(u32)
	for rec in msg.answer {
		ttl = min(ttl, rec.ttl)
	}
	return ttl, true
}

first_cname_or_name :: proc(wire: []u8) -> string {
	msg, err := dns.decode_message(wire, context.temp_allocator)
	if err != .None {
		return ""
	}
	for rec in msg.answer {
		if n, is_name := rec.data.(dns.Rdata_Name); is_name {
			return n.name
		}
	}
	return ""
}

bytes_equal :: proc(a, b: []u8) -> bool {
	if len(a) != len(b) {
		return false
	}
	for i in 0 ..< len(a) {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
