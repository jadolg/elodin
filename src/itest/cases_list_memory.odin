package itest

import "core:fmt"
import "core:net"
import "core:os"
import "core:path/filepath"
import "core:strconv"
import "core:strings"
import "core:time"
import "elodin:dns"

/*
A blocklist rebuild hands the replaced rule sets' memory back (#513).

A rebuild allocates the new sets' tables, tens of MB at a few hundred thousand
rules, and frees the ones they replace. glibc serves blocks that large with
mmap and unmaps them on free, but each such free raises its dynamic mmap
threshold to the block's size (up to 32 MB), so the next rebuild's tables come
from the heap instead, whose freed middle is never returned. Resident memory
then settles at a rebuild's peak, old and new sets together. The shipped unit
pins the threshold with MALLOC_MMAP_THRESHOLD_, which also turns the adjustment
off.

The case rebuilds one list over SIGHUP in two processes: one started with the
environment `packaging/elodin.service` sets, which has to stay near the RSS it
started with, and one without it - the premise, which has to grow. A control
that does not grow fails the case: the check would pass whatever the unit set,
so the list's size needs moving back into the band where glibc keeps the
memory. Under a sanitizer, whose allocator is not glibc's, it is skipped.
*/

/*
How much memory a rebuild keeps depends on where the tables' sizes fall against
the threshold glibc has moved to, so the premise holds at some sizes and not
others: half a million names of a realistic length, about 23 MB of list, keep
roughly as much again as the process started with.
*/
@(private = "file")
MEMORY_RULES :: 500_000

@(private = "file")
MEMORY_RELOADS :: 4

@(private = "file")
UNIT_FILE :: "packaging/elodin.service"

// The `KEY=VALUE` assignments of the unit's Environment= lines. Quoting,
// specifiers, an empty line (which resets the list), an assignment without `=`,
// a key set twice (where systemd takes the last and getenv the first), an
// Environment= outside [Service] (which systemd ignores) and any other
// environment directive (UnsetEnvironment=, EnvironmentFile=, PassEnvironment=)
// are refused rather than interpreted, so a value this does not read cannot
// pass as one.
@(private = "file")
unit_environment :: proc(r: ^Runner) -> (env: [dynamic]string, ok: bool) {
	data, err := os.read_entire_file(UNIT_FILE, context.temp_allocator)
	if err != nil {
		fail(r, "cannot read %s: %v", UNIT_FILE, err)
		return
	}
	env = make([dynamic]string, context.temp_allocator)
	text := string(data)
	in_service := false
	for raw in strings.split_lines_iterator(&text) {
		// systemd strips ASCII blanks around the directive and its `=`.
		line := strings.trim_left(raw, " \t")
		if strings.has_prefix(line, "[") {
			in_service = strings.trim_right(line, " \t\r") == "[Service]"
			continue
		}
		eq := strings.index_byte(line, '=')
		if eq < 0 || strings.has_prefix(line, "#") || strings.has_prefix(line, ";") {
			continue
		}
		directive := strings.trim_right(line[:eq], " \t")
		if !strings.contains(directive, "Environment") {
			continue
		}
		value := line[eq + 1:]
		if directive != "Environment" || !in_service || strings.contains_any(value, `"'\%`) || strings.trim_space(value) == "" {
			fail(r, "%s: %q is not read here", UNIT_FILE, line)
			return
		}
		// systemd splits on ASCII blanks only, where `strings.fields` also
		// splits on \v, \f and Unicode spaces.
		for field in strings.fields_proc(value, proc(c: rune) -> bool {return c == ' ' || c == '\t' || c == '\r'}, context.temp_allocator) {
			sep := strings.index_byte(field, '=')
			if sep <= 0 {
				fail(r, "%s: %q is not an assignment", UNIT_FILE, field)
				return
			}
			key := field[:sep + 1]
			for set in env {
				if strings.has_prefix(set, key) {
					fail(r, "%s: %s is set twice", UNIT_FILE, key)
					return
				}
			}
			append(&env, field)
		}
	}
	return env, true
}

/*
Whether the binary is built with AddressSanitizer, skipping case `name` if so.
A sanitizer's runtime answers malloc itself and ignores glibc's settings, and
its quarantine grows every process alike.
*/
@(private = "file")
built_with_asan :: proc(r: ^Runner, name: string) -> bool {
	// Heap: the temp allocator is not reset until the next case ends, and a
	// skip from here ends none.
	exe, xerr := os.read_entire_file(r.binary, context.allocator)
	if xerr != nil {
		fail(r, "%s: cannot read %s: %v", name, r.binary, xerr)
		return true
	}
	asan := strings.contains(string(exe), "__asan_init")
	delete(exe)
	if asan {
		skip_case(r, name, "the binary is built with AddressSanitizer, whose allocator is not glibc's")
	}
	return asan
}

/*
The environments the memory cases start a server with: `control` is this
process's own without any MALLOC_ setting or GLIBC_TUNABLES of the suite's own
or an LD_PRELOAD (which can replace the allocator), so it is glibc's defaults;
`shipped` is that with the unit's assignments first. getenv takes the first of a
key set twice, and under systemd the unit's value is the one the process sees.
`control` keeps its capacity when every variable is dropped: a nil environment
is the suite's own, MALLOC_ settings included.
*/
@(private = "file")
glibc_environments :: proc(r: ^Runner, name: string, unit_env: []string) -> (control, shipped: []string, ok: bool) {
	inherited, eerr := os.environ(context.temp_allocator)
	if eerr != nil {
		fail(r, "%s: cannot read the environment: %v", name, eerr)
		return
	}
	kept := make([dynamic]string, 0, len(inherited), context.temp_allocator)
	for kv in inherited {
		if !strings.has_prefix(kv, "MALLOC_") && !strings.has_prefix(kv, "GLIBC_TUNABLES=") && !strings.has_prefix(kv, "LD_PRELOAD=") {
			append(&kept, kv)
		}
	}
	with_unit := make([dynamic]string, context.temp_allocator)
	append(&with_unit, ..unit_env)
	append(&with_unit, ..kept[:])
	return kept[:], with_unit[:], true
}

@(private = "file")
list_memory_config :: proc(udp_port: int, list_path: string, timeout_s: int) -> string {
	return fmt.tprintf(
		`log: {{ level: info }}
listeners:
  udp: {{ enabled: true, address: "127.0.0.1", port: %d }}
  tcp: {{ enabled: false }}
upstream:
  timeout: %ds
  servers: ["127.0.0.1:1"]
cache: {{ enabled: false }}
blocking:
  enabled: true
  lists:
    - {{ name: big, file: %s, format: hosts }}
`,
		udp_port,
		timeout_s,
		list_path,
	)
}

// One numeric field of /proc/<pid>/status, such as `VmRSS` in KiB or `Threads`.
@(private = "file")
proc_status_int :: proc(pid: int, field: string) -> (n: int, ok: bool) {
	value := proc_status_field(fmt.tprintf("/proc/%d/status", pid), field) or_return
	return strconv.parse_int(strings.trim_space(strings.trim_suffix(value, "kB")))
}

/*
Start a server on the list, rebuild it MEMORY_RELOADS times, and report its RSS
once ready and after the last rebuild. Each reload changes `upstream.timeout`
and rereads the `file:` list; the rebuild that follows logs its `filter:` line
once the old sets are freed.
*/
@(private = "file")
rss_across_rebuilds :: proc(r: ^Runner, env: []string, list_path: string) -> (start, end: int, ok: bool) {
	udp_port := next_port(r)
	srv, started := start_server_raw(r, list_memory_config(udp_port, list_path, 2), udp_port, env = env)
	if !started {
		return
	}
	defer stop_server(&srv)
	if !check(r, wait_ready(&srv, 60 * time.Second), "the server never became ready; log:\n%s", read_log(&srv)) {
		return
	}
	start, ok = proc_status_int(srv.process.pid, "VmRSS")
	if !check(r, ok, "cannot read the server's VmRSS") {
		return
	}

	for i in 1 ..= MEMORY_RELOADS {
		reloaded := reload_to(r, &srv, list_memory_config(udp_port, list_path, 2 + i % 2), "block rules (", 60 * time.Second)
		if !check(r, reloaded, "reload %d never finished; log:\n%s", i, read_log(&srv)) {
			return start, 0, false
		}
	}
	end, ok = proc_status_int(srv.process.pid, "VmRSS")
	check(r, ok, "cannot read the server's VmRSS")
	return
}

run_list_memory_cases :: proc(r: ^Runner) {
	NAME :: "lists: a rebuild under the shipped unit's environment gives the old sets' memory back"

	// Its failure is already a setup failure, and a skip would count it twice.
	unit_env, unit_ok := unit_environment(r)
	if !unit_ok {
		return
	}

	if built_with_asan(r, NAME) {
		return
	}

	// Heap: the deferred removal runs after `end_case` has reset the temp
	// allocator.
	list_path := filepath.join({r.work_dir, "list-memory.txt"}, context.allocator) or_else ""
	defer delete(list_path)
	b := strings.builder_make(context.allocator)
	for i in 0 ..< MEMORY_RULES {
		fmt.sbprintfln(&b, "0.0.0.0 host%07d.sub%d.example-blocked-domain.test", i, i % 97)
	}
	werr := os.write_entire_file(list_path, b.buf[:])
	strings.builder_destroy(&b)
	if werr != nil {
		fail(r, "%s: cannot write %s: %v", NAME, list_path, werr)
		return
	}
	defer os.remove(list_path)

	control, shipped, env_ok := glibc_environments(r, NAME, unit_env[:])
	if !env_ok {
		return
	}

	start_case(r, NAME)
	c0, c1, cok := rss_across_rebuilds(r, control[:], list_path)
	// The premise: the defaults keep a rebuild's peak, here at least half as
	// much again as the process started with.
	premise :=
		cok &&
		check(
			r,
			c1 * 2 >= c0 * 3,
			"without the unit's environment RSS went only %d -> %d KiB over %d rebuilds, so this cannot tell whether the unit's setting works; move MEMORY_RULES back to a size glibc keeps",
			c0,
			c1,
			MEMORY_RELOADS,
		)
	if premise {
		if u0, u1, uok := rss_across_rebuilds(r, shipped[:], list_path); uok {
			check(
				r,
				u1 * 4 <= u0 * 5,
				"RSS went %d -> %d KiB over %d rebuilds with the unit's environment %v (%d -> %d KiB without it)",
				u0,
				u1,
				MEMORY_RELOADS,
				unit_env[:],
				c0,
				c1,
			)
		}
	}
	end_case(r)
}

/*
A connection costs a fiber and not a thread, and its memory is given back when it
closes (#526, #547).

Every TCP connection answers on a fiber of one of the server's loops, so holding
CONN_BURST of them adds no threads at all - the premise of everything else here,
read off `/proc/<pid>/status` - and costs what the fiber touched of its stack and
its scratch. Both are mapped by elodin rather than taken from libc, whose 256 KiB
`calloc` per arena glibc memsets in full and keeps; elodin also turns transparent
huge pages off for itself, which would otherwise back a touched page of either
with 2 MB (only where the kernel has them on).

The case holds CONN_BURST connections open with one query answered on each,
counted by the server's own descriptors, then closes them and waits for those to
go, reading the server's VmRSS at each step. Both figures are held to a few times
what was measured here (~29 KB a held connection, ~5 KB of each left behind) and
well under the 275 KB of each the calloc costs. What stays after the close is
the few stacks each loop keeps warm through a quiet spell
(`loop.WARM_IDLE_KEEP`), which is a figure per loop rather than per connection.
*/
@(private = "file")
CONN_BURST :: 200
@(private = "file")
HELD_KIB_PER_CONN :: 64
@(private = "file")
KEPT_KIB_PER_CONN :: 32
@(private = "file")
KEPT_HUGE_KIB :: 2048

// Descriptors the process holds open, counted off /proc/<pid>/fd.
@(private = "file")
open_descriptors :: proc(pid: int) -> (n: int, ok: bool) {
	dir, err := os.open(fmt.tprintf("/proc/%d/fd", pid))
	if err != nil {
		return 0, false
	}
	defer os.close(dir)
	entries, rerr := os.read_dir(dir, -1, context.temp_allocator)
	if rerr != nil {
		return 0, false
	}
	return len(entries), true
}

// The process's huge pages in KiB, summed over its mappings by the kernel.
@(private = "file")
anon_huge_kib :: proc(pid: int) -> (kib: int, ok: bool) {
	value := proc_status_field(fmt.tprintf("/proc/%d/smaps_rollup", pid), "AnonHugePages") or_return
	return strconv.parse_int(strings.trim_space(strings.trim_suffix(value, "kB")))
}

run_connection_memory_cases :: proc(r: ^Runner) {
	NAME :: "conns: a burst of TCP connections under the shipped unit's environment gives their memory back on close"

	unit_env, unit_ok := unit_environment(r)
	if !unit_ok || built_with_asan(r, NAME) {
		return
	}
	_, shipped, env_ok := glibc_environments(r, NAME, unit_env[:])
	if !env_ok {
		return
	}

	start_case(r, NAME)
	defer end_case(r)
	udp_port := next_port(r)
	tcp_port := next_port(r)
	config := fmt.tprintf(
		`log: {{ level: info }}
listeners:
  udp: {{ enabled: true, address: "127.0.0.1", port: %d }}
  tcp: {{ enabled: true, address: "127.0.0.1", port: %d }}
server:
  max_connections: %d
  max_connections_per_prefix: %d
  rate_limit: {{ enabled: false }}
upstream:
  servers: ["127.0.0.1:1"]
cache: {{ enabled: false }}
blocking: {{ enabled: false }}
`,
		udp_port,
		tcp_port,
		CONN_BURST * 2,
		CONN_BURST * 2,
	)
	srv, started := start_server_raw(r, config, udp_port, env = shipped)
	if !started {
		return
	}
	defer stop_server(&srv)
	if !check(r, wait_ready(&srv, 10 * time.Second) && wait_tcp(tcp_port, 10 * time.Second), "the server never became ready; log:\n%s", read_log(&srv)) {
		return
	}
	pid := srv.process.pid
	// The premise of the huge-page bound, which a host with THP `never` passes
	// whatever the server does: the server turned them off for itself.
	thp, thp_ok := proc_status_int(pid, "THP_enabled")
	if !check(r, thp_ok && thp == 0, "the server's THP_enabled is %d (read %v), not 0", thp, thp_ok) {
		return
	}
	base, bok := proc_status_int(pid, "VmRSS")
	threads0, tok := proc_status_int(pid, "Threads")
	fds0, fok := open_descriptors(pid)
	if !check(r, bok && tok && fok, "cannot read the server's status") {
		return
	}

	// Answered locally, so every connection's thread runs a query through its
	// scratch arena without an upstream.
	query := build_query("version.bind.", u16(dns.Type.TXT), class = u16(dns.Class.CH))
	sockets := make([dynamic]net.TCP_Socket, 0, CONN_BURST, context.temp_allocator)
	defer for s in sockets {
		net.close(s)
	}
	for _ in 0 ..< CONN_BURST {
		socket, err := net.dial_tcp_from_endpoint(net.Endpoint{address = net.IP4_Loopback, port = tcp_port})
		if !check(r, err == nil, "dial %d: %v", len(sockets), err) {
			return
		}
		_ = net.set_option(socket, .Receive_Timeout, CLIENT_TIMEOUT)
		_ = net.set_option(socket, .Send_Timeout, CLIENT_TIMEOUT)
		append(&sockets, socket)
		conn := Test_Conn {
			socket = socket,
		}
		if !check(r, stream_query(&conn, query, context.temp_allocator).ok, "connection %d was not answered; log:\n%s", len(sockets), read_log(&srv)) {
			return
		}
	}
	held, hok := proc_status_int(pid, "VmRSS")
	threads1, _ := proc_status_int(pid, "Threads")
	fds1, _ := open_descriptors(pid)
	// The premise: the server is holding every connection - one descriptor
	// each. One short, as `wait_tcp`'s probe may still have been in the first
	// reading.
	if !check(r, hok && fds1 >= fds0 + CONN_BURST - 1, "descriptors went %d -> %d holding %d connections", fds0, fds1, CONN_BURST) {
		return
	}
	// And held on the loops' threads, not on threads of their own.
	if !check(r, threads1 <= threads0, "threads went %d -> %d holding %d connections", threads0, threads1, CONN_BURST) {
		return
	}

	for s in sockets {
		net.close(s)
	}
	clear(&sockets)
	// Until the server has closed its ends, which is when the fibers have
	// returned and their scratch is unmapped. The bound only ends a failing run.
	fds2 := fds1
	for start := time.tick_now(); fds2 > fds0 && time.tick_since(start) < 10 * time.Second; {
		time.sleep(20 * time.Millisecond)
		fds2, _ = open_descriptors(pid)
	}
	if !check(r, fds2 <= fds0, "descriptors still at %d (from %d) after the connections closed", fds2, fds0) {
		return
	}
	/*
	And until the loops have given back the stacks they kept warm, which they do
	after a second with nothing to do (`loop.TRIM_AFTER`). Read until the figure
	is inside the bound; the deadline only ends a failing run, which then reports
	the last reading.
	*/
	after, aok := proc_status_int(pid, "VmRSS")
	for start := time.tick_now(); aok && after - base > CONN_BURST * KEPT_KIB_PER_CONN && time.tick_since(start) < 5 * time.Second; {
		time.sleep(100 * time.Millisecond)
		after, aok = proc_status_int(pid, "VmRSS")
	}
	huge, sok := anon_huge_kib(pid)
	if !check(r, aok && sok, "cannot read the server's VmRSS or smaps") {
		return
	}
	check(
		r,
		held - base <= CONN_BURST * HELD_KIB_PER_CONN,
		"holding %d answered connections took RSS %d -> %d KiB, past %d KiB each",
		CONN_BURST,
		base,
		held,
		HELD_KIB_PER_CONN,
	)
	check(
		r,
		after - base <= CONN_BURST * KEPT_KIB_PER_CONN,
		"after %d connections closed RSS is %d KiB from %d (%d KiB while held), past %d KiB each",
		CONN_BURST,
		after,
		base,
		held,
		KEPT_KIB_PER_CONN,
	)
	check(r, huge <= KEPT_HUGE_KIB, "%d KiB of huge pages after the burst", huge)
}
