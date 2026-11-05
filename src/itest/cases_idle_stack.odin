package itest

import "base:runtime"
import "core:fmt"
import "core:net"
import "core:os"
import "core:strconv"
import "core:strings"
import "core:sys/posix"
import "core:time"
import "elodin:dns"

/*
A held connection between queries keeps only the stack its parked frames are on
(#596).

Each stream connection is a fiber of its own, parked in its read between
queries. A query takes it many pages deeper than that park, and left resident
those pages are most of what a held connection costs. The loop hands them back
once an idle connection has been parked for `loop.IDLE_TRIM_AFTER`
(`loop.set_idle`).

Read from smaps: a fiber stack is an anonymous mapping of `loop.STACK_SIZE`, and
each held connection adds one. The case holds `IDLE_HELD` connections per
transport, each answered once, and counts the stacks resident past
`IDLE_STACK_KIB`. A stack that a finished fiber leaves to the loop's cache is
kept warm on purpose, so up to `IDLE_WARM` of them may be over. A connection's own stack never may, so a server that
keeps them has every held connection over.
*/
@(private = "file")
IDLE_HELD :: 200

// 256 KiB: `loop.STACK_SIZE` outside AddressSanitizer, which this case skips.
@(private = "file")
STACK_KIB :: 256

/*
What an idle connection's stack may keep: the frames it is parked under. Two
4 KiB pages on every transport in the debug build this suite runs, one in the
release build; a query takes the stack to 20 KiB and more. Raised to two of the
kernel's pages on a 16 or 64 KiB-page kernel, where the page the stack pointer is
in stays resident whole.
*/
@(private = "file")
IDLE_STACK_KIB :: 8

// Warm stacks a finished fiber may leave; a loop trims to `loop.WARM_IDLE_KEEP` within seconds.
@(private = "file")
IDLE_WARM :: 64

@(private = "file")
Idle_Transport :: enum {
	TCP,
	DoT,
	DoH_HTTP1,
	DoH_H2,
}

run_idle_stack_cases :: proc(r: ^Runner) {
	NAME :: "conns: an idle stream connection gives back the stack its query touched"
	if built_with_asan(r, NAME, "the binary is built with AddressSanitizer, whose fiber stacks are four times the size and whose frames carry redzones") {
		return
	}
	start_case(r, NAME)
	defer end_case(r)

	udp_port := next_port(r)
	tcp_port := next_port(r)
	dot_port := next_port(r)
	doh_port := next_port(r)
	config := fmt.tprintf(
		`log: {{ level: info }}
listeners:
  udp: {{ enabled: true, address: "127.0.0.1", port: %d, readers: 1 }}
  tcp: {{ enabled: true, address: "127.0.0.1", port: %d }}
  dot: {{ enabled: true, address: "127.0.0.1", port: %d, cert_file: %s, key_file: %s }}
  doh: {{ enabled: true, address: "127.0.0.1", port: %d, path: /dns-query, cert_file: %s, key_file: %s }}
server:
  client_timeout: 60s
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
		dot_port,
		r.cert_file,
		r.key_file,
		doh_port,
		r.cert_file,
		r.key_file,
		IDLE_HELD * 2,
		IDLE_HELD * 2,
	)
	srv, started := start_server(
		r,
		Server_Options {
			config = config,
			udp_port = udp_port,
			tcp_port = tcp_port,
			dot_port = dot_port,
			doh_port = doh_port,
		},
	)
	if !started {
		return
	}
	defer stop_server(&srv)
	pid := srv.process.pid
	bound_kib := max(IDLE_STACK_KIB, 2 * int(posix.sysconf(._PAGESIZE)) / 1024)

	// Answered locally, so the query runs the whole answer path with no upstream.
	query := build_query("version.bind.", u16(dns.Type.TXT), class = u16(dns.Class.CH))
	for transport in Idle_Transport {
		conns := make([dynamic]Test_Conn, 0, IDLE_HELD, context.temp_allocator)
		defer for &c in conns {
			close_tls(&c)
			net.close(c.socket)
		}
		for _ in 0 ..< IDLE_HELD {
			c, answered := idle_hold_one(transport, tcp_port, dot_port, doh_port, query)
			// A dial that failed has no socket, and closing its zero one closes fd 0.
			if c.socket != 0 {
				append(&conns, c)
			}
			// The log is read only on a failure: an argument is read on every call.
			if !answered {
				fail(r, "%v connection %d was not answered; log:\n%s", transport, len(conns), read_log(&srv))
				return
			}
		}
		/*
		Read until the figure is inside the bound, since the stacks go back
		`loop.IDLE_TRIM_AFTER` into the wait; the deadline only ends a failing
		run, which then reports the last reading. `client_timeout` is set far
		past the time the connections take to open, which on a loaded host is
		seconds, so none of the connections being measured is closed for idling.
		*/
		held, over, hok := fiber_stacks(pid, bound_kib)
		for start := time.tick_now(); hok && over > IDLE_WARM && time.tick_since(start) < 5 * time.Second; {
			time.sleep(100 * time.Millisecond)
			held, over, hok = fiber_stacks(pid, bound_kib)
		}
		if !check(r, hok, "cannot read the server's smaps") {
			return
		}
		// The premise: every held connection is parked on a stack of its own. The
		// last transport's connections may have left theirs to the cache, where
		// this one's took them up again, so the count is of all of them.
		if !check(r, held >= IDLE_HELD, "%v: %d fiber stacks holding %d connections", transport, held, IDLE_HELD) {
			return
		}
		check(
			r,
			over <= IDLE_WARM,
			"%v: %d of %d fiber stacks hold more than %d KiB with %d idle connections",
			transport,
			over,
			held,
			bound_kib,
			IDLE_HELD,
		)
	}
}

// One connection of `transport`, asked `query` once and left open.
@(private = "file")
idle_hold_one :: proc(transport: Idle_Transport, tcp_port, dot_port, doh_port: int, query: []u8) -> (c: Test_Conn, ok: bool) {
	switch transport {
	case .TCP:
		socket, err := net.dial_tcp_from_endpoint(net.Endpoint{address = net.IP4_Loopback, port = tcp_port})
		if err != nil {
			return {}, false
		}
		_ = net.set_option(socket, .Receive_Timeout, CLIENT_TIMEOUT)
		c = Test_Conn{socket = socket}
		return c, stream_query(&c, query, context.temp_allocator).ok
	case .DoT:
		c = dial_tls(dot_port) or_return
		return c, stream_query(&c, query, context.temp_allocator).ok
	case .DoH_HTTP1:
		c = dial_tls(doh_port, []string{"http/1.1"}) or_return
		if !conn_write(&c, build_http_request("POST", "/dns-query", "application/dns-message", query)) {
			return c, false
		}
		res := read_http_response(&c, context.temp_allocator)
		return c, res.ok && res.status == 200
	case .DoH_H2:
		h := h2_connect(doh_port) or_return
		c = h.conn
		return c, h2_send_get(h, 1, "/dns-query", query) && h2_collect(h, {1})
	}
	return
}

/*
The server's fiber stacks, and how many of them are resident past
`bound_kib`: anonymous mappings of `STACK_KIB`, read from smaps. Nothing else
the server maps is that size and anonymous; the guard page below each is a
mapping of its own.
*/
@(private = "file")
fiber_stacks :: proc(pid: int, bound_kib: int) -> (count, over: int, ok: bool) {
	// Polled until the stacks go back, and the temp allocator is reset only when
	// the case ends: each reading's file and fields go when it returns.
	runtime.DEFAULT_TEMP_ALLOCATOR_TEMP_GUARD()
	data, err := os.read_entire_file(fmt.tprintf("/proc/%d/smaps", pid), context.temp_allocator)
	if err != nil {
		return 0, 0, false
	}
	text := string(data)
	anonymous := false
	size := 0
	for line in strings.split_lines_iterator(&text) {
		fields := strings.fields(line, context.temp_allocator)
		if len(fields) == 0 {
			continue
		}
		switch {
		case strings.contains_rune(fields[0], '-') && !strings.has_suffix(fields[0], ":"):
			// A mapping's header: address range, perms, offset, device, inode, path.
			anonymous = len(fields) == 5
			size = 0
		case fields[0] == "Size:" && len(fields) >= 2:
			size, _ = strconv.parse_int(fields[1])
		case fields[0] == "Rss:" && len(fields) >= 2 && anonymous && size == STACK_KIB:
			rss, _ := strconv.parse_int(fields[1])
			count += 1
			over += 1 if rss > bound_kib else 0
		}
	}
	return count, over, true
}
