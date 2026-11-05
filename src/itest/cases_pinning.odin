package itest

import "core:fmt"
import "core:os"
import "core:slice"
import "core:strconv"
import "elodin:loop"

/*
`server.pin_loops` against the running binary (#610): with it each event loop's
thread is allowed one CPU, a different one per loop, and without it no thread is
held to one.

Read from each thread's `Cpus_allowed_list`, the affinity the scheduler places it
by. The loops are the threads to look for because nothing else in the server is
pinned: a thread allowed exactly one CPU, on a run allowed more, is a loop.
*/

@(private = "file")
config_pinning :: proc(udp_port, upstream_port, readers: int, pin: bool) -> string {
	return fmt.tprintf(
		`log: {{ level: info }}
server: {{ pin_loops: %v }}
listeners:
  udp: {{ enabled: true, address: "127.0.0.1", port: %d, readers: %d }}
  tcp: {{ enabled: false }}
upstream:
  timeout: 3s
  servers: ["127.0.0.1:%d"]
cache: {{ enabled: false }}
blocking: {{ enabled: false }}
`,
		pin,
		udp_port,
		readers,
		upstream_port,
	)
}

// The CPU of each of `pid`'s threads that is allowed exactly one, sorted.
@(private = "file")
pinned_thread_cpus :: proc(pid: int) -> (cpus: []int, ok: bool) {
	entries, err := os.read_directory_by_path(fmt.tprintf("/proc/%d/task", pid), -1, context.temp_allocator)
	if err != nil {
		return
	}
	found := make([dynamic]int, context.temp_allocator)
	for e in entries {
		list, read := proc_status_field(fmt.tprintf("/proc/%d/task/%s/status", pid, e.name), "Cpus_allowed_list")
		if !read {
			continue // a thread that has just ended
		}
		// "3" is one CPU; "0-3" or "0,2" is more.
		if cpu, single := strconv.parse_int(list, 10); single {
			append(&found, cpu)
		}
	}
	slice.sort(found[:])
	return found[:], true
}

run_pinning_cases :: proc(r: ^Runner) {
	allowed := loop.allowed_cpus(context.temp_allocator)
	if len(allowed) < 2 {
		skip_case(r, "server.pin_loops", "this run may use fewer than two CPUs, so a pinned thread looks like any other")
		return
	}
	upstream_port := next_port(r)
	mock := mock_make("pinning", upstream_port)
	mock_synth_all(mock, {203, 0, 113, 45})
	if !mock_start(mock) {
		skip_case(r, "server.pin_loops", "cannot start the mock upstream")
		return
	}
	defer mock_stop(mock)

	start_case(r, "server.pin_loops: each event loop is held to a CPU of its own")
	{
		udp_port := next_port(r)
		srv, ok := start_server(r, Server_Options{config = config_pinning(udp_port, upstream_port, 2, true), udp_port = udp_port})
		if check(r, ok, "server did not start") {
			defer stop_server(&srv)
			check(r, query_udp(udp_port, build_query("pin.example.", 1, id = 0x610, allocator = context.temp_allocator), context.temp_allocator).ok, "a query was not answered")
			cpus, read := pinned_thread_cpus(srv.process.pid)
			if check(r, read, "the server's threads could not be listed") {
				check(r, slice.equal(cpus, allowed[:2]), "pinned threads are on CPUs %v, not one loop on each of %v", cpus, allowed[:2])
			}
			check(r, log_contains(&srv, "the event loops run on CPUs"), "startup did not say where the loops run; log:\n%s", read_log(&srv))
		}
	}
	end_case(r)

	start_case(r, "server.pin_loops: off by default, no thread is held to one CPU")
	{
		udp_port := next_port(r)
		srv, ok := start_server(r, Server_Options{config = config_pinning(udp_port, upstream_port, 2, false), udp_port = udp_port})
		if check(r, ok, "server did not start") {
			defer stop_server(&srv)
			cpus, read := pinned_thread_cpus(srv.process.pid)
			if check(r, read, "the server's threads could not be listed") {
				check(r, len(cpus) == 0, "threads are pinned to CPUs %v with pin_loops off", cpus)
			}
		}
	}
	end_case(r)
}
