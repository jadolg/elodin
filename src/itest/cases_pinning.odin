package itest

import "core:fmt"
import "core:slice"
import "core:strconv"
import "core:time"
import "elodin:config"
import "elodin:loop"

/*
`server.pin_loops` against the running binary (#610): with it each event loop's
thread is allowed one CPU, a different one per loop, and without it no thread is
held to one.

Read from each thread's `Cpus_allowed_list`, the affinity the scheduler places it
by. The loops are the threads to look for because nothing else in the server is
pinned: a thread allowed exactly one CPU, on a run allowed more, is a loop.
*/

// Without `pin`, the file does not name `pin_loops`, so the default is what runs.
@(private = "file")
config_pinning :: proc(udp_port, upstream_port, readers: int, pin: bool) -> string {
	return fmt.tprintf(
		`log: {{ level: info }}
%s
listeners:
  udp: {{ enabled: true, address: "127.0.0.1", port: %d, readers: %d }}
  tcp: {{ enabled: false }}
upstream:
  timeout: 3s
  servers: ["127.0.0.1:%d"]
cache: {{ enabled: false }}
blocking: {{ enabled: false }}
`,
		"server: { pin_loops: true }" if pin else "",
		udp_port,
		readers,
		upstream_port,
	)
}

// The CPU of each of `pid`'s threads that is allowed exactly one, sorted.
@(private = "file")
pinned_thread_cpus :: proc(pid: int) -> (cpus: []int, ok: bool) {
	ids := task_ids(pid) or_return
	found := make([dynamic]int, context.temp_allocator)
	for id in ids {
		list, read := proc_status_field(fmt.tprintf("/proc/%d/task/%s/status", pid, id), "Cpus_allowed_list")
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

/*
The pinned threads' CPUs once they equal `want`, or as they last stood when
`PIN_WAIT` ran out. Each loop pins itself on its own thread, and the server
answering is not ordered after every loop has done so.
*/
@(private = "file")
PIN_WAIT :: 5 * time.Second

@(private = "file")
wait_pinned :: proc(pid: int, want: []int) -> (cpus: []int, ok: bool) {
	start := time.tick_now()
	for {
		cpus, ok = pinned_thread_cpus(pid)
		if !ok || slice.equal(cpus, want) || time.tick_since(start) >= PIN_WAIT {
			return
		}
		time.sleep(10 * time.Millisecond)
	}
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
			cpus, read := wait_pinned(srv.process.pid, allowed[:2])
			if check(r, read, "the server's threads could not be listed") {
				check(r, slice.equal(cpus, allowed[:2]), "pinned threads are on CPUs %v, not one loop on each of %v", cpus, allowed[:2])
			}
			check(r, log_contains(&srv, "pinning the event loops to CPUs"), "startup did not say where the loops run; log:\n%s", read_log(&srv))
		}
	}
	end_case(r)

	/*
	Two loops pinned to one CPU would queue behind each other for good, so with
	more loops than CPUs none is pinned. The warning is what decides it: it is
	written before any loop's thread starts. The thread list is a second look.
	*/
	if len(allowed) >= config.MAX_UDP_READERS {
		skip_case(r, "server.pin_loops: with more loops than CPUs, none is pinned", "one loop past this run's CPUs is past the most listeners.udp.readers takes")
	} else {
		start_case(r, "server.pin_loops: with more loops than CPUs, none is pinned")
		udp_port := next_port(r)
		srv, ok := start_server(r, Server_Options{config = config_pinning(udp_port, upstream_port, len(allowed) + 1, true), udp_port = udp_port})
		if check(r, ok, "server did not start") {
			defer stop_server(&srv)
			check(r, query_udp(udp_port, build_query("pin.example.", 1, id = 0x611, allocator = context.temp_allocator), context.temp_allocator).ok, "a query was not answered")
			cpus, read := pinned_thread_cpus(srv.process.pid)
			if check(r, read, "the server's threads could not be listed") {
				check(r, len(cpus) == 0, "threads are pinned to CPUs %v with more loops than CPUs", cpus)
			}
			check(r, log_contains(&srv, "the event loops run unpinned"), "startup did not warn that the loops run unpinned; log:\n%s", read_log(&srv))
		}
		end_case(r)
	}

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
			check(r, !log_contains(&srv, "server.pin_loops"), "startup spoke of pinning with pin_loops off; log:\n%s", read_log(&srv))
		}
	}
	end_case(r)
}
