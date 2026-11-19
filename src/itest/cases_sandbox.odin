package itest

import "core:fmt"
import "core:os"
import "core:strings"
import "core:sys/linux"
import "core:time"

/*
`server.sandbox` on the shipped binary (#417): which layers each mode puts on
every thread of the process, as each thread's `status` under `/proc` shows
them, what
the startup line says about Landlock against what this kernel offers, and that
a reload cannot take the sandbox off. The rest of the suite runs under `strict`
(`with_sandbox`, `suite_sandbox`), which is what shows the allowlist and the Landlock
rules cover the paths a serving process takes.
*/
run_sandbox_cases :: proc(r: ^Runner) {
	own_filters, own_read := proc_status_int(os.get_pid(), "Seccomp_filters")
	if !own_read {
		skip_case(r, "server.sandbox", "this kernel reports no Seccomp_filters in /proc")
		return
	}
	abi := max(linux.syscall(linux.SYS_landlock_create_ruleset, uintptr(0), uintptr(0), uintptr(1)), 0)

	Case :: struct {
		name, setting: string,
	}
	cases := []Case {
		// Left to the harness: `suite_sandbox`.
		{name = "server.sandbox unset in the suite: the harness's mode is the one in force (#417)"},
		{name = "server.sandbox strict: every thread runs under no_new_privs and one more filter (#417)", setting = "strict"},
		{name = "server.sandbox basic: every thread runs under no_new_privs and no filter of its own (#417)", setting = "basic"},
		{name = "server.sandbox off: no thread is narrowed and nothing is said (#417)", setting = "off"},
	}
	for c in cases {
		mode := c.setting if c.setting != "" else suite_sandbox(r)
		if mode == "strict" && r.asan {
			skip_case(r, c.name, "LeakSanitizer's exit makes calls the allowlist does not have (see `suite_sandbox`)")
			continue
		}
		start_case(r, c.name)
		defer end_case(r)
		// What every thread's status says.
		no_new_privs := 0 if mode == "off" else 1
		filters := own_filters + 1 if mode == "strict" else own_filters

		udp_port := next_port(r)
		extra := fmt.tprintf("server:\n  sandbox: %s", c.setting) if c.setting != "" else ""
		config := base_config(udp_port, upstream_at(next_port(r)), log = "{ level: info }", extra = extra)
		srv, ok := start_server(r, Server_Options{config = config, udp_port = udp_port})
		if !ok {
			continue
		}
		defer stop_server(&srv)
		if !check(r, wait_for_log(&srv, "msg=ready", 5 * time.Second), "the server never logged ready:\n%s", read_log(&srv)) {
			continue
		}

		if mode != "off" {
			line := fmt.tprintf("msg=sandbox mode=%s no_new_privs=true landlock_abi=%d seccomp=%v", mode, abi, mode == "strict")
			check(r, strings.contains(read_log(&srv), line), "no %q in the log:\n%s", line, read_log(&srv))
		} else {
			check(r, !strings.contains(read_log(&srv), "msg=sandbox"), "a sandbox line with the sandbox off:\n%s", read_log(&srv))
		}
		expect_every_thread(r, srv.process.pid, no_new_privs, filters)

		if c.setting != "strict" {
			continue
		}
		// Changed to off in the file: named, held, and every thread as it was.
		off := base_config(udp_port, upstream_at(next_port(r)), log = "{ level: info }", extra = "server:\n  sandbox: off")
		if check(r, reload_to(r, &srv, off, "server.sandbox changed, which takes a restart"), "the change was not named:\n%s", read_log(&srv)) {
			expect_every_thread(r, srv.process.pid, no_new_privs, filters)
		}
	}
}

// Every thread of `pid` - more than the main one, or there is nothing to say
// about the others - shows `no_new_privs` and `filters` in its status.
@(private = "file")
expect_every_thread :: proc(r: ^Runner, pid: int, no_new_privs, filters: int) {
	ids, listed := task_ids(pid)
	if !check(r, listed && len(ids) > 1, "the threads of %d could not be listed, or there is only one: %v", pid, ids) {
		return
	}
	for id in ids {
		task := fmt.tprintf("task/%s/status", id)
		nnp, nnp_read := proc_status_int(pid, "NoNewPrivs", task)
		count, count_read := proc_status_int(pid, "Seccomp_filters", task)
		if !nnp_read || !count_read {
			continue // a thread that has just ended
		}
		check(r, nnp == no_new_privs, "thread %s: NoNewPrivs %d, want %d", id, nnp, no_new_privs)
		check(r, count == filters, "thread %s: Seccomp_filters %d, want %d", id, count, filters)
	}
}
