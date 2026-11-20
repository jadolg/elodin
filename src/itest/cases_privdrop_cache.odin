package itest

import "core:fmt"
import "core:os"
import "core:path/filepath"
import "core:strings"
import "core:sys/posix"
import "elodin:dns"

/*
Issue #688: started as root with `server.user` set, elodin hands the blocklist
cache directory to the account before the drop. The directory is the account's
after the first start, so anything running as it can put a hard link to a file
elsewhere in there, and a chown of that link as root would hand the file over
too. The directory alone is handed over, and each copy elodin caches is the
account's as it is written.

The link is made as root here, which `fs.protected_hardlinks` allows; the
account making it is not what the case is about.
*/
run_privdrop_cache_cases :: proc(r: ^Runner) {
	NAME :: "privdrop: a hard link in the blocklist cache keeps the owner of the file it links to (#688)"
	if posix.geteuid() != 0 {
		skip_case(r, NAME, "starting as root and dropping to nobody needs root")
		return
	}

	http_port := next_port(r)
	http := http_mock_make(http_port)
	http_mock_serve(http, "/hosts.txt", "0.0.0.0 cached.test\n")
	http_mock_serve(http, "/later.txt", "0.0.0.0 later.test\n")
	http_ok := http_mock_start(http)
	defer http_mock_stop(http)
	if !http_ok {
		skip_case(r, NAME, "cannot start the HTTP mock")
		return
	}

	start_case(r, NAME)
	defer end_case(r)
	cache_dir := filepath.join({r.work_dir, "privcache"}, context.temp_allocator) or_else ""
	outside := filepath.join({r.work_dir, "privcache-outside"}, context.temp_allocator) or_else ""
	if !check(r, os.make_directory(cache_dir) == nil, "cannot make %s", cache_dir) {
		return
	}
	if !write_fixture(r, outside, transmute([]u8)string("root's own\n")) {
		return
	}
	link := fmt.ctprintf("%s/x.list", cache_dir)
	if !check(r, posix.link(strings.clone_to_cstring(outside, context.temp_allocator), link) == .OK, "cannot link %s into the cache", outside) {
		return
	}

	udp_port := next_port(r)
	conf := base_config(
		udp_port,
		upstream_at(next_port(r)),
		log = "{ level: info }",
		blocking = fmt.tprintf(`{{ enabled: true, cache_dir: %q, lists: ["http://127.0.0.1:%d/hosts.txt"] }}`, cache_dir, http_port),
		extra = "server: { user: nobody }",
	)
	srv, ok := start_server(r, Server_Options{config = conf, udp_port = udp_port, allow_fetch = true})
	if !ok {
		return
	}
	defer stop_server(&srv)

	owner := proc(path: string) -> (uid: posix.uid_t, ok: bool) {
		st: posix.stat_t
		if posix.stat(strings.clone_to_cstring(path, context.temp_allocator), &st) != .OK {
			return 0, false
		}
		return st.st_uid, true
	}
	// The positive half: the directory itself was handed over.
	if dir_uid, read := owner(cache_dir); check(r, read, "cannot stat %s", cache_dir) {
		check(r, dir_uid != 0, "the cache directory was not handed over: still uid %d", dir_uid)
	}
	if out_uid, read := owner(outside); check(r, read, "cannot stat %s", outside) {
		check(r, out_uid == 0, "the file the link points at was given to uid %d", out_uid)
	}
	// And what elodin wrote there itself was handed over with the directory.
	entries, rerr := os.read_directory_by_path(cache_dir, -1, context.temp_allocator)
	if check(r, rerr == nil, "cannot list %s: %v", cache_dir, rerr) {
		own := 0
		for entry in entries {
			if entry.name == "x.list" {
				continue
			}
			own += 1
			if uid, read := owner(entry.fullpath); check(r, read, "cannot stat %s", entry.fullpath) {
				check(r, uid != 0, "%s, which elodin wrote, was not handed over", entry.name)
			}
		}
		check(r, own > 0, "elodin cached nothing in %s", cache_dir)
	}

	/*
	A download after the drop, under the suite's strict sandbox: the account
	writes its own copy, so nothing calls `fchown`, which the sandbox kills the
	process for.
	*/
	later := base_config(
		udp_port,
		upstream_at(next_port(r)),
		log = "{ level: info }",
		blocking = fmt.tprintf(
			`{{ enabled: true, cache_dir: %q, lists: ["http://127.0.0.1:%d/hosts.txt", "http://127.0.0.1:%d/later.txt"] }}`,
			cache_dir,
			http_port,
			http_port,
		),
		extra = "server: { user: nobody }",
	)
	if check(r, reload_to(r, &srv, later, "later.txt: 1 rules"), "the reload never downloaded the second list:\n%s", read_log(&srv)) {
		res := query_udp(udp_port, build_query("later.test.", u16(dns.Type.A)))
		check(r, res.ok, "no answer after a download as the account; log:\n%s", read_log(&srv))
	}
}
