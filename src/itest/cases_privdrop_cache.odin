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
account's, as the account writes it after the drop (#755).

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

	// `nobody` has to reach the cache after the drop: not through a work
	// directory a 077 umask or a private TMPDIR made root's alone.
	if !traversable_by_all(r.work_dir) {
		skip_case(r, NAME, "nobody cannot reach the work directory")
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
	/*
	A fresh copy of hosts.txt that only root can read: the account, which
	reads the cache (#755), cannot load it, so the list is downloaded over it
	rather than lost.
	*/
	unreadable := fmt.tprintf("%s/http___127.0.0.1_%d_hosts.txt.list", cache_dir, http_port)
	if !write_fixture(r, unreadable, transmute([]u8)string("0.0.0.0 stale.test\n")) {
		return
	}
	if !check(r, posix.chmod(strings.clone_to_cstring(unreadable, context.temp_allocator), {.IRUSR, .IWUSR}) == .OK, "cannot make %s root's alone", unreadable) {
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
	// Whatever uid `nobody` is here: 65534 on most systems, 99 on older ones.
	account := posix.getpwnam("nobody")
	if !check(r, account != nil, "there is no nobody account") {
		return
	}
	nobody_uid := account.pw_uid
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
	check(r, http_mock_hits(http, "/hosts.txt") == 1, "a copy the account cannot read was taken as fresh:\n%s", read_log(&srv))
	blocked := query_udp(udp_port, build_query("cached.test.", u16(dns.Type.A)))
	if check(r, blocked.ok, "no answer for cached.test") {
		check(r, parse_header(r, blocked.wire).rcode == int(dns.Rcode.NX_Domain), "the list downloaded in place of the unreadable copy was not applied")
	}
	// The positive half: the directory itself was handed over.
	if dir_uid, read := owner(cache_dir); check(r, read, "cannot stat %s", cache_dir) {
		check(r, dir_uid == nobody_uid, "the cache directory is uid %d's, not nobody's (%d)", dir_uid, nobody_uid)
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
				check(r, uid == nobody_uid, "%s, which elodin wrote, is uid %d's, not nobody's (%d)", entry.name, uid, nobody_uid)
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
		if check(r, res.ok, "no answer after a download as the account; log:\n%s", read_log(&srv)) {
			check(r, parse_header(r, res.wire).rcode == int(dns.Rcode.NX_Domain), "the list downloaded after the drop was not applied")
		}
		// The copy was written, by the account: the write after the drop is
		// what reached the `fchown` this case exists for.
		cached := false
		after, aerr := os.read_directory_by_path(cache_dir, -1, context.temp_allocator)
		if check(r, aerr == nil, "cannot list %s: %v", cache_dir, aerr) {
			for entry in after {
				if !strings.contains(entry.name, "later.txt") {
					continue
				}
				cached = true
				if uid, read := owner(entry.fullpath); check(r, read, "cannot stat %s", entry.fullpath) {
					check(r, uid == nobody_uid, "%s, written after the drop, is uid %d's, not nobody's (%d)", entry.name, uid, nobody_uid)
				}
			}
		}
		check(r, cached, "the list downloaded after the drop was not cached")
	}

	/*
	After the drop the process is the account, and reads nothing through a
	link it could not by name: a copy that is a hard link - as a backup tool
	that links its snapshots leaves - still stands in for a list whose download
	fails.
	*/
	linked := filepath.join({r.work_dir, "privcache-gone"}, context.temp_allocator) or_else ""
	if !write_fixture(r, linked, transmute([]u8)string("0.0.0.0 gone.test\n")) {
		return
	}
	gone_copy := fmt.ctprintf("%s/http___127.0.0.1_%d_gone.txt.list", cache_dir, http_port)
	if !check(r, posix.link(strings.clone_to_cstring(linked, context.temp_allocator), gone_copy) == .OK, "cannot link the copy for gone.txt") {
		return
	}
	gone := base_config(
		udp_port,
		upstream_at(next_port(r)),
		log = "{ level: info }",
		blocking = fmt.tprintf(
			`{{ enabled: true, cache_dir: %q, lists: ["http://127.0.0.1:%d/hosts.txt", "http://127.0.0.1:%d/later.txt", "http://127.0.0.1:%d/gone.txt"] }}`,
			cache_dir,
			http_port,
			http_port,
			http_port,
		),
		extra = "server: { user: nobody }",
	)
	if check(r, reload_to(r, &srv, gone, "gone.txt: 1 rules"), "the hard-linked copy of gone.txt was not loaded after the drop:\n%s", read_log(&srv)) {
		res := query_udp(udp_port, build_query("gone.test.", u16(dns.Type.A)))
		if check(r, res.ok, "no answer for gone.test") {
			check(r, parse_header(r, res.wire).rcode == int(dns.Rcode.NX_Domain), "the hard-linked copy of gone.txt was not applied")
		}
	}
}

// Whether every directory on `path` lets anyone through (o+x).
@(private = "file")
traversable_by_all :: proc(path: string) -> bool {
	dir := path
	for {
		st: posix.stat_t
		if posix.stat(strings.clone_to_cstring(dir, context.temp_allocator), &st) != .OK || .IXOTH not_in st.st_mode {
			return false
		}
		// Up to `/`, or `.` for a relative path, which is its own parent.
		up := filepath.dir(dir)
		if up == dir {
			return true
		}
		dir = up
	}
}
