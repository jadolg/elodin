package main

import "core:fmt"
import "core:os"
import "core:path/filepath"
import "core:slice"
import "core:strings"
import "core:sys/posix"
import "core:testing"
import "elodin:config"

// A scratch tree under /tmp: `dir`, a file `dir/real/file` and a symlink
// `dir/link` to it, so a test sees a name and its target in two directories.
@(private = "file")
Tree :: struct {
	dir, real_dir, real_file, link: string,
}

@(private = "file")
make_tree :: proc(t: ^testing.T, loc := #caller_location) -> (tree: Tree, ok: bool) {
	tree.dir = fmt.tprintf("/tmp/elodin-main-sandbox-%d-%s", posix.getpid(), loc.procedure)
	tree.real_dir = strings.concatenate({tree.dir, "/real"}, context.temp_allocator)
	tree.real_file = strings.concatenate({tree.real_dir, "/file"}, context.temp_allocator)
	tree.link = strings.concatenate({tree.dir, "/link"}, context.temp_allocator)
	if err := os.make_directory_all(tree.real_dir); err != nil {
		testing.expectf(t, false, "cannot make %s: %v", tree.real_dir, err, loc = loc)
		return
	}
	if err := os.write_entire_file(tree.real_file, transmute([]u8)string("x")); err != nil {
		testing.expectf(t, false, "cannot write %s: %v", tree.real_file, err, loc = loc)
		return
	}
	if err := os.symlink(tree.real_file, tree.link); err != nil {
		testing.expectf(t, false, "cannot link %s: %v", tree.link, err, loc = loc)
		return
	}
	return tree, true
}

@(private = "file")
remove_tree :: proc(t: ^testing.T, tree: Tree) {
	if tree.dir != "" {
		err := os.remove_all(tree.dir)
		testing.expectf(t, err == nil, "cannot remove %s: %v", tree.dir, err)
	}
}

/*
The cache directory has a rule while blocking is off if it is there, so a
reload that turns blocking on can write to it; one that is not there has none,
and is not made, as nothing asked for it.
*/
@(test)
test_the_plan_grants_an_existing_cache_with_blocking_off :: proc(t: ^testing.T) {
	tree, ok := make_tree(t)
	defer remove_tree(t, tree)
	if !ok {
		return
	}
	cfg := config.default_config()
	cfg.blocking.enabled = false
	cfg.server.sandbox = .Basic

	cfg.blocking.cache_dir = tree.real_dir
	plan, pinned := sandbox_plan(&cfg, tree.real_file, "", context.temp_allocator)
	testing.expectf(t, len(pinned) == 0, "pinned %v", pinned)
	testing.expectf(t, plan.cache_dir == tree.real_dir, "an existing cache: %q, want %q", plan.cache_dir, tree.real_dir)

	cfg.blocking.cache_dir = strings.concatenate({tree.dir, "/absent"}, context.temp_allocator)
	plan, pinned = sandbox_plan(&cfg, tree.real_file, "", context.temp_allocator)
	testing.expectf(t, plan.cache_dir == "", "an absent cache with blocking off: %q, want none", plan.cache_dir)
	testing.expect(t, !os.exists(cfg.blocking.cache_dir), "the plan made the cache directory")
}

// A log reached through a symlink is made where it points, and only there: the
// link's own directory - `/dev` for `/dev/stdout` led to a file - is not granted.
@(test)
test_the_plan_grants_a_symlinked_logs_target_directory_only :: proc(t: ^testing.T) {
	tree, ok := make_tree(t)
	defer remove_tree(t, tree)
	if !ok {
		return
	}
	cfg := config.default_config()
	cfg.server.sandbox = .Basic
	plan, pinned := sandbox_plan(&cfg, tree.real_file, tree.link, context.temp_allocator)
	testing.expectf(t, plan.log_dir == tree.real_dir, "log grants %q, want only %q", plan.log_dir, tree.real_dir)
	testing.expectf(t, len(pinned) == 0, "pinned %v", pinned)

	plan, pinned = sandbox_plan(&cfg, tree.real_file, "", context.temp_allocator)
	testing.expectf(t, plan.log_dir == "" && len(pinned) == 0, "logging to stderr: grants %q, pinned %v", plan.log_dir, pinned)
}

/*
Under strict: the directory of a re-read file and of its symlink's target, and
procfs and the cgroup tree at their mounts, never an entry under /proc whose
inode procfs replaces. Basic confines no reads, so it lists none.
*/
@(test)
test_the_strict_plan_reads_targets_and_mounts :: proc(t: ^testing.T) {
	tree, ok := make_tree(t)
	defer remove_tree(t, tree)
	if !ok {
		return
	}
	cfg := config.default_config()
	cfg.server.sandbox = .Strict
	plan, pinned := sandbox_plan(&cfg, tree.link, "", context.temp_allocator)
	testing.expectf(t, len(pinned) == 0, "pinned %v", pinned)
	for want in ([]string{tree.dir, tree.real_dir, "/proc", "/sys/fs/cgroup"}) {
		testing.expectf(t, slice.contains(plan.readable, want), "%v lacks %q", plan.readable, want)
	}
	for path in plan.readable {
		testing.expectf(t, !strings.has_prefix(path, "/proc/"), "%q is under /proc, whose inodes do not last", path)
	}

	cfg.server.sandbox = .Basic
	plan, pinned = sandbox_plan(&cfg, tree.link, "", context.temp_allocator)
	testing.expectf(t, len(plan.readable) == 0 && len(pinned) == 0, "basic lists reads %v, pins %v", plan.readable, pinned)
}

// A file directly in `/` or `/etc` is granted alone and named: the directory
// would be every path, or every secret on the host.
@(test)
test_the_plan_pins_files_directly_in_shared_directories :: proc(t: ^testing.T) {
	cfg := config.default_config()
	cfg.server.sandbox = .Strict
	plan, pinned := sandbox_plan(&cfg, "/etc/elodin-test.yaml", "/elodin-test.log", context.temp_allocator)
	for file in ([]string{"/etc/elodin-test.yaml"}) {
		testing.expectf(t, slice.contains(plan.readable, file), "%v lacks the file itself", plan.readable)
	}
	for dir in PINNED_DIRS {
		testing.expectf(t, !slice.contains(plan.readable, dir), "%v grants %s", plan.readable, dir)
		testing.expectf(t, plan.log_dir != dir, "the log grants %s", dir)
	}
	testing.expectf(t, slice.contains(pinned, "/etc/elodin-test.yaml") && slice.contains(pinned, "/elodin-test.log"), "pinned %v", pinned)
}

// A shared directory reached through a symlink is the shared directory: the
// rule is put on what the name opens.
@(test)
test_the_plan_pins_a_shared_directory_reached_through_a_link :: proc(t: ^testing.T) {
	tree, ok := make_tree(t)
	defer remove_tree(t, tree)
	if !ok {
		return
	}
	etc := strings.concatenate({tree.dir, "/etc-link"}, context.temp_allocator)
	if err := os.symlink("/etc", etc); !testing.expectf(t, err == nil, "cannot link %s: %v", etc, err) {
		return
	}
	cfg := config.default_config()
	cfg.server.sandbox = .Strict
	config_path := strings.concatenate({etc, "/elodin-test.yaml"}, context.temp_allocator)
	plan, pinned := sandbox_plan(&cfg, config_path, "", context.temp_allocator)
	testing.expectf(t, !slice.contains(plan.readable, etc) && !slice.contains(plan.readable, "/etc"), "%v grants /etc through %s", plan.readable, etc)
	testing.expectf(t, len(pinned) == 1, "pinned %v, want the configuration", pinned)
}

// A log on a device, FIFO or socket is written through the descriptor already
// open, and its directory would be all of /dev; a regular file, or one not made
// yet, is granted where it is.
@(test)
test_the_plan_grants_only_a_regular_or_new_log :: proc(t: ^testing.T) {
	tree, ok := make_tree(t)
	defer remove_tree(t, tree)
	if !ok {
		return
	}
	fifo := strings.concatenate({tree.dir, "/fifo"}, context.temp_allocator)
	cfifo := strings.clone_to_cstring(fifo, context.temp_allocator)
	if !testing.expectf(t, posix.mkfifo(cfifo, {.IRUSR, .IWUSR}) == .OK, "cannot make %s: %v", fifo, posix.errno()) {
		return
	}
	cfg := config.default_config()
	cfg.server.sandbox = .Basic
	for path in ([]string{"/dev/null", fifo}) {
		plan, pinned := sandbox_plan(&cfg, "/etc/elodin/elodin.yaml", path, context.temp_allocator)
		testing.expectf(t, plan.log_dir == "" && len(pinned) == 0, "a log at %s grants %q, pins %v", path, plan.log_dir, pinned)
	}
	not_yet := strings.concatenate({tree.real_dir, "/new.log"}, context.temp_allocator)
	for path in ([]string{tree.real_file, not_yet}) {
		plan, pinned := sandbox_plan(&cfg, "/etc/elodin/elodin.yaml", path, context.temp_allocator)
		testing.expectf(t, plan.log_dir == tree.real_dir && len(pinned) == 0, "a log at %s grants %q, pins %v, want %q", path, plan.log_dir, pinned, tree.real_dir)
	}
}

/*
Under strict: every `file:` list, disabled or with blocking off, since a reload
may turn it on; the resolver's files; and the directories a hashed certificate
directory's entries lead into.
*/
@(test)
test_the_strict_plan_reads_lists_resolver_and_cert_targets :: proc(t: ^testing.T) {
	tree, ok := make_tree(t)
	defer remove_tree(t, tree)
	if !ok {
		return
	}
	cfg := config.default_config()
	cfg.server.sandbox = .Strict
	cfg.blocking.enabled = false
	cfg.blocking.lists = []config.Block_List{{name = "off", file = tree.real_file, enabled = false}}
	plan, pinned := sandbox_plan(&cfg, "/etc/elodin/elodin.yaml", "", context.temp_allocator)
	testing.expectf(t, len(pinned) == 0, "pinned %v", pinned)
	testing.expectf(t, slice.contains(plan.readable, tree.real_dir), "%v lacks a disabled list's directory", plan.readable)
	// The resolver's files by themselves: their directory, /etc, holds every
	// other secret on the host. Unless a symlink leads into /etc itself.
	for file in ([]string{"/etc/resolv.conf", "/etc/hosts"}) {
		testing.expectf(t, slice.contains(plan.readable, file), "%v lacks %s", plan.readable, file)
	}
	etc_by_link := false
	for file in ([]string{"/etc/resolv.conf", "/etc/hosts"}) {
		if target, resolved := resolve(file, context.temp_allocator); resolved && target != file && filepath.dir(target) == "/etc" {
			etc_by_link = true
		}
	}
	testing.expectf(t, etc_by_link || !slice.contains(plan.readable, "/etc"), "%v grants all of /etc", plan.readable)

	// A hashed entry in a certificate directory that leads elsewhere.
	certs := strings.concatenate({tree.dir, "/certs"}, context.temp_allocator)
	if err := os.make_directory(certs); !testing.expectf(t, err == nil, "cannot make %s: %v", certs, err) {
		return
	}
	hashed := strings.concatenate({certs, "/0000abcd.0"}, context.temp_allocator)
	if err := os.symlink(tree.real_file, hashed); !testing.expectf(t, err == nil, "cannot link %s: %v", hashed, err) {
		return
	}
	readable := make([dynamic]string, context.temp_allocator)
	pins := make([dynamic]string, context.temp_allocator)
	add_cert_dir(&readable, &pins, certs, context.temp_allocator)
	testing.expectf(t, len(pins) == 0, "pinned %v", pins)
	testing.expectf(t, slice.contains(readable[:], certs), "%v lacks the directory itself", readable)
	testing.expectf(t, slice.contains(readable[:], tree.real_dir), "%v lacks where its entries lead", readable)
	testing.expectf(t, !slice.contains(readable[:], tree.dir), "%v grants the directory's parent", readable)
}

// OpenSSL's bundle is reached where it leads: its name's directory, where the
// host's private keys are, is not granted; one that is itself in such a
// directory is granted alone.
@(test)
test_the_bundle_is_reached_where_it_leads :: proc(t: ^testing.T) {
	tree, ok := make_tree(t)
	defer remove_tree(t, tree)
	if !ok {
		return
	}
	out := make([dynamic]string, context.temp_allocator)
	add_bundle(&out, tree.link, context.temp_allocator)
	testing.expectf(t, slice.equal(out[:], []string{tree.real_dir}), "grants %v, want only %q", out, tree.real_dir)

	for dir in ([]string{"/etc/ssl", "/etc/ssl/private", "/etc/pki/tls", "/etc/pki/tls/private"}) {
		testing.expectf(t, is_pinned(dir), "%s, which holds private keys, is not pinned", dir)
	}
}

// A directory that is not there gets no rule, and so no warning that it is out
// of reach: OpenSSL's built-in paths often are not.
@(test)
test_a_missing_directory_is_not_granted :: proc(t: ^testing.T) {
	tree, ok := make_tree(t)
	defer remove_tree(t, tree)
	if !ok {
		return
	}
	out := make([dynamic]string, context.temp_allocator)
	pins := make([dynamic]string, context.temp_allocator)
	absent := strings.concatenate({tree.dir, "/absent"}, context.temp_allocator)
	grant_dir(&out, &pins, absent, strings.concatenate({absent, "/cert.pem"}, context.temp_allocator), context.temp_allocator)
	grant_dir(&out, &pins, tree.real_dir, tree.real_file, context.temp_allocator)
	testing.expectf(t, slice.equal(out[:], []string{tree.real_dir}) && len(pins) == 0, "grants %v, pins %v, want only %q", out, pins, tree.real_dir)
}

// A file directly in root's home, an account's home, or one of the roots other
// services keep data in is granted alone: the directory would expose them.
@(test)
test_the_plan_pins_homes_and_shared_roots :: proc(t: ^testing.T) {
	for dir in ([]string{"/root", "/home/someone", "/tmp", "/var/lib", "/srv"}) {
		testing.expectf(t, is_pinned(dir), "%s is not pinned", dir)
	}
	for dir in ([]string{"/etc/elodin", "/home/someone/elodin", "/var/lib/elodin"}) {
		testing.expectf(t, !is_pinned(dir), "%s, a directory of its own, is pinned", dir)
	}
}
