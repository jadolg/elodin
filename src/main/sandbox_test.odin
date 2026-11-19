package main

import "core:fmt"
import "core:os"
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
	plan := sandbox_plan(&cfg, tree.real_file, "", context.temp_allocator)
	testing.expectf(t, plan.cache_dir == tree.real_dir, "an existing cache: %q, want %q", plan.cache_dir, tree.real_dir)

	cfg.blocking.cache_dir = strings.concatenate({tree.dir, "/absent"}, context.temp_allocator)
	plan = sandbox_plan(&cfg, tree.real_file, "", context.temp_allocator)
	testing.expectf(t, plan.cache_dir == "", "an absent cache with blocking off: %q, want none", plan.cache_dir)
	testing.expect(t, !os.exists(cfg.blocking.cache_dir), "the plan made the cache directory")
}

// A log file that is a symlink is written where it points, so that directory is
// granted as well as the one that names it.
@(test)
test_the_plan_grants_a_symlinked_logs_target_directory :: proc(t: ^testing.T) {
	tree, ok := make_tree(t)
	defer remove_tree(t, tree)
	if !ok {
		return
	}
	cfg := config.default_config()
	cfg.server.sandbox = .Basic
	plan := sandbox_plan(&cfg, tree.real_file, tree.link, context.temp_allocator)
	testing.expectf(t, slice.contains(plan.log_dirs, tree.dir), "%v lacks the link's directory %q", plan.log_dirs, tree.dir)
	testing.expectf(t, slice.contains(plan.log_dirs, tree.real_dir), "%v lacks the target's directory %q", plan.log_dirs, tree.real_dir)

	plan = sandbox_plan(&cfg, tree.real_file, "", context.temp_allocator)
	testing.expectf(t, len(plan.log_dirs) == 0, "logging to stderr: %v, want none", plan.log_dirs)
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
	plan := sandbox_plan(&cfg, tree.link, "", context.temp_allocator)
	for want in ([]string{tree.dir, tree.real_dir, "/proc", "/sys/fs/cgroup"}) {
		testing.expectf(t, slice.contains(plan.readable, want), "%v lacks %q", plan.readable, want)
	}
	for path in plan.readable {
		testing.expectf(t, !strings.has_prefix(path, "/proc/"), "%q is under /proc, whose inodes do not last", path)
	}

	cfg.server.sandbox = .Basic
	plan = sandbox_plan(&cfg, tree.link, "", context.temp_allocator)
	testing.expectf(t, len(plan.readable) == 0, "basic lists reads: %v", plan.readable)
}

// A file directly in `/` is granted alone: its directory would be every path.
@(test)
test_the_plan_never_grants_the_root :: proc(t: ^testing.T) {
	cfg := config.default_config()
	cfg.server.sandbox = .Strict
	plan := sandbox_plan(&cfg, "/elodin.yaml", "/elodin.log", context.temp_allocator)
	testing.expectf(t, slice.contains(plan.readable, "/elodin.yaml"), "%v lacks the file itself", plan.readable)
	testing.expectf(t, !slice.contains(plan.readable, "/"), "%v grants every read", plan.readable)
	testing.expectf(t, slice.equal(plan.log_dirs, []string{"/elodin.log"}), "log grants %v, want the file alone", plan.log_dirs)
}

// A log on a character device is written through the descriptor already open,
// and its directory is all of /dev.
@(test)
test_the_plan_grants_nothing_for_a_device_log :: proc(t: ^testing.T) {
	if !testing.expect(t, is_character_device("/dev/null"), "/dev/null is not a character device here") {
		return
	}
	cfg := config.default_config()
	cfg.server.sandbox = .Basic
	plan := sandbox_plan(&cfg, "/etc/elodin/elodin.yaml", "/dev/null", context.temp_allocator)
	testing.expectf(t, len(plan.log_dirs) == 0, "a device log grants %v", plan.log_dirs)
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
	plan := sandbox_plan(&cfg, "/etc/elodin/elodin.yaml", "", context.temp_allocator)
	testing.expectf(t, slice.contains(plan.readable, tree.real_dir), "%v lacks a disabled list's directory", plan.readable)
	testing.expectf(t, slice.contains(plan.readable, "/etc"), "%v lacks the resolver's directory", plan.readable)

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
	add_cert_dir(&readable, certs, context.temp_allocator)
	testing.expectf(t, slice.contains(readable[:], certs), "%v lacks the directory itself", readable)
	testing.expectf(t, slice.contains(readable[:], tree.real_dir), "%v lacks where its entries lead", readable)
	testing.expectf(t, !slice.contains(readable[:], tree.dir), "%v grants the directory's parent", readable)
}
