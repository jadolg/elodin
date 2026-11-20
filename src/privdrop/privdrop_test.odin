package privdrop

import "core:fmt"
import "core:log"
import "core:os"
import "core:path/filepath"
import "core:slice"
import "core:strings"
import "core:sys/linux"
import "core:sys/posix"
import "core:testing"

/*
Every test here runs unprivileged, which is exactly where the interesting
behaviour lives: resolution has to work without any privilege at all, and a
drop that cannot happen has to say so rather than carrying on as root.

The one thing not covered is a real drop, which needs a root process to be
possible at all. The check at the end of `apply` is what stands in for it: the
drop is only reported as done once the kernel agrees it happened.
*/

@(private = "file")
skip_when_root :: proc() -> bool {
	if posix.geteuid() == 0 {
		log.info("running as root; skipping the unprivileged case")
		return true
	}
	return false
}

@(test)
test_resolve_named_user :: proc(t: ^testing.T) {
	id, err := resolve("root", "")
	testing.expect_value(t, err, Error.None)
	testing.expect_value(t, id.uid, posix.uid_t(0))
	testing.expect_value(t, id.gid, posix.gid_t(0))
}

@(test)
test_resolve_numeric_user :: proc(t: ^testing.T) {
	id, err := resolve("0", "")
	testing.expect_value(t, err, Error.None)
	testing.expect_value(t, id.uid, posix.uid_t(0))
	testing.expect_value(t, id.gid, posix.gid_t(0))
}

@(test)
test_resolve_explicit_group_wins :: proc(t: ^testing.T) {
	// A uid with no passwd entry of its own is fine as long as the group is
	// given, which is the whole point of allowing one to be.
	id, err := resolve("60999", "root")
	testing.expect_value(t, err, Error.None)
	testing.expect_value(t, id.uid, posix.uid_t(60999))
	testing.expect_value(t, id.gid, posix.gid_t(0))
}

@(test)
test_resolve_rejects_unknown_names :: proc(t: ^testing.T) {
	_, uerr := resolve("elodin-no-such-user", "")
	testing.expect_value(t, uerr, Error.Unknown_User)

	_, gerr := resolve("root", "elodin-no-such-group")
	testing.expect_value(t, gerr, Error.Unknown_Group)

	_, eerr := resolve("", "")
	testing.expect_value(t, eerr, Error.Unknown_User)
}

/*
A numeric id is digits and nothing else, and fits the id type. Read by
`strconv` and cut to 32 bits, each of these would be root or `(uid_t)-1`: a
start as root would then find the drop already done and report success (#639).
`(uid_t)-1` is the set*id calls' "leave this id alone", never an identity.
*/
@(test)
test_resolve_refuses_a_numeric_id_out_of_range :: proc(t: ^testing.T) {
	for user in ([]string{"4294967296", "18446744073709551616", "4294967295", "99999999999999999999999"}) {
		id, err := resolve(user, "root")
		testing.expectf(t, err == .Id_Out_Of_Range, "user %q resolved to uid %d (%v)", user, id.uid, err)
	}
	for group in ([]string{"4294967296", "18446744073709551616", "4294967295"}) {
		id, err := resolve("60999", group)
		testing.expectf(t, err == .Id_Out_Of_Range, "group %q resolved to gid %d (%v)", group, id.gid, err)
	}

	// The largest id there is, and a leading zero, which is still that number.
	id, err := resolve("4294967294", "04294967294")
	testing.expect_value(t, err, Error.None)
	testing.expect_value(t, id.uid, posix.uid_t(4294967294))
	testing.expect_value(t, id.gid, posix.gid_t(4294967294))
}

// Not digits, so not an id: what is left is a name, and no account is called this.
@(test)
test_resolve_reads_only_digits_as_an_id :: proc(t: ^testing.T) {
	for user in ([]string{"+0", "0_0", "-0", "+60999", " 0", "0 "}) {
		id, err := resolve(user, "root")
		testing.expectf(t, err == .Unknown_User, "user %q resolved to uid %d (%v)", user, id.uid, err)
	}
	for group in ([]string{"+0", "0_0", " 0"}) {
		id, err := resolve("60999", group)
		testing.expectf(t, err == .Unknown_Group, "group %q resolved to gid %d (%v)", group, id.gid, err)
	}
}

/*
A numeric uid nobody has an account for leaves nowhere to read a primary group
from. Guessing one would be a silent choice about which files the process can
reach, so it is refused instead.
*/
@(test)
test_resolve_bare_numeric_uid_needs_a_group :: proc(t: ^testing.T) {
	UID :: 60999
	// Through the same reentrant lookup `resolve` uses; `posix.getpwuid` answers
	// out of a buffer the other tests in this package are reading at the time.
	if _, taken := group_of_uid(posix.uid_t(UID)); taken {
		log.info("uid 60999 has a passwd entry here; skipping")
		return
	}
	_, err := resolve(fmt.tprintf("%d", UID), "")
	testing.expect_value(t, err, Error.Unknown_Group)
}

/*
Being asked to become who we already are is not a failure. It is what a
correctly configured service looks like when systemd has already put it under
its own account, and refusing there would make the unit and the config
mutually exclusive.
*/
@(test)
test_apply_is_a_noop_for_the_current_identity :: proc(t: ^testing.T) {
	id := Identity {
		uid  = posix.geteuid(),
		gid  = posix.getegid(),
		name = "self",
	}
	testing.expect_value(t, apply(id), Error.None)
}

@(test)
test_apply_refuses_what_it_cannot_do :: proc(t: ^testing.T) {
	if skip_when_root() {
		return
	}
	id := Identity {
		uid  = 0,
		gid  = 0,
		name = "root",
	}
	// Without the privilege to change uid, the only honest answer is to say so.
	// Reporting success would leave the caller believing it had dropped.
	testing.expect_value(t, apply(id), Error.Not_Permitted)
}

@(test)
test_hand_over_covers_the_directory_and_its_entries :: proc(t: ^testing.T) {
	dir, ok := scratch_dir(t, "elodin-privdrop-test")
	if !ok {
		return
	}
	defer os.remove_all(dir)

	entry, _ := filepath.join({dir, "some.list"}, context.temp_allocator)
	if err := os.write_entire_file(entry, []u8{'x'}); err != nil {
		testing.expectf(t, false, "cannot write %s: %v", entry, err)
		return
	}

	// Handing a path to the identity already holding it is the no-op case, and
	// the only one an unprivileged test can carry out.
	self := Identity {
		uid  = posix.geteuid(),
		gid  = posix.getegid(),
		name = "self",
	}
	handed, named, skipped := hand_over(dir, self)
	testing.expect(t, handed, "handing a path to its own owner should succeed")
	testing.expectf(t, skipped == 0 && len(named) == 0, "a plain file was left as it was: %d %v", skipped, named)

	if skip_when_root() {
		return
	}
	other := Identity {
		uid  = 0,
		gid  = 0,
		name = "root",
	}
	handed, named, skipped = hand_over(dir, other)
	testing.expect(t, !handed, "an unprivileged chown to root should be reported as failed")
	testing.expectf(t, skipped == 0 && len(named) == 0, "a plain file was left as it was: %d %v", skipped, named)
}

/*
Only a directory, or a regular file with a single link, is handed over (#688).
A hard link is the same inode as a file elsewhere, which a chown as root would
hand over too; a symlink, a FIFO and the like are not elodin's output either.
Handed to its own owner, which any user can do, so what the test reads is which
entries `hand_over` took and which it left.
*/
@(test)
test_hand_over_takes_only_directories_and_singly_linked_files :: proc(t: ^testing.T) {
	dir, ok := scratch_dir(t, "elodin-privdrop-kinds")
	if !ok {
		return
	}
	defer os.remove_all(dir)
	elsewhere, eok := scratch_dir(t, "elodin-privdrop-elsewhere")
	if !eok {
		return
	}
	defer os.remove_all(elsewhere)

	path := proc(dir, name: string) -> cstring {
		return fmt.ctprintf("%s/%s", dir, name)
	}
	outside := path(elsewhere, "outside")
	if !testing.expect(t, os.write_entire_file(string(outside), []u8{'x'}) == nil, "cannot write the file outside") {
		return
	}
	if !testing.expect(t, os.write_entire_file(string(path(dir, "plain.list")), []u8{'x'}) == nil, "cannot write plain.list") {
		return
	}
	if !testing.expect(t, posix.mkdir(path(dir, "sub"), {.IRUSR, .IWUSR, .IXUSR}) == .OK, "cannot make sub") {
		return
	}
	if !testing.expect(t, posix.symlink(outside, path(dir, "symlink.list")) == .OK, "cannot make symlink.list") {
		return
	}
	if !testing.expect(t, posix.mkfifo(path(dir, "fifo.list"), {.IRUSR, .IWUSR}) == .OK, "cannot make fifo.list") {
		return
	}
	// A hard link to a file of this user's own, which `fs.protected_hardlinks`
	// allows: what matters is the second link, not whose file it is.
	if !testing.expect(t, posix.link(outside, path(dir, "hardlink.list")) == .OK, "cannot make hardlink.list") {
		return
	}

	self := Identity {
		uid  = posix.geteuid(),
		gid  = posix.getegid(),
		name = "self",
	}
	handed, named, skipped := hand_over(dir, self)
	testing.expect(t, handed, "handing the directory over failed")
	slice.sort(named)
	testing.expectf(t, skipped == 3 && slice.equal(named, []string{"fifo.list", "hardlink.list", "symlink.list"}), "left as they were: %d %v", skipped, named)
}

/*
As root, the same directory handed to another account: the file a hard link and
a symlink in it point at keeps its owner, and the plain file is the account's.
*/
@(test)
test_hand_over_as_root_leaves_a_linked_file_alone :: proc(t: ^testing.T) {
	if posix.geteuid() != 0 {
		log.info("skipped: handing a file to another account needs root")
		return
	}
	dir, ok := scratch_dir(t, "elodin-privdrop-root")
	if !ok {
		return
	}
	defer os.remove_all(dir)
	elsewhere, eok := scratch_dir(t, "elodin-privdrop-root-elsewhere")
	if !eok {
		return
	}
	defer os.remove_all(elsewhere)

	path := proc(dir, name: string) -> cstring {
		return fmt.ctprintf("%s/%s", dir, name)
	}
	outside := path(elsewhere, "outside")
	plain := path(dir, "plain.list")
	for p in ([]cstring{outside, plain}) {
		if !testing.expectf(t, os.write_entire_file(string(p), []u8{'x'}) == nil, "cannot write %s", p) {
			return
		}
	}
	if !testing.expect(t, posix.link(outside, path(dir, "hardlink.list")) == .OK, "cannot make hardlink.list") {
		return
	}
	if !testing.expect(t, posix.symlink(outside, path(dir, "symlink.list")) == .OK, "cannot make symlink.list") {
		return
	}

	nobody := Identity {
		uid  = 65534,
		gid  = 65534,
		name = "nobody",
	}
	handed, named, skipped := hand_over(dir, nobody)
	testing.expect(t, handed, "handing the directory over failed")
	slice.sort(named)
	testing.expectf(t, skipped == 2 && slice.equal(named, []string{"hardlink.list", "symlink.list"}), "left as they were: %d %v", skipped, named)
	owner := proc(p: cstring) -> posix.uid_t {
		st: posix.stat_t
		if posix.stat(p, &st) != .OK {
			return max(posix.uid_t)
		}
		return st.st_uid
	}
	testing.expectf(t, owner(outside) == 0, "the file outside was given to uid %d", owner(outside))
	// The positive half: the handing over did happen.
	testing.expectf(t, owner(plain) == nobody.uid, "the plain file is uid %d's", owner(plain))
}

/*
The account decides how many entries the directory holds, so `hand_over` names
at most `HAND_OVER_NAMED` of those it leaves and counts the rest.
*/
@(test)
test_hand_over_names_a_bounded_number_of_what_it_leaves :: proc(t: ^testing.T) {
	dir, ok := scratch_dir(t, "elodin-privdrop-many")
	if !ok {
		return
	}
	defer os.remove_all(dir)
	FIFOS :: HAND_OVER_NAMED * 3
	for i in 0 ..< FIFOS {
		if !testing.expectf(t, posix.mkfifo(fmt.ctprintf("%s/f%d", dir, i), {.IRUSR, .IWUSR}) == .OK, "cannot make FIFO %d", i) {
			return
		}
	}
	self := Identity {
		uid  = posix.geteuid(),
		gid  = posix.getegid(),
		name = "self",
	}
	handed, named, skipped := hand_over(dir, self)
	testing.expect(t, handed, "handing the directory over failed")
	testing.expectf(t, skipped == FIFOS && len(named) == HAND_OVER_NAMED, "left %d, named %d", skipped, len(named))
}

// An entry removed between the listing and the look is gone, not a failure.
@(test)
test_take_reads_a_vanished_entry_as_gone :: proc(t: ^testing.T) {
	dir, ok := scratch_dir(t, "elodin-privdrop-gone")
	if !ok {
		return
	}
	defer os.remove_all(dir)
	fd := posix.open(strings.clone_to_cstring(dir, context.temp_allocator), {.DIRECTORY, .CLOEXEC})
	if !testing.expect(t, fd != -1, "cannot open the directory") {
		return
	}
	defer posix.close(fd)
	self := Identity {
		uid  = posix.geteuid(),
		gid  = posix.getegid(),
		name = "self",
	}
	testing.expect_value(t, take(linux.Fd(fd), "not-there.list", self), Take.Gone)
}

@(test)
test_hand_over_ignores_a_path_that_is_not_there :: proc(t: ^testing.T) {
	self := Identity {
		uid  = posix.geteuid(),
		gid  = posix.getegid(),
		name = "self",
	}
	// A cache directory that was never created is not something to fail over:
	// the process makes it itself on the next refresh, under its own account.
	handed, named, skipped := hand_over("/nonexistent/elodin-cache", self)
	testing.expect(t, handed, "a missing path should not be an error")
	testing.expectf(t, skipped == 0 && len(named) == 0, "a missing path left entries: %d %v", skipped, named)
}

/*
A file the process cannot open is out of reach, whichever way it is asked for,
and one it can is not. Mode 0 stands in for a root-owned 0600 key, which an
unprivileged process cannot open either; root opens anything, so the case is
skipped there.
*/
@(test)
test_can_reopen :: proc(t: ^testing.T) {
	if skip_when_root() {
		return
	}
	dir, ok := scratch_dir(t, "elodin-privdrop-reopen")
	if !ok {
		return
	}
	defer os.remove_all(dir)

	open_one, _ := filepath.join({dir, "open"}, context.temp_allocator)
	shut, _ := filepath.join({dir, "shut"}, context.temp_allocator)
	read_only, _ := filepath.join({dir, "read-only"}, context.temp_allocator)
	missing, _ := filepath.join({dir, "missing"}, context.temp_allocator)
	testing.expect(t, os.write_entire_file(open_one, []byte{}, {.Read_User, .Write_User}) == nil, "cannot write the open file")
	testing.expect(t, os.write_entire_file(shut, []byte{}, {}) == nil, "cannot write the shut file")
	testing.expect(t, os.write_entire_file(read_only, []byte{}, {.Read_User}) == nil, "cannot write the read-only file")

	testing.expect(t, can_reopen(open_one, false), "a readable file is out of reach")
	testing.expect(t, can_reopen(open_one, true), "a writable file is out of reach")
	testing.expect(t, !can_reopen(shut, false), "a file with no permissions is in reach for reading")
	testing.expect(t, !can_reopen(shut, true), "a file with no permissions is in reach for writing")
	testing.expect(t, can_reopen(read_only, false), "a read-only file is out of reach for reading")
	testing.expect(t, !can_reopen(read_only, true), "a read-only file is in reach for writing")
	testing.expect(t, !can_reopen(missing, false), "a missing file is in reach")
	testing.expect(t, !os.exists(missing), "checking a missing file created it")
}

// The pid keeps a run in another checkout from removing this one's files.
@(private = "file")
scratch_dir :: proc(t: ^testing.T, name: string) -> (dir: string, ok: bool) {
	tmp, terr := os.temp_directory(context.temp_allocator)
	if terr != nil {
		testing.expectf(t, false, "no temporary directory: %v", terr)
		return
	}
	dir, _ = filepath.join({tmp, fmt.tprintf("%s-%d", name, posix.getpid())}, context.temp_allocator)
	os.remove_all(dir)
	if err := os.make_directory(dir); err != nil {
		testing.expectf(t, false, "cannot create %s: %v", dir, err)
		return
	}
	return dir, true
}
