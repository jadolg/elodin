package sandbox

import "core:io"
import "core:os"
import "core:strings"
import "core:sync"
import "core:sys/linux"

// <linux/landlock.h>: the access rights, by the ABI version that added them.
@(private)
Access :: enum u64 {
	Execute     = 0,
	Write_File  = 1,
	Read_File   = 2,
	Read_Dir    = 3,
	Remove_Dir  = 4,
	Remove_File = 5,
	Make_Char   = 6,
	Make_Dir    = 7,
	Make_Reg    = 8,
	Make_Sock   = 9,
	Make_Fifo   = 10,
	Make_Block  = 11,
	Make_Sym    = 12,
	// ABI 2.
	Refer       = 13,
	// ABI 3.
	Truncate    = 14,
	// ABI 5.
	Ioctl_Dev   = 15,
}
@(private)
Access_Set :: bit_set[Access;u64]

@(private)
Scope :: enum u64 {
	Abstract_Unix_Socket = 0,
	Signal               = 1,
}
@(private)
Scope_Set :: bit_set[Scope;u64]

@(private)
ABI1_ACCESS :: Access_Set {
	.Execute,
	.Write_File,
	.Read_File,
	.Read_Dir,
	.Remove_Dir,
	.Remove_File,
	.Make_Char,
	.Make_Dir,
	.Make_Reg,
	.Make_Sock,
	.Make_Fifo,
	.Make_Block,
	.Make_Sym,
}

// Everything that changes the filesystem or runs from it.
@(private)
WRITE_ACCESS :: Access_Set {
	.Execute,
	.Write_File,
	.Remove_Dir,
	.Remove_File,
	.Make_Char,
	.Make_Dir,
	.Make_Reg,
	.Make_Sock,
	.Make_Fifo,
	.Make_Block,
	.Make_Sym,
	.Refer,
	.Truncate,
	.Ioctl_Dev,
}
@(private)
READ_ACCESS :: Access_Set{.Read_File, .Read_Dir}

// The rights landlock_add_rule(2) accepts on a rule for a file rather than a
// directory; any other is EINVAL.
@(private)
FILE_ACCESS :: Access_Set{.Execute, .Write_File, .Read_File, .Truncate, .Ioctl_Dev}

// The cache is replaced by a rename over the old copy, which removes it, and
// written through `.tmp` files it creates and truncates.
@(private)
CACHE_ACCESS :: READ_ACCESS + Access_Set{.Write_File, .Remove_File, .Make_Reg, .Truncate}
// A SIGHUP reopens the log by name, creating it when logrotate moved it away.
@(private)
LOG_ACCESS :: Access_Set{.Write_File, .Make_Reg}

@(private)
Ruleset_Attr :: struct {
	handled_access_fs:  Access_Set,
	handled_access_net: u64,
	scoped:             Scope_Set,
}

@(private)
Path_Beneath_Attr :: struct #packed {
	allowed_access: Access_Set,
	parent_fd:      i32,
}

@(private)
CREATE_RULESET_VERSION :: 1
@(private)
RULE_PATH_BENEATH :: 1
@(private)
PR_SET_NO_NEW_PRIVS :: 38

/*
Apply the plan's `PR_SET_NO_NEW_PRIVS` and Landlock layers to this thread and
every thread it starts after.

`ok` is false only when `PR_SET_NO_NEW_PRIVS` failed, which leaves nothing
applied. A Landlock that is missing or fails is said in the report and is not
an error: the process is then as confined as it was without this package. The
filesystem is never half-restricted - a ruleset is put in force whole, after
every rule was added, or not at all.

`report.unreachable` is allocated with `allocator`.
*/
confine :: proc(plan: Plan, allocator := context.allocator) -> (report: Report, ok: bool) {
	report.unreachable = make([dynamic]Unreachable, allocator)
	if plan.mode == .Off {
		return report, true
	}
	if linux.prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != .NONE {
		return report, false
	}

	abi := linux.syscall(linux.SYS_landlock_create_ruleset, uintptr(0), uintptr(0), uintptr(CREATE_RULESET_VERSION))
	if abi <= 0 {
		report.landlock = .Unavailable
		report.errno = i32(-abi)
		return report, true
	}
	report.abi = abi

	supported := supported_access(abi)
	attr := Ruleset_Attr {
		handled_access_fs = (WRITE_ACCESS + (READ_ACCESS if plan.mode == .Strict else {})) & supported,
		scoped            = supported_scopes(abi),
	}
	ruleset := linux.syscall(linux.SYS_landlock_create_ruleset, &attr, size_of(attr), uintptr(0))
	if ruleset < 0 {
		report.landlock = .Failed
		report.errno = i32(-ruleset)
		return report, true
	}
	defer linux.close(linux.Fd(ruleset))

	grants := make([dynamic]Grant, 0, 2 + len(plan.readable), context.temp_allocator)
	if plan.cache_dir != "" {
		append(&grants, Grant{plan.cache_dir, CACHE_ACCESS})
	}
	if plan.log_dir != "" {
		append(&grants, Grant{plan.log_dir, LOG_ACCESS})
	}
	for path in plan.readable {
		append(&grants, Grant{path, READ_ACCESS})
	}
	for g in grants {
		unopened, errno := add_rule(linux.Fd(ruleset), g, attr.handled_access_fs)
		if unopened {
			append(&report.unreachable, Unreachable{g.path, i32(errno)})
		} else if errno != .NONE {
			report.landlock = .Failed
			report.errno = i32(errno)
			return report, true
		}
	}

	if ret := linux.syscall(linux.SYS_landlock_restrict_self, uintptr(ruleset), uintptr(0)); ret != 0 {
		report.landlock = .Failed
		report.errno = i32(-ret)
		return report, true
	}
	report.landlock = .Applied
	sync.atomic_store(&landlock_reads, plan.mode == .Strict)
	sync.atomic_store(&landlock_in_force, true)
	return report, true
}

/*
Whether a Landlock ruleset `confine` applied is in force. Set once, before the
process starts any thread, and never cleared.
*/
@(private)
landlock_in_force: bool
// Whether that ruleset confines reading too, as `.Strict`'s does.
@(private)
landlock_reads: bool

// What a warning about a file the process could not open adds when Landlock
// may be the reason: it refuses with EACCES, as a mode or an owner would.
REFUSAL_HINT :: " (or server.sandbox refuses it: its Landlock rules reach only the paths named at startup)"

// `REFUSAL_HINT` when `err` is EACCES and the Landlock rules in force confine
// the access refused - writing, or reading under `.Strict` - "" otherwise.
refusal_hint :: proc(err: os.Error, write: bool) -> string {
	confined := sync.atomic_load(&landlock_in_force) && (write || sync.atomic_load(&landlock_reads))
	// `core:os` reports EACCES as `Permission_Denied`; a raw open, as itself.
	if confined && (err == os.Platform_Error(linux.Errno.EACCES) || err == io.Error.Permission_Denied) {
		return REFUSAL_HINT
	}
	return ""
}

@(private)
Grant :: struct {
	path:   string,
	access: Access_Set,
}

// Add a rule for `g`, cut to what the ruleset handles and, on a file, to what a
// file rule may hold. `unopened` when the path cannot be opened, which is the
// path's doing, with why in `errno`; any other failure is Landlock's.
@(private)
add_rule :: proc(ruleset: linux.Fd, g: Grant, handled: Access_Set) -> (unopened: bool, errno: linux.Errno) {
	cpath := strings.clone_to_cstring(g.path, context.temp_allocator)
	fd, err := linux.open(cpath, {.PATH, .CLOEXEC})
	if err != .NONE {
		return true, err
	}
	defer linux.close(fd)

	access := g.access & handled
	st: linux.Stat
	if serr := linux.fstat(fd, &st); serr != .NONE {
		return false, serr
	}
	if !linux.S_ISDIR(st.mode) {
		access &= FILE_ACCESS
	}
	if access == {} {
		return false, .NONE
	}
	attr := Path_Beneath_Attr {
		allowed_access = access,
		parent_fd      = i32(fd),
	}
	if ret := linux.syscall(linux.SYS_landlock_add_rule, uintptr(ruleset), uintptr(RULE_PATH_BENEATH), &attr, uintptr(0)); ret != 0 {
		return false, linux.Errno(-ret)
	}
	return false, .NONE
}

/*
The rights a kernel of Landlock ABI `abi` knows. Asking it to handle one it
does not is EINVAL, so a newer right is handled only where it exists - and
where it does not, the kernel never restricted it, so there is nothing to give.
*/
@(private)
supported_access :: proc(abi: int) -> Access_Set {
	set := ABI1_ACCESS
	if abi >= 2 {
		set += {.Refer}
	}
	if abi >= 3 {
		set += {.Truncate}
	}
	if abi >= 5 {
		set += {.Ioctl_Dev}
	}
	return set
}

// Scoping came with ABI 6: the process cannot signal, or connect to an abstract
// unix socket of, anything outside its own domain.
@(private)
supported_scopes :: proc(abi: int) -> Scope_Set {
	return {.Abstract_Unix_Socket, .Signal} if abi >= 6 else {}
}
