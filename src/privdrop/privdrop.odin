/*
Giving up root once there is nothing left that needs it.

Binding :53 is the only privileged thing elodin does, and it happens once at
startup. Everything after that — parsing DNS wire data, HTTP/2 frames and TLS
records straight off the network — is exactly the code an attacker gets to
reach, and it runs for the life of the process. Staying root through all of it
means any single memory bug in that surface is a root compromise rather than a
compromise of one service account, and the release build is compiled with
`-no-bounds-check`.

`packaging/elodin.service` already avoids the problem by never being root:
systemd binds the port through `AmbientCapabilities` and runs the process under
`DynamicUser`. This package is for every other way of starting it — a bare
`sudo elodin`, a container, an init system without that machinery — where the
process has to put the privilege down itself.
*/
package privdrop

import "core:c"
import "core:os"
import "core:strconv"
import "core:strings"
import "core:sys/posix"

when ODIN_OS == .Darwin {
	foreign import libc "system:System"
} else {
	foreign import libc "system:c"
}

/*
Not in `core:sys/posix` because it is not in POSIX: setting the supplementary
group list is a BSD extension every Unix went on to adopt. It matters here
because `setgid` does not touch that list, so a process that dropped uid and
gid without it would keep root's supplementary groups and whatever they open.
*/
@(default_calling_convention = "c")
foreign libc {
	setgroups :: proc(size: c.size_t, list: [^]posix.gid_t) -> c.int ---
}

Identity :: struct {
	uid:  posix.uid_t,
	gid:  posix.gid_t,
	// What the operator wrote, kept for log lines.
	name: string,
}

Error :: enum u8 {
	None,
	Unknown_User,
	Unknown_Group,
	// Asked to become somebody else without the privilege to do it.
	Not_Permitted,
	Setgroups_Failed,
	Setgid_Failed,
	Setuid_Failed,
	// Every call reported success and the process is still not who it should be.
	Still_Privileged,
}

explain :: proc(err: Error) -> string {
	switch err {
	case .None:
		return "no error"
	case .Unknown_User:
		return "no such user"
	case .Unknown_Group:
		return "no such group"
	case .Not_Permitted:
		return "not running as root, so the identity cannot be changed"
	case .Setgroups_Failed:
		return "cannot clear the supplementary groups"
	case .Setgid_Failed:
		return "cannot change group"
	case .Setuid_Failed:
		return "cannot change user"
	case .Still_Privileged:
		return "the identity did not change despite every call reporting success"
	}
	return "unknown error"
}

is_root :: proc() -> bool {
	return posix.geteuid() == 0 || posix.getuid() == 0
}

/*
Turn what the operator configured into ids, without changing anything.

Kept separate from `apply` so it can run before the listeners bind: a misspelt
user name is then a startup error, rather than a process that comes up, takes
the port, and only then discovers it has nowhere to go.

`user` is a name or a numeric uid; `group` is a name or a numeric gid, and may
be empty to take the user's primary group.
*/
resolve :: proc(user: string, group: string) -> (id: Identity, err: Error) {
	if user == "" {
		return {}, .Unknown_User
	}
	id.name = user

	have_gid := false
	if uid, ok := strconv.parse_uint(user, 10); ok {
		id.uid = posix.uid_t(uid)
		// A numeric uid is allowed to have no account behind it — containers do
		// this — but then there is no primary group to read, and picking one
		// would be a silent decision about what the process can reach.
		if pw := posix.getpwuid(id.uid); pw != nil {
			id.gid = pw.pw_gid
			have_gid = true
		}
	} else {
		pw := posix.getpwnam(strings.clone_to_cstring(user, context.temp_allocator))
		if pw == nil {
			return {}, .Unknown_User
		}
		id.uid = pw.pw_uid
		id.gid = pw.pw_gid
		have_gid = true
	}

	if group != "" {
		if gid, ok := strconv.parse_uint(group, 10); ok {
			id.gid = posix.gid_t(gid)
		} else {
			gr := posix.getgrnam(strings.clone_to_cstring(group, context.temp_allocator))
			if gr == nil {
				return {}, .Unknown_Group
			}
			id.gid = gr.gr_gid
		}
		have_gid = true
	}

	if !have_gid {
		return {}, .Unknown_Group
	}
	return id, .None
}

/*
Become `id`, for good.

Order is the whole of the correctness here. The supplementary groups go first
because only root may clear them, then the gid, then the uid — dropping the uid
first would take away the privilege needed for the other two and leave the
process holding root's groups. `setgid` and `setuid` are the real, effective
and saved ids together, so there is no saved uid left to step back into.

The final check is not ceremony. Both calls can report success on a system
where a resource limit or a container's uid map quietly leaves the process
where it was, and a drop that did not happen must never read as one that did.
*/
apply :: proc(id: Identity) -> Error {
	if already(id) {
		return .None
	}
	if !is_root() {
		return .Not_Permitted
	}

	if setgroups(0, nil) != 0 {
		return .Setgroups_Failed
	}
	if posix.setgid(id.gid) != .OK {
		return .Setgid_Failed
	}
	if posix.setuid(id.uid) != .OK {
		return .Setuid_Failed
	}
	if !already(id) {
		return .Still_Privileged
	}
	return .None
}

// Real as well as effective: an effective id alone can be handed back.
@(private)
already :: proc(id: Identity) -> bool {
	return(
		posix.getuid() == id.uid &&
		posix.geteuid() == id.uid &&
		posix.getgid() == id.gid &&
		posix.getegid() == id.gid \
	)
}

/*
Hand a directory the process keeps writing to over to `id`.

The blocklist cache is the one path still opened by name after the drop: the
lists are downloaded before the listeners bind, so the files land under whoever
started the process, and a refresh hours later would then fail on every one of
them. Ownership moves with the process.

One level deep, because that is the shape of the directory - a flat set of
`.list` files - and a recursive chown as root over a path an operator supplied
is a much larger thing to get right. `lchown` rather than `chown` so a symlink
planted in there is retargeted rather than followed.

A path that does not exist is not a failure: nothing has been cached yet, and
the process creates the directory itself, under its own account.
*/
hand_over :: proc(path: string, id: Identity) -> bool {
	if path == "" || !os.exists(path) {
		return true
	}

	ok := take(path, id)
	entries, err := os.read_directory_by_path(path, -1, context.temp_allocator)
	if err != nil {
		return ok
	}
	for entry in entries {
		ok = take(entry.fullpath, id) && ok
	}
	return ok
}

@(private)
take :: proc(path: string, id: Identity) -> bool {
	cpath := strings.clone_to_cstring(path, context.temp_allocator)
	return posix.lchown(cpath, id.uid, id.gid) == .OK
}
