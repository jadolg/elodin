package server

import "core:fmt"
import "core:mem/virtual"
import "core:strings"
import "core:sync"
import "core:testing"
import "core:time"
import "elodin:config"
import "elodin:loop"
import "elodin:sandbox"

/*
What a reload keeps: the cookie secrets it does not change, the running
configuration when the file cannot be used, and the keys only a restart applies.
The fixture is `Gen_Fixture` in generation_test.odin.
*/

@(test)
test_a_reload_keeps_the_cookie_secret_unless_the_file_changes_it :: proc(t: ^testing.T) {
	/*
	A drawn secret is what every client holds its cookie under; a reload that
	only changes `require` must not draw another, or each client pays a round
	trip for an edit that had nothing to do with it.
	*/
	f, ok := boot_fixture(t, "cookies", BASE)
	if !ok {
		return
	}
	defer close_fixture(f)
	old := f.s.gens.current.cookies
	secret := old.secrets.slots[old.secrets.epoch % COOKIE_SECRET_SLOTS].key
	testing.expect(t, old.secrets.next_roll != 0, "a drawn secret has no rollover scheduled")

	reload_applied(t, f, swap(BASE, "cookies: { enabled: true }", "cookies: { enabled: true, require: true }"))
	cur := f.s.gens.current.cookies
	if !testing.expect(t, cur != nil, "no keeper after the reload") {
		return
	}
	testing.expect(t, cur.require, "require was not applied")
	// Shared, not copied: the retiring generation answers on under the same
	// secrets, and a rollover either of them makes is the other's too.
	testing.expect(t, cur.secrets == old.secrets, "a reload that left the secret alone did not share the secrets")
	testing.expect(t, .Cookie_Secrets in f.s.gens.current.owns, "the secrets were not handed to the new generation")

	/*
	A rollover, then two reloads that change the secret, all inside one grace:
	the secrets the rollover and the first reload retired keep the rest of
	their grace, and the one the second replaces gets its own (RFC 7873
	section 7.1).
	*/
	req: Cookie_Request
	copy(req.client[:], "clientck")
	req.ip_len = 4
	req.ip[0] = 192
	now := cookie_now()
	under_first := make_cookie(cur, req, now)
	sync.atomic_store(&cur.secrets.next_roll, loop.moment_add(loop.moment_now(), -time.Second))
	under_second := make_cookie(cur, req, now)
	if !testing.expect_value(t, cur.secrets.epoch, 1) {
		return
	}

	replaced := cur
	cur = reload_with_cookies(t, f, "cookies: { enabled: true, secret: \"000102030405060708090a0b0c0d0e0f\" }")
	/*
	The replaced keeper stops rolling, and issues under the new secrets from
	the swap on: the retiring generation answers on while it drains, and a
	cookie it handed out under its own secrets after their grace, or under one
	it drew now, is one the new generation would refuse.
	*/
	expect_issued_under_the_new_secrets(t, old, replaced, cur, req, now)
	issued := cur.secrets.slots[cur.secrets.epoch % COOKIE_SECRET_SLOTS]
	testing.expect(t, issued.key != secret, "a configured secret did not replace the drawn one")
	testing.expect_value(t, cur.secrets.next_roll, 0)
	under_third := make_cookie(cur, req, now)

	cur = reload_with_cookies(t, f, "cookies: { enabled: true, secret: \"101112131415161718191a1b1c1d1e1f\" }")
	testing.expect(t, verify_cookie(cur, under_third[:], req, now), "the secret the second reload replaced was refused inside its grace")
	testing.expect(t, verify_cookie(cur, under_second[:], req, now), "the secret the first reload replaced was refused inside its grace")
	testing.expect(t, verify_cookie(cur, under_first[:], req, now), "the secret the rollover retired was refused inside its grace")
	later := cookie_now() + COOKIE_ROLLOVER_GRACE + 1
	testing.expect(t, !verify_cookie(cur, under_third[:], req, later), "the replaced secret was accepted past the grace")
	// Replaced twice now: the oldest keeper issues under the latest secrets.
	from_oldest_again := make_cookie(old, req, now)
	testing.expect(t, verify_cookie(cur, from_oldest_again[:], req, later), "a keeper two replacements back does not issue under the latest secrets")

	cur = reload_with_cookies(t, f, "cookies: { enabled: true, secret: \"000102030405060708090a0b0c0d0e0f\" }")

	// `previous_secret` alone changing keeps the secret issued under.
	staged := reload_with_cookies(t, f, "cookies: { enabled: true, secret: \"000102030405060708090a0b0c0d0e0f\", previous_secret: \"f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff\" }")
	testing.expect(t, staged.has_accepted, "previous_secret was not applied")
	testing.expect(t, staged.secrets == cur.secrets, "a change to previous_secret alone replaced the secrets")
}

@(test)
test_a_reload_of_an_unusable_file_keeps_the_running_configuration :: proc(t: ^testing.T) {
	f, ok := boot_fixture(t, "unusable", BASE)
	if !ok {
		return
	}
	defer close_fixture(f)
	old := f.s.gens.current

	out := reload_from(t, f, "upstream: { servers: [\n")
	testing.expect(t, !out.applied, "an unparseable file was applied")
	testing.expect(t, f.s.gens.current == old, "an unparseable file replaced the running generation")

	// Parses, and is refused by the loader's own checks: a cookie secret that is
	// not hex. A file that loads and then cannot be built is
	// `test_a_reload_that_cannot_be_built_releases_what_it_built`.
	out = reload_from(
		t,
		f,
		swap(
			BASE,
			"cookies: { enabled: true }",
			"cookies: { enabled: true, secret: \"not hex at all, not hex at all!\" }"),
	)
	testing.expect(t, !out.applied, "a configuration that could not be built was applied")
	testing.expect(t, f.s.gens.current == old, "a half-built configuration replaced the running one")
	testing.expect(t, f.s.gens.retired == nil, "a refused reload retired the running generation")
}

@(test)
test_a_reload_holds_restart_only_keys_at_their_starting_values :: proc(t: ^testing.T) {
	f, ok := boot_fixture(t, "restart", BASE + "listeners: { udp: { port: 5300 } }\n")
	if !ok {
		return
	}
	defer close_fixture(f)
	old := f.s.gens.current
	table := old.cfg.server.max_connections

	// Only keys that need a restart: nothing a reload can apply has changed.
	out := reload_from(
		t,
		f,
		strings.concatenate(
			{
				swap(BASE, "server:\n", fmt.tprintf("server:\n  max_connections: %d\n", table + 3)),
				"listeners: { udp: { port: 5301 } }\n",
			},
			context.temp_allocator,
		),
	)
	testing.expect(t, !out.applied, "a change to restart-only keys alone made a new generation")
	testing.expect(t, f.s.gens.current == old, "the running generation was replaced")

	// With something else beside them, the rest is applied and they are held.
	out = reload_from(
		t,
		f,
		strings.concatenate(
			{
				swap(BASE, "blocking: { enabled: false }", "blocking: { enabled: false, cache_dir: /var/tmp/elsewhere }"),
				"listeners: { udp: { port: 5301 } }\nrewrites:\n  - { domain: h.test, answer: 192.0.2.1 }\n",
			},
			context.temp_allocator,
		),
	)
	testing.expect(t, out.applied, "the reloadable part was not applied")
	testing.expect_value(t, f.s.gens.current.cfg.listeners.udp.port, 5300)
	testing.expect_value(t, f.s.gens.current.cfg.blocking.cache_dir, old.cfg.blocking.cache_dir)
	testing.expect_value(t, f.s.gens.current.cfg.server.max_connections, table)
	testing.expect_value(t, len(f.s.gens.current.cfg.rewrites), 1)
}

// A share the starting file wrote and the new one leaves to be derived is held,
// and so is said: only one derived both times goes unnamed.
@(test)
test_a_restart_only_key_dropped_from_the_file_is_named :: proc(t: ^testing.T) {
	arena: virtual.Arena
	if !testing.expect(t, virtual.arena_init_growing(&arena) == nil, "cannot reserve an arena") {
		return
	}
	defer virtual.arena_destroy(&arena)
	boot, boot_ok := load(t, swap(BASE, "server:\n", "server:\n  max_connections: 512\n  max_connections_per_prefix: 97\n"), &arena)
	cfg, cfg_ok := load(t, swap(BASE, "server:\n", "server:\n  max_connections: 512\n"), &arena)
	if !boot_ok || !cfg_ok {
		return
	}
	testing.expect(t, cfg.server.max_connections_per_prefix != 97, "the derived figure is the written one, so nothing is tested")

	named := keep_restart_only(&boot, &cfg, context.temp_allocator)
	testing.expectf(t, len(named) == 1 && named[0] == "server.max_connections_per_prefix", "named %v", named)
	testing.expect_value(t, cfg.server.max_connections_per_prefix, 97)
}

// Derived both times, and from the same `max_connections`: nothing to say.
@(test)
test_a_restart_only_key_derived_both_times_is_not_named :: proc(t: ^testing.T) {
	arena: virtual.Arena
	if !testing.expect(t, virtual.arena_init_growing(&arena) == nil, "cannot reserve an arena") {
		return
	}
	defer virtual.arena_destroy(&arena)
	first, first_ok := load(t, swap(BASE, "server:\n", "server:\n  max_connections: 512\n"), &arena)
	again, again_ok := load(t, swap(BASE, "server:\n", "server:\n  max_connections: 512\n"), &arena)
	if !first_ok || !again_ok {
		return
	}
	testing.expect_value(t, len(keep_restart_only(&first, &again, context.temp_allocator)), 0)
}

// The sandbox went on before the first loop started and cannot come off, so a
// reload that changes it is named and held.
@(test)
test_a_changed_sandbox_is_held_and_named :: proc(t: ^testing.T) {
	arena: virtual.Arena
	if !testing.expect(t, virtual.arena_init_growing(&arena) == nil, "cannot reserve an arena") {
		return
	}
	defer virtual.arena_destroy(&arena)
	boot, boot_ok := load(t, swap(BASE, "server:\n", "server:\n  sandbox: strict\n"), &arena)
	cfg, cfg_ok := load(t, swap(BASE, "server:\n", "server:\n  sandbox: off\n"), &arena)
	if !boot_ok || !cfg_ok {
		return
	}
	testing.expect_value(t, cfg.server.sandbox, sandbox.Mode.Off)

	named := keep_restart_only(&boot, &cfg, context.temp_allocator)
	testing.expectf(t, len(named) == 1 && named[0] == "server.sandbox", "named %v", named)
	testing.expect_value(t, cfg.server.sandbox, sandbox.Mode.Strict)
}

// A moved log is applied by a reload under any sandbox: a reopen Landlock
// refuses fails as any other does, and logging stays where it was.
@(test)
test_a_moved_log_is_not_held_under_a_sandbox :: proc(t: ^testing.T) {
	arena: virtual.Arena
	if !testing.expect(t, virtual.arena_init_growing(&arena) == nil, "cannot reserve an arena") {
		return
	}
	defer virtual.arena_destroy(&arena)
	sandboxed := swap(BASE, "server:\n", "server:\n  sandbox: strict\n")
	boot, boot_ok := load(t, swap(sandboxed, "log: { level: info }", "log: { level: info, file: /var/log/a.log }"), &arena)
	cfg, cfg_ok := load(t, swap(sandboxed, "log: { level: info }", "log: { level: info, file: /srv/b.log }"), &arena)
	if !boot_ok || !cfg_ok {
		return
	}
	named := keep_restart_only(&boot, &cfg, context.temp_allocator)
	testing.expectf(t, len(named) == 0 && cfg.log.file == "/srv/b.log", "named %v, log %q", named, cfg.log.file)
}

/*
A bound the file never sized, loaded on a machine whose memory limit moved since
startup: derived again from the starting machine, and nothing the operator wrote
to name. And UDP readers left to the machine, which shows more CPUs than at
startup: held, and nothing to name either.
*/
@(test)
test_a_restart_only_key_the_machine_moved_is_held_unnamed :: proc(t: ^testing.T) {
	arena: virtual.Arena
	if !testing.expect(t, virtual.arena_init_growing(&arena) == nil, "cannot reserve an arena") {
		return
	}
	defer virtual.arena_destroy(&arena)
	derived, derived_ok := load(t, BASE, &arena)
	moved, moved_ok := load(t, BASE, &arena)
	readers, readers_ok := load(t, BASE, &arena)
	more, more_ok := load(t, BASE, &arena)
	if !derived_ok || !moved_ok || !readers_ok || !more_ok {
		return
	}

	testing.expect(t, derived.server.sizing.derived_max_pending, "BASE names max_pending, so nothing is tested")
	moved.server.sizing.machine.memory = derived.server.sizing.machine.memory * 2 + config.QUERY_MEMORY_BYTES * 64
	moved.server.max_pending = config.derive_max_pending(moved.server.sizing.machine)
	named := keep_restart_only(&derived, &moved, context.temp_allocator)
	testing.expectf(t, len(named) == 0, "named %v for a file that names no max_pending", named)
	testing.expect_value(t, moved.server.max_pending, derived.server.max_pending)

	testing.expect(t, readers.server.sizing.derived_udp_readers, "BASE names a reader count, so nothing is tested")
	more.listeners.udp.readers = readers.listeners.udp.readers + 1
	named = keep_restart_only(&readers, &more, context.temp_allocator)
	testing.expectf(t, len(named) == 0, "named %v for a file that names no reader count", named)
	testing.expect_value(t, more.listeners.udp.readers, readers.listeners.udp.readers)
}

// A per-prefix share neither file writes moves with `max_connections`, which is
// the one key the operator changed and the one to name.
@(test)
test_a_restart_only_share_moved_by_max_connections_names_it :: proc(t: ^testing.T) {
	arena: virtual.Arena
	if !testing.expect(t, virtual.arena_init_growing(&arena) == nil, "cannot reserve an arena") {
		return
	}
	defer virtual.arena_destroy(&arena)
	table, table_ok := load(t, BASE, &arena)
	if !table_ok {
		return
	}
	halved, halved_ok := load(t, swap(BASE, "server:\n", fmt.tprintf("server:\n  max_connections: %d\n", table.server.max_connections / 2)), &arena)
	if !halved_ok {
		return
	}
	testing.expect(t, halved.server.max_connections_per_prefix != table.server.max_connections_per_prefix, "the share did not move, so nothing is tested")
	named := keep_restart_only(&table, &halved, context.temp_allocator)
	testing.expectf(t, len(named) == 1 && named[0] == "server.max_connections", "named %v", named)
	testing.expect_value(t, halved.server.max_connections_per_prefix, table.server.max_connections_per_prefix)
}

// `cookies` in place of BASE's cookie line, reloaded; the keeper it left current.
@(private = "file")
reload_with_cookies :: proc(t: ^testing.T, f: ^Gen_Fixture, cookies: string, loc := #caller_location) -> ^Cookie_Keeper {
	reload_applied(t, f, swap(BASE, "cookies: { enabled: true }", cookies), loc = loc)
	return f.s.gens.current.cookies
}

/*
After `cur` replaced the secrets `replaced` and `old` share, both issue under
`cur`'s and stop rolling their own, and each still takes `cur`'s cookies.
*/
@(private = "file")
expect_issued_under_the_new_secrets :: proc(t: ^testing.T, old, replaced, cur: ^Cookie_Keeper, req: Cookie_Request, now: u32) {
	testing.expect_value(t, sync.atomic_load(&replaced.secrets.next_roll), 0)
	testing.expect(t, sync.atomic_load(&replaced.secrets.successor) == cur.secrets, "the replaced keeper does not issue under the new secrets")
	from_retiring := make_cookie(replaced, req, now)
	testing.expect(t, verify_cookie(cur, from_retiring[:], req, cookie_now() + COOKIE_ROLLOVER_GRACE + 1), "a cookie the retiring generation issued is refused once the grace is over")
	// So does an older generation sharing them since a reload that kept them,
	// and each checks the new generation's cookies as well.
	from_oldest := make_cookie(old, req, now)
	testing.expect(t, verify_cookie(cur, from_oldest[:], req, cookie_now() + COOKIE_ROLLOVER_GRACE + 1), "a cookie an older generation sharing the replaced secrets issued is refused once the grace is over")
	from_new := make_cookie(cur, req, now)
	testing.expect(t, verify_cookie(old, from_new[:], req, now), "a retiring generation refused a cookie the new one issued")
	testing.expect(t, verify_cookie(replaced, from_new[:], req, now), "the replaced generation refused a cookie the new one issued")
}
