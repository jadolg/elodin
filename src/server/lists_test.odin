package server

import "base:runtime"
import "core:fmt"
import "core:mem"
import "core:net"
import "core:os"
import "core:strings"
import "core:sys/posix"
import "core:testing"
import "core:thread"
import "core:time"
import "elodin:config"
import "elodin:dns"
import "elodin:filter"
import "elodin:testkit"
import "elodin:upstream"

/*
The default configuration with its list cache in a directory of its own, made
here: `/tmp/elodin-server-lists-test-<name>-<pid>`, per process since other
worktrees run this suite on the same box. The caller removes it, and frees the
temp arena the path is in only after that.
*/
@(private = "file")
list_test_dir :: proc(t: ^testing.T, name: string, loc := #caller_location) -> (cfg: config.Config, dir: string) {
	dir = fmt.tprintf("/tmp/elodin-server-lists-test-%s-%d", name, os.get_pid())
	testing.expect(t, os.make_directory(dir) == nil, "cannot make the cache directory", loc = loc)
	cfg = config.default_config()
	cfg.blocking.cache_dir = dir
	return
}

// A server over `cfg` with an empty filter engine, as a list reload finds one.
@(private = "file")
list_server :: proc(cfg: ^config.Config) -> Server {
	return Server{cfg = cfg, filters = filter.engine_make()}
}

@(private = "file")
close_list_server :: proc(s: ^Server) {
	filter.engine_destroy(s.filters)
	delete(s.lists_loaded)
}

// `reload_filters_from` the configuration in effect: a rebuild's reload, for a
// test that has no rebuild's copy to hand it.
reload_filters :: proc(s: ^Server, allow_network: bool) -> (current: bool) {
	return reload_filters_from(s, live(s).cfg, allow_network)
}

@(test)
test_a_list_badfilter_does_not_cancel_the_operators_own_rules :: proc(t: ^testing.T) {
	/*
	A subscribed list's `$badfilter` is its author taking back a rule some list
	carries. The operator's own `blocking.rules` are not a list's to take back:
	`rules: ["||pl.ua^"]` has to keep blocking pl.ua whatever a list downloaded
	tonight says. The operator's own `$badfilter` still reaches the lists.
	*/
	// Per process: other worktrees run this suite on the same box.
	path := fmt.tprintf("/tmp/elodin-server-lists-test-badfilter-%d.txt", os.get_pid())
	testing.expect(t, os.write_entire_file(path, "||pl.ua^$badfilter\n@@||ok.example^$badfilter\n||listed.example^\n") == nil)
	defer os.remove(path)

	cfg := config.default_config()
	cfg.blocking.rules = []string{"||pl.ua^", "||listed.example^$badfilter"}
	cfg.blocking.allow_rules = []string{"||ok.example^"}
	cfg.blocking.lists = []config.Block_List{{name = "l", file = path, format = .Adblock, enabled = true}}
	block, allow, whole := build_filter_sets(&cfg, false)
	testing.expect(t, whole, "the sets were not built whole")
	defer filter.set_destroy(block)
	defer filter.set_destroy(allow)

	testing.expect(t, filter.set_cover(block, "www.pl.ua", .A) != .None, "the operator's block survives a list's badfilter")
	testing.expect(t, filter.set_cover(allow, "ok.example", .A) != .None, "and so does the operator's allow")
	testing.expect(t, filter.set_cover(block, "listed.example", .A) == .None, "and the operator's badfilter cancels a list's rule")
}

@(test)
test_an_operator_badfilter_that_is_skipped_is_warned_of :: proc(t: ^testing.T) {
	// A `$badfilter` adds no rule, so what it takes back is what tells it from
	// one skipped for a modifier urlfilter refuses (#464).
	block, allow := filter.set_make(), filter.set_make()
	defer filter.set_destroy(block)
	defer filter.set_destroy(allow)
	testing.expect(t, operator_rule_takes(block, allow, "||x.example^"))
	testing.expect(t, operator_rule_takes(block, allow, "||x.example^$important,badfilter"))
	testing.expect(t, operator_rule_takes(block, allow, "/x/$badfilter"))
	testing.expect(t, !operator_rule_takes(block, allow, "||x.example^$important, badfilter"))
	testing.expect(t, !operator_rule_takes(block, allow, "||x.example^$third-party,badfilter"))
	testing.expect(t, !operator_rule_takes(block, allow, "||x.example^$third-party"))
}

@(test)
test_a_query_with_a_slash_in_a_label_is_matched_against_the_lists :: proc(t: ^testing.T) {
	/*
	A label may hold any byte. Presentation form escapes the dot, whitespace and
	anything unprintable, but not `/`, so a query for `x/.blocked.example.` is
	decoded with the slash in it - and is still under a blocked zone (#398).
	*/
	engine, ok := test_filters(t, "||blocked.example^\n", .Adblock)
	defer filter.engine_destroy(engine)
	if !ok {
		return
	}

	for name in ([]string{"x/.blocked.example.", "a/b.c.blocked.example.", "/.blocked.example."}) {
		questions := []dns.Question{{name = name, type = .A, class = .IN}}
		wire, _, err := dns.encode_message(dns.Message{id = 0x3980, question = questions}, context.temp_allocator)
		testing.expect_value(t, err, dns.Encode_Error.None)
		msg, derr := dns.decode_message(wire, context.temp_allocator)
		if !testing.expect_value(t, derr, dns.Decode_Error.None) || !testing.expect_value(t, len(msg.question), 1) {
			continue
		}
		// The premise: what the resolver matches is the name with its slash.
		testing.expect_value(t, msg.question[0].name, name)
		testing.expectf(t, filter.engine_match(engine, msg.question[0].name, .A) == .Blocked, "%s was not blocked", name)
	}
	free_all(context.temp_allocator)
}

@(test)
test_a_refresh_that_loses_a_list_keeps_the_rules_in_effect :: proc(t: ^testing.T) {
	/*
	A list that loaded before and has neither its source nor a cached copy now
	keeps the rules in effect rather than taking everything it blocked out until
	the next refresh (#411), and the refresh says it was not current so it is
	retried sooner.
	*/
	// A downloaded list read from its cached copy, as a start without the
	// network reads it; taking the copy away is losing both.
	// Registered first so it runs last: the removals below read paths it zeroes.
	defer free_all(context.temp_allocator)
	cfg, dir := list_test_dir(t, "lost")
	defer os.remove(dir)
	cfg.blocking.lists = []config.Block_List{{name = "l", url = "http://192.0.2.1/l.txt", format = .Adblock, enabled = true}}
	path := strings.clone(list_cache_path(&cfg, cfg.blocking.lists[0]), context.temp_allocator)
	testing.expect(t, os.write_entire_file(path, "||kept.example^\n") == nil)
	defer os.remove(path)

	s := list_server(&cfg)
	defer close_list_server(&s)
	engine := s.filters

	testing.expect(t, reload_filters(&s, false), "the first load was not current")
	testing.expect(t, filter.engine_match(engine, "kept.example", .A) == .Blocked)

	os.remove(path)
	generation := filter.engine_generation(engine)
	testing.expect(t, !reload_filters(&s, false), "a refresh that lost a list was reported current")
	testing.expect_value(t, filter.engine_generation(engine), generation)
	testing.expect(t, filter.engine_match(engine, "kept.example", .A) == .Blocked, "the lost list's rules were swapped out")

	// Once the list is back, the refresh goes through again.
	testing.expect(t, os.write_entire_file(path, "||back.example^\n") == nil)
	testing.expect(t, reload_filters(&s, false))
	testing.expect(t, filter.engine_match(engine, "back.example", .A) == .Blocked)
	testing.expect(t, filter.engine_match(engine, "kept.example", .A) != .Blocked)
}

@(test)
test_a_list_that_never_loaded_does_not_hold_the_others_back :: proc(t: ^testing.T) {
	// Otherwise one list gone for good would freeze every other list at the
	// rules it had when the server started.
	path := fmt.tprintf("/tmp/elodin-server-lists-test-never-%d.txt", os.get_pid())
	testing.expect(t, os.write_entire_file(path, "||first.example^\n") == nil)
	defer os.remove(path)

	cfg := config.default_config()
	// A download with no copy in an empty cache directory, read without the
	// network: unavailable from the start.
	cfg.blocking.cache_dir = fmt.tprintf("/tmp/elodin-server-lists-test-never-cache-%d", os.get_pid())
	cfg.blocking.lists = []config.Block_List {
		{name = "missing", url = "http://192.0.2.1/l.txt", format = .Adblock, enabled = true},
		{name = "l", file = path, format = .Adblock, enabled = true},
	}
	s := list_server(&cfg)
	defer close_list_server(&s)
	engine := s.filters

	testing.expect(t, !reload_filters(&s, false), "a load missing a list was reported current")
	testing.expect(t, filter.engine_match(engine, "first.example", .A) == .Blocked)

	testing.expect(t, os.write_entire_file(path, "||second.example^\n") == nil)
	testing.expect(t, !reload_filters(&s, false))
	testing.expect(t, filter.engine_match(engine, "second.example", .A) == .Blocked, "the refresh was held back")
}

@(test)
test_a_failed_refresh_is_retried_on_a_doubling_backoff :: proc(t: ^testing.T) {
	day := 24 * time.Hour
	testing.expect_value(t, refresh_retry(0, day), REFRESH_RETRY_FIRST)
	testing.expect_value(t, refresh_retry(REFRESH_RETRY_FIRST, day), 2 * REFRESH_RETRY_FIRST)
	testing.expect_value(t, refresh_retry(REFRESH_RETRY_MAX / 2 + time.Minute, day), REFRESH_RETRY_MAX)
	testing.expect_value(t, refresh_retry(REFRESH_RETRY_MAX, day), REFRESH_RETRY_MAX)
	// Nor longer than the interval, where that is shorter than the cap.
	testing.expect_value(t, refresh_retry(20 * time.Minute, 30 * time.Minute), 30 * time.Minute)
	// An interval shorter than the first retry is never exceeded.
	testing.expect_value(t, refresh_retry(0, 10 * time.Second), 10 * time.Second)
	// The maintenance loop waits the retry while there is one, and the
	// interval otherwise.
	testing.expect_value(t, refresh_wait(REFRESH_RETRY_FIRST, day), REFRESH_RETRY_FIRST)
	testing.expect_value(t, refresh_wait(0, day), day)
}

@(test)
test_a_cached_copy_is_replaced_whole :: proc(t: ^testing.T) {
	/*
	A reader that opened the old copy keeps reading all of it while the new one
	is written: the new copy is renamed over the old rather than written into
	it, so a crash mid-write leaves one or the other whole, never a truncated
	list the next start would load as the whole of it (#411).
	*/
	// Registered first so it runs last: the removals below read paths it zeroes.
	defer free_all(context.temp_allocator)
	path := fmt.tprintf("/tmp/elodin-server-lists-test-cache-%d.list", os.get_pid())
	testing.expect(t, os.write_entire_file(path, "||old.example^\n") == nil)
	defer os.remove(path)

	old, oerr := os.open(path)
	if !testing.expect_value(t, oerr, nil) {
		return
	}
	defer os.close(old)

	testing.expect_value(t, write_cache_file(path, transmute([]byte)string("||new.example^\n")), nil)

	buf: [64]u8
	n, read_err := os.read(old, buf[:])
	testing.expect_value(t, read_err, nil)
	testing.expect_value(t, string(buf[:n]), "||old.example^\n")
	now, rerr := os.read_entire_file(path, context.temp_allocator)
	testing.expect_value(t, rerr, nil)
	testing.expect_value(t, string(now), "||new.example^\n")
	testing.expect(t, !os.exists(fmt.tprintf("%s.tmp", path)), "the temporary copy was left behind")
}

@(test)
test_a_download_that_opens_with_markup_is_not_a_list :: proc(t: ^testing.T) {
	testing.expect(t, begins_with_markup("<!DOCTYPE html>\n<html>"))
	testing.expect(t, begins_with_markup("\r\n \t<html lang=en>"))
	testing.expect(t, begins_with_markup("<?xml version=\"1.0\"?>"))
	testing.expect(t, !begins_with_markup("0.0.0.0 x.example\n<html>"))
	testing.expect(t, !begins_with_markup("! Title: a list\n||x.example^\n"))
	testing.expect(t, !begins_with_markup(""))
	// Only ASCII blanks are skipped; U+00A0 is not one, so this is not markup
	// at the start of a line and falls to the parse.
	testing.expect(t, !begins_with_markup(" <html>"))
	// A byte order mark is skipped, since a page may open with one.
	testing.expect(t, begins_with_markup("\xef\xbb\xbf<!DOCTYPE html>"))
}

@(test)
test_a_list_of_badfilter_rules_holds_rules :: proc(t: ^testing.T) {
	// It adds nothing and takes rules back, so `held` and not `added` says
	// whether the download holds rules.
	block, allow := filter.set_make(), filter.set_make()
	defer filter.set_destroy(block)
	defer filter.set_destroy(allow)

	added, held, _ := parse_list_text(block, allow, "||x.example^$badfilter\n", .Adblock)
	testing.expect_value(t, added, 0)
	testing.expect(t, held, "a list of $badfilter rules was read as empty")

	// A list whose regexes the lists before it left no budget for.
	for i := 0; block.regex_refused == 0; i += 1 {
		filter.parse_rule(block, allow, fmt.tprintf("/^r%d[0-9a-f]{60}$/", i))
		if !testing.expect(t, i < 100_000) {
			return
		}
	}
	added, held, _ = parse_list_text(block, allow, "/^late[0-9a-f]{60}$/\n", .Adblock)
	testing.expect_value(t, added, 0)
	testing.expect(t, held, "a list of regexes past the budget was read as empty")

	_, held, _ = parse_list_text(block, allow, "! only a comment\n\n", .Adblock)
	testing.expect(t, !held, "a list with no rules was read as holding some")
	free_all(context.temp_allocator)
}

@(test)
test_a_list_says_how_many_names_are_not_ascii :: proc(t: ^testing.T) {
	// The count is this list's own, not what the lists before it left in the set.
	block, allow := filter.set_make(), filter.set_make()
	defer filter.set_destroy(block)
	defer filter.set_destroy(allow)

	_, _, not_ascii := parse_list_text(block, allow, "b\u00fccher.example\n\u00e9t\u00e9.example\nok.example\n", .Domains)
	testing.expect_value(t, not_ascii, 2)
	_, _, not_ascii = parse_list_text(block, allow, "caf\u00e9.example\n", .Domains)
	testing.expect_value(t, not_ascii, 1)
	_, _, not_ascii = parse_list_text(block, allow, "xn--bcher-kva.example\n", .Domains)
	testing.expect_value(t, not_ascii, 0)
	// An allowlist parses into the allow set as both of its targets.
	_, _, not_ascii = parse_list_text(allow, allow, "bücher.example\n", .Domains)
	testing.expect_value(t, not_ascii, 1)
}

@(test)
test_a_deleted_file_list_is_lifted :: proc(t: ^testing.T) {
	// A `file:` list is the operator's own: deleting it is how its blocks are
	// lifted, so its absence does not keep them (#411 keeps a download's).
	path := fmt.tprintf("/tmp/elodin-server-lists-test-deleted-%d.txt", os.get_pid())
	testing.expect(t, os.write_entire_file(path, "||lifted.example^\n") == nil)
	defer os.remove(path)

	cfg := config.default_config()
	cfg.blocking.lists = []config.Block_List{{name = "l", file = path, format = .Adblock, enabled = true}}
	s := list_server(&cfg)
	defer close_list_server(&s)
	engine := s.filters

	testing.expect(t, reload_filters(&s, false))
	testing.expect(t, filter.engine_match(engine, "lifted.example", .A) == .Blocked)
	os.remove(path)
	// Nor is it retried: no retry brings a local file back.
	testing.expect(t, reload_filters(&s, false), "a deleted file list was retried")
	testing.expect(t, filter.engine_match(engine, "lifted.example", .A) != .Blocked, "a deleted file list kept its blocks")
}

// A copy that holds no list is not loaded as one: a page cached by a build that
// wrote a download before checking it, and an empty download an earlier build
// cached, or a copy its in-place write truncated before a crash.
@(test)
test_a_cached_copy_that_is_no_list_is_not_loaded :: proc(t: ^testing.T) {
	// Registered first so it runs last: the removals below read paths it zeroes.
	defer free_all(context.temp_allocator)
	cfg, dir := list_test_dir(t, "not-a-list")
	defer os.remove(dir)
	list := config.Block_List{name = "l", url = "http://192.0.2.1/l.txt", format = .Hosts, enabled = true}
	path := list_cache_path(&cfg, list)
	defer os.remove(path)
	for body in ([]string{"<html>\n0.0.0.0 portal.example\n</html>\n", " \n\r\n"}) {
		testing.expect(t, os.write_entire_file(path, body) == nil)
		text, load := cached_copy(&cfg, list, .Current)
		testing.expectf(t, load == .Unavailable, "%q was loaded as %v", body, load)
		testing.expect_value(t, text, "")
	}
}

// Every copy `test_a_cache_named_by_a_query_moves` planted or moved, and their
// fingerprints.
@(private = "file")
remove_copies :: proc(cfg: ^config.Config, files: []string, moved, other, on: config.Block_List) {
	for f in ([]string{list_cache_path(cfg, moved), list_cache_path(cfg, other), list_cache_path(cfg, on)}) {
		os.remove(f)
	}
	for f in files {
		os.remove(f)
		os.remove(source_path(f))
	}
	os.remove(source_path(list_cache_path(cfg, moved)))
}

/*
A copy an earlier build cached under a list's whole url, query and key included,
moves to the name the list goes by now, so an offline start still loads it and
the key leaves the cache directory; with a copy already there it is removed. A
file that is another list's cache under its own name is not touched (#487).
*/
@(test)
test_a_cache_named_by_a_query_moves :: proc(t: ^testing.T) {
	defer free_all(context.temp_allocator)
	cfg, dir := list_test_dir(t, "move")
	defer os.remove(dir)
	moved := config.Block_List{name = "http://192.0.2.1/a", url = "http://192.0.2.1/a?key=SECRET", format = .Hosts, enabled = true}
	stale := config.Block_List{name = "http://192.0.2.1/b", url = "http://192.0.2.1/b?key=SECRET", format = .Hosts, enabled = true}
	kept := config.Block_List{name = "http://192.0.2.1/c?key=SECRET", url = "http://192.0.2.1/c?key=SECRET", format = .Hosts, enabled = true, named = true}
	other := config.Block_List{name = "http://192.0.2.1/c", url = "http://192.0.2.1/c?key=SECRET", format = .Hosts, enabled = true}
	// A disabled list is not loaded, and its old copy is not moved: its name is
	// another list's here, which would load the disabled one's rules.
	off := config.Block_List{name = "http://192.0.2.1/d", url = "http://192.0.2.1/d?key=SECRET", format = .Hosts}
	on := config.Block_List{name = "http://192.0.2.1/d", url = "http://192.0.2.9/d", format = .Hosts, enabled = true}
	// The copy under its current name is of the url with no query, which an
	// earlier build cached there: the old copy is this url's, and moves over it.
	over := config.Block_List{name = "http://192.0.2.1/e", url = "http://192.0.2.1/e?key=SECRET", format = .Hosts, enabled = true}
	cfg.blocking.lists = []config.Block_List{moved, stale, kept, other, off, on, over}

	path_of :: proc(dir, name: string) -> string {
		return strings.concatenate({dir, "/", config.list_cache_name(name)}, context.temp_allocator)
	}
	moved_old := path_of(dir, moved.url)
	stale_old := path_of(dir, stale.url)
	stale_current := list_cache_path(&cfg, stale)
	kept_own := path_of(dir, kept.name)
	off_old := path_of(dir, off.url)
	over_old := path_of(dir, over.url)
	over_bare := list_cache_path(&cfg, over)
	files := []string{moved_old, stale_old, stale_current, kept_own, off_old, over_old, over_bare}
	bodies := []string{"0.0.0.0 moved.example\n", "0.0.0.0 stale.example\n", "0.0.0.0 current.example\n", "0.0.0.0 kept.example\n", "0.0.0.0 off.example\n", "0.0.0.0 over.example\n", "0.0.0.0 bare.example\n"}
	for f, i in files {
		testing.expect(t, os.write_entire_file(f, bodies[i]) == nil)
	}
	// The current copy is the stale list's own, by its fingerprint.
	src, sourced := source_of(stale)
	if testing.expect(t, sourced, "the stale list has no fingerprint") {
		testing.expect(t, os.write_entire_file(source_path(stale_current), src) == nil)
	}
	defer remove_copies(&cfg, files, moved, other, on)

	block, allow, whole := build_filter_sets(&cfg, false)
	testing.expect(t, whole, "the sets were not built whole")
	defer filter.set_destroy(block)
	defer filter.set_destroy(allow)
	testing.expect(t, filter.set_cover(block, "moved.example", .A) != .None, "the old copy did not stand in offline")
	testing.expect(t, filter.set_cover(block, "current.example", .A) != .None, "the current copy was replaced")
	testing.expect(t, !os.exists(moved_old), "the old copy is still under its url")
	testing.expect(t, os.exists(list_cache_path(&cfg, moved)), "the old copy did not move to the list's name")
	testing.expect(t, !os.exists(stale_old), "the old copy beside a current one was kept")
	testing.expect(t, os.exists(kept_own), "another list's own cache was touched")
	testing.expect(t, filter.set_cover(block, "off.example", .A) == .None, "a disabled list's old copy loaded as another list")
	testing.expect(t, os.exists(off_old), "a disabled list's old copy moved")
	testing.expect(t, filter.set_cover(block, "over.example", .A) != .None, "the old copy was removed for another url's")
	testing.expect(t, filter.set_cover(block, "bare.example", .A) == .None, "the url with no query's copy loaded as the list")
	testing.expect(t, !os.exists(over_old), "the old copy is still under its url")
}

/*
A list whose url has a query is cached under a name without it, and a copy of
one query is not fresh for another: the list is downloaded again rather than
read from the old query's copy for the rest of the refresh window. The fragment,
never sent, changes nothing, and a url with no query needs no fingerprint. No
file name, and no fingerprint, holds the query (#487).
*/
@(test)
test_a_changed_query_is_not_fresh :: proc(t: ^testing.T) {
	defer free_all(context.temp_allocator)
	cfg, dir := list_test_dir(t, "query")
	defer os.remove(dir)
	// Port 1 on loopback refuses at once, so a download that is tried fails fast.
	a := config.Block_List{name = "http://127.0.0.1:1/l", url = "http://127.0.0.1:1/l?key=SECRET1", format = .Hosts, enabled = true}
	b := config.Block_List{name = a.name, url = "http://127.0.0.1:1/l?key=SECRET2", format = .Hosts, enabled = true}
	c := config.Block_List{name = a.name, url = "http://127.0.0.1:1/l?key=SECRET1#x", format = .Hosts, enabled = true}
	plain := config.Block_List{name = "http://127.0.0.1:1/p", url = "http://127.0.0.1:1/p", format = .Hosts, enabled = true}
	path := list_cache_path(&cfg, a)
	defer {
		os.remove(path)
		os.remove(source_path(path))
		os.remove(list_cache_path(&cfg, plain))
	}
	save_cached_copy(&cfg, a, "0.0.0.0 a.example\n")
	save_cached_copy(&cfg, plain, "0.0.0.0 p.example\n")

	_, fresh := fetch_list(&cfg, a)
	testing.expect_value(t, fresh, Fetch.Cache_Is_Fresh)
	_, fresh = fetch_list(&cfg, c)
	testing.expect_value(t, fresh, Fetch.Cache_Is_Fresh)
	_, fresh = fetch_list(&cfg, b)
	testing.expect_value(t, fresh, Fetch.Failed)
	_, fresh = fetch_list(&cfg, plain)
	testing.expect_value(t, fresh, Fetch.Cache_Is_Fresh)
	testing.expect(t, !os.exists(source_path(list_cache_path(&cfg, plain))), "a url with no query has a fingerprint")
	// Nor does it stand in when that download fails: it is another list. Its
	// own url's copy does.
	text, load := cached_copy(&cfg, b, .Stale)
	testing.expect_value(t, load, List_Load.Unavailable)
	testing.expect_value(t, text, "")
	text, load = cached_copy(&cfg, a, .Stale)
	testing.expect_value(t, load, List_Load.Stale)
	testing.expect_value(t, text, "0.0.0.0 a.example\n")
	delete(text)

	testing.expect(t, !strings.contains(path, "SECRET"), "the query is in the file name")
	src, serr := os.read_entire_file(source_path(path), context.temp_allocator)
	testing.expect_value(t, serr, nil)
	testing.expectf(t, len(src) > 0 && !strings.contains(string(src), "SECRET"), "the fingerprint is %q", string(src))

	// The query dropped from the url: the copy of the query is not fresh for it,
	// and its own copy, once saved, leaves no fingerprint behind to say otherwise.
	bare := config.Block_List{name = a.name, url = "http://127.0.0.1:1/l", format = .Hosts, enabled = true}
	_, fresh = fetch_list(&cfg, bare)
	testing.expect_value(t, fresh, Fetch.Failed)
	save_cached_copy(&cfg, bare, "0.0.0.0 bare.example\n")
	testing.expect(t, !os.exists(source_path(path)), "the query's fingerprint outlived its copy")
	_, fresh = fetch_list(&cfg, bare)
	testing.expect_value(t, fresh, Fetch.Cache_Is_Fresh)
	_, fresh = fetch_list(&cfg, a)
	testing.expect_value(t, fresh, Fetch.Failed)
}

/*
A list the file names was cached under that name before #487, with no
fingerprint: that copy is still the list's, fresh and standing in offline. And a
copy that cannot be written leaves the old one beside its own fingerprint, not
one that reads as a url with no query's.
*/
@(test)
test_a_named_lists_copy_survives_the_fingerprint :: proc(t: ^testing.T) {
	defer free_all(context.temp_allocator)
	cfg, dir := list_test_dir(t, "named")
	defer os.remove(dir)
	named := config.Block_List{name = "oisd", url = "http://127.0.0.1:1/l?key=SECRET", format = .Hosts, enabled = true, named = true}
	path := list_cache_path(&cfg, named)
	defer {
		os.remove(path)
		os.remove(source_path(path))
		os.remove_all(fmt.tprintf("%s.tmp", path))
	}
	testing.expect(t, os.write_entire_file(path, "0.0.0.0 named.example\n") == nil)
	_, fresh := fetch_list(&cfg, named)
	testing.expect_value(t, fresh, Fetch.Cache_Is_Fresh)
	text, load := cached_copy(&cfg, named, .Stale)
	testing.expect_value(t, load, List_Load.Stale)
	delete(text)

	// A query copy, then a write of the same name for the url with none fails.
	save_cached_copy(&cfg, named, "0.0.0.0 named.example\n")
	testing.expect(t, os.exists(source_path(path)))
	// A non-empty directory in the `.tmp`'s place, which the write cannot
	// remove to create its own.
	testing.expect(t, os.make_directory(fmt.tprintf("%s.tmp", path)) == nil)
	testing.expect(t, os.write_entire_file(fmt.tprintf("%s.tmp/keep", path), "x") == nil)
	bare := config.Block_List{name = "oisd", url = "http://127.0.0.1:1/l", format = .Hosts, enabled = true, named = true}
	save_cached_copy(&cfg, bare, "0.0.0.0 bare.example\n")
	testing.expect(t, os.exists(source_path(path)), "a failed write dropped the old copy's fingerprint")
}

/*
A name the file gives is the file's, though it spells the url up to its query:
the copy an earlier build cached under it, with no fingerprint, is still the
list's, fresh and standing in offline (#487).
*/
@(test)
test_a_given_name_like_a_default_keeps_its_copy :: proc(t: ^testing.T) {
	defer free_all(context.temp_allocator)
	dir := fmt.tprintf("/tmp/elodin-server-lists-test-given-%d", os.get_pid())
	testing.expect(t, os.make_directory(dir) == nil)
	defer os.remove(dir)
	cfg, err := config.load_string(
		"upstream:\n  servers: [1.1.1.1]\nblocking:\n  lists: [{name: \"http://127.0.0.1:1/g\", url: \"http://127.0.0.1:1/g?key=SECRET\"}]\n",
		context.temp_allocator,
	)
	if e, has := err.?; has {
		testing.expectf(t, false, "%v", e.messages)
		return
	}
	cfg.blocking.cache_dir = dir
	list := cfg.blocking.lists[0]
	path := list_cache_path(&cfg, list)
	defer {
		os.remove(path)
		os.remove(source_path(path))
	}
	testing.expect(t, os.write_entire_file(path, "0.0.0.0 given.example\n") == nil)
	_, fresh := fetch_list(&cfg, list)
	testing.expect_value(t, fresh, Fetch.Cache_Is_Fresh)
	text, load := cached_copy(&cfg, list, .Stale)
	testing.expect_value(t, load, List_Load.Stale)
	delete(text)
}

@(private = "file")
One_List :: struct {
	listener: net.TCP_Socket,
	body:     string,
	count:    int,
	// Requests answered, read once the thread is joined.
	served:   int,
}

// Answer `count` requests on `listener` with `body` as a 200.
@(private = "file")
serve_one_list :: proc(one: ^One_List) {
	for _ in 0 ..< one.count {
		client, _, err := net.accept_tcp(one.listener)
		if err != nil {
			return
		}
		// A fetcher that connects and then never sends fails its test rather
		// than hanging the run: shutting the listener down wakes an accept,
		// not this read. A connection with no request on it is closed
		// unanswered, and one this cannot bound stops the server, the listener
		// shut so that the fetches after it are refused rather than left to
		// wait out their timeout.
		if net.set_option(client, .Receive_Timeout, 3 * time.Second) != nil {
			net.close(client)
			net.shutdown(one.listener, .Both)
			return
		}
		buf: [1024]u8
		if n, rerr := net.recv_tcp(client, buf[:]); rerr != nil || n == 0 {
			net.close(client)
			continue
		}
		head := fmt.tprintf("HTTP/1.1 200 OK\r\nContent-Length: %d\r\nConnection: close\r\n\r\n", len(one.body))
		_, _ = net.send_tcp(client, transmute([]u8)head)
		_, _ = net.send_tcp(client, transmute([]u8)one.body)
		net.close(client)
		one.served += 1
		free_all(context.temp_allocator)
	}
}

/*
`serve_one_list` answering `count` requests with `body` on a loopback listener,
and the URL that reaches it. `one` is the caller's, so it outlives the thread;
`stop_one_list` shuts the listener down, which wakes an accept still waiting,
joins the thread and closes the listener.
*/
@(private = "file")
start_one_list :: proc(
	t: ^testing.T,
	one: ^One_List,
	body: string,
	count: int,
	loc := #caller_location,
) -> (
	server: ^thread.Thread,
	url: string,
	ok: bool,
) {
	listener, err := net.listen_tcp(net.Endpoint{address = net.IP4_Loopback, port = 0})
	if !testing.expect_value(t, err, nil, loc = loc) {
		return
	}
	bound, berr := net.bound_endpoint(listener)
	if !testing.expect_value(t, berr, nil, loc = loc) {
		net.close(listener)
		return
	}
	one^ = One_List{listener, body, count, 0}
	server = thread.create_and_start_with_poly_data(one, serve_one_list)
	if !testing.expect(t, server != nil, "cannot start the list server", loc = loc) {
		net.close(listener)
		return
	}
	return server, fmt.tprintf("http://127.0.0.1:%d/l.txt", bound.port), true
}

@(private = "file")
stop_one_list :: proc(one: ^One_List, server: ^thread.Thread) {
	// Wakes an accept still waiting, for a test that returned before dialling
	// every request: an event, not a deadline the fetches between dials race.
	// Ignored on a listener every accept is already done with.
	net.shutdown(one.listener, .Both)
	thread.join(server)
	thread.destroy(server)
	net.close(one.listener)
}

@(test)
test_a_fresh_cached_page_is_downloaded_over :: proc(t: ^testing.T) {
	/*
	A copy inside the refresh window skips the download. One that cannot stand
	in - a page an earlier build cached (#317) - is downloaded over, or the list
	would be out of effect until it aged past the window.
	*/
	one: One_List
	server, url, ok := start_one_list(t, &one, "0.0.0.0 fetched.example\n", 1)
	if !ok {
		return
	}
	defer stop_one_list(&one, server)

	// Registered before the removals so it runs after them: they read paths it
	// zeroes.
	defer free_all(context.temp_allocator)
	cfg, dir := list_test_dir(t, "fresh-page")
	defer os.remove(dir)
	list := config.Block_List {
		name    = "l",
		url     = url,
		format  = .Hosts,
		enabled = true,
	}
	path := strings.clone(list_cache_path(&cfg, list), context.temp_allocator)
	testing.expect(t, os.write_entire_file(path, "<html>\n0.0.0.0 portal.example\n</html>\n") == nil)
	defer os.remove(path)

	text, load, downloaded := list_contents(&cfg, list, true)
	defer delete(text)
	testing.expect_value(t, load, List_Load.Current)
	testing.expect(t, downloaded, "a fresh cached page kept the download from running")
	testing.expect_value(t, text, "0.0.0.0 fetched.example\n")
}

@(test)
test_a_refresh_leaves_no_download_in_scratch :: proc(t: ^testing.T) {
	/*
	Scratch is cleared only when the maintenance tick ends, so a download read
	into it is held for the whole refresh, and every list's buffers pile up on
	top of the old and new rule sets.
	*/
	LISTS :: 8
	body := strings.builder_make()
	defer strings.builder_destroy(&body)
	for i := 0; strings.builder_len(body) < 512 * 1024; i += 1 {
		fmt.sbprintf(&body, "0.0.0.0 n%d.example\n", i)
	}
	one: One_List
	server, url, ok := start_one_list(t, &one, strings.to_string(body), LISTS)
	if !ok {
		return
	}
	defer stop_one_list(&one, server)

	defer free_all(context.temp_allocator)
	cfg, dir := list_test_dir(t, "scratch")
	defer os.remove_all(dir)
	lists: [LISTS]config.Block_List
	for &list, i in lists {
		list = {name = fmt.tprintf("l%d", i), url = fmt.tprintf("%s%d", url, i), format = .Hosts, enabled = true}
	}
	cfg.blocking.lists = lists[:]

	if !testing.expect(t, context.temp_allocator.data == &runtime.global_default_temp_allocator_data, "scratch is not the thread's own arena") {
		return
	}
	scratch := &runtime.global_default_temp_allocator_data.arena
	before := int(scratch.total_used)
	loads: [LISTS]List_Load
	block, allow, whole := build_filter_sets(&cfg, true, loads[:])
	testing.expect(t, whole, "the sets were not built whole")
	defer filter.set_destroy(block)
	defer filter.set_destroy(allow)
	held := int(scratch.total_used) - before

	for load in loads {
		testing.expect_value(t, load, List_Load.Current)
	}
	testing.expectf(
		t,
		held < len(one.body),
		"%d lists of %d bytes left %d bytes in the scratch arena; a download should not outlive its exchange there",
		LISTS,
		len(one.body),
		held,
	)
}

@(test)
test_an_empty_download_with_no_copy_does_not_hold_the_others_back :: proc(t: ^testing.T) {
	/*
	A list that loaded before, then downloads empty with no cached copy behind
	it - a cleared tmpfs `cache_dir`, a publisher that emptied it. It arrived,
	so it is empty rather than lost: the refresh goes through without it, and is
	not current so it is tried again.
	*/
	one: One_List
	server, url, ok := start_one_list(t, &one, "# emptied\n", 1)
	if !ok {
		return
	}
	defer stop_one_list(&one, server)

	// Registered before the removals so it runs after them: they read paths it
	// zeroes.
	defer free_all(context.temp_allocator)
	cfg, dir := list_test_dir(t, "emptied")
	defer os.remove(dir)
	cfg.blocking.refresh = 0
	cfg.blocking.lists = []config.Block_List{{name = "l", url = url, format = .Hosts, enabled = true}}
	s := list_server(&cfg)
	defer close_list_server(&s)
	engine := s.filters
	// As if it had loaded at the last refresh.
	key := list_key(cfg.blocking.lists[0], false)
	s.lists_loaded[key] = true
	generation := filter.engine_generation(engine)

	testing.expect(t, !reload_filters(&s, true), "an empty download was reported current")
	testing.expect(t, filter.engine_generation(engine) != generation, "an empty download held the refresh back")
	testing.expect(t, !os.exists(list_cache_path(&cfg, cfg.blocking.lists[0])), "an empty download was cached")
	// It added nothing, so losing it later has no rules of its to keep.
	testing.expect(t, !s.lists_loaded[key], "an empty list was recorded as loaded")
}

@(test)
test_a_disabled_entry_does_not_lend_its_source_a_history :: proc(t: ^testing.T) {
	/*
	`lists_loaded` is keyed by where a list comes from, and two entries for one
	url are one list. A disabled one adds nothing, so it says nothing about
	whether that source's rules are in effect: an enabled entry that never
	loaded holds nothing back when it is unavailable again.
	*/
	cfg := config.default_config()
	cfg.blocking.cache_dir = "/nonexistent/elodin-lists-test-disabled-twin"
	cfg.blocking.refresh = 0
	url := "http://127.0.0.1:1/twin.txt"
	cfg.blocking.lists = []config.Block_List {
		{name = "twin", url = url, format = .Hosts, enabled = true},
		{name = "twin-off", url = url, format = .Hosts, enabled = false},
	}
	s := list_server(&cfg)
	defer close_list_server(&s)
	engine := s.filters

	testing.expect(t, !reload_filters(&s, true), "an unreachable list was reported current")
	testing.expect(t, !s.lists_loaded[list_key(cfg.blocking.lists[0], false)], "a list that never loaded was recorded as loaded")
	generation := filter.engine_generation(engine)
	reload_filters(&s, true)
	testing.expect(t, filter.engine_generation(engine) != generation, "a list that never loaded held the refresh back")
}

/*
The write follows no symlink: a `.tmp` planted as a link to another file is
replaced, not written through. A copy is read, and fresh, as any regular file,
however it is linked or owned: the cache is read only by the account that owns
it (#755), which reads nothing more through a link than it could by name. A
FIFO is neither waited on nor read.
*/
@(test)
test_the_list_cache_follows_no_symlink :: proc(t: ^testing.T) {
	// Registered first so it runs last: the removals below read paths it zeroes.
	defer free_all(context.temp_allocator)
	cfg, dir := list_test_dir(t, "symlinks")
	defer os.remove_all(dir)
	victim := fmt.tprintf("%s-victim", dir)
	defer os.remove(victim)
	if !testing.expect(t, os.write_entire_file(victim, "0.0.0.0 secret.example\n") == nil, "cannot write the victim") {
		return
	}
	list := config.Block_List{name = "l", url = "http://192.0.2.1/l.txt", format = .Hosts, enabled = true}
	path := list_cache_path(&cfg, list)
	if !expect_written_through_no_link(t, path, victim) {
		return
	}

	// A plain copy: read and fresh.
	_, why, read := read_cache_file(path, context.temp_allocator)
	testing.expectf(t, read, "a plain copy was not read: %q", why)
	_, fresh := plain_cache_file(path)
	testing.expect(t, fresh, "a plain copy is not fresh")

	// Linked copies: read, and fresh, as the file they link to.
	links := []struct {
		name: string,
		make: proc "c" (target, at: cstring) -> posix.result,
	} {
		{name = "symlink", make = posix.symlink},
		{name = "hard link", make = posix.link},
	}
	for l in links {
		testing.expect_value(t, os.remove(path), nil)
		if !testing.expectf(t, l.make(cpath(victim), cpath(path)) == .OK, "cannot plant the %s", l.name) {
			return
		}
		data, lwhy, lread := read_cache_file(path, context.temp_allocator)
		testing.expectf(t, lread && string(data) == "0.0.0.0 secret.example\n", "the %s was not read: %q", l.name, lwhy)
		_, lfresh := plain_cache_file(path)
		testing.expectf(t, lfresh, "the %s is not fresh", l.name)
	}

	expect_a_fifo_refused(t, &cfg, list, path)
}

// `p` as a C string, in the temp arena.
@(private = "file")
cpath :: proc(p: string) -> cstring {
	return strings.clone_to_cstring(p, context.temp_allocator)
}

/*
That `write_cache_file` replaces a `.tmp` planted beside `path` as a link to
`victim` rather than writing through it. False, and said, when the link could
not be planted.
*/
@(private = "file")
expect_written_through_no_link :: proc(t: ^testing.T, path, victim: string) -> bool {
	if !testing.expect(t, posix.symlink(cpath(victim), cpath(fmt.tprintf("%s.tmp", path))) == .OK, "cannot plant the .tmp link") {
		return false
	}
	testing.expect_value(t, write_cache_file(path, transmute([]byte)string("0.0.0.0 new.example\n")), nil)
	after, verr := os.read_entire_file(victim, context.temp_allocator)
	testing.expect_value(t, verr, nil)
	testing.expectf(t, string(after) == "0.0.0.0 secret.example\n", "the file the .tmp linked to was written: %q", string(after))
	written, werr := os.read_entire_file(path, context.temp_allocator)
	testing.expect_value(t, werr, nil)
	testing.expect_value(t, string(written), "0.0.0.0 new.example\n")
	return true
}

// That a FIFO in place of `list`'s copy at `path` is neither waited on nor read,
// by anyone, and that the list then loads no copy, nor once it is gone.
@(private = "file")
expect_a_fifo_refused :: proc(t: ^testing.T, cfg: ^config.Config, list: config.Block_List, path: string) {
	testing.expect_value(t, os.remove(path), nil)
	if !testing.expect(t, posix.mkfifo(cpath(path), {.IRUSR, .IWUSR}) == .OK, "cannot make the FIFO") {
		return
	}
	_, fifo_why, fifo_read := read_cache_file(path, context.temp_allocator)
	testing.expectf(t, !fifo_read && fifo_why == "it is not a regular file", "a FIFO was read: %q", fifo_why)
	_, fifo_fresh := plain_cache_file(path)
	testing.expect(t, !fifo_fresh, "a FIFO is fresh")

	// The list loads no copy that is refused - the FIFO, still in place - nor
	// one that is missing.
	text, load := cached_copy(cfg, list, .Stale)
	testing.expectf(t, load == .Unavailable && text == "", "a refused copy loaded: %v %q", load, text)
	delete(text)
	testing.expect_value(t, os.remove(path), nil)
	text, load = cached_copy(cfg, list, .Stale)
	testing.expectf(t, load == .Unavailable && text == "", "a missing copy loaded: %v %q", load, text)
	delete(text)
}
/*
A cached copy is read whole or not at all: an allocator that runs dry, a copy
larger than any download elodin writes, and a file that holds more or less
than its size said are each refused with a reason, never handed on cut short (#757).
*/
@(test)
test_a_cached_copy_is_read_whole_or_refused :: proc(t: ^testing.T) {
	defer free_all(context.temp_allocator)
	path := fmt.tprintf("/tmp/elodin-server-lists-test-whole-%d.txt", os.get_pid())
	body := make([]u8, 40000, context.temp_allocator)
	for &b in body {
		b = 'a'
	}
	if !testing.expect(t, os.write_entire_file(path, body) == nil, "cannot write the copy") {
		return
	}
	defer os.remove(path)

	// Room for the whole copy: read, all of it.
	data, why, read := read_cache_file(path, context.temp_allocator)
	testing.expectf(t, read && len(data) == len(body), "a copy with room was not read whole: %v %q, %d of %d bytes", read, why, len(data), len(body))

	// Room for half of it: refused, not cut short.
	backing := make([]u8, len(body) / 2)
	defer delete(backing)
	arena: mem.Arena
	mem.arena_init(&arena, backing)
	data, why, read = read_cache_file(path, mem.arena_allocator(&arena))
	testing.expectf(t, !read && why == "there is no memory to read it", "a copy with no room for it: %v %q, %d of %d bytes", read, why, len(data), len(body))

	// Larger than any download, as a sparse file: refused before any allocation.
	big := fmt.tprintf("/tmp/elodin-server-lists-test-big-%d.txt", os.get_pid())
	if !testing.expect(t, os.write_entire_file(big, "0.0.0.0 a.example\n") == nil, "cannot write the large copy") {
		return
	}
	defer os.remove(big)
	if !testing.expect(t, posix.truncate(strings.clone_to_cstring(big, context.temp_allocator), upstream.MAX_HTTP_BODY + 1) == .OK, "cannot grow the large copy") {
		return
	}
	data, why, read = read_cache_file(big, context.temp_allocator)
	testing.expectf(t, !read && why == "it is larger than any download", "a copy past the download cap: %v %q, %d bytes", read, why, len(data))

	// More than its size said: a /proc file says 0 and holds lines.
	data, why, read = read_cache_file("/proc/self/status", context.temp_allocator)
	testing.expectf(t, !read && why == "its size changed while it was read", "a file past its stat size: %v %q, %d bytes", read, why, len(data))

	// Less than its size said: a sysfs attribute says a page and holds a line.
	short :: "/sys/kernel/mm/transparent_hugepage/enabled"
	held, rerr := os.read_entire_file(short, context.temp_allocator)
	fi, serr := os.stat(short, context.temp_allocator)
	if !testing.expectf(t, rerr == nil && serr == nil && fi.size > i64(len(held)), "the premise: %s holds less than its size, %v %v", short, rerr, serr) {
		return
	}
	data, why, read = read_cache_file(short, context.temp_allocator)
	testing.expectf(t, !read && why == "its size changed while it was read", "a file short of its stat size: %v %q, %d bytes", read, why, len(data))
}

/*
A rebuild with no memory to build the rule sets whole is dropped, and the rules
already in effect are kept (#765): whichever allocation is refused - the sets,
the list's text, a rule, the record of what loaded - every rule the list holds
still matches after it, and the refresh is not current, so it is tried again.
*/
@(test)
test_a_rebuild_without_memory_keeps_the_rules_in_effect :: proc(t: ^testing.T) {
	N :: 300
	path := fmt.tprintf("/tmp/elodin-server-lists-test-oom-%d.txt", os.get_pid())
	b := strings.builder_make(context.temp_allocator)
	for i in 0 ..< N {
		fmt.sbprintf(&b, "0.0.0.0 oom-%d.example\n", i)
	}
	if !testing.expect(t, os.write_entire_file(path, strings.to_string(b)) == nil, "cannot write the list") {
		return
	}
	defer os.remove(path)

	cfg := config.default_config()
	cfg.blocking.lists = []config.Block_List{{name = "l", file = path, format = .Hosts, enabled = true}}
	// Enough that the operator's rules take the table past the list's 80%.
	OPERATOR :: 150
	rules: [OPERATOR]string
	for &rule, i in rules {
		rule = fmt.tprintf("||operator-%d.example^", i)
	}
	cfg.blocking.rules = rules[:]
	s := list_server(&cfg)
	defer close_list_server(&s)
	if !testing.expect(t, reload_filters(&s, false), "the list did not load") {
		return
	}
	key := list_key(cfg.blocking.lists[0], false)

	// One for every run, so the allocator a swapped-in set keeps stays good.
	f: testkit.Fail_Nth
	f.backing = context.allocator
	dropped := 0
	for fail_at := 1; ; fail_at += 1 {
		f.seen, f.fail_at, f.fail_for = 0, fail_at, 1
		generation := filter.engine_generation(s.filters)
		current: bool
		{
			context.allocator = testkit.fail_nth(&f)
			current = reload_filters(&s, false)
		}
		swapped := filter.engine_generation(s.filters) != generation
		if !swapped {
			dropped += 1
			testing.expectf(t, !current, "run %d: a dropped rebuild is current", fail_at)
		}
		testing.expectf(t, s.lists_loaded[key], "run %d: the list is no longer recorded as loaded", fail_at)
		for i in 0 ..< N {
			name := fmt.tprintf("oom-%d.example.", i)
			if !testing.expectf(t, filter.engine_match(s.filters, name, .A) == .Blocked, "run %d: %s is not blocked", fail_at, name) {
				return
			}
		}
		for i in 0 ..< OPERATOR {
			name := fmt.tprintf("operator-%d.example.", i)
			if !testing.expectf(t, filter.engine_match(s.filters, name, .A) == .Blocked, "run %d: the operator's %s is not blocked", fail_at, name) {
				return
			}
		}
		if f.seen < fail_at {
			// Nothing was refused: every allocation has been.
			testing.expect(t, current && swapped, "a rebuild with every allocation granted did not take")
			break
		}
	}
	// The premise: refusals reached the build, not only what follows the swap.
	testing.expectf(t, dropped >= 5, "only %d rebuilds were dropped", dropped)
}

/*
A list's key is spelt without allocating, so a temp allocator that cannot grow
gives it the key it has, not one cut short that `lists_loaded` holds no entry
for (#765). Each part of the list it is drawn from tells it from another.
*/
@(test)
test_a_list_key_needs_no_memory :: proc(t: ^testing.T) {
	list := config.Block_List{url = "https://lists.example/ads.txt"}
	want := list_key(list, false)
	// Every request refused, as a temp arena that cannot grow refuses them.
	f := testkit.Fail_Nth{fail_at = 1, fail_for = 1 << 30}
	got: u64
	{
		context.allocator = testkit.fail_nth(&f)
		context.temp_allocator = context.allocator
		got = list_key(list, false)
	}
	testing.expect_value(t, f.seen, 0)
	testing.expect_value(t, got, want)
	testing.expect(t, list_key(list, true) != want, "an allowlist shares a blocklist's key")
	testing.expect(t, list_key({file = list.url}, false) != want, "a file shares a url's key")
	testing.expect(t, list_key({url = "https://lists.example/ads.tx", file = "t"}, false) != want, "the url and file run together")
}

/*
An operator's allow rule written without `@@` is spelt with it in the temp
allocator; one that cannot grow drops the rebuild rather than the rule (#765).
*/
@(test)
test_an_operator_allow_rule_without_memory_drops_the_build :: proc(t: ^testing.T) {
	cfg := config.default_config()
	cfg.blocking.rules = []string{"||ok.example^"}
	cfg.blocking.allow_rules = []string{"||ok.example^"}
	block, allow, whole := build_filter_sets(&cfg, false)
	if !testing.expect(t, whole, "no whole sets with memory to spare") {
		return
	}
	// The premise: with memory, the allow rule takes.
	testing.expect(t, filter.set_cover(allow, "ok.example", .A) != .None, "the allow rule did not take")
	filter.set_destroy(block)
	filter.set_destroy(allow)

	// Every request refused, as a temp arena that cannot grow refuses them.
	f := testkit.Fail_Nth{fail_at = 1, fail_for = 1 << 30}
	{
		context.temp_allocator = testkit.fail_nth(&f)
		block, allow, whole = build_filter_sets(&cfg, false)
	}
	testing.expect(t, f.seen > 0, "the temp allocator was not asked")
	testing.expect(t, !whole, "sets without the allow rule were built whole")
	filter.set_destroy(block)
	filter.set_destroy(allow)
}

/*
A rebuild dropped for want of memory is tried again whether or not the server
fetches or refreshes (#765): what it lacked was memory, not a list the network
could bring back, and the rules in effect may be none. One that was not current
for want of a download is retried only where downloads and refreshes happen.
*/
@(test)
test_a_rebuild_without_memory_is_retried_whatever_the_refresh :: proc(t: ^testing.T) {
	day := 24 * time.Hour
	Case :: struct {
		current, no_memory, no_fetch: bool,
		refresh:                      time.Duration,
		want:                         time.Duration,
	}
	cases := []Case {
		{current = true, refresh = day, want = 0},
		{refresh = day, want = REFRESH_RETRY_FIRST},
		{no_fetch = true, refresh = day, want = 0},
		{refresh = 0, want = 0},
		{no_memory = true, refresh = day, want = REFRESH_RETRY_FIRST},
		{no_memory = true, no_fetch = true, refresh = day, want = REFRESH_RETRY_FIRST},
		{no_memory = true, refresh = 0, want = REFRESH_RETRY_FIRST},
		{no_memory = true, no_fetch = true, refresh = 0, want = REFRESH_RETRY_FIRST},
	}
	for c in cases {
		got := retry_after(c.current, c.no_memory, c.no_fetch, c.refresh, 0)
		testing.expectf(t, got == c.want, "%v: waits %v", c, got)
	}
	// With no refresh interval to stop at, the doubling stops at the cap.
	testing.expect_value(t, retry_after(false, true, true, 0, REFRESH_RETRY_MAX), REFRESH_RETRY_MAX)

	// A retry for want of memory is due once waited, whether or not refreshes
	// run; any other retry, and the interval, only where they do.
	testing.expect(t, refresh_due(true, true, 0, REFRESH_RETRY_FIRST, REFRESH_RETRY_FIRST), "a retry for memory without refreshes is never due")
	testing.expect(t, !refresh_due(true, true, 0, REFRESH_RETRY_FIRST, REFRESH_RETRY_FIRST - time.Second), "a retry is due before its wait")
	testing.expect(t, !refresh_due(false, false, 0, REFRESH_RETRY_FIRST, 2 * day), "a download's retry left pending runs with refreshes off")
	testing.expect(t, !refresh_due(true, false, day, REFRESH_RETRY_FIRST, 2 * day), "a download's retry left pending runs without the network")
	testing.expect(t, refresh_due(false, false, day, REFRESH_RETRY_FIRST, REFRESH_RETRY_FIRST), "a download's retry is not due where refreshes run")
	testing.expect(t, !refresh_due(true, false, day, 0, 2 * day), "a refresh is due without the network")
	testing.expect(t, !refresh_due(false, false, 0, 0, 2 * day), "a refresh is due with refreshes off")
	testing.expect(t, refresh_due(false, false, day, 0, day), "the interval's refresh is not due")
	testing.expect(t, !refresh_due(false, false, day, 0, day - time.Second), "the interval's refresh is due early")
}

/*
A cached copy there is no memory to name, fingerprint or read is `.No_Memory`,
as a `file:` list is (#765), never taken for one of another url or a copy that
is not there. Each allocation `cached_copy` makes, in either allocator, is
refused in turn: the copy is read whole or the load is `.No_Memory`.
*/
@(test)
test_a_cached_copy_with_no_memory_to_read_is_no_memory :: proc(t: ^testing.T) {
	defer free_all(context.temp_allocator)
	cfg, dir := list_test_dir(t, "no-memory-copy")
	defer os.remove(dir)
	// A query, so the copy is read only beside its fingerprint.
	list := config.Block_List{name = "l", url = "http://192.0.2.1/l.txt?key=k", format = .Hosts, enabled = true}
	BODY :: "0.0.0.0 a.example\n"
	save_cached_copy(&cfg, list, BODY)
	path := list_cache_path(&cfg, list)
	defer os.remove(path)
	defer os.remove(source_path(path))
	// The premise: with memory, the copy loads.
	text, load := cached_copy(&cfg, list, .Stale)
	testing.expect_value(t, load, List_Load.Stale)
	testing.expect_value(t, text, BODY)
	delete(text)

	for temp in ([]bool{false, true}) {
		refused := 0
		for fail_at := 1; ; fail_at += 1 {
			f := testkit.Fail_Nth{backing = context.temp_allocator if temp else context.allocator, fail_at = fail_at, fail_for = 1}
			{
				// Each scoped to this block: one allocator refuses, the other is as it was.
				context.temp_allocator = testkit.fail_nth(&f) if temp else context.temp_allocator
				context.allocator = context.allocator if temp else testkit.fail_nth(&f)
				text, load = cached_copy(&cfg, list, .Stale)
			}
			if f.seen < fail_at {
				testing.expectf(t, load == .Stale && text == BODY, "temp %v: with every allocation granted, %v %q", temp, load, text)
				delete(text)
				break
			}
			refused += 1
			testing.expectf(t, load == .No_Memory || (load == .Stale && text == BODY), "temp %v, run %d: %v %q", temp, fail_at, load, text)
			delete(text)
		}
		testing.expectf(t, refused > 0, "temp %v: no allocation was refused", temp)
	}
}

/*
A `file:` list whose read runs out of memory frees what was read before the
refusal (#765): a file whose size reads as nothing is read a piece at a time,
and the pieces read come back with the error.
*/
@(test)
test_a_file_list_with_no_memory_to_read_frees_what_it_read :: proc(t: ^testing.T) {
	cfg := config.default_config()
	// Its size reads as nothing, and it holds more than one piece.
	list := config.Block_List{name = "l", file = "/proc/self/status", format = .Hosts, enabled = true}
	refused := 0
	for fail_at := 1; ; fail_at += 1 {
		f := testkit.Fail_Nth{backing = context.allocator, fail_at = fail_at, fail_for = 1}
		text: string
		load: List_Load
		downloaded: bool
		{
			context.allocator = testkit.fail_nth(&f)
			text, load, downloaded = list_contents(&cfg, list, false)
		}
		defer delete(text)
		testing.expectf(t, !downloaded, "run %d: a file: list was downloaded", fail_at)
		if f.seen < fail_at {
			testing.expect_value(t, load, List_Load.Current)
			break
		}
		refused += 1
		testing.expectf(t, load == .No_Memory || load == .Current, "run %d: %v", fail_at, load)
	}
	// The premise: more than the first piece was asked for, so a refusal came
	// with some already read.
	testing.expectf(t, refused >= 2, "only %d allocations were refused", refused)
}

/*
The operator's rules stop at the first there is no memory for: the build is
dropped, and the rules after it are neither added nor warned of as adding
nothing (#765).
*/
@(test)
test_operator_rules_stop_at_the_first_without_memory :: proc(t: ^testing.T) {
	N :: 150
	rules: [N]string
	for &rule, i in rules {
		rule = fmt.tprintf("||operator-%d.example^", i)
	}
	cfg := config.default_config()
	cfg.blocking.rules = rules[:]
	refused := 0
	for fail_at := 1; ; fail_at += 1 {
		f := testkit.Fail_Nth{backing = context.allocator, fail_at = fail_at, fail_for = 1}
		block, allow: ^filter.Set
		whole: bool
		{
			context.allocator = testkit.fail_nth(&f)
			block, allow = filter.set_make(), filter.set_make()
			if block != nil && allow != nil {
				whole = add_operator_rules(&cfg, block, allow)
			}
		}
		defer filter.set_destroy(block)
		defer filter.set_destroy(allow)
		if f.seen < fail_at {
			testing.expect(t, whole, "a run with every allocation granted is not whole")
			testing.expect_value(t, block.count, N)
			break
		}
		if block == nil || allow == nil {
			continue
		}
		refused += 1
		testing.expectf(t, !whole, "run %d: a refusal reads as whole", fail_at)
		// What was added is the rules before the refused one, and none after.
		first := N
		for i in 0 ..< N {
			if filter.set_cover(block, fmt.tprintf("operator-%d.example", i), .A) == .None {
				first = i
				break
			}
		}
		if !testing.expectf(t, first < N, "run %d: every rule was added", fail_at) {
			continue
		}
		for i in first + 1 ..< N {
			name := fmt.tprintf("operator-%d.example", i)
			testing.expectf(t, filter.set_cover(block, name, .A) == .None, "run %d: %s was added after the refusal at %d", fail_at, name, first)
		}
	}
	testing.expect(t, refused > 0, "no refusal reached the operator's rules")
}

/*
A list there is no memory to hold that never loaded is left out, and the others
are built again without it (#765), as AdGuard Home goes on with the filters that
load: no list is ever in effect cut short, and the operator's own rules - here
an allow rule for a name a list blocks - are in effect whole or not at all. Each
allocation of a first build is refused in turn, from an empty engine.
*/
@(test)
test_a_list_without_memory_that_never_loaded_is_left_out :: proc(t: ^testing.T) {
	N :: 200
	paths: [2]string
	for &path, l in paths {
		path = fmt.tprintf("/tmp/elodin-server-lists-test-first-%d-%d.txt", l, os.get_pid())
		b := strings.builder_make(context.temp_allocator)
		for i in 0 ..< N {
			fmt.sbprintf(&b, "0.0.0.0 first-%d-%d.example\n", l, i)
		}
		if !testing.expect(t, os.write_entire_file(path, strings.to_string(b)) == nil, "cannot write a list") {
			return
		}
	}
	defer os.remove(paths[0])
	defer os.remove(paths[1])
	cfg := config.default_config()
	cfg.blocking.lists = []config.Block_List {
		{name = "a", file = paths[0], format = .Hosts, enabled = true},
		{name = "b", file = paths[1], format = .Hosts, enabled = true},
	}
	cfg.blocking.rules = []string{"||operator.example^"}
	// The first list's first name, which the operator allows.
	cfg.blocking.allow_rules = []string{"||first-0-0.example^"}
	held :: proc(s: ^Server, l: int) -> (n: int) {
		for i in 0 ..< N {
			n += int(filter.engine_match(s.filters, fmt.tprintf("first-%d-%d.example.", l, i), .A) == .Blocked)
		}
		return
	}

	// One for every run, so the allocator a swapped-in set keeps stays good
	// until the server holding it is closed.
	f: testkit.Fail_Nth
	f.backing = context.allocator
	left_out, unrecorded := 0, 0
	for fail_at := 1; ; fail_at += 1 {
		s := list_server(&cfg)
		defer close_list_server(&s)
		f.seen, f.fail_at, f.fail_for = 0, fail_at, 1
		current: bool
		{
			context.allocator = testkit.fail_nth(&f)
			current = reload_filters(&s, false)
		}
		a, b := held(&s, 0), held(&s, 1)
		swapped := filter.engine_generation(s.filters) != 0
		if f.seen < fail_at {
			testing.expect(t, current && !s.rules_no_memory && a == N - 1 && b == N, "a build with every allocation granted is not whole")
			break
		}
		if !swapped {
			testing.expectf(t, !current && s.rules_no_memory, "run %d: a dropped build is not marked for a retry", fail_at)
			continue
		}
		// Each list whole (but the name the operator allows) or not at all.
		testing.expectf(t, a == 0 || a == N - 1, "run %d: the first list is in effect cut short, %d of %d", fail_at, a, N - 1)
		testing.expectf(t, b == 0 || b == N, "run %d: the second list is in effect cut short, %d of %d", fail_at, b, N)
		testing.expectf(t, filter.engine_match(s.filters, "operator.example.", .A) == .Blocked, "run %d: the operator's block rule is not in effect", fail_at)
		testing.expectf(t, filter.engine_match(s.filters, "first-0-0.example.", .A) != .Blocked, "run %d: the operator's allow rule is not in effect", fail_at)
		// A list is recorded as loaded only if in effect; and each in effect is,
		// unless there was no memory to record them, which a retry does.
		for l in 0 ..< 2 {
			in_effect := (a if l == 0 else b) > 0
			recorded := s.lists_loaded[list_key(cfg.blocking.lists[l], false)]
			testing.expectf(t, in_effect || !recorded, "run %d: list %d recorded and not in effect", fail_at, l)
			testing.expectf(t, recorded == in_effect || s.rules_no_memory, "run %d: list %d in effect and not recorded, with no retry", fail_at, l)
			unrecorded += int(in_effect && !recorded)
		}
		if a == 0 || b == 0 {
			left_out += 1
			testing.expectf(t, !current && s.rules_no_memory, "run %d: a build that left a list out is not marked for a retry", fail_at)
		}
	}
	// The premise: some runs left a list out and swapped in the rest, and some
	// had no memory to record the lists and swapped them in all the same.
	testing.expectf(t, left_out > 0, "no run left a list out")
	testing.expectf(t, unrecorded > 0, "no run swapped in lists it could not record")
}

/*
With rules in effect, a list added since that there is no memory to hold is left
out too, and the refresh of the lists that loaded before goes ahead (#765): a
list too big to ever fit does not hold every refresh back for good.
*/
@(test)
test_a_new_list_without_memory_does_not_hold_the_others_back :: proc(t: ^testing.T) {
	N :: 200
	paths: [2]string
	for &path, l in paths {
		path = fmt.tprintf("/tmp/elodin-server-lists-test-new-%d-%d.txt", l, os.get_pid())
		b := strings.builder_make(context.temp_allocator)
		for i in 0 ..< N {
			fmt.sbprintf(&b, "0.0.0.0 new-%d-%d.example\n", l, i)
		}
		if !testing.expect(t, os.write_entire_file(path, strings.to_string(b)) == nil, "cannot write a list") {
			return
		}
	}
	defer os.remove(paths[0])
	defer os.remove(paths[1])
	old := config.Block_List{name = "old", file = paths[0], format = .Hosts, enabled = true}
	added := config.Block_List{name = "added", file = paths[1], format = .Hosts, enabled = true}
	held :: proc(s: ^Server, l: int) -> (n: int) {
		for i in 0 ..< N {
			n += int(filter.engine_match(s.filters, fmt.tprintf("new-%d-%d.example.", l, i), .A) == .Blocked)
		}
		return
	}

	f: testkit.Fail_Nth
	f.backing = context.allocator
	went_ahead := 0
	for fail_at := 1; ; fail_at += 1 {
		cfg := config.default_config()
		cfg.blocking.lists = []config.Block_List{old}
		s := list_server(&cfg)
		defer close_list_server(&s)
		if !testing.expect(t, reload_filters(&s, false), "the old list did not load") {
			return
		}
		// The added list first, so running out on it leaves the old one untried.
		cfg.blocking.lists = []config.Block_List{added, old}
		generation := filter.engine_generation(s.filters)
		f.seen, f.fail_at, f.fail_for = 0, fail_at, 1
		{
			context.allocator = testkit.fail_nth(&f)
			reload_filters(&s, false)
		}
		testing.expectf(t, held(&s, 0) == N, "run %d: the old list is out of effect", fail_at)
		if f.seen < fail_at {
			break
		}
		if filter.engine_generation(s.filters) != generation && held(&s, 1) == 0 {
			went_ahead += 1
			testing.expectf(t, s.rules_no_memory, "run %d: the added list left out is not retried", fail_at)
		}
	}
	testing.expectf(t, went_ahead > 0, "no refresh went ahead without the added list")
}

/*
A rebuild that leaves a list out for want of memory builds the others again from
the copies the first build saved, and downloads nothing twice, while a list the
first build never reached is downloaded in the next (#765). Each allocation of
a rebuild of two downloaded lists is refused in turn.
*/
@(test)
test_a_rebuild_downloads_each_list_once :: proc(t: ^testing.T) {
	N :: 200
	// Not in the temp allocator, which each run below frees.
	bodies: [2]string
	for &body, l in bodies {
		b := strings.builder_make()
		for i in 0 ..< N {
			fmt.sbprintf(&b, "0.0.0.0 once-%d-%d.example\n", l, i)
		}
		body = strings.to_string(b)
	}
	defer delete(bodies[0])
	defer delete(bodies[1])
	held :: proc(s: ^Server, l: int) -> (n: int) {
		for i in 0 ..< N {
			n += int(filter.engine_match(s.filters, fmt.tprintf("once-%d-%d.example.", l, i), .A) == .Blocked)
		}
		return
	}

	f: testkit.Fail_Nth
	f.backing = context.allocator
	left_out, first_left_out := 0, 0
	for fail_at := 1; ; fail_at += 1 {
		// Registered first so it runs last: the removals below read paths it
		// zeroes.
		defer free_all(context.temp_allocator)
		ones: [2]One_List
		servers: [2]^thread.Thread
		urls: [2]string
		for l in 0 ..< 2 {
			server, url, ok := start_one_list(t, &ones[l], bodies[l], 4)
			if !ok {
				for k in 0 ..< l {
					stop_one_list(&ones[k], servers[k])
				}
				return
			}
			servers[l], urls[l] = server, url
		}
		cfg, dir := list_test_dir(t, fmt.tprintf("once-%d", fail_at))
		defer os.remove(dir)
		// Never fresh, so every build would download.
		cfg.blocking.refresh = 0
		cfg.blocking.lists = []config.Block_List {
			{name = "a", url = urls[0], format = .Hosts, enabled = true},
			{name = "b", url = urls[1], format = .Hosts, enabled = true},
		}
		for list in cfg.blocking.lists {
			defer os.remove(list_cache_path(&cfg, list))
		}
		s := list_server(&cfg)
		defer close_list_server(&s)
		f.seen, f.fail_at, f.fail_for = 0, fail_at, 1
		{
			context.allocator = testkit.fail_nth(&f)
			reload_filters(&s, true)
		}
		for l in 0 ..< 2 {
			stop_one_list(&ones[l], servers[l])
			testing.expectf(t, ones[l].served <= 1, "run %d: list %d was downloaded %d times", fail_at, l, ones[l].served)
		}
		if f.seen < fail_at {
			testing.expect(t, held(&s, 0) == N && held(&s, 1) == N, "a rebuild with every allocation granted is not whole")
			break
		}
		left_out += int(held(&s, 0) == N && held(&s, 1) == 0)
		if filter.engine_generation(s.filters) != 0 && held(&s, 0) == 0 {
			// The second list, which the first build never reached, was
			// downloaded by the next.
			first_left_out += 1
			testing.expectf(t, held(&s, 1) == N && ones[1].served == 1, "run %d: with the first list left out, the second is in effect for %d of %d names, downloaded %d times", fail_at, held(&s, 1), N, ones[1].served)
		}
	}
	// The premise: some rebuilds left the second list out and built the first
	// again, and some left the first out before the second was reached.
	testing.expectf(t, left_out > 0, "no rebuild left the second list out")
	testing.expectf(t, first_left_out > 0, "no rebuild left the first list out")
}

/*
Where a list that loaded before runs out, the lists added since are left out
first, to make room for the ones in effect (#765): a new list ahead of an old
one that took the memory does not hold every refresh back. Refreshes that go
ahead without the added list, each with one allocation refused, are counted
with the old list behind it and with the added one alone: the same refusals of
the added one's own load go ahead in both, and only the old one's, which
`leave_out_new` makes room for, add to the first.
*/
@(test)
test_a_list_in_effect_that_runs_out_leaves_out_the_new_ones_first :: proc(t: ^testing.T) {
	N :: 200
	paths: [2]string
	for &path, l in paths {
		path = fmt.tprintf("/tmp/elodin-server-lists-test-room-%d-%d.txt", l, os.get_pid())
		b := strings.builder_make(context.temp_allocator)
		for i in 0 ..< N {
			fmt.sbprintf(&b, "0.0.0.0 room-%d-%d.example\n", l, i)
		}
		if !testing.expect(t, os.write_entire_file(path, strings.to_string(b)) == nil, "cannot write a list") {
			return
		}
	}
	defer os.remove(paths[0])
	defer os.remove(paths[1])
	old := config.Block_List{name = "old", file = paths[0], format = .Hosts, enabled = true}
	added := config.Block_List{name = "added", file = paths[1], format = .Hosts, enabled = true}

	// Refreshes of `lists`, over the old list loaded alone, that go ahead without
	// the added one.
	went_ahead :: proc(t: ^testing.T, old: config.Block_List, lists: []config.Block_List) -> (n: int) {
		f: testkit.Fail_Nth
		f.backing = context.allocator
		for fail_at := 1; ; fail_at += 1 {
			cfg := config.default_config()
			cfg.blocking.lists = []config.Block_List{old}
			s := list_server(&cfg)
			defer close_list_server(&s)
			if !testing.expect(t, reload_filters(&s, false), "the old list did not load") {
				return
			}
			cfg.blocking.lists = lists
			generation := filter.engine_generation(s.filters)
			f.seen, f.fail_at, f.fail_for = 0, fail_at, 1
			{
				context.allocator = testkit.fail_nth(&f)
				reload_filters(&s, false)
			}
			if f.seen < fail_at {
				return
			}
			added_held := filter.engine_match(s.filters, "room-1-0.example.", .A) == .Blocked
			n += int(filter.engine_generation(s.filters) != generation && !added_held)
		}
	}
	alone := went_ahead(t, old, []config.Block_List{added})
	ahead := went_ahead(t, old, []config.Block_List{added, old})
	// The premise: the added list's own refusals were reached.
	testing.expectf(t, alone > 0, "no refresh of the added list alone went ahead without it")
	testing.expectf(t, ahead > alone, "%d refreshes went ahead without the added list ahead of the old one, %d with it alone", ahead, alone)
}

// Where refreshes are off, the maintenance loop's retries read the copies on
// disk; only a reload downloads, and nothing does under `--no-fetch` (#765).
@(test)
test_a_retry_with_refreshes_off_downloads_nothing :: proc(t: ^testing.T) {
	day := 24 * time.Hour
	testing.expect(t, rebuild_fetches(false, false, day), "a refresh does not download")
	testing.expect(t, rebuild_fetches(false, true, 0), "a reload with refreshes off does not download")
	testing.expect(t, !rebuild_fetches(false, false, 0), "a retry with refreshes off downloads")
	testing.expect(t, !rebuild_fetches(true, true, day), "a reload under --no-fetch downloads")
	testing.expect(t, !rebuild_fetches(true, false, day), "a refresh under --no-fetch downloads")
}

/*
A list a later build of one rebuild reads again from its copy is `.Stale`, never
taken for current because the copy was read without the network (#765): here a
download that failed, with a copy standing in. Each allocation is refused in
turn; where the new list after it is left out, the downloaded one is read again.
*/
@(test)
test_a_list_read_again_keeps_its_load :: proc(t: ^testing.T) {
	defer free_all(context.temp_allocator)
	cfg, dir := list_test_dir(t, "read-again")
	defer os.remove(dir)
	// Never fresh, so the download is tried, and refused: nothing listens there.
	cfg.blocking.refresh = 0
	stale := config.Block_List{name = "stale", url = "http://127.0.0.1:1/l.txt", format = .Hosts, enabled = true}
	save_cached_copy(&cfg, stale, "0.0.0.0 stale.example\n")
	defer os.remove(list_cache_path(&cfg, stale))
	defer os.remove(source_path(list_cache_path(&cfg, stale)))
	path := fmt.tprintf("/tmp/elodin-server-lists-test-read-again-%d.txt", os.get_pid())
	b := strings.builder_make(context.temp_allocator)
	for i in 0 ..< 200 {
		fmt.sbprintf(&b, "0.0.0.0 new-%d.example\n", i)
	}
	if !testing.expect(t, os.write_entire_file(path, strings.to_string(b)) == nil, "cannot write the list") {
		return
	}
	defer os.remove(path)
	cfg.blocking.lists = []config.Block_List{stale, {name = "new", file = path, format = .Hosts, enabled = true}}
	s := list_server(&cfg)
	defer close_list_server(&s)

	read_again := 0
	for fail_at := 1; ; fail_at += 1 {
		loads: [2]List_Load
		passes: [2]List_Pass
		f := testkit.Fail_Nth{backing = context.allocator, fail_at = fail_at, fail_for = 1}
		block, allow: ^filter.Set
		whole: bool
		{
			context.allocator = testkit.fail_nth(&f)
			block, allow, whole = build_what_fits(&s, &cfg, true, loads[:], passes[:])
		}
		filter.set_destroy(block)
		filter.set_destroy(allow)
		if f.seen < fail_at {
			testing.expect(t, whole && loads[0] == .Stale && loads[1] == .Current, "a build with every allocation granted")
			break
		}
		if whole && passes[1].left_out {
			read_again += 1
			testing.expectf(t, loads[0] == .Stale, "run %d: the list read again is %v", fail_at, loads[0])
		}
	}
	testing.expectf(t, read_again > 0, "no build read the first list again")
}

/*
Where the operator's own rules run out, a list that never loaded is left out to
make room for them (#765), rather than the build dropped: at a start, that would
leave no rule in effect while the list that took the memory stays the same.
Builds that leave the list out with the operator's rules in effect, each with
one allocation of a first build refused, are counted with enough operator rules
to grow the table and with none: the list's own refusals leave it out in both,
and only the operator's rules', which `leave_out_newest` makes room for, add to
the first.
*/
@(test)
test_operator_rules_without_memory_leave_a_new_list_out :: proc(t: ^testing.T) {
	N :: 200
	path := fmt.tprintf("/tmp/elodin-server-lists-test-operator-room-%d.txt", os.get_pid())
	b := strings.builder_make(context.temp_allocator)
	for i in 0 ..< N {
		fmt.sbprintf(&b, "0.0.0.0 big-%d.example\n", i)
	}
	if !testing.expect(t, os.write_entire_file(path, strings.to_string(b)) == nil, "cannot write the list") {
		return
	}
	defer os.remove(path)
	// Enough that they grow the table the list filled.
	OPERATOR :: 300
	rules: [OPERATOR]string
	for &rule, i in rules {
		rule = fmt.tprintf("||operator-%d.example^", i)
	}

	made_room :: proc(t: ^testing.T, path: string, rules: []string) -> (n: int) {
		cfg := config.default_config()
		cfg.blocking.lists = []config.Block_List{{name = "big", file = path, format = .Hosts, enabled = true}}
		cfg.blocking.rules = rules
		f: testkit.Fail_Nth
		f.backing = context.allocator
		for fail_at := 1; ; fail_at += 1 {
			s := list_server(&cfg)
			defer close_list_server(&s)
			f.seen, f.fail_at, f.fail_for = 0, fail_at, 1
			{
				context.allocator = testkit.fail_nth(&f)
				reload_filters(&s, false)
			}
			if f.seen < fail_at {
				return
			}
			operator := true
			for i in 0 ..< len(rules) {
				operator &&= filter.engine_match(s.filters, fmt.tprintf("operator-%d.example.", i), .A) == .Blocked
			}
			big := filter.engine_match(s.filters, "big-0.example.", .A) == .Blocked
			if filter.engine_generation(s.filters) != 0 && operator && !big {
				n += 1
				testing.expectf(t, s.rules_no_memory, "run %d: the list left out is not retried", fail_at)
			}
		}
	}
	none := made_room(t, path, nil)
	with := made_room(t, path, rules[:])
	// The premise: the list's own refusals were reached.
	testing.expectf(t, none > 0, "the list was never left out")
	testing.expectf(t, with > none, "%d builds made room for the operator's rules, %d left the list out with none", with, none)
}

/*
A build's `loads` say what that build did, whatever an earlier build of the same
rebuild found (#765): a list after the one that ran out is `.No_Memory`, never
the load an earlier build gave it, so `leave_out_newest` can only pick a list
this build loaded. Each allocation of a build of two lists read before is
refused in turn.
*/
@(test)
test_a_build_says_only_what_it_loaded :: proc(t: ^testing.T) {
	paths: [2]string
	for &path, l in paths {
		path = fmt.tprintf("/tmp/elodin-server-lists-test-said-%d-%d.txt", l, os.get_pid())
		b := strings.builder_make(context.temp_allocator)
		for i in 0 ..< 200 {
			fmt.sbprintf(&b, "0.0.0.0 said-%d-%d.example\n", l, i)
		}
		if !testing.expect(t, os.write_entire_file(path, strings.to_string(b)) == nil, "cannot write a list") {
			return
		}
	}
	defer os.remove(paths[0])
	defer os.remove(paths[1])
	cfg := config.default_config()
	cfg.blocking.lists = []config.Block_List {
		{name = "a", file = paths[0], format = .Hosts, enabled = true},
		{name = "b", file = paths[1], format = .Hosts, enabled = true},
	}
	ran_out_first := 0
	for fail_at := 1; ; fail_at += 1 {
		// As an earlier build of the rebuild left them.
		loads := [2]List_Load{.Current, .Current}
		passes := [2]List_Pass{{read = true, found = .Current}, {read = true, found = .Current}}
		f := testkit.Fail_Nth{backing = context.allocator, fail_at = fail_at, fail_for = 1}
		block, allow: ^filter.Set
		{
			context.allocator = testkit.fail_nth(&f)
			block, allow, _ = build_filter_sets(&cfg, false, loads[:], passes[:]) // lint:allow whole is what `loads` says here
		}
		filter.set_destroy(block)
		filter.set_destroy(allow)
		if f.seen < fail_at {
			break
		}
		if loads[0] == .No_Memory {
			ran_out_first += 1
			testing.expectf(t, loads[1] == .No_Memory, "run %d: the list after the one that ran out says %v", fail_at, loads[1])
		}
	}
	testing.expect(t, ran_out_first > 0, "no build ran out on the first list")
}

/*
A rebuild that leaves a list out for want of memory is marked for a retry
whatever else holds the refresh back, and wherever the list is in the order
(#765): here a list in effect whose copy is a web page comes first.
*/
@(test)
test_a_list_left_out_is_retried_whatever_holds_the_refresh_back :: proc(t: ^testing.T) {
	defer free_all(context.temp_allocator)
	cfg, dir := list_test_dir(t, "left-out-held")
	defer os.remove(dir)
	page := config.Block_List{name = "page", url = "http://192.0.2.1/page.txt", format = .Hosts, enabled = true}
	page_path := list_cache_path(&cfg, page)
	if !testing.expect(t, os.write_entire_file(page_path, "<html>no list</html>\n") == nil, "cannot write the copy") {
		return
	}
	defer os.remove(page_path)
	path := fmt.tprintf("/tmp/elodin-server-lists-test-left-out-held-%d.txt", os.get_pid())
	b := strings.builder_make(context.temp_allocator)
	for i in 0 ..< 200 {
		fmt.sbprintf(&b, "0.0.0.0 held-%d.example\n", i)
	}
	if !testing.expect(t, os.write_entire_file(path, strings.to_string(b)) == nil, "cannot write the list") {
		return
	}
	defer os.remove(path)
	cfg.blocking.lists = []config.Block_List{page, {name = "new", file = path, format = .Hosts, enabled = true}}

	held_back := 0
	for fail_at := 1; ; fail_at += 1 {
		s := list_server(&cfg)
		defer close_list_server(&s)
		// As if the page's list had loaded at the last refresh.
		s.lists_loaded[list_key(page, false)] = true
		f := testkit.Fail_Nth{backing = context.allocator, fail_at = fail_at, fail_for = 1}
		{
			context.allocator = testkit.fail_nth(&f)
			reload_filters(&s, false)
		}
		if f.seen < fail_at {
			break
		}
		// Every refused run is held back, by the page or for want of memory.
		testing.expectf(t, filter.engine_generation(s.filters) == 0, "run %d: the refresh went ahead", fail_at)
		testing.expectf(t, s.rules_no_memory, "run %d: a refusal is not marked for a retry", fail_at)
		held_back += 1
	}
	testing.expect(t, held_back > 0, "no run was refused")
}

/*
Where a later build of a rebuild has no copy to read a list again from - the
first read could not save its download, `cache_dir` not being writable - it
downloads the list again rather than leave out a list that loaded (#765). Each
allocation of a first build is refused in turn; where the file list after the
downloaded one is left out, the downloaded one is still in effect.
*/
@(test)
test_a_list_with_no_copy_to_read_again_is_downloaded_again :: proc(t: ^testing.T) {
	N :: 200
	// Not in the temp allocator, which each run below frees.
	body_b := strings.builder_make()
	for i in 0 ..< N {
		fmt.sbprintf(&body_b, "0.0.0.0 unsaved-%d.example\n", i)
	}
	body := strings.to_string(body_b)
	defer delete(body)
	path := fmt.aprintf("/tmp/elodin-server-lists-test-unsaved-%d.txt", os.get_pid())
	defer delete(path)
	file_b := strings.builder_make(context.temp_allocator)
	for i in 0 ..< N {
		fmt.sbprintf(&file_b, "0.0.0.0 unsaved-file-%d.example\n", i)
	}
	if !testing.expect(t, os.write_entire_file(path, strings.to_string(file_b)) == nil, "cannot write the list") {
		return
	}
	defer os.remove(path)

	f: testkit.Fail_Nth
	f.backing = context.allocator
	kept := 0
	for fail_at := 1; ; fail_at += 1 {
		defer free_all(context.temp_allocator)
		one: One_List
		server, url, ok := start_one_list(t, &one, body, 4)
		if !ok {
			return
		}
		cfg := config.default_config()
		// Nothing can be saved there, by root either.
		cfg.blocking.cache_dir = "/proc/elodin-lists-test-unsaved"
		cfg.blocking.lists = []config.Block_List {
			{name = "downloaded", url = url, format = .Hosts, enabled = true},
			{name = "file", file = path, format = .Hosts, enabled = true},
		}
		s := list_server(&cfg)
		defer close_list_server(&s)
		f.seen, f.fail_at, f.fail_for = 0, fail_at, 1
		{
			context.allocator = testkit.fail_nth(&f)
			reload_filters(&s, true)
		}
		stop_one_list(&one, server)
		downloaded := filter.engine_match(s.filters, "unsaved-0.example.", .A) == .Blocked
		file := filter.engine_match(s.filters, "unsaved-file-0.example.", .A) == .Blocked
		if f.seen < fail_at {
			testing.expect(t, downloaded && file, "a build with every allocation granted is not whole")
			break
		}
		if filter.engine_generation(s.filters) != 0 && !file {
			testing.expectf(t, downloaded, "run %d: the downloaded list is out with the file list left out", fail_at)
			kept += int(downloaded)
		}
	}
	testing.expect(t, kept > 0, "no build left the file list out")
}

// The names of the entries in `dir`, which the test fails on when it cannot list.
@(private = "file")
entries_of :: proc(t: ^testing.T, dir: string, loc := #caller_location) -> (names: [dynamic]string, ok: bool) {
	infos, err := os.read_directory_by_path(dir, -1, context.temp_allocator)
	if !testing.expectf(t, err == nil, "cannot list %s: %v", dir, err, loc = loc) {
		return
	}
	names = make([dynamic]string, 0, len(infos), context.temp_allocator)
	for fi in infos {
		append(&names, fi.name)
	}
	return names, true
}

// Whether every entry of `dir` is one of `allowed`; the test fails on any other.
@(private = "file")
expect_only_entries :: proc(t: ^testing.T, dir: string, allowed: []string, what: string, loc := #caller_location) {
	names, ok := entries_of(t, dir, loc)
	if !ok {
		return
	}
	outer: for name in names {
		for a in allowed {
			if name == a {
				continue outer
			}
		}
		testing.expectf(t, false, "%s: a stray %q in %s", what, name, dir, loc = loc)
	}
}

/*
A copy named by a query moves only under names spelt whole (#780). Whichever
allocation of the temp allocator spelling them is refused, a list's own copy
stays where it is and lands under no other list's name, and a copy that moves is
read back as its own url's. With memory to spare, the move is made.
*/
@(test)
test_a_move_without_memory_moves_nothing_it_cannot_name :: proc(t: ^testing.T) {
	defer free_all(context.temp_allocator)
	cfg, dir := list_test_dir(t, "move-no-memory")
	defer os.remove(dir)
	// `kept` is named by its url, so its own copy has the name `other`'s url
	// gave its copy before #487.
	kept := config.Block_List{name = "http://192.0.2.1/c?key=SECRET", url = "http://192.0.2.1/c?key=SECRET", format = .Hosts, enabled = true, named = true}
	other := config.Block_List{name = "http://192.0.2.1/c", url = "http://192.0.2.1/c?key=SECRET", format = .Hosts, enabled = true}
	moved := config.Block_List{name = "http://192.0.2.1/a", url = "http://192.0.2.1/a?key=SECRET", format = .Hosts, enabled = true}
	cfg.blocking.lists = []config.Block_List{kept, other, moved}
	KEPT :: "0.0.0.0 kept.example\n"
	MOVED :: "0.0.0.0 moved.example\n"
	kept_own := list_cache_path(&cfg, kept)
	other_path := list_cache_path(&cfg, other)
	moved_old := strings.concatenate({dir, "/", config.list_cache_name(moved.url)}, context.temp_allocator)
	moved_path := list_cache_path(&cfg, moved)
	all := []string{kept_own, other_path, moved_old, moved_path}
	files := []string{filepath_base(kept_own), filepath_base(moved_old), filepath_base(moved_path), filepath_base(source_path(moved_path))}
	defer for f in all {
		os.remove(f)
		os.remove(source_path(f))
	}

	refused := 0
	for fail_at := 1; ; fail_at += 1 {
		os.remove(moved_path)
		os.remove(source_path(moved_path))
		if !testing.expect(t, os.write_entire_file(kept_own, KEPT) == nil && os.write_entire_file(moved_old, MOVED) == nil, "cannot plant the copies") {
			return
		}
		f := testkit.Fail_Nth{fail_at = fail_at, fail_for = 1}
		{
			context.temp_allocator = testkit.fail_nth(&f)
			move_query_named_caches(&cfg)
		}
		text, load := cached_copy(&cfg, kept, .Stale)
		testing.expectf(t, load == .Stale && text == KEPT, "run %d: the named list's own copy reads as %v %q", fail_at, load, text)
		delete(text)
		testing.expectf(t, !os.exists(other_path), "run %d: a copy was moved to another list's name", fail_at)
		expect_only_entries(t, dir, files, fmt.tprintf("run %d", fail_at))
		if os.exists(moved_old) {
			testing.expectf(t, !os.exists(moved_path), "run %d: a copy left under its url beside one moved", fail_at)
		} else {
			text, load = cached_copy(&cfg, moved, .Stale)
			testing.expectf(t, load == .Stale && text == MOVED, "run %d: the moved copy reads as %v %q", fail_at, load, text)
			delete(text)
		}
		if f.seen < fail_at {
			testing.expectf(t, !os.exists(moved_old), "with every allocation granted, the copy named by its query did not move")
			break
		}
		refused += 1
	}
	testing.expect(t, refused > 0, "no allocation was refused")
}

// The last element of `path`.
@(private = "file")
filepath_base :: proc(path: string) -> string {
	return path[strings.last_index_byte(path, '/') + 1:]
}

// What is in the cache before `test_a_copy_saved_without_memory_is_its_own` saves.
@(private = "file")
Before :: enum {
	None,
	Same_Url,
	Other_Url,
}

// What `test_a_copy_saved_without_memory_is_its_own` saves into.
@(private = "file")
Save_Fixture :: struct {
	cfg:          config.Config,
	dir:          string,
	// The list, and the same list before its query changed.
	list, before: config.Block_List,
	path:         string,
}

@(private = "file")
SAVE_OLD :: "0.0.0.0 old.example\n"
@(private = "file")
SAVE_NEW :: "0.0.0.0 new.example\n"
// What the save test plants as `.tmp` in the working directory.
@(private = "file")
SAVE_SENTINEL :: "not the cache's"
@(private = "file")
SAVE_SUB :: "cache"

/*
A copy saved while the temp allocator refuses a run of requests is read back as
the list's own, new or the one before, and never as another url's: a copy of
another query saved before is read as that query's only while it is that copy.
Nothing is written but the copy and its fingerprint, beside each other in
`cache_dir` (#780): a name spelt short is another list's file, or one outside
the cache, and is never written. The cache directory, made by the save, is made
where it is named and nowhere else. Lists the file names, whose copy with no
fingerprint is their own, and lists it does not, alike.
*/
@(test)
test_a_copy_saved_without_memory_is_its_own :: proc(t: ^testing.T) {
	defer free_all(context.temp_allocator)
	cfg, dir := list_test_dir(t, "save-no-memory")
	defer os.remove(dir)
	cfg.blocking.cache_dir = strings.concatenate({dir, "/", SAVE_SUB}, context.temp_allocator)
	defer os.remove(cfg.blocking.cache_dir)
	// A query, so the copy is read only beside its fingerprint.
	f := Save_Fixture {
		cfg    = cfg,
		dir    = dir,
		list   = {name = "l", url = "http://192.0.2.1/l.txt?key=k", format = .Hosts, enabled = true},
		before = {name = "l", url = "http://192.0.2.1/l.txt?key=old", format = .Hosts, enabled = true},
	}
	f.path = list_cache_path(&f.cfg, f.list)
	defer clear_save_copies(f.path)
	// A fingerprint spelt short is ".src", and a temporary file ".tmp", in the
	// working directory; a ".tmp" there is removed to make way for it. One
	// holding the sentinel is this test's, left by a run stopped before its
	// cleanup.
	planted, _ := os.read_entire_file(".tmp", context.temp_allocator) // lint:allow absent reads as not planted
	if !testing.expect(t, !os.exists(".src") && (!os.exists(".tmp") || string(planted) == SAVE_SENTINEL), "the premise: no .src or .tmp in the working directory") {
		return
	}
	if !testing.expect(t, os.write_entire_file(".tmp", SAVE_SENTINEL) == nil, "cannot plant .tmp") {
		return
	}
	defer os.remove(".tmp")

	for named in ([]bool{false, true}) {
		f.list.named, f.before.named = named, named
		for old in Before {
			// A run longer than one refuses the fingerprint's write and what follows.
			for run_length in 1 ..= 3 {
				if !save_refused_in_turn(t, &f, old, run_length) {
					return
				}
			}
		}
	}
}

@(private = "file")
clear_save_copies :: proc(path: string) {
	os.remove(path)
	os.remove(source_path(path))
}

// One case of `test_a_copy_saved_without_memory_is_its_own`, each allocation
// refused in turn; false where the test cannot go on.
@(private = "file")
save_refused_in_turn :: proc(t: ^testing.T, f: ^Save_Fixture, old: Before, run_length: int) -> bool {
	files := []string{filepath_base(f.path), filepath_base(source_path(f.path))}
	refused := 0
	for fail_at := 1; ; fail_at += 1 {
		clear_save_copies(f.path)
		os.remove(f.cfg.blocking.cache_dir)
		if old != .None {
			saved := f.list if old == .Same_Url else f.before
			save_cached_copy(&f.cfg, saved, SAVE_OLD)
			text, load := cached_copy(&f.cfg, saved, .Stale)
			ok := testing.expectf(t, load == .Stale && text == SAVE_OLD, "the premise: the old copy reads as %v %q", load, text)
			delete(text)
			if !ok {
				return false
			}
		}
		fail := testkit.Fail_Nth{fail_at = fail_at, fail_for = run_length}
		{
			context.temp_allocator = testkit.fail_nth(&fail)
			save_cached_copy(&f.cfg, f.list, SAVE_NEW)
		}
		run := fmt.tprintf("named %v, old %v, %d refused from %d", f.list.named, old, run_length, fail_at)
		text, load := cached_copy(&f.cfg, f.list, .Stale)
		saved := load == .Stale && text == SAVE_NEW
		switch old {
		case .None, .Other_Url:
			testing.expectf(t, saved || load == .Unavailable, "%s: read back as %v %q", run, load, text)
		case .Same_Url:
			testing.expectf(t, saved || (load == .Stale && text == SAVE_OLD), "%s: read back as %v %q", run, load, text)
		}
		delete(text)
		if old == .Other_Url {
			// Cleared only for the new copy to land: a save refused for want of
			// memory leaves it.
			text, load = cached_copy(&f.cfg, f.before, .Stale)
			testing.expectf(t, (saved && load == .Unavailable) || (!saved && load == .Stale && text == SAVE_OLD), "%s: the other query reads as %v %q", run, load, text)
			delete(text)
		}
		if !expect_nothing_stray(t, f, files, run) {
			return false
		}
		if fail.seen < fail_at {
			testing.expectf(t, saved, "%s: with every allocation granted, the new copy was not read back", run)
			break
		}
		refused += 1
	}
	testing.expectf(t, refused > 0, "named %v, old %v, runs of %d: no allocation was refused", f.list.named, old, run_length)
	return true
}

// Whether nothing but the copy and its fingerprint was written, in the cache or
// the working directory; false where the sentinel cannot be planted again.
@(private = "file")
expect_nothing_stray :: proc(t: ^testing.T, f: ^Save_Fixture, files: []string, run: string) -> bool {
	expect_only_entries(t, f.dir, {SAVE_SUB}, run)
	if os.exists(f.cfg.blocking.cache_dir) {
		expect_only_entries(t, f.cfg.blocking.cache_dir, files, run)
	}
	testing.expectf(t, !os.exists(".src"), "%s: a fingerprint written to the working directory", run)
	os.remove(".src")
	sentinel, rerr := os.read_entire_file(".tmp", context.temp_allocator)
	testing.expectf(t, rerr == nil && string(sentinel) == SAVE_SENTINEL, "%s: the working directory's .tmp was replaced (%v)", run, rerr)
	return string(sentinel) == SAVE_SENTINEL || testing.expect(t, os.write_entire_file(".tmp", SAVE_SENTINEL) == nil, "cannot plant .tmp again")
}

/*
A copy whose fingerprint cannot be written, for a reason other than memory, is
not saved (#780): a named list's copy with no fingerprint is read as the copy of
any url the list is given, so written alone it would stand in for the url
before, or for one the list is given later. Another url's copy is left as it was.
*/
@(test)
test_a_copy_without_its_fingerprint_is_not_saved :: proc(t: ^testing.T) {
	defer free_all(context.temp_allocator)
	cfg, dir := list_test_dir(t, "save-unmarked")
	defer os.remove(dir)
	list := config.Block_List{name = "l", url = "http://192.0.2.1/l.txt?key=k", format = .Hosts, enabled = true, named = true}
	before := config.Block_List{name = "l", url = "http://192.0.2.1/l.txt?key=old", format = .Hosts, enabled = true, named = true}
	path := list_cache_path(&cfg, list)
	// A directory with a file in it where the fingerprint's temporary file goes:
	// its create finds one there and cannot remove it.
	blocker := strings.concatenate({source_path(path), ".tmp"}, context.temp_allocator)
	inside := strings.concatenate({blocker, "/x"}, context.temp_allocator)
	defer for p in ([]string{path, source_path(path), inside, blocker}) {
		os.remove(p)
	}
	if !testing.expect(t, os.make_directory(blocker) == nil && os.write_entire_file(inside, "x") == nil, "cannot plant the blocker") {
		return
	}

	// The list's first save.
	save_cached_copy(&cfg, list, SAVE_NEW)
	testing.expect(t, !os.exists(path), "a first copy was written with no fingerprint")

	// Over another url's copy, which is a save's to clear only for its own.
	src, sourced := source_of(before)
	if !testing.expect(t, sourced && os.write_entire_file(path, SAVE_OLD) == nil && os.write_entire_file(source_path(path), src) == nil, "cannot plant the other url's copy") {
		return
	}
	text, load := cached_copy(&cfg, before, .Stale)
	testing.expectf(t, load == .Stale && text == SAVE_OLD, "the premise: the other query's copy reads as %v %q", load, text)
	delete(text)
	save_cached_copy(&cfg, list, SAVE_NEW)
	text, load = cached_copy(&cfg, before, .Stale)
	testing.expectf(t, load == .Stale && text == SAVE_OLD, "the other query's copy reads as %v %q", load, text)
	delete(text)

	// Over this url's own copy, beside its own fingerprint, which stands for the
	// new copy too; nothing else lands as the fingerprint.
	src, sourced = source_of(list)
	if !testing.expect(t, sourced && os.write_entire_file(source_path(path), src) == nil, "cannot plant this url's fingerprint") {
		return
	}
	save_cached_copy(&cfg, list, SAVE_NEW)
	text, load = cached_copy(&cfg, list, .Stale)
	testing.expectf(t, load == .Stale && text == SAVE_NEW, "this url's new copy reads as %v %q", load, text)
	delete(text)
}

/*
A list is not taken as fresh where an allocation deciding it was refused (#780):
`ab` spelt short is `b`, whose copy is fresh, and `q`'s fresh copy is beside
another url's fingerprint, which a check refused would not find. Either would
keep the list from being downloaded for the rest of the refresh window. The
download goes to a port nothing listens on.
*/
@(test)
test_a_name_spelt_short_is_not_fresh :: proc(t: ^testing.T) {
	defer free_all(context.temp_allocator)
	cfg, dir := list_test_dir(t, "fresh-no-memory")
	defer os.remove(dir)
	b := config.Block_List{name = "b", url = "http://127.0.0.1:1/b", format = .Hosts, enabled = true}
	ab := config.Block_List{name = "ab", url = "http://127.0.0.1:1/ab", format = .Hosts, enabled = true}
	q := config.Block_List{name = "q", url = "http://127.0.0.1:1/q", format = .Hosts, enabled = true}
	cfg.blocking.lists = []config.Block_List{b, ab, q}
	b_path := list_cache_path(&cfg, b)
	q_path := list_cache_path(&cfg, q)
	defer for p in ([]string{b_path, q_path, source_path(q_path)}) {
		os.remove(p)
	}
	planted := os.write_entire_file(b_path, "0.0.0.0 b.example\n") == nil && os.write_entire_file(q_path, "0.0.0.0 q.example\n") == nil
	if !testing.expect(t, planted && os.write_entire_file(source_path(q_path), "0123456789abcdef\n") == nil, "cannot write the copies") {
		return
	}
	// The premise: b's copy is fresh for b, and q's is another url's.
	_, fetch := fetch_list(&cfg, b)
	testing.expect_value(t, fetch, Fetch.Cache_Is_Fresh)
	_, fetch = fetch_list(&cfg, q)
	testing.expect_value(t, fetch, Fetch.Failed)

	for list in ([]config.Block_List{ab, q}) {
		refused := 0
		for fail_at := 1; ; fail_at += 1 {
			f := testkit.Fail_Nth{fail_at = fail_at, fail_for = 1}
			text: string
			{
				context.temp_allocator = testkit.fail_nth(&f)
				text, fetch = fetch_list(&cfg, list)
			}
			delete(text)
			testing.expectf(t, fetch != .Cache_Is_Fresh, "%s, run %d: taken as fresh with no copy of its own", list.name, fail_at)
			if f.seen < fail_at {
				testing.expect_value(t, fetch, Fetch.Failed)
				break
			}
			refused += 1
		}
		testing.expectf(t, refused > 0, "%s: no allocation was refused", list.name)
	}
}

/*
The cache directory and those above it are made with a temp allocator that
refuses every request (#780): each is a prefix of the path, so none is made
short, at a path the operator never named.
*/
@(test)
test_cache_directories_need_no_memory :: proc(t: ^testing.T) {
	defer free_all(context.temp_allocator)
	_, dir := list_test_dir(t, "mkdirs-no-memory")
	defer os.remove(dir)
	top := strings.concatenate({dir, "/a"}, context.temp_allocator)
	path := strings.concatenate({top, "//b/"}, context.temp_allocator)
	defer os.remove(top)
	defer os.remove(path)
	f := testkit.Fail_Nth{fail_at = 1, fail_for = max(int)}
	{
		context.temp_allocator = testkit.fail_nth(&f)
		// The premise: every request is refused.
		_, aerr := mem.alloc(1, allocator = context.temp_allocator)
		if !testing.expect_value(t, aerr, mem.Allocator_Error.Out_Of_Memory) {
			return
		}
		make_directories(path)
	}
	testing.expect(t, os.is_dir(path), "the cache directory was not made")
}

// A cache file is the file in `cache_dir` whatever the directory's spelling: a
// slash at its end, the root, or none at all, which is the working directory.
@(test)
test_a_cache_file_is_in_the_cache_directory :: proc(t: ^testing.T) {
	defer free_all(context.temp_allocator)
	cfg := config.default_config()
	Case :: struct {
		dir, want: string,
	}
	for c in ([]Case {
			{"/var/cache/elodin", "/var/cache/elodin/l.list"},
			{"/var/cache/elodin/", "/var/cache/elodin/l.list"},
			{"/", "/l.list"},
			{"cache", "cache/l.list"},
			{"", "l.list"},
		}) {
		cfg.blocking.cache_dir = c.dir
		testing.expect_value(t, cache_file_path(&cfg, "l.list"), c.want)
	}
}

// A refused allocation is no verdict on the cache: only an error of the file or
// the directory reports `cache_dir` unwritable.
@(test)
test_no_memory_is_told_from_an_unwritable_cache :: proc(t: ^testing.T) {
	testing.expect(t, no_memory(mem.Allocator_Error.Out_Of_Memory), "a refused allocation is not no memory")
	testing.expect(t, !no_memory(os.General_Error.Not_Exist), "a missing directory is no memory")
	testing.expect(t, !no_memory(os.Platform_Error(posix.Errno.EACCES)), "a refused write is no memory")
	testing.expect(t, !no_memory(nil), "no error is no memory")
}

/*
A copy named by a query whose fingerprint cannot be written, for a reason other
than memory, still moves (#780): the key leaves `cache_dir`, and a load after it
does not move it back and forth. Another query's fingerprint at the list's name
goes, so the moved copy is never read as that query's download.
*/
@(test)
test_a_move_whose_fingerprint_cannot_be_written_drops_the_key :: proc(t: ^testing.T) {
	defer free_all(context.temp_allocator)
	cfg, dir := list_test_dir(t, "move-unmarked")
	defer os.remove(dir)
	moved := config.Block_List{name = "http://192.0.2.1/a", url = "http://192.0.2.1/a?key=SECRET", format = .Hosts, enabled = true}
	// The same name before the query changed, whose copy and fingerprint are at it.
	before := config.Block_List{name = "http://192.0.2.1/a", url = "http://192.0.2.1/a?key=old", format = .Hosts, enabled = true}
	cfg.blocking.lists = []config.Block_List{moved}
	old := strings.concatenate({dir, "/", config.list_cache_name(moved.url)}, context.temp_allocator)
	path := list_cache_path(&cfg, moved)
	// A directory with a file in it where the fingerprint's temporary file goes:
	// its create finds one there and cannot remove it.
	blocker := strings.concatenate({source_path(path), ".tmp"}, context.temp_allocator)
	inside := strings.concatenate({blocker, "/x"}, context.temp_allocator)
	defer for f in ([]string{old, path, source_path(path), inside, blocker}) {
		os.remove(f)
	}
	save_cached_copy(&cfg, before, "0.0.0.0 before.example\n")
	ok := os.make_directory(blocker) == nil && os.write_entire_file(inside, "x") == nil && os.write_entire_file(old, "0.0.0.0 moved.example\n") == nil
	if !testing.expect(t, ok, "cannot plant the copies") {
		return
	}
	text, load := cached_copy(&cfg, before, .Stale)
	testing.expectf(t, load == .Stale && text == "0.0.0.0 before.example\n", "the premise: the other query's copy reads as %v %q", load, text)
	delete(text)

	for i in 1 ..= 2 {
		move_query_named_caches(&cfg)
		testing.expectf(t, !os.exists(old), "load %d: the copy named by its query is still there", i)
		body, rerr := os.read_entire_file(path, context.temp_allocator)
		testing.expectf(t, rerr == nil && string(body) == "0.0.0.0 moved.example\n", "load %d: the moved copy is %q (%v)", i, body, rerr)
		text, load = cached_copy(&cfg, before, .Stale)
		testing.expectf(t, load == .Unavailable, "load %d: the moved copy reads as the other query's: %v %q", i, load, text)
		delete(text)
		testing.expectf(t, !os.exists(source_path(path)), "load %d: something landed as the fingerprint", i)
	}
}

// Replace the file at `path` with `body` as a save does: staged whole on disk,
// then renamed over it.
@(private = "file")
write_cache_file :: proc(path: string, body: []byte) -> (err: os.Error) {
	tmp := stage_cache_file(path, body) or_return
	if err = os.rename(tmp, path); err != nil {
		os.remove(tmp)
	}
	return
}
