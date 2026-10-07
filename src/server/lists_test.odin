package server

import "core:fmt"
import "core:net"
import "core:os"
import "core:strings"
import "core:testing"
import "core:thread"
import "core:time"
import "elodin:config"
import "elodin:dns"
import "elodin:filter"

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
	block, allow := build_filter_sets(&cfg, false)
	defer filter.set_destroy(block)
	defer filter.set_destroy(allow)

	testing.expect(t, filter.set_lookup(block, "www.pl.ua"), "the operator's block survives a list's badfilter")
	testing.expect(t, filter.set_lookup(allow, "ok.example"), "and so does the operator's allow")
	testing.expect(t, !filter.set_lookup(block, "listed.example"), "and the operator's badfilter cancels a list's rule")
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
	decoded with the slash in it - and is still under a blocked zone (#398). The
	matcher used to refuse such a name as not a domain and let it through.
	*/
	block, allow := filter.set_make(), filter.set_make()
	filter.parse_list(block, allow, "||blocked.example^\n", .Adblock)
	engine := filter.engine_make()
	defer filter.engine_destroy(engine)
	filter.engine_swap(engine, block, allow)

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
		testing.expectf(t, filter.engine_match(engine, msg.question[0].name) == .Blocked, "%s was not blocked", name)
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
	dir := fmt.tprintf("/tmp/elodin-server-lists-test-lost-%d", os.get_pid())
	testing.expect(t, os.make_directory(dir) == nil)
	defer os.remove(dir)
	cfg := config.default_config()
	cfg.blocking.cache_dir = dir
	cfg.blocking.lists = []config.Block_List{{name = "l", url = "http://192.0.2.1/l.txt", format = .Adblock, enabled = true}}
	path := strings.clone(list_cache_path(&cfg, cfg.blocking.lists[0]), context.temp_allocator)
	testing.expect(t, os.write_entire_file(path, "||kept.example^\n") == nil)
	defer os.remove(path)

	engine := filter.engine_make()
	defer filter.engine_destroy(engine)
	s := Server {
		cfg     = &cfg,
		filters = engine,
	}
	defer delete(s.lists_loaded)

	testing.expect(t, reload_filters(&s, false), "the first load was not current")
	testing.expect(t, filter.engine_match(engine, "kept.example") == .Blocked)

	os.remove(path)
	generation := filter.engine_generation(engine)
	testing.expect(t, !reload_filters(&s, false), "a refresh that lost a list was reported current")
	testing.expect_value(t, filter.engine_generation(engine), generation)
	testing.expect(t, filter.engine_match(engine, "kept.example") == .Blocked, "the lost list's rules were swapped out")

	// Once the list is back, the refresh goes through again.
	testing.expect(t, os.write_entire_file(path, "||back.example^\n") == nil)
	testing.expect(t, reload_filters(&s, false))
	testing.expect(t, filter.engine_match(engine, "back.example") == .Blocked)
	testing.expect(t, filter.engine_match(engine, "kept.example") != .Blocked)
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
	engine := filter.engine_make()
	defer filter.engine_destroy(engine)
	s := Server {
		cfg     = &cfg,
		filters = engine,
	}
	defer delete(s.lists_loaded)

	testing.expect(t, !reload_filters(&s, false), "a load missing a list was reported current")
	testing.expect(t, filter.engine_match(engine, "first.example") == .Blocked)

	testing.expect(t, os.write_entire_file(path, "||second.example^\n") == nil)
	testing.expect(t, !reload_filters(&s, false))
	testing.expect(t, filter.engine_match(engine, "second.example") == .Blocked, "the refresh was held back")
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
	n, _ := os.read(old, buf[:])
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
	// It adds nothing and takes rules back, so reading it by what it added
	// alone called its download empty and never cached it.
	block, allow := filter.set_make(), filter.set_make()
	defer filter.set_destroy(block)
	defer filter.set_destroy(allow)

	added, held := parse_list_text(block, allow, "||x.example^$badfilter\n", .Adblock)
	testing.expect_value(t, added, 0)
	testing.expect(t, held, "a list of $badfilter rules was read as empty")

	// A list whose regexes the lists before it left no budget for.
	for i := 0; block.regex_refused == 0; i += 1 {
		filter.parse_rule(block, allow, fmt.tprintf("/^r%d[0-9a-f]{60}$/", i))
		if !testing.expect(t, i < 100_000) {
			return
		}
	}
	added, held = parse_list_text(block, allow, "/^late[0-9a-f]{60}$/\n", .Adblock)
	testing.expect_value(t, added, 0)
	testing.expect(t, held, "a list of regexes past the budget was read as empty")

	_, held = parse_list_text(block, allow, "! only a comment\n\n", .Adblock)
	testing.expect(t, !held, "a list with no rules was read as holding some")
	free_all(context.temp_allocator)
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
	engine := filter.engine_make()
	defer filter.engine_destroy(engine)
	s := Server {
		cfg     = &cfg,
		filters = engine,
	}
	defer delete(s.lists_loaded)

	testing.expect(t, reload_filters(&s, false))
	testing.expect(t, filter.engine_match(engine, "lifted.example") == .Blocked)
	os.remove(path)
	// Nor is it retried: no retry brings a local file back.
	testing.expect(t, reload_filters(&s, false), "a deleted file list was retried")
	testing.expect(t, filter.engine_match(engine, "lifted.example") != .Blocked, "a deleted file list kept its blocks")
}

@(test)
test_a_cached_page_is_not_a_list :: proc(t: ^testing.T) {
	// A page cached by a build that wrote a download before checking it.
	// Registered first so it runs last: the removals below read paths it zeroes.
	defer free_all(context.temp_allocator)
	dir := fmt.tprintf("/tmp/elodin-server-lists-test-page-%d", os.get_pid())
	testing.expect(t, os.make_directory(dir) == nil)
	defer os.remove(dir)
	cfg := config.default_config()
	cfg.blocking.cache_dir = dir
	list := config.Block_List{name = "l", url = "http://192.0.2.1/l.txt", format = .Hosts, enabled = true}
	path := list_cache_path(&cfg, list)
	testing.expect(t, os.write_entire_file(path, "<html>\n0.0.0.0 portal.example\n</html>\n") == nil)
	defer os.remove(path)

	text, load := cached_copy(&cfg, list, .Current)
	testing.expect_value(t, load, List_Load.Unavailable)
	testing.expect_value(t, text, "")
}

@(private = "file")
One_List :: struct {
	listener: net.TCP_Socket,
	body:     string,
}

// Answer one request on `listener` with `body` as a 200.
@(private = "file")
serve_one_list :: proc(one: ^One_List) {
	client, _, err := net.accept_tcp(one.listener)
	if err != nil {
		return
	}
	defer net.close(client)
	buf: [1024]u8
	_, _ = net.recv_tcp(client, buf[:])
	reply := fmt.tprintf("HTTP/1.1 200 OK\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s", len(one.body), one.body)
	_, _ = net.send_tcp(client, transmute([]u8)reply)
}

// A loopback listener for `serve_one_list`, and the URL that reaches it.
@(private = "file")
listen_one_list :: proc(t: ^testing.T) -> (listener: net.TCP_Socket, url: string, ok: bool) {
	err: net.Network_Error
	listener, err = net.listen_tcp(net.Endpoint{address = net.IP4_Loopback, port = 0})
	if !testing.expect_value(t, err, nil) {
		return
	}
	bound, _ := net.bound_endpoint(listener)
	// So a test that returns before dialling ends the accept, not the suite.
	_ = net.set_option(listener, .Receive_Timeout, 3 * time.Second)
	return listener, fmt.tprintf("http://127.0.0.1:%d/l.txt", bound.port), true
}

@(test)
test_a_fresh_cached_page_is_downloaded_over :: proc(t: ^testing.T) {
	/*
	A copy inside the refresh window skips the download. One that cannot stand
	in - a page an earlier build cached (#317) - is downloaded over, or the list
	would be out of effect until it aged past the window.
	*/
	listener, url, ok := listen_one_list(t)
	if !ok {
		return
	}
	defer net.close(listener)
	one := One_List{listener, "0.0.0.0 fetched.example\n"}
	server := thread.create_and_start_with_poly_data(&one, serve_one_list)
	defer thread.destroy(server)
	defer thread.join(server)

	// Registered first so it runs last: the removals below read paths it zeroes.
	defer free_all(context.temp_allocator)
	dir := fmt.tprintf("/tmp/elodin-server-lists-test-fresh-page-%d", os.get_pid())
	testing.expect(t, os.make_directory(dir) == nil)
	defer os.remove(dir)
	cfg := config.default_config()
	cfg.blocking.cache_dir = dir
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
test_an_empty_download_with_no_copy_does_not_hold_the_others_back :: proc(t: ^testing.T) {
	/*
	A list that loaded before, then downloads empty with no cached copy behind
	it - a cleared tmpfs `cache_dir`, a publisher that emptied it. It arrived,
	so it is empty rather than lost: the refresh goes through without it, and is
	not current so it is tried again.
	*/
	listener, url, ok := listen_one_list(t)
	if !ok {
		return
	}
	defer net.close(listener)
	one := One_List{listener, "# emptied\n"}
	server := thread.create_and_start_with_poly_data(&one, serve_one_list)
	defer thread.destroy(server)
	defer thread.join(server)

	// Registered first so it runs last: the removals below read paths it zeroes.
	defer free_all(context.temp_allocator)
	dir := fmt.tprintf("/tmp/elodin-server-lists-test-emptied-%d", os.get_pid())
	testing.expect(t, os.make_directory(dir) == nil)
	defer os.remove(dir)
	cfg := config.default_config()
	cfg.blocking.cache_dir = dir
	cfg.blocking.refresh = 0
	cfg.blocking.lists = []config.Block_List{{name = "l", url = url, format = .Hosts, enabled = true}}
	engine := filter.engine_make()
	defer filter.engine_destroy(engine)
	s := Server {
		cfg     = &cfg,
		filters = engine,
	}
	defer delete(s.lists_loaded)
	// As if it had loaded at the last refresh.
	s.lists_loaded = make([]bool, 1)
	s.lists_loaded[0] = true
	generation := filter.engine_generation(engine)

	testing.expect(t, !reload_filters(&s, true), "an empty download was reported current")
	testing.expect(t, filter.engine_generation(engine) != generation, "an empty download held the refresh back")
	testing.expect(t, !os.exists(list_cache_path(&cfg, cfg.blocking.lists[0])), "an empty download was cached")
	// It added nothing, so losing it later has no rules of its to keep.
	testing.expect(t, !s.lists_loaded[0], "an empty list was recorded as loaded")
}

@(test)
test_an_empty_cached_copy_is_not_a_list :: proc(t: ^testing.T) {
	// An empty download an earlier build cached, or a copy its in-place write
	// truncated before a crash.
	// Registered first so it runs last: the removals below read paths it zeroes.
	defer free_all(context.temp_allocator)
	dir := fmt.tprintf("/tmp/elodin-server-lists-test-empty-copy-%d", os.get_pid())
	testing.expect(t, os.make_directory(dir) == nil)
	defer os.remove(dir)
	cfg := config.default_config()
	cfg.blocking.cache_dir = dir
	list := config.Block_List{name = "l", url = "http://192.0.2.1/l.txt", format = .Hosts, enabled = true}
	path := list_cache_path(&cfg, list)
	testing.expect(t, os.write_entire_file(path, " \n\r\n") == nil)
	defer os.remove(path)

	text, load := cached_copy(&cfg, list, .Current)
	testing.expect_value(t, load, List_Load.Unavailable)
	testing.expect_value(t, text, "")
}
