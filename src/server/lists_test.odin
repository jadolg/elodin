package server

import "core:fmt"
import "core:os"
import "core:testing"
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
		testing.expect_value(t, derr, dns.Decode_Error.None)
		// The premise: what the resolver matches is the name with its slash.
		testing.expect_value(t, msg.question[0].name, name)
		testing.expectf(t, filter.engine_match(engine, msg.question[0].name) == .Blocked, "%s was not blocked", name)
	}
	free_all(context.temp_allocator)
}
