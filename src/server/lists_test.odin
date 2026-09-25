package server

import "core:os"
import "core:testing"
import "elodin:config"
import "elodin:filter"

@(test)
test_a_list_badfilter_does_not_cancel_the_operators_own_rules :: proc(t: ^testing.T) {
	/*
	A subscribed list's `$badfilter` is its author taking back a rule some list
	carries. The operator's own `blocking.rules` are not a list's to take back:
	`rules: ["||pl.ua^"]` has to keep blocking pl.ua whatever a list downloaded
	tonight says. The operator's own `$badfilter` still reaches the lists.
	*/
	path :: "/tmp/elodin-server-lists-test-badfilter.txt"
	testing.expect(t, os.write_entire_file(path, "||pl.ua^$badfilter\n||listed.example^\n") == nil)
	defer os.remove(path)

	cfg := config.default_config()
	cfg.blocking.rules = []string{"||pl.ua^", "||listed.example^$badfilter"}
	cfg.blocking.lists = []config.Block_List{{name = "l", file = path, format = .Adblock, enabled = true}}
	block, allow := build_filter_sets(&cfg, false)
	defer filter.set_destroy(block)
	defer filter.set_destroy(allow)

	testing.expect(t, filter.set_lookup(block, "www.pl.ua"), "the operator's block survives a list's badfilter")
	testing.expect(t, !filter.set_lookup(block, "listed.example"), "and the operator's badfilter cancels a list's rule")
}
