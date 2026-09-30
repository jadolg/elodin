package server

import "core:fmt"
import "core:os"
import "core:path/filepath"
import "core:strings"
import "core:sync"
import "core:time"
import "elodin:config"
import "elodin:filter"
import "elodin:logx"
import "elodin:upstream"

/*
Loading and refreshing sink lists.

Remote lists are cached on disk. A refresh that fails falls back to the cached
copy, so a network outage cannot silently turn blocking off. Where there is no
copy either, a refresh keeps the rules already in effect rather than swapping in
a set that lacks a list it had (#411); see `reload_filters`.
*/

FETCH_TIMEOUT :: 30 * time.Second
/*
The whole download, redirects included (#445): `FETCH_TIMEOUT` bounds one read,
and a host sending a little just inside it could otherwise hold the refresh -
and the maintenance thread it runs on - for as long as the body limit allows.
Five minutes is a 64 MB list, the most `fetch_url` accepts, at under 2 Mbit/s.
*/
FETCH_DEADLINE :: 5 * time.Minute

/*
How soon a refresh that could not bring every list up to date is tried again,
doubling on each further failure up to `blocking.refresh` (#411). Waiting the
whole interval left a list that one outage kept from loading out of effect, or
out of date, for a day by default.
*/
REFRESH_RETRY_FIRST :: 1 * time.Minute

// How one list fared in a load.
List_Load :: enum u8 {
	// Downloaded, read from its file, or served from a cached copy still
	// inside the refresh window.
	Current,
	// The download failed and a cached copy older than the window stood in.
	Stale,
	// Neither the source nor a cached copy could be read: it adds nothing.
	Unavailable,
}

/*
Build a fresh pair of rule sets from the configuration.

Returns them ready to hand to `filter.engine_swap`; the caller is responsible
for destroying whatever that swap displaces. When `loads` is given it has one
slot per list, `blocking.lists` then `blocking.allowlists`, and says how each
one fared.
*/
build_filter_sets :: proc(cfg: ^config.Config, allow_network: bool, loads: []List_Load = nil) -> (block, allow: ^filter.Set) {
	block = filter.set_make()
	allow = filter.set_make()

	for list, i in cfg.blocking.lists {
		load := load_one_list(cfg, list, block, allow, allow_network, false)
		if loads != nil {
			loads[i] = load
		}
	}
	for list, i in cfg.blocking.allow_lists {
		load := load_one_list(cfg, list, block, allow, allow_network, true)
		if loads != nil {
			loads[len(cfg.blocking.lists) + i] = load
		}
	}

	// A list's `$badfilter` takes back rules lists carry, not the operator's
	// own: forget them before those are added. The operator's `$badfilter`
	// still cancels what the lists added.
	clear(&block.cancelled)
	clear(&allow.cancelled)
	for rule in cfg.blocking.rules {
		if !operator_rule_takes(block, allow, rule) {
			warn_rule_adds_nothing(rule)
		}
	}
	for rule in cfg.blocking.allow_rules {
		// Entries here are allow rules whether or not they carry the @@ prefix.
		text := rule
		if !strings.has_prefix(text, "@@") {
			text = fmt.tprintf("@@%s", text)
		}
		if !operator_rule_takes(block, allow, text) {
			warn_rule_adds_nothing(rule)
		}
	}

	return
}

// What a pair of sets holds. Said of the sets being swapped in, so that a
// refresh `reload_filters` drops does not log a count nothing is enforcing.
@(private)
log_filter_sets :: proc(block, allow: ^filter.Set) {
	logx.infof(
		"filter: %d block rules (%d regex), %d allow rules (%d regex)",
		block.count,
		len(block.regexes),
		allow.count,
		len(allow.regexes),
	)
	if refused := block.regex_refused + allow.regex_refused; refused > 0 {
		logx.warnf(
			"filter: %d regex rules skipped: a set holds %d of regex cost (compiled bytes, plus one for each character or range a class lists), and the lists loaded first used it up",
			refused,
			filter.MAX_REGEX_TOTAL,
		)
	}
}

/*
Whether the operator's rule added a rule or, as a `$badfilter`, took one back.
Looking for `badfilter` in the text instead let a skipped one, such as
`$important, badfilter` or `$third-party,badfilter`, cancel nothing unremarked.
*/
@(private)
operator_rule_takes :: proc(block, allow: ^filter.Set, text: string) -> bool {
	cancels := block.cancels + allow.cancels
	return filter.parse_rule(block, allow, text) > 0 || block.cancels + allow.cancels > cancels
}

// A list skipping what it cannot honour is routine; the operator's own rule
// doing nothing is worth a word, since one that did block may now be skipped.
@(private)
warn_rule_adds_nothing :: proc(rule: string) {
	// A dnsmasq route has its own warning at startup.
	if !strings.has_prefix(strings.trim_space(rule), "server=/") {
		logx.warnf("blocking rule %q adds nothing: it carries a modifier DNS cannot honour, is cosmetic, is a wildcard or path rule, is a regex this engine cannot run as AdGuard Home does (see docs/blocking.md) or over %d compiled bytes, or no longer fits the regex budget, names no domain, a $badfilter cancels it, or its name is not ASCII (write an international name in punycode, xn--...)", rule, filter.MAX_REGEX_PROGRAM)
	}
}

@(private)
load_one_list :: proc(
	cfg: ^config.Config,
	list: config.Block_List,
	block, allow: ^filter.Set,
	allow_network: bool,
	as_allowlist: bool,
) -> List_Load {
	// A disabled list is expected to add nothing, which is not a failure.
	if !list.enabled {
		return .Current
	}

	text, load, downloaded := list_contents(cfg, list, allow_network)
	if load == .Unavailable {
		logx.warnf("list %s: unavailable, skipping it", list.name)
		return load
	}
	defer delete(text)

	// An allowlist's entries always land in the allow set, whatever syntax the
	// file happens to use.
	target_block, target_allow := block, allow
	if as_allowlist {
		target_block = allow
	}

	added, held_rules := parse_list_text(target_block, target_allow, text, list.format)
	if downloaded {
		/*
		A download replaces the cached copy only once it has been parsed and
		found to hold rules (#317). Written first, an empty file mid-publish or
		an error page served as a 200 - which parses to nothing - was the copy
		every later fallback read. Pi-hole falls back to its cached copy on an
		empty download likewise. A download that holds no rules added nothing to
		the sets either, so the cached copy is parsed in its place.
		*/
		if held_rules {
			save_cached_copy(cfg, list, text)
		} else {
			logx.warnf("list %s: the download holds no rules, so it is not cached", list.name)
			delete(text)
			text, load = cached_copy(cfg, list, .Stale)
			if load == .Unavailable {
				logx.warnf("list %s: unavailable, skipping it", list.name)
				return load
			}
			added, _ = parse_list_text(target_block, target_allow, text, list.format)
		}
	}
	logx.infof("list %s: %d rules", list.name, added)
	return load
}

/*
Parse a list's text into the sets, and say whether it held rules: it added some,
took some back with `$badfilter`, or had regex rules refused because the lists
before it used up the budget. `added` alone reads a list of `$badfilter` rules,
or of regexes past the budget, as empty, so its download was never cached and
the list never counted as current.
*/
@(private)
parse_list_text :: proc(block, allow: ^filter.Set, text: string, format: config.List_Format) -> (added: int, held_rules: bool) {
	cancels := block.cancels + allow.cancels
	refused := block.regex_refused + allow.regex_refused
	// config.List_Format and filter.Format are declared in the same order so a
	// list's configured format maps straight across.
	added = filter.parse_list(block, allow, text, filter.Format(format))
	held_rules = added > 0 || block.cancels + allow.cancels > cancels || block.regex_refused + allow.regex_refused > refused
	return
}

/*
A list's text, and how current it is. `downloaded` is true when it has just been
fetched and is not yet what the cache holds.
*/
@(private)
list_contents :: proc(
	cfg: ^config.Config,
	list: config.Block_List,
	allow_network: bool,
) -> (
	text: string,
	load: List_Load,
	downloaded: bool,
) {
	if list.file != "" {
		data, err := os.read_entire_file(list.file, context.allocator)
		if err != nil {
			logx.warnf("list %s: cannot read %q (%v)", list.name, list.file, err)
			return "", .Unavailable, false
		}
		return string(data), .Current, false
	}
	if list.url == "" {
		return "", .Unavailable, false
	}

	// Without the network the cached copy is all there is, and --no-fetch asks
	// for exactly that, so it is not held against the load.
	load = .Current
	if allow_network {
		fresh, fetch := fetch_list(cfg, list)
		switch fetch {
		case .Fetched:
			return fresh, .Current, true
		case .Cache_Is_Fresh:
		case .Failed:
			load = .Stale
		}
	}
	text, load = cached_copy(cfg, list, load)
	return
}

// The cached copy of a downloaded list, as `load` when it can be read.
@(private)
cached_copy :: proc(cfg: ^config.Config, list: config.Block_List, load: List_Load) -> (string, List_Load) {
	cache_path := list_cache_path(cfg, list)
	data, err := os.read_entire_file(cache_path, context.allocator)
	if err != nil {
		return "", .Unavailable
	}
	logx.infof("list %s: using the cached copy at %s", list.name, cache_path)
	return string(data), load
}

@(private)
save_cached_copy :: proc(cfg: ^config.Config, list: config.Block_List, text: string) {
	cache_path := list_cache_path(cfg, list)
	// filepath.dir returns a slice of its argument rather than a new string, so
	// there is nothing here to free.
	if dir := filepath.dir(cache_path); dir != "" {
		make_directories(dir)
	}
	if werr := write_cache_file(cache_path, transmute([]byte)text); werr != nil {
		warn_cache_unwritable(cfg, cache_path, werr)
	}
}

@(private)
Fetch :: enum u8 {
	Fetched,
	Cache_Is_Fresh,
	Failed,
}

@(private)
fetch_list :: proc(cfg: ^config.Config, list: config.Block_List) -> (text: string, fetch: Fetch) {
	// Skip the download when the cached copy is still within the refresh window.
	if info, err := os.stat(list_cache_path(cfg, list), context.temp_allocator); err == nil {
		age := time.diff(info.modification_time, time.now())
		if age < cfg.blocking.refresh {
			return "", .Cache_Is_Fresh
		}
	}

	logx.infof("list %s: downloading %s", list.name, list.url)
	body, ferr := upstream.fetch_url(list.url, cfg.upstream.bootstrap, FETCH_TIMEOUT, FETCH_DEADLINE, context.allocator)
	if ferr != .None {
		logx.warnf("list %s: download failed (%v)", list.name, ferr)
		return "", .Failed
	}
	if begins_with_markup(string(body)) {
		// A captive portal's login page, or a mirror's error page served as a
		// 200 (#317). AdGuard Home refuses a list that opens `<html` or
		// `<!doctype` the same way.
		logx.warnf("list %s: the download is a web page, not a list", list.name)
		delete(body)
		return "", .Failed
	}
	return string(body), .Fetched
}

/*
Whether a download opens with markup. No list format this reads puts `<` first
on a line - hosts, domains, dnsmasq and adblock rules all begin otherwise - so a
body whose first non-blank byte is one is a page, not a list. Only ASCII blanks
are skipped: `strings.trim_space` would skip Unicode ones too.
*/
@(private)
begins_with_markup :: proc(body: string) -> bool {
	// A UTF-8 byte order mark is no blank, but a page may open with one.
	rest := strings.trim_left(strings.trim_prefix(body, "\xef\xbb\xbf"), " \t\r\n")
	return strings.has_prefix(rest, "<")
}

/*
Replace a cached copy so that a crash at any point leaves the old one or the new
one whole on disk, never a truncated file (#411).

Writing in place truncated the copy first, and a power cut mid-write - on the
router or SD-card board `small-device.yaml` is for - left a partial list that
the next start without a network loaded as if it were the whole of it. The new
copy goes to a temporary file beside the old, reaches the disk, and is renamed
over it; rename(2) replaces the name atomically. The temporary name ends in
`.tmp`, which no `sanitise_name` result does, so it cannot be another list's.
*/
@(private)
write_cache_file :: proc(path: string, body: []byte) -> (err: os.Error) {
	tmp := fmt.tprintf("%s.tmp", path)
	f := os.open(tmp, {.Write, .Create, .Trunc}, os.Permissions_Read_All + {.Write_User}) or_return
	_, err = os.write(f, body)
	if err == nil {
		err = os.sync(f)
	}
	if cerr := os.close(f); err == nil {
		err = cerr
	}
	if err == nil {
		err = os.rename(tmp, path)
	}
	if err != nil {
		os.remove(tmp)
	}
	return
}

@(private)
list_cache_path :: proc(cfg: ^config.Config, list: config.Block_List) -> string {
	joined, _ := filepath.join({cfg.blocking.cache_dir, sanitise_name(list.name)}, context.temp_allocator)
	return joined
}

// Turn a list name into something safe to use as a file name.
@(private)
sanitise_name :: proc(name: string) -> string {
	b := strings.builder_make(context.temp_allocator)
	for i in 0 ..< len(name) {
		c := name[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '-', c == '_', c == '.':
			strings.write_byte(&b, c)
		case:
			strings.write_byte(&b, '_')
		}
	}
	strings.write_string(&b, ".list")
	return strings.to_string(b)
}

/*
Report an unwritable cache directory once, not once per list.

Losing the on-disk cache is not fatal: the lists were downloaded and are in
effect. It only means the next start has to download them again instead of
falling back to a copy on disk, so it warrants one clear line rather than a
warning per list that reads like a failure to block anything.
*/
@(private)
cache_warned: bool

@(private)
warn_cache_unwritable :: proc(cfg: ^config.Config, cache_path: string, err: os.Error) {
	if sync.atomic_exchange(&cache_warned, true) {
		return
	}
	logx.warnf(
		"blocking.cache_dir %q is not writable (%v); lists are loaded but will be re-downloaded on each start",
		cfg.blocking.cache_dir,
		err,
	)
}

@(private)
make_directories :: proc(path: string) {
	// Create each component in turn; an existing directory is not an error.
	if path == "" || path == "/" {
		return
	}
	parts := strings.split(path, "/", context.temp_allocator)
	current := strings.builder_make(context.temp_allocator)
	if strings.has_prefix(path, "/") {
		strings.write_byte(&current, '/')
	}
	for part, i in parts {
		if part == "" {
			continue
		}
		if i > 0 && strings.to_string(current) != "/" && len(strings.to_string(current)) > 0 {
			strings.write_byte(&current, '/')
		}
		strings.write_string(&current, part)
		_ = os.make_directory(strings.to_string(current))
	}
}

/*
Reload every list and swap the result in.

Called at startup and again on the refresh interval. The old rule sets are
destroyed only after the swap returns them, at which point no new query can
reach them.

A list that loaded last time and is unavailable now - no download and no
readable cached copy, say a cleared tmpfs `cache_dir` during an outage - would
have the swap take its rules out of effect until the next refresh a day later
(#411). The new sets are dropped instead and the ones in effect kept, whole: they
cannot be patched per list, being one merged set, and holding each list's text
in memory to rebuild from would double the footprint on the small devices this
runs on. A list that never loaded does not hold the others back.

`current` is false when some list is unavailable or stood in for by a stale copy,
so the caller retries sooner than the interval; see `refresh_retry`.
*/
reload_filters :: proc(s: ^Server, allow_network: bool) -> (current: bool) {
	lists := len(s.cfg.blocking.lists)
	loads := make([]List_Load, lists + len(s.cfg.blocking.allow_lists))
	block, allow := build_filter_sets(s.cfg, allow_network, loads)

	current = true
	for load, i in loads {
		if load == .Current {
			continue
		}
		current = false
		if load == .Unavailable && s.lists_loaded != nil && s.lists_loaded[i] {
			name := s.cfg.blocking.lists[i].name if i < lists else s.cfg.blocking.allow_lists[i - lists].name
			logx.warnf("list %s: loaded before and unavailable now; keeping the rules already in effect", name)
			filter.set_destroy(block)
			filter.set_destroy(allow)
			delete(loads)
			return false
		}
	}
	if s.lists_loaded == nil {
		s.lists_loaded = make([]bool, len(loads))
	}
	for load, i in loads {
		s.lists_loaded[i] = load != .Unavailable
	}
	delete(loads)

	log_filter_sets(block, allow)
	old_block, old_allow := filter.engine_swap(s.filters, block, allow)

	/*
	The answer cache is left as it is.

	Its entries were matched against the sets just displaced, and some of them -
	the ones whose answer leads somewhere else - have to be matched again before
	they are served. They carry the generation `engine_swap` has just moved past,
	which is what asks for that; see `serve_from_cache`. Emptying the cache here
	would do the same job in one line and take every unrelated entry with it,
	buying a burst of upstream traffic on every refresh interval to re-learn
	answers nothing was wrong with.
	*/

	// In-flight queries hold a shared lock across their match, which the swap
	// waited on, so nothing can still be reading the displaced sets.
	filter.set_destroy(old_block)
	filter.set_destroy(old_allow)
	return
}

/*
How long to wait before the next refresh after one that was not `current`:
`REFRESH_RETRY_FIRST` after the first, doubling after each one since, and never
longer than the interval itself. `retry` is the wait just served, zero when the
refresh before this one was current.
*/
refresh_retry :: proc(retry, interval: time.Duration) -> time.Duration {
	if retry <= 0 {
		return min(REFRESH_RETRY_FIRST, interval)
	}
	return min(retry * 2, interval)
}

// How long after the last refresh the next one is due.
refresh_wait :: proc(retry, interval: time.Duration) -> time.Duration {
	return retry if retry > 0 else interval
}
