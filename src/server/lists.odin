package server

import "core:fmt"
import "core:hash"
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
and every rebuild after it, a reload's change to the rules included, which
waits for it (see `Rebuild`) - for as long as the body limit allows.
Five minutes is a 64 MB list, the most `fetch_url` accepts, at under 2 Mbit/s.
*/
FETCH_DEADLINE :: 5 * time.Minute

/*
How soon a refresh that could not bring every list up to date is tried again,
doubling on each further failure up to `blocking.refresh` (#411), so a list one
outage kept from loading is not out of effect, or out of date, for a whole
interval - a day by default.
*/
REFRESH_RETRY_FIRST :: 1 * time.Minute
/*
The longest a retry waits, whatever `blocking.refresh` says. `small-device.yaml`
refreshes weekly, and a box that boots during a long outage gets its lists
within the hour of the network coming back, not hours after.
*/
REFRESH_RETRY_MAX :: 1 * time.Hour

// How one list fared in a load.
List_Load :: enum u8 {
	// Downloaded, read from its file, or served from a cached copy still
	// inside the refresh window.
	Current,
	// The download failed and a cached copy older than the window stood in.
	Stale,
	// Neither the source nor a cached copy could be read: it adds nothing.
	Unavailable,
	// The download arrived holding no rules and there is no copy: it adds
	// nothing, but is empty rather than lost, so it holds nothing back.
	Empty,
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
	move_query_named_caches(cfg)

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

/*
A list the file names only by a url with a query was cached, before #487, under
the whole url, so the file name held whatever key the query carried. Each such
copy moves to the name the list goes by now, or is removed when that url's copy
is there already: the key leaves `cache_dir`, and a box that boots offline still has the
list. A file that is some list's own cache under its current name is left alone,
and so is a disabled list's copy: nothing loads that list, and its name may be
another list's, which would then load its rules.
*/
@(private)
move_query_named_caches :: proc(cfg: ^config.Config) {
	lists := [][]config.Block_List{cfg.blocking.lists, cfg.blocking.allow_lists}
	current := make(map[string]bool, context.temp_allocator)
	for set in lists {
		for list in set {
			current[config.list_cache_file(list)] = true
		}
	}
	for set in lists {
		for list in set {
			if list.url == "" || list.file != "" || !list.enabled || list.named {
				continue
			}
			old := config.list_cache_name(list.url)
			if current[old] {
				continue
			}
			old_path, _ := filepath.join({cfg.blocking.cache_dir, old}, context.temp_allocator)
			if !os.exists(old_path) {
				continue
			}
			// A copy under the current name that is of another url - one with no
			// query an earlier build cached there - is moved over, not kept.
			path := list_cache_path(cfg, list)
			if os.exists(path) && copy_is_of(list, path) {
				if err := os.remove(old_path); err != nil {
					logx.warnf("list %s: cannot remove the cached copy named by its url's query (%v)", list.name, err)
				}
				continue
			}
			if err := os.rename(old_path, path); err != nil {
				logx.warnf("list %s: cannot move the cached copy to %s (%v)", list.name, path, err)
				continue
			}
			// Named by this very url, so it is this url's copy.
			mark_copy_source(cfg, list, path)
		}
	}
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
		logx.warnf("blocking rule %q adds nothing: it carries a modifier DNS cannot honour or a $dnstype this engine cannot read, that takes its name past %d types, or that needs one set of types past the %d the lists loaded first left room for, is cosmetic, is a wildcard or path rule, is a regex this engine cannot run as AdGuard Home does (see docs/blocking.md) or over %d compiled bytes, or no longer fits the regex budget, names no domain, a $badfilter cancels it, or its name is not ASCII (write an international name in punycode, xn--...)", rule, filter.MAX_RULE_TYPES, filter.MAX_TYPE_FILTERS, filter.MAX_REGEX_PROGRAM)
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

	added, held_rules, not_ascii := parse_list_text(target_block, target_allow, text, list.format)
	if downloaded {
		/*
		A download replaces the cached copy only once it has been parsed and
		found to hold rules (#317), so an empty file mid-publish or an error
		page served as a 200 never becomes the copy every later fallback reads.
		Pi-hole falls back to its cached copy on an empty download likewise. A
		download that holds no rules has added nothing to the sets either, so
		the cached copy is parsed in its place.
		*/
		if held_rules {
			save_cached_copy(cfg, list, text)
		} else {
			logx.warnf("list %s: the download holds no rules, so it is not cached", list.name)
			// A download of nothing but international names is one to name.
			warn_not_ascii(list.name, not_ascii)
			delete(text)
			text, load = cached_copy(cfg, list, .Stale)
			if load == .Unavailable {
				// The download arrived and holds nothing, and there is no copy
				// to stand in: the list is empty, not lost, so it does not hold
				// the other lists back as `reload_filters` holds them for a
				// list it cannot reach. It stays not current, and so retried.
				return .Empty
			}
			added, _, not_ascii = parse_list_text(target_block, target_allow, text, list.format)
		}
	}
	logx.infof("list %s: %d rules", list.name, added)
	warn_not_ascii(list.name, not_ascii)
	return load
}

/*
A stub asks for an international name in punycode (RFC 5891 section 5), and
a query spells any other byte past ASCII as \DDD, so such an entry can never
match. AdGuard Home's urlfilter refuses it likewise; converting it needs the
IDNA2008 and NFC tables RFC 5891 section 5 asks of a lookup.
*/
@(private)
warn_not_ascii :: proc(name: string, skipped: int) {
	if skipped > 0 {
		logx.warnf("list %s: %d names skipped as not ASCII; an international name matches only when written in punycode (xn--...)", name, skipped)
	}
}

/*
Parse a list's text into the sets, and say whether it held rules: it added some,
took some back with `$badfilter`, or had regex rules refused because the lists
before it used up the budget. `added` alone would read a list of `$badfilter`
rules, or of regexes past the budget, as empty: never cached, never current.

`not_ascii` is how many of its names were refused as international names
written in UTF-8 (`filter.Set.not_ascii`).
*/
@(private)
parse_list_text :: proc(block, allow: ^filter.Set, text: string, format: config.List_Format) -> (added: int, held_rules: bool, not_ascii: int) {
	// An allowlist parses into the allow set as both targets: count it once.
	skipped :: proc(block, allow: ^filter.Set) -> int {
		return block.not_ascii + (0 if allow == block else allow.not_ascii)
	}
	cancels := block.cancels + allow.cancels
	before := skipped(block, allow)
	refused := block.regex_refused + allow.regex_refused
	// config.List_Format and filter.Format are declared in the same order so a
	// list's configured format maps straight across.
	added = filter.parse_list(block, allow, text, filter.Format(format))
	held_rules = added > 0 || block.cancels + allow.cancels > cancels || block.regex_refused + allow.regex_refused > refused
	not_ascii = skipped(block, allow) - before
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
			if text, load = cached_copy(cfg, list, .Current); load != .Unavailable {
				return
			}
			// A fresh copy that cannot stand in - unreadable, or a page an
			// earlier build cached - is downloaded over. Otherwise the list
			// stays out of effect until the copy ages past the window, every
			// retry meanwhile skipping the download as fresh.
			if fresh, fetch = fetch_list(cfg, list, ignore_fresh = true); fetch == .Fetched {
				return fresh, .Current, true
			}
			return "", .Unavailable, false
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
	// A copy of another query is another list: `?category=ads` does not stand
	// in for `?category=malware`.
	if !copy_is_of(list, cache_path) {
		if os.exists(cache_path) {
			logx.infof("list %s: the cached copy at %s is of another url", list.name, cache_path)
		}
		return "", .Unavailable
	}
	data, err := os.read_entire_file(cache_path, context.allocator)
	if err != nil {
		return "", .Unavailable
	}
	// A page an earlier build cached before downloads were checked (#317).
	if begins_with_markup(string(data)) {
		logx.warnf("list %s: the cached copy at %s is a web page, not a list", list.name, cache_path)
		delete(data)
		return "", .Unavailable
	}
	// An empty download an earlier build cached (#317), or a copy its in-place
	// write truncated before a crash (#411): no list either.
	if strings.trim(string(data), " \t\r\n") == "" {
		logx.warnf("list %s: the cached copy at %s is empty", list.name, cache_path)
		delete(data)
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
	// The copy goes first: a write that fails leaves the old copy beside its own
	// fingerprint, which removed first would make it read as a url with no query.
	// A stop between the two leaves the new copy beside the old url's, or none.
	if werr := write_cache_file(cache_path, transmute([]byte)text); werr != nil {
		warn_cache_unwritable(cfg, cache_path, werr)
		return
	}
	mark_copy_source(cfg, list, cache_path)
}

// The fingerprint of `list`'s url beside its copy at `cache_path`, or none for a
// url with no query.
@(private)
mark_copy_source :: proc(cfg: ^config.Config, list: config.Block_List, cache_path: string) {
	if sp := source_path(cache_path); os.exists(sp) {
		// Left in place, it marks the copy as another url's for good.
		if rerr := os.remove(sp); rerr != nil {
			logx.warnf("list %s: cannot remove the old fingerprint at %s (%v)", list.name, sp, rerr)
		}
	}
	if src, has := source_of(list); has {
		if werr := write_cache_file(source_path(cache_path), transmute([]byte)src); werr != nil {
			warn_cache_unwritable(cfg, cache_path, werr)
		}
	}
}

/*
A list whose url has a query is cached under a name without it, so the copy of
`?category=ads` would read as fresh for `?category=malware`, or for a rotated
key. A fingerprint of the url as sent goes in a file beside the copy, and only a
copy whose fingerprint matches is fresh, or stands in when a download fails;
any other is another list's, and is downloaded over. The fingerprint is never logged, and
the file name the log does show holds no part of the query. A url with no query
is the list its name says, and has none; a copy beside a fingerprint is of a url
with a query, so it is not fresh for one without.
*/
@(private)
source_of :: proc(list: config.Block_List) -> (src: string, has: bool) {
	sent := config.url_sent(list.url)
	if sent == config.url_name(list.url) {
		return "", false
	}
	return fmt.tprintf("%016x\n", hash.fnv64a(transmute([]byte)sent)), true
}

@(private)
source_path :: proc(cache_path: string) -> string {
	return fmt.tprintf("%s.src", cache_path)
}

/*
Whether the cached copy at `cache_path` was downloaded from the url `list` names
now. A copy with no fingerprint is of a url with no query, or of a list the file
names: a build before #487 cached that under its name and wrote none.
*/
@(private)
copy_is_of :: proc(list: config.Block_List, cache_path: string) -> bool {
	src, has := source_of(list)
	if !os.exists(source_path(cache_path)) {
		return !has || list.named
	}
	if !has {
		return false
	}
	data, err := os.read_entire_file(source_path(cache_path), context.temp_allocator)
	return err == nil && string(data) == src
}

@(private)
Fetch :: enum u8 {
	Fetched,
	Cache_Is_Fresh,
	Failed,
}

@(private)
fetch_list :: proc(cfg: ^config.Config, list: config.Block_List, ignore_fresh := false) -> (text: string, fetch: Fetch) {
	// Skip the download when the cached copy is still within the refresh window.
	path := list_cache_path(cfg, list)
	if info, err := os.stat(path, context.temp_allocator); err == nil && !ignore_fresh {
		age := time.diff(info.modification_time, time.now())
		if age < cfg.blocking.refresh && copy_is_of(list, path) {
			return "", .Cache_Is_Fresh
		}
	}

	logx.infof("list %s: downloading %s", list.name, config.url_name(list.url))
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
	rest := strings.trim_left(strings.trim_prefix(body, filter.BOM), " \t\r\n")
	return strings.has_prefix(rest, "<")
}

/*
Replace a cached copy so that a crash at any point leaves the old one or the new
one whole on disk, never a truncated file (#411).

A write in place truncates the copy first, and a power cut mid-write - on the
router or SD-card board `small-device.yaml` is for - leaves a partial list the
next start without a network would load as the whole of it. So the new copy goes
to a temporary file beside the old, reaches the disk, and is renamed over it;
rename(2) replaces the name atomically. The temporary name ends in
`.tmp`, which no `config.list_cache_file` result or fingerprint file does, so it
cannot be another list's.
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
	joined, _ := filepath.join({cfg.blocking.cache_dir, config.list_cache_file(list)}, context.temp_allocator)
	return joined
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

A rebuild calls `reload_filters_from` with its copy of the configuration (see
`rebuild_rules`); this reads the one in effect. The old rule sets are destroyed
only after the swap returns them, at which point no new query can reach them.

A list that loaded last time and is unavailable now - no download and no
readable cached copy, say a cleared tmpfs `cache_dir` during an outage - would
have the swap take its rules out of effect until the next refresh a day later
(#411). The new sets are dropped instead and the ones in effect kept, whole: they
cannot be patched per list, being one merged set, and holding each list's text
in memory to rebuild from would double the footprint on the small devices this
runs on. A list that never loaded does not hold the others back, and neither does
a `file:` list: that one is the operator's own, and one deleted to lift its
blocks has to lift them, where a download is lost to the network.

`current` is false when some list is unavailable or stood in for by a stale copy,
so the caller retries sooner than the interval; see `refresh_retry`.
*/
reload_filters :: proc(s: ^Server, allow_network: bool) -> (current: bool) {
	return reload_filters_from(s, live(s).cfg, allow_network)
}

// `reload_filters` from `cfg`, which a rebuild holds a copy of rather than a
// pin on its generation; see `Rebuild`.
reload_filters_from :: proc(s: ^Server, cfg: ^config.Config, allow_network: bool) -> (current: bool) {
	lists := len(cfg.blocking.lists)
	loads := make([]List_Load, lists + len(cfg.blocking.allow_lists))
	block, allow := build_filter_sets(cfg, allow_network, loads)

	current = true
	for load, i in loads {
		if load == .Current {
			continue
		}
		list := cfg.blocking.lists[i] if i < lists else cfg.blocking.allow_lists[i - lists]
		// A retry is for a download. A missing `file:` list is the operator's
		// to put back, and retrying it would rebuild every set hourly for good.
		if list.file != "" {
			continue
		}
		current = false
		if load == .Unavailable && s.lists_loaded[list_key(list, i >= lists)] {
			logx.warnf("list %s: loaded before and unavailable now; keeping the rules already in effect", list.name)
			filter.set_destroy(block)
			filter.set_destroy(allow)
			delete(loads)
			return false
		}
	}
	clear(&s.lists_loaded)
	for load, i in loads {
		list := cfg.blocking.lists[i] if i < lists else cfg.blocking.allow_lists[i - lists]
		// An empty or disabled list contributed nothing, so it has nothing to
		// keep later. Only a load is recorded: two entries for one source share
		// a key, and the one that loaded is the one whose rules are in effect.
		if list.enabled && (load == .Current || load == .Stale) {
			s.lists_loaded[list_key(list, i >= lists)] = true
		}
	}
	delete(loads)

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

	// In-flight queries hold a read lock across their match, which the swap
	// waited on, so nothing can still be reading the displaced sets.
	filter.set_destroy(old_block)
	filter.set_destroy(old_allow)
	// Once the old sets are gone, so the line says the rebuild is over. Only a
	// rebuild swaps the sets, one at a time, so these are still the ones in effect.
	log_filter_sets(block, allow)
	return
}

/*
A list as `lists_loaded` knows it: where it is fetched from, and which kind of
list it is. A list keeps its history wherever a reload moves it, and a new one
starts with none, which is what it would have at startup.
*/
list_key :: proc(list: config.Block_List, allow: bool) -> u64 {
	return hash.fnv64a(transmute([]byte)fmt.tprintf("%v\x00%s\x00%s", allow, list.url, list.file))
}

/*
How long to wait before the next refresh after one that was not `current`:
`REFRESH_RETRY_FIRST` after the first, doubling after each one since, and never
longer than the interval itself or `REFRESH_RETRY_MAX`. `retry` is the wait just
served, zero when the refresh before this one was current.
*/
refresh_retry :: proc(retry, interval: time.Duration) -> time.Duration {
	if retry <= 0 {
		return min(REFRESH_RETRY_FIRST, interval)
	}
	return min(retry * 2, interval, REFRESH_RETRY_MAX)
}

// How long after the last refresh the next one is due.
refresh_wait :: proc(retry, interval: time.Duration) -> time.Duration {
	return retry if retry > 0 else interval
}
