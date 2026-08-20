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
copy, so a network outage cannot silently turn blocking off.
*/

FETCH_TIMEOUT :: 30 * time.Second

/*
Build a fresh pair of rule sets from the configuration.

Returns them ready to hand to `filter.engine_swap`; the caller is responsible
for destroying whatever that swap displaces.
*/
build_filter_sets :: proc(cfg: ^config.Config, allow_network: bool) -> (block, allow: ^filter.Set) {
	block = filter.set_make()
	allow = filter.set_make()

	for rule in cfg.blocking.rules {
		filter.parse_rule(block, allow, rule)
	}
	for rule in cfg.blocking.allow_rules {
		// Entries here are allow rules whether or not they carry the @@ prefix.
		text := rule
		if !strings.has_prefix(text, "@@") {
			text = fmt.tprintf("@@%s", text)
		}
		filter.parse_rule(block, allow, text)
	}

	for list in cfg.blocking.lists {
		load_one_list(cfg, list, block, allow, allow_network, false)
	}
	for list in cfg.blocking.allow_lists {
		load_one_list(cfg, list, block, allow, allow_network, true)
	}

	logx.infof("filter: %d block rules, %d allow rules", block.count, allow.count)
	return
}

@(private)
load_one_list :: proc(
	cfg: ^config.Config,
	list: config.Block_List,
	block, allow: ^filter.Set,
	allow_network: bool,
	as_allowlist: bool,
) {
	if !list.enabled {
		return
	}

	text, ok := list_contents(cfg, list, allow_network)
	if !ok {
		logx.warnf("list %s: unavailable, skipping it", list.name)
		return
	}
	defer delete(text)

	// An allowlist's entries always land in the allow set, whatever syntax the
	// file happens to use.
	target_block, target_allow := block, allow
	if as_allowlist {
		target_block = allow
	}

	// config.List_Format and filter.Format are declared in the same order so a
	// list's configured format maps straight across.
	added := filter.parse_list(target_block, target_allow, text, filter.Format(list.format))
	logx.infof("list %s: %d rules", list.name, added)
}

@(private)
list_contents :: proc(cfg: ^config.Config, list: config.Block_List, allow_network: bool) -> (text: string, ok: bool) {
	if list.file != "" {
		data, err := os.read_entire_file(list.file, context.allocator)
		if err != nil {
			logx.warnf("list %s: cannot read %q (%v)", list.name, list.file, err)
			return "", false
		}
		return string(data), true
	}
	if list.url == "" {
		return "", false
	}

	cache_path := list_cache_path(cfg, list)
	if allow_network {
		if fresh, fetched := fetch_list(cfg, list, cache_path); fetched {
			return fresh, true
		}
	}

	data, err := os.read_entire_file(cache_path, context.allocator)
	if err != nil {
		return "", false
	}
	logx.infof("list %s: using the cached copy at %s", list.name, cache_path)
	return string(data), true
}

@(private)
fetch_list :: proc(cfg: ^config.Config, list: config.Block_List, cache_path: string) -> (text: string, ok: bool) {
	// Skip the download when the cached copy is still within the refresh window.
	if info, err := os.stat(cache_path, context.temp_allocator); err == nil {
		age := time.diff(info.modification_time, time.now())
		if age < cfg.blocking.refresh {
			return "", false
		}
	}

	logx.infof("list %s: downloading %s", list.name, list.url)
	body, ferr := upstream.fetch_url(list.url, cfg.upstream.bootstrap, FETCH_TIMEOUT, context.allocator)
	if ferr != .None {
		logx.warnf("list %s: download failed (%v)", list.name, ferr)
		return "", false
	}

	// filepath.dir returns a slice of its argument rather than a new string, so
	// there is nothing here to free.
	if dir := filepath.dir(cache_path); dir != "" {
		make_directories(dir)
	}
	if werr := os.write_entire_file(cache_path, body); werr != nil {
		warn_cache_unwritable(cfg, cache_path, werr)
	}
	return string(body), true
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
*/
reload_filters :: proc(s: ^Server, allow_network: bool) {
	block, allow := build_filter_sets(s.cfg, allow_network)
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
}
