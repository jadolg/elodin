package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

func aghConfig(h *harness, o serverOpts, p ports, bin string) ([]string, error) {
	web, err := freePort()
	if err != nil {
		return nil, err
	}
	work := filepath.Join(h.dir, o.name+"-agh")
	_ = os.RemoveAll(work)
	if err := os.MkdirAll(work, 0o755); err != nil {
		return nil, err
	}
	cert, key := h.certs(o)
	filters := "filters: []\n"
	if o.blockRules > 0 {
		list, err := h.writeList(o, "txt", "", func(n string) string { return "||" + n + "^" })
		if err != nil {
			return nil, err
		}
		filters = fmt.Sprintf("filters:\n  - enabled: true\n    url: %s\n    name: bench\n    id: 1\n", list)
	}
	cache := "true"
	if !o.cache {
		cache = "false"
	}
	// The schema 0.107.80 writes; without it the file is migrated as a
	// version-0 one and the migration refuses it.
	cfg := fmt.Sprintf(aghTemplate, web, p.dns, p.upPort, p.upPort, inflightBound(o), cache, cacheBytes(o, 4096), p.doh, p.dot, cert, key, h.dir, filters)
	path, err := h.writeConf(o, "yaml", cfg)
	if err != nil {
		return nil, err
	}
	return []string{bin, "-c", path, "-w", work, "--no-check-update", "--no-permcheck"}, nil
}

func blockyConfig(h *harness, o serverOpts, p ports, bin string) ([]string, error) {
	cert, key := h.certs(o)
	blocking := ""
	if o.blockRules > 0 {
		list, err := h.writeList(o, "txt", "", func(n string) string { return n })
		if err != nil {
			return nil, err
		}
		blocking = fmt.Sprintf(blockyTemplate, list)
	}
	caching := fmt.Sprintf("caching:\n  maxItemsCount: %d\n  prefetching: false\n", o.cacheEntries)
	if !o.cache {
		caching = "caching:\n  maxTime: -1m\n"
	}
	cfg := fmt.Sprintf(`upstreams:
  groups:
    default: [127.0.0.1:%s]
  timeout: 5s
  init:
    strategy: fast
ports:
  dns: 127.0.0.1:%d
  tls: 127.0.0.1:%d
  https: 127.0.0.1:%d
certFile: %s
keyFile: %s
# Blocky answers RFC 6761 names itself, NXDOMAIN for all of test.; the
# mock's zone is under it, so it has to be forwarded instead.
specialUseDomains:
  enable: false
%s%squeryLog:
  type: none
log:
  level: warn
`, p.upPort, p.dns, p.dot, p.doh, cert, key, caching, blocking)
	path, err := h.writeConf(o, "yaml", cfg)
	if err != nil {
		return nil, err
	}
	return []string{bin, "--config", path}, nil
}

func corednsConfig(h *harness, o serverOpts, p ports, bin string) ([]string, error) {
	cert, key := h.certs(o)
	cache := fmt.Sprintf("cache 3600 {\n    success %d\n    denial %d\n  }", o.cacheEntries, o.cacheEntries)
	if !o.cache {
		cache = ""
	}
	// CoreDNS keeps one cache per server block, so the three blocks each
	// fill their own.
	block := func(scheme string, port int, tls string) string {
		return fmt.Sprintf(`%s.:%d {
  bind 127.0.0.1
  %s
  forward . 127.0.0.1:%s {
    max_concurrent %d
  }
  %s
  timeouts {
    idle %ds
  }
}
`, scheme, port, tls, p.upPort, inflightBound(o), cache, secs(o.clientTimeout))
	}
	tls := fmt.Sprintf("tls %s %s", cert, key)
	// CoreDNS serves at most 200 DoH connections unless told otherwise; the
	// counterpart of max_connections, as for the other listeners.
	https := fmt.Sprintf("%s\n  https {\n    max_connections %d\n  }", tls, o.maxConnections)
	cfg := block("", p.dns, "") + block("tls://", p.dot, tls) + block("https://", p.doh, https)
	path, err := h.writeConf(o, "Corefile", cfg)
	if err != nil {
		return nil, err
	}
	return []string{bin, "-conf", path, "-quiet"}, nil
}

func dnsmasqConfig(h *harness, o serverOpts, p ports, bin string) ([]string, error) {
	cache := o.cacheEntries
	if !o.cache {
		cache = 0
	}
	cfg := fmt.Sprintf(`port=%d
listen-address=127.0.0.1
bind-interfaces
no-resolv
no-hosts
no-poll
server=127.0.0.1#%s
cache-size=%d
dns-forward-max=%d
max-tcp-connections=%d
pid-file=
`, p.dns, p.upPort, cache, inflightBound(o), o.maxConnections)
	if o.blockRules > 0 {
		// Pi-hole's own form before it moved the list into gravity.db.
		list, err := h.writeList(o, "conf", "", func(n string) string { return "address=/" + n + "/" })
		if err != nil {
			return nil, err
		}
		cfg += "conf-file=" + list + "\n"
	}
	path, err := h.writeConf(o, "conf", cfg)
	if err != nil {
		return nil, err
	}
	return []string{bin, "--keep-in-foreground", "--conf-file=" + path}, nil
}

func pdnsConfig(h *harness, o serverOpts, p ports, bin string) ([]string, error) {
	dir := filepath.Join(h.dir, o.name+"-pdns")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	sock, err := os.MkdirTemp("", "pdns")
	if err != nil {
		return nil, err
	}
	threads := unboundThreads(o.loops)
	entries := o.cacheEntries
	if !o.cache {
		entries = 0
	}
	cfg := fmt.Sprintf(pdnsTemplate, p.dns, p.upPort, threads, entries, entries, inflightBound(o), o.maxConnections, secs(o.clientTimeout), sock)
	if o.blockRules > 0 {
		rpz, err := h.writeRPZ(o)
		if err != nil {
			return nil, err
		}
		lua := filepath.Join(dir, "rpz.lua")
		if err := os.WriteFile(lua, []byte(fmt.Sprintf("rpzFile(%q, {policyName=\"bench\"})\n", rpz)), 0o644); err != nil {
			return nil, err
		}
		cfg += "lua-config-file=" + lua + "\n"
	}
	if err := os.WriteFile(filepath.Join(dir, "recursor.conf"), []byte(cfg), 0o644); err != nil {
		return nil, err
	}
	return []string{bin, "--config-dir=" + dir, "--enable-old-settings"}, nil
}

func dnsdistConfig(h *harness, o serverOpts, p ports, bin string) ([]string, error) {
	cert, key := h.certs(o)
	threads := unboundThreads(o.loops)
	var sb strings.Builder
	sb.WriteString("setSecurityPollSuffix('')\nsetACL({'127.0.0.0/8'})\n")
	// One UDP listener is one thread; SO_REUSEPORT listeners are how dnsdist
	// spreads UDP over more.
	fmt.Fprintf(&sb, "setLocal('127.0.0.1:%d', {reusePort=true})\n", p.dns)
	for range threads - 1 {
		fmt.Fprintf(&sb, "addLocal('127.0.0.1:%d', {reusePort=true})\n", p.dns)
	}
	fmt.Fprintf(&sb, "addTLSLocal('127.0.0.1:%d', %q, %q)\n", p.dot, cert, key)
	fmt.Fprintf(&sb, "addDOHLocal('127.0.0.1:%d', %q, %q, '/dns-query')\n", p.doh, cert, key)
	fmt.Fprintf(&sb, "newServer({address='127.0.0.1:%s', healthCheckMode='up'})\n", p.upPort)
	fmt.Fprintf(&sb, "setUDPTimeout(5)\nsetTCPRecvTimeout(%d)\nsetMaxTCPClientThreads(%d)\n", secs(o.clientTimeout), threads)
	if o.cache {
		fmt.Fprintf(&sb, "getPool(''):setCache(newPacketCache(%d))\n", o.cacheEntries)
	}
	if o.blockRules > 0 {
		list, err := h.writeList(o, "txt", "", func(n string) string { return n })
		if err != nil {
			return nil, err
		}
		fmt.Fprintf(&sb, `local s = newDNSNameSet()
for l in io.lines(%q) do s:add(newDNSName(l)) end
addAction(QNameSetRule(s), RCodeAction(DNSRCode.NXDOMAIN))
`, list)
	}
	path, err := h.writeConf(o, "lua", sb.String())
	if err != nil {
		return nil, err
	}
	return []string{bin, "--supervised", "--disable-syslog", "-C", path}, nil
}

func bindConfig(h *harness, o serverOpts, p ports, bin string) ([]string, error) {
	dir := filepath.Join(h.dir, o.name+"-bind")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	cert, key := h.certs(o)
	cacheSize := fmt.Sprint(cacheBytes(o, 4096))
	// BIND's idle timeouts are tenths of a second, at most two minutes.
	idle := min(1200, secs(o.clientTimeout)*10)
	rpz, zone := "", ""
	if o.blockRules > 0 {
		path, err := h.writeRPZ(o)
		if err != nil {
			return nil, err
		}
		// log no: BIND otherwise logs every rewrite, and -g sends it to
		// stderr whatever the logging statement says, a line per blocked
		// answer that no other server writes.
		rpz = `  response-policy { zone "rpz.bench" log no; };` + "\n"
		zone = fmt.Sprintf("zone \"rpz.bench\" { type primary; file %q; };\n", path)
	}
	nocache := ""
	if !o.cache {
		nocache = "  max-cache-ttl 0;\n  max-ncache-ttl 0;\n"
	}
	cfg := fmt.Sprintf(bindTemplate, cert, key, dir, p.dns, p.dot, p.doh, p.upPort, cacheSize, nocache, inflightBound(o),
		o.maxConnections, o.maxConnections, idle, idle, rpz, zone)
	path, err := h.writeConf(o, "conf", cfg)
	if err != nil {
		return nil, err
	}
	return []string{bin, "-g", "-c", path, "-n", fmt.Sprint(unboundThreads(o.loops))}, nil
}

func knotConfig(h *harness, o serverOpts, p ports, bin string) ([]string, error) {
	dir := filepath.Join(h.dir, o.name+"-knot")
	_ = os.RemoveAll(dir)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	cert, key := h.certs(o)
	var sb strings.Builder
	fmt.Fprintf(&sb, `net.listen('127.0.0.1', %d, {kind='dns'})
net.listen('127.0.0.1', %d, {kind='tls'})
net.listen('127.0.0.1', %d, {kind='doh2'})
net.tls(%q, %q)
net.tcp_in_idle(%d)
trust_anchors.remove('.')
cache.open(%d, 'lmdb://%s')
`, p.dns, p.dot, p.doh, cert, key, o.clientTimeout.Milliseconds(), max(10<<20, cacheBytes(o, 4096)), filepath.Join(dir, "cache"))

	if o.blockRules > 0 {
		rpz, err := h.writeRPZ(o)
		if err != nil {
			return nil, err
		}
		fmt.Fprintf(&sb, "policy.add(policy.rpz(policy.DENY, %q))\n", rpz)
	}
	// Knot answers RFC 6761 names itself, NXDOMAIN for all of test.; the
	// rule for the mock's zone is more specific than its own and forwards it.
	for _, zone := range []string{".", "bench.test."} {
		fmt.Fprintf(&sb, "policy.rule_forward_add(%q, {dnssec=false}, {{'127.0.0.1@%s'}})\n", zone, p.upPort)
	}
	path, err := h.writeConf(o, "lua", sb.String())
	if err != nil {
		return nil, err
	}
	// One kresd is one thread; Knot scales across cores by running one
	// process per core behind SO_REUSEPORT, which this harness, sampling one
	// pid, does not do. Its rows are one process.
	return []string{bin, "-n", "-q", "-c", path, dir}, nil
}

// piholeConfig runs Pi-hole's FTL, which reads its configuration and its
// list from /etc/pihole and nowhere else. It runs as root in a mount namespace
// of its own with the run's directory bound over /etc/pihole (which has to
// exist as an empty mount point), and the list is a gravity.db built from
// Pi-hole's own schema, -competitors/pihole/gravity.db.sql.
func piholeConfig(h *harness, o serverOpts, p ports, bin string) ([]string, error) {
	dir := filepath.Join(h.dir, o.name+"-pihole")
	etc := filepath.Join(dir, "etc")
	_ = exec.Command("sudo", "rm", "-rf", dir).Run()
	if err := os.MkdirAll(etc, 0o755); err != nil {
		return nil, err
	}
	web, err := freePort()
	if err != nil {
		return nil, err
	}
	schema, err := os.ReadFile(filepath.Join(h.competitorDir, "pihole", "gravity.db.sql"))
	if err != nil {
		return nil, err
	}
	var sql strings.Builder
	sql.Write(schema)
	sql.WriteString("\nBEGIN;\nINSERT INTO adlist (id,address,enabled) VALUES (1,'file:///bench',1);\n")
	if o.blockRules > 0 {
		for _, n := range blockNames(o.blockRules) {
			fmt.Fprintf(&sql, "INSERT INTO gravity (domain,adlist_id) VALUES ('%s',1);\n", n)
		}
	}
	fmt.Fprintf(&sql, "INSERT OR REPLACE INTO info VALUES ('updated', %d);\n", time.Now().Unix())
	fmt.Fprintf(&sql, "INSERT OR REPLACE INTO info VALUES ('gravity_count', %d);\nCOMMIT;\n", o.blockRules)
	db := exec.Command(bin, "sqlite3", filepath.Join(etc, "gravity.db"))
	db.Stdin = strings.NewReader(sql.String())
	if outb, err := db.CombinedOutput(); err != nil {
		return nil, fmt.Errorf("building gravity.db: %w: %s", err, outb)
	}
	cache := o.cacheEntries
	if !o.cache {
		cache = 0
	}
	cfg := fmt.Sprintf(piholeTemplate, p.upPort, p.dns, cache, web, dir, dir, dir, dir, inflightBound(o), o.maxConnections, p.upPort)
	if err := os.WriteFile(filepath.Join(etc, "pihole.toml"), []byte(cfg), 0o644); err != nil {
		return nil, err
	}
	return []string{"sudo", "unshare", "-m", "sh", "-c",
		fmt.Sprintf("mount --bind %s /etc/pihole && exec %s -f", etc, bin)}, nil
}
