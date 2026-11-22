# Installing and running

## From the apt repository

Packages for amd64 and arm64 are published to <https://deb.akiel.dev/> with
every release, so `apt upgrade` keeps elodin current:

```sh
sudo install -d -m755 /etc/apt/keyrings
curl -fsSL https://deb.akiel.dev/gpg.pub.key | gpg --dearmor | sudo tee /etc/apt/keyrings/akiel.gpg > /dev/null
echo 'deb [signed-by=/etc/apt/keyrings/akiel.gpg] https://deb.akiel.dev/ all main' | sudo tee /etc/apt/sources.list.d/akiel.list
sudo apt update
sudo apt install elodin
```

`signed-by` trusts the key for this repository only, rather than for every
source apt reads. What the package installs, and the question it asks, are
below.

## From a .deb

Each GitHub release also carries the `.deb` for each architecture:

```sh
sudo apt install ./elodin_*_amd64.deb
```

The binary lands at `/usr/bin/elodin`, the unit at
`/usr/lib/systemd/system/elodin.service`, and the example configuration at
`/etc/elodin/elodin.yaml` as a conffile, so dpkg keeps your edits across
upgrades. `apt purge` removes the configuration, the blocklist cache and the
state directory.

The install asks one question, defaulting to yes:

> **Make elodin the system resolver?**

Yes stops, disables and **masks** systemd-resolved (masked so a later systemd
upgrade cannot switch it back on and take port 53), replaces `/etc/resolv.conf`
with a real file naming `127.0.0.1`, carrying over any `search` domains, and
starts elodin. elodin reaches its blocklists and upstreams through
`upstream.bootstrap`, so it does not depend on the resolver it replaces.

Nothing is disabled until `elodin --check` has passed. If elodin then fails to
stay up, the package puts systemd-resolved and the old `/etc/resolv.conf` back
and fails the install; `apt remove` restores them the same way. An upgrade
restarts a running elodin only once the new version's `--check` passes; if it
fails, the running one is left alone and the upgrade fails until the file is
corrected and `sudo dpkg --configure -a` is run.
`sudo dpkg-reconfigure elodin` asks again. For unattended installs, preseed it:

```sh
echo 'elodin elodin/takeover-dns boolean true' | sudo debconf-set-selections
```

## From source, as a service

Build it as in the [README](../README.md#building-from-source), then install
`packaging/elodin.service`, which expects the binary at `/usr/local/bin/elodin`
and the configuration at `/etc/elodin/elodin.yaml`:

```sh
sudo install -m755 bin/elodin /usr/local/bin/elodin
sudo install -Dm644 examples/elodin.yaml /etc/elodin/elodin.yaml
sudo install -m644 packaging/elodin.service /etc/systemd/system/
sudo systemctl enable --now elodin
```

The unit binds :53 through `AmbientCapabilities=CAP_NET_BIND_SERVICE` rather
than as root, and runs under `DynamicUser=yes` with `ProtectSystem=strict`; its
`SystemCallFilter=` names the Landlock and `seccomp` calls
[`server.sandbox`](#sandbox) makes, one by one: `@system-service` has none of
them, and `@sandbox`, which does, is only known to systemd 254 and later. On
a host whose libseccomp is older than 2.5.2 (Debian 11, Ubuntu 20.04), systemd
cannot name the Landlock calls and the unit stops the process at its first one
(`status=31/SYS` in `systemctl status`); there, a drop-in with
`SystemCallErrorNumber=EPERM`, or `server.sandbox: off`, starts it.
`Restart=on-failure` with `StartLimitBurst=5` retries a start that fails for a
passing reason and gives up in `failed` on one that does not — a port it cannot
have, a certificate it cannot read. `systemctl reset-failed elodin` clears that.
The unit also sets `MALLOC_MMAP_THRESHOLD_=131072`, without which glibc keeps the
memory each blocklist refresh frees (see [Sink lists](blocking.md));
`UnsetEnvironment=MALLOC_MMAP_THRESHOLD_` in a drop-in takes glibc's default
instead.

GitHub releases also carry `linux-amd64` and `linux-arm64` tarballs of the
binary, the unit and the example configuration.

## Static tarballs, for musl systems and any other amd64 or arm64 Linux

The binary in the tarballs above, like the `.deb`'s, links against glibc and the
system OpenSSL, so it does not start on Alpine, OpenWrt or another musl system.
Each release also carries `elodin-<tag>-linux-amd64-static.tar.gz` and
`elodin-<tag>-linux-arm64-static.tar.gz`, with the same contents and a binary
that carries musl and OpenSSL inside it. It runs on any Linux of its
architecture, glibc distributions included. Where systemd runs it, it installs
as [above](#from-source-as-a-service). `elodin --version` names the OpenSSL it
carries, with `static` after it:

```
elodin 0.28.0 (OpenSSL 3.5.9 29 Sep 2026, static)
```

Where it differs from the dynamic build:

- **OpenSSL fixes arrive only with an elodin release.** The system's package
  manager does not update an OpenSSL linked into the binary. Check an OpenSSL
  advisory against the version `--version` prints.
- **Trusted certificates.** Blocklist downloads over HTTPS and DoT and DoH
  upstreams with `verify` on check the peer against `/etc/ssl/cert.pem` and the
  hashed directory `/etc/ssl/certs`. Debian, Ubuntu, Fedora, openSUSE, Arch,
  Alpine and OpenWrt keep their bundle there, once their `ca-certificates`
  (OpenWrt: `ca-bundle`) package is installed. Elsewhere, name the bundle in the
  service's environment, `Environment=SSL_CERT_FILE=/path/to/bundle.pem` (or
  `SSL_CERT_DIR` for a hashed directory). Without one, every list download
  fails with `download failed (TLS_Failed)` and every verified upstream with
  `certificate verify failed`.
- **The system's `openssl.cnf` is not read**, nor a file `OPENSSL_CONF` names:
  it is written for the system's own OpenSSL, and the embedded one can refuse
  it (openSUSE's names an option only openSUSE's OpenSSL knows). A system-wide
  crypto policy does not apply; elodin's own floor of TLS 1.2 does. A dynamic
  build applies the file, and logs `OpenSSL could not apply its configuration`
  with OpenSSL's reason when it cannot. The file can narrow elodin's TLS 1.2
  suites (see [what is implemented](protocol-support.md#what-is-implemented))
  and raise its TLS 1.2 floor with `CipherString`, `Ciphersuites` and
  `MinProtocol`, never widen or lower them. The listeners pick by elodin's own
  suite order whatever `Options` says. A file that leaves no TLS elodin
  will speak (none of its TLS 1.2 suites within the version bounds, and no TLS
  1.3) fails every TLS context with `No_Suite` and the reason in the log: a DoT
  or DoH listener stops the server at startup, and a TLS upstream or list
  download fails.
- **Accounts come from `/etc/passwd` and `/etc/group` only.** musl has no NSS,
  so a `server.user` or `server.group` that LDAP, SSSD or systemd-userdb
  provides is `no such user` to the static build and its `--check`. Use a local
  account, or leave `server.user` empty and start unprivileged, as the systemd
  unit does.
- **It is larger on disk, smaller in memory and slower under TLS load.** The
  binary is about 8.5 MB against 1.8 MB. musl's allocator costs the
  TLS transports most: on a 4-core x86 machine, `mise run bench -- -only
  transports` measured DoT at 46,000 queries a second against the dynamic
  build's 77,000 and DoH at about three quarters of its rate, with UDP and TCP
  within 8%. Idle, it held 6.3 MB resident against 10.5 MB. On a glibc system
  with a busy DoT or DoH listener, prefer the dynamic build.

The unit's `MALLOC_MMAP_THRESHOLD_` is glibc's, and musl ignores it; musl's
allocator gives a blocklist refresh's memory back without it.

## Container image

Each release publishes an image for amd64 and arm64 to the GitHub Container
Registry, tagged with the release (`0.28.0`), its minor version (`0.28`) and
`latest`:

```sh
docker run -d --name elodin --restart unless-stopped --ulimit nofile=65536 \
  -p 192.168.1.2:53:53/udp -p 192.168.1.2:53:53/tcp \
  -v elodin-cache:/var/cache/elodin ghcr.io/jadolg/elodin:latest
```

[`examples/compose.yaml`](../examples/compose.yaml) is the same for Docker
Compose, with a read-only root, every capability dropped and
`no-new-privileges`, none of which the image needs.
[`examples/compose-public.yaml`](../examples/compose-public.yaml) runs it as a
public DoT and DoH resolver instead, with certbot obtaining and renewing a
Let's Encrypt certificate and reloading elodin when it changes.

**What is in it.** elodin on Google's [distroless](https://github.com/GoogleContainerTools/distroless)
Debian 13 base (`base-debian13:nonroot`), about 10 MB to pull. The base carries
glibc, OpenSSL and the CA bundle, and no other program: no shell, no package
manager, no busybox. elodin adds:

| path | what |
|---|---|
| `/usr/bin/elodin` | the binary, linked in Debian 13 against the base's glibc and OpenSSL |
| `/etc/elodin/elodin.yaml` | [`examples/docker.yaml`](../examples/docker.yaml) |
| `/var/cache/elodin/` | the blocklist cache, owned by the account it runs as, `nonroot` (uid and gid 65532) |

`docker exec` finds nothing to run but elodin and the shared libraries, two of
which are executable as every dynamically linked image's are: glibc's
`libc.so.6`, which only prints its version, and the dynamic loader, which starts
an ELF file it is given. With the root read-only, the only place such a file
could be written is the cache volume. The build fails if the image holds any
other program, so a shell arriving with a base update is caught before it is
published. For a shell beside a running
container, `docker debug`, or the base's `:debug-nonroot` variant with busybox,
are the tools.

**Updates and verification.** The base is pinned by digest in the
`Dockerfile`, so a commit builds the same image whenever it is built.
Dependabot moves the pin when Google rebuilds the base for a Debian security
update; a weekly job then checks whether the newest release's image still sits
on the pinned base, and if not rebuilds it and moves its tags, so an OpenSSL or
glibc fix reaches the image without waiting for an elodin release. Only the
newest release is refreshed: the tag of an older line (`0.27`) keeps the base it
was published on, so follow `latest` or the newest minor tag. The base's
package metadata is in the image, so scanners such as Trivy and Grype see glibc
and OpenSSL and their versions; each image also carries an SBOM and build
provenance:

```sh
docker buildx imagetools inspect ghcr.io/jadolg/elodin:latest --format '{{json .SBOM}}'
```

Images are signed with cosign, keyless, by the workflow that built them, run
for a release tag or, for a refresh, from `main`; a signature made from any
other branch does not verify:

```sh
cosign verify ghcr.io/jadolg/elodin:latest \
  --certificate-identity-regexp '^https://github\.com/jadolg/elodin/\.github/workflows/image\.yml@refs/(tags/[^/]+|heads/main)$' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

`latest` moves only to the highest release, and `0.28` only to the highest
`0.28.x`, so publishing a fix for an older line never moves either backwards.

**Building it yourself.** `docker build -t elodin .` in a checkout is the
whole build: elodin compiles inside it, with the Odin release `mise.toml` pins,
in the Debian release the base is built from, so the host needs nothing but
Docker. It builds for the host's architecture. `--target verify` also checks
what the image holds.

**Your own configuration.** Mount it over the default, read-only, and check it
first with the image that will run it:

```sh
docker run --rm -v "$PWD/elodin.yaml:/etc/elodin/elodin.yaml:ro" ghcr.io/jadolg/elodin --check
```

Certificates for DoT or DoH and `file:` lists are mounted the same way; the
account has to be able to read them. `docker kill -s HUP elodin` reloads as
`SIGHUP` does [below](#signals). Allow `docker stop` more than
`server.client_timeout` (`-t 15`), or an idle connection's wait is cut short by
SIGKILL.

**Ports.** The image runs as uid 65532 from the start, and binds port 53 without
any capability because Docker lets an unprivileged process bind low ports in a
container's own network namespace. Publish on the host's LAN address rather
than on every address: systemd-resolved holds `127.0.0.53:53`, and Docker
cannot publish `0.0.0.0:53` beside it. Never publish it on a public address:
a client Docker's proxy relays (every IPv6 client, on a bridge without IPv6) arrives
from the bridge's gateway, which the default `allow_from` admits as private, so
the list does not keep the internet out. With `--network host` the host's rule for
ports below 1024 applies instead; start it as root with `--user 0` and set
`server.user: nonroot`, and it drops to the image's account once its ports are
bound ([below](#privileges)).

**Descriptors.** Docker's default limit of 1,024 is short of what the default
configuration can want, which elodin warns about at startup (`descriptors:
the limit is 1024`); `--ulimit nofile=65536` raises it.

**How it differs from the `.deb`'s build.** The same glibc and dynamically
linked OpenSSL, at Debian 13's versions rather than your distribution's. The
image sets `MALLOC_MMAP_THRESHOLD_=131072`, as the systemd unit does, and
`SSL_CERT_FILE` names the base's CA bundle; mount another bundle and point
`SSL_CERT_FILE` at it to change what upstreams are checked against. OpenSSL
applies the file `OPENSSL_CONF` names, if any; the image carries none.

## Privileges

Binding a port below 1024 is the only thing elodin needs root for. Either of two
arrangements keeps it from being root while it parses what comes off the
network.

**Never become root.** Grant the capability, as the systemd unit does, or
`setcap` as the [README](../README.md#building-from-source) shows, and start as an ordinary
user. Leave `server.user` empty.

**Start as root and put it down.** Name an account and elodin switches to it the
moment the listeners have their ports. Nothing is read from them before the
switch, nor, under `server.sandbox: strict`, before the syscall filter: a query
that arrives in between waits in the kernel, and the lines saying where elodin
listens come after both.

```yaml
server:
  user: elodin        # a name or a numeric uid
  group: elodin       # optional; defaults to the user's primary group
```

Supplementary groups go first, then the gid, then the uid — real, effective and
saved — and the real and effective ids are read back from the kernel before the
drop is reported. A drop that was configured and did not happen ends the
process. A misspelt account name fails `--check`; running as root with no
`server.user` logs a warning. `blocking.cache_dir` changes owner along with the
process, since a refresh hours later has to write there: the directory itself,
and each list elodin caches as it writes it. Nothing else in the directory
changes owner, since a chown as root of a hard link the account put there would
hand over the file it links to, wherever that file is. For the same reason a
root start reads a cached list only as a plain file with one link that belongs
to the account, never through a symlink; any other is not read (the log says
why) and is downloaded again. A copy an earlier version cached as root is one of
those, once: the first root start after upgrading has no cached lists to fall
back on, so if it cannot download them it serves without them until a refresh
succeeds (`chown -R` the directory to the account before upgrading to avoid it). On a filesystem with no owners (vfat, including one mounted
`quiet`, or an NFS export that squashes root) no copy can belong to the account:
each start uses what it downloads and downloads the lists again at the next
start rather than read them, so a start with no network has none. Started as
anyone but root, and after the drop, elodin reads its copies however they are
linked or owned, since it reads nothing more through a link than by name. A `cache_dir` that is itself
a symlink is not followed, and so not handed over: name the directory it points
at. Started this way, elodin downloads and parses the blocklists before it
binds, so that much happens as root; the first arrangement avoids it.

The files a [`SIGHUP`](#signals) opens again by name are opened as that account,
not as root: the configuration file, the DoT/DoH `cert_file` and `key_file`,
`file:` lists and `log.file` (for writing; a log file elodin creates is
given to the account as it is made, see [Logs](logging.md)). Startup reads them as root, so a
root-only file — certbot's `privkey.pem` is root's and `0600` — starts fine and
then fails at every reload: the certificate is not renewed in place, and the
listener goes on serving the old one until it expires. A `file:` list is read
again by every scheduled refresh as well, and one the account cannot read has
its rules lifted then. elodin does not take
these files over. Give the account read access in a way that survives a
renewal, which writes a new `privkeyN.pem` under `archive/`: certbot carries the
previous key's group and group-read bit over to the new one, but not an ACL on
it. So `chgrp elodin` and `chmod g+r` the current
`/etc/letsencrypt/archive/<name>/privkeyN.pem` (and give the group `x` on
`/etc/letsencrypt/live` and `/etc/letsencrypt/archive`, which certbot makes
`0700`), or use a certbot deploy hook that copies the pair somewhere the account
can read. Each file out of reach is named
in a `warn` right after the drop:

```
ts=2026-11-03T15:41:14Z level=warn msg="listeners.dot.key_file: elodin cannot open \"/etc/letsencrypt/live/dns.example/privkey.pem\" (Permission denied), so a SIGHUP will keep the certificate loaded now"
```

The [systemd unit](#from-source-as-a-service) never starts as root, so it reads them as its own
account from the start, and a key it cannot read fails the start instead.

### Sandbox

`server.sandbox` narrows what the process may do once it serves, however it
was started, as root or not:

```yaml
server:
  sandbox: basic      # off, basic (the default) or strict
```

| Mode | What it applies |
|---|---|
| `off` | nothing |
| `basic` | `no_new_privs`, and [Landlock](https://docs.kernel.org/userspace-api/landlock.html) on writes: the process can create, write and remove files only in `blocking.cache_dir` (with blocking on, or when the directory exists at startup), and create and write them only there and in the directory `log.file` is in (the directory of the file it resolves to, not of a symlink's name). Only for a regular file: a log on a device, FIFO or socket, such as `/dev/stdout`, is written through the descriptor already open, and a `SIGHUP` keeps it. Nothing can be executed. Reads are not confined. On Landlock ABI 6 kernels it also cannot signal another process or connect to an abstract unix socket outside itself |
| `strict` | `basic`, with Landlock on reads too, and a seccomp allowlist of system calls installed after the privilege drop and before any listener is read |

Both layers are set before the event loops start, so every thread has them,
and they last for the life of the process: `server.sandbox` takes a restart.

- With blocking off and `blocking.cache_dir` not there yet, startup says that a
  reload turning blocking on will not be able to keep copies of the lists. A
  cache directory removed while the process runs cannot be made again until a
  restart, for the same reason.
- A file the sandbox would reach through its directory that sits directly in
  `/`, `/etc`, `/etc/ssl` and `/etc/pki` and their private-key directories,
  `/root`, an account's home under `/home`, or one of `/home`, `/tmp`, `/var`,
  `/var/lib`, `/var/tmp`, `/srv`, `/opt`, `/usr` and `/run` (by its name or by
  where a symlink leads) is reached alone
  instead, and startup names it: one that replaces it - an editor, a renewal, a
  log rotation - is not seen until a restart, so give it a directory of its own.
- A file the sandbox refuses is reported as for any other file that cannot be
  opened, with `(or server.sandbox refuses it: ...)` added where the sandbox
  confines that access. A reload that moves `log.file` somewhere it refuses
  keeps logging where it was.

Landlock needs Linux 5.13 or later with `landlock` among the kernel's `lsm=`
modules, and a container runtime that allows its system calls. Without it
the rest applies and startup warns:

```
ts=2026-11-19T08:59:48Z level=warn msg="server.sandbox: Landlock is unavailable (Operation not supported), so writing files is not confined; it needs Linux 5.13 with landlock among the lsm= modules, and a container runtime that allows its system calls"
```

A path the sandbox would grant that cannot be opened at startup is named in a
warning with the reason, and stays out of reach until a restart, even once it
can be. Under `strict`, startup lists every path reads are granted on
(`server.sandbox: strict reads ...`). The line after the drop says what is in
force:

```
ts=2026-11-19T08:59:48Z level=info msg=sandbox mode=strict no_new_privs=true landlock_abi=6 seccomp=true
```

Under `strict`, reading is confined to these:

- the directories of the configuration file, the DoT and DoH `cert_file` and
  `key_file`, and every `file:` list (enabled or not, and with blocking off
  too), and, when one is a symlink, the directory of what it points to. A file
  directly in `/` is granted alone rather than through its directory;
- `blocking.cache_dir`;
- `/etc/resolv.conf` and `/etc/hosts` themselves, and the directory of what
  either links to (`/run/systemd/resolve` under systemd-resolved), which a list
  download reads when `upstream.bootstrap` does not answer for its host. The
  files and not `/etc`, which holds every other secret on the host; a resolver
  that replaces `/etc/resolv.conf` by renaming a new file over it (NetworkManager
  without systemd-resolved, dhclient) leaves the rule on the old file, so with
  hosts to look up and no `upstream.bootstrap`, startup says to set one;
- OpenSSL's trust store, or what `SSL_CERT_FILE` and `SSL_CERT_DIR` name: the
  directory the bundle file leads to (not the one its name is in, `/etc/ssl` or
  `/etc/pki/tls`, beside the host's private keys), the certificate directory,
  and every directory that directory's entries point into
  (`/usr/share/ca-certificates/mozilla` on Debian and Ubuntu);
- `/proc` and `/sys/fs/cgroup`, which the metrics and the sizing read. Both are
  granted whole: procfs makes a new inode each time it looks up an entry it
  had let go of, so a rule on `/proc/<pid>` would stop matching. Only the
  mount's root lasts.

A reload that names a file outside those, such as a certificate moved to a new
directory or a new `file:` list elsewhere, cannot read it until a restart, and
says so as for any file it cannot open. The syscall allowlist kills the process
on any call off the list. The calls a serving process makes on glibc and musl,
on x86_64 and arm64, are on it. A libc that makes another one ends the process
with `SIGSYS`; set `basic` and report it. `execve`, `ptrace`, `bind`, `ioctl`,
new processes (a `clone` that is not a thread) and namespaces, sockets other
than IPv4 and IPv6 streams and datagrams over TCP or UDP (no raw sockets, no
SCTP), scheduling policies other than the default and the one the process was started
under, and socket options other
than the read and write timeouts and `TCP_NODELAY` are not on it.
`strict` refuses to start where the filter cannot be installed, which includes
any architecture other than x86_64 and arm64.

## Signals

`SIGTERM` and `SIGINT` stop the listeners and let the queries in flight finish. An idle
client connection is only noticed when its read times out, so stopping can take
up to `server.client_timeout` (ten seconds by default). A second signal
terminates immediately. Blocklists are downloaded and the rule sets built on a
thread of their own, so a signal is acted on at once whatever a download is
waiting for; a stop does not wait for a rebuild in progress (`blocklists: not
waiting for the rebuild in progress`), and one during the downloads at startup
exits before anything is listening.

`SIGHUP` (`systemctl reload elodin`) reloads without dropping a connection or a
cached answer it has no reason to, in this order:

1. The log file is opened again by name, which is what logrotate's `create`
   expects.
2. The configuration file is read again. It goes through the checks `--check`
   runs, and every upstream group, trust anchor and cookie secret a change needs
   is built before anything is swapped in. A file that fails any of that is
   logged (`reload: ... is not usable; keeping the configuration already in
   effect`) and changes nothing. A query already being answered finishes under
   the configuration it started with. A change to the rule sets rebuilds them
   afterwards on the blocklists' own thread, once any rebuild in progress is
   over (`reload: the rules are rebuilt once the rebuild in progress is over`).
3. The DoT/DoH certificate and key are read again from the paths the process
   started with, whether or not the file loaded, as the account the process
   runs as ([Privileges](#privileges)). A session in progress keeps the
   certificate it handshook with; one that fails to load is logged and the
   listener keeps serving what it had.

A reload that applies something logs one line, then the warnings startup logs
about the configuration:

```
ts=2026-10-19T19:35:57Z level=info msg=reloaded changed=upstream,rewrites rebuilt=upstreams cache=flushed
```

`changed` is the sections that differ; `rebuilt` the parts built afresh
(`upstreams`, `validator`, `cookies`, `cookie_secrets`, `limiter`, `answers`,
or `none`; `cookie_secrets` is cookie secrets built afresh, for a changed
`cookies.secret` or cookies turned on); rule
sets rebuilt after it log their own `filter:` line (`filter: blocking is off; no
rules in effect` when turned off), or keep the rules in effect;
`cache` is `kept`, `flushed`, `new` or `off`.

| section | on reload |
|---|---|
| `log`, `rewrites`, `special_use`, `rebind` | applied from the next query |
| `server.allow_from`, `max_pending`, `max_udp_response`, `client_timeout` | applied from the next query or read |
| `server.rate_limit` | a change rebuilds the limiter, so every prefix starts again from a full budget |
| `upstream`, `cookies.upstream` | a change rebuilds every group and route: new connections, new upstream cookies |
| `cache` | resized in place; turned off or on, dropped or started empty |
| `dnssec` | a change rebuilds the validator, which fetches its zone keys again |
| `cookies` | applied; the secret is kept unless `cookies.secret` changes |
| `blocking` | a change to `enabled`, the lists or the rules rebuilds the rule sets, and a list whose cached copy is within `refresh` is not downloaded again; `response`, `custom_ipv4`, `custom_ipv6`, `block_ttl` and `refresh` apply from the next query or tick. Lists read from a `file:` are read again on every SIGHUP, changed configuration or not. If a list that loaded before cannot be had, the rules in effect are kept, as on a refresh, and the change applies at the retry |
| `listeners` (including `udp.readers`, the loop count), `ddr`, `metrics`, `max_connections`, `max_connections_per_prefix`, `pin_loops`, `user`, `group`, `sandbox`, `blocking.cache_dir` | need a restart; each one changed is named in a warning and keeps the value it started with |

A change to which upstreams are asked (`upstream.servers`, `upstream.bootstrap`,
`upstream.zones` and their servers), to `dnssec.enabled`, `trust_anchors` or
`max_nsec3_iterations`, to `rebind`, or to `cache.min_ttl`,
`max_ttl` or `negative_ttl` empties the answer cache, since each decides what was
stored and how it was checked first. An answer a query already in flight stores afterwards is not served
either. Unchanged sections keep what they built: the upstream connections and
cookies, the cache, the client cookie secret and the rate-limit budgets survive a
reload of anything else.

`blocking.cache_dir` is handed to `server.user` at startup only if blocking is
on then. Turning blocking on with a reload after that needs the directory to be
writable by that user already (the packaged unit's `CacheDirectory=` is);
otherwise the lists still load, are not cached, and the log says so.

A listener cannot move without a restart: below port 1024 it could not be bound
again once privileges are dropped, and the event loops it runs on are started once.
