# Installing and running

## As a service

`packaging/elodin.service` expects the binary at `/usr/local/bin/elodin` and the
configuration at `/etc/elodin/elodin.yaml`:

```sh
sudo install -m755 bin/elodin /usr/local/bin/elodin
sudo install -Dm644 examples/elodin.yaml /etc/elodin/elodin.yaml
sudo install -m644 packaging/elodin.service /etc/systemd/system/
sudo systemctl enable --now elodin
```

It binds :53 through `AmbientCapabilities=CAP_NET_BIND_SERVICE` rather than as
root, and runs under `DynamicUser=yes` with `ProtectSystem=strict`.
`Restart=on-failure` with `StartLimitBurst=5` retries a start that fails for a
reason that passes, and gives up in `failed` on one that does not — a port it
cannot have, a certificate it cannot read. `systemctl reset-failed elodin` clears
that.

A published GitHub release carries `linux-amd64` and `linux-arm64` tarballs and a
`.deb` for each, both built natively: elodin binds the system libssl, so
cross-compiling would mean carrying a sysroot per architecture.

## From a .deb

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

Yes stops, disables and **masks** systemd-resolved — masking too, since a later
systemd upgrade would otherwise switch it back on and take port 53 at the next
boot — replaces `/etc/resolv.conf` with a real file naming `127.0.0.1`, carrying
over any `search` domains, and starts elodin. elodin reaches its blocklists and
upstreams through `upstream.bootstrap`, so it does not depend on the resolver it
is replacing.

Nothing is disabled until `elodin --check` has passed, and if elodin then fails
to stay up the package puts systemd-resolved and the old `/etc/resolv.conf` back
and fails the install. Removing the package restores them the same way, at `apt
remove` rather than waiting for `apt purge`. `sudo dpkg-reconfigure elodin` asks
again; for unattended installs, preseed it:

```sh
echo 'elodin elodin/takeover-dns boolean true' | sudo debconf-set-selections
```

## Privileges

Binding a port below 1024 is the only thing elodin needs root for, and it is
over within a second of starting; everything after that is parsing input that
came off the network. Either of two arrangements keeps it from being root while
it does that.

**Never become root.** Grant the capability, as the systemd unit does, or
`setcap` as the [README](../README.md#running) shows, and start as an ordinary user. Leave `server.user` empty —
there is nothing to drop.

**Start as root and put it down.** Name an account and elodin switches to it the
moment the listeners have their ports:

```yaml
server:
  user: elodin        # a name or a numeric uid
  group: elodin       # optional; defaults to the user's primary group
```

Supplementary groups go first, then the gid, then the uid — all three of real,
effective and saved — and the real and effective ids are read back from the
kernel before the drop is reported. A drop that was configured and did not
happen ends the process. A misspelt account name fails `--check`; running as
root with no `server.user` logs a warning. `blocking.cache_dir` changes owner
along with the process, since a refresh hours later has to reopen it.

Started this way, elodin downloads and parses the blocklists before it binds, so
that much happens as root. The first arrangement avoids it.

## Signals

`SIGTERM` and `SIGINT` stop the listeners and let the worker pools drain. Open
client connections are waited on, and an idle one is only noticed when its read
times out, so stopping can take up to `server.client_timeout` (ten seconds by
default). A second signal terminates immediately.

`SIGHUP` re-reads the DoT/DoH certificate and key from the paths already in the
configuration and switches the listeners over, with no restart and no dropped
connections: a session in progress keeps the certificate it handshook with. One
that fails to load is logged and left alone, and the listener keeps serving what
it had. Nothing else is reloaded this way — listener addresses, the upstream set
and blocking need a restart.
