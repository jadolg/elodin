#!/bin/sh
# Build a .deb from an already-built bin/elodin.
#
# This assembles the archive by hand with dpkg-deb rather than going through
# debhelper and a debian/ directory. The package is one binary, one unit file
# and one configuration file; a source package built the official way would be
# a dozen files of boilerplate around the same three, and elodin is published
# from a GitHub release into a personal apt repository, never into Debian, so
# nothing downstream reads the parts that boilerplate exists to provide.
#
#   packaging/build-deb.sh [version] [architecture]
#
# Version defaults to $ELODIN_VERSION, then to the tag or short sha of the
# checkout, matching what the binary reports for --version. Architecture
# defaults to the machine running the script; a build for another one has to
# name it, because the binary decides it and this script only labels it.
set -eu

repo_root=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)

binary=${ELODIN_OUT:-$repo_root/bin/elodin}
out_dir=${ELODIN_DEB_OUT:-$repo_root/dist}

# The Debian revision counts packaging changes made against one upstream
# version. It is only ever bumped by hand, to re-release a version whose
# packaging was wrong rather than its code.
revision=${ELODIN_DEB_REVISION:-1}

maintainer=${ELODIN_DEB_MAINTAINER:-'Jorge Alberto Díaz Orozco (Akiel) <diazorozcoj@gmail.com>'}
homepage=https://github.com/jadolg/elodin

version=${1:-${ELODIN_VERSION:-}}
if [ -z "$version" ]; then
    version=$(git -C "$repo_root" describe --tags --exact-match 2>/dev/null \
        || echo "dev-$(git -C "$repo_root" rev-parse --short HEAD 2>/dev/null || echo unknown)")
fi

# Releases are tagged `0.2.0`, but a `v0.2.0` would give a package version that
# sorts below every numeric one, so drop the prefix if it is ever used.
version=${version#v}

# A Debian version has to start with a digit, which `dev-1a2b3c` does not. The
# `0~` prefix fixes that and sorts below every real release, so a machine that
# installed a development build still takes 0.1.0 as an upgrade. `~` is the one
# character that sorts before the empty string in dpkg's comparison.
case $version in
    [0-9]*) ;;
    *) version="0~$version" ;;
esac

arch=${2:-}
if [ -z "$arch" ]; then
    if command -v dpkg-architecture >/dev/null 2>&1; then
        arch=$(dpkg-architecture -qDEB_HOST_ARCH)
    else
        case $(uname -m) in
            x86_64) arch=amd64 ;;
            aarch64) arch=arm64 ;;
            *) echo "unknown machine $(uname -m): pass the architecture explicitly" >&2; exit 1 ;;
        esac
    fi
fi

[ -x "$binary" ] || { echo "no binary at $binary — run 'mise run release' first" >&2; exit 1; }

# A package labelled for one architecture holding a binary for another installs
# cleanly and then fails to run, so check the ELF header against the label the
# same way the release workflow checks the tarball.
case $arch in
    amd64) expect=x86-64 ;;
    arm64) expect=aarch64 ;;
    *) expect= ;;
esac
if [ -n "$expect" ] && command -v file >/dev/null 2>&1; then
    file -b "$binary" | grep -q "$expect" || {
        echo "$binary is not $arch: $(file -b "$binary")" >&2
        exit 1
    }
fi

stage=$(mktemp -d)
trap 'rm -rf "$stage"' EXIT

# mktemp makes its directory 0700, and that mode would travel into the archive
# as the mode of `/`.
chmod 755 "$stage"

install -Dm755 "$binary" "$stage/usr/bin/elodin"

# The unit file in packaging/ is the one a manual install uses, and that puts
# the binary in /usr/local/bin, where a package may not write. Rewriting the
# path here keeps a single unit file for both routes.
unit=$stage/usr/lib/systemd/system/elodin.service
mkdir -p "$(dirname "$unit")"
sed 's|/usr/local/bin/elodin|/usr/bin/elodin|' "$repo_root/packaging/elodin.service" > "$unit"
chmod 644 "$unit"

grep -q '^ExecStart=/usr/bin/elodin ' "$unit" || {
    echo "packaging/elodin.service no longer starts /usr/local/bin/elodin — fix the rewrite above" >&2
    exit 1
}

install -Dm644 "$repo_root/examples/elodin.yaml" "$stage/etc/elodin/elodin.yaml"
install -Dm644 "$repo_root/README.md" "$stage/usr/share/doc/elodin/README.md"

# `copyright` is the name dpkg, apt and every archive tool expect for the
# licence, and the file Debian will not ship a package without. It is the
# repository's LICENSE verbatim rather than a rewrite of it, so there is one
# copy to keep current.
install -Dm644 "$repo_root/LICENSE" "$stage/usr/share/doc/elodin/copyright"

# Reported by apt before it downloads anything, so it is worth being right
# rather than absent. Every payload file is in place by now.
installed_size=$(du -k -s "$stage" | cut -f1)

mkdir -p "$stage/DEBIAN"

# dpkg replaces a conffile on upgrade only when the administrator has not
# touched it, and asks otherwise. Without this the example configuration would
# overwrite a working one on every upgrade.
echo /etc/elodin/elodin.yaml > "$stage/DEBIAN/conffiles"

# The dependencies are written out rather than derived with dpkg-shlibdeps,
# which names the packages of the distribution doing the build: the release
# runs on Ubuntu, where libssl3 was renamed libssl3t64 for the 64-bit time_t
# transition, and a package depending on that name is uninstallable on Debian
# stable. The alternation covers both. There is no version floor on libssl
# because elodin uses OpenSSL 3 API only, and no distribution ships a 3.x
# without it.
cat > "$stage/DEBIAN/control" <<EOF
Package: elodin
Version: $version-$revision
Architecture: $arch
Maintainer: $maintainer
Section: net
Priority: optional
Homepage: $homepage
Depends: libc6, zlib1g, libssl3t64 | libssl3, debconf (>= 0.5) | debconf-2.0
Installed-Size: $installed_size
Description: Filtering DNS forwarder
 elodin serves plain DNS, DNS-over-TLS and DNS-over-HTTPS, forwards to
 upstreams over any of those, filters against blocklists in hosts, plain-domain
 and adblock syntax, caches answers, and validates DNSSEC against the root
 trust anchors. One binary and one YAML file, with no web interface.
 .
 The package offers to make elodin the system resolver: to disable
 systemd-resolved, point /etc/resolv.conf at 127.0.0.1 and start elodin.
 Removing the package puts both back.
EOF

# Asked before the package is unpacked, so the answer is available to postinst.
# Type boolean rather than a select, because there are two coherent outcomes:
# elodin is the resolver on this machine, or it is installed and left alone.
cat > "$stage/DEBIAN/templates" <<'EOF'
Template: elodin/takeover-dns
Type: boolean
Default: true
Description: Make elodin the system resolver?
 elodin listens on port 53, which on this machine belongs to systemd-resolved.
 Both cannot have it.
 .
 Accepting stops, disables and masks systemd-resolved, replaces
 /etc/resolv.conf with one naming 127.0.0.1, and enables and starts elodin.
 Any search domains in the current resolv.conf are carried over. There is a
 gap of a second or two where neither resolver is answering; elodin reaches
 its blocklists and upstreams through the bootstrap addresses in its own
 configuration rather than through the system resolver, so its start does not
 depend on that gap being closed.
 .
 Declining installs elodin without starting it and leaves the resolver alone.
 .
 Removing the package restores systemd-resolved and the previous
 /etc/resolv.conf, whichever answer was given.
EOF

cat > "$stage/DEBIAN/config" <<'EOF'
#!/bin/sh
set -e

. /usr/share/debconf/confmodule

db_input high elodin/takeover-dns || true
db_go || true
EOF

cat > "$stage/DEBIAN/postinst" <<'EOF'
#!/bin/sh
set -e

. /usr/share/debconf/confmodule

# What the takeover changed, so removal puts back what was there and nothing
# else. /var/backups is where Debian keeps this kind of thing. The resolv.conf
# copy doubles as the record that resolv.conf was replaced at all, and is a
# copy rather than a rewrite so a symlink comes back as the same symlink.
saved_resolv=/var/backups/elodin-resolv.conf
resolved_marker=/var/backups/elodin-resolved-disabled

[ "$1" = configure ] || exit 0

if [ -d /run/systemd/system ]; then
    systemctl daemon-reload >/dev/null 2>&1 || true
fi

# `dpkg -i` does not run the config script, so the question may never have been
# asked and the template may not be registered. The default stands in for it.
takeover=true
if db_get elodin/takeover-dns 2>/dev/null; then
    takeover=$RET
fi

# Nothing below can work without systemd, and a container or a chroot is the
# usual reason for it to be missing.
if [ ! -d /run/systemd/system ]; then
    takeover=false
fi

if [ "$takeover" = true ]; then
    # Nothing is touched until elodin agrees the configuration it is about to
    # be started with is usable. Stopping the resolver first and finding out
    # afterwards is how a machine ends up with no DNS at all. --check is
    # offline and takes a few milliseconds.
    if ! /usr/bin/elodin --config /etc/elodin/elodin.yaml --check; then
        db_stop
        cat >&2 <<'MSG'

The resolver on this machine has been left alone, because elodin will not
start with /etc/elodin/elodin.yaml. Correct it and run:

  sudo dpkg-reconfigure elodin
MSG
        exit 1
    fi

    # Only recorded when resolved was actually running or enabled: on a machine
    # that never had it, removing elodin must not switch it on.
    if [ ! -e "$resolved_marker" ]; then
        if systemctl is-enabled systemd-resolved.service >/dev/null 2>&1 \
           || systemctl is-active systemd-resolved.service >/dev/null 2>&1; then
            mkdir -p /var/backups
            : > "$resolved_marker"
        fi
    fi

    if [ -e "$resolved_marker" ]; then
        systemctl disable --now systemd-resolved.service >/dev/null 2>&1 || true
        # Masked as well as disabled, because an upgrade of systemd or of
        # systemd-resolved itself will otherwise start it again, and it would
        # take port 53 back from elodin at the next boot.
        systemctl mask systemd-resolved.service >/dev/null 2>&1 || true
    fi

    # On this machine /etc/resolv.conf is normally a symlink into
    # /run/systemd/resolve, which stops existing the moment resolved does. A
    # real file naming elodin has to replace it or nothing on the machine
    # resolves anything.
    if [ ! -e "$saved_resolv" ] && [ ! -L "$saved_resolv" ]; then
        mkdir -p /var/backups
        cp -aP /etc/resolv.conf "$saved_resolv" 2>/dev/null || true
    fi

    # Short names keep resolving the way they did.
    search=$(sed -n 's/^[[:space:]]*\(search\|domain\)[[:space:]]/\1 /p' \
        /etc/resolv.conf 2>/dev/null || true)

    rm -f /etc/resolv.conf
    {
        echo "# Written by the elodin package. The original is at $saved_resolv"
        echo "# and is put back when the package is removed."
        echo "nameserver 127.0.0.1"
        # An `A && B` here would be the last word of a `set -e` script on a
        # machine whose resolv.conf names no search domain, and would abort the
        # install halfway through writing this file.
        if [ -n "$search" ]; then
            echo "$search"
        fi
        # elodin validates DNSSEC itself and sets AD, so the resolver library
        # is allowed to believe that bit from 127.0.0.1.
        echo "options edns0 trust-ad"
    } > /etc/resolv.conf

    systemctl enable elodin.service >/dev/null 2>&1 || true
fi

# Hand the terminal back before starting a daemon that takes a few seconds to
# load its lists.
db_stop

if [ "$takeover" = true ]; then
    systemctl restart elodin.service || true

    # The unit is Type=simple, so the restart above returned the moment exec
    # succeeded and says nothing about whether elodin stayed up. Anything it
    # only discovers at startup — a port it cannot have, a certificate it
    # cannot read — shows up as an exit and a restart within a couple of
    # seconds, and Restart=on-failure would otherwise leave that looping
    # quietly behind a successful-looking install.
    restarts_before=$(systemctl show elodin.service -p NRestarts --value 2>/dev/null || echo 0)
    started=true
    watched=0
    while [ "$watched" -lt 10 ]; do
        sleep 1
        watched=$((watched + 1))
        state=$(systemctl show elodin.service -p ActiveState --value 2>/dev/null || echo failed)
        restarts=$(systemctl show elodin.service -p NRestarts --value 2>/dev/null || echo 0)
        if [ "$state" = failed ] || [ "$restarts" != "$restarts_before" ]; then
            started=false
            break
        fi
    done

    if [ "$started" != true ]; then
        # A machine pointed at a resolver that never came up has no DNS at
        # all, which is worse than a failed installation, so the takeover is
        # undone before failing. These are the same steps as postrm and cannot
        # be shared with it: postrm runs after this package's files are gone,
        # so there is nowhere to put a helper that both could call.
        if [ -e "$saved_resolv" ] || [ -L "$saved_resolv" ]; then
            rm -f /etc/resolv.conf
            cp -aP "$saved_resolv" /etc/resolv.conf
            rm -f "$saved_resolv"
        fi
        if [ -e "$resolved_marker" ]; then
            systemctl unmask systemd-resolved.service >/dev/null 2>&1 || true
            systemctl enable --now systemd-resolved.service >/dev/null 2>&1 || true
            rm -f "$resolved_marker"
        fi
        # --now, or the restart loop that just failed the install carries on
        # in the background.
        systemctl disable --now elodin.service >/dev/null 2>&1 || true
        systemctl reset-failed elodin.service >/dev/null 2>&1 || true

        echo "elodin did not start, so the previous resolver has been put back." >&2
        echo "What went wrong is in: journalctl -u elodin" >&2
        exit 1
    fi
elif [ -d /run/systemd/system ] && systemctl is-active elodin.service >/dev/null 2>&1; then
    # Not ours to start, but it is running and the binary underneath it has
    # just been replaced.
    systemctl restart elodin.service
elif [ -z "${2:-}" ]; then
    cat <<'MSG'
elodin is installed but not running. Review /etc/elodin/elodin.yaml, then:

  sudo systemctl disable --now systemd-resolved   # if it holds port 53
  sudo systemctl enable --now elodin
MSG
fi
EOF

cat > "$stage/DEBIAN/prerm" <<'EOF'
#!/bin/sh
set -e

# Only on the way out. An upgrade passes "upgrade" here, and stopping there
# would leave the resolver down for the length of the unpack.
if [ "$1" = remove ] && [ -d /run/systemd/system ]; then
    systemctl stop elodin.service >/dev/null 2>&1 || true
fi
EOF

cat > "$stage/DEBIAN/postrm" <<'EOF'
#!/bin/sh
set -e

saved_resolv=/var/backups/elodin-resolv.conf
resolved_marker=/var/backups/elodin-resolved-disabled

if [ -d /run/systemd/system ]; then
    systemctl daemon-reload >/dev/null 2>&1 || true
fi

# The machine has just lost its resolver, so this runs on the way out under
# either verb rather than only on purge: `apt remove` leaves a box that cannot
# resolve anything otherwise. Both halves are guarded by the marker the
# takeover left, so a machine whose resolved was already off stays that way,
# and running twice changes nothing the second time.
if [ "$1" = remove ] || [ "$1" = purge ]; then
    if [ -e "$saved_resolv" ] || [ -L "$saved_resolv" ]; then
        rm -f /etc/resolv.conf
        cp -aP "$saved_resolv" /etc/resolv.conf
        rm -f "$saved_resolv"
    fi

    if [ -e "$resolved_marker" ]; then
        if [ -d /run/systemd/system ]; then
            systemctl unmask systemd-resolved.service >/dev/null 2>&1 || true
            systemctl enable --now systemd-resolved.service >/dev/null 2>&1 || true
        fi
        rm -f "$resolved_marker"
    fi
fi

if [ "$1" = purge ]; then
    # The unit is gone by now, so `systemctl disable` has nothing to read and
    # would leave the enablement symlink behind.
    rm -f /etc/systemd/system/multi-user.target.wants/elodin.service

    # Blocklists and cached state. Under DynamicUser=yes systemd keeps these
    # in /var/{cache,lib}/private and leaves a symlink at the plain path, so
    # both have to go.
    rm -rf /var/cache/elodin /var/cache/private/elodin \
           /var/lib/elodin /var/lib/private/elodin

    # Anything the administrator added next to the configuration — a local
    # blocklist, a certificate — is theirs, so this only removes the directory
    # if dpkg's own removal of the conffile already emptied it.
    rmdir /etc/elodin 2>/dev/null || true

    if [ -e /usr/share/debconf/confmodule ]; then
        . /usr/share/debconf/confmodule
        db_purge
    fi
fi
EOF

chmod 755 "$stage/DEBIAN/config" "$stage/DEBIAN/postinst" "$stage/DEBIAN/prerm" "$stage/DEBIAN/postrm"
chmod 644 "$stage/DEBIAN/templates"

(cd "$stage" && find . -path ./DEBIAN -prune -o -type f -print0 \
    | xargs -0 md5sum | sed 's|  \./|  |' > DEBIAN/md5sums)

mkdir -p "$out_dir"
deb="$out_dir/elodin_${version}-${revision}_${arch}.deb"

# --root-owner-group makes every path root:root without needing fakeroot,
# which is the only reason a build like this would otherwise want it.
dpkg-deb --root-owner-group --build "$stage" "$deb" >/dev/null

echo "$deb"
