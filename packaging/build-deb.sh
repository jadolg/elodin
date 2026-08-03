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
Depends: libc6, zlib1g, libssl3t64 | libssl3
Installed-Size: $installed_size
Description: Filtering DNS forwarder
 elodin serves plain DNS, DNS-over-TLS and DNS-over-HTTPS, forwards to
 upstreams over any of those, filters against blocklists in hosts, plain-domain
 and adblock syntax, caches answers, and validates DNSSEC against the root
 trust anchors. One binary and one YAML file, with no web interface.
 .
 The package installs a systemd unit but does not enable or start it: elodin
 wants port 53, which on a Debian or Ubuntu machine usually belongs to
 systemd-resolved.
EOF

cat > "$stage/DEBIAN/postinst" <<'EOF'
#!/bin/sh
set -e

if [ "$1" = configure ]; then
    [ -d /run/systemd/system ] && systemctl daemon-reload >/dev/null 2>&1 || true

    # Nothing is enabled or started here. elodin binds port 53, and on the
    # distributions this package targets that port is systemd-resolved's:
    # starting the unit would fail the installation over a conflict only the
    # administrator can settle, and leave a failed unit behind.
    if [ -z "${2:-}" ]; then
        cat <<'MSG'
elodin is installed but not running. Review /etc/elodin/elodin.yaml, then:

  sudo systemctl disable --now systemd-resolved   # if it holds port 53
  sudo systemctl enable --now elodin
MSG
    fi
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

if [ -d /run/systemd/system ]; then
    systemctl daemon-reload >/dev/null 2>&1 || true
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
fi
EOF

chmod 755 "$stage/DEBIAN/postinst" "$stage/DEBIAN/prerm" "$stage/DEBIAN/postrm"

(cd "$stage" && find . -path ./DEBIAN -prune -o -type f -print0 \
    | xargs -0 md5sum | sed 's|  \./|  |' > DEBIAN/md5sums)

mkdir -p "$out_dir"
deb="$out_dir/elodin_${version}-${revision}_${arch}.deb"

# --root-owner-group makes every path root:root without needing fakeroot,
# which is the only reason a build like this would otherwise want it.
dpkg-deb --root-owner-group --build "$stage" "$deb" >/dev/null

echo "$deb"
