#!/usr/bin/env bash
#
# Build the container image for this machine's architecture (see
# packaging/Dockerfile): elodin linked against musl and the system OpenSSL as
# shared libraries, in an image that holds those files, the CA bundle and the
# default configuration (examples/docker.yaml) and nothing else.
#
#   scripts/build-image.sh [--itest]
#
# Tags the image $ELODIN_IMAGE (default elodin:dev). --itest also builds
# $ELODIN_IMAGE-itest, the integration suite linked the same way beside the same
# binary and libraries, which `mise run itest-image` runs. Needs the mise
# toolchain and docker.
#
# Odin compiles on the host into objects, as in scripts/build-static.sh, and the
# Dockerfile links them in Alpine. One architecture per run, the host's: each CI
# runner builds its own, and the release joins them under one tag.

set -euo pipefail
cd "$(dirname "$0")/.."

itest=0
while [ $# -gt 0 ]; do
	case "$1" in
	--itest) itest=1 ;;
	*) echo "build-image: unknown argument $1" >&2; exit 2 ;;
	esac
	shift
done

: "${ELODIN_DEFINES:?run through mise, which sets ELODIN_DEFINES}"
: "${ELODIN_ALPINE:?run through mise, which sets ELODIN_ALPINE}"
: "${ELODIN_VERSION:?run through mise, which sets ELODIN_VERSION}"
image=${ELODIN_IMAGE:-elodin:dev}
command -v docker >/dev/null || { echo "build-image: needs docker" >&2; exit 1; }
[ -f bin/elodin_switch.o ] || { echo "build-image: bin/elodin_switch.o is missing; run mise run prepare" >&2; exit 1; }

case $(uname -m) in
x86_64) arch=amd64 ;;
aarch64) arch=arm64 ;;
*) echo "build-image: no image for $(uname -m)" >&2; exit 1 ;;
esac

# The build context: only what the Dockerfile copies, so nothing else in the
# checkout reaches the build or its cache key. obj/itest exists either way, for
# the COPY that takes all of obj/.
ctx=bin/image
rm -rf "$ctx"
mkdir -p "$ctx/obj/elodin" "$ctx/obj/itest"
cp bin/elodin_switch.o "$ctx/obj/"
cp examples/docker.yaml "$ctx/elodin.yaml"

# shellcheck disable=SC2086 # ELODIN_DEFINES is a list of flags
odin build src/main -collection:elodin=src -o:speed -build-mode:obj \
	$ELODIN_DEFINES -out:"$ctx/obj/elodin/elodin.o"
if [ "$itest" = 1 ]; then
	# shellcheck disable=SC2086
	odin build src/itest -collection:elodin=src -build-mode:obj \
		$ELODIN_DEFINES -out:"$ctx/obj/itest/itest.o"
fi

build() {
	docker build -f packaging/Dockerfile \
		--build-arg ALPINE="$ELODIN_ALPINE" \
		--build-arg VERSION="$ELODIN_VERSION" \
		--build-arg REVISION="$(git rev-parse HEAD 2>/dev/null || echo unknown)" \
		"$@" "$ctx"
}
build --target image -t "$image"
if [ "$itest" = 1 ]; then
	build --target itest -t "$image-itest"
fi

# The image's whole filesystem, as a tar, so what it holds is checked against
# the list below rather than assumed: a shell, a package database or a stray
# library the Dockerfile picked up would fail here. The build is cached, so this
# costs the export alone.
build --target image -q --output "type=tar,dest=$ctx/rootfs.tar" >/dev/null
allowed='^(etc/|etc/passwd|etc/group|etc/ssl/|etc/ssl/cert\.pem|etc/elodin/|etc/elodin/elodin\.yaml|lib/|lib/ld-musl-[a-z0-9_]+\.so\.1|usr/|usr/bin/|usr/bin/elodin|usr/lib/|usr/lib/libssl\.so\.[0-9]+|usr/lib/libcrypto\.so\.[0-9]+|var/|var/cache/|var/cache/elodin/)$'
unexpected=$(tar -tf "$ctx/rootfs.tar" | sed 's#^\./##; /^$/d' | grep -Ev "$allowed" || true)
if [ -n "$unexpected" ]; then
	echo "build-image: the image holds files it should not:" >&2
	echo "$unexpected" >&2
	exit 1
fi
# The cache directory has to be the account's, or a blocklist refresh cannot
# write it; COPY gives files to root unless told otherwise.
owner=$(tar -tvf "$ctx/rootfs.tar" --numeric-owner | awk '$NF ~ /^(\.\/)?var\/cache\/elodin\/$/ { print $2 }')
[ "$owner" = 65532/65532 ] || { echo "build-image: var/cache/elodin is owned by ${owner:-nobody}, want 65532/65532" >&2; exit 1; }

# The architecture the image says it is, and the binary in it starting with
# nothing but what the image carries.
got=$(docker image inspect -f '{{.Architecture}}' "$image")
[ "$got" = "$arch" ] || { echo "build-image: $image is $got, want $arch" >&2; exit 1; }
docker run --rm "$image" --version
docker run --rm "$image" --check >/dev/null
echo "build-image: $image ($arch, $(docker image inspect -f '{{.Size}}' "$image" | awk '{ printf "%.1f MB", $1 / 1e6 }'))"
