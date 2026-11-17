#!/usr/bin/env bash
#
# Build the container image for this machine's architecture (see
# packaging/Dockerfile): elodin on the distroless Debian base, with the default
# configuration (examples/docker.yaml).
#
#   scripts/build-image.sh [--itest]
#   scripts/build-image.sh --push <repository>
#
# The first form compiles, builds and checks the image, tagged $ELODIN_IMAGE
# (default elodin:dev). --itest also builds $ELODIN_IMAGE-itest, the integration
# suite linked the same way beside the same binary, which `mise run itest-image`
# runs.
#
# --push sends the image the first form built to <repository> by digest, with
# no tag, carrying an SBOM and build provenance, and writes the digest to
# bin/image/digest; the release joins each architecture's digest under its
# tags. It compiles nothing: it builds the same context again, which the
# builder's cache answers, so what is pushed is what was checked and tested.
# The attestations need a builder that can export them (the containerd image
# store, or a docker-container builder such as docker/setup-buildx-action
# makes).
#
# Odin compiles on the host into objects, as in scripts/build-static.sh, and the
# Dockerfile links them in Debian. One architecture per run, the host's: each CI
# runner builds its own.

set -euo pipefail
cd "$(dirname "$0")/.."

itest=0 push=
while [ $# -gt 0 ]; do
	case "$1" in
	--itest) itest=1 ;;
	--push)
		[ $# -ge 2 ] || { echo "build-image: --push needs a repository" >&2; exit 2; }
		push=$2
		shift
		;;
	*) echo "build-image: unknown argument $1" >&2; exit 2 ;;
	esac
	shift
done

: "${ELODIN_DEFINES:?run through mise, which sets ELODIN_DEFINES}"
: "${ELODIN_VERSION:?run through mise, which sets ELODIN_VERSION}"
image=${ELODIN_IMAGE:-elodin:dev}
command -v docker >/dev/null || { echo "build-image: needs docker" >&2; exit 1; }

case $(uname -m) in
x86_64) arch=amd64 ;;
aarch64) arch=arm64 ;;
*) echo "build-image: no image for $(uname -m)" >&2; exit 1 ;;
esac

# The base, as the Dockerfile pins it, for the image's labels.
base=$(sed -nE 's/^FROM ([^ ]+)@(sha256:[0-9a-f]{64}) AS image$/\1 \2/p' packaging/Dockerfile)
[ -n "$base" ] || { echo "build-image: packaging/Dockerfile has no pinned FROM ... AS image" >&2; exit 1; }
base_name=${base% *} base_digest=${base#* }

ctx=bin/image
build() {
	docker buildx build -f packaging/Dockerfile --platform "linux/$arch" \
		--build-arg VERSION="$ELODIN_VERSION" \
		--build-arg REVISION="$(git rev-parse HEAD 2>/dev/null || echo unknown)" \
		--build-arg BASE_NAME="$base_name" \
		--build-arg BASE_DIGEST="$base_digest" \
		"$@" "$ctx"
}

if [ -n "$push" ]; then
	[ -f "$ctx/obj/elodin/elodin.o" ] || { echo "build-image: nothing built to push; run scripts/build-image.sh first" >&2; exit 1; }
	build --target image --sbom=true --provenance=mode=max \
		--output "type=image,name=$push,push-by-digest=true,name-canonical=true,push=true" \
		--metadata-file "$ctx/push.json"
	digest=$(sed -nE 's/.*"containerimage\.digest": *"(sha256:[0-9a-f]{64})".*/\1/p' "$ctx/push.json" | head -1)
	[ -n "$digest" ] || { echo "build-image: the push reported no digest:" >&2; cat "$ctx/push.json" >&2; exit 1; }
	echo "$digest" > "$ctx/digest"
	echo "build-image: pushed $push@$digest ($arch)"
	exit 0
fi

[ -f bin/elodin_switch.o ] || { echo "build-image: bin/elodin_switch.o is missing; run mise run prepare" >&2; exit 1; }

# The build context: only what the Dockerfile copies, so nothing else in the
# checkout reaches the build or its cache key. obj/itest exists either way, for
# the COPY that takes all of obj/; cache/ is the empty cache directory.
rm -rf "$ctx"
mkdir -p "$ctx/obj/elodin" "$ctx/obj/itest" "$ctx/cache"
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

build --target image --load -t "$image"
if [ "$itest" = 1 ]; then
	build --target itest --load -t "$image-itest"
fi

# The image's whole filesystem, as a tar, so what it holds is checked rather
# than assumed. The build is cached, so this costs the export alone.
build --target image -q --output "type=tar,dest=$ctx/rootfs.tar" >/dev/null
listing=$(tar -tvf "$ctx/rootfs.tar" --numeric-owner | sed -E 's#  *\./# #')

# Nothing in it can run but elodin: every program - an ELF file or a `#!`
# script - is elodin or a shared library under usr/lib, which a process has to
# be running already to load. Read from the files themselves, since the base
# marks some data executable (its CA bundle is 0755). The base's update-motd
# script is the one exception, and with no shell there is nothing to run it. A
# shell, busybox or a package manager arriving with a base update fails here,
# before it is published.
runnable=$(python3 -I - "$ctx/rootfs.tar" <<'PY'
import re, sys, tarfile
allowed = re.compile(r"(usr/bin/elodin|etc/update-motd\.d/10-uname|usr/lib(64)?/.*\.so(\.[0-9.]+)?|usr/lib/[^/]+-linux-gnu/.*\.so(\.[0-9.]+)?)")
with tarfile.open(sys.argv[1]) as tar:
    for m in tar:
        if not m.isfile():
            continue
        head = tar.extractfile(m).read(4)
        name = m.name.removeprefix("./")
        if (head == b"\x7fELF" or head[:2] == b"#!") and not allowed.fullmatch(name):
            print(name)
PY
)
if [ -n "$runnable" ]; then
	echo "build-image: the image holds programs other than elodin:" >&2
	echo "$runnable" >&2
	exit 1
fi
for f in usr/bin/elodin etc/elodin/elodin.yaml; do
	grep -qE " $f\$" <<<"$listing" || { echo "build-image: the image has no $f" >&2; exit 1; }
done
# The cache directory has to be the account's, or a blocklist refresh cannot
# write it.
owner=$(awk '$NF ~ /^var\/cache\/elodin\/$/ { print $2 }' <<<"$listing")
[ "$owner" = 65532/65532 ] || { echo "build-image: var/cache/elodin is owned by ${owner:-nobody}, want 65532/65532" >&2; exit 1; }

# The architecture the image says it is, and the binary in it starting with
# what the image carries: the libraries it names resolve, and it reads the
# default configuration.
got=$(docker image inspect -f '{{.Architecture}}' "$image")
[ "$got" = "$arch" ] || { echo "build-image: $image is $got, want $arch" >&2; exit 1; }
docker run --rm "$image" --version
docker run --rm "$image" --check >/dev/null
echo "build-image: $image ($arch, $(gzip -c "$ctx/rootfs.tar" | wc -c | awk '{ printf "%.1f MB compressed", $1 / 1e6 }'), on $base_name@${base_digest:7:12})"
