#!/usr/bin/env bash
#
# Package a release binary as <name>.tar.gz, in the current directory: the
# binary, the systemd unit, the example configuration, the README, the docs and
# the licence, under a directory of the same name.
#
#   packaging/build-tarball.sh <name> <binary>
#
# Both release tarballs, the dynamic and the static one, are made here, so they
# carry the same files.

set -euo pipefail

[ $# -eq 2 ] || { echo "usage: packaging/build-tarball.sh <name> <binary>" >&2; exit 2; }
name=$1 binary=$2
root=$(cd "$(dirname "$0")/.." && pwd)

mkdir "$name"
cp "$binary" "$name"/
cp "$root/packaging/elodin.service" "$name"/
cp "$root/examples/elodin.yaml" "$name"/
cp "$root/README.md" "$name"/
cp -r "$root/docs" "$name"/
cp "$root/LICENSE" "$name"/
tar -czf "$name.tar.gz" "$name"
