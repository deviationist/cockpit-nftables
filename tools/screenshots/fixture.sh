#!/bin/sh
# SPDX-License-Identifier: LGPL-2.1-or-later
#
# Build the demo "read" snapshot the screenshots render, from test/demo/:
# the demo nftables.conf and Docker/Tailscale-style iptables rules are loaded
# by the real nft / iptables-restore inside a throwaway network namespace (its
# own empty ruleset; the host firewall is never touched), the helper reads it
# back, and the demo sockets / interfaces / route are filled in.
#
#   sudo sh tools/screenshots/fixture.sh preview-dist/fixture.json
set -eu

OUT=${1:?usage: fixture.sh OUT.json}
[ "$(id -u)" = 0 ] || { echo "needs root (network namespace): sudo sh $0 $OUT" >&2; exit 1; }

HERE=$(cd "$(dirname "$0")" && pwd)
REPO=$(cd "$HERE/../.." && pwd)
DEMO="$REPO/test/demo"
HELPER="$REPO/src/helper/nft_helper.py"
ROOT=$(mktemp -d /tmp/cnft-demo.XXXXXX)
trap 'rm -rf "$ROOT"' EXIT

mkdir -p "$ROOT/etc/cockpit-nftables"
cp "$DEMO/nftables.conf" "$ROOT/etc/nftables.conf"
touch "$ROOT/etc/cockpit-nftables/apply-enabled"

unshare --net sh -c "
    set -e
    iptables-restore < '$DEMO/iptables.rules'
    nft -f '$ROOT/etc/nftables.conf'
    CNFT_ROOT='$ROOT' python3 -I '$HELPER' read
" > "$ROOT/read.json"

python3 -I "$HERE/patch-fixture.py" "$ROOT/read.json" "$DEMO" "$OUT"

# hand the file to the invoking user
[ -n "${SUDO_UID:-}" ] && chown "$SUDO_UID:${SUDO_GID:-$SUDO_UID}" "$OUT"
echo "wrote $OUT"
