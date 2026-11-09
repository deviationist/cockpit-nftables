#!/bin/sh
# End-to-end test of src/helper/nft_helper.py in a private network namespace:
# its nftables ruleset starts empty and is thrown away afterwards, so the
# host firewall is never touched. Run: sudo unshare --net sh test/helper-netns.sh
set -eu
HELPER="$(cd "$(dirname "$0")/.." && pwd)/src/helper/nft_helper.py"
R=$(mktemp -d /tmp/cnft-test.XXXXXX)
export CNFT_ROOT="$R" CNFT_NO_TIMER=1
trap 'rm -rf "$R"' EXIT
h() { python3 -I "$HELPER" "$@"; }
j() { python3 -c "import json,sys; d=json.load(sys.stdin); print($1)"; }
fail() { echo "FAIL: $*"; exit 1; }
pass() { echo "ok   $*"; }

mkdir -p "$R/etc"
cat > "$R/etc/nftables.conf" <<'NFT'
table inet t1
delete table inet t1
table inet t1 {
    chain input {
        type filter hook input priority filter; policy accept;
        tcp dport 22 accept comment "ssh"
    }
}
NFT
nft -f "$R/etc/nftables.conf"
# a "foreign" table, like Docker's, that the helper must never touch
nft add table ip foreign; nft add chain ip foreign c; nft add rule ip foreign c counter accept

SHA=$(h read | j 'd["conf"]["sha256"]')
[ "$(h read | j 'd["apply_enabled"]')" = "False" ] || fail "apply should start disabled"
pass "read: apply disabled by default"

body() { python3 -c "import json,sys; print(json.dumps({'text': open(sys.argv[1]).read(), 'base_sha256': sys.argv[2], 'timeout': 60, 'added_tables': [['inet','t2']]}))" "$1" "$2"; }

sed 's/policy accept/policy drop/' "$R/etc/nftables.conf" > "$R/new.conf"
printf 'table inet t2\ndelete table inet t2\ntable inet t2 {\n    chain c { }\n}\n' >> "$R/new.conf"
[ "$(body "$R/new.conf" "$SHA" | h apply | j 'd["ok"]')" = "False" ] || fail "apply must refuse while disabled"
pass "apply refused while disabled"

mkdir -p "$R/etc/cockpit-nftables"; touch "$R/etc/cockpit-nftables/apply-enabled"
[ "$(printf '{"text":"table inet x { chain c { nonsense } }"}' | h check | j 'd["ok"]')" = "False" ] || fail "check accepted garbage"
pass "check rejects invalid config"
[ "$(body "$R/new.conf" "$SHA" | python3 -c "import json,sys; d=json.load(sys.stdin); print(json.dumps({'text': d['text']}))" | h check | j 'd["ok"]')" = "True" ] || fail "check rejected valid config"
pass "check accepts valid config"

[ "$(body "$R/new.conf" "deadbeef" | h apply | j 'd["ok"]')" = "False" ] || fail "apply ignored stale base sha"
pass "apply refuses a stale base (file changed on disk)"

out=$(body "$R/new.conf" "$SHA" | h apply); [ "$(echo "$out" | j 'd["ok"]')" = "True" ] || fail "apply: $out"
nft list chain inet t1 input | grep -q "policy drop" || fail "new policy not live"
nft list table inet t2 >/dev/null || fail "t2 not created"
cmp -s "$R/new.conf" "$R/etc/nftables.conf" || fail "file not written"
[ "$(ls "$R/var/lib/cockpit-nftables/backups" | wc -l)" = 1 ] || fail "no backup"
pass "apply: file written, backup kept, ruleset live"

[ "$(body "$R/new.conf" "$(h read | j 'd["conf"]["sha256"]')" | h apply | j 'd["ok"]')" = "False" ] || fail "second apply while pending"
pass "apply refused while previous apply is pending"

[ "$(h revert | j 'd["ok"]')" = "True" ] || fail "revert"
nft list chain inet t1 input | grep -q "policy accept" || fail "old policy not restored"
nft list table inet t2 >/dev/null 2>&1 && fail "added table t2 not removed"
[ "$(h read | j 'd["conf"]["sha256"]')" = "$SHA" ] || fail "file not restored"
nft list chain ip foreign c | grep -q "counter" || fail "foreign table touched"
[ "$(h read | j 'd["pending"]')" = "None" ] || fail "pending not cleared"
pass "revert: file + ruleset restored, added table removed, foreign table untouched"

out=$(body "$R/new.conf" "$SHA" | h apply); [ "$(echo "$out" | j 'd["ok"]')" = "True" ] || fail "re-apply: $out"
[ "$(h confirm | j 'd["ok"]')" = "True" ] || fail "confirm"
[ "$(h read | j 'd["pending"]')" = "None" ] || fail "pending after confirm"
nft list chain inet t1 input | grep -q "policy drop" || fail "confirmed config not live"
[ "$(h revert | j 'd["ok"]')" = "False" ] || fail "revert after confirm should be a no-op"
pass "confirm: change kept, nothing left to revert"

echo "ALL PASSED"
