#!/bin/sh
# SPDX-License-Identifier: LGPL-2.1-or-later
#
# Full apply / auto-undo / revert / confirm cycle against a SANDBOX COPY of
# this host's firewall, including the real systemd undo timer.
#
#   sudo sh test/sandbox-copy.sh
#
# Safety model:
#   - Every nft/iptables WRITE runs via `sb` = `ip netns exec cnft-sandbox`, a
#     throwaway network namespace with its own empty ruleset.
#   - On the host this script only READS (nft -s list, iptables-save, sha256sum)
#     and creates/deletes the named netns + a transient test timer unit.
#   - The helper runs with CNFT_ROOT (scratch copy of /etc/nftables.conf) and
#     CNFT_NETNS (refuses to run outside the sandbox; its undo script re-enters
#     the sandbox or aborts).
#   - Host state is fingerprinted before and compared after.
set -u

NS=cnft-sandbox
NSFILE=/run/netns/$NS
UNIT=cnft-sandbox-revert
HELPER="$(cd "$(dirname "$0")/.." && pwd)/src/helper/nft_helper.py"
R=$(mktemp -d /tmp/cnft-sandbox.XXXXXX)
FAILED=0

sb() { ip netns exec "$NS" "$@"; }
h() { sb env CNFT_ROOT="$R" CNFT_NETNS="$NSFILE" CNFT_UNIT="$UNIT" python3 -I "$HELPER" "$@"; }
j() { python3 -c "import json,sys; d=json.load(sys.stdin); print($1)"; }
ok() { echo "ok    $*"; }
bad() { echo "FAIL  $*"; FAILED=1; }
host_fp() {
    # stateless (no counters) fingerprint of the host ruleset + config file
    { nft -s list ruleset; sha256sum /etc/nftables.conf; } 2>/dev/null | sha256sum | cut -c1-16
}
ipt_fp() { { iptables-save; ip6tables-save; } | grep -v '^#' | sed 's/\[[0-9]*:[0-9]*\]//' | sha256sum | cut -c1-16; }

cleanup() {
    systemctl stop "$UNIT.timer" "$UNIT.service" >/dev/null 2>&1
    systemctl reset-failed "$UNIT.timer" "$UNIT.service" >/dev/null 2>&1
    ip netns del "$NS" 2>/dev/null
    rm -rf "$R"
}
trap cleanup EXIT

[ "$(id -u)" = 0 ] || { echo "run as root"; exit 1; }
ip netns list | grep -qw "$NS" && { echo "netns $NS already exists, aborting"; exit 1; }

HOST_BEFORE=$(host_fp)
CONF_SHA=$(sha256sum /etc/nftables.conf | cut -c1-16)
echo "host fingerprint before: $HOST_BEFORE  (nftables.conf $CONF_SHA)"

# ---- build the sandbox copy -------------------------------------------------
ip netns add "$NS"
mkdir -p "$R/etc/cockpit-nftables"
cp /etc/nftables.conf "$R/etc/nftables.conf"
touch "$R/etc/cockpit-nftables/apply-enabled"
iptables-save > "$R/ipt4"; ip6tables-save > "$R/ipt6"      # host: read only
sb iptables-restore < "$R/ipt4" || bad "iptables-restore (v4) into sandbox"
sb ip6tables-restore < "$R/ipt6" || bad "ip6tables-restore (v6) into sandbox"
sb nft -f "$R/etc/nftables.conf" || bad "load nftables.conf copy into sandbox"
echo "sandbox tables: $(sb nft list tables | awk '{print $2"/"$3}' | tr '\n' ' ')"
sb_ipt() { sb sh -c '{ iptables-save; ip6tables-save; } | grep -v "^#" | sed "s/\[[0-9]*:[0-9]*\]//" | sha256sum | cut -c1-16'; }
[ "$(sb_ipt)" = "$(ipt_fp)" ] && ok "sandbox has an exact copy of the host's iptables-nft rules (Docker, Tailscale)" \
                            || bad "sandbox iptables copy differs from host"

# ---- guards ----------------------------------------------------------------
[ "$(env CNFT_ROOT="$R" CNFT_NETNS="$NSFILE" python3 -I "$HELPER" read | j 'd.get("ok")')" = "False" ] \
    && ok "helper refuses to run outside the sandbox netns" || bad "helper ran outside the sandbox"

# ---- read / check on the copy ----------------------------------------------
SHA=$(h read | j 'd["conf"]["sha256"]')
[ "$(h read | j 'd["apply_enabled"] and d["ruleset_ok"]')" = "True" ] && ok "read: sandbox copy readable, apply enabled in sandbox" || bad "read"
[ "$(python3 -c "import json;print(json.dumps({'text':open('$R/etc/nftables.conf').read()}))" | h check | j 'd["ok"]')" = "True" ] \
    && ok "check: nft -c accepts the copied config" || bad "check on copy"

# ---- the edit: one extra rule in inet filter + one new table ---------------
python3 - "$R" <<'EOF'
import re, sys
r = sys.argv[1]
t = open(r + "/etc/nftables.conf").read()
# Put the test rule first in the first input base chain the config declares.
m = re.search(r"^([ \t]*)type filter hook input[^\n]*\n", t, re.M)
if not m:
    sys.exit("no 'type filter hook input' chain in the config: nothing to test against")
t = t[:m.end()] + m.group(1) + 'tcp dport 9999 accept comment "SANDBOX TEST"\n' + t[m.end():]
t += "\ntable inet cnft_new\ndelete table inet cnft_new\ntable inet cnft_new {\n    chain c { }\n}\n"
open(r + "/new.conf", "w").write(t)
EOF
body() { python3 -c "import json,sys; print(json.dumps({'text': open(sys.argv[1]).read(), 'base_sha256': sys.argv[2], 'timeout': int(sys.argv[3]), 'added_tables': [['inet','cnft_new']]}))" "$R/new.conf" "$1" "$2"; }
IPT0=$(sb_ipt)

[ "$(body deadbeef 15 | h apply | j 'd["ok"]')" = "False" ] && ok "apply refuses a stale base" || bad "stale base accepted"
printf '{"text":"table inet x { chain c { nonsense } }"}' | h check | grep -q '"ok": false' && ok "check rejects invalid config" || bad "check accepted garbage"

# ---- 1. apply, do NOT confirm: the real systemd timer must undo it ---------
out=$(body "$SHA" 15 | h apply)
[ "$(echo "$out" | j 'd["ok"]')" = "True" ] || bad "apply: $out"
sb nft list ruleset 2>/dev/null | grep -q 'SANDBOX TEST' && ok "apply: new rule live in sandbox" || bad "rule not live"
sb nft list table inet cnft_new >/dev/null 2>&1 && ok "apply: new table live in sandbox" || bad "new table not live"
[ "$(systemctl is-active "$UNIT.timer")" = active ] && ok "undo timer armed ($UNIT.timer)" || bad "timer not armed"
[ "$(sb_ipt)" = "$IPT0" ] && ok "apply left Docker/Tailscale rules untouched" || bad "apply changed iptables-nft rules"
nft list ruleset 2>/dev/null | grep -q 'SANDBOX TEST' && bad "RULE LEAKED TO HOST" || ok "host ruleset does not have the test rule"
echo "      waiting 20 s for the timer…"; sleep 20
sb nft list ruleset 2>/dev/null | grep -q 'SANDBOX TEST' && bad "timer did not remove the rule" || ok "timer undo: rule gone"
sb nft list table inet cnft_new >/dev/null 2>&1 && bad "timer did not delete the new table" || ok "timer undo: new table deleted"
[ "$(h read | j 'd["conf"]["sha256"]')" = "$SHA" ] && ok "timer undo: config file copy restored" || bad "file not restored"
[ "$(h read | j 'd["pending"]')" = "None" ] && ok "timer undo: pending cleared" || bad "pending left"
[ "$(sb_ipt)" = "$IPT0" ] && ok "timer undo left Docker/Tailscale rules untouched" || bad "undo changed iptables-nft rules"

# ---- 2. apply, then Revert now ----------------------------------------------
body "$SHA" 120 | h apply >/dev/null
[ "$(h revert | j 'd["ok"]')" = "True" ] || bad "revert"
sb nft list ruleset 2>/dev/null | grep -q 'SANDBOX TEST' && bad "revert left the rule" || ok "revert now: rule gone"
[ "$(systemctl is-active "$UNIT.timer")" != active ] && ok "revert now: timer disarmed" || bad "timer still armed after revert"

# ---- 3. apply, then confirm --------------------------------------------------
body "$SHA" 120 | h apply >/dev/null
[ "$(h confirm | j 'd["ok"]')" = "True" ] || bad "confirm"
sb nft list ruleset 2>/dev/null | grep -q 'SANDBOX TEST' && ok "confirm: rule kept" || bad "confirm lost the rule"
[ "$(systemctl is-active "$UNIT.timer")" != active ] && ok "confirm: timer disarmed" || bad "timer still armed after confirm"
[ "$(h revert | j 'd["ok"]')" = "False" ] && ok "nothing to revert after confirm" || bad "revert after confirm did something"
[ "$(sb_ipt)" = "$IPT0" ] && ok "Docker/Tailscale rules untouched through all cycles" || bad "iptables-nft rules changed"

# ---- host must be exactly as before ----------------------------------------
cleanup; trap - EXIT
HOST_AFTER=$(host_fp)
[ "$(sha256sum /etc/nftables.conf | cut -c1-16)" = "$CONF_SHA" ] && ok "host /etc/nftables.conf unchanged" || bad "HOST CONFIG CHANGED"
[ "$HOST_AFTER" = "$HOST_BEFORE" ] && ok "host ruleset fingerprint unchanged ($HOST_AFTER)" \
    || echo "NOTE  host ruleset fingerprint changed ($HOST_BEFORE -> $HOST_AFTER): check for Docker/fail2ban activity during the run"
ip netns list | grep -qw "$NS" && bad "sandbox netns left behind" || ok "sandbox removed"

[ "$FAILED" = 0 ] && echo "ALL PASSED" || { echo "SOME CHECKS FAILED"; exit 1; }
