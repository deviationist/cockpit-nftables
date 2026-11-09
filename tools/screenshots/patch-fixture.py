# SPDX-License-Identifier: LGPL-2.1-or-later
"""Fill the demo sockets, interfaces and route into a helper `read` result.

A fresh network namespace has no interfaces or listening services, so those
come from test/demo/ instead; paths are shown as on a real host.

    python3 patch-fixture.py READ.json DEMO_DIR OUT.json
"""
import json
import sys

read_json, demo, out = sys.argv[1:4]
r = json.load(open(read_json))
if not r.get("ruleset_ok"):
    sys.exit("nft list ruleset failed in the demo namespace: %s" % r.get("ruleset_stderr"))
r["ss"] = open(demo + "/ss.txt").read()
r["addrs"] = json.dumps(json.load(open(demo + "/addrs.json")))
r["routes"] = json.dumps(json.load(open(demo + "/route.json")))
r["conf"]["path"] = "/etc/nftables.conf"
r["apply_enabled_flag"] = "/etc/cockpit-nftables/apply-enabled"
r["backup_dir"] = "/var/lib/cockpit-nftables/backups"
r["pending"] = None
with open(out, "w") as f:
    json.dump(r, f)
