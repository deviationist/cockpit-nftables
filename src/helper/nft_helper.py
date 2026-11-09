# SPDX-License-Identifier: LGPL-2.1-or-later
#
# Privileged helper for cockpit-nftables. Runs as root via
#   cockpit.spawn(["python3", "-I", "-c", <this file>, <cmd>], {superuser: "require"})
# (the source is bundled into the page as text, so there is no helper file on
# disk that the browser side could point elsewhere).
#
# Design rules (see AGENTS.md):
#   - The config FILE is the source of truth. We never write a kernel dump back
#     to it, and we never run `flush ruleset`.
#   - Apply = back up the file, write the new one, `nft -f` it. Undo = put the
#     backup back and `nft -f` it again, plus delete tables the new file added.
#     That only ever touches tables the file declares, so it works on hosts
#     where Docker/Tailscale own iptables-nft tables nft can't re-parse.
#   - Every apply arms a systemd timer that undoes it unless confirmed.
#
# Commands (one JSON object on stdout):
#   read                      -> config file + live ruleset text + pending state
#   check    <stdin {text}>   -> nft -c result for a candidate config
#   apply    <stdin {text, base_sha256, timeout, added_tables}>
#   confirm                   -> keep the applied config, disarm the timer
#   revert                    -> undo now

import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time

# CNFT_ROOT prefixes every path (tests run against a scratch tree in a private
# network namespace). The UI never sets it.
ROOT = os.environ.get("CNFT_ROOT", "")
CONF = ROOT + "/etc/nftables.conf"
SETTINGS_DIR = ROOT + "/etc/cockpit-nftables"
APPLY_ENABLED_FLAG = os.path.join(SETTINGS_DIR, "apply-enabled")
STATE_DIR = ROOT + "/var/lib/cockpit-nftables"
BACKUP_DIR = os.path.join(STATE_DIR, "backups")
RUN_DIR = ROOT + "/run/cockpit-nftables"
PENDING = os.path.join(RUN_DIR, "pending.json")
REVERT_SCRIPT = os.path.join(RUN_DIR, "revert.sh")
UNIT = os.environ.get("CNFT_UNIT", "cockpit-nftables-revert")
# Tests only: the network namespace the sandbox lives in. The undo script must
# run there, but systemd starts it in the host namespace, so it re-enters the
# sandbox itself and refuses to run if it can't.
NETNS = os.environ.get("CNFT_NETNS", "")
NO_TIMER = os.environ.get("CNFT_NO_TIMER") == "1"  # tests only
MAX_TIMEOUT = 600


def out(obj):
    sys.stdout.write(json.dumps(obj))
    sys.stdout.flush()


def stdin_json():
    data = sys.stdin.read()
    return json.loads(data) if data.strip() else {}


def sha256_bytes(b):
    return hashlib.sha256(b).hexdigest()


def read_conf():
    try:
        with open(CONF, "rb") as f:
            raw = f.read()
        st = os.stat(CONF)
        return {"path": CONF, "exists": True, "text": raw.decode("utf-8", "replace"),
                "sha256": sha256_bytes(raw), "mtime": int(st.st_mtime)}
    except FileNotFoundError:
        return {"path": CONF, "exists": False, "text": "", "sha256": sha256_bytes(b""), "mtime": 0}


def nft(args, stdin=None):
    r = subprocess.run(["nft"] + args, input=stdin, capture_output=True, text=True)
    return r.returncode, r.stdout, r.stderr


def read_pending():
    try:
        with open(PENDING) as f:
            p = json.load(f)
    except (FileNotFoundError, ValueError):
        return None
    p["seconds_left"] = max(0, int(p.get("deadline", 0)) - int(time.time()))
    if not NO_TIMER:
        r = subprocess.run(["systemctl", "is-active", UNIT + ".timer"], capture_output=True, text=True)
        p["timer_active"] = r.stdout.strip() == "active"
    return p


def cmd_read():
    # Text (with handles) is the display form; JSON is the structure.
    rc, ruleset, err = nft(["-a", "list", "ruleset"])
    jrc, rjson, _jerr = nft(["-j", "list", "ruleset"])
    # Zone Matrix inputs (read-only): listening sockets, interfaces, default route
    ss = subprocess.run(["ss", "-Hlntup"], capture_output=True, text=True).stdout
    addrs = subprocess.run(["ip", "-j", "-d", "-4", "addr"], capture_output=True, text=True).stdout
    routes = subprocess.run(["ip", "-j", "-4", "route", "show", "default"], capture_output=True, text=True).stdout
    out({
        "conf": read_conf(),
        "ruleset": ruleset if rc == 0 else "",
        "ruleset_json": rjson if jrc == 0 else "",
        "ss": ss,
        "addrs": addrs or "[]",
        "routes": routes or "[]",
        "ruleset_stderr": err,
        "ruleset_ok": rc == 0,
        "apply_enabled": os.path.exists(APPLY_ENABLED_FLAG),
        "apply_enabled_flag": APPLY_ENABLED_FLAG,
        "pending": read_pending(),
        "backup_dir": BACKUP_DIR,
    })


def check_text(text):
    """nft -c on the candidate. Runs in a private dir so includes relative to
    the real config's directory still resolve (we pass -I <confdir>)."""
    os.makedirs(RUN_DIR, mode=0o700, exist_ok=True)
    fd, path = tempfile.mkstemp(prefix="candidate-", suffix=".nft", dir=RUN_DIR)
    try:
        with os.fdopen(fd, "w") as f:
            f.write(text)
        rc, _o, err = nft(["-c", "-I", os.path.dirname(CONF) or "/", "-f", path])
        # Point error locations at the editor's line numbers, not the temp name.
        return rc == 0, err.replace(path, "nftables.conf").strip()
    finally:
        os.unlink(path)


def cmd_check():
    body = stdin_json()
    ok, err = check_text(body.get("text", ""))
    out({"ok": ok, "error": err or None})


def write_atomic(path, text, like):
    """Write text to path atomically, keeping the mode/owner of `like`."""
    d = os.path.dirname(path) or "/"
    fd, tmp = tempfile.mkstemp(prefix=".cnft-", dir=d)
    with os.fdopen(fd, "w") as f:
        f.write(text)
        f.flush()
        os.fsync(f.fileno())
    if like and os.path.exists(like):
        st = os.stat(like)
        os.chmod(tmp, st.st_mode & 0o7777)
        os.chown(tmp, st.st_uid, st.st_gid)
    else:
        os.chmod(tmp, 0o644)
    os.replace(tmp, path)


def shq(s):
    return "'" + s.replace("'", "'\"'\"'") + "'"


def write_revert_script(backup, added_tables):
    """A standalone undo that the timer can run with nothing but sh + nft:
    restore the previous file, reload it, drop tables the new file added."""
    lines = [
        "#!/bin/sh",
        "# Written by cockpit-nftables apply; runs on timeout or 'Revert now'.",
        "set -u",
    ]
    if NETNS:
        ns = shq(NETNS)
        lines += [
            "# test sandbox: only ever act inside the sandbox network namespace",
            "want=$(stat -L -c %%i %s) || exit 3" % ns,
            "if [ \"$(stat -L -c %i /proc/self/ns/net)\" != \"$want\" ]; then",
            "    [ -z \"${CNFT_IN_NS:-}\" ] || exit 3",
            "    CNFT_IN_NS=1 exec nsenter --net=%s /bin/sh \"$0\"" % ns,
            "fi",
            "[ \"$(stat -L -c %i /proc/self/ns/net)\" = \"$want\" ] || exit 3",
        ]
    lines += [
        "cp -p %s %s || exit 1" % (shq(backup), shq(CONF)),
        "nft -f %s" % shq(CONF),
        "rc=$?",
    ]
    for fam, name in added_tables:
        lines.append("nft delete table %s %s 2>/dev/null" % (shq(fam), shq(name)))
    lines += [
        "rm -f %s" % shq(PENDING),
        "logger -t cockpit-nftables \"reverted to %s (nft rc=$rc)\"" % backup.replace('"', ""),
        "exit $rc",
    ]
    with open(REVERT_SCRIPT, "w") as f:
        f.write("\n".join(lines) + "\n")
    os.chmod(REVERT_SCRIPT, 0o700)


def disarm():
    if NO_TIMER:
        return
    for unit in (UNIT + ".timer", UNIT + ".service"):
        subprocess.run(["systemctl", "stop", unit], capture_output=True)
        subprocess.run(["systemctl", "reset-failed", unit], capture_output=True)


def cmd_apply():
    body = stdin_json()
    if not os.path.exists(APPLY_ENABLED_FLAG):
        out({"ok": False, "error": "Applying is disabled on this host. Create %s to enable it." % APPLY_ENABLED_FLAG})
        return
    if read_pending():
        out({"ok": False, "error": "A previous apply is still waiting for confirmation. Confirm or revert it first."})
        return
    text = body.get("text", "")
    timeout = max(15, min(int(body.get("timeout", 60)), MAX_TIMEOUT))
    added = [(t[0], t[1]) for t in body.get("added_tables", []) if len(t) == 2]

    cur = read_conf()
    if cur["sha256"] != body.get("base_sha256"):
        out({"ok": False, "error": "%s changed on disk since you loaded it. Reload and re-apply." % CONF})
        return
    ok, err = check_text(text)
    if not ok:
        out({"ok": False, "error": err or "nft -c rejected the config"})
        return

    os.makedirs(BACKUP_DIR, mode=0o700, exist_ok=True)
    os.makedirs(RUN_DIR, mode=0o700, exist_ok=True)
    backup = os.path.join(BACKUP_DIR, "nftables.conf.%s" % time.strftime("%Y%m%d-%H%M%S"))
    if cur["exists"]:
        shutil.copy2(CONF, backup)
    else:
        open(backup, "w").close()
    write_revert_script(backup, added)

    write_atomic(CONF, text, CONF if cur["exists"] else None)
    rc, _o, err = nft(["-f", CONF])
    if rc != 0:
        # nft -f is one transaction: nothing was applied. Put the file back.
        shutil.copy2(backup, CONF)
        out({"ok": False, "error": "nft -f failed, nothing applied, file restored: " + err.strip()})
        return

    deadline = int(time.time()) + timeout
    with open(PENDING, "w") as f:
        json.dump({"deadline": deadline, "timeout": timeout, "backup": backup,
                   "added_tables": added, "applied_at": int(time.time())}, f)
    if not NO_TIMER:
        disarm()
        r = subprocess.run(["systemd-run", "--unit=" + UNIT, "--on-active=%ds" % timeout,
                            "--timer-property=AccuracySec=1s", "/bin/sh", REVERT_SCRIPT],
                           capture_output=True, text=True)
        if r.returncode != 0:
            # No safety net: undo immediately rather than leave it unguarded.
            subprocess.run(["/bin/sh", REVERT_SCRIPT], capture_output=True)
            out({"ok": False, "error": "could not arm the undo timer, reverted: " + r.stderr.strip()})
            return
    out({"ok": True, "deadline": deadline, "timeout": timeout, "backup": backup})


def cmd_confirm():
    disarm()
    try:
        os.remove(PENDING)
    except FileNotFoundError:
        pass
    out({"ok": True})


def cmd_revert():
    if not os.path.exists(REVERT_SCRIPT) or not read_pending():
        out({"ok": False, "error": "nothing to revert"})
        return
    disarm()
    r = subprocess.run(["/bin/sh", REVERT_SCRIPT], capture_output=True, text=True)
    out({"ok": r.returncode == 0, "error": (r.stderr.strip() or None) if r.returncode else None})


COMMANDS = {"read": cmd_read, "check": cmd_check, "apply": cmd_apply,
            "confirm": cmd_confirm, "revert": cmd_revert}

if __name__ == "__main__":
    if len(sys.argv) < 2 or sys.argv[1] not in COMMANDS:
        out({"ok": False, "error": "usage: nft_helper <%s>" % "|".join(COMMANDS)})
        sys.exit(2)
    if NETNS:
        # test sandbox: never act outside the sandbox network namespace
        try:
            inside = os.stat("/proc/self/ns/net").st_ino == os.stat(NETNS).st_ino
        except OSError:
            inside = False
        if not inside:
            out({"ok": False, "error": "refusing: not inside sandbox netns %s" % NETNS})
            sys.exit(3)
    try:
        COMMANDS[sys.argv[1]]()
    except Exception as e:  # always answer with JSON
        out({"ok": False, "error": "%s: %s" % (type(e).__name__, e)})
