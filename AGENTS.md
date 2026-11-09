# AGENTS.md

Cockpit plugin (**PoC**) for hand-written nftables: shows the live ruleset from
every program, and edits `/etc/nftables.conf` with validation and an auto-undo.
Menu label: **nftables**. Stack and build follow [cockpit-upside](https://github.com/deviationist/cockpit-upside) (Cockpit starter-kit).

## Decisions (don't relitigate without reason)

- **The config file is the source of truth.** Edits go to the file text
  (comments, `define`s, sets survive). Never write a kernel dump back to the
  file, never `flush ruleset`. Docker / Tailscale / fail2ban tables are
  **view-only**: their iptables-nft (xt) rules can't even be re-parsed by nft.
- **Undo touches only the file's own tables.** Apply = backup → write → `nft -f`.
  Undo (timer or button) = restore backup → `nft -f` → `delete table` for tables
  the new file added. A transient systemd timer (`cockpit-nftables-revert`)
  runs the undo unless confirmed, so it survives a lost browser/session.
  (enforza-cockpit's whole-ruleset restore fails silently on Docker/Tailscale
  hosts; this design exists because of that.)
- **Apply is off by default** per host: needs `/etc/cockpit-nftables/apply-enabled`.
  Read and `nft -c` checks work without it.
- **Reuse before building.** Cockpit `pkg/lib` (ListingTable, dark theme,
  page.scss), PatternFly 6.4 (pinned to Cockpit 362's bundle, like upside),
  `nft -c` for validation, `nft -j` (libnftables-json) for structure, jsdiff for
  diffs. Custom code is only what nothing else does: owner classification,
  file-scoped apply/undo, safety lint.
- **Display = `nft -a list ruleset` text, structure = `nft -j`**, joined by
  rule handle (`overlayJson`). Text is what operators recognise; JSON is the
  authority for hooks, priorities, policies, counters and verdicts.
- **Helper is bundled as text** (`src/helper/nft_helper.py`, esbuild text
  loader) and run as `python3 -I -c <source>` with `superuser: "require"`; no
  helper file on disk decides what runs as root.

- **"Who can reach what" (Zone Matrix, UniFi-style) is the default tab.** Rows =
  listening services (`ss`), columns = source zones derived from interfaces +
  the config's `ip saddr` sets/literals (nftables has no zones). Each cell walks
  ONE representative IPv4 packet through every base chain on prerouting+input,
  all tables, kernel priority order (`src/lib/evaluate.ts`, over `nft -j`).
  Anything unreadable (xt matches that would decide, maps) is "?", never a
  guess. Non-deciding xt targets (CONNMARK, MARK, LOG…) are skipped but taint
  later mark matches; a jump under an unknown condition is followed, and is
  harmless only if the target chain doesn't decide the packet.
  Docker-published ports show "Docker" (decided by DNAT/FORWARD, not input).

- **"Map" tab** (from a Claude Design prototype, recommended variants): Topology
  = zones -> interface "ports" on the host -> services, edges bundled per
  interface until a zone / interface / service is focused; edge -> trace in a
  side panel. Rule graph = hooks left to right, base chains by priority across
  all ip/inet tables, regular chains via jump/goto. "Is this allowed?" lights
  the path up in both. Plain React + SVG with PatternFly controls (no graph
  library: the columns are fixed, so PatternFly Topology's d3/mobx buy nothing).
  Blocked/Docker/unknown edges are dashed (not colour alone); edges are
  keyboard-reachable. Phone width: lists instead of graphs.

- **Screenshots only ever show `test/demo/`**, never a real host: the repo is
  public. `make screenshots` regenerates them; add a scenario in
  `tools/screenshots/shoot.mjs` rather than taking one-off screenshots.

## Testing rule

**Never test against a host's real firewall.** Test against the sandbox copy
only. The helper's test knobs (`CNFT_ROOT`, `CNFT_NETNS`,
`CNFT_UNIT`, `CNFT_NO_TIMER`) are env-only; the UI never sets them. With
`CNFT_NETNS` set the helper refuses to run outside that namespace, and its undo
script re-enters it or aborts.

## Layout

```
src/helper/nft_helper.py   root helper: read / check / apply / confirm / revert
src/lib/ruleset-parse.ts   nft text parse + JSON overlay + owner classification (pure)
src/lib/conf-lint.ts       pre-apply checks: flush ruleset, unreset tables, foreign tables, SSH lockout (pure)
src/lib/diff.ts            jsdiff adapter (pure)
src/lib/evaluate.ts        packet evaluator over nft -j (pure)
src/lib/zones.ts           zones from ip addr/route + config saddr refs; ss parsing (pure)
src/lib/matrix.ts          matrix cells (pure)
src/Matrix.tsx             "Who can reach what" tab + trace + "Is this allowed?" lookup
src/lib/map-layout.ts      Map tab layout: topology bundling/focus + rule graph (pure)
src/Map.tsx                "Map" tab: topology, rule graph, side panel, phone lists
src/preview.tsx            static preview entry (renders a captured read; no helper)
test/demo/                 neutral demo server (config, iptables rules, sockets, interfaces) for screenshots
tools/screenshots/         fixture.sh (demo -> netns -> read.json), shoot.mjs (playwright-core scenarios)
src/lib/helper.ts          cockpit.spawn wrapper
src/lib/admin.ts           admin gating (from upside)
src/Ruleset.tsx            Live ruleset tab
src/Editor.tsx             Configuration tab: edit, check, review, apply
src/app.tsx                shell, polling, pending-undo banner
test/helper-netns.sh       end-to-end helper test in a private network namespace
test/sandbox-copy.sh       full cycle against a sandbox copy of the host firewall (CNFT_NETNS guards)
```

## Build / test

```sh
make                 # npm ci + pkg/lib + build
make test            # unit tests (node --test)
make check           # tests + tsc + eslint (tsc noise from pkg/lib/node_modules is the same baseline as upside)
sudo unshare --net sh test/helper-netns.sh   # helper e2e in an empty private netns
sudo sh test/sandbox-copy.sh                 # full cycle incl. the real systemd undo timer, against a
                                             # sandbox COPY of this host's firewall (nftables.conf +
                                             # iptables-save of Docker/Tailscale); host fingerprinted
                                             # before/after. All writes go through `ip netns exec`.
make devel-install   # ~/.local/share/cockpit/nftables -> dist (current user only)
make screenshots     # README screenshots from test/demo/ (sudo: throwaway netns; tools/screenshots/)
npm run preview      # static, helper-free preview in preview-dist/ (needs a captured
                     # preview-dist/fixture.json = helper `read` output; gitignored,
                     # contains the host's firewall: delete after use)
```

## Next (not started)

- Map: Docker containers behind the bridge (needs `docker inspect`), per-chain packet totals.
- Shadowed/redundant-rule lint (idea from nftables-analyzer, MIT).
- Matrix: resolve xt matches nft can translate (`nft list` text shows Docker's addrtype as `fib daddr type local`; the JSON keeps `xt`); IPv6; editable zones; full process names (ss truncates to 15 chars).
- Syntax highlighting / line numbers (PatternFly CodeEditor + a grammar ported from the nano/Vim/Kate definitions).
- Debian/RPM packaging like cockpit-upside.
