/*
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

import assert from 'node:assert/strict';
import { test } from 'node:test';

import { chainTags, classify, formatCount, overlayJson, parseIptablesManaged, parseRuleset, tableKey } from './ruleset-parse.ts';

const SAMPLE = `table ip filter {
\tchain DOCKER {
\t\tiifname != "docker0" oifname "docker0" counter packets 0 bytes 0 drop
\t}
\tchain FORWARD {
\t\ttype filter hook forward priority filter; policy drop;
\t\tcounter packets 12 bytes 3400 jump DOCKER-USER
\t}
}
table inet filter {
\tset trusted {
\t\ttype ipv4_addr
\t\tflags interval
\t\telements = { 10.66.0.0/24,
\t\t\t     192.168.1.7 }
\t}

\tchain input {
\t\ttype filter hook input priority filter; policy drop;
\t\tiif "lo" accept
\t\ttcp dport 22 ip saddr @trusted accept comment "SSH: trusted"
\t\tlimit rate 5/minute burst 5 packets log prefix "nft-drop-in: " level info
\t}
\tchain forward {
\t\ttype filter hook forward priority filter; policy accept;
\t}
}
table ip nat {
\tchain ts-postrouting {
\t\tmeta mark & 0x00ff0000 == 0x00040000 counter packets 5 bytes 300 xt target "MASQUERADE"
\t}
}
table inet f2b-table {
\tchain f2b-chain {
\t\ttype filter hook input priority filter - 1; policy accept;
\t}
}
`;

const STDERR = `# Warning: table ip filter is managed by iptables-nft, do not touch!
# Warning: table ip nat is managed by iptables-nft, do not touch!
# Warning: XT target MASQUERADE not found
`;

test('parses tables, chains, sets and rules', () => {
    const t = parseRuleset(SAMPLE);
    assert.deepEqual(t.map(x => tableKey(x.family, x.name)), ["ip filter", "inet filter", "ip nat", "inet f2b-table"]);
    const inet = t[1];
    assert.equal(inet.objects.length, 1);
    assert.equal(inet.objects[0].kind, "set");
    assert.match(inet.objects[0].body, /192\.168\.1\.7/);
    const input = inet.chains.find(c => c.name === "input")!;
    assert.equal(input.hook, "input");
    assert.equal(input.policy, "drop");
    assert.equal(input.priority, "filter");
    assert.equal(input.rules.length, 3);
    assert.equal(input.rules[1].comment, "SSH: trusted");
    assert.equal(input.rules[1].verdict, "accept");
    // "drop" inside the log prefix is not a verdict
    assert.equal(input.rules[2].verdict, null);
});

test('regular chain has no hook; counters and jump verdicts', () => {
    const t = parseRuleset(SAMPLE);
    const docker = t[0].chains[0];
    assert.equal(docker.hook, null);
    assert.deepEqual(docker.tags, ["Docker"]);
    const fwd = t[0].chains[1];
    assert.equal(fwd.rules[0].packets, 12);
    assert.equal(fwd.rules[0].bytes, 3400);
    assert.equal(fwd.rules[0].verdict, "jump DOCKER-USER");
});

test('priority with offset', () => {
    const f2b = parseRuleset(SAMPLE)[3].chains[0];
    assert.equal(f2b.priority, "filter - 1");
    assert.equal(f2b.policy, "accept");
});

test('classify owners', () => {
    const managed = parseIptablesManaged(STDERR);
    assert.deepEqual([...managed].sort(), ["ip filter", "ip nat"]);
    const t = classify(parseRuleset(SAMPLE), new Set(["inet filter"]), managed);
    assert.deepEqual(t.map(x => x.owner), ["iptables-nft", "config", "iptables-nft", "fail2ban"]);
});

test('chain tags', () => {
    assert.deepEqual(chainTags("ts-input"), ["Tailscale"]);
    assert.deepEqual(chainTags("input"), []);
});

test('formatCount', () => {
    assert.equal(formatCount(null), "");
    assert.equal(formatCount(999), "999");
    assert.equal(formatCount(1500), "1.5K");
    assert.equal(formatCount(25_000_000), "25M");
});

test('nft -a handles are stripped and recorded', () => {
    const t = parseRuleset('table inet filter { # handle 13\n\tchain input { # handle 1\n\t\ttype filter hook input priority filter; policy drop;\n\t\tiif "lo" accept # handle 5\n\t}\n}\n');
    assert.equal(t.length, 1);
    assert.equal(t[0].chains[0].name, "input");
    assert.equal(t[0].chains[0].rules[0].text, 'iif "lo" accept');
    assert.equal(t[0].chains[0].rules[0].handle, 5);
});

test('JSON overlay sets counters, comment and verdict by handle', () => {
    const text = 'table ip filter { # handle 2\n\tchain GATE { # handle 9\n\t\tct state new counter packets 1 bytes 2 xt target "MASQUERADE" # handle 175\n\t}\n}\n';
    const json = JSON.stringify({
        nftables: [
            { metainfo: {} },
            { chain: { family: "ip", table: "filter", name: "GATE", handle: 9 } },
            { rule: { family: "ip", table: "filter", chain: "GATE", handle: 175, comment: "c", expr: [{ xt: { type: "match", name: "conntrack" } }, { counter: { packets: 83355, bytes: 690 } }, { xt: { type: "target", name: "MASQUERADE" } }] } },
        ],
    });
    const r = overlayJson(parseRuleset(text), json)[0].chains[0].rules[0];
    assert.equal(r.packets, 83355);
    assert.equal(r.comment, "c");
    assert.equal(r.verdict, "masquerade");
    // bad JSON falls back to the text parse
    assert.equal(overlayJson(parseRuleset(text), "nope")[0].chains[0].rules[0].packets, 1);
});
