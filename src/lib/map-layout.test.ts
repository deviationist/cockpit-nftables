/*
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

import assert from 'node:assert/strict';
import { test } from 'node:test';

import type { CellState } from './matrix.ts';
import { aggregate, hotEdges, ownerOf, prioNum, ruleLayout, topoLayout } from './map-layout.ts';
import { parseRuleset, classify } from './ruleset-parse.ts';
import type { Service, Zone } from './zones.ts';

const Z = (id: string, iif: string): Zone => ({ id, label: id, detail: `via ${iif}`, iif, saddr: "192.0.2.1", daddr: "192.0.2.9" });
const S = (id: string, ports: number[], extra: Partial<Service> = {}): Service =>
    ({ id, name: id, proto: "tcp", bind: "*", scope: null, ports, docker: false, ...extra });

const zones = [Z("trusted", "eth0"), Z("lan", "eth0"), Z("peer", "wg0"), Z("internet", "eth0")];
const services = [S("sshd", [22]), S("nginx", [80, 443]), S("rpc", [111])];
const M: Record<string, CellState[]> = {
    sshd: ["allow", "block", "allow", "block"],
    nginx: ["allow", "allow", "allow", "allow"],
    rpc: ["block", "block", "block", "block"],
};
const inp = { zones, services, cell: (s: string, z: string) => M[s][zones.findIndex(x => x.id === z)] };
const base = { focus: null, showBlocked: false, query: "" };

test('aggregate', () => {
    assert.equal(aggregate(["allow", "allow"]), "allow");
    assert.equal(aggregate(["allow", "block"]), "partial");
    assert.equal(aggregate(["docker", "docker"]), "docker");
    assert.equal(aggregate(["allow", "unknown"]), "unknown");
});

test('bundled view: zone->iface neutral, iface->service aggregated; blocked-everywhere services hidden', () => {
    const l = topoLayout(inp, base);
    assert.deepEqual(l.services.map(s => s.id), ["sshd", "nginx"]); // rpc blocked from everywhere
    assert.deepEqual(l.nodes.filter(n => n.kind === "iface").map(n => n.key), ["eth0", "wg0"]);
    assert.ok(l.edges.filter(e => e.id.startsWith("zp:")).every(e => e.state === "neutral"));
    const eth0ssh = l.edges.find(e => e.id === "ps:eth0:sshd")!;
    assert.equal(eth0ssh.state, "allow"); // only the visible (allowed) zones are aggregated
    const wg0ssh = l.edges.find(e => e.id === "ps:wg0:sshd")!;
    assert.equal(wg0ssh.state, "allow");
    assert.deepEqual(eth0ssh.action, { kind: "bundle", iface: "eth0", service: "sshd" });
});

test('show blocked: mixed bundles become partial with an allowed/total label, rpc appears', () => {
    const l = topoLayout(inp, { ...base, showBlocked: true });
    assert.ok(l.services.some(s => s.id === "rpc"));
    const e = l.edges.find(x => x.id === "ps:eth0:sshd")!;
    assert.equal(e.state, "partial");
    assert.equal(e.label, "1/3");
});

test('focus a zone: one edge per service with that zone\'s own result, others dimmed', () => {
    const l = topoLayout(inp, { ...base, focus: { kind: "zone", id: "peer" } });
    const ps = l.edges.filter(e => e.id.startsWith("ps:"));
    assert.deepEqual(ps.map(e => [e.id, e.state]), [["ps:wg0:sshd", "allow"], ["ps:wg0:nginx", "allow"]]);
    assert.deepEqual(ps[0].action, { kind: "trace", zone: "peer", service: "sshd" });
    assert.ok(l.nodes.find(n => n.id === "z:trusted")!.dim);
    assert.ok(!l.nodes.find(n => n.id === "z:peer")!.dim);
    assert.ok(l.nodes.find(n => n.id === "z:peer")!.selected);
});

test('focus a service: zone edges coloured per zone', () => {
    const l = topoLayout(inp, { ...base, focus: { kind: "service", id: "sshd" } });
    assert.deepEqual(l.edges.filter(e => e.id.startsWith("zp:")).map(e => e.id)
            .sort(), ["zp:peer", "zp:trusted"]);
    assert.ok(l.nodes.find(n => n.id === "z:lan")!.dim);
});

test('query filters and dims', () => {
    const l = topoLayout(inp, { ...base, query: "port 443" });
    assert.ok(l.nodes.find(n => n.id === "s:sshd")!.dim);
    assert.ok(!l.nodes.find(n => n.id === "s:nginx")!.dim);
    assert.ok(l.edges.filter(e => e.id.startsWith("ps:")).every(e => e.id.endsWith(":nginx")));
});

test('priority parsing', () => {
    assert.equal(prioNum("filter"), 0);
    assert.equal(prioNum("-300"), -300);
    assert.equal(prioNum("filter - 1"), -1);
    assert.equal(prioNum("dstnat"), -100);
    assert.equal(prioNum(null), 0);
});

const RULESET = `table ip filter {
\tchain INPUT {
\t\ttype filter hook input priority filter; policy accept;
\t\tcounter packets 1 bytes 2 jump ts-input # handle 3
\t}
\tchain ts-input {
\t\tiifname "tailscale0" accept # handle 4
\t}
\tchain FORWARD {
\t\ttype filter hook forward priority filter; policy drop;
\t}
}
table inet filter {
\tchain input {
\t\ttype filter hook input priority filter; policy drop;
\t\ttcp dport 22 ip saddr @trusted accept # handle 5
\t\tiifname "wg0" jump vpn_in # handle 6
\t}
\tchain vpn_in {
\t\ttcp dport 2049 accept # handle 7
\t}
}
table ip raw {
\tchain PREROUTING {
\t\ttype filter hook prerouting priority raw; policy accept;
\t}
}
`;

test('rule graph: hooks in order, base chains by priority, regular chains via jump, collapsed hooks', () => {
    const tables = classify(parseRuleset(RULESET), new Set(["inet filter"]), new Set(["ip filter", "ip raw"]));
    const l = ruleLayout(tables, {});
    const headers = l.nodes.filter(n => n.kind === "header").map(n => n.title);
    assert.deepEqual(headers, ["prerouting", "input", "forward", "output", "postrouting"]);
    const input = l.nodes.filter(n => n.hook === "input" && n.kind !== "header");
    assert.deepEqual(input.map(n => `${n.kind}:${n.key}`), [
        "base:ip filter INPUT", "regular:ip filter ts-input", "base:inet filter input", "regular:inet filter vpn_in",
    ]);
    assert.equal(input.find(n => n.key === "ip filter ts-input")!.owner, "tailscale");
    assert.equal(input.find(n => n.key === "inet filter input")!.owner, "config");
    assert.deepEqual(input.find(n => n.key === "inet filter input")!.sets, ["@trusted"]);
    assert.equal(input.find(n => n.key === "inet filter vpn_in")!.via, "jump");
    assert.ok(l.edges.some(e => e.kind === "jump" && e.to === "inet filter vpn_in"));
    // forward is collapsed by default, and expands on request
    assert.ok(l.nodes.some(n => n.kind === "collapsed" && n.hook === "forward" && n.count === 1));
    const open = ruleLayout(tables, { forward: true });
    assert.ok(open.nodes.some(n => n.key === "ip filter FORWARD"));
});

test('ownerOf', () => {
    const t = classify(parseRuleset(RULESET), new Set(), new Set(["ip filter"]))[0];
    assert.equal(ownerOf(t, ["Docker"]), "docker");
    assert.equal(ownerOf(t, []), "iptables-nft");
});

test('hover: zone lights its interface line and the bundles to services it reaches', () => {
    const l = topoLayout(inp, base);
    const hot = hotEdges(l.edges, "z:lan", inp, false);
    // lan reaches nginx only (sshd is blocked for lan); its line to eth0 is lit too
    assert.deepEqual([...hot].sort(), ["ps:eth0:nginx", "zp:lan"]);
});

test('hover: service lights its bundles and the zones that reach it', () => {
    const l = topoLayout(inp, base);
    const hot = hotEdges(l.edges, "s:sshd", inp, false);
    assert.deepEqual([...hot].sort(), ["ps:eth0:sshd", "ps:wg0:sshd", "zp:peer", "zp:trusted"]);
});

test('hover: interface lights everything in and out', () => {
    const l = topoLayout(inp, base);
    const hot = hotEdges(l.edges, "i:wg0", inp, false);
    assert.deepEqual([...hot].sort(), ["ps:wg0:nginx", "ps:wg0:sshd", "zp:peer"]);
    assert.equal(hotEdges(l.edges, null, inp, false).size, 0);
});
