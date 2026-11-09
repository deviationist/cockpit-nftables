/*
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

import assert from 'node:assert/strict';
import { test } from 'node:test';

import { buildModel, evaluate, inPrefix, ip4 } from './evaluate.ts';

const m = (op: string, left: unknown, right: unknown) => ({ match: { op, left, right } });
const P = (protocol: string, field: string) => ({ payload: { protocol, field } });
const META = (key: string) => ({ meta: { key } });

// A miniature server: inet filter input (policy drop) + a CVE raw table + an
// iptables-nft style table with an accept-policy INPUT and a Tailscale chain.
const RULESET = JSON.stringify({
    nftables: [
        { metainfo: {} },
        { set: { family: "inet", table: "filter", name: "trusted", type: "ipv4_addr", elem: ["192.168.1.20", { prefix: { addr: "10.66.0.0", len: 24 } }] } },
        { chain: { family: "ip", table: "cve", name: "pre", type: "filter", hook: "prerouting", prio: -300, policy: "accept" } },
        { rule: { family: "ip", table: "cve", chain: "pre", handle: 2, expr: [m(">", P("ip", "hdrlength"), 5), m("==", META("l4proto"), 6), { counter: null }, { drop: null }] } },
        { chain: { family: "ip", table: "filter", name: "INPUT", type: "filter", hook: "input", prio: 0, policy: "accept" } },
        { chain: { family: "ip", table: "filter", name: "ts-input", handle: 9 } },
        { rule: { family: "ip", table: "filter", chain: "INPUT", handle: 10, expr: [{ counter: null }, { jump: { target: "ts-input" } }] } },
        { rule: { family: "ip", table: "filter", chain: "ts-input", handle: 11, expr: [m("==", P("ip", "saddr"), { prefix: { addr: "100.64.0.0", len: 10 } }), m("!=", META("iifname"), "tailscale0"), { drop: null }] } },
        { rule: { family: "ip", table: "filter", chain: "ts-input", handle: 12, expr: [m("==", META("iifname"), "tailscale0"), { accept: null }] } },
        { chain: { family: "inet", table: "filter", name: "input", type: "filter", hook: "input", prio: 0, policy: "drop" } },
        { rule: { family: "inet", table: "filter", chain: "input", handle: 20, expr: [m("in", { ct: { key: "state" } }, ["established", "related"]), { accept: null }] } },
        { rule: { family: "inet", table: "filter", chain: "input", handle: 21, expr: [m("==", P("tcp", "dport"), 22), m("==", P("ip", "saddr"), "@trusted"), { accept: null }] } },
        { rule: { family: "inet", table: "filter", chain: "input", handle: 22, expr: [m("==", P("tcp", "dport"), { set: [80, 443] }), { accept: null }] } },
        { rule: { family: "inet", table: "filter", chain: "input", handle: 23, expr: [m("==", META("iifname"), "wg0"), m("==", P("ip", "saddr"), { set: ["10.20.0.2", "10.20.0.3"] }), m("==", P("tcp", "dport"), 2049), { accept: null }] } },
        { rule: { family: "inet", table: "filter", chain: "input", handle: 24, expr: [m("==", P("udp", "dport"), 41641), { accept: null }] } },
        { rule: { family: "inet", table: "filter", chain: "input", handle: 25, expr: [m("==", META("iifname"), "br-*"), { xt: { type: "match", name: "addrtype" } }, { accept: null }] } },
    ],
});

const model = buildModel(RULESET, ["192.168.1.9", "10.20.0.1"]);
const pkt = (o: Partial<{ iif: string; saddr: string; daddr: string; proto: "tcp" | "udp"; dport: number }>) =>
    ({ iif: "eno1", saddr: "192.168.1.50", daddr: "192.168.1.9", proto: "tcp" as const, dport: 22, ...o });

test('ip helpers', () => {
    assert.equal(ip4("192.168.1.9"), 3232235785);
    assert.equal(ip4("300.1.1.1"), null);
    assert.ok(inPrefix("10.66.0.5", "10.66.0.0", 24));
    assert.ok(!inPrefix("10.8.0.5", "10.66.0.0", 24));
});

test('trusted source reaches SSH via the named set', () => {
    const t = evaluate(model, pkt({ saddr: "192.168.1.20" }));
    assert.equal(t.outcome, "accept");
    const last = t.steps[t.steps.length - 1];
    assert.equal(last.chain, "input");
    assert.equal(last.handle, 21);
});

test('untrusted LAN source hits the policy drop; established rule does not match a new packet', () => {
    const t = evaluate(model, pkt({ saddr: "192.168.1.50" }));
    assert.equal(t.outcome, "drop");
    assert.equal(t.steps[t.steps.length - 1].verdict, "policy drop");
});

test('set prefix member (router VPN) matches', () => {
    assert.equal(evaluate(model, pkt({ saddr: "10.66.0.9" })).outcome, "accept");
});

test('anonymous port set; accept in one table still runs the next base chain', () => {
    const t = evaluate(model, pkt({ dport: 443 }));
    assert.equal(t.outcome, "accept");
    // the iptables-nft INPUT chain ran first (prio 0, kernel order), then inet filter
    assert.ok(t.steps.some(s => s.table === "filter" && s.family === "ip"));
    assert.ok(t.steps.some(s => s.family === "inet" && s.handle === 22));
});

test('jump into a regular chain: tailnet address on the wrong interface is dropped there', () => {
    const t = evaluate(model, pkt({ saddr: "100.100.1.1", dport: 443 }));
    assert.equal(t.outcome, "drop");
    assert.ok(t.steps.some(s => s.verdict === "jump ts-input"));
    assert.equal(t.steps[t.steps.length - 1].handle, 11);
});

test('protocol dependency: a tcp dport rule never matches UDP', () => {
    assert.equal(evaluate(model, pkt({ proto: "udp", dport: 22, saddr: "192.168.1.20" })).outcome, "drop");
    assert.equal(evaluate(model, pkt({ proto: "udp", dport: 41641 })).outcome, "accept");
});

test('literal set of addresses + interface', () => {
    const p = { iif: "wg0", daddr: "10.20.0.1", dport: 2049 };
    assert.equal(evaluate(model, pkt({ ...p, saddr: "10.20.0.2" })).outcome, "accept");
    assert.equal(evaluate(model, pkt({ ...p, saddr: "10.20.0.4" })).outcome, "drop");
});

test('an xt match on a rule that would decide makes the result unknown, with the reason', () => {
    const t = evaluate(model, pkt({ iif: "br-abc", dport: 9999 }));
    assert.equal(t.outcome, "unknown");
    assert.match(t.reason!, /xt match addrtype/);
});

test('raw-priority CVE table runs first and does not drop a normal packet', () => {
    const t = evaluate(model, pkt({ saddr: "192.168.1.20" }));
    assert.equal(t.steps[0].table, "cve");
    assert.equal(t.steps[0].verdict, "policy accept");
});

test('non-deciding xt targets are skipped, but taint later mark matches', () => {
    const M = buildModel(JSON.stringify({
        nftables: [
            { chain: { family: "ip", table: "mangle", name: "PREROUTING", type: "filter", hook: "prerouting", prio: -150, policy: "accept" } },
            { rule: { family: "ip", table: "mangle", chain: "PREROUTING", handle: 1, expr: [{ xt: { type: "match", name: "conntrack" } }, { xt: { type: "target", name: "CONNMARK" } }] } },
            { chain: { family: "inet", table: "filter", name: "input", type: "filter", hook: "input", prio: 0, policy: "drop" } },
            { rule: { family: "inet", table: "filter", chain: "input", handle: 2, expr: [m("==", P("tcp", "dport"), 22), { accept: null }] } },
            { rule: { family: "inet", table: "filter", chain: "input", handle: 3, expr: [m("==", { "&": [META("mark"), 255] }, 1), { accept: null }] } },
        ],
    }));
    assert.equal(evaluate(M, pkt({ dport: 22 })).outcome, "accept");
    const t = evaluate(M, pkt({ dport: 80 }));
    assert.equal(t.outcome, "unknown");
    assert.match(t.reason!, /xt CONNMARK/);
});

test('jump with an unknown condition: harmless if the target chain does not decide this packet', () => {
    const M = buildModel(JSON.stringify({
        nftables: [
            { chain: { family: "ip", table: "nat", name: "PREROUTING", type: "nat", hook: "prerouting", prio: -100, policy: "accept" } },
            { chain: { family: "ip", table: "nat", name: "DOCKER" } },
            { rule: { family: "ip", table: "nat", chain: "PREROUTING", handle: 1, expr: [{ xt: { type: "match", name: "addrtype" } }, { jump: { target: "DOCKER" } }] } },
            { rule: { family: "ip", table: "nat", chain: "DOCKER", handle: 2, expr: [m("==", P("tcp", "dport"), 3306), { dnat: { addr: "172.17.0.2" } }] } },
            { chain: { family: "inet", table: "filter", name: "input", type: "filter", hook: "input", prio: 0, policy: "drop" } },
            { rule: { family: "inet", table: "filter", chain: "input", handle: 3, expr: [m("==", P("tcp", "dport"), 22), { accept: null }] } },
        ],
    }));
    const ssh = evaluate(M, pkt({ dport: 22 }));
    assert.equal(ssh.outcome, "accept");
    assert.ok(ssh.steps.some(s => /doesn't decide/.test(s.note ?? "")));
    const mysql = evaluate(M, pkt({ dport: 3306 }));
    assert.equal(mysql.outcome, "unknown"); // the DNAT would apply only if addrtype matched
    assert.match(mysql.reason!, /addrtype/);
});
