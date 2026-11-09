/*
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

import assert from 'node:assert/strict';
import { test } from 'node:test';

import { buildModel } from './evaluate.ts';
import { cellFor } from './matrix.ts';
import { deriveZones, groupServices, parseDefaultRoute, parseIfaces, parseSs, saddrRefs } from './zones.ts';

const IFACES = JSON.stringify([
    { ifname: "lo", addr_info: [{ family: "inet", local: "127.0.0.1", prefixlen: 8 }] },
    { ifname: "eno1", addr_info: [{ family: "inet", local: "192.168.1.9", prefixlen: 24 }] },
    { ifname: "dummy0", linkinfo: { info_kind: "dummy" }, addr_info: [{ family: "inet", local: "1.2.3.4", prefixlen: 24 }] },
    { ifname: "wg0", linkinfo: { info_kind: "wireguard" }, addr_info: [{ family: "inet", local: "10.20.0.1", prefixlen: 24 }] },
    { ifname: "tailscale0", linkinfo: { info_kind: "tun" }, addr_info: [{ family: "inet", local: "100.101.102.103", prefixlen: 32 }] },
    { ifname: "br-wg", linkinfo: { info_kind: "bridge" }, addr_info: [{ family: "inet", local: "172.30.0.1", prefixlen: 16 }] },
]);

const m = (op: string, left: unknown, right: unknown) => ({ match: { op, left, right } });
const SADDR = { payload: { protocol: "ip", field: "saddr" } };
const RULESET = JSON.stringify({
    nftables: [
        { set: { family: "inet", table: "filter", name: "trusted", elem: ["192.168.1.7", "192.168.1.9", "192.168.1.20", { prefix: { addr: "10.66.0.0", len: 24 } }, { prefix: { addr: "172.30.0.0", len: 16 } }, "10.0.9.2"] } },
        { chain: { family: "inet", table: "filter", name: "input", type: "filter", hook: "input", prio: 0, policy: "drop" } },
        { rule: { family: "inet", table: "filter", chain: "input", handle: 1, expr: [m("==", { payload: { protocol: "tcp", field: "dport" } }, 22), m("==", SADDR, "@trusted"), { accept: null }] } },
        { rule: { family: "inet", table: "filter", chain: "input", handle: 2, expr: [m("==", { payload: { protocol: "udp", field: "dport" } }, 514), m("==", SADDR, "192.168.1.1"), { accept: null }] } },
        { rule: { family: "inet", table: "filter", chain: "input", handle: 3, expr: [m("==", { meta: { key: "iifname" } }, "wg0"), m("==", SADDR, { set: ["10.20.0.2", "10.20.0.3"] }), { accept: null }] } },
        { rule: { family: "inet", table: "filter", chain: "input", handle: 4, expr: [m("==", { payload: { protocol: "tcp", field: "dport" } }, 443), { accept: null }] } },
    ],
});

const SS = `tcp   LISTEN 0 4096   0.0.0.0:22   0.0.0.0:* users:(("sshd",pid=1,fd=3))
tcp   LISTEN 0 511    0.0.0.0:443  0.0.0.0:* users:(("nginx",pid=2,fd=6),("nginx",pid=3,fd=6))
tcp   LISTEN 0 64     10.20.0.1:2049 0.0.0.0:*
tcp   LISTEN 0 4096   10.20.0.1:3306 0.0.0.0:* users:(("docker-proxy",pid=4,fd=7))
tcp   LISTEN 0 4096   127.0.0.1:5432 0.0.0.0:* users:(("docker-proxy",pid=5,fd=7))
tcp   LISTEN 0 4096   100.101.102.103%tailscale0:40479 0.0.0.0:* users:(("tailscaled",pid=6,fd=9))
udp   UNCONN 0 0      192.168.1.9:514 0.0.0.0:* users:(("rsyslogd",pid=7,fd=5))
tcp   LISTEN 0 4096   [::]:22 [::]:* users:(("sshd",pid=1,fd=4))
tcp   LISTEN 0 4096   [fe80::1]:8080 [::]:* users:(("x",pid=8,fd=4))`;

test('interfaces and default route', () => {
    const f = parseIfaces(IFACES);
    assert.deepEqual(f.map(x => `${x.name}:${x.kind}`), ["lo:other", "eno1:lan", "dummy0:other", "wg0:tunnel", "tailscale0:tunnel", "br-wg:bridge"]);
    assert.equal(parseDefaultRoute('[{"dst":"default","gateway":"192.168.1.1","dev":"eno1"}]'), "eno1");
});

test('zones derived from interfaces, the named set and literal addresses', () => {
    const model = buildModel(RULESET);
    const zones = deriveZones(parseIfaces(IFACES), "eno1", saddrRefs(model, new Set(["inet filter"])));
    const show = zones.map(z => `${z.label}=${z.saddr}@${z.iif}`);
    assert.deepEqual(show, [
        "@trusted=192.168.1.7@eno1", // first member that isn't the host itself
        "192.168.1.1=192.168.1.1@eno1", // named by the syslog rule
        "Rest of 192.168.1.0/24=192.168.1.2@eno1",
        "10.20.0.2=10.20.0.2@wg0",
        "10.20.0.3=10.20.0.3@wg0",
        "tailscale0 peer=100.64.0.2@tailscale0",
        "@trusted: 10.66.0.0/24=10.66.0.2@eno1", // routed by the router: arrives on the default-route interface
        "@trusted: 172.30.0.0/16=172.30.0.2@br-wg", // container bridge
        "@trusted: 10.0.9.2=10.0.9.2@eno1",
        "Internet=203.0.113.10@eno1",
    ]);
});

test('ss parsing: loopback and IPv6-only listeners dropped, kernel sockets named, dual-stack kept once', () => {
    const svc = groupServices(parseSs(SS));
    assert.deepEqual(svc.map(s => `${s.name}/${s.proto}/${s.bind}${s.scope ? "%" + s.scope : ""}:${s.ports.join(",")}${s.docker ? " docker" : ""}`), [
        "sshd/tcp/*:22",
        "nginx/tcp/*:443",
        "rsyslogd/udp/192.168.1.9:514",
        "nfsd (kernel)/tcp/10.20.0.1:2049",
        "docker-proxy/tcp/10.20.0.1:3306 docker",
        "tailscaled/tcp/100.101.102.103%tailscale0:40479",
    ]);
});

test('matrix cells', () => {
    const model = buildModel(RULESET, ["192.168.1.9"]);
    const zones = deriveZones(parseIfaces(IFACES), "eno1", saddrRefs(model, new Set(["inet filter"])));
    const svc = groupServices(parseSs(SS));
    const z = (label: string) => zones.find(x => x.label === label)!;
    const s = (name: string) => svc.find(x => x.name === name)!;
    assert.equal(cellFor(model, z("@trusted"), s("sshd")).state, "allow");
    assert.equal(cellFor(model, z("Rest of 192.168.1.0/24"), s("sshd")).state, "block");
    assert.equal(cellFor(model, z("Internet"), s("nginx")).state, "allow");
    assert.equal(cellFor(model, z("192.168.1.1"), s("rsyslogd")).state, "allow");
    assert.equal(cellFor(model, z("Rest of 192.168.1.0/24"), s("rsyslogd")).state, "block");
    assert.equal(cellFor(model, z("Internet"), s("nfsd (kernel)")).state, "none"); // bound to the trunk IP only
    assert.equal(cellFor(model, z("10.20.0.2"), s("nfsd (kernel)")).state, "allow");
    assert.equal(cellFor(model, z("10.20.0.2"), s("docker-proxy")).state, "docker");
    assert.equal(cellFor(model, z("Internet"), s("tailscaled")).state, "none");
});
