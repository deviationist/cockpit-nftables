/*
 * SPDX-License-Identifier: LGPL-2.1-or-later
 *
 * Copyright (C) 2026 deviationist
 *
 * nftables has no zones, so we derive them from what the host and its rules
 * already say (UniFi-Zone-Matrix style rows):
 *   - each LAN interface: the named sets your rules use (@trusted), the
 *     single addresses your rules name (the router), "rest of the LAN", and
 *     "Internet" on the default-route interface
 *   - each tunnel (wireguard / tun): addresses your rules name on it, else one
 *     generic peer
 *   - set members outside every local subnet (VPN clients routed by the gateway, single remote hosts) and
 *     container bridges your rules trust
 * Every zone is evaluated with ONE representative source address, shown in
 * the UI, so the result is never more than "this example packet".
 *
 * Pure + Cockpit-free; also parses `ip -j -d -4 addr`, `ip -j route` and `ss`.
 */

import type { Model } from './evaluate.ts';
import { inPrefix, ip4 } from './evaluate.ts';

type J = Record<string, unknown>;

export type IfaceKind = "lan" | "tunnel" | "bridge" | "other";

export interface Iface {
    name: string;
    addr: string;
    prefixlen: number;
    kind: IfaceKind;
}

export interface Zone {
    id: string;
    label: string;
    detail: string; // "e.g. 192.168.1.20 via eno1"
    iif: string;
    saddr: string;
    daddr: string;
}

export function parseIfaces(json: string): Iface[] {
    let arr: J[] = [];
    try {
        arr = JSON.parse(json) as J[];
    } catch {
        return [];
    }
    const out: Iface[] = [];
    for (const i of arr) {
        const name = i.ifname as string;
        const info = ((i.linkinfo as J | undefined)?.info_kind as string | undefined) ?? "";
        let kind: IfaceKind = "lan";
        if (name === "lo" || info === "dummy" || info === "veth") kind = "other";
        else if (info === "bridge" || name.startsWith("br-") || name === "docker0") kind = "bridge";
        else if (info === "wireguard" || info === "tun") kind = "tunnel";
        for (const a of (i.addr_info as J[]) ?? []) {
            if (a.family && a.family !== "inet") continue;
            out.push({ name, addr: a.local as string, prefixlen: a.prefixlen as number, kind });
        }
    }
    return out;
}

export function parseDefaultRoute(json: string): string | null {
    try {
        const r = (JSON.parse(json) as J[]).find(x => x.dst === "default");
        return (r?.dev as string) ?? null;
    } catch {
        return null;
    }
}

function network(addr: string, len: number): number {
    const a = ip4(addr)!;
    const mask = len === 0 ? 0 : len === 32 ? 0xffffffff : (~((1 << (32 - len)) - 1)) >>> 0;
    return (a & mask) >>> 0;
}

function fromInt(n: number): string {
    return [n >>> 24, (n >>> 16) & 255, (n >>> 8) & 255, n & 255].join(".");
}

interface SaddrRefs {
    sets: Map<string, unknown[]>; // set name -> elements (from config tables)
    literals: string[]; // single addresses named in `ip saddr` matches
}

/** What the CONFIG tables' rules say about source addresses. */
export function saddrRefs(model: Model, configTables: Set<string>): SaddrRefs {
    const sets = new Map<string, unknown[]>();
    const literals = new Set<string>();
    for (const [k, rules] of model.rules) {
        const [family, table] = k.split(" ");
        if (!configTables.has(`${family} ${table}`)) continue;
        for (const r of rules) {
            for (const e of r.expr) {
                const m = e.match as J | undefined;
                if (!m) continue;
                const left = JSON.stringify(m.left);
                if (left !== JSON.stringify({ payload: { protocol: "ip", field: "saddr" } })) continue;
                const right = m.right;
                if (typeof right === "string" && right.startsWith("@")) {
                    const s = model.sets.get(`${family} ${table} ${right.slice(1)}`);
                    if (s) sets.set(right.slice(1), s.elem ?? []);
                } else if (typeof right === "string" && ip4(right) !== null) {
                    literals.add(right);
                } else if (right && typeof right === "object" && (right as J).set) {
                    for (const x of (right as J).set as unknown[]) if (typeof x === "string" && ip4(x) !== null) literals.add(x);
                }
            }
        }
    }
    return { sets, literals: [...literals].sort((a, b) => ip4(a)! - ip4(b)!) };
}

type Member = { kind: "ip"; ip: string } | { kind: "prefix"; addr: string; len: number };

function members(elems: unknown[]): Member[] {
    const out: Member[] = [];
    for (const e of elems) {
        const x = e && typeof e === "object" && (e as J).elem ? ((e as J).elem as J).val : e;
        if (typeof x === "string" && ip4(x) !== null) out.push({ kind: "ip", ip: x });
        else if (x && typeof x === "object" && (x as J).prefix) {
            const p = (x as J).prefix as { addr: string; len: number };
            out.push({ kind: "prefix", addr: p.addr, len: p.len });
        }
    }
    return out;
}

function inSubnet(ip: string, f: Iface): boolean {
    return inPrefix(ip, f.addr, f.prefixlen);
}

export function deriveZones(ifaces: Iface[], defaultDev: string | null, refs: SaddrRefs): Zone[] {
    const zones: Zone[] = [];
    const hostIps = new Set(ifaces.map(f => f.addr));
    const local = ifaces.filter(f => f.kind === "lan" || f.kind === "tunnel" || f.kind === "bridge");
    const lanDefault = ifaces.find(f => f.name === defaultDev) ?? ifaces.find(f => f.kind === "lan");
    const covered = new Set<string>(); // addresses already represented

    const add = (z: Omit<Zone, "id" | "detail">) => {
        zones.push({ ...z, id: `${z.iif}|${z.saddr}`, detail: `e.g. ${z.saddr} via ${z.iif}` });
        covered.add(z.saddr);
    };
    const usedSets = [...refs.sets.entries()].map(([name, el]) => ({ name, members: members(el) }));
    const inAnySet = (ip: string) => usedSets.some(s => s.members.some(m =>
        m.kind === "ip" ? m.ip === ip : inPrefix(ip, m.addr, m.len)));

    // LAN interfaces
    for (const f of ifaces.filter(x => x.kind === "lan")) {
        for (const s of usedSets) {
            const pick = s.members.find(m => m.kind === "ip" && inSubnet(m.ip, f) && !hostIps.has(m.ip));
            if (pick && pick.kind === "ip")
                add({ label: `@${s.name}`, iif: f.name, saddr: pick.ip, daddr: f.addr });
        }
        for (const ip of refs.literals)
            if (inSubnet(ip, f) && !hostIps.has(ip) && !inAnySet(ip))
                add({ label: ip, iif: f.name, saddr: ip, daddr: f.addr });
        // "rest of the LAN": the first address no set or literal covers
        const net = network(f.addr, f.prefixlen);
        const size = f.prefixlen >= 31 ? 0 : 2 ** (32 - f.prefixlen) - 2;
        for (let i = 2; i <= Math.min(size, 4096); i++) {
            const ip = fromInt(net + i);
            if (!hostIps.has(ip) && !inAnySet(ip) && !refs.literals.includes(ip)) {
                add({ label: `Rest of ${fromInt(net)}/${f.prefixlen}`, iif: f.name, saddr: ip, daddr: f.addr });
                break;
            }
        }
    }

    // Tunnels: named peers, else one generic peer
    for (const f of ifaces.filter(x => x.kind === "tunnel")) {
        const named = refs.literals.filter(ip => inSubnet(ip, f) && !hostIps.has(ip));
        for (const ip of named) add({ label: `${ip}`, iif: f.name, saddr: ip, daddr: f.addr });
        if (!named.length) {
            const cgnat = inPrefix(f.addr, "100.64.0.0", 10);
            const peer = cgnat ? "100.64.0.2" : fromInt(network(f.addr, f.prefixlen) + (ip4(f.addr) === network(f.addr, f.prefixlen) + 2 ? 3 : 2));
            add({ label: `${f.name} peer`, iif: f.name, saddr: peer, daddr: f.addr });
        }
    }

    // Set members outside every LAN/tunnel subnet: routed VPN clients, single remote hosts, container bridges
    for (const s of usedSets) {
        for (const m of s.members) {
            const sample = m.kind === "ip" ? m.ip : fromInt(network(m.addr, m.len) + 2);
            if (covered.has(sample) || hostIps.has(sample)) continue;
            if (local.some(f => (f.kind === "lan" || f.kind === "tunnel") && inSubnet(sample, f))) continue;
            const bridge = ifaces.find(f => f.kind === "bridge" && inSubnet(sample, f));
            const via = bridge ?? lanDefault;
            if (!via) continue;
            const what = m.kind === "ip" ? m.ip : `${m.addr}/${m.len}`;
            add({ label: `@${s.name}: ${what}`, iif: via.name, saddr: sample, daddr: via.addr });
        }
    }

    // Internet, arriving on the default-route interface
    if (lanDefault)
        add({ label: "Internet", iif: lanDefault.name, saddr: "203.0.113.10", daddr: lanDefault.addr });
    return zones;
}

/* ---- listening services (`ss -Hlntup`) ---- */

export interface Listener {
    proto: "tcp" | "udp";
    bind: string; // "0.0.0.0", "10.20.0.1", "*"
    scope: string | null; // "%tailscale0" → "tailscale0"
    port: number;
    process: string;
}

export interface Service {
    id: string;
    name: string;
    proto: "tcp" | "udp";
    bind: string;
    scope: string | null;
    ports: number[];
    docker: boolean;
}

const KERNEL_PORTS: Record<number, string> = { 2049: "nfsd (kernel)", 111: "rpcbind", 51820: "wireguard (kernel)", 44101: "wireguard (kernel)", 51900: "wireguard (kernel)" };

export function parseSs(text: string): Listener[] {
    const out: Listener[] = [];
    for (const line of text.split("\n")) {
        const f = line.trim().split(/\s+/);
        if (f.length < 5) continue;
        const proto = f[0] === "tcp" ? "tcp" : f[0] === "udp" ? "udp" : null;
        if (!proto) continue;
        const local = f[4];
        const m = /^(.*):(\d+)$/.exec(local);
        if (!m) continue;
        let host = m[1];
        const port = Number(m[2]);
        let scope: string | null = null;
        const pct = host.indexOf("%");
        if (pct >= 0) {
            scope = host.slice(pct + 1);
            host = host.slice(0, pct);
        }
        host = host.replace(/^\[|\]$/g, "");
        let bind: string;
        if (host === "*" || host === "0.0.0.0" || host === "::") bind = "*";
        else if (ip4(host) !== null) bind = host;
        else continue; // IPv6-only address: this matrix is IPv4
        if (bind.startsWith("127.") || scope === "lo") continue;
        const p = /users:\(\("([^"]+)"/.exec(line);
        out.push({ proto, bind, scope, port, process: p ? p[1] : (KERNEL_PORTS[port] ?? "kernel") });
    }
    return out;
}

export function groupServices(listeners: Listener[]): Service[] {
    const map = new Map<string, Service>();
    for (const l of listeners) {
        const id = `${l.process}|${l.proto}|${l.bind}|${l.scope ?? ""}`;
        let s = map.get(id);
        if (!s) {
            s = { id, name: l.process, proto: l.proto, bind: l.bind, scope: l.scope, ports: [], docker: l.process === "docker-proxy" };
            map.set(id, s);
        }
        if (!s.ports.includes(l.port)) s.ports.push(l.port);
    }
    const out = [...map.values()];
    for (const s of out) s.ports.sort((a, b) => a - b);
    return out.sort((a, b) => a.ports[0] - b.ports[0] || a.proto.localeCompare(b.proto));
}
