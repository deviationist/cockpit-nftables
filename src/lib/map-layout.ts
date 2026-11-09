/*
 * SPDX-License-Identifier: LGPL-2.1-or-later
 *
 * Copyright (C) 2026 deviationist
 *
 * Layout for the Map tab (pure, Cockpit-free, unit-tested):
 *   - topology: zones -> interface "ports" on the host -> services, edges
 *     bundled per interface until a zone, interface or service is focused
 *   - rule graph: netfilter hooks left to right, base chains stacked by
 *     priority, regular chains reached by jump/goto hanging off their parent
 * Positions are in logical pixels; the view scales the whole canvas to fit.
 */

import type { CellState } from './matrix.ts';
import type { Owner, Table } from './ruleset-parse.ts';
import type { Service, Zone } from './zones.ts';

/* ===================== topology ===================== */

export type EdgeState = CellState | "neutral";

export type Focus =
    | { kind: "zone"; id: string }
    | { kind: "service"; id: string }
    | { kind: "iface"; name: string }
    | null;

export type EdgeAction =
    | { kind: "trace"; zone: string; service: string }
    | { kind: "bundle"; iface: string; service: string }
    | { kind: "focus"; focus: Focus };

export interface TNode {
    id: string;
    kind: "zone" | "iface" | "service";
    key: string; // zone id / iface name / service id
    x: number; y: number; w: number; h: number;
    label: string;
    detail: string;
    dim: boolean;
    selected: boolean;
}

export interface TEdge {
    id: string;
    d: string;
    state: EdgeState;
    label?: string;
    title: string; // human description, for screen readers and tooltips
    from: string; // node ids (z:/i:/s:) this edge joins
    to: string;
    lit: boolean;
    action: EdgeAction | null;
}

export interface TopoInput {
    zones: Zone[];
    services: Service[];
    cell: (serviceId: string, zoneId: string) => CellState;
}

export interface TopoOpts {
    focus: Focus;
    showBlocked: boolean;
    query: string;
    lit?: { zone: string; service: string } | null;
}

export const T = {
    ZW: 230, // zone column width
    IX: 320, // interface column x
    IW: 190,
    SX: 660, // service column x
    SW: 240,
    NH: 48, // node height
    STEP: 60,
    PH: 30, // interface "port" height
};

export function visible(st: CellState, showBlocked: boolean): boolean {
    return st !== "none" && (st !== "block" || showBlocked);
}

/** One state for a bundle of zones: identical -> that state, else partial. */
export function aggregate(states: CellState[]): CellState {
    const u = new Set(states);
    if (u.size === 1) return states[0];
    if ([...u].every(s => s === "allow" || s === "block" || s === "partial")) return "partial";
    if (u.has("unknown")) return "unknown";
    return "partial";
}

const curve = (x1: number, y1: number, x2: number, y2: number) => {
    const dx = Math.max(40, (x2 - x1) / 2);
    return `M${x1},${y1} C${x1 + dx},${y1} ${x2 - dx},${y2} ${x2},${y2}`;
};

function serviceText(s: Service): string {
    return `${s.name} ${s.proto} ${s.ports.join(" ")} ${s.bind}`.toLowerCase();
}

export function topoLayout(inp: TopoInput, o: TopoOpts) {
    const q = o.query.trim().toLowerCase()
            .replace(/^port\s+/, "");
    const zoneMatch = (z: Zone) => !q || `${z.label} ${z.detail}`.toLowerCase().includes(q);
    const svcMatch = (s: Service) => !q || serviceText(s).includes(q);
    const ifaceMatch = (n: string) => !q || n.toLowerCase().includes(q);

    // Services worth drawing: reachable (or blocked, when asked) from some zone.
    const services = inp.services.filter(s => inp.zones.some(z => visible(inp.cell(s.id, z.id), o.showBlocked)));
    const zones = inp.zones;
    const ifaces = [...new Set(zones.map(z => z.iif))];

    const zy = (i: number) => 8 + i * T.STEP;
    const sy = (j: number) => 8 + j * T.STEP;
    const zc = (i: number) => zy(i) + T.NH / 2;
    const sc = (j: number) => sy(j) + T.NH / 2;

    // Interface ports: spread evenly down the host (in first-zone order), so
    // the fans to the services don't knot up in the middle.
    const iy: Record<string, number> = {};
    const span = Math.max(zy(zones.length), sy(services.length)) - 8;
    ifaces.forEach((n, k) => { iy[n] = 8 + span * (k + 0.5) / ifaces.length });
    const last = ifaces.length ? iy[ifaces[ifaces.length - 1]] : 0;

    const f = o.focus;
    const fz = f?.kind === "zone" ? f.id : null;
    const fs = f?.kind === "service" ? f.id : null;
    const fi = f?.kind === "iface" ? f.name : null;
    const lit = o.lit ?? null;

    const zIndex = new Map(zones.map((z, i) => [z.id, i]));
    const sIndex = new Map(services.map((s, j) => [s.id, j]));
    const seg1 = (zid: string) => {
        const i = zIndex.get(zid)!;
        return curve(T.ZW, zc(i), T.IX, iy[zones[i].iif]);
    };
    const seg2 = (iface: string, sid: string) => curve(T.IX + T.IW, iy[iface], T.SX, sc(sIndex.get(sid)!));

    const edges: TEdge[] = [];
    // (from/to are filled in below, once all edges exist)
    const isLit = (zid: string, sid: string) => !!lit && lit.zone === zid && lit.service === sid;

    if (fz) {
        const z = zones[zIndex.get(fz)!];
        edges.push({ id: `zp:${fz}`, d: seg1(fz), state: "neutral", title: `${z.label} arrives on ${z.iif}`, lit: !!lit && lit.zone === fz, action: null, from: "", to: "" });
        for (const s of services) {
            const st = inp.cell(s.id, fz);
            if (st === "none" || !(visible(st, o.showBlocked) || isLit(fz, s.id)) || !svcMatch(s)) continue;
            edges.push({ id: `ps:${z.iif}:${s.id}`, d: seg2(z.iif, s.id), state: st, title: `${s.name} from ${z.label}`, lit: isLit(fz, s.id), action: { kind: "trace", zone: fz, service: s.id }, from: "", to: "" });
        }
    } else if (fs && sIndex.has(fs)) {
        for (const n of ifaces) {
            const on = zones.filter(z => z.iif === n && inp.cell(fs, z.id) !== "none");
            const sts = on.map(z => inp.cell(fs, z.id)).filter(st => visible(st, o.showBlocked));
            if (!sts.length) continue;
            edges.push({ id: `ps:${n}:${fs}`, d: seg2(n, fs), state: aggregate(sts), title: `${services[sIndex.get(fs)!].name} via ${n}`, lit: false, action: { kind: "bundle", iface: n, service: fs }, from: "", to: "" });
            for (const z of on) {
                const st = inp.cell(fs, z.id);
                if (!visible(st, o.showBlocked)) continue;
                edges.push({ id: `zp:${z.id}`, d: seg1(z.id), state: st, title: `${services[sIndex.get(fs)!].name} from ${z.label}`, lit: isLit(z.id, fs), action: { kind: "trace", zone: z.id, service: fs }, from: "", to: "" });
            }
        }
    } else {
        for (const z of zones) {
            if ((fi && z.iif !== fi) || !zoneMatch(z)) continue;
            edges.push({ id: `zp:${z.id}`, d: seg1(z.id), state: "neutral", title: `Focus ${z.label}`, lit: !!lit && lit.zone === z.id, action: { kind: "focus", focus: { kind: "zone", id: z.id } }, from: "", to: "" });
        }
        for (const n of ifaces) {
            if (fi && fi !== n) continue;
            for (const s of services) {
                const sts = zones.filter(z => z.iif === n).map(z => inp.cell(s.id, z.id))
                        .filter(st => st !== "none");
                if (!sts.length) continue;
                const shown = sts.filter(st => visible(st, o.showBlocked));
                if (!shown.length) continue;
                const a = aggregate(shown);
                if (q && !(svcMatch(s) || ifaceMatch(n))) continue;
                const allowed = sts.filter(st => st === "allow").length;
                edges.push({
                    id: `ps:${n}:${s.id}`,
                    d: seg2(n, s.id),
                    state: a,
                    label: a === "partial" ? `${allowed}/${sts.length}` : undefined,
                    title: `${s.name} via ${n}`,
                    lit: !!lit && lit.service === s.id && zones[zIndex.get(lit.zone)!]?.iif === n,
                    action: { kind: "bundle", iface: n, service: s.id },
                    from: "",
                    to: "",
                });
            }
        }
    }

    for (const e of edges) {
        if (e.id.startsWith("zp:")) {
            const zid = e.id.slice(3);
            e.from = `z:${zid}`;
            e.to = `i:${zones[zIndex.get(zid)!].iif}`;
        } else {
            const rest = e.id.slice(3);
            const k = rest.indexOf(":");
            e.from = `i:${rest.slice(0, k)}`;
            e.to = `s:${rest.slice(k + 1)}`;
        }
    }

    // What stays bright: the focus/lit/query and whatever they connect to.
    const active = !!(f || lit || q);
    const brightZ = (z: Zone) => {
        if (lit) return lit.zone === z.id;
        if (fz) return fz === z.id;
        if (fi) return z.iif === fi;
        if (fs) return visible(inp.cell(fs, z.id), o.showBlocked);
        return zoneMatch(z);
    };
    const brightS = (s: Service) => {
        if (lit) return lit.service === s.id;
        if (fs) return fs === s.id;
        if (fz) return visible(inp.cell(s.id, fz), o.showBlocked);
        if (fi) return zones.some(z => z.iif === fi && visible(inp.cell(s.id, z.id), o.showBlocked));
        return svcMatch(s);
    };
    const brightI = (n: string) => {
        if (lit) return zones[zIndex.get(lit.zone)!]?.iif === n;
        if (fi) return fi === n;
        if (fz) return zones[zIndex.get(fz)!].iif === n;
        return !q || ifaceMatch(n) || edges.some(e => e.id.startsWith(`ps:${n}:`));
    };

    const nodes: TNode[] = [
        ...zones.map((z, i) => ({
            id: `z:${z.id}`,
            kind: "zone" as const,
            key: z.id,
            x: 0,
            y: zy(i),
            w: T.ZW,
            h: T.NH,
            label: z.label,
            detail: z.detail,
            dim: active && !brightZ(z),
            selected: fz === z.id,
        })),
        ...ifaces.map(n => {
            const z = zones.find(x => x.iif === n)!;
            return {
                id: `i:${n}`,
                kind: "iface" as const,
                key: n,
                x: T.IX,
                y: iy[n] - T.PH / 2,
                w: T.IW,
                h: T.PH,
                label: n,
                detail: z.daddr,
                dim: active && !brightI(n),
                selected: fi === n,
            };
        }),
        ...services.map((s, j) => ({
            id: `s:${s.id}`,
            kind: "service" as const,
            key: s.id,
            x: T.SX,
            y: sy(j),
            w: T.SW,
            h: T.NH,
            label: s.name,
            detail: `${s.proto} ${s.ports.length > 5 ? s.ports.slice(0, 5).join(", ") + " …" : s.ports.join(", ")}${s.bind !== "*" ? ` on ${s.bind}` : ""}${s.docker ? " · Docker" : ""}`,
            dim: active && !brightS(s),
            selected: fs === s.id,
        })),
    ];
    const height = Math.max(zy(zones.length), sy(services.length), last + T.PH) + 8;
    return { nodes, edges, width: T.SX + T.SW, height, host: { x: T.IX - 30, y: 0, w: T.IW + 60, h: height }, services };
}

/**
 * Edges to light up while a node is hovered or keyboard-focused:
 *   zone      -> its line to the interface + the bundles to services it reaches
 *   interface -> everything in and out of it
 *   service   -> the bundles into it + the zones that reach it
 */
export function hotEdges(edges: TEdge[], hover: string | null, inp: TopoInput, showBlocked: boolean): Set<string> {
    const hot = new Set<string>();
    if (!hover) return hot;
    const kind = hover.slice(0, 1);
    const key = hover.slice(2);
    for (const e of edges) {
        if (e.from === hover || e.to === hover) {
            hot.add(e.id);
            continue;
        }
        if (kind === "z" && e.id.startsWith("ps:")) {
            const z = inp.zones.find(x => x.id === key);
            if (z && e.from === `i:${z.iif}` && visible(inp.cell(e.to.slice(2), key), showBlocked)) hot.add(e.id);
        } else if (kind === "s" && e.id.startsWith("zp:")) {
            const zid = e.from.slice(2);
            if (visible(inp.cell(key, zid), showBlocked) && edges.some(x => x.from === e.to && x.to === hover)) hot.add(e.id);
        }
    }
    return hot;
}

/* ===================== rule graph ===================== */

export const HOOKS = ["prerouting", "input", "forward", "output", "postrouting"] as const;
export const DEFAULT_OPEN: Record<string, boolean> = { prerouting: true, input: true, forward: false, output: false, postrouting: false };

export type OwnerLabel = "config" | "docker" | "tailscale" | "fail2ban" | "iptables-nft" | "runtime";

export interface RNode {
    id: string;
    kind: "header" | "base" | "regular" | "collapsed";
    hook: string;
    x: number; y: number; w: number; h: number;
    key?: string; // "family table chain"
    title: string;
    sub?: string;
    owner?: OwnerLabel;
    policy?: string | null;
    rules?: number;
    sets?: string[];
    count?: number; // collapsed: number of base chains
    via?: string; // regular: jump / goto
}

export interface REdge {
    d: string;
    kind: "hook" | "jump";
    label?: string;
    from?: string;
    to?: string;
}

const NAMED_PRIO: Record<string, number> = { raw: -300, mangle: -150, dstnat: -100, filter: 0, security: 50, srcnat: 100 };

export function prioNum(p: string | null): number {
    if (!p) return 0;
    const m = /^(-?\d+)$/.exec(p.trim());
    if (m) return Number(m[1]);
    const n = /^(\w+)\s*([+-])\s*(\d+)$/.exec(p.trim());
    if (n && n[1] in NAMED_PRIO) return NAMED_PRIO[n[1]] + (n[2] === "-" ? -1 : 1) * Number(n[3]);
    return NAMED_PRIO[p.trim()] ?? 0;
}

export function ownerOf(t: Table, chainTags: string[]): OwnerLabel {
    if (chainTags.includes("Tailscale")) return "tailscale";
    if (chainTags.includes("Docker")) return "docker";
    if (chainTags.includes("fail2ban") || t.owner === "fail2ban") return "fail2ban";
    const o: Owner = t.owner;
    if (o === "config") return "config";
    if (o === "iptables-nft") return "iptables-nft";
    return "runtime";
}

const R = { CW: 260, COLLAPSED: 130, GAP: 70, HEAD: 36, BASE_H: 92, REG_H: 56, INDENT: 46, VGAP: 14, TOP: 60 };

export function ruleLayout(tables: Table[], open: Record<string, boolean>, families = ["ip", "inet"]) {
    const nodes: RNode[] = [];
    const edges: REdge[] = [];
    let x = 0;
    let maxY = 0;
    const colX: Record<string, { x: number; w: number }> = {};

    for (const hook of HOOKS) {
        const bases = tables
                .filter(t => families.includes(t.family))
                .flatMap(t => t.chains.filter(c => c.hook === hook).map(c => ({ t, c })))
                .sort((a, b) => prioNum(a.c.priority) - prioNum(b.c.priority));
        const isOpen = open[hook] ?? DEFAULT_OPEN[hook];
        const w = isOpen ? R.CW : R.COLLAPSED;
        colX[hook] = { x, w };
        nodes.push({ id: `h:${hook}`, kind: "header", hook, x, y: 0, w, h: R.HEAD, title: hook, count: bases.length });
        if (!isOpen) {
            nodes.push({ id: `c:${hook}`, kind: "collapsed", hook, x, y: R.TOP, w, h: 70, title: `${bases.length} base chain${bases.length === 1 ? "" : "s"}`, count: bases.length });
            maxY = Math.max(maxY, R.TOP + 70);
        } else {
            let y = R.TOP;
            const seen = new Set<string>();
            for (const { t, c } of bases) {
                const key = `${t.family} ${t.name} ${c.name}`;
                const sets = [...new Set(c.rules.flatMap(r => r.text.match(/@[\w-]+/g) ?? []))];
                nodes.push({
                    id: `b:${key}`,
                    kind: "base",
                    hook,
                    x,
                    y,
                    w,
                    h: R.BASE_H,
                    key,
                    title: `${t.family} ${t.name}`,
                    sub: c.name,
                    owner: ownerOf(t, c.tags),
                    policy: c.policy,
                    rules: c.rules.length,
                    sets,
                    via: c.priority ?? undefined,
                });
                const parentY = y;
                y += R.BASE_H + R.VGAP;
                // regular chains reached from this base chain (two levels deep)
                const walk = (chainName: string, depth: number, fromKey: string, fromX: number, fromY: number) => {
                    const ch = t.chains.find(cc => cc.name === chainName);
                    if (!ch) return;
                    for (const r of ch.rules) {
                        const m = /^(jump|goto) ([\w.-]+)$/.exec(r.verdict ?? "");
                        if (!m) continue;
                        const target = t.chains.find(cc => cc.name === m[2] && !cc.hook);
                        const tkey = `${t.family} ${t.name} ${m[2]}`;
                        if (!target || seen.has(tkey)) continue;
                        seen.add(tkey);
                        const cx = x + R.INDENT * depth;
                        nodes.push({
                            id: `r:${tkey}`,
                            kind: "regular",
                            hook,
                            x: cx,
                            y,
                            w: w - R.INDENT * depth,
                            h: R.REG_H,
                            key: tkey,
                            title: m[2],
                            sub: `${t.family} ${t.name}`,
                            owner: ownerOf(t, target.tags),
                            rules: target.rules.length,
                            via: m[1],
                        });
                        const ex = fromX + 12;
                        edges.push({ kind: "jump", d: `M${ex},${fromY} L${ex},${y + R.REG_H / 2} L${cx},${y + R.REG_H / 2}`, label: m[1], from: fromKey, to: tkey });
                        const ry = y;
                        y += R.REG_H + R.VGAP;
                        if (depth < 2) walk(m[2], depth + 1, tkey, cx, ry + R.REG_H);
                    }
                };
                walk(c.name, 1, key, x, parentY + R.BASE_H);
            }
            maxY = Math.max(maxY, y);
        }
        x += w + R.GAP;
    }

    // Hook arrows: prerouting -> input / forward, forward -> postrouting, output -> postrouting
    const arrow = (a: string, b: string, lane: number) => {
        const A = colX[a];
        const B = colX[b];
        const y = R.HEAD / 2;
        if (HOOKS.indexOf(b as typeof HOOKS[number]) === HOOKS.indexOf(a as typeof HOOKS[number]) + 1) {
            edges.push({ kind: "hook", d: `M${A.x + A.w},${y} L${B.x - 6},${y}`, from: a, to: b });
        } else {
            const top = -14 - lane * 12;
            edges.push({ kind: "hook", d: `M${A.x + A.w / 2},0 C${A.x + A.w / 2},${top} ${B.x + B.w / 2},${top} ${B.x + B.w / 2},-2`, from: a, to: b });
        }
    };
    arrow("prerouting", "input", 0);
    arrow("prerouting", "forward", 0);
    arrow("forward", "postrouting", 1);
    arrow("output", "postrouting", 0);

    return { nodes, edges, width: x - R.GAP, height: maxY + 8, top: -40 };
}
