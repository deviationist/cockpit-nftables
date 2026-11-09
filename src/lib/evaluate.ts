/*
 * SPDX-License-Identifier: LGPL-2.1-or-later
 *
 * Copyright (C) 2026 deviationist
 *
 * A small, honest packet evaluator over `nft -j list ruleset`: walk one IPv4
 * test packet through every base chain on its path (prerouting, then input),
 * in priority order across ALL tables, following jumps/gotos, and report the
 * outcome with the rule that decided it in each chain.
 *
 * Honest = anything it can't evaluate (xt matches/targets from iptables-nft,
 * maps, unknown expressions) makes the result "unknown" with the reason,
 * never a guess. Pure + Cockpit-free so it runs under `node --test`.
 */

type J = Record<string, unknown>;

export interface Packet {
    iif: string;
    saddr: string;
    daddr: string;
    proto: "tcp" | "udp";
    dport: number;
    sport?: number;
}

export type Outcome = "accept" | "drop" | "dnat" | "unknown";

export interface Step {
    hook: string;
    family: string;
    table: string;
    chain: string;
    rule: number | null; // 1-based index in the chain; null = chain policy / end
    handle: number | null;
    verdict: string; // accept / drop / jump X / policy drop / …
    note?: string;
}

export interface Trace {
    outcome: Outcome;
    steps: Step[];
    reason?: string; // why "unknown"
}

interface JChain { family: string; table: string; name: string; type?: string; hook?: string; prio?: number | string; policy?: string }
interface JRule { family: string; table: string; chain: string; handle: number; expr: J[] }
interface JSet { family: string; table: string; name: string; elem?: unknown[] }

export interface Model {
    chains: Map<string, JChain>;
    rules: Map<string, JRule[]>;
    sets: Map<string, JSet>;
    hostIps: Set<string>;
}

const key = (family: string, table: string, name: string) => `${family} ${table} ${name}`;

export function buildModel(json: string, hostIps: string[] = []): Model {
    const m: Model = { chains: new Map(), rules: new Map(), sets: new Map(), hostIps: new Set(hostIps) };
    let items: J[] = [];
    try {
        items = (JSON.parse(json) as { nftables: J[] }).nftables ?? [];
    } catch {
        return m;
    }
    for (const it of items) {
        if (it.chain) {
            const c = it.chain as JChain;
            m.chains.set(key(c.family, c.table, c.name), c);
        } else if (it.rule) {
            const r = it.rule as JRule;
            const k = key(r.family, r.table, r.chain);
            if (!m.rules.has(k)) m.rules.set(k, []);
            m.rules.get(k)!.push(r);
        } else if (it.set || it.map) {
            const s = (it.set ?? it.map) as JSet;
            m.sets.set(key(s.family, s.table, s.name), s);
        }
    }
    return m;
}

/* ---- IPv4 helpers ---- */

export function ip4(s: string): number | null {
    const m = /^(\d+)\.(\d+)\.(\d+)\.(\d+)$/.exec(s);
    if (!m) return null;
    const p = m.slice(1).map(Number);
    if (p.some(x => x > 255)) return null;
    return ((p[0] << 24) >>> 0) + (p[1] << 16) + (p[2] << 8) + p[3];
}

export function inPrefix(ip: string, addr: string, len: number): boolean {
    const a = ip4(ip);
    const b = ip4(addr);
    if (a === null || b === null) return false;
    if (len === 0) return true;
    const mask = len === 32 ? 0xffffffff : (~((1 << (32 - len)) - 1)) >>> 0;
    return ((a & mask) >>> 0) === ((b & mask) >>> 0);
}

/* ---- values ---- */

type LV =
    | { k: "ip"; v: string }
    | { k: "num"; v: number }
    | { k: "str"; v: string }
    | { k: "flags"; v: string[] }
    | { k: "absent" }
    | { k: "unknown"; why: string };

const PROTO: Record<string, number> = { tcp: 6, udp: 17, icmp: 1, icmpv6: 58, sctp: 132 };
const SERVICES: Record<string, number> = { ssh: 22, http: 80, https: 443, domain: 53, smtp: 25, ntp: 123 };

interface Ctx {
    pkt: Packet;
    mark: number;
    markTainted: string | null; // set when an xt target may have changed the mark
    model: Model;
    family: string;
    table: string;
}

function evalExpr(e: unknown, ctx: Ctx): LV {
    if (typeof e === "number") return { k: "num", v: e };
    if (typeof e === "string") return { k: "str", v: e };
    if (!e || typeof e !== "object") return { k: "unknown", why: "empty expression" };
    const o = e as J;
    const kind = Object.keys(o)[0];
    const v = o[kind] as J;
    const pkt = ctx.pkt;
    switch (kind) {
    case "payload": {
        const proto = v.protocol as string;
        const field = v.field as string;
        if (proto === "ip") {
            if (field === "saddr") return { k: "ip", v: pkt.saddr };
            if (field === "daddr") return { k: "ip", v: pkt.daddr };
            if (field === "protocol") return { k: "num", v: PROTO[pkt.proto] };
            if (field === "hdrlength") return { k: "num", v: 5 }; // no IP options
            return { k: "unknown", why: `ip ${field}` };
        }
        if (proto === "ip6") return { k: "absent" }; // IPv4 packet
        if (proto === "tcp" || proto === "udp" || proto === "th") {
            if (proto !== "th" && proto !== pkt.proto) return { k: "absent" };
            if (field === "dport") return { k: "num", v: pkt.dport };
            if (field === "sport") return { k: "num", v: pkt.sport ?? 40000 };
            return { k: "unknown", why: `${proto} ${field}` };
        }
        if (proto === "icmp" || proto === "icmpv6" || proto === "sctp") return { k: "absent" };
        return { k: "unknown", why: `payload ${proto} ${field}` };
    }
    case "meta": {
        const k = v.key as string;
        if (k === "iifname" || k === "iif") return { k: "str", v: pkt.iif };
        if (k === "oifname" || k === "oif") return { k: "str", v: "" }; // none on prerouting/input
        if (k === "l4proto") return { k: "num", v: PROTO[pkt.proto] };
        if (k === "nfproto") return { k: "str", v: "ipv4" };
        if (k === "protocol") return { k: "str", v: "ip" };
        if (k === "mark") return ctx.markTainted ? { k: "unknown", why: ctx.markTainted } : { k: "num", v: ctx.mark };
        if (k === "pkttype") return { k: "str", v: "host" };
        return { k: "unknown", why: `meta ${k}` };
    }
    case "ct": {
        const k = v.key as string;
        if (k === "state") return { k: "flags", v: ["new"] };
        if (k === "mark") return { k: "num", v: 0 };
        if (k === "direction") return { k: "str", v: "original" };
        return { k: "unknown", why: `ct ${k}` };
    }
    case "fib": {
        const flags = (v.flags as string[]) ?? [];
        if (v.result === "type" && flags.includes("daddr"))
            return { k: "str", v: ctx.model.hostIps.has(pkt.daddr) ? "local" : "unicast" };
        return { k: "unknown", why: "fib lookup" };
    }
    case "&": case "|": case "^": {
        const [a, b] = (v as unknown as unknown[]).map(x => evalExpr(x, ctx));
        if (a.k === "unknown") return a;
        if (b.k === "unknown") return b;
        if (a.k !== "num" || b.k !== "num") return { k: "unknown", why: `bitwise ${kind}` };
        const r = kind === "&" ? a.v & b.v : kind === "|" ? a.v | b.v : a.v ^ b.v;
        return { k: "num", v: r >>> 0 };
    }
    default:
        return { k: "unknown", why: kind };
    }
}

type RightEl = { t: "val"; v: string | number } | { t: "prefix"; addr: string; len: number } | { t: "range"; a: string | number; b: string | number };

function rightElements(r: unknown, ctx: Ctx): RightEl[] | "unknown" {
    const one = (x: unknown): RightEl[] | "unknown" => {
        if (typeof x === "number" || typeof x === "string") return [{ t: "val", v: x }];
        if (x && typeof x === "object") {
            const o = x as J;
            if (o.prefix) {
                const p = o.prefix as { addr: string; len: number };
                return [{ t: "prefix", addr: p.addr, len: p.len }];
            }
            if (o.range) {
                const [a, b] = o.range as [string | number, string | number];
                return [{ t: "range", a, b }];
            }
            if (o.elem) return one((o.elem as J).val);
            if (o.set) return many(o.set as unknown[]);
        }
        return "unknown";
    };
    const many = (xs: unknown[]): RightEl[] | "unknown" => {
        const out: RightEl[] = [];
        for (const x of xs) {
            const r = one(x);
            if (r === "unknown") return r;
            out.push(...r);
        }
        return out;
    };
    if (typeof r === "string" && r.startsWith("@")) {
        const s = ctx.model.sets.get(key(ctx.family, ctx.table, r.slice(1)));
        if (!s) return "unknown";
        return many(s.elem ?? []);
    }
    if (Array.isArray(r)) return many(r);
    return one(r);
}

function toNum(x: string | number): number | null {
    if (typeof x === "number") return x;
    if (x in PROTO) return PROTO[x];
    if (x in SERVICES) return SERVICES[x];
    const n = Number(x);
    return Number.isFinite(n) ? n : null;
}

function glob(name: string, pat: string): boolean {
    return pat.endsWith("*") ? name.startsWith(pat.slice(0, -1)) : name === pat;
}

function elMatches(lv: LV, el: RightEl): boolean | "unknown" {
    if (lv.k === "ip") {
        if (el.t === "prefix") return inPrefix(lv.v, el.addr, el.len);
        if (el.t === "range") {
            const a = ip4(String(el.a));
            const b = ip4(String(el.b));
            const x = ip4(lv.v);
            return a !== null && b !== null && x !== null && x >= a && x <= b;
        }
        return String(el.v) === lv.v;
    }
    if (lv.k === "num") {
        if (el.t === "range") {
            const a = toNum(el.a);
            const b = toNum(el.b);
            return a !== null && b !== null && lv.v >= a && lv.v <= b;
        }
        if (el.t === "val") {
            const n = toNum(el.v);
            return n === null ? "unknown" : n === lv.v;
        }
        return "unknown";
    }
    if (lv.k === "str") return el.t === "val" ? glob(lv.v, String(el.v)) : "unknown";
    if (lv.k === "flags") return el.t === "val" ? lv.v.includes(String(el.v)) : "unknown";
    return "unknown";
}

/** true / false / "unknown: why" */
function evalMatch(m: J, ctx: Ctx): true | false | string {
    const op = m.op as string;
    const lv = evalExpr(m.left, ctx);
    if (lv.k === "unknown") return lv.why;
    if (lv.k === "absent") return false; // e.g. tcp dport on a UDP packet: nft's implicit dependency fails
    if ((op === "<" || op === ">" || op === "<=" || op === ">=") && lv.k === "num") {
        const r = toNum(m.right as number);
        if (r === null) return "comparison";
        return op === "<" ? lv.v < r : op === ">" ? lv.v > r : op === "<=" ? lv.v <= r : lv.v >= r;
    }
    const els = rightElements(m.right, ctx);
    if (els === "unknown") return "set or value";
    let hit: boolean | "unknown" = false;
    for (const el of els) {
        const r = elMatches(lv, el);
        if (r === true) {
            hit = true;
            break;
        }
        if (r === "unknown") hit = "unknown";
    }
    if (hit === "unknown") return "value comparison";
    if (op === "==" || op === "in") return hit;
    if (op === "!=") return !hit;
    return `operator ${op}`;
}

/* ---- chains ---- */

type ChainResult =
    | { k: "accept" | "drop" | "dnat" | "return" | "fall" }
    | { k: "unknown"; why: string };

const MAX_DEPTH = 16;

// iptables targets that never decide the packet's fate: evaluation continues.
// MARK / CONNMARK may change the mark, so later mark matches become unknown.
const XT_NONTERMINAL = new Set(["CONNMARK", "MARK", "LOG", "NFLOG", "ULOG", "TCPMSS", "CT", "NOTRACK", "DSCP", "TOS",
    "CHECKSUM", "CLASSIFY", "TRACE", "AUDIT", "SET", "TTL", "HL", "CONNSECMARK", "SECMARK", "IDLETIMER", "LED", "RATEEST"]);
const XT_MARKING = new Set(["CONNMARK", "MARK"]);

function ruleVerdict(e: J): { v: string; target?: string } | null {
    const k = Object.keys(e)[0];
    if (k === "accept" || k === "drop" || k === "return" || k === "continue" || k === "queue") return { v: k };
    if (k === "reject") return { v: "drop" };
    if (k === "jump" || k === "goto") return { v: k, target: (e[k] as J).target as string };
    if (k === "dnat" || k === "redirect") return { v: "dnat" };
    if (k === "snat" || k === "masquerade") return { v: "nat-src" };
    if (k === "xt" && (e.xt as J).type === "target") return { v: "xt", target: (e.xt as J).name as string };
    if (k === "vmap") return { v: "vmap" };
    return null;
}

function runChain(chainKey: string, hook: string, ctx: Ctx, steps: Step[], depth: number): ChainResult {
    if (depth > MAX_DEPTH) return { k: "unknown", why: "jump depth" };
    const chain = ctx.model.chains.get(chainKey);
    const rules = ctx.model.rules.get(chainKey) ?? [];
    const base = { hook, family: chain?.family ?? "", table: chain?.table ?? "", chain: chain?.name ?? chainKey };

    for (let i = 0; i < rules.length; i++) {
        const r = rules[i];
        let unknown: string | null = null;
        let matched = true;
        let verdict: { v: string; target?: string } | null = null;
        for (const e of r.expr) {
            const k = Object.keys(e)[0];
            if (k === "match") {
                const res = evalMatch(e.match as J, ctx);
                if (res === false) {
                    matched = false;
                    break;
                }
                if (res !== true && !unknown) unknown = res;
                continue;
            }
            if (k === "xt" && (e.xt as J).type === "match") {
                if (!unknown) unknown = `xt match ${(e.xt as J).name}`;
                continue;
            }
            if (k === "mangle") {
                const mg = e.mangle as J;
                const isMark = JSON.stringify(mg.key) === JSON.stringify({ meta: { key: "mark" } });
                if (isMark && !unknown) {
                    const val = evalExpr(mg.value, ctx);
                    if (val.k === "num") ctx.mark = val.v;
                    else unknown = "mark expression";
                }
                continue;
            }
            const vd = ruleVerdict(e);
            if (vd) {
                verdict = vd;
                break;
            }
            // counter / log / limit / notrack / comment …: no effect on the verdict
        }
        if (!matched || !verdict) continue;
        if (verdict.v === "xt" && XT_NONTERMINAL.has(verdict.target!)) {
            if (XT_MARKING.has(verdict.target!) && !ctx.markTainted)
                ctx.markTainted = `mark may be set by xt ${verdict.target} (${base.table} ${base.chain})`;
            continue;
        }
        const at = { ...base, rule: i + 1, handle: r.handle };
        if (unknown && verdict.v === "jump") {
            // Condition unknown: follow the jump anyway. If the target chain
            // doesn't decide this packet, the outcome is the same either way.
            const before = steps.length;
            const markBefore = ctx.mark;
            const sub = runChain(key(base.family, base.table, verdict.target!), hook, ctx, steps, depth + 1);
            if (sub.k === "fall" || sub.k === "return") {
                steps.splice(before);
                steps.push({ ...at, verdict: `jump ${verdict.target}`, note: `condition unknown (${unknown}), but ${verdict.target} doesn't decide this packet either way` });
                if (ctx.mark !== markBefore && !ctx.markTainted) ctx.markTainted = `mark may be set in ${verdict.target} (condition unknown)`;
                continue;
            }
            steps.push({ ...at, verdict: `jump ${verdict.target}`, note: `can't evaluate: ${unknown}` });
            return { k: "unknown", why: unknown };
        }
        if (unknown) {
            steps.push({ ...at, verdict: verdict.target ? `${verdict.v} ${verdict.target}` : verdict.v, note: `can't evaluate: ${unknown}` });
            return { k: "unknown", why: unknown };
        }
        switch (verdict.v) {
        case "accept":
        case "drop":
        case "dnat":
            steps.push({ ...at, verdict: verdict.v === "dnat" ? "dnat (forwarded)" : verdict.v });
            return { k: verdict.v as "accept" | "drop" | "dnat" };
        case "return":
            steps.push({ ...at, verdict: "return" });
            return { k: "return" };
        case "continue":
        case "nat-src":
            continue;
        case "jump":
        case "goto": {
            steps.push({ ...at, verdict: `${verdict.v} ${verdict.target}` });
            const sub = runChain(key(base.family, base.table, verdict.target!), hook, ctx, steps, depth + 1);
            if (sub.k === "accept" || sub.k === "drop" || sub.k === "dnat" || sub.k === "unknown") return sub;
            if (verdict.v === "goto") return { k: "return" };
            continue;
        }
        default:
            steps.push({ ...at, verdict: verdict.target ? `${verdict.v} ${verdict.target}` : verdict.v, note: "can't evaluate this verdict" });
            return { k: "unknown", why: verdict.target ? `${verdict.v} ${verdict.target}` : verdict.v };
        }
    }
    return { k: "fall" };
}

function prio(c: JChain): number {
    if (typeof c.prio === "number") return c.prio;
    const named: Record<string, number> = { raw: -300, mangle: -150, dstnat: -100, filter: 0, security: 50, srcnat: 100 };
    return named[String(c.prio)] ?? 0;
}

/** Base chains on a hook for an IPv4 packet, in the order the kernel runs them. */
export function baseChains(model: Model, hook: string): JChain[] {
    return [...model.chains.values()]
            .filter(c => c.hook === hook && (c.family === "ip" || c.family === "inet"))
            .sort((a, b) => prio(a) - prio(b));
}

export function evaluate(model: Model, pkt: Packet, hooks: string[] = ["prerouting", "input"]): Trace {
    const steps: Step[] = [];
    const ctx: Ctx = { pkt, mark: 0, markTainted: null, model, family: "", table: "" };
    for (const hook of hooks) {
        for (const c of baseChains(model, hook)) {
            ctx.family = c.family;
            ctx.table = c.table;
            const res = runChain(key(c.family, c.table, c.name), hook, ctx, steps, 0);
            if (res.k === "unknown") return { outcome: "unknown", steps, reason: res.why };
            if (res.k === "drop") return { outcome: "drop", steps };
            if (res.k === "dnat") return { outcome: "dnat", steps };
            if (res.k === "fall" || res.k === "return") {
                const policy = c.policy ?? "accept";
                steps.push({ hook, family: c.family, table: c.table, chain: c.name, rule: null, handle: null, verdict: `policy ${policy}` });
                if (policy === "drop") return { outcome: "drop", steps };
            }
            // accept: this base chain is done; the next one still runs
        }
    }
    return { outcome: "accept", steps };
}
