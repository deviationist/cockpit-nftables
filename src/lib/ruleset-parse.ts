/*
 * SPDX-License-Identifier: LGPL-2.1-or-later
 *
 * Copyright (C) 2026 deviationist
 *
 * Pure parsing of `nft list ruleset` text into tables / chains / sets / rules,
 * plus ownership classification. Cockpit-free so it runs under `node --test`.
 *
 * We parse the TEXT listing on purpose: it is what an operator recognises, and
 * it is the only form that prints iptables-nft (xt) rules at all. The JSON
 * listing is better structured but we only display, never write back.
 */

export type Owner = "config" | "iptables-nft" | "fail2ban" | "other";

export interface Rule {
    text: string; // the rule as nft printed it
    handle: number | null; // kernel handle (from `nft -a`), joins text to JSON
    packets: number | null;
    bytes: number | null;
    comment: string | null;
    verdict: string | null; // accept / drop / reject / jump X / goto X / return / …
}

export interface Chain {
    name: string;
    type: string | null; // filter / nat / route
    hook: string | null; // input / forward / …
    priority: string | null;
    policy: string | null;
    rules: Rule[];
    tags: string[]; // who populated it (Docker, Tailscale, …)
}

export interface NamedObject {
    kind: string; // set / map / flowtable / counter / …
    name: string;
    body: string;
}

export interface Table {
    family: string;
    name: string;
    chains: Chain[];
    objects: NamedObject[];
    owner: Owner;
}

const OBJECT_KINDS = ["set", "map", "flowtable", "counter", "quota", "ct", "limit", "secmark", "synproxy"];

export function tableKey(family: string, name: string): string {
    return `${family} ${name}`;
}

/** Tables that nft warns are "managed by iptables-nft" (printed on stderr). */
export function parseIptablesManaged(stderr: string): Set<string> {
    const s = new Set<string>();
    const re = /table (\S+) (\S+) is managed by iptables-nft/g;
    let m: RegExpExecArray | null;
    while ((m = re.exec(stderr)) !== null)
        s.add(tableKey(m[1], m[2]));
    return s;
}

function parseRule(text: string): Rule {
    const counter = /counter packets (\d+) bytes (\d+)/.exec(text);
    const comment = /comment "((?:[^"\\]|\\.)*)"/.exec(text);
    // Quoted strings (comments, log prefixes) may contain verdict words.
    const xt = /xt target "(\w+)"/.exec(text);
    const bare = text.replace(/"(?:[^"\\]|\\.)*"/g, '""');
    const re = /\b(accept|drop|reject|return|queue|continue|(?:jump|goto) [\w.-]+|masquerade|snat to \S+|dnat to \S+|redirect(?: to \S+)?)(?=\s|$)/g;
    let verdict: string | null = null;
    let m: RegExpExecArray | null;
    while ((m = re.exec(bare)) !== null) verdict = m[1];
    if (xt) verdict = xt[1].toLowerCase();
    return {
        text,
        handle: null,
        packets: counter ? Number(counter[1]) : null,
        bytes: counter ? Number(counter[2]) : null,
        comment: comment ? comment[1] : null,
        verdict,
    };
}

function parseChainHeader(chain: Chain, line: string): boolean {
    const m = /^type (\w+) hook (\w+)(?: device [^ ]+)? priority ([^;]+);(?: policy (\w+);)?/.exec(line);
    if (!m) {
        const p = /^policy (\w+);$/.exec(line);
        if (p) {
            chain.policy = p[1];
            return true;
        }
        return false;
    }
    chain.type = m[1];
    chain.hook = m[2];
    chain.priority = m[3].trim();
    chain.policy = m[4] ?? null;
    return true;
}

/** Who populated a chain, judged by name. Purely a display hint. */
export function chainTags(name: string): string[] {
    if (/^DOCKER|^docker/.test(name)) return ["Docker"];
    if (/^ts-/.test(name)) return ["Tailscale"];
    if (/^f2b-/.test(name)) return ["fail2ban"];
    if (/^ufw/.test(name)) return ["ufw"];
    if (/^LIBVIRT/.test(name)) return ["libvirt"];
    if (/^KUBE-|^cali-|^cilium/.test(name)) return ["Kubernetes"];
    return [];
}

/**
 * Parse `nft list ruleset` text. Tolerant: unknown lines inside a chain become
 * rules, unknown blocks inside a table become named objects.
 */
export function parseRuleset(text: string): Table[] {
    const tables: Table[] = [];
    const lines = text.split("\n");
    let table: Table | null = null;
    let chain: Chain | null = null;
    let obj: NamedObject | null = null;
    let objDepth = 0;

    for (const raw of lines) {
        let line = raw.trim();
        if (!line || line.startsWith("#")) continue;
        // `nft -a` appends "# handle N" to tables, chains and rules.
        const hm = / # handle (\d+)$/.exec(line);
        const handle = hm ? Number(hm[1]) : null;
        if (hm) line = line.slice(0, hm.index);

        if (obj) {
            // inside a set/map/…: collect until its closing brace
            objDepth += (line.match(/{/g) || []).length - (line.match(/}/g) || []).length;
            if (objDepth <= 0) {
                obj = null;
                continue;
            }
            obj.body += (obj.body ? "\n" : "") + line;
            continue;
        }

        if (!table) {
            const t = /^table (\S+) (\S+) \{$/.exec(line);
            if (t) table = { family: t[1], name: t[2], chains: [], objects: [], owner: "other" };
            continue;
        }

        if (!chain) {
            if (line === "}") {
                tables.push(table);
                table = null;
                continue;
            }
            const c = /^chain (\S+) \{$/.exec(line);
            if (c) {
                chain = { name: c[1], type: null, hook: null, priority: null, policy: null, rules: [], tags: chainTags(c[1]) };
                continue;
            }
            const o = /^(\w+) (\S+) \{$/.exec(line);
            if (o && OBJECT_KINDS.includes(o[1])) {
                obj = { kind: o[1], name: o[2], body: "" };
                objDepth = 1;
                table.objects.push(obj);
                continue;
            }
            // table-level attribute (flags, comment) — ignore
            continue;
        }

        if (line === "}") {
            table.chains.push(chain);
            chain = null;
            continue;
        }
        if (parseChainHeader(chain, line)) continue;
        if (/^comment "/.test(line)) continue; // chain comment
        chain.rules.push({ ...parseRule(line), handle });
    }
    return tables;
}

/**
 * Who owns each table:
 *  - "config": declared in the config file → editable here
 *  - "iptables-nft": nft says iptables-nft manages it (Docker, Tailscale, …)
 *  - "fail2ban": fail2ban's nftables action table
 *  - "other": written by something else at runtime
 */
export function classify(tables: Table[], configTables: Set<string>, iptablesManaged: Set<string>): Table[] {
    return tables.map(t => {
        const key = tableKey(t.family, t.name);
        let owner: Owner = "other";
        if (configTables.has(key)) owner = "config";
        else if (iptablesManaged.has(key)) owner = "iptables-nft";
        else if (/^f2b-/.test(t.name)) owner = "fail2ban";
        return { ...t, owner };
    });
}

/** Distinct chain tags in a table, for the table header. */
export function tableTags(t: Table): string[] {
    const s = new Set<string>();
    for (const c of t.chains) for (const tag of c.tags) s.add(tag);
    return [...s].sort();
}

export function formatCount(n: number | null): string {
    if (n === null) return "";
    if (n < 1000) return String(n);
    const units = ["K", "M", "G", "T"];
    let v = n;
    let i = -1;
    while (v >= 1000 && i < units.length - 1) {
        v /= 1000;
        i++;
    }
    return `${v.toFixed(v < 10 ? 1 : 0)}${units[i]}`;
}

/* ---- `nft -j list ruleset` overlay ----
 * The official JSON (libnftables-json(5)) is the authority for structure:
 * chain type/hook/priority/policy and per-rule counters, comment and verdict.
 * The text listing stays the display form. Rules are joined by handle.
 */

type JsonObj = Record<string, unknown>;

const VERDICTS = ["accept", "drop", "reject", "return", "continue", "queue", "masquerade", "snat", "dnat", "redirect"];

function jsonVerdict(expr: JsonObj[]): string | null {
    let v: string | null = null;
    for (const e of expr) {
        const k = Object.keys(e)[0];
        const val = e[k] as JsonObj | null;
        if (k === "jump" || k === "goto") v = `${k} ${(val as JsonObj).target}`;
        else if (k === "xt" && (val as JsonObj).type === "target") v = String((val as JsonObj).name).toLowerCase();
        else if (VERDICTS.includes(k)) v = k;
    }
    return v;
}

export function overlayJson(tables: Table[], json: string): Table[] {
    let items: JsonObj[];
    try {
        items = (JSON.parse(json) as { nftables: JsonObj[] }).nftables;
    } catch {
        return tables; // fall back to what the text parser found
    }
    const chains = new Map<string, JsonObj>();
    const rules = new Map<string, JsonObj>();
    for (const it of items) {
        if (it.chain) {
            const c = it.chain as JsonObj;
            chains.set(`${c.family} ${c.table} ${c.name}`, c);
        } else if (it.rule) {
            const r = it.rule as JsonObj;
            rules.set(`${r.family} ${r.table} ${r.handle}`, r);
        }
    }
    return tables.map(t => ({
        ...t,
        chains: t.chains.map(c => {
            const jc = chains.get(`${t.family} ${t.name} ${c.name}`);
            const chain: Chain = jc
                ? {
                    ...c,
                    type: (jc.type as string) ?? null,
                    hook: (jc.hook as string) ?? null,
                    // keep the symbolic text form ("filter", "dstnat") when there is one
                    priority: c.priority ?? (jc.prio !== undefined ? String(jc.prio) : null),
                    policy: (jc.policy as string) ?? null,
                }
                : c;
            chain.rules = c.rules.map(r => {
                const jr = r.handle !== null ? rules.get(`${t.family} ${t.name} ${r.handle}`) : undefined;
                if (!jr) return r;
                const expr = (jr.expr as JsonObj[]) ?? [];
                const counter = expr.find(e => "counter" in e)?.counter as { packets: number; bytes: number } | undefined;
                return {
                    ...r,
                    packets: counter ? counter.packets : null,
                    bytes: counter ? counter.bytes : null,
                    comment: (jr.comment as string) ?? null,
                    verdict: jsonVerdict(expr),
                };
            });
            return chain;
        }),
    }));
}
