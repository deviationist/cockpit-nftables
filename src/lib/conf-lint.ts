/*
 * SPDX-License-Identifier: LGPL-2.1-or-later
 *
 * Copyright (C) 2026 deviationist
 *
 * Pure checks on a candidate /etc/nftables.conf, run before `nft -c`.
 * nft -c answers "is this valid nftables?"; these answer "is it safe to apply
 * here, and will undo work?". Cockpit-free so it runs under `node --test`.
 */

import { tableKey } from './ruleset-parse.ts';

export type Severity = "danger" | "warning" | "info";

export interface Finding {
    severity: Severity;
    message: string;
    line?: number; // 1-based line in the candidate
}

export interface DeclaredTable {
    family: string;
    name: string;
    line: number;
}

const FAMILIES = ["ip", "ip6", "inet", "arp", "bridge", "netdev"];

/** Strip a `#` comment, ignoring `#` inside double quotes. */
export function stripComment(line: string): string {
    let inQ = false;
    for (let i = 0; i < line.length; i++) {
        const c = line[i];
        if (c === '"' && line[i - 1] !== "\\") inQ = !inQ;
        else if (c === "#" && !inQ) return line.slice(0, i);
    }
    return line;
}

function codeLines(text: string): string[] {
    return text.split("\n").map(l => stripComment(l));
}

function famName(a: string, b?: string): [string, string] {
    // `table inet filter` or `table filter` (family defaults to ip)
    return b !== undefined && FAMILIES.includes(a) ? [a, b] : ["ip", a];
}

/** Tables the file defines with a body: `table <fam> <name> {`. */
export function declaredTables(text: string): DeclaredTable[] {
    const res: DeclaredTable[] = [];
    const seen = new Set<string>();
    codeLines(text).forEach((l, i) => {
        const m = /^\s*(?:add\s+)?table\s+(\S+)(?:\s+(\S+))?\s*\{/.exec(l);
        if (!m) return;
        const [family, name] = famName(m[1], m[2] === "{" ? undefined : m[2]);
        const key = tableKey(family, name);
        if (seen.has(key)) return;
        seen.add(key);
        res.push({ family, name, line: i + 1 });
    });
    return res;
}

/** Tables the file resets before defining: `delete table X` / `flush table X`. */
function resetTables(text: string): Map<string, number> {
    const res = new Map<string, number>();
    codeLines(text).forEach((l, i) => {
        const m = /^\s*(?:delete|destroy|flush)\s+table\s+(\S+)(?:\s+(\S+))?\s*;?\s*$/.exec(l);
        if (!m) return;
        const [family, name] = famName(m[1], m[2]);
        const key = tableKey(family, name);
        if (!res.has(key)) res.set(key, i + 1);
    });
    return res;
}

export function tableSet(tables: DeclaredTable[]): Set<string> {
    return new Set(tables.map(t => tableKey(t.family, t.name)));
}

/** Tables in `next` that `current` doesn't declare: undo must delete them. */
export function addedTables(current: string, next: string): [string, string][] {
    const cur = tableSet(declaredTables(current));
    return declaredTables(next)
            .filter(t => !cur.has(tableKey(t.family, t.name)))
            .map(t => [t.family, t.name]);
}

export interface LintOptions {
    /** live tables owned by something else (iptables-nft, fail2ban, …) */
    foreignTables?: Set<string>;
    /** TCP port(s) that must stay reachable (default: 22) */
    mustAllowTcp?: number[];
}

export function lint(current: string, next: string, opts: LintOptions = {}): Finding[] {
    const f: Finding[] = [];
    const lines = codeLines(next);

    lines.forEach((l, i) => {
        if (/^\s*flush\s+ruleset\b/.test(l))
            f.push({
                severity: "danger",
                line: i + 1,
                message: "`flush ruleset` wipes every table on reload, including Docker's, Tailscale's and fail2ban's. Reset only your own tables with `delete table <family> <name>` instead.",
            });
        if (/^\s*include\s+"/.test(l))
            f.push({
                severity: "info",
                line: i + 1,
                message: "Included files are loaded, but not backed up or restored by undo. Only this file is.",
            });
    });

    const decl = declaredTables(next);
    const reset = resetTables(next);
    for (const t of decl) {
        const key = tableKey(t.family, t.name);
        const r = reset.get(key);
        if (r === undefined || r > t.line)
            f.push({
                severity: "warning",
                line: t.line,
                message: `table ${key} is not reset before it is defined. Reloading the file adds its rules a second time, and undo can't restore it cleanly. Put \`table ${key}\` + \`delete table ${key}\` above it.`,
            });
        if (opts.foreignTables?.has(key))
            f.push({
                severity: "danger",
                line: t.line,
                message: `table ${key} is managed by another program (iptables-nft, fail2ban …). Writing it from this file will fight that program.`,
            });
    }

    const cur = tableSet(declaredTables(current));
    const nxt = tableSet(decl);
    for (const k of cur)
        if (!nxt.has(k))
            f.push({
                severity: "warning",
                message: `table ${k} is no longer in the file, but applying won't remove it from the kernel. It stays loaded until \`nft delete table ${k}\` or a reboot.`,
            });
    for (const k of nxt)
        if (!cur.has(k))
            f.push({ severity: "info", message: `table ${k} is new. Undo deletes it again.` });

    // Lockout heuristic: the file should still accept the management port(s).
    const ports = opts.mustAllowTcp ?? [22];
    const body = lines.join("\n");
    for (const p of ports) {
        const re = new RegExp(`tcp dport (?:\\{[^}]*\\b${p}\\b[^}]*\\}|${p}\\b)[^\\n]*\\baccept\\b`);
        if (!re.test(body) && /policy drop/.test(body))
            f.push({
                severity: "warning",
                message: `No rule accepts TCP port ${p}, and a chain has policy drop. If that's your SSH or Cockpit port, applying may lock you out (undo still runs after the timeout).`,
            });
    }
    return f;
}

export function worst(findings: Finding[]): Severity | null {
    if (findings.some(x => x.severity === "danger")) return "danger";
    if (findings.some(x => x.severity === "warning")) return "warning";
    if (findings.length) return "info";
    return null;
}
