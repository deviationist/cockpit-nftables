/*
 * SPDX-License-Identifier: LGPL-2.1-or-later
 *
 * Copyright (C) 2026 deviationist
 *
 * Line diff for the "review changes" view: a thin adapter over jsdiff
 * (npm `diff`, BSD-3), shaped for rendering with old/new line numbers.
 */

import { diffLines as jsDiffLines, structuredPatch } from 'diff';

export type DiffOp = "same" | "add" | "del";

export interface DiffLine {
    op: DiffOp;
    text: string;
    oldNo: number | null;
    newNo: number | null;
}

export interface Hunk {
    oldStart: number;
    newStart: number;
    lines: DiffLine[];
}

/** Hunks with `context` unchanged lines around each change. */
export function hunks(a: string, b: string, context = 3): Hunk[] {
    const patch = structuredPatch("a", "b", a, b, "", "", { context });
    return patch.hunks.map(h => {
        let o = h.oldStart;
        let n = h.newStart;
        const lines: DiffLine[] = [];
        for (const l of h.lines) {
            const sign = l[0];
            const text = l.slice(1);
            if (sign === "\\") continue; // "\ No newline at end of file"
            if (sign === "+") lines.push({ op: "add", text, oldNo: null, newNo: n++ });
            else if (sign === "-") lines.push({ op: "del", text, oldNo: o++, newNo: null });
            else lines.push({ op: "same", text, oldNo: o++, newNo: n++ });
        }
        return { oldStart: h.oldStart, newStart: h.newStart, lines };
    });
}

export function changeCount(a: string, b: string): { added: number; removed: number } {
    let added = 0;
    let removed = 0;
    for (const part of jsDiffLines(a, b)) {
        if (part.added) added += part.count ?? 0;
        else if (part.removed) removed += part.count ?? 0;
    }
    return { added, removed };
}
