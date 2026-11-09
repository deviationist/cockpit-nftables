/*
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

import assert from 'node:assert/strict';
import { test } from 'node:test';

import { changeCount, hunks } from './diff.ts';

const lines = (n: number) => Array.from({ length: n }, (_, i) => `l${i + 1}`).join("\n") + "\n";

test('identical text has no hunks', () => {
    assert.deepEqual(hunks("a\nb\n", "a\nb\n"), []);
});

test('single change with context and line numbers', () => {
    const a = lines(20);
    const b = a.replace("l10\n", "L10\n");
    assert.deepEqual(changeCount(a, b), { added: 1, removed: 1 });
    const h = hunks(a, b, 2);
    assert.equal(h.length, 1);
    assert.equal(h[0].oldStart, 8);
    assert.deepEqual(h[0].lines.map(l => l.op), ["same", "same", "del", "add", "same", "same"]);
    assert.deepEqual(h[0].lines.map(l => [l.oldNo, l.newNo]), [[8, 8], [9, 9], [10, null], [null, 10], [11, 11], [12, 12]]);
});

test('distant changes make two hunks, close ones merge', () => {
    const a = lines(30);
    assert.equal(hunks(a, a.replace("l3\n", "x\n").replace("l25\n", "y\n"), 3).length, 2);
    assert.equal(hunks(a, a.replace("l3\n", "x\n").replace("l7\n", "y\n"), 3).length, 1);
});

test('pure insert and delete', () => {
    assert.deepEqual(changeCount("a\nc\n", "a\nb\nc\n"), { added: 1, removed: 0 });
    assert.deepEqual(changeCount("a\nb\nc\n", "a\nc\n"), { added: 0, removed: 1 });
});
