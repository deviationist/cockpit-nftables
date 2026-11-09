/*
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

import assert from 'node:assert/strict';
import { test } from 'node:test';

import { addedTables, declaredTables, lint, stripComment, worst } from './conf-lint.ts';

const GOOD = `#!/usr/sbin/nft -f
# a comment with table inet nope {
table inet filter
delete table inet filter
table inet filter {
    chain input {
        type filter hook input priority filter; policy drop;
        tcp dport 22 accept comment "ssh # not a comment"
    }
}
table ip cve_stopgap
delete table ip cve_stopgap
table ip cve_stopgap {
  chain pre { type filter hook prerouting priority -300; policy accept; }
}
`;

test('stripComment keeps # inside quotes', () => {
    assert.equal(stripComment('accept comment "a # b" # real'), 'accept comment "a # b" ');
});

test('declaredTables ignores comments and bodiless declarations', () => {
    assert.deepEqual(declaredTables(GOOD).map(t => `${t.family} ${t.name}@${t.line}`),
                     ["inet filter@5", "ip cve_stopgap@13"]);
});

test('declaredTables defaults the family to ip', () => {
    assert.deepEqual(declaredTables("table foo {\n}").map(t => t.family), ["ip"]);
});

test('clean config has no findings', () => {
    assert.deepEqual(lint(GOOD, GOOD), []);
    assert.equal(worst([]), null);
});

test('flush ruleset is danger', () => {
    const f = lint(GOOD, "flush ruleset\n" + GOOD);
    assert.equal(worst(f), "danger");
    assert.equal(f[0].line, 1);
});

test('table without reset warns', () => {
    const next = GOOD.replace("delete table inet filter\n", "");
    const f = lint(GOOD, next);
    assert.ok(f.some(x => x.severity === "warning" && /inet filter is not reset/.test(x.message)));
});

test('added and removed tables', () => {
    const next = GOOD + "table inet extra\ndelete table inet extra\ntable inet extra {\n}\n";
    assert.deepEqual(addedTables(GOOD, next), [["inet", "extra"]]);
    const f = lint(GOOD, next);
    assert.ok(f.some(x => x.severity === "info" && /inet extra is new/.test(x.message)));

    const removed = lint(next, GOOD);
    assert.ok(removed.some(x => x.severity === "warning" && /inet extra is no longer/.test(x.message)));
});

test('foreign table is danger', () => {
    const next = GOOD + "table ip nat\ndelete table ip nat\ntable ip nat {\n}\n";
    const f = lint(GOOD, next, { foreignTables: new Set(["ip nat"]) });
    assert.ok(f.some(x => x.severity === "danger" && /ip nat is managed/.test(x.message)));
});

test('lockout heuristic: no ssh accept with policy drop', () => {
    const next = GOOD.replace('tcp dport 22 accept comment "ssh # not a comment"', "");
    assert.ok(lint(GOOD, next).some(x => /TCP port 22/.test(x.message)));
    // set syntax counts
    const set = GOOD.replace("tcp dport 22 accept", "tcp dport { 80, 22 } ip saddr @t accept");
    assert.ok(!lint(GOOD, set).some(x => /TCP port 22/.test(x.message)));
    // a commented-out accept does not count
    const commented = GOOD.replace("tcp dport 22 accept", "# tcp dport 22 accept\n");
    assert.ok(lint(GOOD, commented).some(x => /TCP port 22/.test(x.message)));
});
