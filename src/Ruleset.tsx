/*
 * SPDX-License-Identifier: LGPL-2.1-or-later
 *
 * Copyright (C) 2026 deviationist
 *
 * Read-only view of the live kernel ruleset, grouped by table and owner.
 */

import React, { useMemo, useState } from 'react';
import { Card, CardBody, CardHeader, CardTitle } from "@patternfly/react-core/dist/esm/components/Card/index.js";
import { ExpandableSection } from "@patternfly/react-core/dist/esm/components/ExpandableSection/index.js";
import { Label, LabelGroup } from "@patternfly/react-core/dist/esm/components/Label/index.js";
import { SearchInput } from "@patternfly/react-core/dist/esm/components/SearchInput/index.js";
import { Switch } from "@patternfly/react-core/dist/esm/components/Switch/index.js";
import { Toolbar, ToolbarContent, ToolbarItem } from "@patternfly/react-core/dist/esm/components/Toolbar/index.js";
import { Flex, FlexItem } from "@patternfly/react-core/dist/esm/layouts/Flex/index.js";

import cockpit from 'cockpit';
import { ListingTable } from 'cockpit-components-table';

import { Chain, Owner, Rule, Table, formatCount, tableKey, tableTags } from './lib/ruleset-parse';

const _ = cockpit.gettext;

type Color = "blue" | "grey" | "purple" | "orange" | "green" | "red" | "teal" | "yellow" | "orangered";

const OWNER: Record<Owner, { label: string; color: Color; help: string }> = {
    config: { label: _("Your config"), color: "blue", help: _("Declared in the config file. Edit it on the Configuration tab.") },
    "iptables-nft": { label: _("iptables-nft"), color: "purple", help: _("Written by iptables-nft (Docker, Tailscale, …). View only: those programs rewrite it.") },
    fail2ban: { label: _("fail2ban"), color: "orange", help: _("fail2ban's ban table. View only.") },
    other: { label: _("Runtime"), color: "grey", help: _("Created at runtime by another program. View only.") },
};

function verdictColor(v: string | null): Color {
    if (!v) return "grey";
    if (v === "accept") return "green";
    if (v === "drop" || v.startsWith("reject")) return "red";
    if (v.startsWith("jump") || v.startsWith("goto")) return "teal";
    if (v === "return") return "grey";
    return "yellow"; // nat / masquerade / other
}

function RuleRows({ rules, filter }: { rules: Rule[]; filter: string }) {
    // Cockpit's own ListingTable (pkg/lib, on @patternfly/react-table), so the
    // rules look like every other table in Cockpit. Order is evaluation order,
    // so no sorting: first match wins.
    const rows = rules
            .map((r, i) => ({ r, i }))
            .filter(({ r }) => !filter || r.text.toLowerCase().includes(filter))
            .map(({ r, i }) => ({
                props: { key: String(r.handle ?? i) },
                columns: [
                    { title: i + 1, props: { className: "cnft-col-num" } },
                    {
                        title: (
                            <>
                                <code className="cnft-mono cnft-rule">{r.text.replace(/ comment "(?:[^"\\]|\\.)*"$/, "")}</code>
                                {r.comment && <div className="cnft-comment">{r.comment}</div>}
                            </>
                        ),
                    },
                    {
                        title: r.verdict ? <Label isCompact color={verdictColor(r.verdict)}>{r.verdict}</Label> : "",
                        props: { className: "cnft-col-verdict" },
                    },
                    { title: formatCount(r.packets), props: { className: "cnft-col-count" } },
                    { title: formatCount(r.bytes), props: { className: "cnft-col-count" } },
                ],
            }));
    return (
        <ListingTable
            className="cnft-rules"
            variant="compact"
            gridBreakPoint="grid-md"
            aria-label={_("Rules")}
            columns={["#", _("Rule"), _("Verdict"), _("Packets"), _("Bytes")]}
            rows={rows}
        />
    );
}

function ChainBlock({ chain, filter }: { chain: Chain; filter: string }) {
    const visible = filter ? chain.rules.filter(r => r.text.toLowerCase().includes(filter)).length : chain.rules.length;
    return (
        <div className="cnft-chain">
            <Flex alignItems={{ default: "alignItemsCenter" }} spaceItems={{ default: "spaceItemsSm" }}>
                <FlexItem><strong className="cnft-mono">chain {chain.name}</strong></FlexItem>
                <FlexItem>
                    <LabelGroup>
                        {chain.hook
                            ? <Label isCompact color="blue">{`${chain.type} · ${chain.hook} · ${chain.priority}`}</Label>
                            : <Label isCompact variant="outline">{_("regular chain")}</Label>}
                        {chain.policy && <Label isCompact color={chain.policy === "drop" ? "red" : "green"}>{`policy ${chain.policy}`}</Label>}
                        {chain.tags.map(t => <Label isCompact key={t} variant="outline">{t}</Label>)}
                        <Label isCompact variant="outline">{cockpit.format(cockpit.ngettext("$0 rule", "$0 rules", visible), visible)}</Label>
                    </LabelGroup>
                </FlexItem>
            </Flex>
            {visible > 0 && <RuleRows rules={chain.rules} filter={filter} />}
        </div>
    );
}

function TableCard({ table, filter, hideEmpty }: { table: Table; filter: string; hideEmpty: boolean }) {
    const [expanded, setExpanded] = useState(table.owner === "config");
    const o = OWNER[table.owner];
    const chains = table.chains.filter(c => {
        if (filter) return c.rules.some(r => r.text.toLowerCase().includes(filter));
        return !(hideEmpty && c.rules.length === 0 && !c.hook);
    });
    const rules = table.chains.reduce((a, c) => a + c.rules.length, 0);
    if (filter && chains.length === 0) return null;
    return (
        <Card isCompact className="cnft-table-card">
            <CardHeader>
                <CardTitle>
                    <Flex alignItems={{ default: "alignItemsCenter" }} spaceItems={{ default: "spaceItemsSm" }}>
                        <FlexItem><span className="cnft-mono">table {tableKey(table.family, table.name)}</span></FlexItem>
                        <FlexItem>
                            <LabelGroup>
                                <Label color={o.color} title={o.help}>{o.label}</Label>
                                {tableTags(table).map(t => <Label key={t} variant="outline">{t}</Label>)}
                                <Label variant="outline">
                                    {cockpit.format(_("$0 chains · $1 rules"), table.chains.length, rules)}
                                </Label>
                            </LabelGroup>
                        </FlexItem>
                    </Flex>
                </CardTitle>
            </CardHeader>
            <CardBody>
                <ExpandableSection
                    toggleText={expanded || filter ? _("Hide chains") : _("Show chains")}
                    isExpanded={expanded || !!filter}
                    onToggle={(_e, v) => setExpanded(v)}
                >
                    {table.objects.map(obj => (
                        <div className="cnft-chain" key={obj.kind + obj.name}>
                            <strong className="cnft-mono">{obj.kind} {obj.name}</strong>
                            <pre className="cnft-mono cnft-pre">{obj.body}</pre>
                        </div>
                    ))}
                    {chains.map(c => <ChainBlock key={c.name} chain={c} filter={filter} />)}
                </ExpandableSection>
            </CardBody>
        </Card>
    );
}

export function RulesetView({ tables }: { tables: Table[] }) {
    const [filter, setFilter] = useState("");
    const [hideEmpty, setHideEmpty] = useState(true);
    const f = filter.trim().toLowerCase();
    // Own tables first, then the rest in kernel order.
    const sorted = useMemo(() => [...tables].sort((a, b) => Number(b.owner === "config") - Number(a.owner === "config")), [tables]);
    return (
        <>
            <Toolbar>
                <ToolbarContent>
                    <ToolbarItem>
                        <SearchInput
                            placeholder={_("Filter rules (e.g. 22, docker0, drop)")} value={filter}
                            onChange={(_e, v) => setFilter(v)} onClear={() => setFilter("")}
                        />
                    </ToolbarItem>
                    <ToolbarItem alignSelf="center">
                        <Switch
                            id="hide-empty" label={_("Hide empty regular chains")} isChecked={hideEmpty}
                            onChange={(_e, v) => setHideEmpty(v)}
                        />
                    </ToolbarItem>
                </ToolbarContent>
            </Toolbar>
            <Flex direction={{ default: "column" }} spaceItems={{ default: "spaceItemsMd" }}>
                {sorted.map(t => <TableCard key={tableKey(t.family, t.name)} table={t} filter={f} hideEmpty={hideEmpty} />)}
            </Flex>
        </>
    );
}
