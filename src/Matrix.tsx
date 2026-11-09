/*
 * SPDX-License-Identifier: LGPL-2.1-or-later
 *
 * Copyright (C) 2026 deviationist
 *
 * "Who can reach what": a UniFi-Zone-Matrix-style overview. Rows = services
 * listening on this host, columns = source zones derived from the interfaces
 * and the rules. Each cell is a test packet walked through the real ruleset;
 * clicking a cell shows the trace. Plus a FortiGate-style "Is this allowed?"
 * lookup. Read-only.
 */

import React, { useMemo, useState } from 'react';
import { Alert } from "@patternfly/react-core/dist/esm/components/Alert/index.js";
import { Button } from "@patternfly/react-core/dist/esm/components/Button/index.js";
import { Card, CardBody, CardTitle } from "@patternfly/react-core/dist/esm/components/Card/index.js";
import { ExpandableSection } from "@patternfly/react-core/dist/esm/components/ExpandableSection/index.js";
import { Form, FormGroup } from "@patternfly/react-core/dist/esm/components/Form/index.js";
import { FormSelect, FormSelectOption } from "@patternfly/react-core/dist/esm/components/FormSelect/index.js";
import { Label, LabelGroup } from "@patternfly/react-core/dist/esm/components/Label/index.js";
import { TextInput } from "@patternfly/react-core/dist/esm/components/TextInput/index.js";
import { Flex, FlexItem } from "@patternfly/react-core/dist/esm/layouts/Flex/index.js";

import cockpit from 'cockpit';

import { Model, Trace, evaluate, ip4 } from './lib/evaluate';
import { Cell, CellState, cellFor } from './lib/matrix';
import { Iface, Service, Zone } from './lib/zones';

const _ = cockpit.gettext;

type Color = "green" | "red" | "orange" | "grey" | "purple" | "blue";

const STATE: Record<CellState, { text: string; color: Color }> = {
    allow: { text: _("Allow"), color: "green" },
    block: { text: _("Block"), color: "red" },
    partial: { text: _("Partial"), color: "orange" },
    unknown: { text: "?", color: "grey" },
    docker: { text: _("Docker"), color: "purple" },
    none: { text: "—", color: "grey" },
};

const OUTCOME: Record<Trace["outcome"], { text: string; color: Color }> = {
    accept: { text: _("Allowed"), color: "green" },
    drop: { text: _("Blocked"), color: "red" },
    dnat: { text: _("Forwarded (DNAT)"), color: "purple" },
    unknown: { text: _("Can't tell"), color: "grey" },
};

export type RuleText = (family: string, table: string, chain: string, handle: number | null) => string | null;

function serviceDetail(s: Service): string {
    const ports = s.ports.length > 6 ? `${s.ports.slice(0, 6).join(", ")} …` : s.ports.join(", ");
    const where = s.bind !== "*" ? cockpit.format(_(" on $0"), s.bind) : s.scope ? cockpit.format(_(" on $0"), s.scope) : "";
    return `${s.proto} ${ports}${where}`;
}

export function TraceView({ trace, ruleText }: { trace: Trace; ruleText: RuleText }) {
    const o = OUTCOME[trace.outcome];
    return (
        <div className="cnft-trace">
            <Label color={o.color}>{o.text}</Label>
            {trace.reason && <span className="cnft-muted"> {cockpit.format(_("($0)"), trace.reason)}</span>}
            <ol className="cnft-trace-steps">
                {trace.steps.map((s, i) => {
                    const text = s.rule !== null ? ruleText(s.family, s.table, s.chain, s.handle) : null;
                    return (
                        <li key={i}>
                            <span className="cnft-muted">{s.hook}</span>
                            {" › "}
                            <code className="cnft-mono">{`${s.family} ${s.table} ${s.chain}`}</code>
                            {s.rule !== null && <span className="cnft-muted">{cockpit.format(_(" rule $0"), s.rule)}</span>}
                            {" → "}
                            <strong>{s.verdict}</strong>
                            {text && <div><code className="cnft-mono cnft-rule">{text}</code></div>}
                            {s.note && <div className="cnft-muted">{s.note}</div>}
                        </li>
                    );
                })}
            </ol>
        </div>
    );
}

function PortToggle({ port, trace }: { port: number; trace: Trace }) {
    const o = OUTCOME[trace.outcome];
    return (
        <span>
            {cockpit.format(_("Port $0: "), port)}
            <Label isCompact color={o.color}>{o.text}</Label>
        </span>
    );
}

function Lookup({ model, ifaces, ruleText }: { model: Model; ifaces: Iface[]; ruleText: RuleText }) {
    const usable = ifaces.filter(f => f.kind !== "other");
    const [iif, setIif] = useState(usable[0]?.name ?? "");
    const [saddr, setSaddr] = useState("");
    const [proto, setProto] = useState<"tcp" | "udp">("tcp");
    const [port, setPort] = useState("22");
    const [trace, setTrace] = useState<Trace | null>(null);
    const daddr = usable.find(f => f.name === iif)?.addr ?? "";
    const valid = ip4(saddr) !== null && Number(port) > 0 && Number(port) < 65536;
    return (
        <Form isHorizontal onSubmit={e => { e.preventDefault(); if (valid) setTrace(evaluate(model, { iif, saddr, daddr, proto, dport: Number(port) })); }}>
            <Flex alignItems={{ default: "alignItemsFlexEnd" }} spaceItems={{ default: "spaceItemsMd" }}>
                <FlexItem>
                    <FormGroup label={_("Arrives on")} fieldId="lk-iif">
                        <FormSelect id="lk-iif" value={iif} onChange={(_e, v) => setIif(v)}>
                            {usable.map(f => <FormSelectOption key={f.name + f.addr} value={f.name} label={`${f.name} (${f.addr})`} />)}
                        </FormSelect>
                    </FormGroup>
                </FlexItem>
                <FlexItem>
                    <FormGroup label={_("From address")} fieldId="lk-src">
                        <TextInput
                            id="lk-src" value={saddr} placeholder="192.168.1.50" onChange={(_e, v) => setSaddr(v)}
                            validated={saddr && ip4(saddr) === null ? "error" : "default"}
                        />
                    </FormGroup>
                </FlexItem>
                <FlexItem>
                    <FormGroup label={_("Protocol")} fieldId="lk-proto">
                        <FormSelect id="lk-proto" value={proto} onChange={(_e, v) => setProto(v as "tcp" | "udp")}>
                            <FormSelectOption value="tcp" label="TCP" />
                            <FormSelectOption value="udp" label="UDP" />
                        </FormSelect>
                    </FormGroup>
                </FlexItem>
                <FlexItem>
                    <FormGroup label={_("Port")} fieldId="lk-port">
                        <TextInput id="lk-port" value={port} type="number" onChange={(_e, v) => setPort(v)} className="cnft-port" />
                    </FormGroup>
                </FlexItem>
                <FlexItem>
                    <Button type="submit" variant="secondary" isDisabled={!valid}>{_("Trace")}</Button>
                </FlexItem>
            </Flex>
            {trace && <TraceView trace={trace} ruleText={ruleText} />}
        </Form>
    );
}

interface Props {
    model: Model;
    zones: Zone[];
    services: Service[];
    ifaces: Iface[];
    ruleText: RuleText;
}

export function MatrixView({ model, zones, services, ifaces, ruleText }: Props) {
    const [sel, setSel] = useState<{ svc: string; zone: string } | null>(null);
    const [showAll, setShowAll] = useState(false);

    const cells = useMemo(() => {
        const m = new Map<string, Cell>();
        for (const s of services) for (const z of zones) m.set(`${s.id}#${z.id}`, cellFor(model, z, s));
        return m;
    }, [model, zones, services]);

    // Hide services nobody can even address (bound to a bridge/broadcast/dummy address).
    const rows = services.filter(s => zones.some(z => cells.get(`${s.id}#${z.id}`)!.state !== "none"));
    // Default view: hide rows that are blocked from every zone (claude-relay, rpc.mountd …) behind a toggle.
    const interesting = rows.filter(s => zones.some(z => !["block", "none"].includes(cells.get(`${s.id}#${z.id}`)!.state)));
    const shown = showAll ? rows : interesting;
    const hidden = rows.length - interesting.length;

    const selCell = sel ? cells.get(`${sel.svc}#${sel.zone}`) : null;
    const selSvc = sel ? services.find(s => s.id === sel.svc) : null;
    const selZone = sel ? zones.find(z => z.id === sel.zone) : null;

    return (
        <Flex direction={{ default: "column" }} spaceItems={{ default: "spaceItemsMd" }}>
            <Card isCompact>
                <CardTitle>{_("Who can reach what")}</CardTitle>
                <CardBody>
                    <p className="cnft-muted pf-v6-u-mb-sm">
                        {_("Rows are services listening on this host, columns are where traffic comes from. Each cell is one test packet walked through the live ruleset (every table, in kernel order). Click a cell to see why.")}
                    </p>
                    <LabelGroup className="pf-v6-u-mb-sm" numLabels={10}>
                        <Label color="green" isCompact>{_("Allow")}</Label>
                        <Label color="red" isCompact>{_("Block")}</Label>
                        <Label color="orange" isCompact>{_("Partial: some ports")}</Label>
                        <Label color="purple" isCompact>{_("Docker: decided by Docker's rules")}</Label>
                        <Label color="grey" isCompact>{_("?: can't evaluate")}</Label>
                        <Label isCompact variant="outline">{_("—: not listening on that address")}</Label>
                    </LabelGroup>
                    <div className="cnft-matrix-wrap">
                        <table className="pf-v6-c-table pf-m-compact cnft-matrix" role="grid">
                            <thead className="pf-v6-c-table__thead">
                                <tr className="pf-v6-c-table__tr">
                                    <th className="pf-v6-c-table__th">{_("Service")}</th>
                                    {zones.map(z => (
                                        <th className="pf-v6-c-table__th cnft-matrix-zone" key={z.id}>
                                            <div>{z.label}</div>
                                            <div className="cnft-muted cnft-small">{z.detail}</div>
                                        </th>
                                    ))}
                                </tr>
                            </thead>
                            <tbody className="pf-v6-c-table__tbody">
                                {shown.map(s => (
                                    <tr className="pf-v6-c-table__tr" key={s.id}>
                                        <td className="pf-v6-c-table__td">
                                            <strong>{s.name}</strong>
                                            <div className="cnft-muted cnft-small">{serviceDetail(s)}</div>
                                        </td>
                                        {zones.map(z => {
                                            const c = cells.get(`${s.id}#${z.id}`)!;
                                            const st = STATE[c.state];
                                            const active = sel?.svc === s.id && sel?.zone === z.id;
                                            if (c.state === "none")
                                                return <td className="pf-v6-c-table__td cnft-matrix-cell cnft-muted" key={z.id} title={c.note}>—</td>;
                                            return (
                                                <td className={`pf-v6-c-table__td cnft-matrix-cell${active ? " cnft-active" : ""}`} key={z.id}>
                                                    <Label color={st.color} isCompact onClick={() => setSel({ svc: s.id, zone: z.id })}>
                                                        {c.state === "partial" ? `${c.allowed}/${c.total}` : st.text}
                                                    </Label>
                                                </td>
                                            );
                                        })}
                                    </tr>
                                ))}
                            </tbody>
                        </table>
                    </div>
                    {hidden > 0 &&
                        <Button variant="link" isInline className="pf-v6-u-mt-sm" onClick={() => setShowAll(v => !v)}>
                            {showAll
                                ? _("Hide services that are blocked from everywhere")
                                : cockpit.format(cockpit.ngettext("Show $0 service that is blocked from everywhere", "Show $0 services that are blocked from everywhere", hidden), hidden)}
                        </Button>}
                </CardBody>
            </Card>

            {selCell && selSvc && selZone &&
                <Card isCompact>
                    <CardTitle>
                        {cockpit.format(_("$0 ($1) from $2"), selSvc.name, serviceDetail(selSvc), selZone.label)}
                        <div className="cnft-muted cnft-small">{cockpit.format(_("Test packet: $0 → $1 via $2"), selZone.saddr, selZone.daddr, selZone.iif)}</div>
                    </CardTitle>
                    <CardBody>
                        {selCell.note && <Alert isInline isPlain variant="info" title={selCell.note} />}
                        {selCell.traces.length === 1 && <TraceView trace={selCell.traces[0].trace} ruleText={ruleText} />}
                        {selCell.traces.length > 1 && selCell.traces.map(t => (
                            <ExpandableSection key={t.port} toggleContent={<PortToggle port={t.port} trace={t.trace} />}>
                                <TraceView trace={t.trace} ruleText={ruleText} />
                            </ExpandableSection>
                        ))}
                    </CardBody>
                </Card>}

            <Card isCompact>
                <CardTitle>{_("Is this allowed?")}</CardTitle>
                <CardBody>
                    <Lookup model={model} ifaces={ifaces} ruleText={ruleText} />
                </CardBody>
            </Card>

            <Alert isInline isPlain variant="info" title={_("Limits")}>
                {_("IPv4, new connections only, one example address per zone. Rules the evaluator can't read (iptables xt matches that would decide the packet, maps) show as \"?\", never as a guess.")}
            </Alert>
        </Flex>
    );
}
