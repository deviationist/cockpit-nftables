/*
 * SPDX-License-Identifier: LGPL-2.1-or-later
 *
 * Copyright (C) 2026 deviationist
 *
 * The "Map" tab, built from the Claude Design prototype (recommended variants):
 *   - Topology: zones -> interface ports on the host -> services, edges bundled
 *     per interface, expanded on focus; edge -> trace in the side panel.
 *   - Rule graph: netfilter hooks left to right, base chains by priority,
 *     regular chains reached by jump/goto; chain -> its rules.
 * "Is this allowed?" lights the path up in both. Narrow screens get lists.
 * Read-only. Layout lives in lib/map-layout.ts (unit-tested).
 */

import React, { useEffect, useMemo, useRef, useState } from 'react';
import { Alert } from "@patternfly/react-core/dist/esm/components/Alert/index.js";
import { Button } from "@patternfly/react-core/dist/esm/components/Button/index.js";
import { Card, CardBody, CardHeader, CardTitle } from "@patternfly/react-core/dist/esm/components/Card/index.js";
import { FormSelect, FormSelectOption } from "@patternfly/react-core/dist/esm/components/FormSelect/index.js";
import { Label, LabelGroup } from "@patternfly/react-core/dist/esm/components/Label/index.js";
import { SearchInput } from "@patternfly/react-core/dist/esm/components/SearchInput/index.js";
import { Switch } from "@patternfly/react-core/dist/esm/components/Switch/index.js";
import { ToggleGroup, ToggleGroupItem } from "@patternfly/react-core/dist/esm/components/ToggleGroup/index.js";
import { Toolbar, ToolbarContent, ToolbarItem } from "@patternfly/react-core/dist/esm/components/Toolbar/index.js";
import { Flex, FlexItem } from "@patternfly/react-core/dist/esm/layouts/Flex/index.js";
import { SearchMinusIcon } from "@patternfly/react-icons/dist/esm/icons/search-minus-icon.js";
import { SearchPlusIcon } from "@patternfly/react-icons/dist/esm/icons/search-plus-icon.js";
import { TimesIcon } from "@patternfly/react-icons/dist/esm/icons/times-icon.js";

import cockpit from 'cockpit';

import { Lookup, RuleText, TraceView } from './Matrix';
import { RuleRows } from './Ruleset';
import { Model, Packet, Trace } from './lib/evaluate';
import { Cell, CellState, cellFor } from './lib/matrix';
import { DEFAULT_OPEN, EdgeAction, Focus, HOOKS, OwnerLabel, RNode, TEdge, TNode, hotEdges, ruleLayout, topoLayout } from './lib/map-layout';
import { Table } from './lib/ruleset-parse';
import { Iface, Service, Zone } from './lib/zones';

const _ = cockpit.gettext;

type Color = "green" | "red" | "orange" | "grey" | "purple" | "blue" | "teal" | "yellow";

const STATE: Record<CellState, { text: string; color: Color }> = {
    allow: { text: _("Allow"), color: "green" },
    block: { text: _("Block"), color: "red" },
    partial: { text: _("Partial"), color: "orange" },
    unknown: { text: "?", color: "grey" },
    docker: { text: _("Docker"), color: "purple" },
    none: { text: "—", color: "grey" },
};

const OWNER: Record<OwnerLabel, { text: string; color: Color }> = {
    config: { text: _("Your config"), color: "blue" },
    docker: { text: "Docker", color: "purple" },
    tailscale: { text: "Tailscale", color: "teal" },
    fail2ban: { text: "fail2ban", color: "yellow" },
    "iptables-nft": { text: "iptables-nft", color: "purple" },
    runtime: { text: _("Runtime"), color: "grey" },
};

type Drawer =
    | { kind: "trace"; zone: string; service: string }
    | { kind: "bundle"; iface: string; service: string }
    | { kind: "chain"; key: string }
    | { kind: "lookup"; pkt: Packet; trace: Trace }
    | null;

function useWidth<T extends HTMLElement>(): [React.RefObject<T>, number] {
    const ref = useRef<T>(null);
    const [w, setW] = useState(0);
    useEffect(() => {
        if (!ref.current) return;
        const ro = new ResizeObserver(entries => setW(entries[0].contentRect.width));
        ro.observe(ref.current);
        return () => ro.disconnect();
    }, []);
    return [ref, w];
}

const keyActivate = (fn: () => void) => (e: React.KeyboardEvent) => {
    if (e.key === "Enter" || e.key === " ") {
        e.preventDefault();
        fn();
    }
};

/* ---------------- topology canvas ---------------- */

function TopoCanvas({ layout, scale, onEdge, onNode, hot, onHover }: {
    layout: ReturnType<typeof topoLayout>;
    scale: number;
    onEdge: (a: EdgeAction) => void;
    onNode: (n: TNode) => void;
    hot: Set<string>;
    onHover: (id: string | null) => void;
}) {
    const { nodes, edges, width, height, host } = layout;
    const mid = (e: TEdge) => {
        const m = /M([\d.]+),([\d.]+) C[\d.]+,[\d.]+ [\d.]+,[\d.]+ ([\d.]+),([\d.]+)/.exec(e.d);
        return m ? { x: (Number(m[1]) + Number(m[3])) / 2, y: (Number(m[2]) + Number(m[4])) / 2 } : { x: 0, y: 0 };
    };
    return (
        <div className="cnft-canvas" style={{ height: Math.round(height * scale) + 48 }}>
            <div className="cnft-canvas-inner" style={{ width, height, transform: `scale(${scale})` }}>
                <div className="cnft-host" style={{ left: host.x, top: host.y, width: host.w, height: host.h }}>
                    <span className="cnft-host-label">{_("This host")}</span>
                </div>
                <svg width={width} height={height} className="cnft-edges" aria-label={_("Connections")}>
                    {edges.map(e => {
                        const label = e.title;
                        const m = e.label ? mid(e) : null;
                        return (
                            <g
                                key={e.id}
                                className={`cnft-edge cnft-st-${e.state}${e.lit ? " cnft-lit" : ""}${e.action ? " cnft-clickable" : ""}${hot.size ? (hot.has(e.id) ? " cnft-hot" : " cnft-cold") : ""}`}
                                {...(e.action
                                    ? { role: "button", tabIndex: 0, "aria-label": label, onClick: () => onEdge(e.action!), onKeyDown: keyActivate(() => onEdge(e.action!)) }
                                    : {})}
                            >
                                <title>{e.title}</title>
                                <path d={e.d} className="cnft-edge-hit" />
                                {e.lit && <path d={e.d} className="cnft-edge-glow" />}
                                <path d={e.d} className="cnft-edge-line" />
                                {m && (
                                    <g className="cnft-edge-label">
                                        <rect x={m.x - 18} y={m.y - 9} width={36} height={18} rx={9} />
                                        <text x={m.x} y={m.y + 4} textAnchor="middle">{e.label}</text>
                                    </g>
                                )}
                            </g>
                        );
                    })}
                </svg>
                {nodes.map(n => (
                    <button
                        type="button" key={n.id}
                        className={`cnft-node cnft-node-${n.kind}${n.dim ? " cnft-dim" : ""}${n.selected ? " cnft-selected" : ""}`}
                        style={{ left: n.x, top: n.y, width: n.w, height: n.h }}
                        aria-pressed={n.selected} onClick={() => onNode(n)}
                        onMouseEnter={() => onHover(n.id)} onMouseLeave={() => onHover(null)}
                        onFocus={() => onHover(n.id)} onBlur={() => onHover(null)}
                    >
                        <span className="cnft-node-label">{n.label}</span>
                        {n.kind !== "iface"
                            ? <span className="cnft-node-detail">{n.detail}</span>
                            : <span className="cnft-node-detail cnft-inline">{n.detail}</span>}
                    </button>
                ))}
            </div>
        </div>
    );
}

/* ---------------- rule graph canvas ---------------- */

function RulesCanvas({ layout, scale, lit, decider, query, selected, onNode, hover, onHover }: {
    layout: ReturnType<typeof ruleLayout>;
    scale: number;
    lit: Set<string> | null;
    decider: string | null;
    query: string;
    selected: string | null;
    onNode: (n: RNode) => void;
    hover: string | null;
    onHover: (key: string | null) => void;
}) {
    const { nodes, edges, width, height, top } = layout;
    const q = query.trim().toLowerCase();
    const match = (n: RNode) => !q || `${n.title} ${n.sub ?? ""} ${n.policy ?? ""} ${n.owner ?? ""} ${(n.sets ?? []).join(" ")}`.toLowerCase().includes(q);
    const H = height - top;
    return (
        <div className="cnft-canvas" style={{ height: Math.round(H * scale) + 48 }}>
            <div className="cnft-canvas-inner" style={{ width, height: H, transform: `scale(${scale})` }}>
                <svg width={width} height={H} className="cnft-edges" aria-hidden="true">
                    <defs>
                        <marker id="cnft-arrow" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto">
                            <path d="M0,0 L10,5 L0,10 z" className="cnft-arrowhead" />
                        </marker>
                    </defs>
                    <g transform={`translate(0, ${-top})`}>
                        {edges.map((e, i) => {
                            const faded = lit && e.kind === "jump" && !(lit.has(e.from!) && lit.has(e.to!));
                            const isHot = !!hover && e.kind === "jump" && (e.from === hover || e.to === hover);
                            const cold = !!hover && e.kind === "jump" && !isHot;
                            return (
                                <g key={i} className={`cnft-redge cnft-redge-${e.kind}${faded ? " cnft-dim" : ""}${isHot ? " cnft-hot" : ""}${cold ? " cnft-cold" : ""}`}>
                                    <path d={e.d} markerEnd={e.kind === "hook" ? "url(#cnft-arrow)" : undefined} />
                                    {e.kind === "jump" && e.label && <text className="cnft-redge-label" x={Number(/M([\d.]+)/.exec(e.d)![1]) + 5} y={Number(/L[\d.]+,([\d.]+)/.exec(e.d)![1]) - 4}>{e.label}</text>}
                                </g>
                            );
                        })}
                    </g>
                </svg>
                {nodes.map(n => {
                    const y = n.y - top;
                    const inLit = !lit || n.kind === "header" || n.kind === "collapsed" || (n.key !== undefined && lit.has(n.key));
                    const dim = !(inLit && match(n));
                    const cls = `cnft-rnode cnft-rnode-${n.kind}${dim ? " cnft-dim" : ""}${(n.key && (n.key === selected || n.key === decider)) || (q && n.kind !== "header" && match(n)) ? " cnft-selected" : ""}`;
                    const style = { left: n.x, top: y, width: n.w, height: n.h };
                    if (n.kind === "header")
                        return (
                            <button type="button" key={n.id} className={cls} style={style} onClick={() => onNode(n)} aria-label={cockpit.format(_("Hook $0, collapse or expand"), n.title)}>
                                <span className="cnft-node-label">{n.title}</span>
                            </button>
                        );
                    if (n.kind === "collapsed")
                        return (
                            <button type="button" key={n.id} className={cls} style={style} onClick={() => onNode(n)}>
                                <span className="cnft-node-detail">{n.title}</span>
                                <span className="cnft-link">{_("Expand")}</span>
                            </button>
                        );
                    const own = n.owner ? OWNER[n.owner] : null;
                    const hov = {
                        onMouseEnter: () => onHover(n.key ?? null),
                        onMouseLeave: () => onHover(null),
                        onFocus: () => onHover(n.key ?? null),
                        onBlur: () => onHover(null),
                    };
                    return (
                        <button type="button" key={n.id} className={cls} style={style} onClick={() => onNode(n)} {...hov}>
                            <span className="cnft-rnode-top">
                                <span className="cnft-node-label">{n.kind === "base" ? n.sub : n.title}</span>
                                {own && <Label isCompact color={own.color}>{own.text}</Label>}
                            </span>
                            <span className="cnft-node-detail">
                                {n.kind === "base"
                                    ? `${n.title} · ${cockpit.format(_("prio $0"), n.via)}`
                                    : `${n.via} · ${n.sub}`}
                            </span>
                            <span className="cnft-rnode-meta">
                                {n.kind === "base" && n.policy &&
                                    <Label isCompact color={n.policy === "drop" ? "red" : "grey"} variant={n.policy === "drop" ? "filled" : "outline"}>{`policy ${n.policy}`}</Label>}
                                <span className="cnft-node-detail">
                                    {cockpit.format(cockpit.ngettext("$0 rule", "$0 rules", n.rules ?? 0), n.rules ?? 0)}
                                    {n.key === decider ? ` · ${_("decided here")}` : ""}
                                </span>
                                {(n.sets ?? []).slice(0, 2).map(s => <Label key={s} isCompact variant="outline">{s}</Label>)}
                            </span>
                        </button>
                    );
                })}
            </div>
        </div>
    );
}

/* ---------------- side panel ---------------- */

function DrawerPanel({ drawer, close, zones, services, cells, tables, ruleText, open }: {
    drawer: NonNullable<Drawer>;
    close: () => void;
    zones: Zone[];
    services: Service[];
    cells: Map<string, Cell>;
    tables: Table[];
    ruleText: RuleText;
    open: (d: Drawer) => void;
}) {
    let title = "";
    let sub = "";
    let body: React.ReactNode = null;
    if (drawer.kind === "trace") {
        const z = zones.find(x => x.id === drawer.zone)!;
        const s = services.find(x => x.id === drawer.service)!;
        const c = cells.get(`${s.id}#${z.id}`)!;
        title = cockpit.format(_("$0 from $1"), s.name, z.label);
        sub = cockpit.format(_("Test packet: $0 → $1 via $2"), z.saddr, z.daddr, z.iif);
        body = (
            <>
                <Label color={STATE[c.state].color}>{c.state === "partial" ? `${c.allowed}/${c.total}` : STATE[c.state].text}</Label>
                {c.note && <Alert isInline isPlain variant="info" title={c.note} />}
                {c.traces.map(t => (
                    <div key={t.port}>
                        {c.traces.length > 1 && <strong>{cockpit.format(_("Port $0"), t.port)}</strong>}
                        <TraceView trace={t.trace} ruleText={ruleText} />
                    </div>
                ))}
            </>
        );
    } else if (drawer.kind === "bundle") {
        const s = services.find(x => x.id === drawer.service)!;
        const on = zones.filter(z => z.iif === drawer.iface && cells.get(`${s.id}#${z.id}`)!.state !== "none");
        title = cockpit.format(_("$0 via $1"), s.name, drawer.iface);
        sub = cockpit.format(cockpit.ngettext("$0 zone arrives on $1", "$0 zones arrive on $1", on.length), on.length, drawer.iface);
        body = (
            <ul className="cnft-plain-list">
                {on.map(z => {
                    const st = cells.get(`${s.id}#${z.id}`)!.state;
                    return (
                        <li key={z.id}>
                            <Button variant="link" isInline onClick={() => open({ kind: "trace", zone: z.id, service: s.id })}>{z.label}</Button>
                            {" "}<Label isCompact color={STATE[st].color}>{STATE[st].text}</Label>
                            <div className="cnft-muted cnft-small">{z.detail}</div>
                        </li>
                    );
                })}
            </ul>
        );
    } else if (drawer.kind === "chain") {
        const [family, table, chain] = drawer.key.split(" ");
        const t = tables.find(x => x.family === family && x.name === table);
        const c = t?.chains.find(x => x.name === chain);
        title = drawer.key;
        sub = c?.hook
            ? cockpit.format(_("base chain · hook $0 · priority $1 · policy $2"), c.hook, c.priority ?? "", c.policy ?? "accept")
            : _("regular chain (reached by jump or goto)");
        body = c && c.rules.length ? <RuleRows rules={c.rules} filter="" /> : <p className="cnft-muted">{_("No rules.")}</p>;
    } else {
        title = _("Is this allowed?");
        sub = cockpit.format(_("$0 → $1 $2/$3 via $4"), drawer.pkt.saddr, drawer.pkt.daddr, drawer.pkt.proto, drawer.pkt.dport, drawer.pkt.iif);
        body = <TraceView trace={drawer.trace} ruleText={ruleText} />;
    }
    return (
        <Card isCompact className="cnft-drawer">
            <CardHeader actions={{ actions: <Button variant="plain" aria-label={_("Close")} icon={<TimesIcon />} onClick={close} />, hasNoOffset: true }}>
                <CardTitle>
                    <span className="cnft-mono-ish">{title}</span>
                    <div className="cnft-muted cnft-small">{sub}</div>
                </CardTitle>
            </CardHeader>
            <CardBody className="cnft-drawer-body">{body}</CardBody>
        </Card>
    );
}

/* ---------------- phone fallback ---------------- */

function PhoneTopology({ zones, services, cells, open }: {
    zones: Zone[]; services: Service[]; cells: Map<string, Cell>; open: (d: Drawer) => void;
}) {
    const [zone, setZone] = useState<string | null>(null);
    if (!zone)
        return (
            <ul className="cnft-plain-list cnft-phone-list">
                {zones.map(z => {
                    const reach = services.filter(s => ["allow", "partial"].includes(cells.get(`${s.id}#${z.id}`)!.state)).length;
                    return (
                        <li key={z.id}>
                            <Button variant="link" isInline onClick={() => setZone(z.id)}>{z.label}</Button>
                            <div className="cnft-muted cnft-small">{z.detail}</div>
                            <div className="cnft-small">{cockpit.format(cockpit.ngettext("reaches $0 service", "reaches $0 services", reach), reach)}</div>
                        </li>
                    );
                })}
            </ul>
        );
    const z = zones.find(x => x.id === zone)!;
    return (
        <>
            <Button variant="link" isInline onClick={() => setZone(null)}>{_("‹ All zones")}</Button>
            <h3 className="pf-v6-u-mt-sm">{z.label}</h3>
            <div className="cnft-muted cnft-small">{z.detail}</div>
            <ul className="cnft-plain-list cnft-phone-list">
                {services.map(s => {
                    const c = cells.get(`${s.id}#${z.id}`)!;
                    if (c.state === "none") return null;
                    return (
                        <li key={s.id}>
                            <Button variant="link" isInline onClick={() => open({ kind: "trace", zone: z.id, service: s.id })}>{s.name}</Button>
                            {" "}<Label isCompact color={STATE[c.state].color}>{c.state === "partial" ? `${c.allowed}/${c.total}` : STATE[c.state].text}</Label>
                            <div className="cnft-muted cnft-small">{`${s.proto} ${s.ports.slice(0, 5).join(", ")}`}</div>
                        </li>
                    );
                })}
            </ul>
        </>
    );
}

function PhoneRules({ layout, open }: { layout: ReturnType<typeof ruleLayout>; open: (d: Drawer) => void }) {
    return (
        <>
            {HOOKS.map(h => {
                const chains = layout.nodes.filter(n => n.hook === h && (n.kind === "base" || n.kind === "regular"));
                if (!chains.length) return null;
                return (
                    <div key={h} className="pf-v6-u-mb-md">
                        <h3>{h}</h3>
                        <ul className="cnft-plain-list cnft-phone-list">
                            {chains.map(n => (
                                <li key={n.id} style={{ paddingInlineStart: n.kind === "regular" ? 16 : 0 }}>
                                    <Button variant="link" isInline onClick={() => open({ kind: "chain", key: n.key! })}>{n.kind === "base" ? `${n.title} ${n.sub}` : n.title}</Button>
                                    {" "}{n.owner && <Label isCompact color={OWNER[n.owner].color}>{OWNER[n.owner].text}</Label>}
                                    {n.policy === "drop" && <>{" "}<Label isCompact color="red">policy drop</Label></>}
                                </li>
                            ))}
                        </ul>
                    </div>
                );
            })}
        </>
    );
}

/* ---------------- the tab ---------------- */

interface Props {
    model: Model;
    zones: Zone[];
    services: Service[];
    ifaces: Iface[];
    tables: Table[];
    ruleText: RuleText;
    mode: "topology" | "rules"; // kept in the URL by the parent
    onMode: (m: "topology" | "rules") => void;
}

export function MapView({ model, zones, services, ifaces, tables, ruleText, mode, onMode: setMode }: Props) {
    const [focus, setFocus] = useState<Focus>(null);
    const [showBlocked, setShowBlocked] = useState(false);
    const [query, setQuery] = useState("");
    const [zoom, setZoom] = useState(1);
    const [drawer, setDrawer] = useState<Drawer>(null);
    const [lookupOpen, setLookupOpen] = useState(false);
    const [lit, setLit] = useState<{ zone: string; service: string } | null>(null);
    const [litTrace, setLitTrace] = useState<Trace | null>(null);
    const [hooks, setHooks] = useState<Record<string, boolean>>({ ...DEFAULT_OPEN });
    const [hover, setHover] = useState<string | null>(null);
    const [ref, width] = useWidth<HTMLDivElement>();

    const cells = useMemo(() => {
        const m = new Map<string, Cell>();
        for (const s of services) for (const z of zones) m.set(`${s.id}#${z.id}`, cellFor(model, z, s));
        return m;
    }, [model, zones, services]);

    const topo = useMemo(() => topoLayout(
        { zones, services, cell: (s, z) => cells.get(`${s}#${z}`)!.state },
        { focus, showBlocked, query, lit }), [zones, services, cells, focus, showBlocked, query, lit]);
    const rules = useMemo(() => ruleLayout(tables, hooks), [tables, hooks]);
    const hot = useMemo(() => hotEdges(topo.edges, mode === "topology" ? hover : null,
                                       { zones, services, cell: (s, z) => cells.get(`${s}#${z}`)!.state }, showBlocked),
                        [topo, hover, mode, zones, services, cells, showBlocked]);

    const phone = width > 0 && width < 640;
    const panelW = drawer && width >= 1000 ? 396 : 0;
    const avail = Math.max(200, width - panelW - 16);
    const scale = Math.min(1, avail / (mode === "topology" ? topo.width : rules.width)) * zoom;

    const litKeys = useMemo(() => litTrace ? new Set(litTrace.steps.map(s => `${s.family} ${s.table} ${s.chain}`)) : null, [litTrace]);
    const decider = litTrace && litTrace.steps.length
        ? (s => `${s.family} ${s.table} ${s.chain}`)(litTrace.steps[litTrace.steps.length - 1])
        : null;

    const openDrawer = (d: Drawer) => {
        setDrawer(d);
        if (d?.kind === "trace") {
            setLit({ zone: d.zone, service: d.service });
            setLitTrace(cells.get(`${d.service}#${d.zone}`)?.traces[0]?.trace ?? null);
        }
    };
    const clearAll = () => {
        setFocus(null);
        setLit(null);
        setLitTrace(null);
        setZoom(1);
    };
    const onEdge = (a: EdgeAction) => {
        if (a.kind === "focus") setFocus(a.focus);
        else if (a.kind === "trace") openDrawer({ kind: "trace", zone: a.zone, service: a.service });
        else openDrawer({ kind: "bundle", iface: a.iface, service: a.service });
    };
    const onNode = (n: TNode) => {
        setLit(null);
        setLitTrace(null);
        const same = (focus?.kind === "zone" && n.kind === "zone" && focus.id === n.key) ||
            (focus?.kind === "service" && n.kind === "service" && focus.id === n.key) ||
            (focus?.kind === "iface" && n.kind === "iface" && focus.name === n.key);
        if (same) setFocus(null);
        else setFocus(n.kind === "zone" ? { kind: "zone", id: n.key } : n.kind === "service" ? { kind: "service", id: n.key } : { kind: "iface", name: n.key });
    };
    const onRuleNode = (n: RNode) => {
        if (n.kind === "header" || n.kind === "collapsed") setHooks(h => ({ ...h, [n.hook]: !(h[n.hook] ?? DEFAULT_OPEN[n.hook]) }));
        else if (n.key) setDrawer({ kind: "chain", key: n.key });
    };
    const onLookup = (pkt: Packet, trace: Trace) => {
        setLitTrace(trace);
        const z = zones.find(x => x.iif === pkt.iif && x.saddr === pkt.saddr);
        const s = services.find(x => x.proto === pkt.proto && x.ports.includes(pkt.dport));
        setLit(z && s ? { zone: z.id, service: s.id } : null);
        if (z && mode === "topology") setFocus({ kind: "zone", id: z.id });
        setDrawer({ kind: "lookup", pkt, trace });
    };

    const focusValue = focus ? (focus.kind === "iface" ? `i:${focus.name}` : `${focus.kind[0]}:${focus.id}`) : "";
    const setFocusValue = (v: string) => {
        setLit(null);
        setLitTrace(null);
        if (!v) return setFocus(null);
        const [k, id] = [v.slice(0, 1), v.slice(2)];
        setFocus(k === "z" ? { kind: "zone", id } : k === "s" ? { kind: "service", id } : { kind: "iface", name: id });
    };

    const ifaceNames = [...new Set(zones.map(z => z.iif))];

    const toolbar = (
        <Toolbar className="cnft-map-toolbar">
            <ToolbarContent>
                <ToolbarItem>
                    <ToggleGroup aria-label={_("Map mode")}>
                        <ToggleGroupItem text={_("Topology")} isSelected={mode === "topology"} onChange={() => { setMode("topology"); setDrawer(null); setHover(null) }} />
                        <ToggleGroupItem text={_("Rule graph")} isSelected={mode === "rules"} onChange={() => { setMode("rules"); setDrawer(null); setHover(null) }} />
                    </ToggleGroup>
                </ToolbarItem>
                <ToolbarItem>
                    <SearchInput
                        placeholder={mode === "topology" ? _("Search: port 22, eth0, sshd") : _("Search: drop, DOCKER, @trusted")}
                        value={query} onChange={(_e, v) => setQuery(v)} onClear={() => setQuery("")}
                    />
                </ToolbarItem>
                {mode === "topology" && !phone && (
                    <>
                        <ToolbarItem>
                            <FormSelect value={focusValue} onChange={(_e, v) => setFocusValue(v)} aria-label={_("Focus")}>
                                <FormSelectOption value="" label={_("Focus: everything")} />
                                {zones.map(z => <FormSelectOption key={z.id} value={`z:${z.id}`} label={cockpit.format(_("Zone: $0"), z.label)} />)}
                                {ifaceNames.map(n => <FormSelectOption key={n} value={`i:${n}`} label={cockpit.format(_("Interface: $0"), n)} />)}
                                {topo.services.map(s => <FormSelectOption key={s.id} value={`s:${s.id}`} label={cockpit.format(_("Service: $0"), s.name)} />)}
                            </FormSelect>
                        </ToolbarItem>
                        <ToolbarItem alignSelf="center">
                            <Switch id="map-blocked" label={_("Show blocked")} isChecked={showBlocked} onChange={(_e, v) => setShowBlocked(v)} />
                        </ToolbarItem>
                    </>
                )}
                <ToolbarItem>
                    <Button variant={lookupOpen ? "primary" : "secondary"} onClick={() => setLookupOpen(v => !v)}>{_("Is this allowed?")}</Button>
                </ToolbarItem>
                {!phone && (
                    <ToolbarItem>
                        <Button variant="plain" aria-label={_("Zoom out")} icon={<SearchMinusIcon />} onClick={() => setZoom(z => Math.max(0.4, z / 1.2))} />
                        <Button variant="plain" aria-label={_("Zoom in")} icon={<SearchPlusIcon />} onClick={() => setZoom(z => Math.min(2, z * 1.2))} />
                        <Button variant="link" onClick={clearAll}>{_("Fit")}</Button>
                    </ToolbarItem>
                )}
            </ToolbarContent>
        </Toolbar>
    );

    const legend = mode === "topology"
        ? (
            <Flex className="cnft-legend" alignItems={{ default: "alignItemsCenter" }} spaceItems={{ default: "spaceItemsSm" }}>
                <LabelGroup numLabels={10}>
                    <Label isCompact color="green">{_("Allow")}</Label>
                    <Label isCompact color="red">{_("Block (dashed)")}</Label>
                    <Label isCompact color="orange">{_("Partial")}</Label>
                    <Label isCompact color="purple">{_("Docker (dashed)")}</Label>
                    <Label isCompact color="grey">{_("? can't evaluate (dashed)")}</Label>
                </LabelGroup>
                <FlexItem className="cnft-muted cnft-small">
                    {focus
                        ? _("Focused: click the node again or Fit to go back to the bundled view.")
                        : _("Edges are bundled per interface: grey = zones arriving there, coloured = what those zones get. Click a zone, interface or service to expand it.")}
                </FlexItem>
            </Flex>
        )
        : (
            <div className="cnft-legend cnft-muted cnft-small">
                {_("Incoming IPv4 path (ip and inet tables). Base chains run top to bottom in priority order, every table on the same packet; regular chains hang off the chain that jumps to them. Click a hook to expand or collapse it, a chain to see its rules.")}
            </div>
        );

    const canvas = phone
        ? (mode === "topology"
            ? <PhoneTopology zones={zones} services={topo.services} cells={cells} open={openDrawer} />
            : <PhoneRules layout={rules} open={setDrawer} />)
        : (mode === "topology"
            ? (topo.services.length
                ? <TopoCanvas layout={topo} scale={scale} onEdge={onEdge} onNode={onNode} hot={hot} onHover={setHover} />
                : <Alert isInline isPlain variant="info" title={_("Nothing reachable from any zone. Turn on \"Show blocked\" to see blocked services.")} />)
            : <RulesCanvas layout={rules} scale={scale} lit={litKeys} decider={decider} query={query} selected={drawer?.kind === "chain" ? drawer.key : null} onNode={onRuleNode} hover={mode === "rules" ? hover : null} onHover={setHover} />);

    return (
        <Card isCompact>
            <CardBody>
                {toolbar}
                {lookupOpen && (
                    <div className="cnft-map-lookup">
                        <Lookup model={model} ifaces={ifaces} ruleText={ruleText} onResult={onLookup} />
                    </div>
                )}
                {legend}
                <div ref={ref} className={`cnft-map-body${drawer && !phone && width >= 1000 ? " cnft-with-panel" : ""}`}>
                    <div className="cnft-map-canvas">{canvas}</div>
                    {drawer && (
                        <DrawerPanel
                            drawer={drawer} close={() => { setDrawer(null); setLit(null); setLitTrace(null) }}
                            zones={zones} services={services} cells={cells} tables={tables} ruleText={ruleText} open={openDrawer}
                        />
                    )}
                </div>
            </CardBody>
        </Card>
    );
}
