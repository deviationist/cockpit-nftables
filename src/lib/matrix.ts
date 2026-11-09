/*
 * SPDX-License-Identifier: LGPL-2.1-or-later
 *
 * Copyright (C) 2026 deviationist
 *
 * Zone Matrix cells: for one source zone and one listening service, evaluate a
 * test packet per port and summarise. Pure + Cockpit-free.
 */

import type { Model, Trace } from './evaluate.ts';
import { evaluate } from './evaluate.ts';
import type { Service, Zone } from './zones.ts';

export type CellState = "allow" | "block" | "partial" | "unknown" | "docker" | "none";

export interface PortTrace {
    port: number;
    trace: Trace;
}

export interface Cell {
    state: CellState;
    allowed: number;
    total: number;
    traces: PortTrace[];
    note?: string;
}

export function cellFor(model: Model, zone: Zone, svc: Service): Cell {
    if (svc.bind !== "*" && svc.bind !== zone.daddr)
        return { state: "none", allowed: 0, total: 0, traces: [], note: `listens only on ${svc.bind}` };
    if (svc.scope && svc.scope !== zone.iif)
        return { state: "none", allowed: 0, total: 0, traces: [], note: `listens only on ${svc.scope}` };
    if (svc.docker)
        return {
            state: "docker",
            allowed: 0,
            total: svc.ports.length,
            traces: [],
            note: "Published by Docker: decided by Docker's DNAT and FORWARD rules (DOCKER-USER), not the input chain.",
        };

    const traces = svc.ports.map(port => ({
        port,
        trace: evaluate(model, { iif: zone.iif, saddr: zone.saddr, daddr: zone.daddr, proto: svc.proto, dport: port }),
    }));
    const allowed = traces.filter(t => t.trace.outcome === "accept").length;
    const blocked = traces.filter(t => t.trace.outcome === "drop").length;
    const unknown = traces.filter(t => t.trace.outcome === "unknown" || t.trace.outcome === "dnat").length;
    let state: CellState;
    if (unknown) state = "unknown";
    else if (allowed === traces.length) state = "allow";
    else if (blocked === traces.length) state = "block";
    else state = "partial";
    return { state, allowed, total: traces.length, traces };
}
