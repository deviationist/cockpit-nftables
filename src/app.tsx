/*
 * SPDX-License-Identifier: LGPL-2.1-or-later
 *
 * Copyright (C) 2026 deviationist
 */

import React, { useCallback, useEffect, useMemo, useState } from 'react';
import { Alert, AlertActionLink } from "@patternfly/react-core/dist/esm/components/Alert/index.js";
import { Button } from "@patternfly/react-core/dist/esm/components/Button/index.js";
import { EmptyState, EmptyStateBody, EmptyStateFooter } from "@patternfly/react-core/dist/esm/components/EmptyState/index.js";
import { Page, PageSection } from "@patternfly/react-core/dist/esm/components/Page/index.js";
import { Spinner } from "@patternfly/react-core/dist/esm/components/Spinner/index.js";
import { Tab, TabTitleText, Tabs } from "@patternfly/react-core/dist/esm/components/Tabs/index.js";
import { Content } from "@patternfly/react-core/dist/esm/components/Content/index.js";
import { Flex, FlexItem } from "@patternfly/react-core/dist/esm/layouts/Flex/index.js";
import { LockIcon } from "@patternfly/react-icons/dist/esm/icons/lock-icon.js";
import { SyncAltIcon } from "@patternfly/react-icons/dist/esm/icons/sync-alt-icon.js";

import cockpit from 'cockpit';

import { Editor } from './Editor';
import { RulesetView } from './Ruleset';
import { requestAdmin, useAdmin } from './lib/admin';
import { declaredTables, tableSet } from './lib/conf-lint';
import { buildModel } from './lib/evaluate';
import { deriveZones, groupServices, parseDefaultRoute, parseIfaces, parseSs, saddrRefs } from './lib/zones';
import { MapView } from './Map';
import { MatrixView } from './Matrix';
import { ReadResult, confirmApply, readState, revertApply } from './lib/helper';
import { classify, overlayJson, parseIptablesManaged, parseRuleset, tableKey } from './lib/ruleset-parse';

const _ = cockpit.gettext;

const POLL = 10000;

// Tabs live in the URL (cockpit.location: …/nftables#/map/rules), so a reload,
// the back button or a shared link lands on the same view. Same pattern as
// cockpit-upside.
const TABS = ["matrix", "map", "ruleset", "config"];

function usePageLocation() {
    const [location, setLocation] = useState(cockpit.location);
    useEffect(() => {
        const update = () => setLocation(cockpit.location);
        cockpit.addEventListener("locationchanged", update);
        return () => cockpit.removeEventListener("locationchanged", update);
    }, []);
    return location;
}

function PendingBanner({ data, onDone }: { data: ReadResult; onDone: () => void }) {
    const p = data.pending!;
    // Count down locally from the server's seconds_left (no clock-skew issues).
    const [left, setLeft] = useState(p.seconds_left);
    const [busy, setBusy] = useState(false);
    useEffect(() => {
        setLeft(p.seconds_left);
        const t = window.setInterval(() => setLeft(l => Math.max(0, l - 1)), 1000);
        return () => window.clearInterval(t);
    }, [p.seconds_left, p.deadline]);
    useEffect(() => {
        if (left === 0) {
            const t = window.setTimeout(onDone, 2000); // the timer has fired; re-read
            return () => window.clearTimeout(t);
        }
    }, [left, onDone]);

    const act = async (fn: () => Promise<unknown>) => {
        setBusy(true);
        try {
            await fn();
        } finally {
            setBusy(false);
            onDone();
        }
    };
    const title = left > 0
        ? cockpit.format(_("New config applied. It will be undone in $0 s unless you confirm."), left)
        : _("Time is up: undoing the change…");
    const actions = left > 0 && (
        <>
            <AlertActionLink onClick={() => act(confirmApply)} isDisabled={busy}>{_("Keep this config")}</AlertActionLink>
            <AlertActionLink onClick={() => act(revertApply)} isDisabled={busy}>{_("Revert now")}</AlertActionLink>
        </>
    );
    return (
        <Alert
            variant="warning" isInline className="pf-v6-u-mb-md"
            title={title}
            actionLinks={actions}
        >
            {cockpit.format(_("Backup of the previous file: $0"), p.backup)}
            {p.timer_active === false && left > 0 &&
                <div><strong>{_("Warning: the undo timer is not active. Revert manually if needed.")}</strong></div>}
        </Alert>
    );
}

/** `fixture` = static preview (npm run preview): render a captured read
 *  result, skip admin and the helper entirely. Never set in the real plugin. */
export function Application({ fixture }: { fixture?: ReadResult } = {}) {
    const realAdmin = useAdmin();
    const admin = fixture ? true : realAdmin;
    const [data, setData] = useState<ReadResult | null>(fixture ?? null);
    const [error, setError] = useState<string | null>(null);
    const location = usePageLocation();
    const tab = TABS.includes(location.path[0]) ? location.path[0] : "matrix";
    const mapMode = location.path[1] === "rules" ? "rules" : "topology";
    const [draft, setDraft] = useState<string | null>(null);

    const refresh = useCallback(async () => {
        if (fixture) return;
        try {
            const d = await readState();
            setData(d);
            setError(null);
            // Adopt the file as the draft when the operator has no unsaved edits.
            setDraft(prev => (prev === null ? d.conf.text : prev));
        } catch (e) {
            setError(String((e as Error).message ?? e));
        }
    }, [fixture]);

    useEffect(() => {
        if (!admin) return;
        refresh();
        const t = window.setInterval(refresh, POLL);
        return () => window.clearInterval(t);
    }, [admin, refresh]);

    // When the file changes underneath (applied here, reverted, or edited
    // elsewhere) and the operator has no edits, follow it.
    const [lastSha, setLastSha] = useState<string | null>(null);
    useEffect(() => {
        if (!data) return;
        if (lastSha !== null && lastSha !== data.conf.sha256)
            setDraft(prev => (prev === null || prev === data.conf.text ? data.conf.text : prev));
        setLastSha(data.conf.sha256);
    }, [data, lastSha]);

    const parsed = useMemo(() => {
        if (!data) return null;
        const managed = parseIptablesManaged(data.ruleset_stderr);
        const conf = tableSet(declaredTables(data.conf.text));
        const tables = classify(overlayJson(parseRuleset(data.ruleset), data.ruleset_json), conf, managed);
        const foreign = new Set(tables.filter(t => t.owner !== "config").map(t => tableKey(t.family, t.name)));
        // Zone Matrix inputs
        const ifaces = parseIfaces(data.addrs);
        const model = buildModel(data.ruleset_json, ifaces.map(f => f.addr));
        const zones = deriveZones(ifaces, parseDefaultRoute(data.routes), saddrRefs(model, conf));
        const services = groupServices(parseSs(data.ss));
        const texts = new Map<string, string>();
        for (const t of tables)
            for (const c of t.chains)
                for (const r of c.rules)
                    if (r.handle !== null) texts.set(`${t.family} ${t.name} ${c.name} ${r.handle}`, r.text);
        const ruleText = (family: string, table: string, chain: string, handle: number | null) =>
            handle === null ? null : texts.get(`${family} ${table} ${chain} ${handle}`) ?? null;
        return { tables, foreign, ifaces, model, zones, services, ruleText };
    }, [data]);

    if (admin === null)
        return <Page><PageSection><Spinner /></PageSection></Page>;
    if (!admin)
        return (
            <Page className="no-masthead-sidebar">
                <PageSection>
                    <EmptyState headingLevel="h2" icon={LockIcon} titleText={_("Administrative access required")}>
                        <EmptyStateBody>{_("Reading and changing the firewall needs administrative access.")}</EmptyStateBody>
                        <EmptyStateFooter>
                            <Button variant="primary" onClick={() => requestAdmin()}>{_("Turn on administrative access")}</Button>
                        </EmptyStateFooter>
                    </EmptyState>
                </PageSection>
            </Page>
        );

    const dirty = data !== null && draft !== null && draft !== data.conf.text;
    const fileChanged = dirty && lastSha !== null && data && data.conf.sha256 !== lastSha;

    return (
        <Page className="no-masthead-sidebar">
            <PageSection hasBodyWrapper={false}>
                <Flex alignItems={{ default: "alignItemsCenter" }} justifyContent={{ default: "justifyContentSpaceBetween" }}>
                    <FlexItem>
                        <Content component="h1">{_("nftables")}</Content>
                        <Content component="small">
                            {_("The live ruleset from every program, and your config file as the source of truth.")}
                        </Content>
                    </FlexItem>
                    <FlexItem>
                        <Button variant="plain" aria-label={_("Refresh")} onClick={refresh} icon={<SyncAltIcon />} />
                    </FlexItem>
                </Flex>
            </PageSection>
            <PageSection hasBodyWrapper={false}>
                {error && <Alert isInline variant="danger" className="pf-v6-u-mb-md" title={_("Could not read the firewall")}>{error}</Alert>}
                {data?.pending && <PendingBanner data={data} onDone={refresh} />}
                {fileChanged && <Alert isInline variant="warning" className="pf-v6-u-mb-md" title={_("The file changed on disk while you were editing. Discard your changes to load it.")} />}
                {(!data || !parsed) && <Spinner />}
                {data && parsed &&
                    <Tabs activeKey={tab} onSelect={(_e, k) => cockpit.location.go([String(k)])} mountOnEnter>
                        <Tab eventKey="matrix" title={<TabTitleText>{_("Who can reach what")}</TabTitleText>}>
                            <div className="pf-v6-u-mt-md">
                                <MatrixView
                                    model={parsed.model} zones={parsed.zones} services={parsed.services}
                                    ifaces={parsed.ifaces} ruleText={parsed.ruleText}
                                />
                            </div>
                        </Tab>
                        <Tab eventKey="map" title={<TabTitleText>{_("Map")}</TabTitleText>}>
                            <div className="pf-v6-u-mt-md">
                                <MapView
                                    model={parsed.model} zones={parsed.zones} services={parsed.services}
                                    ifaces={parsed.ifaces} tables={parsed.tables} ruleText={parsed.ruleText}
                                    mode={mapMode} onMode={m => cockpit.location.go(m === "rules" ? ["map", "rules"] : ["map"])}
                                />
                            </div>
                        </Tab>
                        <Tab eventKey="ruleset" title={<TabTitleText>{_("Live ruleset")}</TabTitleText>}>
                            <div className="pf-v6-u-mt-md">
                                {!data.ruleset_ok && <Alert isInline variant="danger" title={_("nft list ruleset failed")}>{data.ruleset_stderr}</Alert>}
                                <RulesetView tables={parsed.tables} />
                            </div>
                        </Tab>
                        <Tab eventKey="config" title={<TabTitleText>{dirty ? _("Configuration •") : _("Configuration")}</TabTitleText>}>
                            <div className="pf-v6-u-mt-md">
                                <Editor
                                    data={data} foreignTables={parsed.foreign} draft={draft ?? data.conf.text}
                                    setDraft={setDraft} onApplied={refresh}
                                />
                            </div>
                        </Tab>
                    </Tabs>}
            </PageSection>
        </Page>
    );
}
