/*
 * SPDX-License-Identifier: LGPL-2.1-or-later
 *
 * Copyright (C) 2026 deviationist
 *
 * The Configuration tab: edit the config file, lint + `nft -c` it, review the
 * diff, then apply with an auto-undo timer.
 */

import React, { useMemo, useRef, useState } from 'react';
import { Alert } from "@patternfly/react-core/dist/esm/components/Alert/index.js";
import { Button } from "@patternfly/react-core/dist/esm/components/Button/index.js";
import { Card, CardBody, CardTitle } from "@patternfly/react-core/dist/esm/components/Card/index.js";
import { FormSelect, FormSelectOption } from "@patternfly/react-core/dist/esm/components/FormSelect/index.js";
import { Label } from "@patternfly/react-core/dist/esm/components/Label/index.js";
import { List, ListItem } from "@patternfly/react-core/dist/esm/components/List/index.js";
import { Modal, ModalBody, ModalFooter, ModalHeader } from "@patternfly/react-core/dist/esm/components/Modal/index.js";
import { TextArea } from "@patternfly/react-core/dist/esm/components/TextArea/index.js";
import { Toolbar, ToolbarContent, ToolbarItem } from "@patternfly/react-core/dist/esm/components/Toolbar/index.js";
import { Flex, FlexItem } from "@patternfly/react-core/dist/esm/layouts/Flex/index.js";

import cockpit from 'cockpit';

import { Finding, addedTables, lint, worst } from './lib/conf-lint';
import { changeCount, hunks } from './lib/diff';
import { ReadResult, Result, applyConfig, checkConfig } from './lib/helper';

const _ = cockpit.gettext;

const SEVERITY_VARIANT = { danger: "danger", warning: "warning", info: "info" } as const;

function DiffView({ before, after }: { before: string; after: string }) {
    const hs = useMemo(() => hunks(before, after), [before, after]);
    if (!hs.length) return <p>{_("No changes.")}</p>;
    return (
        <div className="cnft-diff cnft-mono">
            {hs.map((h, i) => (
                <div key={i} className="cnft-hunk">
                    <div className="cnft-hunk-head">{`@@ -${h.oldStart} +${h.newStart} @@`}</div>
                    {h.lines.map((l, j) => (
                        <div key={j} className={`cnft-diff-line cnft-diff-${l.op}`}>
                            <span className="cnft-diff-no">{l.oldNo ?? ""}</span>
                            <span className="cnft-diff-no">{l.newNo ?? ""}</span>
                            <span className="cnft-diff-sign">{l.op === "add" ? "+" : l.op === "del" ? "-" : " "}</span>
                            <span className="cnft-diff-text">{l.text}</span>
                        </div>
                    ))}
                </div>
            ))}
        </div>
    );
}

function FindingTitle({ finding: f, onJump }: { finding: Finding; onJump: (line: number) => void }) {
    if (f.line === undefined) return <span>{f.message}</span>;
    return (
        <>
            <Button variant="link" isInline onClick={() => onJump(f.line!)}>
                {cockpit.format(_("Line $0"), f.line)}
            </Button>
            {": "}
            {f.message}
        </>
    );
}

function Findings({ findings, onJump }: { findings: Finding[]; onJump: (line: number) => void }) {
    if (!findings.length) return null;
    return (
        <List isPlain className="cnft-findings">
            {findings.map((f, i) => (
                <ListItem key={i}>
                    <Alert
                        isInline isPlain variant={SEVERITY_VARIANT[f.severity]}
                        title={<FindingTitle finding={f} onJump={onJump} />}
                    />
                </ListItem>
            ))}
        </List>
    );
}

interface Props {
    data: ReadResult;
    foreignTables: Set<string>;
    draft: string;
    setDraft: (s: string) => void;
    onApplied: () => void;
}

export function Editor({ data, foreignTables, draft, setDraft, onApplied }: Props) {
    const base = data.conf.text;
    const area = useRef<HTMLTextAreaElement>(null);
    const [check, setCheck] = useState<{ text: string; result: Result } | null>(null);
    const [busy, setBusy] = useState(false);
    const [error, setError] = useState<string | null>(null);
    const [showDiff, setShowDiff] = useState(false);
    const [confirmOpen, setConfirmOpen] = useState(false);
    const [timeout, setTimeoutSecs] = useState("60");

    const dirty = draft !== base;
    const findings = useMemo(() => lint(base, draft, { foreignTables }), [base, draft, foreignTables]);
    const level = worst(findings);
    const counts = useMemo(() => changeCount(base, draft), [base, draft]);
    const checkedThis = check?.text === draft;
    const checkOk = checkedThis && check!.result.ok;
    const pending = !!data.pending;

    const jump = (line: number) => {
        const el = area.current;
        if (!el) return;
        const lines = draft.split("\n");
        const start = lines.slice(0, line - 1).reduce((a, l) => a + l.length + 1, 0);
        el.focus();
        el.setSelectionRange(start, start + (lines[line - 1]?.length ?? 0));
        // scroll roughly to the line
        el.scrollTop = Math.max(0, (line - 5) * (el.scrollHeight / Math.max(lines.length, 1)));
    };

    const runCheck = async () => {
        setBusy(true);
        setError(null);
        try {
            setCheck({ text: draft, result: await checkConfig(draft) });
        } catch (e) {
            setError(String((e as Error).message ?? e));
        } finally {
            setBusy(false);
        }
    };

    const runApply = async () => {
        setBusy(true);
        setError(null);
        try {
            const r = await applyConfig(draft, data.conf.sha256, Number(timeout), addedTables(base, draft));
            setConfirmOpen(false);
            if (!r.ok) setError(r.error ?? _("Apply failed"));
            onApplied();
        } catch (e) {
            setError(String((e as Error).message ?? e));
        } finally {
            setBusy(false);
        }
    };

    let applyBlocker: string | null = null;
    if (!data.apply_enabled) applyBlocker = _("Applying is turned off on this host.");
    else if (pending) applyBlocker = _("Confirm or revert the previous apply first.");
    else if (!dirty) applyBlocker = _("No changes to apply.");
    else if (level === "danger") applyBlocker = _("Fix the problems marked as danger first.");
    else if (!checkOk) applyBlocker = _("Check the config first.");

    return (
        <>
            {!data.apply_enabled &&
                <Alert
                    isInline variant="info" className="pf-v6-u-mb-md"
                    title={_("Read-only on this host: you can edit and check, but not apply.")}
                >
                    {_("To allow applying, run:")}
                    <pre className="cnft-mono">{`sudo mkdir -p ${data.apply_enabled_flag.replace(/\/[^/]+$/, "")} && sudo touch ${data.apply_enabled_flag}`}</pre>
                </Alert>}
            {error && <Alert isInline variant="danger" className="pf-v6-u-mb-md" title={error} />}

            <Card isCompact>
                <CardTitle>
                    <Flex alignItems={{ default: "alignItemsCenter" }}>
                        <FlexItem><span className="cnft-mono">{data.conf.path}</span></FlexItem>
                        {dirty && <FlexItem><Label color="orange">{cockpit.format(_("+$0 −$1 lines, not applied"), counts.added, counts.removed)}</Label></FlexItem>}
                        {data.conf.text && !dirty && <FlexItem><Label color="green">{_("matches the file")}</Label></FlexItem>}
                    </Flex>
                </CardTitle>
                <CardBody>
                    <Toolbar>
                        <ToolbarContent>
                            <ToolbarItem>
                                <Button variant="secondary" onClick={runCheck} isDisabled={busy} isLoading={busy && !confirmOpen}>
                                    {_("Check")}
                                </Button>
                            </ToolbarItem>
                            <ToolbarItem>
                                <Button variant="secondary" onClick={() => setShowDiff(v => !v)} isDisabled={!dirty}>
                                    {showDiff ? _("Hide changes") : _("Review changes")}
                                </Button>
                            </ToolbarItem>
                            <ToolbarItem>
                                <Button
                                    variant="primary" onClick={() => setConfirmOpen(true)} isDisabled={!!applyBlocker || busy}
                                    title={applyBlocker ?? undefined}
                                >
                                    {_("Apply…")}
                                </Button>
                            </ToolbarItem>
                            <ToolbarItem>
                                <Button variant="link" onClick={() => { setDraft(base); setCheck(null) }} isDisabled={!dirty || busy}>
                                    {_("Discard changes")}
                                </Button>
                            </ToolbarItem>
                            {applyBlocker && dirty && <ToolbarItem alignSelf="center"><span className="cnft-muted">{applyBlocker}</span></ToolbarItem>}
                        </ToolbarContent>
                    </Toolbar>

                    {checkedThis && check!.result.ok &&
                        <Alert isInline isPlain variant="success" title={_("nft -c: the config is valid.")} />}
                    {checkedThis && !check!.result.ok &&
                        <Alert isInline variant="danger" title={_("nft -c rejected the config")}>
                            <pre className="cnft-mono cnft-pre">{check!.result.error}</pre>
                        </Alert>}
                    {check && !checkedThis && dirty && <Alert isInline isPlain variant="info" title={_("Edited since the last check.")} />}
                    <Findings findings={findings} onJump={jump} />

                    {showDiff && dirty && <DiffView before={base} after={draft} />}

                    <TextArea
                        ref={area} value={draft} onChange={(_e, v) => setDraft(v)}
                        className="cnft-mono cnft-editor" resizeOrientation="vertical"
                        spellCheck={false} aria-label={_("Config file")}
                    />
                </CardBody>
            </Card>

            <Modal isOpen={confirmOpen} onClose={() => setConfirmOpen(false)} variant="medium" aria-labelledby="apply-title">
                <ModalHeader title={_("Apply the new config?")} labelId="apply-title" titleIconVariant={level === "warning" ? "warning" : undefined} />
                <ModalBody>
                    <p>{cockpit.format(_("This writes $0 (+$1 −$2 lines), keeps a backup, and loads it with nft -f."), data.conf.path, counts.added, counts.removed)}</p>
                    <p className="pf-v6-u-mt-sm">
                        {_("If you don't confirm in time, the previous file is restored and reloaded automatically. That also happens if you lose access to this page.")}
                    </p>
                    <Flex className="pf-v6-u-mt-md" alignItems={{ default: "alignItemsCenter" }}>
                        <FlexItem>{_("Undo unless confirmed within")}</FlexItem>
                        <FlexItem>
                            <FormSelect value={timeout} onChange={(_e, v) => setTimeoutSecs(v)} aria-label={_("Timeout")}>
                                {["30", "60", "120", "300"].map(s => <FormSelectOption key={s} value={s} label={cockpit.format(_("$0 seconds"), s)} />)}
                            </FormSelect>
                        </FlexItem>
                    </Flex>
                    {findings.length > 0 && <div className="pf-v6-u-mt-md"><Findings findings={findings} onJump={() => setConfirmOpen(false)} /></div>}
                </ModalBody>
                <ModalFooter>
                    <Button variant={level === "warning" ? "warning" : "primary"} onClick={runApply} isLoading={busy} isDisabled={busy}>
                        {_("Apply")}
                    </Button>
                    <Button variant="link" onClick={() => setConfirmOpen(false)}>{_("Cancel")}</Button>
                </ModalFooter>
            </Modal>
        </>
    );
}
