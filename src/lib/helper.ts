/*
 * SPDX-License-Identifier: LGPL-2.1-or-later
 *
 * Copyright (C) 2026 deviationist
 *
 * Talks to the privileged helper (src/helper/nft_helper.py). The helper source
 * is bundled as text (build.js loads .py as text) and run with `python3 -I -c`,
 * so nothing outside the package decides what runs as root.
 */

import cockpit from 'cockpit';

import HELPER from '../helper/nft_helper.py';

export interface ConfFile {
    path: string;
    exists: boolean;
    text: string;
    sha256: string;
    mtime: number;
}

export interface Pending {
    deadline: number;
    timeout: number;
    backup: string;
    added_tables: [string, string][];
    applied_at: number;
    seconds_left: number;
    timer_active?: boolean;
}

export interface ReadResult {
    conf: ConfFile;
    ruleset: string;
    ruleset_stderr: string;
    ruleset_json: string;
    ss: string;
    addrs: string;
    routes: string;
    ruleset_ok: boolean;
    apply_enabled: boolean;
    apply_enabled_flag: string;
    pending: Pending | null;
    backup_dir: string;
}

export interface Result {
    ok: boolean;
    error?: string | null;
}

export interface ApplyResult extends Result {
    deadline?: number;
    timeout?: number;
    backup?: string;
}

async function run<T>(cmd: string, body?: unknown): Promise<T> {
    const proc = cockpit.spawn(["python3", "-I", "-c", HELPER, cmd], { superuser: "require", err: "message" });
    const output = await (body === undefined ? proc : proc.input(JSON.stringify(body)));
    return JSON.parse(output) as T;
}

export const readState = () => run<ReadResult>("read");
export const checkConfig = (text: string) => run<Result>("check", { text });
export const confirmApply = () => run<Result>("confirm");
export const revertApply = () => run<Result>("revert");
export const applyConfig = (text: string, base_sha256: string, timeout: number, added_tables: [string, string][]) =>
    run<ApplyResult>("apply", { text, base_sha256, timeout, added_tables });
