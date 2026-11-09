#!/usr/bin/env node
// SPDX-License-Identifier: LGPL-2.1-or-later
//
// Render the README screenshots from the static preview (preview-dist/, with
// the demo fixture from fixture.sh). Serves the preview on 127.0.0.1 only,
// drives a headless browser through each view, writes docs/screenshots/*.png.
//
//   npm run screenshots     (builds, makes the fixture with sudo, then runs this)
//
// Browser: Playwright's own Chromium if installed (npx playwright-core install
// chromium), else the system Google Chrome. Override with CNFT_BROWSER_CHANNEL.

import fs from 'node:fs';
import http from 'node:http';
import path from 'node:path';
import process from 'node:process';
import { fileURLToPath } from 'node:url';

import { chromium } from 'playwright-core';

const REPO = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const SITE = path.join(REPO, 'preview-dist');
const OUT = path.join(REPO, 'docs/screenshots');
const VIEWPORT = { width: 1280, height: 860 };

if (!fs.existsSync(path.join(SITE, 'fixture.json'))) {
    console.error('preview-dist/fixture.json missing: run `npm run screenshots` (or tools/screenshots/fixture.sh) first');
    process.exit(1);
}

/* ---- static server for preview-dist (+ Cockpit's fonts if installed) ---- */
const TYPES = { '.html': 'text/html', '.js': 'text/javascript', '.css': 'text/css', '.json': 'application/json', '.woff2': 'font/woff2', '.map': 'application/json' };
const FONTS = '/usr/share/cockpit/static/fonts';
const server = http.createServer((req, res) => {
    const url = decodeURIComponent(new URL(req.url, 'http://x').pathname);
    let file = url.startsWith('/static/fonts/') ? path.join(FONTS, url.slice('/static/fonts/'.length)) : path.join(SITE, url === '/' ? 'index.html' : url);
    file = path.normalize(file);
    if (!file.startsWith(SITE) && !file.startsWith(FONTS)) {
        res.writeHead(403).end();
        return;
    }
    fs.readFile(file, (err, data) => {
        if (err) {
            res.writeHead(404).end();
            return;
        }
        res.writeHead(200, { 'Content-Type': TYPES[path.extname(file)] ?? 'application/octet-stream' }).end(data);
    });
});
await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
const BASE = `http://127.0.0.1:${server.address().port}/`;

/* ---- browser ---- */
async function launch() {
    const channel = process.env.CNFT_BROWSER_CHANNEL;
    if (channel) return chromium.launch({ channel });
    try {
        return await chromium.launch();
    } catch {
        return chromium.launch({ channel: 'chrome' });
    }
}
const browser = await launch();
fs.mkdirSync(OUT, { recursive: true });

async function page(hash, { dark = false } = {}) {
    const ctx = await browser.newContext({ viewport: VIEWPORT, deviceScaleFactor: 2, colorScheme: dark ? 'dark' : 'light' });
    const p = await ctx.newPage();
    await p.goto(BASE + hash);
    await p.waitForSelector('.pf-v6-c-tabs');
    await p.evaluate(() => document.fonts.ready);
    return p;
}

async function shot(p, name) {
    await p.waitForTimeout(250); // let transitions settle
    await p.screenshot({ path: path.join(OUT, name) });
    await p.context().close();
    console.log('wrote docs/screenshots/' + name);
}

const scenarios = {
    async 'matrix.png'() {
        const p = await page('#/');
        await p.waitForSelector('.cnft-matrix');
        await p.locator('.cnft-matrix tbody tr', { hasText: 'sshd' }).locator('td').nth(3).locator('button').click();
        await shot(p, 'matrix.png');
    },
    async 'map-topology.png'() {
        const p = await page('#/map');
        await p.waitForSelector('.cnft-node-zone');
        await p.locator('.cnft-node-zone', { hasText: '@trusted' }).first().hover();
        await shot(p, 'map-topology.png');
    },
    async 'map-trace.png'() {
        const p = await page('#/map');
        await p.locator('.cnft-node-zone', { hasText: 'Rest of' }).click();
        await p.locator('g.cnft-edge[aria-label^="nginx from"]').first().click();
        await p.waitForSelector('.cnft-drawer');
        await shot(p, 'map-trace.png');
    },
    async 'map-rules.png'() {
        const p = await page('#/map/rules');
        await p.waitForSelector('.cnft-rnode-header');
        await p.getByRole('button', { name: 'Is this allowed?' }).click();
        const form = p.locator('.cnft-map-lookup');
        await form.locator('input[type=text]').fill('192.168.1.50');
        await form.getByRole('button', { name: 'Trace' }).click();
        await p.waitForSelector('.cnft-drawer');
        await shot(p, 'map-rules.png');
    },
    async 'ruleset.png'() {
        const p = await page('#/ruleset');
        await p.waitForSelector('.cnft-table-card');
        await shot(p, 'ruleset.png');
    },
    async 'config.png'() {
        const p = await page('#/config');
        const editor = p.locator('textarea.pf-v6-c-form-control, .cnft-editor textarea').first();
        await editor.waitFor();
        // A realistic edit: open a port, plus a table that isn't reset first (the lint flags it).
        const text = await editor.inputValue();
        await editor.fill(text.replace('udp dport 51820 accept comment "WireGuard"',
                                       'udp dport 51820 accept comment "WireGuard"\n        tcp dport 9100 ip saddr @trusted accept comment "metrics"') +
                          '\ntable inet extra {\n    chain c { }\n}\n');
        await p.getByRole('button', { name: 'Review changes' }).click();
        await shot(p, 'config.png');
    },
    async 'map-topology-dark.png'() {
        const p = await page('#/map', { dark: true });
        await p.waitForSelector('.cnft-node-zone');
        await p.locator('.cnft-node-service', { hasText: 'sshd' }).first().hover();
        await shot(p, 'map-topology-dark.png');
    },
};

const only = process.argv.slice(2);
let failed = 0;
for (const [name, run] of Object.entries(scenarios)) {
    if (only.length && !only.includes(name)) continue;
    try {
        await run();
    } catch (e) {
        failed++;
        console.error(`FAILED ${name}: ${e.message.split('\n')[0]}`);
    }
}
await browser.close();
server.close();
process.exit(failed ? 1 : 0);
