/*
 * SPDX-License-Identifier: LGPL-2.1-or-later
 *
 * Static preview: renders the real UI from a captured helper `read` result
 * (preview-dist/fixture.json, never committed). No Cockpit session, no helper,
 * nothing that can change the system. Build: CNFT_PREVIEW=1 ./build.js
 */

import React from 'react';
import { createRoot } from 'react-dom/client';

import "cockpit-dark-theme";

import { Application } from './app.jsx';
import type { ReadResult } from './lib/helper';

import "patternfly/patternfly-6-cockpit.scss";
import "@patternfly/patternfly/components/Table/table.css";
import "@patternfly/patternfly/utilities/Spacing/spacing.css";
import './app.scss';

document.addEventListener("DOMContentLoaded", async () => {
    const fixture = await (await fetch("fixture.json")).json() as ReadResult;
    createRoot(document.getElementById("app")!).render(<Application fixture={fixture} />);
});
