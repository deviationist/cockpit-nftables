/*
 * SPDX-License-Identifier: LGPL-2.1-or-later
 *
 * Copyright (C) 2017 Red Hat, Inc.
 */

import React from 'react';
import { createRoot } from 'react-dom/client';

import "cockpit-dark-theme";

import { Application } from './app.jsx';

import "patternfly/patternfly-6-cockpit.scss";
// Cockpit's curated PatternFly bundle omits the Table styles and the utilities
// layer; pull in the standalone CSS (same as cockpit-upside).
import "@patternfly/patternfly/components/Table/table.css";
import "@patternfly/patternfly/utilities/Spacing/spacing.css";
import './app.scss';

document.addEventListener("DOMContentLoaded", () => {
    createRoot(document.getElementById("app")!).render(<Application />);
});
