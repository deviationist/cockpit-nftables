// SPDX-License-Identifier: LGPL-2.1-or-later
// build.js loads *.py with esbuild's text loader.
declare module '*.py' {
    const source: string;
    export default source;
}
