// ────────────────────────────────────────────────────────────────────────
// version — shared --version flag handler for the wma-* CLI binaries
// ────────────────────────────────────────────────────────────────────────
//
// v1.1.1 F-13: every CLI binary (wma-fetch, wma-shield, wma-signals,
// wma-upload-fortress, wma-inspect, wma-agents, wma-service) gets a
// --version / -v flag that prints the installed version and exits.
// Operators previously had to grep package.json under npm root to know
// what was deployed; this is now a one-liner.
//
// We resolve the version from the package.json next to the SDK source
// (../package.json relative to this file) so it stays in sync with the
// release that's actually executing.

import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = dirname(fileURLToPath(import.meta.url));
const PKG_PATH = join(HERE, '..', 'package.json');

let cachedVersion = null;

/** Returns the installed watchmyagents version, parsed from package.json. */
export function getVersion() {
  if (cachedVersion) return cachedVersion;
  try {
    const pkg = JSON.parse(readFileSync(PKG_PATH, 'utf8'));
    cachedVersion = pkg.version || 'unknown';
  } catch {
    cachedVersion = 'unknown';
  }
  return cachedVersion;
}

/**
 * If argv contains --version or -v, print the version and exit(0).
 * Call this BEFORE any other parsing so it short-circuits on bad input
 * (e.g., the user types `wma-fetch --version` with no env vars set).
 *
 * Usage at the top of every wma-* script:
 *   import { maybePrintVersionAndExit } from '../src/version.js';
 *   maybePrintVersionAndExit(process.argv);
 */
export function maybePrintVersionAndExit(argv) {
  for (const a of argv) {
    if (a === '--version' || a === '-v') {
      process.stdout.write(`watchmyagents ${getVersion()}\n`);
      process.exit(0);
    }
  }
}
