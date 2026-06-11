// v1.4.1 F-37 (P3 Codex audit on v1.4.0) — uninstall doc/behavior alignment.
//
// Before F-37, SECURITY.md claimed `wma-service uninstall` deleted the env
// file + the whole ~/.watchmyagents dir. The actual implementation left
// them intact (intentional: avoids destroying snapshotted keys on a
// reinstall). The fix:
//
//   - default `uninstall`        → leaves ~/.watchmyagents/env intact (unchanged)
//   - new opt-in `--purge` flag  → removes env file + config dir
//   - SECURITY.md + README       → describe both modes truthfully
//
// We can't easily run the full uninstall path here (it calls launchctl /
// systemctl). What we CAN guard is the documentation surface and the
// presence of the purge branch in the script source. If a future refactor
// silently drops `--purge` from the CLI or the docs, this test fires.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';

const SERVICE_SCRIPT = fileURLToPath(new URL('../scripts/service.js', import.meta.url));
const SECURITY_MD   = fileURLToPath(new URL('../SECURITY.md', import.meta.url));
const README_MD     = fileURLToPath(new URL('../README.md', import.meta.url));

test('F-37: wma-service help text advertises uninstall --purge', () => {
  // `wma-service` with no command prints usage() to stdout. We invoke the
  // script directly via node (no install) to read its self-described surface.
  const res = spawnSync(process.execPath, [SERVICE_SCRIPT], { encoding: 'utf8' });
  // usage() prints to stdout and exits 0.
  assert.equal(res.status, 0, `expected exit 0, got ${res.status}: ${res.stderr}`);
  assert.match(res.stdout, /uninstall \[--with-shield\] \[--purge\]/);
  assert.match(res.stdout, /--purge to also delete the env file/i);
});

test('F-37: service.js source has the --purge branch that wipes ENV_FILE + CONFIG_DIR', async () => {
  const src = await readFile(SERVICE_SCRIPT, 'utf8');
  assert.match(src, /const purge = !!args\.purge;/);
  assert.match(src, /rmSync\(ENV_FILE/);
  assert.match(src, /rmSync\(CONFIG_DIR/);
});

test('F-37: SECURITY.md documents BOTH default-preserve and --purge modes', async () => {
  const md = await readFile(SECURITY_MD, 'utf8');
  // Default behavior — preservation must be explicit, not a vague "may keep".
  assert.match(md, /leaves `~\/\.watchmyagents\/env` on disk/);
  // Opt-in purge mode must be documented.
  assert.match(md, /wma-service uninstall --purge/);
});

test('F-37: README.md mentions --purge under the wma-service section', async () => {
  const md = await readFile(README_MD, 'utf8');
  assert.match(md, /uninstall \[--with-shield\] \[--purge\]/);
  assert.match(md, /--purge` to also delete the env file/i);
});
