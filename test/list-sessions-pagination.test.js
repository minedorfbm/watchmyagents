// v1.4.2 F-45 (P1 audit) — listSessions must paginate the FULL list and
// filter by `since` per-row, never early-break on an assumed created_at
// ordering.
//
// THE BUG: the old code stopped paginating at the first session older than
// `since`, assuming newest-first created_at ordering. Nothing enforces that
// ordering. If an out-of-window session appeared before newer in-window ones
// (e.g. API ordered by id), pagination aborted and the newer sessions were
// NEVER enumerated — untraced agent activity.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { listSessions } from '../src/sources/anthropic-managed.js';

// Build a fake paged fetcher from an array of pages.
function fakeFetcher(pages) {
  let i = 0;
  return async () => {
    const page = pages[i] || [];
    const has_more = i < pages.length - 1;
    i++;
    return { data: page, has_more };
  };
}

const SINCE = new Date('2026-06-10T00:00:00Z');
const OLD = '2026-06-01T00:00:00Z';   // before SINCE
const NEW = '2026-06-11T00:00:00Z';   // after SINCE

test('F-45: an out-of-window session does NOT abort pagination (newer sessions still found)', async () => {
  // Adversarial ordering: an OLD session sits on page 1 BEFORE newer ones on
  // page 2. The old early-break would stop at the old one and miss s_new2.
  const pages = [
    [{ id: 's_new1', created_at: NEW }, { id: 's_old', created_at: OLD }],
    [{ id: 's_new2', created_at: NEW }],
  ];
  const out = await listSessions('k', { since: SINCE, _fetch: fakeFetcher(pages) });
  const ids = out.map((s) => s.id).sort();
  assert.deepEqual(ids, ['s_new1', 's_new2'], 's_new2 on a later page must still be enumerated');
  assert.equal(out.find((s) => s.id === 's_old'), undefined, 'out-of-window session is filtered out');
});

test('F-45: null created_at is treated as in-window (kept)', async () => {
  const pages = [[{ id: 's_nullts' /* no created_at */ }, { id: 's_old', created_at: OLD }]];
  const out = await listSessions('k', { since: SINCE, _fetch: fakeFetcher(pages) });
  assert.ok(out.find((s) => s.id === 's_nullts'), 'null created_at kept (cannot prove it is old)');
  assert.equal(out.find((s) => s.id === 's_old'), undefined);
});

test('F-45: with no `since`, every session across all pages is returned', async () => {
  const pages = [
    [{ id: 'a', created_at: OLD }, { id: 'b', created_at: NEW }],
    [{ id: 'c', created_at: OLD }],
  ];
  const out = await listSessions('k', { _fetch: fakeFetcher(pages) });
  assert.deepEqual(out.map((s) => s.id).sort(), ['a', 'b', 'c']);
});

test('F-45: pagination stops at has_more=false (no infinite loop)', async () => {
  let calls = 0;
  const fetch = async () => { calls++; return { data: [{ id: `s${calls}`, created_at: NEW }], has_more: false }; };
  const out = await listSessions('k', { _fetch: fetch });
  assert.equal(calls, 1, 'one page, has_more=false → exactly one fetch');
  assert.equal(out.length, 1);
});

test('F-45: maxPages backstop bounds a misbehaving always-has_more API', async () => {
  // An API that always says has_more:true with a fresh after_id would loop
  // forever pre-backstop. maxPages caps it.
  let calls = 0;
  const fetch = async () => { calls++; return { data: [{ id: `s${calls}`, created_at: NEW }], has_more: true }; };
  const out = await listSessions('k', { _fetch: fetch, maxPages: 5 });
  assert.equal(calls, 5, 'must stop at maxPages');
  assert.equal(out.length, 5);
});
