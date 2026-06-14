// v1.4.2 F-47 (P1->P2 audit) — SSRF guard on the Fortress base URL.
//
// WMA POSTs the customer Bearer key + signals/decisions to this URL and pulls
// live-enforcement policies from it. Pre-fix the only check was https at the
// request layer, so an env-controlled URL could point at a cloud metadata
// endpoint or internal host and exfiltrate the key. resolveFortressBase now
// rejects non-https, embedded credentials, and private/loopback/link-local IP
// literals (fail-loud).

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { resolveFortressBase, assertSafeFortressBase, guardedLookup } from '../src/fortress/url.js';

// ── public hosts pass ─────────────────────────────────────────────────────

test('F-47: a public https Supabase URL passes', () => {
  const u = 'https://abc.supabase.co/functions/v1';
  assert.equal(resolveFortressBase({ env: { WMA_FORTRESS_BASE_URL: u } }), u);
});

test('F-47: a self-hosted public https host passes (no allowlist pinning)', () => {
  const u = 'https://fortress.mycompany.com/functions/v1';
  assert.equal(assertSafeFortressBase(u), u);
});

test('F-47: a public IP literal passes', () => {
  assert.equal(assertSafeFortressBase('https://8.8.8.8/functions/v1'), 'https://8.8.8.8/functions/v1');
});

// ── blocked: scheme / credentials ─────────────────────────────────────────

test('F-47: http:// is rejected (would send the API key in cleartext)', () => {
  assert.throws(() => assertSafeFortressBase('http://abc.supabase.co'), /must use https/i);
});

test('F-47: embedded credentials are rejected', () => {
  assert.throws(() => assertSafeFortressBase('https://user:pass@abc.supabase.co'), /must not embed credentials/i);
});

// ── blocked: SSRF internal hosts ──────────────────────────────────────────

test('F-47: cloud metadata endpoint 169.254.169.254 is rejected', () => {
  assert.throws(() => assertSafeFortressBase('https://169.254.169.254/latest/meta-data'), /SSRF guard/);
});

test('F-47: loopback / localhost are rejected', () => {
  assert.throws(() => assertSafeFortressBase('https://127.0.0.1/x'), /SSRF guard/);
  assert.throws(() => assertSafeFortressBase('https://localhost/x'), /SSRF guard/);
  assert.throws(() => assertSafeFortressBase('https://[::1]/x'), /SSRF guard/);
});

test('F-47: private ranges (10/8, 172.16/12, 192.168/16) are rejected', () => {
  for (const ip of ['10.0.0.5', '172.16.3.4', '172.31.255.1', '192.168.1.1']) {
    assert.throws(() => assertSafeFortressBase(`https://${ip}/x`), /SSRF guard/, `${ip} must be blocked`);
  }
});

test('F-47: a 172.x address OUTSIDE the private 16-31 block is allowed', () => {
  // 172.15.x and 172.32.x are public.
  assert.equal(assertSafeFortressBase('https://172.15.0.1/x'), 'https://172.15.0.1/x');
  assert.equal(assertSafeFortressBase('https://172.32.0.1/x'), 'https://172.32.0.1/x');
});

test('F-47: IPv6 link-local (fe80::) and ULA (fc00::) are rejected', () => {
  assert.throws(() => assertSafeFortressBase('https://[fe80::1]/x'), /SSRF guard/);
  assert.throws(() => assertSafeFortressBase('https://[fd12:3456::1]/x'), /SSRF guard/);
});

// ── legacy WMA_FORTRESS_URL path also validated ───────────────────────────

test('F-47: legacy WMA_FORTRESS_URL derivation is validated too', () => {
  assert.throws(
    () => resolveFortressBase({ env: { WMA_FORTRESS_URL: 'http://10.0.0.1/functions/v1/ingest-signals' } }),
    /https|SSRF/i,
  );
  // valid legacy URL derives the base correctly
  assert.equal(
    resolveFortressBase({ env: { WMA_FORTRESS_URL: 'https://abc.supabase.co/functions/v1/ingest-signals' } }),
    'https://abc.supabase.co/functions/v1',
  );
});

test('F-47: no config returns null (unchanged)', () => {
  assert.equal(resolveFortressBase({ env: {} }), null);
});

// ── v1.4.11 (Codex P1): IPv4-mapped IPv6 SSRF bypass ─────────────────────
// Node's URL parser normalizes [::ffff:127.0.0.1] → [::ffff:7f00:1] (HEX), so a
// guard matching only the dotted form let loopback/metadata/private slip past.

test('v1.4.11: IPv4-mapped IPv6 loopback is blocked (both dotted + hex-normalized)', () => {
  for (const h of ['https://[::ffff:127.0.0.1]/x', 'https://[::ffff:7f00:1]/x']) {
    assert.throws(() => assertSafeFortressBase(h), /private|loopback|link-local/i, h);
  }
});

test('v1.4.11: IPv4-mapped IPv6 metadata + private ranges are blocked', () => {
  for (const h of [
    'https://[::ffff:169.254.169.254]/x',   // cloud metadata (the dangerous one)
    'https://[::ffff:10.0.0.1]/x',
    'https://[::ffff:192.168.1.1]/x',
    'https://[::ffff:172.16.0.1]/x',
  ]) {
    assert.throws(() => assertSafeFortressBase(h), /private|loopback|link-local/i, h);
  }
});

test('v1.4.11: a PUBLIC IPv4-mapped IPv6 still passes (no false positive)', () => {
  assert.doesNotThrow(() => assertSafeFortressBase('https://[::ffff:8.8.8.8]/x'));
});

// ── v1.4.11 (Codex P1/P2): DNS-rebinding guard (guardedLookup) ────────────

function lookupP(host) {
  return new Promise((resolve) => guardedLookup(host, {}, (err, addr, fam) => resolve({ err, addr, fam })));
}

test('v1.4.11: guardedLookup rejects a private resolved IP', async () => {
  const { err } = await lookupP('127.0.0.1');   // IP literal → no network
  assert.ok(err, 'loopback must be rejected');
  assert.match(err.message, /SSRF guard|private|loopback/i);
});

test('v1.4.11: guardedLookup rejects the cloud metadata IP', async () => {
  const { err } = await lookupP('169.254.169.254');
  assert.ok(err, 'metadata IP must be rejected');
});

test('v1.4.11: guardedLookup allows a public IP', async () => {
  const { err, addr } = await lookupP('8.8.8.8');
  assert.ifError(err);
  assert.equal(addr, '8.8.8.8');
});

test('v1.4.11: guardedLookup blocks localhost (resolves to loopback — the rebinding case)', async () => {
  const { err } = await lookupP('localhost');
  assert.ok(err, 'a hostname resolving to loopback must be rejected (DNS rebinding)');
});

// ── v1.4.11: opt-out for self-hosted Fortress on a private network ────────

test('v1.4.11: WMA_FORTRESS_ALLOW_PRIVATE_IPS=1 lets a private literal + resolution through', async () => {
  const saved = process.env.WMA_FORTRESS_ALLOW_PRIVATE_IPS;
  process.env.WMA_FORTRESS_ALLOW_PRIVATE_IPS = '1';
  try {
    assert.doesNotThrow(() => assertSafeFortressBase('https://10.0.0.5/functions/v1'));
    const { err } = await lookupP('127.0.0.1');
    assert.ifError(err);   // guard disabled → loopback allowed
  } finally {
    if (saved === undefined) delete process.env.WMA_FORTRESS_ALLOW_PRIVATE_IPS;
    else process.env.WMA_FORTRESS_ALLOW_PRIVATE_IPS = saved;
  }
});
