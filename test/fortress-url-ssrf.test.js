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
import { resolveFortressBase, assertSafeFortressBase } from '../src/fortress/url.js';

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
