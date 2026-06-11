// ─────────────────────────────────────────────────────────────────────────
// Fortress URL resolution — shared across upload-fortress, shield, etc.
// ─────────────────────────────────────────────────────────────────────────
// The user sets ONE of:
//
//   WMA_FORTRESS_BASE_URL=https://<project>.supabase.co/functions/v1
//      → preferred. Each tool appends its endpoint (/ingest-signals,
//        /get-policies, /ingest-decisions).
//
//   WMA_FORTRESS_URL=https://<project>.supabase.co/functions/v1/ingest-signals
//      → legacy (v0.5.0 era). The base URL is derived by stripping the
//        last path segment, so other endpoints can be constructed.
//
// Either way, callers receive a `base` they append `/<endpoint>` to.

/**
 * Resolve the Fortress base URL from env / args.
 * @param {object} opts - { explicitUrl, explicitBase, env }
 * @returns {string|null} base URL like https://x.supabase.co/functions/v1
 *                       (no trailing slash), or null if not configured.
 */
export function resolveFortressBase({ explicitUrl, explicitBase, env = process.env } = {}) {
  // 1. Explicit base URL from CLI
  if (explicitBase) return assertSafeFortressBase(stripTrailingSlash(explicitBase));

  // 2. Env: WMA_FORTRESS_BASE_URL (preferred)
  if (env.WMA_FORTRESS_BASE_URL) return assertSafeFortressBase(stripTrailingSlash(env.WMA_FORTRESS_BASE_URL));

  // 3. Legacy: WMA_FORTRESS_URL (full path to ingest-signals)
  const legacy = explicitUrl || env.WMA_FORTRESS_URL;
  if (legacy) {
    // Strip last path segment to get the base
    let derived;
    try {
      const u = new URL(legacy);
      const parts = u.pathname.split('/').filter(Boolean);
      if (parts.length > 0) parts.pop();
      u.pathname = '/' + parts.join('/');
      derived = stripTrailingSlash(u.toString());
    } catch {
      return null;
    }
    return assertSafeFortressBase(derived);
  }

  return null;
}

// v1.4.2 F-47 (P1->P2 audit) — SSRF guard on the operator-supplied Fortress
// base URL. WMA POSTs the customer's Bearer API key + signals/decisions to
// this URL and PULLS live-enforcement policies from it, so an attacker who can
// influence the SDK's environment (templated deploy, shared .env, compromised
// orchestration layer) could previously point it at http://, an internal
// host, or a cloud metadata endpoint (169.254.169.254) and exfiltrate the key
// — the only prior check was `protocol === 'https:'` at the request layer.
//
// We require https, reject embedded credentials, and reject IP-LITERAL hosts
// in private / loopback / link-local / ULA ranges (the direct metadata-
// endpoint vector). We deliberately do NOT pin to *.supabase.co because
// operators self-host Fortress; any PUBLIC host is allowed. Residual:
// DNS-rebinding (a public hostname resolving to a private IP) is not caught
// here — that needs per-request resolved-IP pinning, out of scope for a sync
// URL validator. Throws (fail-loud) on a bad URL rather than returning null,
// so a misconfigured/hostile endpoint stops the run instead of silently
// disabling upload/enforcement.
export function assertSafeFortressBase(base) {
  let u;
  try { u = new URL(base); }
  catch { throw new Error(`Fortress base URL is not a valid URL: ${base}`); }

  if (u.protocol !== 'https:') {
    throw new Error(`Fortress base URL must use https:// (got ${u.protocol}//). Refusing to send credentials over ${u.protocol}//.`);
  }
  if (u.username || u.password) {
    throw new Error('Fortress base URL must not embed credentials (user:pass@host).');
  }
  if (isBlockedHost(u.hostname)) {
    throw new Error(
      `Fortress base URL host "${u.hostname}" is a private/loopback/link-local address — refusing (SSRF guard). ` +
      'Point WMA_FORTRESS_BASE_URL at your public Fortress endpoint.',
    );
  }
  return base;
}

// True if the host is an IP literal in a private/loopback/link-local/ULA range,
// or localhost. Public hostnames and public IPs pass.
function isBlockedHost(hostname) {
  // Node keeps surrounding brackets on IPv6 hostnames (e.g. "[::1]"); strip them.
  const h = hostname.toLowerCase().replace(/^\[/, '').replace(/\]$/, '');
  if (h === 'localhost' || h.endsWith('.localhost')) return true;

  // IPv6 literal. Normalize IPv4-mapped form.
  if (h.includes(':')) {
    if (h === '::1' || h === '::') return true;                 // loopback / unspecified
    if (h.startsWith('fe8') || h.startsWith('fe9') || h.startsWith('fea') || h.startsWith('feb')) return true; // fe80::/10 link-local
    if (h.startsWith('fc') || h.startsWith('fd')) return true;  // fc00::/7 unique-local
    const mapped = h.match(/::ffff:(\d+\.\d+\.\d+\.\d+)$/);     // IPv4-mapped IPv6
    if (mapped) return isBlockedIpv4(mapped[1]);
    return false;
  }

  // IPv4 literal?
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(h)) return isBlockedIpv4(h);
  return false;
}

function isBlockedIpv4(ip) {
  const o = ip.split('.').map(Number);
  if (o.length !== 4 || o.some((n) => !Number.isInteger(n) || n < 0 || n > 255)) return true; // malformed → block
  const [a, b] = o;
  if (a === 127) return true;                          // 127.0.0.0/8 loopback
  if (a === 10) return true;                            // 10.0.0.0/8 private
  if (a === 172 && b >= 16 && b <= 31) return true;     // 172.16.0.0/12 private
  if (a === 192 && b === 168) return true;              // 192.168.0.0/16 private
  if (a === 169 && b === 254) return true;              // 169.254.0.0/16 link-local (cloud metadata)
  if (a === 0) return true;                             // 0.0.0.0/8
  return false;
}

function stripTrailingSlash(s) {
  return s.endsWith('/') ? s.slice(0, -1) : s;
}

/**
 * Build a full endpoint URL given a base + endpoint name.
 * @param {string} base - e.g. https://x.supabase.co/functions/v1
 * @param {string} endpoint - e.g. "ingest-signals", "get-policies"
 */
export function fortressEndpoint(base, endpoint) {
  if (!base) throw new Error('Fortress base URL not configured');
  return `${base}/${endpoint}`;
}
