// ─────────────────────────────────────────────────────────────────────────
// Fortress URL resolution — shared across upload-fortress, shield, etc.
// ─────────────────────────────────────────────────────────────────────────
import { lookup as dnsLookup } from 'node:dns';
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
// We require https, reject embedded credentials, and reject IP hosts that are
// not global-unicast. v1.4.13 (Codex P2) hardens this into a 3-way classify:
//   - 'blocked'  — loopback / link-local+metadata / multicast / reserved /
//                  broadcast / CGNAT / TEST-NET / benchmarking / 0/8. NEVER
//                  allowed, even with the opt-out flag (metadata exfil + the
//                  other non-routable ranges have no legitimate Fortress use).
//   - 'private'  — RFC1918 (10/8, 172.16/12, 192.168/16) + IPv6 ULA. Blocked by
//                  default; allowed ONLY with WMA_FORTRESS_ALLOW_PRIVATE_IPS=1
//                  (a legitimate self-hosted Fortress on a private network).
//   - 'public'   — global-unicast / public hostname. Allowed.
// We deliberately do NOT pin to *.supabase.co because operators self-host. The
// DNS-rebinding gap (a public hostname resolving to a non-global IP at connect
// time) is closed by guardedLookup (below) — wired into every Fortress request.
// Throws (fail-loud) so a misconfigured/hostile endpoint stops the run.
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
  const cat = classifyHost(u.hostname);
  if (cat === 'blocked') {
    throw new Error(
      `Fortress base URL host "${u.hostname}" is a loopback/link-local/metadata/reserved address — refusing (SSRF guard). ` +
      'This is ALWAYS blocked (the opt-out flag does not apply). Point WMA_FORTRESS_BASE_URL at a public endpoint.',
    );
  }
  if (cat === 'private' && !privateFortressAllowed()) {
    throw new Error(
      `Fortress base URL host "${u.hostname}" is a private-network (RFC1918/ULA) address — refusing (SSRF guard). ` +
      'For a legitimate self-hosted Fortress on a private network, set WMA_FORTRESS_ALLOW_PRIVATE_IPS=1.',
    );
  }
  return base;
}

// Classify a host (literal IP or hostname) into 'public' | 'private' | 'blocked'.
//   'blocked' — never a legitimate Fortress target (always refused).
//   'private' — RFC1918 / IPv6 ULA (refused unless the opt-out flag is set).
//   'public'  — global-unicast / public hostname (allowed).
// Used by both the URL validator and the per-request DNS guard so a literal IP
// and a RESOLVED IP go through the EXACT same policy.
export function classifyHost(hostname) {
  // Node keeps surrounding brackets on IPv6 hostnames (e.g. "[::1]"); strip them.
  const h = String(hostname).toLowerCase().replace(/^\[/, '').replace(/\]$/, '');
  if (h === 'localhost' || h.endsWith('.localhost')) return 'blocked';

  // IPv6 literal.
  if (h.includes(':')) {
    if (h === '::1' || h === '::') return 'blocked';            // loopback / unspecified
    if (h.startsWith('fe8') || h.startsWith('fe9') || h.startsWith('fea') || h.startsWith('feb')) return 'blocked'; // fe80::/10 link-local
    if (h.startsWith('ff')) return 'blocked';                  // ff00::/8 multicast
    if (h.startsWith('fc') || h.startsWith('fd')) return 'private'; // fc00::/7 ULA (RFC1918-equivalent)
    // IPv4-mapped IPv6 (::ffff:a.b.c.d). CRITICAL: Node's URL parser normalizes
    // the dotted form to HEX — new URL('https://[::ffff:127.0.0.1]/').hostname
    // is '[::ffff:7f00:1]' — so a regex matching only the dotted form lets
    // 127.0.0.1 / 169.254.169.254 (metadata!) slip past. Decode BOTH forms.
    const mappedDotted = h.match(/^::ffff:(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$/);
    if (mappedDotted) return classifyIpv4(mappedDotted[1]);
    const mappedHex = h.match(/^::ffff:([0-9a-f]{1,4}):([0-9a-f]{1,4})$/);
    if (mappedHex) {
      const hi = parseInt(mappedHex[1], 16), lo = parseInt(mappedHex[2], 16);
      return classifyIpv4(`${(hi >> 8) & 0xff}.${hi & 0xff}.${(lo >> 8) & 0xff}.${lo & 0xff}`);
    }
    return 'public';
  }

  // IPv4 literal?
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(h)) return classifyIpv4(h);
  return 'public';   // public hostname (DNS rebinding closed by guardedLookup)
}

// True if a host is refused under the CURRENT policy (flag-aware).
function hostRefused(hostname) {
  const cat = classifyHost(hostname);
  return cat === 'blocked' || (cat === 'private' && !privateFortressAllowed());
}

// v1.4.11 (Codex P1/P2): per-request DNS guard — closes the DNS-rebinding gap
// the name-based check can't (a public hostname resolving to a private IP at
// connect time). Drop-in `lookup` for https.request: it resolves the hostname,
// rejects the connection if the RESOLVED ip is private/loopback/link-local
// (same ranges as isBlockedHost, incl. IPv4-mapped IPv6), and otherwise pins
// the connection to exactly that resolved address. Wire it into every
// Fortress-bound https.request via `{ lookup: guardedLookup }`.
export function guardedLookup(hostname, options, callback) {
  const cb = typeof options === 'function' ? options : callback;
  const opts = typeof options === 'function' ? {} : (options || {});
  // NOTE: we do NOT early-return when the opt-out flag is set. hostRefused()
  // is flag-aware: it allows RFC1918 ('private') resolutions when the flag is
  // set, but STILL blocks loopback / link-local / metadata / reserved
  // ('blocked') even then — the flag must not open the cloud-metadata vector.
  dnsLookup(hostname, opts, (err, address, family) => {
    if (err) return cb(err);
    const list = Array.isArray(address) ? address : [{ address, family }];
    for (const a of list) {
      if (hostRefused(a.address)) {
        const cat = classifyHost(a.address);
        return cb(new Error(
          `SSRF guard: "${hostname}" resolved to a ${cat === 'blocked' ? 'loopback/link-local/metadata/reserved' : 'private-network'} ` +
          `IP (${a.address}) — refusing the connection.` +
          (cat === 'private' ? ' Set WMA_FORTRESS_ALLOW_PRIVATE_IPS=1 for a self-hosted Fortress on a private network.' : ''),
        ));
      }
    }
    return cb(null, address, family);
  });
}

// Opt-out for self-hosted Fortress on a private network. Default: not allowed.
function privateFortressAllowed() {
  return process.env.WMA_FORTRESS_ALLOW_PRIVATE_IPS === '1';
}

// Classify an IPv4 literal. 'private' = RFC1918 (opt-out-able). Everything
// non-global-unicast and non-RFC1918 is 'blocked' (never allowed): loopback,
// link-local/metadata, CGNAT, IETF protocol, TEST-NET-1/2/3, benchmarking,
// multicast, reserved/future, broadcast, this-network. (v1.4.13 Codex P2.)
function classifyIpv4(ip) {
  const o = ip.split('.').map(Number);
  if (o.length !== 4 || o.some((n) => !Number.isInteger(n) || n < 0 || n > 255)) return 'blocked'; // malformed
  const [a, b, c] = o;
  // RFC1918 private — the only ranges the opt-out flag un-blocks.
  if (a === 10) return 'private';                        // 10.0.0.0/8
  if (a === 172 && b >= 16 && b <= 31) return 'private'; // 172.16.0.0/12
  if (a === 192 && b === 168) return 'private';          // 192.168.0.0/16
  // Always blocked (not global-unicast; flag does NOT apply).
  if (a === 0) return 'blocked';                                 // 0.0.0.0/8 this-network
  if (a === 127) return 'blocked';                               // 127.0.0.0/8 loopback
  if (a === 169 && b === 254) return 'blocked';                  // 169.254.0.0/16 link-local + cloud metadata
  if (a === 100 && b >= 64 && b <= 127) return 'blocked';        // 100.64.0.0/10 CGNAT
  if (a === 192 && b === 0 && c === 0) return 'blocked';         // 192.0.0.0/24 IETF protocol assignments
  if (a === 192 && b === 0 && c === 2) return 'blocked';         // 192.0.2.0/24 TEST-NET-1
  if (a === 198 && (b === 18 || b === 19)) return 'blocked';     // 198.18.0.0/15 benchmarking
  if (a === 198 && b === 51 && c === 100) return 'blocked';      // 198.51.100.0/24 TEST-NET-2
  if (a === 203 && b === 0 && c === 113) return 'blocked';       // 203.0.113.0/24 TEST-NET-3
  if (a >= 224 && a <= 239) return 'blocked';                    // 224.0.0.0/4 multicast
  if (a >= 240) return 'blocked';                                // 240.0.0.0/4 reserved + 255.255.255.255 broadcast
  return 'public';
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
