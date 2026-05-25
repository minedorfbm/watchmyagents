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
  if (explicitBase) return stripTrailingSlash(explicitBase);

  // 2. Env: WMA_FORTRESS_BASE_URL (preferred)
  if (env.WMA_FORTRESS_BASE_URL) return stripTrailingSlash(env.WMA_FORTRESS_BASE_URL);

  // 3. Legacy: WMA_FORTRESS_URL (full path to ingest-signals)
  const legacy = explicitUrl || env.WMA_FORTRESS_URL;
  if (legacy) {
    // Strip last path segment to get the base
    try {
      const u = new URL(legacy);
      const parts = u.pathname.split('/').filter(Boolean);
      if (parts.length > 0) parts.pop();
      u.pathname = '/' + parts.join('/');
      return stripTrailingSlash(u.toString());
    } catch {
      return null;
    }
  }

  return null;
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
