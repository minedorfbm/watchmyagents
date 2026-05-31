// ────────────────────────────────────────────────────────────────────────
// labels — shared sanitization for human-facing identifiers
// ────────────────────────────────────────────────────────────────────────
//
// Customer-set strings (agent display names, workspace labels, etc.) end
// up in:
//   - log lines (stdout/stderr of the Watch + Shield daemons)
//   - the Fortress ingest-signals payload (`display_name` field)
//   - eventually rendered in the Fortress dashboard
//
// We don't trust them. A name carrying:
//   - control bytes (0x00-0x1F, 0x7F) can poison terminal output (ANSI
//     escape sequences) or break NDJSON parsing
//   - excessive length can bloat payloads and break UI columns
//
// `cleanLabel()` is the single, shared sanitizer. Both wma-fetch (the
// daemon) and wma-upload-fortress (the one-shot uploader) MUST run
// every customer-supplied label through it before logging or shipping.
// Extracted to its own module in v1.1.1 (F-11 Codex audit fix) so a
// future change benefits both consumers automatically.

const MAX_LABEL_CHARS = 60;

/**
 * Strip control bytes (< 0x20 and 0x7F DEL) and truncate to MAX_LABEL_CHARS
 * characters. Returns the empty string for null/undefined input.
 *
 * Uses [...str] to iterate by code point so surrogate pairs aren't split.
 */
export function cleanLabel(s) {
  return [...String(s ?? '')]
    .filter((c) => {
      const code = c.charCodeAt(0);
      return code >= 32 && code !== 127;
    })
    .join('')
    .slice(0, MAX_LABEL_CHARS)
    .trim();
}
