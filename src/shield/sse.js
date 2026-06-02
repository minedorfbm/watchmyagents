// SSE line terminator normalization — v1.1.4 F-18 (P1 Codex audit).
//
// The HTML Living Standard's event-stream parsing rules (whatwg SSE)
// accept three line terminator forms: LF (\n), CR (\r), and CRLF (\r\n).
// An event ends at a blank line: TWO consecutive line terminators of any
// of those forms, possibly mixed (e.g. \r\n\r\n, \r\r, \n\n, \r\n\n).
//
// Before this fix, Shield's two SSE consumers (stream.js for live agent
// events, policy-stream.js for Fortress policy push) only looked for
// the LF-LF separator. An upstream proxy or endpoint that emitted CRLF
// (most production-grade reverse-proxies do, by default!) would yield
// a buffer that never matched \n\n — Shield would silently never see
// the events:
//   - agent-stream side: no deny/interrupt would fire live, breaking
//     the sub-second enforcement promise
//   - policy-stream side: updates would fall back to the 60s polling
//     loop, making rule rollouts visibly slow
//
// Fix: normalize the buffer to LF-only before scanning. The normalize
// step is chunk-safe: a CR at the very end of the current buffer is
// preserved verbatim (it might be the first half of an incoming CRLF
// on the next chunk). Once a CR is no longer trailing, it's converted.

/**
 * Normalize SSE line terminators in a streaming buffer to LF.
 *
 * Use as: `buffer = normalizeSseBuffer(buffer + newChunk);`
 *
 * Guarantees, after the call:
 *   - every `\r\n` pair has been replaced by `\n`
 *   - every bare `\r` NOT at the very end has been replaced by `\n`
 *   - a trailing `\r` is preserved verbatim so the next iteration can
 *     check whether it was actually the first half of a CRLF
 *
 * @param {string} buffer  the streaming buffer (already concatenated)
 * @returns {string}       buffer with line terminators normalized to LF
 */
export function normalizeSseBuffer(buffer) {
  if (typeof buffer !== 'string' || buffer.length === 0) return buffer;
  // Defer the very last character if it's a CR — we don't know yet
  // whether it's a bare CR terminator or the first half of CRLF.
  const tail = buffer.endsWith('\r') ? '\r' : '';
  const scannable = tail ? buffer.slice(0, -1) : buffer;
  // Two-pass replace: CRLF first (so we don't double-convert the LF
  // half), then any remaining bare CR.
  const normalized = scannable.replace(/\r\n/g, '\n').replace(/\r/g, '\n');
  return tail ? normalized + tail : normalized;
}
