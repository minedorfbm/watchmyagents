// Shared identifier + path-segment validation.
//
// agentId and sessionId end up as filesystem path segments (logDir/<agentId>/…
// and raw-<sessionId>.jsonl). Without validation a crafted value like
// "../../etc" would traverse out of the log directory. Every entry point that
// turns an id into a path MUST validate it first.

const AGENT_ID_RE = /^agent_[a-zA-Z0-9]+$/;
const SESSION_ID_RE = /^sesn_[a-zA-Z0-9]+$/;

export function isValidAgentId(id) {
  return typeof id === 'string' && AGENT_ID_RE.test(id);
}

export function isValidSessionId(id) {
  return typeof id === 'string' && SESSION_ID_RE.test(id);
}

// Defense-in-depth: reject any value that could escape its parent directory
// before it is passed to path.join(). Throws on anything suspicious.
export function assertSafePathSegment(seg, label = 'path segment') {
  if (typeof seg !== 'string' || seg.length === 0) {
    throw new Error(`${label} must be a non-empty string`);
  }
  if (
    seg === '.' || seg === '..' ||
    seg.includes('/') || seg.includes('\\') ||
    seg.includes('..') || seg.includes('\0')
  ) {
    throw new Error(`${label} "${seg.slice(0, 40)}" contains illegal path characters`);
  }
  return seg;
}
