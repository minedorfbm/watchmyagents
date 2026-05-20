import { createHash } from 'node:crypto';

const PII_PATTERNS = [
  [/\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g, '[EMAIL]'],
  [/Bearer\s+[A-Za-z0-9\-_\.=]+/gi, '[TOKEN]'],
  [/eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+/g, '[TOKEN]'],
  [/\b(sk|pk|rk)-[A-Za-z0-9_\-]{16,}\b/g, '[API_KEY]'],
  [/\bwma_[A-Za-z0-9_\-]{8,}\b/g, '[API_KEY]'],
  [/\b(?:\d[ -]*?){13,19}\b/g, '[CARD]'],
  [/\b\+?\d{1,3}[\s.-]?\(?\d{2,4}\)?[\s.-]?\d{3,4}[\s.-]?\d{3,4}\b/g, '[PHONE]'],
  [/https?:\/\/[^\s"'<>]+/gi, '[URL]'],
  [/\b(?:\d{1,3}\.){3}\d{1,3}\b/g, '[IP]'],
  [/\b(?:[a-f0-9]{1,4}:){7}[a-f0-9]{1,4}\b/gi, '[IP]'],
];

const HASH_FIELDS = new Set(['user_id', 'session_id', 'agent_id']);

export function scrubString(str) {
  if (typeof str !== 'string') return str;
  let out = str;
  for (const [re, tag] of PII_PATTERNS) out = out.replace(re, tag);
  return out;
}

export function hashId(value) {
  if (value == null) return value;
  return 'h_' + createHash('sha256').update(String(value)).digest('hex').slice(0, 24);
}

export function anonymize(obj) {
  if (obj == null) return obj;
  if (typeof obj === 'string') return scrubString(obj);
  if (typeof obj !== 'object') return obj;
  if (Array.isArray(obj)) return obj.map(anonymize);
  const out = {};
  for (const [k, v] of Object.entries(obj)) {
    if (HASH_FIELDS.has(k) && (typeof v === 'string' || typeof v === 'number')) {
      out[k] = hashId(v);
    } else if (typeof v === 'string') {
      out[k] = scrubString(v);
    } else if (typeof v === 'object') {
      out[k] = anonymize(v);
    } else {
      out[k] = v;
    }
  }
  return out;
}
