// Shield decision audit chain — v1.2.0.
//
// Tamper-evidence on the shield_decision NDJSON log. Each record gets two
// new fields:
//
//   prev_hash   — chain_hash of the previous record (or the genesis
//                 marker for the first record in this chain segment)
//   chain_hash  — sha256(prev_hash || canonical(record without these
//                 two fields))
//
// Why this matters (mapping to Anthropic's May 2026 framework, Part IV
// §Phase 6 "audit + forensics"):
//
//   - Operational: after an incident the forensic question is "what did
//     Shield decide, and was the log doctored". With the chain in place,
//     any insertion / deletion / modification breaks the next record's
//     prev_hash. A single broken link locates the tampering window.
//   - Investigator workflow: replay the file through verifyChain() →
//     either OK (every record's chain_hash matches the next record's
//     prev_hash) or BROKEN at index N (everything after is suspect).
//
// Scope + limitations (v1.2.0):
//
//   - Per-process chain. Each Shield restart begins a new chain segment
//     with a fresh genesis. An NDJSON file may therefore contain MORE
//     than one chain — that's deliberate and self-describing (the
//     genesis marker carries process_id + start time). The verifier
//     walks segments sequentially.
//   - Soft tamper-evidence only: an attacker who can re-execute Shield
//     can re-derive the chain from scratch. Strong tamper-evidence
//     requires offloading to an append-only sink (Fortress + signed
//     ingest) — tracked separately. This module is the LOCAL piece.
//   - Hash: SHA-256 hex (32 bytes → 64 chars). Node built-in. We
//     deliberately do NOT introduce a non-stdlib hash to preserve the
//     zero-runtime-deps guarantee.
//   - Canonicalization: reuses canonicalize() from signature.js — same
//     rules as the Ed25519 chain-of-trust, so verifiers only need one
//     serializer.

import { createHash, randomUUID } from 'node:crypto';
import { canonicalize } from './signature.js';

// The two link fields are EXCLUDED from the hashed body of a record —
// the hash of (R) cannot contain its own value, and prev_hash is
// already mixed into the digest input separately.
export const CHAIN_FIELDS = ['prev_hash', 'chain_hash'];

function sha256Hex(input) {
  return createHash('sha256').update(input).digest('hex');
}

// Strip the chain fields from a record before hashing. We do NOT mutate
// the caller's object — we return a shallow copy.
function bodyForHash(record) {
  const out = {};
  for (const k of Object.keys(record)) {
    if (k === 'prev_hash' || k === 'chain_hash') continue;
    out[k] = record[k];
  }
  return out;
}

// Build the digest input for a record: prev_hash followed by a single
// separator byte (chosen as `|` since it never appears in hex output and
// keeps the input human-inspectable), then the canonical body. The
// separator prevents an attacker from shifting bytes between the two
// inputs and re-deriving a collision.
function digestInput(prevHash, body) {
  return prevHash + '|' + canonicalize(body);
}

// Build a structured genesis marker. The verifier treats it as opaque
// (the marker only matters as the prev_hash of the first record), but
// the structure aids manual forensics: an investigator opening the
// NDJSON can tell which Shield process minted that chain.
//
// All three components are LOCAL identifiers — none of them is sensitive
// or correlatable to a customer account.
export function buildGenesisMarker({ agentId, sessionId, startedAtIso, chainId } = {}) {
  const parts = [
    'genesis',
    agentId || 'unknown-agent',
    sessionId || 'unknown-session',
    startedAtIso || new Date(0).toISOString(),  // caller injects a real timestamp
    chainId || 'unknown-chain',
  ];
  return parts.join(':');
}

// Per-process chain state. wrap(body) returns a NEW object with the two
// link fields inserted at the END of the record (NDJSON readers tolerate
// either position, but appending keeps human diffs cleaner).
export function createDecisionChain({ genesis } = {}) {
  if (typeof genesis !== 'string' || genesis.length === 0) {
    throw new Error('createDecisionChain: genesis must be a non-empty string (use buildGenesisMarker)');
  }
  let prevHash = genesis;
  let count = 0;

  return {
    // Returns the chain-augmented record. Caller writes the returned
    // object verbatim to NDJSON.
    wrap(body) {
      if (body == null || typeof body !== 'object' || Array.isArray(body)) {
        throw new Error('decisionChain.wrap: body must be a plain object');
      }
      const chainHash = sha256Hex(digestInput(prevHash, bodyForHash(body)));
      const out = { ...body, prev_hash: prevHash, chain_hash: chainHash };
      prevHash = chainHash;
      count += 1;
      return out;
    },

    // Read-only inspection. Useful for tests + for shield.js to write a
    // periodic "chain snapshot" line if we want one in v1.3.
    state() {
      return { prev_hash: prevHash, count };
    },
  };
}

// Walk an array of records (deserialized from NDJSON) and check that
// every record's chain_hash is reproducible from prev_hash + body, AND
// that record[i+1].prev_hash === record[i].chain_hash. Returns:
//
//   { ok: true,  count, segments }                          if intact
//   { ok: false, broken_at: i, reason, count, segments }   if tampered
//
// A "segment" is a contiguous run of records that share a chain. The
// first segment starts at the genesis marker derived from
// records[0].prev_hash; subsequent segments start at any record whose
// prev_hash does NOT match the previous record's chain_hash AND that
// looks like a genesis marker (starts with "genesis:"). That tolerance
// is what lets one NDJSON file hold the chains of multiple Shield runs.
//
// Anything OTHER than "valid step within the current chain" or "new
// segment starting at a genesis marker" is a tamper signal.
export function verifyDecisionChain(records) {
  if (!Array.isArray(records)) {
    return { ok: false, broken_at: -1, reason: 'records must be an array', count: 0, segments: 0 };
  }
  if (records.length === 0) {
    return { ok: true, count: 0, segments: 0 };
  }

  let segmentCount = 0;
  let runningPrev = null;  // chain_hash of the most recently verified record

  for (let i = 0; i < records.length; i++) {
    const r = records[i];
    if (r == null || typeof r !== 'object') {
      return { ok: false, broken_at: i, reason: 'record is not an object', count: i, segments: segmentCount };
    }
    if (typeof r.prev_hash !== 'string' || typeof r.chain_hash !== 'string') {
      return { ok: false, broken_at: i, reason: 'missing prev_hash or chain_hash', count: i, segments: segmentCount };
    }

    // Is this the start of a new segment?
    const isFirstInFile = i === 0;
    const linksToPrev = !isFirstInFile && r.prev_hash === runningPrev;
    const looksLikeGenesis = r.prev_hash.startsWith('genesis:');

    if (!linksToPrev) {
      if (!isFirstInFile && !looksLikeGenesis) {
        return { ok: false, broken_at: i, reason: 'prev_hash mismatch (not a genesis marker either)', count: i, segments: segmentCount };
      }
      segmentCount += 1;
    }

    // Recompute the chain_hash and compare.
    const expected = sha256Hex(digestInput(r.prev_hash, bodyForHash(r)));
    if (expected !== r.chain_hash) {
      return { ok: false, broken_at: i, reason: 'chain_hash recomputation mismatch', count: i, segments: segmentCount };
    }

    runningPrev = r.chain_hash;
  }

  return { ok: true, count: records.length, segments: segmentCount };
}

// Tiny convenience for shield.js / tests that want a fresh chain id
// without pulling crypto/randomUUID at the call site.
export function newChainId() {
  return randomUUID();
}
