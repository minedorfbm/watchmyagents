// v1.4.3 F-51 (P2 audit) — bounded dedup state for the long-running watch loop.
//
// The watch daemon dedupes events by their stable Anthropic event id so a
// re-fetch of an already-captured session doesn't double-write the NDJSON.
// Pre-F-51 every id ever seen lived in a single Set that was only ever added
// to — on a 24/7 daemon at high event volume that Set grows without bound
// (hundreds of MB within days), and the daemon eventually OOM-kills and stops
// collecting (a silent monitoring gap).
//
// SeenTracker bounds runtime growth WITHOUT weakening dedup:
//   - Preloaded ids (read from on-disk NDJSON at startup) sit in a static set,
//     loaded once. Bounded by what the operator keeps on disk.
//   - Runtime-discovered ids are tracked PER SESSION. When a session
//     terminates it is never re-fetched, so its id set is dropped. Live memory
//     is therefore bounded by ACTIVE sessions, not lifetime event volume.
//
// Correctness: Anthropic event ids are globally unique and an event belongs to
// exactly one session, so checking the preloaded set + that session's set is
// equivalent to the old global-set membership test (no missed dedup, no
// missed events).
export class SeenTracker {
  constructor(preloadedIds = []) {
    this._preloaded = new Set(preloadedIds);
    this._bySession = new Map();   // sessionId -> Set<eventId>
  }

  // v1.4.4 F-53: fold an agent's on-disk history into the static preloaded
  // set. Called lazily the first time an agent is seen (including agents that
  // --all-agents discovers AFTER startup) so their already-captured NDJSON ids
  // are deduped against — otherwise a late-appearing agent with existing logs
  // would re-append and re-upload events it already has.
  addPreloaded(id) {
    if (id) this._preloaded.add(id);
  }

  has(sessionId, eventId) {
    if (this._preloaded.has(eventId)) return true;
    const s = this._bySession.get(sessionId);
    return s ? s.has(eventId) : false;
  }

  add(sessionId, eventId) {
    let s = this._bySession.get(sessionId);
    if (!s) { s = new Set(); this._bySession.set(sessionId, s); }
    s.add(eventId);
  }

  // Drop a terminated session's runtime id set — it will never be re-fetched,
  // so its ids no longer need to be remembered for dedup.
  forgetSession(sessionId) {
    this._bySession.delete(sessionId);
  }

  // Total tracked ids (preloaded + all live per-session sets). For observability.
  get size() {
    let n = this._preloaded.size;
    for (const s of this._bySession.values()) n += s.size;
    return n;
  }

  // Number of sessions currently holding a runtime id set.
  get sessionCount() {
    return this._bySession.size;
  }
}
