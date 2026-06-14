// ────────────────────────────────────────────────────────────────────────
// PolicyStream — Server-Sent Events consumer for instant policy propagation
// ────────────────────────────────────────────────────────────────────────
//
// v1.1.0 Phase 2: instead of polling Fortress every 60s for new policies
// (the FortressPolicySource refreshIntervalMs path), Shield maintains a
// persistent SSE connection to /functions/v1/policies-stream and refreshes
// its ruleset within ~100ms of a policy change in Fortress.
//
// Why SSE (not WebSocket):
//   - Zero runtime dependencies preserved: HTTPS + SSE = node:https built-in,
//     no @supabase/realtime-js, no custom Phoenix Channels client.
//   - Node 18+ compat preserved: no native WebSocket needed.
//   - Firewall-friendly: SSE rides on standard HTTPS — many enterprise
//     proxies block raw WebSocket but pass through text/event-stream cleanly.
//   - Realtime is uni-directional (Fortress → Shield) anyway. SSE is the
//     right tool for one-way push notifications.
//
// Graceful fallback:
//   - On HTTP 404 from the SSE endpoint (Fortress side not yet upgraded
//     with the Lovable prompt), this stream goes into "fallback mode" and
//     stops trying to reconnect aggressively. The FortressPolicySource's
//     existing poll cadence (60s in v1.1.0) covers the gap.
//   - On HTTP 401, this is a config error — logged once, stream stays
//     down.
//   - On network errors / disconnects, reconnect with exponential backoff
//     (1s → 60s cap).
//
// Per-agent: each PolicyStream targets a single anthropic_agent_id so the
// Fortress side can scope the channel to "this customer + this agent".

import { request as httpsRequest } from 'node:https';
import { URL } from 'node:url';
import { EventEmitter } from 'node:events';
import { normalizeSseBuffer } from './sse.js';
import { guardedLookup } from '../fortress/url.js';

const RECONNECT_MIN_MS = 1_000;
const RECONNECT_MAX_MS = 60_000;
const FALLBACK_RETRY_INTERVAL_MS = 5 * 60_000;
const PERMANENT_FAILURE_LOG_INTERVAL_MS = 5 * 60_000;
// v1.1.1 F-9 (P2 Codex audit): hard cap on a single SSE event's buffer.
// A buggy or compromised Fortress endpoint could stream bytes forever
// without emitting the "\n\n" event separator, growing Shield's memory.
// 1 MB is far above any legitimate `policy_changed` payload (the data
// field carries {rule_id, action, ts, kind} = maybe 200 bytes) so we
// abort the connection and reconnect on overflow.
const MAX_SSE_EVENT_BYTES = 1 * 1024 * 1024;

export class PolicyStream extends EventEmitter {
  constructor({ url, apiKey, anthropicAgentId, onError, onInfo }) {
    super();
    if (!url) throw new Error('PolicyStream requires url');
    if (!apiKey) throw new Error('PolicyStream requires apiKey');
    if (!anthropicAgentId) throw new Error('PolicyStream requires anthropicAgentId');
    this.url = url;
    this.apiKey = apiKey;
    this.agentId = anthropicAgentId;
    this.onError = onError || (() => {});
    this.onInfo = onInfo || (() => {});
    this._req = null;
    this._closed = false;
    this._started = false;
    this._backoffMs = RECONNECT_MIN_MS;
    this._inFallback = false;
    this._lastFallbackLogAt = 0;
    this._lastConfigErrorLogAt = 0;
  }

  start() {
    if (this._closed) return;
    this._started = true;
    this._connect();
  }

  close() {
    this._closed = true;
    if (this._req) {
      try { this._req.destroy(); } catch { /* already destroyed */ }
      this._req = null;
    }
  }

  // Whether the stream is currently the source of truth (i.e., started,
  // not closed, AND not in fallback mode). Useful for Shield to know
  // whether to trust SSE or rely on its own polling cadence.
  isLive() {
    return this._started && !this._inFallback && !this._closed;
  }

  _connect() {
    if (this._closed) return;
    const u = new URL(this.url);
    // Query-param scoping so Fortress can filter to this agent's channel.
    u.searchParams.set('agent_id', this.agentId);
    if (u.protocol !== 'https:') {
      this.onError(new Error(`policy-stream: refusing non-https URL: ${this.url}`));
      return;
    }

    const req = httpsRequest({
      hostname: u.hostname,
      port: u.port || 443,
      path: u.pathname + (u.search || ''),
      method: 'GET',
      headers: {
        'authorization': `Bearer ${this.apiKey}`,
        'accept': 'text/event-stream',
        'cache-control': 'no-cache',
        'connection': 'keep-alive',
      },
      rejectUnauthorized: true,
      lookup: guardedLookup,   // v1.4.11: DNS-rebinding guard on the Fortress SSE
    }, (res) => {
      this._req = req;

      // 404 — Fortress side hasn't deployed the endpoint yet. Silent
      // fallback: log once per 5 min, retry every 5 min, don't spam.
      if (res.statusCode === 404) {
        this._inFallback = true;
        const now = Date.now();
        if (now - this._lastFallbackLogAt > PERMANENT_FAILURE_LOG_INTERVAL_MS) {
          this.onInfo(`policy-stream: SSE endpoint not deployed (HTTP 404). Falling back to polling.`);
          this._lastFallbackLogAt = now;
        }
        res.resume(); // drain to free the socket
        this._scheduleReconnect(FALLBACK_RETRY_INTERVAL_MS);
        return;
      }

      // 401 — auth error. Config bug; log once per 5 min.
      if (res.statusCode === 401 || res.statusCode === 403) {
        const now = Date.now();
        if (now - this._lastConfigErrorLogAt > PERMANENT_FAILURE_LOG_INTERVAL_MS) {
          this.onError(new Error(`policy-stream: auth error (HTTP ${res.statusCode}) — check WMA_API_KEY`));
          this._lastConfigErrorLogAt = now;
        }
        this._inFallback = true;
        res.resume();
        this._scheduleReconnect(FALLBACK_RETRY_INTERVAL_MS);
        return;
      }

      if (res.statusCode !== 200) {
        this.onError(new Error(`policy-stream: unexpected HTTP ${res.statusCode}`));
        res.resume();
        this._scheduleReconnect();
        return;
      }

      // We're live. Reset backoff + fallback flag.
      this._backoffMs = RECONNECT_MIN_MS;
      this._inFallback = false;
      this.onInfo(`policy-stream: connected for ${this.agentId.slice(0, 16)}…`);
      res.setEncoding('utf8');

      let buffer = '';
      res.on('data', (chunk) => {
        buffer += chunk;
        // v1.1.4 F-18 (P1 Codex audit): normalize CR / CRLF line
        // terminators to LF before scanning for the event separator.
        // Without this, a Fortress deployment behind a reverse-proxy
        // that emits CRLF would never trigger a policy refresh push —
        // updates would silently fall back to the 60s polling loop,
        // breaking the "sub-second propagation" promise.
        buffer = normalizeSseBuffer(buffer);
        // v1.1.1 F-9: cap on a single SSE event buffer. A buggy/compromised
        // endpoint that never emits "\n\n" would otherwise OOM Shield.
        // Abort + reconnect on overflow; the buffer is dropped so we
        // restart fresh on the new connection.
        if (buffer.length > MAX_SSE_EVENT_BYTES) {
          this.onError(new Error(`policy-stream: SSE event exceeded ${MAX_SSE_EVENT_BYTES} bytes — aborting connection and reconnecting`));
          buffer = '';
          try { res.destroy(); } catch { /* already destroyed */ }
          if (!this._closed) this._scheduleReconnect();
          return;
        }
        // SSE events are separated by a blank line. Post-normalize the
        // canonical separator is "\n\n".
        let eolIdx;
        while ((eolIdx = buffer.indexOf('\n\n')) !== -1) {
          const rawEvent = buffer.slice(0, eolIdx);
          buffer = buffer.slice(eolIdx + 2);
          this._parseAndEmit(rawEvent);
        }
      });
      res.on('end', () => {
        if (!this._closed) {
          this.onInfo('policy-stream: connection closed, reconnecting…');
          this._scheduleReconnect();
        }
      });
      res.on('error', (e) => {
        this.onError(new Error(`policy-stream: response error: ${e.message}`));
        if (!this._closed) this._scheduleReconnect();
      });
    });

    req.on('error', (e) => {
      this.onError(new Error(`policy-stream: request error: ${e.message}`));
      if (!this._closed) this._scheduleReconnect();
    });
    // Stream MUST remain open — no body, no end() until close.
    req.end();
  }

  _parseAndEmit(rawEvent) {
    // SSE spec: each event is a set of "field: value" lines.
    // We care about the `data:` field (multiple data: lines concatenate).
    const dataLines = [];
    for (const line of rawEvent.split('\n')) {
      // Skip comments (lines starting with ":")
      if (line.startsWith(':')) continue;
      if (line.startsWith('data:')) {
        // Drop leading "data:" and optional space
        const v = line.slice(5).replace(/^ /, '');
        dataLines.push(v);
      }
    }
    if (dataLines.length === 0) return;
    const data = dataLines.join('\n');
    let parsed;
    try { parsed = JSON.parse(data); }
    catch (e) {
      this.onError(new Error(`policy-stream: invalid JSON in event: ${e.message}`));
      return;
    }
    // Emit 'policy_changed' — consumers should refresh their ruleset.
    this.emit('policy_changed', parsed);
  }

  _scheduleReconnect(forceDelay) {
    if (this._closed) return;
    const delay = forceDelay != null ? forceDelay : this._backoffMs;
    this._backoffMs = Math.min(this._backoffMs * 2, RECONNECT_MAX_MS);
    setTimeout(() => this._connect(), delay);
  }
}
