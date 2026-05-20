import { request } from 'node:https';
import { URL } from 'node:url';
import { createCipheriv, randomBytes, scryptSync } from 'node:crypto';
import { anonymize } from './anonymizer.js';

const SALT = Buffer.from('watchmyagents.v1.salt', 'utf8');

export class Exporter {
  constructor({ apiKey, exportUrl, agentId, batchInterval = 30000, silent = true }) {
    this.apiKey = apiKey;
    this.exportUrl = exportUrl;
    this.agentId = agentId;
    this.silent = silent;
    this.queue = [];
    this.key = apiKey ? scryptSync(apiKey, SALT, 32) : null;
    this.timer = null;
    this.batchInterval = batchInterval;
  }

  start() {
    if (this.timer || !this.exportUrl || !this.apiKey) return;
    this.timer = setInterval(() => this.flush().catch(() => {}), this.batchInterval);
    if (this.timer.unref) this.timer.unref();
  }
  stop() { if (this.timer) { clearInterval(this.timer); this.timer = null; } }
  enqueue(record) { this.queue.push(anonymize(record)); }

  _encrypt(payload) {
    const iv = randomBytes(16);
    const c = createCipheriv('aes-256-gcm', this.key, iv);
    const data = Buffer.concat([c.update(payload, 'utf8'), c.final()]);
    return { iv: iv.toString('base64'), tag: c.getAuthTag().toString('base64'), data: data.toString('base64') };
  }

  async flush() {
    if (!this.exportUrl || !this.apiKey || this.queue.length === 0) return;
    const batch = this.queue.splice(0, this.queue.length);
    const body = JSON.stringify({ agent_id: this.agentId, count: batch.length, records: batch });
    const payload = JSON.stringify({ v: 1, agent_id: this.agentId, ...this._encrypt(body) });
    for (let attempt = 1; attempt <= 3; attempt++) {
      try { await this._post(payload); return; }
      catch (e) {
        if (attempt === 3) {
          this.queue.unshift(...batch);
          if (!this.silent) process.stderr.write(`[wma] export failed: ${e.message}\n`);
          return;
        }
        await new Promise(r => setTimeout(r, 1000 * 2 ** attempt));
      }
    }
  }

  _post(payload) {
    return new Promise((resolve, reject) => {
      let u; try { u = new URL(this.exportUrl); } catch (e) { return reject(e); }
      if (u.protocol !== 'https:') return reject(new Error('HTTPS only'));
      const req = request({
        host: u.hostname, port: u.port || 443, path: u.pathname + u.search,
        method: 'POST', rejectUnauthorized: true,
        headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(payload), 'X-WMA-Key': this.apiKey },
      }, res => {
        res.resume();
        if (res.statusCode >= 200 && res.statusCode < 300) resolve();
        else reject(new Error(`HTTP ${res.statusCode}`));
      });
      req.on('error', reject);
      req.write(payload); req.end();
    });
  }
}
