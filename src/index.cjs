'use strict';

// CommonJS entrypoint — re-exports the ESM build via dynamic import.
// All consumers receive the same singleton-backed API.

const esmPromise = import('./index.js');

function bind(name) {
  return async function (...args) {
    const mod = await esmPromise;
    return mod[name](...args);
  };
}

class WatchMyAgentsLazy {
  constructor(opts) {
    this._ready = esmPromise.then(mod => new mod.WatchMyAgents(opts));
  }
  async watch(...args) { return (await this._ready).watch(...args); }
  async logAction(...args) { return (await this._ready).logAction(...args); }
  async flush() { return (await this._ready).flush(); }
  async shutdown() { return (await this._ready).shutdown(); }
  get instance() { return this._ready; }
}

module.exports = WatchMyAgentsLazy;
module.exports.default = WatchMyAgentsLazy;
module.exports.WatchMyAgents = WatchMyAgentsLazy;
module.exports.watch = bind('watch');
module.exports.createGenericMonitor = bind('createGenericMonitor');
module.exports.createClaudeMonitor = bind('createClaudeMonitor');
module.exports.createOpenAIMonitor = bind('createOpenAIMonitor');
module.exports.createLangChainHandler = bind('createLangChainHandler');
module.exports.anonymize = bind('anonymize');
module.exports.scrubString = bind('scrubString');
module.exports.hashId = bind('hashId');
