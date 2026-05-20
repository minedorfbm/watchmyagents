import { WatchMyAgents } from '../collector.js';

export async function watch(toolName, params, fn, meta = {}) {
  const wma = WatchMyAgents.getOrCreate();
  return wma.watch(toolName, params, fn, { framework: 'generic', ...meta });
}

export function createGenericMonitor(opts = {}) {
  const wma = WatchMyAgents.current() || new WatchMyAgents(opts);
  return {
    watch: (toolName, params, fn, meta) => wma.watch(toolName, params, fn, { framework: 'generic', ...meta }),
    wrap(obj, methodNames) {
      const names = methodNames || Object.keys(obj).filter(k => typeof obj[k] === 'function');
      const wrapped = {};
      for (const name of names) {
        wrapped[name] = (...args) => wma.watch(name, args, () => obj[name](...args), { framework: 'generic' });
      }
      return { ...obj, ...wrapped };
    },
  };
}
