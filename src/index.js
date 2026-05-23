import { WatchMyAgents } from './collector.js';
import { watch, createGenericMonitor } from './adapters/generic.js';
import { createClaudeMonitor } from './adapters/claude.js';
import { createOpenAIMonitor } from './adapters/openai.js';
import { createLangChainHandler } from './adapters/langchain.js';
import { anonymize, scrubString, hashId } from './anonymizer.js';
import { DEFAULT_PRICING, estimateCost, TokenTracker } from './tokens.js';
import * as anthropicManaged from './sources/anthropic-managed.js';

export {
  WatchMyAgents,
  watch,
  createGenericMonitor,
  createClaudeMonitor,
  createOpenAIMonitor,
  createLangChainHandler,
  anonymize,
  scrubString,
  hashId,
  DEFAULT_PRICING,
  estimateCost,
  TokenTracker,
  anthropicManaged,
};

export default WatchMyAgents;
