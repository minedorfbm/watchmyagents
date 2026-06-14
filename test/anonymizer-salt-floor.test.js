// v1.4.12 (audit residual) — salt entropy floor IN the library.
//
// The wma-* CLIs enforce a >=16-char salt, but the LIBRARY only checked falsy
// (`if (!salt)`), so a programmatic consumer could pass a weak salt → the IoC
// hashes become brute-forceable (IoCs are low-entropy). The floor now lives in
// the library at every salt-acceptance point.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  assertStrongSalt, MIN_SALT_LENGTH, hashWithSalt, normalizeToolName,
  SignalsAggregator, generateSalt,
} from '../src/anonymizer.js';

const WEAK = ['', 'a', 'short', '123456789012345', null, undefined, 12345678901234567];
const STRONG = '0123456789abcdef'; // exactly 16

test('MIN_SALT_LENGTH is 16 (matches the CLI floor + generateSalt output)', () => {
  assert.equal(MIN_SALT_LENGTH, 16);
  assert.ok(generateSalt().length >= MIN_SALT_LENGTH);
});

test('assertStrongSalt rejects weak/short/non-string salts', () => {
  for (const s of WEAK) {
    assert.throws(() => assertStrongSalt(s), /at least 16 characters|brute-forceable/, `weak salt: ${JSON.stringify(s)}`);
  }
});

test('assertStrongSalt accepts a >=16-char salt', () => {
  assert.doesNotThrow(() => assertStrongSalt(STRONG));
  assert.doesNotThrow(() => assertStrongSalt(generateSalt()));
});

test('hashWithSalt enforces the floor (programmatic bypass closed)', () => {
  assert.throws(() => hashWithSalt('1.2.3.4', 'weak'), /at least 16 characters/);
  assert.match(hashWithSalt('1.2.3.4', STRONG), /^sha256:[0-9a-f]{32}$/);
});

test('normalizeToolName enforces the floor for custom tools', () => {
  assert.throws(() => normalizeToolName('my_custom_tool', 'weak'), /at least 16 characters/);
  assert.match(normalizeToolName('my_custom_tool', STRONG), /^tool_hash:[0-9a-f]{32}$/);
  // well-known tools short-circuit BEFORE the salt is needed — still fine.
  assert.equal(normalizeToolName('web_search', 'weak'), 'web_search');
});

test('SignalsAggregator constructor rejects a weak salt', () => {
  assert.throws(() => new SignalsAggregator({ salt: 'weak' }), /at least 16 characters/);
  assert.doesNotThrow(() => new SignalsAggregator({ salt: STRONG }));
});
