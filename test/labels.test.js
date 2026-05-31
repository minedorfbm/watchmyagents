// labels — shared sanitizer for customer-supplied display names
// (v1.1.1 F-11 Codex audit fix)

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { cleanLabel } from '../src/labels.js';

test('cleanLabel returns empty string for null/undefined', () => {
  assert.equal(cleanLabel(null), '');
  assert.equal(cleanLabel(undefined), '');
});

test('cleanLabel coerces non-strings via String()', () => {
  assert.equal(cleanLabel(42), '42');
  assert.equal(cleanLabel(true), 'true');
});

test('cleanLabel strips ASCII control bytes (0x00-0x1F)', () => {
  assert.equal(cleanLabel('foo\x00bar'), 'foobar');
  assert.equal(cleanLabel('a\x07b\x1Fc'), 'abc');
  assert.equal(cleanLabel('\x1B[31mred\x1B[0m'), '[31mred[0m', 'ANSI escapes are stripped of ESC bytes');
});

test('cleanLabel strips the DEL byte 0x7F', () => {
  assert.equal(cleanLabel('a\x7Fb'), 'ab');
});

test('cleanLabel preserves printable ASCII + extended Unicode', () => {
  assert.equal(cleanLabel('Deep researcher'), 'Deep researcher');
  assert.equal(cleanLabel('Agent Financier €'), 'Agent Financier €');
  assert.equal(cleanLabel('日本語'), '日本語');
});

test('cleanLabel truncates to 60 characters', () => {
  const long = 'a'.repeat(100);
  const result = cleanLabel(long);
  assert.equal(result.length, 60);
});

test('cleanLabel trims leading/trailing whitespace AFTER stripping', () => {
  assert.equal(cleanLabel('  hello  '), 'hello');
  assert.equal(cleanLabel('\t\nworld\r\n'), 'world');
});

test('cleanLabel handles surrogate pairs without splitting them', () => {
  // 🤖 (U+1F916) is a 4-byte UTF-8 char represented as a surrogate pair in UTF-16.
  // Using [...str] (Array.from string iterator) preserves it as one element;
  // a naive str.split('') would split it into 2 broken halves.
  const result = cleanLabel('🤖 Worker');
  assert.equal(result, '🤖 Worker');
});

test('cleanLabel returns empty when input is only control bytes', () => {
  assert.equal(cleanLabel('\x00\x01\x02\x7F'), '');
});

test('cleanLabel returns empty when input is only whitespace', () => {
  assert.equal(cleanLabel('   '), '');
  assert.equal(cleanLabel('\t\n'), '');
});
