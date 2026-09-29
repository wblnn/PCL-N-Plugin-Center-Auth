import test from 'node:test';
import assert from 'node:assert/strict';
import { generateRecoveryCodes, hashRecoveryCode, normalizeRecoveryCode } from '../src/recovery.mjs';

test('generates 10 unique well-formed codes without ambiguous characters', () => {
  const codes = generateRecoveryCodes(10);
  assert.equal(codes.length, 10);
  assert.equal(new Set(codes).size, 10);
  for (const code of codes) {
    assert.match(code, /^[ABCDEFGHJKLMNPQRSTUVWXYZ23456789]{5}-[ABCDEFGHJKLMNPQRSTUVWXYZ23456789]{5}$/);
  }
});

test('hashing is normalization-stable', () => {
  const [code] = generateRecoveryCodes(1);
  assert.equal(hashRecoveryCode(code), hashRecoveryCode(code.toLowerCase()));
  assert.equal(hashRecoveryCode(code), hashRecoveryCode(code.replace('-', ' ')));
  assert.equal(normalizeRecoveryCode(` ${code.toLowerCase()} `), code.replace('-', ''));
  assert.match(hashRecoveryCode(code), /^[0-9a-f]{64}$/);
});
