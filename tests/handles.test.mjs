import test from 'node:test';
import assert from 'node:assert/strict';
import { validateHandle, normalizeHandle, isReservedHandle, validateDisplayName, HANDLE_COOLDOWN_DAYS } from '../src/handles.mjs';

test('normalizeHandle lowercases and trims', () => {
  assert.equal(normalizeHandle('  Alice_42-X '), 'alice_42-x');
  assert.equal(normalizeHandle(null), null);
  assert.equal(normalizeHandle(123), null);
});

test('validateHandle enforces WeChat-id-like rules', () => {
  assert.equal(validateHandle('abcdef'), 'abcdef');            // 6 位最小长度
  assert.equal(validateHandle('a1234567890123456789'), 'a1234567890123456789'); // 20 位
  assert.throws(() => validateHandle('abcde'), /6–20/);          // 过短
  assert.throws(() => validateHandle('a12345678901234567890'), /6–20/); // 21 位过长
  assert.throws(() => validateHandle('1abcdef'), /字母开头/);     // 数字开头
  assert.throws(() => validateHandle('abc.def'), /6–20/);        // 非法字符
  assert.throws(() => validateHandle('abc def'), /6–20/);        // 空格
  assert.throws(() => validateHandle(''), /6–20/);
});

test('reserved handles are rejected', () => {
  assert.ok(isReservedHandle('admin'));
  assert.ok(isReservedHandle('nexacl'));
  assert.ok(isReservedHandle('deletedjohn'));
  assert.ok(isReservedHandle('systemghost'));
  assert.throws(() => validateHandle('Nexacl'), /保留/);
  assert.ok(!isReservedHandle('alice_42'));
});

test('cooldown constant is 30 days', () => {
  assert.equal(HANDLE_COOLDOWN_DAYS, 30);
});

test('validateDisplayName strips control chars and enforces bounds', () => {
  assert.equal(validateDisplayName('  玩家\u0000One  '), '玩家One');
  assert.throws(() => validateDisplayName('   '), /1–60/);
  assert.throws(() => validateDisplayName('x'.repeat(61)), /1–60/);
  assert.throws(() => validateDisplayName(42), /无效/);
});
