import test from 'node:test';
import assert from 'node:assert/strict';
import { base32Encode, base32Decode, totpCode, verifyTotp, randomSecret, otpauthUrl, encryptSecret, decryptSecret, safeEqual } from '../src/totp.mjs';

// RFC 6238 附录 B 测试向量（SHA-1，seed '12345678901234567890'），8 位值截取后 6 位。
const RFC_SECRET = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ';

test('base32 roundtrip', () => {
  const bytes = new Uint8Array([0, 1, 254, 255, 16, 32, 64, 128, 99, 200]);
  assert.deepEqual(base32Decode(base32Encode(bytes)), bytes);
});

test('totp matches RFC 6238 vectors (6-digit truncation)', async () => {
  // 向量经 Python hmac/hashlib 独立复算核对（secret = ASCII '12345678901234567890'）。
  assert.equal(await totpCode(RFC_SECRET, 0, 59_000), '287082');          // T=59
  assert.equal(await totpCode(RFC_SECRET, 0, 1_111_111_109_000), '081804'); // T=1111111109
  assert.equal(await totpCode(RFC_SECRET, 0, 2_000_000_000_000), '279037'); // T=2000000000
});

test('verifyTotp accepts ±1 step window and guards replay', async () => {
  const now = 1_700_000_000_000;
  const prev = await totpCode(RFC_SECRET, -1, now);
  const cur = await totpCode(RFC_SECRET, 0, now);
  assert.equal(await verifyTotp(RFC_SECRET, cur, now), Math.floor(now / 30000));
  assert.equal(await verifyTotp(RFC_SECRET, prev, now), Math.floor(now / 30000) - 1);
  assert.equal(await verifyTotp(RFC_SECRET, '000000', now), null);
  assert.equal(await verifyTotp(RFC_SECRET, '12345', now), null);
  // 重放防护：已用步数不再接受
  const step = await verifyTotp(RFC_SECRET, cur, now);
  assert.equal(await verifyTotp(RFC_SECRET, cur, now, step), null);
});

test('randomSecret generates decodable 20-byte secrets and otpauth url', () => {
  const secret = randomSecret();
  assert.equal(base32Decode(secret).length, 20);
  assert.match(otpauthUrl(secret, 'alice'), /^otpauth:\/\/totp\/NexaCloud(%3A|:)alice\?secret=/);
});

test('secret encryption roundtrip (with and without key)', async () => {
  const secret = randomSecret();
  assert.equal(await decryptSecret(await encryptSecret(secret, undefined), undefined), secret);
  const enc = await encryptSecret(secret, 'unit-test-key');
  assert.ok(enc.startsWith('enc:'));
  assert.equal(await decryptSecret(enc, 'unit-test-key'), secret);
  await assert.rejects(() => decryptSecret(enc, undefined));
  await assert.rejects(() => decryptSecret(enc, 'wrong-key'));
});

test('safeEqual is content-based', async () => {
  assert.ok(await safeEqual('123456', '123456'));
  assert.ok(!(await safeEqual('123456', '654321')));
  assert.ok(!(await safeEqual('123456', '1234567')));
});
