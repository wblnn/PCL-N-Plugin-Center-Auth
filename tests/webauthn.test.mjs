import test from 'node:test';
import assert from 'node:assert/strict';
import { cborDecode, verifyRegistration, verifyAssertion, b64url, unb64url, webauthnUserId } from '../src/webauthn.mjs';

// ---------- 测试侧最小 CBOR 编码器（构造认证器数据） ----------
const concat = parts => { const all = parts.flat(); const len = all.reduce((n, p) => n + p.length, 0); const out = new Uint8Array(len); let o = 0; for (const p of all) { out.set(p, o); o += p.length; } return out; };
function head(major, len) {
  const m = major << 5;
  if (len < 24) return new Uint8Array([m | len]);
  if (len < 256) return new Uint8Array([m | 24, len]);
  const b = new Uint8Array([m | 25, 0, 0]); new DataView(b.buffer).setUint16(1, len); return b;
}
function enc(value) {
  if (value instanceof Uint8Array) return concat([head(2, value.length), value]);
  if (typeof value === 'string') { const b = new TextEncoder().encode(value); return concat([head(3, b.length), b]); }
  if (typeof value === 'number' && Number.isInteger(value)) return value >= 0 ? head(0, value) : head(1, -1 - value);
  if (typeof value === 'boolean') return new Uint8Array([value ? 0xf5 : 0xf4]);
  if (value === null) return new Uint8Array([0xf6]);
  if (Array.isArray(value)) return concat([head(4, value.length), value.map(enc)]);
  if (value instanceof Map) return concat([head(5, value.size), [...value].flatMap(([k, v]) => [enc(k), enc(v)])]);
  throw new Error('unsupported');
}

const sha256 = async data => new Uint8Array(await crypto.subtle.digest('SHA-256', data));
const RP_ID = 'pcln.top';
const ORIGIN = 'https://auth.pcln.top';
const text = s => new TextEncoder().encode(s);

async function makeAuthenticator() {
  const pair = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
  const jwk = await crypto.subtle.exportKey('jwk', pair.publicKey);
  const cose = new Map([[1, 2], [3, -7], [-1, 1], [-2, unb64url(jwk.x)], [-3, unb64url(jwk.y)]]);
  const credentialId = crypto.getRandomValues(new Uint8Array(32));
  const rpIdHash = await sha256(text(RP_ID));
  return { pair, jwk, coseBytes: enc(cose), credentialId, rpIdHash };
}
function authData(auth, flags, counter, withCredential) {
  const c = new Uint8Array(4); new DataView(c.buffer).setUint32(0, counter);
  const parts = [auth.rpIdHash, new Uint8Array([flags]), c];
  if (withCredential) {
    const len = new Uint8Array(2); new DataView(len.buffer).setUint16(0, auth.credentialId.length);
    parts.push(new Uint8Array(16), len, auth.credentialId, auth.coseBytes);
  }
  return concat(parts);
}
const clientData = (type, challenge, origin = ORIGIN) => b64url(text(JSON.stringify({ type, challenge, origin, crossOrigin: false })));

async function register(auth, challenge = b64url(crypto.getRandomValues(new Uint8Array(32)))) {
  const attestationObject = b64url(enc(new Map([['fmt', 'none'], ['attStmt', new Map()], ['authData', authData(auth, 0x45, 0, true)]])));
  return { challenge, result: await verifyRegistration({ clientDataJSON: clientData('webauthn.create', challenge), attestationObject, expectedChallenge: challenge, expectedOrigins: [ORIGIN], rpId: RP_ID }) };
}

test('cborDecode roundtrips the encoder subset', () => {
  const value = new Map([['fmt', 'none'], ['n', 42], ['neg', -7], ['bytes', new Uint8Array([1, 2, 3])], ['arr', [true, false, null]]]);
  const decoded = cborDecode(enc(value));
  assert.equal(decoded.get('fmt'), 'none');
  assert.equal(decoded.get('n'), 42);
  assert.equal(decoded.get('neg'), -7);
  assert.deepEqual(decoded.get('bytes'), new Uint8Array([1, 2, 3]));
  assert.deepEqual(decoded.get('arr'), [true, false, null]);
});

test('verifyRegistration parses credential and COSE key', async () => {
  const auth = await makeAuthenticator();
  const { result } = await register(auth);
  assert.equal(result.credentialId, b64url(auth.credentialId));
  assert.equal(result.alg, -7);
  assert.equal(result.jwk.kty, 'EC');
  assert.equal(result.jwk.crv, 'P-256');
  assert.equal(result.jwk.x, auth.jwk.x);
  assert.equal(result.signCount, 0);
});

test('verifyRegistration rejects wrong origin / challenge / fmt', async () => {
  const auth = await makeAuthenticator();
  const challenge = b64url(text('c1'));
  const good = b64url(enc(new Map([['fmt', 'none'], ['attStmt', new Map()], ['authData', authData(auth, 0x45, 0, true)]])));
  await assert.rejects(() => verifyRegistration({ clientDataJSON: clientData('webauthn.create', challenge, 'https://evil.example'), attestationObject: good, expectedChallenge: challenge, expectedOrigins: [ORIGIN], rpId: RP_ID }), /origin/);
  await assert.rejects(() => verifyRegistration({ clientDataJSON: clientData('webauthn.create', b64url(text('other'))), attestationObject: good, expectedChallenge: challenge, expectedOrigins: [ORIGIN], rpId: RP_ID }), /challenge/);
  const packed = b64url(enc(new Map([['fmt', 'packed'], ['attStmt', new Map()], ['authData', authData(auth, 0x45, 0, true)]])));
  await assert.rejects(() => verifyRegistration({ clientDataJSON: clientData('webauthn.create', challenge), attestationObject: packed, expectedChallenge: challenge, expectedOrigins: [ORIGIN], rpId: RP_ID }), /none attestation/);
});

test('verifyAssertion accepts a genuine P-256 signature and enforces counter/origin/signature', async () => {
  const auth = await makeAuthenticator();
  const { result } = await register(auth);
  const challenge = b64url(text('assert-challenge'));
  const ad = authData(auth, 0x05, 1, false);
  const cd = clientData('webauthn.get', challenge);
  const signed = concat([ad, await sha256(unb64url(cd))]);
  const signature = b64url(new Uint8Array(await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, auth.pair.privateKey, signed)));
  const ok = await verifyAssertion({ publicKeyJwk: result.jwk, alg: result.alg, clientDataJSON: cd, authenticatorData: b64url(ad), signature, expectedChallenge: challenge, expectedOrigins: [ORIGIN], rpId: RP_ID, storedSignCount: 0 });
  assert.equal(ok.signCount, 1);
  // 计数器未增长 → 拒绝（克隆认证器启发式）
  await assert.rejects(() => verifyAssertion({ publicKeyJwk: result.jwk, alg: result.alg, clientDataJSON: cd, authenticatorData: b64url(ad), signature, expectedChallenge: challenge, expectedOrigins: [ORIGIN], rpId: RP_ID, storedSignCount: 1 }), /counter/);
  // 签名篡改 → 拒绝
  const tampered = unb64url(signature); tampered[0] ^= 0xff;
  await assert.rejects(() => verifyAssertion({ publicKeyJwk: result.jwk, alg: result.alg, clientDataJSON: cd, authenticatorData: b64url(ad), signature: b64url(tampered), expectedChallenge: challenge, expectedOrigins: [ORIGIN], rpId: RP_ID, storedSignCount: 0 }), /signature/);
  // 来源不符 → 拒绝
  await assert.rejects(() => verifyAssertion({ publicKeyJwk: result.jwk, alg: result.alg, clientDataJSON: clientData('webauthn.get', challenge, 'https://evil.example'), authenticatorData: b64url(ad), signature, expectedChallenge: challenge, expectedOrigins: [ORIGIN], rpId: RP_ID, storedSignCount: 0 }), /origin/);
  // 缺少用户在场标志 → 拒绝
  const noUp = authData(auth, 0x04, 2, false);
  await assert.rejects(() => verifyAssertion({ publicKeyJwk: result.jwk, alg: result.alg, clientDataJSON: cd, authenticatorData: b64url(noUp), signature, expectedChallenge: challenge, expectedOrigins: [ORIGIN], rpId: RP_ID, storedSignCount: 1 }), /presence/);
});

test('webauthnUserId maps UUIDs to 16 raw bytes and falls back to hashing', async () => {
  const id = '3f2504e0-4f89-11d3-9a0c-0305e82c3301';
  assert.equal(unb64url(await webauthnUserId(id)).length, 16);
  assert.equal(unb64url(await webauthnUserId('not-a-uuid')).length, 16);
});
