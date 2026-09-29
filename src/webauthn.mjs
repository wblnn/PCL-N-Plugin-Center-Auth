// WebAuthn（passkey）验证：零依赖实现注册（attestation 'none'）与断言校验。
// 仅支持 ES256(-7) 与 RS256(-257)；CBOR 解码覆盖 WebAuthn 所需子集。

export const b64url = bytes => btoa(String.fromCharCode(...new Uint8Array(bytes))).replaceAll('+', '-').replaceAll('/', '_').replace(/=+$/g, '');
export const unb64url = text => Uint8Array.from(atob(String(text).replaceAll('-', '+').replaceAll('_', '/') + '='.repeat((4 - String(text).length % 4) % 4)), c => c.charCodeAt(0));

// ---------- 最小 CBOR 解码器 ----------
export function cborDecode(bytes) {
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  let offset = 0;
  const readArg = (info) => {
    if (info < 24) return info;
    if (info === 24) return view.getUint8(offset++);
    if (info === 25) { const v = view.getUint16(offset); offset += 2; return v; }
    if (info === 26) { const v = view.getUint32(offset); offset += 4; return v; }
    if (info === 27) { const v = view.getBigUint64(offset); offset += 8; return Number(v); }
    throw new Error('cbor: unsupported additional info ' + info);
  };
  const decode = () => {
    const head = view.getUint8(offset++);
    const major = head >> 5, info = head & 0x1f;
    switch (major) {
      case 0: return readArg(info);
      case 1: return -1 - readArg(info);
      case 2: { const len = readArg(info); const v = bytes.slice(offset, offset + len); offset += len; return v; }
      case 3: { const len = readArg(info); const v = new TextDecoder().decode(bytes.subarray(offset, offset + len)); offset += len; return v; }
      case 4: { const len = readArg(info); const arr = []; for (let i = 0; i < len; i++) arr.push(decode()); return arr; }
      case 5: { const len = readArg(info); const map = new Map(); for (let i = 0; i < len; i++) { const k = decode(); map.set(typeof k === 'object' && k?.buffer ? b64url(k) : k, decode()); } return map; }
      case 7: {
        if (info === 20) return false;
        if (info === 21) return true;
        if (info === 22) return null;
        if (info === 26) { const v = view.getFloat32(offset); offset += 4; return v; }
        if (info === 27) { const v = view.getFloat64(offset); offset += 8; return v; }
        throw new Error('cbor: unsupported simple value ' + info);
      }
      default: throw new Error('cbor: unsupported major type ' + major);
    }
  };
  const value = decode();
  if (offset !== bytes.length) throw new Error('cbor: trailing bytes');
  return value;
}

// ---------- COSE 公钥 → JWK ----------
const EC_CURVES = new Map([[1, 'P-256'], [2, 'P-384'], [3, 'P-521']]);
const ALG_NAMES = new Map([[-7, { name: 'ECDSA', hash: 'SHA-256' }], [-35, { name: 'ECDSA', hash: 'SHA-384' }], [-36, { name: 'ECDSA', hash: 'SHA-512' }], [-257, { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }]]);

export function coseToJwk(coseMap) {
  const kty = coseMap.get(1), alg = coseMap.get(3);
  if (!ALG_NAMES.has(alg)) throw new Error('webauthn: unsupported algorithm ' + alg);
  if (kty === 2) { // EC2
    const crv = EC_CURVES.get(coseMap.get(-1));
    if (!crv) throw new Error('webauthn: unsupported curve');
    return { jwk: { kty: 'EC', crv, x: b64url(coseMap.get(-2)), y: b64url(coseMap.get(-3)), ext: true, key_ops: ['verify'] }, alg };
  }
  if (kty === 3) { // RSA
    return { jwk: { kty: 'RSA', n: b64url(coseMap.get(-1)), e: b64url(coseMap.get(-2)), ext: true, key_ops: ['verify'] }, alg };
  }
  throw new Error('webauthn: unsupported key type ' + kty);
}

export const sha256 = async data => new Uint8Array(await crypto.subtle.digest('SHA-256', data));

// ---------- authenticatorData 解析 ----------
export function parseAuthenticatorData(authData) {
  if (authData.length < 37) throw new Error('webauthn: authenticatorData too short');
  const view = new DataView(authData.buffer, authData.byteOffset, authData.byteLength);
  const rpIdHash = b64url(authData.slice(0, 32));
  const flags = authData[32];
  const signCount = view.getUint32(33);
  const parsed = { rpIdHash, flags, userPresent: Boolean(flags & 0x01), userVerified: Boolean(flags & 0x04), attestedCredentialData: Boolean(flags & 0x40), signCount };
  if (parsed.attestedCredentialData) {
    let offset = 37 + 16; // aaguid
    const credLen = view.getUint16(offset); offset += 2;
    parsed.credentialId = authData.slice(offset, offset + credLen); offset += credLen;
    // COSE 公钥是 authData 尾部的 CBOR map；截取到结尾解码。
    const coseBytes = authData.slice(offset);
    parsed.cose = cborDecode(coseBytes);
    parsed.coseBytes = coseBytes;
  }
  return parsed;
}

function verifyClientData(clientDataJSON, expectedType, expectedChallenge, expectedOrigins) {
  let clientData;
  try { clientData = JSON.parse(new TextDecoder().decode(clientDataJSON)); } catch { throw new Error('webauthn: invalid clientDataJSON'); }
  if (clientData.type !== expectedType) throw new Error('webauthn: unexpected ceremony type');
  if (clientData.challenge !== expectedChallenge) throw new Error('webauthn: challenge mismatch');
  if (!expectedOrigins.includes(clientData.origin)) throw new Error('webauthn: origin not allowed');
  if (clientData.crossOrigin === true) throw new Error('webauthn: cross-origin ceremony rejected');
}

// ---------- 注册 ----------
export async function verifyRegistration({ clientDataJSON, attestationObject, expectedChallenge, expectedOrigins, rpId }) {
  verifyClientData(unb64url(clientDataJSON), 'webauthn.create', expectedChallenge, expectedOrigins);
  const attestation = cborDecode(unb64url(attestationObject));
  const fmt = attestation.get('fmt');
  if (fmt !== 'none') throw new Error('webauthn: only none attestation is accepted, got ' + fmt);
  const authData = attestation.get('authData');
  if (!authData) throw new Error('webauthn: missing authData');
  const parsed = parseAuthenticatorData(new Uint8Array(authData));
  if (parsed.rpIdHash !== b64url(await sha256(new TextEncoder().encode(rpId)))) throw new Error('webauthn: rpIdHash mismatch');
  if (!parsed.userPresent) throw new Error('webauthn: user presence flag required');
  if (!parsed.attestedCredentialData || !parsed.credentialId || !parsed.cose) throw new Error('webauthn: missing attested credential data');
  const { jwk, alg } = coseToJwk(parsed.cose);
  return { credentialId: b64url(parsed.credentialId), coseBytes: b64url(parsed.coseBytes), jwk, alg, signCount: parsed.signCount };
}

// ---------- 断言 ----------
export async function importCoseJwk(jwk, alg) {
  const meta = ALG_NAMES.get(alg);
  if (!meta) throw new Error('webauthn: unsupported algorithm ' + alg);
  const params = meta.name === 'ECDSA' ? { name: 'ECDSA', namedCurve: jwk.crv } : { name: 'RSASSA-PKCS1-v1_5', hash: meta.hash };
  return { key: await crypto.subtle.importKey('jwk', jwk, params, false, ['verify']), meta };
}

export async function verifyAssertion({ publicKeyJwk, alg, clientDataJSON, authenticatorData, signature, expectedChallenge, expectedOrigins, rpId, storedSignCount = 0 }) {
  const clientDataBytes = unb64url(clientDataJSON);
  verifyClientData(clientDataBytes, 'webauthn.get', expectedChallenge, expectedOrigins);
  const authData = unb64url(authenticatorData);
  const parsed = parseAuthenticatorData(authData);
  if (parsed.rpIdHash !== b64url(await sha256(new TextEncoder().encode(rpId)))) throw new Error('webauthn: rpIdHash mismatch');
  if (!parsed.userPresent) throw new Error('webauthn: user presence flag required');
  if (parsed.signCount !== 0 || storedSignCount !== 0) {
    if (parsed.signCount <= storedSignCount) throw new Error('webauthn: signature counter did not increase');
  }
  const { key, meta } = await importCoseJwk(publicKeyJwk, alg);
  const signed = new Uint8Array([...authData, ...(await sha256(clientDataBytes))]);
  const algorithm = meta.name === 'ECDSA' ? { name: 'ECDSA', hash: meta.hash } : { name: 'RSASSA-PKCS1-v1_5' };
  const ok = await crypto.subtle.verify(algorithm, key, unb64url(signature), signed);
  if (!ok) throw new Error('webauthn: signature verification failed');
  return { signCount: parsed.signCount };
}

// user.id 需为 16–64 字节：UUID 转原始字节，非 UUID 时取 SHA-256 前 16 字节。
export async function webauthnUserId(userId) {
  const uuid = String(userId).match(/^([0-9a-f]{8})([0-9a-f]{4})([0-9a-f]{4})([0-9a-f]{4})([0-9a-f]{12})$/i);
  if (uuid) {
    const hex = uuid.slice(1).join('');
    const bytes = new Uint8Array(16);
    for (let i = 0; i < 16; i++) bytes[i] = parseInt(hex.substr(i * 2, 2), 16);
    return b64url(bytes);
  }
  return b64url((await sha256(new TextEncoder().encode(String(userId)))).slice(0, 16));
}
