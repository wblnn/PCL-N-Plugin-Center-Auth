// TOTP（RFC 6238，SHA-1 / 30 秒 / 6 位）与可选的 AES-GCM 密钥加密。
const B32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

export function base32Encode(bytes) {
  let bits = 0, value = 0, out = '';
  for (const byte of bytes) {
    value = (value << 8) | byte; bits += 8;
    while (bits >= 5) { out += B32[(value >>> (bits - 5)) & 31]; bits -= 5; }
  }
  if (bits > 0) out += B32[(value << (5 - bits)) & 31];
  return out;
}

export function base32Decode(text) {
  const clean = String(text).toUpperCase().replace(/=+$/g, '').replace(/\s/g, '');
  if (!/^[A-Z2-7]+$/.test(clean)) throw new Error('invalid base32');
  const bytes = [];
  let bits = 0, value = 0;
  for (const char of clean) {
    value = (value << 5) | B32.indexOf(char); bits += 5;
    if (bits >= 8) { bytes.push((value >>> (bits - 8)) & 0xff); bits -= 8; }
  }
  return new Uint8Array(bytes);
}

export function randomSecret(bytes = 20) {
  return base32Encode(crypto.getRandomValues(new Uint8Array(bytes)));
}

export function otpauthUrl(secret, accountName, issuer = 'NexaCloud') {
  const label = encodeURIComponent(`${issuer}:${accountName}`);
  return `otpauth://totp/${label}?secret=${secret}&issuer=${encodeURIComponent(issuer)}&algorithm=SHA1&digits=6&period=30`;
}

async function hmacSha1(keyBytes, message) {
  const key = await crypto.subtle.importKey('raw', keyBytes, { name: 'HMAC', hash: 'SHA-1' }, false, ['sign']);
  return new Uint8Array(await crypto.subtle.sign('HMAC', key, message));
}

// 与输入字符串等长的定时安全比较。
export async function safeEqual(a, b) {
  const [ha, hb] = await Promise.all([a, b].map(async v => new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(String(v))))));
  let diff = ha.length ^ hb.length;
  for (let i = 0; i < ha.length; i++) diff |= ha[i] ^ hb[i];
  return diff === 0;
}

export async function totpCode(secret, timeStep = 0, now = Date.now()) {
  const counter = Math.floor(now / 30000) + timeStep;
  const buf = new ArrayBuffer(8);
  new DataView(buf).setBigUint64(0, BigInt(counter));
  const hmac = await hmacSha1(base32Decode(secret), buf);
  const offset = hmac[hmac.length - 1] & 0x0f;
  const code = (((hmac[offset] & 0x7f) << 24) | (hmac[offset + 1] << 16) | (hmac[offset + 2] << 8) | hmac[offset + 3]) % 1000000;
  return String(code).padStart(6, '0');
}

// 允许 ±1 个时间步；lastStep 防重放。验证通过返回步数，否则返回 null。
export async function verifyTotp(secret, code, now = Date.now(), lastStep = null) {
  if (!/^\d{6}$/.test(String(code ?? ''))) return null;
  const base = Math.floor(now / 30000);
  for (const delta of [0, -1, 1]) {
    const step = base + delta;
    if (lastStep !== null && lastStep !== undefined && step <= lastStep) continue;
    if (await safeEqual(await totpCode(secret, delta, now), String(code))) return step;
  }
  return null;
}

// ---- 可选静态加密：配置 MFA_ENC_KEY 后 TOTP secret 以 AES-GCM 落库 ----
async function aesKey(encKey) {
  const raw = new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(encKey)));
  return crypto.subtle.importKey('raw', raw, { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']);
}
const b64url = bytes => btoa(String.fromCharCode(...bytes)).replaceAll('+', '-').replaceAll('/', '_').replace(/=+$/g, '');
const unb64url = text => Uint8Array.from(atob(text.replaceAll('-', '+').replaceAll('_', '/') + '='.repeat((4 - text.length % 4) % 4)), c => c.charCodeAt(0));

export async function encryptSecret(plaintext, encKey) {
  if (!encKey) return plaintext;
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, await aesKey(encKey), new TextEncoder().encode(plaintext)));
  return 'enc:' + b64url(new Uint8Array([...iv, ...ct]));
}

export async function decryptSecret(stored, encKey) {
  if (!stored.startsWith('enc:')) return stored;
  if (!encKey) throw new Error('TOTP secret is encrypted but MFA_ENC_KEY is not configured');
  const all = unb64url(stored.slice(4));
  const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: all.slice(0, 12) }, await aesKey(encKey), all.slice(12));
  return new TextDecoder().decode(pt);
}
