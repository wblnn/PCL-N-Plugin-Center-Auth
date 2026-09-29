// 一次性 2FA 恢复码：形如 A1B2C-3D4E5（去除易混淆字符），仅存 SHA-256。
import { digest } from './password.mjs';

const ALPHABET = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';

export function generateRecoveryCodes(count = 10) {
  const codes = new Set();
  while (codes.size < count) {
    const bytes = crypto.getRandomValues(new Uint8Array(10));
    let code = '';
    for (let i = 0; i < 10; i++) {
      if (i === 5) code += '-';
      code += ALPHABET[bytes[i] % ALPHABET.length];
    }
    codes.add(code);
  }
  return [...codes];
}

export const normalizeRecoveryCode = code => String(code ?? '').toUpperCase().replace(/[^A-Z0-9]/g, '');

export const hashRecoveryCode = code => digest(normalizeRecoveryCode(code));
