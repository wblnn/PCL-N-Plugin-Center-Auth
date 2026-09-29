// 用户 ID（类微信号）：6–20 位，字母开头，小写字母 / 数字 / 下划线 / 连字符。
// 全库唯一、大小写不敏感（统一存小写），更改受冷却期约束。
export const HANDLE_PATTERN = /^[a-z][a-z0-9_-]{5,19}$/;
export const HANDLE_COOLDOWN_DAYS = 30;

const RESERVED = new Set([
  'admin', 'administrator', 'root', 'system', 'api', 'auth', 'www', 'mail', 'email',
  'support', 'help', 'staff', 'mod', 'moderator', 'pcln', 'pcl', 'nexa', 'nexacl',
  'official', 'security', 'abuse', 'info', 'news', 'blog', 'docs', 'manage',
  'console', 'operations', 'store', 'download', 'account', 'login', 'logout',
  'register', 'signup', 'settings', 'profile', 'user', 'users', 'me', 'all',
  'everyone', 'null', 'undefined', 'true', 'false', 'anonymous', 'bot', 'crawler'
]);

export function normalizeHandle(value) {
  if (typeof value !== 'string') return null;
  const handle = value.trim().toLowerCase();
  return HANDLE_PATTERN.test(handle) ? handle : null;
}

export function isReservedHandle(handle) {
  return RESERVED.has(handle) || handle.startsWith('deleted') || handle.startsWith('system');
}

// 校验失败抛出的 Error.message 即用户可见文案。
export function validateHandle(value) {
  const handle = normalizeHandle(value);
  if (!handle) throw new Error('用户 ID 需为 6–20 位，以字母开头，仅可包含字母、数字、下划线或连字符');
  if (isReservedHandle(handle)) throw new Error('该用户 ID 为系统保留，无法使用');
  return handle;
}

// 展示名（用户名）：1–60 字符，剔除控制符与首尾空白。
export function validateDisplayName(value) {
  if (typeof value !== 'string') throw new Error('用户名无效');
  const name = value.replace(/[\u0000-\u001f\u007f]/g, '').trim();
  if (!name || name.length > 60) throw new Error('用户名需为 1–60 个字符');
  return name;
}
