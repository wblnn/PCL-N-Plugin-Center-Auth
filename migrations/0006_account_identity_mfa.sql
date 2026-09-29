-- 账户身份与两步验证：用户 ID（类微信号）、显示名、密码登录挑战与 MFA 因子。
ALTER TABLE users ADD COLUMN user_handle TEXT;
ALTER TABLE users ADD COLUMN handle_changed_at INTEGER;
ALTER TABLE users ADD COLUMN password_set_at INTEGER;
CREATE UNIQUE INDEX users_handle ON users(user_handle);

-- Authenticator app（TOTP，RFC 6238）。每用户一行；secret 在配置 MFA_ENC_KEY 时为 AES-GCM 密文。
CREATE TABLE mfa_totp(
  user_id TEXT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
  secret TEXT NOT NULL,
  confirmed INTEGER NOT NULL DEFAULT 0 CHECK(confirmed IN (0,1)),
  last_step INTEGER,
  created_at TEXT NOT NULL,
  confirmed_at TEXT
);

-- Passkey（WebAuthn）。public_key 存 COSE 字节（base64url），仅支持 ES256 / RS256。
CREATE TABLE mfa_passkeys(
  credential_id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  public_key TEXT NOT NULL,
  algorithm INTEGER NOT NULL,
  sign_count INTEGER NOT NULL DEFAULT 0,
  name TEXT,
  created_at TEXT NOT NULL,
  last_used_at TEXT
);
CREATE INDEX mfa_passkeys_user ON mfa_passkeys(user_id);

-- 一次性恢复码：仅存 SHA-256，明文只在生成时返回一次。
CREATE TABLE mfa_recovery_codes(
  code_hash TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  created_at TEXT NOT NULL,
  used_at TEXT
);
CREATE INDEX mfa_recovery_user ON mfa_recovery_codes(user_id);

-- 密码登录两段式挑战（含 WebAuthn 断言挑战与 passkey 注册挑战）。
CREATE TABLE login_challenges(
  challenge_hash TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  purpose TEXT NOT NULL DEFAULT 'login' CHECK(purpose IN ('login','register')),
  wa_challenge TEXT,
  expires INTEGER NOT NULL,
  consumed INTEGER NOT NULL DEFAULT 0 CHECK(consumed IN (0,1)),
  created_at TEXT NOT NULL
);
CREATE INDEX login_challenges_expiry ON login_challenges(expires);
