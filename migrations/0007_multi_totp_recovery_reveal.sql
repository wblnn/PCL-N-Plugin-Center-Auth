-- 多验证器支持 + 恢复码可查看。
-- mfa_totp 重建为多行（每设备一条，命名），原单行数据无损迁移。
CREATE TABLE mfa_totp_devices(
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  name TEXT,
  secret TEXT NOT NULL,
  confirmed INTEGER NOT NULL DEFAULT 0 CHECK(confirmed IN (0,1)),
  last_step INTEGER,
  created_at TEXT NOT NULL,
  confirmed_at TEXT
);
INSERT INTO mfa_totp_devices(id,user_id,name,secret,confirmed,last_step,created_at,confirmed_at)
  SELECT lower(hex(randomblob(16))), user_id, NULL, secret, confirmed, last_step, created_at, confirmed_at FROM mfa_totp;
DROP TABLE mfa_totp;
ALTER TABLE mfa_totp_devices RENAME TO mfa_totp;
CREATE INDEX mfa_totp_user ON mfa_totp(user_id);

-- 恢复码可查看：追加可解密副本（配置 MFA_ENC_KEY 时为 AES-GCM 密文，否则明文）。
-- 登录核销仍以 code_hash 为唯一依据；code_store 仅用于账户主复核后展示/打印。
ALTER TABLE mfa_recovery_codes ADD COLUMN code_store TEXT;
