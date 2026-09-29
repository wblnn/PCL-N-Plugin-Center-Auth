-- 注册流程（用户名 + 用户 ID + 密码 + 强制 TOTP 确认）与 Microsoft 令牌加密存储。
ALTER TABLE users ADD COLUMN created_at TEXT;
ALTER TABLE users ADD COLUMN confirmed_at TEXT;
-- 既有账户（OAuth / 管理员预置）视为已确认，避免被未确认清理任务误删。
UPDATE users SET created_at='2026-09-29T00:00:00.000Z', confirmed_at='2026-09-29T00:00:00.000Z' WHERE confirmed_at IS NULL;

-- Microsoft 刷新令牌（AES-GCM 加密存储，密钥来自 TOKEN_ENC_KEY；未配置密钥则不存储）。
-- 用途：为已绑定账户重新派生 Xbox/Minecraft 令牌（启动器自动添加档案）。
CREATE TABLE microsoft_tokens(
  user_id TEXT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
  refresh_token_enc TEXT NOT NULL,
  obtained_at TEXT NOT NULL
);
