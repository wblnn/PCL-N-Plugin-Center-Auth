-- Microsoft 绑定 → Xbox Live → Minecraft 拥有状况与档案。
-- 供启动器登录后自动添加游戏档案（profile_id 即 Minecraft UUID）。
CREATE TABLE minecraft_profiles(
  user_id TEXT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
  owned INTEGER CHECK(owned IN (0,1)),            -- NULL = 核查未成功（见 error）
  profile_id TEXT,
  profile_name TEXT,
  error TEXT,
  checked_at TEXT NOT NULL
);
