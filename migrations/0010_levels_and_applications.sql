-- 等级与经验系统:Lv0~7。Lv0→1 需启动一次游戏(launched 标记);
-- Lv2~7 按累计经验:2k / 5k / 10k / 20k / 50k / 100k(阈值常量在 Worker 中)。
ALTER TABLE users ADD COLUMN trusted_developer INTEGER NOT NULL DEFAULT 0 CHECK(trusted_developer IN (0,1));

CREATE TABLE user_levels(
  user_id TEXT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
  xp INTEGER NOT NULL DEFAULT 0,
  launched INTEGER NOT NULL DEFAULT 0 CHECK(launched IN (0,1)),
  first_launch_at TEXT,
  updated_at TEXT NOT NULL
);

-- 经验事件流水:dedupe_key 幂等(同一遥测事件重放不重复计分)。
CREATE TABLE xp_events(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  type TEXT NOT NULL,
  amount INTEGER NOT NULL,
  dedupe_key TEXT,
  occurred_at TEXT NOT NULL,
  created_at TEXT NOT NULL
);
CREATE UNIQUE INDEX xp_events_dedupe ON xp_events(user_id, dedupe_key) WHERE dedupe_key IS NOT NULL;
CREATE INDEX xp_events_day ON xp_events(user_id, occurred_at);

-- 资格标记(如 popular_plugin:拥有下载量 >1k 的插件,由商店侧内部通道写入并附证据)。
CREATE TABLE user_flags(
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  flag TEXT NOT NULL,
  value TEXT,
  set_at TEXT NOT NULL,
  PRIMARY KEY(user_id, flag)
);

-- 资格申请:developer(Lv2)/ trusted_developer(开发者+Lv3+热门插件)/ admin(Lv4)。
CREATE TABLE applications(
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  kind TEXT NOT NULL CHECK(kind IN ('developer','trusted_developer','admin')),
  state TEXT NOT NULL DEFAULT 'pending' CHECK(state IN ('pending','approved','rejected')),
  note TEXT,
  created_at TEXT NOT NULL,
  reviewed_at TEXT,
  reviewer TEXT
);
CREATE UNIQUE INDEX one_pending_application ON applications(user_id, kind) WHERE state='pending';
CREATE INDEX applications_state ON applications(state, created_at);
