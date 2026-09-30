-- 经验来源改造 + 铭牌墙。
--
-- 1) 经验来源收敛为四种日常行为 + 一次性首启:每日登录、每日启动、游戏时长、Nexa 在线时长。
--    全部由启动器(或本站登录流程)上报「发生了什么 / 持续多久」,数值由 Worker 权威决定。
-- 2) 引入毫 XP(xp_micro)结算,让 0.5 XP/分钟这类小数速率不会在逐次上报时丢失余量。
-- 3) 铭牌不单独存储授予记录:全部由 等级 / 连续启动 / 累计时长 / user_flags / users.staff
--    实时派生(见 src/nameplates.mjs),避免与真实信号产生漂移。只持久化「佩戴中的铭牌」。

-- 毫 XP 累计值(权威),xp = floor(xp_micro / 1000) 为派生的整数经验。
ALTER TABLE user_levels ADD COLUMN xp_micro INTEGER NOT NULL DEFAULT 0;
-- 每日登录 / 每日启动的 UTC 日锚点,同时充当幂等标记(同一天重复上报只计一次)。
ALTER TABLE user_levels ADD COLUMN last_login_day TEXT;
ALTER TABLE user_levels ADD COLUMN last_launch_day TEXT;
-- 连续启动天数:launch_streak 为当前连击,launch_streak_best 为历史最长(LvMC 铭牌依据后者,
-- 因此断签不会撤销已达成的铭牌)。
ALTER TABLE user_levels ADD COLUMN launch_streak INTEGER NOT NULL DEFAULT 0;
ALTER TABLE user_levels ADD COLUMN launch_streak_best INTEGER NOT NULL DEFAULT 0;
-- 累计时长(分钟),只增不减。game_minutes_total 是 Lv∞ 铭牌「MC 时长 > 1000 小时」的依据。
ALTER TABLE user_levels ADD COLUMN game_minutes_total INTEGER NOT NULL DEFAULT 0;
ALTER TABLE user_levels ADD COLUMN launcher_minutes_total INTEGER NOT NULL DEFAULT 0;
-- 佩戴中的铭牌 id;为 NULL 表示只显示等级。佩戴 replacesLevel 铭牌时前端隐藏等级数字。
ALTER TABLE user_levels ADD COLUMN equipped_plate TEXT;

-- 事件流水按毫 XP 记账:日上限(全局 + 单来源)都基于 amount_micro 求和。
ALTER TABLE xp_events ADD COLUMN amount_micro INTEGER NOT NULL DEFAULT 0;

-- 存量数据回填:历史上 1 单位 = 1 XP,故毫 XP = XP × 1000。
UPDATE user_levels SET xp_micro = xp * 1000 WHERE xp_micro = 0 AND xp > 0;
UPDATE xp_events SET amount_micro = amount * 1000 WHERE amount_micro = 0 AND amount > 0;

-- 日上限统计走 (user_id, type, occurred_at) 与 (user_id, occurred_at),补一个覆盖单来源的索引。
CREATE INDEX IF NOT EXISTS xp_events_source_day ON xp_events(user_id, type, occurred_at);
