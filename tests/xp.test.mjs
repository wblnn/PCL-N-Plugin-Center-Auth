import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  XP_RULES, XP_DAILY_CAP, MICRO, LEVEL_THRESHOLDS, computeLevel,
  nextLaunchStreak, normalizeUnits, computeXpGain, xpSourceCatalog, XP_EVENT_TYPES
} from '../src/index.mjs';

const rule = type => XP_RULES[type];
const xp = micro => micro / MICRO;

test('经验来源恰好是四种日常行为 + 一次性首启', () => {
  assert.deepEqual(XP_EVENT_TYPES.sort(), [
    'daily.launch', 'daily.login', 'game.first_launch', 'game.play_minutes', 'launcher.online_minutes'
  ]);
  // 旧的无上限刷分来源已移除
  for (const gone of ['game.launch', 'install.complete', 'resource.download']) assert.ok(!(gone in XP_RULES), gone);
});

test('定额来源的数值:每日登录 +50、每日启动 +30、首次启动 +100', () => {
  assert.equal(xp(rule('daily.login').micro), 50);
  assert.equal(xp(rule('daily.launch').micro), 30);
  assert.equal(xp(rule('game.first_launch').micro), 100);
  assert.equal(rule('daily.login').perDay, 'last_login_day');
  assert.equal(rule('daily.launch').perDay, 'last_launch_day');
  assert.ok(rule('daily.launch').streak, '每日启动需推进连续天数');
  assert.ok(rule('daily.launch').setsLaunched && rule('game.first_launch').setsLaunched, '启动类事件解锁 Lv1');
  assert.ok(rule('game.first_launch').once && rule('game.first_launch').capExempt);
});

test('时长来源的速率:游戏 1 XP/分钟、Nexa 在线 0.5 XP/分钟', () => {
  assert.equal(xp(rule('game.play_minutes').microPerUnit), 1);
  assert.equal(xp(rule('launcher.online_minutes').microPerUnit), 0.5);
  assert.equal(rule('game.play_minutes').accrue, 'game_minutes_total');
  assert.equal(rule('launcher.online_minutes').accrue, 'launcher_minutes_total');
  assert.equal(xp(rule('game.play_minutes').dailyMicroCap), 480);
  assert.equal(xp(rule('launcher.online_minutes').dailyMicroCap), 180);
});

test('normalizeUnits 向下取整、夹到非负与单次上限', () => {
  const r = rule('game.play_minutes');
  assert.equal(normalizeUnits(r, 90), 90);
  assert.equal(normalizeUnits(r, 90.9), 90, '不足 1 分钟不计');
  assert.equal(normalizeUnits(r, -500), 0, '负数时长夹到 0');
  assert.equal(normalizeUnits(r, r.unitCap + 100), r.unitCap, '单次上报不超过 unitCap');
  assert.equal(normalizeUnits(r, '不是数字'), 0);
  assert.equal(normalizeUnits(r, undefined), 0);
  // 定额事件忽略客户端计量,防止启动器自行声明时长刷分
  assert.equal(normalizeUnits(rule('daily.login'), 99999), 0);
  assert.equal(normalizeUnits(rule('game.first_launch'), 99999), 0);
});

test('computeXpGain 对定额与时长来源正确结算', () => {
  assert.equal(computeXpGain({ rule: rule('daily.login'), units: 0, bonus: 1 }), 50 * MICRO);
  assert.equal(computeXpGain({ rule: rule('game.play_minutes'), units: 30, bonus: 1 }), 30 * MICRO);
  assert.equal(computeXpGain({ rule: rule('launcher.online_minutes'), units: 30, bonus: 1 }), 15 * MICRO);
  assert.equal(computeXpGain({ rule: rule('game.play_minutes'), units: 0, bonus: 1 }), 0);
});

test('铭牌加成按倍率放大,小数余量以毫 XP 保留', () => {
  // 0.5 XP/分钟 × 1.75(Ultimate) = 0.875 XP/分钟 → 875 毫 XP,不丢精度
  assert.equal(computeXpGain({ rule: rule('launcher.online_minutes'), units: 1, bonus: 1.75 }), 875);
  assert.equal(computeXpGain({ rule: rule('launcher.online_minutes'), units: 8, bonus: 1.75 }), 7000);
  assert.equal(computeXpGain({ rule: rule('game.play_minutes'), units: 10, bonus: 2 }), 20 * MICRO);
  assert.equal(computeXpGain({ rule: rule('daily.login'), units: 0, bonus: 1.1 }), 55 * MICRO);
  // 加成 < 1 或畸形时退化为 1,绝不减少经验
  assert.equal(computeXpGain({ rule: rule('daily.login'), units: 0, bonus: 0.5 }), 50 * MICRO);
  assert.equal(computeXpGain({ rule: rule('daily.login'), units: 0, bonus: Number.NaN }), 50 * MICRO);
});

test('单来源日上限:游戏 480、在线 180', () => {
  const game = rule('game.play_minutes');
  assert.equal(computeXpGain({ rule: game, units: 600, bonus: 1, sourceRoomMicro: 480 * MICRO }), 480 * MICRO);
  assert.equal(computeXpGain({ rule: game, units: 600, bonus: 1, sourceRoomMicro: 100 * MICRO }), 100 * MICRO);
  assert.equal(computeXpGain({ rule: game, units: 600, bonus: 1, sourceRoomMicro: 0 }), 0, '额度用尽不再入账');
  const online = rule('launcher.online_minutes');
  assert.equal(computeXpGain({ rule: online, units: 1440, bonus: 1, sourceRoomMicro: 180 * MICRO }), 180 * MICRO);
});

test('上限在加成之后套用:加成不会突破日上限', () => {
  const game = rule('game.play_minutes');
  // 480 分钟 × 1 XP × 2.0(Lv∞) = 960 XP,但单来源日上限只有 480
  assert.equal(computeXpGain({ rule: game, units: 480, bonus: 2, sourceRoomMicro: 480 * MICRO }), 480 * MICRO);
  // 全局日上限同样生效
  assert.equal(computeXpGain({ rule: game, units: 480, bonus: 2, sourceRoomMicro: 480 * MICRO, dayRoomMicro: 300 * MICRO }), 300 * MICRO);
});

test('首次启动豁免日上限,其余来源受 700 XP 全局上限约束', () => {
  assert.ok(rule('game.first_launch').capExempt);
  assert.equal(computeXpGain({ rule: rule('game.first_launch'), units: 0, bonus: 1, dayRoomMicro: 0 }), 100 * MICRO);
  assert.equal(computeXpGain({ rule: rule('daily.login'), units: 0, bonus: 1, dayRoomMicro: 0 }), 0);
  assert.equal(computeXpGain({ rule: rule('daily.login'), units: 0, bonus: 1, dayRoomMicro: 20 * MICRO }), 20 * MICRO);
  assert.equal(xp(XP_DAILY_CAP), 700);
  // 全局上限小于各来源上限之和,是最后一道兜底
  const sumSources = xp(rule('daily.login').micro) + xp(rule('daily.launch').micro)
    + xp(rule('game.play_minutes').dailyMicroCap) + xp(rule('launcher.online_minutes').dailyMicroCap);
  assert.ok(xp(XP_DAILY_CAP) < sumSources, `全局上限 700 应小于各来源之和 ${sumSources}`);
});

test('连续启动天数:首日为 1、连续 +1、断签归 1', () => {
  assert.equal(nextLaunchStreak(null, '2026-09-30', 0), 1);
  assert.equal(nextLaunchStreak('2026-09-29', '2026-09-30', 1), 2);
  assert.equal(nextLaunchStreak('2026-09-29', '2026-09-30', 41), 42);
  assert.equal(nextLaunchStreak('2026-09-28', '2026-09-30', 42), 1, '断签一天即重来');
  assert.equal(nextLaunchStreak('2026-09-01', '2026-09-30', 42), 1);
});

test('连续启动天数:同日重复与旧日期补报都不破坏连击', () => {
  assert.equal(nextLaunchStreak('2026-09-30', '2026-09-30', 7), 7, '同日重复上报不增长');
  assert.equal(nextLaunchStreak('2026-09-30', '2026-09-29', 7), 7, '补报昨天不清零');
  assert.equal(nextLaunchStreak('2026-09-30', '2026-09-01', 7), 7);
});

test('连续启动天数跨月与跨年边界正确', () => {
  assert.equal(nextLaunchStreak('2026-01-31', '2026-02-01', 9), 10);
  assert.equal(nextLaunchStreak('2026-02-28', '2026-03-01', 9), 10, '2026 非闰年');
  assert.equal(nextLaunchStreak('2024-02-28', '2024-02-29', 9), 10, '闰年 2 月 29 日');
  assert.equal(nextLaunchStreak('2025-12-31', '2026-01-01', 99), 100);
  assert.equal(nextLaunchStreak('2026-03-01', '2026-02-28', 9), 9, '反向补报不增长');
});

test('nextLaunchStreak 对畸形连击值安全', () => {
  assert.equal(nextLaunchStreak('2026-09-29', '2026-09-30', undefined), 1);
  assert.equal(nextLaunchStreak('2026-09-29', '2026-09-30', null), 1);
  assert.equal(nextLaunchStreak('2026-09-30', '2026-09-30', undefined), 0);
});

test('等级判定:未启动为 Lv0,启动后至少 Lv1,阈值逐级递进', () => {
  assert.equal(computeLevel(0, 0), 0, '未启动过游戏恒为 Lv0');
  assert.equal(computeLevel(999999, 0), 0, '经验再多也不能跳过启动门槛');
  assert.equal(computeLevel(0, 1), 1);
  assert.equal(computeLevel(1999, 1), 1);
  assert.equal(computeLevel(2000, 1), 2);
  assert.equal(computeLevel(100000, 1), 7);
  assert.equal(computeLevel(10 ** 9, 1), 7, 'Lv7 封顶');
  const values = Object.values(LEVEL_THRESHOLDS);
  assert.deepEqual(values, [...values].sort((a, b) => a - b), '阈值必须递增');
});

test('经验来源目录与 XP_RULES 一致(前端展示不会与实现漂移)', () => {
  const catalog = xpSourceCatalog();
  assert.deepEqual(catalog.map(s => s.type).sort(), XP_EVENT_TYPES.slice().sort());
  const byType = Object.fromEntries(catalog.map(s => [s.type, s]));
  assert.equal(byType['daily.login'].mode, 'daily');
  assert.equal(byType['daily.login'].xp, 50);
  assert.equal(byType['game.first_launch'].mode, 'once');
  assert.equal(byType['game.play_minutes'].mode, 'duration');
  assert.equal(byType['game.play_minutes'].xpPerMinute, 1);
  assert.equal(byType['game.play_minutes'].dailyCap, 480);
  assert.equal(byType['launcher.online_minutes'].xpPerMinute, 0.5);
  assert.equal(byType['launcher.online_minutes'].dailyCap, 180);
  assert.equal(byType['game.first_launch'].countsTowardDailyCap, false);
  assert.equal(byType['daily.launch'].advancesLaunchStreak, true);
  // 除每日登录可由本站写入外,其余全部由启动器上报
  assert.equal(byType['daily.login'].reporter, 'launcher-or-web');
  for (const type of ['daily.launch', 'game.first_launch', 'game.play_minutes', 'launcher.online_minutes']) {
    assert.equal(byType[type].reporter, 'launcher', type);
  }
  // 每种来源都有中文标签与整数化的 XP 数值
  for (const source of catalog) {
    assert.ok(source.label && source.label.length > 0, source.type);
    assert.ok(Number.isInteger(source.dailyCap === null ? 0 : source.dailyCap), source.type);
  }
});
