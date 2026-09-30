import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  NAMEPLATES, PLATE_FLAGS, TIER_RANK, INFINITY_MC_MINUTES, LV_MC_STREAK_DAYS,
  BILIBILI_MIN_LEVEL, BILIBILI_MIN_FOLLOWERS, DONATION_MIN_AMOUNT,
  buildContext, evaluateNameplates, activeBonus, nameplateCatalog, plateById, PLATE_BONUS_STACKING
} from '../src/nameplates.mjs';

const ids = () => NAMEPLATES.map(p => p.id);
const ownedIds = plates => plates.filter(p => p.owned).map(p => p.id);
const ctx = (overrides = {}, flags = {}) => buildContext({ level: 0, staff: false, flags, ...overrides });

test('铭牌目录 id 唯一且覆盖三种类别', () => {
  const list = ids();
  assert.equal(new Set(list).size, list.length, '铭牌 id 必须唯一');
  const kinds = new Set(NAMEPLATES.map(p => p.kind));
  assert.deepEqual([...kinds].sort(), ['badge', 'level', 'subscription']);
  // 4 个订阅档位各一枚铭牌
  assert.equal(NAMEPLATES.filter(p => p.kind === 'subscription').length, Object.keys(TIER_RANK).length);
});

test('replacesLevel 划分正确:仅 Lv∞ / Lv-1 / LvMC 可代替等级', () => {
  const replaceable = NAMEPLATES.filter(p => p.replacesLevel).map(p => p.id).sort();
  assert.deepEqual(replaceable, ['lv_infinity', 'lv_mc', 'lv_minus_one']);
  // 其余铭牌一律与等级并列展示
  for (const plate of NAMEPLATES.filter(p => !p.replacesLevel)) {
    assert.ok(['sub_lite', 'sub_standard', 'sub_advanced', 'sub_ultimate', 'from_bilibili', 'yellow_badge', 'i_like_you'].includes(plate.id), plate.id);
  }
});

test('新账户不拥有任何铭牌', () => {
  const plates = evaluateNameplates(ctx());
  assert.deepEqual(ownedIds(plates), []);
  assert.equal(activeBonus(plates), 1);
});

test('订阅铭牌按档位累积授予:Ultimate 同时拥有四枚', () => {
  for (const [tier, expected] of [['Lite', ['sub_lite']], ['Standard', ['sub_lite', 'sub_standard']], ['Advanced', ['sub_lite', 'sub_standard', 'sub_advanced']], ['Ultimate', ['sub_lite', 'sub_standard', 'sub_advanced', 'sub_ultimate']]]) {
    const plates = evaluateNameplates(ctx({}, { [PLATE_FLAGS.cloudTier]: tier }));
    assert.deepEqual(ownedIds(plates), expected, tier);
  }
});

test('非法或未知的订阅档位不授予铭牌', () => {
  for (const bad of ['ultimate', 'ULTIMATE', 'Pro', '', 'null', undefined]) {
    const plates = evaluateNameplates(ctx({}, { [PLATE_FLAGS.cloudTier]: bad }));
    assert.deepEqual(ownedIds(plates), [], String(bad));
  }
});

test('各订阅档位有各自且递增的经验加成', () => {
  const bonuses = NAMEPLATES.filter(p => p.kind === 'subscription').map(p => p.xpBonus);
  assert.equal(bonuses.length, 4);
  for (let i = 1; i < bonuses.length; i++) assert.ok(bonuses[i] > bonuses[i - 1], '加成应随档位递增');
  for (const b of bonuses) assert.ok(b > 1, '订阅铭牌必须提供正加成');
});

test('Lv∞ 需要三条件全部达成:Lv7 + ∞答题 + MC 1000 小时', () => {
  const quiz = { [PLATE_FLAGS.infinityQuiz]: '2026-09-01T00:00:00Z' };
  const enough = { level: 7, gameMinutes: INFINITY_MC_MINUTES };
  // 三项齐全 → 达成
  assert.ok(evaluateNameplates(ctx(enough, quiz)).find(p => p.id === 'lv_infinity').owned);
  // 缺等级
  assert.ok(!evaluateNameplates(ctx({ ...enough, level: 6 }, quiz)).find(p => p.id === 'lv_infinity').owned);
  // 缺答题
  assert.ok(!evaluateNameplates(ctx(enough, {})).find(p => p.id === 'lv_infinity').owned);
  // 时长差 1 分钟
  assert.ok(!evaluateNameplates(ctx({ ...enough, gameMinutes: INFINITY_MC_MINUTES - 1 }, quiz)).find(p => p.id === 'lv_infinity').owned);
  // 未启动过游戏(launched=0 → level 0)
  assert.ok(!evaluateNameplates(ctx({ gameMinutes: INFINITY_MC_MINUTES }, quiz)).find(p => p.id === 'lv_infinity').owned);
});

test('Lv∞ 返回三项分条件进度供前端展示', () => {
  const plate = evaluateNameplates(ctx({ level: 7, gameMinutes: 100 })).find(p => p.id === 'lv_infinity');
  assert.equal(plate.parts.length, 3);
  assert.deepEqual(plate.parts.map(p => p.done), [true, false, false]);
  assert.equal(plate.parts[2].need, INFINITY_MC_MINUTES);
});

test('Lv-1 与网站管理员身份绑定,身份撤销即失效', () => {
  assert.ok(evaluateNameplates(ctx({ staff: true })).find(p => p.id === 'lv_minus_one').owned);
  assert.ok(!evaluateNameplates(ctx({ staff: false })).find(p => p.id === 'lv_minus_one').owned);
});

test(`LvMC 以历史最长连击 ${LV_MC_STREAK_DAYS} 天为准,断签不撤销`, () => {
  const best = plate => plate.find(p => p.id === 'lv_mc');
  assert.ok(!best(evaluateNameplates(ctx({ streakBest: LV_MC_STREAK_DAYS - 1 }))).owned);
  assert.ok(best(evaluateNameplates(ctx({ streakBest: LV_MC_STREAK_DAYS }))).owned);
  // 当前连击已断(streak=0),但历史最长达标 → 铭牌保留
  assert.ok(best(evaluateNameplates(ctx({ streak: 0, streakBest: LV_MC_STREAK_DAYS }))).owned);
});

test('B 站铭牌阈值:Lv6 达标、粉丝需严格大于 100 万', () => {
  const plate = (flags, id) => evaluateNameplates(ctx({}, flags)).find(p => p.id === id);
  assert.ok(plate({ [PLATE_FLAGS.bilibiliLevel]: '6' }, 'from_bilibili').owned);
  assert.ok(!plate({ [PLATE_FLAGS.bilibiliLevel]: '5' }, 'from_bilibili').owned);
  assert.ok(!plate({ [PLATE_FLAGS.bilibiliLevel]: '不是数字' }, 'from_bilibili').owned);
  assert.ok(plate({ [PLATE_FLAGS.bilibiliFollowers]: String(BILIBILI_MIN_FOLLOWERS + 1) }, 'yellow_badge').owned);
  assert.ok(!plate({ [PLATE_FLAGS.bilibiliFollowers]: String(BILIBILI_MIN_FOLLOWERS) }, 'yellow_badge').owned, '恰好 100 万不算「大于」');
  assert.ok(!plate({}, 'yellow_badge').owned);
  assert.equal(BILIBILI_MIN_LEVEL, 6);
});

test('我喜欢你:无偿捐献 1000+ 达成,999 不达成', () => {
  const plate = flags => evaluateNameplates(ctx({}, flags)).find(p => p.id === 'i_like_you');
  assert.ok(plate({ [PLATE_FLAGS.donation]: '1000' }).owned);
  assert.ok(plate({ [PLATE_FLAGS.donation]: '2500.50' }).owned);
  assert.ok(!plate({ [PLATE_FLAGS.donation]: '999.99' }).owned);
  assert.ok(!plate({}).owned);
  assert.equal(DONATION_MIN_AMOUNT, 1000);
});

test('经验加成不叠加:取已拥有铭牌中的最高倍率', () => {
  assert.equal(PLATE_BONUS_STACKING, false);
  const flags = {
    [PLATE_FLAGS.cloudTier]: 'Lite',
    [PLATE_FLAGS.bilibiliLevel]: '6',
    [PLATE_FLAGS.donation]: '5000'
  };
  const plates = evaluateNameplates(ctx({ staff: true }, flags));
  // 拥有 sub_lite(1.10) + from_bilibili(1.05) + i_like_you(1.30) + lv_minus_one(1.50)
  assert.deepEqual(ownedIds(plates).sort(), ['from_bilibili', 'i_like_you', 'lv_minus_one', 'sub_lite']);
  assert.equal(activeBonus(plates), 1.50);
});

test('同时拥有 Lv∞ 与 Ultimate 时,加成取 Lv∞ 的 2.0 而非相乘', () => {
  const flags = {
    [PLATE_FLAGS.cloudTier]: 'Ultimate',
    [PLATE_FLAGS.infinityQuiz]: 'passed'
  };
  const plates = evaluateNameplates(ctx({ level: 7, gameMinutes: INFINITY_MC_MINUTES }, flags));
  assert.ok(plates.find(p => p.id === 'lv_infinity').owned);
  assert.ok(plates.find(p => p.id === 'sub_ultimate').owned);
  assert.equal(activeBonus(plates), 2.0);
  assert.ok(activeBonus(plates) < 1.75 * 2.0, '不应相乘叠加');
});

test('每枚铭牌都带加成,且不超过 Lv∞ 的上限', () => {
  const max = Math.max(...NAMEPLATES.map(p => p.xpBonus));
  assert.equal(max, plateById('lv_infinity').xpBonus);
  for (const plate of NAMEPLATES) {
    assert.ok(plate.xpBonus >= 1, `${plate.id} 加成不应低于 1`);
    assert.ok(plate.xpBonus <= 2, `${plate.id} 加成超出上限`);
    assert.ok(typeof plate.label === 'string' && plate.label.length > 0);
    assert.ok(typeof plate.requirement === 'string' && plate.requirement.length > 0);
  }
});

test('plateById 对未知 id 返回 null', () => {
  assert.equal(plateById('sub_lite').label, 'Cloud+ Lite');
  assert.equal(plateById('不存在'), null);
  assert.equal(plateById(undefined), null);
  assert.equal(plateById(null), null);
});

test('公开目录只暴露规则,不含运行时状态', () => {
  const catalog = nameplateCatalog();
  assert.equal(catalog.length, NAMEPLATES.length);
  for (const entry of catalog) {
    assert.ok(!('owned' in entry), '公开目录不应泄漏 owned');
    assert.ok(!('progress' in entry) && !('parts' in entry));
    assert.ok('xpBonus' in entry && 'replacesLevel' in entry && 'requirement' in entry);
  }
});

test('进度对象只在存在 need 时出现,且不超过 need', () => {
  const plates = evaluateNameplates(ctx({ streakBest: 40, gameMinutes: 12000 }));
  const mc = plates.find(p => p.id === 'lv_mc');
  assert.deepEqual(mc.progress, { have: 40, need: LV_MC_STREAK_DAYS, unit: '天' });
  // 达标后 have 被夹到 need,前端进度条不会溢出
  const done = evaluateNameplates(ctx({ streakBest: 500 })).find(p => p.id === 'lv_mc');
  assert.equal(done.progress.have, LV_MC_STREAK_DAYS);
  assert.ok(done.owned);
});

test('buildContext 对缺失或畸形输入有安全默认值', () => {
  const context = buildContext({});
  assert.deepEqual(context, {
    level: 0, xp: 0, launched: false, staff: false, streak: 0, streakBest: 0,
    gameMinutes: 0, launcherMinutes: 0, tier: null, tierRank: 0, flags: {}
  });
  const weird = buildContext({ level: 'NaN', streak: null, gameMinutes: '12', flags: null });
  assert.equal(weird.level, 0);
  assert.equal(weird.streak, 0);
  assert.equal(weird.gameMinutes, 12);
  assert.deepEqual(weird.flags, {});
});
