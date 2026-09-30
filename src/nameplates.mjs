// 铭牌墙目录与派生规则。
//
// 设计原则:铭牌**不单独存储授予记录**,全部由真实信号实时派生 ——
//   等级 / 连续启动天数 / 累计时长 / user_flags / users.staff
// 这样铭牌永远不会和账户实际状态漂移,也不需要一个"补发/回收"的后台流程。
// 需要人工核验的铭牌(B 站等级、B 站粉丝、无偿捐献)由运营侧通过
// POST /internal/v1/flags 写入对应标记(附证据),派生逻辑只读这些标记。
//
// 唯一的持久化状态是 user_levels.equipped_plate(当前佩戴的铭牌)。

export const TIERS = ['Lite', 'Standard', 'Advanced', 'Ultimate'];
export const TIER_RANK = { Lite: 1, Standard: 2, Advanced: 3, Ultimate: 4 };

// ---------- 达成阈值(单一事实来源;前端只展示,不自行判断) ----------
export const MAX_LEVEL = 7;
export const INFINITY_MC_MINUTES = 1000 * 60;   // Lv∞:Minecraft 累计时长 > 1000 小时
export const LV_MC_STREAK_DAYS = 100;           // LvMC:连续 100 天启动 Minecraft
export const BILIBILI_MIN_LEVEL = 6;            // b站来的:B 站等级达到 Lv6
export const BILIBILI_MIN_FOLLOWERS = 1000000;  // 小黄标:B 站粉丝大于 100 万
export const DONATION_MIN_AMOUNT = 1000;        // 我喜欢你:为 Nexa 无偿捐献 1000+

// 派生所依赖的 user_flags 名称。/internal/v1/flags 的白名单与此保持一致。
export const PLATE_FLAGS = {
  cloudTier: 'cloud_plus_tier',       // value: 'Lite' | 'Standard' | 'Advanced' | 'Ultimate'
  infinityQuiz: 'infinity_quiz',      // value: 通过时间 / 成绩,任意非空即视为通过
  bilibiliLevel: 'bilibili_level',    // value: 数字字符串,如 '6'
  bilibiliFollowers: 'bilibili_followers', // value: 数字字符串,如 '1200000'
  donation: 'nexa_donation',          // value: 数字字符串(元),如 '1000'
  popularPlugin: 'popular_plugin'     // 既有标记:下载量 > 1k 的插件(受信任开发者资格)
};

const num = value => { const n = Number.parseFloat(String(value ?? '')); return Number.isFinite(n) ? n : 0; };
const normalizeTier = value => TIERS.includes(String(value ?? '')) ? String(value) : null;

// check(ctx) 返回:
//   owned  是否已达成
//   have/need/unit  单条件进度(可选,供前端画进度条)
//   parts  多条件清单(可选),每项 { label, done, have?, need?, unit? }
export const NAMEPLATES = [
  // ========== 订阅铭牌:每个 Cloud+ 档位一枚,各自带经验加成 ==========
  // 由计费侧在订阅生效后写 flag cloud_plus_tier;退订后改写/清除,铭牌与加成随之失效。
  {
    id: 'sub_lite', kind: 'subscription', label: 'Cloud+ Lite', tier: 'Lite',
    xpBonus: 1.10, replacesLevel: false,
    requirement: '订阅 Cloud+ Lite 或更高档位',
    detail: '入门档铭牌。订阅期间所有经验来源 +10%。',
    check: ctx => ({ owned: ctx.tierRank >= TIER_RANK.Lite, have: Math.min(ctx.tierRank, TIER_RANK.Lite), need: TIER_RANK.Lite, unit: '档' })
  },
  {
    id: 'sub_standard', kind: 'subscription', label: 'Cloud+ Standard', tier: 'Standard',
    xpBonus: 1.25, replacesLevel: false,
    requirement: '订阅 Cloud+ Standard 或更高档位',
    detail: '均衡档铭牌。订阅期间所有经验来源 +25%。',
    check: ctx => ({ owned: ctx.tierRank >= TIER_RANK.Standard, have: Math.min(ctx.tierRank, TIER_RANK.Standard), need: TIER_RANK.Standard, unit: '档' })
  },
  {
    id: 'sub_advanced', kind: 'subscription', label: 'Cloud+ Advanced', tier: 'Advanced',
    xpBonus: 1.45, replacesLevel: false,
    requirement: '订阅 Cloud+ Advanced 或更高档位',
    detail: '进阶档铭牌。订阅期间所有经验来源 +45%。',
    check: ctx => ({ owned: ctx.tierRank >= TIER_RANK.Advanced, have: Math.min(ctx.tierRank, TIER_RANK.Advanced), need: TIER_RANK.Advanced, unit: '档' })
  },
  {
    id: 'sub_ultimate', kind: 'subscription', label: 'Cloud+ Ultimate', tier: 'Ultimate',
    xpBonus: 1.75, replacesLevel: false,
    requirement: '订阅 Cloud+ Ultimate 档位',
    detail: '全量档铭牌。订阅期间所有经验来源 +75%。',
    check: ctx => ({ owned: ctx.tierRank >= TIER_RANK.Ultimate, have: Math.min(ctx.tierRank, TIER_RANK.Ultimate), need: TIER_RANK.Ultimate, unit: '档' })
  },

  // ========== 可代替等级的铭牌:佩戴后可只显示铭牌、隐藏 Lv 数字 ==========
  {
    id: 'lv_infinity', kind: 'level', label: 'Lv∞',
    xpBonus: 2.00, replacesLevel: true,
    requirement: `达到 Lv${MAX_LEVEL} + 通过 ∞ 答题 + Minecraft 累计时长超过 1000 小时`,
    detail: '三重门槛的封顶铭牌。三项全部达成后永久保留,不会因后续状态变化而撤销。',
    check: ctx => {
      const parts = [
        { label: `达到 Lv${MAX_LEVEL}`, done: ctx.level >= MAX_LEVEL, have: ctx.level, need: MAX_LEVEL, unit: '级' },
        { label: '通过 ∞ 答题', done: Boolean(ctx.flags[PLATE_FLAGS.infinityQuiz]) },
        { label: 'MC 时长 1000 小时', done: ctx.gameMinutes > INFINITY_MC_MINUTES, have: ctx.gameMinutes, need: INFINITY_MC_MINUTES, unit: '分钟' }
      ];
      return { owned: parts.every(p => p.done), parts };
    }
  },
  {
    id: 'lv_minus_one', kind: 'level', label: 'Lv-1',
    xpBonus: 1.50, replacesLevel: true,
    requirement: '成为网站管理员',
    detail: '站务铭牌。与管理员身份绑定:身份被撤销时铭牌与加成一并收回。',
    check: ctx => ({ owned: Boolean(ctx.staff), have: ctx.staff ? 1 : 0, need: 1, unit: '项' })
  },
  {
    id: 'lv_mc', kind: 'level', label: 'LvMC',
    xpBonus: 1.60, replacesLevel: true,
    requirement: `连续 ${LV_MC_STREAK_DAYS} 天启动 Minecraft`,
    detail: '恒心铭牌。以历史最长连击为准,断签后已获得的铭牌不会消失。',
    check: ctx => ({ owned: ctx.streakBest >= LV_MC_STREAK_DAYS, have: Math.min(ctx.streakBest, LV_MC_STREAK_DAYS), need: LV_MC_STREAK_DAYS, unit: '天' })
  },

  // ========== 不可代替等级的荣誉铭牌:与等级并列展示 ==========
  {
    id: 'from_bilibili', kind: 'badge', label: 'b站来的',
    xpBonus: 1.05, replacesLevel: false,
    requirement: `在 Bilibili 达到 Lv${BILIBILI_MIN_LEVEL}`,
    detail: '需人工核验:提交 B 站主页链接后由运营写入 bilibili_level 标记。',
    check: ctx => {
      const level = num(ctx.flags[PLATE_FLAGS.bilibiliLevel]);
      return { owned: level >= BILIBILI_MIN_LEVEL, have: Math.min(level, BILIBILI_MIN_LEVEL), need: BILIBILI_MIN_LEVEL, unit: '级' };
    }
  },
  {
    id: 'yellow_badge', kind: 'badge', label: '小黄标',
    xpBonus: 1.15, replacesLevel: false,
    requirement: `Bilibili 粉丝大于 ${(BILIBILI_MIN_FOLLOWERS / 10000).toFixed(0)} 万`,
    detail: '需人工核验:由运营写入 bilibili_followers 标记(记录核验时的粉丝数)。',
    check: ctx => {
      const followers = num(ctx.flags[PLATE_FLAGS.bilibiliFollowers]);
      return { owned: followers > BILIBILI_MIN_FOLLOWERS, have: Math.min(followers, BILIBILI_MIN_FOLLOWERS), need: BILIBILI_MIN_FOLLOWERS, unit: '粉丝' };
    }
  },
  {
    id: 'i_like_you', kind: 'badge', label: '我喜欢你',
    xpBonus: 1.30, replacesLevel: false,
    requirement: `为 Nexa 无偿捐献 ${DONATION_MIN_AMOUNT}+`,
    detail: '无偿捐献(非购买订阅或商品)。需人工核验:由运营写入 nexa_donation 标记。',
    check: ctx => {
      const amount = num(ctx.flags[PLATE_FLAGS.donation]);
      return { owned: amount >= DONATION_MIN_AMOUNT, have: Math.min(amount, DONATION_MIN_AMOUNT), need: DONATION_MIN_AMOUNT, unit: '元' };
    }
  }
];

export const PLATE_IDS = NAMEPLATES.map(p => p.id);
const BY_ID = new Map(NAMEPLATES.map(p => [p.id, p]));
export const plateById = id => BY_ID.get(String(id ?? '')) ?? null;

// 铭牌加成不叠加:取已拥有铭牌中的最高倍率。
// 叠加会让高阶订阅 + 全部荣誉铭牌的用户达到 5 倍以上,经验曲线会失控;
// 取最高既保留了"铭牌越强加成越高"的激励,也让上限可预测(当前最高 Lv∞ ×2.0)。
export const PLATE_BONUS_STACKING = false;
export const NO_BONUS = 1;

export function activeBonus(plates) {
  const owned = plates.filter(p => p.owned && p.xpBonus > 1);
  if (!owned.length) return NO_BONUS;
  return PLATE_BONUS_STACKING
    ? owned.reduce((acc, p) => acc * p.xpBonus, 1)
    : owned.reduce((max, p) => Math.max(max, p.xpBonus), NO_BONUS);
}

// 派生上下文:由 index.mjs 从 user_levels / user_flags / users 组装。
// 对缺失/畸形输入一律退化为安全默认值 —— flags 为 null 时也不能抛错,
// 否则铭牌派生失败会连带拖垮 /auth/v1/account/level 整个响应。
export function buildContext({ level, staff, flags, streak = 0, streakBest = 0, gameMinutes = 0, launcherMinutes = 0, xp = 0, launched = false } = {}) {
  const safeFlags = flags && typeof flags === 'object' ? flags : {};
  const tier = normalizeTier(safeFlags[PLATE_FLAGS.cloudTier]);
  return {
    level: Number(level) || 0,
    xp: Number(xp) || 0,
    launched: Boolean(launched),
    staff: Boolean(staff),
    streak: Number(streak) || 0,
    streakBest: Number(streakBest) || 0,
    gameMinutes: Number(gameMinutes) || 0,
    launcherMinutes: Number(launcherMinutes) || 0,
    tier,
    tierRank: tier ? TIER_RANK[tier] : 0,
    flags: { ...safeFlags }
  };
}

// 返回全部铭牌的评估结果(含未达成的进度),供 /auth/v1/nameplates 与账户页共用。
export function evaluateNameplates(ctx) {
  return NAMEPLATES.map(plate => {
    const result = plate.check(ctx) ?? {};
    return {
      id: plate.id,
      kind: plate.kind,
      label: plate.label,
      ...(plate.tier ? { tier: plate.tier } : {}),
      xpBonus: plate.xpBonus,
      replacesLevel: plate.replacesLevel,
      requirement: plate.requirement,
      detail: plate.detail,
      owned: Boolean(result.owned),
      ...(Array.isArray(result.parts) ? { parts: result.parts } : {}),
      ...(result.need ? { progress: { have: Number(result.have) || 0, need: Number(result.need), unit: result.unit ?? null } } : {})
    };
  });
}

// 对外目录(公开铭牌墙使用):剥掉运行时状态,只留规则。
export function nameplateCatalog() {
  return NAMEPLATES.map(plate => ({
    id: plate.id, kind: plate.kind, label: plate.label,
    ...(plate.tier ? { tier: plate.tier } : {}),
    xpBonus: plate.xpBonus, replacesLevel: plate.replacesLevel,
    requirement: plate.requirement, detail: plate.detail
  }));
}
