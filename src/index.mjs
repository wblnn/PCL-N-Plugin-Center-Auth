import { randomBytes } from 'node:crypto';
import { digest, hashPassword, verifyPassword } from './password.mjs';
import { createMailer } from './mailer.mjs';
import { validateHandle, validateDisplayName, normalizeHandle, isReservedHandle, HANDLE_COOLDOWN_DAYS } from './handles.mjs';
import { randomSecret, otpauthUrl, verifyTotp, encryptSecret, decryptSecret } from './totp.mjs';
import { generateRecoveryCodes, hashRecoveryCode } from './recovery.mjs';
import { verifyRegistration, verifyAssertion, webauthnUserId } from './webauthn.mjs';
import { MAX_LEVEL, PLATE_BONUS_STACKING, PLATE_FLAGS, activeBonus, buildContext, evaluateNameplates, nameplateCatalog, plateById } from './nameplates.mjs';
class Failure extends Error { constructor(status, detail) { super(detail); this.status = status; } }
const fail = (status, detail) => { throw new Failure(status, detail); };
const cookieName = scope => scope === 'operations' ? 'nexa_staff' : 'nexa_console';
const cookieValue = (request, name) => (request.headers.get('cookie') || '').split(';').map(s => s.trim()).find(s => s.startsWith(name + '='))?.slice(name.length + 1) || '';
const token = (request, scope) => cookieValue(request, cookieName(scope));
const bearer = request => (request.headers.get('authorization') || '').match(/^Bearer ([^\s]+)$/)?.[1] || '';
const credential = (request, scope) => bearer(request) || token(request, scope);
const scopeOf = scope => ['console', 'operations'].includes(scope) ? scope : fail(400, '无效会话范围');
const cors = env => ({ 'access-control-allow-origin': env.WEB_ORIGIN, 'access-control-allow-credentials': 'true' });
const json = (env, data, status = 200, headers = {}) => Response.json(data, { status, headers: { 'cache-control': 'no-store', ...cors(env), ...headers } });
const oauthStateCookie = 'nexa_oauth_state';
const oauthProviders = {
  github: { authorize: 'https://github.com/login/oauth/authorize', token: 'https://github.com/login/oauth/access_token', profile: 'https://api.github.com/user', callback: 'https://auth.pcln.top/auth/v1/oauth/github/callback', scope: 'read:user user:email' },
  microsoft: { authorize: 'https://login.microsoftonline.com/common/oauth2/v2.0/authorize', token: 'https://login.microsoftonline.com/common/oauth2/v2.0/token', profile: 'https://graph.microsoft.com/oidc/userinfo', callback: 'https://auth.pcln.top/auth/v1/oauth/microsoft/callback', scope: 'openid profile email User.Read' },
  google: { authorize: 'https://accounts.google.com/o/oauth2/v2/auth', token: 'https://oauth2.googleapis.com/token', profile: 'https://openidconnect.googleapis.com/v1/userinfo', callback: 'https://auth.pcln.top/auth/v1/oauth/google/callback', scope: 'openid profile email' }
};
const providerPrefix = { github: 'GITHUB', microsoft: 'MICROSOFT', google: 'GOOGLE' };
const configFor = (provider, env) => {
  const config = { ...oauthProviders[provider], clientId: env[`${providerPrefix[provider]}_CLIENT_ID`], clientSecret: env[`${providerPrefix[provider]}_CLIENT_SECRET`] };
  if (!config.clientId || !config.clientSecret) fail(503, '该登录方式尚未配置');
  return config;
};
const b64json = value => JSON.parse(new TextDecoder().decode(Uint8Array.from(atob(value.replaceAll('-', '+').replaceAll('_', '/') + '='.repeat((4 - value.length % 4) % 4)), c => c.charCodeAt(0))));
// Microsoft 绑定专用：用带 XboxLive.signin 的 MSA 令牌走 XBL → XSTS → Minecraft 服务，
// 查询游戏拥有状况与档案（id/name）。只存结果，不存任何 Xbox/MC 令牌。
async function fetchMinecraftStatus(accessToken) {
  const signal = AbortSignal.timeout(12000);
  const postJson = async (url, body) => {
    const res = await fetch(url, { method: 'POST', headers: { 'Content-Type': 'application/json', Accept: 'application/json' }, body: JSON.stringify(body), signal });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(data?.XErr ? `xbl:${data.XErr}` : `http:${res.status}`);
    return data;
  };
  const xbl = await postJson('https://user.auth.microsoftonline.com/authenticate', {
    RelyingParty: 'http://auth.xboxlive.com', TokenType: 'JWT',
    Properties: { AuthMethod: 'RPS', SiteName: 'user.auth.microsoftonline.com', RpsTicket: 'd=' + accessToken }
  });
  const xsts = await postJson('https://xsts.auth.xboxlive.com/xsts/authorize', {
    RelyingParty: 'rp://http://minecraft.net/production', TokenType: 'JWT',
    Properties: { SandboxId: 'RETAIL', UserTokens: [xbl.Token], SiteName: 'user.auth.microsoftonline.com' }
  });
  const uhs = xsts?.DisplayClaims?.xui?.[0]?.uhs ?? xbl?.DisplayClaims?.xui?.[0]?.uhs;
  const mcAuth = { Authorization: `XBL3.0 x=${uhs};${xsts.Token}`, Accept: 'application/json' };
  const entRes = await fetch('https://api.minecraftservices.com/entitlements/mcstore', { headers: mcAuth, signal });
  if (!entRes.ok) throw new Error('http:' + entRes.status);
  const ent = await entRes.json().catch(() => ({}));
  const owned = Array.isArray(ent?.items) && ent.items.some(item => item?.name === 'product_minecraft' || item?.name === 'game_minecraft');
  let profileId = null, profileName = null;
  if (owned) {
    const profRes = await fetch('https://api.minecraftservices.com/minecraft/profile', { headers: mcAuth, signal });
    if (profRes.ok) {
      const prof = await profRes.json().catch(() => ({}));
      if (typeof prof?.id === 'string') { profileId = prof.id; profileName = typeof prof.name === 'string' ? prof.name.slice(0, 32) : null; }
    }
  }
  // accessToken：XSTS 派生的 Minecraft 服务短时令牌，仅供实时下发（如启动器），绝不落库。
  return { owned: owned ? 1 : 0, profileId, profileName, accessToken: xsts.Token };
}
const oauthError = (env, detail) => Response.redirect(`${env.WEB_ORIGIN}/login?oauth_error=${encodeURIComponent(detail)}`, 303);
const auditEvent = (env, actor, action, detail) => env.DB.prepare('INSERT INTO auth_audit(actor,action,created_at,detail) VALUES(?,?,?,?)').bind(actor, action, new Date().toISOString(), detail ?? null);
// 仅在前一条语句（INSERT OR IGNORE）实际写入时记录，用于条款首次接受等幂等事件。
const auditOnChange = (env, actor, action, detail) => env.DB.prepare('INSERT INTO auth_audit(actor,action,created_at,detail) SELECT ?,?,?,? WHERE changes()=1').bind(actor, action, new Date().toISOString(), detail ?? null);
// ---------- 账户身份与 MFA 基础设施 ----------
const RP_ID = env => env.RP_ID || (env.LOCAL_DEV === 'true' ? 'localhost' : 'pcln.top');
const webauthnOrigins = env => [env.WEB_ORIGIN, 'https://auth.pcln.top', ...(env.LOCAL_DEV === 'true' ? ['http://127.0.0.1:5730', 'http://localhost:5730'] : [])].filter(Boolean);
const clientIp = request => request.headers.get('cf-connecting-ip') || 'unknown';
const hasRealPassword = hash => Boolean(hash) && !hash.startsWith('oauth:') && !hash.startsWith('system:');
// ---------- 等级与经验 ----------
// Lv0→1:启动一次游戏(launched 标记);Lv2~7:累计经验达到阈值。
export const LEVEL_THRESHOLDS = { 2: 2000, 3: 5000, 4: 10000, 5: 20000, 6: 50000, 7: 100000 };
// 经验以「毫 XP」(micro = XP × 1000) 结算:0.5 XP/分钟这类小数速率逐次上报时不会丢余量。
export const MICRO = 1000;
// 经验来源全部由启动器上报事件(每日登录亦可由本站登录流程写入),**数值由 Worker 权威决定**:
// 客户端只能声明「发生了什么、持续了多少分钟」,不能自行声明「这值多少经验」。
//   daily.login             每日登录        +50 XP / UTC 日
//   daily.launch            每日启动        +30 XP / UTC 日,并推进连续启动天数
//   game.play_minutes       游戏时长        1 XP / 分钟,单日 ≤ 480 XP(8 小时)
//   launcher.online_minutes Nexa 在线时长   0.5 XP / 分钟,单日 ≤ 180 XP(6 小时)
//   game.first_launch       首次启动        +100 XP,一次性,不计入日上限
export const XP_RULES = {
  'daily.login': { micro: 50 * MICRO, perDay: 'last_login_day', label: '每日登录' },
  'daily.launch': { micro: 30 * MICRO, perDay: 'last_launch_day', streak: true, setsLaunched: true, label: '每日启动' },
  'game.first_launch': { micro: 100 * MICRO, once: true, capExempt: true, setsLaunched: true, label: '首次启动' },
  'game.play_minutes': { microPerUnit: 1 * MICRO, unitCap: 720, dailyMicroCap: 480 * MICRO, accrue: 'game_minutes_total', label: '游戏时长' },
  'launcher.online_minutes': { microPerUnit: 0.5 * MICRO, unitCap: 1440, dailyMicroCap: 180 * MICRO, accrue: 'launcher_minutes_total', label: 'Nexa 在线时长' }
};
// 每用户每 UTC 日经验总上限(毫 XP)。理论满档为 50+30+480+180 = 740,全局上限兜底防刷。
export const XP_DAILY_CAP = 700 * MICRO;
export const XP_EVENT_TYPES = Object.keys(XP_RULES);
// 可写入的资格标记白名单:这些标记直接驱动铭牌与开发者资格判定,不接受任意名称。
const FLAG_ALLOWLIST = [...new Set([...Object.values(PLATE_FLAGS), 'popular_plugin'])].sort();
// 经验来源说明(公开目录 / 账户页共用),数值直接取自 XP_RULES,避免文案与实现漂移。
export function xpSourceCatalog() {
  return XP_EVENT_TYPES.map(type => {
    const rule = XP_RULES[type];
    return {
      type,
      label: rule.label,
      reporter: type === 'daily.login' ? 'launcher-or-web' : 'launcher',
      ...(rule.micro !== undefined
        ? { mode: rule.once ? 'once' : 'daily', xp: rule.micro / MICRO, dailyCap: rule.once ? null : rule.micro / MICRO }
        : {
          mode: 'duration', xpPerMinute: rule.microPerUnit / MICRO, unit: 'minute',
          perEventUnitCap: rule.unitCap, dailyCap: rule.dailyMicroCap / MICRO
        }),
      countsTowardDailyCap: !rule.capExempt,
      ...(rule.streak ? { advancesLaunchStreak: true } : {}),
      ...(rule.setsLaunched ? { unlocksLevelOne: true } : {})
    };
  });
}
export function computeLevel(xp, launched) {
  if (!launched) return 0;
  let level = 1;
  for (let l = 2; l <= MAX_LEVEL; l++) { if (xp >= LEVEL_THRESHOLDS[l]) level = l; else break; }
  return level;
}
const utcDay = (iso = new Date().toISOString()) => String(iso).slice(0, 10);
const prevUtcDay = day => new Date(new Date(`${day}T00:00:00Z`).getTime() - 86400000).toISOString().slice(0, 10);
// 连续启动天数判定(纯函数,便于单测)。
//   lastLaunchDay 为空     → 首次启动,连击 = 1
//   lastLaunchDay >= day   → 旧日期补报:既不增长也不清零(避免补报把已有连击打断)
//   lastLaunchDay = day-1  → 连击 + 1
//   其余                   → 断签,重新从 1 开始
export function nextLaunchStreak(lastLaunchDay, day, currentStreak) {
  if (!lastLaunchDay) return 1;
  if (lastLaunchDay >= day) return Number(currentStreak) || 0;
  if (lastLaunchDay === prevUtcDay(day)) return (Number(currentStreak) || 0) + 1;
  return 1;
}
// 时长类事件的计量单位归一:向下取整、非负、单次上报不超过 unitCap。
// 定额事件(每日登录/每日启动/首次启动)不接受客户端计量,恒为 0。
export function normalizeUnits(rule, rawAmount) {
  if (rule.micro !== undefined) return 0;
  return Math.max(0, Math.min(rule.unitCap, Math.floor(Number(rawAmount) || 0)));
}
// 经验结算(纯函数):基础值 → 铭牌加成 → 单来源日上限 → 全局日上限。
// 顺序很重要:**先加成再套上限**,否则加成会被上限悄悄吃掉、且上限统计与实际入账不一致。
// 返回应入账的毫 XP;0 表示本次不入账。
export function computeXpGain({ rule, units, bonus = 1, sourceRoomMicro = Infinity, dayRoomMicro = Infinity }) {
  const baseMicro = rule.micro !== undefined ? rule.micro : Math.round(units * rule.microPerUnit);
  if (baseMicro <= 0) return 0;
  // 加成倍率只允许 ≥ 1:畸形值(NaN / 0 / 负数 / 小于 1)一律退化为无加成,
  // 任何情况下都不会因为铭牌数据异常而扣减用户经验。
  const multiplier = Number.isFinite(bonus) && bonus > 1 ? bonus : 1;
  let gainMicro = Math.round(baseMicro * multiplier);
  if (rule.dailyMicroCap) gainMicro = Math.min(gainMicro, Math.max(0, sourceRoomMicro));
  if (!rule.capExempt) gainMicro = Math.min(gainMicro, Math.max(0, dayRoomMicro));
  return Math.max(0, gainMicro);
}
async function loadLevel(env, userId) {
  const row = await env.DB.prepare(`SELECT xp, xp_micro, launched, first_launch_at, last_login_day, last_launch_day,
    launch_streak, launch_streak_best, game_minutes_total, launcher_minutes_total, equipped_plate
    FROM user_levels WHERE user_id=?`).bind(userId).first();
  const xp = row?.xp ?? 0, launched = row?.launched ? 1 : 0;
  const level = computeLevel(xp, launched);
  const nextLevel = level < MAX_LEVEL ? level + 1 : null;
  return {
    level, xp, launched: Boolean(launched), firstLaunchAt: row?.first_launch_at ?? null,
    micro: row?.xp_micro ?? xp * MICRO,
    lastLoginDay: row?.last_login_day ?? null, lastLaunchDay: row?.last_launch_day ?? null,
    streak: row?.launch_streak ?? 0, streakBest: row?.launch_streak_best ?? 0,
    gameMinutes: row?.game_minutes_total ?? 0, launcherMinutes: row?.launcher_minutes_total ?? 0,
    equippedPlate: row?.equipped_plate ?? null,
    next: nextLevel ? { level: nextLevel, threshold: LEVEL_THRESHOLDS[nextLevel], remaining: Math.max(0, LEVEL_THRESHOLDS[nextLevel] - xp) } : null
  };
}
// ---------- 铭牌派生 ----------
// 读取派生所需的全部真实信号,组装成 nameplates.mjs 的上下文。
async function nameplateContext(env, userId, level) {
  const [flags, profile] = await Promise.all([
    env.DB.prepare('SELECT flag,value FROM user_flags WHERE user_id=?').bind(userId).all(),
    env.DB.prepare('SELECT staff FROM users WHERE id=?').bind(userId).first()
  ]);
  return buildContext({
    level: level.level, xp: level.xp, launched: level.launched, staff: Boolean(profile?.staff),
    streak: level.streak, streakBest: level.streakBest,
    gameMinutes: level.gameMinutes, launcherMinutes: level.launcherMinutes,
    flags: Object.fromEntries((flags.results ?? []).map(r => [r.flag, r.value]))
  });
}
// 账户的铭牌评估结果 + 生效加成(取已拥有铭牌中的最高倍率,不叠加)。
async function loadNameplates(env, userId, level) {
  const resolved = level ?? await loadLevel(env, userId);
  const ctx = await nameplateContext(env, userId, resolved);
  const plates = evaluateNameplates(ctx);
  const bonus = activeBonus(plates);
  // 佩戴中的铭牌必须已拥有,否则视为未佩戴(例如订阅到期后仍残留的 sub_* 铭牌)。
  const equipped = plates.find(p => p.id === resolved.equippedPlate && p.owned) ?? null;
  return { plates, bonus, equipped, hidesLevel: Boolean(equipped?.replacesLevel) };
}
// ---------- 经验入账 ----------
// 启动器遥测与本站登录流程共用。逐条事件处理,单条失败不影响其余事件。
// 幂等:一次性事件用类型作键;每日事件由服务端按 UTC 日生成键(客户端无法伪造重复领取);
// 时长类事件沿用调用方传入的 dedupeKey。全部受 xp_events(user_id, dedupe_key) 唯一索引保护。
async function applyXpEvents(env, userId, events) {
  let current = await loadLevel(env, userId);
  const { bonus } = await loadNameplates(env, userId, current);
  let applied = 0, ignored = 0, grantedMicro = 0;
  const dayCache = new Map(), sourceDayCache = new Map();
  const sumMicro = async (sql, binds) => (await env.DB.prepare(sql).bind(...binds).first())?.n ?? 0;
  const dayTotal = async day => {
    if (!dayCache.has(day)) dayCache.set(day, await sumMicro("SELECT COALESCE(sum(amount_micro),0) AS n FROM xp_events WHERE user_id=? AND occurred_at LIKE ? || '%'", [userId, day]));
    return dayCache.get(day);
  };
  const sourceDayTotal = async (type, day) => {
    const key = `${type}|${day}`;
    if (!sourceDayCache.has(key)) sourceDayCache.set(key, await sumMicro("SELECT COALESCE(sum(amount_micro),0) AS n FROM xp_events WHERE user_id=? AND type=? AND occurred_at LIKE ? || '%'", [userId, type, day]));
    return sourceDayCache.get(key);
  };
  for (const event of (Array.isArray(events) ? events : []).slice(0, 100)) {
    const type = String(event?.type ?? '');
    const rule = XP_RULES[type];
    if (!rule) { ignored++; continue; }
    const occurredAt = typeof event?.occurredAt === 'string' && /^\d{4}-\d{2}-\d{2}T/.test(event.occurredAt) ? event.occurredAt : new Date().toISOString();
    const day = utcDay(occurredAt);
    // 服务端生成幂等键,客户端传入的键只对时长类事件生效。
    let dedupeKey = typeof event?.dedupeKey === 'string' && event.dedupeKey ? event.dedupeKey.slice(0, 120) : null;
    if (rule.once) dedupeKey = type;
    else if (rule.perDay) dedupeKey = `${type}:${day}`;
    if (dedupeKey) {
      const done = await env.DB.prepare('SELECT 1 FROM xp_events WHERE user_id=? AND dedupe_key=?').bind(userId, dedupeKey).first();
      if (done) { ignored++; continue; }
    }
    let units = 0, gainMicro;
    if (rule.micro !== undefined) {
      gainMicro = computeXpGain({ rule, units: 0, bonus, dayRoomMicro: rule.capExempt ? Infinity : Math.max(0, XP_DAILY_CAP - await dayTotal(day)) });
    } else {
      units = normalizeUnits(rule, event?.amount);
      if (units <= 0) { ignored++; continue; }
      // 日上限按「事件发生日」计:历史补报不占今天的额度。
      gainMicro = computeXpGain({
        rule, units, bonus,
        sourceRoomMicro: Math.max(0, rule.dailyMicroCap - await sourceDayTotal(type, day)),
        dayRoomMicro: Math.max(0, XP_DAILY_CAP - await dayTotal(day))
      });
    }
    if (gainMicro <= 0) { ignored++; continue; }
    // 记账缓存按实际入账值推进(可能已被上限削减)。
    if (rule.dailyMicroCap) sourceDayCache.set(`${type}|${day}`, (sourceDayCache.get(`${type}|${day}`) ?? 0) + gainMicro);
    if (!rule.capExempt) dayCache.set(day, (dayCache.get(day) ?? 0) + gainMicro);
    // user_levels 用相对累加:单条 UPDATE 的右值全部取原行值(SQLite 语义),并发下不会丢更新。
    const sets = ['xp_micro = xp_micro + ?', 'xp = CAST((xp_micro + ?) / ? AS INTEGER)', 'updated_at = ?'];
    const binds = [gainMicro, gainMicro, MICRO, new Date().toISOString()];
    if (rule.setsLaunched) { sets.push('launched = 1', 'first_launch_at = COALESCE(first_launch_at, ?)'); binds.push(occurredAt); }
    if (rule.accrue && units > 0) { sets.push(`${rule.accrue} = ${rule.accrue} + ?`); binds.push(units); }
    if (rule.perDay === 'last_login_day') { sets.push('last_login_day = MAX(COALESCE(last_login_day, ?), ?)'); binds.push(day, day); }
    if (rule.streak) {
      const streak = nextLaunchStreak(current.lastLaunchDay, day, current.streak);
      // last_launch_day 只前进不回退:否则一条旧日期补报会把锚点拉回去,
      // 让下一次正常启动被误判成「断签」而清零连击。
      sets.push('launch_streak = ?', 'launch_streak_best = MAX(launch_streak_best, ?)', 'last_launch_day = MAX(COALESCE(last_launch_day, ?), ?)');
      binds.push(streak, streak, day, day);
    }
    const nowIso = new Date().toISOString();
    try {
      await env.DB.batch([
        env.DB.prepare('INSERT INTO user_levels(user_id,xp,xp_micro,launched,updated_at) VALUES(?,0,0,0,?) ON CONFLICT(user_id) DO NOTHING').bind(userId, nowIso),
        env.DB.prepare(`UPDATE user_levels SET ${sets.join(', ')} WHERE user_id=?`).bind(...binds, userId),
        env.DB.prepare('INSERT INTO xp_events(user_id,type,amount,amount_micro,dedupe_key,occurred_at,created_at) VALUES(?,?,?,?,?,?,?)').bind(userId, type, Math.floor(gainMicro / MICRO), gainMicro, dedupeKey, occurredAt, nowIso)
      ]);
      applied++; grantedMicro += gainMicro;
    } catch { ignored++; continue; }
    current = await loadLevel(env, userId);
  }
  return { applied, ignored, grantedXp: Math.floor(grantedMicro / MICRO), bonus, level: current };
}
const serviceAuth = (request, env) => {
  const token = (request.headers.get('authorization') || '').replace(/^Bearer /, '');
  if (!env.SERVICE_TOKEN || token !== env.SERVICE_TOKEN) fail(401, '服务凭据无效');
};
// 「每日登录」经验:在真实登录成功点(第三方回调 / passkey / 验证器码)写入。
// 与启动器上报共用同一幂等键 daily.login:<UTC 日>,两条通道不会重复计分。
// 注意:POST /auth/v1/tokens 是既有 Cookie 会话换取内存令牌(每次刷新页面都会调用),
// 不算登录,故不在那里写入,否则「每日登录」会退化成「每日访问」。
// 经验入账失败绝不阻塞登录流程。
async function grantDailyLogin(env, userId, at = new Date().toISOString()) {
  try { await applyXpEvents(env, userId, [{ type: 'daily.login', occurredAt: at }]); }
  catch (error) { console.error(JSON.stringify({ xp: 'daily.login', error: String(error?.message ?? error).slice(0, 120) })); }
}
async function rateLimit(env, key, limit, windowMs, message) {
  const now = Date.now();
  const row = await env.DB.prepare('INSERT INTO rate_limits(key,count,expires) VALUES(?,1,?) ON CONFLICT(key) DO UPDATE SET count=CASE WHEN expires<=? THEN 1 ELSE count+1 END,expires=CASE WHEN expires<=? THEN excluded.expires ELSE expires END RETURNING count').bind(key, now + windowMs, now, now).first();
  if (row.count > limit) fail(429, message);
}
async function loadFactors(env, userId) {
  const [totp, passkeys, recovery] = await Promise.all([
    env.DB.prepare('SELECT count(*) AS n FROM mfa_totp WHERE user_id=? AND confirmed=1').bind(userId).first(),
    env.DB.prepare('SELECT count(*) AS n FROM mfa_passkeys WHERE user_id=?').bind(userId).first(),
    env.DB.prepare('SELECT count(*) AS n FROM mfa_recovery_codes WHERE user_id=? AND used_at IS NULL').bind(userId).first()
  ]);
  return {
    totpCount: totp?.n ?? 0,
    passkeyCount: passkeys?.n ?? 0,
    recoveryCount: recovery?.n ?? 0,
    list: [...(passkeys?.n ? ['passkey'] : []), ...(totp?.n ? ['totp'] : []), ...(recovery?.n ? ['recovery'] : [])]
  };
}
async function createLoginChallenge(env, userId, purpose = 'login') {
  const challenge = randomBytes(32).toString('base64url');
  await env.DB.prepare('INSERT INTO login_challenges(challenge_hash,user_id,purpose,expires,created_at) VALUES(?,?,?,?,?)').bind(digest(challenge), userId, purpose, Date.now() + 300000, new Date().toISOString()).run();
  return challenge;
}
async function loadChallenge(env, challenge, purpose = 'login') {
  const row = await env.DB.prepare('SELECT * FROM login_challenges WHERE challenge_hash=? AND purpose=? AND consumed=0 AND expires>?').bind(digest(String(challenge ?? '')), purpose, Date.now()).first();
  if (!row) fail(401, '登录挑战已失效，请重新开始');
  return row;
}
async function consumeChallenge(env, challenge, purpose = 'login') {
  const row = await loadChallenge(env, challenge, purpose);
  const consumed = await env.DB.prepare('UPDATE login_challenges SET consumed=1 WHERE challenge_hash=? AND consumed=0').bind(row.challenge_hash).run();
  if (!consumed.meta.changes) fail(401, '登录挑战已被使用，请重新开始');
  return row;
}
// 敏感操作（移除 MFA、生成恢复码）：已设置密码时要求复核当前密码。
async function reauthSensitive(env, user, input) {
  const row = await env.DB.prepare('SELECT password_hash FROM users WHERE id=?').bind(user.id).first();
  if (!hasRealPassword(row?.password_hash)) return;
  if (!input?.password || !(await verifyPassword(String(input.password), row.password_hash))) fail(403, '该操作需要验证当前密码');
}
async function body(request, limit = 4096) {
  if (!request.headers.get('content-type')?.startsWith('application/json')) fail(415, '需要 JSON 请求');
  const reader = request.body?.getReader(); if (!reader) fail(400, '缺少请求体');
  let bytes = 0; const parts = [];
  try { for (;;) { const { value, done } = await reader.read(); if (done) break; bytes += value.length; if (bytes > limit) { await reader.cancel(); fail(413, '请求过大'); } parts.push(value); } } finally { reader.releaseLock(); }
  const all = new Uint8Array(bytes); let offset = 0; for (const part of parts) { all.set(part, offset); offset += part.length; }
  try { return JSON.parse(new TextDecoder().decode(all)); } catch { fail(400, '无效 JSON'); }
}
async function currentPolicy(env, kind) {
  const policy = await env.DB.prepare('SELECT * FROM policy_documents WHERE kind=? AND current=1').bind(kind).first();
  if (!policy) fail(503, '政策文档尚未配置');
  return policy;
}
async function sessionUser(env, request, scope) {
  const value = credential(request, scope);
  if (!value) fail(401, '请先登录');
  const user = await env.DB.prepare(`SELECT u.id,COALESCE(u.display_name,u.name) AS name,u.email,u.staff,u.developer,u.trusted_developer AS trustedDeveloper,u.user_handle AS handle,(u.confirmed_at IS NULL) AS setupRequired,
    EXISTS(SELECT 1 FROM terms_acceptances ta JOIN policy_documents pd ON pd.id=ta.policy_id AND pd.kind='terms' AND pd.current=1 WHERE ta.user_id=u.id) AS termsAccepted
    FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token_hash=? AND s.scope=? AND s.expires>? AND u.disabled=0 AND (?=0 OR u.staff=1)`).bind(digest(value), scope, Date.now(), scope === 'operations' ? 1 : 0).first();
  if (!user) fail(401, '请先登录');
  const level = await loadLevel(env, user.id);
  return { ...user, level: level.level, xp: level.xp };
}
async function createSession(env, user, scope, now, secure) {
  const value = randomBytes(32).toString('base64url');
  await env.DB.batch([
    env.DB.prepare('DELETE FROM sessions WHERE expires<?').bind(now),
    env.DB.prepare('INSERT INTO sessions(token_hash,user_id,scope,expires) VALUES(?,?,?,?)').bind(digest(value), user.id, scope, now + (scope === 'operations' ? 3600000 : 86400000))
  ]);
  return { value, cookie: `${cookieName(scope)}=${value}; HttpOnly; SameSite=Strict; Path=/; Max-Age=${scope === 'operations' ? 3600 : 86400}${secure ? '; Secure' : ''}` };
}
async function oauthStart(request, env, provider) {
  const config = configFor(provider, env), url = new URL(request.url);
  const returnPath = url.searchParams.get('return_to') || '/';
  if (!returnPath.startsWith('/') || returnPath.startsWith('//')) fail(400, '无效返回地址');
  const mode = url.searchParams.get('mode') === 'link' ? 'link' : 'login';
  let userId = null, termsPolicyId = null;
  if (mode === 'link') {
    const scope = scopeOf(url.searchParams.get('scope') || 'console');
    const current = await env.DB.prepare('SELECT user_id FROM sessions WHERE token_hash=? AND scope=? AND expires>?').bind(digest(token(request, scope)), scope, Date.now()).first();
    if (!current) fail(401, '请先登录后再绑定身份');
    userId = current.user_id;
  } else {
    const terms = await currentPolicy(env, 'terms');
    if (url.searchParams.get('tos') !== terms.version) fail(400, '需要先接受当前版本的服务条款');
    termsPolicyId = terms.id;
  }
  const state = randomBytes(32).toString('base64url'), nonce = randomBytes(32).toString('base64url'), expires = Date.now() + 600000;
  await env.DB.batch([
    env.DB.prepare('DELETE FROM oauth_states WHERE expires<? OR consumed=1').bind(Date.now()),
    env.DB.prepare('INSERT INTO oauth_states(state,nonce,provider,return_to,user_id,terms_policy_id,expires,created_at) VALUES(?,?,?,?,?,?,?,?)').bind(state, nonce, provider, returnPath, userId, termsPolicyId, expires, new Date().toISOString())
  ]);
  const authorize = new URL(config.authorize);
  authorize.searchParams.set('client_id', config.clientId); authorize.searchParams.set('redirect_uri', config.callback); authorize.searchParams.set('response_type', 'code'); authorize.searchParams.set('state', state);
  // Microsoft 仅在“绑定”时额外请求 XboxLive.signin 与 offline_access：查询 Minecraft 拥有状况与档案，
  // 并加密保存刷新令牌供启动器后续派生令牌；普通登录保持最小 scope（与 7307a22 的收窄一致）。
  authorize.searchParams.set('scope', provider === 'microsoft' && mode === 'link' ? `${config.scope} XboxLive.signin offline_access` : config.scope);
  authorize.searchParams.set('nonce', nonce);
  return new Response(null, { status: 302, headers: { location: authorize.toString(), 'set-cookie': `${oauthStateCookie}=${state}; HttpOnly; SameSite=Lax; Path=/auth/v1/oauth; Max-Age=600${env.LOCAL_DEV === 'true' ? '' : '; Secure'}`, 'cache-control': 'no-store' } });
}
async function oauthCallback(request, env, provider, secure) {
  const config = configFor(provider, env), url = new URL(request.url), state = url.searchParams.get('state'), code = url.searchParams.get('code');
  if (!state || !code || url.searchParams.get('error')) return oauthError(env, '第三方登录未完成');
  const now = Date.now();
  const stateRow = await env.DB.prepare('SELECT * FROM oauth_states WHERE state=? AND provider=? AND consumed=0 AND expires>?').bind(state, provider, now).first();
  if (!stateRow || cookieValue(request, oauthStateCookie) !== state) return oauthError(env, '登录状态已失效，请重试');
  const consumed = await env.DB.prepare('UPDATE oauth_states SET consumed=1 WHERE state=? AND provider=? AND consumed=0 AND expires>?').bind(state, provider, now).run();
  if (!consumed.meta.changes) return oauthError(env, '登录状态已被使用，请重试');
  try {
    const tokenResponse = await fetch(config.token, { method: 'POST', headers: { accept: 'application/json', 'content-type': 'application/x-www-form-urlencoded' }, body: new URLSearchParams({ client_id: config.clientId, client_secret: config.clientSecret, code, redirect_uri: config.callback, grant_type: 'authorization_code' }) });
    if (!tokenResponse.ok) throw new Error('token exchange failed');
    const tokenData = await tokenResponse.json();
    if (!tokenData.access_token) throw new Error('missing access token');
    if (provider === 'microsoft' && tokenData.id_token) {
      const payload = b64json(tokenData.id_token.split('.')[1]);
      if (payload.nonce !== stateRow.nonce) throw new Error('nonce mismatch');
    }
    const profileResponse = await fetch(config.profile, { headers: { authorization: `Bearer ${tokenData.access_token}`, accept: 'application/json', 'user-agent': 'nexa-auth' } });
    if (!profileResponse.ok) throw new Error('profile lookup failed');
    const profile = await profileResponse.json();
    const subject = String(provider === 'github' ? profile.id : (profile.sub || profile.id));
    const email = typeof profile.email === 'string' ? profile.email.toLowerCase().slice(0, 320) : null;
    const displayName = String(profile.name || profile.login || profile.preferred_username || subject).slice(0, 160);
    let identity = await env.DB.prepare('SELECT user_id FROM oauth_identities WHERE provider=? AND subject=?').bind(provider, subject).first();
    let user;
    if (stateRow.user_id) {
      user = await env.DB.prepare('SELECT id,name,disabled FROM users WHERE id=?').bind(stateRow.user_id).first();
      if (!user || user.disabled) throw new Error('account disabled');
      if (identity && identity.user_id !== user.id) throw new Error('该第三方账号已绑定其他账户');
      if (!identity) {
        await env.DB.batch([
          env.DB.prepare('INSERT INTO oauth_identities(provider,subject,user_id,email,created_at,updated_at) VALUES(?,?,?,?,?,?)').bind(provider, subject, user.id, email, new Date().toISOString(), new Date().toISOString()),
          auditEvent(env, user.id, 'oauth.linked', `${provider}:${subject}`)
        ]);
      }
    } else if (identity) {
      user = await env.DB.prepare('SELECT id,name,disabled,confirmed_at FROM users WHERE id=?').bind(identity.user_id).first();
    } else {
      const id = crypto.randomUUID(), name = `${provider}:${subject}`;
      await env.DB.batch([
        // 新用户 confirmed_at 留空:必须到 /register?setup=1 完善用户名/用户 ID 后账户才生效。
        env.DB.prepare("INSERT INTO users(id,name,password_hash,display_name,email,created_at) VALUES(?,?,?,?,?,?)").bind(id, name, `oauth:${randomBytes(32).toString('hex')}`, displayName, email, new Date().toISOString()),
        env.DB.prepare('INSERT INTO oauth_identities(provider,subject,user_id,email,created_at,updated_at) VALUES(?,?,?,?,?,?)').bind(provider, subject, id, email, new Date().toISOString(), new Date().toISOString())
      ]);
      user = { id, name, disabled: 0, confirmed_at: null };
    }
    if (!user || user.disabled) throw new Error('account disabled');
    await env.DB.prepare('UPDATE oauth_identities SET email=?,updated_at=? WHERE provider=? AND subject=?').bind(email, new Date().toISOString(), provider, subject).run();
    const headers = new Headers({ location: new URL(stateRow.return_to, env.WEB_ORIGIN).toString(), 'cache-control': 'no-store' });
    headers.append('set-cookie', `${oauthStateCookie}=; HttpOnly; SameSite=Lax; Path=/auth/v1/oauth; Max-Age=0${secure ? '; Secure' : ''}`);
    if (stateRow.user_id) {
      // 绑定 Microsoft 成功：同步查询 Xbox → Minecraft 拥有状况与档案并落库。
      // 任何一步失败都不阻塞绑定本身，只记录 error 供界面展示。
      if (provider === 'microsoft') {
        let status = null, chainError = null;
        try { status = await fetchMinecraftStatus(tokenData.access_token); }
        catch (chainFailure) { chainError = String(chainFailure?.message ?? chainFailure).slice(0, 60); }
        const statements = [
          env.DB.prepare(`INSERT INTO minecraft_profiles(user_id,owned,profile_id,profile_name,error,checked_at) VALUES(?,?,?,?,?,?)
            ON CONFLICT(user_id) DO UPDATE SET owned=excluded.owned, profile_id=excluded.profile_id, profile_name=excluded.profile_name, error=excluded.error, checked_at=excluded.checked_at`)
            .bind(user.id, status?.owned ?? null, status?.profileId ?? null, status?.profileName ?? null, chainError, new Date().toISOString()),
          auditEvent(env, user.id, 'minecraft.checked', status ? `owned:${status.owned}` : chainError)
        ];
        // 刷新令牌仅在配置 TOKEN_ENC_KEY 时以 AES-GCM 加密保存；无密钥则拒绝落盘（绝不存明文）。
        if (typeof tokenData.refresh_token === 'string' && env.TOKEN_ENC_KEY) {
          statements.push(env.DB.prepare('INSERT INTO microsoft_tokens(user_id,refresh_token_enc,obtained_at) VALUES(?,?,?) ON CONFLICT(user_id) DO UPDATE SET refresh_token_enc=excluded.refresh_token_enc, obtained_at=excluded.obtained_at').bind(user.id, await encryptSecret(tokenData.refresh_token, env.TOKEN_ENC_KEY), new Date().toISOString()));
        }
        await env.DB.batch(statements);
      }
      return new Response(null, { status: 303, headers });
    }
    await env.DB.prepare('UPDATE users SET display_name=?,email=? WHERE id=?').bind(displayName, email, user.id).run();
    if (stateRow.terms_policy_id) {
      // 条款接受与隐私告知随登录原子落库；INSERT OR IGNORE 保证已接受用户不会重复记录。
      await env.DB.batch([
        env.DB.prepare('INSERT OR IGNORE INTO terms_acceptances(user_id,policy_id,accepted_at) VALUES(?,?,?)').bind(user.id, stateRow.terms_policy_id, new Date().toISOString()),
        auditOnChange(env, user.id, 'terms.accepted', stateRow.terms_policy_id),
        env.DB.prepare('INSERT OR IGNORE INTO privacy_notice_receipts(user_id,policy_id,provided_at) SELECT ?,?,? WHERE changes()=1').bind(user.id, (await currentPolicy(env, 'privacy')).id, new Date().toISOString())
      ]);
    }
    const session = await createSession(env, user, 'console', now, secure);
    headers.append('set-cookie', session.cookie);
    await grantDailyLogin(env, user.id);
    // 未完成注册的用户强制进入完善资料页;已确认用户按 return_to 回跳。
    if (!user.confirmed_at) headers.set('location', new URL('/register?setup=1', env.WEB_ORIGIN).toString());
    return new Response(null, { status: 303, headers });
  } catch (error) { console.error(JSON.stringify({ oauth: provider, error: error.name })); return oauthError(env, '第三方登录失败，请重试'); }
}
export async function finalizeAccountDeletion(env, requestId, userId) {
  const now = new Date().toISOString();
  await env.DB.batch([
    env.DB.prepare('DELETE FROM sessions WHERE user_id=?').bind(userId),
    env.DB.prepare('DELETE FROM oauth_identities WHERE user_id=?').bind(userId),
    env.DB.prepare('DELETE FROM oauth_states WHERE user_id=?').bind(userId),
    env.DB.prepare('DELETE FROM microsoft_tokens WHERE user_id=?').bind(userId),
    env.DB.prepare('DELETE FROM mfa_passkeys WHERE user_id=?').bind(userId),
    env.DB.prepare('DELETE FROM mfa_totp WHERE user_id=?').bind(userId),
    env.DB.prepare('DELETE FROM mfa_recovery_codes WHERE user_id=?').bind(userId),
    env.DB.prepare('UPDATE users SET name=?, display_name=NULL, email=NULL, disabled=1 WHERE id=? AND disabled=0').bind('deleted:' + userId, userId),
    env.DB.prepare("UPDATE account_deletion_requests SET state='finalized', finalized_at=?, version=version+1 WHERE id=? AND state='pending'").bind(now, requestId),
    env.DB.prepare('INSERT INTO deletion_tombstones(subject_id,deleted_at,deletion_version,reason) VALUES(?,?,1,?) ON CONFLICT(subject_id) DO UPDATE SET deleted_at=excluded.deleted_at, deletion_version=deletion_tombstones.deletion_version+1').bind(userId, now, 'user_requested'),
    auditEvent(env, userId, 'account.delete.completed', requestId)
  ]);
}
// NCL-007 保留清理 + NCL-008/009 注销冷静期执行；幂等、有界，供每日 cron 调用。
export async function runAuthMaintenance(env) {
  const now = Date.now();
  await env.DB.batch([
    env.DB.prepare('DELETE FROM sessions WHERE expires<?').bind(now),
    env.DB.prepare('DELETE FROM oauth_states WHERE expires<? OR (consumed=1 AND expires<?)').bind(now, now - 86400000),
    env.DB.prepare('DELETE FROM rate_limits WHERE expires<?').bind(now),
    env.DB.prepare('DELETE FROM login_challenges WHERE expires<?').bind(now - 86400000),
    env.DB.prepare('DELETE FROM mfa_totp WHERE confirmed=0 AND created_at<?').bind(new Date(now - 900000).toISOString()),
    env.DB.prepare('DELETE FROM users WHERE confirmed_at IS NULL AND created_at<?').bind(new Date(now - 86400000).toISOString())
  ]);
  const due = await env.DB.prepare("SELECT id,user_id FROM account_deletion_requests WHERE state='pending' AND execute_after<=? LIMIT 20").bind(now).all();
  for (const row of due.results) await finalizeAccountDeletion(env, row.id, row.user_id);
  return { finalized: due.results.length };
}
export default {
  async scheduled(controller, env, ctx) { await ctx.waitUntil(runAuthMaintenance(env)); },
  async fetch(request, env, ctx) {
    const id = crypto.randomUUID(), url = new URL(request.url), path = url.pathname;
    const mailer = createMailer(env);
    // 邮件等旁路任务：未配置服务商时 mailer 可能返回非 Promise，统一包裹后再 waitUntil。
    const later = task => { if (ctx?.waitUntil) ctx.waitUntil(Promise.resolve(task).catch(() => {})); };
    try {
      const secure = env.LOCAL_DEV !== 'true';
      if (!env.WEB_ORIGIN || (secure && !env.WEB_ORIGIN.startsWith('https://'))) fail(503, '身份服务尚未配置');
      if (request.method === 'OPTIONS' && path.startsWith('/auth/v1/')) return new Response(null, { status: 204, headers: { ...cors(env), 'access-control-allow-methods': 'GET, POST, PUT, PATCH, DELETE, OPTIONS', 'access-control-allow-headers': 'content-type, x-nexa-request, authorization', 'access-control-max-age': '600' } });
      // /internal/* 为服务间通道,以 SERVICE_TOKEN 鉴权,不适用浏览器 Origin 检查。
      if (!path.startsWith('/internal/') && !['GET', 'HEAD'].includes(request.method) && (request.headers.get('origin') !== env.WEB_ORIGIN || request.headers.get('x-nexa-request') !== '1')) fail(403, '请求来源无效');
      const oauthMatch = path.match(/^\/auth\/v1\/oauth\/(github|microsoft|google)\/(start|callback)$/);
      if (oauthMatch && request.method === 'GET') return await (oauthMatch[2] === 'start' ? oauthStart(request, env, oauthMatch[1]) : oauthCallback(request, env, oauthMatch[1], secure));
      if (path === '/auth/v1/sessions' && request.method === 'POST') fail(404, '接口不存在');
      if (path === '/auth/v1/tokens' && request.method === 'POST') {
        const scope = scopeOf(url.searchParams.get('scope') || 'console');
        const user = await sessionUser(env, request, scope);
        const now = Date.now();
        const limit = await env.DB.prepare('INSERT INTO rate_limits(key,count,expires) VALUES(?,1,?) ON CONFLICT(key) DO UPDATE SET count=CASE WHEN expires<=? THEN 1 ELSE count+1 END,expires=CASE WHEN expires<=? THEN excluded.expires ELSE expires END RETURNING count').bind('mint:' + user.id, now + 3600000, now, now).first();
        if (limit.count > 60) fail(429, '凭证请求过于频繁');
        const session = await createSession(env, user, scope, now, secure);
        return json(env, { token: session.value, user: { ...user, scope } });
      }
      // ---------- 用户名 / 用户 ID / 密码 ----------
      if (path === '/auth/v1/account/name' && request.method === 'PATCH') {
        const user = await sessionUser(env, request, 'console');
        const input = await body(request);
        let name; try { name = validateDisplayName(input?.name); } catch (error) { fail(400, error.message); }
        await env.DB.batch([
          env.DB.prepare('UPDATE users SET display_name=? WHERE id=?').bind(name, user.id),
          auditEvent(env, user.id, 'account.name.changed', null)
        ]);
        return json(env, { ok: true, name });
      }
      if (path === '/auth/v1/account/handle/availability' && request.method === 'GET') {
        await sessionUser(env, request, 'console');
        const handle = normalizeHandle(url.searchParams.get('handle') || '');
        if (!handle) return json(env, { available: false, reason: 'invalid' });
        if (isReservedHandle(handle)) return json(env, { available: false, reason: 'reserved' });
        const taken = await env.DB.prepare('SELECT 1 FROM users WHERE user_handle=?').bind(handle).first();
        return json(env, { available: !taken, ...(taken ? { reason: 'taken' } : {}) });
      }
      if (path === '/auth/v1/account/handle' && request.method === 'PUT') {
        const user = await sessionUser(env, request, 'console');
        const input = await body(request);
        let handle; try { handle = validateHandle(input?.handle); } catch (error) { fail(400, error.message); }
        const row = await env.DB.prepare('SELECT user_handle, handle_changed_at, email FROM users WHERE id=?').bind(user.id).first();
        const now = Date.now();
        if (row?.user_handle && row.handle_changed_at && now - row.handle_changed_at < HANDLE_COOLDOWN_DAYS * 86400000) {
          const days = Math.ceil((HANDLE_COOLDOWN_DAYS * 86400000 - (now - row.handle_changed_at)) / 86400000);
          fail(429, `用户 ID 每 ${HANDLE_COOLDOWN_DAYS} 天仅可修改一次，请在 ${days} 天后再试`);
        }
        try {
          await env.DB.batch([
            env.DB.prepare('UPDATE users SET user_handle=?, handle_changed_at=? WHERE id=?').bind(handle, now, user.id),
            auditEvent(env, user.id, 'account.handle.changed', row?.user_handle ? `${row.user_handle} -> ${handle}` : handle)
          ]);
        } catch (error) {
          if (String(error?.message ?? error).includes('UNIQUE')) fail(409, '该用户 ID 已被占用');
          throw error;
        }
        if (row?.email) later(mailer.securityNotice(row.email, `你的用户 ID 已变更为 ${handle}。若非本人操作，请立即检查账户安全。`));
        return json(env, { ok: true, handle, nextChangeAt: new Date(now + HANDLE_COOLDOWN_DAYS * 86400000).toISOString() });
      }
      if (path === '/auth/v1/account/password' && request.method === 'POST') {
        const user = await sessionUser(env, request, 'console');
        const input = await body(request);
        const row = await env.DB.prepare('SELECT password_hash, email FROM users WHERE id=?').bind(user.id).first();
        const changing = hasRealPassword(row?.password_hash);
        if (changing && !(input?.currentPassword && await verifyPassword(String(input.currentPassword), row.password_hash))) fail(403, '当前密码不正确');
        let hash; try { hash = await hashPassword(String(input?.password ?? '')); } catch (error) { fail(400, error.message); }
        await env.DB.batch([
          env.DB.prepare('UPDATE users SET password_hash=?, password_set_at=? WHERE id=?').bind(hash, Date.now(), user.id),
          auditEvent(env, user.id, changing ? 'account.password.changed' : 'account.password.set', null)
        ]);
        if (row?.email) later(mailer.securityNotice(row.email, changing ? '你的登录密码已被修改。' : '你的账户已设置登录密码。密码登录将强制要求两步验证。'));
        const factors = await loadFactors(env, user.id);
        return json(env, { ok: true, mfa: { required: true, factors: factors.list, message: '密码登录强制两步验证；尚未注册任何方式时，请先注册 passkey 或验证器应用。' } }, changing ? 200 : 201);
      }
      // ---------- 用户 ID + 密码登录（两段式：密码 → 强制 2FA） ----------
      if (path === '/auth/v1/login' && request.method === 'POST') {
        const input = await body(request);
        const handle = normalizeHandle(input?.handle);
        await rateLimit(env, 'login:' + (handle || 'invalid'), 10, 900000, '登录尝试过于频繁，请稍后再试');
        await rateLimit(env, 'login-ip:' + clientIp(request), 30, 900000, '该网络登录尝试过多，请稍后再试');
        const row = handle ? await env.DB.prepare('SELECT id, COALESCE(display_name,name) AS display_name, password_hash, disabled FROM users WHERE user_handle=?').bind(handle).first() : null;
        const passwordOk = Boolean(row) && hasRealPassword(row.password_hash) && await verifyPassword(String(input?.password ?? ''), row.password_hash);
        if (!row) await verifyPassword(String(input?.password ?? 'x')); // 等时化：用户 ID 不存在也执行一次 scrypt
        if (!row || !passwordOk) {
          if (row) await auditEvent(env, row.id, 'login.password.failed', null).run();
          fail(401, '用户 ID 或密码不正确');
        }
        if (row.disabled) fail(403, '账户已被停用');
        const factors = await loadFactors(env, row.id);
        if (!factors.list.length) {
          await auditEvent(env, row.id, 'login.mfa_missing', null).run();
          return json(env, { type: 'about:blank', title: 'MFA enrollment required', status: 403, code: 'mfa_enrollment_required', detail: '密码登录必须先注册两步验证（passkey、验证器应用或恢复码）。请先使用第三方登录完成注册。' }, 403, { 'content-type': 'application/problem+json' });
        }
        const challenge = await createLoginChallenge(env, row.id);
        await auditEvent(env, row.id, 'login.challenge', factors.list.join('+')).run();
        return json(env, { challenge, factors: factors.list, user: { name: row.display_name } });
      }
      if (path === '/auth/v1/login/passkey/options' && request.method === 'POST') {
        const input = await body(request);
        const row = await loadChallenge(env, input?.challenge, 'login');
        const credentials = await env.DB.prepare('SELECT credential_id FROM mfa_passkeys WHERE user_id=? ORDER BY created_at').bind(row.user_id).all();
        if (!credentials.results.length) fail(400, '该账户未注册 passkey');
        const wa = randomBytes(32).toString('base64url');
        await env.DB.prepare('UPDATE login_challenges SET wa_challenge=? WHERE challenge_hash=?').bind(wa, row.challenge_hash).run();
        return json(env, { challenge: wa, rpId: RP_ID(env), timeout: 60000, userVerification: 'preferred', allowCredentials: credentials.results.map(c => ({ type: 'public-key', id: c.credential_id })) });
      }
      if (path === '/auth/v1/login/passkey' && request.method === 'POST') {
        const input = await body(request, 16384);
        const row = await consumeChallenge(env, input?.challenge, 'login');
        if (!row.wa_challenge) fail(400, '请先获取 passkey 选项');
        const credential = await env.DB.prepare('SELECT * FROM mfa_passkeys WHERE credential_id=? AND user_id=?').bind(String(input?.credentialId ?? ''), row.user_id).first();
        if (!credential) fail(401, 'passkey 与该账户不匹配');
        const user = await env.DB.prepare('SELECT id, COALESCE(display_name,name) AS name, disabled FROM users WHERE id=?').bind(row.user_id).first();
        if (!user || user.disabled) fail(403, '账户已被停用');
        let result;
        try {
          result = await verifyAssertion({
            publicKeyJwk: JSON.parse(credential.public_key), alg: credential.algorithm,
            clientDataJSON: input.clientDataJSON, authenticatorData: input.authenticatorData, signature: input.signature,
            expectedChallenge: row.wa_challenge, expectedOrigins: webauthnOrigins(env), rpId: RP_ID(env), storedSignCount: credential.sign_count
          });
        } catch (error) { console.error(JSON.stringify({ webauthn: 'assertion', error: error.message })); fail(401, 'passkey 校验失败'); }
        const now = Date.now();
        await env.DB.batch([
          env.DB.prepare('UPDATE mfa_passkeys SET sign_count=?, last_used_at=? WHERE credential_id=?').bind(result.signCount, new Date().toISOString(), credential.credential_id),
          auditEvent(env, row.user_id, 'login.passkey', credential.name || null)
        ]);
        const session = await createSession(env, user, 'console', now, secure);
        await grantDailyLogin(env, user.id);
        return json(env, { ok: true, user: { id: user.id, name: user.name } }, 200, { 'set-cookie': session.cookie });
      }
      if (path === '/auth/v1/login/totp' && request.method === 'POST') {
        const input = await body(request);
        const row = await loadChallenge(env, input?.challenge, 'login');
        const user = await env.DB.prepare('SELECT id, COALESCE(display_name,name) AS name, disabled FROM users WHERE id=?').bind(row.user_id).first();
        if (!user || user.disabled) fail(403, '账户已被停用');
        const code = String(input?.code ?? '');
        let method = null, recoveryRemaining;
        const totpDevices = await env.DB.prepare('SELECT id,secret,last_step FROM mfa_totp WHERE user_id=? AND confirmed=1').bind(row.user_id).all();
        for (const device of totpDevices.results) {
          const step = await verifyTotp(await decryptSecret(device.secret, env.MFA_ENC_KEY), code, Date.now(), device.last_step);
          if (step !== null) { method = 'totp'; await env.DB.prepare('UPDATE mfa_totp SET last_step=? WHERE id=?').bind(step, device.id).run(); break; }
        }
        if (!method && /^[A-Za-z0-9-]{5,}$/.test(code.trim())) {
          const consumedCode = await env.DB.prepare('UPDATE mfa_recovery_codes SET used_at=? WHERE code_hash=? AND user_id=? AND used_at IS NULL').bind(new Date().toISOString(), hashRecoveryCode(code), row.user_id).run();
          if (consumedCode.meta.changes) {
            method = 'recovery';
            const remaining = await env.DB.prepare('SELECT count(*) AS n FROM mfa_recovery_codes WHERE user_id=? AND used_at IS NULL').bind(row.user_id).first();
            recoveryRemaining = remaining?.n ?? 0;
          }
        }
        if (!method) { await auditEvent(env, row.user_id, 'login.mfa.failed', null).run(); fail(401, '验证码不正确'); }
        // 验证通过才消费挑战：输错验证码可原地重试，无需重新输入密码。
        const consumedRow = await env.DB.prepare('UPDATE login_challenges SET consumed=1 WHERE challenge_hash=? AND consumed=0').bind(row.challenge_hash).run();
        if (!consumedRow.meta.changes) fail(401, '登录挑战已被使用，请重新开始');
        await auditEvent(env, row.user_id, 'login.' + method, recoveryRemaining !== undefined ? `remaining:${recoveryRemaining}` : null).run();
        const session = await createSession(env, user, 'console', Date.now(), secure);
        await grantDailyLogin(env, user.id);
        return json(env, { ok: true, method, ...(recoveryRemaining !== undefined ? { recovery: { remaining: recoveryRemaining } } : {}), user: { id: user.id, name: user.name } }, 200, { 'set-cookie': session.cookie });
      }
      // ---------- 注册完善：第三方身份验证后设置用户名 / 用户 ID /（可选）密码 + TOTP ----------
      if (path === '/auth/v1/register/complete' && request.method === 'POST') {
        const user = await sessionUser(env, request, 'console');
        const row = await env.DB.prepare('SELECT id, confirmed_at, email FROM users WHERE id=?').bind(user.id).first();
        if (!row) fail(404, '账户不存在');
        if (row.confirmed_at) fail(409, '账户已激活，请在账户页修改相关设置');
        const input = await body(request);
        let handle, name;
        try { handle = validateHandle(input?.handle); name = validateDisplayName(input?.name); } catch (error) { fail(400, error.message); }
        // 回收他人废弃的未确认同名注册；再检查已确认账户占用。
        await env.DB.prepare('DELETE FROM users WHERE (user_handle=? OR name=?) AND confirmed_at IS NULL AND id!=?').bind(handle, handle, user.id).run();
        const taken = await env.DB.prepare('SELECT 1 FROM users WHERE (user_handle=? OR name=?) AND id!=?').bind(handle, handle, user.id).first();
        if (taken) fail(409, '该用户 ID 已被占用');
        const password = typeof input?.password === 'string' && input.password ? input.password : null;
        let hash = null, totpRow = null, step = null;
        if (password) {
          try { hash = await hashPassword(password); } catch (error) { fail(400, error.message); }
          totpRow = await env.DB.prepare('SELECT id,secret FROM mfa_totp WHERE id=? AND user_id=? AND confirmed=0').bind(String(input?.totpId ?? ''), user.id).first();
          if (!totpRow) fail(400, '设置密码需要先完成验证器绑定');
          step = await verifyTotp(await decryptSecret(totpRow.secret, env.MFA_ENC_KEY), String(input?.totpCode ?? ''));
          if (step === null) fail(400, '动态码不正确');
        }
        const nowIso = new Date().toISOString();
        await env.DB.batch([
          env.DB.prepare('UPDATE users SET display_name=?, user_handle=?, confirmed_at=?, password_hash=COALESCE(?,password_hash), password_set_at=CASE WHEN ? IS NULL THEN password_set_at ELSE ? END WHERE id=?').bind(name, handle, nowIso, hash, hash, Date.now(), user.id),
          ...(totpRow ? [env.DB.prepare('UPDATE mfa_totp SET confirmed=1, confirmed_at=?, last_step=? WHERE id=?').bind(nowIso, step, totpRow.id)] : []),
          auditEvent(env, user.id, 'register.completed', `handle:${handle};password:${hash ? 'set' : 'skip'}`)
        ]);
        if (row.email) later(mailer.securityNotice(row.email, `你的账户已完成注册，用户 ID：${handle}。`));
        return json(env, { ok: true, handle, name, passwordSet: Boolean(hash) });
      }
      // ---------- 2FA 因子管理 ----------
      // 启动器取 Minecraft 令牌：用加密保存的刷新令牌重新派生 XSTS，实时下发短时令牌并刷新档案。
      if (path === '/auth/v1/minecraft/token' && request.method === 'POST') {
        const user = await sessionUser(env, request, 'console');
        await rateLimit(env, 'mctoken:' + user.id, 10, 3600000, '令牌请求过于频繁，请稍后再试');
        const row = await env.DB.prepare('SELECT refresh_token_enc FROM microsoft_tokens WHERE user_id=?').bind(user.id).first();
        if (!row) fail(409, '未存储 Microsoft 刷新令牌：请在账户页重新绑定 Microsoft');
        const config = configFor('microsoft', env);
        const tokenRes = await fetch(config.token, {
          method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded', accept: 'application/json' },
          body: new URLSearchParams({ client_id: config.clientId, client_secret: config.clientSecret, refresh_token: await decryptSecret(row.refresh_token_enc, env.TOKEN_ENC_KEY), grant_type: 'refresh_token', scope: 'XboxLive.signin offline_access' })
        });
        const tokenData = await tokenRes.json().catch(() => ({}));
        if (!tokenRes.ok || !tokenData.access_token) {
          await auditEvent(env, user.id, 'minecraft.token.failed', `http:${tokenRes.status}`).run();
          fail(502, 'Microsoft 令牌刷新失败，请重新绑定账户');
        }
        if (typeof tokenData.refresh_token === 'string' && env.TOKEN_ENC_KEY) {
          await env.DB.prepare('UPDATE microsoft_tokens SET refresh_token_enc=?, obtained_at=? WHERE user_id=?').bind(await encryptSecret(tokenData.refresh_token, env.TOKEN_ENC_KEY), new Date().toISOString(), user.id).run();
        }
        let status;
        try { status = await fetchMinecraftStatus(tokenData.access_token); }
        catch (chainFailure) { fail(502, 'Minecraft 服务暂不可用：' + String(chainFailure?.message ?? chainFailure).slice(0, 40)); }
        await env.DB.batch([
          env.DB.prepare(`INSERT INTO minecraft_profiles(user_id,owned,profile_id,profile_name,error,checked_at) VALUES(?,?,?,?,NULL,?)
            ON CONFLICT(user_id) DO UPDATE SET owned=excluded.owned, profile_id=excluded.profile_id, profile_name=excluded.profile_name, error=NULL, checked_at=excluded.checked_at`)
            .bind(user.id, status.owned, status.profileId, status.profileName, new Date().toISOString()),
          auditEvent(env, user.id, 'minecraft.token.issued', `owned:${status.owned}`)
        ]);
        if (!status.owned) fail(403, '该 Microsoft 账户未拥有 Minecraft');
        return json(env, { accessToken: status.accessToken, profileId: status.profileId, profileName: status.profileName, owned: true });
      }
      // ---------- 内部服务通道(启动器遥测 → nexa-api → 此处;SERVICE_TOKEN 鉴权) ----------
      // 启动器只上报「事件类型 + 持续分钟数 + 发生时间」,经验数值与日上限全部由 Worker 决定。
      if (path === '/internal/v1/xp' && request.method === 'POST') {
        serviceAuth(request, env);
        const input = await body(request, 16384);
        const key = String(input?.user ?? '');
        const user = await env.DB.prepare('SELECT id FROM users WHERE id=? OR user_handle=?').bind(key, key).first();
        if (!user) fail(404, '用户不存在');
        if (!Array.isArray(input?.events) || !input.events.length || input.events.length > 100) fail(400, 'events 需为 1–100 条');
        const result = await applyXpEvents(env, user.id, input.events);
        return json(env, {
          applied: result.applied, ignored: result.ignored,
          grantedXp: result.grantedXp, bonus: result.bonus,
          xp: result.level.xp, level: result.level.level,
          acceptedTypes: XP_EVENT_TYPES
        });
      }
      if (path === '/internal/v1/flags' && request.method === 'POST') {
        serviceAuth(request, env);
        const input = await body(request);
        const key = String(input?.user ?? '');
        const user = await env.DB.prepare('SELECT id FROM users WHERE id=? OR user_handle=?').bind(key, key).first();
        if (!user) fail(404, '用户不存在');
        const flag = String(input?.flag ?? '');
        // 标记名允许数字(如 bilibili_level / nexa_donation),且必须在白名单内:
        // 这些标记直接驱动铭牌与资格判定,不接受任意自定义名称。
        if (!/^[a-z0-9_]{3,40}$/.test(flag) || !FLAG_ALLOWLIST.includes(flag)) fail(400, `无效的标记名(可用:${FLAG_ALLOWLIST.join(', ')})`);
        const value = typeof input?.value === 'string' ? input.value.slice(0, 200) : null;
        // 传 value: null 表示清除标记(例如订阅退订后收回订阅铭牌)。
        if (value === null) {
          await env.DB.batch([
            env.DB.prepare('DELETE FROM user_flags WHERE user_id=? AND flag=?').bind(user.id, flag),
            auditEvent(env, user.id, 'flag.cleared', flag)
          ]);
          return json(env, { ok: true, flag, cleared: true });
        }
        await env.DB.prepare('INSERT INTO user_flags(user_id,flag,value,set_at) VALUES(?,?,?,?) ON CONFLICT(user_id,flag) DO UPDATE SET value=excluded.value, set_at=excluded.set_at').bind(user.id, flag, value, new Date().toISOString()).run();
        await auditEvent(env, user.id, 'flag.set', `${flag}${value ? ':' + value : ''}`).run();
        return json(env, { ok: true, flag });
      }
      // ---------- 铭牌墙 ----------
      // 公开目录:未登录也可读取规则,供 /nameplates 铭牌墙页面渲染。
      if (path === '/auth/v1/nameplates' && request.method === 'GET') {
        return json(env, {
          plates: nameplateCatalog(),
          levels: LEVEL_THRESHOLDS,
          maxLevel: MAX_LEVEL,
          xpSources: xpSourceCatalog(),
          dailyCap: XP_DAILY_CAP / MICRO,
          bonusStacking: PLATE_BONUS_STACKING,
          bonusNote: PLATE_BONUS_STACKING ? '多枚铭牌的加成相乘叠加' : '多枚铭牌不叠加,取已拥有铭牌中的最高加成'
        }, 200, { 'cache-control': 'public, max-age=300' });
      }
      // 我的铭牌:已拥有清单、未达成进度、生效加成与佩戴状态。
      if (path === '/auth/v1/account/nameplates' && request.method === 'GET') {
        const user = await sessionUser(env, request, 'console');
        const level = await loadLevel(env, user.id);
        const { plates, bonus, equipped, hidesLevel } = await loadNameplates(env, user.id, level);
        return json(env, { plates, bonus, equipped: equipped?.id ?? null, hidesLevel, displayLevel: hidesLevel ? null : level.level });
      }
      // 佩戴 / 卸下铭牌。只有 replacesLevel 的铭牌可以隐藏等级数字。
      if (path === '/auth/v1/account/nameplates/equip' && request.method === 'PUT') {
        const user = await sessionUser(env, request, 'console');
        const input = await body(request);
        const wanted = input?.plate === null || input?.plate === '' ? null : plateById(input?.plate);
        if (input?.plate !== null && input?.plate !== '' && !wanted) fail(400, '未知的铭牌');
        const level = await loadLevel(env, user.id);
        if (wanted) {
          const { plates } = await loadNameplates(env, user.id, level);
          const owned = plates.find(p => p.id === wanted.id && p.owned);
          if (!owned) fail(403, `尚未达成「${wanted.label}」铭牌`);
        }
        await env.DB.batch([
          env.DB.prepare('INSERT INTO user_levels(user_id,xp,xp_micro,launched,equipped_plate,updated_at) VALUES(?,0,0,0,?,?) ON CONFLICT(user_id) DO UPDATE SET equipped_plate=excluded.equipped_plate, updated_at=excluded.updated_at').bind(user.id, wanted?.id ?? null, new Date().toISOString()),
          auditEvent(env, user.id, 'nameplate.equipped', wanted?.id ?? 'none')
        ]);
        return json(env, { ok: true, equipped: wanted?.id ?? null, hidesLevel: Boolean(wanted?.replacesLevel) });
      }
      // ---------- 等级 / 资格申请 ----------
      if (path === '/auth/v1/account/level' && request.method === 'GET') {
        const user = await sessionUser(env, request, 'console');
        const level = await loadLevel(env, user.id);
        const [popular, apps, profile, plates] = await Promise.all([
          env.DB.prepare("SELECT value, set_at FROM user_flags WHERE user_id=? AND flag='popular_plugin'").bind(user.id).first(),
          env.DB.prepare('SELECT id,kind,state,note,created_at,reviewed_at FROM applications WHERE user_id=? ORDER BY created_at DESC LIMIT 20').bind(user.id).all(),
          env.DB.prepare('SELECT staff, developer, trusted_developer FROM users WHERE id=?').bind(user.id).first(),
          loadNameplates(env, user.id, level)
        ]);
        const met = {
          developer: level.level >= 2,
          trustedDeveloper: level.level >= 3 && Boolean(popular) && Boolean(profile?.developer),
          admin: level.level >= 4
        };
        const today = utcDay();
        return json(env, {
          ...level,
          roles: { staff: Boolean(profile?.staff), developer: Boolean(profile?.developer), trustedDeveloper: Boolean(profile?.trusted_developer) },
          popularPlugin: popular ? { evidence: popular.value, setAt: popular.set_at } : null,
          // 经验来源与今日进度:启动器据此展示「今天还能拿多少」。
          xpSources: xpSourceCatalog().map(source => ({
            ...source,
            claimedToday: source.mode === 'daily' ? (source.type === 'daily.login' ? level.lastLoginDay === today : level.lastLaunchDay === today) : null
          })),
          dailyCap: XP_DAILY_CAP / MICRO,
          thresholds: LEVEL_THRESHOLDS,
          maxLevel: MAX_LEVEL,
          // 连续启动天数(streak / streakBest / lastLaunchDay)与累计时长
          // (gameMinutes / launcherMinutes)已由 ...level 展开,保持扁平契约,
          // 不再包一层同名对象 —— 否则 streak 会被对象覆盖掉数值。
          // LvMC 铭牌依据 streakBest,Lv∞ 依据 gameMinutes。
          // 铭牌墙:全部铭牌(含未达成进度)、生效加成与佩戴状态。
          nameplates: {
            plates: plates.plates,
            bonus: plates.bonus,
            bonusStacking: PLATE_BONUS_STACKING,
            equipped: plates.equipped?.id ?? null,
            equippedPlate: plates.equipped,
            hidesLevel: plates.hidesLevel,
            displayLevel: plates.hidesLevel ? null : level.level
          },
          requirements: {
            developer: { level: 2, met: met.developer },
            trustedDeveloper: { level: 3, popularPlugin: Boolean(popular), isDeveloper: Boolean(profile?.developer), met: met.trustedDeveloper },
            admin: { level: 4, met: met.admin }
          },
          applications: apps.results
        });
      }
      if (path === '/auth/v1/applications' && request.method === 'POST') {
        const user = await sessionUser(env, request, 'console');
        const input = await body(request);
        const kind = String(input?.kind ?? '');
        if (!['developer', 'trusted_developer', 'admin'].includes(kind)) fail(400, '无效的申请类型');
        const profile = await env.DB.prepare('SELECT staff, developer, trusted_developer, confirmed_at FROM users WHERE id=?').bind(user.id).first();
        if (!profile?.confirmed_at) fail(403, '请先完成注册');
        if (kind === 'developer' && profile.developer) fail(409, '你已经是开发者');
        if (kind === 'trusted_developer' && profile.trusted_developer) fail(409, '你已经是受信任的开发者');
        if (kind === 'trusted_developer' && !profile.developer) fail(403, '需要先成为开发者');
        if (kind === 'admin' && profile.staff) fail(409, '你已经是网站管理员');
        const level = await loadLevel(env, user.id);
        if (kind === 'developer' && level.level < 2) fail(403, '开发者申请需要达到 Lv2(先启动一次游戏,再累计 2,000 经验)');
        if (kind === 'trusted_developer' && level.level < 3) fail(403, '受信任的开发者需要达到 Lv3(累计 5,000 经验)');
        if (kind === 'admin' && level.level < 4) fail(403, '网站管理员申请需要达到 Lv4(累计 10,000 经验)');
        if (kind === 'trusted_developer') {
          const popular = await env.DB.prepare("SELECT 1 FROM user_flags WHERE user_id=? AND flag='popular_plugin'").bind(user.id).first();
          if (!popular) fail(403, '受信任的开发者需要拥有一个下载量超过 1,000 的插件');
        }
        const id = crypto.randomUUID();
        const nowIso = new Date().toISOString();
        try {
          await env.DB.batch([
            env.DB.prepare("INSERT INTO applications(id,user_id,kind,state,created_at) VALUES(?,?,?,'pending',?)").bind(id, user.id, kind, nowIso),
            auditEvent(env, user.id, 'application.submitted', kind)
          ]);
        } catch (error) {
          if (String(error?.message ?? error).includes('UNIQUE')) fail(409, '已有同类型的待审申请');
          throw error;
        }
        return json(env, { ok: true, id, kind, state: 'pending' }, 201);
      }
      if (path === '/auth/v1/applications/pending' && request.method === 'GET') {
        const user = await sessionUser(env, request, 'console');
        if (!user.staff) fail(403, '仅网站管理员可查看待审申请');
        const rows = await env.DB.prepare(`SELECT a.id,a.kind,a.state,a.created_at,u.id AS user_id,COALESCE(u.display_name,u.name) AS user_name,u.user_handle,
          COALESCE(ul.xp,0) AS xp, COALESCE(ul.launched,0) AS launched FROM applications a JOIN users u ON u.id=a.user_id
          LEFT JOIN user_levels ul ON ul.user_id=u.id WHERE a.state='pending' ORDER BY a.created_at LIMIT 100`).all();
        return json(env, { applications: rows.results.map(r => ({ id: r.id, kind: r.kind, createdAt: r.created_at, user: { id: r.user_id, name: r.user_name, handle: r.user_handle }, level: computeLevel(r.xp, r.launched) })) });
      }
      const reviewMatch = path.match(/^\/auth\/v1\/applications\/([0-9a-f-]{36})\/review$/);
      if (reviewMatch && request.method === 'POST') {
        const user = await sessionUser(env, request, 'console');
        if (!user.staff) fail(403, '仅网站管理员可审批');
        const input = await body(request);
        const decision = input?.decision === 'approved' ? 'approved' : input?.decision === 'rejected' ? 'rejected' : null;
        if (!decision) fail(400, 'decision 需为 approved 或 rejected');
        const note = typeof input?.note === 'string' ? input.note.slice(0, 400) : null;
        const app = await env.DB.prepare("SELECT id,user_id,kind,state FROM applications WHERE id=? AND state='pending'").bind(reviewMatch[1]).first();
        if (!app) fail(404, '申请不存在或已处理');
        if (app.user_id === user.id) fail(403, '不能审批自己的申请');
        const nowIso = new Date().toISOString();
        const statements = [
          env.DB.prepare('UPDATE applications SET state=?, note=?, reviewed_at=?, reviewer=? WHERE id=?').bind(decision, note, nowIso, user.id, app.id),
          auditEvent(env, user.id, 'application.reviewed', `${app.kind}:${decision}`)
        ];
        if (decision === 'approved') {
          if (app.kind === 'developer') statements.push(env.DB.prepare('UPDATE users SET developer=1 WHERE id=?').bind(app.user_id));
          if (app.kind === 'trusted_developer') statements.push(env.DB.prepare('UPDATE users SET trusted_developer=1 WHERE id=?').bind(app.user_id));
          if (app.kind === 'admin') statements.push(env.DB.prepare('UPDATE users SET staff=1 WHERE id=?').bind(app.user_id));
        }
        await env.DB.batch(statements);
        return json(env, { ok: true, state: decision });
      }
      if (path === '/auth/v1/mfa/factors' && request.method === 'GET') {
        const user = await sessionUser(env, request, 'console');
        const [passkeys, totpDevices, recovery, passwordRow] = await Promise.all([
          env.DB.prepare('SELECT credential_id, name, created_at, last_used_at FROM mfa_passkeys WHERE user_id=? ORDER BY created_at').bind(user.id).all(),
          env.DB.prepare('SELECT id, name, confirmed, created_at, confirmed_at FROM mfa_totp WHERE user_id=? ORDER BY created_at').bind(user.id).all(),
          env.DB.prepare('SELECT count(*) AS n FROM mfa_recovery_codes WHERE user_id=? AND used_at IS NULL').bind(user.id).first(),
          env.DB.prepare('SELECT password_set_at FROM users WHERE id=?').bind(user.id).first()
        ]);
        return json(env, {
          passwordSet: Boolean(passwordRow?.password_set_at),
          passkeys: passkeys.results.map(p => ({ credentialId: p.credential_id, name: p.name, createdAt: p.created_at, lastUsedAt: p.last_used_at })),
          totp: totpDevices.results.map(t => ({ id: t.id, name: t.name, confirmed: Boolean(t.confirmed), createdAt: t.created_at, confirmedAt: t.confirmed_at })),
          recovery: { count: recovery?.n ?? 0 }
        });
      }
      if (path === '/auth/v1/mfa/totp/enroll' && request.method === 'POST') {
        const user = await sessionUser(env, request, 'console');
        const cap = await env.DB.prepare('SELECT count(*) AS n FROM mfa_totp WHERE user_id=?').bind(user.id).first();
        if ((cap?.n ?? 0) >= 10) fail(400, '最多注册 10 个验证器');
        const id = crypto.randomUUID();
        const secret = randomSecret();
        const account = await env.DB.prepare('SELECT user_handle, COALESCE(display_name,name) AS name FROM users WHERE id=?').bind(user.id).first();
        await env.DB.prepare('INSERT INTO mfa_totp(id,user_id,secret,confirmed,created_at) VALUES(?,?,?,0,?)').bind(id, user.id, await encryptSecret(secret, env.MFA_ENC_KEY), new Date().toISOString()).run();
        return json(env, { id, secret, otpauthUrl: otpauthUrl(secret, account?.user_handle || account?.name || 'user'), expiresAt: new Date(Date.now() + 900000).toISOString() }, 201);
      }
      if (path === '/auth/v1/mfa/totp/confirm' && request.method === 'POST') {
        const user = await sessionUser(env, request, 'console');
        const input = await body(request);
        const row = await env.DB.prepare('SELECT id,secret,created_at FROM mfa_totp WHERE id=? AND user_id=? AND confirmed=0').bind(String(input?.id ?? ''), user.id).first();
        if (!row) fail(400, '请先发起注册');
        if (Date.now() - Date.parse(row.created_at) > 900000) fail(400, '注册已超时，请重新发起');
        const step = await verifyTotp(await decryptSecret(row.secret, env.MFA_ENC_KEY), String(input?.code ?? ''));
        if (step === null) fail(400, '验证码不正确');
        const name = typeof input?.name === 'string' && input.name.trim() ? input.name.trim().slice(0, 60) : null;
        await env.DB.batch([
          env.DB.prepare('UPDATE mfa_totp SET confirmed=1, confirmed_at=?, last_step=?, name=COALESCE(?,name) WHERE id=? AND user_id=?').bind(new Date().toISOString(), step, name, row.id, user.id),
          auditEvent(env, user.id, 'mfa.totp.enabled', name)
        ]);
        return json(env, { ok: true, id: row.id });
      }
      const totpDelete = path.match(/^\/auth\/v1\/mfa\/totp\/([A-Za-z0-9-]+)$/);
      if (totpDelete && request.method === 'DELETE') {
        const user = await sessionUser(env, request, 'console');
        const input = await body(request).catch(() => ({}));
        await reauthSensitive(env, user, input);
        const factors = await loadFactors(env, user.id);
        const passwordRow = await env.DB.prepare('SELECT password_set_at FROM users WHERE id=?').bind(user.id).first();
        const remaining = factors.passkeyCount + factors.recoveryCount + Math.max(0, factors.totpCount - 1);
        if (passwordRow?.password_set_at && remaining === 0) fail(400, '密码登录必须保留至少一种两步验证方式，请先注册其他方式');
        const deleted = await env.DB.prepare('DELETE FROM mfa_totp WHERE id=? AND user_id=?').bind(totpDelete[1], user.id).run();
        if (!deleted.meta.changes) fail(404, '验证器不存在');
        await auditEvent(env, user.id, 'mfa.totp.disabled', totpDelete[1]).run();
        return json(env, { ok: true });
      }
      if (path === '/auth/v1/mfa/passkey/register/options' && request.method === 'POST') {
        const user = await sessionUser(env, request, 'console');
        const account = await env.DB.prepare('SELECT user_handle, COALESCE(display_name,name) AS name FROM users WHERE id=?').bind(user.id).first();
        const existing = await env.DB.prepare('SELECT credential_id FROM mfa_passkeys WHERE user_id=?').bind(user.id).all();
        if (existing.results.length >= 10) fail(400, '最多注册 10 个 passkey');
        const challenge = await createLoginChallenge(env, user.id, 'register');
        await env.DB.prepare('UPDATE login_challenges SET wa_challenge=? WHERE challenge_hash=?').bind(challenge, digest(challenge)).run();
        return json(env, {
          challenge,
          rp: { id: RP_ID(env), name: 'Nexa Cloud' },
          user: { id: await webauthnUserId(user.id), name: account?.user_handle || account?.name || 'user', displayName: account?.name || 'user' },
          pubKeyCredParams: [{ type: 'public-key', alg: -7 }, { type: 'public-key', alg: -257 }],
          timeout: 120000,
          authenticatorSelection: { residentKey: 'preferred', userVerification: 'preferred' },
          attestation: 'none',
          excludeCredentials: existing.results.map(c => ({ type: 'public-key', id: c.credential_id }))
        });
      }
      if (path === '/auth/v1/mfa/passkey/register' && request.method === 'POST') {
        const user = await sessionUser(env, request, 'console');
        const input = await body(request, 16384);
        const row = await consumeChallenge(env, input?.challenge, 'register');
        if (!row.wa_challenge) fail(400, '请先获取注册选项');
        const attestation = input?.credential?.response ?? {};
        let result;
        try {
          result = await verifyRegistration({
            clientDataJSON: attestation.clientDataJSON, attestationObject: attestation.attestationObject,
            expectedChallenge: row.wa_challenge, expectedOrigins: webauthnOrigins(env), rpId: RP_ID(env)
          });
        } catch (error) { console.error(JSON.stringify({ webauthn: 'registration', error: error.message })); fail(400, 'passkey 校验失败'); }
        const name = typeof input?.name === 'string' && input.name.trim() ? input.name.trim().slice(0, 60) : null;
        try {
          await env.DB.batch([
            env.DB.prepare('INSERT INTO mfa_passkeys(credential_id,user_id,public_key,algorithm,sign_count,name,created_at) VALUES(?,?,?,?,?,?,?)').bind(result.credentialId, user.id, JSON.stringify(result.jwk), result.alg, result.signCount, name, new Date().toISOString()),
            auditEvent(env, user.id, 'mfa.passkey.registered', name)
          ]);
        } catch (error) {
          if (String(error?.message ?? error).includes('UNIQUE')) fail(409, '该 passkey 已注册');
          throw error;
        }
        return json(env, { ok: true, credentialId: result.credentialId, name }, 201);
      }
      const passkeyDelete = path.match(/^\/auth\/v1\/mfa\/passkey\/([A-Za-z0-9_-]+)$/);
      if (passkeyDelete && request.method === 'DELETE') {
        const user = await sessionUser(env, request, 'console');
        const input = await body(request).catch(() => ({}));
        await reauthSensitive(env, user, input);
        const factors = await loadFactors(env, user.id);
        const passwordRow = await env.DB.prepare('SELECT password_set_at FROM users WHERE id=?').bind(user.id).first();
        const stillHas = factors.passkeyCount > 1 || factors.totp || factors.recoveryCount > 0;
        if (passwordRow?.password_set_at && !stillHas) fail(400, '密码登录必须保留至少一种两步验证方式，请先注册其他方式');
        const deleted = await env.DB.prepare('DELETE FROM mfa_passkeys WHERE credential_id=? AND user_id=?').bind(passkeyDelete[1], user.id).run();
        if (!deleted.meta.changes) fail(404, 'passkey 不存在');
        await auditEvent(env, user.id, 'mfa.passkey.removed', passkeyDelete[1]).run();
        return json(env, { ok: true });
      }
      if (path === '/auth/v1/mfa/recovery/generate' && request.method === 'POST') {
        const user = await sessionUser(env, request, 'console');
        const input = await body(request).catch(() => ({}));
        await reauthSensitive(env, user, input);
        const factors = await loadFactors(env, user.id);
        if (!factors.totpCount && !factors.passkeyCount) fail(400, '请先注册 passkey 或验证器应用，再生成恢复码');
        const codes = generateRecoveryCodes(10);
        const now = new Date().toISOString();
        await env.DB.batch([
          env.DB.prepare('DELETE FROM mfa_recovery_codes WHERE user_id=? AND used_at IS NULL').bind(user.id),
          ...(await Promise.all(codes.map(async code => env.DB.prepare('INSERT INTO mfa_recovery_codes(code_hash,user_id,code_store,created_at) VALUES(?,?,?,?)').bind(hashRecoveryCode(code), user.id, await encryptSecret(code, env.MFA_ENC_KEY), now)))),
          auditEvent(env, user.id, 'mfa.recovery.generated', String(codes.length))
        ]);
        return json(env, { codes, note: '恢复码为一次性使用，可稍后在账户页复核身份后再次查看。' }, 201);
      }
      if (path === '/auth/v1/mfa/recovery/reveal' && request.method === 'POST') {
        const user = await sessionUser(env, request, 'console');
        const input = await body(request).catch(() => ({}));
        await reauthSensitive(env, user, input);
        const rows = await env.DB.prepare('SELECT code_store, used_at FROM mfa_recovery_codes WHERE user_id=? AND used_at IS NULL ORDER BY rowid').bind(user.id).all();
        const codes = [];
        for (const row of rows.results) {
          if (row.code_store === null || row.code_store === undefined) continue;
          try { codes.push(await decryptSecret(row.code_store, env.MFA_ENC_KEY)); } catch { /* 密钥变更导致不可解密的旧码跳过 */ }
        }
        await auditEvent(env, user.id, 'mfa.recovery.revealed', String(codes.length)).run();
        return json(env, { codes, missing: rows.results.length - codes.length });
      }
      if (path === '/auth/v1/policies/accept' && request.method === 'POST') {
        const user = await sessionUser(env, request, 'console');
        const [terms, privacy] = await Promise.all([currentPolicy(env, 'terms'), currentPolicy(env, 'privacy')]);
        const now = new Date().toISOString();
        await env.DB.batch([
          env.DB.prepare('INSERT OR IGNORE INTO terms_acceptances(user_id,policy_id,accepted_at) VALUES(?,?,?)').bind(user.id, terms.id, now),
          auditOnChange(env, user.id, 'terms.accepted', terms.id),
          env.DB.prepare('INSERT OR IGNORE INTO privacy_notice_receipts(user_id,policy_id,provided_at) SELECT ?,?,? WHERE changes()=1').bind(user.id, privacy.id, now)
        ]);
        return json(env, { ok: true, terms: { kind: 'terms', version: terms.version, effectiveAt: terms.effective_at, contentHash: terms.content_hash, acceptedAt: now } });
      }
      if (path === '/auth/v1/policies/status' && request.method === 'GET') {
        const user = await sessionUser(env, request, 'console');
        const rows = await env.DB.prepare(`SELECT pd.kind,pd.version,pd.effective_at AS effectiveAt,pd.content_hash AS contentHash,ta.accepted_at AS acceptedAt
          FROM policy_documents pd LEFT JOIN terms_acceptances ta ON ta.policy_id=pd.id AND ta.user_id=?
          WHERE pd.current=1 AND pd.kind IN ('terms','privacy') ORDER BY pd.kind`).bind(user.id).all();
        return json(env, { policies: rows.results });
      }
      if (path === '/auth/v1/identities' && request.method === 'GET') {
        const user = await sessionUser(env, request, 'console');
        const rows = await env.DB.prepare('SELECT provider,email,created_at FROM oauth_identities WHERE user_id=? ORDER BY created_at').bind(user.id).all();
        return json(env, { identities: rows.results });
      }
      // Minecraft 拥有状况与档案：启动器与账户页共用（绑定 Microsoft 时写入）。
      if (path === '/auth/v1/account/minecraft' && request.method === 'GET') {
        const user = await sessionUser(env, request, 'console');
        const [identity, profile] = await Promise.all([
          env.DB.prepare("SELECT 1 AS linked FROM oauth_identities WHERE user_id=? AND provider='microsoft'").bind(user.id).first(),
          env.DB.prepare('SELECT owned, profile_id, profile_name, error, checked_at FROM minecraft_profiles WHERE user_id=?').bind(user.id).first()
        ]);
        return json(env, {
          microsoftLinked: Boolean(identity),
          owned: profile?.owned ?? null,
          profileId: profile?.profile_id ?? null,
          profileName: profile?.profile_name ?? null,
          error: profile?.error ?? null,
          checkedAt: profile?.checked_at ?? null
        });
      }
      const identityMatch = path.match(/^\/auth\/v1\/identities\/(github|microsoft|google)$/);
      if (identityMatch && request.method === 'DELETE') {
        const user = await sessionUser(env, request, 'console');
        const count = await env.DB.prepare('SELECT count(*) AS n FROM oauth_identities WHERE user_id=?').bind(user.id).first();
        if ((count?.n ?? 0) <= 1) fail(400, '至少保留一个登录方式');
        await env.DB.batch([
          env.DB.prepare('DELETE FROM oauth_identities WHERE user_id=? AND provider=?').bind(user.id, identityMatch[1]),
          ...(identityMatch[1] === 'microsoft' ? [env.DB.prepare('DELETE FROM minecraft_profiles WHERE user_id=?').bind(user.id), env.DB.prepare('DELETE FROM microsoft_tokens WHERE user_id=?').bind(user.id)] : []),
          auditEvent(env, user.id, 'oauth.unlinked', identityMatch[1])
        ]);
        return json(env, { ok: true });
      }
      if (path === '/auth/v1/account/delete') {
        const user = await sessionUser(env, request, 'console');
        if (request.method === 'GET') {
          const row = await env.DB.prepare('SELECT id,state,requested_at AS requestedAt,execute_after AS executeAfter,cancelled_at AS cancelledAt,finalized_at AS finalizedAt FROM account_deletion_requests WHERE user_id=?').bind(user.id).first();
          return json(env, { request: row ?? null, cooldownDays: 7 });
        }
        if (request.method === 'POST') {
          const existing = await env.DB.prepare("SELECT id,state,requested_at AS requestedAt,execute_after AS executeAfter FROM account_deletion_requests WHERE user_id=? AND state='pending'").bind(user.id).first();
          if (existing) return json(env, { request: existing, cooldownDays: 7 });
          const now = Date.now(), executeAfter = now + 7 * 86400000, requestId = crypto.randomUUID();
          await env.DB.batch([
            env.DB.prepare("INSERT INTO account_deletion_requests(id,user_id,state,requested_at,execute_after) VALUES(?,?,'pending',?,?)").bind(requestId, user.id, new Date().toISOString(), executeAfter),
            auditEvent(env, user.id, 'account.delete.requested', requestId)
          ]);
          if (user.email) later(mailer.accountDeletionRequested(user.email, new Date(executeAfter).toISOString()));
          return json(env, { request: { id: requestId, state: 'pending', requestedAt: new Date().toISOString(), executeAfter }, cooldownDays: 7 }, 201);
        }
        if (request.method === 'DELETE') {
          const result = await env.DB.prepare("UPDATE account_deletion_requests SET state='cancelled', cancelled_at=?, version=version+1 WHERE user_id=? AND state='pending'").bind(new Date().toISOString(), user.id).run();
          if (result.meta.changes) {
            await auditEvent(env, user.id, "account.delete.cancelled", null).run();
            if (user.email) later(mailer.accountDeletionCancelled(user.email));
          }
          return json(env, { ok: true, cancelled: Boolean(result.meta.changes) });
        }
      }
      if (path === '/auth/v1/account/export' && request.method === 'GET') {
        const user = await sessionUser(env, request, 'console');
        const [identities, sessions, acceptances, deletion, privacy, mfa, minecraft] = await Promise.all([
          env.DB.prepare('SELECT provider,subject,email,created_at,updated_at FROM oauth_identities WHERE user_id=?').bind(user.id).all(),
          env.DB.prepare("SELECT scope, CASE WHEN expires>? THEN 'active' ELSE 'expired' END AS state FROM sessions WHERE user_id=?").bind(Date.now(), user.id).all(),
          env.DB.prepare('SELECT pd.kind,pd.version,ta.accepted_at AS acceptedAt FROM terms_acceptances ta JOIN policy_documents pd ON pd.id=ta.policy_id WHERE ta.user_id=?').bind(user.id).all(),
          env.DB.prepare('SELECT id,state,requested_at AS requestedAt,execute_after AS executeAfter,cancelled_at AS cancelledAt,finalized_at AS finalizedAt FROM account_deletion_requests WHERE user_id=?').bind(user.id).first(),
          env.DB.prepare('SELECT id,request_type AS type,state,created_at AS createdAt,updated_at AS updatedAt FROM privacy_requests WHERE user_id=? ORDER BY created_at').bind(user.id).all(),
          loadFactors(env, user.id),
          env.DB.prepare('SELECT owned, profile_id, profile_name, error, checked_at FROM minecraft_profiles WHERE user_id=?').bind(user.id).first()
        ]);
        return json(env, {
          profile: { id: user.id, name: user.name, email: user.email, staff: user.staff, developer: user.developer, handle: user.handle ?? null },
          identities: identities.results, activeSessions: sessions.results, policyAcceptances: acceptances.results,
          deletionRequest: deletion ?? null, privacyRequests: privacy.results,
          mfa: { factors: mfa.list, passkeys: mfa.passkeyCount, totp: mfa.totpCount, recoveryCodes: mfa.recoveryCount },
          minecraft: minecraft ? { owned: minecraft.owned, profileId: minecraft.profile_id, profileName: minecraft.profile_name, checkedAt: minecraft.checked_at } : null,
          exportedAt: new Date().toISOString()
        });
      }
      if (path === '/auth/v1/privacy-requests') {
        const user = await sessionUser(env, request, 'console');
        if (request.method === 'GET') {
          const rows = await env.DB.prepare('SELECT id,request_type AS type,state,created_at AS createdAt,updated_at AS updatedAt FROM privacy_requests WHERE user_id=? ORDER BY created_at').bind(user.id).all();
          return json(env, { requests: rows.results });
        }
        if (request.method === 'POST') {
          const input = await body(request);
          const types = ['access', 'correction', 'deletion', 'portability', 'objection', 'other'];
          if (!types.includes(input?.type)) fail(400, '无效的请求类型');
          const now = new Date().toISOString(), requestId = crypto.randomUUID();
          await env.DB.batch([
            env.DB.prepare("INSERT INTO privacy_requests(id,user_id,request_type,state,created_at,updated_at) VALUES(?,?,?,'received',?,?)").bind(requestId, user.id, input.type, now, now),
            auditEvent(env, user.id, 'privacy.request.created', input.type)
          ]);
          return json(env, { request: { id: requestId, type: input.type, state: 'received', createdAt: now, updatedAt: now } }, 201);
        }
      }
      if (path === '/auth/v1/sessions/current') {
        const scope = scopeOf(url.searchParams.get('scope'));
        if (request.method === 'GET') return json(env, { ...await sessionUser(env, request, scope), scope });
        if (request.method === 'DELETE') {
          const value = credential(request, scope);
          if (!value) fail(401, '请先登录');
          // 注销该用户当前范围的全部会话（含 auth 域 Cookie 会话），避免静默续签绕过登出。
          await env.DB.batch([
            env.DB.prepare('DELETE FROM sessions WHERE scope=? AND user_id=(SELECT user_id FROM sessions WHERE token_hash=? AND scope=?)').bind(scope, digest(value), scope),
            auditEvent(env, 'unknown', 'session.revoked', scope)
          ]);
          return new Response(null, { status: 204, headers: { 'cache-control': 'no-store', ...cors(env), 'set-cookie': `${cookieName(scope)}=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0${secure ? '; Secure' : ''}` } });
        }
        return json(env, { type: 'about:blank', title: 'Method Not Allowed', status: 405, detail: '方法不支持' }, 405, { Allow: 'GET, DELETE', 'content-type': 'application/problem+json' });
      }
      fail(404, '接口不存在');
    } catch (error) {
      if (!error.status) console.error(JSON.stringify({ requestId: id, error: error.name }));
      return json(env, { type: 'about:blank', title: 'Request failed', status: error.status || 500, detail: error.status ? error.message : '身份服务暂时不可用', instance: path, requestId: id }, error.status || 500, { 'content-type': 'application/problem+json', 'x-request-id': id });
    }
  }
};
