import { randomBytes } from 'node:crypto';
import { digest, hashPassword, verifyPassword } from './password.mjs';
import { createMailer } from './mailer.mjs';
import { validateHandle, validateDisplayName, normalizeHandle, isReservedHandle, HANDLE_COOLDOWN_DAYS } from './handles.mjs';
import { randomSecret, otpauthUrl, verifyTotp, encryptSecret, decryptSecret } from './totp.mjs';
import { generateRecoveryCodes, hashRecoveryCode } from './recovery.mjs';
import { verifyRegistration, verifyAssertion, webauthnUserId } from './webauthn.mjs';
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
const oauthError = (env, detail) => Response.redirect(`${env.WEB_ORIGIN}/account?oauth_error=${encodeURIComponent(detail)}`, 303);
const auditEvent = (env, actor, action, detail) => env.DB.prepare('INSERT INTO auth_audit(actor,action,created_at,detail) VALUES(?,?,?,?)').bind(actor, action, new Date().toISOString(), detail ?? null);
// 仅在前一条语句（INSERT OR IGNORE）实际写入时记录，用于条款首次接受等幂等事件。
const auditOnChange = (env, actor, action, detail) => env.DB.prepare('INSERT INTO auth_audit(actor,action,created_at,detail) SELECT ?,?,?,? WHERE changes()=1').bind(actor, action, new Date().toISOString(), detail ?? null);
// ---------- 账户身份与 MFA 基础设施 ----------
const RP_ID = env => env.RP_ID || (env.LOCAL_DEV === 'true' ? 'localhost' : 'pcln.top');
const webauthnOrigins = env => [env.WEB_ORIGIN, 'https://auth.pcln.top', ...(env.LOCAL_DEV === 'true' ? ['http://127.0.0.1:5730', 'http://localhost:5730'] : [])].filter(Boolean);
const clientIp = request => request.headers.get('cf-connecting-ip') || 'unknown';
const hasRealPassword = hash => Boolean(hash) && !hash.startsWith('oauth:') && !hash.startsWith('system:');
async function rateLimit(env, key, limit, windowMs, message) {
  const now = Date.now();
  const row = await env.DB.prepare('INSERT INTO rate_limits(key,count,expires) VALUES(?,1,?) ON CONFLICT(key) DO UPDATE SET count=CASE WHEN expires<=? THEN 1 ELSE count+1 END,expires=CASE WHEN expires<=? THEN excluded.expires ELSE expires END RETURNING count').bind(key, now + windowMs, now, now).first();
  if (row.count > limit) fail(429, message);
}
async function loadFactors(env, userId) {
  const [totp, passkeys, recovery] = await Promise.all([
    env.DB.prepare('SELECT secret, confirmed, last_step FROM mfa_totp WHERE user_id=? AND confirmed=1').bind(userId).first(),
    env.DB.prepare('SELECT count(*) AS n FROM mfa_passkeys WHERE user_id=?').bind(userId).first(),
    env.DB.prepare('SELECT count(*) AS n FROM mfa_recovery_codes WHERE user_id=? AND used_at IS NULL').bind(userId).first()
  ]);
  return {
    totp: totp ?? null,
    passkeyCount: passkeys?.n ?? 0,
    recoveryCount: recovery?.n ?? 0,
    list: [...(passkeys?.n ? ['passkey'] : []), ...(totp ? ['totp'] : []), ...(recovery?.n ? ['recovery'] : [])]
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
  const user = await env.DB.prepare(`SELECT u.id,COALESCE(u.display_name,u.name) AS name,u.email,u.staff,u.developer,u.user_handle AS handle,
    EXISTS(SELECT 1 FROM terms_acceptances ta JOIN policy_documents pd ON pd.id=ta.policy_id AND pd.kind='terms' AND pd.current=1 WHERE ta.user_id=u.id) AS termsAccepted
    FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token_hash=? AND s.scope=? AND s.expires>? AND u.disabled=0 AND (?=0 OR u.staff=1)`).bind(digest(value), scope, Date.now(), scope === 'operations' ? 1 : 0).first();
  if (!user) fail(401, '请先登录');
  return user;
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
  authorize.searchParams.set('scope', config.scope); authorize.searchParams.set('nonce', nonce);
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
      user = await env.DB.prepare('SELECT id,name,disabled FROM users WHERE id=?').bind(identity.user_id).first();
    } else {
      const id = crypto.randomUUID(), name = `${provider}:${subject}`;
      await env.DB.batch([
        env.DB.prepare("INSERT INTO users(id,name,password_hash,display_name,email) VALUES(?,?,?,?,?)").bind(id, name, `oauth:${randomBytes(32).toString('hex')}`, displayName, email),
        env.DB.prepare('INSERT INTO oauth_identities(provider,subject,user_id,email,created_at,updated_at) VALUES(?,?,?,?,?,?)').bind(provider, subject, id, email, new Date().toISOString(), new Date().toISOString())
      ]);
      user = { id, name, disabled: 0 };
    }
    if (!user || user.disabled) throw new Error('account disabled');
    await env.DB.prepare('UPDATE oauth_identities SET email=?,updated_at=? WHERE provider=? AND subject=?').bind(email, new Date().toISOString(), provider, subject).run();
    const headers = new Headers({ location: new URL(stateRow.return_to, env.WEB_ORIGIN).toString(), 'cache-control': 'no-store' });
    headers.append('set-cookie', `${oauthStateCookie}=; HttpOnly; SameSite=Lax; Path=/auth/v1/oauth; Max-Age=0${secure ? '; Secure' : ''}`);
    if (stateRow.user_id) return new Response(null, { status: 303, headers });
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
    return new Response(null, { status: 303, headers });
  } catch (error) { console.error(JSON.stringify({ oauth: provider, error: error.name })); return oauthError(env, '第三方登录失败，请重试'); }
}
export async function finalizeAccountDeletion(env, requestId, userId) {
  const now = new Date().toISOString();
  await env.DB.batch([
    env.DB.prepare('DELETE FROM sessions WHERE user_id=?').bind(userId),
    env.DB.prepare('DELETE FROM oauth_identities WHERE user_id=?').bind(userId),
    env.DB.prepare('DELETE FROM oauth_states WHERE user_id=?').bind(userId),
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
    env.DB.prepare('DELETE FROM mfa_totp WHERE confirmed=0 AND created_at<?').bind(new Date(now - 900000).toISOString())
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
      if (!['GET', 'HEAD'].includes(request.method) && (request.headers.get('origin') !== env.WEB_ORIGIN || request.headers.get('x-nexa-request') !== '1')) fail(403, '请求来源无效');
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
        return json(env, { ok: true, user: { id: user.id, name: user.name } }, 200, { 'set-cookie': session.cookie });
      }
      if (path === '/auth/v1/login/totp' && request.method === 'POST') {
        const input = await body(request);
        const row = await consumeChallenge(env, input?.challenge, 'login');
        const user = await env.DB.prepare('SELECT id, COALESCE(display_name,name) AS name, disabled FROM users WHERE id=?').bind(row.user_id).first();
        if (!user || user.disabled) fail(403, '账户已被停用');
        const code = String(input?.code ?? '');
        let method = null, recoveryRemaining;
        const totpRow = await env.DB.prepare('SELECT secret, last_step FROM mfa_totp WHERE user_id=? AND confirmed=1').bind(row.user_id).first();
        if (totpRow) {
          const step = await verifyTotp(await decryptSecret(totpRow.secret, env.MFA_ENC_KEY), code, Date.now(), totpRow.last_step);
          if (step !== null) { method = 'totp'; await env.DB.prepare('UPDATE mfa_totp SET last_step=? WHERE user_id=?').bind(step, row.user_id).run(); }
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
        await auditEvent(env, row.user_id, 'login.' + method, recoveryRemaining !== undefined ? `remaining:${recoveryRemaining}` : null).run();
        const session = await createSession(env, user, 'console', Date.now(), secure);
        return json(env, { ok: true, method, ...(recoveryRemaining !== undefined ? { recovery: { remaining: recoveryRemaining } } : {}), user: { id: user.id, name: user.name } }, 200, { 'set-cookie': session.cookie });
      }
      // ---------- 2FA 因子管理 ----------
      if (path === '/auth/v1/mfa/factors' && request.method === 'GET') {
        const user = await sessionUser(env, request, 'console');
        const [passkeys, totp, recovery, passwordRow] = await Promise.all([
          env.DB.prepare('SELECT credential_id, name, created_at, last_used_at FROM mfa_passkeys WHERE user_id=? ORDER BY created_at').bind(user.id).all(),
          env.DB.prepare('SELECT confirmed, created_at, confirmed_at FROM mfa_totp WHERE user_id=?').bind(user.id).first(),
          env.DB.prepare('SELECT count(*) AS n FROM mfa_recovery_codes WHERE user_id=? AND used_at IS NULL').bind(user.id).first(),
          env.DB.prepare('SELECT password_set_at FROM users WHERE id=?').bind(user.id).first()
        ]);
        return json(env, {
          passwordSet: Boolean(passwordRow?.password_set_at),
          passkeys: passkeys.results.map(p => ({ credentialId: p.credential_id, name: p.name, createdAt: p.created_at, lastUsedAt: p.last_used_at })),
          totp: totp ? { confirmed: Boolean(totp.confirmed), createdAt: totp.created_at, confirmedAt: totp.confirmed_at } : null,
          recovery: { count: recovery?.n ?? 0 }
        });
      }
      if (path === '/auth/v1/mfa/totp/enroll' && request.method === 'POST') {
        const user = await sessionUser(env, request, 'console');
        const secret = randomSecret();
        const account = await env.DB.prepare('SELECT user_handle, COALESCE(display_name,name) AS name FROM users WHERE id=?').bind(user.id).first();
        await env.DB.prepare('INSERT INTO mfa_totp(user_id,secret,confirmed,created_at) VALUES(?,?,0,?) ON CONFLICT(user_id) DO UPDATE SET secret=excluded.secret, confirmed=0, last_step=NULL, created_at=excluded.created_at, confirmed_at=NULL').bind(user.id, await encryptSecret(secret, env.MFA_ENC_KEY), new Date().toISOString()).run();
        return json(env, { secret, otpauthUrl: otpauthUrl(secret, account?.user_handle || account?.name || 'user'), expiresAt: new Date(Date.now() + 900000).toISOString() }, 201);
      }
      if (path === '/auth/v1/mfa/totp/confirm' && request.method === 'POST') {
        const user = await sessionUser(env, request, 'console');
        const input = await body(request);
        const row = await env.DB.prepare('SELECT secret, created_at FROM mfa_totp WHERE user_id=? AND confirmed=0').bind(user.id).first();
        if (!row) fail(400, '请先发起注册');
        if (Date.now() - Date.parse(row.created_at) > 900000) fail(400, '注册已超时，请重新发起');
        const step = await verifyTotp(await decryptSecret(row.secret, env.MFA_ENC_KEY), String(input?.code ?? ''));
        if (step === null) fail(400, '验证码不正确');
        await env.DB.batch([
          env.DB.prepare('UPDATE mfa_totp SET confirmed=1, confirmed_at=?, last_step=? WHERE user_id=?').bind(new Date().toISOString(), step, user.id),
          auditEvent(env, user.id, 'mfa.totp.enabled', null)
        ]);
        return json(env, { ok: true });
      }
      if (path === '/auth/v1/mfa/totp' && request.method === 'DELETE') {
        const user = await sessionUser(env, request, 'console');
        const input = await body(request).catch(() => ({}));
        await reauthSensitive(env, user, input);
        const factors = await loadFactors(env, user.id);
        const passwordRow = await env.DB.prepare('SELECT password_set_at FROM users WHERE id=?').bind(user.id).first();
        if (passwordRow?.password_set_at && !factors.passkeyCount && !factors.recoveryCount) fail(400, '密码登录必须保留至少一种两步验证方式，请先注册其他方式');
        await env.DB.batch([env.DB.prepare('DELETE FROM mfa_totp WHERE user_id=?').bind(user.id), auditEvent(env, user.id, 'mfa.totp.disabled', null)]);
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
        if (!factors.totp && !factors.passkeyCount) fail(400, '请先注册 passkey 或验证器应用，再生成恢复码');
        const codes = generateRecoveryCodes(10);
        const now = new Date().toISOString();
        await env.DB.batch([
          env.DB.prepare('DELETE FROM mfa_recovery_codes WHERE user_id=? AND used_at IS NULL').bind(user.id),
          ...codes.map(code => env.DB.prepare('INSERT INTO mfa_recovery_codes(code_hash,user_id,created_at) VALUES(?,?,?)').bind(hashRecoveryCode(code), user.id, now)),
          auditEvent(env, user.id, 'mfa.recovery.generated', String(codes.length))
        ]);
        return json(env, { codes, note: '恢复码为一次性使用，仅此一次完整展示，请立即妥善保存。' }, 201);
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
      const identityMatch = path.match(/^\/auth\/v1\/identities\/(github|microsoft|google)$/);
      if (identityMatch && request.method === 'DELETE') {
        const user = await sessionUser(env, request, 'console');
        const count = await env.DB.prepare('SELECT count(*) AS n FROM oauth_identities WHERE user_id=?').bind(user.id).first();
        if ((count?.n ?? 0) <= 1) fail(400, '至少保留一个登录方式');
        await env.DB.batch([
          env.DB.prepare('DELETE FROM oauth_identities WHERE user_id=? AND provider=?').bind(user.id, identityMatch[1]),
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
        const [identities, sessions, acceptances, deletion, privacy, mfa] = await Promise.all([
          env.DB.prepare('SELECT provider,subject,email,created_at,updated_at FROM oauth_identities WHERE user_id=?').bind(user.id).all(),
          env.DB.prepare("SELECT scope, CASE WHEN expires>? THEN 'active' ELSE 'expired' END AS state FROM sessions WHERE user_id=?").bind(Date.now(), user.id).all(),
          env.DB.prepare('SELECT pd.kind,pd.version,ta.accepted_at AS acceptedAt FROM terms_acceptances ta JOIN policy_documents pd ON pd.id=ta.policy_id WHERE ta.user_id=?').bind(user.id).all(),
          env.DB.prepare('SELECT id,state,requested_at AS requestedAt,execute_after AS executeAfter,cancelled_at AS cancelledAt,finalized_at AS finalizedAt FROM account_deletion_requests WHERE user_id=?').bind(user.id).first(),
          env.DB.prepare('SELECT id,request_type AS type,state,created_at AS createdAt,updated_at AS updatedAt FROM privacy_requests WHERE user_id=? ORDER BY created_at').bind(user.id).all(),
          loadFactors(env, user.id)
        ]);
        return json(env, {
          profile: { id: user.id, name: user.name, email: user.email, staff: user.staff, developer: user.developer, handle: user.handle ?? null },
          identities: identities.results, activeSessions: sessions.results, policyAcceptances: acceptances.results,
          deletionRequest: deletion ?? null, privacyRequests: privacy.results,
          mfa: { factors: mfa.list, passkeys: mfa.passkeyCount, totp: Boolean(mfa.totp), recoveryCodes: mfa.recoveryCount },
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
