// 通过真实的 Worker fetch handler 验证铭牌墙接口:路由、鉴权门禁、来源校验与响应结构。
// 用极简 fake D1(按 SQL 片段匹配返回桩数据),不需要 wrangler / miniflare,保持零依赖。
import { test } from 'node:test';
import assert from 'node:assert/strict';
import worker from '../src/index.mjs';

const WEB_ORIGIN = 'https://pcln.top';

// 按 SQL 片段匹配的最小 D1 桩。未登记的语句返回空结果,足以驱动本文件覆盖的路径。
function fakeDb(routes = []) {
  const prepared = [];
  const find = sql => routes.find(([needle]) => sql.includes(needle));
  const statement = sql => ({
    bind: (...args) => {
      prepared.push({ sql, args });
      const route = find(sql);
      return {
        first: async () => (route?.[1]?.first ? route[1].first(...args) : null),
        run: async () => ({ meta: { changes: route?.[1]?.changes ?? 0 } }),
        all: async () => ({ results: route?.[1]?.all ? route[1].all(...args) : [] })
      };
    }
  });
  return { prepare: statement, batch: async statements => statements, prepared };
}

const env = (overrides = {}) => ({ WEB_ORIGIN, DB: fakeDb(), ...overrides });

async function call(path, init = {}, environment = {}) {
  const request = new Request('https://auth.pcln.top' + path, init);
  const response = await worker.fetch(request, env(environment), { waitUntil: () => {} });
  const type = response.headers.get('content-type') || '';
  return { status: response.status, body: type.includes('json') ? await response.json() : null, headers: response.headers };
}

// 浏览器写请求必须带 Origin + X-Nexa-Request,否则被来源校验拦下。
const browserInit = (method, body) => ({
  method,
  headers: { 'content-type': 'application/json', origin: WEB_ORIGIN, 'x-nexa-request': '1' },
  body: JSON.stringify(body)
});

test('GET /auth/v1/nameplates 未登录即可读取公开目录', async () => {
  const { status, body, headers } = await call('/auth/v1/nameplates');
  assert.equal(status, 200);
  assert.equal(headers.get('access-control-allow-origin'), WEB_ORIGIN);
  assert.match(headers.get('cache-control') ?? '', /max-age=/, '公开目录应可缓存');
  assert.equal(body.plates.length, 10);
  assert.equal(body.maxLevel, 7);
  assert.equal(body.dailyCap, 700);
  assert.equal(body.bonusStacking, false);
  assert.ok(body.bonusNote.includes('不叠加'));
});

test('公开目录含四档订阅铭牌与三枚可代替等级的铭牌', async () => {
  const { body } = await call('/auth/v1/nameplates');
  const byId = Object.fromEntries(body.plates.map(p => [p.id, p]));
  // 订阅:每个 Cloud+ 档位一枚,加成各不相同且递增
  const subs = body.plates.filter(p => p.kind === 'subscription');
  assert.deepEqual(subs.map(p => p.tier), ['Lite', 'Standard', 'Advanced', 'Ultimate']);
  assert.deepEqual(subs.map(p => p.xpBonus), [1.1, 1.25, 1.45, 1.75]);
  assert.ok(subs.every(p => p.replacesLevel === false), '订阅铭牌不可代替等级');
  // 可代替等级:Lv∞ / Lv-1 / LvMC
  assert.deepEqual(body.plates.filter(p => p.replacesLevel).map(p => p.id).sort(), ['lv_infinity', 'lv_mc', 'lv_minus_one']);
  assert.deepEqual(byId.lv_infinity.label, 'Lv∞');
  assert.deepEqual(byId.lv_minus_one.label, 'Lv-1');
  assert.deepEqual(byId.lv_mc.label, 'LvMC');
  assert.match(byId.lv_infinity.requirement, /Lv7/);
  assert.match(byId.lv_infinity.requirement, /∞ 答题/);
  assert.match(byId.lv_infinity.requirement, /1000 小时/);
  assert.match(byId.lv_minus_one.requirement, /网站管理员/);
  assert.match(byId.lv_mc.requirement, /连续 100 天启动 Minecraft/);
  // 不可代替等级的荣誉铭牌
  assert.equal(byId.from_bilibili.label, 'b站来的');
  assert.match(byId.from_bilibili.requirement, /Lv6/);
  assert.equal(byId.yellow_badge.label, '小黄标');
  assert.match(byId.yellow_badge.requirement, /100 万/);
  assert.equal(byId.i_like_you.label, '我喜欢你');
  assert.match(byId.i_like_you.requirement, /无偿捐献 1000\+/);
  for (const id of ['from_bilibili', 'yellow_badge', 'i_like_you']) {
    assert.equal(byId[id].replacesLevel, false, `${id} 不可代替等级`);
    assert.equal(byId[id].kind, 'badge');
  }
});

test('公开目录不泄漏运行时状态,且暴露四种经验来源', async () => {
  const { body } = await call('/auth/v1/nameplates');
  for (const plate of body.plates) {
    assert.ok(!('owned' in plate), `${plate.id} 不应含 owned`);
    assert.ok(!('progress' in plate) && !('parts' in plate));
  }
  assert.deepEqual(body.xpSources.map(s => s.type).sort(), [
    'daily.launch', 'daily.login', 'game.first_launch', 'game.play_minutes', 'launcher.online_minutes'
  ]);
  const byType = Object.fromEntries(body.xpSources.map(s => [s.type, s]));
  assert.equal(byType['daily.login'].xp, 50);
  assert.equal(byType['daily.launch'].xp, 30);
  assert.equal(byType['game.play_minutes'].xpPerMinute, 1);
  assert.equal(byType['launcher.online_minutes'].xpPerMinute, 0.5);
  assert.equal(byType['game.play_minutes'].dailyCap, 480);
  assert.equal(byType['launcher.online_minutes'].dailyCap, 180);
  assert.deepEqual(body.levels, { 2: 2000, 3: 5000, 4: 10000, 5: 20000, 6: 50000, 7: 100000 });
});

test('个人铭牌接口要求登录', async () => {
  const { status, body } = await call('/auth/v1/account/nameplates');
  assert.equal(status, 401);
  assert.match(body.detail, /登录/);
});

test('佩戴铭牌接口要求登录,且浏览器写请求校验来源', async () => {
  const unauthorized = await call('/auth/v1/account/nameplates/equip', browserInit('PUT', { plate: 'lv_infinity' }));
  assert.equal(unauthorized.status, 401);
  // 无 Origin / X-Nexa-Request 的写请求在鉴权之前就被来源校验拦下
  const badOrigin = await call('/auth/v1/account/nameplates/equip', {
    method: 'PUT', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ plate: 'lv_infinity' })
  });
  assert.equal(badOrigin.status, 403);
  assert.match(badOrigin.body.detail, /来源/);
});

test('内部通道要求 SERVICE_TOKEN', async () => {
  const xp = await call('/internal/v1/xp', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ user: 'u1', events: [] }) }, { SERVICE_TOKEN: 'secret' });
  assert.equal(xp.status, 401);
  // 未配置 SERVICE_TOKEN 时一律拒绝,避免"空令牌 == 空请求头"被放行
  const unconfigured = await call('/internal/v1/xp', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({}) });
  assert.equal(unconfigured.status, 401);
});

test('内部通道拒绝未知用户与非法 events', async () => {
  const service = { SERVICE_TOKEN: 'secret' };
  const auth = { method: 'POST', headers: { 'content-type': 'application/json', authorization: 'Bearer secret' } };
  const notFound = await call('/internal/v1/xp', { ...auth, body: JSON.stringify({ user: 'nobody', events: [{ type: 'daily.login' }] }) }, service);
  assert.equal(notFound.status, 404);

  const db = fakeDb([['SELECT id FROM users WHERE id=? OR user_handle=?', { first: () => ({ id: 'u1' }) }]]);
  const empty = await call('/internal/v1/xp', { ...auth, body: JSON.stringify({ user: 'u1', events: [] }) }, { ...service, DB: db });
  assert.equal(empty.status, 400);
  assert.match(empty.body.detail, /events/);
  const tooMany = await call('/internal/v1/xp', { ...auth, body: JSON.stringify({ user: 'u1', events: Array.from({ length: 101 }, () => ({ type: 'daily.login' })) }) }, { ...service, DB: db });
  assert.equal(tooMany.status, 400);
});

test('内部标记通道只接受白名单内的标记名', async () => {
  const db = fakeDb([['SELECT id FROM users WHERE id=? OR user_handle=?', { first: () => ({ id: 'u1' }) }]]);
  const service = { SERVICE_TOKEN: 'secret', DB: db };
  const auth = { method: 'POST', headers: { 'content-type': 'application/json', authorization: 'Bearer secret' } };
  for (const bad of ['not_a_known_flag', 'DROP TABLE', 'x', 'popular-plugin', 'BILIBILI_LEVEL']) {
    const res = await call('/internal/v1/flags', { ...auth, body: JSON.stringify({ user: 'u1', flag: bad, value: '1' }) }, service);
    assert.equal(res.status, 400, `${bad} 应被拒绝`);
    assert.match(res.body.detail, /无效的标记名/);
  }
  // 白名单内的铭牌标记可写入
  for (const good of ['cloud_plus_tier', 'infinity_quiz', 'bilibili_level', 'bilibili_followers', 'nexa_donation', 'popular_plugin']) {
    const res = await call('/internal/v1/flags', { ...auth, body: JSON.stringify({ user: 'u1', flag: good, value: '1' }) }, service);
    assert.equal(res.status, 200, `${good} 应被接受:${res.body?.detail ?? ''}`);
    assert.equal(res.body.flag, good);
  }
});

test('未知接口返回 404 且不泄漏堆栈', async () => {
  const { status, body } = await call('/auth/v1/nameplates/unknown');
  assert.equal(status, 404);
  assert.equal(body.title, 'Request failed');
  assert.ok(body.requestId, '应带 request id 便于排查');
});
