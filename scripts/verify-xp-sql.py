"""端到端验证 applyXpEvents 生成的 SQL 与结算逻辑。

用真实 SQLite 加载 migrations/*.sql,再用 Python 忠实复刻 src/index.mjs 中
applyXpEvents 的语句与判定顺序,检查 SQL 语法、幂等、上限、连击与毫 XP 余量。
这是本地验证脚本,不属于仓库测试套件(node --test)。
"""
import sqlite3, glob, os, math, sys

MICRO = 1000
XP_DAILY_CAP = 700 * MICRO
LEVEL_THRESHOLDS = {2: 2000, 3: 5000, 4: 10000, 5: 20000, 6: 50000, 7: 100000}
MAX_LEVEL = 7
XP_RULES = {
    'daily.login':             {'micro': 50 * MICRO,  'perDay': 'last_login_day'},
    'daily.launch':            {'micro': 30 * MICRO,  'perDay': 'last_launch_day', 'streak': True, 'setsLaunched': True},
    'game.first_launch':       {'micro': 100 * MICRO, 'once': True, 'capExempt': True, 'setsLaunched': True},
    'game.play_minutes':       {'microPerUnit': 1 * MICRO,   'unitCap': 720,  'dailyMicroCap': 480 * MICRO, 'accrue': 'game_minutes_total'},
    'launcher.online_minutes': {'microPerUnit': 0.5 * MICRO, 'unitCap': 1440, 'dailyMicroCap': 180 * MICRO, 'accrue': 'launcher_minutes_total'},
}

db = sqlite3.connect(':memory:')
db.isolation_level = None
db.row_factory = sqlite3.Row
for f in sorted(glob.glob('migrations/*.sql')):
    db.executescript(open(f, encoding='utf8').read())

db.execute("INSERT INTO users(id,name,password_hash,created_at) VALUES('u1','tester','oauth:x','2026-01-01T00:00:00Z')")


def prev_day(day):
    import datetime
    return (datetime.date.fromisoformat(day) - datetime.timedelta(days=1)).isoformat()


def next_launch_streak(last, day, cur):
    if not last:
        return 1
    if last >= day:
        return int(cur or 0)
    if last == prev_day(day):
        return int(cur or 0) + 1
    return 1


def normalize_units(rule, raw):
    if 'micro' in rule:
        return 0
    try:
        v = math.floor(float(raw))
    except (TypeError, ValueError):
        v = 0
    return max(0, min(rule['unitCap'], v))


def compute_gain(rule, units, bonus, source_room=math.inf, day_room=math.inf):
    base = rule['micro'] if 'micro' in rule else round(units * rule['microPerUnit'])
    if base <= 0:
        return 0
    mult = bonus if (isinstance(bonus, (int, float)) and bonus == bonus and bonus > 1) else 1
    gain = round(base * mult)
    if rule.get('dailyMicroCap'):
        gain = min(gain, max(0, source_room))
    if not rule.get('capExempt'):
        gain = min(gain, max(0, day_room))
    return max(0, gain)


def load_level(uid):
    r = db.execute("""SELECT xp, xp_micro, launched, first_launch_at, last_login_day, last_launch_day,
        launch_streak, launch_streak_best, game_minutes_total, launcher_minutes_total, equipped_plate
        FROM user_levels WHERE user_id=?""", (uid,)).fetchone()
    if r is None:
        return {'level': 0, 'xp': 0, 'micro': 0, 'launched': False, 'lastLoginDay': None, 'lastLaunchDay': None,
                'streak': 0, 'streakBest': 0, 'gameMinutes': 0, 'launcherMinutes': 0, 'equippedPlate': None}
    xp, launched = r['xp'], 1 if r['launched'] else 0
    lvl = 0 if not launched else 1
    if launched:
        for l in range(2, MAX_LEVEL + 1):
            if xp >= LEVEL_THRESHOLDS[l]:
                lvl = l
            else:
                break
    return {'level': lvl, 'xp': xp, 'micro': r['xp_micro'], 'launched': bool(launched),
            'lastLoginDay': r['last_login_day'], 'lastLaunchDay': r['last_launch_day'],
            'streak': r['launch_streak'], 'streakBest': r['launch_streak_best'],
            'gameMinutes': r['game_minutes_total'], 'launcherMinutes': r['launcher_minutes_total'],
            'equippedPlate': r['equipped_plate']}


def apply(uid, events, bonus=1.0):
    cur = load_level(uid)
    applied = ignored = granted = 0
    for ev in events[:100]:
        typ = str(ev.get('type', ''))
        rule = XP_RULES.get(typ)
        if not rule:
            ignored += 1
            continue
        occ = ev.get('occurredAt') or '2026-09-30T12:00:00.000Z'
        day = occ[:10]
        dedupe = ev.get('dedupeKey')
        if rule.get('once'):
            dedupe = typ
        elif rule.get('perDay'):
            dedupe = f'{typ}:{day}'
        if dedupe and db.execute('SELECT 1 FROM xp_events WHERE user_id=? AND dedupe_key=?', (uid, dedupe)).fetchone():
            ignored += 1
            continue
        units = 0
        if 'micro' in rule:
            day_used = db.execute("SELECT COALESCE(sum(amount_micro),0) AS n FROM xp_events WHERE user_id=? AND occurred_at LIKE ? || '%'", (uid, day)).fetchone()['n']
            gain = compute_gain(rule, 0, bonus, day_room=(math.inf if rule.get('capExempt') else max(0, XP_DAILY_CAP - day_used)))
        else:
            units = normalize_units(rule, ev.get('amount'))
            if units <= 0:
                ignored += 1
                continue
            src_used = db.execute("SELECT COALESCE(sum(amount_micro),0) AS n FROM xp_events WHERE user_id=? AND type=? AND occurred_at LIKE ? || '%'", (uid, typ, day)).fetchone()['n']
            day_used = db.execute("SELECT COALESCE(sum(amount_micro),0) AS n FROM xp_events WHERE user_id=? AND occurred_at LIKE ? || '%'", (uid, day)).fetchone()['n']
            gain = compute_gain(rule, units, bonus, max(0, rule['dailyMicroCap'] - src_used), max(0, XP_DAILY_CAP - day_used))
        if gain <= 0:
            ignored += 1
            continue
        sets = ['xp_micro = xp_micro + ?', 'xp = CAST((xp_micro + ?) / ? AS INTEGER)', 'updated_at = ?']
        binds = [gain, gain, MICRO, occ]
        if rule.get('setsLaunched'):
            sets += ['launched = 1', 'first_launch_at = COALESCE(first_launch_at, ?)']
            binds += [occ]
        if rule.get('accrue') and units > 0:
            sets.append(f"{rule['accrue']} = {rule['accrue']} + ?")
            binds.append(units)
        if rule.get('perDay') == 'last_login_day':
            sets.append('last_login_day = MAX(COALESCE(last_login_day, ?), ?)')
            binds += [day, day]
        if rule.get('streak'):
            s = next_launch_streak(cur['lastLaunchDay'], day, cur['streak'])
            sets += ['launch_streak = ?', 'launch_streak_best = MAX(launch_streak_best, ?)', 'last_launch_day = MAX(COALESCE(last_launch_day, ?), ?)']
            binds += [s, s, day, day]
        db.execute('BEGIN')
        db.execute('INSERT INTO user_levels(user_id,xp,xp_micro,launched,updated_at) VALUES(?,0,0,0,?) ON CONFLICT(user_id) DO NOTHING', (uid, occ))
        db.execute(f"UPDATE user_levels SET {', '.join(sets)} WHERE user_id=?", binds + [uid])
        db.execute('INSERT INTO xp_events(user_id,type,amount,amount_micro,dedupe_key,occurred_at,created_at) VALUES(?,?,?,?,?,?,?)',
                   (uid, typ, gain // MICRO, gain, dedupe, occ, occ))
        db.execute('COMMIT')
        applied += 1
        granted += gain
        cur = load_level(uid)
    return {'applied': applied, 'ignored': ignored, 'grantedXp': granted // MICRO, 'level': cur}


fails = []
def check(label, got, want):
    if got != want:
        fails.append(f'{label}: got {got!r} want {want!r}')
        print(f'  FAIL {label}: got {got!r} want {want!r}')
    else:
        print(f'  ok   {label} = {got!r}')

print('\n--- 场景 1: 正常一天 (每日登录 + 每日启动 + 60 分钟游戏 + 120 分钟在线) ---')
r = apply('u1', [
    {'type': 'daily.login', 'occurredAt': '2026-09-28T09:00:00Z'},
    {'type': 'daily.launch', 'occurredAt': '2026-09-28T09:01:00Z'},
    {'type': 'game.first_launch', 'occurredAt': '2026-09-28T09:01:00Z'},
    {'type': 'game.play_minutes', 'amount': 60, 'occurredAt': '2026-09-28T11:00:00Z'},
    {'type': 'launcher.online_minutes', 'amount': 120, 'occurredAt': '2026-09-28T12:00:00Z'},
])
check('applied', r['applied'], 5)
check('xp', r['level']['xp'], 50 + 30 + 100 + 60 + 60)
check('xp_micro 一致', r['level']['micro'], r['level']['xp'] * MICRO)
check('launched', r['level']['launched'], True)
check('level', r['level']['level'], 1)
check('streak', r['level']['streak'], 1)
check('game_minutes_total', r['level']['gameMinutes'], 60)
check('launcher_minutes_total', r['level']['launcherMinutes'], 120)

print('\n--- 场景 2: 同一批事件重放 (幂等) ---')
r = apply('u1', [
    {'type': 'daily.login', 'occurredAt': '2026-09-28T22:00:00Z'},
    {'type': 'daily.launch', 'occurredAt': '2026-09-28T22:00:00Z'},
    {'type': 'game.first_launch', 'occurredAt': '2026-09-28T22:00:00Z'},
])
check('applied', r['applied'], 0)
check('ignored', r['ignored'], 3)
check('xp 未变', r['level']['xp'], 300)
check('streak 未变', r['level']['streak'], 1)

print('\n--- 场景 3: 连续两天启动 → 连击 2; 跳过一天 → 归 1 ---')
r = apply('u1', [{'type': 'daily.launch', 'occurredAt': '2026-09-29T08:00:00Z'}])
check('day2 streak', r['level']['streak'], 2)
r = apply('u1', [{'type': 'daily.launch', 'occurredAt': '2026-09-30T08:00:00Z'}])
check('day3 streak', r['level']['streak'], 3)
check('best', r['level']['streakBest'], 3)
r = apply('u1', [{'type': 'daily.launch', 'occurredAt': '2026-10-05T08:00:00Z'}])
check('断签后 streak', r['level']['streak'], 1)
check('best 保留', r['level']['streakBest'], 3)

print('\n--- 场景 4: 旧日期补报不清零连击 ---')
r = apply('u1', [{'type': 'daily.launch', 'occurredAt': '2026-10-04T08:00:00Z'}])
check('补报昨天后 streak', r['level']['streak'], 1)
check('last_launch_day 不回退', r['level']['lastLaunchDay'], '2026-10-05')
# 回归要点:补报之后,下一次正常启动仍应基于 10-05 锚点判定。
# 若 last_launch_day 被拉回 10-04,这里会得到 1(误判断签)而不是 2。
r = apply('u1', [{'type': 'daily.launch', 'occurredAt': '2026-10-06T08:00:00Z'}])
check('补报后次日连击继续 +1', r['level']['streak'], 2)
check('best 更新', r['level']['streakBest'], 3)

print('\n--- 场景 5: 单来源日上限 (游戏 480 / 在线 180) ---')
db.execute("DELETE FROM xp_events WHERE user_id='u2'")
r = apply('u2', [{'type': 'game.play_minutes', 'amount': 720, 'occurredAt': '2026-09-28T10:00:00Z', 'dedupeKey': 'g1'},
                 {'type': 'game.play_minutes', 'amount': 720, 'occurredAt': '2026-09-28T18:00:00Z', 'dedupeKey': 'g2'}])
rows = db.execute("SELECT type, amount, amount_micro FROM xp_events WHERE user_id='u2' ORDER BY id").fetchall()
check('游戏时长入账总额(XP)', sum(x['amount'] for x in rows), 480)
check('单来源日上限生效', r['level']['xp'], 480)
r = apply('u2', [{'type': 'launcher.online_minutes', 'amount': 1440, 'occurredAt': '2026-09-29T10:00:00Z', 'dedupeKey': 'o1'}])
day2 = db.execute("SELECT COALESCE(sum(amount),0) n FROM xp_events WHERE user_id='u2' AND occurred_at LIKE '2026-09-29%'").fetchone()['n']
check('在线时长单日上限', day2, 180)

print('\n--- 场景 6: 全局日上限 700 ---')
r = apply('u3', [{'type': 'daily.login', 'occurredAt': '2026-09-28T09:00:00Z'},
                 {'type': 'daily.launch', 'occurredAt': '2026-09-28T09:00:00Z'},
                 {'type': 'game.play_minutes', 'amount': 720, 'occurredAt': '2026-09-28T10:00:00Z', 'dedupeKey': 'a'},
                 {'type': 'launcher.online_minutes', 'amount': 1440, 'occurredAt': '2026-09-28T20:00:00Z', 'dedupeKey': 'b'}])
check('当日入账 XP <= 700', r['level']['xp'] <= 700, True)
check('当日入账 XP', r['level']['xp'], 700)

print('\n--- 场景 7: 铭牌加成 ×1.75, 0.5 XP/分钟 的毫 XP 余量 ---')
r = apply('u4', [{'type': 'launcher.online_minutes', 'amount': 1, 'occurredAt': '2026-09-28T10:00:00Z', 'dedupeKey': 'm1'}], bonus=1.75)
check('1 分钟 ×1.75 → 毫 XP', db.execute("SELECT amount_micro FROM xp_events WHERE user_id='u4'").fetchone()['amount_micro'], 875)
check('整数 XP 仍为 0(余量保留)', r['level']['xp'], 0)
check('xp_micro 保留余量', r['level']['micro'], 875)
r = apply('u4', [{'type': 'launcher.online_minutes', 'amount': 7, 'occurredAt': '2026-09-28T11:00:00Z', 'dedupeKey': 'm2'}], bonus=1.75)
check('累计 8 分钟 ×1.75 = 7 XP', r['level']['xp'], 7)
check('xp_micro = 7000', r['level']['micro'], 7000)

print('\n--- 场景 8: 佩戴铭牌字段可写可读 ---')
db.execute("UPDATE user_levels SET equipped_plate='lv_infinity' WHERE user_id='u1'")
check('equipped_plate', load_level('u1')['equippedPlate'], 'lv_infinity')
db.execute("INSERT INTO user_levels(user_id,xp,xp_micro,launched,equipped_plate,updated_at) VALUES('u9',0,0,0,NULL,'2026-09-30T00:00:00Z') ON CONFLICT(user_id) DO UPDATE SET equipped_plate=excluded.equipped_plate, updated_at=excluded.updated_at")
db.execute("INSERT INTO user_levels(user_id,xp,xp_micro,launched,equipped_plate,updated_at) VALUES('u9',0,0,0,'lv_mc','2026-09-30T00:00:01Z') ON CONFLICT(user_id) DO UPDATE SET equipped_plate=excluded.equipped_plate, updated_at=excluded.updated_at")
check('装备 upsert 覆盖', db.execute("SELECT equipped_plate FROM user_levels WHERE user_id='u9'").fetchone()['equipped_plate'], 'lv_mc')

print('\n--- 场景 9: 标记白名单允许的名称可写入 ---')
for flag in ('cloud_plus_tier', 'infinity_quiz', 'bilibili_level', 'bilibili_followers', 'nexa_donation', 'popular_plugin'):
    db.execute("INSERT INTO user_flags(user_id,flag,value,set_at) VALUES('u1',?,?,'2026-09-30T00:00:00Z') ON CONFLICT(user_id,flag) DO UPDATE SET value=excluded.value, set_at=excluded.set_at", (flag, '1'))
check('写入标记数', db.execute("SELECT count(*) n FROM user_flags WHERE user_id='u1'").fetchone()['n'], 6)

print('\n' + ('ALL SQL SCENARIOS PASSED' if not fails else f'{len(fails)} FAILURES:\n' + '\n'.join(fails)))
sys.exit(1 if fails else 0)
