# PCL N Authentication Portal

This repository publishes the authentication entry point at
[`auth.pcln.top`](https://auth.pcln.top/).

The application source remains in
[`PCL-N-Plugin-Center-Web`](https://github.com/MuXue1230-owo/PCL-N-Plugin-Center-Web).
The Pages workflow checks out that repository, builds its production bundle,
and publishes it with the authentication custom domain.

## 账户身份与两步验证（migration 0006）

账户管理逻辑全部在本 Worker：身份绑定/解绑、注销生命周期、数据导出、隐私请求，
以及新增的用户名 / 用户 ID / 密码登录与强制 2FA。所有敏感变更写 `auth_audit` 并触发安全邮件。

### 用户名与用户 ID

- `PATCH /auth/v1/account/name` — 修改用户名（展示名，1–60 字符，剔除控制符）。
- `PUT /auth/v1/account/handle` — 设置 / 修改用户 ID（类微信号：6–20 位、字母开头、
  `[a-z0-9_-]`、大小写不敏感、全库唯一、保留名单拦截；修改后 30 天冷却，409 表示被占用）。
- `GET /auth/v1/account/handle/availability?handle=` — 登录后可查询占用情况。

### 密码与强制 2FA

- `POST /auth/v1/account/password` — 设置 / 修改密码（scrypt N=32768；修改需 `currentPassword`）。
  设置密码后，密码登录**强制**两步验证：未注册任何 2FA 因子时登录返回
  `403 mfa_enrollment_required`，需先经第三方登录注册因子。
- `POST /auth/v1/login` `{handle,password}` — 第一段。限流：每 ID 10 次/15 分钟、
  每 IP 30 次/15 分钟；用户 ID 不存在时也执行等时 scrypt。成功返回 5 分钟一次性
  `challenge` 与可用 `factors`（passkey/totp/recovery）。
- `POST /auth/v1/login/passkey/options` → `POST /auth/v1/login/passkey` — WebAuthn 断言
  （ES256/RS256，rpId 默认 `pcln.top`，origin 白名单，签名计数器防克隆）。
- `POST /auth/v1/login/totp` `{challenge,code}` — 验证器 6 位码（±1 步窗口 + 步数防重放），
  同端点接受一次性恢复码（用后作废并返回剩余数量）。
- 登录成功签发与 OAuth 相同的 `nexa_console` 会话 Cookie。

### 2FA 因子管理（需登录）

- `GET /auth/v1/mfa/factors` — 因子清单（passkey 列表 / TOTP 设备列表 / 恢复码余量 / 是否已设密码）。
- `POST /auth/v1/mfa/totp/enroll` → `confirm {id,code,name?}` — 注册验证器应用，**支持多设备**
  （每账户至多 10 个，各自命名、独立停用；secret 可选 `MFA_ENC_KEY` AES-GCM 静态加密；
  15 分钟未确认由 cron 清理）。确认时记录时间步，同一窗口的码不可重放。
- `POST /auth/v1/mfa/passkey/register/options` → `register` — 注册 passkey（attestation
  'none'，每账户至多 10 个）。
- `POST /auth/v1/mfa/recovery/generate` — 重新生成 10 个一次性恢复码（要求已有 passkey 或 TOTP）。
  登录核销仅依据 SHA-256 哈希；同时保存可解密副本（`MFA_ENC_KEY` AES-GCM），供账户主复核后查看。
- `POST /auth/v1/mfa/recovery/reveal` — 身份复核后返回未使用的恢复码明文（用于查看/打印），写审计。
- `DELETE /auth/v1/mfa/totp/:id`、`DELETE /auth/v1/mfa/passkey/:credentialId` — 移除单个因子；
  已设密码时要求复核当前密码，且必须保留至少一种因子。

部署顺序：先 `wrangler d1 migrations apply pcln-production --remote`，再 `wrangler deploy`。
本地开发 `pnpm dev`（端口 5733，与 Web 仓库 vite 代理一致）；单元测试 `pnpm test`（零依赖，
覆盖 RFC 6238 向量、CBOR 往返、真实 P-256 密钥的 WebAuthn 注册/断言全流程）。

## Microsoft 绑定 → Xbox → Minecraft 档案（migration 0008）

- Microsoft **绑定（link）模式**额外请求 `XboxLive.signin`；普通登录保持最小 scope。
- 绑定成功后服务端执行 XBL → XSTS → `entitlements/mcstore` → `minecraft/profile` 链路，
  将拥有状况与档案（UUID/名称）写入 `minecraft_profiles`；不存储任何 Xbox/MC 令牌。
  链路失败不阻塞绑定，错误码记入 `error` 字段并写审计（`minecraft.checked`）。
- `GET /auth/v1/account/minecraft` — 账户页与启动器共用读取端点；解绑 Microsoft 时级联清除。

## 注册与 Microsoft 令牌保管（migration 0009）

- **注册必须经第三方身份验证**（GitHub / Google / Microsoft）。OAuth 首登创建的账户
  `confirmed_at` 为空（未激活），回调后强制重定向 `/register?setup=1` 完善资料；
  24 小时未完善的账户由 cron 级联清理。会话响应携带 `setupRequired` 标记。
- `POST /auth/v1/register/complete` `{name,handle,password?,totpId?,totpCode?}` —
  仅未激活账户可用：设置用户名与用户 ID（唯一性校验、回收他人废弃同名注册）；
  **设置密码时必须同时完成验证器绑定**（密码 ⇔ 2FA 不变量），成功后账户激活。
  不提供纯密码直连注册。
- Microsoft 绑定追加 `offline_access`：刷新令牌以 AES-GCM（`TOKEN_ENC_KEY`）加密存入
  `microsoft_tokens`；未配置密钥则拒绝落盘。解绑与注销级联清除。
- `POST /auth/v1/minecraft/token` — 启动器端点：用保管的刷新令牌重新派生 XSTS，
  实时返回 Minecraft 短时令牌与档案（不存令牌本体），限流 10 次/小时，写审计。

## 等级与经验系统（migration 0010 / 0011）

- **Lv0~7**：Lv0→1 需启动一次游戏（`game.first_launch`，一次性）；Lv2~7 按累计经验
  **2k / 5k / 10k / 20k / 50k / 100k**。等级由服务端按 `xp + launched` 实时计算，不存冗余字段。

### 加经验方式（migration 0011 重写）

经验来源收敛为**四种日常行为 + 一次性首启**，全部由**启动器上报事件**，数值由 Worker 权威决定
——客户端只能声明「发生了什么、持续了多少分钟」，**不能自行声明这值多少经验**：

| 事件 `type` | 含义 | 数值 | 单日上限 |
| --- | --- | --- | --- |
| `daily.login` | 每日登录 | +50 XP / UTC 日 | 每日一次 |
| `daily.launch` | 每日启动 | +30 XP / UTC 日，并推进连续启动天数 | 每日一次 |
| `game.play_minutes` | 游戏时长 | 1 XP / 分钟（`amount` = 分钟数） | 480 XP（8 小时） |
| `launcher.online_minutes` | Nexa 在线时长（启动器挂机，未启动 MC） | 0.5 XP / 分钟 | 180 XP（6 小时） |
| `game.first_launch` | 首次启动 | +100 XP，一次性 | 豁免日上限 |

- **全局日上限 700 XP**（按「事件发生日」计，历史补报不占今天的额度）。各来源上限之和为 740，
  全局上限是最后一道兜底。
- **毫 XP 结算**：`user_levels.xp_micro` 是权威累计值，`xp = floor(xp_micro / 1000)` 为派生整数。
  这样 0.5 XP/分钟这类小数速率在逐次上报时不会丢余量（1 分钟 ×1.75 加成 = 875 毫 XP，攒够才进位）。
- **幂等**：一次性事件的键为类型本身；每日事件的键由**服务端**按 `type:YYYY-MM-DD`（UTC）生成，
  客户端无法伪造重复领取；时长类事件沿用调用方 `dedupeKey`。均受 `xp_events(user_id, dedupe_key)`
  唯一索引保护，重放同一批事件不会重复计分。
- **连续启动天数**：`launch_streak`（当前）/ `launch_streak_best`（历史最长）/ `last_launch_day`。
  锚点**只前进不回退**，旧日期补报既不会增长也不会清零连击。
- `daily.login` 亦可由本站真实登录成功点写入（第三方回调 / passkey / 验证器码），与启动器上报
  共用同一幂等键，两条通道不会重复计分。`POST /auth/v1/tokens` 是既有 Cookie 会话换取内存令牌
  （每次刷新页面都会调用），**不算登录**，故不在那里写入。

### 铭牌墙（migration 0011）

铭牌**不单独存储授予记录**，全部由真实信号实时派生（`src/nameplates.mjs`）：
等级 / 连续启动 / 累计时长 / `user_flags` / `users.staff`。这样铭牌永远不会与账户实际状态漂移，
也不需要「补发 / 回收」的后台流程。唯一持久化的状态是 `user_levels.equipped_plate`（佩戴中的铭牌）。

**订阅铭牌**（每个 Cloud+ 档位一枚，各自带经验加成）：

| 铭牌 | 条件 | 经验加成 |
| --- | --- | --- |
| Cloud+ Lite | 订阅 Lite 或更高档位 | ×1.10 |
| Cloud+ Standard | 订阅 Standard 或更高档位 | ×1.25 |
| Cloud+ Advanced | 订阅 Advanced 或更高档位 | ×1.45 |
| Cloud+ Ultimate | 订阅 Ultimate 档位 | ×1.75 |

**可代替等级的铭牌**（佩戴后可只显示铭牌、隐藏 Lv 数字）：

| 铭牌 | 条件 | 经验加成 | 撤销 |
| --- | --- | --- | --- |
| **Lv∞** | 达到 Lv7 + 通过 ∞ 答题 + MC 累计时长 > 1000 小时 | ×2.00 | 永久 |
| **Lv-1** | 成为网站管理员 | ×1.50 | 随管理员身份收回 |
| **LvMC** | 连续 100 天启动 Minecraft（按历史最长连击） | ×1.60 | 断签不撤销 |

**不可代替等级的荣誉铭牌**（与等级并列展示）：

| 铭牌 | 条件 | 经验加成 |
| --- | --- | --- |
| b站来的 | 在 Bilibili 达到 Lv6 | ×1.05 |
| 小黄标 | Bilibili 粉丝 > 100 万 | ×1.15 |
| 我喜欢你 | 为 Nexa 无偿捐献 1000+ | ×1.30 |

- **加成不叠加**：取已拥有铭牌中的最高倍率（当前上限 Lv∞ ×2.0）。叠加会让高阶订阅 + 全部荣誉
  铭牌的用户达到 5 倍以上，经验曲线失控。开关见 `PLATE_BONUS_STACKING`。
- **加成先于上限套用**：`基础值 → ×加成 → 单来源日上限 → 全局日上限`，因此加成永远无法突破日上限。
- 需人工核验的铭牌由运营侧写入标记（附证据）：`bilibili_level`、`bilibili_followers`、
  `nexa_donation`、`infinity_quiz`；订阅档位由计费侧写入 `cloud_plus_tier`（退订时传
  `value: null` 清除）。`POST /internal/v1/flags` 的标记名已改为白名单校验（`FLAG_ALLOWLIST`），
  不再接受任意自定义名称——这些标记直接驱动铭牌与资格判定。

### 接口

- **内部通道**（`SERVICE_TOKEN` Bearer 鉴权，豁免浏览器 Origin 检查，供 nexa-api/遥测管道调用）：
  - `POST /internal/v1/xp` `{user, events:[{type, amount?, dedupeKey?, occurredAt?}]}`
    → `{applied, ignored, grantedXp, bonus, xp, level, acceptedTypes}`
  - `POST /internal/v1/flags` `{user, flag, value}` — `value: null` 表示清除标记
- **公开**：`GET /auth/v1/nameplates` — 铭牌墙目录（未登录可读，`cache-control: max-age=300`），
  含 `plates` / `levels` / `xpSources` / `dailyCap` / `bonusNote`。前端 `/nameplates` 页面直接渲染。
- **用户端**：
  - `GET /auth/v1/account/level` — 等级/经验/下一级进度/角色/资格达成情况/我的申请，
    外加 `xpSources`（含 `claimedToday`）、`dailyCap`、`thresholds`、`streak` / `streakBest` /
    `lastLaunchDay`、`gameMinutes` / `launcherMinutes`、`nameplates`（全部铭牌 + 未达成进度
    + 生效加成 + 佩戴状态）。字段保持扁平，不再包同名对象以免覆盖数值。
  - `GET /auth/v1/account/nameplates` — 我的铭牌、`bonus`、`equipped`、`hidesLevel`、`displayLevel`。
  - `PUT /auth/v1/account/nameplates/equip` `{plate}` — 佩戴 / 卸下（`plate: null`）；
    未达成的铭牌返回 403。会话与 `/tokens` 响应也携带 `level`、`xp`、`trustedDeveloper`。
- **资格申请**（`POST /auth/v1/applications`）：developer 需 Lv2；trusted_developer 需
  developer + Lv3 + `popular_plugin` 标记；admin 需 Lv4。同类 pending 唯一；已具备角色 409。
- **审批**（staff）：`GET /applications/pending`、`POST /applications/:id/review {decision,note}`；
  不能审批自己的申请；批准即写 `users.developer / trusted_developer / staff`，全程审计。

### 测试

- `pnpm test`（零依赖）：`tests/nameplates.test.mjs` 覆盖铭牌派生全部分支（订阅档位累积、
  非法档位、Lv∞ 三条件、Lv-1 随身份收回、LvMC 断签不撤销、B 站阈值边界、加成取最高不叠加）；
  `tests/xp.test.mjs` 覆盖经验结算（来源清单、定额/时长数值、单位归一、加成、单来源与全局上限、
  连击跨月跨年与补报边界、等级判定、目录与规则一致性）。
- `python3 scripts/verify-xp-sql.py`（本地验证脚本，非 CI）：用真实 SQLite 加载全部 migration，
  复刻 `applyXpEvents` 的语句与判定顺序，端到端验证 SQL 语法、幂等重放、上限削减、毫 XP 余量
  与连击锚点不回退。

