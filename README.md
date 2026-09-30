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

## 等级与经验系统（migration 0010）

- **Lv0~7**：Lv0→1 需启动一次游戏（`game.first_launch`，一次性）；Lv2~7 按累计经验
  **2k / 5k / 10k / 20k / 50k / 100k**。等级由服务端按 `xp + launched` 实时计算，不存冗余字段。
- 经验事件（`XP_RULES` 可调）：首启 +100、游戏启动 +10、游玩每分钟 +1、完成安装 +20、资源下载 +5；
  每用户每“事件发生日”上限 500（首启豁免），`dedupeKey` 幂等防重放。
- **内部通道**（`SERVICE_TOKEN` Bearer 鉴权，豁免浏览器 Origin 检查，供 nexa-api/遥测管道调用）：
  - `POST /internal/v1/xp` `{user, events:[{type, amount?, dedupeKey?, occurredAt?}]}`
  - `POST /internal/v1/flags` `{user, flag, value}` — 如商店侧写入 `popular_plugin`（下载量>1k 证据）
- 用户端 `GET /auth/v1/account/level` — 等级/经验/下一级进度/角色/资格达成情况/我的申请；
  会话与 `/tokens` 响应也携带 `level`、`xp`、`trustedDeveloper`。
- **资格申请**（`POST /auth/v1/applications`）：developer 需 Lv2；trusted_developer 需
  developer + Lv3 + `popular_plugin` 标记；admin 需 Lv4。同类 pending 唯一；已具备角色 409。
- **审批**（staff）：`GET /applications/pending`、`POST /applications/:id/review {decision,note}`；
  不能审批自己的申请；批准即写 `users.developer / trusted_developer / staff`，全程审计。
