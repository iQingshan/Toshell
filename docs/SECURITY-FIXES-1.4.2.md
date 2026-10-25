# v1.4.2 安全修复说明（对外版）

> 本文件说明 **2026-10-24 第三方安全审计**所发现问题的修复情况与**残余风险**。
> 原始审计报告含逐步可复制的攻击步骤与测试机地址，**不随仓库分发**（已在 `.gitignore`）。
> 修复的逐条判定与复审计结论见 [`SECURITY-REAUDIT-1.4.2.md`](SECURITY-REAUDIT-1.4.2.md)。
> 适用版本：**v1.4.2 及以后**；v1.4.1 及以前**受影响**。

---

## 1. 结论

- 审计未发现**未认证 RCE** 或**认证绕过**；管理路由（除登录/健康检查与植入端兼容端点外）均要求凭据。
- 已修复 **4 个 High + 9 个 Medium + 3 个 Low**；修复后逐条回放审计 PoC，**21 条用例全部被拒（0 通过）**；随后第三方复审计（见 `SECURITY-REAUDIT-1.4.2.md`）在此基础上又挖出 7 项残留（下文 §2.6 已一并修掉 5 项，另 2 项属设计与部署边界）。
- 仍有 **1 个设计层风险（M3）未修复**，见 §4 —— 它决定了"载荷样本"的敏感级别，请务必读。

## 2. 修了什么（按影响排序）

### 2.1 认证后任意文件读 / 写 / 删（H2 / H3 / H4 / M9）

四条的根因是同一类：**用户可控字符串直接进了路径拼接**，而 `filepath.Join` 只做词法 `Clean`、不构成"基目录边界"。

- 统一收敛到 `internal/server/api/safe_path.go`：
  - `safePayloadName`：载荷名只允许 `[A-Za-z0-9._-]`，1..64 字节，必须等于自身的 `Base`；
  - `resolveInDir`：`Join` → `Abs` → `Rel(dir, p)` 前缀断言；目标存在时再做一次 `EvalSymlinks` 后断言（软链逃逸）。
- 载荷下载的后缀只来自固定白名单（`exe/dll/bin/txt/raw/so`），`format` 不再直接当后缀用。
- `serveStoredImplant` 的每个候选路径都过 `resolveInDir`；历史脏数据不再能把下载导向目录外。
- 插件（MCP `plugin_upload` 与 multipart 上传）增加四道防线：名字白名单 → `Rel` 断言 → `EvalSymlinks(pluginDir)` 真实根 + `Lstat` 拒同名软链（fail-closed）→ 同目录临时文件 + `rename` 覆盖（与链接类型无关，硬链接也只会被替换、不会被写穿）。`scanPlugins` 同步只登记普通文件。
  - multipart 上传**自行**从 `Content-Disposition` 取原始文件名：Go 标准库的 `Part.FileName()` 会先做 `filepath.Base`，会把 `../x.exe` 静默归一成 `x.exe`，丢失穿越信号。

### 2.2 未认证可操纵会话与任务（H1 / M1 / M2）

- `/api/v1/implant/{register,heartbeat,result}` 是历史兼容端点，**真实植入端并不使用**（它只用 `payload/` 与 `uac/`）。现已：
  - 挂上与管理 API 相同的认证（`X-API-Key` / `Bearer`）；
  - 请求体必须显式给 `SessionID`；
  - **任务结果必须校验归属**（`task.CompleteForSession/FailForSession`），跨会话伪造返回 403；
  - 心跳只能更新自己那条会话；dead/离线会话返回 409 且**零写入**（`LastSeen` 是判活唯一依据，刷新它等于让会话复活）。
- HTTP 轮询 `/task`（明文 GET）改为**会话令牌**：
  - 注册（走 AEAD 加密帧，等价已认证）时下发 32 字节随机令牌，随加密响应返回；
  - `/task` **先校验令牌、再取任务**，缺失/错配一律 403 —— 这堵住了"知道 session_id 就能把任务抢走"。
- 管理 API 不再接受 `?token=<JWT>`（仅 `/api/v1/ws/events` 与 `/api/v1/sessions/{id}/shell` 例外，因为浏览器 WebSocket API 不能自定义请求头）。其余路径会返回 401 并说明"请用 Authorization 头"。

### 2.3 资源耗尽与配置暴露（M4 / M5 / M7 / L2 / L5）

- 已识别的请求入口加 `http.MaxBytesReader`：小 JSON 64 KiB、结果/文件/隧道 16 MiB、**未认证 `/api/v1/login` 8 KiB**（登录请求只有两个短字段），超限 **413**。
- gzip 解压上限 **32 MiB**（`io.LimitReader`），超限按协议错误断开（HTTP 回 413），不再可能被"小输入大膨胀"打爆内存。
- 内嵌 MQTT broker **默认只绑 `127.0.0.1`**（新增 `listener.mqtt_embedded_bind`），并支持可选账号口令（`listener.mqtt_username/password`）；启动会打印 WARN 标注实际绑定地址与是否启用认证。
- 首次启动生成的明文管理员口令**不再进日志**，改写入 `data/initial-admin-password.txt`（0600，Linux/macOS）；Windows 上没有 0600 语义，请用 ACL 或登录后立即删除。
- 设置接口不再回显 webhook secret（只回 `secret_set`）。

### 2.4 WebSocket（M8）

- `CheckOrigin` 从"永远 true"改为：空 `Origin`（非浏览器客户端）/ 同 `Host` / 同 `X-Forwarded-Host`（反代改写 Host 的部署）放行，其余拒绝。
- shell WebSocket 增加 1 MiB 读上限。

### 2.5 密钥卫生（L4 / L6）

- 脚本与文档里的开发用 API Key 已改为占位值/参数/环境变量；测试 fixture 里的疑似真实 JWT key 换成假值。
- `docs/skills/toshell-api/SKILL.md` 明确：**API Key / JWT 没有任何 RBAC 分权，等价于 root 凭据** —— 因为服务端可配置的 `mingw_gcc_path` / `sign_signtool_path` 会被当子进程执行。请按 root 凭据管理：不共享、不进 CI 明文变量、定期轮换。

---

### 2.6 复审计后的第二轮修复（同版追加）

第三方复审计（`SECURITY-REAUDIT-1.4.2.md`）在上一轮修复的基础上又找到 7 项残留，其中 5 项已在 **同一版本**（v1.4.2）内修掉：

| 编号 | 复审计发现 | 修法 |
|---|---|---|
| **N1** | `resolveInDir` 的物理断言对 **Windows 目录 junction** 失效（`EvalSymlinks` 报错时回落到只做词法断言）→ 未认证可经 `file:` 合成 ID 读到基目录外的文件、认证可删外部文件 | 改为 **fail-closed**：`EvalSymlinks` 失败一律拒绝；父目录必须先解析并再断言；目标不存在时**只允许单段文件名**；并**逐段 `Lstat` 拒绝 `ModeIrregular`**（junction 在 Lstat 下不是 symlink，只能靠这个 mode 位识别）。`file:`/DB 候选强制单段 |
| **N2** | 未认证 `/api/v1/login` 无请求体上限（32 MiB 完整解析，RSS 66→172 MB） | 登录限 **8 KiB**，超限 **413**（此前是 401，会被误读成"口令错"）；其余裸读入口一并收口 |
| **N3** | 插件**硬链接**写穿（`O_NOFOLLOW` 只防软链） | 改为**同目录临时文件 + rename** 替换目录项——与链接类型无关，硬链接/软链都会被替换而不是写穿 |
| **N4** | 初始口令文件登录后不删 | **首次登录成功后删除** `data/initial-admin-password.txt`（删除失败只记 warn，不影响登录） |
| **N5** | 载荷名未拒绝 Windows 保留设备名与尾点（`CON`/`NUL.raw`/`a.`） | 与插件名规则对齐：拒绝设备名、尾点、尾空格 |

**仍留的 2 项（属设计与部署边界，不改代码）**：
- 复审计 N6（文档里残留开发用 key）——已清，`git grep` 归零。
- 复审计点出的"部分关闭"5 条里，**内置 TLS** 与 **WS 一次性 ticket** 属 v1.5 计划；**MQTT 每会话主题 ACL** 与 **每植入端密钥（M3）** 同理。
## 3. 升级会影响什么（破坏性变更）

| 变化 | 影响 | 你需要做什么 |
|---|---|---|
| `/api/v1/implant/{register,heartbeat,result}` 需要凭据 + `SessionID` | 自研脚本若打这 3 个端点会 401/400 | 补 `X-API-Key`/`Bearer` 与 `SessionID`；或改用监听器协议 |
| `GET /task` 需要 `session_token` | 仍走 `GET /task` 的旧/自研客户端会 403 | 仓库内模板不受影响；自研客户端按注册响应里的 `session_token` 改造 |
| 管理 API 不再接受 `?token=` | 脚本/自定义前端会 401 | 改用 `Authorization: Bearer` 或 `X-API-Key` |
| 构建 `name` / 插件名收严 | 含 `/ \ : ..`、点开头、Windows 保留设备名的名字会 400 | 插件名可用中文/空格/括号；**构建载荷 `name` 只允许 ASCII 字母数字与 `._-`**（中文、空格会 400） |
| 内嵌 MQTT 默认绑回环 | 远程植入端不再能连内嵌 broker | 显式配置 `listener.mqtt_embedded_bind`，并**配合认证**；不要把 broker 暴露公网 |

---

## 4. 残余风险（必读）

### 4.1 M3：全局静态协议密钥 —— "拿到一个样本 ≈ 拿到协议层身份"（**未修复**）

- 载荷里的加密密钥是**同一把**（构建期写入、仅做可逆混淆），因此任何人拿到**任意一个**载荷样本，就能取出它；
- 用它可：解密抓到的控制帧、冒充服务端向植入端下发任务、伪造结果（服务端已加归属校验，但"同一密钥下的另一台植入端"仍能互相串）；
- 免认证载荷下载（`/api/v1/implant/payload/{id}`）是**产品有意设计**（支持"一条命令上线"），所以**该 URL 应视为敏感信息**：会进截图、聊天记录、CI 日志。
- **建议**：不要在不可信渠道分享载荷 ID/URL；演练结束即删除产物；把"样本泄露 = 密钥泄露"当既有前提做隔离（每场演练独立 `listener.encryption_key`）。
- 修复方向（**v1.5/v1.6**）：每植入端独立密钥或密钥对、帧 nonce/序列号防重放、免认证下载改一次性短 TTL URL。已列入 `ROADMAP.md`。

### 4.2 其它

- **植入端 TLS 不校验服务端证书**（`InsecureSkipVerify`）：应用层 AEAD 保证了内容不被伪造，但失去"对端是哪台服务器"的身份校验。严格校验会让自签/域前置部署不可用，故保留；在意这一点请用公信证书 + 反代。
- **管理 API 本身不带 TLS**：生产部署**必须**放在 TLS 反代之后（或隔离网段）。`docs/DEPLOY-DOMAIN-CDN.md` 有样例。
- **无 RBAC**：一个 API Key = 全部权限（含执行构建工具链）。多人协同时请各自发 key 并定期轮换。
- **Windows 上的文件权限**：`0600` 只在 Linux/macOS 生效；Windows 请用 `icacls` 收紧 `data/initial-admin-password.txt` 与 `release/configs/server.yaml`。

---

## 5. 验证方式（你可以自己复核）

```powershell
# 1) 单元测试（含本轮全部回归用例）
go test ./... -count=1

# 2) 发版门禁（起临时服务端 + 构建真实载荷 + 上线 + 下发任务）
pwsh -NoProfile -ExecutionPolicy Bypass -File scripts/e2e_smoke.ps1

# 3) MCP 面
pwsh -NoProfile -ExecutionPolicy Bypass -File scripts/mcp_smoke.ps1
```

本仓库不复述攻击步骤；如需复核具体判定，请对照 `docs/SECURITY-REAUDIT-1.4.2.md` 里的"攻击面 / 判定 / 结论"表与对应单测文件名。

---

**披露与致谢**：本轮问题由第三方安全审计发现并提供可复现证据（含 root 部署下的实测提权链）。按 `SECURITY.md` 的流程处理；涉及具体环境的信息未随本仓库发布。
