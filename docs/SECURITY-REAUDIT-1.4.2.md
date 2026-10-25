# ToShell v1.4.2 复审计报告（独立复核）

- 审计对象：`C:\Users\123\Desktop\project\toshell`，HEAD `f23d750`（提交信息：“fix(security): 按 2026-10-24 安全审计修复 4 High + 9 Medium + 3 Low（v1.4.2）”），版本号 1.4.2。
- 对照基线：`Toshell_AUDIT_2026-10-24.md`（原始审计：4 High / 9 Medium / 6 Low）。
- 审计方式：源码静态复核 + 自建沙箱动态验证 + 全量单测。
- 动态环境：Windows，Go 1.25.0 windows/386，`CGO_ENABLED=0`；临时端口 18730（管理 API）、18731（默认监听器）、18732（HTTP 轮询监听器）、18734（第二实例）、18830（内嵌 MQTT）；临时目录 + 临时 SQLite；临时配置显式设置独立管理员口令、API Key、JWT/AES key。未使用 18081/18581/18777/18601；未改动 `release/`、`configs/server.yaml`、`data/toshell.db`。
- 约束：本轮只写入本文件；未修改产品代码或其它文档，未 `git add`/`commit`。
- 版本说明：审计开始时工作区是“未提交的修复改动”，审计过程中该改动被提交为 `f23d750`；提交后 `git diff` 为空，因此本报告的文件/行号均对应 `f23d750`，动态验证用的二进制也由同一份内容构建。

---

## 1. 结论摘要

**一句话结论**：审计中 H1/H2/H3/H4/M1/M2/M7/M9/L2/L5 的**原始攻击路径已实测关闭**；M4/M5/M6/M8/L4 只做到**部分关闭**；未发现新的未认证 RCE 或认证绕过，但修复代码新增/遗留了 **1 个 Windows 目录重解析点（junction）绕过**（默认部署 Medium；载荷目录可被低权用户写入时等同 High）与 **1 个未覆盖的未认证内存 DoS 面**（`/api/v1/login` 无请求体上限），另有 4 个 Low。

### 1.1 判定计数（本轮要求逐条判定的 15 条）

| 结果 | 数量 | 条目 |
|---|---|---|
| 已关闭 | 10 | H1 H2 H3 H4 M1 M2 M7 M9 L2 L5 |
| 部分关闭 | 5 | M4 M5 M6 M8 L4 |
| 未关闭 | 0 | — |

### 1.2 其余 Low（只说明现状）

| ID | 现状 | 说明 |
|---|---|---|
| L1 | 未关闭（设计保留） | 植入端 TLS 仍 `InsecureSkipVerify`；应用层 AEAD 兜底，属既有取舍 |
| L3 | 已关闭（v1.4.1 已修，非本轮） | `blob_unix.go` 与非 Windows light stub 的重复定义已拆开；本轮实测 linux/amd64 light 载荷可构建 |
| L6 | 未关闭（设计接受、已文档化） | `mingw_gcc_path` / `sign_signtool_path` 仍会作为子进程执行；新增文档明确“API Key/JWT 等同 root 凭据” |

### 1.3 新增/回归问题计数

| 等级 | 数量 | 条目 |
|---|---|---|
| Medium（其中 1 条为条件性 High） | 3 | N1 路径物理断言对 junction 失效；N2 未认证 `/login` 无体积上限；N3 插件硬链接写穿 |
| Low | 4 | N4 初始管理员明文口令长期落盘；N5 载荷名未拒绝 Windows 设备名/尾点；N6 L4 修复残留；N7 对外文档过度声明 |

> 计数口径：N2 与 M4 的“部分关闭”是同一事实的两种呈现（一条记“修复不完整”，一条记“新增/未覆盖”），不重复计入“未关闭”。

---

## 2. 逐条判定

### 2.1 判定总表

| ID | 原等级 | 结论 | 依据（文件:行 / 实测） | 残余风险 |
|---|---|---|---|---|
| H1 | High | **已关闭** | `internal/server/api/api.go:497-504`（三条兼容端点挂 `auth.Middleware` + `webGate`）；`handlers_implant.go:292-380`（要求显式 `SessionID` + 归属校验）；`internal/server/task/task.go:760-817`。实测：未认证 POST register/heartbeat/result → **401**；认证后跨会话上报 → **403** 且任务仍 `pending`；本会话上报 → **200** 且 `completed`；不存在的会话 → 404；缺 TaskID → 400 | 管理员本就全权，可对任意会话上报；对已终态任务的重复结果仍会广播一次 WS 事件（无状态副作用） |
| H2 | High | **已关闭** | `internal/server/api/safe_path.go:62-89`（`safePayloadName`）；`handlers_builders.go:186-199`（入口收敛）、`:398-410`（清理前再断言 + `resolveInDir`）。实测：`name` 为 `../canary.txt`、`../canary`、`a/b`、`..` 等 → **400**，目录外 canary 文件**仍在**；合法名下载 → 200 | 清理目标仍允许“implants 目录内的任意单段文件”（管理员本就可删载荷）；Windows 尾点/设备名归一化差异见 N5 |
| H3 | High | **已关闭** | `handlers_builders.go:517-539`（按名下载收敛 + 后缀白名单）、`:783-802`（`format` 只作白名单标签）、`:992-1006`（`{name}` 走 `resolveInDir`）。实测：4 类穿越 PoC（`../configs/server` + `format=yaml`、`format` 内嵌 `..` 等）全部 **400**；合法按名下载 **200** 且内容一致；`/implants/download/..%5c…` → 400 | 物理断言缺陷见 N1（junction），可用性/功能回归：含空格或非 ASCII 的载荷名现在无法按名下载/构建 |
| H4 | High | **已关闭**（原 PoC） | `internal/server/plugin/plugin.go:171-217`（名字白名单）、`:240-250`（`Rel` 断言）、`:259-300`（`O_NOFOLLOW`）、`:311-373`（四道防线）；`handlers_mcp.go:395-429`；`handlers_plugins.go:70-160`。实测：MCP `plugin_upload` 的 `../`、`..\`、绝对路径、`C:\`、`CON.exe`、`evil.exe.`、`a.exe::$DATA`、`sub/..` 全部 **400**；`source` 穿越 → 404；multipart 文件名 `../../evil2.exe` → 400；合法名 → 200；目录外未出现写入文件 | 硬链接写穿见 N3；Windows 无 `O_NOFOLLOW`，仅有 `Lstat` 预检（TOCTOU 需对插件目录有写权限）；插件目录自身是软链/junction 时按真实根写入属预期 |
| M1 | Medium | **已关闭**（未认证面） | `handlers_implant.go:224-268`（心跳只写自己那条、dead → 409 零写入）；`internal/server/session/session.go:266-300`（`RefreshInfo` 会把状态置回 active）。实测：未认证 → 401；心跳 A 会话时 B 会话指标**不受影响**；dead 会话心跳 → **409** 且状态仍 `dead`；重新注册可复活（200，hostname 被覆盖） | 认证后 `register` 仍可“复活”dead 会话并覆盖**已存在会话**的身份字段（hostname/username/OS/IP）；上线通知限频按来源 IP，`trust_proxy_headers` 开启时可被伪造 XFF 放大（需管理员凭据） |
| M2 | Medium | **已关闭**（`session_id`-only 威胁模型） | `internal/server/listener/http_polling.go:58-71`（令牌表）、`:149-204`（签发/校验/清理）、`:653-671`（**先校验再 `GetNext`**）；`internal/server/builder/implant/transport_http.go:42-87,369-379`（模板保存 token；当前模板主循环用 `/heartbeat` 取任务，`/task` 主要供旧/自研客户端，模板在 `task` 路径会自动追加 token）。实测：无 token / 随机 token / **B 会话的正确 token 去打 A 会话** → 均 **403** 且 A 的任务仍 `pending`；A 的 token → **200** 且任务变 `sent`；重注册轮换 token 后旧 token → 403；token 为 64 hex（32 字节 CSPRNG） | token 在 GET 查询串（会进反代/访问日志）；持 M3 全局协议密钥者仍可伪造注册/心跳取任务（M2 不对该威胁模型设防）；令牌表按 `sessionID` 取值，无“A 的 token 打开 B 的门”错配；`pruneSessionTokens` 只清“会话已不存在”的令牌，服务端不跨重启恢复会话，**未发现“会话还在但令牌被清”的可用性回归** |
| M4 | Medium | **部分关闭** | 已限：`handlers_implant.go:44,78-96`（64 KiB）、`http_polling.go:74-101`（64 KiB/16 MiB）、`handlers_plugins.go:72`（50MiB）。实测：70 KiB → 兼容端点与轮询 `/register` 均 **413**；32 MiB 带凭据打兼容端点 → 413，打轮询监听器时客户端侧为连接重置（服务端已停止读取，内存受控）。未限：`handlers_auth.go:125-134`（`/api/v1/login`，**未认证**）、`handlers_sessions.go:41,106`、`handlers_tasks.go:54`、`handlers_tasks_bulk.go:154`（认证）。实测 `/login` 提交 **32 MiB 合法 JSON → 401，进程 RSS 66 MB → 172 MB，无 413** | 未认证内存 DoS（N2）；“413 + Connection: close”并非所有通道/所有体积都成立 |
| M5 | Medium | **部分关闭** | `internal/server/listener/mqtt_listener.go:543-620`（默认回环 + 可选账号）、`internal/server/config/config.go:818-820`（默认 `127.0.0.1`）、`handlers_listeners.go:434-441`（从现行配置继承）。实测：内嵌 broker 监听 `127.0.0.1:18830`；启动 WARN 标注 bind/auth；本机匿名 CONNECT 返回 CONNACK=0，匿名 SUBSCRIBE 返回 **SUBACK 授予 QoS1** | 默认远程面已关闭；但“匿名”本身仍在（仅回环），本机低权进程可订阅 `toshell/<sid>/up|down`、注入垃圾帧；若显式把 `mqtt_embedded_bind` 配成 `0.0.0.0` 且不配凭据，审计时的远程匿名场景原样复现；无 per-session topic ACL |
| M6 | Medium | **部分关闭** | `internal/server/auth/auth.go:149-163,195-221`（`tokenQueryAllowed`，仅两条 WS 路径）；`api/api.go:452-459`（仍 `ListenAndServe`，无 TLS）；`oneliner.go:82`（`server.tls_cert/tls_key` 只影响 one-liner 的 scheme）。实测：`/sessions?token=<JWT>` → 401；`/sessions/{id}/shell?token=` → 404（已通过认证，说明该路径接受查询令牌）；无 TLS 监听 | **内置 TLS 未实现**；WS 两条路径的 JWT 仍在 URL（反代访问日志、浏览器历史）；默认明文 HTTP |
| M7 | Medium | **已关闭** | `listener/listener.go:1066-1110`（32 MiB `io.LimitReader` + 哨兵错误）；`tcp_listener.go:408-416`（超限断连）；`http_polling.go:103-116`（HTTP 413）；TCP/WS/MQTT/relay 均经 `parsePacket` → `decompressData`。实测：40 MiB 全零 gzip（压缩后 40,795 B）经 AEAD 加密后 POST 轮询 `/register` → **413 `decompressed frame too large`**；单测 32 MiB/40 MiB 通过；多成员 gzip 由 `gzip.Reader` 默认多流 + 单 `LimitReader` 统一封顶 | 32 MiB/请求的放大仍在（多连接并发可累积，需协议密钥）；未把解压上限接到 TCP/WS 的真实线上压测（见第 4 节） |
| M8 | Medium | **部分关闭** | `internal/server/api/handlers_shell.go:30-57`（`originAllowed`）、`ws_push.go:41-47`（事件 WS 复用同一判定）、`handlers_shell.go:85-89`（shell 1 MiB 读上限）。实测原始握手：`Origin: http://evil.example` → **403**；`Origin: null` → **403**；尾点 host → 403；同 host → **101**；无 Origin（非浏览器）→ **101**；带匹配 `X-Forwarded-Host` 时放行（仅非浏览器能设该头） | CSWSH 面已关闭；但 **WS 的 JWT 仍在 URL**（未改一次性 ticket）；反代把 `X-Forwarded-Host` 写成带默认端口的形式（如 `host:443`）时，与浏览器不带端口的 `Origin` 不相等 → WS 连不上（可用性问题） |
| M9 | Medium | **已关闭** | `handlers_builders.go:186-199`（构造时收敛 `Name`）、`:839-888`（`serveStoredImplant` 每个候选过 `resolveInDir`）、`:900-915`（未认证 `file:` 合成 ID 也过 `resolveInDir`）；`safe_path.go:101-148`。实测：构造 `name=../canary` → 400；在临时 DB 合成历史行 `Name=../canary`（`Filename=NULL`）后，未认证按 ID 下载 → **404**，未读到 canary 内容；同一 `Name` 但 `Filename` 为合法文件的历史行仍 **200**；未认证按 build ID 下载合法载荷 → 200（产品有意的“一条命令上线”） | 物理断言的 junction 缺陷见 N1；未认证载荷下载仍是设计面（见 M3 语境），URL 应视为敏感信息 |
| L2 | Low | **已关闭** | `cmd/server/main.go:109-118`（不再打印口令）、`:666-717`（`bootstrapAdminPassword` 写 0600 文件）。实测（无 `admin_password` 的全新临时实例）：stdout/stderr 均不含生成口令，日志只给路径；`data/initial-admin-password.txt` 为 16 字符；用该口令登录 **200**；文件在登录后仍存在 | 新增 at-rest 风险见 N4：明文口令长期落盘、未自动删除；Windows 上 `0600` 无 POSIX 语义 |
| L4 | Low | **部分关闭** | 原报告点名的 `docs/skills/toshell-api/SKILL.md`、`scripts/smoke.sh`、`config_save_test.go` 已改。但 `git grep` 仍命中 `docs/PROXY-DOWNLOAD-STALL-ANALYSIS.md:221`（**tracked**）里的同一开发 key；`USAGE.html:81`、`web/ws_test.cjs:3`（ignored/生成物）也有；真实 `configs/server.yaml` 仍是该 key；`CHANGELOG.md:27` 的“grep 归零”**不成立** | 开发 key 仍是“公开的默认值”，真实部署必须轮换；tracked 文档里的示例仍可能被直接复制使用 |
| L5 | Low | **已关闭** | `handlers_settings.go:248-254`（GET 只回 `secret_set`）、`:1150-1165`（测试通知未显式给 secret 时服务端回退已存值，密钥不回浏览器）；`handlers_shell.go:85-89`（shell WS 1 MiB 读上限）。实测：`GET /settings` 的 `notifications` 仅含 `secret_set:false`，无 `secret` 字段 | 前端若依赖旧 `secret` 字段需同步（当前前端口径已改）；测试通知会隐式使用已保存密钥（管理员操作，可接受） |

---

### 2.2 关键实测证据（状态码/数量级）

- **H1/M1（兼容端点）**：未认证 401；跨会话结果 403 且任务 `pending`；本会话 200 `completed`；dead 心跳 409 且状态不变；心跳只影响指定会话；`register` 可复活并覆盖身份。
- **M2（轮询令牌）**：无/错/跨会话 token 403 且任务仍待取；正确 token 200 且变 `sent`；重注册后旧 token 403；token 长度 64 hex。
- **M4（体积）**：70 KiB → 413（兼容端点和轮询端点）；32 MiB（带凭据）兼容端点 413、轮询端点客户端见重置；`/login` 8 MiB→401、32 MiB→401，RSS 66→172 MB。
- **M5（MQTT）**：监听 `127.0.0.1:18830`；匿名 CONNECT 成功、匿名 SUBSCRIBE 获 QoS1 授予。
- **M6（查询令牌）**：`/sessions?token=` 401；shell WS 路径带 `?token=` 通过认证（404 而非 401）。
- **M7（炸弹）**：40 MiB gzip（40,795 B 密文）→ 413。
- **M8（Origin）**：evil/null/尾点 403，同 host/无 Origin 101。
- **M9（历史脏行）**：`Name=../canary` 的历史行 → 404 且无内容；合法 `Filename` → 200。
- **H2/H3（文件路径）**：构造/下载穿越全 400，canary 未删；合法按名 200。
- **H4（插件）**：8 类名字花招 400；multipart 穿越 400；合法 200；硬链接写穿 200（见 N3）。
- **L2**：日志无明文，文件存在，口令可登录。
- **L3**：`linux/amd64` + `light` 载荷构建 200（6,267,281 B）。
- **回归**：`go test ./... -count=1` 全绿（25 个有测试的包全部 `ok`）。

---

## 3. 新增/回归问题

> 本节区分“修复引入的回归”和“修复未覆盖的同一威胁面”：N1/N2 属后者（安全能力没达到修复文档宣称的边界），N3 是同一威胁面的另一种载体，N4 是 L2 修法带来的新副作用，N5/N6/N7 属低风险与准确性问题。

### N1. `resolveInDir` 的物理断言对 Windows 目录重解析点（junction）失效 —— Medium（条件性 High）

- **位置**：`internal/server/api/safe_path.go:137-146`（`EvalSymlinks` 报错时**保持词法结论**）；同类模式 `internal/server/api/handlers_mcp.go:813-819`（`resolveToolPath`）；使用点 `handlers_builders.go:862/900-915/994/1056`。
- **机制**：Windows 的目录 junction 在 Go 的 `Lstat` 中**不带 `ModeSymlink`**；`filepath.EvalSymlinks` 对 junction 路径返回原路径，对 `junction\file` 直接报错。`resolveInDir` 把“`EvalSymlinks` 失败”当作“目标不存在”跳过物理断言，只保留词法结论；随后 `os.Stat/Open/Remove` 由操作系统**跟随** junction，于是读写落到基目录之外。
- **攻击面**：未认证的载荷下载端点 `/api/v1/implant/payload/{id}` 的 `file:` 合成 ID 允许反斜杠子路径；`{id}` 里的反斜杠在 Windows 上是合法路径分隔符（正斜杠会被 mux 拒绝）。
- **实测**：在 `implants/` 内置一个指向 `%WINDIR%` 的目录 junction 后，未认证请求经 `file:` 合成 ID 读取系统目录下的 `win.ini`（200，92 B）与 `System32\drivers\etc\hosts`（200，845 B）；同一构造下**认证** `DELETE /api/v1/implants/{id}` 成功删除目录外文件（200，文件消失）；`data/tools` 下的 junction 使 `resolveToolPath` 同样失效（`plugin_upload` 读取 `win.ini` 返回 200）。Go 侧探针确认：junction 的 `Lstat` 无 `ModeSymlink`、`EvalSymlinks(junction)` 原样返回、`EvalSymlinks(junction\file)` 报错。
- **前提与影响**：需要基目录（载荷输出目录 / data/tools）内已存在目录重解析点。创建 junction 在 Windows 上**不需要管理员**，但需要对该目录的写权限；默认 0755 且服务账号持有目录时无法远程创建（当前没有 API 能在 implants 下建目录）。一旦条件成立，读取以 ToShell 进程权限执行；以 root/SYSTEM 运行时即“未认证任意文件读”，可取得 `configs/server.yaml` 中的 `jwt_key`/`encryption_key`，等同认证绕过。因此默认部署记 Medium，**“安装/输出目录可被低权用户写入”的部署按 High 处理**。
- **建议**：
  1. `EvalSymlinks`/`Readlink` 失败一律按**拒绝**处理（fail-closed），不要回落成“只做词法断言”；
  2. 对 `file:` 合成 ID 与 DB 候选强制**单段名**（拒绝 `/`、`\`），从根上消除“子路径 + 中间重解析点”；
  3. Windows 上打开后用 `GetFinalPathNameByHandle` 复核最终路径仍在基目录内（或逐段用 `FILE_FLAG_OPEN_REPARSE_POINT` 打开并拒绝重解析点）；Linux 用 `openat2(RESOLVE_BENEATH|RESOLVE_NO_SYMLINKS)` 或逐段 `O_NOFOLLOW`；
  4. 服务不以 root/SYSTEM 运行，输出目录权限收紧到服务账号。

### N2. 未认证 `/api/v1/login` 无请求体上限 —— Medium

- **位置**：`internal/server/api/handlers_auth.go:125-134`（`json.NewDecoder(r.Body)`，无 `MaxBytesReader`）；对照 `handlers_implant.go:78-96` 已加限。
- **实测**：未认证向 `/api/v1/login` 提交 **32 MiB 的合法形状 JSON**（用户名/口令字段填充）→ **401**（不是 413），进程 RSS 66 MB → 172 MB；8 MiB 同样被完整解析（401）。
- **影响**：与审计 M4 同类的未认证内存 DoS；默认 Web 防护关闭时可直接打（`/login` 是认证豁免路径）。认证后的 `POST /tasks`、`PATCH /sessions/{id}`、`/tasks/bulk` 仍是裸 `io.ReadAll`，同属未限面（全权凭据下风险较低，但仍是崩溃向量）。
- **建议**：`/login` 加 `MaxBytesReader`（4~8 KiB 足够）；认证端点也统一加上限；修复说明不要写成“所有请求入口”。

### N3. 插件目录内的硬链接可写穿（`Lstat`/`O_NOFOLLOW` 只防软链） —— Medium（条件性）

- **位置**：`internal/server/plugin/plugin.go:259-267`（Windows `O_NOFOLLOW` 取 0）、`:275-285`（`os.OpenFile` 截断写）、`:343-349`（`Lstat` 只拒绝 `ModeSymlink`）。
- **实测**：在插件目录内创建一个指向目录外文件的硬链接后，MCP `plugin_upload` 以同名覆盖上传 → **200**，目录外目标文件内容被替换；`Lstat` 看到的是普通文件，`O_NOFOLLOW` 对硬链接无效（Windows 上更无该 flag）。
- **前提与影响**：需要能在插件目录创建硬链接（对该目录写权限），且 ToShell 以更高权限运行。Linux 默认 `fs.protected_hardlinks=1` 会限制对 root 文件的硬链；Windows 同卷硬链限制更弱。不是本轮修复引入的回归，而是 H4“四道防线”未覆盖的同一威胁面（软链面已关闭）。
- **建议**：写前检查链接数（Linux `Stat_t.Nlink > 1`；Windows `GetFileInformationByHandle` 的 `NumberOfLinks`/FileId）；或统一“写临时文件 + 原子 rename”；插件目录权限收紧、服务不以高权限运行。

### N4. 首次启动的明文管理员口令长期落盘 —— Low

- **位置**：`cmd/server/main.go:666-717`。
- **实测**：文件 `data/initial-admin-password.txt` 在首次登录成功后仍存在；内容为 16 字符口令；日志只给路径、无明文（L2 已修）；Windows 上 `0600` 无 POSIX 语义（ACL 实测为继承的完全控制）。
- **影响**：`data/` 目录新增了一个明文凭据；备份、卷快照、任意文件读（如 N1）都会放大影响；口令在改密后也不会被清理。
- **建议**：首次登录成功后删除/清零该文件；改密时删除；启动时若发现旧文件给出显式提示并清理；Windows 用 `icacls` 收紧。

### N5. `safePayloadName` 未拒绝 Windows 保留设备名与尾点 —— Low

- **位置**：`internal/server/api/safe_path.go:62-89`（对比 `plugin.go:220-236` 的 `isReservedDeviceName` 已拒绝）。
- **实测**：`CON`、`NUL.raw`、`a.` 均通过载荷名校验（后续用非法 `format` 触发 500 证明已过名字校验）；未认证 `file:NUL` 返回 **200 空体**；`a.` 在 Windows 上等价于 `a`。
- **影响**：清理 `os.Remove` 对设备路径是 no-op；按名下载 `NUL` 会返回空载荷；尾点会造成“校验名”与“磁盘名”不一致（仅目录内，未发现越界）。与插件名规则不一致，易在后续维护中漂移。
- **建议**：拒绝 `CON/PRN/AUX/NUL/COM1-9/LPT1-9`（含带扩展名形式）与尾点/尾空格，与 `ValidatePluginName` 对齐。

### N6. L4 残留：tracked 文档仍内置开发 API Key —— Low

- **证据**：`git grep` 命中 `docs/PROXY-DOWNLOAD-STALL-ANALYSIS.md:221`（tracked）仍使用同一开发 key；`USAGE.html:81`、`web/ws_test.cjs:3`（ignored/生成物）也有；真实 `configs/server.yaml` 仍是该 key；`CHANGELOG.md:27` 的“grep 归零”与实际不符。
- **建议**：清掉 tracked 文档里的 key、改为占位符；真实部署按 L4 原建议轮换；CHANGELOG 改为“点名位置已改，示例文档/本地配置仍需自行替换”。

### N7. 对外文档的绝对化表述与实际能力不一致 —— Low

- **证据与实测**：
  - `docs/SECURITY-FIXES-1.4.2.md:13`、`CHANGELOG.md:10`：“全部被拒 / 21 条全部被拒”。实际 M5 的本机匿名 CONNECT/SUBSCRIBE 仍成功、M6 仍无 TLS、M8 的 JWT 仍在 URL、`/login` 仍未限体积。
  - `docs/SECURITY-FIXES-1.4.2.md:44`、`CHANGELOG.md:20`：“所有请求入口加 `MaxBytesReader`”。实际 `/api/v1/login` 未加（N2）。
  - `docs/SECURITY-FIXES-1.4.2.md:69`：“中文、空格、括号仍允许”。实际**插件名**允许（实测中文+空格+括号 200），**构建 `name`** 不允许（实测带空格 400）。
  - `CHANGELOG.md:21` 的 M5 行：“匿名订阅失败”。实际是“默认只绑回环、远程不可达”，本机匿名订阅是成功的（SUBACK 授予）。
  - `CHANGELOG.md:20` 的 M4 行：“32 MiB → 413 + Connection: close”。实际 32 MiB 打轮询监听器时客户端看到连接重置；`/login` 是 401；只有 <= 上限附近的体积稳定拿到 413。
- **建议**：按本复审计的判定修订对外表述，把“全部被拒”改成逐条结论，把“所有入口”改成具体端点清单。

### 3.1 非新增但值得一并处理的观察

- `cmd/server/main.go:132` 仍打印“JWT key 前 16 字符”（预存在）。16/44 个 base64 字符不足以直接恢复密钥，但无必要；建议只打印“已生成”。
- WS 的 JWT 在 URL（M8 残余）：反代日志/浏览器历史仍会记录；若要彻底关闭，需一次性 WS ticket。
- `resolveInDir` 的检查与 `os.Open/Remove` 之间仍有 TOCTOU 窗口（需本地写基目录），与 N1 同前提；N1 的修法（单段名 + fail-closed）可同时缩小它。
- `implantResultHandler` 对已终态任务的重复结果：`CompleteForSession` 幂等返回 nil，但 handler 仍广播一次事件；仅认证用户可触发，建议终态时跳过广播。
- `plugin.scanPlugins` 会把插件目录内的符号链接当普通插件登记，读取时跟随（本地前提）；建议扫描时跳过非普通文件，与 N3 一并处理。

---

## 4. 无法验证的项（如实列出）

1. **Linux/root 场景**：`/etc/shadow`、`/etc/sudoers.d`、`O_NOFOLLOW` 的真实拦截、`fs.protected_hardlinks` 对 N3 的缓解，均未在 Linux 上复测（本机 Windows，非 root）。
2. **Windows 文件符号链接**：当前会话非管理员，`SeCreateSymbolicLinkPrivilege` 不可用，无法创建**文件 symlink**。因此“插件 `Lstat` 拒绝软链”“`resolveInDir` 对软链 `EvalSymlinks` 拒绝”只做了代码审查 + 项目单测（项目单测在 Windows 上按设计跳过该用例）。N1 用**目录 junction** 完成了重解析点的等价验证。
3. **TCP/WS 通道的压缩炸弹**：只在 HTTP 轮询通道实测了 413；TCP/WS 共用 `decompressData` 且单测覆盖，未在真实 TCP/WS 帧上打。
4. **内嵌 MQTT 的远程匿名面**：未把 `mqtt_embedded_bind` 改成 `0.0.0.0` 做跨机复现；只验证了默认回环绑定 + 本机匿名 CONNECT/SUBSCRIBE。
5. **会话重启/令牌清理时序**：服务端不在重启时恢复会话，无法构造“会话仍存在但令牌已被清理”；仅做代码审查（结论：未发现该可用性回归）。
6. **并发 OOM/DoS 规模**：只做了单请求 32 MiB 的 RSS 测量，未做并发压测；N2 的“可打爆内存”是推断而非实测 OOM。
7. **真实浏览器 CSWSH**：用原始 WS 握手模拟 Origin，未用真实浏览器；结论基于握手层判定。
8. **原审计 M3（全局静态协议密钥/无每植入端身份）**：本轮范围外，未复测；仍未修复（修复文档已如实标注）。
9. **`scripts/e2e_smoke.ps1` / 真实植入端上线**：未运行（会构建并启动真实植入端，超出本轮“沙箱 + 只读”范围）；以 `go test ./...` 全绿 + 协议级手工 E2E 替代。

---

## 5. 复审计方法与范围

**做了什么**：

- 完整阅读原始审计报告与本轮全部改动（`git diff` / 逐文件复核），并对照 `docs/SECURITY-FIXES-1.4.2.md`、`CHANGELOG.md` 的修复声明逐条核对。
- 以 `GOOS=windows GOARCH=386 CGO_ENABLED=0 go build -tags webui ./cmd/server` 构建临时服务端；用临时配置（独立管理员口令、API Key、JWT/AES key）在 18730/18731/18732/18734/18830 端口起沙箱。
- 用 Python（AES-256-GCM + TSHL 帧 + gzip）实现协议级客户端，完成：加密注册取令牌、token 绑定/轮换/跨会话校验、gzip 炸弹、TCP/WS 之外的 HTTP 轮询 E2E。
- 用真实 HTTP/WS 握手验证认证边界、`?token=` 收窄、Origin 判定、413/409/403/401 状态码。
- 用临时 SQLite 注入**历史脏行**验证 M9 的第二层防线；用 junction/硬链接验证 N1/N3；用第二临时实例验证 L2 首次启动路径；用 `go build` 验证 L3 的 linux/amd64 light 载荷。
- 跑 `go test ./... -count=1`，25 个有测试的包全部通过。

**没做什么**：

- 未修改任何产品代码/其它文档/配置；未 `git add`/`commit`；未写入 `release/`、`configs/server.yaml`、`data/toshell.db`。
- 未对 18081/18581/18777/18601 或任何真实测试站发起请求；未运行真实植入端上线、未做并发压测、未在 Linux/root 环境复测。
- 未包含可直接复制的完整攻击命令（按“攻击面/判定/结论”呈现证据）。

**清理**：临时服务端进程已终止；临时目录、临时配置、临时 SQLite、临时 junction/硬链接/插件文件均已删除；未改动真实产物。

---

## 6. 建议的处置顺序

1. **N1（junction 物理断言失效）**：先按“fail-closed + 单段名”修，成本低、直接封住未认证读/认证删的越界面；若部署上无法保证输出目录权限，按 High 处理。
2. **N2（`/login` 未限体积）**：一行 `MaxBytesReader`；顺带把认证端点的裸 `ReadAll` 收口。
3. **N3（硬链接）**：与插件目录权限加固一起做；Linux 侧校验 `Nlink`，Windows 侧校验句柄最终路径/链接数。
4. **M6/M8 的剩余面**：内置 TLS（或明确“必须反代 TLS”的强制校验）与 WS 一次性 ticket，建议放到 v1.5 与 M3 的“每植入端身份”一起设计。
5. **M5 的剩余面**：若坚持保留匿名模式，至少把“回环 + 匿名”写进启动 WARN 与文档；如需跨机，强制要求账号密码。
6. **N4/N5/N6/N7**：随手修 + 文档校正；其中 N4 建议在首个管理员登录成功后自动删除明文文件。