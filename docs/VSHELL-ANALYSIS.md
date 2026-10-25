# VShell 参考实现分析（对 ToShell 的取舍建议）

> **分析对象**：`vshell/` 目录（本地未跟踪的第三方源码，已加进 `.gitignore`，**不随本仓库分发**）
> **分析时间**：2026-10（ToShell 基线 v1.4.0 已发布，v1.4.1 开发中）
> **本文用途**：只回答三件事 —— **它哪里做得好、能不能抄、抄的代价与风险**。
> **口径**：本文**不复制** vshell 的任何代码/资源/字符串；文中 `文件:行号` 仅用于**定位可核查的事实**。所有 ToShell 现状判断都读过本仓库代码，出处附在行内。

---

## 0. 许可证与"不可搬运"边界（先看这一节，再往下读）

**先说结论：这份源码只能读设计，不能搬代码，连前端资源也不能搬。**

| 核查点 | 证据（文件:行） | 结论 |
|---|---|---|
| 仓库自称的性质 | `vshell/README.md:3`：*"An incomplete reverse-engineered re-implementation of the in-the-wild exploited C2 framework **VShell**"*；`vshell/README.md:14-15`：*"Unofficial, unaffiliated with the original author; all rights of the original software remain with its author"* | 它是**对一款商用 C2（VShell v3.0）的反编译复刻**，不是原创开源项目 |
| 许可证声明 | `vshell/README.md:6` 的徽章指向 `license.txt`（许可证写作 **All Rights Reserved**）；**仓库里没有 `license.txt`**（`vshell/` 根目录只有 `go.mod / go.sum / main.go / README.md / README.zh-CN.md`） | **许可证正文缺失**，只有徽章上的一句话 |
| 正文许可条款 | `vshell/README.md:211-213`：*"This repository does not include the original license; all rights of the original software belong to its author. **Research only — no commercial or unlawful use.**"* | 授权范围**未授予**（无 MIT/Apache/GPL 等任何许可文本），且明确"仅研究用途" |
| 前端资源来源 | `vshell/README.md:199`：*"Frontend assets: the SPA in `static/` was extracted from the original binary"*；`vshell/static/index.html:1`、`vshell/static/app.config.js` 为打包产物 | 前端 SPA 是**从原版二进制里抽出来的**，属于他人作品的复制件 |
| 授权体系实现 | `vshell/utils/license.go:1-17`：原版二进制内**内置 RSA 私钥**用于解密 license blob | 复刻者也无权处置该密钥/授权逻辑 |

**因此执行以下红线（写入本文作为约束，不只写在口头）**：

1. **不复制代码**：不拷贝任何 `.go` 文件、类型名、常量名、协议帧码、注释文本。需要同类能力时**从零写**，只把它的"设计意图"当输入。
2. **不复制资源**：`vshell/static/**`（SPA/JS/CSS/字体/图标）一律不进本仓库；ToShell 前端是自研 React（`web/`）。
3. **不复制协议常量**：例如 `vshell/c2engine/wire.go:30-46` 那组帧码（`0x54/0xa6/0xb1…`）是**原版的线格式**，属于互操作契约，不是"可自由采用的方案"。ToShell 的帧类型独立定义在 `internal/common/protocol/packet.go:13-33`。
4. **不宣称兼容**：不要做"能接管 VShell 会话/载荷"的互操作功能（那既涉及授权，也会把两个协议的错误码绑死）。
5. **引用要克制**：本文引用行号只为可核查；不把它的实现细节写成"我们也可以这样写"的伪规格。

> 一句话：**它的价值是"隔壁工位的设计笔记"，不是"可以编译进来的依赖"。**

---

## 1. TL;DR

**它是什么**：一份**逆向复刻**的国产商用 C2（VShell v3.0）Go 重实现 —— Beego 后端 + 从原版抽出的 Vue SPA（`vshell/go.mod:5-11`、`vshell/static/index.html:1`），内含 HTTP/HTTPS/WebSocket/CDN-WebSocket/DNS/KCP 六种协议面、agent 端 41 个有效 opcode（`vshell/agent/main.go:2516-2520`）、隧道与反代主机管理。**不完整**：`vshell/README.md:171-183` 自己列了一整页"未恢复"项（多数 opcode、插件下发、屏幕质量参数等）。

**一句话能说出的 5 个强项**：

1. **一个进程里并存多套协议面**，且按 `mode` 在运行期装配端点点集（`vshell/c2engine/listener.go:98-115`、`:224-267`）。
2. **载荷是"请求时生成"的**：每种形态一个投递端点（`/swt /sww /swk /sws /swd /swl /swld`），参数取自监听器、带 `Public`/`Expires` 标记（`vshell/c2engine/listener.go:232-239`、`:646-703`；`vshell/c2engine/payload_build.go:156-193`）。
3. **隧道/反代主机是一等持久化资源**，各自带 tcp/http/icmp 健康检查与并发上限（`vshell/c2engine/types.go:272-301`、`vshell/c2engine/health.go:20-130`）。
4. **可运营性细节齐**：每客户端连接数上限、流量统计与限速字段、系统资源面板（`vshell/c2engine/types.go:98-180`、`:25-51`、`vshell/c2engine/monitor.go:41-64`）。
5. **逆向工程纪律可审计**：每个模块都标注"已对齐/未恢复/占位（PLACEHOLDER）"并附反编译地址（`vshell/c2engine/payload_build.go:227-239` 是最好的例子 —— 它连"这个常量是猜的"都写进注释）。

**ToShell 与它的定位差异**：

| 维度 | vshell（参考实现） | ToShell（本项目） |
|---|---|---|
| 出身 | 对商用 C2 的逆向复刻，**功能对齐原版**是最高目标 | 自研，**可维护性与可验证性**是最高目标 |
| 正确性来源 | 反编译地址 + 单测（`vshell/README.md:111-124`） | 代码 + 单测 + 真机 E2E + CI（`.github/workflows/ci.yml:59-83`） |
| 文档口径 | "未恢复就返回 not implemented"（`vshell/controllers/runner.go:68-90`） | "未验证就标 ❌/🟡"（本仓库 ROADMAP 五态表） |
| 许可 | 无许可证、Orig 版权归他人 | MIT（`LICENSE`） |
| 安全默认值 | 部分路径 fail-open（见 §4） | fail-closed 占多数（AV-Ops / MCP / 中继 409） |

> **决策含义**：**不要在"原版对齐"上跟它比**（我们永远对不齐，也没必要对齐）；要在"工程证据链 + 可运营性 + 生态"上比它。前者是它的唯一赛道，后两者是它完全没做的。

---

## 2. 架构对比表（vshell 做法 vs ToShell 现状）

> ToShell 一列**逐行读过代码**，出处写在单元格里。凡"未做"的，都能在仓库里找到"没有这段代码"或"标了 stub"。

| 维度 | vshell 做法（文件:行） | ToShell 现状（出处） |
|---|---|---|
| **通信模型** | 拉取式：`/api/checkin` → `/api/tasks` 轮询 → `/api/result` 回传（`c2engine/listener.go:273-363`、`:369-429`、`:435+`） | 长连接帧协议（TCP）+ HTTP 轮询 + WS + MQTT，帧类型 0x00–0x0E（`internal/common/protocol/packet.go:13-33`；四条监听器在 `internal/server/listener/`） |
| **传输面** | `http/https/dns/websocket/cdn_websocket/reverse`（`c2engine/types.go:364-381`），运行期按 mode 装配（`listener.go:98-115`） | `tcp/http/websocket/mqtt`，协议差异在**构建期按 tag** 决定（`internal/server/builder/builder.go:881-916`），服务端一套路由 |
| **加密** | 每监听器一把 salt，密钥 = `hex(md5(salt))` 直接当 AES-256 密钥（`c2engine/protocol.go:196-208`）；checkin/result **可退化为明文 JSON**（`listener.go:286-303`） ；**`VerifyKey` 是客户端标识不是密钥**（`engine.go:370` 用 `==` 比较，非恒定时间），KCP 通道密钥是 `salt+verifyKey` 直接截断补 NUL 到 32 字节（`kcp.go` `kcpBlockCrypt`），且默认值就是字面量 `"default"`（`builder.go:153-154`） | 控制帧 AES-256-GCM + 隧道数据 SM4-GCM，密钥域分离（`internal/common/crypto/crypto.go:21-37`、`internal/common/crypto/sm4.go`） |
| **TLS 指纹** | 未见 uTLS/JA3 相关实现（`go.mod` 无 utls） | **HTTP 通道 full 档已用 uTLS `HelloChrome_102`**（`internal/server/builder/implant/transport_tls_utls.go:39-56`），light 档用标准库（`transport_tls_std.go:1-19`）；WS 仍是标准库 TLS（`transport_ws.go:122-149`） |
| **多级代理/中继** | 无中继；`tunnel` 是端口转发登记（`controllers/tunnel.go:20-66`） | Beacon Mesh 多跳中继，`maxRelayHops=16`、`TypeRelay` 帧路由（`internal/server/listener/relay.go:17-27`、`internal/common/protocol/packet.go:24`） |
| **多点/多监听器** | ListenerManager 多监听器并存，每监听器独立 vkey/salt（`c2engine/listener.go:1270-1354`） | DB 持久化多监听器 + 重启恢复（`internal/server/api/handlers_listeners.go:472-503`），默认监听器在 `cmd/server/main.go:276-283` |
| **任务队列** | 单表 tasks；`pending→dispatched` 原子领取（`c2engine/engine.go:803-815`）；另有按 md5 口令反查任务（`engine.go:817-828`） | `task.Manager` 状态机 + 重连补发/重投递策略 + 破坏性任务禁自动重试（`internal/server/task/task.go`、`internal/server/task/noretry_test.go`） |
| **载荷形态** | `stage / stageless / shellcode / dll / listen / listen_dll` + **loader 源码**分支（`c2engine/types.go:383-390`、`payload_build.go:156-221`） | `exe/dll/shellcode/shellcode_bin/raw`（Windows）/`bin/so/raw`（unix）（`internal/server/builder/builder.go:1134-1139`）+ C 植入端 + `exec_module` 内存模块 |
| **投递方式** | 按请求从监听器参数生成/取模板，六种形态各一端点（`listener.go:232-239`、`:675-703`） | 构建 → 落盘 → 下载 URL（`/api/v1/builders/download`、`/implants/stored*`，见 `docs/skills/toshell-api/SKILL.md` §2） |
| **前端技术栈** | Vue SPA，**从原版二进制抽出**（`static/index.html:1`、`README.md:199`） | React 18 + Vite 5 + TS + zustand + xterm 6（`web/package.json`） |
| **插件机制** | `./plugins` 目录按扩展名选平台/架构，hex 展开随命令下发（`controllers/runner.go:55-66`）；**agent 端未实现**（`:68-73`） | `plugin` 管理器 + BOF + `exec_module`（ABI v1 + 一次性 token + 9 步校验链，`internal/server/modules/`、`internal/common/moduleabi/`） |
| **权限模型** | 3 角色 + **路径前缀**白名单 + JWT 声明 `role_id`（`utils/auth.go:72-103`、`:137-151`） | API Key / JWT / MCP token / Web 防测绘门槛（`internal/server/auth/auth.go`、`auth/webgate.go`）；JWT `Claims` 有 `Role` 字段（`auth/auth.go:18-22`），但登录时**固定写死 `"admin"`**（`api/handlers_auth.go:140`、`:156`），**全仓库没有任何基于 role 的授权判定** |
| **情报/取证** | 无凭据库、无情报库；只有截图/屏幕/终端/插件 | `intel` 情报抽取 + `credentials` + `avdetect`（`internal/server/intel/intel.go`、`handlers_credentials.go`、`avdetect/avdetect.go`） |
| **免杀** | 无（只有 UPX/ebpf 参数占位，`payload_build.go:167-172`） | 落地/动态/静态三层 + AV-Ops L0–L4 分级（`internal/common/avops/avops.go:47-56`）+ 8 条加载器链 + 代码签名 + PE 节规范化（`internal/server/builder/finalize_order.go`、`pe_sections.go`） |
| **加密对抗分级** | 无 | 有（表驱动 + 服务端定级 + 审计；L2+ 默认关） |
| **构建方式** | 预编译模板 + 定长占位符 `ldflags -X` 注入（`protocol.go:595`、`README.md:90-99`）+ gzip/XOR | 源码复制到临时目录按 tag 编译 + 字节加工流水线（`builder.go:587-604`、`:765-810`、`finalize_order.go`） |
| **数据存储** | SQLite（Web）+ JSON（引擎）双存储（`c2engine/storage.go`） | 单 SQLite（`internal/server/database/`），额外 4 张 agent 表 |
| **审计** | 无独立审计，只有运行日志（`utils/logger.go`） | JSONL 审计 + AV-Ops 审计 + agent 轨迹（`internal/server/mcp/audit.go`、`handlers_avops.go`） |
| **可观测性** | 服务端资源面板：CPU/内存/磁盘/连接数/带宽（`monitor.go:41-64`） | `/health`、`/logs`、`/system/stats`、`/channels/health`（`internal/server/api/api.go:557-558`、`handlers_channels.go`）；指标端点齐，但**帧限速/广播去抖这类运行指标未上界面** |
| **许可/授权门控** | 内置 RSA **私钥**解 license，失败回退默认值（`utils/license.go:1-17`、`README.md:187-193`） | 无（MIT，开源即全功能） |

**读表结论**：ToShell 在"加密/中继/任务可靠性/免杀分层/审计/插件 ABI"上已经领先；vshell 在**投递面（请求时生成 + 形态端点）**、**通道落点抽象（运行期装配协议面）**、**隧道/主机的健康与配额**、**批量操作契约**、**DNS/UDP 通道骨架**上更接近"能运营的 C2"。

---

## 3. 值得借鉴的 10 个点（按"成本低 / 收益高"排序）

> 每条格式固定：**现象**（它怎么做的，文件:行）→ **为什么好** → **ToShell 落地成本** → **风险/坑** → **建议版本**。
> "成本"按改动面估：小 ≈ ≤3 文件 / ≤300 行；中 ≈ 一个子系统 + 前端；大 ≈ 跨模块重构或需要外部材料。

### B1 运行期按 `mode` 装配协议面（而不是按构建 tag 分叉）

- **现象**：`vshell/c2engine/listener.go:98-115` 用 `switch cl.Config.Mode` 决定注册哪套 handler；`:224-267` 里 HTTP/HTTPS 注册 11 个端点，WS 再加 `/ws`，CDN-WS 再加 `/cdn/ws`，DNS 模式仍复用 HTTP 端点。**加一种协议 = 加一个 `registerXxxHandlers` + 一个常量**。
- **为什么好**：直接对应我们最痛的成本项 —— ROADMAP 已记录"加一个新协议 = **12 类落点 / 20+ 处编辑**，其中 8 处漏改就静默降级或编译失败"。把"协议面"收敛成**一张注册表**（端点集合 + 协议能力标志），新通道只写一个适配器。
- **ToShell 落地成本**：**中**。改动面：`internal/server/listener/*`（新建 `protoface.go` 注册表）+ `internal/common/protocol/packet.go`（能力标志）+ `api/router.go`（路由按注册表挂载）+ 单测（"注册表⊇现役四通道"的守卫用例）。
- **风险/坑**：① 运行期装配会让"哪些端点存在"变成数据而不是代码，**必须同时做端点指纹自检**（否则又回到"任意路径都能升级"那类探测面问题，参考 S5 第 0 步的教训）；② 不要把植入端也改成运行期协商（那会多一轮握手，且老载荷不兼容）；③ 注册表要 fail-closed：未知 mode 拒绝而不是回退 HTTP。
- **建议版本**：**v1.5**（作为 DNS/UDP 通道的前置）。

### B2 载荷"请求时生成"：每种形态一个投递端点 + 过期/公开标记

- **现象**：`listener.go:232-239` 为 `stage/stageless/kcp/shellcode/dll/linux/listendll` 各挂一个端点；`:675-703` 里 `serveAgentBinary` 现场取 `GetBuildInfo` + `loadAgentBinary`，取不到就 `generateAgentBinary`（用监听器参数即时生成）；`payload_build.go:156-193` 的 `PoConfig` 带 `Public` / `Expires`。
- **为什么好**：① 载荷**不必落服务端磁盘**（少一份"证据文件"）；② 端点即形态，URL 可长期复用、可轮换；③ 过期/公开标记能压掉"链接被分析员反复拉取"的风险，也天然支持"一次性投放"。
- **ToShell 落地成本**：**中**。现状是"构建 → 落盘（`data/implants` / `/implants/stored*`）→ 下载 URL"。改动面：`api/handlers_implant.go` + `handlers_builders.go`（加"按形态取/即时构建"的路由）+ 构建缓存（同一组参数 60s 内复用，避免每次请求都编 20s）+ 下载 URL 的过期/一次性 token（可复用 `internal/server/modules` 的一次性 token 机制）。
- **风险/坑**：① 现场构建是**重操作**，必须限流 + 排队 + 明确超时，否则一个探测者就能把构建器打满；② 构建参数来自 URL 时会变成**注入面**（`os/exec` 参数拼接），必须白名单化（只允许枚举值）；③ 过期链接会让"演练中途换链接"成为运维动作，要写进文档；④ 不要让它替代现有落盘路径（先并存 + 开关）。
- **建议版本**：**v1.5**。

### B3 stage / stageless 双形态 + loader 源码模板

- **现象**：`payload_build.go:156-193` 把 `stage`（小加载器）与 `stageless`（完整载荷）分成两条构建入口；`:195-221` 的 `PoLoaderSource()` 在 `arch=loader` 时**直接返回一段 loader 源码骨架**给操作员编译。
- **为什么好**：我们目前只有"命令模板"（`api/oneliner.go` + `docs/LOADERS.md` 8 条链），操作员还得自己拼工程。给"可编译的加载器工程模板"能把落地链的成功率从"看文档试"提升到"改两个常量就能编"，也顺手把"加载器该怎么传参/怎么定位载荷"固化成代码。
- **ToShell 落地成本**：**小**。改动面：`internal/server/api/oneliner.go` 旁边加 `loader_templates/`（Go/C 各 1~2 个最小骨架 + `go:embed`）+ 前端"加载器源码"下载按钮；验收 = 每个模板在本机 `go build` / `mingw-gcc` 能过。
- **风险/坑**：① 模板必须**真的能编译**（vshell 的 loader 骨架就是空壳，`payload_build.go:209-221` 里只有 `syscall.LoadDLL` 占位）——我们不能再造"看起来能用"的骨架；② 模板里**不要内置签名/官方 PE 宿主**；③ 模板同样要过 `docs/EVASION.md` 的"未验证"标注纪律。
- **建议版本**：**v1.5**（与 P1 投递面一起）。

### B4 隧道/反代主机作为一等持久化资源 + 周期健康检查

- **现象**：`types.go:272-301` 的 `Tunnel{ID, ClientID, Port, Mode, Target, TargetAddr, Remark, Health, RunStatus}` 与 `Host{... TargetStr, Scheme, Flow, Health ...}` 都是可增删改查的实体；`health.go:20-130` 每 30s 扫一遍，`CheckType` 支持 `tcp/http/icmp`、`MaxFail` 判失败、并发上限 20；`types.go:303-326` 的 `Target` 持有多个目标可轮换。
- **为什么好**：ToShell 的中继是"会话属性"（`relay` 帧 + `relay_nodes` 列表），**没有独立健康探测**：中继节点挂了只能等会话判死（`session.HeartbeatTimeout`），而 SOCKS5 隧道目前是内存态 `s.socks5Servers`（`api/handlers_tunnels.go:18-66`），**进程重启即丢**。把"隧道/反代端点"实体化 + 健康探测，能直接改善"长演练里的可运营性"。
- **ToShell 落地成本**：**中**。改动面：DB 新表（tunnels/hosts，参考 `database/agent_schema.go` 的幂等 DDL 写法）+ `internal/server/tunnel` 健康探测 goroutine（限并发）+ API/前端 Tunnels 页；SOCKS5 实例改为"按规则重建"。
- **风险/坑**：① 健康探测 = **向目标端口主动发包**，是新的流量足迹，必须默认关闭 / 只在"操作员显式开启的隧道"上跑；② 探测失败不能自动删规则（只标记 `unhealthy` 并告警），否则回滚困难；③ 别把健康检查和会话判活混成一个阈值（会互相打架，S5 已经踩过判活抖动的坑）。
- **建议版本**：**v1.5**（实体化）/ **v1.6**（自动选路）。

### B5 每会话连接数 / 流量配额

- **现象**：`types.go:98-142` 的 `Client{MaxConn, NowConn, RateLimit, Flow}`（DB 列里另有 `FlowLimit`，见 `types.go:99-102` 的列序注释）+ `:144-170` 的 `AddConn/GetConn/CutConn`（`GetConn` 到了 `MaxConn` 直接拒），`:25-51` 的 `Flow` 统计入/出流量。
- **为什么好**：ToShell 目前只在**传输层**有 `write_queue_size` 与屏幕帧限速（`api/screen_frame_limiter.go`），**没有 per-session 的连接数/流量上限**。一次横向过程中某个会话被工具打满（比如 8 个并发下载 + 屏幕流），会把其它会话的判活和任务回传一起拖坏。
- **ToShell 落地成本**：**小**。改动面：`internal/server/session/session.go` 加两个计数 + `internal/common/tunnel` 的入口处判定 + 配置项（`session.max_conns_per_session` / `max_kbps`）+ 超限回明确错误码（别静默丢包）。
- **风险/坑**：① 大文件传输本来就是多分块（`listener/handler_core.go:187-240`），配额算法要**按"并发流"而不是"帧数"**，否则正常传输被误杀；② 超限必须可见（回 429/明确日志），否则表现为"随机卡住"；③ 配额是内存态还是持久态要一次定清楚（推荐内存 + 会话内重启归零）。
- **建议版本**：**v1.5**。

### B6 DNS 隐蔽信道的**最小可读骨架**

- **现象**：`dns.go:17-63` 定义 `DNSListener{Domain, PublicDNS, MaxSize, VerifyKey, pendingOut}`；`:67-90` 绑 UDP `:53`（失败退 `:5353`）；查询编码用 `base32`（`README.md:118` 记录"Go std base32 无 padding；query = `[8B agent ID][message].domain`"）；`types.go:246-249` 把 `DNSDomain/PublicDNS/MaxDNSsize` 挂在监听器上。
- **为什么好**：ROADMAP 第 8 项（S5 首个冷门通道）候选首位就是 DNS/DoH，但**我们连"查询怎么编码、多大 MTU、TXT 怎么回、无响应怎么重试"的最小骨架都没有**。这份骨架（哪怕不完整）能省掉一轮"从零设计线格式"的成本。
- **ToShell 落地成本**：**中~大**（新通道本身是 12 类落点，见 B1）。若先做 B1，则只剩"一个适配器 + 一个服务端监听器"。
- **风险/坑**：① DNS 通道**吞吐极低**（`MaxSize` 512 级别），只能当控制面，不能传文件；② 需要**域名与委派运维**（ROADMAP 已记为外部材料依赖）；③ 企业 DNS 日志/NRDS 会让隐蔽性远低于直觉，别在文档里吹"绕过出口管控"；④ `:53` 绑定需要特权端口，服务端部署形态要一并说明。
- **建议版本**：**v1.6**（v1.5 先做 B1）。

### B7 流式帧的"多查看者广播 + 压缩 + 投递计数"

- **现象**：`stream_hub.go:52-57` 按 `(streamKind, clientID)` 维护查看者集合；`:170-196` 的 `publish` 逐个投递并返回**成功投递数**；`:205-247` 把 `screen_frame:` 载荷 base64 解出后 **zlib 压缩**再下发（`:269-282`，级别明确写"占位值，不是原版参数"）。
- **为什么好**：ToShell 的屏幕流是 `api.BroadcastScreenFrame` 一把广播（`listener.go:126` 回调注册），**没有"投递成功数"**，也没有"压缩级别/查看者数"这类可观测信号；出问题时只能看"前端黑屏"。多查看者 + 投递计数 + 压缩是最小可用的诊断面。
- **ToShell 落地成本**：**小**。改动面：`api/screen_frame_limiter.go` 加 `delivered/skipped` 计数并进 `/system/stats`，WebSocket 推送处记录慢消费者（丢弃计数）；压缩已有（帧为 JPEG/PNG，可选 zlib 只对文本类结果有意义）。
- **风险/坑**：① **别给图像帧再套一层通用压缩**（JPEG 已压缩，二次压缩只吃 CPU），vshell 那层 zlib 是它的原版约定，我们不该照搬；② 计数器要防溢出/高基数（按会话聚合，不要按帧存）。
- **建议版本**：**v1.4.x / v1.5**（纯可观测性，风险最低）。

### B8 统一列表契约 + 批量操作

- **现象**：所有列表接口同一套参数 `page / pageSize / field / order / search / sort`，响应 `{total, items}`（`controllers/tunnel.go:20-46`、`controllers/client.go`、`controllers/listener.go` 同形）；批量删除统一 `dellist` 收逗号分隔 id 列表（`tunnel.go:113-126`，client/listener/file/process 都有对应端点，见 `router/router.go:36-96`）。
- **为什么好**：ToShell 的列表接口是各写各的（`docs/skills/toshell-api/SKILL.md` §2 里 `/sessions`、`/tasks`、`/plugins`、`/intel` 参数名与筛选能力都不一致），且**没有批量操作 API**（`internal/server/api` 里搜不到 `bulk/batch`）。批量是"横向阶段"的刚需：一次给 20 台机器下发同一条侦察命令，现在只能循环调 20 次。
- **ToShell 落地成本**：**小~中**。改动面：`api/router.go` + 各 `handlers_*.go` 的列表签名统一（`page/page_size/sort/order/q`）+ 新增 `POST /sessions/bulk`、`POST /tasks/bulk`（复用现有下发 helper + 逐项结果数组 + 部分失败语义）+ 前端表格列复用。
- **风险/坑**：① 批量下发必须**逐项独立事务**并回"每一项的成功/失败原因"（别一个失败全回滚）；② 批量操作要进审计（一条记录带 N 个目标，不要展开成 N 条噪声）；③ 统一列表契约是**破坏性 API 变更**，要么加版本前缀，要么保留旧参数别名一版。
- **建议版本**：**v1.5**。

### B9 RBAC 的"形态"，不是它的实现

- **现象**：`utils/auth.go:72-103` 把角色定义成 `super/admin/user` + **路径前缀白名单** + 权限判定 `HasPermission(role, path)`（`:137-151`），JWT 里带 `role_id`（`:74-81`）。
- **为什么好**：ToShell 的鉴权是"全有或全无"：JWT `Claims` 里有 `Role` 字段（`internal/server/auth/auth.go:18-22`），但登录时**固定写 `"admin"`**（`api/handlers_auth.go:140`、`:156`），**没有任何基于 role 的判定**。一个"只读观察员"和"能下发 BYOVD 的操作员"目前等价。这在多人协同演练里是真实缺口（也是 MCP/Agent 权限分级的自然延伸）。
- **ToShell 落地成本**：**中**。改动面：路由注册处加 `requireRole(...)` 元数据（不要用路径前缀字符串匹配）+ 角色→能力表（与 `avops` 的 read/confirm/danger 三档对齐）+ 审计字段 + 设置页角色管理（先固定 3 个内置角色，不做自定义）。
- **风险/坑**：① **前缀匹配本身就是坑**：`/api/client/` 前缀会把"编辑/删除"也放进来（vshell 的 `RoleAdmin` 正是这样，`:94-99`），我们要按**路由元数据**授权；② 单账户模型下做 RBAC 会立刻暴露"没有用户库"的问题（要一并做最小用户表）；③ 不要做"前端隐藏按钮 = 权限"（服务端必须二次判定，参考 MCP 的守卫测试做法）。
- **建议版本**：**v1.5 评估 / v1.6 落地**（先做"角色→路由元数据"骨架 + 审计，不动 UI）。

### B10 UDP 通道（KCP 风格）的抗丢包与分片口径

- **现象**：`agent/main.go:294-460`：KCP 传输用 `maxKCPFrame = 60000`（`:352`）、`writeFrame`/`writeFragmented`（`:360`、`:392`）做分片，`kcpBlockCrypt`（`:319`）用 salt 派生块加密；`c2engine/kcp.go` 是服务端侧的 KCP 监听器（含 FEC 依赖，见 `go.mod:8` 的 `kcp-go/v5`）。
- **为什么好**：ToShell 已有 `internal/common/tunnel/quic/{client.go,server.go}` 的可复用骨架，但**全仓库没有任何地方 import 它**（`grep tunnel/quic` = 0 命中）→ 未接线。UDP 通道的价值不是"更快"，而是**在丢包/高延迟链路上保持会话**（跨境/移动网络/劣质线路），这正是 v1.6 的目标场景。
- **ToShell 落地成本**：**大**（依赖 B1 的落点收敛；且需真机弱网验证）。
- **风险/坑**：① 企业网**大面积封 UDP**，做成默认通道会掉线率上升，只能按 tag 可选；② 分片重组是最容易出安全 bug 的地方（长度/序号/上限校验必须 fail-closed，参考 `listener/handler_core.go:214-240` 对 offset/size 的校验纪律）；③ 与 QUIC 骨架二选一，别同时维护两套。
- **建议版本**：**v1.6**（先 B1，再选 QUIC 或 KCP 一条）。

---

## 4. 不建议借鉴的 5 个点

| # | 不建议的点 | 它怎么做（证据） | 为什么不借 |
|---|---|---|---|
| N1 | **明文 JSON 回退 + key 走 query string** | `listener.go:286-303`：JSON 解析失败才尝试 GCM 解密，否则 `400`；`listener.go:379-389`：任务通道用 `?verify_key=` 鉴权 | 密钥进 URL 会被反代/网关/浏览器历史记录留存；"先试明文"等于给探测者一个**无密钥也能探活**的判别面（返回 JSON 错误 vs 400 的差异）。ToShell 的做法是帧级 AEAD + 独立鉴权（`packet.go` 帧类型 + 会话注册校验），不要退回混合模式。 |
| N2 | **`md5(salt)` 当 AES 密钥** | `protocol.go:196-208`：`FrameSaltKey = hex(md5(salt))`，32 个 ASCII 字符直接当 AES-256 密钥；盐每监听器共享 | 无 KDF、无迭代、无每会话随机、无前向安全；盐泄漏=全量历史帧可解。ToShell 已有 AES-256-GCM + SM4 域分离（`internal/common/crypto/*`），**不要为了"对齐"把密钥派生做弱**。 |
| N3 | **内置 RSA 私钥做 license 校验 + 失败静默降级** | `utils/license.go:1-17`（私钥内置于服务端）、`README.md:187-193`（私钥不包含 → 回退默认值 `public/20990101/99 clients/VIP`） | 私钥在服务端二进制里 = 授权形同虚设；"校验失败用默认值继续跑"是**fail-open**，会把"授权过期"变成"没人知道"。ToShell 是 MIT 全功能开源，**不需要授权门控**，更不要引入"悄悄降级"。 |
| N4 | **双存储（SQLite + JSON）与"读侧多次容错解析"** | `c2engine/storage.go`（SQL + JSON 两份）、`listener.go:465-470`（结果帧有两种形态、只对"都不是"才拒绝） | 双写一致性、迁移、备份都会翻倍；多形态容错解析会让"到底哪个是权威格式"长期含糊（vshell 自己的注释就承认"当前唯一有生产者的形态"是 JSON）。ToShell 单 SQLite + 幂等 DDL（`database/agent_schema.go`）已经够用。 |
| N5 | **前端资源从原版二进制抽取 / 复刻品牌外观** | `README.md:199`（SPA 从原版二进制提取）、`static/**`、`static/index.html` 标题为中文"管理平台" | 版权风险（见 §0）；且外观/文案与商用产品一致会带来**识别与归因风险**。ToShell 的前端必须自研（现为 React/Vite），"中性化外观"只做到"像正常业务系统"，不做品牌冒充（`builder/patch_resources.go` 的 `resource_preset="neutral"` 已按这个原则实现）。 |

---

## 5. 对 ToShell 的净结论（3 + 3 + 3）

### 立刻做（成本低、收益直观，v1.4.x / v1.5 前置）

1. **可观测性补 3 个计数**：屏幕帧 `delivered/skipped`、WS 慢消费者丢弃数、广播去抖抑制次数，全进 `/system/stats`（现状端点已存在：`api/api.go:558`）。依据：B7；对应 ROADMAP 的 P1-6（"可观测性计数上界面"）。
2. **统一列表契约 + 批量下发**：先只做 `sessions` 与 `tasks` 两张表的批量操作（复用现有下发 helper，逐项返回结果），并把参数名统一为 `page/page_size/sort/order/q`。依据：B8；`internal/server/api` 现无 `bulk/batch`。
3. **把"未验证"钉进代码而不是只写在文档里**：给 `transport_tls_utls.go`（uTLS）与 `mimicry`（HTTP 反代）各加一个"能力自述 + 未验证标记"的守卫用例，避免文档与代码继续漂移（本次分析已发现 4 处漂移，见 §6）。依据：表"TLS 指纹"行、`config.go:296-313`。

### 评估（需要设计一轮再动手）

1. **通道落点注册表（B1）**：收益最大但改动最深，须先写一页"注册表契约"（端点集合、能力标志、fail-closed 规则、探测面自检）再动手；否则会重演 S5 第 0 步"必须先收敛探测面"的顺序问题。
2. **载荷请求时生成 + 一次性 URL（B2/B3）**：先只做"同一组参数 60s 缓存 + 过期 URL"，不动"现场全量构建"；观察构建耗时与并发上限再决定是否扩大。
3. **RBAC（B9）**：只先做"角色→路由元数据 + 审计 + 服务端判定"，UI 与用户库放后；JWT `Role` 字段已存在（`internal/server/auth/auth.go:18-22`），改造成本主要在"给 100+ 条路由打元数据"。

### 明确不做

1. **不做"与 VShell 互操作"**（协议兼容、接管其会话、读它的插件格式）：无授权依据（§0），且会把两个错误码体系绑死。**依据**：`vshell/README.md:201`（"interop … not guaranteed; intended for independent research only"）。
2. **不引入第二套存储或"多形态解析容错"**（N4）：ToShell 单 SQLite 已支撑 agent 4 张表 + 任务 + 会话；加 JSON 副本只会把备份/迁移/对账变成三份。
3. **不做"免杀承诺型"功能**（如"绕过某 EDR"的自动选路）：当前 `docs/EVASION.md` 的纪律是"没有目标机就不出运行期结论"，而 `vshell` 在这块**没有任何可借鉴的实测数据**（全库无 EDR 对抗实现）。依据：`vshell/README.md:194-201`（已知限制全在"协议/许可/前端"层面，无对抗层）。

---

## 6. 附：本次核实出的"文档与代码不一致"清单（供修文档，不在本文改代码）

> 这些是**分析副产品**，已同步写进 `ROADMAP.md` 的「技术债」与「v1.4.1 登记」，此处保留原始证据以便复核。

| # | 文档原话 | 代码事实 | 处置建议 |
|---|---|---|---|
| D1 | ROADMAP「S5 第 0 步延伸」：uTLS/JA3 **未开工** | `internal/server/builder/implant/transport_tls_utls.go:1-61` 已实现 uTLS（`HelloChrome_102`，`go.mod` 里是 `refraction-networking/utls v1.4.0`，仅 `transport_http && !light`）；缺的是 **JA3 抓包验证与真机联调** | 改成 🟡「已实现、未验证」 |
| D2 | ROADMAP「发版门禁（接进 CI）❌ 未做」 | `.github/workflows/release.yml:40-69` 已有 `e2e-smoke` job 跑 `scripts/e2e_smoke.ps1 -SkipImplant`，且发布 job `needs: [web, e2e-smoke]`（`:76`） | 改成 ✅，并把"托管 runner 固定 `-SkipImplant`"写进口径 |
| D3 | ROADMAP「缺陷①/② ❌ 未开工」 | `09e3bbe`（前端按轮次切 timeline + SSE 水位线）、`9c98599`（并行 `tool_calls` 全量遍历）已修；回归用例在 `internal/server/ai/parallel_tool_calls_test.go` | 改成 ✅ 并归档 |
| D4 | ROADMAP/README：WS 拟态"只回 404、不反代" | HTTP 监听器已支持 `mimicry_site` **反向代理真实站点**（`internal/server/listener/http_polling.go:280-283`）与 `mimicry_profile` 响应整形（`internal/server/mimicry/mimicry.go:81-119`）；WS 侧确实只 404 | 分开写：HTTP 🟡（已实现未验证）、WS ❌ |

---

**维护约定**：本文只随"重新分析"更新；`vshell/` 目录不提交、不打包、不进发布包（`.gitignore` 已加）。任何"借鉴"落地时，**提交信息必须写明"设计参考、代码自研"**，禁止出现与 vshell 相同的类型名/常量名/文件结构。

---

## 7. 致谢（写在这里，也写进 README 与 Release 说明）

**感谢 [VShell](https://github.com/veo/vshell) —— 早期开放源码的老牌 C2 项目（后续已闭源）。**

它在公开阶段留下的设计与工程取舍，是这个领域后来者共同的"参考地面"：本文列出的 10 条可借鉴点，多数来自拿它的公开做法与我们的现状对表，而不是来自任何代码复制。v1.4.1 落地时的**隧道持久化（B4）、批量操作（B8）、屏幕流投递计数（B7）**三项，就是这张表的直接产物。

同时把边界写在致谢旁边，避免被误读：

- 我们**没有**复制它的代码、前端资源（SPA）、协议常量或协议格式；
- 本文的 `文件:行` 引用**只用于让结论可核核查**，不构成任何代码许可；
- 它的早期开源姿态值得感谢，但"现在已闭源"也意味着后来者更应当**只借思想、不借实现**；
- ToShell 的协议、前端、构建流水线全部自研，`LICENSE` 仍是 MIT（仅覆盖本项目自己的代码）。
