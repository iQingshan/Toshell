# ToShell 后续优化路线（ROADMAP）

> **本文只回答三件事：做完没、还差什么、下一步做什么。** 每条只保留现状（代码事实）、剩余项与验收口径，不重复发版说明。
> **状态口径只有一处**：下方「v1.4.0 状态总览」表（一行一个交付项，取值仅 `✅ 完成` / `🟡 部分完成` / `❌ 未开工` / `⚠️ 卡在本地 stash` / `🚫 已定论不做`）；「后续优化清单」给收尾顺序与四段验收口径；各阶段详情只补充方案与证据，不另判状态。
> 已完成的项归档在本文件底部「已完成」章节；更新日志（实现细节）见 [CHANGELOG.md](CHANGELOG.md)，免杀实现现状见 [docs/EVASION.md](docs/EVASION.md)，不落地上线手段见 [docs/LOADERS.md](docs/LOADERS.md)。v1.4.0 之前的 P0~P3 条目池降为「附 A」（只保留背景与验收口径，不再单独判状态）。

---

## 当前版本状态（v1.4.0 已发布 · 2026-09-28；下表为 v1.3.5 基线）

| 能力 | 状态 |
|---|---|
| 会话判活 | ✅ 不再抖动（阈值含 3 倍心跳余量 + 广播去抖；实测 60s 心跳连跑 220s 零抖动、真掉线仍按 3m1s 判死） |
| 屏幕流/截图（Windows） | ✅ 参数化（fps/quality/max_kbps/monitor/max_width）+ 带宽自适应 + 服务端限速；实测 2560×1440 → 640×360（343KB → 21KB） |
| 屏幕流/截图（Linux/macOS） | ❌ 仍为 stub（`screen_stream_unix.go` 只回 "only supported on Windows"）；跨平台排期见「后续优化清单」第 9 项 |
| 内存执行 | ✅ shellcode / BOF / DLL / **EXE（反射映射 + 参数注入）**；✅ **下发前 PE 预检**（Go 载荷/架构不符/.NET 直接拒绝，TLS 无重定位给警告，可 `force` 强制） |
| BYOVD 驱动 | ✅ **不内置任何驱动**（操作员自备 .sys + manifest 档案）；✅ 驱动击杀/档案登记/会话级记忆；✅ **加载前自检**（sha256 一致性硬拦 + Authenticode 签名者 + 易受攻击驱动黑名单提示） |
| C 植入端工具链 | ✅ 探测鲁棒（配置/环境变量/便携目录/注册表 PATH）+ 架构校验 |
| 通知 | ✅ 飞书/钉钉/企业微信/Slack/Discord 各自结构 + 业务码判定 |
| 运行时行为足迹 | ✅ 启动自动"枚举进程找杀软"默认关闭（`evasion_scan` 显式开启）；pclntab 高信号名中性化；**BOF 默认不编译（`beacon*`=0）**；**Go buildinfo/构建 ID 已擦除**；启动延迟/心跳节奏可按载荷配置 |
| 构建后代码签名 | ✅ pfx / 证书存储指纹两种模式 + 签名栈回退 + 签名后复核 + 前端显示；本机实测自签已签上（`SignatureType=Authenticode`、+1.4KB），"链不受信任"与"未签名"已如实区分 |
| 加载器链模板 | 🟡 8 条链的**命令模板与降级建议**已实现（`oneliner.go` + `docs/LOADERS.md`）；**真机落地实测未做**（无验收环境，见总览 S3 行） |
| 动态免杀（运行时行为） | 🟡 第一批已实现（sleep mask 休眠期内存加密 + apihash/PEB 手工解析 + 直接系统调用 + 去 RWX）；**运行期零实测**（本机杀软会删除任何新生成的 PE） |
| Web 控制台 | ✅ 主题 token 统一 + 组件层（卡片/分组/徽标/提示条/空态/骨架屏）+ 键盘焦点可见；生成载荷页分组折叠、命令分组/搜索/风险等级、载荷 ID 一键复制与填入、签名结论与落地建议；会话详情「更多 ▾」收纳；顶栏状态为真实 `/health` 探测 |
| 发版门禁（脚本与 CI 校验） | ✅ `scripts/e2e_smoke.ps1`（临时服务端 + 三档载荷 + 关键接口 + 可选真植入端上线，实测 19 项 0 失败）+ CI 侧 tag/版本号一致性、zip 内容清单与 `checksums.txt` |
| 发版门禁（接进 CI） | ❌ 未做：tag 前 workflow 还没调用 `e2e_smoke.ps1`（见「后续优化清单」第 10 项） |
| 平台工具库 `data/tools/` | ❌ 未建设（目录下只有 `.gitkeep`，无 manifest、无工具）；排期见「后续优化清单」第 7 项 |

> **v1.4.0 迭代项的完成情况不在本表** —— 唯一权威口径是下方「v1.4.0 状态总览」，同一件事只在一处判状态。

---

## v1.4.0 迭代计划（已随 v1.4.0 发布落地 · 剩余项转入「后续优化清单」）

> **执行方式**：分 6 个阶段，每阶段**先在本地完成实现与验证**（编译 / 类型检查 / 单元测试 / 本地服务端与 UI 联调），确认通过后再提交推送。
> **详细方案**（接口签名、DDL、YAML、协议报文、里程碑人日、验证矩阵）保存在本地文档 `docs/plan/*.md` 与 `docs/PLAN-NEXT-ROUND.md`（**不入库**）；本节即为其入库版本。
> **状态取值只有 5 个，不许含糊**：`✅ 完成`（已实现 + 有实测证据）/ `🟡 部分完成`（主体做了，**未做子项写在同一行的"剩余什么"里**）/ `❌ 未开工` / `⚠️ 卡在本地 stash`（被叫停的半成品）/ `🚫 已定论不做`（附依据）。

### v1.4.0 状态总览

| 交付项 | 状态 | 一句话依据（实测/证据） | 剩余什么 |
|---|---|---|---|
| **S1** 开放 MCP 接口 + 公共执行基础设施 | ✅ 完成 | 注册表 38 工具（read 13 / confirm 14 / danger 11）三处同源；`scripts/mcp_smoke.ps1` **18/18**（无/错 token 401、会话头 400、危险默认 403、路径穿越 403、超 RPM 429）；`go test ./internal/server/mcp/...` ok | 无 |
| **S2** 内置 Agent 长任务可靠性 | 🟡 部分完成 | 状态机 + 4 张表 + `agentstore` + 重启对账、长结果外置回读、上下文四层 + token 双预算、三处硬上限 + 防死循环、分级审批、trace + SSE 断点续传**全部落地**；离线黄金集 **12 例**随 CI；`go test ./...` 全绿（13 包）；`scripts/e2e_smoke.ps1` 19 项 0 失败 | ① 评估门禁的**在线**部分（`/agent/metrics` + 前端状态条，原计划标为可选）未做；② `tasks.output` 仍截断 **500 字节**，限制重启恢复的结果长度；③ 挂起会重置 `max_wallclock`/`max_turns`，token 用量未落 `agent_runs`；④ `ai.long_task_threshold_sec` 只走 YAML，未进设置页 PUT 白名单 |
| **AI 修复 ①** 流式调用改空闲超时 + LLM 失败原因可见 | ✅ 完成 | commit `db2bccd`；`ai.timeout` 语义从"整段回答上限"改为"连续多久没收到数据"，出错兜底正文**必带失败原因** | 无 |
| **AI 修复 ②** `assistant.tool_calls` 与 `tool` 回执不成对导致 400 | ✅ 完成 | commit `27dbb90`；缺 id 补 `call_auto_<index>`，新增 `context.sanitizeToolPairs()` 装配出口补齐 + `tool_pair_test.go`（6 子用例）；`go test ./...` **19 包全 ok** | 无 |
| **缺陷 ①**（本轮新发现）前端把 run 跨轮时间线当"本轮步骤"重画 + 每轮 SSE 水位线从 0 起 | ❌ 未开工 | 代码事实：`web/src/pages/Copilot.tsx` 的 `buildActs()` 用 `tl.slice(-80)` 整条 timeline 重画（未按 `run_id + seq` 去重）；服务端对终态 run 的无水位线订阅会回放缓冲尾部。表现为界面"看起来又重复执行了一遍"（已实测**不影响模型输入**） | 前端按 `run_id + seq` 去重；服务端让终态 run 不再被无水位线订阅回放（详见「后续优化清单」第 1 项） |
| **缺陷 ②**（本轮新发现）同一条 assistant 消息里的第二个并行 `tool_calls` 被静默跳过 | ❌ 未开工 | 实测：一次声明 `session_list` + `session_context`，审计日志只有第一个，第二个**既没执行也没记录**；目前仅由 `sanitizeToolPairs()` 补的"未完成回执"兜住协议正确性 | 定位并行 `tool_calls` 的处理/去重路径并修复 + 黄金集用例钉住（详见第 2 项） |
| **S3** 静态降特征（字符串混淆盲区 / DLL 路径 / Go 版本串 / PE 资源 / `.symtab`） | ✅ 完成 | 实测：DLL 明文高信号 API 名 11 处 → 0、`http://` 2 → 0、ETW 4 → 0；`go1.20.14` 残留 1 处 → 0；资源开启后 +2048 B（默认不注入时字节数与改前完全一致）；`.symtab` 删除后 **−512 B**、节数 6→5；五份产物 `LoadLibraryEx` **5/5 LOADER OK** | 已知边界：C 植入端（mingw）未接入资源修补；**签名后的真实复核仍需真实证书**（本机只有顺序契约 + 单测） |
| **S3** 落地链与验收环境 | ❌ 未开工（缺验收环境与材料） | 8 条链目前只有**命令模板与降级建议**，无一条真机落地记录；本机未签名 PE 在**进程创建阶段**即被拒（连 Hello-World Go 也一样）→ 本机做不出运行期结论；两级验收环境至今未建立 | 真实证书/EV + 信任链落地；白加黑 / 不落 PE 加器链真机实测；干净 VM（仅 Defender）+ 装 360 的目标机 + 宿主 exe/DLL/SCT 素材 |
| **S3** 动态免杀批次 2（C2 地址/sessionID 改 `[]byte` 纳入 sleep mask、启动期 ntdll 脱钩 + ETW patch、单稳加固） | ❌ 未开工 | 批次 1（sleep mask / 去 RWX / apihash）已实现但**运行期零实测**；批次 2 未动一行代码，且依赖批次 1 的验收环境 | 同上一行（放行环境 / 目标机）；另需把 `docs/EVASION.md` §3.1 的动态测试矩阵脚本化 |
| **S4** 能力位图（前置阻塞项） | ✅ 完成 | `internal/common/features` 唯一纯函数（档案/tag/OS → 能力集 + `tabs` + `cap:v1:<hex>`）烘进载荷并随心跳上报；服务端 `Resolve()` 上报优先、老载荷按 OS 兜底并标 `source`。实测 light 载荷 **11 项**能力、tabs 仅 av·files·info·process·shell；full **31 项** | 无（"light 档也点亮注入/截图按钮"的旧缺陷已修） |
| **S4** `exec_module` 契约与 ABI | ✅ 完成 | `internal/common/moduleabi`（ABI v1，三份副本单测钉住）+ 一次性 token + 9 步校验链 + `TypeModuleData(0x0E)`；实测门控 **+27,136 B**、示例模块 **7,680 B**、`credentials` 搬模块可省 **67,584 B**；真机 E2E **21/21**、两份植入端镜像 **63 文件 SHA-256 一致** | 已知边界：**只真机测过 TCP 通道**（HTTP/WS/MQTT 已接线未真机跑）；单帧上限 **4 MiB** 未做分块；**未暴露给 MCP/Agent 工具面** |
| **S4** 体积实测矩阵（V0~V7） | ✅ 完成 | windows/386 同参数实测（发布版口径）：地板 801,280 B；核心标准库地板 2,010,624 B；light/tcp **2,946,805 B**；+`bof` = **0**；+`evasionscan` = +7,168 B；http **+2,508,808 B**；websocket **+2,150,923 B**；mqtt +2,452,993 B；full/tcp **+575,488 B** | 无（矩阵已落成本文件 S4 阶段的表格） |
| **S4** 体积分档结论（nano / light / full） | 🟡 部分完成 | light / full 两档已实现且有实测；但**目标体积未达成**（light 实测 2.95 MB > 目标 2.4 MB；full 3.52 MB > 目标 3.2 MB）；且**默认档仍是 `full`**（代码事实：`features.NormalizeProfile("")` → full、前端生成载荷页默认 `profile:'full'`）—— 本文件旧版"默认档改为 light"的说法与代码不符，已更正 | ① 默认档是否改 `light` 需明确定论；② `light ≤2.4 MB` 只能靠 stdlib 瘦身（手写 JSON/精简 `fmt`、避开 `crypto/tls`）后重测；③ 每档的功能对账表与构建命令待补齐 |
| **S4** nano（≤1.8 MB） | 🚫 已定论不做 | 实测核心标准库地板 **2.01 MB**（`net`+`json`+`fmt`）已高于 nano 目标 1.8 MB；Go 做不到，要做得换第二套 C 植入端，工作量与维护成本远超收益 | 不排入 v1.4.0；若日后有"≤1.8 MB 且要跨平台"的硬需求再单独立项 |
| **S4** 传输栈瘦身与模块化 | 🚫 已定论不做 | 实测 http/ws/mqtt 各 +2.1~2.5 MB，但这是 `net/http` + `crypto/tls` 的成本、**不是可裁剪的冗余**：现有构建已按通道 tag 只编一个传输，没有重复可回收；想省只能手写 TLS（不现实且不安全）或换 uTLS（只会更大） | 保持现状；把"要小就选 tcp 档"写进分档说明即可，不再为此投入 |
| **S4 / P2** 工具库与远程加载 | ❌ 未开工 | 代码事实：`data/tools/` 下只有 `.gitkeep`，无 `manifest.json`、无任何工具、无下载校验代码 | 目录规范 + `manifest.json`（sha256/来源/许可）+ 远程加载闭环「下载→校验→内存加载→执行→回传→清理」；需第三方下载源与哈希清单策略（第 7 项） |
| **S5 第 0 步** WS 主动探测面收敛（严格 `ws_path` + Host 名单 + `front_domain` + 中继 409） | ✅ 完成 | 改前**任意路径**都能升级、普通 GET 也回 400 + `Sec-Websocket-Version`（等于自报 WS 端点）；改后只对一条路径升级，变形路径/不完整握手一律普通 **404**（与未知路径逐字节不可区分）；`go test ./...` 全绿 + 真机 E2E（WS 载荷上线 + `whoami`、`curl --path-as-is` 探测不可区分、错 Host 被拒）；中继对非 TCP 通道明确 409 | 无 |
| **S5 第 0 步延伸** uTLS/JA3、WS 拟态、HTTP/2、真实 CDN 域前置 | ❌ 未开工 | 代码事实：WS 仍走 Go 标准库 TLS（本步不改 TLS 指纹、不加新 tag、不动 `go.mod`）；非 C2 路径只回 404、不反代伪装站；`ws_path` 还是全局配置，无 per-listener 覆盖 | 真实 CDN 域与证书做域前置联调；uTLS / 拟态 / HTTP/2 逐项实现 |
| **S5** 首个新通道（DNS/DoH/DoT、QUIC/HTTP2 之一） | ❌ 未开工 | 代码无对应实现（`internal/common/tunnel/quic/` 有可复用骨架但未接线）；成本约束：加一个新协议 = **12 类落点 / 20+ 处编辑**，其中 8 处"漏改就静默降级或编译失败" | 先端到端跑通**一条**（真实服务端 + 模拟植入端脚本联调）；按 tag 编译、默认只带 1~2 个通道；DoH/DoT 需域名与委派运维（第 8 项） |
| **S6** AV-L0 侦察 / AV-L1 温和 | ✅ 完成 | `internal/common/avops` 表驱动分级 + 8 个既有动作全部登记（逐条核对植入端 `executeTask` 与能力位）；聚合入口 `GET/POST /api/v1/sessions/{id}/av-ops`（服务端定级 + 七步前置检查 + 影响评估 + 审计）；**L0 `av_detect` 真实下发回传实测**；`go test ./...` 18 包全绿；注册表仍 38 工具 + 两条守卫测试钉住"L1+ 不可能经工具面触达"；前端「对抗分级」面板已上线 | 无（协议层唯一保底口径见阶段详情：植入端每次新连接会 `clearResultCache()`，"同一 task ID 再送一次必再执行"在协议层仍成立） |
| **S6** L2 / L3 / L4 真实执行验证 | 🟡 部分完成 | 已有实测：L2+ 默认 `allow_l2/l3/l4=false` → **被拒**（缺 confirm→409、tier 不符→400、未知动作→400、L2→403、L3 无驱动→409、超上限→400，且被拒动作**没有产生任何任务**）；L0 真实下发回传有记录。**放行路径零实测** | **L2/L3/L4 真实执行未验证**（需授权 VM + 快照 + 操作员自备 `rw`/`kill` 档 `.sys`）；面板侧"破坏性动作成功下发"分支同样未实测（真机只点到"弹确认层后取消"） |
| **S6** L4 落地动作 | ❌ 未开工 | 代码事实：`TierL4.Implemented = false`、`ActionsOfTier(TierL4)` 为空（有单测断言为 0）；`avops.allow_l4=true` 也不会让任何动作变成可下发（刻意不造"点了没反应"的假入口） | 需要植入端独立的 AMSI/ETW 抑制任务类型 + 登记进 L4 + 前端入口。AMSI patch 对 Go 默认载荷收益≈0，只在进程内加载 .NET/脚本时才有意义 |
| **S6** 驱动体系（`purpose` 选路 / 残留驱动清场 / catalog 签名驱动） | ❌ 未开工 | 代码事实：`ppl_kill` 仍只走句柄窃取；无按 `purpose`(kill/rw/both) 自动选路、无进程重启后的残留驱动服务清场、catalog 签名驱动只能给"未内嵌签名" | **纯代码项、无外部材料硬前置**（可先做）：`purpose` 选路 + 缺档时明确提示"无 rw 档驱动，PPL 清除不可用（走句柄窃取）" + 清场任务 + `CryptCATAdminCalcHashFromFileHandle` |
| **S6** 内存执行加固（hook `ExitProcess`/`RtlExitUserProcess` + stdout/stderr 重定向） | 🟡 部分完成 | 已从 `git stash@{0}` **捡回并补完**（新增 `mexecguard_windows.go` + `imgexec_windows.go` 重构 + `apihash_windows.go` 转发导出修复 + `memprotect_windows.go` 注销 + `config.go`/`handlers_auth.go`/`handlers_settings.go`/`task.go` 与四个 listener），含同 stash 的**「配置热重载报错可见」**；真机实测（windows/386 植入端 + mingw 32 位 `exit7.exe`，TCP 全链路）：改前 HEAD 模板下载荷执行**当秒** `Connection cleared` → 15s 后 `广播 session_offline`、任务停在 `sent`；改后 30s 内 **15 次采样全程 `active`**、退出码 **7**、载荷 stdout `HELLO_MEMEXEC`、`whoami` 回执正常，连续两次 `exe_mem` 与 `exit` 自杀均正常；配置写坏 → error 级原始错误 + `/settings` 回传原文 + `/health` `ok:false` | ① 运行时 `GetProcAddress` 解析地址后裸调 / 静态链入的退出调用**拦不到**；② `TerminateProcess(自身真实句柄)`/`NtTerminateProcess(真实句柄)` 放行（桩只认 `GetCurrentProcess()` 伪句柄）；③ `WriteFileEx`/`NtWriteFile`/自开 `CONOUT$` 的输出不捕获，**且宿主自身没有有效 std 句柄时（无控制台方式启动，例如被 WMI/服务拉起）同样捕获不到** —— 此时结果里会明确写"未捕获到任何内容（可能原因…）"而不是给空串；④ 原计划的 **inline hook 双保险未做**（只做 IAT 层）；⑤ `dll` 路径在宿主线程上同步执行被映射代码，该分支**未真机验证**（详见 S6 阶段详情 P0-2 段） |
| **S6** 屏幕流 / 截图跨平台（P0-3） | ❌ 未开工 | 代码事实：只有 Windows 实现（GDI BitBlt + PrintWindow 回退）；`screen_stream_unix.go` 是 stub（`//go:build !windows && !light`，直接返回 "only supported on Windows"）；无 X11 / ScreenCaptureKit / DXGI 代码 | Linux(X11) / macOS(ScreenCaptureKit) / Windows DXGI 增量捕获；三项都必须真机验证（第 9 项） |
| **S6** 工程收尾（P3） | ❌ 未开工 | `scripts/e2e_smoke.ps1` 已存在但**未接进 CI**；前端任务列表虚拟滚动、Sessions/仪表盘 WS 事件统一订阅、运行指标上界面、服务端在线更新均无实现 | e2e 接 CI（零依赖可先做）；多通道语义对齐；配置热更新边界文档化；前端虚拟滚动 + WS 统一订阅；可观测性上界面；自更新（需先做服务化守护 + 可信更新源决策，第 10 项） |

### 后续优化清单（按优先级，v1.4.0 发布后收尾）

> **排序依据**：① 先修**用户已实测到的**正确性/可观察性缺陷（改动小、收益直观）→ ② 再处置**已有半成品**（丢掉就白丢）→ ③ 再做**零外部材料依赖**的纯代码项（可与其他项并行）→ ④ 最后做"**没有操作员提供的材料就无法验收**"的事，并按"谁阻塞谁"排（S3 验收环境是动态批次 2 与 S6 真机验证的共同前置，所以排在它们前面）。
> 本清单取代旧版「下一步优先级」表：编号即执行顺序，每项补齐"做什么 / 为什么 / 验收口径 / 需要你提供什么"四段。

#### 1. 前端时间线 + SSE 水位线去重（"看起来重复执行"）

- **做什么**：`web/src/pages/Copilot.tsx` 的 `buildActs()` 改为按 `run_id + seq` 增量渲染（不再对整条 timeline 做 `tl.slice(-80)` 重画）；`agentApi.events()` 保存每个事件的 `id:` 水位线并以其续订；服务端让**终态 run 的无水位线订阅不再回放缓冲尾部**。
- **为什么**：本轮**用户直接实测反馈**的缺陷 —— 界面把前几轮步骤重画一遍、上一轮答复正文被再追加一次，掩盖真实进度（已实测**不影响模型输入**，属显示/续接层）。改动小（前端为主 + 服务端一处），收益最直观。
- **验收口径**：同一 run 连发 3 条指令，界面上每轮步骤只出现一次、无重复正文；服务端新增断言"终态 run 无水位线订阅不回放"；`npm run build` 通过 + `go test ./internal/server/ai/...` 绿。
- **需要你（操作员）提供什么**：无。

#### 2. 同一条 assistant 消息里的第二个并行 `tool_calls` 被静默跳过

- **做什么**：`internal/server/ai/` 循环里的 `tool_calls` 处理改为遍历**全部**声明项（不得因第一个已处理/去重而跳过后续），并补审计与 `tool` 回执。
- **为什么**：Agent **正确性**缺陷 —— 模型声明了工具却不执行、也不留痕，模型只能靠"未完成回执"重试，任务会静默走偏；现在只有 `sanitizeToolPairs()` 兜住协议正确性。
- **验收口径**：一次声明 `session_list` + `session_context`，两者都进审计与 `tool` 回执；新增黄金集用例（`internal/server/ai/testdata/golden/cases.json`）；`go test ./internal/server/ai/...` 绿。
- **需要你（操作员）提供什么**：无。

#### 3. 捡回 / 丢弃 `git stash@{0}`，补完内存执行加固 —— ✅ 本轮已完成（保留编号以免打断交叉引用）

- **做什么**：先决策**捡回还是丢弃重做**，然后补完 hook `ExitProcess`/`RtlExitUserProcess`（IAT + inline hook 双保险，把载荷退出改成只退线程 → 宿主不掉线）与 stdout/stderr 重定向捕获；同 stash 里被叫停的「配置热重载报错可见」（`config.go` / `handlers_settings.go` / `handlers_auth.go` / 四个 listener）一并处理。
- **为什么**：它是 S6 验收项"`exe_mem` 跑原生工具后植入端不掉线"的**前置**；半成品已 20 文件 / +454 −204，丢掉等于白丢已完成的重构，捡回则需复核被叫停处的正确性（`release/implant/*` 镜像要同步）。
- **验收口径**：`attrib.exe`/`cmd.exe` 在 `exe_mem` 下执行完植入端**不掉线**、带输出的工具能拿到回传内容；配置热重载出错时设置页能看到原因（不再静默失败）；`go test ./...` 全绿。（真机放行环境见第 4/5 项。）
- **结果（本轮）**：已**捡回并补完**（`git stash@{0}` 仍保留作备份，未 drop）。真机验收：改前 HEAD 模板下载荷执行**当秒掉线**（`Connection cleared` → 15s 后 `广播 session_offline`、任务停在 `sent`），改后 30s 全程 `active` + 退出码 **7** + stdout `HELLO_MEMEXEC` + `whoami` 回执 + 连续两次 `exe_mem` + `exit` 自杀均正常；配置写坏 → error 级原始错误 + "继续使用旧配置" + `/settings` 回传原文。`go build`/`go vet`/`go test ./...`（**19 个测试包**）全绿、两份镜像 **64 文件 SHA-256 一致**。**未做**：inline hook 那一半（IAT 层已够用，理由见 S6 阶段详情）；`attrib.exe`/`cmd.exe` 本身未单独跑（用的是等价的自编 32 位原生 exe）。
- **需要你（操作员）提供什么**：无（本轮已闭环）；若要扩到 amd64 与 HTTP/WS/MQTT 通道可再排一轮。

#### 4. S3 验收环境 + 落地链

- **做什么**：建立两级验收环境与测试矩阵脚本（干净 VM（仅 Defender）+ 装 360 的目标机）；真实代码签名（pfx/EV）+ 信任链落地；白加黑 / 不落 PE 加器链真机实测（`oneliner.go` 8 条链 + `docs/LOADERS.md`）；并把"在哪一层被拦 → 该做哪一类改造"的判定矩阵落成脚本。
- **为什么**：**没有目标机，S3 全部结论都无法验收** —— 当前所有免杀结论只有静态/结构级证据（字节数、节表、loader 接受性、单测）；它同时是第 6 项（动态批次 2）的前置。本机连新生成的 PE 都无法执行（进程创建阶段即被拒）。
- **验收口径**：目标机上给出"**签名载荷可执行 / 白加黑链可执行**"的实测记录；干净 VM（仅 Defender）里默认载荷执行后 5 分钟内不触发 `Behavior:` 类拦截；判定矩阵脚本能输出"被拦层级 → 改造类别"。
- **需要你（操作员）提供什么**：**真实代码签名证书或 EV 证书**；**干净 VM（仅 Defender）+ 装 360 的目标机**；宿主 exe / DLL 名 / SCT 等加器链素材。

#### 5. S6 驱动体系 + L2/L3/L4 真机验证 + L4 落地动作评估

- **做什么**：`purpose`(kill/rw/both) 真正驱动选路（`ppl_kill` 自动挑 `rw` 档，没有就明确提示）；进程重启后残留驱动服务清场任务；catalog 签名驱动（`CryptCATAdminCalcHashFromFileHandle`）；然后在授权 VM 上逐个放行 L2/L3/L4 做真机验证，并评估 L4 的落地动作（植入端独立 AMSI/ETW 抑制任务类型）。
- **为什么**：爆炸半径最大，必须在授权实验环境、有快照、且由操作员自备驱动；`ppl_kill` 的选路与清场是它的直接阻塞项。**其中"驱动体系"是零外部材料依赖的纯代码项，可以先动手，不必等 VM。**
- **验收口径**：放入 `rw` 档驱动后 `ppl_kill` 打印命中的 EPROCESS 与 Protection 原值/新值；`kill` 档能杀普通杀软进程；manifest 哈希不符的驱动加载时 400 拒绝；L2/L3/L4 各留一条真机执行记录（或明确"不做"的定论）；面板"破坏性动作成功下发"分支实测。
- **需要你（操作员）提供什么**：**授权实验 VM + 快照**；**操作员自备的 `rw` / `kill` 档 `.sys`**（项目不内置任何驱动）。

#### 6. S3 动态免杀批次 2

- **做什么**：C2 地址/sessionID/关键配置改成 `[]byte` 存取以纳入 sleep mask（真实工作量在 `string`→`[]byte` 重构，且掩码只能覆盖空闲窗口）；启动期 **ntdll 脱钩 + ETW patch**（AMSI patch 对 Go 默认载荷收益≈0，只在进程内加载 .NET/脚本时才有意义）；单稳加固。
- **为什么**：批次 1（sleep mask / 去 RWX / apihash）已实现但**运行期零实测**；批次 2 在没有放行环境时做，产出又只是未验证代码。
- **验收口径**：把 `docs/EVASION.md` §3.1 的流程脚本化（记录 360 拦截记录 + Defender 1116/1117 + 是否上线），每项改动按"一次只改一个变量 + ≥3 次重复 + 记录拦截原文"验收；休眠窗口内在 Process Hacker / x64dbg 里搜不到明文结果缓存与 SM4 子密钥特征。
- **需要你（操作员）提供什么**：同第 4 项（放行环境 / 目标机）。

#### 7. S4 / P2 工具库与远程加载

- **做什么**：`data/tools/<os>/<arch>/` + 同级 `manifest.json`（用途/平台/调用示例/来源/SHA-256/许可/体积/最后校验时间）；只预置自研脚本型工具，第三方走"按需下载 + sha256 校验 + 版本轮换"；`remote_download` 拉到服务端再分发到会话；内网探测/横向/凭据利用/规避载荷全部远程加载。
- **为什么**：无破坏性、无外部材料依赖，可与其他项并行；直接兑现"植入端体积与功能面不随能力增长"。
- **验收口径**：植入端二进制体积/功能面不随上述能力增长；「下载→校验→内存加载→执行→回传→清理」闭环可跑通；工具元数据缺失或 sha256 不符时**明确拒绝执行**。
- **需要你（操作员）提供什么**：第三方二进制的下载源与哈希清单策略（预置只放自研脚本）。

#### 8. S5 首个冷门通道

- **做什么**：DNS / DoH / DoT 优先（QUIC / HTTP2 备选，`internal/common/tunnel/quic/` 有可复用骨架），端到端跑通**一条**；新协议必须按 tag 编译，默认只带 1~2 个通道。
- **为什么**：加一个新协议 = **12 类落点 / 20+ 处编辑**，其中 8 处"漏改就静默降级或编译失败"，必须单独排一轮；先跑通一条再谈多通道热切换与自动降级状态机。
- **验收口径**：新通道端到端可用（真实服务端 + 模拟植入端脚本联调）；镜像一致性、tag 编译矩阵、特征裁剪核对全绿。
- **需要你（操作员）提供什么**：若走 DoH/DoT：**域名与委派运维**；企业出口放行情况。

#### 9. S6 屏幕流 / 截图跨平台（P0-3）

- **做什么**：Linux 用 **X11 (`XGetImage`)** 起步（Wayland 走 PipeWire + portal 授权作为后续）；macOS 用 **ScreenCaptureKit**（屏幕录制权限提示与授权路径）；screenshot 同步补全；Windows 换 **Desktop Duplication API** 做增量帧捕获（保留 GDI 回退）。
- **为什么**：这三项都**必须在真机验证**（无桌面/授权/GPU 条件写不出来），所以排在材料阻塞类的最后。
- **验收口径**：Linux amd64 能出图；Win10/11 桌面会话 ≥5fps 且 CPU 占用可控；Server 无桌面返回明确错误。
- **需要你（操作员）提供什么**：**Linux 桌面机（X11）**；**macOS + 屏幕录制授权**；Win10+ 带 GPU 的目标机。

#### 10. 工程收尾 / 服务端在线更新（P3）

- **做什么**：`scripts/e2e_smoke.ps1` 接进 CI（tag 前，零依赖可先做）；多通道语义对齐（TCP 最完整）；配置热更新边界文档化；前端任务列表虚拟滚动 + Sessions/仪表盘 WS 事件统一订阅；运行指标（帧限速丢弃数、广播去抖抑制次数）上界面；服务端自更新：先做**服务化守护**（Windows 服务 / systemd / 计划任务）→ 下载 → sha256（可选 Authenticode）校验 → **原子替换**（`MoveFileEx` / `rename`）→ 重启 → 自检 → 失败保持现有二进制 + sqlite 备份回滚 → 可信源白名单 + 独立密钥 + 默认关闭。
- **为什么**：前 9 项之间可穿插；自更新**必须**先有服务化守护，否则"更新完自动重启"无从谈起；更新通道 = 完整 C2 控制端，被劫持等于 C2 被接管，所以默认关闭。
- **验收口径**：CI 在 tag 前跑通 e2e；升版流程"检查 → 校验 → 替换 → 重启 → 自检"在测试环境完成，植入端自动重连、配置与 sqlite 数据不受影响；断网/摘要不符/签名不符时**明确失败且不改动现有二进制**；保留上一版二进制可一键回滚。
- **需要你（操作员）提供什么**：自更新需要**可信更新源**（自建源 / GitHub Release）与**更新密钥**决策。

> **口径（继续生效）**：在第 4 项完成之前，本文件与 CHANGELOG **不得新增任何"免杀已生效 / 能过某杀软"的表述** —— 本轮免杀改动目前只有静态与结构级证据。

### 阶段详情（S1~S6）

> 每个阶段**先列「✅ 已完成」，再列「❌ 未完成 / 待做」，最后单列「🚫 已定论不做」**（S6 的 P0-2 从"卡在本地 stash"捡回后为 **🟡 部分完成**，与总览表同口径）；同一件事只出现在一处，口径与上面的状态总览一致。

#### S1 开放 MCP 服务接口 + 公共执行基础设施

**✅ 已完成**
- **工具元数据单源化**：新增 `internal/server/mcp`（`registry.go` 类型与 JSON Schema 生成、`registry_tools.go` **38 个工具**的类型化参数与风险分级 read 13 / confirm 14 / danger 11）；REST `/api/v1/mcp/tools`、内置 AI 的 function schema、对外 MCP `tools/list` **三处同源**；删掉 `handlers_mcp.go` 里 190 行工具清单与 `copilot.go` 里 33 条硬编码 schema。
- **统一结果信封 + 大结果外置**（`envelope.go` / `resultstore.go`）：`{status,data,error,meta}`，超限结果落盘 `data/mcp-results/<日期>/<hex>` 并由 `result_read` 分页回读；**截断一律显式标注**；句柄做白名单 + `Abs`/`EvalSymlinks` 双校验防穿越。
- **MCP 协议层**：`initialize` / `notifications/initialized` / `ping` / `tools/list` / `tools/call` / `resources/list` / `resources/read`；`Mcp-Session-Id` 会话、`DELETE` 结束、`GET` SSE；stdio 桥 `cmd/toshell-mcp`。
- **安全边界**：独立回环监听（默认 `127.0.0.1:18082`）、MCP 专用 token（常量时间比较，不复用管理 API Key）、CIDR/Origin 校验、三档分级默认只放行只读、审批门扩展点（`ConsentGate`，真正的审批接线在 S2）、RPM/并发/挂起句柄三道闸、JSONL 审计（参数只记摘要、敏感键全脱敏）、fail-closed。
- **兼修两个既有缺陷**：`delegate` 绕过审批（`isRiskyTool` 原为"允许列表 + fail-open"）、`plugin_upload`/`fileless_exec` 的路径穿越。
- **验收证据**：`go build ./...` / `go vet` 通过；`go test ./internal/server/mcp/...` ok；`scripts/mcp_smoke.ps1` **18/18**（无 token/错 token 401、会话头 400、tools/list=38、只读可调用、危险默认 403、未注册 403、路径穿越 403、超 RPM 429、设置页 GET/PUT 与工具名校验）；`npm run build` 通过。

**❌ 未完成 / 待做**
- 无（S1 范围内没有剩余项；对外审批接线的最后一段已在 S2 完成）。

**🚫 已定论不做**
- 无。

#### S2 内置 Agent：长任务可靠性

**✅ 已完成**
- **异步任务状态机**：`task.Manager` 增加终结通知原语（`Subscribe`/`WaitSettled`，注册与状态判定同锁防丢通知、等待者摘除不泄漏），`pushAndAwait`/`task_wait`/`execAndAwait`/剧本 `waitForTask` 全部改为**事件驱动等待**（不再 sleep 轮询，对外契约逐字段不变）；预估超时 ≥ `ai.long_task_threshold_sec`（默认 150s）的工具改为「提交 → `awaiting_task` 挂起并落库 `waiting_on` → **释放并发槽位** → 完成通知唤醒 → 结果接回 → 重入循环」；启动时对账 `agent_runs` 与 `tasks`（已完成→接回、仍在跑→重新订阅、丢失→明确终态 `task_lost`），顺带修掉"重启前下发的任务结果永远丢失"。收益有专门用例（并发上限 1 时挂起后槽位可再获取）。
- **状态落盘**：4 张表（`agent_runs`/`agent_steps`/`agent_tool_calls`/`tool_results`，见 `internal/server/database/agent_schema.go`）+ 专用存储层 `internal/server/agentstore`（run 状态机推进、step 恢复游标、tool_call 幂等 upsert、result TTL 清理、同参重复计数）；全部 `IF NOT EXISTS`，对既有库幂等。顺带 `SeedTaskCounter(MAX(tasks.id))` 修掉进程重启后任务 id 撞号。
- **长结果外置 + 句柄内联 + 分页回读**（设计见 `docs/AGENT-RESULT-OFFLOAD.md`）：唯一转换点 `mcp.InlineForModel`（≤8 KiB 原文；超限只给"摘要 + 句柄 + 显式截断说明"的合法 JSON 信封）；`result_read` 从"只在注册表里"补成真实现并加入 Agent 工具面（slice/tail + 游标，页大小自适应收缩）；删掉 8 处字符串硬截断，顺带修掉"截图 base64 被切成非法 JSON"与"integer 工具参数被静默丢弃"。
- **上下文分层与 token 预算**：常驻 / 任务 / 工作（默认最近 14 条原文）/ 历史（更早折叠）四层装配抽成纯函数（`ai/context.go`），同步与异步共用；**常驻层逐字节稳定**（每轮都变的在线会话清单从 system 移到任务层，按 run + 5 分钟 TTL 缓存，顺带消掉 `currentSessions()` 内部那次未审计的 `session_list`）；折叠摘要保留真实工具名 + 外置句柄 + 截断标注且不拆散 `tool_calls`/`tool` 配对；两道 token 预算（`ai.max_context_tokens=32000` / `ai.max_run_tokens=400000`）+ `ai.context_working_keep=14`，字符近似估算 + **解析 `usage` 回填校准** + 30% 余量，超预算**先压缩后停止**（`stop_reason=max_tokens`）。
- **控制循环三处硬上限 + 防死循环**：`ai.max_turns=20`（统一）、`ai.max_tool_calls=40`、`ai.max_wallclock_sec=900`，触发即停并记 `stop_reason`；同工具同参数签名第 2 次提示换策略、第 3 次判 `loop_detected`（只读工具豁免）。判定逻辑为纯函数（`shouldStopRun`/`loopSignature`），有单测。
- **审批分级**：`ai.consent_policy: graded|all|off`（旧值 `auto→off`、`normal→graded` 兼容），按注册表 read/confirm/danger 分级，未注册工具按 danger、`delegate` 恒危险；设置页可改，接口回传的是**生效策略**。
- **可观测性**：trace id 全链路（run/事件/日志/工具调用/**HTTP 响应**，`DoneInfo` 带 `stop_reason`）；**SSE `id:`/`Last-Event-ID` 断点续传**（每个 run 事件带 run 内单调递增 `seq`，重连带 `Last-Event-ID` 头或 `?last_event_id=` 恰好补齐缺口后无缝转实时；控制帧不带 id；`retry:` 提示 + 15s 心跳注释帧；`resync` 显式告知两类缺口 —— `events_expired`（缓冲淘汰，512 条/2 MiB）与 `events_dropped`（事件通道满），提示客户端改用 run 详情兜底；交接采用"先订阅通道、再取快照 + `seq ≤ lastSent` 去重"，有并发竞态用例断言 seq 连续无重复）。前端已接入续传并在缺口时显式提示、立即重取 run 详情，切走后不再重连。
- **验收证据**：离线黄金集 `internal/server/ai/testdata/golden/cases.json`（**12 例**：纯问答 / 工具往返 / 防死循环（含只读豁免）/ 轮次·工具数·token 三种预算 / 分级审批挂起（含 `delegate` 与未注册工具 fail-closed）/ 大结果外置与句柄回读 / 历史折叠保真）+ 桩 LLM 与假执行器（不联网、无需真实模型与植入端），`scripts/eval.ps1` 一键跑并随 `./internal/server/ai/...` 进 CI；另有一条**全局不变量**：任何一次发往上游的消息里 `tool` 回执都必须能配到 `assistant.tool_calls`。`go test ./...` 全绿（13 个包）；`scripts/e2e_smoke.ps1` **19 项 0 失败**。

**❌ 未完成 / 待做**
- **本轮新发现的两个缺陷**（详细验收见「后续优化清单」第 1、2 项）：① 前端把 run 的跨轮累积时间线当"本轮步骤"重画、且每轮 SSE 水位线从 0 起（表现为界面"看起来又重复执行了一遍"，不影响模型输入）；② 同一条 assistant 消息里的第二个并行 `tool_calls` 被静默跳过（既没执行也没记录）。
- **评估门禁的在线部分**（计划 M5，原计划标为可选）：`/agent/metrics` 指标、Dashboard 卡片与前端状态条。
- `tasks.output` 仍被截到 **500 字节**，限制重启恢复的结果长度（已在给模型的说明里标注）。
- 挂起会重置 `max_wallclock`/`max_turns` 预算（应接入 `agent_runs` 用量字段）；token 预算用量也尚未纳入 `agent_runs` 的持久化统计（跨挂起/重启累计）。
- `ai.long_task_threshold_sec` 只走 YAML，未进设置页 PUT 白名单。
- 本机 `CGO_ENABLED=0`，`go test -race` 在 windows/386 不可用（现用并发顺序用例替代）。

**🚫 已定论不做**
- 无。

#### S3 免杀：分层治理（先解决"起不来"，再谈"藏得深"）

**✅ 已完成**
- **先定性的关键事实（元项的一部分）**：本机（360 + 电脑管家 + 无边界安全系统）实测证明**未签名 PE 在进程创建阶段就被拒**（连 Hello-World Go 都被拒、微软签名程序正常）→ 拦截在**签名/信誉层**，**改载荷字节无效**。该结论与证据写进 `docs/EVASION.md`（含"一次只改一个变量 + ≥3 次重复 + 记录拦截原文"的纪律），避免后续重复踩坑。
- **签名顺序契约**：`finalize_order.go`（纯函数定序 + 构建日志 + 违规打 error + 表驱动单测），并确认 `sign_timestamp_url` 在 signtool（`/tr` + `/td sha256`）与 PowerShell（`-TimestampServer`）两条路径上都真的传到；**签名必须是最后一步**。
- **静态降特征：字符串混淆盲区与 DLL 路径补齐**（修掉三处**实测到的**漏点）—— ① exe 与 dll 各残留 1 次 `go1.20.14`（`runtime.buildVersion` 落在锚定窗口之外 → 新增全文件版擦除，长度不变）；② 混淆器只认"简单双引号字面量"，含转义的 Windows 路径/设备名与**全部反引号原始字符串**（注册表键、脚本模板）都被放行 → 现已覆盖（struct tag 与 const 行保留）；③ **DLL 路径此前根本没做字符串混淆与每构建随机化**（实测明文高信号 API 名 11 处、`http://` 2 处、ETW 4 处）→ 补齐后与 exe 同水平。代价：产物 **+0.3%（exe）/ +2.8%（dll）**。
- **PE 版本资源 / 图标 / 公司信息 / 时间戳（第二批）**：`builder/patch_resources.go`（纯标准库）写 `RT_VERSION` + `RT_ICON`/`RT_GROUP_ICON`，按 `StepResourcePatch` 插在指纹擦除之后、**UPX 与签名之前**（exe 的 `compile()` 与 dll 的 `compileLibrary()` 都接了）；**默认不注入**（实测 3,469,557 → 3,469,557 完全一致），开启后 exe / dll 各 **+2048 字节**；实测达成验收口径：`.rsrc` 出现、**Windows 原生 `VersionInfo` 读得出八个字段**、`ExtractAssociatedIcon` 取得到图标、`LoadLibraryEx(IMAGE_RESOURCE)` + 真机"打资源的 exe/dll 都能加载并回连"。
- **一键中性预设 `resource_preset="neutral"`**：套用**自有品牌**外观（`ToShell Ops Toolkit` 公司名/产品名/描述/版权 + `toshell-agent.exe|dll` + `fixed` 时间戳），语义是"只填操作员没显式给的字段"，**不猜版本号**，预设名拼错**直接构建报错**。**明确不预置"像系统组件"的外观**（品牌冒充字符串不该由默认值写进公开仓库）。预设默认关闭，零值请求逐字节不变。
- **节名 / 节熵口径 + `.symtab` 清理（第三批）**：`builder/pe_sections.go` 的 `NormalizePESections` 删掉 Go 链接器残留的非典型节 `.symtab`（COFF 时代节名，正常 Windows PE 没有），并把自相矛盾的 `PointerToSymbolTable`（实测非 0，如 3468800）/`NumberOfSymbols`（=0）置 0；**默认执行**，`section_normalize` 排在 `pe_resource_patch` **之前**。实测 `windows/386` exe **3,469,557 → 3,469,045（−512 B）**、`windows/amd64` **3,574,517 → 3,574,005（−512）**、节数 **6→5**，其余节与全部数据目录逐字段不变；`format=dll`（mingw）本来就没有 `.symtab` → no-op。节熵判定口径写进 `docs/EVASION.md` §2.3：看**"有没有接近 7.8 的节 / 有没有非标准节名"**，`.text` 6.08 / `.rdata` 5.68 / `.data` 5.60 是正常区间，**不要**当可疑去"优化"。
- **修掉"用了资源预设的载荷无法运行"（用户实测抓到的回归）**：节规范化删掉 `.symtab` 后在 RVA 空间留下**一页没人映射的空洞**，一旦再追加 `.rsrc`，`LoadLibraryEx` 就以 `ERROR_BAD_EXE_FORMAT(193)` 拒绝整个镜像。修复：新增 `coverFreedSectionRVA()`，把被删节原本占用的虚拟区间**划给前一个节**（只扩大 `VirtualSize`，不动节数/文件长度/任何数据）。验证：386/amd64 × 无资源/预设/预设+图标**五份产物 `LoadLibraryEx` 5/5 LOADER OK**，带 `neutral` 预设的真实载荷进程存活并成功上线；新增 `TestNormalizeLeavesNoUnmappedRVAGap` 回归用例。教训写进 `docs/EVASION.md` §2.3：**"能通过静态体检"不等于"能被 loader 接受"**，改 PE 节布局的验收口径必须包含 Windows loader 接受 + 真实执行。
- **验收证据**：`go test ./...` 全绿；`scripts/e2e_smoke.ps1` **19 项 0 失败**（真实构建 + 执行 + 上线 + `whoami` 回执）；`scripts/pe_footprint.ps1` 追加资源细节与 `PointerToSymbolTable`/非标准节名/最高节熵打印。

**❌ 未完成 / 待做**
- **两级验收环境与测试矩阵脚本至今未建立**（干净 VM（仅 Defender）+ 装 360 的目标机）→ 本节全部结论都只有**静态/结构级证据**（字节数、节表、loader 接受性、单测），**没有一条"目标机上不被拦"的运行期结论**。
- **真实证书 / EV + 信任链落地**未做：本机无证书，只有顺序契约与单测保证签名顺序；**签名后的真实复核**同理未做。
- **白加黑 / 不落 PE 的加器链真机实测**未做（只有 8 条链的命令模板与降级建议）。
- **判定矩阵**（"在哪一层被拦 → 该做哪一类改造"）尚未落成脚本。
- C 植入端（mingw）未接入资源修补（现有资源/节规范化只对 Go 产物生效）。

**🚫 已定论不做**
- **更全的反沙箱反调试、间接系统调用与调用栈伪装、模块 stomp**：有实测依据表明带进程枚举的载荷在 360 机器上"一启动即被拒"，**净收益为负**，一律默认关闭、按需编译。

#### S4 植入端体积分档与内存加载

**✅ 已完成**
- **能力位图（前置阻塞项）**：`/sessions/{id}/capabilities` 原来**只按 OS** 推导（用 `light` 档构建的载荷照样点亮注入/截图/凭据/EDR/BYOVD 面板，点下去只得到"未包含在精简构建中"）。现在新增 `internal/common/features` 作为**唯一一份纯函数**（档案/tag/OS → 能力集合 + `tabs` + `cap:v1:<hex>` 位图；未知档案 fail-closed 归入 light），构建期把位图烘进载荷（照旧走字符串混淆），植入端经**已有**的 `Modules` 字段随心跳上报（四条传输一致），服务端 `Resolve()` **上报优先、老载荷按 OS 兜底**并标 `source: reported|os_fallback` + `source_note`。**实测**：light 载荷 **11 项**能力 / tabs 只有 av·files·info·process·shell；full 载荷 **31 项**、注入/截图/凭据/EDR/BYOVD/插件按真实编译结果点亮。
- **内存模块按需裁剪**：现有 `light` 档案已裁掉注入/EDR/凭据/BYOVD/截图/插件/中继（`!light` 构建约束，实测 full−light = **+575,488 B（约 575 KB）**，见下表 V6）。**如实边界**：粒度是"整档"—— `injection`/`edr`/`stomp`/`imgexec` 目前**不能各自独立开关 tag**；需要单模块级裁剪时走 `exec_module` 按需加载（下方）。
- **`exec_module` 契约与 ABI**：新增 `internal/common/moduleabi`（ABI v1 + C 头 `builder/implant_c/module/tsh_module.h`，三份副本由单测钉住）+ `internal/server/modules`（清单 / sha256 硬拦 / 一次性 token）+ 接口 `POST|GET /api/v1/sessions/{id}/module` + 二进制帧 `TypeModuleData(0x0E)`。模块**只接受原生 C PE**（Go/CLR/TLS 目录硬拒 —— 反射映射宿主里跑 Go 模块会出两个 runtime），`tsh_module_main(ctx*)` 拿得到参数与返回值（ctx 只用 ≤4 字节标量，386 用 `__stdcall`）。9 步校验链全部返回机器可读 code + 中文文案：会话 active / 已登记 / **sha256 与大小硬拦** / 架构与 PE 实际位宽一致 / ABI 导出存在（新增 `builder.ExportedNames`）/ 三层版本握手 / token（绑定 session+module+sha256+size+abi、TTL 120s、用后即废）/ 下发 fail-closed / 审计。能力位只追加第 32 位、**不加空面板**，默认载荷零行为变化（无 tag 时 +512 B，给出"未包含在本次构建中"的明确错误而非 `Unknown task type`）。
- **`exec_module` 实测**（windows/386，同参数）：light/tcp 2,946,805 → light+execmodule 2,973,941（门控 **+27,136**）；示例模块 `cred_probe`（C + `-nostdlib`）**7,680 字节**，把 `credentials` 搬成模块可省 **67,584**。判读：`exec_module` 买到的是"最小载荷 + 按需全功能 + 模块可服务端更新"，**不是**体积数量级下降 —— 真正的数量级在传输栈。
- **模板文件名/函数名中性化**：`exec_module_windows.go`/桩 → `xload_windows.go`/`xload_stub.go`，`handleXLoad`/`handleXData`；E2E 复测 pclntab 内模块相关残留 **1 处 → 0 处**。
- **体积实测矩阵（V0~V7）**（windows/386，`-s -w -buildid= -H windowsgui -trimpath`，Go 1.20.14；按 1 MB = 10⁶ 字节计）：

| 变体 | 字节 | 相对 light/tcp | 说明 |
|---|---|---|---|
| 空程序（地板） | 801,280 | — | **Go runtime 地板 0.80 MB** |
| 空程序 + `net`+`json`+`fmt`+`os`+`time` | 2,010,624 | — | **核心标准库地板 2.01 MB**（已超 nano 目标 1.8 MB） |
| V0 light / tcp | **2,946,805** | 基准 | 当前默认档 |
| V1 light / tcp + `bof` | 2,946,805 | **0** | light 档本就排除 BOF，tag 无效果（与能力位图一致） |
| V2 light / tcp + `evasionscan` | 2,953,973〔换算〕 | +7,168 | 杀软进程枚举 7 KB |
| V3 light / **http** | 5,455,613 | **+2,508,808** | 引入 `net/http`+`crypto/tls` |
| V4 light / **websocket** | 5,097,728 | +2,150,923 | 再叠 gorilla/websocket |
| V5 light / **mqtt** | 5,399,798 | +2,452,993 | 再叠 MQTT 库 |
| V6 full / tcp | 3,522,293 | **+575,488** | 全部 Windows 可选功能（注入/EDR/凭据/BYOVD/截图/插件/中继） |
| V7 full / mqtt | 5,975,286〔换算〕 | +3,026,433 | 最重组合 |

> **口径说明（2026-09-28 对齐）**：地板两行与 V0 / V3 / V4 / V5 / V6 是**发布版（v1.4.0）工作区**的逐档实测（与 [README.md](README.md)「植入端体积（v1.4.0 本机实测）」同源）；**V2 / V7 未随发布版重测**，其绝对值按"发布版基准 + 同一迭代早期实测增量"换算（V2 = light/tcp + 7,168；V7 = full/tcp + mqtt 增量 2,452,993），标〔换算〕，只作量级参考。本文 **S3 阶段详情**里的绝对字节数（3,469,557 / 3,469,045 / 3,574,517 / 3,574,005）同样是**早期迭代口径**，保留原因：它们只用于支撑"−512 B / 默认不注入时字节数完全一致"这类**相对**结论；绝对体积一律以本表与 README 为准。

  判读：① 体积大头是**传输栈**（http/ws/mqtt 各 +2.1~2.5 MB），比所有功能 tag 加起来（+0.58 MB）还大一个量级；② light/tcp 的 2.95 MB 里 **2.01 MB 是核心标准库地板**，我们的代码只占约 0.94 MB；③ 所以 `light ≤2.4 MB` 只能靠 stdlib 瘦身，`nano ≤1.8 MB` 在 Go 里做不到。

**❌ 未完成 / 待做**
- **分档与目标体积**：nano / light / full 三档只实现了 light / full；**默认档仍是 `full`**（代码事实：`features.NormalizeProfile("")` → full、前端生成载荷页默认 `profile:'full'` —— 本文件旧版"默认档改为 `light`"的说法与代码不符，已更正）；**目标体积未达成**（light 实测 2.95 MB > 目标 2.4 MB；full 3.52 MB > 目标 3.2 MB）；每档的功能对账表与构建命令待补齐（前端按能力位图的提示已落地）。
- **`exec_module` 的已知边界**：只真机测过 TCP 通道（HTTP/WS/MQTT 已接线并编译通过、未真机跑）；单帧下发上限 **4 MiB**（未做分块）；模块自身字符串是明文（只存操作员 `data/modules/`，按需下发、不落目标磁盘）；token 只在内存（服务端重启使在途 token 失效）；**未暴露给 MCP/Agent 工具面**（保守口径）。
- **工具库与远程加载（P2）**：`data/tools/` 只有 `.gitkeep`，未开工（见「后续优化清单」第 7 项）。

**🚫 已定论不做**
- **传输栈瘦身与模块化**：实测 http/ws/mqtt 各 +2.1~2.5 MB（V3/V4/V5），比全部功能 tag 之和（+575 KB）大一个数量级 —— 但这部分是 `net/http` + `crypto/tls` 的成本、**不是可裁剪的冗余**：① 现有构建**已经**按通道 tag 只编一个传输（tcp 档不会带上 http/ws/mqtt 的字节，所以"模块化"并没有可回收的重复）；② 想省下这 2 MB 只能手写 TLS 客户端（不现实且不安全）或换 uTLS（只会更大）。结论：**保持现状**，把"要小就选 tcp 档"写进分档说明即可。
- **`nano` 档（≤1.8 MB）**：核心标准库地板已 **2.01 MB**（见上表"空程序 + `net`+`json`+`fmt`+`os`+`time`"行），nano 只能走 **C 植入端**或手写收发层 / 精简 `fmt`+JSON。**已决定不排入 v1.4.0**（等于第二套植入端，工作量与维护成本都远超收益）；若后续确有"≤1.8 MB 且要跨平台"的硬需求，再单独立项。

#### S5 新增低特征通道

**✅ 已完成（第 0 步：不新增协议，只做路径/Host 收敛与中继对齐）**
- **严格路径**：改造前 WS 对**任意路径**都升级（`GET /whatever` 也能拿到 `101`，普通 GET 也会回 `400` + `Sec-Websocket-Version: 13`，都等于宣布"这里有 WS 端点"）。新增 `listener.ws_path`（默认 `/`，**与现役植入端口径同源** = `transport.DefaultUpgradePath`），WS **只对一条路径**升级；变形路径（`//`、`/./`、尾部斜杠、`..`、百分号编码、大小写）与不完整握手一律回**普通 404**（与"该路径没有处理器"逐字节一致，绝不回 `Sec-Websocket-Version`）；顺带去掉 `ServeMux` 的 301 清洗。因默认路径未变，**无需新旧路径兼容窗口**（改 `ws_path` 必须同步改植入端 `server_url`）。
- **Host 收敛 + 域前置**：新增 `listener.ws_host_allowlist`（**空 = 不检查**；非空时非名单 Host → 404）；植入端 WS 支持 `front_domain`（SNI + Host，与 HTTP 通道同一口径；gorilla 的 `Host` 键特判使 SNI/Host 不冲突）。
- **中继对齐**：确认 WS/HTTP/MQTT 均不支持中继 → `POST /sessions/{id}/relay` 对非 TCP 通道回 **409** 明确报错、WS 监听器对中继帧记结构化告警（不再静默）、`ListRelayNodes` 与 HTTP 逐字一致。**没有**做半个中继。
- **可观测**：被拒升级记结构化日志（reason/path/raw_path/host/remote_ip；**不记请求头与 query**，字段消毒 + 截断；按"是否像握手尝试"过滤噪声）。
- **验收证据**：`go test ./...` 全绿（新增两组探测面单测：各类变形被拒且被拒响应与 `http.NotFoundHandler` 逐字段一致、Host 名单三种口径、日志消毒、中继能力判定）；`scripts/mcp_smoke.ps1` 18/18；真机 E2E（websocket 载荷上线 + `whoami` 回执、`curl --path-as-is` 探测与未知路径不可区分、错 Host 握手被拒）。

**❌ 未完成 / 待做**
- **第 0 步的延伸**：uTLS/JA3 指纹（WS 仍是 Go 标准库 TLS）、WS 拟态（非 C2 路径不反代伪装站，只回 404）、HTTP/2、**真实 CDN 域前置联调**（含 `wss` 真实证书链）；`ws_path` 目前是**全局配置**（所有 WS 监听器共用），未做 per-listener 覆盖。
- **首个新通道（未开工）**：候选为 DNS/DoH/DoT 控制通道（穿透性最好、可零新库）、QUIC/HTTP3（服务端 `go.mod` 已依赖 quic-go，`internal/common/tunnel/quic/` 有可复用骨架）、HTTP/2（共用端口证书；现有 HTTP 通道很可能实为 h1.1）。**先端到端跑通一个**。
- **组合与降级（未开工）**：控制面走低特征低速通道 + 数据面走高吞吐通道；多通道热切换与自动降级状态机。
- **成本约束（实施前提）**：加一个新协议目前需要 **12 类落点 / 20+ 处编辑**，且有 8 处"漏改就静默降级或编译失败"；新协议必须**按 tag 编译**，默认只带 1~2 个，避免撑大体积。
- **验收口径**：新通道端到端可用（真实服务端 + 模拟植入端脚本联调）；镜像一致性、tag 编译矩阵、特征裁剪核对全绿。

**🚫 已定论不做**
- 无（第 0 步明确"不改 TLS 指纹、不加任何新 tag、不动 `go.mod`"，但那是本步的范围界定，不是永久放弃）。

#### S6 杀软对抗能力分级 + 工程收尾

**✅ 已完成（第一批：AV-L0 侦察 / AV-L1 温和）**
- 分级真源 `internal/common/avops`（等级 + 动作表 + 策略，纯逻辑表驱动，未知动作/未知等级 fail-closed）；**8 个既有动作全部登记**（`av_detect` L0；`edr_blind` L1；`edr_kill`/`process_kill` L2；`byovd_load`/`byovd_unload`/`byovd_kill`/`ppl_kill` L3），逐条核对过植入端 `executeTask` 的任务类型与能力位。
- 聚合入口 `GET /api/v1/av-ops`（等级目录 + 配置是否允许 + 原因）、`GET /api/v1/sessions/{id}/av-ops`（逐动作 `allowed` + `reasons[]`，**排障先看这里**）、`POST /api/v1/sessions/{id}/av-ops`（服务端按动作定级 + 七步前置检查 + 复用既有 `task.Manager`/`TaskPusher` 下发 + 结构化审计 + `impact{}` 影响评估）。**既有 6 条链的路由与语义一行未改**。
- 配置 `avops.allow_l2/allow_l3/allow_l4` 默认 **false**（fail-closed 落点）、`require_confirm` 默认 true（`*bool`：零值也按"更严"处理）、显式超时 120/600（超上限拒绝，服务端看门狗把超时置为 `timeout` 终态）。
- **破坏性任务禁止自动重试**：堵住 `ListReplayable`（重连补发）与 `RequeueSent`（HTTP 轮询重投递）两条服务端自动路径，并按任务类型判定（落 sqlite、重启后仍有效）；被拒任务**保持 `sent` 不改终态**（我们并不知道植入端有没有执行过）。
- **Agent/MCP 侧只暴露 L0**：工具面**未新增任何工具**（注册表仍 38 个），用注册表扫描 + 源码扫描两条守卫测试钉住"L1+ 动作不可能经工具面触达"。
- **前端二次确认 UI**：会话详情新增「对抗分级」面板（`web/src/components/AVOpsPanel.tsx` + `.css`）—— 策略/驱动档位回显、按等级分组、逐动作 `reasons[]` 中文原因、破坏性动作二次确认弹层（服务端 `impact` 原文 + 目标预览 + "不会自动重投递/不可回滚"）、超上限超时前端拦住、L4 显示"暂无落地动作"且按钮数 0。真机核对出并处理了一个语义坑：**L1 的 `allowed:false` 只带 `confirmation_required`（= 必须带 confirm），按 `!allowed` 禁用会让 L1+ 永远点不了** —— 面板区分"硬阻塞"与"需确认"。
- **验收证据**：`go test ./...` **18 个包全绿**（新增 avops 表驱动、handler、任务重投递、驱动档位、MCP 扫描守卫用例）；真机 E2E 验证了默认开关（L0/L1 开、L2/L4 关）、逐动作 `allowed/reasons`、**L0 `av_detect` 真实下发回传**、缺 confirm→409 / tier 不符→400 / 未知动作→400 / L2→403 / L3 无驱动→409 / 超上限→400、被拒动作**没有产生任何任务**、审计 `avops_dispatched`/`avops_rejected` 齐备。

**❌ 未完成 / 待做**
- **L2/L3/L4 真实执行未验证**（默认关闭，需目标机 + 操作员自备驱动）：真机 E2E 只验证了"**被拒**"与 L0 的真实下发回传，**没有**真的在测试主机上执行过任何破坏性动作；面板侧"破坏性动作成功下发"的分支同样未实测（真机只点到"弹出确认层后取消"）。
- **L4 没有任何落地动作**（`implemented:false`、`action_count:0`）：植入端目前没有独立的 AMSI/ETW 抑制任务类型，`allow_l4=true` 也不会让任何动作变成可下发 —— 不造"点了没反应"的假入口。
- **协议层重投递仍可再执行**：植入端每次新建连接都会 `clearResultCache()`，"同一个 task ID 再送一次就一定会再执行"在**协议层仍然成立**；目前只有"服务端不自动重发"这一层保证。
- **驱动体系三项均未开工**：`purpose`(kill/rw/both) 真正驱动选路、进程重启后残留驱动服务清场、catalog 签名驱动支持。
- **屏幕流/截图跨平台（P0-3）未开工**：Linux(X11) / macOS(ScreenCaptureKit) + Windows DXGI 增量捕获（需真机验证，因此排在最后）。
- **工程收尾（P3）未开工**：e2e 冒烟接进 CI（tag 前）、多通道语义对齐、配置热更新边界文档化、前端任务列表虚拟滚动与 WS 事件统一订阅、可观测性指标暴露到界面、**服务端在线更新（自更新）**（先做服务化守护 → 原子替换 → sha256/签名校验与防降级 → sqlite 备份与回滚 → 可信源白名单，默认关闭）。

**🟡 部分完成（P0-2 内存执行加固 + 「配置热重载报错可见」：本轮从 `git stash@{0}` 捡回并补完）**
- **解决什么**：`fileless-exec` 的 `exe_mem`/`dll` 把 PE **反射映射进植入端自己的进程**，被执行的程序收尾调 `ExitProcess`/`RtlExitUserProcess` 会连宿主一起结束 —— **会话永久掉线**（服务端只看到"目标机掉线了"）、任务永远停在 `sent`。现在在 **IAT 层**（被映射镜像自身 + 已加载模块两层，后者才覆盖 `msvcrt`/`ucrtbase` 这类 CRT 自己的 IAT —— "main 返回"这条最常见的收尾路径走的正是它们）把退出类调用改写为**原生机器码桩**：只 `ExitThread(退出码)` 并记录退出码/命中来源，**宿主存活**；stdout/stderr 在 `WriteFile`/`WriteConsoleA|W` 按 std 句柄截流回传。**宿主自身收尾结构性不受影响**：层 2 显式跳过 `ntdll`/`kernel32`/`kernelbase` 与宿主主镜像，宿主走的是 `os.Exit`/`exit` 任务/自杀路径，一个字节没动。同 stash 的**「配置热重载报错可见」**一并落地：`config.Reload()` 先 `ReadInConfig` 再 `Apply`，失败打 error 级日志 + 原始错误 + "继续使用旧配置"，结果经 `/health`（未认证：只给 ok/时间/失败计数，不泄露路径与解析细节）与 `/settings`（已认证：给完整原文）回传。
- **实测证据（windows/386 植入端 + mingw 32 位原生 `exit7.exe`，TCP 全链路真机跑通；载荷由服务端 `fileless-exec` 以 `kind=exe_mem` 下发）**：
  - 改前（HEAD 模板，`TOSHELL_IMPLANT_TEMPLATE_DIR` 指向 `git worktree` 出的 `.tmp-verify/pre-p02`）：载荷执行**当秒**服务端记 `Connection cleared` → `判定离线，15s 后广播` → `广播 session_offline`；植入端进程消失，任务停在 `sent`（第 2 次下发 500）。**直接调 `ExitProcess` 与 CRT 收尾两条路径都是这个结果** —— 旧实现的重定向目标取自 `resolveAPI`，而本机 `kernel32!ExitThread` 是**转发导出**（`NTDLL.RtlExitUserThread`），旧 `getProcAddr` 把"转发字符串的 RVA"当函数地址返回，重定向实际指向数据，反而把宿主打死（本轮已在 `apihash_windows.go` 修掉：转发项一律返回 0 交给 `GetProcAddress`）。
  - 改后（当前工作区模板）：30s 内 **15 次采样全程 `active`**，植入端进程存活；任务 `exit_code=7`，结果里明确写出 `加固已生效：退出拦截+输出捕获（镜像 IAT N 处 / 已加载模块(CRT 等) IAT 23 处）`、`[退出拦截] 载荷调用 kernel32!ExitProcess(7) 已被改写为 ExitThread：只结束载荷线程，宿主植入端**未退出**`、`--- 载荷 stdout (15 字节) --- HELLO_MEMEXEC`；随后 `whoami` 回执 `desktop-sfkhr1b\123`（exit_code 0）；**连续两次 `exe_mem` 都成功**（第二次 IAT 命中 0 处 = 幂等，加固仍在）；`exit` 任务仍能自杀（`status=completed`、`output=implant exit acknowledged`）—— **宿主正常退出路径未被这次拦截逻辑破坏**。
  - 配置侧：把配置写坏后热重载 → `2026/09/28 16:01:15 [ERROR] [config] 配置文件重载失败：While parsing config: yaml: line 6: did not find expected key（**继续使用旧配置**，本次改动未生效）`，`GET /settings` 回传同一原文、`GET /health` 回 `ok:false failures:2`；恢复成合法 YAML → `[INFO] [config] 配置文件已重新加载并生效` + `[INFO] [server] 配置变更已应用（热重载成功）`。
- **剩余什么 / 明确不覆盖（如实）**：① 载荷运行时用 `GetProcAddress`/`LdrGetProcedureAddress` 解析出 `ExitProcess`/`RtlExitUserProcess` 再**裸调**，或把退出调用**静态链入/内联**进自身代码 —— 不经过任何被改的 IAT，**拦不到**；② `TerminateProcess(<本进程的真实句柄>)` / `NtTerminateProcess(<真实句柄>)` **放行**（原生桩只能比较常量伪句柄 `GetCurrentProcess() == -1`）；③ `WriteFileEx`/`NtWriteFile`/自己 `CreateFile("CONOUT$")` 再写的输出**不捕获**，并且**宿主自身没有有效 std 句柄时（无控制台方式启动）同样捕获不到** —— 这两类情况结果里会写明"未捕获到任何内容（可能原因…）"而不是静默给空串（本轮实测：WMI 直起、植入端无控制台 → 捕获为空；用 `cmd /c … > log` 给了真实 stdout 后正常拿到 `HELLO_MEMEXEC`）；④ 原计划的 **inline hook 双保险未做** —— 只做了 IAT 层（inline hook 需搬运被覆盖函数序言，失败模式是"被 hook 的 API 全进程变砖"，对宿主可用性的风险大于收益）；⑤ `dll` 路径是在**宿主线程**上同步执行被映射代码，若该 DLL 调 `ExitProcess`，改写后的 `ExitThread` 结束的是宿主自己的线程，这条分支**未做真机验证**（`blob_windows.go` 里"判定走栈上镜像帧"的注释与实现不符，实现在 `mexecguard_windows.go`，属文档待修）；⑥ 真机结论只在 **TCP 通道 + windows/386** 上取得，HTTP/WS/MQTT 与 amd64 未跑。

**🚫 已定论不做**
- 无（本阶段没有"定论不做"项；"不造 L4 假入口"是显式取舍，见上面的待做）。

**验收口径（S6 收尾）**
- AV-L0/L1 在授权实验 VM 上通过最小可验证集；L2/L3/L4 留真机执行记录或明确结论；`exe_mem` 跑原生工具后植入端**不掉线**；CI 在 tag 前跑通 e2e；自更新在测试环境完成"检查→校验→替换→重启→自检"且失败不改动现有二进制。

---

## 附 A：历史条目池（P0~P3：背景、根因与验收口径）

> 本节是 v1.4.0 之前编写的条目池：**背景、根因与验收口径仍然有效**，但**状态与顺序的唯一口径是上方「v1.4.0 状态总览」与「后续优化清单」** —— 本节不再单独判状态、也不重复列"待做"清单。

### P0-1 驱动体系：操作员自备 + 多档能力 + 加载前自检

- **已达成的部分**：v1.3.4 完成**加载前自检**（`internal/server/drivers/verify*.go`）—— manifest `sha256` 一致性不一致直接拒绝下发；Authenticode 用 `WinVerifyTrust` 判签名与篡改、尽力取签名者；易受攻击驱动黑名单只读本机策略与名单文件、给出"1275 静默拒绝"提示；`GET /api/v1/drivers/{name}/verify`，前端驱动按钮直接标出"哈希不符/未签名"并展示警告。
- **现状**：不再内置任何驱动（v1.3.3 起），`ppl_kill` 只能走句柄窃取，**PPL 保护进程（Defender MsMpEng 等）清不掉** —— 因为没有具备内核读写的 `rw` 档驱动。目录签名（catalog）的 `.sys` 取不到签名者，只给"签名有效/未签名"结论（不伪造结论）。
- **未做**：见「后续优化清单」第 5 项。
- **验收口径**：放入 `rw` 档驱动后 `ppl_kill` 能打印命中的 EPROCESS 与 Protection 原值/新值；`kill` 档驱动能杀普通杀软进程；manifest 哈希不符的驱动在加载时被 400 拒绝。
- **需要操作员提供**：授权实验 VM + 快照；操作员自备的 `rw` / `kill` 档 `.sys`。

### P0-2 内存执行加固（`exe_mem` 的可用边界收窄）

- **已达成的部分**：v1.3.4 **下发前 PE 预检**（`internal/server/builder/pecheck.go` + `handlers_fileless.go`）—— 手写解析 PE 头（架构/DLL/TLS/CLR/重定位）+ Go 载荷识别（`.gopclntab`、`\xff Go buildinf:`），`exe_mem`/`dll` 命中硬边界直接 400 拒绝并给出 `reasons`/`suggestion`/`pe_info`，`warn` 类照常下发但回传 warnings，`force:true` 可强制（留痕）；前端展示原因并支持强制下发。
- **现状**：`ExitProcess`/`RtlExitUserProcess` 的 IAT 层拦截 + stdout/stderr 捕获**已从 `git stash@{0}` 捡回并补完、真机验收通过**（改前载荷执行即掉线，改后 30s 全程在线 + 退出码/stdout 回传 + `whoami` 回执）；同 stash 的「配置热重载报错可见」一并验收。**剩余**：运行时解析地址后裸调/静态链入的退出调用拦不到、`TerminateProcess(自身真实句柄)` 放行、`WriteFileEx`/`NtWriteFile` 输出不捕获、inline hook 双保险未做、`dll` 路径未真机验证（详见 S6 阶段详情的 P0-2 段）。
- **未做**：见「后续优化清单」第 3 项（该项已完成，保留编号以免打断交叉引用）与 S6 阶段详情的 P0-2「剩余什么」。
- **验收口径**：`attrib.exe`/`cmd.exe` 这类原生工具在 `exe_mem` 下执行完，植入体**不掉线**；带输出的工具能拿到返回内容；Go 载荷被明确拒绝（已达成）。**前两项已用"会调 `ExitProcess` 的 32 位原生 exe"在真机上验收通过**（真实 `attrib.exe`/`cmd.exe` 未单独跑）。
- **需要操作员提供**：无（决策与真机验收本轮已闭环）；amd64 载荷与 HTTP/WS/MQTT 通道的复测仍可另做。

### P0-3 屏幕流 / 截图：跨平台 + 增量捕获

- **现状**：只有 Windows 实现（GDI BitBlt + PrintWindow 回退，参数化后帧率上限由带宽而非采集能力决定）；Linux/macOS 全是 stub（`screen_stream_unix.go`）。
- **为什么没做**：三项都**必须在真机**（Linux 桌面 / macOS 授权 / Win10+ GPU）验证；本机连新生成的载荷都无法执行，写了只能交付未验证代码。
- **未做**：见「后续优化清单」第 9 项（Linux X11 起步，Wayland 走 PipeWire + portal 作为后续；macOS ScreenCaptureKit；Windows Desktop Duplication API，保留 GDI 回退）。
- **验收口径**：Linux amd64 能出图；Win10/11 桌面会话 ≥5fps 且 CPU 占用可控；Server 无桌面返回明确错误。
- **需要操作员提供**：Linux 桌面机（X11）；macOS + 屏幕录制授权；Win10+ 带 GPU 的目标机。

### P0-4 发版门禁：一条命令的端到端冒烟

- **已达成的部分**：`scripts/e2e_smoke.ps1`（临时服务端 + 鉴权/关键路由校验 + windows full/light + linux 三档载荷构建 + 可选真植入端上线与任务下发 + ✅/⚠️/❌ 摘要，有 ❌ 即非 0 退出；实测 **19 项 0 失败**）；CI 侧 tag 与 `toserver -version` 一致性校验、zip 内容清单校验、`checksums.txt`（本地 `scripts/package_release.ps1` 同步生成）。
- **未做**：见「后续优化清单」第 10 项（把脚本接进 CI 的 tag 前 workflow；本地"发布包内 `toserver -version` == tag"校验 —— CI 已有）。
- **验收口径**：CI 在 tag 前跑该脚本；本地 `powershell -File scripts/e2e_smoke.ps1` 一条命令可复现。
- **需要操作员提供**：无。

### P0-5 动态（行为）查杀：先解决"起不来"，再谈"藏得深"

- **现状（本机实测）**：装有 360 安全卫士 + 腾讯电脑管家 + 无边界安全系统的主机上，**任何新生成/未签名的 PE 一执行就被拒并删文件**：一个只有 `time.Sleep` 的 Hello-World Go 程序同样被拒（`Access is denied` + 文件被删除），对照 MS 签名的 `notepad.exe` 副本可正常执行。所以本机看到的"动态被查杀"**判别不出载荷特征**（拦截依据是"未签名/未知 PE + 主动防御策略"）；Defender 日志里唯一的 C2 类记录是历史样本的 `Behavior:Win32/CommandAndControl.A!ml`（行为判定，非本项目）。
- **已做**：见顶部「当前版本状态」（代码签名 / 8 条加载器链 / 真 DLL 载荷 / BOF 按需编译 / Go 构建期指纹擦除 / sleep mask / 去 RWX / `docs/EVASION.md`）与 S3 阶段详情（静态降特征三批 + 布局回归修复）。内存模块按需裁剪（`light` 整档）与 PE 资源/节名口径**已完成**，不再列在待做。
- **未做**：见「后续优化清单」第 6 项（C2 地址/sessionID 等改 `[]byte` 纳入 sleep mask；启动期 AMSI/ETW patch —— 注意 `edr_blind` 现在是任务级 + 需管理员，存在鸡生蛋问题，且 AMSI patch 对 Go 默认载荷收益≈0；EDR/杀软名单字符串外置，即 `edr_windows.go` 的 `defaultAVProcesses` 改由服务端下发；动态测试矩阵自动化）。
- **验收口径**：干净 VM（仅 Defender）里默认载荷执行后 5 分钟内不触发 `Behavior:` 类拦截；装有 360 的机器上给出"签名载荷可执行 / 白加黑链可执行"的实测记录（**需要目标机，本机因安全软件拦截无法执行任何新 PE**）。
- **需要操作员提供**：放行环境 / 目标机（与第 4 项相同）。

### P1 Agent / 智能化（延续 v1.3.x 方向）

> **状态：全部未开工**（S2 只做了"长任务可靠性"这一层，本节是能力层方向）。均为纯代码项，无外部材料依赖，可按需插队。
- **分层记忆持久化**：agent 会话记忆落 sqlite（当前 run 内存保留 30 分钟即清），支持跨重启召回历史目标/判断/已采集情报；前端可按会话回放历史 run。
- **多 Agent 编排 / 委派**：把单 run + 剧本 delegate 升级为「规划者 + 执行子代理」，子代理并发跑不同会话/路径，规划者聚合结果并去重。
- **执行轨迹回放面板**：timeline 已有结构化事件（thinking/tool/result），前端做可暂停、可跳转、可导出的回放视图。
- **信息收集「一键情报库」**：侦察报告结构化（用户/组/IP/端口/杀软/凭据线索）写入 intel 库，后续会话直接 `intel_query` 命中，避免重复侦察。
- **工具面原子化/收敛**：playbook 与 agent 共用统一原子工具层；长耗时任务（大文件传输、凭据 lsa）设计为「可查询的原子任务」而非仅轮询。
- **Agent 与 BYOVD/EDR 对抗联动**：把「检测到杀软 → 选路（驱动击杀/EDR 失明/进程注入）→ 验证是否成功」做成确定性剧本，减少模型自由发挥。
- **验收口径**：每项各自定义；共同前提是不得让"未验证的能力"出现在工具面（沿用 S6 的守卫测试做法）。

### P2 平台工具库与远程加载（不增植入端体积）

> **状态：全部未开工**（`data/tools/` 只有 `.gitkeep`）；执行顺序见「后续优化清单」第 7 项。
> **设计原则**：植入端保持"小而精" —— 只内置命令执行/文件/进程/注入/凭据/截屏/网络等底层原语；高阶能力（端口扫描、横向、凭据传递、内网探测）**不编译进植入端**，由服务端工具库按需远程加载执行。

- **2.1 工具库建设（前置）**：目录按**平台/架构**组织 `data/tools/<os>/<arch>/<tool>`，同级 `manifest.json` 记元数据（用途、平台/arch、调用参数示例、**SHA-256**、来源出处、许可、体积、最后校验时间）。**预置范围（已确认）**：只预置**自研脚本型工具**（纯文本、可审计、无版权/供应链风险）；**第三方二进制不预置**，走"按需下载 + sha256 校验 + 版本轮换"，下载源与哈希写进 manifest（agent 用 `remote_download` 拉到服务端 `data/tools/`，再分发到会话）。校验：下载后强校验 sha256（不匹配即拒绝并告警），记录来源 URL 与时间；定期轮换版本。
- **2.2 能力链（都走远程加载）**：内网探测链（端口扫描/主机发现/共享枚举 → 结果收敛进情报库，落成确定性 playbook）；横向移动（复用既有 exec 原子机制、会话忙期判活与高危审批护栏）；凭据利用（采集仍走植入端原生原语，**利用**工具走远程加载并纳入高危审批）；免杀/规避载荷远程化（新注入方式、新载荷形态按需下发，痕迹清理做成轻量命令链 playbook）。
- **验收口径**：植入端二进制体积/功能面不随上述能力增长；「下载→校验→内存加载→执行→回传→清理」闭环可跑通；工具元数据缺失/哈希不符时明确拒绝执行。
- **需要操作员提供**：第三方二进制的下载源与哈希清单策略（预置只放自研脚本）。

### P3 平台 / 工程

> **状态**：除"Release/打包的 CI 校验部分"与"前端杀软对抗页重排"外**均未开工**；执行顺序见「后续优化清单」第 10 项。

- **多通道一致性**：MQTT/relay/HTTP-polling 与 TCP 的判活、忙期、任务重放语义对齐（TCP 最完整；已统一判活入口 `Session.IsAlive`，其余语义仍待对齐）。
- **Release/打包**：✅ CI 三级校验（`toserver -version` == tag、zip 内容清单、`checksums.txt`）已完成；❌ tag 前接 `e2e_smoke.ps1` 未做。
- **配置热更新边界**：心跳超时等会话参数改动后对存量会话的生效时机文档化（现为"改动后新会话立即生效、存量会话按采样自适应"）；`git stash@{0}` 里的"配置热重载报错可见"**已捡回并真机验收**（见 S6 阶段详情 P0-2 段），这里只剩"生效时机文档化"本身未做。
- **前端**：✅ 杀软对抗页信息架构已重排（BYOVD 区块 + 驱动加载前自检结论直接标在按钮与提示区）；❌ 任务列表虚拟滚动（大量任务不卡）、Sessions/仪表盘 WS 事件统一订阅组件（现在多处重复实现）未做。
- **可观测性**：屏幕流帧限速丢弃数、广播去抖抑制次数等运行指标暴露到界面/日志汇总（当前只在日志里；v1.3.4 已把"真正烘焙进载荷的参数"写进构建日志）。
- **服务端在线更新（自更新）**：
  - **现状（手工、会断线）**：升级 = 停掉 `toserver(.exe)` → 覆盖文件 → 重新启动；期间**所有会话与 SOCKS5 隧道全断**。既没有版本检查，也没有产物校验、回滚或审计。
  - **目标**：控制台「关于/设置」提供「检查更新 → 查看版本与变更摘要 → 确认更新」，随后自动完成**下载 → 校验 → 落盘 → 原子替换 → 重启 → 自检**，全程有日志与状态回显；失败时必须**保持现有二进制可用**。
  - **实现要点（按顺序做）**：① **先做服务化/守护**（前置）：当前服务端是前台进程，替换后没人拉起 —— 需要 `install.ps1`/`install.sh` 支持注册为 **Windows 服务 / systemd unit / 计划任务**；② **原子替换**：Windows 上无法覆盖正在运行的自映像 —— 下载到 `toserver.new` → 校验 → 旁路脚本 `MoveFileEx(..., MOVEFILE_REPLACE_EXISTING)` 或"改名旧文件 + 换名 + 重启"；Unix 侧可直接 `rename`（原子）；③ **校验与防降级**：强制 **sha256 比对**（复用 Release 的 `checksums.txt`），可选 **Authenticode 签名校验**（复用 `builder/sign.go` 的验签能力）；拒绝从更高版本降级、拒绝摘要/签名不符；④ **数据安全**：更新前**自动备份 `data/toshell.db`**，保证 schema 迁移向后兼容（新版本启动失败可回滚上一版二进制 + 数据库）；⑤ **安全边界（重要）**：服务端二进制 = 完整 C2 控制端，**更新通道被劫持等于整个 C2 被接管** —— 因此默认**关闭**在线更新，需显式开启并配置**可信更新源白名单**（自建源 / GitHub Release）+ 独立更新密钥；更新动作要求二次确认并写审计日志。
  - **验收口径**：在测试环境从 v1.3.5 升到下一版：点「检查更新」→ 显示版本与摘要 → 确认后自动下载校验、替换、重启 → 植入端自动重连、配置与 sqlite 数据不受影响；**断网 / 摘要不符 / 签名不符时明确失败且不改变现有二进制**；保留上一版二进制可一键回滚。
- **需要操作员提供**：自更新需要可信更新源（自建源 / GitHub Release）与更新密钥决策。

---

## 已完成（归档，见 [CHANGELOG.md](CHANGELOG.md) 对应版本）



<details>
<summary><b>v1.3.5（2026-09）</b></summary>

- ✅ **Web 控制台 UI 全面优化**：修掉"短别名变量没定义、只有深色兜底值"导致**浅色主题配色错误**的根因，统一 token（颜色/间距/字号/动效/焦点环）；新增一层基础件（`web/src/components/ui`：Card/Section/Badge/RiskBadge/Callout/Field/Check/Empty/Skeleton/Stat/KeyValue/Toolbar/Code）与 `ui-*` 工具类；生成载荷页把 30 多个控件收进可折叠分组、一键上线命令改为**分组筛选 + 搜索 + 复制全部 + 风险等级徽标**、新增**落地建议**与**签名结论**提示、**载荷 ID 一键复制 + 加载器链命令「填入载荷 ID」**、`dll` 格式出现导出名与"加载即启动"选项；侧栏折叠持久化与窄屏浮层、会话详情 13 个 tab 改为**常用常驻 + 「更多 ▾」下拉收纳**（下拉被 tab 条 `overflow` 裁掉的坑已修）、仪表盘/会话列表/设置/登录/关于统一卡片与空态/骨架屏；设置页新增 `builder.sign_*` 等构建配置可视化填写；顶栏「在线」改为**真实探测 `/api/v1/health`**（20s + 窗口聚焦）。
- ✅ **修掉"光标狂闪 / 状态灯爆闪"（用户实测）**：根因是本项目 `prefers-reduced-motion` 规则写成 `* { animation-duration: 0.01ms !important }`，把**所有 `infinite` 动画压到 0.01ms 却仍无限循环**（≈10 万次/秒），xterm v6 的 CSS 光标闪烁首当其冲。现改为只收敛 `transition-duration`、装饰性无限动画逐个点名 `animation: none`，**永不压缩动画时长**（`web/src/index.css` 已注明原因）。
- ✅ **构建后代码签名（P0-5）**：pfx / 证书存储指纹两种模式；签名栈优先 signtool、回退系统自带 PowerShell（密码走环境变量、不进命令行）；签名后复核并回传签名者/状态/中文说明；前端「上次构建」显示签名结果。实测自签证书已签上（`SignatureType=Authenticode`、+1.4KB），并修掉两个真实坑：PowerShell 5.1 的 `Get-PfxCertificate` 无 `-Password`；`UnknownError` + 有签名者应判为"已签名但链不受信任"。
- ✅ **8 条加载器链 + 落地建议（P0-5）**：白加黑 DLL 侧加载 / 计划任务 + 已签名宿主 / rundll32 / mshta / regsvr32 Squiblydoo / certutil + 宿主 / PowerShell 内存注入 shellcode / mshta + 宿主注入骨架，每条带 `note`（前置条件 + 风险等级）；`LoaderAdvice()` → `loader_advice_title/tips` 给出降级顺序；新增 `docs/LOADERS.md`。
- ✅ **BOF 按需编译（P0-5）**：`-tags bof` 才编译，默认载荷 `beaconAPI=0`（勾选后 22），full 档案最后一项高信号明文消失；新增 `TestBOFIsOptIn`。
- ✅ **Go 构建期指纹擦除（P0-5）**：`ScrubGoFingerprint` 擦除 buildinfo 魔数 / 窗口内版本串 / `Go build ID:` 前缀（长度不变），exe 与 dll 路径都接入，实测均归零；单测覆盖擦除/幂等/边界。
- ✅ **动态免杀第一批：休眠期内存加密（P0-5）**：新增 `sleepmask_windows.go`/`_unix.go`（模板双份镜像），在空闲窗口（启动随机延迟 / HTTP 轮询 / 重连退避 / 非工作时段）对**隧道 SM4 子密钥**与**任务结果缓存**做 XOR 掩码，休眠走 apihash 解析的 `NtDelayExecution` 并分片 ≤300ms + 抖动；`ensureUnmasked()`（abort 标志 + ≤2s 轮询）保证用密钥的路径最多等 1 个分片；结果缓存用 `maskIfMaskedCopy()` 加密副本，避免与发送缓冲互相干扰。**如实说明**：加密不了整个镜像/代码段（Go runtime 时刻在跑），C2 地址这类 string 也暂不在范围内（列入待做 1）。
- ✅ **去 RWX（P0-5）**：审计植入端全部 `VirtualAlloc/VirtualProtect/NtProtectVirtualMemory` 调用点，改为 **RW 写 → RX 执行**两段式（`memprotect_windows.go`/`_unix.go` 提供 `allocRW`/`protectRX`/`protectRW`/`withWritable` 并**硬拒 `PAGE_EXECUTE_READWRITE`**），覆盖 `blob`/`bof`/`carve`/`imgexec`/`plugin` 等路径；实测默认载荷 `PAGE_EXECUTE_READWRITE=0`。
- ✅ **验证文档 `docs/EVASION.md`**：把「落地 / 动态免杀 / 静态降特征」分开，逐项标注**验证状态**与验证方法（含"一次只改一个变量 + ≥3 次重复 + 记录拦截原文"的纪律），并明确标注运行期未实测的部分。
- ✅ **设置页拆成 4 个分页**：原先一页堆 10 个分组（靠滚动监听高亮侧栏），现按主题分为 通用与服务 / 植入端与载荷 / 集成与通知 / 账户与鉴权，左侧导航切换、只渲染当前分页；`draft`/`baseline` 仍是组件级单一状态（切页不丢未保存改动），吸顶保存条按分组汇总；支持 `/settings?page=` 深链接与旧 `#sec-*` 锚点映射；内容列限宽 + 分组间距走 `--sp-*` 标尺，窄屏侧栏变横向标签条。
- ✅ **设置页「通用与服务」「日志与审计」改为可写**：这两个分组的保存接口 v1.3.5 已放行（`server.api_host/api_port`、`logging.level/format`、`listener.heartbeat_timeout`、`listener.write_queue_size`），页面上却仍挂着"需改 server.yaml"的旧提示且输入框 disabled —— 前后端口径不一致已修正，并标注"改端口/主机需重启、日志与心跳超时热生效"。
- ✅ **关于页许可证与文档改为在线预览地址**：原来指向 `/LICENSE`、`/USAGE.md` 等**并不由控制台静态资源提供**的同源路径（点了 404），现改为 GitHub `blob/main` 在线地址并补齐 EVASION/LOADERS/DEPLOY-DOMAIN-CDN/SECURITY；首页两个空 `href=""` 一并填上。
- ✅ **发布包补上 `docs/`**：CI 与本地打包脚本此前都不带 `docs/`，而包内 README/USAGE 大量链接指向 `docs/EVASION.md`、`docs/LOADERS.md`（截图也在 `docs/screenshots/`）—— 包内死链；现两条打包路径都带上，并加入包内容校验清单。同时修掉 `retry_wait == 0` 硬编码 5（没读 `implant.retry_wait`）导致"设置页配了不生效"的口径不一致。
- ✅ **版本 1.3.5**：全量版本号统一。

- ✅ **DLL 载荷修成真 DLL（P0-5 落地链的关键前置）**：`format=dll` 以前因 `CGO_ENABLED=0` 下 `import "C"` 被静默跳过，产物其实是"改了扩展名的 EXE"（实测 `IMAGE_FILE_DLL=false`、导出表为空），白加黑/rundll32 三条链第一步就失败。现在用 `-buildmode=c-shared + mingw-w64 gcc`（**要求与目标架构一致的 gcc**，否则明确报错而不是产出错误架构的 DLL）编译真 DLL：`IMAGE_FILE_DLL=true` + 导出表；默认**加载即启动**（`init()` → `go startImplant()`），导出名可配（默认 `Start`，可填宿主期望的系统 API 名；C 侧 `__stdcall` 包装，386 用 `-Wl,--kill-at` 剥 `@16`）；能力接口新增 `dll_available/dll_message`，生成载荷页显示缺哪个 gcc。实测 386 DLL 导出 `Start` 与自定义 `GetFileVersionInfoW` 均正确。
- ✅ **共享库构建取舍（如实说明）**：cgo 包不能带 Go 汇编 → 排除 PEB 汇编与 amd64 直接系统调用，新增 `directsyscall_windows_amd64_shared.go` 走 apihash 回退；`main.go` 拆出 `startImplant()`（DLL/exe 共用）+ `entry_exec.go`（`!shared`）。
- ✅ **修 JSON 响应 bug**：构建失败时错误文本含换行会产出非法 JSON（前端只看到"解析失败"而非真正原因），新增 `writeJSONError` 并改写构建相关错误响应。
</details>

<details>
<summary><b>v1.3.4（2026-09）</b></summary>

- ✅ **动态查杀定位（P0-5 前置）**：本机（360 + 电脑管家 + 无边界安全系统）实测证明"新生成/未签名 PE 一执行就被拒并删除"，与载荷代码无关（Hello-World Go 程序同样被拒、MS 签名程序正常）——结论与证据写进 `CHANGELOG.md`，避免后续重复踩坑。
- ✅ **植入端默认行为收敛（P0-5）**：启动时"枚举全系统进程 + 比对 38 个杀软进程名"默认关闭（`-tags evasionscan` 才编译，前端开关默认关）；pclntab 高信号标识符与文件名中性化（`stomp*→carve*`、`memexe→imgexec`、`memload→blob`、`evasion→gate`、`loadShellcode→runBlob` 等，`light` 档案连 `beacon*` 都为 0）。
- ✅ **三个"配置了却无效"的缺陷（P0-5）**：`startup_delay_min/max` 请求字段补齐并透传（此前被静默丢弃）；`interval==0 → 5s`、`jitter==0 → 2%` 的硬编码覆盖改为优先跟服务端配置（示例配置默认 60s/20%）；驱动加载失败回传 Win32 错误码与排查结论。构建参数写入服务端日志。
- ✅ **驱动加载前自检（P0-1）**：manifest `sha256` 一致性硬拦（不一致 400 拒发）+ `WinVerifyTrust` 签名/篡改校验与签名者 + 易受攻击驱动黑名单策略提示（不内置名单）；`GET /drivers/{name}/verify`；前端标出"哈希不符/未签名"并展示警告。
- ✅ **内存执行下发前 PE 预检（P0-2）**：手写 PE 解析 + Go 载荷识别，Go/架构不符/.NET 直接拒绝并给原因与建议，TLS/无重定位/donut 给警告，`force:true` 可强制但留痕。
- ✅ **发版门禁（P0-4）**：`scripts/e2e_smoke.ps1`（临时服务端 + 鉴权/路由 + 三档载荷 + 可选真植入端上线与任务回执 + 摘要与非 0 退出）；CI 增加 tag/版本一致性、zip 内容清单校验与 `checksums.txt`。
- ✅ **版本 1.3.4**：全量版本号统一（服务端默认版本、Web、About、README、USAGE、部署脚本、打包脚本）。

</details>

<details>
<summary><b>v1.3.3（2026-09）</b></summary>

- ✅ **会话判活去抖（P0-1）**：阈值 = `max(heartbeat_timeout, 3×实测心跳间隔)`（按会话自适应 + 首周期保护），三监听器统一判活、扫描 10s→5s；`session_offline` 延迟 15s 观察窗，窗口内重连不发任何事件；重复注册不再重复广播上线（webhook 同步去重）。实测 60s 心跳跑 220s 零抖动、真掉线仍按 3m1s 判死。
- ✅ **屏幕流/截图参数化（P0.2 Windows 部分）**：`fps/quality/max_kbps/monitor/max_width/format`；植入端带宽自适应（超限降质→降帧+限宽，有余量逐级恢复）；服务端帧限速/合并（硬上限 10fps）；捕获失败回传原因帧。实测 2560×1440 → 640×360 JPEG（343KB → 21KB）。
- ✅ **内存执行 EXE 带参数**：`fileless_exec` 新增 `exe_mem`（反射映射 + PEB 命令行注入 + IAT 退出重定向 + 架构校验 + `wait_ms`）；修正 donut 路径 `Thread/ExitOpt` 导致**杀宿主**的老 bug，并支持 donut 参数。实测 argv 正确注入。
- ✅ **BYOVD 驱动换代**：删除 `RTCore64.sys`，内置 **kgameprotect.sys**（WHQL 签名、设备 `\\.\kgameprotect`、终止 IOCTL `0x222048`、SHA-256 与 LOLDrivers PR #428 一致）；新增 `byovd_kill` 任务/接口/前端入口；`ppl_kill` 保留句柄窃取路线（能力变化见 P0-1）。
- ✅ **C 植入端工具链探测（issue #6）**：配置 → 环境变量 → 便携目录 → 常见安装目录 → PATH → **注册表 PATH** 逐级探测 + `gcc -dumpmachine` 架构校验；garble 改为真实构建探测（修掉"显示可用但构建必失败"）。
- ✅ **多平台 webhook（issue #7）**：飞书 `msg_type`+`content.text`／企业微信 `msgtype`+`text.content`／Slack／Discord／钉钉 markdown 各发各的结构；飞书 body 内加签；响应体业务码（`code`/`errcode`/`ok`）判定成功与失败原因。真植入端上线实测通知送达。
- ✅ **一键命令上线**：下载地址改为服务端按配置解析（`public_host` 优先，否则控制台地址/`server_url` 主机/内网 IP，不可达时显式告警）；Windows 6 种 + Linux 6 种免杀变体；载荷列表实时重新生成。
- ✅ **版本 1.3.3**：全量版本号统一；CI `main.version` 跟随 tag。

</details>

<details>
<summary><b>v1.3.2（2026-09-14）</b></summary>

- ✅ Web 控制台防资产测绘（Basic 前置门槛 / 404 伪装 / `/__gate` 隐蔽入口，issue #1）
- ✅ 配置写入可靠性：原子写 + 读-改-写保注释、凭据必须落盘（否则拒绝启动）、设置页不再破坏 API Key（issue #2）
- ✅ 跨平台载荷构建修复（macOS/Linux full/light 标签冲突，issue #2）

</details>

---

## 附：本会话实测发现、尚未修的问题（现场记录）

| 现象 | 影响 | 处置建议 |
|---|---|---|
| garble v0.16 要求 Go ≥ 1.26，本机 go1.25.0 → 任何 garble 构建必失败 | 混淆选项不可用（界面已如实显示"不可用 + 原因"） | 升级 Go 或安装匹配版本 garble（属环境问题，非代码缺陷；本机已装 v0.15.0 可用） |
| 本机装有 360/电脑管家/无边界安全系统，**新生成或未签名的 PE 用 `Start-Process`/`cmd start`/`.NET Process.Start` 启动一律 `Access is denied`**（连 Hello-World Go 程序也一样，MS 签名程序正常），且植入端 exe 放一会儿会被直接删文件 | 常规启动路径下本机做不了动态验证（`go test` 的新测试二进制同样会被杀） | **可用绕法（本轮实测有效）**：用 **WMI `Win32_Process.Create`** 启动载荷（拦截只挂在用户态 `CreateProcess` 调用方上，走 `WmiPrvSE` 起进程不受影响）；需要真实 stdout 时用 `cmd.exe /c "payload.exe > log 2>&1"` 包一层（给不了控制台就没法验输出回传）。长期解仍是干净 VM（仅 Defender）或 CI |
| Go 编译的 EXE 用 `exe_mem` 反射执行会崩宿主（双 Go runtime） | ✅ v1.3.4 已在下发前**明确拒绝**并给建议（P0-2 预检） | —— |
| `exe_mem` 下载荷自行退出会带走植入体（CRT 内部 ExitProcess） | 只对"跑完即退"的工具致命 | ✅ **本轮已修并真机验收**：IAT 双层拦截（镜像 + 已加载模块）改写为原生 `ExitThread` 桩、stdout/stderr 回传。改前载荷执行当秒掉线、改后 30s 全程在线且退出码/stdout 正确；覆盖边界见 S6 阶段详情 P0-2 段 |
| PPL 进程杀不掉（无具备内核读写的 `rw` 档驱动） | Defender 等 PPL 保护进程需句柄窃取 | 补 `rw` 档驱动档案与 `purpose` 选路（见「后续优化清单」第 5 项 / 附 A P0-1） |
| 一条上线命令的下载地址依赖人工配置 `public_host` | 配置错则命令不可用（已有告警与自动回退） | 可加"服务端主动探测该地址可达性"的自检（与「后续优化清单」第 10 项的可观测性一起做） |
