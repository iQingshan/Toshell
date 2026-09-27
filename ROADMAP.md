# ToShell 后续优化路线（ROADMAP）

> 记录 **v1.4.0 迭代计划**与后续待优化的方向。每条标注现状（代码事实）、问题/根因、目标与验收方式，按阶段与优先级排序。
> 已完成的项归档在本文件底部「已完成」章节；更新日志见 [CHANGELOG.md](CHANGELOG.md)。
> **本文只聚焦「下一步要做什么、为什么」**，不重复发版说明。免杀相关的实现现状与验证状态见 [docs/EVASION.md](docs/EVASION.md)，不落地上线手段见 [docs/LOADERS.md](docs/LOADERS.md)。

---

## 当前版本状态（v1.3.5 已发布 · v1.4.0 开发中）

| 能力 | 状态 |
|---|---|
| 会话判活 | ✅ 不再抖动（阈值含 3 倍心跳余量 + 广播去抖） |
| 屏幕流/截图（Windows） | ✅ 参数化（fps/quality/max_kbps/monitor/max_width）+ 带宽自适应 + 服务端限速 |
| 屏幕流/截图（Linux/macOS） | ❌ 仍为 stub（P0-3，下一版） |
| 内存执行 | ✅ shellcode / BOF / DLL / **EXE（反射映射 + 参数注入）**；✅ **下发前 PE 预检**（Go 载荷/架构不符/.NET 直接拒绝，TLS 无重定位给出警告，可 `force` 强制） |
| BYOVD 驱动 | ✅ **不内置任何驱动**（操作员自备 .sys + manifest 档案）；✅ 驱动击杀/档案登记/会话级记忆；✅ **加载前自检**（sha256 一致性硬拦 + Authenticode 签名者 + 易受攻击驱动黑名单提示） |
| C 植入端工具链 | ✅ 探测鲁棒（配置/环境变量/便携目录/注册表 PATH）+ 架构校验 |
| 通知 | ✅ 飞书/钉钉/企业微信/Slack/Discord 各自结构 + 业务码判定 |
| 运行时行为足迹 | ✅ 启动自动"枚举进程找杀软"默认关闭（`evasion_scan` 显式开启）；pclntab 高信号名中性化；**BOF 默认不编译（`beacon*`=0）**；**Go buildinfo/构建 ID 已擦除**；启动延迟/心跳节奏可按载荷配置 |
| 落地能力（"起不来"的正解） | ✅ **代码签名**（pfx/证书指纹 + 签名后复核 + 前端显示）；✅ **8 条加载器链**（白加黑/计划任务/LOLBin/内存加载）+ 降级建议；✅ **真 DLL 载荷**（c-shared + 架构匹配的 mingw，加载即启动、导出名可配）；⚠️ 真实证书获取与目标机信任链落地仍需操作员准备 |
| **动态免杀（运行时行为）** | 🟡 **第一批已实现、运行期未实测**：休眠期内存加密（sleep mask：隧道子密钥 + 任务结果缓存）+ apihash/PEB 手工解析 + 直接系统调用；✅ **去 RWX**（RW 写 → RX 执行，硬拒 `PAGE_EXECUTE_READWRITE`）。本机杀软会删除任何新生成的 PE，**无法在本机做运行期验证**（见 P0-5 待做 6） |
| **Web 控制台** | ✅ 主题 token 统一 + 组件层（卡片/分组/徽标/提示条/空态/骨架屏）+ 键盘焦点可见；✅ 生成载荷页分组折叠、命令分组/搜索/风险等级、**载荷 ID 一键复制与填入**、签名结论与落地建议；✅ 会话详情「更多 ▾」下拉收纳；✅ 顶栏状态为真实 `/health` 探测 |
| 发版门禁 | ✅ `scripts/e2e_smoke.ps1`（临时服务端 + 三档载荷 + 关键接口 + 可选真植入端上线）+ CI 侧版本号与包内容校验 + `checksums.txt` |
| 平台工具库 `data/tools/` | ❌ 未建设（P2 前置项） |

---

## v1.4.0 迭代计划（分阶段落地，当前目标）

> **执行方式**：分 6 个阶段，每阶段**先在本地完成实现与验证**（编译 / 类型检查 / 单元测试 / 本地服务端与 UI 联调），确认通过后再提交推送。
> **详细方案**（接口签名、DDL、YAML、协议报文、里程碑人日、验证矩阵）保存在本地文档 `docs/plan/*.md` 与 `docs/PLAN-NEXT-ROUND.md`（**不入库**）；本节即为其入库版本，落地进度直接回填本节。

| 阶段 | 主题 | 关键交付 | 吸收的原有条目 |
|---|---|---|---|
| **S1** | 开放 MCP 服务接口 + 公共执行基础设施 | 工具注册表单源化、统一结果信封与外置句柄、MCP 协议层（stdio/HTTP）、三档分级与审批门、审计 | 新建（同时是 S2 的地基） |
| **S2** | 内置 Agent：长任务可靠性 | 异步任务状态机 + 状态落盘 + 断线恢复、长结果外置与回读、上下文分层预算、三处硬上限、审批分级、trace 回放 | **P1 全部** |
| **S3** | 免杀：分层治理（落地 / 动态 / 静态） | 验收环境与分层判定矩阵、签名链路与顺序约束、落地链（白加黑 / 不落 PE）、动态批次 2、静态降特征 | **P0-5 待做 1/2/5/6** |
| **S4** | 植入端体积分档与内存加载 | 能力位图（前置）、nano/light/full 分档与构建命令、内存模块 build tag 化、`exec_module` 契约与 ABI、工具库远程加载 | **P0-5 待做 3/4 + P2 全部** |
| **S5** | 新增低特征通道 | WS 补域前置/拟态/uTLS（零新库）、首个新通道端到端、多通道热切换 | 新建 |
| **S6** | 杀软对抗能力分级 + 工程收尾 | AV-L0 侦察 / AV-L1 温和、驱动选路与清场、内存执行加固、屏幕流跨平台、e2e 接 CI、可观测性、服务端在线更新 | **P0-1 / P0-2 / P0-3 / P0-4 + P3 全部** |

### S1 开放 MCP 服务接口 + 公共执行基础设施（✅ 已完成）

- **工具元数据单源化**：新增 `internal/server/mcp`（`registry.go` 类型与 JSON Schema 生成、`registry_tools.go` 38 个工具的**类型化参数与风险分级** read 13 / confirm 14 / danger 11），REST `/api/v1/mcp/tools`、内置 AI 的 function schema、对外 MCP `tools/list` **三处同源**；删掉 `handlers_mcp.go` 里 190 行的工具清单与 `copilot.go` 里 33 条硬编码 schema。
- **统一结果信封 + 大结果外置**（`envelope.go` / `resultstore.go`）：`{status,data,error,meta}`，超限结果落盘 `data/mcp-results/<日期>/<hex>` 并由 `result_read` 分页回读；**截断一律显式标注**；句柄做白名单 + `Abs`/`EvalSymlinks` 双校验防穿越。
- **MCP 协议层**：`initialize` / `notifications/initialized` / `ping` / `tools/list` / `tools/call` / `resources/list` / `resources/read`；`Mcp-Session-Id` 会话、`DELETE` 结束、`GET` SSE；stdio 桥 `cmd/toshell-mcp`。新增 `scripts/mcp_smoke.ps1`（18 项权限/协议/设置页矩阵，不需要植入端）。
- **安全边界**：独立回环监听（默认 `127.0.0.1:18082`）、MCP 专用 token（常量时间比较，不复用管理 API Key）、CIDR/Origin 校验、三档分级默认只放行只读、审批门扩展点（`ConsentGate`，真正的审批接线在 S2）、RPM/并发/挂起句柄三道闸、JSONL 审计（参数只记摘要、敏感键全脱敏）、fail-closed。
- **兼修两个既有缺陷**：`delegate` 绕过审批（`isRiskyTool` 原为"允许列表 + fail-open"）、`plugin_upload`/`fileless_exec` 的路径穿越。
- **验收证据**：`go build ./...` / `go vet` 通过；`go test ./internal/server/mcp/...` ok；`scripts/mcp_smoke.ps1` **18/18 通过**（无 token/错 token 401、会话头 400、tools/list=38、只读可调用、危险默认 403、未注册 403、路径穿越 403、超 RPM 429、设置页 GET/PUT 与工具名校验）；`npm run build` 通过。

### S2 内置 Agent：长任务可靠性

- **进行中**。已完成：
  - **状态落盘**：4 张表（`agent_runs`/`agent_steps`/`agent_tool_calls`/`tool_results`，见 `internal/server/database/agent_schema.go`）+ 专用存储层 `internal/server/agentstore`（run 状态机推进、step 恢复游标、tool_call 幂等 upsert、result TTL 清理、同参重复计数）；全部 `IF NOT EXISTS`，对既有库幂等。
  - **任务 id 计数器校准**：`task.Manager.SeedTaskCounter(MAX(tasks.id))`，修掉进程重启后新任务与历史任务撞号。
  - 顺带确认：`ai` 事件通道**已是 8192**（无需再改），SSE 满通道丢弃策略仍待改成"可续传"。
- **已在真实服务端 + mock LLM 上跑通的循环行为**（不依赖任何真实模型/植入端）：`max_turns` 触发即停且提示里带真实轮次；同一 confirm 级工具同参数第 3 次**在调用前**停止并记 `loop_detected`（只读工具重复不误杀）；`graded` 下 confirm 级工具执行前挂起（`status/stop_reason=awaiting_consent`，未下发命令），deny 后恢复并留"已跳过"轨迹。
- 待做（按依赖顺序）：
  1. ✅ **异步任务状态机**（已完成）：`task.Manager` 增加终结通知原语（`Subscribe`/`WaitSettled`，注册与状态判定同锁防丢通知、等待者摘除不泄漏），`pushAndAwait`/`task_wait`/`execAndAwait`/剧本 `waitForTask` 全部改为**事件驱动等待**（不再 sleep 轮询，对外契约逐字段不变）；Agent 侧对预估超时 ≥ `ai.long_task_threshold_sec`（默认 150s）的工具改为「提交 → `awaiting_task` 挂起并落库 `waiting_on` → **释放并发槽位** → 任务完成通知唤醒 → 结果接回 → 重入循环」；启动时对账 `agent_runs` 与 `tasks`（已完成→接回、仍在跑→重新订阅、丢失→明确终态 `task_lost`），顺带修掉"重启前下发的任务结果永远丢失"。**收益有专门用例**（并发上限 1 时挂起后槽位可再获取）。剩余：`tasks.output` 截断 500 字节限制了重启恢复的结果长度；挂起会重置 `max_wallclock`/`max_turns` 预算（应接入 `agent_runs` 用量字段）。
  2. ✅ **长结果外置 + 句柄内联 + 分页回读**（已完成，设计见 `docs/AGENT-RESULT-OFFLOAD.md`）：唯一转换点 `mcp.InlineForModel`（≤8 KiB 原文；超限只给"摘要 + 句柄 + 显式截断说明"的合法 JSON 信封；外置失败则给预览 + 说明）；`result_read` 从"只在注册表里"补成真实现并加入 Agent 工具面（slice/tail + 游标，页大小自适应收缩）；删掉 8 处字符串硬截断，顺带修掉"截图 base64 被切成非法 JSON"（根因在服务端，植入端未改）与"integer 工具参数被静默丢弃"（回读翻不动页的真因）。
  3. ✅ **上下文分层与 token 预算**（已完成）：常驻 / 任务 / 工作（默认最近 14 条原文）/ 历史（更早折叠）四层装配抽成纯函数（`ai/context.go`），同步与异步共用；**常驻层逐字节稳定**（把每轮都变的在线会话清单从 system 移到任务层，并按 run + 5 分钟 TTL 缓存 —— 顺带消掉 `currentSessions()` 内部那次未审计的 `session_list` 调用），折叠摘要保留**真实工具名 + 外置句柄 + 截断标注**且不拆散 `tool_calls`/`tool` 配对；两道 token 预算（`ai.max_context_tokens=32000` / `ai.max_run_tokens=400000`）+ `ai.context_working_keep=14`，字符近似估算 + **解析 `usage` 回填校准** + 30% 余量，超预算**先压缩后停止**（`stop_reason=max_tokens`）。剩余：预算用量尚未纳入 `agent_runs` 的持久化统计（跨挂起/重启累计）。
  4. ✅ **控制循环三处硬上限 + 防死循环**（已完成）：`ai.max_turns=20`（统一）、`ai.max_tool_calls=40`、`ai.max_wallclock_sec=900`，触发即停并记 `stop_reason`；同工具同参数签名第 2 次提示换策略、第 3 次判 `loop_detected`（只读工具豁免）。判定逻辑为纯函数（`shouldStopRun`/`loopSignature`），有单测。
  5. ✅ **审批分级**（已完成）：`ai.consent_policy: graded|all|off`（旧值 `auto→off`、`normal→graded` 兼容），按注册表 read/confirm/danger 分级，未注册工具按 danger、`delegate` 恒危险；设置页可改，接口回传的是**生效策略**，旧键在保存时按同一语义同步写回。
  6. ✅ **可观测性**：trace id 全链路（run/事件/日志/工具调用/**HTTP 响应**，`DoneInfo` 带 `stop_reason`）；✅ **SSE `id:`/`Last-Event-ID` 断点续传**（每个 run 事件带 run 内单调递增 `seq`，重连带 `Last-Event-ID` 头或 `?last_event_id=` 恰好补齐缺口后无缝转实时；控制帧不带 id；`retry:` 提示 + 15s 心跳注释帧；`resync` 显式告知两类缺口 —— `events_expired`（缓冲淘汰，512 条/2 MiB）与 `events_dropped`（事件通道满），提示客户端改用 run 详情兜底；交接采用"先订阅通道、再取快照 + `seq ≤ lastSent` 去重"，有并发竞态用例断言 seq 连续无重复）。剩余：前端尚未使用续传（`web/src/api/index.ts` 仍需保存 `id:` 并在重连时带上、并处理 `resync`）。
  7. 🟡 **评估门禁**（离线部分已完成）：黄金集 `internal/server/ai/testdata/golden/cases.json`（**12 例**：纯问答 / 工具往返 / 防死循环（含只读豁免）/ 轮次·工具数·token 三种预算 / 分级审批挂起（含 `delegate` 与未注册工具 fail-closed）/ 大结果外置与句柄回读 / 历史折叠保真）+ 桩 LLM 与假执行器（不联网、无需真实模型与植入端），`scripts/eval.ps1` 一键跑，随 `./internal/server/ai/...` 进 CI；另有一条**全局不变量**：任何一次发往上游的消息里 `tool` 回执都必须能配到 `assistant.tool_calls`。**待做**：在线指标（`/agent/metrics`、Dashboard 卡片）与前端状态条（计划 M5，属可选）。

### S3 免杀：分层治理（先解决"起不来"，再谈"藏得深"）

- **先定性（元项）**：建立**两级验收环境 + 测试矩阵脚本**（干净 VM（仅 Defender）+ 装有 360 的目标机），并给"在哪一层被拦 → 该做哪一类改造"的**判定矩阵**。已确认的关键事实：本机**未签名 PE 在进程创建阶段就被拒**（连 Hello-World Go 都被拒、微软签名的程序正常）→ 这在**签名/信誉层**，**改载荷字节无效**。
- **落地（delivery）**：签名链路（真实证书/EV + 信任链落地）与**签名顺序约束**（签名必须是**最后一步**，资源/时间戳/UPX 都必须在签名前）。✅ v1.4.0 已把顺序做成可断言的契约（`finalize_order.go`：纯函数定序 + 构建日志 + 违规打 error + 表驱动单测），并确认 `sign_timestamp_url` 在 signtool（`/tr`/`/td sha256`）与 PowerShell（`-TimestampServer`）两条路径上都真的传到；**下一步**：真实证书/EV + 信任链落地（需操作员准备）、白加黑 / 不落 PE 的加器链实测。
- **动态免杀批次 2**：C2 地址/sessionID 等改 `[]byte` 存取以纳入 sleep mask（**真实工作量在 `string`→`[]byte` 重构**，且掩码只能覆盖空闲窗口）；**启动期 ntdll 脱钩 + ETW patch**（AMSI patch 对 Go 默认载荷收益≈0，只在进程内加载 .NET/脚本时才有意义）；单稳加固。
- **静态降特征**：PE 版本资源 / 图标 / 公司信息 / 时间戳（同时是签名前置，**必须插在 UPX 与签名之前** —— 顺序契约见 `builder/finalize_order.go` 与 `docs/EVASION.md` §2.4）；补字符串混淆的**盲区**；节名/节熵口径。✅ v1.4.0 已修掉三处**实测到的**漏点：① exe 与 dll 各残留 1 次 `go1.20.14`（`runtime.buildVersion` 落在锚定窗口之外，已加全文件版擦除）；② **混淆器只认"简单双引号字面量"** —— 含转义的 Windows 路径/设备名与**全部反引号原始字符串（注册表键、脚本模板）都被放行**，现已覆盖（struct tag 与 const 行仍保留）；③ **DLL 路径此前根本没做字符串混淆与每构建随机化**（实测明文高信号 API 名 11 处、`http://` 2 处、ETW 4 处），补齐后与 exe 同水平。代价：产物 +0.3%（exe）/ +2.8%（dll）。**待做**：PE 版本资源/图标/公司信息（需在 UPX 与签名之前插入）、节名/节熵口径。
- **明确不做/高风险项**：更全的反沙箱反调试、间接系统调用与调用栈伪装、模块 stomp —— 有实测依据表明带进程枚举的载荷在 360 机器上"一启动即被拒"，**净收益为负**，一律默认关闭、按需编译。
- **验收**：目标机上给出"签名载荷可执行 / 白加黑链可执行"的实测记录；默认载荷在干净 VM（仅 Defender）5 分钟内不触发 `Behavior:` 类拦截。

### S4 植入端体积分档与内存加载

- **能力位图（前置阻塞项）**：`internal/server/api/handlers_capabilities.go` 的注释写着"按 OS + 通道 + 档案推导"，实现却**只按 OS** → 现在用 light/nano 档生成的载荷，界面上照样显示截图/凭据/注入等按钮。必须先按档案返回真实能力集，否则分档"点了没反应"。
- **分档与构建**：`nano / light / full` 三档（含通道维度），给出每档的功能对账表、构建命令、前端提示；**默认档改为 `light`**；目标体积：nano ≤1.8 MB / light ≤2.4 MB / full ≤3.2 MB（TCP、不含 BOF；**Go 档做不到 800 KB 级**，那是 C 植入端的量级）；**UPX 不做默认**（破坏签名、与"去 RWX"冲突）。
- **内存模块 build tag 化**：`injection / edr / stomp / imgexec` 等按需裁剪（P0-5 待做 3）。
- **`exec_module` 契约与 ABI**：复用已有反射式加载底座（`blob_windows.go` 在 light 档也保留、全程无 RWX），补 `tsh_module_ctx` + `tsh_module_main` ABI（现有导出是**零参调用**，拿不到参数/返回值）；传输走一次性 token（取代"内联 base64 塞任务"）；9 步校验链（sha256 硬拦 + 复用 `pecheck.go`）。
- **工具库与远程加载（P2）**：`data/tools/<os>/<arch>/` + `manifest.json`（sha256/来源/许可），预置自研脚本、第三方按需下载校验；内网探测 / 横向 / 凭据利用 / 规避载荷全部**远程加载**，植入端体积不随能力增长。
- **验收**：各档体积落到目标区间（构建机实测）；`light` 载荷在界面上不再显示未编译能力；远程模块能完成「下载→校验→内存加载→执行→回传→清理」闭环，哈希不符即拒绝。

### S5 新增低特征通道

- **第 0 步（不新增协议）**：WS 现在**不吃域前置、不支持中继、任意路径都升级**（可被主动探测）→ 先补 `front_domain`/拟态/uTLS，零新库零新 tag。
- **首个新通道**：候选为 DNS/DoH/DoT 控制通道（穿透性最好、可零新库）、QUIC/HTTP3（服务端 `go.mod` 已依赖 quic-go，且 `internal/common/tunnel/quic/` 有可复用骨架）、HTTP/2（共用端口证书；现有 HTTP 通道很可能实为 h1.1）。**先端到端跑通一个**。
- **组合与降级**：控制面走低特征低速通道 + 数据面走高吞吐通道；多通道热切换与自动降级状态机。
- **成本约束**：加一个新协议目前需要 **12 类落点 / 20+ 处编辑**，且有 8 处"漏改就静默降级或编译失败"；新协议必须**按 tag 编译**，默认只带 1~2 个，避免撑大体积。
- **验收**：新通道端到端可用（用真实服务端 + 模拟植入端脚本联调）；镜像一致性、tag 编译矩阵、特征裁剪核对全绿。

### S6 杀软对抗能力分级 + 工程收尾

- **杀软对抗分级**：现状不是一个功能而是 6 条链（`av_detect`/`edr_blind`/`edr_kill`/`byovd_*`/`ppl_kill`/`process_kill`），缺**分级/前置检查/回滚/审计/风险回显**。方案：**AV-L0 侦察**（默认开、只读）→ **AV-L1 用户态温和**（默认开需确认）→ AV-L2 强（默认关）→ AV-L3 BYOVD（默认关，**驱动仍由操作员自备、项目不内置**）→ AV-L4 检测面抑制（默认关）；补聚合入口 + 统一信封 + 显式超时 + **破坏性任务禁止自动重试**（植入端结果缓存按 task ID 去重，重发=再执行）+ 影响评估回显 + 结构化审计 + 界面二次确认；Agent/MCP 侧只暴露 L0。
- **驱动体系（P0-1）**：`purpose` 分档真正驱动选路（`ppl_kill` 自动挑 `rw` 档，没有就明确提示）；进程重启后**残留驱动服务清场**；catalog 签名驱动支持。
- **内存执行加固（P0-2）**：hook `ExitProcess`/`RtlExitUserProcess`（把载荷退出改成只退线程，**宿主不掉线**）+ stdout/stderr 重定向捕获。
- **屏幕流/截图（P0-3）**：Linux(X11) / macOS(ScreenCaptureKit) 跨平台 + Windows DXGI 增量捕获（需真机验证，因此排在最后）。
- **工程收尾（P3）**：e2e 冒烟接进 CI（tag 前）；多通道语义对齐；配置热更新边界文档化；前端任务列表虚拟滚动与 WS 事件统一订阅；可观测性指标暴露到界面；**服务端在线更新（自更新）**（先做服务化守护 → 原子替换 → sha256/签名校验与防降级 → sqlite 备份与回滚 → 可信源白名单，默认关闭）。
- **验收**：AV-L0/L1 在授权实验 VM 上通过最小可验证集；`exe_mem` 跑原生工具后植入端不掉线；CI 在 tag 前跑通 e2e；自更新在测试环境完成"检查→校验→替换→重启→自检"且失败不改动现有二进制。

---

## P0 — 下一版优先（稳定性 / 能力补齐 / 发版门禁）

### 1. 驱动体系：操作员自备 + 多档能力 + 加载前自检（PPL 回归）

- **v1.3.4 已完成**：**加载前自检**（`internal/server/drivers/verify*.go`）——manifest `sha256` 一致性不一致直接拒绝下发；Authenticode 用 `WinVerifyTrust` 判签名与篡改、尽力取签名者；易受攻击驱动黑名单只读本机策略与名单文件、给出"1275 静默拒绝"提示；新增 `GET /api/v1/drivers/{name}/verify`，前端驱动按钮直接标出"哈希不符/未签名"并展示警告。
- **现状**：不再内置任何驱动（v1.3.3 起），`ppl_kill` 只能走句柄窃取，**PPL 保护进程（Defender MsMpEng 等）清不掉** —— 因为没有具备内核读写的 `rw` 档驱动。
- **待做**：
  - 驱动档案的 `purpose` 分档（`kill` / `rw` / `both`）真正驱动选路：`ppl_kill` 自动挑 `rw` 档；没有就明确提示"当前无 rw 档驱动，PPL 清除不可用（走句柄窃取）"；
  - **卸载兜底**：进程重启后残留的驱动服务自动清理（当前依赖操作员手点「卸载驱动」；可按服务名前缀 + 驱动目录清单做一次"清场"任务）；
  - 目录签名（catalog）驱动：目前只能给"未内嵌签名"，可补 `CryptCATAdminCalcHashFromFileHandle` 路线。
- **验收**：放入 `rw` 档驱动后 `ppl_kill` 能打印命中的 EPROCESS 与 Protection 原值/新值；`kill` 档驱动能杀普通杀软进程；manifest 哈希不符的驱动在加载时被 400 拒绝。

### 2. 内存执行加固（`exe_mem` 的可用边界收窄）

- **v1.3.4 已完成**：**下发前 PE 预检**（`internal/server/builder/pecheck.go` + `handlers_fileless.go`）——手写解析 PE 头（架构/DLL/TLS/CLR/重定位）+ Go 载荷识别（`.gopclntab`、`\xff Go buildinf:`），`exe_mem`/`dll` 命中硬边界直接 400 拒绝并给出 `reasons`/`suggestion`/`pe_info`，`warn` 类照常下发但回传 warnings，`force:true` 可强制（留痕）；前端展示原因并支持强制下发。
- **待做**：
  - **hook `ExitProcess`/`RtlExitUserProcess`**（IAT + 运行时 inline hook 双保险），把载荷的退出改成只退线程 —— 当前"跑完即退"的载荷仍会带走宿主；
  - **stdout/stderr 重定向捕获**（管道 + 读取线程），让 `exe_mem` 跑出来的工具能给回输出；
  - donut 路径的 `warn` 项细化（TLS/复杂 CRT/.NET 各自给更明确的结论）。
- **验收**：`attrib.exe`/`cmd.exe` 这类原生工具在 `exe_mem` 下执行完，植入体**不掉线**；带输出的工具能拿到返回内容；Go 载荷被明确拒绝（已达成）。

### 3. 屏幕流 / 截图：跨平台 + 增量捕获（**v1.3.4 未动**）

- **现状**：只有 Windows 实现（GDI BitBlt + PrintWindow 回退，参数化后帧率上限由带宽而非采集能力决定）；Linux/macOS 全是 stub。
- **P0.3 跨平台**：Linux 用 **X11 (XGetImage)** 起步（Wayland 走 PipeWire 需 portal 授权，作为后续）；macOS 用 **ScreenCaptureKit**（需屏幕录制权限，明确提示授权路径）；screenshot 同步补全。
- **P0.2 DXGI**：Win8+ 换 **Desktop Duplication API** 做增量帧捕获（当前每帧全量 BitBlt，1080p 下 CPU 占用偏高），保留 GDI 作为回退。
- **为什么没做**：这三项都**必须在真机（Linux 桌面 / macOS 授权 / Win10+ GPU）上验证**，本机连新生成的载荷都无法执行（见第 5 条），写了只能交付未验证代码；放到下一版在有验证条件时做。
- **验收**：Linux amd64 能出图；Win10/11 桌面会话 ≥5fps 且 CPU 占用可控；Server 无桌面返回明确错误。

### 4. 发版门禁：一条命令的端到端冒烟

- **v1.3.4 已完成**：`scripts/e2e_smoke.ps1`（临时服务端 + 鉴权/关键路由校验 + windows full/light + linux 三档载荷构建 + 可选真植入端上线与任务下发 + ✅/⚠️/❌ 摘要，有 ❌ 即非 0 退出）；CI 侧补了 **tag 与 `toserver -version` 一致性校验**、**zip 内容清单校验**（`implant/main.go`、配置样例、许可证等）与 **`checksums.txt`**（sha256 清单随 Release 发布，本地 `scripts/package_release.ps1` 同步生成）。
- **待做**：把该脚本接进 CI（tag 前 workflow）；补"发布包内 `toserver -version` == tag"的本地校验（CI 已有）。
- **验收**：CI 在 tag 前跑该脚本；本地 `powershell -File scripts/e2e_smoke.ps1` 一条命令可复现。

### 5. 动态（行为）查杀：先解决"起不来"，再谈"藏得深"

- **现状（本机实测，2026-09）**：
  - 装有 360 安全卫士 + 腾讯电脑管家 + 无边界安全系统的主机上，**任何新生成/未签名的 PE 一执行就被拒并删文件**：一个只有 `time.Sleep` 的 Hello-World Go 程序同样被拒（`Access is denied` + 文件被删除），`release/implants/` 历史产物已被清空；对照 MS 签名的 `notepad.exe` 副本可正常执行。
  - 所以本机看到的"动态被查杀"**判别不出载荷特征**：拦截依据是"未签名/未知 PE + 主动防御策略"。Defender 日志里唯一的 C2 类记录是历史样本的 `Behavior:Win32/CommandAndControl.A!ml`（行为判定，非本项目）。
- **已做（v1.3.4）**：启动阶段的"枚举全系统进程 + 比对 38 个杀软/分析工具进程名"默认关闭（`-tags evasionscan` 才编译）；启动随机延迟、心跳间隔/抖动可按载荷配置且服务端配置真正生效（示例配置默认改为 60s/20%）；pclntab 高信号标识符中性化；驱动加载失败回传具体 Win32 错误码；构建参数写入服务端日志便于核对。
- **已做（v1.3.5，本版重点）**：
  1. ✅ **代码签名**（`sign.go`）：pfx / 证书存储指纹两种模式，签名栈优先 signtool、回退系统自带 PowerShell（密码走环境变量），签名后立刻复核并把 `signed/signer/sign_method/sign_status/sign_message` 回传前端；**本机实测已签上**（`SignatureType=Authenticode`、签名者与指纹一致、+1.4KB），自签证书因根未受信任为 `UnknownError`（已如实区分"已签名但链不受信任"与"未签名"）。
  2. ✅ **8 条加载器链**（`oneliner.go` + `docs/LOADERS.md`）：每条带前置条件与风险等级；`LoaderAdvice()` 给出"直接运行 → 计划任务 → 白加黑 → 内存加载"的降级顺序。
  3. ✅ **真 DLL 载荷**：`-buildmode=c-shared` + mingw（要求架构一致），加载即启动、导出名可配（386 用 `--kill-at` 剥 `@16`）；静态实测 `IMAGE_FILE_DLL` + 导出表正确。
  4. ✅ **BOF 按需编译**：默认载荷 `beaconAPI=0`（勾选后 22）。
  5. ✅ **Go 构建期指纹擦除**：buildinfo 魔数 / 窗口内版本串 / `Go build ID:` 前缀（长度不变）。
  6. ✅ **动态免杀第一批 —— 休眠期内存加密（sleep mask）**：空闲窗口对隧道 SM4 子密钥与任务结果缓存做 XOR 加密，休眠走 `NtDelayExecution` 分片（≤300ms + 抖动）；用密钥的路径先 `ensureUnmasked()` 提前还原（≤1 分片），缓存与发送缓冲用"加密副本"避免互相干扰。**如实说明**：加密不了整镜像/代码段（Go runtime 时刻在跑），C2 地址这类 string 也暂不在范围内。
  7. ✅ **去 RWX**：注入/加载路径改为 RW 写 → RX 执行两段式保护。
  8. ✅ **概念与验证文档**：新增 `docs/EVASION.md` —— 把「落地 / 动态免杀 / 静态降特征」分开，逐项标注验证状态与验证方法（含"一次只改一个变量 + ≥3 次重复 + 记录拦截原文"的纪律）。
- **待做（按收益排序）**：
  1. **把 C2 地址/sessionID/关键配置改成 `[]byte` 存取**：让它们也能进 sleep mask 的加密范围（现在 string 可能位于只读段，无法安全原地加密）；
  2. **启动即做 AMSI/ETW 用户态 patch**（现在 `edr_blind` 是任务级 + 需管理员，存在鸡生蛋问题）；**间接系统调用**替换裸 `syscall`；
  3. **内存模块 build tag 化**：`injection/edr/stomp/imgexec` 等按需 `-tags` 裁剪；
  4. **EDR/杀软名单字符串外置**：`edr_windows.go` 的 `defaultAVProcesses` 改由服务端下发；
  5. **PE 版本资源/图标/时间戳**（"合法外观"，也为签名铺垫）；
  6. **动态测试矩阵自动化**：把 `docs/EVASION.md` §3.1 的流程脚本化（记录 360 拦截记录 + Defender 1116/1117 + 是否上线），以后每项免杀改动都用它验收。
- **验收**：在干净 VM（仅 Defender）里，默认载荷执行后 5 分钟内不触发 `Behavior:` 类拦截；在装有 360 的机器上给出"签名载荷可执行 / 白加黑链可执行"的实测记录（**需要目标机配合，本机因安全软件拦截无法执行任何新 PE**）。

---

## P1 — Agent / 智能化（延续 v1.3.x 方向）

- **分层记忆持久化**：agent 会话记忆落 sqlite（当前 run 内存保留 30 分钟即清），支持跨重启召回历史目标/判断/已采集情报；前端可按会话回放历史 run。
- **多 Agent 编排 / 委派**：把单 run + 剧本 delegate 升级为「规划者 + 执行子代理」，子代理并发跑不同会话/路径，规划者聚合结果并去重。
- **执行轨迹回放面板**：timeline 已有结构化事件（thinking/tool/result），前端做可暂停、可跳转、可导出的回放视图。
- **信息收集「一键情报库」**：侦察报告结构化（用户/组/IP/端口/杀软/凭据线索）写入 intel 库，后续会话直接 `intel_query` 命中，避免重复侦察。
- **工具面原子化/收敛**：playbook 与 agent 共用统一原子工具层；长耗时任务（大文件传输、凭据 lsa）设计为「可查询的原子任务」而非仅轮询。
- **Agent 与 BYOVD/EDR 对抗联动**：把「检测到杀软 → 选路（驱动击杀/EDR 失明/进程注入）→ 验证是否成功」做成确定性剧本，减少模型自由发挥。

## P2 — 平台工具库与远程加载（不增植入端体积）

> **设计原则**：植入端保持「小而精」——只内置命令执行/文件/进程/注入/凭据/截屏/网络等底层原语；高阶能力（端口扫描、横向、凭据传递、内网探测）**不编译进植入端**，由服务端工具库按需远程加载执行。

### 2.1 工具库建设（前置，本会话已确认范围待开工）
- 目录按 **平台/架构** 组织：`data/tools/<os>/<arch>/<tool>`，同级 `manifest.json` 记元数据：用途、平台/arch、调用参数示例、**SHA-256**、来源出处、许可、体积、最后校验时间。
- **预置范围（已确认）**：只预置**自研脚本型工具**（纯文本、可审计、无版权/供应链风险）：端口扫描、共享枚举、内网存活探测、凭据线索收集、域信息收集等 PowerShell/Bash 脚本；
- **第三方二进制不预置**：走「按需下载 + sha256 校验 + 版本轮换」，下载源与哈希写进 manifest（agent 用 `remote_download` 拉取到服务端 `data/tools/`，再分发到会话）。
- 校验：下载后强校验 sha256（不匹配即拒绝并告警），记录来源 URL 与时间；定期轮换版本。

### 2.2 能力链（都走远程加载，不内置）
- **内网探测链**：端口扫描/主机发现/共享枚举 → 优先加载轻量扫描器跑在目标会话上；结果收敛进情报库，落成确定性 playbook。
- **横向移动**：加载成熟横向工具/载荷到会话执行；复用既有 exec 原子机制、会话忙期判活与高危审批护栏。
- **凭据利用（PTH/Kerberoast 等）**：凭据**采集**仍走植入端原生原语，**利用**工具走远程加载；纳入高危审批。
- **免杀/规避载荷远程化**：新注入方式、新载荷形态按需下发，不常驻；痕迹清理（amcache/事件日志）做成轻量命令链 playbook。
- **验收**：植入端二进制体积/功能面不随上述能力增长；agent（或一条指令）能完成「下载→校验→内存加载→执行→回传→清理」闭环；工具元数据缺失/哈希不符时明确拒绝执行。

## P3 — 平台 / 工程

- **多通道一致性**：MQTT/relay/HTTP-polling 与 TCP 的判活、忙期、任务重放语义对齐（TCP 最完整；本会话已统一判活入口 `Session.IsAlive`，其余语义仍待对齐）。
- **Release/打包**：✅ **v1.3.4 已完成**：CI 增加 `toserver -version` == tag 校验、zip 内容清单校验、`checksums.txt`（sha256，随 Release 发布；本地 `scripts/package_release.ps1` 同步生成）。待做：tag 前接 `e2e_smoke.ps1`。
- **配置热更新边界**：心跳超时等会话参数改动后对存量会话的生效时机文档化（本会话改成自适应阈值后，需说明"改动后新会话立即生效、存量会话按采样自适应"）。
- **前端**：任务列表虚拟滚动（大量任务不卡）；Sessions/仪表盘 WS 事件统一订阅组件（现在多处重复实现）；杀软对抗页信息架构继续收敛（本会话已重排 BYOVD 区块，并把驱动加载前自检结论（哈希不符/未签名/警告）直接标在按钮与提示区）。
- **可观测性**：屏幕流帧限速丢弃数、广播去抖抑制次数等运行指标暴露到界面/日志汇总（当前只在日志里；v1.3.4 已把"真正烘焙进载荷的参数"写进构建日志）。
- **服务端在线更新（自更新）**：让控制台能一键把**服务端自身**升级到新版本，不必登录主机手工替换二进制再重启。
  - **现状（手工、会断线）**：升级 = 停掉 `toserver(.exe)` → 覆盖文件 → 重新启动；期间**所有会话与 SOCKS5 隧道全断**（本开发周期里我为了验证 UI/构建参数，就手工重建并强杀重启过 4 次，每次都会把在线的植入端全部踢下线，然后等它们重连）。既没有版本检查，也没有产物校验、回滚或审计。
  - **目标**：控制台「关于/设置」提供「检查更新 → 查看版本与变更摘要 → 确认更新」，随后自动完成**下载 → 校验 → 落盘 → 原子替换 → 重启 → 自检**，整个过程有日志与状态回显；失败时必须**保持现有二进制可用**。
  - **实现要点（待定，按顺序做）**：
    1. **先做服务化/守护**（前置）：当前服务端是前台进程，替换后没人拉起。需要 `install.ps1`/`install.sh` 支持注册为 **Windows 服务 / systemd unit / 计划任务**，否则"更新完自动重启"无从谈起；
    2. **原子替换**：Windows 上无法覆盖正在运行的自映像 —— 走"下载到 `toserver.new` → 校验 → 由旁路脚本 `MoveFileEx(..., MOVEFILE_REPLACE_EXISTING)` 或 改名旧文件 + 换名 + 重启"；Unix 侧可直接 `rename`（原子）；
    3. **校验与防降级**：强制 **sha256 比对**（复用 Release 的 `checksums.txt`），可选 **Authenticode 签名校验**（复用 `builder/sign.go` 的验签能力）；拒绝从更高版本降级、拒绝摘要/签名不符；
    4. **数据安全**：更新前**自动备份 `data/toshell.db`**，并保证 schema 迁移向后兼容（新版本启动失败可回滚上一版二进制 + 数据库）；
    5. **安全边界（重要）**：服务端二进制 = 完整 C2 控制端，**更新通道被劫持等于整个 C2 被接管**。因此：默认**关闭**在线更新，需显式开启并配置**可信更新源白名单**（自建源 / GitHub Release）+ 独立更新密钥；更新动作要求二次确认并写审计日志。
  - **验收**：在测试环境从 v1.3.5 升到下一版：点「检查更新」→ 显示版本与摘要 → 确认后自动下载校验、替换、重启 → 植入端自动重连、配置与 sqlite 数据不受影响；**断网 / 摘要不符 / 签名不符时明确失败且不改变现有二进制**；保留上一版二进制可一键回滚。

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
| 本机装有 360/电脑管家/无边界安全系统，**任何新生成或未签名的 PE 一执行就被拒并删文件**（连 Hello-World Go 程序也一样，MS 签名程序正常） | **本机无法做任何"动态/行为"验证**（载荷上不了线、`go test` 的新测试二进制也被杀） | 动态验证放到干净 VM（仅 Defender）或 CI；长期解见 P0-5（代码签名 / 由已签名宿主加载） |
| Go 编译的 EXE 用 `exe_mem` 反射执行会崩宿主（双 Go runtime） | ✅ v1.3.4 已在下发前**明确拒绝**并给建议（P0-2 预检） | —— |
| `exe_mem` 下载荷自行退出会带走植入体（CRT 内部 ExitProcess） | 只对"跑完即退"的工具致命 | 仍需 P0-2 的 ExitProcess hook（下一版） |
| PPL 进程杀不掉（无具备内核读写的 `rw` 档驱动） | Defender 等 PPL 保护进程需句柄窃取 | P0-1 里补 `rw` 档驱动档案与 `purpose` 选路 |
| 一条上线命令的下载地址依赖人工配置 `public_host` | 配置错则命令不可用（已有告警与自动回退） | 可加"服务端主动探测该地址可达性"的自检（P3 可观测性一起做） |
