# 更新日志 / Changelog

本项目采用 [语义化版本](https://semver.org/lang/zh-CN/)。所有值得注意的改动都会记录在本文件。
后续优化方向（含驱动能力分档、内存执行加固、屏幕流跨平台、平台工具库与远程加载型红队能力等）见 [ROADMAP.md](ROADMAP.md)。

## [v1.4.0] - 2026-09（开发中）

当前版本。本版主题：**把 C2 从"能用"推到"能长期稳定用"** —— 开放标准 MCP 接口、Agent 长任务可靠性（异步状态机 + 状态落盘 + 大结果外置）、免杀分层治理（先解决"起不来"再谈"藏得深"）、植入端体积分档与内存加载、杀软对抗能力分级、新增低特征通道。

> 状态：**进行中**。分阶段落地，每阶段完成即本地验证；具体条目见 [ROADMAP.md](ROADMAP.md) 的「v1.4.0 迭代计划」。

### 🧩 S1 开放 MCP 服务接口 + 公共执行基础设施
- **工具元数据单源化（消除三处硬编码）**：新增 `internal/server/mcp` 包，工具定义集中在 `registry_tools.go`（**38 个工具**：37 个原工具 + 新增回读元工具 `result_read`），每个工具带**类型化参数**与 **JSON Schema**，并按风险分为 **read 13 / confirm 14 / danger 11**。REST `GET /api/v1/mcp/tools`、内置 AI 的 function schema、对外 MCP 的 `tools/list` **三处同源**；此前它们是三份各自维护的清单（`handlers_mcp.go` 的 `mcpToolList`、`copilot.go` 的 33 条 schema、命令映射），已删掉其中两份重复数据。
- **参数与描述纠正**（都是"代码早就这么读、清单没写对"）：`task_id`/`pid`/`local_port`/`timeout_sec` 由 string 改为 **integer**；补上一直被漏掉的 `timeout_sec`（exec/内置命令）、`fileless_exec` 的 `wait_ms` 与 `entry`；`session_ids` 改为 **array**；`exec.kind` 枚举剔除实际不存在的 `process_list`；`intel_query.kind` 补上真实入库的 `hash_sha1`/`url`；把旧描述里"结果通过 task_wait 获取"（其实早已原子化直接返回）等过期说法改正。
- **统一结果信封 + 大结果外置**（`envelope.go`/`resultstore.go`）：所有工具返回 `{status,data,error,meta}`，`meta` 带 `call_id`/`truncated`/`truncation_note`/`total_bytes`/`returned_bytes`/`handle`/`untrusted`；**超出内联上限的结果外置落盘**（`data/mcp-results/<日期>/<hex>`）并只回摘要 + 句柄，模型/客户端可用 `result_read`（`handle`+`offset`/`limit`）分页取回。**截断一律显式标注**——旧实现是静默 `truncateStr`，模型会把"部分"当"全部"；句柄做了严格白名单与目录逃逸双重校验（防路径穿越）。
- **安全默认值修正（两个真实缺陷）**：
  1. `internal/server/ai/copilot.go` 的审批判定 `isRiskyTool()` 原是**允许列表 + fail-open**（未登记的工具默认免审批），且**未包含 `delegate`** —— 于是"需用户同意"模式可以被 `delegate`（内部会提交任务、跑含 `credentials` 的剧本）整个绕过。现改为**默认危险、只有只读白名单免审批**，并直接以工具注册表的等级为准；未登记的工具一律按危险处理。
  2. `handlers_mcp.go` 的 `plugin_upload`/`fileless_exec` 直接 `filepath.Join("data","tools", src)` 后 `os.ReadFile`，`src` 来自 LLM/外部调用 → **路径穿越可读任意文件并入库/送去执行**。新增 `resolveToolPath()`：拒绝对路径/盘符/`..` 逃逸，拼接后 `Abs` 与 `EvalSymlinks` 双重确认仍在 `data/tools` 内。
- **对外 MCP 服务端**：新增配置段（`mcp.*`，默认 `enabled: false`、只绑回环、必须有 token、默认只放行只读工具），配置样例与 `release/configs` 同步更新；**设置页可直接改**（`GET/PUT /api/v1/settings` 的新 `mcp` 段，token 只写不回显：空串=保持、`clear`=清空；白名单里的工具名会逐个校验是否登记在案，写错直接 400）。服务端启动日志会打印 bind、放行工具数与三道闸参数；关闭服务端时优雅停掉 MCP 监听。
- **本地端到端冒烟 `scripts/mcp_smoke.ps1`**：不需要任何植入端，起一个临时服务端（独立端口 + 独立 token + 只读白名单 + 低 RPM），跑 15 项权限/协议矩阵——无 token/错 token 401、initialize 下发会话、缺/错会话头 400、tools/list 工具数、只读工具可调用且带统一信封、危险工具默认 403、未注册工具 403、resources/list、**resources/read 路径穿越被拒**、超 RPM 429、审计落盘；有 ❌ 即非 0 退出。**当前实测 15/15 通过**。
- **CI**：单元测试范围增加 `./internal/server/mcp/...` 与 `./internal/server/ai/...`（注册表形状与分级 fail-closed、信封与截断标注、结果外置句柄与路径穿越拒绝、Agent 工具面必须都能在注册表找到、`delegate` 越权回归）。

### 🤖 S2 内置 Agent：长任务可靠性

**目标**：把「单轮同步阻塞 + 状态全在内存 + 长结果整段灌上下文」换成可恢复、有预算、可回放的长任务执行。

- **离线评估门禁：黄金集 + 桩 LLM（本版核心增量）**
  - **解决什么**：Agent 的行为（工具序列、何时停、为什么停、上下文里留下什么）此前**没有任何回归保护**——改一行循环逻辑只能靠真机人工试。现在把这些固化成**可执行用例**：`internal/server/ai/testdata/golden/cases.json` **12 例**，每例声明"输入 → 期望工具序列 → 期望终态/`stop_reason` → 期望答复要点 → 期望上下文痕迹"，用**桩 LLM（httptest SSE，按脚本逐轮应答）+ 进程内假工具执行器**驱动真实 `RunAgent`：**不联网、不需要真实模型、不需要植入端**，因此本机与 CI 都确定可复现。
  - **覆盖**：纯问答收尾 / 单工具往返 / 防死循环（第 3 次调用前停止，轨迹只有 2 条）/ **只读工具重复豁免** / 轮次与工具调用数两处预算 / **token 预算（装配即超预算时一次 LLM 请求都不发）** / 分级审批挂起（含 **`delegate` 不能绕过**与**未注册工具 fail-closed**）/ 大结果外置成句柄且上下文不留原文 / **按句柄 `result_read` 回读**（脚本用 `$LAST_HANDLE` 从上下文现取句柄）/ **历史折叠保留真实工具名与「非原文」标注**。
  - **全局不变量**：任何一次发往上游的消息序列里，`tool` 回执都必须能配到 `assistant.tool_calls`（配对断了上游会直接拒绝，而压缩/折叠最容易在这里出事）——对每个用例的每一轮请求都校验。
  - **一键跑**：`scripts/eval.ps1`（退出码可直接接进门禁）；随 `./internal/server/ai/...` 进 CI（无需改 CI 配置）。加用例只需改 JSON，不用写 Go。

- **上下文四层装配 + token 双预算（本版核心增量）**
  - **常驻层逐字节稳定（前缀缓存终于能命中）**：旧实现把**每轮都变的在线会话清单**拼进 system prompt，而且 `currentSessions()` 内部**又真的调一次 `session_list` 工具**（一次未审计的调用 + 缓存前缀每轮失效）。现在常驻层只含不变的方法论；在线会话快照移到**任务层**，并按 **run + 5 分钟 TTL 缓存**（模型随时可自己复查 `session_list`，而快照晚 5 分钟几乎不影响决策）。分层与装配抽成纯函数 `AssembleContext`/`CompressMessages`（新文件 `ai/context.go`），同步与异步两条路径共用同一套实现。
  - **四层与折叠保真**：常驻 / 任务 / 工作（最近 N 条原文，默认 14） / 历史（更早折叠成摘要）。折叠摘要现在**保留真实工具名**（旧实现把工具名写死成 `task_wait`，模型会误判自己做过什么）、保留**外置句柄与截断标注**（识别结果信封），并显式标注「历史摘要-非原文」；同时保证 `assistant.tool_calls` 与配对的 `tool` 消息不被拆散（否则上游 chat/completions 直接拒绝）。
  - **token 预算（两道）**：`ai.max_context_tokens`（单次请求上下文预算，默认 **32000**）与 `ai.max_run_tokens`（一次 run 累计预算，默认 **400000**≈20 轮），外加 `ai.context_working_keep`（默认 14）。估算用**字符近似**（中文 1 token/字、其余 4 字符/token，不引入 tiktoken/词表依赖）并留 **30% 安全余量**；同时**解析 LLM 响应的 `usage`**（旧实现完全没解析）做**校准回填**，避免估算长期漂移。超预算两段式：先做更激进的分层压缩（缩减工作层、大结果换成句柄说明）→ 压到极限仍超才停止，并把 `stop_reason` 记为 **`max_tokens`**，照常产出"因预算耗尽而停止"的最终回复（附上下文用量、触发阈值、压缩情况），不静默中断。设置页可改三个值并回传**生效值**。
  - **可观测性**：run 查询新增可选字段 `context_tokens`/`context_budget_tokens`/`context_compressed`/`token_usage_estimated`/`token_usage_total`/`token_calibration_factor`（既有字段名未动）。
  - **验证**：`go test ./...` 全绿（13 个包）；`scripts/mcp_smoke.ps1` **18/18**（对外契约未变）；**真实服务端 + mock LLM 端到端**：把 `max_context_tokens` 压到下限 1000 → run 立刻以 `stop_reason=max_tokens` 收尾，回复里写明"估算 3361 token / 预算 1000（含 30% 余量，阈值 770）"且"工作层已压到 1 条"，即先压缩后停止两段都被实际触发；把预算恢复正常（32000）后重跑三档循环回归：`loop_detected` / `awaiting_consent` / `max_turns` 全部符合预期。
- **SSE 断点续传 + 显式缺口告知（S2 可观测性收尾）**
  - **每个 run 事件带 `id: <seq>`**（run 内单调递增，从 1 起）；`status`/`state`/`resync` 这类**控制帧刻意不带 id** —— 带上会把客户端续传水位线推到一个"没有对应事件"的位置，重连反而漏事件。连接建立即下发 `retry: 3000`，空闲每 15s 发 `:\n\n` 心跳注释帧（不是事件、不占 seq、不进缓冲，用于防中间代理掐连接）。
  - **重连恰好补齐缺口**：`Last-Event-ID` 头优先，浏览器 `EventSource` 设不了头时用 `?last_event_id=<seq>`（`0` = 要缓冲全部）。交接算法是"**先订阅 live 通道、再在同一把锁下取快照**，回放 `(L, Head]` 后按 `seq ≤ lastSent` 去重切实时"—— 先回放后订阅的话，回放期间的事件只能指望"通道缓冲恰好装得下"，满了就是静默缺口。
  - **`resync` 显式告知两类缺口**（新增可选事件，老客户端忽略）：`events_expired`（水位线早于缓冲最旧事件，缓冲 512 条 / 2 MiB 双上限）与 `events_dropped`（运行期事件通道满丢过事件，被丢事件**不占 seq**，缺口用 `dropped_after/dropped_count` 表达）。两者都提示客户端改用 `GET /agent/runs/{id}` 重建视图，而不是让流"看起来完整"。
  - **兼容性**：`thinking`/`message`/`final` 的载荷**仍是 JSON 字符串**（包成对象会打断前端 `typeof data === 'string'` 的正文累加），只对对象载荷注入 `seq/run_id/ts`；老前端不认新字段也不会坏（只享受不到续传）。
  - **前端已接入续传**（`web/src/api/index.ts` 的 `streamAgent`）：解析并保存每个事件的 `id:`，断线后按服务端下发的 `retry:` 间隔自动重连并带 `Last-Event-ID`（最多 8 次，之后交给 2s 轮询兜底），`shouldContinue` 保证用户切到别的 run 后旧连接不再重连；`resync` 会在对话页顶部显式提示「事件流缺口…过程以轮询结果为准」并立刻重取一次 run 详情（**不静默吞掉** —— 否则用户会把"缺一段过程"误当成 agent 真的没做那些事）。
  - **验证**：`go test ./...` 全绿（13 个包，新增 20 个用例：环形缓冲/载荷注入/并发 seq 顺序/交接竞态/过期与丢弃 resync/终态晚订阅上限/心跳不是事件）；交接竞态用例 `-count=5` 无抖动；`scripts/mcp_smoke.ps1` **18/18**；**真实服务端 HTTP 实测**：终态 run 的连接先发 `retry: 3000`，run 事件带 `id: 1..N` 且回放缓冲；带 `Last-Event-ID: 3` 或 `?last_event_id=3` 时**首条即为 `id: 4`** 且流短 3 条事件（协议与前端假设一致）。**未验证**：本机 `go test -race` 不支持 windows/386（改用"通道到达顺序 == seq 顺序且无丢失"的并发用例替代）；真实浏览器 EventSource 端到端未做（前端为 fetch 实现，`tsc -b` + `npm run build` 通过）。
- **异步任务状态机：提交 → 句柄 → 事件驱动恢复（本版核心增量）**
  - **彻底去掉 sleep 轮询**：`task.Manager` 新增终结通知原语（`Subscribe`/`WaitSettled`/`WaiterCount`，注册与状态判定共用一把锁，避免"判定非终态→此刻终结→永远收不到通知"的丢通知窗口；通道一次性关闭、等待者摘除不留泄漏），通知挂在**真正的状态变更点**（Complete/Fail/Cancel/Delete/CleanupOldTasks）。`pushAndAwait`/`task_wait`/`execAndAwait` 与剧本的 `waitForTask` 全部改为等待通知：一次 300s 下载不再空转 600 次、每个等待者少掉最多 500ms 固定延迟。**对外契约逐字段不变**（超时仍表示"仍在跑"、错误码与响应字段名全等，有测试断言 key 集合）。
  - **Agent 长任务不再占满并发槽位**：预估超时 ≥ `ai.long_task_threshold_sec`（默认 **150s**）的任务类工具改为「提交任务 → run 进入 `awaiting_task` 并落库 `waiting_on` → 退出循环（**释放 agent_concurrency 槽位**）→ 任务完成事件唤醒 → 结果接回上下文与轨迹 → 重入循环」。判定是纯函数 `ShouldSuspendLongTask`（含 `NeverSuspend` 运维开关；阈值 ≤0 回落默认，不允许用它关掉）。恢复复用既有的**审批挂起**模式（同一套"消息在 run 里 + 恢复即重入循环 + trace 不变"），两套状态一条恢复路径。
  - **重启恢复**：启动时扫描 `agent_runs.status=awaiting_task`，按 `waiting_on.internal_task_id` 与 `tasks` 表对账 —— 已完成→重建 run（复用 run_id/trace_id）+ 最小上下文 + 接回结果并继续；仍在跑→重新订阅等它完成；任务已丢失/`waiting_on` 不可解析→**明确终态**（`failed` + `task_lost`/`waiting_on_unparsable`）+ 中文说明，绝不静默卡在等待态。`task.Manager` 顺带修掉一个既有缺陷：Complete/Fail 原先要求任务在内存里，**重启前下发的任务结果永远丢失**，现在会从库回填。
  - **可观测性**：新状态 `awaiting_task`，新 SSE 事件 `task_wait`（含 task_id/correlation_id/timeout_sec/trace_id）；`GET /agent/runs/{id}` 回传 `waiting_on`/`task_id`/`task_timeout_sec`；挂起的 run 不再被"终态后 30 分钟清理"回收；`GET /settings` 回传生效阈值。
  - **顺手修掉的接线漏点**：`ReconfigureCopilot` 的重建分支只重注入结果外置存储、**漏了长任务通道** → "AI 原本未启用、之后在设置页启用"这条路径上造出来的 Copilot 没有长任务能力，所有工具静默退回同步等待（无任何报错，只有重启才恢复）。现已同时注入，并用 `LongTaskEnabled()` + `TestReconfigureCopilotReinjectsLongTask` 钉住。
  - **验证**：`go test ./...` 全绿（13 个包，本增量新增 37 个用例，含新的 `task` 包）；`scripts/mcp_smoke.ps1` **18/18**；`scripts/e2e_smoke.ps1` **19 项 0 失败**（其中"真实植入端上线 + whoami 任务 completed"证明改造后的事件驱动等待在真实植入端上工作正常）；另补一条**收益断言**用例 `TestSuspendedLongTaskReleasesAgentSlot`（并发上限压到 1：挂起后槽位必须立刻可再获取，且第二个 run 能同样挂起）—— 防止将来把挂起实现成"在循环里等事件"而用例照样全绿。
  - **已知边界（如实记录）**：`database.truncateTaskContent` 仍把 `tasks.output` 截到 500 字节 → 重启恢复拿到的结果最多 500 字节（已在给模型的说明里显式标注）；挂起期间的 `max_wallclock_sec`/`max_turns` 预算会重置（沿用审批恢复的既有行为，理论上可被多次挂起绕过墙钟上限，后续应把用量接到 `agent_runs` 已有字段）；阈值目前只在 YAML/viper 可配（GET 已回传生效值，未加入设置页 PUT 白名单）；旧前端不认识 `awaiting_task` 与新事件 `task_wait`（走 default 忽略，不影响既有功能）；新用例未跑 `-race`（本机 CGO_ENABLED=0，Windows 上 race 需要 cgo）。

- **长结果外置 + 句柄内联 + 分页回读（本版核心增量，完整设计见 [docs/AGENT-RESULT-OFFLOAD.md](docs/AGENT-RESULT-OFFLOAD.md)）**
  - **唯一转换点**：新增 `mcp.InlineForModel`/`mcp.ModelView`（放在 `mcp` 包：外置信封、句柄、分页语义本就在那里，且 `mcp` 不依赖 `ai`/`api`/`config`，三个消费方都能复用同一把尺子）。两个 ReAct 循环 + 两条审批恢复路径**全部**改走它，**删掉 8 处 `truncate(out, 4000)` 字符串硬截断**。
  - **判定**：≤ `mcp.inline_limit`（默认 8192 字节）→ 原文；超限且外置成功 → 模型只看到**统一信封 JSON（摘要 + 句柄 + 总字节 + 显式截断说明）**；外置失败/未配置存储 → 信封里放**开头预览**（作为 JSON 字符串字段转义，因此**恒为合法 JSON**）+ 说明"这不是全部、没有句柄可回读"。硬性质：**凡被截断，模型拿到的一定是合法 JSON 且必带显式标注**。
  - **回读闭环**：`result_read` 此前**只登记在注册表里 —— `invokeTool` 没有实现、`agentToolNames` 也没有它**，等于"外置=丢结果"。现已实现（含 `slice`/`tail` 两种模式、页大小自适应收缩到内联上限以内以免"句柄套句柄"自锁、`has_more`/`next_offset` 游标）并加入 Agent 工具面（LevelRead 免审批）。存储与 `mcp.enabled` **解耦**（默认关闭 MCP 也能用），并补了 api 侧 30 分钟 GC；`agentstore.tool_results` 索引已接线（句柄/sha256/字节数/TTL，写失败只告警）。
  - **修掉"截图 base64 被截断成非法 JSON"**：根因在**服务端**（`pushAndAwait` 的 `truncateStr(t.Output, 8000)`、`task_result`/`task_wait` 的 4000、copilot 的 4000 三处把内层 JSON 切在中间），植入端返回的一直是完整 JSON——**故未改植入端模板**（`release/implant` 与 `internal/server/builder/implant` 61 个文件已 SHA-256 逐一核对一致）。任务输出改为 `taskOutput()` + `output_bytes` 显式标注。
  - **顺手修掉的既有 bug**：工具参数以 `map[string]string` 反序列化会**静默丢弃 integer 参数**（`offset`/`limit`/`pid`/`task_id`/`timeout_sec`/`wait_ms`/`local_port`），这正是"回读翻不动页"的原因（`json.Unmarshal` 的类型错误被 `_ =` 丢弃、字段直接消失）。新增 `ai.toolArgs`（口径对齐 `mcp.buildArgs`），两处解析点统一改走它。
  - **前端可见**：`ToolTrace` 与 SSE `tool_result` 事件新增 `handle`/`truncated`/`truncation_note`/`total_bytes` 四个**可选**字段（既有字段名一个没动，老前端忽略即可）。

- **状态落盘：4 张新表 + 专用存储层**（`internal/server/database/agent_schema.go`、新包 `internal/server/agentstore`）
  - `agent_runs`（run 级状态机与预算：status/stop_reason/**waiting_on**/三处上限/token 用量/trace_id）、
    `agent_steps`（步骤级 checkpoint：`UNIQUE(run_id, step_no)` 作恢复游标、每步指标、压缩摘要）、
    `agent_tool_calls`（工具调用：**correlation_id 幂等**、审批结论、内部 task id、attempt）、
    `tool_results`（结果外置索引：句柄、sha256、**截断显式标注**、TTL、redacted）。
  - 全部 `CREATE TABLE/INDEX IF NOT EXISTS`：**对既有库幂等**，不动既有表、无破坏性 DDL，回滚只是多几张没人查的空表；DDL 抽成导出的 `AgentSchemaStatements`，让存储层的测试与生产共用同一份定义（schema 不会漂移）。
  - 存储层提供：run 的 upsert/状态机推进/用量累加/可恢复列表、step 的 next-cursor 与幂等 append、tool_call 的幂等 upsert 与待决列表、result 的索引与 TTL 清理（清理时回传外置文件路径供调用方删除）、以及 **`CountArgsHash`（同工具同参数计数，供防死循环）**。
- **修掉「重启后任务 id 撞号」**：任务 id 来自内存 atomic 计数器（`task/task.go`），进程重启即归零 → 新任务会与 `tasks` 表里的历史任务撞号（按 id 查任务会串到旧记录）。新增 `Manager.SeedTaskCounter()`，启动时用 `MAX(tasks.id)` 校准（只在更大方向抬升、CAS 幂等），`cmd/server` 在数据库就绪后调用并写日志。
- **控制循环三处硬上限**（`ai.max_turns` 统一为 **20**、新增 `ai.max_tool_calls=40`、`ai.max_wallclock_sec=900`）：循环内每轮检查，任一触发立刻停止并记 `stop_reason`（`max_turns` / `max_tool_calls` / `max_wallclock`），同时写含 trace id 的告警日志；**设置页可改**（区间校验：轮次/工具调用 1~1000、墙钟 30~86400 秒，越界 400 —— 上限只在"有效值"上生效，0/负数不会变成"不设限"）。
- **防死循环**：以「工具名 + 规范化参数 JSON」的 sha256 前 16 位作签名，在一次 run 内计数——**第 2 次**出现同签名时在结果后追加"同工具同参数已重复，请换策略或收尾"的系统提示，**第 3 次**停止循环并记 `stop_reason=loop_detected`（明确告知是哪把工具、什么参数）。**只读工具豁免**（重复查一次会话列表是正常的），理由写在注释里。
- **分级审批**（取代原来的二元 `auto/normal`）：新增 `ai.consent_policy`，取值 `graded`（默认：只读免审、confirm/danger 需同意）、`all`（全都要问）、`off`（不询问，危险）；**旧值兼容** `auto→off`、`normal→graded`，无法识别的值按 `graded` 处理并告警。等级判定统一走工具注册表（`mcp.Default().LevelOf`），**未注册工具按 danger**，`delegate` 恒按危险处理（v1.3.5 的绕过点）。挂起等待审批时 `status=awaiting_consent` 且 `stop_reason=awaiting_consent`（脚本轮询只看 reason 也能区分"在等人"与"失败"）。**接口回传的是"生效策略"**（`EffectiveConsentPolicy`：空配置→graded、旧键 auto/normal→off/graded，与循环里的判定是同一个函数），设置页与副驾驶页都改为编辑/显示新键，保存时把旧键按同一语义同步写回（off→auto，其余→normal），避免新旧两键在配置文件里互相矛盾。
- **trace id 全链路**：每次 run 生成 `trace_id`，贯穿 run 结构、SSE 事件（`ToolStart`/`ToolResult`/`TraceInfo`/`DoneInfo`）、**HTTP 响应**（`POST /agent/chat` 新建/续接、`GET /agent/runs/{id}`、`/copilot/chat`、`/copilot/consent`）与相关日志；新增字段对老前端是可选忽略项，不改既有字段名。
- **设置页新增「MCP 服务端」配置段**（集成与通知分页）：安全前提警告（与内置 AI 共享同一张工具表、默认关闭/只绑回环/必须配 token/白名单留空只放行只读）、`bind`/`token`（三态：留空=保持、`clear`=清空、其它=覆盖）/`allowed_tools`(CSV)/`allowed_origins`/`allow_cidrs`/`max_rpm`/`max_concurrent`/`max_pending_handles`/`inline_limit`/`result_dir`/`result_ttl`/`audit_path`/`fail_closed`，并显示"实际生效 N 个（留空即只读集合）"与 read/confirm/danger 三档数量；**CSV⇄字符串数组只有一个转换点**（`mcpCsvToArray`/`mcpArrayToCsv`，留空 → `[]` 绝不产生 `[""]`），提交前做与后端同口径的预校验（不通就不发 PUT），并提示"MCP 改动需重启生效"。
- **验证**：`go build ./...` / `go vet`(ai,config,api) / `tsc -b` / `npm run build` 全绿；**设置页 API 端到端实测**——`GET /settings` 的 `ai` 段已暴露三个新键、`PUT` 非法值（`consent_policy=nonsense`、`consent_mode=weird`、`max_tool_calls=0`、`max_turns=0`、`max_wallclock_sec=10`）均 400 且不改动已存配置、旧值 `AUTO` 被规范化为 `off` 且落盘为 `consent_policy: off` + `consent_mode: auto`；`scripts/mcp_smoke.ps1` 回归 **18/18**。
- **控制循环的真实行为验证**（本地 mock LLM 假服务 + 隔离配置/DB 起真实服务端，`/agent/chat` → 轮询 `/agent/runs/{id}`）：
  - `max_turns=3` 时 3 次工具调用后停止，`stop_reason=max_turns`，最终回复给出"已达轮次上限（3 轮，实际 3 轮）"——顺带修掉收尾统计漏传 `Turns` 导致恒显示"实际 0 轮"的 bug。
  - 同一只读工具（`session_list`）重复调用 3 次**不**触发防死循环（豁免生效）；同一 confirm 级工具（`user_info`）同参数：第 1 次执行、第 2 次执行并追加 `loop_warn` 提示、**第 3 次在调用前停止**，`stop_reason=loop_detected`，timeline 里记明是哪只工具与参数。
  - `consent_policy=graded` 下 confirm 级工具在**执行前**挂起（`status/stop_reason=awaiting_consent`，`traces=0`，未下发命令），deny 后恢复并记录"已跳过"轨迹；`off` 下不再询问。
- **长结果外置的端到端验证**（同一套本地沙箱：真实服务端 + mock LLM 假服务；45 个假工具文件把 `tool_list` 撑到 **11814 字节**）：
  - 模型可见文本变成 **535 字节的合法 JSON 信封**（`truncated=true` + `handle` + `total_bytes=11814`），上下文里**不再出现原始正文**；
  - 假模型从上一轮 tool 消息里现取句柄调 `result_read(mode=tail)` → 回读 2000 字节、响应 2407 字节（未超 8192，不会"句柄套句柄"），**与磁盘外置文件逐字节一致**；
  - 改完这一层后重跑三档循环回归：`loop_detected`（第 3 次调用前停止，轨迹 2 条）/ `awaiting_consent` / `max_turns` 全部符合预期。
- **工程质量（本机杀软关闭后首次跑全量单测暴露出来的问题，已修）**：
  - `agentstore` 的 6 个用例本身全绿，但在 Windows 上因**临时 sqlite 没关**导致 `t.TempDir` 清理失败（`unlinkat ... being used by another process`），整体判 FAIL；`newTestStore`/`TestMaxTaskID`/`TestSchemaCreatesAgentTables` 全部补 `t.Cleanup(Close)`。
  - `internal/server/api` 有 **4 个用例长期红着却没人发现**：`TestLoaderChainVariantsCoverage`/`TestLoaderChainHasNoBundledThirdParty` 挂在测试助手 `decodeEncCommand` 上——它取**最后一个** `-enc ` 去 Base64 解码，而 mshta 骨架里是 `-enc <注入器Base64>` 这种**占位符**，必然解码失败；改为扫描全部 `-enc ` 片段、只展开能成功解码的，占位符原样保留。`TestLoaderAdvice/windows_shellcode_未签名` 要求 tips 里出现"内存加载"，而文案写的是"注入当前 powershell.exe"，已把该条改成明确说"只走内存加载"（与项目既有词汇一致）。
  - **CI 测试范围补上 `api`/`auth`/`session`/`webhook`/`avdetect`**：此前 `./internal/server/api/...` 根本不在 CI 里，而本机又被杀软拦着跑不了 → 上面 4 个红灯得以"存活"很久。这类"没人跑"的包从此纳入门禁。
- **本地单测门禁恢复**：关闭 360 后本机可执行测试 PE，`go test ./...` 已跑通（除本轮在做的 S2 增量外全绿）：`common/crypto`、`server/{agentstore,auth,avdetect,builder,config,drivers,mcp,session,webhook}` 全 ok。
- **仍未做**（S2 剩余）：异步任务状态机（工具调用改成"提交 → 句柄 → 事件驱动恢复"）、上下文四层与 token 预算、SSE `id`/`Last-Event-ID` 断点续传、评估门禁；`ai/playbook.go` 的步骤输出仍是字符串硬截断（会动到剧本 API 字段语义，留给下一增量）。

### 🥷 S3 免杀：分层治理（落地 / 动态 / 静态）

- **修掉字符串混淆的两处盲区 + DLL 路径漏做的静态降特征**（本次实测发现，见 `docs/EVASION.md` §2.3 的前后对照表）
  - **DLL 路径漏了两道工序**：`compileLibrary()` 只做 `copyImplantSource` + `processTemplates`，**没做** `injectBuildConstants`（每构建随机配置块魔数/密钥）与 `obfuscateImplantSources`（字符串混淆）—— 而 exe 路径一直都有。白加黑链交付的正是 DLL，等于把 C2 地址、持久化注册表键、ETW/注入 API 名**明文**交出去。实测（windows/386）：**明文高信号 API 名 11 处、`http://` 2 处、ETW 4 处、注册表键 3 处**；补齐两道工序后降到与 exe 同水平（只剩 Go 标准库自带的各 1 处）。
  - **混淆器盲区**：此前只处理"简单双引号字面量"，于是 ① 含转义的字面量（`"\\\\.\\kgameprotect"`、`"HKCU\\Software\\..."` —— Windows 路径/设备名在 Go 里的**标准写法**）被跳过；② **全部反引号原始字符串**被跳过（旧理由只有"struct tag 不能改"，却把注册表键与脚本模板一并放行）。修法：转义字面量用 `strconv.Unquote` 取运行期真实值再 XOR+hex（`xd()` 是纯字节解码，`\r\n`/NUL/非 UTF-8 都能原样还原）；原始字符串改为"**非 struct tag、非 const 行、≥4 字节**就混淆"，struct tag 与 const 行仍原样保留（后者是因为 `xd()` 是函数调用，放进常量声明会编译失败）。
  - **代价（如实记录）**：明文换两倍长 hex，产物变大 —— exe 3456757 → 3467509（**+0.3%**），DLL 3414528 → 3511296（**+2.8%**，因为 DLL 此前完全没混淆）；仍远低于 S4 的体积目标。
  - **验证**：新增 `implant_obfuscate_test.go`（三类字面量各自"该混淆的要混淆、还原值逐字节一致"，struct tag/const/注释/短串/已混淆的不误伤，且**幂等**）；`scripts/e2e_smoke.ps1` 用混淆后的模板**真实构建并执行** Windows 载荷（19 项 0 失败、会话上线 + `whoami` 回执正常），证明混淆没破坏路径/格式串/脚本模板的运行期语义。
- **签名顺序约束（防"白签"，计划 §3 D3）**：新增 `internal/server/builder/finalize_order.go` —— 把"字节加工顺序"写成**唯一一份可断言的契约**（步骤名常量 + 纯函数 `finalizeSteps` + 守卫 `signOrderWarning`），每次构建打一行 `交付流水线（…签名必须是最后一步）：…`，顺序被改坏（签名之后仍有改字节的步骤）立即打 **error** 日志并点名违规步骤。动机：签名复核发生在签名之后、后处理之前，**白签从接口上看仍是 `signed=true`**，只能靠顺序约束 + 日志留痕。新增 PE 资源/图标/版本信息/时间戳类步骤时必须插在 `upx` 与 `sign` 之前，`finalize_order_test.go` 的表驱动用例（平台 × 格式 × 开关）会拦住"sign 不在最后"的改动。
- **确认时间戳真的传给了签名命令**（计划里唯一一处"待确认"）：`signWithSigntool` 用 `/tr <url> /td sha256`、PowerShell 路径走 `-TimestampServer`，两条路径都在；同时把"启用真实证书必须开时间戳，否则证书过期后签名一次性全废"写进 `docs/EVASION.md`。
- **修掉 Go 构建指纹的版本串漏点（实测发现，exe 与 dll 都有）**：构建 `windows/386` 产物后逐字节计数，`format=exe` 与 `format=dll` **都残留 1 次 `go1.20.14`**。原因不是"没擦"，而是**擦的范围不够**：既有擦除的版本窗口是**锚在 buildinfo 魔数之后 512 字节**里的（dll 路径在 `dll.go` 里也已做过这层锚定擦除，所以两种产物的魔数与 `Go build ID:` 本来就是 0），而 `runtime.buildVersion` 那份版本串（`runtime.Version()` 读的）落在**别处的只读数据段**，锚定窗口永远扫不到。新增 `ScrubGoVersionStrings`（全文件扫描，匹配规则与窗口版**完全一致**：`go1.` 必须紧跟数字、回退收尾点号，只清零、长度不变），exe 路径（`compile()`）与 dll 路径（`compileLibrary()`）各接一遍，都排在 UPX 与签名之前。**修复后两种产物的三项标记（魔数 / Go build ID / `go1.x`）全部为 0，且产物字节数完全不变**（exe 3456757、dll 3414528）。安全性已核对：植入端模板不引用 `runtime.Version()`/`Debug.ReadBuildInfo()`，清零只影响运行时崩溃/诊断输出里的版本信息。
- 文档：`docs/EVASION.md` 新增 §2.4「签名顺序约束（防白签）」，§2.3 补上版本串漏点的实测前后对照表，自查口径加上 `go1.x` 版本串。

### 📦 S4 植入端体积分档与内存加载

- **会话能力位图（前置阻塞项，已修）**：`/sessions/{id}/capabilities` 的注释写着"按 OS + 通道 + 档案推导"，实现却**只按 OS** —— 用 `light` 档构建的载荷，控制台照样点亮注入/截图/凭据/EDR/BYOVD 面板，点下去只得到"未包含在精简构建中"，操作员会误以为是自己环境的问题。现在改成"**载荷自报优先、老载荷按 OS 兜底**"：
  - 新增 `internal/common/features`：把"档案 + 通道 + BOF/侦察开关 + OS/arch"→ 能力集合的推导做成**唯一一份纯函数**（构建侧烘位图、服务端展示共用同一份判定），并带 `Tabs()`（面板 ← 支撑能力，前端契约的 `tabs` 键名不变）、位掩码 `Bitmask/Decode`、`Resolve(reported, os)`（**上报优先，缺省按 OS 兜底**，并返回 `source: reported|os_fallback`）；未知档案 **fail-closed 归入 light**（宁可少功能也不撒谎，且与 `buildTagList` 的实际编译结果一致）。
  - 构建侧：把能力位图编码成 `cap:v1:<hex>` 令牌，随 `injectBuildConstants` 一起烘进模板源码（**并且照旧走字符串混淆**，不给静态特征添新明文），植入端运行时解出。
  - 植入端：注册与心跳把该令牌放进**已有的** `Modules []string`（不新增协议字段），四条传输路径（http 轮询 / tcp / relay / mqtt）一致；服务端 `listener` 侧新增 `heartbeat_modules.go` 把心跳 `Modules` 落到会话 `ActiveModules`。
  - **老载荷兼容**：`ActiveModules` 为空时沿用旧口径（按 OS 推导），但响应里带 `source: "os_fallback"` + `source_note` 明确"这是兜底推导、未必等于载荷真实能力"——不把兜底当事实。
  - **验证**：`go test ./...` → **15 个包全 ok**（新增 `internal/common/features` 与 `internal/server/listener` 两个测试包，含"位表只增不改且唯一、未知档案 fail-closed、令牌烘焙后仍被混淆、心跳携带令牌、上报优先/老载荷兜底"等 15 个用例）；`scripts/mcp_smoke.ps1` **18/18**；**真实载荷端到端**（本地沙箱：构建 → 执行 → 等上线 → 查能力接口）：
    - `profile=light` → `source=reported`、**features 11 条**（command/file_list/.../av_detect）、`tabs` 只有 av/files/info/process/shell，**注入/截图/凭据/EDR/BYOVD/BOF 全部不在**
    - `profile=full` → `source=reported`、**features 31 条**，注入/截图/凭据/EDR/BYOVD/插件面板按实际编译结果点亮
  - CI 门禁补上 `./internal/server/listener/...`（新测试包不能只在本机跑）。

### 🛰 S5 新增低特征通道
- （待填）

### 🛡 S6 杀软对抗能力分级
- （待填）

### 🩹 其它

- **修掉"恢复过的 run 事件缓冲缩水"**：`AgentManager.NewRun` 的事件通道是 8192，而 `ResetForResume`（审批/长任务挂起后恢复、续接指令走的路径）单独写死 **256** —— 恢复后的 run 事件缓冲只有新 run 的 1/32，一旦 thinking/message 事件密集，最先被丢的恰恰是 `final`/`done` 这类**终态事件**，前端表现为收不到最终答复（network error）。现收敛成唯一常量 `agentEventBuffer=8192`，并加 `TestResumeKeepsEventBufferSize` 钉住"两侧容量必须一致"。顺带把 HEAD 上本就没过 gofmt 的 `internal/server/ai/playbook.go` 格式化干净。
- **会话不存在返回 404 而不是 500（e2e 冒烟长期挂着的观察项，已全量铺开）**：`task.Manager.Create` 在会话不存在时返回 `session not found: <id>`，而 handler 一律当 500 返回 —— **客户端输入错误被报成服务端故障**：调用方会重试而不是修正会话 id，监控也会把它计入服务端错误率（掩盖真问题）。新增 `internal/server/api/handlers_session_guard.go` 作为这一约定的唯一出处（会话不存在→404 `session_not_found`、listener 未就绪→503 `listener_unavailable`、其余框架错误→保持 500），提供 `requireSession`/`requireSessionFromPath`/`requireListener` 三个薄封装。
  - **17 处下发类 handler 全部改走 helper**：files（list/download/delete）、processes（list/kill/bof）、screenshot、credentials、fileless-exec、edr（blind/kill/byovd load/unload/kill/ppl_kill）、relay、screen-stream、persistence 与 injection（execute/spawn）、privesc（UAC，本身已有 404 只改 listener 档）。真实服务端实测 7 条代表性路由（files/screenshot/credentials/relay/edr-blind/screen-stream/fileless-exec）在会话不存在时**全部 404**。
  - **防回归**：`handlers_session_guard_scan_test.go` 用**源码扫描**把这一类错误码钉住（出现 `Listener not available` + 500、或 `session not found` + 500 即失败，并提示改用哪个 helper）—— 已用"临时插入违规代码→用例确实红→删除后转绿"验证守卫真的会响。行为用例只能覆盖被点名的路由，源码扫描能覆盖整个类。

## [v1.3.5] - 2026-09-15

重点：**直击"开了国产杀软就起不来"** —— 构建后 **Authenticode 代码签名**（实测已签上、可复核）、**8 条加载器链**（白加黑/计划任务/LOLBin/内存加载，不落地未签名 PE）、**真 DLL 载荷**（c-shared + mingw，加载即启动、导出名可配，白加黑/rundll32 真正可用）、**BOF 改为按需编译**（默认载荷 `beacon*` 归零）、**Go 构建期指纹擦除**（buildinfo 魔数 / build ID）；同时做了**一次 Web 控制台 UI 全面优化**。

### 🎨 Web 控制台 UI 全面优化
- **先修一个根因**：很多组件写的是 `var(--text-dim, #9a9aab)` 这类"变量根本没定义、只有深色兜底值"的写法 —— **浅色主题下这些地方颜色全是错的**。现在把两套命名（`--color-*` 与 `--bg/--text/--border/--warn…` 短别名）统一指向同一组 token，并补齐**间距/字号/动效标尺**（`--sp-1..8`、`--fs-xs..2xl`、`--ring`、`--transition`）与**键盘焦点环**（`:focus-visible`，此前只有 `:hover`）。
- **新增一层基础件** `web/src/components/ui/index.tsx` + `index.css` 里的 `ui-*` 工具类：`Card`（卡片）、`Section`（可折叠分组）、`Badge`/`RiskBadge`（状态与风险等级）、`Callout`（提示条）、`Field`/`Check`（表单字段）、`Empty`/`Skeleton`（空态与加载骨架）、`Stat`/`KeyValue`/`Toolbar`/`Code`。
- **生成载荷页（改动最大）**：
  - 「高级选项」与「免杀与落地选项」改成可折叠分组（后者带一句"默认按最小特征设置"的说明），一屏不再堆 30 多个控件；
  - 结果面板新增：**落地建议**（`loader_advice_title/tips`，直接给出"直接运行 → 计划任务 → 白加黑 → 内存加载"的降级顺序）、**签名结论 Callout**（已签名/未签名 + 未签名时明确告诉你"装 360 的机器会拒绝执行"）；
  - 一键上线命令从"一长条 10~14 条"改为**分组 + 搜索 + 复制全部**：`全部 / 下载即执行 / 加载器链` 分段切换、按命令/手法/前置条件搜索、每条标注 **加载器链 / 直连** 与**风险等级**徽标；
  - `format=dll` 时出现「DLL 载荷」选项组：导出函数名（rundll32 用/白加黑可填宿主期望的系统 API 名）与「DLL 加载即启动」开关，并显示本机是否装了**架构匹配的 mingw gcc**（缺哪个一目了然）。
- **布局与导航**：侧栏折叠状态持久化（`localStorage`）、折叠态图标居中并带 `title` 提示、窄屏（<900px）浮层侧栏加遮罩与顶部汉堡入口、点击导航自动收起；顶栏与内容区内边距在窄屏收敛。
- **会话详情面板**：头部改成两行（主机名 + 状态徽标 / 系统·架构·地址·进程·用户）；13 个 tab 改为**常用常驻 + 其余收进「更多 ▾」下拉**（信息/文件/进程/Shell/无文件常驻，其余收纳），关闭按钮改为 hover 变红防误点。
  - **踩坑记录 1**：下拉一开始点不出来 —— tab 条上的 `overflow-x: auto` 把绝对定位的菜单裁掉了（菜单在 tab 条内部渲染）。改成 `position: fixed` + 用 `getBoundingClientRect()` 算坐标，并让 tab 条 `overflow: visible` 后正常。
  - **踩坑记录 2**：会话详情的 tab 文案与「更多」按钮在窄屏会被挤成两行、把内容顶下去 —— tab 条改为 `flex-wrap` + 吸顶。
- **载荷 ID 可见可复制**：结果面板把**载荷 ID** 单独列出并支持一键复制（此前只藏在"下载 URL"里）；「一键上线命令」里带占位符的加载器链命令新增 **「填入载荷 ID」**，一次把 `<DLL载荷ID>` / `<shellcode载荷ID>` 全部替换成真实 ID，`<宿主进程>` 之类仍需人工替换的占位符保留高亮。
- **回连节奏参数不再"两处打架"**：以前「生成载荷」页把心跳/重试/启动延迟**预填成写死的 60s / 10% / 3 次 / 5s**，于是「设置 → 植入端默认参数」里配的值被前端预填值直接覆盖 —— 用户在设置里配了默认值，构建页还得再填一遍，而且**两边不一致时以谁为准完全看不出来**。现在这些输入框**默认留空**，留空（请求里为 0）＝ 服务端按顺序取 `implant.interval`/`jitter`/`retry_wait`/`startup_delay_min/max`，未配置时回退 60s / 20% / 5s / 2~10s；输入框**placeholder 直接显示服务端当前生效值**（`GET /api/v1/builders` 新增 `implant_defaults` 字段），下方还有一行"留空 = 用服务端当前配置（60 秒）"的说明。只有**确实要覆盖**时才填。顺带统一了一处口径不一致：`implant.jitter` 的配置默认值原本是 **10%**，而能力接口对外声明与构建回退都是 **20%**，现统一为 20%。
- **动效与状态灯（用户实测反馈的 bug）**：终端光标"狂闪"、右上角在线指示"爆闪" —— 根因是本项目自己的 `prefers-reduced-motion` 规则写成了 `* { animation-duration: 0.01ms !important }`，把**所有 `infinite` 动画压到 0.01ms 却仍在无限循环**（≈10 万次/秒）。xterm v6 的光标闪烁就是 CSS `animation: blink_xxx 1s step-end infinite`，所以首当其冲。现在改为：只收敛 `transition-duration`，要停的装饰性无限动画**逐个点名 `animation: none`**，**永不压缩动画时长**（`web/src/index.css` 该段已写明原因，勿改回）。同时顶栏「在线」不再写死，改为**每 20s + 窗口聚焦时探测 `/api/v1/health`**，拿到非 5xx 响应即视为在线，并显示最后检查时间。
- **设置页拆成分页**（用户反馈"都挤在一块，视觉上很难受"）：原先一页从上到下堆 10 个分组（滚动找、还要靠滚动监听高亮侧栏）。现在按主题拆成 **4 个分页**，左侧导航直接切换、**同一时刻只渲染当前分页**：① 通用与服务（通用与服务 · 监听器与回连 · 安全与防测绘 · 日志与审计）② 植入端与载荷（植入端默认参数 · 载荷构建与签名）③ 集成与通知（通知 Webhook · AI 副驾驶）④ 账户与鉴权。
  - `draft`/`baseline` 仍是组件级单一状态，**切页不丢未保存改动**，吸顶保存条依旧一次提交整份配置并按分组汇总"待保存：监听器与回连、AI 副驾驶…"；侧栏每个分页带**未保存圆点**与段数徽标。
  - 支持深链接：`/settings?page=implant`；旧的 `/settings#sec-ai` 这类锚点会映射到对应分页；没带参数时记住上次停留的分页。
  - 版式：内容列限宽 1040px（页面 1440px 居中）、分页标题下有分隔与段摘要、分组间距走 `--sp-*` 标尺、窄屏侧栏变横向可滚动的标签条 —— 不再"贴着保存条堆叠"。
- **设置页里「通用与服务」「日志与审计」从只读变成可写**：这两个分组的保存接口其实从 v1.3.5 起就放行了（`server.api_host`/`api_port`/`logging.level`/`logging.format`/`listener.heartbeat_timeout`/`listener.write_queue_size`），但页面上还挂着"该分组当前无法保存，请改 server.yaml"的旧提示、输入框全是 disabled —— 属于**前后端口径不一致**。现在输入框可直接改并随保存提交，并明确标注生效方式：**改主机/端口/写队列需重启服务端**，日志级别/格式/心跳超时**保存即热生效**。
- **关于页的许可证与文档改成在线地址**：原先写的是 `/LICENSE`、`/USAGE.md` 这类同源相对路径，而这些文件只存在于部署目录、并不由控制台的静态资源提供 —— **点了就是 404**。现在全部指向 GitHub 仓库的在线预览（`.../blob/main/...`），并补齐 `docs/EVASION.md`、`docs/LOADERS.md`、`docs/DEPLOY-DOMAIN-CDN.md`、`SECURITY.md`；顶部原本两个 `href=""`（GitHub / 官方文档）也一并填上。
- **各页面统一**：仪表盘与会话列表改用统一的卡片/统计块/徽标/空态/骨架屏（含"没有会话"与"筛选无结果"两种空态区分）、表头吸顶、窄屏自适应；设置页按语义分组并配吸顶保存条（显示"有未保存修改"），**新增代码签名等 `builder.sign_*` 配置项可直接在页面上填写**；登录页与关于页统一卡片化排版（版本 1.3.5 + 合规声明）。

### 🛌 动态免杀第一批：休眠期内存加密（sleep mask）+ 去 RWX

**先把概念分清楚**（上一版把它们混在"免杀"里说，是不严谨的）：

| 类别 | 作用对象 | 对"运行即被拦"（360/电脑管家）有用吗 |
|---|---|---|
| **静态降特征** | 文件里的字符串/符号/构建指纹 | ❌ 基本无用 —— 那层看签名、信誉、投放路径与运行时行为 |
| **动态免杀** | 进程运行时的内存与调用行为 | ✅ 这才是对付内存扫描/行为引擎的 |
| **落地（delivery）** | 怎么把载荷送上目标机 | ✅ 对付"未签名 PE 被拒绝执行" |

本次只动**动态免杀**这一列：

- **新增 `sleepmask_windows.go`（+ 非 Windows stub）**：在"长时间不做事"的窗口
  （启动随机延迟、HTTP 轮询间隔、重连退避、非工作时段）里，对**我们自己的堆缓冲**
  做 XOR 加密，休眠结束再还原；休眠改走 `ntdll!NtDelayExecution`（经 apihash 解析、
  不进 IAT 明文），并且**分片 ≤300ms + 随机抖动** —— 不再是一个固定节奏的 `Sleep(大值)`。
  - 参与加密的：**隧道 SM4 子密钥**、**任务结果缓存**（结果里可能有凭据/文件内容）。
  - **不参与（如实说明）**：① 整个镜像/代码段 —— Go 的 GC/调度器/信号栈时刻在跑，
    加密代码段或 runtime 元数据必崩（这是 Go 植入端做 Ekko/Foliage 式全量 sleep mask 的
    根本障碍）；② 主 AES 密钥 —— `initAES` 之后原始密钥已零化并置 nil，剩下的是
    `cipher.AEAD` 内部密钥表（Go 侧不可达）；③ **C2 地址/sessionID 这类 string** ——
    Go 字符串可能位于只读段，原地写入即 ACCESS_VIOLATION，要覆盖需先把它们改成 []byte
    存取（已列入 ROADMAP）。
  - **并发正确性**（这块最容易写崩，所以设计得很保守）：用密钥的路径（`initAES`/`encrypt`/
    `decrypt`/`sm4*Tunnel`）先调 `ensureUnmasked()`——置 abort 标志并在 ≤1 个分片（≈300ms）内
    等到还原，任务结果不会被卡住；结果缓存与"发送用的同一块缓冲"不能互相干扰，休眠期间
    缓存时存的是 `maskIfMaskedCopy()` 返回的**加密副本**，原缓冲保持明文供发送；
    `masked` 状态与批量加解密由 `maskStateMu` 串起来，但**不覆盖整个休眠窗口**，
    所以 `cacheResult` 不会被卡几分钟。
- **实测到什么程度（别夸大）**：渲染模板后 windows/386、windows/amd64、light、evasionscan
  四种组合**编译全部通过**；算法对称性与并发设计经人工审查；**运行期行为未经实测**
  （本机 360 会删掉任何新生成的 PE，无法执行）—— 需要你在放行环境里按下面的方法验证。
- **你可以怎么验证**（给操作员的具体步骤）：
  1. 在放行环境上线（HTTP 通道效果最明显，轮询间隔 ≥2s 才会触发加密）；
  2. 用 Process Hacker / x64dbg 在休眠窗口里搜索结果缓存内容（例如刚执行过的
    `whoami` 输出、凭据采集结果）与 `TOSHELL_CFG`/SM4 子密钥特征 —— 加密窗口内应当
    **搜不到明文**；唤醒（心跳/任务）后再搜可以看到；
  3. 观察任务是否仍正常：休眠期间下发的任务最迟 1 个分片（≈300ms，最多 2s）后恢复处理，
    结果不应出现损坏（若出现解码失败/协议错误，说明加密门有问题，请反馈）。

### 🧹 去 RWX（写 → 执行两段式保护）
- 内存扫描器把"PAGE_EXECUTE_READWRITE 私有无映像内存 + 写入后立即执行"视为核弹级特征。
  本次审计植入端所有 `VirtualAlloc/VirtualProtect/NtProtectVirtualMemory` 调用点，
  改为 **RW 写入 → RX 执行** 两段式（需要再改内容时先改回 RW），不再同时请求 RWX。
  少数确实无法避免的场景在代码注释与 CHANGELOG 中单列说明（见下）。
- 具体改动文件与例外见本节末尾的审计结果（由 `memprotect_windows.go` 统一提供
  `allocRW`/`protectRX`/`protectRW` 辅助函数）。

### 🔏 构建后代码签名（Authenticode）——本版最重要的一项
- **背景（实测）**：装有 360 安全卫士/腾讯电脑管家等国产安全软件的主机上，**未签名的新 PE 会在"创建进程"阶段被拒绝执行并删除文件**（连 Hello-World Go 程序也一样；微软签名的 `notepad.exe` 副本可正常运行）。改载荷代码对这一层无效，**签名是"能不能跑起来"的敲门砖**。
- **服务端实现**（`internal/server/builder/sign.go`）：构建产物落盘前签名，`size`/`sha256` 按签名后的字节计算，保证下载物与接口一致。
  - 证书两种模式：`sign_pfx_path` + `sign_pfx_password`（证书文件）或 `sign_thumbprint`（本机证书存储 `CurrentUser\My` 按指纹取证书）；
  - 签名栈：优先 `signtool.exe`（配置路径 → PATH → Windows SDK 目录；**只有指纹模式**用它，避免证书密码进命令行），否则回退系统自带的 PowerShell `Set-AuthenticodeSignature`（**pfx 密码通过环境变量传给子进程，不出现在命令行**）；
  - `sign_fail_closed=true` 时签名失败即放弃该载荷；默认只告警并返回未签名产物；
  - 签名后立刻用 `Get-AuthenticodeSignature` 复核，把 **签名者/状态/中文说明**随构建响应回传（`signed/signer/sign_method/sign_status/sign_message`），前端「上次构建」直接显示。
- **实测（本机端到端，未执行载荷）**：`New-SelfSignedCertificate` 生成自签证书 → 导出 pfx → 服务端构建 → 产物 `Get-AuthenticodeSignature`：`SignatureType=Authenticode`、`Signer=CN=ToShell Test Signing`（指纹一致）、体积 +1,427 字节；因自签根未导入，`Status=UnknownError`（"chain terminated in a root certificate which is not trusted"）——这正是自签名的预期状态，**导入目标机「受信任的根证书颁发机构」后即为 Valid**。
- **踩坑记录**：Windows PowerShell 5.1 的 `Get-PfxCertificate` **没有 `-Password` 参数**（实测报"找不到与参数名称 Password 匹配的参数"），改为 `X509Certificate2(path, password, flags)` 构造函数（5.1/7 通用）；复核状态为 `UnknownError` 但取到签名者时，语义应是"**已签名、链不受信任**"而不是"未签名"，已按此修正结论文案。
- 配置项与自签证书生成/导出/导入步骤写进 `configs/server.yaml.example`（两份）与 `USAGE.md`。

### 🧩 加载器链：不把未签名 PE 落到目标机（8 条）
- `oneLinerSet` 除原有「下载即执行」变体外，新增 **8 条加载器链**，每条都带 `note`（前置条件、占位符含义、**国产杀软下的风险等级**），前端直接渲染：
  1. **白加黑 · 签名宿主 DLL 侧加载**（把 dll 改名成宿主会加载的 DLL 放同目录 → 启动签名宿主；磁盘上没有未签名 PE，风险中）；
  2. **计划任务 · 已签名宿主加载**（`schtasks /create` + `/run` + `/delete`，动作 `rundll32` 加载我们的 DLL）；
  3. **LOLBin · rundll32 侧加载**；4. **LOLBin · mshta 脚本下载并加载**（内联 JScript + WinHttp + ADODB.Stream）；
  5. **LOLBin · regsvr32 Squiblydoo**（如实说明本项目不托管 `.sct`，需操作员自备）；
  6. **LOLBin · certutil 下载 + 宿主加载**；7. **内存加载 · PowerShell 注入 shellcode**（不落地 PE，hex/`shellcode_bin` 分别解码）；8. **内存加载 · mshta + 签名宿主注入**（骨架）。
- Windows `dll`/`shellcode`/`shellcode_bin` 以前只回"不支持一条命令上线"，现在返回纯文本加载器链（兼容字段 `one_liner` = 白加黑命令）；exe/raw 由 6 条变 14 条。
- 新增纯函数 **`LoaderAdvice(targetOS, format, signed)`**：构建响应新增 `loader_advice_title` / `loader_advice_tips`，按"是否已签名 + 平台/格式"给出**该走哪条链、按什么顺序降级**（直接运行 → 计划任务 → 白加黑 → 内存加载），并写明"签名很脆弱：签名后再 UPX/改资源会让签名失效"。
- 新增文档 **`docs/LOADERS.md`**：什么时候用哪条、前置条件、国产杀软下的风险、常见失败原因、合规声明。**本项目不内置任何第三方加载器/宿主程序**，宿主 exe 与其 DLL 名、SCT 脚本均由操作员自备并自负合规责任。

### 🥷 BOF 改为按需编译（默认载荷 `beacon*` 归零）
- 上一版体检里唯一剩下的高信号明文就是 BOF 兼容层的 **Cobalt Strike Beacon API 名字**（`BeaconDataParse`/`BeaconOutput`/`BeaconPrintf`… 实测 22 处，靠 pclntab 保留）。这是 BOF 二进制的符号契约、**不能改名**，所以改为**按需编译**：`bof_windows.go` 标签改成 `windows && !light && bof`，默认走新增的 `bof_stub_windows.go`（返回"BOF 未编译进本载荷"）。
- 生成载荷页新增「BOF 支持」开关（默认关，提示代价）；服务端请求字段 `bof_enabled`。
- **实测**：默认载荷 `beaconAPI=0`；勾选后 `beaconAPI=22`（证明门控生效），且体积从 3,551,880 → 3,656,840（+105KB，就是整套 BOF 兼容层）。

### 🫥 Go 构建期指纹擦除（`internal/server/builder/harden.go`）
- `-s -w` 去不掉 Go 的 **buildinfo 块**（`\xff Go buildinf:` 魔数 + 内嵌 Go 版本串）与构建 ID（`Go build ID:`），而它们是 Go 家族 YARA 规则最稳定的命中点。新增 `ScrubGoFingerprint(bin)`：**只做原地 0x00 覆盖、绝不改变长度**（PE 节表/RVA/重定位/UPX 输入全部不受影响），擦除 ① 全部 `\xff Go buildinf:` 16 字节头；② 该头后 512 字节窗口内的 `go1.x.y` 版本串；③ `Go build ID:` 前缀（规范形态连 ID 与换行一起清）。**pclntab / 符号表绝不触碰**（运行期栈回溯与 GC 的核心数据，且属 garble 的职责）。
- 接入点：Go exe 与 DLL 两条编译路径（都在 UPX 之前），**实测**默认载荷 `Go buildinf=0`、`Go build ID:=0`。
- 单测 `harden_test.go` 覆盖擦除/幂等/边界（窗口外版本串不动/非 Go 文件字节不变）。已知边界：函数**不能**用于服务端自身产物（服务端含 `pecheck.go` 的同类常量）。

### 🩹 修复：SOCKS5 代理并发隧道上限 100 → 300
- **现象（实测）**：同时开多个测速/多标签页时，代理会"看起来崩了"——新连接一律失败、下载 0。排查结果：植入端 `maxTunnelConns = 100` 被**打满**，`tunnelSem` 信号量为空后新隧道直接被拒（`sendAckMsg(ok=false,"too many connections")` → 服务端 `notifyClose` + `CloseTunnel` → 浏览器看到连接立即失败）。实测：隧道数钉在 100/100 时并发 12 条 100 KB 请求**全部失败**（`http_code=000`），回落到 79 条后单连接立刻恢复 200。
- **为什么容易打满**：浏览器对单域名保活 6+ 条连接，一个测速站还会开 4~16 条并行流，两三个测速叠加就能占满 100；而隧道空闲回收要 `readLoop` 5s×120 ≈ **10 分钟**，期间一直占坑。**叠加今天修掉的那个 readLoop panic 缺陷时更致命** —— 每条卡死的下载会**永久占住一个坑**（readLoop 死了 → `writeLoop` 永远等 `<-e.readDone` → `finishClose/del` 不执行 → 信号量不释放），于是"越测越容易崩"；而植入端每次重连 `resetPool()` 清空残留，所以它又"自己恢复"。
- **改动**：`release/implant/tunnel.go`（两个镜像目录同步）`maxTunnelConns 100 → 300`，仍远小于 `maxTunnelGoroutines(500)`。**需要重新生成载荷才生效。**
- **实测（新载荷）**：并发隧道可稳定超过 100（旧的 100 上限下必然被拒），单连接下载正常。

### 🩹 修复：SOCKS5 代理「下载传几百 KB 后永久卡死」（上行正常）
- **现象（实测）**：经代理下载 1 MB/5 MB 分别只到 302 KB/335 KB 就**彻底停住**，10 MB 在 120 s 内只到 172 KB；同一时刻 `tunnel.bytes_out` **零增长**、植入端 CPU 几乎不动、会话仍显示 active，而**上传完全正常**（5 MB / 485 KB/s）。表现为测速"延迟正常、下载 0 Mbps、上传正常"。
- **根因**：`release/implant/tunnel.go` 的 `readLoop` 把"读入数据区"的上界写成了 `cap(fb)`。池缓冲容量公式是 `frameHdrLen+nonceLen+envHdrLen+maxRead+tagLen`，**cap 里那 16B 是留给 SM4-GCM tag 的**；按 cap 读会让单次 `Read` 最多返回 `maxRead+16` 字节，于是 ① `sm4GCMSeal` 的 `append(tag)` 越过 cap → 重新分配新数组而返回值被 `_ =` 丢弃（fb 里留下没有 tag 的密文）、② `fb[:frameHdrLen+nonceLen+envHdrLen+n+tagLen]` 越界 **panic**，被 `readLoop` 里**空的 `recover()` 静默吞掉** → 该隧道**唯一的下行产出 goroutine 直接消失**（`writeLoop` 还在等 `<-e.readDone`，隧道既不产出数据也永不收尾）。
- **年龄**：该行自 **v1.2.0 首次开源导入（2026-08-27）** 就存在，属长期潜伏缺陷（触发条件是单次 Read 拿到 >64 KB，取决于目标侧内核缓冲被填满，与目标是谁无关），**不是本次改动引入**。
- **修复**：
  1. 读上界收紧为 `frameHdrLen+nonceLen+envHdrLen+maxRead`，tag 余量不再被数据吃掉；
  2. `readLoop` 的 panic 兜底改为按"读侧结束"收尾（幂等 `closeReadDone` + 关目标连接），杜绝"看着 active、实际再不出数据"的僵尸隧道；任何未来的 panic 都会让隧道干净结束而不是无限挂住；
  3. 补上**方向不对称**：下行热路径（`readLoop` 的 `sm4GCMSeal`、`sendCloseAsync`）此前直接使用 `tunnelKey`，而上行解密走 `sm4DecryptTunnel` 里已有 `ensureUnmasked()` —— 一旦休眠掩码生效，下行会用被 XOR 的密钥加密 → 服务端认证失败丢帧。现两处均补 `ensureUnmasked()`。
- **实测（A/B，同机）**：修复前 1 MB/5 MB 下载卡在 302 KB/335 KB、10 MB 不可用；修复后 **10 MB 下载 8.7 s 完成（1.14 MB/s）**、连续 3×3 MB 全部完成、5 MB 上传 3.2 MB/s 正常。
- 定位与验证过程完整记录在 **`docs/PROXY-DOWNLOAD-STALL-ANALYSIS.md`**（含 `TOSHELL_TUNNEL_DEBUG=1` 现场日志与逐条排除）。

### 🩹 其它
- **修掉 `retry_wait` 的口径不一致**：构建侧归一化原来是硬编码 `retry_wait == 0 → 5`，**没读** `implant.retry_wait` —— 也就是设置页把重试间隔配成 5 以外的值时根本不生效（而 `interval`/`jitter` 早就改成"先读配置再回退"了）。现改为同一套逻辑，`implant_defaults` 报给生成载荷页的 placeholder 与实际烘焙进载荷的值同源。
- **发布包补上 `docs/`**：CI（`.github/workflows/release.yml`）与本地打包脚本（`scripts/package_release.ps1`）此前都不把 `docs/` 打进 zip，而包里 README/USAGE 大量链接指向 `docs/EVASION.md`、`docs/LOADERS.md`、`docs/DEPLOY-DOMAIN-CDN.md`（README 的截图也在 `docs/screenshots/`）—— 等于**包内一堆死链**。现在两条打包路径都带上 `docs/`，并把 `docs/EVASION.md`、`docs/LOADERS.md` 加进"包内容校验"清单。
- `internal/server/builder/gate_scan_test.go` 同步 4 参数 `buildTagList`，并新增 `TestBOFIsOptIn`（默认 stub 不得含任何 Beacon 符号）。
- 发版门禁脚本与 CI 校验沿用 v1.3.4（`scripts/e2e_smoke.ps1`、版本/包内容校验、`checksums.txt`）。

### 🧩 DLL 载荷修好了（v1.3.5 的加载器链只有它不是真的）
- **问题（实测）**：`format=dll` 走的是普通 `go build`（`CGO_ENABLED=0`），而生成胶水里 `import "C"` 的文件在 CGO_ENABLED=0 下会被 Go **静默跳过**，产物是一个普通 EXE 改了扩展名 —— 实测 `IMAGE_FILE_DLL=false`、导出目录 RVA=0。也就是说 v1.3.5 给出的"白加黑（DLL 侧加载）""rundll32 侧加载""计划任务 + rundll32"三条链**第一步就失败**。
- **修法**（`internal/server/builder/dll.go`）：
  - `go build -buildmode=c-shared` + `CGO_ENABLED=1` + mingw-w64 gcc，**且要求 gcc 与目标架构一致**（x64 需要 `x86_64-w64-mingw32-gcc`；只有 i686 时会明确报错并给出安装命令，绝不产出一个架构不对的 DLL）；
  - **加载即启动**：Go 的 `init()` 在 c-shared 下会执行 → `go startImplant()`，白加黑不用关心宿主调用哪个导出；可在页面取消勾选（去掉 `autostart` 标签）；
  - **导出名可配**：C 侧 `__declspec(dllexport) void __stdcall <名字>(...)` 包装 → 调 Go 的 `tshEntry`。这样导出名可以填成**宿主期望的系统 API 名**（如 `GetFileVersionInfoW`）而不会与 windows.h 同名声明冲突；386 上再加 `-Wl,--kill-at` 剥掉 `@16` 修饰，`rundll32 payload.dll,Start` 才能按字面名找到导出；
  - 服务端能力接口新增 `dll_available` / `dll_message`，生成载荷页直接显示"本机能不能构 DLL、缺哪个 gcc"。
- **踩坑记录**：cgo 的 preamble 会被编进两个目标文件，把导出函数定义写在里面会 `multiple definition of 'Start@16'`（实测）→ 定义移到单独的 `dllentry.c`；`extern void tshEntry(void)` 声明留在 preamble。
- **实测（本机 386，未执行 DLL）**：`isDLL=true`、`machine=0x14c`、导出表有 **`Start`**（默认）与 **`GetFileVersionInfoW`**（自定义名）；`dll_autostart=false` 时仍导出函数、只是没有 `init` 启动；请求 amd64 时因本机只有 i686 gcc 而**明确报错**（提示 `pacman -S mingw-w64-x86_64-gcc`）。

### 🪟 配套：共享库构建的取舍（如实说明）
- Go 不允许"使用 cgo 的包"同时带 Go 汇编文件（`package using cgo has Go assembly file`），所以 DLL 构建会排除 PEB 汇编（`getpeb_windows_*.s`）与 amd64 直接系统调用（`directsyscall_windows_amd64.{go,s}`），并新增 `directsyscall_windows_amd64_shared.go` 提供接口一致的 apihash 回退实现。
- 代价：**DLL 载荷里没有 PEB 快速解析与直接系统调用**（回退 `LoadLibrary`/`GetProcAddress` + ntdll 导出），功能不变、静态与行为特征略增。需要这两条更强规避路径时用 `exe`/`raw` 格式；`main.go` 的入口也相应拆成 `startImplant()`（DLL 与 exe 共用）+ `entry_exec.go`（`!shared` 的 `main()`）。

### 🩹 顺带修掉的 JSON 响应 bug
- 构建失败时返回的是 `fmt.Sprintf(`{"error":"%s"}`, err)`：只要错误里含换行（编译失败信息几乎必然多行）产出的就是**非法 JSON**，前端 `JSON.parse` 直接抛错、用户只看到"解析失败"而不是真正的失败原因（本次实测踩到）。新增 `writeJSONError`（`json_response.go`）并按此改写构建相关错误响应。

## [v1.3.4] - 2026-09-15

重点：**动态（行为）查杀**排查与本机实测反差、植入端默认行为收敛（不再自动枚举进程查杀软）、pclntab 高信号标识符中性化、启动/心跳节奏参数与服务端配置真正生效、驱动加载前自检、内存执行载荷预检、发版端到端冒烟门禁。

### 🧪 动态查杀排查：先把"到底是什么在拦"钉死
- 本机（装有 **360 安全卫士 + 腾讯电脑管家 + 无边界安全系统**）实测结论：**任何新生成/未签名的 PE 一执行就被拒并删文件**，与载荷里有什么代码无关 ——
  - 一个只有 `time.Sleep(3s)` 的 **Hello-World Go 程序**（1.85 MB，无任何 C2 代码）：`Start-Process` 报 `Access is denied`，随后**文件被删除**；
  - 生成的植入端（windows/amd64，3.66 MB）同样被拒 + 删除；连 `release/implants/` 里历史构建的产物也已被清空；
  - 对照：`notepad.exe` 的副本（微软签名）**可以正常执行**。→ 拦截依据是"未签名/未知 PE + 主动防御策略"，不是某个字符串或某段代码。
- `Microsoft-Windows-Windows Defender/Operational` 里唯一与"C2"相关的记录是 `Behavior:Win32/CommandAndControl.A!ml`（**Behavior: 前缀 = 行为判定**，且是历史样本 TscanPlus 的，不是本项目载荷）；本机 Defender 实时防护处于关闭状态（第三方安全软件接管）。
- 结论（写进本文件以免重复踩）：**本机的"动态查杀"实验环境不具备判别力**。要么在干净 VM（仅 Defender）里跑行为验证，要么先解决"未签名 PE 被策略拒绝执行"这个前置问题（代码签名 / 白加黑加载器 / 由已签名宿主内存加载）。

### 🥷 植入端默认行为收敛：不再自动"枚举进程找杀软"
- **问题**：`gate_windows.go` 的 `evasionInit()` 在**每次启动**都用 `CreateToolhelp32Snapshot` 遍历全系统进程，并与 38 个安全软件/分析工具进程名（含 `360tray`/`huorong`/`qhactivedefense`/`QQPCTray` 等）做 `strings.Contains` 比对。这正是国产杀软主动防御**明确拦截的"对抗安全软件"行为**；它还必须静态导入 toolhelp32 API 并携带这批进程名字符串，绕开 apihash"零 API 明文"的免杀路径 —— 属于"用强行为特征换弱反沙箱能力"。
- **修复**：该逻辑移入 `implant/gate_scan_windows.go`，用构建标签 `evasionscan` 门控；默认编译 `gate_scan_off_windows.go`（空实现）。生成载荷页新增「主动反沙箱进程检测」开关（默认关闭，并在 UI 上写明代价），服务端请求字段 `evasion_scan`。
- **实测（只编译不执行，规避本机拦截）**：默认构建与 `-tags evasionscan` 构建在 windows/386、windows/amd64、`light` 三种档位下均编译通过；二进制里 `360tray`/`huorong`/`qihoo`/`zhudongfangyu`/`vboxservice` 命中数由 0 变为 1~2，体积差约 2~5 KB（即默认载荷**完全不含**这些字符串与逻辑）。

### ⏱ 启动随机延迟与心跳节奏：三个"配置了却无效"的真实缺陷
- **启动随机延迟无法按载荷配置**：Web/API 侧 `BuildRequest` 从来没有 `startup_delay_min/max` 字段（前端 TS 类型里却有），请求里带了也被服务端**静默丢弃**，只能吃服务端全局配置。现已补齐 `startup_delay_min/max` 请求字段并透传到模板渲染；生成载荷页新增「启动随机延迟 (秒)」最小/最大输入框（0 = 用服务端配置）。
- **心跳间隔/抖动被硬编码覆盖**：`createBuilderHandler` 里 `interval==0 → 5s`、`jitter==0 → 2%`，把设置页里配的 60s 心跳悄悄改回 **5s 固定轮询**（最典型的 C2 行为特征）。现改为**优先取服务端配置**（`implant.interval` / `implant.jitter`），配置也没有才回退 60s / 20%。
- **驱动加载失败只说"可能被 HVCI/黑名单拦截"**：`drv_windows.go` 现在捕获 `GetLastError` 并翻译成可定位的结论（`1275` 被内核代码完整性策略/易受攻击驱动黑名单拦截、`577` 证书吊销、`1053` 加载即崩、`1058` 服务被禁用、`1073`/`1056` 服务已存在、`5` 权限不足、`2` 文件缺失……），并说明"1275 这类拦截不会有杀软弹窗，属内核静默拒绝"。
- **可回归**：新增 `internal/server/builder/gate_scan_test.go`（构建标签矩阵、启动延迟渲染、默认模板不得含进程枚举/杀软进程名）——**本机因安全软件拦截新编译的测试二进制无法执行**，需在干净环境或 CI 上跑。

### 🔩 驱动体系：加载前自检（ROADMAP P0-1）
- **`GET /api/v1/drivers` 与 `/drivers/{name}` 现在带自检结论**（新增 `verify` 字段，既有字段全部不动）：`sha256 / manifest_sha256 / hash_ok / signed / signature_checked / signer / blocklisted / blocklist_reason / warnings / errors`。
- **sha256 一致性是硬拦**：`manifest.json` 新增 `sha256` 字段声明期望哈希；上传/加载的驱动与之不一致 → `byovd_load` **直接 400 拒绝下发**，错误里写明"可能被替换/损坏"。这是这条链路上唯一能可靠拦住"文件被换过"的检查（WinVerifyTrust 只能校验磁盘文件，校验不了内存里上传的字节；同名同哈希才复用签名结论）。
- **Authenticode 签名状态**：`WinVerifyTrust(WTD_CHOICE_FILE + WTD_REVOKE_NONE + WTD_STATEACTION_VERIFY→CLOSE + WTD_CACHE_ONLY_URL_RETRIEVAL)` 判签名有效与是否被篡改；签名者走 `CryptQueryObject → CryptMsgGetParam(CMSG_SIGNER_INFO) → CertFindCertificateInStore → CertGetNameString`。目录签名(catalog)的 `.sys` 取不到签名者，只给"签名有效/未签名"结论并如实提示（不伪造结论）。4 秒软超时，超时只警告不拦截、不缓存；结构体大小在 `init()` 断言（x86 52/88、x64 88/32 不一致时立即失败，而不是给一个莫名的 `ERROR_INVALID_PARAMETER`）。
- **易受攻击驱动黑名单提示**：只读本机 `HKLM\SYSTEM\CurrentControlSet\Control\CI\Config\VulnerableDriverBlocklistEnable` + 探测 `%windir%\System32\CodeIntegrity\driversipolicy.p7b`（含 Sysnative，规避 WOW64 重定向）。**不下载、不内置任何名单数据、代码里不写死任何驱动名**，只告诉操作员"策略已启用，名单内驱动会被内核静默拒绝（植入端 `StartServiceW` 报 1275）"。
- **警告 vs 硬错误分流**：未签名/黑名单可能拦截 → 允许下发 + `logging.Warn` + 响应带 `warnings`；只有 sha256 不一致这类硬错误才拒发。新增 `GET /api/v1/drivers/{name}/verify` 单独查询；`List()` 复用同一次读取的字节与已解析的 manifest（不做二次全文件读取），签名结论按 `path+sha256` 缓存（超时结论不缓存，下次重试）。
- **测试**：`internal/server/drivers/verify_test.go` 覆盖哈希一致/不一致/未声明、警告合并、签名者比对、JSON 字段名、`List()` 携带自检结论；签名校验通过可替换的 `signatureCheck` 桩函数完成，**不依赖本机证书链与联网吊销检查**。

### 🧠 内存执行：下发前 PE 预检（ROADMAP P0-2）
- **问题**：`exe_mem`/`dll` 是植入端**同进程内**反射映射，命中硬边界会直接崩宿主（实测：Go 编译的 EXE 因双 Go runtime 必崩；架构不符、.NET 载荷也起不来），而失败信息只有"目标机掉线了"。
- **方案**：服务端新增 `internal/server/builder/pecheck.go`，在 `fileless-exec` 下发前**手写解析 PE 头**（DOS/PE/可选头/节表 + COM 描述符目录 14 = CLR、TLS 目录、重定位表），并用 `.gopclntab` / `\xff Go buildinf:` 特征识别 Go 载荷，然后按宿主会话架构给出 `reject / warn / ok` 三种判定：
  - **reject**（不下发，HTTP 400 + `reasons` + `suggestion` + 精简 `pe_info`）：Go 载荷走 `exe_mem`、架构与宿主不一致（`exe_mem`）、带 CLR 目录（.NET）；
  - **warn**（照常下发 + `warnings`）：有 TLS 回调、无重定位表、donut 转换路径；
  - 高危逃生门：请求带 `force: true` 时 reject 降级为警告，但**日志明确记录"操作员强制下发"**并附带原拒绝原因，便于事后追溯。
- **测试**：`pecheck_test.go` 用代码构造最小 PE 覆盖主要分支（合法 amd64、i386 对 amd64 宿主、带 `.gopclntab`、带 CLR 目录、坏数据），不依赖外部样本文件。

### 🚦 发版门禁：端到端冒烟 + 产物校验（ROADMAP P0-4 / P3）
- **新增 `scripts/e2e_smoke.ps1`**（一条命令、幂等、非 0 退出即阻断发版）：临时端口起一个自建服务端 → `/health`（含 401/404/5xx 的中文区分）→ **鉴权必须生效**（无 Key 访问会话列表必须 401）→ C2 监听端口可连接 → `GET /builders` → **构建三档载荷**（windows/amd64 full、windows/amd64 light、linux/amd64 full，校验 `size`/`sha256` 并下载回来再核对大小与哈希）→ 关键路由存在性（`/drivers`、`fileless-exec`、`screen-stream`；404 = 路由缺失判失败，400/401/403/409 = 存在）→ （可选）真实 Windows 载荷上线 + 下发 `whoami` 拿回执 → 清理进程/临时目录，输出 ✅/⚠️/❌ 摘要。
  - 参数：`-Port` / `-WorkDir` / `-SkipImplant` / `-RequireImplant` / `-KeepArtifacts` / `-ServerExe` / `-ApiKey`。
  - **在装有国产安全软件的机器上会自动降级**：识别"载荷被拒绝执行/文件被删"后只把该环节记为 ⚠️ 并明确打印原因，不死循环、不假装成功；需要严格阻断时加 `-RequireImplant`。
  - 用法与 CI 片段见 `scripts/README.md`。
  - **首次真机执行后修掉一个 PowerShell 5.1 陷阱**：`Invoke-WebRequest -OutFile` **不返回带 `StatusCode` 的响应对象**，脚本原先把空值转成 0，于是"下载其实成功"被误判为 `HTTP 0` 失败（本机与 CI 都复现）。现改为 `-OutFile` 无异常即判定 200，再由文件大小与 sha256 复核。实测本地跑完整脚本：**19 项检查 ❌ 0、⚠️ 3（跳过植入端/已知 500 语义），exit 0**；三档载荷均构建并下载校验通过（windows full 3,655,413B、windows light 2,984,693B、linux full 3,301,769B）。
- **CI（`.github/workflows/release.yml`）**：新增 `e2e-smoke` job（windows runner，`-SkipImplant`）并让打包 job `needs: [web, e2e-smoke]` —— **冒烟不过就不出包**；打包 job 内新增 **`toserver -version` 与 tag 一致性校验**、**发布包内容清单校验**（`toserver`/`implant/main.go`/配置样例/README/USAGE/LICENSE）；新增 `checksums` job 生成 **`checksums.txt`（sha256）** 随 Release 发布（本地 `scripts/package_release.ps1` 同步生成同样的清单）。
- **顺便修掉两处**：① `configs/server.yaml.example`（根目录与 release 两份）里 133 个 **U+FFFD 损坏字符**（早期转码丢字）已重写为干净中文注释，`api_keys` 从标量改为标准列表；② `scripts/package_release.ps1` 补上 **UTF-8 BOM**（含中文注释，PowerShell 5.1 无 BOM 会按 ANSI 解析乱码）。

### 🏷 pclntab 高信号标识符中性化（免杀）
- Go 的 `-s -w` 只去掉符号表与 DWARF，**函数名/文件路径仍在 pclntab 里**。实测默认载荷里可直接搜到 `loadShellcode`、`loadEXEMem`、`reflectLoadPE`、`injectShellcodeHost`、`memexe_windows.go`、`memload_windows.go`、`stomp_windows.go`、`evasionInit`、`gate_windows.go` 等"一看就是 C2 组件"的名字。
- 全部改为中性名（**能力零变化**，两份模板副本同步）：
  `stompShellcode→carveRun`、`moduleStomp→carveModule`、`loadShellcode→runBlob`、`injectShellcodeHost→runBlobInHost`、`loadEXEMem→runMappedImage`、`reflectLoadPE→mapImagePE`、`evasionInit→initGate`、`evasionSuspectDelay→hostDelay`；文件 `stomp_*→carve_*`、`memexe_windows.go→imgexec_windows.go`、`memload_*→blob_*`、`evasion_*→gate_*`。
- 实测（渲染模板后只编译、`-s -w` 关闭以便体检）：上述标识符命中数**全部归零**；`-tags evasionscan` 与默认构建在 windows/386、windows/amd64 下均编译通过。
- 实测（**服务端真实构建 + 字符串体检**，windows/amd64/tcp）：

  | 载荷 | 体积 | `beacon*` | `loadShellcode`/`loadEXEMem`/`reflectLoadPE` | `memexe_windows.go` 等文件路径 | `kgameprotect`/`byovd`/`HVCI`/杀软进程名 |
  |---|---|---|---|---|---|
  | `full` | 3,655,412 | 22（BOF ABI，保留） | 0 | 0 | 0 |
  | `light` | **2,984,692** | **0** | 0 | 0 | 0 |
  | `full` + `evasion_scan` | 3,661,044 | 22 | 0 | 0 | 0 |

  即：对名字敏感的场景用 `light`（体积同时小 18%），全功能档只剩 BOF API 这一项不可去除的 ABI 名字。
- **保留且如实说明**：`BeaconDataParse`/`BeaconOutput` 等 **Cobalt Strike BOF API 名字不能改**（BOF 二进制靠这些名字解析符号，是 ABI 契约），因此 full 档案仍会有 `beacon*` 命中；对名字敏感的场景请用 `light` 档案（`bof_windows.go` 带 `!light`，不参与编译）。

### 🧪 构建可观测：载荷参数写进服务端日志
- 新增两行日志，且**只在这里能看到"真正烘焙进载荷的值"**（前端请求 / 服务端配置 / 默认值三层，任一层都可能覆盖）：
  - `rendering implant: url=… interval=60s jitter=20% startup_delay=2~10s evasion_scan=false profile=full`
  - `compiling implant: os=windows arch=amd64 tags="evasionscan" garble=false go=go1.20.14`
- 排查"配了没生效/载荷里怎么还有这个特征"时，先看这两行，实测已用它确认 `evasion_scan`/`startup_delay` 的请求值确实生效。

### 🔧 其它
- 驱动诊断文案全部写成**不含转义的简单双引号字面量**（用 `" + "` 拼接代替 `\n`），以保证植入端字符串混淆器会把它们编译成 `xd("hex")`，避免 `HVCI`/`ERROR_ACCESS_DISABLED_BY_POLICY` 明文留在载荷里（混淆器对含转义的字面量不做处理）。
- **默认心跳节奏收敛**：`configs/server.yaml.example`（根目录与 release 两份）从 `interval: 5 / jitter: 2` 改为 **`interval: 60 / jitter: 20`** 并写明理由 —— 5 秒固定轮询是最典型的 C2 行为特征；`GET /api/v1/builders` 里的 `jitter` 默认值同步改为 20。

## [v1.3.3] - 2026-09-15

重点：ROADMAP P0 两项（会话掉线抖动、屏幕流/截图可控）、内存模块 EXE 带参执行、平台工具库、BYOVD 驱动可插拔、issue #6 / #7。

### 🧠 内存模块支持 EXE 带参数执行
- 新增 `fileless_exec` 的 **`exe_mem`**：植入端反射式映射 EXE（映射/重定位/导入表）后 `CreateThread` 到入口点，并把 `args` **注入 PEB 命令行**（`RTL_USER_PROCESS_PARAMETERS.CommandLine`），使被执行的 EXE 的 `argv` 真正拿到参数。实测：反射执行测试 PE 后其 `argv` 为 `["tool.exe","mem-hello","42"]`（`argc=3`）。
- 新增 `wait_ms`：等待执行线程结束并回传退出码；0 = 立即返回（后台线程继续运行）。
- 退出保护：对映射镜像 **IAT 里的 `ExitProcess`/`TerminateProcess`/`RtlExitUserProcess` 重定向到 `ExitThread`**，避免载荷退出时带走植入体（局限见下）。
- 架构校验：32 位 PE 无法进 64 位进程时**明确报错**，不再静默失败。
- 前端「内存执行」面板新增 `exe_mem` 选项、`args`（EXE 命令行）、`entry`（argv[0]）与 `wait_ms` 输入，并按 kind 给出提示。
- 修正既有 `exe`（donut）路径：原先 `Thread=0 + ExitOpt=2`，内存执行的程序结束时调用 `RtlExitUserProcess` 会**把植入体一起杀掉**；改为 `Thread=1 + ExitOpt=1`（独立线程 + 只退线程），并支持把 `args` 作为 donut `Parameters`（上限 255 字节，超长直接报错）。
- **已知边界**（写在面板提示与任务输出里）：`exe_mem` 要求与植入体同架构；**不要用它跑 Go 编译的 EXE**（宿主也是 Go，两个 runtime 冲突）；载荷 CRT 内部直接调用的 `ExitProcess` 拦不住（彻底解决需 hook 系统 API），「跑完即退」的工具请走落地执行；内存执行不重定向 stdout，故无控制台输出。

### 🔩 BYOVD 内置驱动换成 kgameprotect（删除 RTCore64.sys）
- **内置驱动替换**：删除 `RTCore64.sys`（MSI Afterburner / CVE-2019-16098，任意内核读写，被微软易受攻击驱动黑名单与几乎所有杀软重点标记），改为内置 **`kgameprotect.sys`**（WHQL 签名 / Microsoft Windows Hardware Compatibility Publisher，AMD64，59,592 字节，SHA-256 `6c1d596d…126ee`，与 [LOLDrivers PR #428](https://github.com/magicsword-io/LOLDrivers/pull/428) 记录一致）。
- **能力定位改为"击杀"**：该驱动设备 `\\.\kgameprotect`，暴露**无鉴权进程终止 IOCTL `0x222048`**（METHOD_BUFFERED + FILE_ANY_ACCESS，入参首个 DWORD 为 PID），驱动内部 `PsLookupProcessByProcessId → ObOpenObjectByPointer(PROCESS_TERMINATE) → ZwTerminateProcess`，因此**不需要调用方持有目标进程权限**即可终止普通杀软/EDR 进程。
- **新增 `byovd_kill` 任务与接口**：`POST /api/v1/sessions/{id}/edr/byovd-kill`（`pid` 或 `process_name`，`driver` 可选），前端杀软对抗页新增「驱动击杀」入口与目标输入。
- **能力变化（如实说明）**：kgameprotect 只提供进程终止、**没有任意内核读写**，因此"用驱动改 EPROCESS.Protection"的 PPL 清除路线**已移除**；`ppl_kill` 只保留**句柄窃取**路线，对 PPL 保护进程（如 Defender 的 MsMpEng）无效时会有明确提示。
- 前端文案与排版一并整理：BYOVD 区块改为「驱动说明 + 内置驱动一键加载/卸载 + 驱动击杀 + 自定义 .sys 上传」四段式，去掉原先那段与实现不再匹配的 RTCore64 长文与挤在一行的排版；About/USAGE 同步更新。


### 🚫 不再内置任何 BYOVD 驱动（改为操作员自备）
- **移除 kgameprotect.sys**（连同上一版的 RTCore64.sys）：内置驱动的代价是**载荷与服务端里都带驱动名/IOCTL 明文**，而 AV/EDR 普遍按易受攻击驱动名做规则 —— 实测改动前载荷里可直接搜到 `kgameprotect` ×5 与 `\\.\kgameprotect`。现在发布包与二进制里**不含任何驱动**。
- **驱动目录改为运行期扫描 + manifest**：`drivers/`（发布包同目录）与 `data/drivers/` 下的 `*.sys` 由 `/api/v1/drivers` 实时列出（SHA-256 现算），同目录 `manifest.json` 声明 `device/service/ioctl/purpose`；没有 manifest 也会列出，只是元数据留空（前端提示补全）。
- **植入端不再内置任何驱动默认值**：设备名/服务名/终止 IOCTL 全部由服务端在任务数据里下发；缺参数时明确报错（不再回退到某个内置驱动名）。同时把 `handleBYOVD*` / `byovdKillByPID` 等**高信号函数名改成中性名**（`handleDrvLoad/Unload/Kill` / `drvXferPid`），减少 Go pclntab 里的明文特征。
- **服务端新增会话级驱动档案**：`byovd_load` 可带 `name/device_name/kill_ioctl`，服务端登记后 `byovd_kill` 直接复用（也可在请求里显式带 `device`/`ioctl`）；前端「杀软对抗」页改为"服务端 drivers/ 目录 + 上传 .sys"，并新增设备名/服务名/终止 IOCTL 三个输入框。
- **合规**：`THIRD-PARTY-NOTICES.md` 相应改写为"本项目不再内置任何驱动；使用者自行提供并自负合规责任"。
### 📡 会话稳定性：不再「离线几秒又在线」（ROADMAP P0-1）
- **判活阈值强制留余量**：实际超时 = `max(listener.heartbeat_timeout, 3 × 实测心跳间隔)`，并在启动日志里写明「margin 3x」。此前 `heartbeat_timeout=60s` 与心跳间隔 60s 几乎零余量，任何一次心跳迟到（调度抖动/网络排队/休眠唤醒）都会被判离线，下一个心跳又恢复，前端表现为闪断。
- **按会话自适应**：会话运行中采样实测心跳间隔（只向上立即生效、向下缓慢回收），因此构建时可自定义 `interval` 的载荷也按自己的节奏判活，不再依赖全局配置猜。
- **首周期保护**：会话刚上线、还没采样到节奏时阈值放宽到 2 倍基准，避免第一个心跳刚好踩线被判死。
- **判定统一**：TCP / HTTP 轮询 / MQTT 三个监听器的判活都改为走 `Session.IsAlive()`（此前各自用 10s ticker + 固定阈值，且窗口误差达 10s），扫描周期调整为 5s。
- **广播去抖**：`session_offline` 延迟 15s 观察窗广播，期间会话重连则**不发任何事件**（消除「离线→在线」闪烁），只有持续失联才广播离线；重复注册不再重复广播 `session_online`，上线 webhook 也随之不再重复推送。
- 实测验收：60s 心跳（jitter 5s）的植入端连续运行 220s，**零次状态抖动**；杀掉植入端后按 3 倍间隔（3m1s）判死并广播一次 `session_offline`。

### 🖥 屏幕流 / 截图参数化与限速（ROADMAP P0-2 部分）
- **参数化**：屏幕流与截图支持 `fps`(1-10) / `quality`(20-95) / `max_kbps`(带宽上限) / `monitor`(多显示器单选) / `max_width`(缩放宽度)，服务端校验钳制后透传植入端；`POST /sessions/{id}/screen-stream` 与 `POST /sessions/{id}/screenshot` 均接受这些参数。
- **带宽自适应**：植入端按秒统计实际发送量，超过 `max_kbps` 时先降 JPEG 画质、再降帧率并限宽，带宽有余量时逐级恢复；默认帧率由固定 1.25fps 提升到可选 1-10fps，屏幕流默认 JPEG。
- **服务端限速/帧合并**：新增帧限速器，超过会话期望帧率的帧直接丢弃（前端只需要最新帧），硬上限 10fps，并在丢弃累计时输出诊断日志。
- **明确的失败提示**：捕获失败时立即回传带原因的 error 帧（锁屏/无交互桌面/Headless），前端展示原因而不是一直「等待画面」；收到正常帧后自动清除错误提示。
- **前端**：屏幕流面板新增「画质参数」面板（帧率/画质/带宽/显示器/缩放宽度）与分辨率显示。
- 实测验收：真实植入端截图 `max_width=640` → 640×360 JPEG 约 21KB（原始 2560×1440 约 343KB，体积降到 1/16）；`monitor=1` 单选显示器生效；屏幕流任务回执确认 `fps=5 quality=60 max_kbps=1200` 已下发，WS 侧可见真实 JPEG 帧。

### 🔔 通知与一键上线
- **飞书通知修复（issue #7）**：各平台按自己的消息结构推送——飞书 `msg_type`+`content.text`、企业微信 `msgtype`+`text.content`、Slack `text`、Discord `content`、钉钉 markdown、其它通用 JSON；新增飞书 body 内 `timestamp`+`sign` 加签。判定结果同时解析响应体业务码（飞书 `code≠0`、钉钉/企业微信 `errcode≠0` 均判失败并给出平台原话），不再出现「HTTP 200 显示成功但消息没发出去」。
- **一键上线命令**：下载地址改为服务端按配置解析（`public_host` 优先，其次控制台访问地址 / 载荷 `server_url` 主机 / 本机内网 IP，不可达时显式告警），不再取控制台自身的 `localhost`；新增 Windows 6 种 / Linux 6 种免杀上线命令变体（PowerShell -enc、BITS、HttpClient、certutil、bitsadmin、curl.exe / curl-wget、wget、busybox、python3、规避 noexec、setsid）。

### 🧰 C 植入端工具链探测（issue #6）
- mingw gcc 探测改为「配置 → 环境变量 → 服务端同目录便携工具链 → 常见安装目录 → PATH → **Windows 注册表 PATH**」逐级查找，并用 `gcc -dumpmachine` 校验目标架构；解决「gcc 已加入系统环境变量但服务端仍显示无 gcc」（进程环境是旧快照）与「32 位 gcc 静默编译 amd64」两个问题。
- 新增配置项 `builder.mingw_gcc_path`；garble 可用性改为一次极小真实构建探测（此前只查 PATH，会出现「显示可用但构建必失败」）。

### 🎛 前端可读性
- 屏幕流参数面板在中文名后标出接口字段名（`fps` / `quality` / `max_kbps` / `monitor` / `max_width`），并补范围与悬浮说明，避免"只有一个中文名不知道对应哪个参数"。
- 杀软对抗页 BYOVD 区块重排为「驱动说明 / 内置驱动一键加载与卸载 / 驱动击杀 / 自定义 .sys 上传」四段式，驱动信息（设备、服务名、IOCTL、SHA-256、签名者）来自 `/drivers` 接口，不再把长说明挤在一行。

### 🔢 版本
- 全量版本号更新为 **1.3.3**（服务端 `-version`、Web、About、README、USAGE、部署脚本、打包脚本、CDN 指南），CI 的 `main.version` 改为跟随 tag（`${GITHUB_REF_NAME#v}`），避免每次发版手改 workflow。

### 🚀 一键部署脚本（发布包自带）
- 新增 **`install.ps1`（Windows）/ `install.sh`（Linux、macOS）**；`deploy.bat` / `deploy.sh` 变为调用它们的入口（双击 `deploy.bat` 即可，不用记参数）：
  1. **环境检测**：服务端二进制（并打印 `-version`）、配置文件（缺失自动生成）、`data/` 可写、磁盘剩余空间、**控制台端口与监听端口占用**（正确区分 `listener.port` 与 `database.port`）、Go 工具链版本、`GOPROXY` 可达性、UPX（随包自带）、garble、mingw gcc（含 32/64 位提示）；
  2. **按需在线安装**：Go 缺失或过旧时从 go.dev 官方源下载并**校验官方 SHA-256**，解压到 `./.tools/go`（Windows 为 `%LOCALAPPDATA%\ToShell\tools`）并写入 PATH；`-WithGarble` 装 garble；`-WithMingw` 在 Windows 上尝试用 winget/choco 装 MSYS2/MinGW；`-OpenFirewall` 用 netsh 放行端口（需管理员）；
  3. 末尾给出「通过 / 警告 / 失败」汇总与「必须处理 / 建议处理」清单，随后可直接启动服务端并打印控制台地址。
- 安全设计：默认**不改动系统**（每步询问，`-Check` 只检测）；所有在线下载均做 SHA-256 校验，失败即删除并报错；脚本以 UTF-8 BOM 存盘，避免 PowerShell 5.1 按 ANSI 解析导致乱码/语法错误。

### 📦 发布包修正
- **移除包内残留的 `RTCore64.sys`**：v1.3.3 首次打包时 `release/drivers/RTCore64.sys`（git 跟踪的另一份副本）仍被 CI 打进 zip，与「删除 RTCore64」目标不符；现已删除，改为随包提供内置驱动 `kgameprotect.sys` 副本 + `release/drivers/README.md`（写明 SHA-256、签名者、设备名、IOCTL 与离线复核命令），便于操作员加载前自行核对。
- CI 与本地 `scripts/package_release.ps1` 同步：`install.sh` / `install.ps1` 一并打进包。

### ⚖️ 开源许可补齐
- 补回丢失的 **`LICENSE`（MIT）**：README 一直标注并链接 `LICENSE`，但仓库里没有该文件（链接 404、GitHub 侧识别不到许可）。现补回**纯净的 MIT 全文**（不掺别的文字，保证 GitHub 正确识别为 MIT），README 加 MIT 徽章；授权使用声明单独放在新增的 **`DISCLAIMER.md`**（中英双语：仅限授权测试/红队演练/自建实验环境，禁止未授权用途）。
- 新增 **`THIRD-PARTY-NOTICES.md`**：集中声明发布包内**不受 MIT 覆盖**的第三方组件——**UPX**（GPL-2.0-or-later + 压缩产物例外，`COPYING`/`LICENSE` 已随包放在 `upx/` 目录内）、内置 **`kgameprotect.sys`**（第三方 WHQL 签名驱动，版权归原权利人，附哈希/来源/移除承诺）、Go 模块依赖清单（BSD/MIT/EPL 等）与 `data/` 数据说明；并说明 `RTCore64.sys`/`dbutil_2_3.sys` 自 v1.3.3 起不再捆绑。
- CI 与 `scripts/package_release.ps1` 把 `LICENSE` 与 `THIRD-PARTY-NOTICES.md` 一并打进发布包（此前 zip 内含 UPX 却没有任何许可文本）。
### 📮 联系方式
- README 新增「联系方式 / Contact」：作者、GitHub、邮箱 **qingshan@88.com**、Issue 入口与安全/滥用报告渠道（并说明"使用问题先提 Issue、商务合作与漏洞披露走邮件"）；顶部信息行补邮箱。
- `SECURITY.md` 的报告渠道具体化：邮箱 + GitHub Security Advisories 私密报告入口，并说明建议附上的材料（影响版本/复现要点/影响面/披露时间线）。
- `USAGE.md` 新增「七、联系方式与支持」（原免责声明顺延为八），发布包内的 `release/README.md` 也补了联系表（用户实际先看到的是包内 README）。
### ✅ 实测验收（本轮已跑过的真实验证）
- **会话抖动**：60s 心跳（jitter 5s）的植入端连续运行 220s → 状态**零抖动**；杀掉植入端后按 3m1s（3 倍间隔）判死并只广播一次 `session_offline`；启动日志可见 `Session heartbeat timeout: 3m0s (implant interval 1m0s, margin 3x)`。
- **屏幕流/截图**：`max_width=640` → 640×360 JPEG 约 21KB（原始 2560×1440 约 343KB）；`monitor=1` 单选显示器生效；屏幕流回执确认 `fps=5 quality=60 max_kbps=1200` 已下发且 WS 侧可见真实 JPEG 帧。
- **内存执行 EXE 带参**：反射执行测试 PE 后其 `argv` 为 `["tool.exe","mem-hello","42"]`（`argc=3`）——参数注入生效；32 位 PE 注入 64 位植入体被明确拒绝。
- **webhook**：真植入端上线触发通知，假飞书收到 `{"msg_type":"text","content":{...}}` 返回 `code=0`；同一地址强发旧通用 JSON 时被正确判为失败并显示 `19002` 原因。
- **驱动**：`kgameprotect.sys` 本地复算 SHA-256 与 LOLDrivers PR #428 记录一致、`Get-AuthenticodeSignature` 为 **Valid**（Microsoft Windows Hardware Compatibility Publisher / WHQL）；`/api/v1/drivers` 返回 `purpose=kill, device=\\.\kgameprotect, ioctl=0x222048`。
- **模板构建矩阵**：变更后 windows/amd64 full、windows/amd64 light、linux/amd64 full 三档均构建成功；`internal/server/builder/implant` 与 `release/implant` 全量模板 MD5 一致。

### ⚠️ 本轮已知边界（未修，已列入 ROADMAP P0）
- `exe_mem` 下**载荷自行退出会带走植入体**（载荷 CRT 内部调用 `ExitProcess` 拦不住）；**Go 编译的载荷不能这样跑**（双 runtime 冲突）；内存执行不重定向 stdout。
- BYOVD 换成 kgameprotect 后**失去任意内核读写**，**PPL 保护进程杀不掉**（`ppl_kill` 仅剩句柄窃取路线）。
- 本机 AV 会拦截新编译的 **386 位 Go 载荷**（换文件名亦然），32 位链路未能本机实测。
- garble 与 Go 版本不兼容（garble v0.16 要求 Go ≥ 1.26，本机 go1.25.0），混淆选项在升级 Go 前不可用（界面已如实提示）。
- **未在本机加载内核驱动**：驱动加载与真实击杀由操作员在授权环境实测。

## [v1.3.2] - 2026-09-14

重点：Web 控制台防资产测绘、配置写入可靠性、跨平台载荷构建修复（对应 issue #1 / #2）。

### 🛡 Web 控制台防资产测绘（issue #1）
- **基础认证前置门槛**：新增 `web.*` 配置（`basic_auth_enabled` / `basic_auth_user` / `basic_auth_password`(bcrypt) / `unauth_mode` / `decoy_title` / `allow_cidrs`），在控制台与全部管理 API 前加一道认证，阻止 Fofa/Quake/Hunter 等测绘引擎抓取收录；设置页「安全 → 防资产测绘」可视化配置，保存即热生效。
- **未认证响应双模式**：`basic` = 401 + 认证挑战（浏览器弹框，前端照常可用，默认）；`disguise` = 纯 404 伪装（不泄露任何 C2 特征）。
- **隐蔽入口**：disguise 模式下浏览器无法弹认证框（服务端不返回 401 挑战，且浏览器不会把 URL 内嵌凭据带到 JS/CSS 子资源请求），新增 `GET /__gate`：
  - `/__gate?k=<stealth_key>` 带密钥直接进入（可书签，无需输入）；
  - `/__gate` 返回 401 挑战，浏览器弹框输入控制台凭据即可进入；
  - 两者都只种下 HttpOnly 入口 Cookie（30 天），之后前端与 API 凭 Cookie 通行；`/` 与其他任何路径依旧 404 伪装。
- **不破坏业务**：植入端 `/api/v1/implant/*`（注册/心跳/结果/一条命令上线载荷/UAC 一次性载荷）完全豁免；已持有 API Key / JWT 的脚本、AI 副驾驶与 MCP 调用继续放行；C2 监听器端口不受影响。
- 附带加固：`/api/v1/health` 纳入防护（原先 200 响应是测绘指纹）、`robots.txt` 拒绝收录、入口密钥用 hex 生成（base64 的 `+` `/` 放进 URL 查询串会被解析坏）。

### ⚙️ 配置写入可靠性（issue #2 第一部分）
- **原子写 + 读-改-写**：配置保存改为 YAML 节点树「只改目标 key → 同目录临时文件 fsync → rename 原子替换」，不再使用 `viper.WriteConfig()`。修复点：不再丢字段、**不再抹掉手工维护的注释与字段顺序**、写入中途中断不会损坏配置。
- **凭据必须落盘**：首次启动生成的 admin 密码 / JWT key / 监听加密 key 若写入失败，将**直接终止启动并打印配置路径**（此前只打 WARNING 继续运行，导致每次重启都重新生成随机密码 → 用户被永久锁在门外）；配置文件不存在时自动创建（含父目录）。
- 启动日志打印实际使用的配置路径，避免"改了 A 文件、服务端读的是 B 文件"这类排查困难。
- 修复设置页保存破坏 API Key 的事故：前端脱敏回显值（`Qing****2026`）曾被当作新密钥整组写回，现前端不再回传该字段、后端忽略含 `****` 的条目。
- 测试新增 14 项（auth 10 + config 4：伪装/挑战/凭据/植入端豁免/API Key 放行/CIDR/入口 Cookie、注释保留、缺文件创建、示例文件保护）。

### 🔧 跨平台载荷构建修复（issue #2 第二部分）
- **非 Windows full 档构建失败**：`stompShellcode` 仅存在 `windows && !light` 与 `light` 两个实现，macOS/Linux 的 full 档报 `undefined: stompShellcode`；补 `!windows && !light` 空实现。
- **非 Windows light 档编译失败**：`features_unix.go` / `injection_unix.go` / `screen_stream_unix.go` 构建标签只写了 `!windows`，与 `features_stub_light.go` 重复定义；补齐 `&& !light`。
- 实测验收：`{windows,linux,darwin} × {amd64,arm64} × {full,light}` 构建矩阵全部通过（此前仅 Windows 可用）。

### 🧪 工程
- 新增本地打包脚本 `scripts/package_release.ps1`（复刻 CI 布局，输出 6 平台 zip）；CI `-ldflags` 版本号同步。

## [v1.3.1] - 2026-09-08

重点：Agent 执行可靠性重构、会话实时事件推送、Web 控制台体验优化。

### 🤖 Agent 执行可靠性
- **全原子工具面**：命令/文件/进程/凭据/截屏/插件/内存加载等一次性工具全部原子化（服务端自动等待，一次调用直接返回最终结果）；agent 工具清单移除 `task_submit/task_result/task_wait/run_command`，杜绝编造 task_id 引发的 task not found 死循环。
- **信息收集收敛**：侦察/枚举类请求按固定清单一次收齐 → 命令级去重（同命令只下发一次，重复调用回放结果）→ 结构化情报报告收尾；不再重复刷命令、不再空转到轮数上限后只给工具清单。
- **建议/咨询类分流**：只要「建议/思路/方案」不执行时只做轻量取材（session_context/attack_suggest）直接输出可执行方案，不自动展开侦察链；会话在线状态只信工具返回值，不再臆断掉线。
- **短消息纯聊**：极短输入（如「1」「好」）走独立纯聊通道（无工具、token 封顶、一两句回应），不再触发长篇执行回复。
- **剧本 AI 建议补发**：剧本完成后的 AI 分析生成较慢或超限时先出兜底摘要，analysis 晚到仍会补发正式建议；服务端分析超时放宽至 90s。

### 🌐 Web 控制台
- **Agent 执行内联**：移除副驾驶页独立 Agent 状态条/计划面板，执行过程以带 icon 的日志行（🎯/🔧/✅/❌）内联进聊天气泡，随执行实时滚动并可随历史消息保存。
- **会话列表实时刷新**：TCP/HTTP/WS/MQTT/relay 监听器的上线/下线/复活统一广播 WS 事件，Sessions 页即时更新（此前仅 10s 轮询兜底）；副驾驶侧栏会话列表 10s 静默刷新。

### ⚙️ 稳定性 / 工程
- **植入端心跳隔离**：心跳改异步入队，绝不阻塞主读循环（消除长任务期间掉线/network error）；服务端心跳超时可配（`listener.heartbeat_timeout`），任务运行中按 busy 宽限 ×3 判活。
- **原子 exec 工具（TaskOrchestrator）**：下发命令由服务端统一创建→推送→等待→归位，结果与命令一一对应。
- **新增剧本** `capability-assess`（原子 exec 链快速评估目标能力）；新增 `scripts/smoke.sh` 核心链路冒烟回归脚本（release gate）。
- i18n：修复侧边栏缺失的 `nav.settings` 键；时间线/轨迹结构化展示与审计保留。

---

## [v1.3.0] - 2026-09-07

大版本：Agent 智能升级、安全加固、Web 多语言与 Agent 控制台、工程化与稳定性。

### 🧠 Agent 智能
- **目标驱动执行**：Agent 收到复杂/多步目标会先输出【执行计划】并逐步推进；run 记录 objective 与计划进度，跨消息保持（会话记忆续接）。
- **上下文压缩**：历史过长时保留 system + 最近 14 条，更早的工具结果折叠为一行摘要，防止长任务 token 爆炸。
- **动作审计**：每次工具调用写结构化日志（component=agent-audit：run/tool/args/成败），动作可追溯。
- （此前 v1.2.1 已具备：异步不阻塞、SSE 流式、连续记忆、自主提权闭环、失败刹车。）

### 🛡 安全加固
- **API Key 一键轮换**：设置页轮换生成新密钥（仅一次性展示并复制），支持整组替换/删除/脱敏展示。
- **密钥环境变量覆盖**：`TOSHELL_AUTH_JWT_KEY` / `TOSHELL_AUTH_API_KEYS` / `TOSHELL_LISTENER_ENCRYPTION_KEY` / `TOSHELL_AI_API_KEY` 等可用环境变量注入敏感配置。
- 登录防爆破锁定（此前已具备：5 次失败锁 5 分钟）。

### 🌐 Web 多语言 + Agent 控制台
- **i18n（中/英）**：新增语言切换（顶栏与登录页），导航/侧栏/页头/登录页双语；字典可扩展。
- **Agent 控制台视图**：副驾驶页顶部显示当前 run 的目标、执行计划步骤与运行状态，任务结束自动收起。
- 浅色主题（此前已具备的 CSS 变量与切换按钮保持可用）。

### ⚙️ 工程 / 稳定性
- **版本号升级至 v1.3.0**；README/USAGE/本文件同步。
- **CI**：`check-latest` 修正 Go 工具链；构建时 `-ldflags` 注入 `version/commit/buildTime`（`-version` 可溯源）。
- **任务幂等**：Complete/Fail 对已终态任务忽略重复结果帧，杜绝重连补发导致的重复副作用。

### 🧪 测试
- Agent 计划解析、上下文压缩单测；既有 SSRF/工具/状态机等测试全通过。

### ⏳ 未纳入 v1.3.0（规划 v1.4+，详见 [ROADMAP.md](ROADMAP.md)）
- 高阶红队能力（内网探测/端口扫描/共享枚举、PsExec/WMI 横向、NTLM PTH）**不做植入端内置**，改由服务端工具库 + 远程加载（`remote_download`→`plugin_load`/`fileless_exec`）实现，保持植入端轻量。
- 多 Agent 编排委派、Agent 分层记忆持久化到 sqlite、轨迹时间线回放面板。

## [v1.2.1] - 2026-08-28

本次更新的核心是把「指令式的 AI 副驾驶」升级为「真正自主的 Agent」，并配套一批任务执行稳定性的修复。

### ✨ 自主 Agent（新特性）

- **异步自主执行（不阻塞对话）**
  - 交代任务后立即返回 `run_id`，后台 goroutine 自主完成完整 ReAct 循环（侦察 → 行动 → 等结果 → 复盘）；
  - 支持**取消**、**并发上限**（`ai.agent_concurrency`，默认 2）、超出排队。

- **SSE 流式思考可见**
  - agent 的推理（reasoning_content）与每步工具执行，经 SSE 事件流实时推送前端；
  - 前端展示「思考中」、打字机光标、工具轨迹滚动。

- **连续上下文记忆**
  - 同一 agent 会话跨消息追加记忆（`session_id` 续接），agent 记住全部历史判断，能持续规划。

- **System 提示真正生效**
  - 修复此前 `RunAgent` 未注入系统提示的问题，现在注入完整角色 + 方法论（自主提权闭环、失败恢复、只输出结论与建议、联网搜索约定）。

- **只输出结论与建议**
  - 最终答复聚焦【现状】+【建议】+【为何】，不再大段堆砌原始结果；已执行步骤摘要优化。

- **审慎决策 + 失败刹车**
  - 提权等高风险操作**先评估后谨慎行动**，不再一提提权就无脑连发工具；
  - 工具连续失败 ≥3 次自动**强制收敛**，输出建议而非无限重试；
  - **严禁**对不存在/不匹配的工具执行内存注入（避免崩溃植入端）。

### 🛠 稳定性修复

- **任务结果乱序修复（`clearResultCache`）**
  - 根因：服务端重启后 task.ID 复用旧结果缓存，导致任务输出错位（如 `whoami` 返回 `systeminfo`）；
  - 修复：植入端每次重连清空结果缓存。

- **任务/命令超时保护**
  - 植入端所有任务（含重活 plugin_exe/BOF 等）强制超时（轻 90s / 重 180s），不再无限占住 worker，任务不卡在 `sent`。

- **串行防错乱**
  - agent 每轮**只执行一个工具**，结果与任务一一对应，不再并发串联。

- **task_wait 短路**
  - 等待不存在任务或会话离线时**立即返回错误**，不再空转到超时（避免 network error）。

- **前端轮询兜底**
  - 轮询 `status()` 作为可靠主路径，SSE 仅作实时增强；SSE 错误**静默**，不再覆盖已显示内容。

### ⚙️ 其它

- **启动随机延迟修复**：反沙箱延迟从 25s/15s + 0~20s 降到 5s/3s + 0~3s，默认 5~30 秒调为 2~10 秒，上线时间从约 50s 降到约 2s。
- **版本号升级至 v1.2.1**，README / USAGE 更新自主 Agent 说明与更新日志。

### 🧪 新增测试

- SSRF 防护（拒绝内网/回环/保留地址）
- 工具元数据推断（platform/arch/usage/kind）
- `isRiskyTool` 权限判定
- run 状态机、并发信号量

---

## [v1.2.0] - 2026-08-27
- AI 副驾驶（LLM ReAct，30+ 工具），自动注入在线会话上下文、连续编排「侦察→行动→等结果→复盘」；支持 Markdown 结构化输出。
- 权限模式与操作审批（全自动 / 正常模式，影响会话的操作执行前需用户确认，任务流除外）。
- 任务流（剧本）统一：副驾驶任务面板与「任务模板」页同源，可编辑/删除；一键执行跑完自动 AI 总结。
- 多通道监听（TCP / HTTP / WebSocket / MQTT），监听列表实时统计在线会话数。
