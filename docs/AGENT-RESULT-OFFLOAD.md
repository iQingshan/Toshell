# v1.4.0 S2 增量报告：内置 Agent 的长结果外置（统一信封 + 句柄内联 + 分页回读）

> 范围：只改后端 Go。未动 `web/**`、未动 `release/bin/**`、未动版本号、未动植入端模板、未 git commit。
> 所有改动留在工作区供审阅。

---

## ① 改了哪些文件（一句话说明）

新增 7 个文件、修改 8 个文件（另有一个 `internal/server/agentstore/store_test.go` 显示为已修改，
**不是本次改动**，见 ⑥-12）。

### 新增

| 文件 | 一句话 |
| --- | --- |
| `internal/server/mcp/inline_model.go` | 「工具结果 → 模型可见文本」的唯一实现：`ModelView` + `InlineForModel` + 截断预览（超限外置/显式标注/合法 JSON 保证） |
| `internal/server/mcp/inline_model_test.go` | 该转换点的纯函数单测（分档边界、外置失败、无存储、UTF-8 边界、分页往返、句柄穿越拒绝） |
| `internal/server/ai/toolargs.go` | LLM 工具参数解析修复：integer 参数不再因 `map[string]string` 类型不符而丢失 |
| `internal/server/ai/toolargs_test.go` | 参数解析单测（integer/数组/布尔/对象/null/截断 JSON/双层编码） |
| `internal/server/ai/tool_result_view_test.go` | 转换点接线单测：句柄进 ToolTrace/SSE 事件、sha256 进索引、降级路径显式标注 |
| `internal/server/api/agent_results.go` | Agent 侧结果外置接线：存储构造、TTL GC、`result_read` 实现（回读页自适应收缩）、`agentstore.tool_results` 索引适配 |
| `internal/server/api/result_read_test.go` | 回读接口级单测（页必须塞进内联上限、分页往返、tail、穿越拒绝、缺句柄/无存储、任务输出不被截断） |

### 修改

| 文件 | 一句话 |
| --- | --- |
| `internal/server/mcp/registry_tools.go` | `result_read` 的描述与 `limit` 参数说明对齐新语义（服务端可能只回更小的一页，以 `length/next_offset` 为准） |
| `internal/server/ai/copilot.go` | Copilot 新增 `results/inlineLimit/resultIdx` 与 `SetResultStore/SetResultIndexer`、`resultRef/IndexedResult/ResultIndexer/toolResultView/withResultMeta/toolResultEvent`；**4 个执行点改走唯一转换点，删掉全部 8 处 `truncate(out, 4000)` 类硬截断**；`agentToolNames` 加入 `result_read`；`summarizeToolResult` 识别信封；上下文压缩标注「已压缩」 |
| `internal/server/ai/agent.go` | `ToolResult`（SSE 事件）新增 4 个可选字段 `handle/truncated/truncation_note/total_bytes`；`cachedExec` 增加 `View mcp.ModelView`（去重复用不再回放被截断的正文） |
| `internal/server/api/api.go` | `Server` 新增 `agentResults *mcp.ResultStore`；`New` 里构造存储 + 注入 Copilot + 启动 GC；新增 `mcp` import |
| `internal/server/api/handlers_copilot.go` | `ReconfigureCopilot` 重建 Copilot 时重新注入结果外置存储（否则热更新一次就静默降级） |
| `internal/server/api/handlers_mcp.go` | 新增 `result_read` 分支；**删掉 5 处任务输出字符串硬截断**（`task_result`/`task_wait`/`pushAndAwait`）改用 `taskOutput()` + `output_bytes`；`session_context` 增加 `recent_tasks_note` 说明「这里是 200 字符摘要」 |
| `cmd/server/main.go` | `apiServer.SetAgentStore(agentStore)`：把外置结果索引落到 `agentstore.tool_results`（句柄/sha256/TTL） |

---

## ② 新增的公开函数签名与语义

### mcp 包（新增）

```go
// 一次工具结果在模型上下文里的可见形态。
type ModelView struct {
	Text           string // 模型可见文本：未超限=原文；超限=统一信封 JSON（恒为合法 JSON）
	Truncated      bool   // 超限即 true（与是否成功外置无关）
	Handle         string // 外置句柄；空=未外置（必须靠 TruncationNote 说明原因）
	TotalBytes     int    // 原文总字节数
	ReturnedBytes  int    // 实际内联给模型的字节数
	TruncationNote string // 中文截断说明（未截断为空）
	SHA256         string // 原文摘要（仅超限时计算），供结果索引/事后核对
	Envelope       *Envelope // 外置成功时的信封（其余路径为 nil）
}

// 唯一转换点：纯函数，便于不依赖网络/LLM 单测。
func InlineForModel(tool, callID, raw string, store ResultWriter, inlineLimit int) ModelView
```

### ai 包（新增）

```go
func (c *Copilot) SetResultStore(store mcp.ResultWriter, inlineLimit int) // 注入外置存储与内联上限
func (c *Copilot) SetResultIndexer(idx ResultIndexer)                    // 注入结果索引（可空）

type ResultIndexer interface { IndexToolResult(rec IndexedResult) error }

type IndexedResult struct {
	CorrelationID string // trace:call_id（结果索引的幂等键）
	RunID, Tool, Status, MediaType string
	BytesTotal int64
	SHA256     string
	Handle     string // 句柄（落 agentstore.Result.ExternalPath）
	Summary    string
	Truncated  bool
	PageSize   int
}
```

### api 包（新增）

```go
func (s *Server) SetAgentStore(st *agentstore.Store) // 启用 tool_results 索引落库（nil=只跳过索引）
```

### 内部（不导出）关键函数

| 函数 | 语义 |
| --- | --- |
| `(*Copilot).toolResultView(resultRef, raw) mcp.ModelView` | Agent 侧唯一转换入口：取存储/上限 → 调 `mcp.InlineForModel` → 外置成功时写结果索引（失败只告警） |
| `toolResultEvent(name, traceID, view, err) ToolResult` | 组装 SSE `tool_result` 事件，统一带上外置元信息 |
| `ToolTrace.withResultMeta(view) ToolTrace` | 把 handle/truncated/note/total 挂到轨迹（新增可选字段） |
| `(*Server).readResult(params) (interface{}, error)` | `result_read` 实现：handle/offset/limit/mode(slice\|tail)，页大小自适应 |
| `(*Server).startResultGC()` | 每 30 分钟 `ResultStore.GC()`（TTL + 容量上限）——`mcp.enabled=false` 时也生效 |
| `ai.toolArgs(raw string) map[string]string` | 工具参数解析（数字/布尔/数组/对象），修掉 integer 参数丢失 |

### 判定表：多大算大、超限怎么处理、句柄怎么给、模型怎么回读

内联上限来自配置 `mcp.inline_limit`（`viper` 默认 **8192 字节**，回落常量 `mcp.DefaultInlineLimit`）。
历史值是散落的 `truncate(out, 4000)` 字符硬截断——本增量把它换成**同一把尺子**。

| 情况 | 模型可见文本 | handle | 截断标注 | ToolTrace / SSE `tool_result` | 模型怎么回读 |
| --- | --- | --- | --- | --- | --- |
| `len(raw) ≤ 上限` | 原样（工具结果本就是 `json.Marshal` 产物） | 无 | 无 | `truncated=false`，无 handle | 不需要 |
| `> 上限`，存储可用且写成功 | **统一信封 JSON**：`data{summary,handle,total,read_tool}` + `meta{truncated,total_bytes,returned_bytes=0,truncation_note}`，**不内联任何正文** | `YYYYMMDD/<16~64位小写hex>` | `truncation_note` 明说「共 N 字节，已外置为句柄 H，需要细节请调用 result_read 按 offset/limit 分页回读」 | `handle/truncated/truncation_note/total_bytes` | `result_read(handle, offset, limit)` |
| `> 上限`，外置**失败**（磁盘/权限） | 信封 JSON，`data.truncated_preview` = 开头预览（**JSON 转义后的字符串字段**，因此信封一定合法） | 无（明确说明没有句柄） | `truncation_note` 说明「外置失败（原因），仅返回前 N 字节」 | 同上但 handle 为空 | 不能回读，说明里要求缩小输出范围重试 |
| `> 上限`，**未配置**存储 | 同上（预览 + 信封） | 无 | 说明「服务端未启用结果外置存储（mcp.result_dir 未配置或目录不可用）」 | 同上 | 不能回读 |
| `result_read` 的一页 | 页 JSON：`content/offset/length/total/has_more/next_offset/next_call/page_note/untrusted`；**整段序列化长度 ≤ 内联上限** | 原句柄 | 页被压小时给 `page_note` + `next_offset` | — | 按 `next_offset` 继续翻页直到 `has_more=false` |

**硬性质（本增量的核心）**：只要发生截断，模型拿到的文本一定是**合法 JSON**，且一定带显式说明；
能外置时一定给出可用句柄。再也不存在「字符串切片切出坏 JSON / 坏 base64」。

---

## ③ 关键取舍与理由

### 3.1 转换点放 `mcp` 包，而不是 `ai` 包

放 `internal/server/mcp/inline_model.go`（`InlineForModel`），理由：

1. **语义本来就归 mcp 包**：`Envelope.FinalizeInline` 定义信封形状、`resultstore.go` 定义句柄格式与分页口径、
   `registry_tools.go` 定义回读元工具。放别处会出现「两份外置语义」。
2. **依赖方向不允许反过来**：`mcp/server.go` 顶部明确写了「刻意不 import api/ai/config」以防循环依赖。
   转换点若放 ai 包，mcp/REST 想复用就得让 mcp 依赖 ai，方向就反了。
3. **三个消费方都会 import mcp**（内置 Agent 的 ai 包、REST 的 api 包、对外 MCP 的 mcp 包本身），
   放这里才能做到「同一个 `inline_limit`、同一套句柄、同一段截断文案」。
4. `ai` 侧只留一层薄壳 `(*Copilot).toolResultView`：取本实例的存储/上限 + 写结果索引 + 回传元信息，
   判定逻辑一行都不重复。

对外 MCP 路径（`handleToolsCall` → `FinalizeInline`）**保持原样不动**：它的语义已被 `scripts/mcp_smoke.ps1`
钉住（18 项检查），本次不去动它，避免把 MCP 侧信封语义改坏。两条路径共享同一个 mcp 包的定义。

### 3.2 「超限就外置」而不是「把上限调大」

- 截图结果是 `{"image":"<base64>","format":"png"}`，动辄数百 KB～数 MB。把上限从 4000 抬到 8 KiB
  只是把「切在中间」的位置往后挪，治不了本；正确做法是外置 + 摘要 + 显式告知 + 可回读。
- 省 token：长结果只注入**一次**摘要，后续轮次不会把同一段长输出反复灌进上下文。
- 上限取值 8 KiB（`mcp.inline_limit` 默认）：足够覆盖会话列表/单条命令输出这类「模型直接就能用」的结果；
  再大就该让模型自己决定读哪一段（`result_read` 支持按 offset/limit/tail 精确定位）。

### 3.3 无存储/外置失败时**不做** `raw[:limit]` 字符串切片

`Envelope.FinalizeInline` 在无存储时会退化成 `Data = raw[:limit]`（对 REST/MCP 消费方无害，因为外层仍是合法 JSON）。
但把它当「模型可见文本」就会重演历史 bug。因此 `InlineForModel` 在这两条降级路径上**自己构造信封**：
预览作为**字符串字段**放进 `data.truncated_preview`，由 `json.Marshal` 负责转义 —— 外层一定是合法 JSON，
且 `truncation_note` 说明「这是开头预览，不是全部，也没有句柄」。另外预览按 UTF-8 字符边界回退，
避免半个汉字被替换成 U+FFFD。

### 3.4 `result_read` 的页大小自适应收缩（回读闭环的真正难点）

回读出来的内容同样要进模型上下文。若这一页超过内联上限，转换层会把它**再次外置**，
模型拿到「句柄套句柄」——再读又超限，可能自锁（尤其 `limit` 取文档默认 256 KiB 时必然发生）。
所以 `readResult` 保证：**响应 JSON 序列化后的长度 ≤ 内联上限**。

实现：先按 `min(请求 limit, 256 KiB, 内联上限)` 读，再按**实测序列化长度**回缩（0.75 安全系数，
兼顾 JSON 转义最坏约 6 倍膨胀），最多 24 轮；回缩后重算 `offset/length/has_more/next_offset` 并写 `page_note`。
代价：REST 侧 `result_read` 单页从「最多 256 KiB」变成「约 8 KiB 一页」——这是**有意的**，
页大小是服务端策略而不是调用方承诺，注册表描述已同步改成「一律以返回的 `length/total/next_offset` 为准」。
（对外 MCP 客户端读大结果的正路仍是 `resources/read`，不受影响。）

### 3.5 存储与 `mcp.enabled` 解耦

`mcp.enabled` 默认 false。若把 Agent 的外置挂在对外 MCP 服务端实例上，默认配置下「外置 + 回读」整条链就是断的。
因此 api 侧**独立**构造指向同一目录（`mcp.result_dir`）+ 同 TTL（`mcp.result_ttl`）的 `ResultStore`：
两实例读写同一批文件、句柄格式一致，谁先写都能被另一方读到；同时补上 api 侧 30 分钟一次的 GC
（原来只有 MCP 服务端后台循环调 `GC()`，默认配置下结果目录会无限增长）。

### 3.6 顺手修掉「integer 参数被丢弃」（否则分页回读根本翻不动页）

`result_read` 的 `offset/limit` 在 schema 里是 integer，模型会按 JSON 数字给（`{"offset":8192}`）。
历史实现 `json.Unmarshal(args, &map[string]string)` 遇到数字会返回 `UnmarshalTypeError`，
而调用点 `_ = ` 丢掉了错误 → **该字段直接丢失** → `offset` 恒为 0 → 模型永远只能读第一页。
`pid`/`task_id`/`timeout_sec`/`wait_ms`/`local_port` 同样受影响（既有 bug）。
新增 `ai.toolArgs` 按 `mcp.buildArgs` 的口径统一转换（数字取最短十进制、布尔、数组逗号连接、对象 JSON、null 视为未提供）。

---

## ④ 校验命令与结果（实际输出）

```powershell
$env:CGO_ENABLED='0'

> go build ./...
（无输出，exit 0）

> go vet ./internal/server/... ./cmd/server/
（无输出，exit 0）

> gofmt -l <本次改动的 13 个文件>
（无输出 —— 全部已格式化）

> go vet ./...        # 仅供参考，见 ⑤
FAIL：internal/implant/injection/process_hollowing.go:75  uintptr(buffer[4]) (32 bits) too small for shift of 32
      internal/implant/bof.go:144  possible misuse of unsafe.Pointer
      …（均为 windows/386 下既有问题，与本次改动无关的文件）
```

**`_test.go` 也会被类型检查**（用「临时插入未定义符号再回滚」确认，这是本机不跑 `go test` 的替代手段）：

```
# 注入 var _ = undefinedSymbolForTypeCheck 后：
> go vet ./internal/server/mcp/ ./internal/server/api/
vet.exe: internal\server\mcp\inline_model_test.go:234:9: undefined: undefinedSymbolForTypeCheck
vet.exe: internal\server\api\result_read_test.go:245:9: undefined: undefinedSymbolForTypeCheck

> go vet ./internal/server/ai/
vet.exe: internal\server\ai\tool_result_view_test.go:245:9: undefined: undefinedSymbolForTypeCheck

# 回滚后：
> go vet ./internal/server/mcp/ ./internal/server/api/ ./internal/server/ai/ ./cmd/server/
exit 0
```

**植入端模板一致性核对**（结论：无需改动，两份仍然逐字节一致）：

```powershell
> 对 internal\server\builder\implant 与 release\implant 逐文件比对 SHA-256（61 个文件）
IDENTICAL (all files match by SHA-256)
```

**MCP 冒烟兼容性（静态核对，未执行脚本）**：注册表工具数仍为 38（`tools/list` 断言）、
`session_list` 信封形状未变、`resources/read` 与限流/鉴权路径未改；
`registry_tools.go` 只改了 `result_read` 的描述文本，未改工具集与参数名。

---

## ⑤ 未能验证的部分（如实列出）

1. **没有跑 `go test`**（本机 360 拦截新编译的测试 PE）。新增/扩展的单测只做到
   「`go vet` 类型检查通过 + 逐条人工推演期望值」；实际执行结果需在 CI 或放行环境确认。
2. **没有真实 LLM 端到端**：无法验证模型是否会按 `truncation_note` 的指引去调 `result_read`、
   以及翻页到 `has_more=false`。提示词文案已尽量指令化（含 `next_offset`/`next_call`）。
3. **没有真实植入端/截图**：截图路径只做到「读代码定位 + 单测断言任务输出不被截断」。
   真实截图（含大分辨率 JPEG）落到外置目录、再被模型分页读回，需要一次实机验证。
4. **没有验证 `agentstore.tool_results` 的运行时写入**：schema 已确认由
   `database.go:161` 建好（`AgentSchemaStatements`），索引适配器的逻辑单测只覆盖「无 DB 时静默跳过」
   与「空 correlation_id 报错」；真实 sqlite 写入路径建议在 CI 的 agentstore 测试里补一条端到端断言
   （本机不能跑测试，所以未加需要 DB 的用例）。
5. **新字段的前端呈现未验证**（`web/**` 明确不在本次范围）：`ToolTrace.handle/truncated/truncation_note/total_bytes`
   与 SSE `tool_result` 的同名新字段都是**新增可选字段**，既有字段名/语义未动，序列化断言已在单测里钉住。
6. **`go vet ./...` 全仓库仍有既有失败**（`internal/implant/**` 在 windows/386 下的位移与 unsafe.Pointer 告警），
   与本次改动无关，未处理。
7. **热更新边界**：`mcp.inline_limit`/`result_dir` 改动仍需重启才生效（`api.Server.cfg` 不随
   `config.OnChange` 换新对象，MCP 服务端本身也是重启生效）。已在报告里说明，未扩大改动范围。

---

## ⑥ 发现的既有问题 / 与本次改动相关的坑

1. **`result_read` 之前只存在于注册表，没有实现**：`invokeTool` 里没有对应 case，落到
   `default: unknown tool`；`agentToolNames` 里也没有它。也就是说「超限结果外置」这件事
   在 S2 上一步之后**根本无法回读**（对外 MCP 客户端只能走 `resources/read`）。已补实现 + 加入 Agent 工具面。
2. **工具参数里的 integer 会被静默丢弃**（`map[string]string` + 忽略 `UnmarshalTypeError`）：
   影响 `pid`/`task_id`/`timeout_sec`/`wait_ms`/`local_port` 以及本次的 `offset`/`limit`。
   这是「分页回读翻不动页」的直接原因，已用 `ai.toolArgs` 修掉（口径与 `mcp.buildArgs` 对齐）。
3. **截图 base64 被截断成坏 JSON 的真实位置（服务端，不是植入端）**：
   - `internal/server/api/handlers_mcp.go` 的 `pushAndAwait` → `truncateStr(t.Output, 8000)`
     （`screenshot` 工具正是走 `pushAndAwait`），把 `{"image":"<base64>",…}` 的内层 JSON 切在中间；
   - `internal/server/api/handlers_mcp.go` 的 `task_result`/`task_wait` → `truncateStr(t.Output, 4000)`（同类问题）；
   - `internal/server/ai/copilot.go` 的 `truncate(out, 4000)` 再把外层 JSON 也切一刀。
   **植入端模板没有截断**：`screenshot_windows.go#handleScreenshot` 返回的是完整 `json.Marshal`
   结果（完整 base64），`sendResultPayload` → `sendPacketSync` 全程无截断，服务端
   `task.Manager.Complete` 也原样保存。因此**不需要改植入端**，`release/implant` 与
   `internal/server/builder/implant` 天然保持一致（已 SHA-256 核对：61 个文件全同）。
4. **`ResultStore.GC()` 只挂在对外 MCP 服务端的后台循环上**：`mcp.enabled=false`（默认）时无人 GC，
   而 Agent 一旦开始外置结果，目录会无限增长（TTL 与 512 MB 容量上限都失效）。已在 api 侧补 30 分钟 GC。
5. **`cachedExec.Brief` 写入后从未被读取**（dead field）。本次保留它不动，只加了真正要用的 `View`。
6. **`compressRunMessages` 用硬编码的 `"task_wait"` 去 summarize 所有工具消息**（形状猜测的隐患）。
   本次通过「信封优先」分支绕过了外部化结果的误摘要，并在折叠文本前加了「（历史结果已压缩为摘要）」
   标注，但那个硬编码本身仍未清理。
7. **`playbook.go` 还会硬截断步骤输出**（`truncate(out, 8000)`、`taskWaitOutputForAnalysis`）。
   它既进 AI 分析、又是 REST 可见的 `StepResult.Output`，改造会动到剧本 API 字段语义，
   故**留给下一个增量**（建议与「playbook 步骤结果也走外置句柄」一起做）。
8. **对外 MCP 路径调用 `result_read` 仍可能「句柄套句柄」**：`tools/call` 会把回读页再包一层信封，
   在极端情况下超过内联上限时该页会被外置一次。对 HTTP 客户端不构成自锁（可改用 `resources/read`，
   它直接读文件、不经过信封），但语义上不优雅；`resources/read` 才是 MCP 客户端的分页正道。
9. **`handlers_copilot.go` 对用户历史消息做 `m.Content[:4000]` 原始切片**（前端输入，不是工具结果）。
   与本增量无关，未改。
10. **`session_context.recent_tasks[].output` 仍是 200 字符**（列表摘要字段）。现在加了
    `recent_tasks_note` 显式说明「这是摘要不是完整输出」，不再算静默截断。
11. **`mcp.inline_limit` 热更新不生效**（`api.Server.cfg` 不换对象、MCP 服务端本身也需重启）。
    如果要支持热更新，正确做法是让 `applyResultStore` 从 `config.Get()` 读现值并在
    `SetOnConfigApplied` 里重注入；本次未做（避免扩大改动面）。
12. **工作区里 `internal/server/agentstore/store_test.go` 显示为已修改，且不是我的改动**
    （内容是给测试补 `t.Cleanup(close)` 以避免 Windows 下 `t.TempDir` 清理失败）。
    该文件与其他并行改动共用同一个工作区，提交时请勿误归到本次增量。


---

## 复核补充（主控复核，360 关闭后本机可跑测试）

本节覆盖上文"未验证"部分，全部为**实测**结果（同一工作区、同一份代码）。

1. **本机全量单测已跑通**：`go test ./...` → **12 个包全 ok、0 FAIL**
   （`common/crypto`、`server/{agentstore,ai,api,auth,avdetect,builder,config,drivers,mcp,session,webhook}`）。
   上文"本机 360 拦测试 PE，未跑 go test"的结论已作废（360 已关闭）。
2. **本次新增用例里发现 2 处不自洽，已修**（都不是产品缺陷，是"测试与实现口径不一致"）：
   - `TestToolResultViewDegradesExplicitly` 用 2.4 KB 样本去验"无存储时也必须标注截断"，
     但默认内联上限是 8 KiB —— 上限之内本就不该截断。样本改成 > 8 KiB，并加了
     "样本必须超过默认上限"的自检，避免这条用例将来变成永真。
   - `TestToolResultViewLargeExternalizesAndReports` 期望 `ToolTrace.Result` 等于模型可见文本，
     而 `withResultMeta` 只挂了元信息。已让 `withResultMeta` **同时**把 `Result` 对齐到
     `ModelView.Text`（并把"轨迹与上下文必须是同一份文本"写进注释），调用点的重复赋值随之冗余但无害。
3. **该增量的用例抓到一个真实 bug**：`result_read` 的 `mode=tail` 在"响应超限需要回缩"时
   取的是 `chunk[:target]`（这段尾巴的**开头**），"取末尾"语义丢失。
   已改为 tail 分支取 `chunk[len(chunk)-target:]`，`TestReadResultTailMode` 通过。
4. **端到端验证（真实服务端 + mock LLM 假服务，不接触真实模型/植入端/载荷）**：
   - 用 45 个假工具文件把 `tool_list` 撑到 **11814 字节**（> 8192 内联上限）→ 模型可见文本
     变成 **535 字节的合法 JSON 信封**（`meta.truncated=true` + `meta.handle` + `total_bytes`），
     上下文里不再出现原始正文；
   - mock 从**上一轮 tool 消息**里现取该句柄调 `result_read`（`mode=tail`）→ 回读 2000 字节，
     响应 2407 字节仍在 8192 以内（不会"句柄套句柄"）；**与磁盘外置文件逐字节一致**；
   - 三档循环语义回归通过：`off` + 重复 confirm 工具 → `loop_detected`（第 3 次调用前停止，
     只有 2 条轨迹）；`graded` + confirm 工具 → `awaiting_consent`（traces=0，未下发命令）；
     `off` + 只读工具打满轮次 → `max_turns`（6 轮）。
   - 复核脚本（本地沙箱，不入库）：`.tmp-verify/regress/{loop_regression.py,verify_offload.py}`。
5. **观察到但未改**：只读工具在防死循环里整体豁免，因此"同一 handle + 同一 offset 的
   `result_read` 被重复调用"不会触发 `loop_detected`，只能靠 `max_tool_calls`/`max_turns` 兜住。
   分页本身必须豁免（不同 offset 是正常行为），但"完全相同的只读调用"可以更细地区分——
   列入下一步增量，不在本次扩大改动面。