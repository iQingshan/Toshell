# v1.4.3 修复计划（只覆盖 3 个 open issue：#14 / #15 / #16）

> 全部在 **v1.4.3** 一次性解决，关闭的 issue 不处理。
> 每项给 2–3 个可选方案：**你回编号，我按你选的做**；没选的我不猜，按「推荐」那档执行。
> 下面所有「代码事实」都是在本仓库里核过的，不是凭印象写的。

---

## 1. #14 会话标题「内网IP」与实际不符（iBesokuse）

**现象**：列表里显示的是外网 IP，标题写「内网IP」；希望内外网都能看到。

**代码事实**
- `web/src/components/SessionTable.tsx:175` 表头 = 「内网IP」
- `:182` `const ip = session.remote_addr ? session.remote_addr.split(':')[0] : ''` → 渲染的是**服务端看到的对端地址**（多为外网 / NAT 后地址）
- 植入端上报的本机网卡 IP 在 `types.SessionInfo.IPAddresses`，目前只在详情页 `SessionDetail.tsx:520` 显示

| 方案 | 内容 | 工作量 | 代价 |
|---|---|---|---|
| **14-A** 最小 | 表头改「对端 IP」，只纠正语义，不新增信息 | 10 min | 用户想看的「内网 IP」还是没有 |
| **14-B** 推荐 | 列内双行：`对端 IP` + `内网 IP`（`ip_addresses[0]`，多网卡 hover 显示全量）；详情页两行分别标注「对端 IP（服务端视角）」「本机 IP（植入端上报）」 | 30 min | 列宽略增 |
| **14-C** | 14-B + 列显示模式开关（对端 / 内网 / 两者，存 localStorage，默认两者）+ 点击复制 IP | 1.5 h | 多一个设置项 |

**验收**：Windows 与 Linux 各一台真机会话，列表能同时看到两个不同 IP；老载荷无 `ip_addresses` 显示 `-`；`SessionTable.tsx:91` 的搜索索引带上新字段，搜索仍能按 IP 命中。

---

## 2. #16 隧道看不出是哪个会话建立的（iBesokuse）

**代码事实**
- 数据层有归属：`internal/server/tunnelstore/store.go:51-56` `Tunnel{ ID, SessionID, LocalPort, TargetAddr, ... }`
- 接口已返回：`handlers_tunnels.go:92`（列表项含 `session_id`）、`:196`（按 session_id 排序）
- 前端没渲染：`web/src/pages/Tunnels.tsx:411` 卡片 = `会话: {server.session_id.slice(0,16)}...`，`:463` 详情同样

| 方案 | 内容 | 工作量 | 代价 |
|---|---|---|---|
| **16-A** 纯前端 | Tunnels 页并取 `/api/v1/sessions` 建 `id → 主机名/用户` 映射，卡片标题 `主机名 · 用户`、副标题 `session_id`、点击跳会话详情；查不到显示「已下线」 | 2 h | 多一次接口请求，会话多时映射稍慢 |
| **16-B** 推荐 | 后端 enrich：列表每项追加 `session_host` / `session_user` / `session_alive`（**只增字段，旧的都不删**），前端直接用；带响应兼容单测 | 2 h | 要补一条接口测试 |
| **16-C** | 16-B + 按会话分组/过滤 + 已下线隧道整卡置灰提示 | 4 h | 列表交互变复杂 |

**验收**：两台不同主机会话各建一条隧道，列表直接看出主机名与用户；会话下线后该隧道卡显示「会话已下线」；老响应字段（`session_id` 等）保持不变。

---

## 3. #15 六个子诉求（soshunte）

### 3.1 上传多选 + 断点续传

**代码事实**
- 前端 `FileManager.tsx:825` `handleUploadFile(file)` **单文件**；`:833` 1 MB 分片；`:832` `upload_id = Date.now()-文件名-随机` → 每次新建，**无法续传**
- 服务端 `handlers_files.go:149` 按 1 MB 分片接收，暂存 `data/uploads/<session>/<upload_id>`，`upload_id` 已做 `/\:` 过滤

| 方案 | 内容 | 工作量 |
|---|---|---|
| **15a-A** | `<input multiple>` + 串行队列 + 每文件独立进度（复用现有进度 UI） | 0.5 天 |
| **15a-B** 推荐 | 15a-A + 真续传：`upload_id = sha1(文件名+大小+mtime)`；新增 `GET /sessions/{id}/files/upload/{upload_id}` 返回已收字节；前端从 offset 续；失败自动重试 3 次；刷新页面回来能接着传 | 1.5 天 |
| **15a-C** | 15a-B + 2 路并发 + 暂停/取消 + 服务端 24 h 过期分片清理 | 2.5 天 |

**验收**：一次选 5 个文件（含一个 200 MB）全部成功；传一半断网/刷新后续传从断点继续；`data/uploads` 不留过期分片。

### 3.2 载荷下载链接暴露面板入口（`http://x:18081/api/v1/implant/payload/build-xxx`）

**代码事实**：构建响应 `DownloadURL = /api/v1/implants/stored/<id>`（`handlers_builders.go:340`）；一条命令上线用的是 `/api/v1/implant/payload/<id>`，该路径**产品上就是免认证的**（`handlers_implant.go:38` 明确）。

| 方案 | 内容 | 工作量 |
|---|---|---|
| **15b-A** 推荐先做 | 短 TTL 签名：`?e=<unix>&s=<HMAC-SHA256(id|e|key)>`，默认 30 min，过期 410；面板与一条命令生成的链接自动带签名；`payload.require_signature` 可强制 | 0.5 天 |
| **15b-B** | 监听器端口托管 + 伪静态随机路径 `/<8位随机>/<随机文件名>`：由监听器直接下发字节，URL 里完全不出现面板入口与 `/api/v1`（类 vshell）；需改监听器路由 + 构建产物链接 + 文档 | 1.5 天 |
| **15b-C** | A + B 都做 | 2 天 |

**验收**：A —— 把链接放到 30 min 后再打开返回 410，带签名的仍能下；B —— `curl http://<监听器>:<端口>/<随机目录>/<随机名>` 直接拿到载荷，URL 里没有 `/api/v1`。

### 3.3 「点开之后马上一闪就没了」

**代码事实**：具体组件**尚未定位**（issue 里那两张截图我这边看不到内容）。已知有弹层的位置：Copilot 页（`web/src/pages/Copilot.tsx`）工具卡片、生成载荷页下拉、会话表格操作菜单。

| 方案 | 内容 | 工作量 |
|---|---|---|
| **15c-A** 兜底 | 所有弹层统一「打开后 300 ms 忽略外部点击」+ 外部点击判定改 `pointerdown` + 防父组件重渲染重挂 | 0.5 天 |
| **15c-B** 推荐 | 你给我「哪个页面、点什么按钮」，我定位到具体组件改，并补一条 UI 回归用例 | 0.5 天（含定位） |

**验收**：同一操作连点 20 次不闪；Esc / 点外部能正常关闭。

### 3.4 右侧栏改 tab（截图原话：「右边的栏目是否可以直接tab栏」）

**代码事实**：会话详情主区已有 `TAB_SPECS` + mount-and-hide + `sessionStorage` 记忆（`SessionDetail.tsx:58` 起）；右栏（会话信息卡）目前整块铺开。

| 方案 | 内容 | 工作量 |
|---|---|---|
| **15d-A** 推荐 | 右栏改 tab（信息 / 网络 / 备注 / AI 建议），复用主区 tab 机制与记忆键 | 0.5 天 |
| **15d-B** | 15d-A + 右栏整体折叠/展开（窄屏默认折叠） | 1 天 |

**验收**：1600×900 与 2560×1440 下切换 tab 主区高度不变（此前的「切 tab 变矮」回归不能再出现）；刷新后停原 tab。

### 3.5 AI 驾驶：一句话出载荷 + 免杀技术蒸馏

**代码事实**：agent 现有 **22 个工具**（`file_list` / `file_download` / `process_list` / `process_kill` / `screenshot` / `credentials` / `session_kill` / `plugin_load` / `tunnel_start` / `tunnel_stop` / `user_info` / `system_info` / `service_list` / `check_av` / `net_info` / `net_connections` / `env_vars` / `scheduled_tasks` / `delegate` / `task_wait` / `session_list` / `intel_query`），**没有 build_payload**；工具 schema 在 `copilot.go:2250 toolSchemas()`，有覆盖测试 `tool_schema_test.go`。

| 方案 | 内容 | 工作量 |
|---|---|---|
| **15e-A** 推荐 | 新增 `payload_build` 工具（参数：监听器/协议、os/arch、档位、输出名、server_url 可省），返回下载链接 + 体积 + 免杀自查项 | 1 天 |
| **15e-B** | 15e-A + 把 `EVASION.md` / `LOADERS.md` 摘成 playbook 条目（`internal/server/ai/playbook.go` 已有机制），AI 回答免杀问题时给「选项 + 代价」 | 1.5 天 |
| **15e-C** | 15e-B + 构建随机化（PE 时间戳/资源/字符串种子/编译标志随机组合），同一目标每次产物不同；**只承诺特征不重复 + 有自查**，不承诺真正免杀 | 4.5 天 |

**验收**：在 Copilot 里说「给 192.168.1.28:18080 出个 linux amd64 载荷」，得到真实构建 + 可下载链接 + 体积；构建失败给可读原因（不是 500）。

### 3.6 不稳定：vshell 在线、toshell 掉线 / 卡住

**代码事实**：判活已有 `observedInterval` 平滑 + `BusyUntil` 忙期放宽（session 包）；任务侧有 `agent_runs` 对账；**缺**卡死自愈与队列可观测。

| 方案 | 内容 | 工作量 |
|---|---|---|
| **15f-A** | 可观测：`/api/v1/health` 增每会话「最后心跳 / 最后任务回传 / 待发任务数 / 最近错误」；日志把卡点分段（取任务 / 回传结果 / 解压 / 写库） | 0.5 天 |
| **15f-B** 推荐 | 15f-A + 看门狗自愈：超阈值（默认 3×observedInterval）下发 re-register 重建会话；连续 N 次失败标 dead 并在 UI 提示 | 1 天 |
| **15f-C** | 15f-B + 双超时策略可配（心跳 / 任务回传分开）并在设置页暴露 | 1.5 天 |

**验收**：杀掉植入端进程，UI 在阈值内变 dead（不卡在 online）；构造「任务不回传」场景，看门狗重建会话并记录原因；日志一眼看出卡在哪段。

---

## 4. Agent（AI 副驾驶）优化 —— 与 3.5 同批做

现状已核：`TokenBudget` / 折叠摘要 / 截断标注在 `context.go`；事件 ring + resync 在 `agent_event_ring.go`；`Cancel()` 在 `agent.go:762`；并发上限 `NewAgentManager(maxConcurrent)`。

| 编号 | 内容 | 工作量 |
|---|---|---|
| **D1** | 工具面补齐：隧道归属查询（配合 #16）、文件分片上传、`payload_build`（3.5）、批量会话操作（一次对多会话下同一命令） | 0.5 天 |
| **D2** | 上下文预算可见：把 budget / 超预算收口原因显示到面板（现在只有后端 `stop_reason`）；工具结果超限时明确提示「用 `result_read` 分页回读」 | 0.5 天 |
| **D3** | 事件流断线重连：前端 SSE 断开自动 resync，并显示丢弃事件计数（ring 已有快照能力） | 0.5 天 |
| **D4** | 并发与串行：同一会话的 run 串行化（避免两个 run 抢同一会话任务）；并发满时显示排队位置 | 0.5 天 |
| **D5** | 失败可见性：LLM 错误分类（405 / 超时 / 参数不符 / 余额），并给「切到 DeepSeek 模板」的一键建议 | 0.5 天 |
| **D6** | Copilot 面板稳定性：流式渲染不闪烁、错误可复制、停止/继续状态明确（与 3.3 合并做） | 0.5 天 |

---

## 5. 执行顺序（同一版本 v1.4.3）

| 批次 | 内容 | 说明 |
|---|---|---|
| 1 | #14-B、#16-B、#15d-A | 纯展示层，先出可见效果 |
| 2 | #15b-A、#15f-A/B、D2 | 安全与稳定性，改动集中在服务端 |
| 3 | #15a-B、#15e-A/B、D1/D3/D4/D5、#15c | 功能与 agent 能力 |
| 4 | 可选档：15a-C、15b-B、15e-C、15d-B、15f-C | 你要就做，不做不影响前三批 |
| 5 | 打包 | `go build ./...` → `go vet`（改动包）→ `go test ./...`（26 包）→ `scripts/e2e_smoke.ps1` → CI 绿 → tag `v1.4.3` → 6 平台 zip |

工作量：批次 1–3 + D 组 ≈ **6–7 天**；含全部可选项 ≈ **12 天**。

---

## 6. 请你回这几个选择（回编号即可）

1. **#14**：14-A / **14-B** / 14-C
2. **#16**：16-A / **16-B** / 16-C
3. **#15**：
   - 3.1 上传：**15a-A** / 15a-B / 15a-C
   - 3.2 载荷链接：**15b-A** / 15b-B / 15b-C
   - 3.3 弹层：15c-A / **15c-B**（需你补页面 + 按钮）
   - 3.4 右栏：**15d-A** / 15d-B
   - 3.5 AI 驾驶：**15e-A** / 15e-B / 15e-C
   - 3.6 掉线：15f-A / **15f-B** / 15f-C
4. **Agent**：D1–D6 全做 / 只做 D1+D2+D5 / 其他组合

> 加粗的是我建议的默认档；你要全都要最重的档我也照做，只是时间按上表走。
