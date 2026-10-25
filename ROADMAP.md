# ToShell 后续路线（ROADMAP）

> **当前版本：v1.4.2（安全修复版）** · **基线版本：v1.4.0（2026-09-28 已发布，tag 不动）**
> 本文只回答三件事：**现在做到哪、下一步做什么、什么明确不做**。每条只保留「代码事实 / 剩余项 / 验收口径」，不重复发版日志（细节见 [CHANGELOG.md](CHANGELOG.md)）。
> 配套文档：[docs/EVASION.md](docs/EVASION.md)（免杀实现与验证状态）、[docs/LOADERS.md](docs/LOADERS.md)（不落地未签名 PE 的落地链）、[docs/DEPLOY-DOMAIN-CDN.md](docs/DEPLOY-DOMAIN-CDN.md)（域名/CDN/域前置）、[docs/VSHELL-ANALYSIS.md](docs/VSHELL-ANALYSIS.md)（第三方参考实现分析）。

**状态取值只有 5 个，不许含糊**：

| 取值 | 含义 | 证据要求 |
|---|---|---|
| ✅ 完成 | 已实现且**有实测或测试证据** | 能指到测试名/脚本输出/真机记录 |
| 🟡 部分完成 | 主体做了，子项未做 | 未做子项必须写在同一行"剩余什么"里 |
| ⚠️ 已实现未验证 | 代码在里面，但**没有真机/真实链路验证** | 必须写明"缺哪种验证" |
| ❌ 未开工 | 无代码或无可用实现 | 允许写"只有骨架/stub" |
| 🚫 已定论不做 | 有明确理由的取舍 | 必须附依据（实测数字或工程判断） |

> **口径纪律**：本文件与 CHANGELOG **不得出现"完全免杀""绕过所有 EDR""100% 免杀"**这类表述。v1.4.0 之前的所有"免杀已生效"结论都**只有静态/结构级证据**——在拿到目标机放行环境之前，不得升级为运行期结论。

---

## 定位与不做什么

**ToShell 是什么**：自托管的授权红队 C2 —— Go team server（单二进制，内嵌 React 控制台）+ 多通道多平台植入端（Go 为主、C 为辅）+ 内存模块体系（`exec_module`）+ 开放自动化接口（MCP / REST）。MIT 许可，**代码可审计**。

**服务对象**：授权范围内的红队演练、内网横向验证、EDR/蓝队检测能力评估、安全教学实验。

### 明确的边界（写在最前面，避免被误读成承诺）

| 不做 | 理由 |
|---|---|
| 🚫 **不做免杀产品** | 我们只做"降低特征 + 明确分级 + 如实标注验证状态"；**不承诺对抗任何具体 EDR/AV**。本机能跑通 ≠ 目标机不被拦（本机实测：未签名新 PE 在进程创建阶段即被拒，见 `docs/EVASION.md`） |
| 🚫 **不内置任何内核驱动 / 第三方二进制** | BYOVD 驱动由操作员自备并自负合规责任（`internal/server/drivers/verify*.go` 只做校验与选路）；`data/tools/` 只放自研脚本 |
| 🚫 **不做"原版对齐"** | 不追求与任何商用 C2 的协议/载荷互操作（详见 `docs/VSHELL-ANALYSIS.md` §0：无授权依据，且会把错误码体系绑死） |
| 🚫 **不做授权/许可门控** | MIT 全功能开源；不引入"校验失败静默降级"的 fail-open 路径 |
| 🚫 **不做品牌冒充外观** | `resource_preset="neutral"` 只填操作员没给的字段，**不预置"像系统组件"的公司名/产品名**（`internal/server/builder/patch_resources.go`） |
| 🚫 **不把未验证能力放进工具面** | 未验证的能力不得出现在 MCP/Agent 可自主调用的工具表里（S6 的两条守卫测试钉住 L1+ 不可达） |
| 🚫 **不做移动端/固件植入端** | Android/iOS 与 IoT 的威胁模型、体积约束、授权形态完全不同；投在这里会拖垮主线的可维护性 |

**授权红线**：仅限**明确书面授权**的目标；`DISCLAIMER.md` / `SECURITY.md` 的边界条款优先于本文任何功能描述。

---

## 版本节奏

| 版本 | 主题（一句话） | 时间感 | 出口条件（可验收） |
|---|---|---|---|
| **v1.4.1**（补丁，本轮交付） | **把"显示/可用性"层的真实缺陷修掉，不引入新能力** | 2026-10 | 本文「v1.4.1 登记」7 项全部落地；`go build ./...` / `go vet` / `go test ./...` 全绿；`scripts/e2e_smoke.ps1` 无 ❌ |
| **v1.5** | **实战化与工具互操作**（不集成工具、只给接口）：契约导出、CLI 薄壳、SOCKS 兼容、凭据/取证包导出、最小 RBAC、并发闸 | 2026-11 ~ 2026-12 | P1 清单前 4 项各有一条**验收脚本或真机记录**；新增能力全部进状态表；无"点了没反应"的入口 |
| **v1.6** | **第二植入端 + 冷门通道**：Rust 植入端（可行但为"第二形态"）、DNS/DoH 或 UDP 通道、L2/L3 真机验证 | 2027-Q1 | Rust 植入端能完成"上线 + 3 类任务 + 体积达标"；新通道端到端跑通一条；AV-Ops L2/L3 至少各一条真机记录 |
| **v2.0** | **生态化**：插件市场与签名、OpenAPI+SDK、多实例联邦、可验证对抗分级对外口径、AI 原生操作员 2.0 | 2027-Q2 起 | 5 条"护城河"各有一个**可度量里程碑**达成（见 §6.7） |

> **节奏纪律**：补丁版（v1.4.x）只修不扩；次要版本（v1.5/v1.6）必须自带验收脚本；主版本（v2.0）才允许做**破坏性 API 变更**（由 `api/v1` → `api/v2` 承载）。

---

## 状态总览

> 一行一个交付项。**"依据"列必须能指向代码或脚本**；本次已修正 4 处与代码不符的旧表述（见「技术债」末节 D1~D4）。

| 能力 | 状态 | 依据（代码 / 实测） | 剩余什么 |
|---|---|---|---|
| 会话判活 | ✅ | 阈值含 3 倍心跳余量 + 广播去抖（`internal/server/session/`，`liveness_test.go`）；实测 60s 心跳连跑 220s 零抖动 | 无 |
| 屏幕流 / 截图（Windows） | ✅ | GDI + PrintWindow 回退，参数化 fps/quality/max_kbps/monitor/max_width（`builder/implant/screen_stream_windows.go`、`api/screen_frame_limiter.go`） | 无 |
| 屏幕流 / 截图（Linux/macOS） | ❌ | `builder/implant/screen_stream_unix.go` 为 stub，直接返回 "only supported on Windows" | X11（Wayland 后续）/ ScreenCaptureKit；均需真机 |
| 内存执行（shellcode / BOF / DLL / EXE） | ✅ | 反射映射 + 参数注入 + 下发前 PE 预检（`builder/pecheck.go`、`handlers_fileless.go`） | 无 |
| 内存执行加固（宿主不掉线） | 🟡 | IAT 双层退出桩 + stdout/stderr 截流（`builder/implant/mexecguard_windows.go`）；真机 30s 全程 active、退出码 7、stdout 回传 | 仅 IAT 层（`GetProcAddress` 裸调拦不到）；无控制台时抓不到 stdout；`dll` 分支未真机；HTTP/WS/MQTT 与 amd64 未复测 |
| BYOVD 驱动（自备 + 档案 + 自检） | ✅ | 不内置驱动；`drivers/verify*.go` sha256 硬拦 + Authenticode + 黑名单提示 | 无 |
| 驱动体系（purpose 选路 / 残留台账 / catalog 签名声明） | 🟡 | `drivers/route.go`（purpose=kill/rw/both 纯函数选路）、`drivers/ledger.go` + `BuildCleanupPlan`（清场**指引**）、`drivers/signature.go`（声明↔实测一致性） | 清场是"给可照抄命令的指引"，**不是自动清场任务**；真实 `.sys` 加载未真机验证 |
| 代码签名（构建后 Authenticode） | 🟡 | pfx / 证书存储指纹双模式 + 签名后复核（`builder/sign.go`、`finalize_order.go`）；自签本机实测已签上 | **真实证书/EV 与目标机信任链未落地**（无材料） |
| 加载器链 | 🟡 | 8 条链的命令模板 + 降级顺序（`api/oneliner.go`、`docs/LOADERS.md`） | **无一条真机落地记录**；无 loader 源码/工程模板（见 P1-2） |
| 运行时行为足迹 | ✅ | 启动不枚举进程（`evasion_scan` 显式开启）、pclntab 中性化、BOF 默认不编译、Go 指纹擦除、启动延迟/心跳可配 | 无 |
| 动态免杀（sleep mask / 去 RWX / apihash / 直调） | ⚠️ | `builder/implant/sleepmask_*.go`、`memprotect_*.go`、`apihash_windows.go`、`directsyscall_windows_amd64*.go` | **运行期零实测**（本机杀软会删新生成 PE）；批次 2（C2 地址改 `[]byte`、ntdll 脱钩 + ETW patch）未开工 |
| uTLS / JA3（HTTP 通道） | ⚠️ | `builder/implant/transport_tls_utls.go`（`HelloChrome_102`，仅 `transport_http && !light`；依赖 `refraction-networking/utls v1.4.0`，见 `release/implant/go.mod`） | **未抓包验证 JA3**、未做真实 CDN 联调；WS 仍走标准库 TLS（`transport_ws.go`） |
| 流量拟态（HTTP 反代 / 响应整形） | 🟡 | `internal/server/mimicry`（cdn/api/stream 三套模板，`Shape` + `DecoyHandler`）+ `mimicry_site` 反代（`listener/http_polling.go`） | 仅 HTTP 监听器；**WS 的非 C2 路径只回 404、不反代**；无真机探测面复核 |
| WebSocket 探测面收敛 | ✅ | 只对 `listener.ws_path` 一条路径升级、变形路径一律普通 404、Host 名单 + `front_domain`（`common/transport/websocket.go` 的 `UpgradePolicy`） | 无（per-listener 覆盖属 v1.5 增强，不算本项未完成，见 T19） |
| 中继（Beacon Mesh） | ✅ | `listener/relay.go` 多跳（`maxRelayHops=16`）+ `TypeRelay` 帧路由；非 TCP 通道明确 409 | 中继节点无独立健康探测（见 P1-5） |
| 任务队列 / 状态机 | ✅ | `task.Manager` + 事件驱动等待 + 重连补发/禁自动重试（破坏性任务）+ 挂起恢复（`internal/server/task/`） | 无（入库截断 500 字节属独立债务，见 T13） |
| 文件传输（分块 + 断点） | ✅ | 1 MiB 分块 + offset 落盘 + `resume` 任务 + 进度（`listener/handler_core.go`、`task.TrackTransfer`） | 无 |
| 文件预览（后缀白名单 + 二次校验） | ✅ | `internal/common/preview`（分类/上限/二进制嗅探/图片魔数）+ `POST /sessions/{id}/files/preview` 二次校验 + `GET /files/preview-policy` 下发；前端 `previewPolicy.ts` + 弹窗确认 | 只覆盖"内联预览"，下载不受影响；>64 MB 直接 413；超大文本只回前 64 KB（植入端无 range 读取） |
| 代理认证（SOCKS5 / HTTP CONNECT） | ✅ | `internal/common/tunnel/auth.go`（RFC 1929 + `Proxy-Authorization` Basic，常量时间比较，HTTP 路径同样校验） | 认证在 **C2 侧监听器**，植入端只是 TCP 中继、不解析 SOCKS5；留空 = 无认证 |
| MCP（对外协议服务） | ✅ | `internal/server/mcp`：38 工具三档分级、JSONL 审计、RPM/并发/句柄三闸、默认关闭只绑回环（空 token 拒启动） | 无（工具面**故意**不含 `exec_module` 与 L1+ 动作；多客户端互操作冒烟属生态项，见 §6.1） |
| Agent 长任务可靠性 | ✅ | 4 张表 + `agentstore` + 事件驱动 + 长结果外置回读 + 四层上下文 + 双 token 预算 + SSE 断点续传（`internal/server/ai/`） | 无（两个已知缺陷已修，见下两行） |
| Agent 缺陷①（重复显示上一轮步骤） | ✅ | `09e3bbe`：`web/src/pages/agentRound.ts` 按轮次切 timeline + per-run SSE 水位线 | 无 |
| Agent 缺陷②（并行 `tool_calls` 丢失） | ✅ | `9c98599`：`RunAgent` 遍历全部声明项；回归用例 `ai/parallel_tool_calls_test.go` | 无 |
| 能力位图（载荷上报 → 标签/按钮） | ✅ | `internal/common/features` 唯一纯函数 + `cap:v1:<hex>` 随心跳上报；服务端 `Resolve()` 上报优先、老载荷按 OS 兜底 | 无 |
| `exec_module` 内存模块 | 🟡 | ABI v1（`common/moduleabi`）+ 一次性 token + 9 步校验链 + `TypeModuleData(0x0E)` | 只真机测过 **TCP**；单帧上限 4 MiB 无分块；未暴露给 MCP/Agent 工具面 |
| AV-Ops 分级（L0/L1） | ✅ | `common/avops` 表驱动 + 聚合入口 + 七步前置检查 + 审计 + 面板；L2+ 出厂关、禁自动重投递 | 无（L1 的 `allowed:false` 语义坑——区分"硬阻塞"与"需确认"——已修） |
| AV-Ops（L2/L3/L4） | 🟡 | L2/L3 的**被拒路径**已真机验证（缺 confirm→409、tier 不符→400、L2→403…且不产生任务）；L0 真实下发回传有记录 | **L2/L3 放行路径零实测**（需授权 VM + 操作员自备驱动）；L4 无任何落地动作（`implemented:false`，刻意不造假入口） |
| Web 控制台 | ✅ | 主题 token + 组件层 + 折叠分组 + 风险分级徽标 + 真实 `/health` 顶栏 + 数据驱动标签页 + AV-Ops 面板 | 移动端体验未评估（见 P3-6） |
| 发版门禁（CI 内） | ✅ | `release.yml` 的 `e2e-smoke` job 跑 `scripts/e2e_smoke.ps1 -SkipImplant`，发布 job `needs: [web, e2e-smoke]`；CI 另跑 build/vet/test | **托管 runner 固定 `-SkipImplant`**（无真实植入端上线），真机上线仍需本地跑 |
| 平台工具库 `data/tools/` | ❌ | 目录下只有 `.gitkeep`，无 manifest、无工具、无下载校验代码 | 目录规范 + manifest（sha256/来源/许可）+ 远程加载闭环（P2-3） |
| 第二植入端（Rust） | ❌ | 无代码；v1.4.1 已出可行性结论（见 P2-1） | 立项在 v1.6 |

---

## v1.4.1 登记（补丁版，本轮交付）

> 本批全部是**补丁级**改动：不加新协议、不动 `go.mod` 的 server 依赖、不改变对外错误码语义（新增错误码只增不改）。

| # | 项 | 类型 | 状态 | 依据 / 需求 | 验收口径 |
|---|---|---|---|---|---|
| 1 | **植入端 Rust 版本可行性评估** | 立项评估 | ✅ 已出结论（含实测体积） | 结论：**可行，作为"第二植入端"**；本机实测 `light` 等价物 **350,720 B**（Go 同形态 2,946,805 B，小 8.4 倍），`light+http` 走 SChannel 仅 **≈368 KB**（Go 5,455,613 B，小 14.8 倍）；工程量约 13,000~15,000 行 Rust，成本约为 Go 版的 60~70% | 结论入档 `docs/RUST-IMPLANT.md` + 探针入档 `docs/rust-probe/`；**立项排 v1.6**（P2-1），不在 v1.4.1 写产品代码 |
| 2 | **显示层修复**：Linux 会话用户名不再 `unknown`；杀软击杀回显、启动项回显的 GBK/CP936 乱码 | 缺陷修复 | ✅ 已完成（Linux 运行时未验证） | 根因：`builder/implant/platform_unix.go:13` 只读 `USER/USERNAME`，无登录环境（systemd / cron / `docker exec` / ssh 命令）为空 → `unknown`；乱码根因是 `builder/implant/main.go:1811`（旧）对**整串**输出做 GBK 转换，而回执是"UTF-8 中文 + GBK 工具输出"的混合串 | 已改：`implant/username.go`（环境链 → `/etc/passwd` → `uid:<n>`）、`platform_windows.go:274 decodeConsoleText`（逐行判 UTF-8，幂等）、`common/encoding/text.go` + `api/output_display.go`（服务端展示漏斗）；**原始结果字节不动**，另增 `GET /tasks/{id}?raw=1` 无损回读。前后对比证据见 CHANGELOG |
| 3 | **代理创建支持可选认证**（SOCKS5 RFC 1929） | 功能（小） | ✅ 已完成 | `common/tunnel/auth.go`：用户/口令 1~255 字节、禁控制字符、成对校验、常量时间比较；HTTP CONNECT 一并校验 `Proxy-Authorization`（否则 HTTP 路径绕过认证） | 不填认证 = 行为与 v1.4.0 一致（`[05 01 00]`→`05 00`）；填了 → 错口令 `01 01` / HTTP 407；**两条路径都拒绝**；口令不进日志、不回显 |
| 4 | **文件预览按后缀白名单限制** + 未识别后缀弹窗 + 后端二次校验 | 功能（小） | ✅ 已完成 | `internal/common/preview`：text/image/executable/archive/database/unknown + 阈值（文本 1 MiB、超大回 64 KiB 前缀、未知后缀强制预览 8 KiB、图片 2 MiB、源文件 64 MiB）；`GET /files/preview-policy` 下发清单 | 白名单外 415 且**不建任务**；未识别后缀 409 → 弹窗确认后才能前缀预览；**直接打 API 也拒**；截断显式标 `truncated`；`/files/transfer` 强制 `attachment + nosniff + CSP sandbox` |
| 5 | **Linux/amd64 植入端"秒断"** | 缺陷修复 | 🟡 部分（代码级缺陷已修；Linux 真机待验证） | 修掉两个真 bug：① `blob_unix.go` 标签与 light 档重复定义 → **linux+light 编译不过**；② 混淆器改写 `const` 字面量 → **全平台构建 500**。另新增构建期拦截 `listenerChannelMismatch`（协议与监听器通道不一致必然"连上即断"）与 `resolveTransport` 单一口径 | 已达成：两类编译失败消失、72 组 tag 矩阵测试、通道不一致构建时 400。**未达成**：本机无 Linux 运行时，"上线即 panic/被杀"证伪不了；需现场日志（`Implant registered` 是否有 / `Connection closed` 原因）才能定论 |
| 6 | **参考项目分析** `docs/VSHELL-ANALYSIS.md` | 文档 | ✅ 已完成 | 许可证结论：**未声明（README 徽章 All Rights Reserved，`license.txt` 缺失）→ 只吸收设计思想，不复制代码/资源/常量**；含 10 条借鉴、5 条不借鉴、3+3+3 净结论 | 文档入档；`vshell/` 不进 git、不进发布包 |
| 7 | **文档 / 路线图重写**（本文件 + README/CHANGELOG 口径对齐） | 文档 | ✅ 已完成 | 见本文「技术债」D1~D4 四处过期表述的修正 | 文档内每个 ✅ 都能指到代码/脚本；无"完全免杀"类表述 |
| 8 | **隧道/代理持久化 + 重启自动恢复**（取自参考实现 B4） | 缺陷修复（可用性） | ✅ 已完成 | 原实现只有内存态 `s.socks5Servers`，重启即丢。新增 `tunnels` 表 + `internal/server/tunnelstore` + `RestoreTunnels()`；口令加密落库且绝不回显 | 重启后 `restored=true` 且端口重新监听；端口被占用时**不崩**（标 `status=error` + 中文原因）；`DELETE` 后重启不复活 |
| 9 | **批量任务下发** `POST /api/v1/tasks/bulk`（取自参考实现 B8） | 功能（小） | ✅ 已完成 | 复用 `createTaskHandler` 字段；逐项独立结果；`avops.TaskNoRetry` + 侦察类白名单双守卫；一次批量 = 一条审计；上限 200 | 部分失败不影响其它项；空/超限 400；破坏性任务全被拒且不产生任务；会话页多选 + 逐行结果 |
| 10 | **屏幕流投递可观测性**（取自参考实现 B7） | 可观测性 | ✅ 已完成 | `screen_stats.go` 聚合计数（收帧/投递/丢弃/限速/订阅者/最后帧时间）+ `WSHub` nil 安全锁外观测回调；`/system/stats` 与 `/channels/health` **只追加** `screen_stream` | 旧字段逐项不变（单测断言）；丢弃有 1 秒限频 warning；**不给图像帧加通用压缩** |
| 11 | **设置页配置分组默认折叠** | 体验修复 | ✅ 已完成 | 10 个 `<Section>` 改为 `defaultOpen={false}`；`Section` 组件默认值不变（其他页面不受影响） | 进设置页需点标题才展开；不改变任何配置读写行为 |

> **对"补丁只修不扩"的偏离要如实记账**：第 9 项（批量下发）在补丁版里确实**新增了一条对外 API**。
> 理由是它属于"操作员明确提出的横向阶段刚需"，且不新增协议、不改动既有接口语义；但严格按本文
> 「节奏纪律」，**后续补丁版不再接受新增 API**，同类需求排进 v1.5 的 P1 清单。

---

## v1.4.2 登记（安全修复，2026-10-25）

> 来源：2026-10-24 第三方安全审计（4 High / 9 Medium / 6 Low）。原始报告含可复制的 PoC 与测试机地址，**不入库**（`.gitignore` 已忽略）；对外发布的是
> [`docs/SECURITY-FIXES-1.4.2.md`](docs/SECURITY-FIXES-1.4.2.md) 与 [`docs/SECURITY-REAUDIT-1.4.2.md`](docs/SECURITY-REAUDIT-1.4.2.md)。
> 纪律：**这类修复不写进"功能"叙事**，只写"哪条边界塌了、现在怎么挡"。

| # | 项 | 等级 | 状态 | 依据 |
|---|---|---|---|---|
| 1 | 认证后任意文件读/删（builders `name`/`format` 穿越） | **H2 / H3** | ✅ | `api/safe_path.go`（`safePayloadName` + `resolveInDir`）+ 后缀白名单 + 全部候选断言 |
| 2 | 认证后任意文件写（MCP `plugin_upload` `name` 穿越 + 跟随软链） | **H4** | ✅ | `plugin.ValidatePluginName` + `Rel` 断言 + `EvalSymlinks` 真实根 + `Lstat` + `O_NOFOLLOW` |
| 3 | 未认证伪造/终止任意任务结果 | **H1** | ✅ | 兼容端点挂认证 + `CompleteForSession/FailForSession` 归属校验 |
| 4 | 未认证伪造会话 / 心跳污染与复活 | **M1** | ✅ | 认证 + 心跳只写自己那条 + dead 会话 409 零写入 |
| 5 | 未认证抢取任务（`/task`） | **M2** | ✅ | 注册时下发 `session_token`，`/task` 先验令牌再 `GetNext` |
| 6 | 未认证 `/payload/{id}` 用 DB `name` 拼候选读任意文件 | **M9** | ✅ | `serveStoredImplant` 五候选全部 `resolveInDir` |
| 7 | 请求体无上限 / gzip 压缩炸弹 | **M4 / M7** | ✅ | `MaxBytesReader`（64 KiB/16 MiB）+ 解压 32 MiB 上限 |
| 8 | 内嵌 MQTT 匿名可连 + 绑 0.0.0.0 | **M5** | ✅（无主题 ACL） | `mqtt_embedded_bind` 默认回环 + 可选账号口令 |
| 9 | `?token=` 查询串、WS Origin、shell WS 读上限 | **M6 / M8** | ✅ | `tokenQueryAllowed` 白名单 + `originAllowed` + `SetReadLimit(1 MiB)` |
| 10 | 启动明文口令进日志 / 回显 webhook secret / 内置开发密钥 | **L2 / L5 / L4** | ✅ | 口令写 0600 文件；`secret_set`；脚本与文档改占位值 |
| 11 | **全局静态协议密钥可提取、无每植入端身份与帧重放防护** | **M3** | ❌ **未修（设计层）** | 已写入两份对外文档的"残余风险"；修复排 **P1**（见下） |
| 12 | 植入端 TLS `InsecureSkipVerify` / `mingw_gcc_path` 子进程执行 | **L1 / L6** | 🟡 记录 | 前者靠 AEAD 兜底、后者属管理员信任边界，已在 `docs/skills/toshell-api/SKILL.md` 写明 |
| 13 | MQTT 通道压缩帧解析异常（本轮顺带发现） | 缺陷 | ❌ 未修 | `mqtt_listener.go` 的 `decodePacket` 注释称会解压、实际不会；>1 KiB 压缩帧大概率解析异常 |

### v1.4.2 之后的安全待办（P1，按优先级）

1. **M3 设计层改造**：每植入端独立密钥/密钥对（构建时下发或首注册协商）→ 帧带 session 绑定 + 单调序列号防重放 → 免认证载荷下载改**一次性短 TTL**。
2. 内嵌 MQTT 的**每会话主题 ACL**（当前认证后是单账号全主题放行）。
3. 管理 API 内置 TLS 选项（或把"必须反代 TLS"做成启动时的显式检查与提示）。
4. `?token=` 进一步换成**一次性 WS ticket**（避免 JWT 出现在 URL）。
5. CI 增加 `-race`（Linux runner）与 fuzz（路径/名字解析函数）。

---
## v1.5 实战化与工具互操作（**不集成工具，只给接口**）

> 用户口径（2026-10-25）："下一轮优化方案贴合实战攻防一些，方便结合工具，**我们不集成工具**。"
> 这一节就是把这个口径落成可验收的条目。

### 三条硬原则

1. **不打包**：不内置、不分发任何第三方工具本体（nmap / hydra / bloodhound / mimikatz / impacket / fscan …）。原因三条：许可、体积、以及**别人家的免杀**——内置等于把别人的特征也背在自己身上。
2. **不替操作员"点按钮跑工具"**：不提供"一键攻击"编排。AI 可以建议，**必须人确认**（沿用 v1.4.0 的分级审批）。
3. **只给三样东西**：**稳定数据契约**（格式/字段/错误码）、**可被调用的入口**（REST/MCP/Webhook/CLI 薄壳）、**能被消费的产物**（NDJSON/CSV/json/zip）。

> 验收口径：任何一条都必须能回答"**外部工具 x 能在 5 分钟内接进来**"，而不是"我们内置了 x"。

### A. 出站互操作 —— 让外部工具借道我们的通道

| # | 条目 | 为什么实战需要 | 验收标准 | 成本 |
|---|---|---|---|---|
| A1 | **SOCKS5 出口的实战兼容** | 现在只有 TCP CONNECT，且只验证过 `curl`。实战里 `nmap --proxies`、`impacket` 的 SOCKS 插件、`proxychains`、浏览器插件都要跑 | 4 类客户端各一条实测记录（nmap/curl/impacket/proxychains），写明谁支持 UDP、谁只能 TCP | 小 |
| A2 | **UDP ASSOCIATE** | DNS、SNMP、部分内网服务只能 UDP；`nmap -sU` 走代理必然失败 | 通过代理做一次 UDP DNS 查询成功；不支持时**明确回错**而不是静默丢包 | 中 |
| A3 | **多跳代理链** | 演练常是"入口→DMZ→核心"三跳，现在一次只有一条中继 | 链式 `listen→relay→relay` 可达第三跳内网；每跳可单独起停 | 中 |
| A4 | **单端口/固定目标转发** | SOCKS5 是动态的，很多工具只会连固定 `127.0.0.1:port` | Tunnels 页新增"固定目标端口转发"（local:port → target:port），带健康检查 | 小 |
| A5 | **文件读写支持 range** | 大文件（>64 MB）现在只能整传，且预览只回前 64 KiB | `file_download` 支持 offset/length；外部工具能 `curl -r` 式续传；审计记录 | 中 |

### B. 入站编排 —— 让我们能被工具 / AI / SOAR 调

| # | 条目 | 为什么 | 验收标准 | 成本 |
|---|---|---|---|---|
| B1 | **OpenAPI 3.1 描述文件** | 现在接口文档是手写的 SKILL.md，外部生成 client 要人肉对齐 | 从路由 + handler 结构导出 `docs/api/openapi.json`，CI 里跑"描述 ⊆ 实际路由"的守卫用例 | 中 |
| B2 | **MCP 补齐 resources / prompts** | 现在主要是 tools；AI 客户端缺"看会话/看文件/看任务"的结构化资源与常用 playbook 提示词 | `resources/list` 覆盖 sessions/tasks/files/credentials（只读），`prompts/list` 给 3~5 个实战 playbook（侦察/提权检查/横向前的信息收集） | 中 |
| B3 | **Webhook 事件流工程化** | 现在只有"上线通知"，且没有签名/重试，SOAR 接不稳 | 事件类型细分（online/offline/task_done/task_failed/av_hit）+ **HMAC-SHA256 签名** + 指数退避重试 + 死信表 + 可查询投递记录 | 中 |
| B4 | **事件与结果导出** | 事后复盘要能进 ELK/Splunk/表格 | `GET /api/v1/events/export?since=…&format=ndjson`；任务结果 NDJSON（每任务一行，含 exit/stdout_sha256/耗时） | 小 |
| B5 | **官方 CLI 薄壳** | 现在所有自动化都靠手拼 curl（参数多、易错） | `scripts/toshell.sh`（bash）/ `toshell.ps1`：登录/批量下发/等结果/导出，**只封装我们的 API**，不复制任何第三方工具逻辑 | 小 |
| B6 | **脚本模板库（不是工具库）** | 操作员常写一次性脚本，重复造轮子 | `docs/recipes/` 放 8~10 个可复制的**调用示例**（jq 过滤、批量 whoami、结果落表、失败重试），每条标注"依赖外部工具时有哪几个" | 小 |

### C. 产物互操作 —— 我们产出的东西别处能直接用

| # | 条目 | 为什么 | 验收标准 | 成本 |
|---|---|---|---|---|
| C1 | **凭据导出为标准格式** | 拿到 hash/ticket 之后要进 hashcat / impacket / Rubeus | 导出选项：`hashcat-1000`（NTLM）、`kirbi`、`ccache`、`json`；默认**不导出明文**，需显式 `--allow-plaintext`；导出动作进审计 | 中 |
| C2 | **会话快照导出** | 自动化要"选机器"（按 OS/权限/杀软/网段）而不是人眼看界面 | `GET /api/v1/sessions/export` 输出 `sessions.json`（含 capability/modules/网段/杀软摘要） | 小 |
| C3 | **取证包 / 演练报告素材** | 报告工具（Word/Notion/Obsidian）要结构化输入 | `GET /api/v1/projects/{id}/bundle.zip`：任务 NDJSON + 文件 sha256 清单 + 时间线 CSV + `manifest.json` | 中 |

### D. 投放互操作 —— 外部工具**编译出来的东西**能直接投

| # | 条目 | 为什么 | 验收标准 | 成本 |
|---|---|---|---|---|
| D1 | **COFF/BOF 兼容性矩阵** | 现有加载器只跑过自研 BOF；外部 BOF 生态（CS 生态）大量在用，兼容面不清 | 文档写清支持的 API 子集 + 20 个公开 BOF 的实测表（能跑/报什么错），**不打包任何 BOF** | 中 |
| D2 | **`exec_module` ABI 公开化** | 现在 ABI 只有我们自己用；外部想要"往内存里塞自己的模块" | `docs/MODULE-ABI.md` + 示例模块（已有 `cred_probe`）+ CI 编译验证；外部编译产物能直接下发 | 小 |
| D3 | **.NET 程序集内存加载（可选）** | 实战里 SharpXxx 系列都是 .NET，落地即被拦 | 内存 `Assembly.Load` 执行，输出捕获 + 宿主不掉线；能跑 1 个公开 .NET 工具做验证 | 大 |
| D4 | **加载器源码模板（可编译）** | 现有 8 条加载器链是"命令模板"，操作员还得自己拼工程 | `go:embed` 骨架（白加黑/计划任务/LOLBin），改两个常量即可编；**每个模板必须在 CI 里真的 `go build` / `mingw-gcc` 通过**（不做 vshell 那种空壳） | 中 |

### E. 实战运营面（把"能用"变成"能持续用"）

| # | 条目 | 为什么 | 验收标准 | 成本 |
|---|---|---|---|---|
| E1 | **多操作员与最小 RBAC** | 现在 JWT `role` 固定写死 `admin`，只读观察员与能下 BYOVD 的人权限一样 | 3 个内置角色（observer/operator/admin）+ **按路由元数据**授权（不用路径前缀字符串匹配）+ 审计带操作者 | 中 |
| E2 | **项目/标签分组** | 一次演练几十台、多个项目并行时，会话列表会混成一片 | 会话可打 `project` / `tag`；列表支持按项目过滤；批量下发可"按项目选" | 中 |
| E3 | **批量并发闸 + 聚合视图** | 已有 `POST /tasks/bulk`，但 20 台同时跑会把服务端和通道打满 | 批内并发上限（可配）+ 结果按会话聚合（成功/失败/超时三态） | 小 |
| E4 | **离线任务队列** | 会话短暂掉线时下发的任务现在会"发不出去" | 会话离线时任务入队，重连后按序补发；破坏性任务仍**不**自动补发 | 中 |
| E5 | **长驻稳定性** | 多域名/IP 轮询已有，但退避与判活"半死"状态不清 | 重连指数退避 + 抖动；`alive/suspect/dead` 三态；连续 N 次失败才判死 | 小 |
| E6 | **失败可观测** | 现在任务失败只剩一句错误 | `/system/stats` 扩到任务成功率、按会话吞吐、通道 RTT；列表页可按"最近失败"筛 | 小 |

### 明确不做（写下来省得反复讨论）

- ❌ 不内置任何第三方工具（含"最小版 nmap"这类）；`data/tools/` 只放**自研脚本**或**用户自带 + sha256 固定**的二进制。
- ❌ 不做"一键攻击/一键横向"编排按钮：AI 只给建议，动作必须人确认。
- ❌ 不为了"接工具"引入新的重型依赖（例如把整个 Python 运行时塞进服务端）。CLI 薄壳只用 bash/PowerShell + curl。

### 建议批次（v1.5 分三批，先低风险高收益）

- **v1.5.0**：B1/B4/B5/B6（契约与薄壳）+ C2（会话快照）+ E3/E6（并发闸与可观测）—— 纯增量、不碰协议。
- **v1.5.1**：A1/A4/A5（SOCKS 兼容实测、固定目标转发、range）+ D1/D2（BOF 矩阵、模块 ABI 文档）。
- **v1.5.2**：B2/B3（MCP resources/prompts、Webhook 签名与重试）+ C1/C3（凭据/取证包导出）+ E1/E2（RBAC、项目分组）。
- **v1.6**：A2/A3（UDP、多跳）+ D3（.NET）+ E4（离线队列）+ 冷门通道（DNS/DoH，见 P2-2）。

---
## 后续优化清单（按优先级）

> **排序依据**：① 先收口**会影响正确性/可观测性**的小改 → ② 再做**零外部材料依赖**的纯代码项（可并行） → ③ 最后做"**没有操作员材料就无法验收**"的事。
> 每条四段：**动机 / 验收标准 / 改动面 / 风险**。

### P0（v1.4.1 收口 —— ✅ 本批已全部完成）

> 下面五条**保留原始验收口径**供复核，状态已在上文「v1.4.1 登记」逐条记为 ✅（第 2/3/4 项）或已完成。
> 其中 P0-3 的根因位置以登记表为准（`builder/implant/platform_unix.go:13`，不是 `internal/implant/sysinfo/`），
> P0-4 的「Linux 真机 ≥10 分钟」这一条**未达成**（无 Linux 运行环境），如实留在 🟡。

#### P0-1 文件预览白名单的"全链路闭环"

- **动机**：预览当前复用下载任务 + 前端二进制猜测（`web/src/components/FileManager.tsx` 的 `previewFile`），既无后缀约束也无服务端裁定；一个"看起来是文本"的 PE 会被当文本塞进 `<pre>`。
- **验收标准**：① `internal/common/preview` 有表驱动单测（每类 ≥2 后缀）；② 直接 `POST` 预览接口传 `../../etc/passwd` 或白名单外后缀 → 明确拒绝码；③ 未识别后缀前端**必须**弹窗（截图/交互记录）；④ 超大文件只回前缀且 `truncated=true` 可见。
- **改动面**：`internal/common/preview`（纯逻辑）+ `api/handlers_files.go`（后端二次校验）+ `api/api.go`（policy 路由）+ `web/src/components/FileManager.tsx`。
- **风险**：① 白名单过窄会让正常运维预览失效（先跟"常用运维后缀"对齐）；② 强制预览走"只读前缀"，别顺手把它做成任意文件读原语（路径必须复用既有校验）。

#### P0-2 代理认证的 fail-closed 复核

- **动机**：同一监听端口同时服务 SOCKS5 与 HTTP CONNECT；只校验 SOCKS5 认证等于给了一条绕过路径。
- **验收标准**：① 启用认证后，无凭据的 SOCKS5 握手被拒；② 无 `Proxy-Authorization` 的 HTTP CONNECT 被拒（407）；③ 错误口令不写日志原文；④ 不启用认证时与 v1.4.0 行为逐字节一致（含错误码）。
- **改动面**：`internal/common/tunnel/auth.go` + `tunnel.go` + `api/handlers_tunnels.go` + 前端参数。
- **风险**：① 常量时间比较要用 `subtle.ConstantTimeCompare`（别用 `==`）；② 认证字段进 DB/配置时要按密文处理（不回显）。

#### P0-3 显示层三处修复的一致性

- **动机**：Linux 用户名 `unknown`、杀软击杀回显、启动项回显三处都是"数据对、显示错"，修法必须统一成"显示层解码"而不是"改原始结果"。
- **验收标准**：① 原始 `task.output` 与修复前**逐字节一致**（断言用例）；② 前端/日志两处显示正确；③ 非法编码不 panic（退回原样）。
- **改动面**：`internal/implant/sysinfo/sysinfo.go` + 显示侧（前端渲染或 API 层格式化，二选一并写清）。
- **风险**：**不要把 GBK→UTF-8 塞回植入端回执**（会污染审计与导出，且与"原始结果不动"的要求冲突）。

#### P0-4 Linux/amd64 "秒断"根因与回归

- **动机**：这是**可用性级**缺陷：平台"支持"但实际连不上，会直接动摇"多平台"这个卖点。
- **验收标准**：真机 Linux/amd64 上线 ≥10 分钟；一次主动重连；`whoami` + `file_list` 回执；把复现条件写进 `scripts/e2e_smoke.ps1` 的说明（或新增 `linux` 专用冒烟段）。
- **改动面**：待定位（传输握手/心跳/判活/构建参数四选一），预计 `builder/implant/*` 与 `listener/*` 各一处。
- **风险**：① 别用"调大超时"掩盖根因；② 修完必须同时在 `internal/server/builder/implant` 与 `release/implant` 两份镜像改（见技术债 T17）。

#### P0-5 文档口径归零

- **动机**：本轮分析发现 4 处"文档说没做、代码其实做了"或"文档说做了、其实没验证"的漂移（D1~D4），继续漂会让路线图失去可信度。
- **验收标准**：`grep` 三份文档（README/ROADMAP/CHANGELOG）不再出现与代码矛盾的状态词；每个 ✅ 行都有出处。
- **改动面**：纯文档。
- **风险**：改状态时**不要把 🟡 扩大成 ✅**（宁严不宽）。

### P1（v1.5：从"能用"到"可运营"）

#### P1-1 通道落点注册表（新协议成本从"12 类落点"降到"1 个适配器"）

- **动机**：ROADMAP 旧版已承认"加一个新协议 = 12 类落点 / 20+ 处编辑，8 处漏改就静默降级或编译失败"；这是 v1.6 冷门通道的最大前置成本。（设计参考：`docs/VSHELL-ANALYSIS.md` B1，只借思想不借代码）
- **验收标准**：① 新增一张"协议面注册表"（端点集合 + 能力标志 + 编译期常量），现役四通道在注册表里各占一行且行为不变；② 守卫用例断言"注册表 ⊇ 现役端点"且"未知通道 fail-closed"；③ 用注册表**只改 3 处**就能挂一个空实现通道（用于验证抽象是否成立）。
- **改动面**：`internal/server/listener/*`（新 `protoface.go`）+ `api/router.go` + `internal/common/protocol/packet.go` + 单测。
- **风险**：① 运行期装配会让"哪些端点存在"变成数据 → 必须同时做**端点自检与探测面核对**（重演 S5 第 0 步的坑）；② 植入端**不要**跟着改成运行期协商（老载荷不兼容）。

#### P1-2 载荷投递面：请求时生成 + 一次性/过期 URL + loader 模板

- **动机**：现在载荷必须"构建 → 落盘 → 手工发下载链接"；演练中途换链接、链接被分析员反复拉取都没有对策。（设计参考：`docs/VSHELL-ANALYSIS.md` B2/B3）
- **验收标准**：① 同一组构建参数 60s 内复用同一产物（缓存命中日志可查）；② 生成一次性 URL（TTL 可配，默认关闭），过期后明确 410；③ 参数来自 URL 时**只接受枚举值**（架构/档案/通道/格式），非法值 400；④ 每个 loader 模板能在本机 `go build` / `mingw-gcc` 通过。
- **改动面**：`api/handlers_builders.go` / `handlers_implant.go` + 构建缓存 + 新 `loader_templates/`（`go:embed`）+ 前端按钮。
- **风险**：① 现场构建是重操作 → 必须限流 + 排队 + 超时，否则一个探测者能打满构建器；② 模板必须**真能编译**（不造空壳，参考 vshell 的空 loader 骨架教训）；③ 缓存要按"参数指纹"而不是"请求 ID"。

#### P1-3 批量操作 + 列表契约统一

- **动机**：横向阶段"一次给 20 台下发同一条侦察命令"现在只能循环调 20 次；列表接口参数各写各的（`/sessions`、`/tasks`、`/plugins` 不一致）。
- **验收标准**：① 新增 `POST /sessions/bulk`、`POST /tasks/bulk`，返回**逐项**结果（成功/失败原因）；② 部分失败不回滚已成功的项；③ 列表统一 `page/page_size/sort/order/q`（旧参数保留一版别名）；④ 批量操作只写**一条**审计（带目标列表）。
- **改动面**：`api/router.go` + 各 `handlers_*.go` 列表签名 + 前端表格/工具栏。
- **风险**：① 批量下发的审批/分级不能绕过（AV-Ops 的 tier 判定必须逐项复用）；② 一次 20 台同时执行会打满服务端 goroutine → 批内并发上限。

#### P1-4 RBAC 骨架（角色 → 路由元数据 → 审计）

- **动机**：JWT `Claims` **已经有 `Role` 字段**（`internal/server/auth/auth.go:18-22`），但登录时固定写死 `"admin"`（`api/handlers_auth.go:140`、`:156`），**全仓库没有任何基于 role 的授权判定** —— 只读观察员与能下 BYOVD 的操作员等价。
- **验收标准**：① 路由注册处带 `requireRole` 元数据（**不用路径前缀匹配**）；② 3 个内置角色（viewer/operator/admin），viewer 打任何写接口得 403 且进审计；③ 未打元数据的路由默认**拒绝**（fail-closed）并由守卫用例钉住；④ UI 只做"隐藏 + 提示"，服务端判定为准。
- **改动面**：`api/router.go`（100+ 路由加元数据）+ `auth` + 最小用户表 + 审计字段。
- **风险**：① **前缀式 RBAC 是反例**（vshell 的 `/api/client/` 前缀把编辑/删除都放行了，见分析文档 N/B9）；② 单账户模型下做角色会暴露"没有用户库"，要一并做最小用户表；③ 别把"前端隐藏按钮"当权限。

#### P1-5 隧道/反代主机实体化 + 健康检查 + 配额

- **动机**：SOCKS5 隧道现在是内存态（`api/handlers_tunnels.go` 的 `s.socks5Servers`），**进程重启即丢**；中继节点无独立健康探测，只能等会话判死。
- **验收标准**：① 隧道规则入库（幂等 DDL），重启后按规则重建；② 健康探测默认**关闭**，仅对显式开启的规则跑，`tcp/http` 两种检查；③ 连续失败只标 `unhealthy` + 告警，**不自动删规则**；④ 每会话连接数/流量上限超限时回明确错误（不静默丢帧）。
- **改动面**：`database/`（新表）+ `common/tunnel` + `listener` 健康 goroutine（限并发 20）+ 前端 Tunnels 页。
- **风险**：① 健康探测 = 新的主动流量足迹（默认关）；② 探测阈值别和会话判活共用（S5 已踩过判活抖动）；③ 配额按"并发流"算，不要按帧数（大文件传输会被误杀）。

#### P1-6 可观测性计数上界面

- **动机**：屏幕流帧限速丢弃数、广播去抖抑制次数、慢消费者丢弃数现在**只在日志里**；`/system/stats` 已存在但缺这些业务指标。
- **验收标准**：`/system/stats` 增加 3 组计数（frame_dropped / debounce_suppressed / ws_slow_consumer），仪表盘有卡片，计数器不按帧存（防高基数）。
- **改动面**：`api/screen_frame_limiter.go`、`session_broadcast.go`、`ws_push.go`、`api/api.go`、`web/src/pages/Dashboard.tsx`。
- **风险**：计数器只增不重置会导致"历史累计"误读 → 同时暴露 `since` 时间戳。

#### P1-7 真机冒烟矩阵脚本化

- **动机**：CI 里的 e2e 固定 `-SkipImplant`（托管 runner 无真实植入端），真机验证完全靠人工记；`docs/EVASION.md` §3.1 的动态测试矩阵还没脚本化。
- **验收标准**：`scripts/evasion_matrix.ps1`（已存在）补成"一次只改一个变量 + ≥3 次重复 + 记录拦截原文 + 输出判定矩阵"的可重复流程；产物落 `docs/` 附证据。
- **改动面**：脚本 + 文档。
- **风险**：**不得**把脚本跑出的"某次通过"写成"免杀已生效"（口径纪律）。

### P2（v1.6：第二植入端 + 冷门通道）

#### P2-1 Rust 第二植入端（结论：可行 · 已实测体积）

- **动机**：Go 版地板已探明（核心标准库 2.01 MB，最小 TCP 栈 ≈2.8 MB），`nano ≤1.8 MB` 在 Go 下不可行。Rust 侧 **v1.4.1 已在本机实测**（探针源码随仓库提供，见 `docs/RUST-IMPLANT.md` 与 `docs/rust-probe/`）：
  - `light` 等价物（TCP 帧协议 + 注册/心跳 + shell/文件/进程 + SM4-GCM）**350,720 B**，Go 同形态 2,946,805 B → **小 8.4 倍**；
  - `light + http`：Rust 走 **Windows SChannel** 时 TLS 增量仅 **17,408 B**（总 ≈368 KB），Go 为 5,455,613 B → **小 14.8 倍**；
  - 若改用 rustls 自带密码学，TLS 增量 +888,320 B（总 ≈1.15 MB），仍比 Go 小 4.4 倍；
  - `full` 档（含注入/BOF/凭据/驱动）体积为**推导值 650 KB–1 MB**，须在 R4/R5 完成后替换为实测值。
- **验收标准**：① 能完成"上线 + `whoami`/`file_list`/`file_download` 三类任务"；② `light` 档产物 ≤ 450 KB（`opt-level=z + lto + strip` 已在探针里定死，不开 LTO 会涨 3.7 倍）；③ 与 Go 版**共用协议与配置块格式**（同一服务端无需分支）；④ 明确标注"第二植入端，不替代 Go 版"（能力子集），UI 按能力位图自动灰掉未实现项。
- **改动面**：新 `implant-rs/`（协议/配置块/传输/TLS）+ 构建器加 `language` 分支 + CI 交叉编译矩阵；服务端与前端**几乎不用改**（线协议、配置块、能力位图都是语言无关的 JSON）。
- **风险**：① 成本被低估：TLS/JSON/协议帧/配置块/PE 资源修补都要重写一遍，**60~70% 的 Go 版工作量**是乐观值，实测工程量约 13,000~15,000 行 Rust；② 双植入端 = 双倍回归面（必须共用协议单测向量 + "Go 产物 ↔ Rust 产物打同一服务端"的双向互通回归）；③ 别为了体积牺牲"能力位图/exec_module"这些已有契约；④ **小体积 ≠ 免杀**，R1 阶段就要做一次"落地/动态/静态"三分类体检并入 `docs/EVASION.md`。

#### P2-2 冷门通道（DNS/DoH 优先，需 P1-1 前置）

- **动机**：现有通道在"仅放行 DNS/443 CDN"的出口里全军覆没；DNS 通道是穿透性最好的一档。
- **验收标准**：真实域名 + 委派下，DNS 通道能跑"心跳 + 一条命令 + 小结果"；吞吐/延迟有实测数字（并写明"只适合控制面"）。
- **改动面**：新 listener + 植入端适配器（依赖 P1-1 注册表）。
- **风险**：① 需要**域名与委派运维**（外部材料）；② 吞吐极低（`MaxDNSsize` 级别）；③ 企业 DNS 日志/NRDS 让隐蔽性远低于直觉 —— **禁止**写"绕过出口管控"。

#### P2-3 平台工具库与远程加载（`data/tools/`）

- **动机**：植入端体积/功能面不随能力增长；高阶能力（端口扫描/横向/凭据利用）不该编进载荷。
- **验收标准**：`data/tools/<os>/<arch>/` + `manifest.json`（用途/平台/调用示例/来源/SHA-256/许可/体积/校验时间）；"下载→校验→内存加载→执行→回传→清理"闭环跑通；元数据缺失或 sha256 不符**明确拒绝**。
- **改动面**：新工具库 + `api` 远程下载 + `exec_module`/`blob` 复用。
- **风险**：第三方二进制的**来源与许可**是运营问题（预置只放自研脚本）；下载源必须是白名单 + 哈希固定。

#### P2-4 落地链与真实证书验收（材料依赖）

- **动机**：S3 的全部结论目前只有静态/结构级证据；本机连新生成 PE 都执行不了。
- **验收标准**：目标机上给出"签名载荷可执行 / 白加黑链可执行"的**实测记录**；干净 VM（仅 Defender）里默认载荷 5 分钟内不触发 `Behavior:` 类拦截；判定矩阵能输出"被拦层级 → 改造类别"。
- **改动面**：脚本 + 文档；代码改动取决于实测结论。
- **风险**：**没有材料就写不出结论** —— 这一项要明确标注"阻塞在操作员提供证书/目标机"，不许用"理论可行"充数。

#### P2-5 AV-Ops L2/L3 真机验证

- **动机**：L2/L3 只验证过"被拒"，没验证过"放行后真的执行"；L3 还依赖操作员自备 `rw` 档驱动。
- **验收标准**：授权 VM + 快照下，`process_kill`（L2）与 `byovd_kill`/`ppl_kill`（L3）各留一条**真机执行记录**（命中 EPROCESS/Protection 原值→新值）；面板"破坏性动作成功下发"分支实测一次。
- **改动面**：代码基本不动（补 `purpose` 选路提示与失败原因），主要是验证与文档。
- **风险**：爆炸半径最大 → 仅授权实验环境 + 快照 + 操作员自备驱动；**项目不内置任何 `.sys`**。

### P3（v2.0 / 长期）

#### P3-1 插件市场：清单 + 签名 + 索引
- **动机**：`plugins/` 是本机目录 + `exec_module` 只做 sha256 硬拦；社区分享没有信任模型。
- **验收标准**：Ed25519 签名（可开关）→ 未签名模块默认拒装；索引文件带版本/兼容 ABI/作者；至少 3 个官方示例模块 + 1 个第三方模块通过校验。
- **改动面**：`internal/server/plugin` + `modules/manifest.go` + 前端 Plugins 页。
- **风险**：签名私钥的分发与轮换；别把"签名"当"安全"（恶意但已签名照样能跑）。

#### P3-2 OpenAPI 导出 + Go/TS/Python client
- **动机**：现在生态靠 `docs/skills/toshell-api/SKILL.md` 人工维护（109 条路由），脚本党只能抄文档。
- **验收标准**：`GET /api/v1/openapi.json` 可下载且通过 schema 校验；从它生成的 TS client 能 `tsc --noEmit`、Python client 能跑通 `session_list`；OpenAPI 由注册表生成（不手写）。
- **改动面**：`api/router.go` 元数据 + 生成器 + `sdk/` 目录。
- **风险**：路由元数据不全是"防漂移"的关键（与 P1-4 共用同一份元数据）。

#### P3-3 多实例联邦 / 多级 team server（先只读）
- **动机**：现在严格单实例（每实例独立 sqlite、独立 MCP 监听）；多团队/多级场景只能靠人工汇总。
- **验收标准**：两个实例互见"对端在线数/会话数/健康"，**断链不清空本地数据**；只读镜像，不做双向写。
- **改动面**：新 `federation` 子系统 + 鉴权（独立 token）+ 前端"对端"卡片。
- **风险**：双向写 = 分布式一致性地狱（明确不做）；对端信任模型要单独设计。

#### P3-4 工程证据链：SBOM / 依赖审计 / Fuzz / 基准 / 可复现
- **验收标准**：SBOM（CycloneDX）随 Release 发布；`govulncheck` 0 critical；协议解析与 `preview`/`moduleabi` 有 Fuzz 目标（≥1 万次执行无 panic）；关键路径 bench 基线入 CI；`-trimpath` + 固定工具链 + 依赖锁定 → 两次构建 SHA-256 一致。
- **改动面**：workflows + `scripts/` + `*_fuzz_test.go`。
- **风险**：可复现构建与 `-buildid=` 擦除/UPX 的顺序冲突要一起设计（现在顺序契约在 `finalize_order.go`）。

#### P3-5 服务端自更新（服务化守护 → 原子替换 → 回滚）
- **动机**：现在升级 = 停进程覆文件重启，期间**全部会话与 SOCKS5 隧道断开**。
- **验收标准**：装成服务（Windows 服务/systemd）→ 检查更新 → 校验（sha256 + 可选 Authenticode）→ 原子替换 → 重启 → 自检；失败**不改动现有二进制**；保留上一版一键回滚；默认**关闭**。
- **改动面**：`release/install.*` + 更新器 + 设置页。
- **风险**：更新通道 = 完整 C2 控制端，**被劫持等于 C2 被接管** → 必须可信源白名单 + 独立密钥 + 二次确认 + 审计。

#### P3-6 产品体验：i18n 补全 / 无障碍 / 移动端
- **动机**：`web/src/i18n.ts` 已有 zh/en 字典骨架，但页面文案**迁移未完成**；窄屏只做到"能用"。
- **验收标准**：主要页面文案走 i18n key（无硬编码中文）；键盘可完成"登录→切会话→下发命令→看结果"；无障碍基线（对比度/焦点环/aria-live）；移动端只承诺"能看会话与任务，不做全功能"。
- **改动面**：前端为主。
- **风险**：全站 i18n 是大工程 → 按页面分批，不做一次性替换。

---

## 生态与"跟上时代"

> 这一节只写**可执行**的东西：每条都带"现在有什么 / 缺什么 / 怎么验收"。空口号不写。

### 6.1 互操作与生态

| 方向 | 现状（依据） | 缺口 | 里程碑 |
|---|---|---|---|
| **MCP** | `internal/server/mcp`：38 工具三档分级、JSONL 审计、RPM/并发/句柄三闸、默认关闭且**独立监听** `mcp.bind`（默认 `127.0.0.1:18082`，`mcp/server.go`）；`cmd/toshell-mcp` 提供 stdio 桥 | ① 没有"AI 客户端接入指南 + 真实客户端冒烟"；② stdio 桥没有一行安装；③ 工具面**故意**不含 `exec_module` 与 L1+ 动作 | `scripts/mcp_client_smoke.ps1`：stdio + HTTP 两种传输各跑 `session_list`/`task_wait`；文档补"3 个客户端（Claude Desktop/Cursor/自研脚本）配置片段" |
| **API / SDK** | REST 109 条路由（`docs/skills/toshell-api/SKILL.md` 逐条列出）；无 OpenAPI（`grep -i openapi` = 0 命中） | OpenAPI 导出、代码生成、版本化策略 | P3-2：`/openapi.json` + TS client 通过 `tsc --noEmit` |
| **Webhook / 告警** | 飞书/钉钉/企业微信/Slack/Discord 各自结构 + 业务码判定（`internal/server/webhook/`）+ `POST /settings/webhook/test` | 告警分级、去重、静默窗口、失败重试 | `alert_rules.yaml`：事件类型 → 渠道 → 静默期；一次演练只发 1 条聚合告警 |
| **插件市场 / 签名** | `plugins/` 本地目录 + `exec_module` 清单 sha256 硬拦 + 一次性 token + 9 步校验链 | 签名、索引、兼容 ABI 声明 | P3-1 |
| **导入导出与迁移** | 单 sqlite + 幂等 DDL（`database/agent_schema.go`）；无 `schema_version` 表 | 会话/情报/模板/剧本的 JSON 导入导出；迁移脚本 | `toshell-migrate` 子命令 + `schema_version` + 备份/回滚说明 |
| **多实例联邦** | 严格单实例（每实例独立 DB + 独立 MCP 监听） | 只读镜像、对端健康、断链保护 | P3-3 |

**MCP 怎么"真的用起来"（三条具体动作）**：
1. **给 AI 客户端一段可复制的配置**：`mcp.enabled=true` + token + `allowed_tools`（只读起步），文档里贴 Claude Desktop 的 `mcpServers` 片段。
2. **把"危险工具"做成显式开关而不是默认**：`allowed_tools` 留空 = 只读（现状已如此），写工具名才逐项放行；每加一个工具必须在 `registry_tools.go` 里分级，并有守卫用例防"忘了分级就默认放行"。
3. **让人能审计 AI 做了什么**：`audit_path` 的 JSONL 要能被"按 run/按会话"聚合查询（现在只能 grep），并在 UI 的 Logs 页给出过滤入口。

### 6.2 对抗面（如实标状态，不吹能力）

| 手段 | 状态 | 说明 / 边界 |
|---|---|---|
| HTTP(S) 回连 | ✅ | 四种通道之一；证书/SNI 可配（`front_domain`） |
| wss | ✅ | WS 通道可用；WS 走 Go 标准库 TLS |
| HTTP/2 | ❌ | **未做协商验证**：没有 h2 相关代码/测试，文档不得宣称支持 |
| uTLS / JA3 | ⚠️ | HTTP 全量档已接 uTLS `HelloChrome_102`（`transport_tls_utls.go`），**未抓包验证** JA3 指纹与真实 CDN 行为；light 档仍用标准库 |
| 域前置（Domain Fronting） | 🟡 | HTTP/WS 已支持"SNI + Host 分离"（`front_domain`）+ WS Host 名单；**真实 CDN/证书链未联调**（`docs/DEPLOY-DOMAIN-CDN.md` 只有配置与排错） |
| CDN 回连 | 🟡 | 文档齐全、配置可用；无真实 CDN 环境实测记录 |
| 加载器（loader / stager） | 🟡 | 8 条链命令模板 + 降级顺序；**无 stage/stageless 双形态、无 loader 源码模板**（P1-2） |
| BOF / COFF | ✅ | `-tags bof` 按需编译，默认载荷不含 `Beacon*`；`internal/implant/bof.go` 自带 COFF 解析 |
| .NET 内存加载 | ❌ | 无实现；只在 `exe_mem` 预检里识别 `.NET` 并**拒绝**（避免双 runtime） |
| 反射 DLL | 🟡 | `format=dll` 产出**真 DLL**（c-shared，加载即启动）；内存路径是反射映射宿主，但 `dll` 分支**未真机验证** |
| 静态降特征 | ✅ | 字符串混淆 + pclntab 中性化 + Go 指纹擦除 + PE 资源/节规范化 + 每构建随机化 |
| 睡眠期内存加密（sleep mask） | ⚠️ | 已实现（隧道子密钥 + 结果缓存），**运行期零实测**；C2 地址等 `string` 未纳入 |
| 去 RWX | ✅ | `allocRW`/`protectRX` 硬拒 `PAGE_EXECUTE_READWRITE`；默认载荷 `PAGE_EXECUTE_READWRITE=0` |
| 直接系统调用 | ✅ | 注入路径 `directsyscall_windows_amd64*.go`；cgo 共享库（DLL）构建时回退 apihash |
| **inline hook** | 🚫 | **明确不做**（`mexecguard_windows.go` 注释给出理由：搬运被覆盖函数序言，失败模式是"全进程变砖"） |
| ETW patch | 🟡 | `edr_blind` 任务级（需管理员），**不是启动期自动**；存在"需要先有权限才能降检测"的鸡生蛋问题 |
| AMSI patch | 🚫 | 对 Go 默认载荷收益≈0（只在进程内加载 .NET/脚本时才有意义）；不排期 |

**免杀三层的说法必须固定**（避免混用）：**落地（delivery）** = 怎么送上目标机；**动态免杀** = 运行时内存与调用行为；**静态降特征** = 文件里的字符串/符号/构建指纹。三层各自有验证口径，`docs/EVASION.md` 是唯一权威表。

### 6.3 平台覆盖（以及为什么某些不做）

| 平台 | 架构 | 状态 | 说明 |
|---|---|---|---|
| Windows | amd64 / 386 | ✅ | 主力平台；全功能（注入/BYOVD/屏幕/凭据/UAC/持久化） |
| Windows | arm64 | ⚠️ | 构建矩阵里有（`GetSupportedArch`），**无真机验证**；注入/驱动等能力未适配 |
| Linux | amd64 | 🟡 | 基础任务可用（v1.4.1 正在修"秒断"）；无屏幕流/无注入 |
| Linux | arm64 | ⚠️ | 可构建，未真机验证 |
| macOS | amd64 / arm64 | 🟡 | 可构建（`GetSupportedOS` 含 darwin），但**无签名/公证、无屏幕录制授权路径、无真机验证** |
| Windows | 386 载荷 / WoW64 边界 | 🟡 | 32 位载荷能在 64 位系统上跑（已实测 386 全链路），但 32 位载荷做 64 位目标的注入/驱动交互有已知边界（见 `docs/EVASION.md`） |
| Android / iOS | — | 🚫 | 不做：授权形态不同、无越狱/root 前提下的能力为零、体积与维护成本溢出 |
| 固件 / IoT | — | 🚫 | 不做：威胁模型与协议栈完全不同（MIPS/RTOS），投在这里会拖垮主线 |

### 6.4 工程化

| 项 | 现状 | 缺口 / 里程碑 |
|---|---|---|
| CI/CD | `.github/workflows/ci.yml`（web build → server build → vet → test）+ `release.yml`（e2e-smoke 门禁 → 三平台打包 → tag/版本一致性 → zip 清单 → checksums） | 缺**覆盖率门槛**与"测试包数量"趋势；里程碑：覆盖率报告随 PR 评论 |
| 可复现构建 | `-trimpath` + `-buildid=` 擦除 + 固定植入端工具链（go1.20.14，`release.yml` 预取） | 缺 vendor 与"两次构建 SHA-256 一致"的自动化断言；里程碑：`scripts/repro_check.ps1` |
| SBOM | 仅有 `THIRD-PARTY-NOTICES.md`（人工维护） | CycloneDX + 随 Release 发布（P3-4） |
| 依赖审计 | 无自动化 | `govulncheck` 进 CI，critical 即失败（P3-4） |
| Fuzz | 无 | 协议解析（`internal/server/listener/listener.go` 的 `parsePacket`/`parseTunnelPacket`）、`preview`、`moduleabi` 三个目标（P3-4） |
| 基准性能 | 无 | 关键路径 bench（帧编解码、分块落盘、SSE 推送）+ CI 基线 |
| 灰度 / 回滚 | 无（升级=停进程覆文件） | 自更新（P3-5）+ "保留上一版二进制"约定 |
| 迁移脚本 | 只有幂等 DDL | `schema_version` + 迁移命令 |
| 可观测性 | `/health`、`/logs`、`/system/stats`、`/channels/health` | metrics 端点（Prometheus 文本格式）+ trace 关联（agent trace 已有，HTTP 侧待统一） |
| 多租户 / RBAC | 无租户；RBAC 仅"有 role 字段无判定" | P1-4（RBAC）；多租户**明确不做**（单团队使用为主，租户隔离会把每条查询都复杂化） |

### 6.5 产品体验

- **Copilot 自主性（✅ 已做 agent loop）**：`max_turns=20` / `max_tool_calls=40` / `max_wallclock_sec=900`、防死循环（`loop_detected`）、审批分级、SSE 断点续传、长任务挂起/恢复。**剩余**：多 run 并行（同一服务端同时跑两个不同目标的 run）、"下一步建议"的确定性剧本化（减少模型自由发挥）。
- **任务编排**：剧本（playbook）已有；缺"可视化编排 + 失败分支 + 重试策略"。
- **批量操作**：P1-3。
- **UI 一致性**：组件层已建（`web/src/components/ui`）；缺"新页面必须复用组件"的 lint/清单。
- **i18n**：`web/src/i18n.ts` 有 zh/en 字典骨架，页面文案迁移未完成（P3-6）。
- **无障碍**：焦点环与键盘导航已做（会话详情 tab 条 ←/→/Home/End）；缺对比度与 `aria-live` 审计。
- **移动端**：窄屏浮层已做；明确只承诺"看会话/任务"，不做全功能（P3-6）。

### 6.6 合规与安全（产品化必须补的）

| 项 | 现状 | 要做 |
|---|---|---|
| 审计日志 | MCP JSONL + AV-Ops 审计 + agent 轨迹（`internal/server/mcp/audit.go`、`handlers_avops.go`） | 统一审计查询 API（按会话/时间/操作者）+ 保留策略配置 |
| 密钥管理 | 配置明文（`configs/server.yaml`），有"凭据必须落盘否则拒启"的保护 | 可选 KMS/HSM 或至少"环境变量/文件权限"两种加载方式；密钥轮换流程文档 |
| 数据保留 | 结果外置有 `result_ttl`（默认 24h） | 会话/任务/日志的 TTL 与"演练结束清理"一键命令 |
| 生产部署加固 | TLS 可配、`trust_proxy_headers` 默认 false、Web 防测绘门槛（`/__gate`） | 反代样例（nginx/caddy）+ 隔离网段部署说明 + 默认口令强度检查 |

### 6.7 如何领先同类型项目：5 条护城河 + 可度量里程碑

| # | 护城河 | 为什么是我们（而不是别人） | 可度量里程碑 |
|---|---|---|---|
| 1 | **AI 原生操作员** | 工具表单一来源（REST / 内置 AI / 对外 MCP 三处同源）+ 分级审批 + 长任务可靠性；同类项目多为"面板 + 按钮" | 一条自然语言指令完成"侦察 → 汇报 → 建议"且**全程可回放**（SSE 事件 + 审计）；MCP 客户端冒烟 3/3 通过 |
| 2 | **可验证的对抗分级** | AV-Ops 把"对抗动作"分级并**逐动作回显能不能下发 + 中文原因**，被拒动作**不产生任务**；工具面不暴露 L1+ | L0~L3 每档各一条真机执行记录；拒绝路径 100% 有审计；"点击无反应"的假入口数 = 0 |
| 3 | **完整证据链** | 每个 ✅ 都能指到测试/脚本；体积、节表、loader 接受性都有口径（含"未验证"标注） | 状态表 100% 条目有出处；覆盖率报告 + bench 基线进 CI；两次构建 SHA-256 一致 |
| 4 | **开源可审计** | MIT、不内置驱动/二进制、第三方声明齐、fail-closed 默认值 | SBOM 随 Release；`govulncheck` 0 critical；`THIRD-PARTY-NOTICES.md` 与依赖树 100% 对齐 |
| 5 | **插件生态（会签名、有 ABI）** | `exec_module` ABI v1 + 一次性 token + 9 步校验链；插件可服务端更新而不重编载荷 | 3 个官方示例模块 + 1 个第三方模块通过签名校验；插件 CRUD 与兼容矩阵进文档 |

> **不做的"领先"**：不比"能不能过某杀软"（不可验证、不做承诺）、不比"协议数量"（多通道是成本不是勋章）、不比"UI 花哨"。

---

## 技术债与已知边界

> 逐条都能在仓库里找到依据（代码注释/文档/stub）。**未验证 ≠ 已完成**；这一节是"我们欠自己的账"。

| # | 边界 / 债务 | 依据 | 影响 | 处置 |
|---|---|---|---|---|
| T1 | 真实证书链未落地（只有自签实测） | `builder/sign.go` + 无证书材料 | 装 360/电脑管家的主机上未签名 PE **进程创建即被拒** | 材料依赖（P2-4） |
| T2 | 真实 CDN 域前置未联调（含 wss 证书链） | `docs/DEPLOY-DOMAIN-CDN.md` 只有配置与排错 | 域前置在真实链路上可能失败且无记录 | 材料依赖 |
| T3 | uTLS/JA3 未抓包验证 | `transport_tls_utls.go` 已实现，无验证记录 | "用了 uTLS"≠"指纹像 Chrome" | P2-4 顺带做 |
| T4 | HTTP/2 **是否有协商**未验证 | 无 h2 相关代码/测试 | 文档不得宣称支持 | 先验证再写 |
| T5 | AV-Ops L2/L3 放行路径零实测；L4 无动作 | `avops` 表 + `TierL4.Implemented=false` | 面板能点但没真机证明 | P2-5 |
| T6 | 真实 `.sys` 加载未真机验证 | `drivers/` 只做校验与选路 | 驱动路线未闭环 | P2-5 |
| T7 | **inline hook 未做**（IAT 单层） | `mexecguard_windows.go` 注释明确"不做" | 运行期解析地址裸调/静态链入的退出调用拦不到 | 🚫 定论不做 |
| T8 | 无控制台启动时抓不到 stdout | 结果里会写"未捕获到任何内容（可能原因…）" | WMI/服务拉起的宿主拿不到输出 | 文档化；后续可考虑管道重定向 |
| T9 | `dll` 内存执行分支未真机验证 | 宿主线程同步执行被映射代码 | 该分支可能带走宿主线程 | 待真机 |
| T10 | `blob_windows.go` 注释声称"判定栈上镜像帧"，实现里没有 | `blob_windows.go` 的注释指向 `mexecguard_windows.go`，后者只做 IAT | 误导后续维护 | 改注释（文档债） |
| T11 | `nano ≤1.8 MB` 在 Go 下不可行 | 核心标准库地板 2.01 MB（下表） | 只能靠第二植入端（Rust） | 🚫 定论不做（Go 侧） |
| T12 | `light ≤2.4 MB` / `full ≤3.2 MB` 未达成 | 实测 2.95 MB / 3.52 MB | 体积目标需重定或靠 stdlib 瘦身 | 重定目标（P2-1 后一起评） |
| T13 | `tasks.output` 入库截断 500 字节 | `database/database.go:344`（`truncateTaskContent(..., 500)`） | 重启恢复后的结果长度受限 | 提高上限或改外置（v1.5 后单独评估） |
| T14 | `data/tools/` 空 | 目录只有 `.gitkeep` | 远程加载无载体 | P2-3 |
| T15 | `exec_module`：仅 TCP 真机 / 单帧 4 MiB 无分块 / 未暴露工具面 | `handlers_modules.go`、`modules/` | 大模块下发受限；AI 无法自主用 | 分块 + 工具面（需先解决"谁批准的"） |
| T16 | 屏幕流 unix 全 stub | `screen_stream_unix.go` 直接返回 "only supported on Windows" | Linux/macOS 无屏幕能力 | P2-4 类真机依赖 |
| T17 | 植入端**两份镜像**（`internal/server/builder/implant` 与 `release/implant`）靠人工 SHA-256 比对 | 两目录内容重复 | 改动漏同步 = 发布版与源码不一致 | 加 CI 一致性校验（P0-4/P1-7） |
| T18 | `go test -race` 在 windows/386 不可用（`CGO_ENABLED=0`） | 本机环境约束 | 并发缺陷只能靠顺序用例兜 | 记录在 CHANGELOG；CI 上跑 linux/amd64 的 race |
| T19 | `listener.ws_path` / `ws_host_allowlist` 是**全局配置**，WS 监听器共用 | `config.go` 注释明确 | 多监听器共用同一路径策略 | per-listener 覆盖（v1.5 后） |
| T20 | `docs/plan/*.md` 不入库（本地方案文档） | `.gitignore` 忽略 `docs/plan/` | 外部无法复核早期方案 | 保留（避免泄露内部计划） |

**本次核实到的 4 处「文档说过头 / 已过期」（已在本文件修正，原始证据见 `docs/VSHELL-ANALYSIS.md` §6）**：

| # | 原表述 | 代码事实 | 本文件处理 |
|---|---|---|---|
| D1 | "uTLS/JA3 **未开工**"（S5 延伸） | `transport_tls_utls.go` 已实现（`HelloChrome_102`，utls v1.4.0，仅 full 档 HTTP） | 改为 ⚠️「已实现未验证」 |
| D2 | "发版门禁接进 CI ❌ 未做" | `release.yml` 已有 `e2e-smoke` job，且发布 job `needs: [web, e2e-smoke]` | 改为 ✅（并注明托管 runner 固定 `-SkipImplant`） |
| D3 | "缺陷①/② ❌ 未开工" | `09e3bbe` / `9c98599` 已修，回归用例在 `ai/parallel_tool_calls_test.go` | 改为 ✅ 并归档 |
| D4 | "WS 拟态不反代，只回 404" | HTTP 监听器已支持 `mimicry_site` 反代 + `mimicry_profile` 响应整形；WS 侧确实只 404 | 分开写：HTTP 🟡 / WS ❌ |

---

## 附 A：体积矩阵（v1.4.0 本机实测）

**口径**：`windows / 386`、`exe`、植入端工具链 **Go 1.20.14**、**不启用** garble / UPX / BOF / `evasionscan`；按 1 MB = 10⁶ 字节计。构建参数：`-s -w -buildid= -trimpath -H windowsgui`。本次由构建器逐档直接构建，与 `scripts/pe_footprint.ps1` 同一套口径。

| 变体 | 字节 | 相对 `light`+tcp | 说明 |
|---|---|---|---|
| 空程序（Go runtime 地板） | 801,280 | — | **0.80 MB 地板** |
| 空程序 + `net`+`json`+`fmt`+`os`+`time` | 2,010,624 | — | **核心标准库地板 2.01 MB**（已超 nano 目标 1.8 MB） |
| **`light` + tcp** | **2,946,805**（≈2.81 MB） | 基准 | 最小可用档 |
| `light` + tcp + **`execmodule`** | 2,973,941 | **+27,136** | 内存模块门控的代价 |
| `light` + tcp + `evasionscan` | 2,953,973〔换算〕 | +7,168 | 杀软进程枚举（默认关） |
| **`full` + tcp** | 3,522,293（≈3.36 MB） | **+575,488** | 全部 Windows 可选功能 tag 之和 |
| `light` + **http** | 5,455,613 | **+2,508,808** | 引入 `net/http` + `crypto/tls` + uTLS |
| `light` + **websocket** | 5,097,728 | +2,150,923 | 再叠 gorilla/websocket |
| `light` + **mqtt** | 5,399,798 | +2,452,993 | 再叠 MQTT 库 |
| `full` + mqtt | 5,975,286〔换算〕 | +3,026,433 | 最重组合 |

**工具链与交叉编译说明**：

- **服务端**：当前仓库 `go.mod` 为 `go 1.25.0`，用本机 Go 直接编译；`-tags webui` 才内嵌控制台（`cmd/server/embed*.go`）。
- **植入端**：模板锁定 **go1.20 工具链**（构建时自动取对应版本；`release.yml` 会预取 **go1.20.14**），以便在较老 Windows 上运行；`full` 档 HTTP 通道依赖 `refraction-networking/utls v1.4.0`，`websocket` 档依赖 `gorilla/websocket v1.5.0`（见 `release/implant/go.mod`）。
- **C 植入端**：需与目标架构一致的 mingw-w64 gcc（缺则构建明确报错，而不是产出错架构产物）；`format=dll` 走 `-buildmode=c-shared`。
- **口径提醒**：表中标〔换算〕的两行（`light`+`evasionscan`、`full`+`mqtt`）未随发布版重测，绝对值按"发布版基准 + 同迭代早期实测增量"换算，只作量级参考；**绝对体积一律以本表为准**，CHANGELOG 只记相对增量。

**结论（如实）**：

1. 体积大头是**传输栈**（http/ws/mqtt 各 +2.15~2.51 MB），比所有功能 tag 加起来（+0.58 MB）大一个量级 → **要小就留在 tcp 档**。
2. `exec_module` 买到的是"**最小载荷 + 按需全功能 + 模块可服务端更新**"，**不是**把 2.8 MB 压到 1 MB 级。
3. `nano ≤1.8 MB` 在 Go 下**做不到**（核心标准库地板 2.01 MB）；要碰 200 KB~1 MB 只能**第二植入端**（Rust，见 P2-1）。

---

## 附 B：文档纪律（每次发版前自查）

1. **状态只在「状态总览」判一次**：其他章节只写方案与证据，不另判状态（避免两处矛盾）。
2. **✅ 必须有出处**：测试名、脚本输出、真机记录，三者之一。
3. **⚠️ 必须写清缺哪种验证**（不是"待验证"三个字）。
4. **禁止表述**：「完全免杀」「绕过所有 EDR」「100% 免杀」「一定能过 X」。
5. **改动 `internal/server/builder/implant/*` 时同步 `release/implant/*`**，并在提交信息里写明两份镜像的 SHA-256 一致性检查结果。
6. **发版前三件事**：`go build ./...` / `go vet ./internal/server/...`（与 CI 同口径）/ `go test ./...` 全绿；`scripts/e2e_smoke.ps1` 无 ❌；`scripts/mcp_smoke.ps1` 全过（若改了 MCP 面）。

---

**© 2026 ToShell · MIT License** · 仅供授权测试与学习研究
