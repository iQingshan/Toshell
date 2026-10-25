# SOCKS5 代理「下载卡死」问题分析报告

> 状态：**已定位 → 已修复 → 已实测验证**（根因与修复见 §10；§1–§9 保留当时的定位过程，未回改）。
> 时间：2026-09-15 20:0x–20:5x　环境：服务端与植入端**同一台机器**（本机 = 192.168.1.28）
> 分析口径：先给可复现的实测数据，再给"本次会话到底动了什么"的可达性判定，最后给假设排序与判定实验。

---

## 0. 结论摘要（先看这段）

| 项 | 结论 | 置信度 |
|---|---|---|
| 现象是否真实 | **真实且可复现**：经 SOCKS5 代理(127.0.0.1:1080) 的**下载**在传了约 170–335 KB 后**彻底停止**；**上传完全正常**（5 MB / 485 KB/s） | 确定（实测） |
| 是否"代理整体坏了" | 否，是**单向（下行）坏**：每个 tunnel 都能正常建连、握手、返回 200 | 确定 |
| **根因（已确认）** | **`release/implant/tunnel.go` 的 `readLoop` 把"读入数据区"的上界写成了 `cap(fb)`** —— 池缓冲容量里还留着 16B 的 SM4-GCM tag 余量，于是单次 `Read` 最多返回 `maxRead+16` 字节 → `sm4GCMSeal` 的 `append(tag)` 越过 cap（重新分配、返回值被 `_ =` 丢弃）+ `fb[:…+tagLen]` 越界 → **panic 被 `recover()` 静默吞掉 → 该隧道下行 goroutine 直接消失**（writeLoop 还在等 `readDone`） | **确定（已修复并实测）** |
| 该缺陷的年龄 | 自 **v1.2.0 首次开源导入（2026-08-27）** 起就存在（`git log -S 'envOff+envHdrLen : cap(fb)'`），属**长期潜伏**缺陷，**不是本次会话引入** | 确定（git 证据） |
| 与本次会话的关联 | 本次会话只动过两处与代理路径相交：① 植入端发送路径插入 `ensureUnmasked()`（`8156619`）——属**方向不对称隐患，已一并修掉，但不是本次卡死的根因**；② 运行中的服务端被本地重建替换（`Commit: dev / Build Time: unknown`） | 事实 + 结论已修正 |
| 修复后实测 | **10 MB 下载 8.7 s 完成（1.14 MB/s）**；连续 3×3 MB 全部完成；5 MB 上传 3.2 MB/s 正常 | 确定（实测） |


> 换句话说：**"哪个改动导致的"这个问题，我用静态分析给不出确定答案**，必须靠 §6 的第 1、2 条实验定性。下面把每一步推理和证据都摊开，你可以直接按实验清单去验。

---

## 1. 现象与复现（硬数据）

全部为本机实测（`curl.exe`，2026-09-15 20:2x）。代理：`socks5h://127.0.0.1:1080`（服务端为当前会话起的 SOCKS5 隧道代理，走植入端 `build-1789472722331327900.exe` 出网）。

### 1.1 下载（目标 → 植入端 → 服务端 → 浏览器）

| 测试 | 结果 |
|---|---|
| **直连对照** Cloudflare 10 MB | 666 KB/s，15.0 s **完成** ✅ |
| 代理 10 KB | 14 KB/s，0.71 s **完成** ✅ |
| 代理 100 KB | 193 KB/s，0.52 s **完成** ✅ |
| 代理 1 MB | 只到 **302 KB**，25 s 超时未完成（12 KB/s） ❌ |
| 代理 5 MB | 只到 **335 KB**，25 s 超时未完成（13 KB/s） ❌ |
| 代理 1 MB（放宽到 120 s） | 只到 **172 KB**，120 s 超时未完成（1.4 KB/s） ❌ |
| 代理 3 MB（30 s） | 只到 **22 KB** ❌ |

**关键特征**：卡死点不固定（172 / 302 / 325 / 335 KB），说明**不是"某个固定缓冲区阈值"**，而更像"某个时刻状态被破坏后永久停摆"。

### 1.2 上传（浏览器 → 服务端 → 植入端 → 目标）

| 测试 | 结果 |
|---|---|
| 代理上传 1 MB | 411 KB/s，2.5 s **完成** ✅ |
| 代理上传 5 MB | 485 KB/s，10.8 s **完成** ✅ |

### 1.3 卡死瞬间的方向定位（关键证据）

在代理下载 3 MB 的过程中同时采样：

| 时刻 | tunnel 102 `bytes_out`（下行） | 植入端 CPU | 植入端 `ReadTransferCount` |
|---|---|---|---|
| t=3 s | 325,052 | — | — |
| t=11 s | **325,052（零增长）** | 20 s 内仅 0.188 s | 冻结 |

- 服务端侧 `bytes_out` **完全不再增长** → 服务端**没有收到任何下行隧道帧**（`tunnel.go:712` 的 `AddBytesOut` 在成功解析出下行包之后才累加）。
- 植入端 CPU 几乎不动、读计数冻结 → **不是"在疯狂加密/发送"，而是链路被阻塞**。
- 与此同时上传仍然畅通 → **问题严格限定在"植入端 → 服务端"的发送方向**。

---

## 2. 事实基础：数据路径与方向映射（带代码位置）

```
下载: 目标 ──▶ 植入端 dial 的连接 ──▶ writeRawFrame() ──▶ C2 socket ──▶ 服务端 tcp_listener 解密 ──▶ SOCKS5 ──▶ 浏览器
      release/implant/main.go:731            :737                                  tcp_listener.go:1200
      ↑ 本会话在此插入 ensureUnmasked()（sm4.go:278）           ↑ 服务端侧本次未改
      累加点: internal/common/tunnel/tunnel.go:712 (AddBytesOut)

上传: 浏览器 ──▶ SOCKS5 ──▶ 服务端 tcp_listener 加密 ──▶ C2 socket ──▶ 植入端收帧 ──▶ 写目标
                              tcp_listener.go:564                      main.go:591 起（frameTypeRaw 快路径）
      累加点: internal/common/tunnel/tunnel.go:1211 (AddBytesIn)
```

**方向不对称的结构性事实**（这是本报告最重要的一条）：

| 方向 | 植入端使用的函数 | 本会话是否插入 `ensureUnmasked()` |
|---|---|---|
| **下载**（植入端发出） | `writeRawFrame` → `sm4EncryptTunnel`（`main.go:737` → `sm4.go:276`） | **是**（`sm4.go:278`） |
| 上传（植入端接收） | 收到 `frameTypeRaw` 走 **raw 快路径**（`main.go:591` 注释：*"gost fast path: raw 隧道帧（无 AES-GCM）"*） | 否 |

也就是说：**"只有下载坏、上传好"这个形态，恰好等于"唯一被插入 hook 的那条方向坏了"**。这是目前最强的间接指向。

---

## 3. 本次会话改了什么（完整清单 + 是否可达代理路径）

会话范围：`8fc4bda` 之后到 `a425c04`（HEAD），外加**运行产物的操作**（重建服务端 exe、多次强杀重启）。

| # | 提交/操作 | 触及代理路径？ | 说明 |
|---|---|---|---|
| 1 | `8156619` 动态免杀第一批（sleep mask + 去 RWX）— 植入端模板 12 个文件 | **间接相交** | `sm4.go` 两个函数各插入一行 `ensureUnmasked()`（`:278` 加密=下载方向、`:295` 解密）；`main.go` 增加 `initSleepMask`/`maskedSleep`×3/`registerSecret("sm4-tunnel-key")`/`maskIfMaskedCopy`。其余改动（`memprotect/blob/bof/carve/imgexec/plugin`）属**注入与内存执行**路径，**与本代理无关** |
| 2 | `bc03389` 生成载荷页节奏参数留空即跟随服务端 | 间接 | `handlers_builders.go`（新增 `implant_defaults`、`retry_wait` 归一化）、`config.go`（`implant.jitter` 默认 10%→20%）。**副作用**：页面不再预填 `jitter=10`，新载荷改为用服务端配置 `jitter=2` |
| 3 | `09ba630` `retry_wait` 归一化 | 否 | 仅构建请求字段 |
| 4 | `3a28811` / `ba126cc` / `75d0daa` / `47275ca` / `8fc4bda` | 否 | 纯 Web 前端 |
| 5 | `a425c04` 文档 + 打包 | 否 | 仅 md/yml/ps1 |
| 6 | **运行中服务端被本地重建 4 次并替换** | **是（但非源码差异）** | 现运行 `release\toserver.exe` = 我本地 `go build -tags webui -trimpath -ldflags "-s -w"`，`-version` 报 **`Commit: dev / Build Time: unknown`**（CI 构建会带上 commit 与时间）。中继/隧道源码未变，但**运行产物变了**，且我每次都用 `Stop-Process -Force` → **每杀一次，所有会话与 SOCKS5 隧道全部断掉** |

**本次会话"确定没有碰"的东西**（git 证据）：

| 目录/文件 | 最后改动 |
|---|---|
| `internal/common/tunnel/**`（下行/上行转发、`AddBytesIn/Out`） | `96f3fc5` 2026-09-14 |
| `internal/server/listener/**`（TCP 监听、心跳、SM4 收发） | `96f3fc5` 2026-09-14 |
| `internal/server/api/handlers_tunnels.go`（SOCKS5 管理） | `96f3fc5` 2026-09-14 |
| `release/implant/relay.go`、`release/implant/tunnel.go` | `56c349c` 2026-08-27（首版导入） |
| Clash/系统代理/防火墙/网络配置 | 本会话**从未读取或修改**（只做过 `git push`、网页抓取） |

---

## 4. 与代理相交的那一处改动：机理逐条分析

### 4.1 `ensureUnmasked()` 什么时候是空操作

```go
// release/implant/sleepmask_windows.go:145
func ensureUnmasked() {
    if !masked.Load() { return }        // ← masked=false 时立即返回，零开销
    abort.Store(true)
    deadline := time.Now().Add(2 * time.Second)
    for masked.Load() && time.Now().Before(deadline) { rawSleep(20 * time.Millisecond) }
}
```

- `masked` 只会被 `maskedSleep(d)`（`sleepmask_windows.go:181`）置起，且要求 **`d ≥ 2s` 且掩码密钥就绪**。
- `maskedSleep` 的调用点只有 4 处：`main.go:303`（启动随机延迟）、`main.go:409`（非工作时段 5 min）、`main.go:439`（重连退避）、`transport_http.go:321`（HTTP 轮询空闲 5 min）。
- **TCP 长连接正常工作时不会走任何一处** → 理论上 `masked == false` → 对下行路径**零影响**。

**结论**：如果只有这一条路径，`8156619` 对代理应无影响。**但**"理论应无影响"与"实测坏了"冲突，所以要么存在我尚未找到的 `masked` 置起路径，要么真正的根因在别处（见 §5）。

### 4.2 若 `masked` 真被置起，会发生什么（能否解释现象）

| 环节 | 后果 | 是否吻合"下载卡死/上传正常" |
|---|---|---|
| 下行帧经 `sm4EncryptTunnel` → 密钥缓冲 `tunnelKey` 已被 XOR | 密文用错密钥 → 服务端 `SM4DecryptTunnel` 认证失败 → **静默丢帧** → 下行永久停摆 | **吻合**（下行零增长） |
| 每帧都等 `ensureUnmasked()`（最多 2 s） | 下行限速到"一帧/2 s" | 不完全吻合（实测是**彻底停**，不是慢速蠕动） |
| 上传走 raw 接收路径（不查密钥） | 上传不受影响 | **吻合** |
| 客户端上行数据也走 AES-GCM 控制帧 | 上传仍正常 | **吻合** |

**重要反证**：如果 `tunnelKey` 被 XOR 后一直没还原，植入端**解密**上行帧同样会用错密钥 → 上传也该坏。实测上传 5 MB 正常，说明**要么 `tunnelKey` 没被破坏，要么上传方向根本不使用该密钥**（与 §2 的 raw 快路径一致）。**后者的可能性更大**，于是"下行用密钥、上行不用"就成了唯一解释通道——这也是必须做对照实验的原因：**光靠读代码无法判断 `masked` 是否曾被置起**。

### 4.3 另一个本会话引入的、与代理无关但值得记录的风险

`sleepMaskHook` 与 `maskIfMaskedCopy` 引入了 `maskStateMu` / `resultCacheMu` 的嵌套加锁。当前代码的加锁顺序是一致的（`maskStateMu` → `resultCacheMu`，参数在进入 `cacheResult` 前求值），**未发现死锁路径**；但这是"任务结果"路径，不参与隧道转发。

---

## 5. 假设排序（含支持/反对证据）

| ID | 假设 | 支持证据 | 反对证据 | 置信度 |
|---|---|---|---|---|
| **H1** | `8156619` 的休眠掩码改动破坏了**下行发送路径**（密钥被 XOR 或 hook 阻塞） | 坏的方向**恰好**是本次唯一被插入 hook 的方向；卡死点随机（符合"某时刻状态被破坏"）；上行完全正常 | 代码上 `masked` 在 TCP 会话期间本不该为真，**未找到触发链**；若密钥被破坏，上行解密也应受影响 | **中**（形态吻合，机理缺口） |
| **H2** | 运行中的服务端被**本地重建替换**并在本会话被强杀 4 次 | `-version` 显示 `Commit: dev / Build Time: unknown`（非 CI 产物）；每次强杀掐断所有隧道；用户首次感知到故障的时间窗（20:13）就在最后一次重启（20:09）之后 | 中继/隧道源码未改；直连与上传都正常，不容易解释"仅下行永久停" | **中** |
| **H3** | 植入端**空闲判死**（`maxIdleReadDuration = 60s`，代码注释写明按 `interval 5s` 设计）与当前 `interval = 60s` 不匹配 → 下载期上行静默可能判死重连 | 常量与注释明确不匹配（`main.go:93`）；下载期上行几乎无应用层数据 | 实测会话远端端口 8 分钟未变（无重连）；且判死会**双向**中断 | **中低**（真实隐患，但非当前直接原因） |
| **H4** | 本机安全软件（360 / 腾讯电脑管家 / 无边界）对**下行大流量**做内容检查/阻断 | 本机 AV 行为极活跃：**就在刚才，`release\bin\` 下 6 个未签名 PE 在我尝试执行时被删除（整个目录消失）**；只坏一个方向与该类产品行为一致；与本次改代码无关 | 直连 10 MB 下载正常（说明不是"所有入站都拦"）；无法解释为何恰好卡在 ~300 KB | **中低** |
| **H5** | 上游遗留的下行转发缺陷（`tunnel.go:1195` 注释提到历史"~51 Mbps 吞吐上限"；存在 `internal/common/tunnel/optimized/` 双实现） | 卡死属于"消费者停止 drain"型特征；上报的 44 Mbps 上传接近历史天花板 | 该代码 2026-09-14 后未改，属"一直存在"，不能解释"最近才坏" | **低** |
| **H6** | Clash / 系统代理 / 文档 / 打包 / Web UI 导致 | — | 本会话**没有**改动任何网络或代理配置，未读写 Clash 配置；文档与打包完全离线 | **排除** |

---

## 6. 判定实验（**未执行**，按性价比排序）

> 目标是**定性**，不是修复。第 1、2 条任一完成即可把 H1 与 H2 分开。

**实验 1（最快，直接区分"没发"还是"解不出"）**
把服务端日志落到文件后再复现一次下行卡死：
1. 临时把 `release/configs/server.yaml` 的 `logging.output` 改为文件（或直接前台运行 `toserver.exe` 看 stdout）；
2. 重启服务端，让植入端自动重连；
3. 重放 `curl -x socks5h://127.0.0.1:1080 https://speed.cloudflare.com/__down?bytes=3000000`；
4. 观察是否出现 **SM4 解密失败/丢帧** 类日志。
   - 有 → 植入端发了但服务端解不出 ⇒ **H1**（密钥/掩码问题）成立；
   - 无（服务端只是收不到帧）⇒ H1 削弱，转 H2/H4/H5。

**实验 2（最决定性）**
用 `8156619` **之前**的模板构建对照载荷：
1. 取 `f19264f`（或 `8fc4bda`）时的 `release/implant/` 到临时目录，用同一服务端构建一个对照 exe（服务端只读 `release/implant`，替换前后各构建一次即可）；
2. 在同一台机器上停掉当前植入端、运行对照载荷、上线；
3. 重放同一组 `curl`（下载 3 MB + 上传 1 MB）。
   - 对照载荷下载正常 → **回归来自 `8156619`**（H1 确认）；
   - 对照载荷同样卡死 → **与本次植入端改动无关**（转 H2/H4/H5）。

**实验 3（排除"我本地重建的服务端"）**
从 GitHub Release 下载 CI 构建的 `toshell-server-windows-amd64.zip`，用**同一份配置**替换运行中的 `release\toserver.exe`（保持监听 8080/1080/18081），重放同一组测试。CI 产物会显示 `Commit/Build Time`，可与当前 `Commit: dev` 明确区分。

**实验 4（排除公网/对端因素）**
在 `release\` 下用一个临时静态服务（或任何本机可控 HTTP）托管一个 20 MB 文件，把它作为代理目标重放测试。本机→本机不受公网与 CDN 影响，能把变量压到只剩隧道本身。

**实验 5（排除本机安全软件）**
在安全软件放行/临时退出后重放实验 4。注意本机 AV 对未签名 PE 是**直接删除**级别（现场已复现），所以第 2 条实验要提前把对照载荷加入白名单，否则会被删。

**实验 6（补证方向性）**
卡死时同步观察：`GET /api/v1/tunnels` 的 `bytes_out` 是否零增长（我已实测：是零增长）、服务端侧是否仍在收字节（需日志或 ETW 才能按连接看，PowerShell 无现成计数器）。

---

## 7. 影响面与风险

- **用户可见影响**：经 SOCKS5 代理的**网页浏览、文件下载、远程下载工具**等一切"下行 > ~300 KB"的场景会卡死；小响应（<100 KB）与上行（上传）正常。因此短连接测速表现为 **延迟正常、下载 0 Mbps、上传正常**，与你的测速数据完全一致。
- **不是"代理整体不可用"**：建连、鉴权、握手、上行都正常，容易误判成"网络问题"。
- **与本报告相关的现场副作用**（如实记录）：
  - `release\bin\` 下 6 个旧跨平台二进制已被本机安全软件删除（我尝试执行其中一个时触发）；
  - 当前运行的服务端为本地构建（`Commit: dev / Build Time: unknown`），非 CI 产物；
  - 本次会话中我**强杀并重启服务端 4 次**，每次都会掐断所有会话与隧道。

---

## 8. 附：原始命令

```powershell
# 下载对照（直连 / 代理）
curl.exe -s -o NUL --max-time 60 -w "http=%{http_code} dl=%{speed_download} t=%{time_total}`n" "https://speed.cloudflare.com/__down?bytes=10000000"
curl.exe -s -o NUL --max-time 60 -x socks5h://127.0.0.1:1080 -w "http=%{http_code} dl=%{speed_download} t=%{time_total}`n" "https://speed.cloudflare.com/__down?bytes=10000000"

# 上传对照
curl.exe -s -o NUL --max-time 60 -x socks5h://127.0.0.1:1080 -X POST --data-binary "@$env:TEMP\up5mb.bin" -w "sent=%{size_upload} speed=%{speed_upload}`n" "https://speed.cloudflare.com/__up"

# 卡死时看隧道计数（bytes_out 零增长 = 服务端没收到下行帧）
> 注：本文示例里的 `change-me-api-key` 是占位符，请换成你自己的 API Key（不要提交真实 key）。

Invoke-WebRequest -Uri 'http://127.0.0.1:18081/api/v1/tunnels' -Headers @{'X-API-Key'='change-me-api-key'} -UseBasicParsing
```

---

## 9. 待你确认的问题（会影响下一步定位方向）

1. **故障起点**：这条"下载卡死"是**今天什么时候开始**的？如果早于 `8156619`（19:38）就存在，H1 直接排除。
2. **对照基线**：在故障出现前，代理下载**曾经跑满过**吗（比如能拉完 10 MB 的文件）？
3. **是否只有本机路径**：换一台机器/换一个植入端目标，下行还卡吗？
4. **44 Mbps 上传的测法**：是在浏览器里跑测速站得到的，还是用代理客户端节点测速得到的？这决定"代理"指的是 ToShell SOCKS5 还是本机 Clash。

---

## 10. 根因与修复（已实施并实测验证）

### 10.1 根因：`readLoop` 读上界写成了 `cap(fb)`

`release/implant/tunnel.go`（植入端下行热路径）：

```go
var tunnelBufPool = sync.Pool{New: func() interface{} {
    // 容量 = 5(len) + 12(nonce) + 9(信封头) + 64KB(数据) + 16(tag)
    return make([]byte, frameHdrLen+nonceLen+envHdrLen+maxRead+tagLen)   // 65,578
}}
...
n, err := e.c.Read(fb[envOff+envHdrLen : cap(fb)])                       // ❌ 上界多算了 16B tag
sealed, _ := sm4GCMSeal(fb[envOff:envOff+envHdrLen+n], tunnelKey, fb[frameHdrLen:envOff])
...
case tunnelFrameCh <- fb[:frameHdrLen+nonceLen+envHdrLen+n+tagLen]:      // ❌ n>maxRead 时越界
```

- `cap(fb)` = 65,578，`envOff+envHdrLen` = 26 ⇒ 单次 `Read` 最多返回 **65,552 = maxRead+16** 字节。
- `sm4GCMSeal` 内部是 `return append(plaintext, tag[:]...)`：当 `9+n+16 > cap-envOff`（即 `n > 65,536`）时它会**重新分配新数组**，而调用处把返回值丢给了 `_`，`fb` 里留下"没有 tag 的密文"。
- 紧接着 `fb[:5+12+9+n+16]` = `fb[:42+n]`，`n > 65,536` 时 **> 65,578 越界 → panic**。
- panic 被 `readLoop` 的 `recover()` **静默吞掉**（旧代码里 recover 体是空的），而 `readLoop` 是这条隧道**唯一的下行产出者**；`writeLoop` 还在等 `<-e.readDone` ⇒ 隧道既不产出数据、也永不收尾。

**这解释了全部观测**：下行在随机几百 KB 后永久冻结、`bytes_out` 零增长、植入端 CPU 几乎不动（不是在发送）、会话仍显示 active、上行完全不受影响、换目标换机器一样复现（取决于目标单次能塞满多少内核缓冲，与目标是谁无关）。

> 为什么"以前可以用"：触发条件是**单次 Read 拿到 >64 KB**（需要目标侧内核缓冲被填满），属于时序相关；小资源浏览不会命中，大文件/测速才会。该行自 8-27 首版导入就存在，因此**不是今天改出来的**——这点我按 git 证据如实修正了 §0/§5 的推断。

### 10.2 修复内容（两个镜像目录同步改，`release/implant` 与 `internal/server/builder/implant` 保持字节一致）

1. **收紧读上界**（根因修复）：
   ```go
   n, err := e.c.Read(fb[envOff+envHdrLen : frameHdrLen+nonceLen+envHdrLen+maxRead])
   ```
   让 16B tag 余量不再被数据吃掉，`append(tag)` 必然原地完成、`fb[:42+n]` 必然不越界。
2. **panic 不再造成僵尸隧道**：`readLoop` 的 `recover()` 里按"读侧结束"收尾（幂等 `closeReadDone(e)` + 关目标连接），任何未来的 panic 都会让隧道**干净地结束**（浏览器立刻拿到 EOF/失败），而不是无限挂住。
3. **补上方向不对称**：下行热路径（`readLoop` 的 `sm4GCMSeal`、`sendCloseAsync`）此前**直接**用 `tunnelKey`，而上行解密走 `sm4DecryptTunnel` 里有 `ensureUnmasked()`。一旦休眠掩码生效，下行就会用被 XOR 的密钥加密 → 服务端认证失败丢帧。现两处均补 `ensureUnmasked()`，两个方向口径一致。

### 10.3 实测验证（同一台机器，A/B 对照）

| 测试 | 修复前（旧载荷） | 修复后（新载荷） |
|---|---|---|
| 代理下载 1 MB | 302 KB 后卡死 | **1,000,000 B 完成**（133 KB/s） |
| 代理下载 5 MB | 335 KB 后卡死 | **5,000,000 B 完成**（382 KB/s） |
| 代理下载 10 MB | 120 s 只到 172 KB | **10,000,000 B 完成，8.7 s，1.14 MB/s** |
| 连续 3×3 MB | 随机卡死 | **3/3 全部完成** |
| 代理上传 5 MB | 正常（485 KB/s） | 正常（**3.2 MB/s**） |

现场状态：旧的（有缺陷的）植入端进程已停止，SOCKS5 代理已重新绑定到修复后的会话，**端口仍是 1080**，浏览器无需改配置。

---

*本报告的第一版只做归因分析（未改代码）；在拿到确认后按 §10 完成了修复与实测验证。§5 的 H1（"`8156619` 的掩码改动是根因"）已被证据否定：卡死期间植入端**完全静默**（不是在发送用错密钥的数据），真正消失的是下行 readLoop 本身。*

