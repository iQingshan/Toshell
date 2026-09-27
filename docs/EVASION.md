# 免杀：概念、当前手段、验证方法与实测状态

> 这份文档存在的唯一目的：**别再自己骗自己**。
> 上一版把"把二进制里的字符串改一改"写成"免杀"，导致操作员按文档预期去测却发现"运行即被拦"——
> 那是三类完全不同的东西被混在一起说。本文件把它们分开，并且对每一项标注**验证到了什么程度**。
>
> 适用版本：v1.4.0（开发中；上一发布版 v1.3.5）｜ 仅限**授权**测试使用（见仓库根 `DISCLAIMER.md`）。

---

## 1. 三类东西，别混着说

| 类别 | 作用对象 | 典型手段 | 对"运行即被拦"有用吗 |
|---|---|---|---|
| **落地 delivery** | 怎么把载荷送上目标机、能不能被执行 | 代码签名、白加黑 DLL 侧加载、计划任务 + 已签名宿主、内存加载 shellcode | ✅ **这才是治"起不来"的**（在装有 360/电脑管家的机器上，未签名的新 PE 会在创建进程阶段被拒绝执行并删除） |
| **动态免杀 evasion** | 进程**运行期**的内存与调用行为 | 休眠期内存加密（sleep mask）、去掉 RWX、APC/`NtDelayExecution` 替代 `Sleep`、AMSI/ETW 用户态 patch、间接系统调用、模块 stomping、调用栈伪装 | ✅ 对抗内存扫描 / 行为引擎；**对"未签名 PE 被拒绝执行"无效** |
| **静态降特征 footprint** | 文件字节（字符串、符号、构建指纹） | 字符串混淆、pclntab 中性化、BOF 按需编译、Go buildinfo 擦除、每构建随机化、UPX/garble | ❌ 基本无效（那层看签名、信誉、投放路径与运行时行为），只降低静态查杀/规则命中的概率 |

**一句话**：静态降特征 ≠ 免杀；免杀 ≠ 能落地。三件事要分别做、分别验。

> §1 表里的"典型手段"只是**这一类手法的举例**，不代表本项目都已实现。哪些做了、做到什么程度，只看 §2 的逐项标注。

> **先读这一段（重要）**：下面 **2.2 动态免杀** 里的每一项，维护者都**没有在测试 VM 上做过运行期验证**。
> 原因是开发机装有 360 安全卫士 / 腾讯电脑管家等国产安全软件，**任何新构建的未签名二进制一执行就被拒绝并删除**
> （连 `time.Sleep` 的 Hello-World Go 程序也一样，见 CHANGELOG v1.3.4），根本跑不到"观察内存"这一步。
> 因此动态条目当前能给的最强结论是 **编译验证 + 源码审计**，请**不要**把它读成"运行期已验证"或"实测免杀有效"。
> 动态结论只能靠 §3 的流程在你自己的目标机上得出。

---

## 2. 当前手段与验证状态（v1.3.5）

图例：✅ = 有实测证据 ｜ ⚠️ = 只有编译验证 / 源码审计 / 命令生成验证，**运行期未实测**。

植入端模板有**两份字节一致的镜像**：`internal/server/builder/implant/`（开发/构建源）与 `release/implant/`（发布包内随 `toserver` 分发，服务端会在 exe 同目录找 `implant/`）。模板目录解析顺序（`resolveImplantTemplateDir`，`internal/server/builder/builder.go`）：`implant.template_dir` 配置 → 环境变量 `TOSHELL_IMPLANT_TEMPLATE_DIR` → exe 同目录 `implant/` → exe 同目录 `internal/server/builder/implant` → 当前工作目录 `internal/server/builder/implant`（命中条件是该目录里存在 `main.go`）。下文实现位置以镜像内的同名文件为准；**只改一份会导致"开发能用、发布包失效"**。

### 2.1 落地 delivery

| 手段 | 实现位置 | 验证到什么程度 |
|---|---|---|
| 代码签名（pfx 证书文件 / 本机证书存储指纹） | `internal/server/builder/sign.go`（接线：`internal/server/api/handlers_builders.go`、`internal/server/api/handlers_settings.go`） | ✅ **实测**：本机自签证书 → 构建 → `Get-AuthenticodeSignature`：`SignatureType=Authenticode`、签名者指纹一致、体积 +1.4KB；自签根未导入时状态 `UnknownError`（= 已签名但链不受信任，符合预期）。**未验证**：签名后在装有 360 的机器上是否放行（需要目标机） |
| 8 条加载器链 + 降级建议 | `internal/server/api/oneliner.go`（`loaderChainVariants` / `LoaderAdvice`）、`docs/LOADERS.md` | ⚠️ 命令生成已实测（含单测 `oneliner_loader_test.go`）；**端到端成功率未验证**（需要自备宿主 exe / 放行环境） |
| 真 DLL（c-shared，加载即启动、导出名可配） | `internal/server/builder/dll.go`（`sharedGCC` / `compileSharedLibrary` / 胶水生成）；入口拆分 `internal/server/builder/implant/entry_exec.go` + `main.go` 的 `startImplant()` | ✅ **静态实测**：386 DLL `IMAGE_FILE_DLL=true` + 导出表含 `Start` / 自定义 `GetFileVersionInfoW`；**未验证**运行加载是否上线 |
| PE 头解析 + 内存执行预检（`fileless-exec` 下发前） | `internal/server/builder/pecheck.go`（接线 `internal/server/api/handlers_fileless.go`，`CheckMemoryExec` / `DetectGoBinary`） | ✅ **静态实测**（`pecheck_test.go`）：Go 载荷、架构不符、带 CLR 目录 → 拒绝；TLS 回调 / 无重定位表 / DLL 误用 `exe_mem` → 警告。**未验证**目标机上的实际加载行为 |
| 一份模板两处镜像（发布包不漏模板） | `internal/server/builder/implant/` ↔ `release/implant/` | ✅ 逐文件比对：两份目录各 61 个文件，**文件名集合与 SHA-256 全部相同**（含 `sleepmask_*`、`memprotect_*`、`main.go`、`gate_scan_*`） |

> **如实说明（避免误读）**：`pecheck.go` 只做 **PE 头解析**（machine / 是否 DLL / TLS 目录 / CLR 目录 / 重定位表 / 节表属性），
> 它**不判定 W^X**；"绝不请求 RWX"的实现在植入端 `memprotect_windows.go`（见 2.2）。两者不是同一件事，不要混着引用。

### 2.2 动态免杀 evasion

> 本节全部条目：**没有运行期实测**（原因见文首）。

| 手段 | 实现位置 | 验证到什么程度 |
|---|---|---|
| 休眠期内存加密（sleep mask） | `internal/server/builder/implant/sleepmask_windows.go`（镜像 `release/implant/sleepmask_windows.go`）；调用点 `internal/server/builder/implant/main.go`（`initSleepMask` / `registerSecret` / `sleepMaskHook` / `cacheResult` → `maskIfMaskedCopy` / `maskedSleep`） | ⚠️ **仅编译验证**（386/amd64/light/evasionscan 全通过）+ 并发设计人工审查；**运行期未实测**。验证方法见 §3.2 |
| 去 RWX（RW 申请 → RX 执行） | `internal/server/builder/implant/memprotect_windows.go`（镜像 `release/implant/memprotect_windows.go`）；调用方 `imgexec_windows.go` / `injection_windows.go` / `bof_windows.go` 等 | ⚠️ 源码审计 + 编译验证；**未验证**改保护后注入/内存执行仍成功。验证方法见 §3.3 |
| `NtDelayExecution` 替代 `Sleep` | `internal/server/builder/implant/sleepmask_windows.go` 的 `rawSleep`（走 apihash 解析，不进 IAT 明文） | ⚠️ 编译验证；未实测（IAT 里不再出现 `Sleep` 可用 `dumpbin /imports` 复核） |
| apihash / PEB 手工解析 API | `internal/server/builder/implant/apihash_windows.go`、`peb_windows.go`（镜像 `release/implant/` 同名文件） | ⚠️ 仓库既有能力；**未评估收益与代价**（手工解析本身也可能被 EDR 标记） |
| 直接系统调用（注入路径，amd64） | `internal/server/builder/implant/directsyscall_windows_amd64.go` + `.s`（DLL 构建走 `directsyscall_windows_amd64_shared.go` 回退） | ⚠️ 仓库既有能力；未实测 |
| `evasion_scan`（枚举进程找杀软）**默认关闭** | `internal/server/builder/implant/gate_scan_windows.go`（`//go:build windows && evasionscan`），默认实现 `gate_scan_off_windows.go`；门控在 `internal/server/builder/builder.go` 的 `buildTagList` | ✅ 行为变化实测（构建标签与产物体积，`gate_scan_test.go`）；收益未量化 |

sleep mask 具体做了什么（便于自查与排错）：

1. **休眠前掩码、唤醒后还原**：`initSleepMask()` 生成 32 字节掩码密钥（取不到随机数就**保持不加密**，不用固定密钥假装加密）；`maskedSleep(d)` 在休眠前对已注册缓冲做 XOR 掩码，睡醒后还原。
2. **注册了哪些秘密**：`registerSecret(label, buf)` 注册堆缓冲；当前 `main.go` 注册了 SM4 隧道密钥（`registerSecret("sm4-tunnel-key", tunnelKey)`）。
3. **缓存的任务结果也算**：`sleepMaskHook` 由 `main.go` 注册，休眠中对任务结果缓存存**加密副本**（`maskIfMaskedCopy`）；任何要解密/要用密钥的路径先 `ensureUnmasked()`，最多等一个分片（≈300ms）就还原。
4. **只在真正长睡时生效**：`maskedSleep` 仅在密钥就绪且 `d ≥ 2s` 时启用，否则退化为 `rawSleep`；休眠按 ≤300ms 分片并加随机抖动，便于随时被唤醒处理任务。
5. **不做什么**：不加密代码段、不加密 Go runtime 元数据、不加密 `string` 常量（见下方"已知做不到的"）。

去 RWX 具体做了什么：`allocRW` 用 `PAGE_READWRITE(0x04)` 申请（不可执行），写完再 `protectRX` → `PAGE_EXECUTE_READ(0x20)`；`setProtect` 在入口**硬性拒绝** `PAGE_EXECUTE_READWRITE(0x40)`（返回错误而不是降级），`sanitizeProt` / `restoreProtect` 保证"还原旧保护"时也不会还原成 RWX。

> **平台边界**：`sleepmask_unix.go` 与 `memprotect_unix.go` 是**空实现 stub**（只保持函数签名），
> Linux/macOS 上既不做休眠期内存加密，也没有自申请可执行内存的代码路径。
> 别把这两条动态能力当成跨平台的。

### 2.3 静态降特征 footprint

| 手段 | 实现位置 | 验证到什么程度 |
|---|---|---|
| 编译期字符串混淆（`xd("hex")` 运行时解码） | `internal/server/builder/implant_obfuscate.go` + 各植入端模板（解码层 `implant/obfuscate.go`） | ✅ **实测**（字符串体检 + 真实载荷上线）：v1.4.0 起覆盖**含转义的双引号字面量**（Windows 路径/设备名）与**反引号原始字符串**（注册表键/多行脚本，struct tag 仍原样保留），见下方"字符串明文漏点"；`implant_obfuscate_test.go` 覆盖三类字面量 + tag/const/注释/短串不误伤 + 幂等 |
| **DLL 路径的静态降特征对齐**（v1.4.0 S3 补） | `internal/server/builder/builder.go` 的 `compileLibrary()`：补 `injectBuildConstants` + `obfuscateImplantSources` | ✅ **实测**（产物计数）：DLL 修复前明文高信号 API 名 **11** 处、`http://` **2**、ETW **4**、持久化注册表键 **3**；补上混淆后降到与 exe 同水平（只剩 Go 标准库自带的各 1 处） |
| pclntab 中性化（函数名/文件名改中性名） | `internal/server/builder/implant/` 各模板（`main.go` 等） | ✅ **实测**（字符串体检） |
| BOF 按需编译（**默认关**） | `internal/server/builder/implant/bof_windows.go`（`//go:build windows && !light && bof`）与默认实现 `bof_stub_windows.go`；门控 `internal/server/builder/builder.go` 的 `buildTagList` | ✅ **实测**（字符串体检）：默认载荷 `beaconAPI=0`，勾选后 22（证明门控生效）；`gate_scan_test.go: TestBOFIsOptIn` |
| Go 构建指纹擦除（原地置零，长度不变） | `internal/server/builder/harden.go`（`ScrubGoFingerprint`：`\xff Go buildinf:` 魔数 / buildinfo 窗口内 `go1.x.y` / `Go build ID:` 前缀） | ✅ **实测**（字符串体检）：默认载荷 `Go buildinf=0`、`Go build ID:=0`；`harden_test.go` 覆盖擦除/幂等/边界 |
| **全文件 Go 版本串擦除**（v1.4.0 S3 新增，见下） | `internal/server/builder/harden.go` 的 `ScrubGoVersionStrings`，接入 `builder.go` 的 `compile()`（exe/bin/raw/shellcode）与 `compileLibrary()`（dll） | ✅ **实测**（产物计数）：修复前 exe 与 dll 各残留 `go1.20.14` **1 次**，修复后 **0 次**；`harden_test.go` 覆盖"窗口外命中/普通文本不误伤/幂等/空输入" |
| 每构建随机化（配置块魔数/密钥、xd 密钥基准、API 哈希种子） | `internal/server/builder/builder.go`、`internal/server/builder/evasion.go`、`internal/server/builder/implant/obfuscate.go` | ✅ **实测**（字符串体检）：默认载荷 `loadShellcode=0`、`kgameprotect/byovd/HVCI=0` |
| 高信号标识符（`loadShellcode` 等）默认不进载荷 | 同 pclntab 中性化 | ✅ **实测** |

静态体检的完整口径：默认载荷 `beaconAPI=0`、`loadShellcode=0`、`Go buildinf=0`、`Go build ID=0`、`kgameprotect/byovd/HVCI=0`、**`go1.` 版本串=0**。

#### 实测发现的字符串明文漏点（v1.4.0 S3，已修）

用 `windows/386` 产物逐条 `strings` 体检（高信号特征计数，脚本口径见 §4）：

| 产物 / 时点 | 明文高信号 API 名 | `http://` | ETW | 持久化注册表键 | 设备路径 |
|---|---|---|---|---|---|
| **DLL 修复前**（`format=dll`，白加黑链交付的正是它） | **11** | **2** | **4** | **3** | 2 |
| DLL 修复后 | 1（仅 Go 标准库的 `WriteProcessMemory` 符号表） | 0 | 0 | 1（仅标准库 `Time Zones`） | 1（仅标准库 `\\.\UNC`） |
| exe 修复前 | 1（标准库） | 0 | 2 | 3 | 2（1 处标准库） |
| exe 修复后 | 1（标准库） | 0 | 0 | 1（标准库） | 1（标准库） |

两个根因：

1. **DLL 路径漏了两道工序**：`compileLibrary()` 只做了 `copyImplantSource` + `processTemplates`，**没做** `injectBuildConstants`（每构建随机配置块魔数/密钥）与 `obfuscateImplantSources`（字符串混淆）——而 exe 路径一直都有。等于"最该藏的那条链"把 C2 地址、注册表键、ETW/注入 API 名**明文**交出去。
2. **混淆器本身有两处盲区**：只处理"简单双引号字面量"，于是 ① 含转义的 `"\\\\.\\kgameprotect"`、`"HKCU\\Software\\..."` 这类（Windows 路径/设备名在 Go 源码里的**标准写法**）被跳过；② 全部反引号原始字符串被跳过（旧理由只有一条："struct tag 不能改"）。修法：转义字面量用 `strconv.Unquote` 求运行期真实值再 XOR+hex（`xd()` 是纯字节解码，`\r\n`/NUL/非 UTF-8 都能原样还原）；原始字符串改为"**非 struct tag、非 const 行、≥4 字节**就混淆"，struct tag 仍原样保留。

代价（如实记录）：混淆把明文换成两倍长的 hex，**产物变大** —— exe 3456757 → 3467509（**+0.3%**），DLL 3414528 → 3511296（**+2.8%**，因为 DLL 此前完全没混淆）。这是 §4 体积分档要权衡的：默认档仍远低于 3.2MB 目标。

行为回归验证：`scripts/e2e_smoke.ps1` 用混淆后的模板真实构建并**执行** Windows 载荷（19 项 0 失败，会话上线 + `whoami` 回执正常），证明混淆没有破坏路径/格式串/脚本模板的运行期语义。

#### 实测：PE 节表 / 熵 / 资源现状（口径与下一步验收）

对 `windows/386` 默认档案产物逐节测量（脚本见 §4；这组数字是"节名/节熵口径"的基线）：

| 节 | 虚拟大小 | 原始大小 | 熵 |
|---|---|---|---|
| `.text` | 1716024 | 1716224 | 6.08 |
| `.rdata` | 1556184 | 1556480 | 5.69 |
| `.data` | 285352 | 110592 | 5.59 |
| `.idata` | 988 | 1024 | 4.58 |
| `.reloc` | 81202 | 81408 | 6.70 |
| `.symtab` | 4 | 512 | 0.02 |

另有：`TimeDateStamp = 0`（Go 链接器置零，**不是**指纹漏点）、overlay **245 字节**（就是被 XOR 过的配置块，符合预期）、**没有 `.rsrc` 节**。

判读：

- 熵都在 4.5~6.7 之间，是"未加壳的 Go 产物"的正常区间；一旦上 UPX 会整体升到 7.9+ —— 所以**熵本身不能当"是否可疑"的判据**，只能当"加壳前后是否如预期"的对照。
- `.symtab` 是 Go 在 PE 上自带的符号表节（`-s -w` 也保留），不是我们的疏漏。
- **没有 `.rsrc` 是目前最扎眼的"非典型 PE"信号**：正常商业/系统程序几乎都带版本信息（公司名/产品名/文件描述/版本/原始文件名）、图标与 manifest，而我们交付的载荷一样都没有；这也正是计划里"PE 版本资源 / 图标 / 公司信息 / 时间戳"那一项要补的东西，且**必须插在 UPX 与签名之前**（顺序契约见 §2.4，`builder/finalize_order.go` 会拦住"sign 不在最后"的改动）。
- 该项的验收口径（写在这里，落地时按它验）：① 产物出现 `.rsrc` 节；② `Get-ItemProperty <载荷> | Select-Object -ExpandProperty VersionInfo` 能读出我们写入的公司名/产品名/文件描述/版本；③ 资源查看器能看到图标；④ **顺序正确时签名仍有效**（签名在最后一步，改资源在它之前）—— 最后一条是整项的意义所在。

#### 实测发现的指纹漏点（v1.4.0 S3，已修）

构建 `windows/386` 产物后逐字节计数（`\xff Go buildinf:` / `Go build ID:` / 正则 `go1\.[0-9]`）：

| 产物 | 修复前 | 原因 | 修复后 |
|---|---|---|---|
| `format=exe`（Go，CGO_ENABLED=0） | 魔数 0、Build ID 0、**`go1.20.14` 命中 1 次** | `ScrubGoFingerprint` 的版本擦除窗口是**锚在 buildinfo 魔数之后 512 字节**里的；而 `runtime.buildVersion` 那份版本串（`runtime.Version()` 读的）落在别处的只读数据段，锚定窗口扫不到 | 三项全 0 |
| `format=dll`（c-shared + mingw） | 魔数 0、Build ID 0、**`go1.20.14` 命中 1 次** | 同上：这条路径的锚定擦除**已经在做**（`dll.go` 里对 `ScrubGoFingerprint` 的调用，所以魔数与 Build ID 早已归零），但版本串同样漏在锚定窗口之外 | 三项全 0 |

修法：新增 `ScrubGoVersionStrings`（全文件扫描，规则与窗口版**完全一致** —— `go1.` 必须紧跟数字、回退收尾点号，只清零、长度不变），在 exe 路径（`compile()`）与 dll 路径（`compileLibrary()`）里各接一遍，都排在 UPX 与签名之前。实测修复后两种产物三项标记全为 0，**且字节数完全不变**（exe 3456757、dll 3414528）。安全性已核对：植入端模板不调用 `runtime.Version()`/`Debug.ReadBuildInfo()`（`internal/server/builder/implant` 与 `release/implant` 均无引用），清零只影响运行时崩溃/诊断输出里的版本信息。

> 复现命令：构建产物后跑 `python .tmp-verify/count_fingerprint.py <产物>`（本地验证脚本，不入库），或按 §4 的 `findstr` 口径核对。

可选外部工具（不计入"内置特性"）：UPX 仅对 Windows `exe`/`bin` 生效（`internal/server/builder/builder.go`）；garble 的可用性由一次真实探测构建判定（`internal/server/builder/toolchain.go: GarbleStatus`），版本不匹配时直接判"不可用"。两者对查杀率的影响**未量化**。

### 2.4 签名顺序约束（防"白签"）

**规则：签名必须是交付流水线的最后一步；签名之后不得再改一个字节。**

为什么单列一条：签名覆盖的是"签名那一刻的字节"，签名后再做 UPX / 资源修补 / 图标 / 版本信息 / 字符串擦除 / 文本编码都会让签名失效。而签名复核（`internal/server/builder/sign.go` 的 `verifyWithPowerShell`）发生在**签名之后、后处理之前**，所以白签**从接口上看仍然是 `signed=true`** —— 目标机上才表现为"签名了还是被拦"，极难回头定位。

实现（v1.4.0 S3）：

- 顺序契约集中在 `internal/server/builder/finalize_order.go`：步骤名常量 + `finalizeSteps()`（纯函数）+ `signOrderWarning()`（守卫）。
- 每次构建开始打一行 `交付流水线（字节加工顺序，签名必须是最后一步）：步骤 → 步骤 → 签名`；一旦顺序被改坏（签名之后还有改字节的步骤）立刻打 **error 级**日志并点名违规步骤。
- 当前顺序（`format=exe`，全开）：`scrub_fingerprint → scrub_version_string → upx → sign`。
- 新增"会改字节"的步骤时必须：① 登记步骤名；② 插到 `upx` 与 `sign` **之前**（例如 PE 资源/图标/版本信息/时间戳修补）；③ 让 `finalize_order_test.go` 的表驱动用例继续通过（该用例遍历"平台 × 格式 × 开关"，断言"只要出现 sign 就必在最后"）。
- 另外确认过：`sign_timestamp_url` 在两条签名路径上都真的传给了签名命令（`signWithSigntool` 用 `/tr <url> /td sha256`，PowerShell 路径走 `-TimestampServer`）—— 计划里"待确认"的那一项到此闭环。启用真实证书时**务必**配时间戳，否则证书过期后签名一次性全废。

### 2.5 已知做不到的（写在这里省得反复试）

- **加密整个镜像/代码段**：Go 的 GC、调度器与信号栈时刻在跑，加密代码段或 runtime 元数据必崩。
  Ekko/Foliage 那套"整块 ROP 链 + 定时器回调"在 Go 植入端**做不到**（除非把载荷改成 C/C++ 或纯 shellcode）。
- **原地加密 `string`**：Go 字符串可能位于只读段，写入即 `ACCESS_VIOLATION`。C2 地址、sessionID 这类
  目前**不在**掩码范围；要覆盖必须先把它们改成 `[]byte` 存取（见 §5）。
- **让静态改动影响"起不来"**：不可能。未签名 PE 被策略拒绝执行是签名/信誉层的事。
- **Linux/macOS 上的内存加密与 W^X**：当前是 stub（见 2.2 的平台边界），**未实现**。

---

## 3. 怎么验证（固定流程，避免被单次结果骗）

> **验收环境请用 `scripts/evasion_matrix.ps1`**（v1.4.0 新增）：
> `-Preflight` 只读体检目标机（OS/HVCI/VBS/驱动黑名单/Defender/第三方杀软/待测样本），
> `-Record` 把每轮观测（环境、样本变体、次数、结论、拦截原文、Defender 事件号、是否上线）写进
> `docs/evasion-results/matrix.csv` 并自动渲染 `summary.md` 汇总表（13 个固定用例，未测的就显示"未测"）。
> 它的存在就是为了避免"改完感觉更隐蔽了"这种没有证据的结论。

**本机当前基线（2026-09-27 用 `-Preflight` 实测，仅供对照，不是验收结论）**：

| 项 | 值 | 对本次改造的含义 |
|---|---|---|
| OS | Windows 11 专业版 build 26200 | —— |
| HVCI（内存完整性） | **1（启用）** | 可写+可执行内存与部分驱动手段会被拒 → 代码侧只能走 RW→RX 两段式（已在实现里硬拒 RWX） |
| VBS | `SecurityServicesRunning=2` | 与 HVCI 一致 |
| 易受攻击驱动黑名单 | 1（启用） | BYOVD 加载名单内驱动会 `1275`，自备驱动需先核对 |
| Defender 实时防护 | False（被第三方接管） | Defender 事件号 1116/1117 在本机**不产生**，不能拿它当"未被拦"的证据 |
| 第三方安全软件 | `ZhuDongFangYu`、`QQPCExternal`（360tray 已退出） | 主动防御仍在"进程创建/行为"层拦截，与文件特征无关 |
| 本机待测样本 | 历史构建产物 | 本机杀软会删除新生成的 PE，静态结论需在构建机上取，运行期结论必须到目标机 |

> 记录这行的原因：v1.4.0 期间多次出现"本机跑不了就以为没验证/或反过来把编译期结论当运行期结论"。
> 采样环境写进文档，读结论的人才知道它能证明什么、不能证明什么。

### 3.1 通用规则（很重要）
AV 的判定里权重很大的是**文件哈希信誉 / 云端结果 / 母进程 / 投放路径 / 时间窗**。因此：
1. **一次只改一个变量**（例如只开/关 sleep mask），其它全部保持不变；
2. **每个样本至少重复 3 次**（间隔 > 10 分钟），并**换文件名但不改内容**再测一次（排除缓存）；
3. 记录：是否被执行、是否上线、多久被删/被杀、杀软名称与**拦截原文/威胁名**；
4. 同机历史结论**不能**外推到别的机器（装没装 360、HVCI 状态、Defender 是否被接管都会变）。

> **开发机实测环境（2026-09，`-Preflight` 输出）**：Windows 11 build 26200 ·
> **HVCI（内存完整性）已启用** · **VBS 运行中（SecurityServicesRunning=2）** ·
> **易受攻击驱动黑名单已启用** · Defender 实时防护**关闭**（被第三方杀软接管）·
> 在跑的第三方安全软件：`360tray` / `QQPCExternal` / `ZhuDongFangYu`。
> 三条直接后果，别在这台机器上做无效实验：
> 1. **HVCI 开启时，创建"同时可写可执行"的内存页会被拒** —— 这正好说明本项目"RW 写 → RX 执行"是**必须**而不是可选；
> 2. **驱动黑名单开启时，名单内的易受攻击驱动会被内核静默拒绝**（`StartService` 报 `1275 ERROR_DRIVER_BLOCKED`）→ BYOVD 类手段在**这类配置**的目标机上直接不可用，投驱动前先跑 `-Preflight`；
> 3. Defender 被接管时 **Defender 事件日志（1116/1117）不会记录拦截**，此时只能看第三方杀软自己的拦截记录/隔离区 —— 别把"日志里没有"当成"没被拦"。

### 3.2 sleep mask 验证方法
1. 用 **HTTP 通道**、`interval ≥ 5s`（`maskedSleep` 只在休眠 ≥ 2s 时生效）；
2. 目标机上线后先执行一条会产生可识别输出的任务（如 `whoami`），让它进入结果缓存；
3. 等到**心跳间隔的休眠窗口**，用 Process Hacker / x64dbg / `strings` 式内存搜索：
   - 搜索 `whoami` 的输出片段、`TOSHELL_CFG`、SM4 子密钥特征；
   - **预期：加密窗口内搜不到明文**；心跳唤醒后再搜可以看到（说明还原成功）；
4. 同时在休眠窗口内**下发一条任务**：应在 ≤1 个分片（≈300ms，最坏 2s）内执行并回传；
   - 如果出现"结果乱码 / 解密失败 / 任务卡死"，说明加密门有问题 → 报 issue 并附日志。

### 3.3 去 RWX 验证方法
1. 目标机上让载荷完成一次内存执行/注入（任务类型 `fileless_exec`，接口 `POST /api/v1/sessions/{id}/fileless-exec`，或注入面板）；
2. 用 Process Hacker 看进程的内存区域：**不应出现 RWX 私有无映像区域**（`RWX` + `Private` + 非 image）；
3. 功能回归：注入/内存执行仍然成功（改保护最容易把功能改坏）。

### 3.4 落地链路验证方法（签名 / 白加黑）
1. **签名**：`Get-AuthenticodeSignature .\payload.exe`（`Status=Valid` 才代表目标机会认；自签要先导入目标机「受信任的根证书颁发机构」）；再在目标机直接双击运行；
2. **白加黑**：自备已签名宿主 + 它启动时加载的 DLL 名 → 用 `dll` 格式构建载荷 → 改名为该 DLL 名放宿主同目录 → 运行宿主 → 看是否上线（详见 `docs/LOADERS.md`）。

---

## 4. 如何自查（对**已构建产物**做静态核对）

以下检查只依赖本机工具（`strings` 在 Linux/macOS 自带；Windows 可用 WSL、Git Bash、`sigcheck -a -h` 或 `findstr` 替代）。
把 `payload.exe` 换成实际产物（`dll` 用 `payload.dll`）：

```bash
# ① Go 构建指纹：三条都应搜不到（harden.go 擦除是否生效）
#    注意 `go1.x.y` 这一条不是装饰：v1.4.0 S3 之前 exe/dll 各残留 1 次（runtime.buildVersion），
#    锚定窗口版擦除扫不到，靠全文件版 ScrubGoVersionStrings 才收掉（见 §2.3）。
strings -a payload.exe | grep -E 'Go buildinf:|Go build ID:|go1\.[0-9]+\.[0-9]+'

# ② Go 运行时/pclntab 特征：默认应有 gopclntab，但不应出现 C2 组件的函数名
strings -a payload.exe | grep -E 'gopclntab|loadShellcode|memexe_windows|stompShellcode'

# ③ 高信号 API 名：apihash/字符串混淆生效时不应有明文
strings -a payload.exe | grep -E 'VirtualAllocEx|CreateRemoteThread|WriteProcessMemory|IsDebuggerPresent|NtDelayExecution'

# ④ 明文配置块/回连地址：应为空
strings -a payload.exe | grep -E 'TOSHELL_CFG|https?://'

# ⑤ BOF：默认（未勾选「BOF 支持」）应为 0 次；勾选后为 22
strings -a payload.exe | grep -c 'Beacon'

# ⑥ "真 DLL"核对：IMAGE_FILE_DLL 是否置位 + 是否有导出表（v1.3.5 之前两者都没有）
dumpbin /headers payload.dll | grep -i -E 'DLL|characteristics'
dumpbin /exports payload.dll
```

Windows 纯 PowerShell 的等价写法（无 `strings` 时）：

```powershell
# 逐字节当 Latin-1 读，避免编码影响 ASCII 特征匹配
$t = [Text.Encoding]::GetEncoding(28591).GetString([IO.File]::ReadAllBytes('.\payload.exe'))
foreach ($p in 'Go buildinf:','Go build ID:','loadShellcode','VirtualAllocEx','TOSHELL_CFG') {
  '{0,-20} {1}' -f $p, ([regex]::Matches($t, [regex]::Escape($p))).Count
}
Get-AuthenticodeSignature .\payload.exe | Format-List Status,SignerCertificate
```

> **这些结果只能证明"静态足迹"，永远不能证明动态免杀**：
> `strings` / `dumpbin` / `Get-AuthenticodeSignature` 看不到运行期的内存保护、看不出 sleep mask 是否真的加密了堆缓冲、
> 也看不出行为引擎是否放行。**"grep 不到 XXX"最多说明某个明文特征不在了**，
> 把它当成"动态免杀有效"就是本文开头批评的那种自欺。
> 动态结论只能在目标机上按 §3 的流程测——而截至 v1.3.5，维护者自己**还没做这一步**。

---

## 5. 待办 / 未实现（下一批动态工作）

> **以下全部尚未实现**，只是计划，不要当成已有能力。排序大致按收益。

1. **把 C2 地址/sessionID/关键配置改成 `[]byte` 存取**，让它们也能进 sleep mask 的加密范围（当前 `string` 常量在只读段，原地加密必崩，见 2.4）；
2. **启动即做 AMSI/ETW 用户态 patch**（现在 `edr_blind` 是任务级、且需要管理员，存在鸡生蛋问题）；
3. **间接系统调用**（调用栈更像合法调用，比裸 `syscall` 安全）+ 目标机验证；
4. **PE 版本资源/图标/时间戳**（"合法外观"，同时为签名做铺垫）；
5. **动态测试矩阵自动化**：把 §3.1 的流程脚本化（记录 360 拦截记录 + Defender 事件 1116/1117 + 是否上线），
   以后每一项免杀改动都用它验收，并在 `CHANGELOG.md` 里只写实测结论；
6. **Linux/macOS 侧补齐动态能力**：`sleepmask_unix.go` / `memprotect_unix.go` 目前是空实现 stub。
