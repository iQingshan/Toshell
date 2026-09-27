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
| 编译期字符串混淆（`xd("hex")` 运行时解码） | `internal/server/builder/implant_obfuscate.go` + 各植入端模板（解码层 `implant/obfuscate.go`） | ✅ **实测**（字符串体检） |
| pclntab 中性化（函数名/文件名改中性名） | `internal/server/builder/implant/` 各模板（`main.go` 等） | ✅ **实测**（字符串体检） |
| BOF 按需编译（**默认关**） | `internal/server/builder/implant/bof_windows.go`（`//go:build windows && !light && bof`）与默认实现 `bof_stub_windows.go`；门控 `internal/server/builder/builder.go` 的 `buildTagList` | ✅ **实测**（字符串体检）：默认载荷 `beaconAPI=0`，勾选后 22（证明门控生效）；`gate_scan_test.go: TestBOFIsOptIn` |
| Go 构建指纹擦除（原地置零，长度不变） | `internal/server/builder/harden.go`（`ScrubGoFingerprint`：`\xff Go buildinf:` 魔数 / buildinfo 窗口内 `go1.x.y` / `Go build ID:` 前缀） | ✅ **实测**（字符串体检）：默认载荷 `Go buildinf=0`、`Go build ID:=0`；`harden_test.go` 覆盖擦除/幂等/边界 |
| 每构建随机化（配置块魔数/密钥、xd 密钥基准、API 哈希种子） | `internal/server/builder/builder.go`、`internal/server/builder/evasion.go`、`internal/server/builder/implant/obfuscate.go` | ✅ **实测**（字符串体检）：默认载荷 `loadShellcode=0`、`kgameprotect/byovd/HVCI=0` |
| 高信号标识符（`loadShellcode` 等）默认不进载荷 | 同 pclntab 中性化 | ✅ **实测** |

静态体检的完整口径：默认载荷 `beaconAPI=0`、`loadShellcode=0`、`Go buildinf=0`、`Go build ID=0`、`kgameprotect/byovd/HVCI=0`。

可选外部工具（不计入"内置特性"）：UPX 仅对 Windows `exe`/`bin` 生效（`internal/server/builder/builder.go`）；garble 的可用性由一次真实探测构建判定（`internal/server/builder/toolchain.go: GarbleStatus`），版本不匹配时直接判"不可用"。两者对查杀率的影响**未量化**。

### 2.4 已知做不到的（写在这里省得反复试）

- **加密整个镜像/代码段**：Go 的 GC、调度器与信号栈时刻在跑，加密代码段或 runtime 元数据必崩。
  Ekko/Foliage 那套"整块 ROP 链 + 定时器回调"在 Go 植入端**做不到**（除非把载荷改成 C/C++ 或纯 shellcode）。
- **原地加密 `string`**：Go 字符串可能位于只读段，写入即 `ACCESS_VIOLATION`。C2 地址、sessionID 这类
  目前**不在**掩码范围；要覆盖必须先把它们改成 `[]byte` 存取（见 §5）。
- **让静态改动影响"起不来"**：不可能。未签名 PE 被策略拒绝执行是签名/信誉层的事。
- **Linux/macOS 上的内存加密与 W^X**：当前是 stub（见 2.2 的平台边界），**未实现**。

---

## 3. 怎么验证（固定流程，避免被单次结果骗）

### 3.1 通用规则（很重要）
AV 的判定里权重很大的是**文件哈希信誉 / 云端结果 / 母进程 / 投放路径 / 时间窗**。因此：
1. **一次只改一个变量**（例如只开/关 sleep mask），其它全部保持不变；
2. **每个样本至少重复 3 次**（间隔 > 10 分钟），并**换文件名但不改内容**再测一次（排除缓存）；
3. 记录：是否被执行、是否上线、多久被删/被杀、杀软名称与**拦截原文/威胁名**；
4. 同机历史结论**不能**外推到别的机器（装没装 360、HVCI 状态、Defender 是否被接管都会变）。

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
