# ToShell Team Server — Release 包

> **版本 v1.4.0（开发中；上一发布版 v1.3.5）** · 自托管 C2（命令与控制）远程管理平台，仅用于**授权红队演练、渗透测试与安全研究**。请仅在获得授权的前提下使用。

完整项目说明、架构、REST API、植入体/载荷构建、C2 协议、插件与隧道系统见包内 `README.md` 与 `USAGE.md`。

> 落地链路（不落地未签名 PE 的投放方式）与三类免杀能力（**落地 / 动态免杀 / 静态降特征**）的完整说明在
> [docs/LOADERS.md](../docs/LOADERS.md) 与 [docs/EVASION.md](../docs/EVASION.md)。
> 发布 zip 内已带上 `README.md` / `USAGE.md` / `docs/`（含上述文档与截图）；仓库里其余的
> `ROADMAP.md` / `CHANGELOG.md` / `SECURITY.md` 等可在线查看：<https://github.com/iQingshan/Toshell>。

## 本目录内容

| 项 | 说明 |
|---|---|
| `toserver.exe` / `toserver` | 预编译服务端（单二进制，内嵌 Web 控制台） |
| `implant/` | 植入端编译模板（Go，含免杀随机化源码） |
| `implant_c/` | C 植入端模板（mingw） |
| `configs/server.yaml.example` | 开源占位配置模板（复制为 `server.yaml` 后修改） |
| `deploy.sh` / `deploy.bat` | **一键安装启动脚本**（入口；实际逻辑在 `install.sh` / `install.ps1`） |
| `install.sh` / `install.ps1` | 环境检测、按需在线安装与启动的实现（被 `deploy.*` 调用） |
| `README.md` / `USAGE.md` | 本说明与使用手册 |
| `LICENSE` / `DISCLAIMER.md` / `THIRD-PARTY-NOTICES.md` | MIT 许可全文、授权使用范围声明、第三方组件与许可清单 |
| `upx/ drivers/ plugins/ data/` | 运行时依赖/数据目录（`drivers/` 为空，BYOVD 驱动由操作员自备） |

## 一键部署（推荐）

发布包根目录自带傻瓜式部署脚本，**直接运行即可**（Windows 双击 `deploy.bat`，Linux/macOS `chmod +x deploy.sh && ./deploy.sh`）：

```bash
# Linux / macOS（在 release 目录）
chmod +x deploy.sh && ./deploy.sh

# Windows（在 release 目录）
deploy.bat
```

脚本会逐项检测并打印 `[ OK ] / [WARN] / [FAIL]`：服务端二进制（含 `-version`）、配置文件、`data/` 可写、磁盘空间、**控制台与监听端口占用**、Go 工具链版本、`GOPROXY` 可达性、UPX（随包自带）、garble、mingw gcc。

缺 Go 时会询问是否**从 go.dev 官方源在线安装**（下载后校验官方 SHA-256，解压到 `./.tools/go` 或 `%LOCALAPPDATA%\ToShell\tools` 并写入 PATH）。其它可选：

```powershell
deploy.bat -Check                 # 只检测环境，不安装、不启动（建议先跑）
deploy.bat -Yes                   # 无人值守，全部自动确认
deploy.bat -NoStart               # 只装依赖 + 生成配置
deploy.bat -WithMingw -WithGarble # 额外装 MinGW（C 植入端）/ garble（混淆）
deploy.bat -OpenFirewall          # 放行控制台与监听端口（需管理员）
```

```bash
./deploy.sh --check        # 只检测
./deploy.sh --yes --daemon # 后台启动（日志写 server.log）
```

启动后：从 `configs/server.yaml.example` 自动生成配置（首次）、打印 Web 控制台地址；日志在 `server.log`（Windows 前台启动则显示在控制台窗口）。

## 首次配置（必改）

编辑 `configs/server.yaml`：

- `listener.public_host` — 服务器公网 IP / 域名（生成的植入端连接它）
- `auth.api_keys` — API 调用密钥（`X-API-Key` 头）
- `auth.jwt_key` — JWT 签名密钥（留空首次启动自动生成）
- `listener.encryption_key` — 植入端加密密钥（留空首次启动自动生成）
- `auth.admin_password` — 管理员密码（默认 `admin / toshell`，务必修改）

> 更换 `listener.encryption_key` 后，**所有已生成的植入端必须重新生成**（旧植入端无法与新密钥通信）。

## 生成植入端

登录 Web 控制台 →「生成载荷」页选监听器/平台/通道 → 构建。载荷按你在 `listener` 中选定的通道（TCP / HTTP(S) / WebSocket / MQTT）编译，`-tags` 条件裁剪通道代码。

- 加载后会话出现在「会话管理」，可下发命令、文件、进程、截图、凭据、注入、插件、任务流等。
- **AI 副驾驶**：在「设置 → AI 副驾驶」填 `base_url/api_key/model` 启用；可自动理解会话上下文、编排操作、联网搜索（`web_search`）、下载工具（`remote_download`，存 `data/tools/` 可复用）、按用途以插件（`plugin_upload`+`plugin_load`）或内存加载（`fileless_exec`）分发使用。

## 落地 / 动态免杀 / 静态降特征（v1.3.5）

这三类是**三件不同的事**，对手与验证方法都不同，请不要混着看（逐项验证状态见 [docs/EVASION.md](../docs/EVASION.md)）：

| 类别 | 作用对象 | v1.3.5 有什么 |
|---|---|---|
| **落地（delivery）** | 怎么把载荷送上目标机、能不能被执行 | Authenticode 代码签名（`builder.sign_*`）+ **8 条加载器链**（白加黑 DLL 侧加载 / 计划任务 + 已签名宿主 / LOLBin / 内存加载） |
| **动态免杀（dynamic evasion）** | 进程**运行期**的内存与调用行为 | 休眠期内存加密（sleep mask）+ 去掉 RWX（RW 写 → RX 执行）—— **已实现、静态验证；运行期效果待验证** |
| **静态降特征（static footprint reduction）** | 文件里的字符串 / 符号 / 构建指纹 | 字符串混淆、每构建随机化、apihash + PEB、pclntab 中性化、**Go 构建指纹擦除**、garble / UPX |

### 落地（delivery）

- **Authenticode 代码签名（PFX）**：证书二选一 —— `builder.sign_pfx_path` + `builder.sign_pfx_password`（PFX 文件，密码通过环境变量传给子进程、不出现在命令行），或 `builder.sign_thumbprint`（本机证书存储 `CurrentUser\My` 按指纹取）。构建产物**落盘前签名**，`size` / `sha256` 按签名后的字节计算，保证下载物与接口一致；响应里带 `signed / signer / sign_method / sign_status / sign_message`，失败可配 `sign_fail_closed` 决定丢弃还是返回未签名产物。配置方法见 `USAGE.md` 与 `configs/server.yaml.example` 的 `builder:` 段。
- **真 DLL 载荷 + 8 条加载器链**：`format=dll` 走 `-buildmode=c-shared` + mingw-w64 编译出**真正的 DLL**（`IMAGE_FILE_DLL` + 导出表；导出名可配，默认「加载即启动」），所以**白加黑（DLL 侧加载）与 `rundll32` 链才真正可用** —— 此前 `dll` 其实是"改了扩展名的 EXE"，这两条链第一步就失败。DLL 载荷需要**与目标架构一致的 mingw-w64 gcc**（x64 要 `x86_64-w64-mingw32-gcc`），生成载荷页会直接告诉你本机是否可用、缺哪一个。
  其余链路：计划任务 + 已签名宿主、LOLBin（`mshta` / `regsvr32` Squiblydoo / `certutil` + 宿主）、内存加载（PowerShell 注入 shellcode / mshta + 签名宿主），每条都带前置条件与风险等级。**本项目不内置任何第三方加载器 / 宿主 exe / SCT 脚本，全部由操作员自备并自负合规责任**。选型与排错见 [docs/LOADERS.md](../docs/LOADERS.md)。

### 动态免杀（dynamic evasion）—— 第一批（待验证）

- **休眠期内存加密（sleep mask）**：在启动随机延迟、HTTP 轮询间隔、重连退避、非工作时段，对**我们自己的堆缓冲**（隧道 SM4 子密钥、任务结果缓存）做 XOR 加密，休眠结束还原；休眠改走 `ntdll!NtDelayExecution`（经 apihash 解析、不进 IAT 明文），并分片 ≤300ms + 随机抖动。
- **去掉 RWX**：审计植入端全部 `VirtualAlloc` / `VirtualProtect` / `NtProtectVirtualMemory` 调用点，改成 **RW 写入 → RX 执行**两段式，不再同时申请可写可执行内存。
- **验证状态（别夸大）**：以上两项**已实现，并通过源码审计 + 编译验证**（windows/386、windows/amd64、`light`、`evasionscan` 组合全部编译通过）；**运行期行为尚未在测试 VM 上实测**（本机国产安全软件会删除任何新生成的未签名 PE，无法执行），因此**属待验证** —— 请按 [docs/EVASION.md](../docs/EVASION.md) §3 的固定流程在放行环境自行验证。
- **明确做不到的**：加密整个镜像 / 代码段（Go 的 GC、调度器与信号栈时刻在跑，必崩）；原地加密 `string`（C2 地址、sessionID 这类暂不在掩码范围内）。理由见 [docs/EVASION.md](../docs/EVASION.md) §1/§2。

### 静态降特征（static footprint reduction）

编译期字符串混淆、**每构建随机化的配置块魔数/密钥、xd 字符串密钥基准、API 哈希种子/乘子**（打破跨样本同指纹）、apihash + PEB 动态解析、进程注入随机良性宿主、通信密钥内存清零、**启动随机延迟 + 心跳抖动（均可按载荷配置）**、pclntab 高信号标识符中性化、garble / `-s -w` / `-trimpath` / `-buildid=`。

v1.3.5 新增 **`ScrubGoFingerprint`**（`internal/server/builder/harden.go`）：对 Go exe 与 DLL 两条编译路径在 UPX 之前**原地 0x00 覆盖** ① 全部 `\xff Go buildinf:` 魔数、② 该头后 512 字节窗口内的 `go1.x.y` 版本串、③ `Go build ID:` 前缀；**只覆盖、不改长度**（PE 节表 / RVA / 重定位不受影响），**pclntab 与符号表绝不触碰**。这些是 Go 家族 YARA 规则最稳定的命中点。

> ⚠️ **BOF 支持是兼容选项，不是免杀手段**：上一版体检里剩下的高信号明文就是 BOF 兼容层的 Cobalt Strike Beacon API 名字（`BeaconDataParse` / `BeaconOutput` / `BeaconPrintf` 等，实测 22 处）—— 它是 BOF 二进制的符号契约，**不能改名**。所以 v1.3.5 改成**按需编译**：默认载荷**不含** BOF 兼容层（`beacon*` 命中 0），只有在生成载荷页**勾选「BOF 支持」**（请求字段 `bof_enabled`）时才编译进去（勾选后体积约 +105KB）。**打开它不会让你更隐蔽，只会让静态特征变多**；只有在确实要跑现成 BOF 时才开。

> **历史记录 · v1.3.4 行为变化**：不再默认"枚举进程找杀软"。原实现启动时遍历全系统进程并与一批安全软件进程名比对，这是 360/火绒/电脑管家主动防御**明确拦截**的对抗行为；现在只有勾选「主动反沙箱进程检测」才会编译进载荷。
> 免杀是持续对抗，无永久方案；请结合自身环境做多样本测试，并仅用于授权范围。构建档位与免杀边界的逐项对照见仓库根 [README.md](../README.md) 的「构建档位与免杀边界（v1.3.5）」，更多细节见 [docs/EVASION.md](../docs/EVASION.md)。
> ⚠️ 装有国产安全软件的主机上，**未签名的新 PE 常在创建进程阶段就被拒绝执行并删除**（与载荷代码无关，微软签名的程序可正常执行），此类环境需要代码签名或由已签名宿主加载（见 [ROADMAP.md](../ROADMAP.md) P0-5）。

## 停止服务端

- Linux/macOS：`kill <PID>`（deploy.sh 启动时打印）或 `pkill -f toserver`
- Windows：关闭 `deploy.bat` 启动的“ToShell Server”控制台窗口

## 联系方式 / Contact

| 渠道 | 地址 |
|---|---|
| 作者 | 青山（iQingshan） |
| GitHub | <https://github.com/iQingshan> |
| Issue / 功能建议 | <https://github.com/iQingshan/Toshell/issues> |
| 邮箱（合作 / 漏洞披露） | <qingshan@88.com> |
| 使用说明 | <https://github.com/iQingshan/Toshell/blob/main/USAGE.md> |
| 更新日志 | <https://github.com/iQingshan/Toshell/blob/main/CHANGELOG.md> |

> 遇到问题请先看 `USAGE.md` 的「常见问题」章节，仍未解决再到 GitHub 提 Issue（附版本、系统环境、复现步骤与相关日志）。安全/滥用问题请走邮箱，**不要**在公开 Issue 里贴可利用细节。

## 免责声明

仅用于**授权测试与学习研究**，严禁未经授权的入侵/攻击/数据窃取。因使用本工具产生的任何后果由使用者自行承担。详见包内 `LICENSE` / `DISCLAIMER.md` / `THIRD-PARTY-NOTICES.md`，以及仓库根 `README.md` 的「开源与授权」段落。

## 相关文档

- [USAGE.md](USAGE.md) — 主手册：安装部署、配置项逐条说明、生成载荷、会话操作、签名与加载器链、常见问题
- [../docs/EVASION.md](../docs/EVASION.md) — 落地 / 动态免杀 / 静态降特征三类能力与逐项验证状态
- [../docs/LOADERS.md](../docs/LOADERS.md) — 白加黑、计划任务、rundll32/mshta/certutil、内存加载链的前置条件与取舍
- [../docs/DEPLOY-DOMAIN-CDN.md](../docs/DEPLOY-DOMAIN-CDN.md) — 域名 + CDN / Nginx 反代 / 域前置上线
- [../CHANGELOG.md](../CHANGELOG.md) ｜ [../ROADMAP.md](../ROADMAP.md) ｜ [../SECURITY.md](../SECURITY.md) — 版本变更、后续计划、安全与滥用报告（仓库内文档，**不在 zip 包中**，可在线查看）
