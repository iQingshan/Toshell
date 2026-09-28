# ToShell Team Server 使用说明

> **当前版本: v1.4.0(2026-09-28 已发布)** · 更新日志见 [CHANGELOG.md](CHANGELOG.md) 与文末「附」章节。

> ToShell 是一个自托管的 C2(命令与控制)框架,用于授权红队演练、渗透测试与安全研究。请仅在获得授权的前提下使用。

> **作者:青山、Q1lintu、c0ffee(核心开发者)** · © 2026 ToShell

---

## 目录

- [一、项目简介](#一项目简介)
- [二、快速部署](#二快速部署)
  - [1. 环境要求(运行服务端)](#1-环境要求运行服务端)
  - [2. 部署步骤](#2-部署步骤)
  - [2.1 一键部署脚本(发布包自带,推荐)](#21-一键部署脚本发布包自带推荐)
  - [3. 默认凭据与安全提醒](#3-默认凭据与安全提醒)
- [三、生成载荷(重点)](#三生成载荷重点)
  - [1. 环境要求](#1-环境要求)
  - [2. 依赖库](#2-依赖库)
  - [3. 可选工具(强烈建议安装)](#3-可选工具强烈建议安装)
  - [3.1 内置免杀/隐藏特性(无需额外工具)](#31-内置免杀隐藏特性无需额外工具)
  - [3.2 代码签名(Authenticode)](#32-代码签名authenticode解决装着-360-就跑不起来)
  - [3.3 落地方案:8 条加载器链](#33-落地方案8-条加载器链不把未签名-pe-落到目标机)
    - [3.3.1 DLL 载荷怎么用](#331-dll-载荷怎么用v135-起是真-dll)
  - [4. 支持的目标平台](#4-支持的目标平台)
  - [5. 生成步骤(Web 控制台)](#5-生成步骤web-控制台)
  - [5.1 一条命令上线(多种免杀方式)](#51-一条命令上线多种免杀方式)
  - [6. 命令行方式(可选)](#6-命令行方式可选)
- [四、Web 控制台功能](#四web-控制台功能)
  - [文件传输说明](#文件传输说明)
  - [仪表盘统计口径说明](#仪表盘统计口径说明)
  - [截图与 BOF 优化](#截图与-bof-优化)
  - [驱动(BYOVD)加载前自检](#驱动byovd加载前自检)
  - [内存执行载荷预检(下发前)](#内存执行载荷预检下发前)
- [五、云端部署注意事项](#五云端部署注意事项)
  - [发布正式版(清空历史数据)](#发布正式版清空历史数据)
- [六、常见问题](#六常见问题)
- [七、联系方式与支持](#七联系方式与支持)
- [八、免责声明](#八免责声明)
- [附、更新日志与新增功能](#附更新日志与新增功能)

> 免杀/落地能力的实现位置与**验证状态**(哪些是实测、哪些只是静态验证)见 [docs/EVASION.md](docs/EVASION.md);加载器链的完整说明见 [docs/LOADERS.md](docs/LOADERS.md)。

## 一、项目简介

ToShell 由三部分组成:

| 组件 | 说明 |
|---|---|
| **Team Server** | 服务端,提供 Web 控制台、REST API、TCP C2 监听器、载荷生成 |
| **Web 控制台** | 浏览器管理界面(会话管理、文件管理、载荷生成、插件等) |
| **Implant(植入端)** | 由服务端生成的客户端程序,运行在目标主机,通过 TCP 回连服务端 |

通信架构:植入端通过 **TCP 长连接(自定义加密帧,控制帧 AES-256-GCM + 隧道 SM4-GCM)** 或 **HTTPS 轮询通道(域前置)** 与监听器通信;Web 控制台通过 REST API(JWT 认证)管理服务端,交互终端走 WebSocket。

---

## 二、快速部署

### 1. 环境要求(运行服务端)

| 项 | 要求 |
|---|---|
| 操作系统 | Windows / Linux / macOS(提供对应平台二进制) |
| CPU 架构 | amd64 / arm64 |
| 内存 | ≥ 256MB(推荐 1GB) |
| 磁盘 | ≥ 1GB |
| 网络 | 需开放 C2 监听端口(默认 8080)与 API 端口(默认 18081) |

> 若需要在服务端**生成载荷**,还需安装 Go 工具链,详见下文「三、生成载荷」。

### 2. 部署步骤

1. 将 `release/` 目录整体拷贝到服务器(目录内 `implant/` 为植入端编译模板,必须与可执行文件保持同目录);
2. 按需编辑 `configs/server.yaml`:
   - **必改**:`listener.public_host`(服务器公网 IP/域名)、`auth.api_keys`、`auth.jwt_key`、`listener.encryption_key`;
   - 若 `encryption_key` / `jwt_key` 留空,首次启动会自动生成并写回配置文件;
3. 启动服务端:
   ```bash
   ./toserver                       # Linux / macOS,默认读 configs/server.yaml
   toserver.exe                     # Windows
   ./toserver -config /path/server.yaml   # 配置文件不在默认位置时用 -config 指定
   ./toserver -version              # 打印版本/commit/构建时间(排障时先跑这个)
   ```
4. 浏览器访问 `http://<服务器IP>:18081`,使用默认账号 `admin / toshell` 登录(登录后请立即修改密码)。

### 2.1 一键部署脚本(发布包自带,推荐)

发布包根目录自带傻瓜式部署脚本,**直接运行即可**:检测环境 → 按需在线安装依赖 → 生成配置 → 启动打包好的 `toserver`。

| 平台 | 入口 | 说明 |
| --- | --- | --- |
| Windows | 双击 `deploy.bat`(或 `install.ps1`) | 内部就是 `install.ps1`,已绕过执行策略限制 |
| Linux / macOS | `./deploy.sh`(或 `./install.sh`) | 首次需 `chmod +x` |

脚本逐项检测并给出 `[ OK ] / [WARN] / [FAIL]`:

- **服务端二进制**(并打印 `-version`)、**配置文件**(缺失时从 `server.yaml.example` 自动生成)、**data/ 可写**、**磁盘剩余空间**;
- **端口占用**:控制台 `api_port`(默认 18081)与监听 `listener.port`(默认 8080);
- **Go 工具链**:构建载荷必需(≥ 1.21;Windows 载荷默认用 go1.20.14 工具链编译以兼容 Win7/2008R2,首次构建自动下载)。**缺失时可选择在线安装**——从 go.dev 官方源下载 `go<版本>.<os>-<arch>`,**校验官方 SHA-256** 后解压到 `./.tools/go`(Windows 为 `%LOCALAPPDATA%\ToShell\tools`)并写入 PATH;
- **模块代理可达性**(`GOPROXY`;国内建议 `go env -w GOPROXY=https://goproxy.cn,direct`);
- **UPX**(包内自带 `upx/`)、**garble**(可选,`-WithGarble` 在线安装)、**mingw gcc**(可选,仅 C 植入端需要;Windows 下 `-WithMingw` 会用 winget/choco 尝试在线安装)。

常用参数:

```powershell
.\deploy.bat -Check          # 只检测环境,不安装、不启动(建议先跑这个)
.\deploy.bat -Yes            # 无人值守,全部自动确认
.\deploy.bat -NoStart        # 只装依赖、生成配置,不启动
.\deploy.bat -WithMingw -WithGarble
.\deploy.bat -OpenFirewall   # 放行控制台与监听端口(需管理员)
```

```bash
./deploy.sh --check          # 只检测
./deploy.sh --yes --daemon   # 后台启动(日志写 server.log)
./deploy.sh --with-garble
```

> 当 `auth.admin_password` / `auth.jwt_key` / `listener.encryption_key` **留空**时,首次启动会自动生成随机凭据,**打印在日志里并落盘到 `configs/server.yaml`**(下次重启沿用,不会变);落盘失败会直接终止启动并打印配置路径,避免"每次重启都换随机密码、被锁在门外"。注意:示例配置里 `admin_password` 预置为明文 `toshell`,因此**不会**触发自动生成 —— 上线前必须自行改掉。生产部署请再按 [docs/DEPLOY-DOMAIN-CDN.md](docs/DEPLOY-DOMAIN-CDN.md) 配置域名/反代与防测绘。

### 3. 默认凭据与安全提醒

| 项 | 默认值 | 说明 |
|---|---|---|
| 管理员账号 | `admin` | 在 `auth.admin_username` 配置 |
| 管理员密码 | `toshell` | `auth.admin_password` 可填 bcrypt 哈希(`$2a$` 开头)或明文;填明文时按明文比对(**不会**自动改写为哈希),留空则首次启动随机生成 16 位密码、哈希后落盘并打印一次 |
| API Key | `change-me-api-key` | `auth.api_keys` 的第一项(示例配置值,可配多个),调用 API 时通过 `X-API-Key` 请求头传递,部署后必须更换 |

> **上线前必须更换**:API Key、JWT 密钥、监听加密密钥、管理员密码。更换加密密钥后,**所有已生成的植入端必须重新生成**(旧植入端无法与新密钥通信)。

---

## 三、生成载荷(重点)

### 1. 环境要求

生成载荷是在**服务端**上通过调用 Go 工具链完成的,因此:

| 项 | 要求 |
|---|---|
| Go 工具链 | **Go ≥ 1.21(推荐 1.24)**。检查:`go version` |
| 网络 | 服务端需能访问 Go module proxy(`proxy.golang.org`,可配置 `GOPROXY`) |
| CGO | 普通载荷无需(植入端以 `CGO_ENABLED=0` 交叉编译,不需要 gcc);**`dll` 格式例外** —— c-shared 构建必须 `CGO_ENABLED=1` + 架构匹配的 mingw-w64 gcc,见 3.3.1 |
| 磁盘/内存 | 编译临时目录需可写;生成多个载荷时注意磁盘空间 |

> **Windows 老系统兼容(Windows 7 / Server 2008 R2)**:
> 从 Go 1.22 起编译的 exe 启动时会依赖 `GetSystemTimePreciseAsFileTime`(仅 Windows 8+ 提供),
> 在 Windows 7 / Server 2008 R2 上会报"无法定位程序输入点"导致**无法启动**。
> 因此服务端生成 **Windows 载荷时自动切换 Go 1.20.14 工具链**编译(`GOTOOLCHAIN=go1.20.14`,
> 由本机 Go ≥ 1.21 自动下载并缓存,无需手动安装),保证老系统兼容。
> - 首次生成 Windows 载荷时会自动下载 go1.20.14 工具链(约 120MB),耗时较长,属正常;
> - 该逻辑仅对 Windows 目标生效,Linux/macOS 载荷仍使用本机工具链;
> - 开启 garble 混淆时不切换(garble 与 go1.20 不兼容),此时老系统兼容由用户自行权衡。

> **GOPROXY 配置命令**(国内网络建议切换加速镜像):
> - 查看当前配置:`go env GOPROXY`
> - 使用官方代理:`go env -w GOPROXY=https://proxy.golang.org,direct`
> - 使用国内加速镜像(七牛):`go env -w GOPROXY=https://goproxy.cn,direct`
> - 使用阿里云镜像:`go env -w GOPROXY=https://mirrors.aliyun.com/goproxy/,direct`
> - 临时只对单次命令生效(不改全局配置):`GOPROXY=https://goproxy.cn,direct go mod download`
> - 验证能否正常拉取依赖:`go mod download`(无报错即说明代理可达)

### 2. 依赖库

植入端编译依赖以下 Go 库(`go mod tidy` 自动拉取):

| 库 | 用途 |
|---|---|
| `golang.org/x/sys` | 跨平台系统调用(WinAPI / 系统信息 / 进程操作) |
| `golang.org/x/text` | 简体中文 GBK/UTF-8 转码(Windows 命令输出) |
| `golang.org/x/crypto` | 加密原语(如 HMAC/随机数) |

> 服务端本体依赖 `go-sqlite3`、`viper`、`gorilla/mux`、`gorilla/websocket`、`golang-jwt` 等,运行**无需编译**;仅生成载荷时需要上述植入端依赖。

### 3. 可选工具(强烈建议安装)

| 工具 | 安装命令 | 用途 |
|---|---|---|
| **garble** | `go install mvdan.cc/garble@latest` | Go 源码混淆,提升免杀效果(`-literals -tiny` 等参数) |
| **UPX** | 见 https://upx.github.io | Windows PE 压缩,减小体积(仅 Windows 的 `exe`/`bin` 格式会调用,包内自带 `upx/`) |

安装后确认可执行:`garble version` / `upx --version`。
服务端启动日志会显示是否检测到这两个工具;若未检测到,生成载荷时对应的混淆/压缩选项将不可用。
注意 garble 的可用性**不是**只看 `LookPath`:服务端会用一个极小工程真跑一次 `garble build` 做探测,版本不匹配时界面直接显示"不可用"并给出原因(见下方说明)。

> **garble 版本兼容性**:最新版 garble(v0.16+)要求 **Go ≥ 1.26**。若 Go 版本较旧,生成载荷时开启 garble 会报
> `Go version "goX.Y.Z" is too old; please upgrade to goX.Y.Z or newer`。
> 解决办法:升级 Go 工具链,或安装与当前 Go 版本兼容的旧版 garble(如 `go install mvdan.cc/garble@v0.15.0`)。

### 3.1 内置免杀/隐藏特性(无需额外工具)

即使不安装 garble/UPX,生成的载荷已内置以下隐藏特性(除表中特别标注的 opt-in 项外均默认开启,对 exe / raw / dll 等格式均生效):

| 特性 | 说明 |
|---|---|
| **编译期字符串混淆** | 服务端在编译前自动扫描植入端源码,将敏感字符串(C2 回连地址、API 函数名、配置块标识、安全软件特征等)加密为运行时解码调用,二进制中不残留明文 |
| **配置块加密** | 植入端的回连地址/加密密钥等配置以 **XOR 加密块**形式附加在二进制尾部,通过加密后的标识常量定位,二进制中无明文 magic 与明文 URL |
| **启动随机延迟** | 载荷启动后随机休眠 `[启动延迟最小, 最大]` 秒再首次回连(默认取服务端配置,生成载荷页可直接覆盖),打乱"启动即行为"的检测节奏 |
| **心跳抖动** | 心跳间隔在 `base ± jitter%` 内随机,打破固定周期轮询的流量指纹;不填则跟随「设置 → 植入端」 |
| **pclntab 中性化** | 内存执行/驱动等模块的函数名与文件名已改成中性名,Go 的 pclntab 里不再出现 `loadShellcode`、`memexe_windows.go` 这类"一看就是 C2 组件"的明文 |
| **反调试** | 启动时检测调试器(`IsDebuggerPresent`),CPU < 2 核或内存 < 2GB 时延迟执行(不做任何进程枚举) |
| **BOF 支持(默认关,opt-in)** | **只有显式勾选「BOF 支持」才会带 `-tags bof` 编译进来**。开启后载荷会带上整套 `Beacon*` API 名字(`full` 档案实测 22 处 pclntab 明文,是默认载荷里唯一剩下的高信号特征),`light` 档案则完全不含 BOF。开启它只是为了**兼容**现成的 BOF 插件,**不是**免杀收益 —— 不跑 BOF 就不要开 |
| **老系统兼容** | Windows 载荷自动使用 Go 1.20.14 工具链编译,兼容 Windows 7 / Server 2008 R2 |

> 验证方式:生成的 exe 中搜索 `TOSHELL_CFG_V1`、回连 IP/域名、`VirtualAllocEx`、`loadShellcode` 等字符串应均无明文。
> 注意:混淆不改变载荷功能,但极个别杀软仍可能因行为特征报毒,建议结合 garble + UPX 使用。
> **行为变化(v1.3.4 起)**:不再默认"枚举进程找杀软"。原实现在启动时遍历全系统进程并与一批安全软件进程名比对 —— 这是 360/火绒/电脑管家主动防御**明确拦截**的对抗行为,现在必须显式勾选「主动反沙箱进程检测」(`evasion_scan`)才会编译进载荷。
> **如何确认参数真的生效**:服务端日志会打印 `rendering implant: … interval=… jitter=… startup_delay=… evasion_scan=… profile=…` 与 `compiling implant: … tags="…"`,这是唯一可信的"真正烘焙进载荷的值"。
> **一个必须知道的边界**:装有 360/电脑管家等国产安全软件的主机上,**未签名的新 PE 常在创建进程阶段就被拒绝执行并删除**(实测连 Hello-World Go 程序也一样,而微软签名的 `notepad.exe` 副本可正常执行)。这类拦截与载荷代码无关 —— v1.3.5 起有两条正解:**代码签名**(见 3.2)与**加载器链**(见 3.3)。
> **验证到了什么程度(如实说明)**:上表里"编译期字符串混淆 / 配置块加密 / pclntab 中性化 / Go 指纹擦除"属于**静态降特征**,可以用本机 `strings` 式搜索复核(自查方法见 [docs/EVASION.md](docs/EVASION.md));而**运行期**对抗能力(休眠期内存加密、去 RWX 等)目前只做到**编译验证 + 源码审计**,维护者**没有**在测试 VM 上完成运行期实测(开发机的杀软会拦截新构建的未签名二进制执行),不要把它当成已经跑通的结论。

### 3.2 代码签名(Authenticode):解决"装着 360 就跑不起来"

**为什么**:未签名的新 PE 会被国产杀软的"未知程序"策略在创建进程阶段拦掉,这与载荷里写了什么代码无关。签名是"能不能跑起来"的敲门砖(不是免杀银弹:杀软还会看云端信誉与运行时行为)。

**怎么配**(服务端 `configs/server.yaml` 的 `builder` 段,生成载荷页会自动显示"已配置/未配置"):

```yaml
builder:
    sign_enabled: true
    # 方式一:证书文件(密码通过环境变量传给子进程,不会出现在命令行里)
    sign_pfx_path: "C:/path/codesign.pfx"
    sign_pfx_password: "你的pfx密码"
    # 方式二:用本机证书存储 CurrentUser\My 里的证书(填指纹;有 signtool.exe 时优先用它)
    # sign_thumbprint: "A1B2C3..."
    sign_timestamp_url: ""      # 时间戳服务器,内网/离线留空即可(失败不影响签名本身)
    sign_signtool_path: ""      # 留空自动探测 PATH 与 Windows SDK 目录
    sign_description: ""        # 可选:写入签名的描述
    sign_fail_closed: false     # true=签名失败就丢弃该载荷
```

**关于 pfx 密码(重要)**:

- 密码**永远不会**被控制台或 API 回显 —— `GET /api/v1/settings` 只返回布尔量 `sign_pfx_password_set`,判断"是否已配置密码",不返回密码本身;
- 通过 `PUT /api/v1/settings`(设置页「构建/签名」)更新时:`sign_pfx_password` **传空串 `""` = 保持原值不变**;传字符串 `clear` = **清除已保存的密码**;传其它值 = 覆盖为新密码。前端不回传该字段,因此"只改别的配置"不会把密码冲掉;
- pfx 证书走 PowerShell 签名路径(`X509Certificate2(path, pw, flags)`),密码经**环境变量**传给子进程,不进命令行;指纹模式(证书存储)才优先用 `signtool.exe`,两者都不会把密码写进命令行。

**怎么确认签上了**:生成载荷页会显示"已签名(签名者:CN=…)"或未签名原因;接口响应字段 `signed`/`signer`/`sign_method`/`sign_status`/`sign_message`;本机也可用
`Get-AuthenticodeSignature .\payload.exe | Format-List Status,SignerCertificate` 复核。
注意三个如实说明:
- 状态 `UnknownError` + 有签名者 = **签名本身有效,但证书链不受信任**(自签名证书未导入受信任根时就是这样),不是"没签上";
- **签名后再 UPX 加壳/改资源会让签名失效** —— 产物是先 UPX、后签名,别在签名之后动产物;
- 签名只解决"未签名新 PE 被拒"这一层,**不是**免杀银弹:杀软依旧看云端信誉与运行期行为,签名后仍可能被行为拦截。

**自签名证书(仅测试用)**:

```powershell
New-SelfSignedCertificate -Type CodeSigningCert -Subject "CN=YourName" `
  -KeyUsage DigitalSignature -KeySpec Signature `
  -CertStoreLocation Cert:\CurrentUser\My -NotAfter (Get-Date).AddYears(3)
$c = Get-ChildItem Cert:\CurrentUser\My | Where-Object Subject -like '*YourName*'
Export-PfxCertificate -Cert $c -FilePath .\codesign.pfx `
  -Password (ConvertTo-SecureString '你的密码' -AsPlainText -Force)
# 目标机上把证书导入"受信任的根证书颁发机构"后,签名状态才会是 Valid:
Import-Certificate -FilePath .\codesign.cer -CertStoreLocation Cert:\LocalMachine\Root   # 需管理员
```

### 3.3 落地方案:8 条加载器链(不把未签名 PE 落到目标机)

构建响应里的 `one_liners` 除"下载即执行"变体外,还会给出 **8 条加载器链**(每条带 `note`:前置条件、占位符、国产杀软下的风险等级),并按"是否已签名 + 平台/格式"给出 `loader_advice_title/tips`,明确**降级顺序:直接运行 → 计划任务 → 白加黑 → 内存加载**:

1. **白加黑(DLL 侧加载)**:把植入端按 `dll` 格式构建,改名为已签名宿主会加载的 DLL 名,放到宿主同目录 → 启动签名宿主。磁盘上不出现未签名 PE(风险:中);
2. **计划任务 + 已签名宿主**:`schtasks /create` + `/run` + `/delete`,动作是 `rundll32` 加载我们的 DLL;
3. **LOLBin 直载**:`rundll32` / `mshta`(JScript + WinHttp + ADODB.Stream)/ `certutil` 下载 + 宿主加载 / `regsvr32` Squiblydoo;
4. **内存加载**:拉 shellcode 注入已签名进程,不落地 PE(`powershell -enc`,或 mshta 骨架)。

> **合规与前置**:本项目**不内置任何第三方加载器/宿主程序** —— 白加黑需要的已签名宿主 exe 及其 DLL 名、Squiblydoo 需要的 `.sct` 脚本,全部由操作员自备并自负合规责任。完整说明(何时用哪条、失败排查)见 [docs/LOADERS.md](docs/LOADERS.md)。

#### 3.3.1 DLL 载荷怎么用(v1.3.5 起是**真 DLL**)

生成载荷页把格式选成 `dll` 时(**只有 Windows 目标支持 DLL**):

- **前置:gcc 必须与目标架构一致**。c-shared 构建走 C 工具链,编译器不对会直接产出**架构错误、宿主加载不了**的 DLL,因此服务端宁可明确报错也不给你一个坏产物:

  | 目标架构 | 需要的编译器(可执行文件名) | MSYS2 安装命令 |
  |---|---|---|
  | `amd64` | `x86_64-w64-mingw32-gcc` | `pacman -S mingw-w64-x86_64-gcc` |
  | `386` | `i686-w64-mingw32-gcc` | `pacman -S mingw-w64-i686-gcc` |

  页面上的「DLL 载荷」一栏直接显示本机是否可用、**缺哪一个**;`GET /api/v1/builders` 的 `evasion.dll_available` / `dll_message` 与按架构细分的 `evasion.dll_arch.{amd64,386,arm64}` 给的是同样的结论。

  > **历史缺陷(及现在的行为)**:v1.3.5 之前 `format=dll` 其实是"改了扩展名的 EXE"(`go build` 在 `CGO_ENABLED=0` 下静默跳过 `import "C"` 的胶水,产物 `IMAGE_FILE_DLL=false`、没有导出表),白加黑/rundll32 第一步就失败。现在改成 `-buildmode=c-shared + CGO_ENABLED=1`,产物 `IMAGE_FILE_DLL=true` + 真导出表;**缺 gcc 或只有错误架构的 gcc 时构建阶段就报错**(提示请求的架构与本机只有的三元组),不会再静默产出坏 DLL。
- **导出函数名**:默认 `Start`,可直接 `rundll32 payload.dll,Start`;也可以填成**宿主期望的名字**(如 `GetFileVersionInfoW`)用于白加黑。名字限合法 C 标识符(字母/下划线开头、字母数字下划线、≤64 字符),不合法会在构建前被拒。服务端用 C 侧 `__stdcall` 包装导出,不会与系统声明冲突,386 上还会用 `-Wl,--kill-at` 剥掉 `@16` 修饰,保证 `rundll32 payload.dll,Start` 按字面名能找到。
- **DLL 加载即启动**(默认开,对应构建标签 `autostart`):DLL 被宿主加载时 `init()` 就自动跑植入端,白加黑场景无需宿主调用任何导出函数;需要由宿主决定触发时机时,在页面上取消勾选(请求里 `dll_autostart: false`)。
- **两条落地链**(完整说明见 [docs/LOADERS.md](docs/LOADERS.md)):

  ```bat
  :: ① 白加黑(推荐):把 payload.dll 改名成已签名宿主会加载的 DLL 名,放到宿主同目录,直接运行宿主
  copy payload.dll "C:\Path\SignedHost\version.dll"
  start "" "C:\Path\SignedHost\SignedHost.exe"

  :: ② rundll32 直载(不需要自备宿主;rundll32 是系统签名程序,但该组合被安全软件重点监控)
  rundll32.exe "%TEMP%\payload.dll",Start
  ```

  两条链都靠服务端给出的**载荷 ID** 串起来:构建响应返回 `id`(形如 `build-1789...`),加载器链命令模板里用 `<DLL载荷ID>` / `<shellcode载荷ID>` 占位,控制台的载荷列表会直接显示该 ID 并提供一键填入 —— 也可以直接 `GET /api/v1/implants/stored/{id}/oneliner` 让服务端用当前对外地址重新生成整套命令。
- **如实说明的取舍**:
  - DLL **本身并不更隐蔽**。就文件本身而言,DLL 的特征不比 exe 少;它的价值是**投递/加载链**——磁盘上没有未签名的 PE 可执行文件,发起执行的是已签名宿主进程,从而绕开"未签名新 PE 一律拒绝执行"的策略。**不要**把它当免杀手段;
  - Go 不允许 cgo 包带 Go 汇编,所以 DLL 构建**排除**了 PEB 汇编(`peb_windows.go` 带 `!shared`)与 amd64 直接系统调用(`directsyscall_windows_amd64_shared.go` 回退到 apihash + ntdll 导出)。功能不变,静态/行为特征比 `exe` 略增;需要这两条更强的规避路径时用 `exe`/`raw`;
  - 与 `exe` 一样,DLL 构建也会走 Go 1.20.14 工具链(老系统兼容)与 Go 指纹擦除。

### 4. 支持的目标平台

| 目标系统 | 架构 | 生成格式(`format` 取值 → 产物) |
|---|---|---|
| Windows | amd64 / 386 / arm64 | `exe` → `.exe`;`dll` → `.dll`(需架构匹配的 mingw gcc,见 3.3.1);`shellcode` → `.txt`(hex 文本);`shellcode_bin` → `.bin`(原始字节);`raw` → `.raw` |
| Linux | amd64 / 386 / arm64 | `exe` → ELF 可执行文件(无扩展名);`shellcode` → `.txt`;`shellcode_bin` → `.bin`;`raw` → `.raw` |
| macOS | amd64 / arm64 | `exe` → Mach-O 可执行文件(无扩展名);`shellcode` → `.txt`;`shellcode_bin` → `.bin`;`raw` → `.raw` |

> `format` 还兼容两个旧值:`bin`(Windows 下等同 `exe`,其它平台无扩展名)与 `so`。控制台能力接口 `GET /api/v1/builders` 返回的 `formats` 为 `exe / dll / shellcode / shellcode_bin / raw` —— 想拿**原始二进制**请用 `shellcode_bin`,不要用 `shellcode`(后者是 hex 文本,体积翻倍)。
> 部分平台专属功能(持久化、凭据收集、截图、进程注入)仅 Windows 可用,其余平台会返回"仅支持 Windows"提示。

### 5. 生成步骤(Web 控制台)

1. 打开「生成载荷 / Implants」页面;
2. 选择:目标系统、架构、格式、回连服务器地址(`listener.public_host` + 端口)、行为参数。
   **心跳 / 抖动 / 重试 / 启动延迟这几个输入框默认是空的 —— 留空(请求字段传 0)就等于"跟随设置页",只有确实要覆盖时才填**。不要把同一组参数"在设置页配一遍、再到构建页填一遍":

   | 参数 | 请求字段 | 留空(传 0)时的实际取值 |
   |---|---|---|
   | 心跳间隔 | `interval` | `implant.interval`,未配置则 **60 秒** |
   | 抖动 | `jitter` | `implant.jitter`,未配置则 **20%** |
   | 重试间隔 | `retry_wait` | `implant.retry_wait`,未配置则 **5 秒** |
   | 重试次数 | `retry_count` | **3**(该项**没有**服务端配置项,设置页里也没有) |
   | 启动随机延迟 | `startup_delay_min` / `startup_delay_max` | `implant.startup_delay_min/max`,未配置则 **2~10 秒** |

   页面会把这些服务端**当前生效值**显示成各输入框的 placeholder;`GET /api/v1/builders` 额外返回 `implant_defaults` 对象(含 `interval`/`jitter`/`retry_wait`/`retry_count`/`startup_delay_min`/`startup_delay_max`),控制台据此显示。
   两个容易踩的点:
   - **0 = "未设置",不等于"不延迟"**:启动随机延迟想几乎为零请填 `1/1`,填 0 会回退到配置值(或 2~10 秒);
   - `interval` / `jitter` 的旧硬编码回退(interval==0 → 5s、jitter==0 → 2%)已不再存在 —— 那会把设置页里配好的 60s 心跳悄悄改回 5s 固定轮询。

   > **口径一致性(v1.3.5 已对齐)**:`interval` / `jitter` / `retry_wait` 三条在"请求留 0"时都是**先读服务端配置、再回退内置默认**,与能力接口 `implant_defaults` 报给页面的值同源,因此 placeholder 显示的就是实际烘焙进载荷的值。`retry_count` 例外 —— 它没有服务端配置项,留空固定为 3。
3. 按需开启:garble 混淆、UPX 压缩、XOR 加密、**BOF 支持**(默认关,opt-in)、**主动反沙箱进程检测**(默认关);
4. 点击「生成」,等待构建完成(首次构建需拉取依赖/工具链,耗时较长)。构建成功后响应里会返回载荷 **`id`**(形如 `build-1789...`)与 `download_url`,后续加载器链命令模板靠这个 ID 引用该载荷;
5. 在列表中点击「下载」获取载荷。**已生成的载荷再次下载会直接从磁盘返回,不会重新编译**,速度极快。

> **如何确认参数真的生效**:服务端日志会打印 `rendering implant: … interval=… jitter=… startup_delay=… evasion_scan=… profile=…` 与 `compiling implant: … tags="…"`,这是唯一可信的"真正烘焙进载荷的值"。
> **升级提示**:旧版本的生成载荷表单会**预填**一组默认参数值,升级后这些输入框是空的 —— 这是**预期行为**(空 = 跟随设置页),不是配置丢失或界面出错。

### 5.1 一条命令上线(多种免杀方式)

生成**可直接运行**的载荷后(Windows:`exe` / `raw`;Linux:`exe` / `raw` / `bin`),
页面会列出**多条一键上线命令**,任选一条复制到目标主机执行,即可静默下载并运行该载荷,
无需手动传文件。落地文件名每次随机,避免固定文件名被静态特征命中:

| 平台 | 方式 | 说明 |
| --- | --- | --- |
| Windows | PowerShell · Base64 编码 | `-enc` 编码后命令行不暴露下载地址与落地路径,WebClient 静默下载 + 隐藏窗口启动(首选) |
| Windows | PowerShell · BITS 传输 | 由 BITS 服务(svchost)出网下载,可绕只放行系统更新出网的主机策略 |
| Windows | PowerShell · HttpClient | 去掉 `WebClient` + `DownloadFile` 组合明文特征 |
| Windows | CMD · certutil | 系统自带签名工具下载,白名单/应用控制策略常放过 |
| Windows | CMD · bitsadmin | BITS 命令行工具,兼容老系统 |
| Windows | CMD · curl.exe | Win10 1803+ / Server 2019+ 自带,不触发 PowerShell 执行策略 |
| Linux | Shell · curl / wget 兜底 | curl 失败自动回退 wget(首选) |
| Linux | Shell · wget | 仅依赖 wget(部分加固镜像卸载了 curl) |
| Linux | Shell · busybox wget | 路由 / IoT / 精简容器镜像 |
| Linux | Shell · python3 | 没有 curl/wget 但装了 python3 的镜像 |
| Linux | Shell · 落地用户目录 | 规避 `/tmp` 被挂载为 `noexec` 的加固基线 |
| Linux | Shell · setsid 脱离终端 | 独立会话,ssh 执行后立即断开也不会被回收 |

> **`dll` / `shellcode` 格式没有"下载即执行"变体**,取而代之的是 **8 条加载器链**命令(见 3.3 与 [docs/LOADERS.md](docs/LOADERS.md)),它们同样出现在 `one_liners` 里。

- 下载端点 `/api/v1/implant/payload/{id}` **免认证**,URL 内已绑定载荷 ID,只有拿到该载荷 ID 的人才可下载;这个 `id` 就是构建响应里的 `id`(载荷列表里也会显示),加载器链命令模板中的 `<DLL载荷ID>` / `<shellcode载荷ID>` 占位符要替换成它;
- 命令里的下载地址**由服务端解析**为目标机可达的地址(不再取控制台自身的 `localhost`),优先级:
  `listener.public_host`(推荐:公网 IP 或 CDN/反代域名) → 控制台访问地址(反代域名自动识别) →
  载荷 `server_url` 的主机名 + API 端口 → 本机内网 IP;全部落空时页面会显示醒目告警,提示去配置 `public_host`;
- 需要临时指定地址(例如同一次构建供不同网段使用),可在生成请求里带 `download_host`
  (如 `{"download_host":"https://c2.example.com"}`,填完整 URL 会原样使用,可含反代子路径);
- 载荷列表每项的「一条命令上线」按钮会**实时**向服务端重新生成命令(`GET /api/v1/implants/stored/{id}/oneliner`),改了对外地址无需重新构建载荷。

### 6. 命令行方式(可选)

Web 控制台内置任务调度,命令行方式适合脚本化:

```bash
# 1) 生成载荷(保存到 implants/ 目录,返回 JSON 含 id / sha256 / download_url / one_liners)
curl -X POST http://<IP>:18081/api/v1/builders \
  -H "Authorization: Bearer <JWT>" -H "Content-Type: application/json" \
  -d '{"name":"demo","format":"exe","os":"windows","arch":"amd64","server_url":"1.2.3.4:8080"}'

# 2) 下载已生成的载荷(可重复下载,直接读磁盘,不重新编译)
#    优先按 id 精确下载(避免同名串文件);旧写法也可以只给 name
curl -X POST http://<IP>:18081/api/v1/builders/download \
  -H "Authorization: Bearer <JWT>" -H "Content-Type: application/json" \
  -d '{"id":"build-1789472722331327900"}' -o demo.exe

# 3) 用当前对外地址重新生成该载荷的一键上线/加载器链命令
curl -H "Authorization: Bearer <JWT>" \
  http://<IP>:18081/api/v1/implants/stored/build-1789472722331327900/oneliner
```

**关于签名参数(可选)**:请求体可带 `sign_enabled: true`(证书必须在服务端 `builder.sign_*` 里配好,请求本身**不能**传证书或密码);成功与否看响应里的 `signed` / `signer` / `sign_method` / `sign_status` / `sign_message`。
**关于行为参数**:`interval` / `jitter` / `retry_wait` / `retry_count` / `startup_delay_min` / `startup_delay_max` **不填(或传 0)即跟随服务端配置与内置默认**(与生成载荷页留空等价,见 5 节的对照表);要覆盖就显式给,例如 `"interval":120,"jitter":30`。可用 `GET /api/v1/builders` 的 `implant_defaults` 读出当前生效值。
**关于 DLL**:`format=dll` 时可带 `"dll_export":"Start"`(留空即 `Start`)与 `"dll_autostart":true`(缺省为 true);`bof_enabled` 缺省为 false。

---

## 四、Web 控制台功能

| 模块 | 功能 |
|---|---|
| **仪表盘** | 会话统计、系统信息、版本信息(关于页) |
| **会话** | 会话列表、信息查看、备注、删除、心跳状态 |
| **会话详情** | 系统信息、进程列表、进程注入、交互 Shell、文件管理、截图、BOF 插件、持久化、凭据收集 |
| **文件管理** | 目录浏览、文件上传/下载/删除/重命名/预览 |
| **生成载荷** | 多平台载荷生成(见上文) |
| **模板/插件** | BOF 插件上传与加载管理 |
| **监听器** | TCP / HTTP(S) / WebSocket / MQTT 多通道管理(启动/停止/删除),实时连接数 |
| **隧道** | SOCKS5 隧道代理(起代理横向访问内网) |
| **AI 副驾驶** | LLM 对话 + 30+ 工具闭环,自动理解会话上下文并编排侦察→行动→复盘;支持权限模式(正常模式影响会话操作需确认,任务流除外)与操作审批弹窗 |
| **任务流** | 可编辑任务流模板一键化执行多步链路,跑完自动由 AI 给出结果综述与下一步攻击建议(横向/提权/凭据/域渗透) |
| **通道健康** | 四通道(TCP/HTTP/WS/MQTT)在线会话数与监听器数报表 |
| **登录日志** | 后台登录审计(成功/失败) |

### 文件传输说明

- **上传**:Web 控制台直接选择文件,按 **1MB 分片直传目标主机**并写盘,带实时进度条,支持大文件(无 20MB 限制);
- **下载(小文件 ≤ 2MB)**:植入端 base64 直传,即时返回;
- **下载(大文件 > 2MB)**:植入端按 1MB 分块直传服务端磁盘(`data/transfers/`),控制台再从服务端**流式下载**,支持断点续传,不占用数据库、不一次性载入内存;
- 已生成过的载荷重复下载直接从磁盘返回(不重新编译)。

### 仪表盘统计口径说明

| 指标 | 口径 |
|---|---|
| **总任务** | 数据库全部任务记录(`total`,包含 sent/pending/running 等中间态) |
| **成功率** | 分母只统计**已出结果**的任务:`completed + failed + timeout`。`sent/pending/running` 等下发中/等待中的任务不参与分母,避免正在执行的任务拉低成功率显示 |

> 示例:共 10 条任务,其中 6 条完成、2 条失败、1 条超时、1 条还在下发中(sent)。
> 总任务显示 10,成功率 = 6 / (6+2+1) = 67%,而不是 6/10 = 60%。

### 截图与 BOF 优化

- 截图:PNG 快速编码;超大截图(>2MB)自动切换 JPEG(体积更小、回传更快);
- BOF:系统 DLL 句柄缓存,符号解析无需反复加载 DLL,加载速度显著提升。

### 驱动(BYOVD)加载前自检

下发驱动加载任务前,服务端先做三项检查,结论随驱动列表(`GET /api/v1/drivers`)与加载响应一起返回(字段 `verify`/`warnings`/`selfcheck`):

1. **sha256 一致性(硬拦)**:`manifest.json` 可写 `sha256` 声明期望哈希,与实际哈希不一致即判定「可能被替换/损坏」并**拒绝下发**(HTTP 400);未声明时只提示建议补全。
2. **签名状态**:用 `WinVerifyTrust` 校验 Authenticode 签名与文件是否被篡改,有效时尽量取签名者显示名(目录签名/catalog 的 `.sys` 取不到签名者,只给"签名有效"结论);首次校验可能因证书链/吊销检查变慢,带 4 秒软超时,超时只提示不拦截。
3. **易受攻击驱动黑名单提示**:读注册表 `HKLM\SYSTEM\CurrentControlSet\Control\CI\Config\VulnerableDriverBlocklistEnable` 判断策略是否启用,并探测本机微软黑名单数据 `%windir%\System32\CodeIntegrity\driversipolicy.p7b` 是否存在。若启用,内核会**静默拒绝**名单内驱动(植入端 `StartServiceW` 会报 `1275 ERROR_DRIVER_BLOCKED`);服务端只提示,**不下载也不内置任何名单数据**。

未签名、可能被黑名单拦截等只算**警告**:允许下发但记日志并回传;只有 sha256 不一致这类硬错误才拒发。也可用 `GET /api/v1/drivers/{name}/verify` 单独查某个驱动的自检结论(未找到驱动返回 404 + 中文原因)。自检仅 Windows 生效,其他平台返回「非 Windows 平台不做驱动自检」。

### 内存执行载荷预检(下发前)

`fileless-exec` 下发前,**服务端先读 PE 头**判断这条载荷能不能内存执行,避免"目标机崩了才知道":

| 判定 | 情况 | 结论 |
|---|---|---|
| **拒绝** | Go 编译的 PE + `kind=exe_mem` | 宿主植入端也是 Go runtime,反射执行会崩宿主 → 改用落地执行 |
| **拒绝** | 架构与植入端不一致 | `exe_mem` 无法跨架构;`kind=exe`(donut) 只给警告 |
| **拒绝** | 带 CLR 目录(.NET) | `exe_mem` 没有 CLR 宿主环境 → 落地执行或 donut |
| **警告** | 有 TLS 目录 / 无重定位表 / donut 转换 | 允许下发,但提示可能初始化不全或映射失败 |
| 通过 | 其余原生 PE | 正常下发 |

响应里同时带 `reasons`(为什么)、`suggestion`(怎么办)与精简 `pe_info`(machine/是否 64 位/是否 DLL/是否 Go/是否有 TLS 或 CLR);确需强行下发可带 `force: true`,此时拒绝降级为警告并在日志里留痕。

---

## 五、云端部署注意事项

> **域名 + CDN / 反向代理 / 域前置上线**:完整操作说明(C2 端点清单、CDN 回源配置、Nginx 反代示例、域前置的正确用法与限制、排错 FAQ)见 **[docs/DEPLOY-DOMAIN-CDN.md](docs/DEPLOY-DOMAIN-CDN.md)**。

1. **安全组/防火墙**:放行 C2 端口(默认 8080)与 API 端口(默认 18081);
2. **域名与证书**:建议使用 HTTPS 访问控制台(`server.tls_cert` / `server.tls_key`),C2 可启用 TLS(`listener.tls_enabled` + `cert_file` / `key_file`);
3. **密钥管理**:`encryption_key`、`jwt_key` 留空可自动生成;更换后需重新生成所有植入端;
4. **数据库**:默认 SQLite 单文件(`data/toshell.db`),建议定期备份;高并发可切换 PostgreSQL;
5. **日志**:默认输出到 stdout,可配置 JSON 格式输出到文件并按天轮转压缩;
6. **清理**:会话删除后,`data/transfers/` 下的已下载大文件不会自动清理,可定期手动删除。

### 发布正式版(清空历史数据)

正式发布前需要清空历史任务/会话/日志记录时,使用项目内脚本 `scripts/reset_release_db.py`:

```bash
# 清空项目根目录库(开发/构建环境)
python scripts/reset_release_db.py

# 清空 release/ 目录正式库(正式版 toserver 运行在 release/ 下,库路径为相对路径 ./data/toshell.db)
python scripts/reset_release_db.py --db release/data/toshell.db
```

脚本功能:

| 操作 | 说明 |
|---|---|
| **备份** | `VACUUM INTO` 一致性快照到 `data/backup/`,含 WAL 未落盘数据;自动保留最近 20 份 |
| **清空** | `tasks`(任务)、`sessions`(会话)、`logs`(日志)三张表 |
| **重置** | 重置 `tasks`/`logs` 自增序列,后续 ID 从 1 重新开始 |
| **保留** | `listeners`(监听器)、`custom_templates`(自定义模板)、`implants`(植入物记录)不受影响 |

> **重要**:
> - 执行前请先**停止服务端进程**,再执行脚本,最后重新启动,否则 Web 仍会显示内存中的旧任务;
> - 脚本执行前若需保险,可先用 `--no-backup` 外的手动复制再执行,或直接依赖脚本自带备份;
> - 只清空不备份:`python scripts/reset_release_db.py --no-backup`(不推荐,除非已自行备份)。

---

## 六、常见问题

| 问题 | 解决方法 |
|---|---|
| 植入端无法回连 | 检查 `listener.public_host` 是否为公网可达地址、端口是否放行、加密密钥是否一致 |
| 生成 Linux/macOS 载荷报错 `undefined: handleXxx` | 请使用本次修复后的版本(已为 Linux/macOS 补充功能 stub);同时更新 `release/implant/` 模板 |
| 下载载荷很慢 | 已生成过的载荷再次下载直接从磁盘返回(不重新编译);首次生成因拉依赖/编译较慢属正常 |
| 载荷体积与页面显示不符 / 体积翻倍 | **`shellcode`(.txt)格式保存的是 hex 文本,体积是原始字节的 2 倍属正常**。需要更小的请生成 `shellcode_bin`(原始二进制)或 `raw` 格式;页面显示已按实际下载文件大小修正 |
| Windows 7 / Server 2008 R2 上 exe 无法启动 | 该问题已修复:服务端生成 Windows 载荷时自动使用 Go 1.20.14 工具链编译(见上文"老系统兼容")。若仍失败,确认使用的是最新版 `toserver` |
| 大文件下载失败 | 确认 `data/transfers/` 可写;大文件走流式下载通道 |
| garble/UPX 选项不可用 | 服务端未安装对应工具,按上文安装后重启服务端。**garble 还要求 Go 版本足够新**(如 garble v0.16 需 Go ≥ 1.26),版本不匹配时界面会直接显示"不可用"并给出原因,不会再出现"显示可用但构建必失败" |
| 页面显示未检测到 mingw gcc(C 植入端不可用) | 按以下顺序排查:<br>① 在**设置页刷新**即可——服务端每次打开生成载荷页都会重新探测(30 秒缓存),装好工具链无需重启服务端;<br>② 已装 MSYS2 但没有 64 位 gcc:执行 `pacman -S mingw-w64-x86_64-gcc`(32 位用 `mingw-w64-i686-gcc`);<br>③ 只装了 32 位 gcc 也能编 **C 植入端**,但界面会明确提示"产物是 32 位 PE";**`dll` 格式则必须架构严格匹配**(见下一行),32 位 gcc 不能用来生成 x64 DLL;<br>④ 便携版 MinGW 可直接解压到服务端目录(如 `release/mingw64/bin/gcc.exe`)即被自动识别;<br>⑤ 也可设置环境变量 `TOSHELL_MINGW_GCC`/`CC`(或 `MINGW_HOME`/`MSYS2_ROOT`),或在 `configs/server.yaml` 配置 `builder.mingw_gcc_path`。服务端会同时读 **Windows 注册表 PATH**,因此"刚把 gcc 加进系统环境变量"这种情况不用重启进程也能识别 |
| 生成 `dll` 报错"需要与目标架构一致的 mingw-w64 gcc" | 这是**预期行为**,不是坏产物:c-shared 构建要求编译器架构与目标严格一致(`amd64` 要 `x86_64-w64-mingw32-gcc`,`386` 要 `i686-w64-mingw32-gcc`)。按提示装对应 gcc(`pacman -S mingw-w64-x86_64-gcc` / `mingw-w64-i686-gcc`),或把正确路径填到 `builder.mingw_gcc_path`;本机只有 i686 时请把目标架构改成 `386`,服务端**不会**拿它硬凑出一个宿主加载不了的 x64 DLL |
| DLL 加载后没有任何反应 | ① 导出名对不上:`rundll32 payload.dll,<导出名>` 必须与构建时填的导出名一致(默认 `Start`;386 上已用 `-Wl,--kill-at` 剥掉 `@16`,按字面名找即可);② 「DLL 加载即启动」被取消勾选,而宿主又不调用任何导出函数;③ DLL 与宿主进程的架构不一致 |
| 载荷体积过大(3~7MB) | 体积取决于通道与选项:**TCP 通道全量约 3.4MB**,**HTTP(S) 轮询通道约 7MB**(HTTP 传输自带 `net/http` + `crypto/tls` + uTLS 指纹库)。要小体积可选:① 开 **UPX 压缩**(约 1.1~2.2MB);② 选 **light 精简档案**(TCP 约 2.9MB / HTTP 约 5.3MB);③ 选 **C 植入端**(仅 Windows exe,约 60KB) |
| 登录日志不显示图标 | 旧版本日志级别为大写格式,升级后新日志统一为小写,图标全部正常 |
| 后台 401 | 登录后 Token 有效期 24h;使用 `X-API-Key` 时需在 `auth.api_keys` 配置 |
| 清空数据库后 Web 仍显示旧任务 | **服务端内存缓存了任务,需重启服务端进程**。任务列表/统计优先读内存,清空数据库只清磁盘,重启后才会同步为空 |
| 成功率偏低 / 与预期不符 | 成功率分母只统计已出结果任务(`completed+failed+timeout`),`sent/pending/running` 下发中任务不计入分母(见上文统计口径) |

---

## 七、联系方式与支持

| 渠道 | 地址 | 用途 |
|---|---|---|
| GitHub | <https://github.com/iQingshan/Toshell> | 源码、Release、Wiki |
| Issue | <https://github.com/iQingshan/Toshell/issues> | 使用问题、功能建议、Bug 反馈(建议附版本/系统环境/复现步骤/日志) |
| 邮箱 | <qingshan@88.com> | 商务合作、授权咨询、漏洞与滥用披露 |
| 作者主页 | <https://github.com/iQingshan> | 其它工具与项目 |

提 Issue 前建议先检索已有 Issue 与本文「六、常见问题」;安全/滥用问题请走邮件,**不要**在公开 Issue 里贴可利用细节(详见 `SECURITY.md`)。

---

## 八、免责声明

本工具仅限**授权测试**与安全研究使用。使用者须自行遵守当地法律法规,因滥用造成的后果与作者无关。详见 `LICENSE` 与 `DISCLAIMER.md`。

---

## 附、更新日志与新增功能

### v1.4.0(2026-09-28)

- **开放 MCP 接口 + 公共执行基础设施(S1)**:工具元数据单源化——38 个工具(37 + 回读元工具 `result_read`)按 read 13 / confirm 14 / danger 11 分档,`GET /api/v1/mcp/tools`、内置 AI function schema 与 MCP `tools/list` 三处同源;所有工具统一结果信封 `{status,data,error,meta}`,超限结果落盘 `data/mcp-results/` 并用 `result_read` 分页回读(不再静默截断);审批从"允许列表 + fail-open"改为**默认危险、只读白名单免审批**,并修掉 `plugin_upload`/`fileless_exec` 的路径穿越;对外 MCP 服务端 `mcp.*` 默认关闭、只绑回环、必须有 token。
- **Agent 长任务可靠性(S2)**:任务等待改**事件驱动**(不再 sleep 轮询)、4 张 `agent_*` 表落盘 + 重启对账;长结果外置成句柄;上下文按常驻/任务/工作/历史四层装配 + `max_context_tokens`/`max_run_tokens` 双预算(超预算先压缩后停止);SSE 支持 `Last-Event-ID` 断点续传,事件缺口用 `resync` 显式告知;三处硬上限 + 防死循环;离线黄金集 12 例随 CI 跑。
- **免杀分层治理(S3)**:字符串混淆补齐转义字面量与反引号原始字符串、DLL 路径降特征;签名顺序契约(`finalize_order.go`,**签名必须是最后一步**);Go 版本串全文件擦除;PE 资源/图标/版本信息/时间戳(步骤 `pe_resource_patch`,**默认不注入**)+ 一键中性预设 `resource_preset="neutral"`;节名规范化(步骤 `section_normalize`,**默认执行**,实测 −512 B、节数 6→5);顺带修掉"用了资源预设的载荷无法运行"的回归(五份产物 `LoadLibraryEx` 5/5 通过)。
- **体积分档与内存加载(S4)**:新增 `exec_module` 内存模块(ABI v1 + 一次性 token + 9 步校验链,`-tags execmodule` 门控);会话能力位图 `internal/common/features` 改由载荷上报(light 11 项 / full 31 项),不再给未编译进载荷的能力造"点了没反应"的假面板。发布版实测:light/tcp 2,946,805 B、execmodule 门控 +27,136 B、full 相对 light +575,488 B;`nano ≤1.8 MB` 与传输栈模块化**已定论不做**。
- **低特征通道(S5)**:`listener.ws_path` 只对一条路径升级(变形路径与不完整握手一律普通 404,不再回 `Sec-Websocket-Version`)、`listener.ws_host_allowlist` 收窄 Host、植入端 WS 与 HTTP 同口径吃 `front_domain`;不支持中继的通道从"静默失败"改为明确 **409**。
- **杀软对抗分级 AV-Ops(S6)**:新增 `GET/POST /api/v1/av-ops` 与 `GET/POST /api/v1/sessions/{id}/av-ops`(七步前置检查 + `impact{}`/`checks[]`/`warnings[]` + 中文原因,排障先看后者);L0 侦察默认开、L1 温和需二次确认、**L2+ 出厂关闭**且 fail-closed;破坏性任务**禁止服务端自动重投递**;控制台新增「对抗分级」面板;**内存执行加固**(`exe_mem`/`dll` 载荷退出不再带走宿主,stdout/stderr 回传)与**配置热重载报错可见**同版落地。
- **AI/agent 修复**:流式调用改**空闲超时**(`ai.timeout` = 连续多久没收到数据)且出错兜底必带失败原因;上游缺 tool_call id 时补稳定 id,新增 `context.sanitizeToolPairs()` 在装配出口补齐"未完成回执"(不伪造结果),修掉 `assistant.tool_calls` 与 `tool` 不成对导致的 400。
- **如实边界(未验证/未做)**:真实证书/EV 与目标机信任链、真实 CDN 域前置、`wss` 真实证书链、uTLS/JA3 指纹、HTTP/2 均**未落地**;AV-Ops 的 **L2/L3/L4 从未在真机执行**(L4 无落地动作);`exec_module` 只真机跑过 **TCP** 通道、单帧上限 4 MiB(未做分块);内存执行加固只覆盖 IAT 间接调用(**inline hook 未做**),**无控制台启动时捕获不到 stdout**;`nano ≤1.8 MB` 在 Go 里做不到。逐条实现细节与全部未验证项见 `CHANGELOG.md` 的 v1.4.0 段。

### v1.3.5(2026-09)

- **DLL 载荷修好了**:`format=dll` 以前其实是"改了扩展名的 EXE"——普通 `go build`(`CGO_ENABLED=0`)下 `import "C"` 的胶水被 Go 静默跳过,实测产物 `IMAGE_FILE_DLL=false`、无导出表,导致白加黑/rundll32 三条链第一步就失败。现在用 `-buildmode=c-shared + mingw-w64 gcc` 编译**真 DLL**:`IMAGE_FILE_DLL=true` + 导出表;默认**加载即启动**(Go 的 `init()` 在 c-shared 下执行 → `go startImplant()`),导出名可配置(默认 `Start`,可填宿主期望的系统 API 名),386 上用 `-Wl,--kill-at` 剥掉 `@16` 修饰以便 `rundll32 payload.dll,Start` 按字面名找到。要求 gcc 与目标架构一致(x64 需 `x86_64-w64-mingw32-gcc`),否则明确报错而不是产出错误架构的 DLL;能力接口新增 `dll_available/dll_message`,页面直接显示缺哪个 gcc。
- **共享库构建的取舍(如实说明)**:Go 不允许 cgo 包带 Go 汇编,故 DLL 构建排除 PEB 汇编与 amd64 直接系统调用,新增 `directsyscall_windows_amd64_shared.go` 走 apihash 回退(功能不变,特征略增);`main.go` 入口拆成 `startImplant()`(DLL/exe 共用)+ `entry_exec.go`(`!shared`)。
- **修 JSON 响应 bug**:构建失败时按 `{"error":"%s"}` 拼字符串,错误里含换行(编译失败信息几乎必然多行)时产出非法 JSON,前端 `JSON.parse` 抛错、只显示"解析失败"。新增 `writeJSONError` 并按此改写。
- 实测:386 DLL 导出 `Start` / 自定义 `GetFileVersionInfoW` 均正确;请求 amd64 且本机只有 i686 gcc 时给出 `pacman -S mingw-w64-x86_64-gcc` 的明确提示。
- **构建后代码签名(Authenticode)**:新增服务端签名能力(证书文件 pfx 或本机证书存储指纹),构建产物在落盘前签名,接口返回 `signed/signer/sign_method/sign_status/sign_message`,生成载荷页直接显示"已签名/未签名原因"。实测:自签证书签名后 `SignatureType=Authenticode`、签名者与指纹一致、体积 +1.4KB;签名栈优先 `signtool.exe`(仅指纹模式,避免密码进命令行),否则回退系统自带 PowerShell(密码走环境变量)。踩坑修复:Windows PowerShell 5.1 的 `Get-PfxCertificate` 没有 `-Password` 参数,改用 `X509Certificate2(path,pw,flags)`;`Status=UnknownError` 且有签名者时语义是"已签名但链不受信任",不再误报"未签名"。
- **8 条加载器链 + 落地建议**:`one_liners` 新增白加黑(DLL 侧加载)/ 计划任务 + 已签名宿主 / rundll32 / mshta / regsvr32 Squiblydoo / certutil + 宿主 / PowerShell 内存注入 shellcode / mshta + 签名宿主注入(骨架),每条带 `note`(前置条件与国产杀软下风险等级);Windows `dll`/`shellcode` 格式以前回"不支持一条命令上线",现在返回加载器链。新增 `LoaderAdvice(targetOS, format, signed)` → 响应字段 `loader_advice_title/tips`,给出"直接运行 → 计划任务 → 白加黑 → 内存加载"的降级顺序。文档见 `docs/LOADERS.md`。
- **BOF 改为按需编译(默认关)**:BOF 兼容层必须导出整套 `Beacon*` API 名字(实测 22 处明文,是 full 档案里唯一剩下的高信号特征),现改为 `-tags bof` 才编译;默认载荷 `beaconAPI=0`,勾选后为 22(证明门控生效)。生成载荷页新增「BOF 支持」开关。
- **Go 构建期指纹擦除**:新增 `ScrubGoFingerprint`(只做原地置零、长度不变):擦除 `\xff Go buildinf:` 魔数、buildinfo 窗口内的 `go1.x.y` 版本串、`Go build ID:` 前缀(这三类是 Go 家族 YARA 规则最稳定的命中点,运行时不需要);pclntab/符号表绝不触碰。exe 与 dll 两条编译路径都已接入,实测默认载荷 `Go buildinf=0`、`Go build ID:=0`。
- **生成载荷页不再预填行为参数(留空=跟随设置页)**:心跳间隔/抖动/重试间隔/重试次数/启动随机延时的输入框改为**默认空**,空(= 请求字段传 0)即取服务端「设置 → 植入端默认参数」的值,未配置才回退内置默认(60 秒 / 20% / 5 秒 / 3 次 / 2~10 秒);每个输入框把服务端当前生效值显示成 placeholder,能力接口新增 `implant_defaults` 对象供控制台读取。目的是不再让用户"设置里配一遍、构建页再填一遍"。
- **可回归**:`gate_scan_test.go` 增加 `TestBOFIsOptIn`;`harden_test.go` 覆盖擦除/幂等/边界。

### v1.3.4(2026-09)
- **动态查杀排查(重要结论)**:本机(装有 360 安全卫士 + 腾讯电脑管家 + 无边界安全系统)实测——**任何新生成或未签名的 PE 一执行就被拒绝并删除文件**,与载荷里有什么代码无关:一个只有 `time.Sleep` 的 Hello-World Go 程序同样被拒(`Access is denied` + 文件被删除),`release/implants/` 历史产物被清空;对照微软签名的 `notepad.exe` 副本可正常执行。→ 拦截依据是"未签名/未知 PE + 主动防御策略",**改载荷代码无用**;这类环境请走代码签名或由已签名宿主加载(见 `ROADMAP.md` P0-5)。
- **植入端默认行为收敛**:不再默认"枚举进程找杀软"。原实现启动时遍历全系统进程并与 38 个安全软件/分析工具进程名比对,这是国产杀软主动防御**明确拦截**的对抗行为,还必须静态导入 toolhelp32 并携带这批字符串;现改为构建标签 `evasionscan` 门控,生成载荷页勾选「主动反沙箱进程检测」才编译进来(默认关)。
- **pclntab 高信号标识符中性化**:`loadShellcode`/`loadEXEMem`/`reflectLoadPE`/`injectShellcodeHost`/`stompShellcode`/`evasionInit` 等函数名与 `memexe_windows.go`/`memload_windows.go`/`stomp_windows.go` 等文件名全部改为中性名(实测命中数归零,能力不变);`light` 档案进一步裁剪 BOF,连 `beacon*` 也为 0。BOF API(`BeaconDataParse` 等)是 ABI 契约不能改名,已在文档写明。
- **三个"配置了却无效"的缺陷**:① 请求里的 `startup_delay_min/max` 此前被服务端**静默丢弃**(结构体没这两个字段),现已透传,生成载荷页新增启动随机延迟输入框;② `interval==0 → 5s`、`jitter==0 → 2%` 的硬编码会把设置页的 60s 心跳改回 5s 固定轮询,现改为优先跟服务端配置(示例配置默认 60s / 20%);③ 驱动加载失败只报"可能被 HVCI 拦截",现回传具体 Win32 错误码(1275/577/1053/1058/1073/1056/5/2)与排查结论。
- **构建参数可核对**:服务端日志新增 `rendering implant: … interval=… jitter=… startup_delay=… evasion_scan=… profile=…` 与 `compiling implant: … tags="…"`,这是唯一可信的"真正烘焙进载荷的值"。
- **BYOVD 驱动加载前自检**:sha256 与 `manifest.json` 声明不一致 → 拒绝下发(400);`WinVerifyTrust` 校验签名与篡改并尽量取签名者;读本机策略提示"易受攻击驱动黑名单/HVCI 会静默拒绝(1275)"。列表与加载响应带 `verify`/`warnings`,也可 `GET /api/v1/drivers/{name}/verify` 单查;前端驱动按钮直接标出"哈希不符/未签名"。
- **内存执行下发前 PE 预检**:`fileless-exec` 之前先解析 PE 头并识别 Go 载荷,Go+`exe_mem`、架构不符、.NET 直接拒绝并给出原因与建议(可用 `force: true` 强制,日志留痕);TLS 回调/无重定位表/donut 路径给警告。
- **发版门禁**:新增 `scripts/e2e_smoke.ps1`(临时服务端 + 鉴权与关键路由校验 + windows full/light + linux 三档载荷构建 + 可选真植入端上线与任务回执,输出 ✅/⚠️/❌ 摘要,有 ❌ 非 0 退出);CI 增加 tag 与 `toserver -version` 一致性校验、发布包内容清单校验,并生成 `checksums.txt`(sha256)随 Release 发布。

### v1.3.3(2026-09)
- **Web 控制台防资产测绘**:新增 `web.*` 配置(基础认证/未认证响应模式/来源白名单),在控制台与管理 API 前加认证门槛,阻止 Fofa/Quake/Hunter 等测绘引擎收录;设置页「安全 → 防资产测绘」可视化配置,保存即热生效。
- **两种未认证响应**:basic = 401 认证框(浏览器弹框,前端照常可用,默认);disguise = 纯 404 伪装(不留 C2 特征)。
- **隐蔽入口 `/__gate`**:disguise 模式不返回 401 挑战,浏览器也不会把 URL 内嵌凭据带到 JS/CSS 请求,故提供入口——`/__gate?k=<密钥>` 直接进入,或访问 `/__gate` 由浏览器弹框输入凭据;成功后种下 HttpOnly 入口 Cookie(30 天),前端与 API 凭 Cookie 通行,而 `/` 与其他路径依旧 404。
- **不影响业务**:植入端 `/api/v1/implant/*` 完全豁免(注册/心跳/结果/一条命令上线载荷/UAC 载荷);API Key / JWT 客户端继续放行;C2 监听器端口不受影响。
- **配置写入可靠性**:保存改为「YAML 节点树读-改-写 + 临时文件 fsync → rename 原子替换」,不再丢字段、不再抹掉注释与字段顺序、中断不损坏配置;首次启动生成的凭据写盘失败将直接终止启动并打印配置路径(修复「每次重启都换随机密码、被锁在门外」);启动日志打印实际配置路径。
- **修复设置页破坏 API Key**:脱敏回显值曾被当作新密钥写回配置,现前端不回传该字段、后端忽略含 `****` 的条目。
- **跨平台载荷构建修复**:macOS/Linux 的 full 档此前报 `undefined: stompShellcode`、light 档因构建标签与 light stub 冲突而编译失败,均已修复;`{windows,linux,darwin}×{amd64,arm64}×{full,light}` 构建矩阵全部通过。

### v1.3.1(2026-09)
- **Agent 全原子工具面**:命令/文件/进程/凭据/截屏/插件/内存加载等工具全部原子化(一次调用直接返回最终结果),agent 不再暴露 task_wait/task_submit/run_command —— 杜绝编造 task_id 导致的 task not found 死循环。
- **信息收集收敛成报告**:侦察类请求固定清单一次收齐 + 命令级去重,最后输出结构化情报报告;建议/咨询类请求只轻量取材直接给方案,不再自动展开侦察链。
- **短消息纯聊**:发「1」「好」等极短输入走独立无工具、token 封顶的纯聊通道,不再长篇执行回复。
- **执行过程内联**:副驾驶执行过程以带 icon 日志行(🎯/🔧/✅/❌)直接显示在会话气泡里,去掉顶部独立 Agent 面板;剧本 AI 建议晚到也会补发。
- **会话列表实时刷新**:上线/下线/复活统一 WS 事件推送,Sessions 页与副驾驶侧栏即时更新。
- **稳定性**:植入端心跳异步入队(长任务不掉线)、心跳超时可配 + 任务 busy 宽限;剧本 AI 分析超时放宽至 90s;新增 capability-assess 剧本与 scripts/smoke.sh 冒烟脚本。

### v1.3.0(2026-09)
- **Agent 目标驱动执行**:复杂/多步目标先输出【执行计划】并逐步推进;run 记录目标与计划进度,跨消息保持。
- **上下文压缩**:历史过长时保留 system+最近 14 条,更早工具结果折叠为一行摘要,防长任务 token 爆炸。
- **动作审计**:每次 agent 工具调用写结构化日志(component=agent-audit),动作可追溯。
- **安全加固**:API Key 一键轮换(设置页,新密钥一次性展示);敏感配置支持环境变量覆盖(TOSHELL_AUTH_JWT_KEY/TOSHELL_AUTH_API_KEYS/TOSHELL_LISTENER_ENCRYPTION_KEY/TOSHELL_AI_API_KEY)。
- **Web 多语言 + Agent 控制台**:新增中/英语言切换(顶栏/登录页);副驾驶页显示当前 run 的目标、执行计划与状态(Agent 控制台视图)。
- **任务幂等**:已终态任务忽略重复结果帧,杜绝重连补发导致的重复副作用。
- **工程**:CI check-latest 修正 Go 工具链;-ldflags 注入 version/commit/buildTime(`-version` 可溯源)。

### v1.2.1(2026-08)
- **自主 Agent（异步）**:副驾驶改为异步自主执行——交代任务后立即返回 run_id，后台 goroutine 自主完成 ReAct 循环，不再同步阻塞对话；支持取消、并发上限。
- **SSE 流式思考**:agent 推理（reasoning）与工具步骤经 SSE 事件流实时推送前端，思考过程与每步工具可见。
- **连续上下文记忆**:同一 agent 会话跨消息追加记忆（session_id 续接），agent 记住全部历史判断，能持续规划。
- **自主提权/失败恢复**:评估后谨慎提权，工具失败自动换路径、说明原因，不再无脑重试；任务/命令加超时保护，不再卡死会话。
- **只输出结论与建议**:最终答复聚焦【现状】+【建议】+【为何】，不再大段堆砌原始结果。

### v1.2.0(2026-08)
- **AI 副驾驶(全新)**:内置 LLM ReAct 智能副驾驶(30+ 工具),自动注入当前在线会话上下文、连续编排「侦察→行动→等结果→复盘」;支持 Markdown 结构化输出;删除原"自主规划"(鸡肋功能)。
- **权限模式与操作审批**:设置页「AI 副驾驶」新增权限模式(全自动 / 正常模式),正常模式下影响会话的操作(命令/文件/进程/凭据/截屏/隧道/插件等)执行前弹窗需用户「允许/拒绝」,任务流(delegate)除外;热生效,无需重启。
- **任务流(剧本)统一**:副驾驶任务面板与「任务模板」页同源(数据库模板),可编辑/删除;模板即任务流,一键执行跑完自动由 AI 给出结果综述+下一步攻击建议;内置 3 个示例模板(可删可改)。
- **自主任务规划器已移除**:其"多阶段规划"为占位实现,功能鸡肋,已删除。
- **多通道监听**:新增 MQTT 监听器(内嵌/外部 broker),监听器页支持 TCP/HTTP/WebSocket/MQTT;监听列表连接数改为实时统计在线会话数。
- **免杀加固**:每构建随机化配置块魔数/密钥、xd 字符串密钥基准、API 哈希种子/乘子,打破跨样本同指纹;进程注入自动随机挑选良性宿主(explorer/svchost/dllhost/Teams 等);配置块魔数与 XOR 密钥三端(服务端/Go/C 植入端)一致。
- **副驾驶体验**:左「在线会话」右「最近任务」三栏布局,聊天区更宽;任务完成自动在对话给一条 AI 建议(按触发批次去重,不刷屏);上下文压缩(历史限 14 条/单条截断)控制 token 与超时。
- **仪表盘**:最近任务命令过长自动截断,修复撑爆布局。

### v1.1.0(2026-08)

#### 1. 回连通道与载荷生成
- **双回连通道**:TCP(自定义加密帧协议,载荷约 3.4MB,全功能)与 HTTP(S) 轮询通道。
  生成载荷页「回连通道」按监听器类型自动匹配:选 TCP 监听器 → 通道 TCP、地址 `host:port`(勿加 `http://` 前缀,误加会自动剥离);选 HTTP/HTTPS 监听器 → 通道 HTTP/HTTPS、地址 `http(s)://host:port`。
- **域前置(Domain Fronting)**:HTTPS 轮询通道支持自定义 TLS SNI 与 HTTP Host 拟态域名(构建页「域前置拟态域名」或 `listener.front_domain`)。服务器部署在 CDN/反向代理后,目标机出站流量表现为访问合法域名,可过域名白名单出口。**v1.4.0 S5 起 WebSocket 通道同样吃 `front_domain`**(口径一致:连接目标仍是真实 C2 地址,TLS SNI 与 HTTP Host 头用前置域)。
- **WebSocket 通道的主动探测面(v1.4.0 S5;详见 `docs/EVASION.md` §2.6)**:WS 监听器只对配置的 `listener.ws_path`(默认 `/`)升级,其它路径/路径变形/不完整握手一律返回普通 404(与"路径不存在"不可区分);可用 `listener.ws_host_allowlist` 收窄 Host。改 `ws_path` 必须同时改载荷 `server_url` 里的路径,否则载荷连不上。
- **transport 条件编译**:TCP 载荷不链接 net/http/crypto/tls,体积由约 6MB 降至 3.4MB(约减半),标准库指纹更少,利于免杀。
- **监听器页简化**:合并"类型/协议"为单一「类型」选择(TCP / HTTP),不再出现易混淆的 WebSocket 等协议值。

#### 2. 网络与对抗能力
- **Beacon Mesh 中继**:在线会话可一键升级为中继节点(会话详情「中继」页),叶子植入端链式回连,支持多跳;中继链路 SM4-GCM 加密;构建页可从在线中继列表直接选取回连地址。
- **实时屏幕流**:会话详情「屏幕流」页,前端支持缩放与全屏。
- **内核级对抗(Windows,实验性)**:EDR 失明(ntdll 脱钩 + ETW 抑制 + Autologger 禁用)、EDR 击杀、**驱动击杀**(操作员自备的易受攻击驱动:用其无鉴权进程终止 IOCTL 按 PID 杀进程,入参首个 DWORD 为 PID;对 PPL 保护进程无效,那类走句柄窃取)、PPL 保护清除(句柄窃取路线)。RTCore64/dbutil_2_3 已不再内置(黑名单重点标记、落地即被查杀);如需自定义驱动,可在杀软对抗页上传 .sys。

#### 3. 设置与运维
- **运行时设置热更新**:设置页真实读写配置(监听器/拟态模板/通知/账户),webhook、流量拟态模板、认证信息保存即热生效,无需重启进程;配置文件被外部修改自动重载。
- **各平台 webhook 通知**:按 URL 自动识别目标平台并发送**各自要求的消息结构**——钉钉(markdown,加签走 URL 参数)、飞书/Lark(`msg_type`+`content.text`,加签走 body 内 `timestamp`+`sign`)、企业微信(`msgtype`+`text.content`)、Slack(`text`)、Discord(`content`),其它地址回退通用 JSON;也可在设置页手动指定格式。加签 Secret 配 `server.yaml` 的 `webhook.secret`。**判定结果同时看响应体**:飞书 `code≠0`、钉钉/企业微信 `errcode≠0` 都算失败并显示平台原话(HTTP 200 不代表成功),设置页「发送测试通知」会显示识别到的平台与失败原因。
- **BYOVD 驱动(操作员自备)**:服务端**不再内置任何驱动**(内置等于把驱动名与 IOCTL 明文写进服务端与载荷,是最稳定的查杀特征)。请自行准备已签名的易受攻击 `.sys`:放到服务端 `drivers/`(或 `data/drivers/`)并在 `manifest.json` 里声明 `device/service/ioctl`,或直接在杀软对抗页上传并手填设备名/服务名/终止 IOCTL;加载后即可按 PID 或进程名「驱动击杀」普通杀软/EDR 进程,测完点「卸载驱动」清理。
- **会话判活余量**:实际判活阈值 = `max(listener.heartbeat_timeout, 3 × 植入端实测心跳间隔)`,启动日志会打印 `margin 3x`。因此心跳间隔与超时几乎相等也不会出现「离线几秒又在线」抖动;只有真正持续失联才判死。会话闪断重连在 15 秒观察窗内**不会**广播离线/上线事件(也不再重复推送上线通知)。
- **屏幕流/截图参数**:实时屏幕流与截图支持 `fps`(1-10)/`quality`(20-95)/`max_kbps`(带宽上限,超限自动降画质再降帧)/`monitor`(0=全部显示器拼接,N=第 N 个显示器)/`max_width`(缩放宽度)。屏幕流面板「画质参数」可直接设置;实测 2560×1440 缩放到 640 宽后 JPEG 体积从约 343KB 降到约 21KB。捕获失败(锁屏/无交互桌面/Headless)会立即回传原因并在面板提示。

#### 4. 注意
- 升级后请**重启服务端**并**重新生成植入端**(旧植入端与新密钥/新模板不兼容)。
- 域前置与 HTTPS 轮询需要服务器配置 TLS 证书(`listener.tls_enabled` + `cert_file`/`key_file`)并部署在 CDN/反向代理之后。
- 内核级对抗(BYOVD/PPL/EDR 击杀)为实验性能力,偏移与驱动行为随系统版本变化,需在目标环境实机验证。
