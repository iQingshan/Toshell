# ToShell Team Server

> 自托管的 C2（命令与控制）远程管理平台，用于**授权红队演练、渗透测试与安全研究**。
> **仅限获得授权后使用。** 严禁未授权的入侵 / 攻击 / 数据窃取。

**v1.2.0** · [MIT License](LICENSE) · 作者：青山 / Q1lintu / c0ffee

---

## 这是什么

ToShell 是一个轻量 C2 框架，由 **服务端（Team Server）+ Web 控制台 + 多平台植入端** 组成，覆盖「生成载荷 → 会话管理 → 任务执行」的完整链路。单二进制即可部署整套服务，开箱即用。

## 核心特性

**多通道 · 多平台植入端**
- 回连通道：**TCP / HTTP(S) / WebSocket / MQTT**（可配合域前置、TLS 拟态）。
- 植入端：**Windows / Linux / macOS**，格式 `exe / dll / raw / shellcode`，支持 `full / light` 档案与老系统兼容（Go 1.20 工具链）。

**全功能会话操作**
- 交互 Shell、目录/文件管理（上传/下载/删除/预览，断点续传）、进程枚举/注入/杀死。
- 截图、实时屏幕流、凭据收集、UAC 提权、持久化、文件无执行、BOF/DLL/EXE 插件。

**组网与隧道**
- Beacon Mesh 多跳中继、SOCKS5 隧道代理（横向访问内网）、中继链路加密。

**任务流 + AI 副驾驶**
- 任务流/剧本化执行（可编辑模板，跑完自动 AI 复盘）。
- **AI 副驾驶**：联网搜索、远程下载工具、按用途插件/内存加载、结果分析与下一步建议；支持**权限审批**（影响会话的操作需确认）。

**免杀与隐蔽**
- 每构建随机化（配置块魔数/密钥、字符串密钥、API 哈希种子）、编译期字符串混淆、apihash/PEB 动态解析、**反沙箱 + 启动随机延迟**、进程注入随机良性宿主。

**加密通信**
- 控制帧 AES-256-GCM 认证加密 + 隧道数据 SM4-GCM（国密自研），密钥域分离；配置热更新。

## 功能截图

> 截图位于 `docs/screenshots/`。

**仪表盘**：会话/任务概览、图表与实时状态。

<img src="docs/screenshots/dashboard.png" width="100%" alt="仪表盘">

**会话管理**：多平台会话、任务下发与状态跟踪。

<img src="docs/screenshots/sessions.png" width="100%" alt="会话管理">

**AI 副驾驶**：联网分析、工具调用与权限审批。

<img src="docs/screenshots/copilot.png" width="100%" alt="AI 副驾驶">

**文件管理**：上传 / 下载 / 在线预览，断点续传。

<img src="docs/screenshots/files.png" width="100%" alt="文件管理">

**内存执行**：免落地加载 DLL / EXE / BOF 与内存操作。

<img src="docs/screenshots/memexec.png" width="100%" alt="内存执行">

**杀软识别**：检测目标环境杀软 / 安全监控进程，辅助规避。

<img src="docs/screenshots/avidentify.png" width="100%" alt="杀软识别">

## 使用前准备

### 环境依赖

下面按**用途**列出需要安装的工具。只有对应功能用到时才需要，基础运行只装 **Go** 即可。

| 用途 | 依赖 | 说明 |
|---|---|---|
| **构建 / 运行服务端** | [Go](https://go.dev/dl/) **≥ 1.25**（go.mod 为 `go 1.25.0`） | 必需。服务端 + 植入端都用它编译。 |
| **源码构建时嵌入 Web 界面** | [Node.js](https://nodejs.org/) **≥ 20** + npm | 仅当从源码构建并带前端时用 `-tags webui`。发行版自带前端，可跳过。 |
| **构建 C 植入端（体积极小）** | [mingw-w64](https://www.msys2.org/) gcc（`x86_64-w64-mingw32-gcc`） | 仅生成 C 植入端时需要。普通 Go 植入端不依赖。 |
| **字符串混淆（可选）** | [garble](https://github.com/burrowers/garble) | 可选。未装则候选载荷自动禁用混淆。 |
| **UPX 压缩（可选）** | UPX | 发行版 `upx/` 目录已内置，自动探测。未装则候选载荷不启用压缩。 |

> **Go 工具链**：服务端用当前 Go 版本编译；植入端模板锁定 go1.20 工具链，构建时自动下载对应版本，无需手动安装。

### 安装步骤

**Windows**
```bash
# 1) 安装 Go（下载安装包或 winget）
winget install GoLang.Go

# 2) （可选，C 植入端）安装 MSYS2，并在其中安装 mingw-w64 工具链
#    MSYS2 安装后执行: pacman -S mingw-w64-x86_64-gcc

# 3) （可选，字符串混淆）
go install mvdan.cc/garble@latest
```

**Linux / macOS**
```bash
# Debian/Ubuntu / macOS (Homebrew)
sudo apt install -y golang-go                    # Linux
# brew install go                                 # macOS

# （可选，C 植入端）mingw-w64
sudo apt install -y gcc-mingw-w64-x86-64         # Linux
# brew install mingw-w64                          # macOS

# （可选，字符串混淆）
go install mvdan.cc/garble@latest
```

> 确认安装成功：`go version` 应输出 ≥ 1.25；`go env GOPROXY` 可设国内镜像加速依赖下载（如 `https://goproxy.cn,direct`）。

## 快速开始

### 一键部署（推荐）

```bash
cd release && chmod +x deploy.sh && ./deploy.sh   # Linux / macOS
# Windows: 在 release 目录双击 deploy.bat
```

> 首次运行会基于 `server.yaml.example` 自动生成配置，请先修改敏感项。完整部署说明见 [USAGE.md](USAGE.md)。

### 默认启动方式

服务端是一个**单一可执行文件**，无需安装任何服务，直接运行即可：

```bash
# Linux / macOS
./toserver -config configs/server.yaml

# Windows
toserver.exe -config configs\server.yaml
```

启动后浏览器打开 **http://<服务器IP>:18081**（`server.api_port`，默认 18081）进入 Web 控制台。

> 首次启动会自动创建 SQLite 数据库 `./data/toshell.db`；未指定 `-config` 时默认加载 `./configs/server.yaml`。

### 从源码构建

```bash
# 在项目根目录，构建服务端（嵌入已构建的 Web 前端需先 npm run build）
go build -tags webui -ldflags "-s -w" -o toserver ./cmd/server
```

> 仅构建后端、不带前端（纯 API/无 Web 控制台）可去掉 `-tags webui`。

## 生成植入端

登录 Web 控制台 →「生成载荷」→ 选平台 / 通道 / 免杀配置 → 构建 → 目标机运行即回连。

> 生成载荷时可用「启动随机延迟」等默认参数（在「设置 → 植入端」配置，构建时取全局默认）。

## 配置

复制 `configs/server.yaml.example` → 修改 `public_host / api_keys / jwt_key / encryption_key / admin_password`；更多字段说明见 [USAGE.md](USAGE.md)。设置页可热更新多数配置（无需重启）。

## 开源与授权

- 使用说明：[USAGE.md](USAGE.md)
- 安全披露：[SECURITY.md](SECURITY.md)
- License：[MIT](LICENSE)
- **免责声明**：仅用于授权测试与学习研究，禁止任何未授权的入侵、攻击或数据窃取行为；使用者后果自负。

---

**© 2026 ToShell (Tanovo) · MIT License** · 仅供授权测试与学习
