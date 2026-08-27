# ToShell Team Server

> 自托管的 C2（命令与控制）远程管理平台，用于授权红队演练、渗透测试与安全研究。
> **请仅在获得授权的前提下使用本工具。**

**版本：v1.2.0** · **作者：青山 / Q1lintu / c0ffee（核心开发者）** · © 2026 ToShell (Tanovo)

---

## 目录

- [项目简介](#项目简介)
- [核心特性](#核心特性)
- [架构设计](#架构设计)
- [快速开始](#快速开始)
- [配置文件说明](#配置文件说明)
- [Web 控制台](#web-控制台)
- [命令行工具（CLI）](#命令行工具cli)
- [植入体（Implant）](#植入体implant)
- [载荷构建器](#载荷构建器)
- [C2 通信协议](#c2-通信协议)
- [数据库结构](#数据库结构)
- [REST API 接口](#rest-api-接口)
- [隧道系统](#隧道系统)
- [插件系统（BOF）](#插件系统bof)
- [免杀与隐蔽特性](#免杀与隐蔽特性)
- [目录结构](#目录结构)
- [技术栈](#技术栈)
- [安全提醒](#安全提醒)
- [免责声明](#免责声明)

---

## 项目简介

ToShell（Tanovo）是一个基于 Go 语言的自托管 C2 框架。它由 **Team Server**（服务端 + Web 控制台）、**Implant**（植入端）与 **CLI 工具** 三部分组成，覆盖从载荷生成、会话管理到任务执行的完整攻击链路：

- **Team Server**：提供 REST API、Web 管理界面、TCP/HTTP C2 监听器、载荷构建器，单二进制文件即可运行全部服务。
- **Web 控制台**：基于 React + TypeScript 的现代化管理界面，内置会话管理、文件管理、载荷生成、BOF 插件、登录审计等功能。
- **Implant**：运行于目标主机的客户端，通过加密 TCP 通道回连服务端执行任务，支持 Windows / Linux / macOS。
- **CLI**：命令行交互工具，可在无浏览器环境下完成登录、会话管理、监听器管理等操作。

项目内置多种隐蔽与免杀特性：编译期字符串混淆、配置块 XOR 加密、**每构建随机化的配置块魔数/密钥与 API 哈希种子**（打破跨样本同指纹）、API 哈希免杀解析（apihash + PEB）、反沙箱/反调试检测、流量抖动（jitter）、进程注入随机良性宿主、KillDate 自毁、WorkingHours 工作时段等。

v1.2.0 新增 **AI 副驾驶**（LLM ReAct 助手 + 30+ 工具，自动注入会话上下文、支持权限审批）、**任务流/剧本化执行**、**多通道监听（TCP/HTTP/WebSocket/MQTT）**、**SOCKS5 隧道代理** 与 **免杀随机化加固**。详细使用请见 [USAGE.md](USAGE.md)。

---

## 核心特性

### 通信与安全
- **AES-256-GCM 加密**：C2 流量使用 AES-GCM 认证加密，密钥由服务端统一生成并写入植入体。
- **流量隐蔽**：心跳间隔随机抖动（jitter），破坏固定节奏流量指纹；动态运行时生成协议魔数，避免明文特征字节落盘。
- **隧道混淆**：内置隧道帧封装，控制通道与数据通道分离，降低流量可识别性。
- **JWT 认证**：Web 后台与 API 使用 JWT Token（24h 过期）+ 可选 API Key 双重鉴权。
- **管理员密码 bcrypt 哈希**：默认密码 `toshell`，部署后必须修改；支持首次启动自动生成随机密码并打印到控制台。

### 隐蔽与免杀
- **编译期字符串混淆**：编译前自动扫描植入端源码，将回连地址、API 函数名、配置标识、安全软件特征等敏感字符串加密为运行时解码调用。
- **配置块 XOR 加密**：回连地址与加密密钥以 XOR 加密块附加在二进制尾部，通过加密标识常量定位，无明文 magic 与明文 URL。
- **apihash 免杀解析**：通过 PEB 模块链表 + 导出表 FNV-1a 哈希手工解析 API 地址，不依赖 `GetProcAddress`，二进制不留 API 名明文。
- **反沙箱 / 反调试**：启动时检测调试器与常见沙箱/分析环境进程（VMware、VirtualBox、Sandboxie、Wireshark 等），资源不足时延迟执行。
- **免杀工具链**：可选集成 garble（Go 源码混淆）与 UPX（体积压缩）。
- **老系统兼容**：生成 Windows 载荷时自动切换 Go 1.20.14 工具链编译，兼容 Windows 7 / Server 2008 R2 等老系统。

### 功能能力
- 多平台、多架构、多格式载荷生成（exe / dll / raw / shellcode / bin / so）
- 会话管理（列表 / 详情 / 备注 / 心跳状态 / 失联判定）
- 交互式 Shell（WebSocket 实时终端）
- 文件管理（目录浏览 / 上传 / 下载 / 删除 / 重命名 / 预览，支持大文件分片）
- 进程管理（列表 / 结束 / 注入 / 伪装 / 自动注入 / 派生 spawn）
- 截图（PNG 快速编码，超大图自动转 JPEG）
- BOF 插件（上传 / 加载 / 管理，DLL 句柄缓存加速）
- 持久化与凭据收集（Windows）
- 系统信息收集（sysinfo / netstat / AV 检测）
- SOCKS5 / 隧道转发（TCP 隧道 + 优化隧道）
- 登录日志审计（成功 / 失败）
- 数据库一键清理脚本与发布版重置流程

### 回连通道与网络隐蔽（v1.1.0 新增）
- **双回连通道**：TCP（自定义加密帧协议，载荷约 3.4MB，全功能）与 HTTP(S) 轮询通道；构建页按监听器类型自动匹配通道与地址格式，杜绝协议误选。
- **域前置（Domain Fronting）**：HTTPS 轮询通道支持自定义 TLS SNI 与 HTTP Host 拟态域名（`front_domain`），服务器部署在 CDN/反向代理后，目标机出站流量表现为访问合法域名，可过域名白名单出口。
- **transport 条件编译**：TCP 载荷不链接 net/http/crypto/tls，体积从约 6MB 降至 3.4MB（约减半），同时减少标准库指纹，利于免杀。
- **Beacon Mesh 中继**：在线会话可一键升级为中继节点（runtime relay），叶子植入端链式回连，支持多跳；中继链路 SM4-GCM 加密，构建页可从在线中继列表直接选取回连地址。
- **实时屏幕流**：低频帧率实时屏幕直播，前端支持缩放与全屏。
- **内核级对抗（Windows）**：EDR 失明（ntdll 脱钩 + ETW 抑制 + Autologger 禁用）、EDR 击杀、BYOVD 驱动加载（内置原厂签名 RTCore64.sys，SHA-256 已核对）、PPL 保护清除（RTCore64 内核虚拟地址读写，EPROCESS 偏移按 Windows 版本自适应）。
- **运行时设置热更新**：设置页真实读写配置，webhook / 流量拟态模板 / 认证 / 植入默认参数保存即热生效；配置文件被外部修改自动重载（viper WatchConfig）。
- **钉钉等 webhook 通知**：自动识别钉钉机器人（markdown 格式，支持加签），并支持企业微信/飞书/Slack/通用 JSON；设置页一键"发送测试通知"验证。

---

## 架构设计

```
┌─────────────────────────────────────────────────────────────┐
│                        Team Server                          │
│  ┌─────────────┐  ┌──────────────┐  ┌────────────────────┐  │
│  │  Web 控制台  │  │  REST API    │  │  TCP C2 监听器     │  │
│  │  (React)     │→│  (JWT 认证)   │  │  (AES-GCM 加密)    │  │
│  └─────────────┘  └──────┬───────┘  └─────────┬──────────┘  │
│                          │                     │            │
│                    ┌─────▼─────┐         ┌─────▼─────┐      │
│                    │  Builder   │         │  Session  │      │
│                    │ (载荷生成)  │         │  管理      │      │
│                    └─────┬─────┘         └─────┬─────┘      │
│                    ┌─────▼─────┐               │            │
│                    │ SQLite /  │◄──────────────┘            │
│                    │ PostgreSQL│                            │
│                    └───────────┘                            │
└───────────────────────────────────┬─────────────────────────┘
                                    │ AES-256-GCM 加密 TCP 长连接
                                    ▼
                     ┌──────────────────────────┐
                     │       Implant 植入端      │
                     │  Windows / Linux / macOS │
                     └──────────────────────────┘
```

### 三大组件

| 组件 | 入口 | 说明 |
|---|---|---|
| **Team Server** | `cmd/server` | Web 控制台 + REST API + C2 监听器 + 载荷构建器 |
| **Implant** | `cmd/implant` / `release/implant` | 目标主机上的客户端程序 |
| **CLI** | `cmd/cli` | 命令行交互管理工具 |

### 通信链路
- **植入端 → 监听器**：TCP 长连接，TSHL 自定义协议帧，AES-256-GCM 加密 + gzip 压缩，心跳保活 + 指数退避重连。
- **Web 控制台 → 服务端**：REST API（JWT 认证），交互终端走 WebSocket 实时通道。

---

## 快速开始

### 环境要求
- Go 1.22+（编译环境）
- Node.js 18+（构建前端，可选）
- Windows / Linux / macOS（运行环境，Windows 为第一优先支持）

### 方式一：直接使用发布版（一键启动）

`release/` 目录包含**预编译服务端 + 一键启动脚本 + 完好说明文档**：

```bash
# Linux / macOS
cd release && chmod +x deploy.sh && ./deploy.sh

# Windows（在 release 目录）
deploy.bat
```

脚本首次运行会从 `configs/server.yaml.example` 自动生成配置（并提示你修改敏感项），然后在后台启动服务端，日志写入 `server.log`，最后打印 Web 控制台地址。

也可手动启动：

```bash
cd release
./toserver.exe                     # Windows
./toserver                          # Linux/macOS
# 首次启动会在控制台打印自动生成的管理员密码（若配置为空）
# 浏览器访问 http://<服务器IP>:18081
# 默认账号密码: admin / toshell （强烈建议立即修改）
```

### 方式二：从源码构建

```bash
# 1. 构建前端（可选，若使用预构建的 webdist 可跳过）
cd web
npm install
npm run build
cd ..

# 2. 将前端产物复制到嵌入目录
# （web/dist → cmd/server/webdist）

# 3. 编译服务端（-tags webui 启用内嵌前端）
go build -tags webui -trimpath -ldflags "-s -w" -o release/toserver.exe ./cmd/server

# 4. 运行
./release/toserver.exe
```

### 方式三：命令行工具

```bash
# 编译 CLI
go build -o toshell-cli ./cmd/cli

# 使用
./toshell-cli
# 交互式命令: login / sessions / interact / listeners / create-listener / tasks / logs
```

### 首次启动流程

1. 读取 `configs/server.yaml` 配置（可通过 `--config` 参数指定路径）。
2. 若配置中 `admin_password` / `jwt_key` / `listener.encryption_key` 为空，自动生成并写回配置文件，同时打印到控制台。
3. 初始化数据库（SQLite 默认 `./data/toshell.db`，支持 PostgreSQL）。
4. 启动 C2 监听器（TCP，默认 `0.0.0.0:8080`）与 Web 服务（默认 `0.0.0.0:18081`）。
5. 定时清理失联会话与过期任务数据。

---

## 配置文件说明

配置文件：`configs/server.yaml`（可通过 `--config` 指定）。

### 认证鉴权（`auth`）

| 配置项 | 默认值 | 说明 |
|---|---|---|
| `admin_username` | `admin` | 管理员用户名 |
| `admin_password` | bcrypt(`toshell`) | 管理员密码哈希；留空则首次启动自动生成 |
| `enabled` | `true` | 是否启用登录鉴权 |
| `jwt_enabled` | `true` | 是否启用 JWT Token 鉴权 |
| `jwt_expire` | `24` | JWT 有效期（小时） |
| `jwt_key` | 固定值 | **必须修改**，建议 32 字节 base64 随机值；留空自动生成 |
| `api_key_enabled` | `true` | 是否启用 API Key 鉴权（`X-API-Key` 请求头） |
| `api_keys` | `change-me`（示例） | **必须修改**，API Key 列表（逗号分隔） |

### 数据库（`database`）

| 配置项 | 默认值 | 说明 |
|---|---|---|
| `type` | `sqlite` | `sqlite`（默认，单文件）/ `postgres` |
| `path` | `./data/toshell.db` | SQLite 文件路径 |
| `host` / `port` / `username` / `password` / `database` / `ssl_mode` | 空 | PostgreSQL 连接参数 |

### 植入体默认行为（`implant`）

| 配置项 | 默认值 | 说明 |
|---|---|---|
| `interval` | `5` | 回连间隔（秒） |
| `jitter` | `2` | 回连抖动（秒），随机波动规避流量特征 |
| `kill_date` | 空 | 到期自毁时间（`YYYY-MM-DD`），留空不过期 |
| `working_hours` | 空 | 仅在该时间段内工作（`HH:mm-HH:mm`），留空全天 |
| `retry_count` | `3` | 回连失败重试次数 |
| `retry_wait` | `5` | 重试等待时间（秒） |
| `output_dir` | `./implants` | 植入体输出目录 |

### 监听器（`listener`）

| 配置项 | 默认值 | 说明 |
|---|---|---|
| `enabled` | `true` | 是否启用监听器 |
| `host` | `0.0.0.0` | 监听地址 |
| `port` | `8080` | **建议修改**，C2 监听端口 |
| `protocol` | `tcp` | 通信协议：`tcp` / `websocket` |
| `public_host` | `192.168.1.28` | **必须修改**，服务器公网 IP/域名，植入体回连地址 |
| `encryption_key` | 固定值 | **必须修改**，AES-256 加密密钥（16/24/32 字节），修改后需重新生成植入体 |
| `heartbeat_timeout` | `60s` | 心跳超时，判定会话失联 |
| `tls_enabled` / `cert_file` / `key_file` | 空 | TLS 加密 |
| `write_queue_size` | `8192` | 发送队列大小 |

### 服务（`server`）

| 配置项 | 默认值 | 说明 |
|---|---|---|
| `api_host` / `api_port` | `0.0.0.0:18081` | Web 后台 / API 监听地址（**建议修改端口**） |
| `port` | `8080` | 与 `listener.port` 保持一致 |
| `max_connections` | `1000` | 最大并发连接数 |
| `read_timeout` / `write_timeout` / `idle_timeout` | 30s/30s/120s | HTTP 超时 |
| `tls_cert` / `tls_key` | 空 | HTTPS 证书 |

### 日志（`logging`）

| 配置项 | 默认值 | 说明 |
|---|---|---|
| `level` | `info` | `debug` / `info` / `warn` / `error` |
| `format` | `json` | `json` / `text` |
| `output` | `stdout` | `stdout` 或文件路径 |
| `max_size` | `100` | 单文件最大大小（MB） |
| `max_backups` | `10` | 保留备份数 |
| `max_age` | `30` | 保留天数 |
| `compress` | `true` | 是否压缩历史日志 |

---

## Web 控制台

浏览器访问 `http://<服务器IP>:18081`（默认）。

### 页面清单

| 路由 | 页面 | 功能 |
|---|---|---|
| `/` | 仪表盘 Dashboard | 会话统计、系统信息、版本信息 |
| `/sessions` | 会话管理 Sessions | 会话列表、信息查看、备注、心跳状态 |
| `/sessions/:id` | 会话详情 | 系统信息、进程列表、进程注入 |
| `/shell/:sessionId` | 交互 Shell | 全屏 WebSocket 实时终端 |
| `/builds` | 载荷构建 Builds | 多平台载荷生成（exe / dll / raw / shellcode） |
| `/listeners` | 监听器 Listeners | C2 监听器管理与创建 |
| `/templates` | 植入体模板 Templates | 自定义模板管理 |
| `/plugins` | 插件管理 Plugins | BOF 插件上传、加载、管理 |
| `/tunnels` | 隧道管理 Tunnels | TCP / 优化隧道 |
| `/terminal` | 终端 Terminal | 通用终端 |
| `/logs` | 日志审计 Logs | 登录成功/失败审计、任务日志 |
| `/settings` | 设置 Settings | 系统配置 |
| `/about` | 关于 About | 项目说明、作者、特性、安全提醒 |

### 前端技术
React 18 + TypeScript + Vite + React Router + Zustand（状态管理）+ WebSocket。

---

## 命令行工具（CLI）

```bash
go build -o toshell-cli ./cmd/cli
./toshell-cli
```

### 支持的命令

| 命令 | 说明 |
|---|---|
| `login` | 登录服务端 |
| `sessions` | 列出会话 |
| `interact <id>` | 进入会话交互模式 |
| `listeners` | 列出监听器 |
| `create-listener` | 创建监听器 |
| `tasks` | 查看任务 |
| `logs` | 查看日志 |
| `help` | 帮助 |
| `exit` | 退出 |

---

## 植入体（Implant）

### 支持平台与格式

| 目标系统 | 架构 | 生成格式 |
|---|---|---|
| Windows | amd64 / 386 / arm64 | exe / dll / bin / raw / shellcode |
| Linux | amd64 / 386 / arm64 | elf / raw / shellcode |
| macOS | amd64 / arm64 | macho / raw / shellcode |

### 支持的远程任务

| 任务类型 | 说明 |
|---|---|
| `command` | 执行任意命令 |
| `shell` | 交互式 Shell（GBK→UTF-8 转换） |
| `file_list` / `file_download` / `file_upload` / `file_delete` | 文件管理 |
| `process_list` / `process_kill` | 进程管理 |
| `process_inject` | 进程注入（远程线程 / APC / 线程劫持 / DLL 注入） |
| `process_spoof` | 进程伪装（Process Hollowing / Early Bird） |
| `auto_inject` | 自动注入 |
| `injection` | 通用注入 |
| `spawn` | 派生新植入体进程 |
| `persistence` | 持久化（注册表 / 启动项 / WMI 等） |
| `credentials` | 凭据收集（浏览器 / 系统凭据） |
| `screenshot` | 屏幕截图（PNG / JPEG 自适应） |
| `sysinfo` | 系统信息收集 |
| `netstat` | 网络连接 |
| `av_detect` | 安全软件检测（80+ 特征） |
| `bof_load` / `plugin_exe` / `plugin_dll` / `plugin_shellcode` | 插件加载 |
| `tunnel` | 隧道数据处理 |
| `exit` | 退出植入体 |

### 通信行为
- **心跳 + 抖动**：心跳间隔在 base ± jitter% 范围内随机，打破固定节奏流量指纹。
- **指数退避重连**：连续失败时等待时间按 2^n 增长，受 `RETRY_WAIT` 与上限约束。
- **半开连接检测**：读侧按"总空闲时长"判死，活跃期短超时快速感知断连，空闲期拉长超时降低 syscall。
- **任务串行 worker**：任务入队后由独立 worker 顺序执行，长任务不阻塞读循环与心跳。
- **连接世代标记**：重连后旧连接 worker 丢弃过期任务结果，避免串话。
- **KillDate**：到达日期后进程自杀退出。
- **WorkingHours**：仅在工作时段回连与执行任务，其余时间静默休眠。

---

## 载荷构建器

构建器位于 `internal/server/builder`，通过 Web 控制台 `/builds` 或 REST API 调用。

### 构建流程
1. **模板选择**：按优先级解析植入体模板目录（配置项 → 环境变量 → `exeDir/implant` → 工作目录）。
2. **占位符替换**：替换 `{{SERVER_URL}}`、`{{INTERVAL}}` 等占位符。
3. **编译期字符串混淆**（可选）：加密敏感字符串为 `xd("hex")` 运行时解码。
4. **交叉编译**：按目标平台/架构选择 Go 工具链（老系统自动切 Go 1.20.14）。
5. **追加配置块**：将回连地址与加密密钥以 XOR 加密块附加到二进制尾部。
6. **压缩**（可选）：UPX 压缩，输出最终载荷。

### 支持的选项
- **平台/架构**：Windows / Linux / macOS × amd64 / 386 / arm64
- **格式**：exe / dll / bin / raw / shellcode
- **免杀工具链**：garble（源码混淆）、UPX（体积压缩）、go-donut（shellcode 生成）
- **生成方式**：`internal/server/builder/implant`（LazyDLL 版）与 `release/implant`（apihash 免杀版）两套模板

---

## C2 通信协议

正式版植入端使用自定义二进制协议（`release/implant/main.go`）。

### 帧结构
- **Magic（4B）**：运行时解码生成（`xd("0e2ee88f")`），避免明文特征字节落盘。
- **Version（1B）**：协议版本 `0x01`。
- **HeaderSize**：30 字节固定头。
- **Payload**：AES-256-GCM 加密 + gzip 压缩。

### 消息类型
| 类型 | 说明 |
|---|---|
| `TypeRegister` (0x00) | 植入体注册 |
| `TypeHeartbeat` (0x01) | 心跳保活 |
| `TypeTask` (0x02) | 任务下发 |
| `TypeResult` | 任务结果回传 |
| `TypeShell` | Shell 数据 |

### 安全特性
- AES-256-GCM 认证加密（复用 AEAD 实例，避免每帧重建 cipher）。
- 帧级 gzip 压缩降低流量体积。
- 协议魔数运行时生成，二进制中无明文 `TSHL` 连续字节。

---

## 数据库结构

默认 SQLite（`./data/toshell.db`），支持 PostgreSQL。

### 数据表

| 表名 | 说明 | 关键字段 |
|---|---|---|
| `sessions` | 会话表 | id、session_id、hostname、ip、os、arch、user、status、last_seen 等 |
| `tasks` | 任务表 | id、session_id、type、command、args、status、result、created_at |
| `listeners` | 监听器表 | id、name、type、host、port、protocol、status |
| `logs` | 日志表 | id、level、message、source、created_at |
| `custom_templates` | 自定义模板表 | id、name、platform、content、created_at |
| `implants` | 植入体记录表 | id、name、platform、arch、format、hash、created_at |

> 具体表结构以 `internal/server/database/database.go` 中的 schema 为准。

### 清理与备份
- `scripts/reset_release_db.py`：发布版数据库一键清理（清空 tasks/sessions/logs，备份原库到 `data/backup/`）。
- 定时任务自动清理失联会话与过期数据。

---

## REST API 接口

所有 API 均需 `Authorization: Bearer <JWT>` 或 `X-API-Key` 请求头（视配置）。

### 认证
| 方法 | 路径 | 说明 |
|---|---|---|
| POST | `/api/login` | 登录获取 JWT |
| GET | `/api/logs` | 登录日志审计 |

### 会话
| 方法 | 路径 | 说明 |
|---|---|---|
| GET | `/api/sessions` | 会话列表 |
| GET | `/api/sessions/{id}` | 会话详情 |
| DELETE | `/api/sessions/{id}` | 删除会话 |
| POST | `/api/sessions/{id}/tasks` | 下发任务 |
| POST | `/api/sessions/{id}/inject` | 进程注入 |
| POST | `/api/sessions/{id}/persistence` | 持久化 |
| POST | `/api/sessions/{id}/credentials` | 凭据收集 |
| POST | `/api/sessions/{id}/screenshot` | 截图 |

### 文件
| 方法 | 路径 | 说明 |
|---|---|---|
| POST | `/api/sessions/{id}/files/upload` | 文件上传 |
| GET | `/api/sessions/{id}/files/download` | 文件下载 |
| GET | `/api/sessions/{id}/files` | 文件列表 |

### 监听器
| 方法 | 路径 | 说明 |
|---|---|---|
| GET | `/api/listeners` | 监听器列表 |
| POST | `/api/listeners` | 创建监听器 |
| PUT | `/api/listeners/{id}` | 更新监听器 |
| DELETE | `/api/listeners/{id}` | 删除监听器 |

### 构建
| 方法 | 路径 | 说明 |
|---|---|---|
| GET | `/api/builds` | 构建列表 |
| POST | `/api/builds` | 创建构建任务 |
| GET | `/api/builds/{id}/download` | 下载载荷 |
| GET | `/api/templates` | 模板列表 |
| POST | `/api/templates` | 创建模板 |

### 插件与隧道
| 方法 | 路径 | 说明 |
|---|---|---|
| GET | `/api/plugins` | 插件列表 |
| POST | `/api/plugins/upload` | 上传插件 |
| POST | `/api/plugins/{id}/load` | 加载插件 |
| GET | `/api/tunnels` | 隧道列表 |
| POST | `/api/tunnels` | 创建隧道 |
| DELETE | `/api/tunnels/{id}` | 删除隧道 |

> 完整端点清单以 `internal/server/api/api.go` 为准。

---

## 隧道系统

隧道系统位于 `internal/common/tunnel`，支持通过会话建立多级转发通道：

- **TCP 隧道**：基于会话的 TCP 端口转发。
- **优化隧道**：批量帧写出（降低锁竞争与系统调用）、连接复用。
- **隧道协议**：独立的帧格式与压缩/加密封装，控制通道与数据通道分离。

Web 控制台 `/tunnels` 页面提供隧道管理与监控。

---

## 插件系统（BOF）

插件系统位于 `internal/server/plugin`，支持四类插件：

| 类型 | 说明 |
|---|---|
| EXE | 独立可执行文件插件 |
| DLL | 动态链接库插件 |
| Shellcode | 内存加载 shellcode |
| **BOF** | Beacon Object File（Cobalt Strike 格式，无需落盘） |

### 特性
- 上传 / 加载 / 管理完整流程。
- DLL 句柄缓存加速重复加载。
- BOF 参数通过 `Command` 字段传递，兼容旧版 `Args` 数组。

Web 控制台 `/plugins` 页面提供插件管理。

---

## 免杀与隐蔽特性

### 编译期字符串混淆（`obfuscate.go`）
编译前自动扫描植入端源码，将敏感字符串（回连地址、API 函数名、配置标识、安全软件特征）加密为 `xd("hex")` 运行时解码，二进制中不留明文。

### 配置块加密
回连地址与加密密钥以 XOR 加密块附加在二进制尾部，通过加密标识常量定位，无明文 magic 与明文 URL。

### apiHash 免杀解析（`apihash_windows.go` / `peb_windows.go`）
- 遍历 PEB `InMemoryOrderModuleList` 查找模块基址。
- 模块加载失败时先 `LoadDLL` 主动加载，再走 PEB 免杀主路径解析。
- 通过导出表 FNV-1a 哈希匹配 API，不依赖 `GetProcAddress`，二进制不留 API 名明文。
- **每构建随机** FNV-1a 种子/乘子 → 同一 API 名在不同样本中的哈希值不同。

### 每构建随机化（打破跨样本同指纹）
- 配置块魔数 + XOR 密钥随机（服务端 / Go / C 植入端三端一致）。
- `xd` 字符串密钥基准随机 → 同一明文字符串在不同样本中的密文不同。
- apihash FNV 种子/乘子随机。
- 进程注入自动随机挑选良性宿主（explorer / svchost / dllhost / Teams…）。
- 通信密钥派生后原始密钥缓冲清零并释放（缩短 AES/SM4 主密钥内存驻留）。

### 反沙箱 / 反调试（`evasion_windows.go`）
- 检测调试器与常见沙箱/分析环境进程。
- 资源不足时延迟执行。

### 其他
- **garble**：Go 源码级混淆，变量/函数名随机化。
- **UPX**：可执行文件压缩（可选；注意 UPX 本身可能被部分杀软标记，可关闭）。
- **Go 1.20 工具链**：老系统兼容编译。

> 免杀是持续性对抗，以上为多种静态 / 内存 / 行为特征的综合缓解；请结合自身环境做多样本测试，并仅用于授权范围。

---

## 目录结构

```
toshell/
├── cmd/
│   ├── server/            # Team Server 主程序（含 go:embed 前端）
│   ├── implant/           # 植入端入口（Windows / Linux / macOS）
│   ├── cli/               # 命令行工具
│   └── socks5proxy/       # SOCKS5 代理
├── internal/
│   ├── common/
│   │   ├── protocol/      # C2 协议定义（帧/任务类型）
│   │   ├── types/         # 公共类型定义
│   │   └── tunnel/        # 隧道系统（协议/管理器/植入端）
│   ├── implant/           # 植入端核心（internal 版，LazyDLL）
│   │   ├── crypto/        # 加密实现
│   │   ├── injection/     # 进程注入
│   │   ├── sysinfo/       # 系统信息
│   │   └── transport/     # 通信传输
│   ├── operator/          # 操作员命令
│   └── server/
│       ├── api/           # REST API 处理器
│       ├── auth/          # JWT 认证
│       ├── builder/       # 载荷构建器（含 implant 模板）
│       ├── config/        # 配置加载
│       ├── c2/            # C2 核心
│       ├── database/      # 数据库（SQLite/PostgreSQL）
│       ├── listener/      # 监听器（TCP/HTTP）
│       ├── plugin/        # BOF 插件系统
│       ├── session/       # 会话管理
│       └── task/          # 任务调度
├── pkg/
│   ├── bypass/            # 反沙箱/反调试
│   ├── obfuscation/       # 字符串混淆（汇编实现）
│   ├── pe/                # PE 解析（汇编实现）
│   ├── rate/              # 限速
│   ├── shellcode/         # shellcode 转换
│   └── goroutine/         # goroutine 池
├── plugins/               # 插件目录
├── configs/
│   └── server.yaml        # 服务端配置文件
├── web/                   # 前端源码（React + TypeScript + Vite）
├── scripts/               # 运维脚本（数据库清理等）
├── release/               # 发布版（toserver.exe + implant 模板 + 说明文档）
├── data/                  # 运行数据（数据库等）
├── implants/              # 生成的植入体输出目录
├── USAGE.md               # 使用说明
└── README.md              # 本文件
```

---

## 技术栈

| 类别 | 技术 |
|---|---|
| 后端 | Go 1.22+、Gin（HTTP）、viper（配置）、SQLite / PostgreSQL |
| 前端 | React 18、TypeScript、Vite、React Router、Zustand、WebSocket |
| 通信 | TCP / WebSocket、AES-256-GCM、gzip |
| 免杀 | garble、UPX、apihash、PEB 解析、字符串混淆 |
| 工具链 | Go 1.20.14（老系统兼容）、go-donut（shellcode） |

---

## 安全提醒

1. **默认凭据**：默认账号 `admin / toshell`，默认 API Key 与加密/JWT 密钥均为**占位值**（见 `configs/server.yaml.example`）——**部署后必须立即更换**。
2. **回连地址**：`listener.public_host` 默认内网 IP，必须改为部署机公网 IP/域名。
3. **端口**：C2 监听端口（8080）与 Web 端口（18081）建议更换为不常见端口。
4. **修改密钥后需重新生成植入体**：更换 `listener.encryption_key` 后，已部署的旧植入体将无法回连，需重新生成并部署。
5. **授权使用**：本工具仅可用于授权范围内的红队演练、渗透测试与安全研究。
6. **免杀限制**：混淆不改变载荷功能，但极个别杀软仍可能因行为特征报毒，请结合 garble + UPX 使用。
7. **配置文件重写**：通过 Web 界面编辑监听器或自动生成密钥时，程序会调用 `viper.WriteConfig()` 重写配置文件，行内注释可能被移除，建议保留模板副本。

---

## 免责声明

ToShell 仅供**授权测试与学习研究**使用。使用者应遵守当地法律法规与授权范围，**禁止用于任何未经授权的入侵、攻击、破坏或数据窃取行为**。因使用本工具产生的任何后果由使用者自行承担。

> ⚠️ **授权红线（务必阅读）**：仅在你**拥有明确书面授权**的网络/主机、或你自己搭建的靶场/实验环境中使用。未经授权的 C2 控制、凭据窃取、横向移动等行为在多数司法辖区属违法行为。作者不对滥用负责。

---

## License

本项目以 [MIT 许可证](LICENSE) 开源。作者：青山 / Q1lintu / c0ffee（核心开发者）。

## 开源协作

- 使用说明见 [USAGE.md](USAGE.md)；安全披露见 [SECURITY.md](SECURITY.md)。
- 欢迎提交 Issue / PR 参与改进（修复、功能、文档）。请勿提交任何真实密钥、凭据或来自测试的数据。
- 提交前请确认 `.gitignore` 已忽略 `configs/server.yaml`、`release/configs/server.yaml`、`data/`、`*.db`、`*.exe` 等敏感/构建产物；开源配置请用 `configs/server.yaml.example`。
