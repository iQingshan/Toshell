# ToShell Team Server — Release 包

> **版本 v1.2.1** · 自托管 C2（命令与控制）远程管理平台，仅用于**授权红队演练、渗透测试与安全研究**。请仅在获得授权的前提下使用。

完整项目说明、架构、REST API、植入体/载荷构建、C2 协议、插件与隧道系统见项目根 `README.md` 与 `USAGE.md`。

## 本目录内容

| 项 | 说明 |
|---|---|
| `toserver.exe` / `toserver` | 预编译服务端（单二进制，内嵌 Web 控制台） |
| `implant/` | 植入端编译模板（Go，含免杀随机化源码） |
| `implant_c/` | C 植入端模板（mingw） |
| `configs/server.yaml.example` | 开源占位配置模板（复制为 `server.yaml` 后修改） |
| `deploy.sh` / `deploy.bat` | **一键安装启动脚本** |
| `README.md` / `USAGE.md` | 本说明 |
| `upx/ drivers/ plugins/ data/` | 运行时依赖/数据目录 |

## 一键部署

```bash
# Linux / macOS（在 release 目录）
chmod +x deploy.sh && ./deploy.sh

# Windows（在 release 目录）
deploy.bat
```

脚本会自动：从 `configs/server.yaml.example` 生成配置（首次）、后台/前台启动服务端、打印 Web 控制台地址。日志在 `server.log`（Windows 前台启动则显示在控制台窗口）。

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

## 免杀说明

植入端内置：编译期字符串混淆、**每构建随机化的配置块魔数/密钥、xd 字符串密钥基准、API 哈希种子/乘子**（打破跨样本同指纹）、apihash+PEB 动态解析、进程注入随机良性宿主、通信密钥内存清零、反沙箱/反调试、garble / `-s -w` / `-trimpath` / `-buildid=`。

> 免杀是持续对抗，无永久方案；请结合自身环境做多样本测试，并仅用于授权范围。更多细节见项目根 README「免杀与隐蔽特性」。

## 停止服务端

- Linux/macOS：`kill <PID>`（deploy.sh 启动时打印）或 `pkill -f toserver`
- Windows：关闭 `deploy.bat` 启动的“ToShell Server”控制台窗口

## 免责声明

仅用于**授权测试与学习研究**，严禁未经授权的入侵/攻击/数据窃取。因使用本工具产生的任何后果由使用者自行承担。详见项目根 README「免责声明」。
