# ToShell Team Server

> 自托管的 C2（命令与控制）远程管理平台，用于**授权红队演练、渗透测试与安全研究**。
> **仅限获得授权后使用。** 严禁未授权的入侵/攻击/数据窃取。

**v1.2.0** · [MIT License](LICENSE) · 作者：青山 / Q1lintu / c0ffee

---

## 这是什么

ToShell 是一个轻量 C2 框架，由 **服务端（Team Server）+ Web 控制台 + 多平台植入端** 组成，覆盖「生成载荷 → 会话管理 → 任务执行」的完整流程。

## 核心特性

- 多通道回连：**TCP / HTTP(S) / WebSocket / MQTT**
- 多平台植入端：**Windows / Linux / macOS**（exe / dll / raw / shellcode）
- 会话管理 + 交互 Shell + 文件/进程/截图/凭据 + **SOCKS5 隧道** + **插件(BOF/DLL/EXE)**
- **任务流/剧本化执行** + **AI 副驾驶**（联网搜索、远程下载工具、内存加载、结果复盘）+ **权限审批**
- 免杀：每构建随机化混淆 + apihash/PEB 动态解析 + 反沙箱/随机延迟（详见 [USAGE.md](USAGE.md)）
- 加密通信（AES-256-GCM / SM4-GCM）+ 配置热更新

## 快速开始

### 一键部署（推荐）

```bash
cd release && chmod +x deploy.sh && ./deploy.sh   # Linux / macOS
# Windows: 在 release 目录运行 deploy.bat
```

> 首次运行会基于 `server.yaml.example` 自动生成配置，请先修改敏感项。完整部署说明见 [USAGE.md](USAGE.md)。

### 手动

```bash
./toserver -config configs/server.yaml
# 浏览器打开 http://<服务器IP>:18081（api_port）
```

## 生成植入端

登录 Web 控制台 →「生成载荷」→ 选平台 / 通道 → 构建 → 目标机运行即回连。

## 功能截图

> 把截图放入 `docs/screenshots/` 并替换下方图片路径（此处留空，由作者补充）。

| 仪表盘 | 会话管理 |
|---|---|
| ![仪表盘](docs/screenshots/dashboard.png) | ![会话管理](docs/screenshots/sessions.png) |

| AI 副驾驶 | 载荷构建 |
|---|---|
| ![AI 副驾驶](docs/screenshots/copilot.png) | ![载荷构建](docs/screenshots/build.png) |

## 配置

复制 `configs/server.yaml.example` → 修改 `public_host / api_keys / jwt_key / encryption_key / admin_password`。字段说明见 [USAGE.md](USAGE.md)。

## 开源与授权

- 使用说明：[USAGE.md](USAGE.md)
- 安全披露：[SECURITY.md](SECURITY.md)
- License：[MIT](LICENSE)
- **免责声明**：仅用于授权测试与学习研究，禁止任何未授权的入侵、攻击或数据窃取行为；使用者后果自负。

---

**© 2026 ToShell (Tanovo) · MIT License** · 仅供授权测试与学习
