> **⚠️ 归档文档（历史 1.2 周期的 issue / 修复计划）**：本文是 issue #1 / #2 在 **v1.2 周期（排查时点为 v1.3.1）**的结论与修复方案存档，
> 仅作历史参考保留，**其中所有内容都不代表当前版本（v1.4.0）的状态**。
> 文中的「待实施」「设计」「建议」「验收」等表述均为当时的计划与推演，多数已在此后的版本落地或调整。
> 了解当前能力、已修复项与后续方向，请以 [CHANGELOG.md](../CHANGELOG.md) 与 [ROADMAP.md](../ROADMAP.md) 为准。

# Issue #1 / #2 修复方案（历史归档）

> 对应 https://github.com/iQingshan/Toshell/issues/1 与 /issues/2
> 本文记录**实测结论**（不是推测）：哪些复现、哪些不复现、真实根因在哪、怎么改、怎么验收。
> 结论先行：#2 的第二部分（macOS/Linux 载荷编译失败）**已在 `4470abf` 修复并验证**；#2 第一部分（配置写回丢字段）**在 v1.3.1 上无法复现**，但实测发现同一后果的另一条真实缺陷；#1（Web 基础认证防测绘）给出完整设计。

---

## 一、Issue #2 第一部分：修改配置后「密码被重置 / 被锁在门外」

### 1.1 issue 给出的机制（viper.WriteConfig 丢字段）—— 实测**不复现**

在 v1.3.1 上用**真实服务端**复现两条写回路径（隔离实例 + 独立端口，操作前后 diff 配置文件）：

| 路径 | 接口 | 结果 |
| --- | --- | --- |
| 设置页保存监听端口 | `PUT /api/v1/settings` `{"listener":{"port":28090}}` | 端口已改，`auth.admin_password` / `auth.api_keys` / `listener.heartbeat_timeout` / `ai.api_key` **全部保留** ✅ |
| 监听器页保存端口 | `PUT /api/v1/listeners/{id}` | 仅 `listener.port` 变化，其余字段全部保留 ✅ |

原因：当前 viper 版本的 `WriteConfig()` 写的是 `AllSettings()`，其中包含**从配置文件读取到的全部 key**，因此未声明的字段不会丢。同时 `handlers_settings.go` 对空值有守卫（`admin_password` 仅在非空时写入、`api_key` 跳过掩码值）。

> 附带加入回归测试 `internal/server/config/config_save_test.go`：断言 `Save()` 后 `auth.admin_password/api_keys/jwt_key/listener.heartbeat_timeout/ai.*` 等字段仍在，防止将来真的回归。

### 1.2 实测发现的**真实缺陷**：凭据生成后无法落盘 → 每次重启都换密码

复现（`-config` 指向不存在的路径 / 配置文件所在目录不可写 / 工作目录与配置文件不匹配）：

```
[SECURITY] First start - generated admin password: gLIxdpSpRiFQpJvM
[WARNING] Failed to write config file: open configs\server.yaml: The system cannot find the path specified.
[WARNING] Credentials are active for this session but will not persist after restart.
```

- 服务端**照常启动**，但配置目录里**没有生成任何配置文件**；
- 下次重启又走一次 "First start" → 生成**新的随机密码** → 用户永远进不去（就是 issue 描述的"被锁在门外"）；
- 而 `viper.WriteConfig()` **要求配置文件已存在**，不存在时不创建，只报错。

这是「改配置/重启后密码被重置」最可能的真实成因（尤其：换目录启动、用 `-config` 指向新路径、只靠环境变量配置的场景）。

### 1.3 次要但真实的缺陷

1. **非原子写入**：`viper.WriteConfig()` 是「截断 + 写入」，进程被杀/断电/杀软拦截写到一半 → 配置文件损坏或被截断 → 下次启动读到空 `admin_password` → 再次随机生成密码。
2. **注释与字段顺序被抹掉**：每次保存都会把用户手工维护的 `server.yaml`（含注释）重排为 viper 的字母序输出，注释全丢（数据没丢，但对运维是实际损失）。
3. **写回失败只记 WARNING**：不阻断启动，也不把生成的密码写到别处，事后无法找回。

### 1.4 当时提出的修复方案

**A. 写入改成「读-改-写 + 原子落盘」（核心）**

```
1) 解析并固定配置路径：-config 优先 > $TOSHELL_CONFIG > 可执行文件同目录 configs/server.yaml > 默认；启动日志打印绝对路径
2) 读原文件为 YAML 节点树（yaml.Node，保留注释/顺序/缩进）
3) 只修改目标 key（如 listener.port）
4) 写临时文件（同目录 .server.yaml.tmp）→ fsync → rename 覆盖（原子）
5) 重新 viper.ReadInConfig() 同步内存态（不再依赖 fsnotify 兜底）
```

- 保留注释/顺序用 `yaml.v3` 的 Node 树编辑（比"读成 map 再写回"更强：既不会丢字段，也不会丢注释）。
- 原子写用「临时文件 + `os.Rename`」，Windows 上用 `MoveFileEx` 语义（Go 的 `os.Rename` 在同分区覆盖已存在文件在 Windows 上会失败 → 需先 `Remove` 或用 `ReplaceFile`，实现里要处理）。

**B. 凭据必须落盘，否则不静默放行**

- 生成凭据后若写回失败：**升级为 ERROR 并终止启动**（打印明确指引），或退化为写入 `data/.bootstrap_credentials`（0600）并在日志给出该路径；
- 绝不能"生成了密码但既不落盘也不告诉用户"。

**C. 启动自检与可观测**

- 启动日志打印：`Using config file: <abs path>`、`Using database: <abs path>`；
- 若 `-config` 指定路径不存在：直接创建（含生成的凭据）或 fail-fast 报错，二选一并写进文档；
- 新增 `-print-config-path` 便于排查。

**D. 恢复能力**

- 配置文件里 `auth.admin_password` 为空时（用户手工清空以重置密码）→ 保持现有"生成 + 打印"，但必须落盘成功；
- 文档补充「忘记密码」的标准恢复步骤。

**E. 测试**

| 测试 | 断言 |
| --- | --- |
| `TestSaveKeepsUnrelatedFields`（已加） | Save 后敏感字段无丢失 |
| `TestSavePreservesCommentsAndOrder`（待加） | 保存后注释与字段顺序保留 |
| `TestAtomicWrite`（待加） | 写入过程中断不产生半截文件（可用临时文件存在性/内容校验模拟） |
| `TestCredentialsPersistWhenConfigMissing`（待加） | 配置缺失时凭据被创建到磁盘，重启后密码不变 |

---

## 二、Issue #2 第二部分：macOS / Linux 载荷编译失败 —— **已在 v1.3.2 周期修复并验证**

### 2.1 复现（真实构建接口，非推测）

```
POST /api/v1/builders  {os: linux, arch: amd64, profile: (full)}
→ 500 {"error":"failed to compile: build failed: exit status 1,
        output: # toshell-implant .\main.go:1618:30: undefined: stompShellcode"}
darwin/arm64 同样失败；windows/amd64 正常。
```

根因与 issue 判断一致：`stompShellcode` 只有两个实现——`stomp_windows.go`（`windows && !light`）与 `features_stub_light.go`（`light`），而 `main.go` 无条件调用它 → 非 Windows 的 **full** 档缺定义。

### 2.2 还发现了**同一类但 issue 未提及**的第二个缺口

修完 stomp 后继续编译 `-tags light` 的非 Windows 档，暴露：

```
features_unix.go:6: handlePersistence redeclared (features_stub_light.go:81)
injection_unix.go:5: handleProcessInject redeclared (features_stub_light.go:56)
...
```

根因：`features_unix.go` / `injection_unix.go` / `screen_stream_unix.go` 的构建标签只写了 `!windows`，未排除 `light`，与 `features_stub_light.go` 冲突 → **非 Windows 的 light 档构建也是坏的**。

### 2.3 修复（已提交 `4470abf`）

| 文件 | 变更 |
| --- | --- |
| `implant/stomp_unix.go`（新增，两处模板目录） | `//go:build !windows && !light`，返回 "module stomp is only supported on Windows" |
| `implant/features_unix.go` | 标签 `!windows` → `!windows && !light` |
| `implant/injection_unix.go` | 同上 |
| `implant/screen_stream_unix.go` | 同上 |

> 模板双目录（`internal/server/builder/implant` 与 `release/implant`）已 MD5 全量校验：50 个文件 100% 一致。

### 2.4 验收（实测 6/6 通过）

| 平台 | full | light |
| --- | --- | --- |
| windows/amd64 | ✅ 3535 KB | ✅ 2921 KB |
| linux/amd64 | ✅ 3224 KB | ✅ 3188 KB |
| darwin/arm64 | ✅ 3140 KB | ✅ 3107 KB |

### 2.5 防回归（建议）

新增构建矩阵冒烟脚本（`scripts/build_matrix.ps1` / CI job）：对 `{windows,linux,darwin} × {amd64,arm64} × {full,light} × {tcp,http,websocket,mqtt}` 跑一遍 `go build`，任一组合失败即报错。这类"Windows-only 实现 + 跨平台调用"的缺口只能靠编译矩阵兜住，`go vet`/单测都发现不了。

> （归档注：仓库最终落地的是 `scripts/e2e_smoke.ps1` 端到端冒烟，未见 `scripts/build_matrix.ps1` 提交；此处仅保留当时的建议。）

---

## 三、Issue #1：Web 界面基础认证防资产测绘（当时的草案）

### 3.1 需求

资产测绘引擎（Fofa/Quake/Hunter/ZoomEye 等）会扫描公网端口、抓取标题/指纹并收录，导致 IP 被标记污染。需要给 Web 控制台加一层**基础认证**作为前置门槛。

### 3.2 设计

**配置（`configs/server.yaml`）**

```yaml
web:
    basic_auth_enabled: false        # 默认关闭，避免升级即锁死
    basic_auth_user: "toshell"
    basic_auth_password: ""          # bcrypt 哈希；留空 = 不启用
    unauth_mode: "basic"             # basic: 返回 401 挑战；disguise: 直接 404（对测绘更隐蔽）
    decoy_title: ""                  # 可选：伪装的默认页标题
```

**中间件（`internal/server/auth`）**

- 在 `api.go` 的路由装配处，对「控制台 + 管理 API」整体加一层 Basic 认证：
  - 生效范围：`/`（SPA 静态资源与路由回退）、`/api/v1/*` 的**管理类**端点、`/api/v1/ws/events`；
  - **必须豁免**：`/api/v1/implant/*`（植入端注册/心跳/结果回传，走协议层加密与注册校验，不能被浏览器认证拦住）、`/api/v1/implant/payload/{id}` 与 `/api/v1/implant/uac/{token}`（"一条命令上线"/提权载荷的免认证一次性下载）；
  - C2 **监听器端口**（默认 8080）是独立 HTTP/TCP 服务，不受影响（植入端不受影响）。
- 认证失败响应：
  - `unauth_mode=basic`：`401` + `WWW-Authenticate: Basic realm="restricted"`（浏览器弹框，人可正常用）；
  - `unauth_mode=disguise`：直接 `404`（对外表现为"无此服务"，测绘抓到的是普通 404，不产生 C2 特征）；
- 凭据校验：`bcrypt.CompareHashAndPassword`；用户名为空或哈希非法时视为**未启用**并记录 ERROR。

**防测绘加固（与认证配套，低成本高收益）**

1. 去掉/统一响应头指纹：`Server`、`X-Powered-By` 等（Go 默认 `Server` 为空，但要确认反向代理层）；
2. `GET /robots.txt` → `Disallow: /`（对测绘引擎无约束力，但避免被搜索引擎收录）；
3. SPA `index.html` 的 `<title>` 与图标可配置（`web.decoy_title` / `web.favicon`），默认标题不要带 "C2" 等特征词；
4. 未认证时**不返回**任何前端资源（避免 `assets/index-*.js` 被指纹命中）；
5. 可选：仅允许白名单 IP 访问控制台（`web.allow_cidrs`），与认证叠加。

**设置页**

- 「安全设置」增加开关 + 用户名 + 新密码（bcrypt 存储，掩码回显）+ 「测试」按钮；
- 开启前强制校验凭据非空，避免自我锁死；
- 保存后提示"需要重新登录（浏览器会弹出认证框）"。

**验收**

| 用例 | 期望 |
| --- | --- |
| `curl -i http://host:18081/`（未带凭据，default 模式） | `401`，无前端内容 |
| 同上（disguise 模式） | `404`，响应体无 C2 特征 |
| 带正确 Basic 凭据访问 `/` 与 `/api/v1/sessions` | 正常（200） |
| 植入端回连（TCP/HTTP 轮询） | **不受影响**，会话正常上线 |
| `GET /api/v1/implant/payload/{id}`（一条命令上线） | 无需 Basic 认证即可下载 |
| 认证开启后 JWT 登录流程 | 正常（Basic 在前，JWT 在后） |
| 关闭开关 | 恢复原行为（无认证挑战） |

### 3.3 风险与注意事项

- **自我锁死**：开启时若用户名为空或哈希非法 → 拒绝保存（服务端校验 + 前端校验）；
- **WebSocket**：浏览器在 Basic 认证通过后会随请求自动携带凭据，`ws/events` 无需额外改造（前端已用 `?token=` 传 JWT，Basic 层独立生效）；
- **反代场景**：若用户在前面挂了 Nginx，Basic 认证应在 ToShell 层做（避免绕过），文档需说明"不要在反代层重复加，否则双重弹框"；
- **不影响植入端**是硬要求，验证矩阵里必须有"认证开启后植入端仍能上线/心跳"这一条。

### 3.4 实施顺序

1. `auth` 包加 Basic 中间件 + 单测（豁免路径、disguise/401、哈希校验）；
2. `api.go` 装配（豁免清单）+ 配置项落到 `config.Config`；
3. `settings` API 与前端「安全设置」页（开关/用户名/密码/测试）；
4. 加固项（robots/标题/未认证不返回静态资源）；
5. 文档：`USAGE.md` 反测绘章节 + `configs/server.yaml.example` 注释；
6. 验收矩阵（含植入端不受影响）跑通。

---

## 四、汇总与后续（当时的快照）

> 下表是撰写本文时的状态快照。三项在此后的版本中均已落地或调整，**当前状态请以
> [CHANGELOG.md](../CHANGELOG.md) 为准**（尤其 v1.3.2 段：配置原子写 / 凭据落盘 / 防测绘基础认证）。

| Issue | 结论 | 当时状态 | 后续 |
| --- | --- | --- | --- |
| #2 ② macOS/Linux 载荷编译失败 | 复现成功，根因正确 + 发现同类第二缺口 | **已修复（`4470abf`），6/6 构建矩阵验证** | 已并入 v1.3.2 |
| #2 ① 配置写回丢字段 | 描述机制**不复现**；实测发现"凭据无法落盘 → 每次重启换密码"这一真实缺陷 + 非原子写/注释丢失 | 方案见 §1.4，当时待实施 | 读-改-写 + 原子落盘、凭据必须落盘已随 v1.3.2 实施；C/D/E 与 §2.5 的构建矩阵脚本未按原计划落地（详见 CHANGELOG） |
| #1 Web 基础认证防测绘 | 需求明确 | 设计见 §3，当时待实施 | 已随 v1.3.2 实施（`web.*` 配置 + `/__gate` 隐蔽入口） |

**当时建议的实施顺序**：#2① 的 A+B（原子写 + 凭据必须落盘，直接影响可用性，改动小、风险低）→ #1（防测绘，外网部署刚需）→ #2① 的 C/D/E 与 §2.5 构建矩阵脚本（工程防回归）。

（当时的收尾约定是"每一项完成后更新 `CHANGELOG.md` 并把本文条目打 ✅"；本文现已归档，不再维护该标记，现状一律以 `CHANGELOG.md` 与 `ROADMAP.md` 为准。）
