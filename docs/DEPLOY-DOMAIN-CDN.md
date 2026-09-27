# 域名 + CDN 上线使用说明

> 适用版本：**v1.4.0**（开发中；上一发布版 v1.3.5）｜ 对应 [issue #3](https://github.com/iQingshan/Toshell/issues/3)
> 目标：把植入端回连从「裸 IP + 端口」改成「合法域名（+ CDN / 反代）」，让出站流量看起来像正常 HTTPS 访问，提升存活与过白名单能力。

**结论：支持。** 本项目通过 **HTTP(S) 轮询监听器 + 流量拟态 + 域前置** 支持三种上线方式，按自己的条件选一种即可：

| 方案 | 适用场景 | 难度 | 是否需要自有域名 |
| --- | --- | --- | --- |
| **A. CDN 直接回源**（推荐） | 想最快跑通、隐藏源站 IP、借用 CDN 的高信誉 IP | ★ | 需要（CDN 提供商给的子域即可） |
| **B. 自建 Nginx/Caddy 反代** | 想要完全可控、能配真实证书、可做路径级伪装 | ★★ | 需要 |
| **C. 域前置（Domain Fronting）** | 目标出站只允许访问特定域名白名单 | ★★★ | 需要，且一般要自建边缘 |

---

## 一、先理解：C2 通道长什么样

**HTTP(S) 轮询监听器**（`listener.protocol: http`）暴露的端点（大小写敏感，路径固定）：

| 方法 | 路径 | 用途 |
| --- | --- | --- |
| POST | `/register` | 植入端注册上线 |
| POST | `/heartbeat` | 心跳、顺带取回待执行任务（植入端主循环靠它） |
| GET | `/task?session_id=<id>` | 主动拉取待执行任务（备用路径） |
| POST | `/result` | 任务结果回传 |
| POST | `/file`、`/file/pull` | 文件上传 / 分片下载 |
| POST | `/shell`、`/tunnel` | 交互 shell / 隧道数据 |

要点：

1. **上行请求体是 AES-GCM 加密后的二进制**（不是 JSON 明文），普通 CDN/WAF 的内容检查基本不会拦，也不会命中常见规则特征；
2. **除上述路径外的所有请求**都会走拟态逻辑：默认返回拟态诱饵页（`listener.mimicry_profile`：`cdn` / `api` / `stream`），配置了 `listener.mimicry_site` 时则**反向代理到一个真实网站**，探测者看到的就是那个网站；
3. 轮询是**短请求**（非常驻长连接），对 CDN 超时不敏感；心跳间隔由 `implant.interval` 控制，服务端判活阈值是 `listener.heartbeat_timeout`。

---

## 二、方案 A：CDN 直接回源（推荐）

思路：CDN 域名 → 回源到你的 ToShell 监听器；植入端只连 CDN 域名，源站 IP 全程不暴露。

### 1) 服务端配置（`configs/server.yaml`）

```yaml
listener:
    enabled: true
    protocol: http            # HTTP(S) 轮询通道（不是 tcp）
    host: 0.0.0.0
    port: 8080                # 监听端口（CDN 回源端口）
    public_host: cdn.example.com   # 填你的 CDN 域名，生成载荷时用
    heartbeat_timeout: 60s
    encryption_key: ""        # 留空自动生成；更换后需重新生成所有植入端
    # 回源方式二选一：
    # (a) CDN 用 HTTP 回源  → 下面保持 false
    # (b) CDN 用 HTTPS 回源 → 需要证书，且必须是 CDN 认可的证书
    tls_enabled: false
    cert_file: ""
    key_file: ""
    # 拟态：探测者访问非 C2 路径时看到什么
    mimicry_profile: cdn      # cdn / api / stream
    mimicry_site: ""          # 想更真实就填一个真站，如 https://www.example.com
```

> **强烈建议**：控制台端口（`server.api_port`，示例配置为 `18081`）**不要**挂到 CDN 上，并按 v1.3.5 的能力给它加一层防测绘（见文末「安全建议」）。

### 2) CDN 侧配置

以通用 CDN 为例（Cloudflare / 腾讯云 EdgeOne / 阿里云 CDN / CloudFront 均类似）：

| 项 | 配置 |
| --- | --- |
| 加速域名 | 例如 `cdn.example.com`（CNAME 到 CDN 分配的地址） |
| 源站 | `你的服务器IP:8080`（端口必须与 `listener.port` 一致） |
| 回源协议 | HTTP（对应 `tls_enabled: false`）；若选 HTTPS，源站需配好证书 |
| 缓存 | **对 POST 不缓存**（多数 CDN 默认就不缓存 POST）；建议对 `/register`、`/heartbeat`、`/result`、`/file`、`/shell`、`/tunnel` 全路径设置为「不缓存 / 绕过缓存」 |
| 路径改写 | **必须关闭**（不能重写或去掉路径，否则打不到 C2 端点） |
| HTTPS | 开启（植入端走 `https://cdn.example.com`，TLS 由 CDN 终止） |
| WebSocket | 不需要开启 |
| 回源 Host | 保持默认（回源时 Host 通常仍是加速域名，本项目不依赖 Host 区分） |

> **Cloudflare 注意**：SSL/TLS 模式选 **Flexible**（CDN→源站走 HTTP，源站 `tls_enabled: false`）或 **Full (strict)**（源站必须有 CDN 认可的有效证书，否则报 526）。Cloudflare 的「Always Use HTTPS」「Automatic HTTPS Rewrites」可以开，不影响 POST。

### 3) 生成植入端

Web 控制台 →「生成载荷」：

| 字段 | 填法 |
| --- | --- |
| 回连通道 | **HTTP**（或 HTTPS，取决于你的监听器/回源方式；**不要选 TCP**） |
| 服务器地址 / `server_url` | `https://cdn.example.com`（**必须带 `http(s)://` 前缀**；不带前缀会被自动补成 `https://`） |
| 域前置拟态域名 | 方案 A 通常**留空**（同上表说明）；需要时见方案 C |
| 监听器 | 选你配置好的 HTTP 监听器（`public_host` 已是 CDN 域名） |

生成后目标机运行即回连；Sessions 页出现会话即成功。

### 4) 先用直连验证，再切域名

排错时建议先确认「裸连接」没问题，再套 CDN：

```bash
# 直连源站（应能看到拟态响应，例如 CDN 风格的 HTML/JSON，而不是 C2 特征）
curl -i http://<服务器IP>:8080/
# 观察是否有正常的拟态响应头与页面
```

浏览器直连 `http://<服务器IP>:8080/` 看到的是拟态站点，这属于正常现象。

---

## 三、方案 B：自建 Nginx 反代（完全可控）

适合有自有域名 + 证书、希望「只有 C2 路径回连你的服务器，其余流量给真实站点」的场景。

```nginx
# /etc/nginx/conf.d/toshell.conf
server {
    listen 443 ssl http2;
    server_name cdn.example.com;

    ssl_certificate     /etc/letsencrypt/live/cdn.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/cdn.example.com/privkey.pem;

    # 1) C2 路径 → ToShell HTTP 轮询监听器（不用改路径！）
    location ~ ^/(register|heartbeat|task|result|file|file/pull|shell|tunnel)$ {
        proxy_pass http://127.0.0.1:8080;
        proxy_http_version 1.1;
        proxy_set_header Host              $host;
        proxy_set_header X-Real-IP         $remote_addr;
        proxy_set_header X-Forwarded-For   $proxy_add_x_forwarded_for;
        proxy_request_buffering off;      # 加密二进制体，不要缓冲改写
        proxy_buffering off;
        client_max_body_size 100m;        # 文件上传/下载分片需要
    }

    # 2) 其余流量 → 真实网站（拟态），也可删掉这段改为反代到监听器让它返回拟态页
    location / {
        proxy_pass https://www.example.com;
        proxy_set_header Host www.example.com;
        proxy_ssl_server_name on;
    }
}
```

要点：

- **不要**在 Nginx 里改写路径（`rewrite`、`proxy_pass` 带路径都会导致 404）；
- 关闭请求/响应缓冲，避免大文件分片被整段缓冲；
- `client_max_body_size` 要够大（文件上传）；
- 条件允许时，把 C2 端点与真实站点放在**不同域名**上，行为更像正常业务；
- 若反代自身做了访问日志，注意它会记录目标机 IP（按需关闭该域名日志）。

生成载荷时：回连通道选 HTTP/HTTPS，`server_url` 填 `https://cdn.example.com`。

---

## 四、方案 C：域前置（Domain Fronting）

### 本项目里它到底做了什么

代码事实（`internal/server/builder/implant/transport_tls_*.go`、`transport_http.go`）：

- 配置了 **`front_domain`**（构建页「域前置拟态域名」或 `listener.front_domain`）后：
  - 植入端建立 TLS 时 **SNI = front_domain**；
  - HTTP 请求头 **Host = front_domain**；
  - 而 TCP 实际连接的目标仍是 `server_url` 里的地址。
- 也就是说：**SNI 与 Host 是同一个拟态域名**，连接目标由 `server_url` 决定。

### 因此正确的用法是

让 `front_domain` 就是**你自己的、在 CDN/边缘上有配置的那个合法域名**（其源站指向你的 ToShell 服务器），`server_url` 则填该域名或该域名的 CDN 边缘地址。这样：

- 审查设备只看到「访问合法域名」的 TLS SNI 与 Host；
- CDN/边缘按该域名回源到你的服务器，C2 流量正常到达。

### 限制（务必知道）

- **经典域前置**（SNI 用高信誉域名 A、Host 用你自己的域名 B，借 CDN 路由到 B 的源站）需要 CDN 支持「按 Host 跨域回源」，**主流公共 CDN（Cloudflare 等）已普遍封禁**；本项目的实现方式更适合自建 CDN / 自建边缘 / 自有域名场景。
- 若把 `front_domain` 填成「别人的域名」，流量会被 CDN 路由到那个域名的真实源站，**C2 不会上线**。
- 目标机需要能解析并访问该域名；`server_url` 与 `front_domain` 的关系要自己打通（先用 `curl --resolve` 验证）。

---

## 五、常见问题排查（FAQ）

| 现象 | 排查方向 |
| --- | --- |
| 会话一直不上线 | ① 通道是否选了 **HTTP/HTTPS**（TCP 通道不走本说明）；② `server_url` 是否带 `http(s)://` 前缀；③ CDN 是否拦截/改写了 POST 与路径；④ 回源端口是否与 `listener.port` 一致 |
| CDN 报 502/520/526 | 源站端口不通（安全组/防火墙）、回源协议与 `tls_enabled` 不匹配、源站证书不被 CDN 认可（改用 Flexible 或换成有效证书） |
| 心跳正常但收不到任务结果 | 检查 `/result`、`/file` 是否被 CDN 缓存或限制请求体大小；大文件分片需要放宽 `client_max_body_size` |
| 探测访问域名看到 C2 界面 | 说明路径回退到了控制台（接错了端口/服务）；C2 监听端口应与控制台端口分离，且监听器 `mimicry_profile`/`mimicry_site` 必须生效 |
| 重复任务/结果错乱 | 检查 CDN 是否重试了 POST、是否开启了「自动重试/容错」类功能；本项目已做任务幂等，但仍建议关闭 CDN 的重试 |
| 会话频繁掉线 | 调大 `listener.heartbeat_timeout`（如 `180s`），并确认心跳间隔 `implant.interval` 明显小于它 |

---

## 六、安全建议

1. **控制台与 C2 分离**：只把 C2 监听端口放到 CDN/公网；控制台端口尽量只对运维网段开放。
2. **启用控制台防护（v1.3.5）**：`web.basic_auth_enabled: true`，并选择未认证响应方式——`basic`（401 弹认证框）或 `disguise`（纯 404 伪装）。disguise 模式下需填 `web.stealth_key`，用入口 `/__gate?k=<stealth_key>`（或访问 `/__gate` 弹框输入凭据）进入控制台。详见 `configs/server.yaml.example` 的 `web:` 段；部署侧的加固清单见 [SECURITY.md](../SECURITY.md)。
3. **密钥与域名轮换**：`encryption_key`、`jwt_key`、CDN 域名与 `front_domain` 建议定期更换；更换 `encryption_key` 后必须重新生成全部植入端。
4. **最小暴露**：CDN 只回源必要端口；源站安全组只放行 CDN 回源 IP 段（CDN 提供商一般提供回源 IP 列表）。
5. **合规**：仅在你获得书面授权的目标与范围内使用。

---

## 附：相关配置项速查

| 配置项 | 作用 |
| --- | --- |
| `listener.protocol` | 通道类型：`http`（轮询）/ `tcp` / `websocket` / `mqtt` |
| `listener.port` / `host` | 监听地址（CDN 回源目标） |
| `listener.public_host` | 生成载荷时展示/使用的对外地址（填 CDN 域名或真实域名）；**「一条命令上线」的载荷下载地址优先取这里**，因此跨 CDN/反代取件时务必填写完整地址（如 `https://cdn.example.com`） |
| `listener.tls_enabled` + `cert_file`/`key_file` | 源站是否启用 HTTPS（配合 CDN「HTTPS 回源」） |
| `listener.mimicry_profile` | 非 C2 路径的拟态模板：`cdn` / `api` / `stream` |
| `listener.mimicry_site` | 非 C2 路径反向代理到真实站点（更真实） |
| `listener.front_domain` | 域前置拟态域名（SNI + Host），见方案 C |
| `listener.heartbeat_timeout` | 判活阈值；务必大于植入端心跳间隔 |
| `implant.interval` / `jitter` | 植入端心跳间隔与抖动 |
| `web.*` | 控制台防测绘（basic 认证 / 404 伪装 / 隐蔽入口） |

---

## 相关文档

- [README.md](../README.md) — 项目总览与架构
- [USAGE.md](../USAGE.md) — 部署、监听器配置与常见问题
- [SECURITY.md](../SECURITY.md) — 部署加固清单与安全 / 滥用报告渠道
- [DISCLAIMER.md](../DISCLAIMER.md) — 授权使用范围声明
- [CHANGELOG.md](../CHANGELOG.md) ｜ [ROADMAP.md](../ROADMAP.md) — 版本变更与后续计划
