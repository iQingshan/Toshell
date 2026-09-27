#!/usr/bin/env bash
# =====================================================================
#  ToShell Team Server —— 傻瓜式部署脚本 (Linux / macOS)
#
#  用法（在解压出来的目录里）：
#      chmod +x install.sh && ./install.sh
#
#  常用参数：
#      --check          只检测环境，不安装、不启动（安全，建议先跑）
#      --yes            所有询问自动确认
#      --no-start       只做配置与依赖安装，不启动服务端
#      --daemon         后台启动（nohup，日志写 server.log）；默认前台
#      --with-garble    额外安装 garble 混淆器（可选；对 Go 版本有要求）
#      --go-version X.Y.Z   指定要安装的 Go 版本（默认官方最新稳定版）
#
#  它做什么：
#    1) 检测运行环境（Go / 网络 / UPX / garble / 端口 / 磁盘 / 目录权限）
#    2) 缺失依赖可在线安装（Go 从官方源下载并校验 SHA-256）
#    3) 缺配置时从样例生成 configs/server.yaml
#    4) 直接启动打包好的 toserver，并打印控制台地址
# =====================================================================
set -uo pipefail

cd "$(dirname "$0")" || exit 1
ROOT="$(pwd)"
VERSION="v1.4.0"

CHECK=0; YES=0; NO_START=0; DAEMON=0; WITH_GARBLE=0; GO_VERSION=""
while [ $# -gt 0 ]; do
  case "$1" in
    --check) CHECK=1 ;;
    --yes|-y) YES=1 ;;
    --no-start) NO_START=1 ;;
    --daemon) DAEMON=1 ;;
    --with-garble) WITH_GARBLE=1 ;;
    --go-version) shift; GO_VERSION="${1:-}" ;;
    -h|--help) sed -n '2,30p' "$0"; exit 0 ;;
    *) echo "[x] 未知参数：$1（用 --help 查看用法）"; exit 1 ;;
  esac
  shift
done

OK=0; WARN=0; FAIL=0
c_ok()   { printf '[ OK ] %-16s %s\n' "$1" "$2"; OK=$((OK+1)); }
c_warn() { printf '[WARN] %-16s %s\n' "$1" "$2"; WARN=$((WARN+1)); }
c_fail() { printf '[FAIL] %-16s %s\n' "$1" "$2"; FAIL=$((FAIL+1)); }
c_info() { printf '[INFO] %-16s %s\n' "$1" "$2"; }
say()    { printf '%s\n' "$*"; }
ask() {
  [ "$YES" = 1 ] && return 1
  [ "$CHECK" = 1 ] && return 1
  printf '%s [y/N] ' "$1"
  read -r a
  case "$a" in y|Y|yes|YES) return 0 ;; *) return 1 ;; esac
}
have() { command -v "$1" >/dev/null 2>&1; }

say ""
say "====================================================================="
say " ToShell Team Server $VERSION  ·  一键部署（Linux / macOS）"
say "====================================================================="
say " 目录   : $ROOT"
say " 系统   : $(uname -s) $(uname -r)  $(uname -m)"
say " 模式   : $([ "$CHECK" = 1 ] && echo '仅检测 (--check)' || echo '检测 → 安装（按需）→ 启动')"
say ""

# ─── 0) 服务端二进制 ────────────────────────────────────────────────
BIN=""
for c in ./toserver ./toserver.exe; do
  [ -f "$c" ] && BIN="$c" && break
done
if [ -z "$BIN" ]; then
  c_fail '服务端二进制' "未找到 toserver —— 请解压完整发布包（脚本需与 toserver 同目录）"
  say ""; say '无法继续。'; exit 1
fi
chmod +x "$BIN" 2>/dev/null
c_ok '服务端二进制' "$(basename "$BIN")  $("$BIN" -version 2>&1 | head -1)"

# ─── 1) 配置文件 ────────────────────────────────────────────────────
CFG="configs/server.yaml"; EXAMPLE="configs/server.yaml.example"
if [ ! -f "$CFG" ]; then
  if [ -f "$EXAMPLE" ]; then
    cp "$EXAMPLE" "$CFG"
    c_ok '配置文件' '已从 server.yaml.example 生成 configs/server.yaml（密钥类留空时首次启动自动生成并落盘）'
  else
    c_fail '配置文件' '缺少 configs/server.yaml 与样例文件，发布包可能不完整'
  fi
else
  c_ok '配置文件' 'configs/server.yaml 已存在（保留你的现有配置）'
fi
API_PORT=18081; LISTEN_PORT=8080
if [ -f "$CFG" ]; then
  p=$(grep -E '^[[:space:]]*api_port:' "$CFG" | head -1 | tr -dc '0-9'); [ -n "$p" ] && API_PORT="$p"
  # 监听端口只取 listener: 段下的 port:（否则会误取 database.port: 5432）
  p=$(awk '/^[A-Za-z_][A-Za-z0-9_]*:/{s=($1=="listener:")} s && /^[[:space:]]+port:[[:space:]]*[0-9]+/{gsub(/[^0-9]/,"",$0); print; exit}' "$CFG")
  [ -n "${p:-}" ] && LISTEN_PORT="$p"
  grep -q '^listener:' "$CFG" || c_warn '配置内容' '未见 listener: 段，请检查配置是否被改坏'
fi

# ─── 2) 目录可写 / 磁盘 ─────────────────────────────────────────────
if mkdir -p data 2>/dev/null && ( : > data/.write_test ) 2>/dev/null; then
  rm -f data/.write_test
  c_ok '数据目录' 'data/ 可写（数据库/载荷/工具都在这里）'
else
  c_fail '数据目录' 'data/ 不可写（检查权限或挂载只读）'
fi
FREE_GB=$(df -Pk . 2>/dev/null | awk 'NR==2 {printf "%.1f", $4/1048576}')
if [ -n "${FREE_GB:-}" ]; then
  if awk "BEGIN{exit !($FREE_GB < 2)}"; then c_warn '磁盘空间' "剩余 ${FREE_GB} GB，偏小（构建载荷与工具链需要数 GB）"
  else c_ok '磁盘空间' "剩余 ${FREE_GB} GB"; fi
fi

# ─── 3) 端口占用 ────────────────────────────────────────────────────
port_busy() {
  if have ss; then ss -ltn 2>/dev/null | awk '{print $4}' | grep -qE "[:.]$1$" && return 0
  elif have lsof; then lsof -iTCP:"$1" -sTCP:LISTEN >/dev/null 2>&1 && return 0
  elif have netstat; then netstat -ltn 2>/dev/null | awk '{print $4}' | grep -qE "[:.]$1$" && return 0
  fi
  return 1
}
for p in "$API_PORT" "$LISTEN_PORT"; do
  if port_busy "$p"; then c_warn "端口 $p" '已被占用（若就是本服务端在跑可忽略；否则改配置或先停掉占用进程）'
  else c_ok "端口 $p" '空闲'; fi
done

# ─── 4) Go 工具链（构建载荷必需） ───────────────────────────────────
go_info() {
  have go || return 1
  v=$(go version 2>/dev/null) || return 1
  echo "$v"
}
GO_MAJOR=0; GO_MINOR=0
GV=$(go_info || true)
if [ -n "${GV:-}" ]; then
  if echo "$GV" | grep -qE 'go1\.(2[1-9]|[3-9][0-9])'; then
    c_ok 'Go 工具链' "$GV  ($(command -v go))"
  else
    c_fail 'Go 工具链' "$GV 过旧：构建载荷需要 Go ≥ 1.21"
  fi
else
  c_fail 'Go 工具链' '未检测到 go：无法构建载荷（服务端本身仍可运行）'
fi

install_go() {
  os=$(uname -s | tr '[:upper:]' '[:lower:]')
  case "$os" in linux) gos=linux ;; darwin) gos=darwin ;; *) echo "不支持的系统：$os"; return 1 ;; esac
  arch=$(uname -m)
  case "$arch" in x86_64|amd64) goarch=amd64 ;; aarch64|arm64) goarch=arm64 ;; *) echo "不支持的架构：$arch"; return 1 ;; esac

  say "[*] 获取 Go 官方版本信息…"
  json=$(curl -fsSL --max-time 30 'https://go.dev/dl/?mode=json' 2>/dev/null) || { echo '[x] 无法访问 go.dev（检查网络/代理）'; return 1; }
  ver=$(printf '%s' "$json" | tr ',' '\n' | grep -m1 '"version"' | sed -E 's/.*"version": *"([^"]+)".*/\1/')
  [ -n "$GO_VERSION" ] && ver="go$GO_VERSION"
  [ -n "${ver:-}" ] || { echo '[x] 无法解析 Go 版本'; return 1; }
  fname="${ver}.${gos}-${goarch}.tar.gz"
  want=$(printf '%s' "$json" | tr '{' '\n' | grep -F "$fname" -A0 >/dev/null 2>&1; printf '%s' "$json" | python3 -c "
import json,sys
d=json.load(sys.stdin)
for rel in d:
    for f in rel.get('files',[]):
        if f['filename']=='$fname' and f.get('kind')=='archive':
            print(f['sha256']); raise SystemExit
" 2>/dev/null)
  if [ -z "${want:-}" ]; then echo "[x] 未在官方列表中找到 $fname"; return 1; fi

  tools="$ROOT/.tools"; mkdir -p "$tools"
  tarball="$tools/$fname"
  say "[*] 下载 $fname（约 70~100 MB）…"
  curl -fL --progress-bar -o "$tarball" "https://go.dev/dl/$fname" || { echo '[x] 下载失败'; return 1; }
  got=$((have sha256sum && sha256sum "$tarball" || shasum -a 256 "$tarball") | awk '{print $1}')
  if [ "$got" != "$want" ]; then rm -f "$tarball"; echo "[x] SHA-256 校验失败（期望 $want，实际 $got），已删除文件"; return 1; fi
  say '[+] SHA-256 校验通过'
  rm -rf "$tools/go"
  say "[*] 解压到 $tools/go …"
  tar -C "$tools" -xzf "$tarball" || { echo '[x] 解压失败'; return 1; }
  rm -f "$tarball"
  export PATH="$tools/go/bin:$PATH"
  say "[+] 本次会话已生效：$($tools/go/bin/go version)"
  say "[i] 长期生效请自行把 $tools/go/bin 加入 PATH，或用绝对路径 $tools/go/bin/go"
  return 0
}

if [ -z "${GV:-}" ] || ! echo "$GV" | grep -qE 'go1\.(2[1-9]|[3-9][0-9])'; then
  if [ "$CHECK" = 1 ]; then
    say '[i] 仅检测模式：未安装 Go。去掉 --check 会从 go.dev 在线下载安装（含 SHA-256 校验）。'
  elif ask '是否现在从 go.dev 官方源下载并安装 Go？'; then
    if install_go; then c_ok 'Go 安装' '完成'; else c_fail 'Go 安装' '失败（可手动安装后重跑）'; fi
  else
    c_warn 'Go 安装' '已跳过（生成载荷需要 Go）'
  fi
fi

# ─── 5) 模块代理可达性 ──────────────────────────────────────────────
if have go; then
  goproxy=$(go env GOPROXY 2>/dev/null || echo 'https://proxy.golang.org,direct')
  first=$(printf '%s' "$goproxy" | cut -d, -f1)
  case "$first" in
    http*)
      if curl -fsS --max-time 8 -o /dev/null "$first" 2>/dev/null; then
        c_ok '模块代理' "$first 可达（GOPROXY=$goproxy）"
      else
        c_warn '模块代理' "$first 不可达：生成载荷要拉依赖，建议 go env -w GOPROXY=https://goproxy.cn,direct"
      fi ;;
  esac
fi

# ─── 6) UPX / garble ───────────────────────────────────────────────
UPX_BIN=""
for c in upx/linux-amd64/*/upx upx/linux-amd64/upx upx/linux-arm64/*/upx; do
  [ -x "$c" ] && UPX_BIN="$c" && break
done
if [ -n "$UPX_BIN" ]; then c_ok 'UPX 压缩' "已随包提供：$UPX_BIN"
elif have upx; then c_ok 'UPX 压缩' "PATH 中的 upx 可用"
else c_info 'UPX 压缩' '未提供（可选：压缩 Windows 载荷体积）'; fi

if have garble; then
  c_ok 'garble 混淆' "$(garble version 2>&1 | head -1)（与 Go 版本不匹配时界面会显示不可用）"
elif [ "$WITH_GARBLE" = 1 ] && have go; then
  say '[*] 安装 garble …'
  if go install mvdan.cc/garble@latest >/dev/null 2>&1; then c_ok 'garble 混淆' '安装完成'; else c_warn 'garble 混淆' '安装失败'; fi
else
  c_info 'garble 混淆' '未安装（可选；加 --with-garble 安装）'
fi
c_info 'mingw gcc' 'Linux/macOS 不需要（C 植入端是 Windows 专用）'

# ─── 7) 汇总 ────────────────────────────────────────────────────────
say ""
say '───────────────── 环境检测汇总 ─────────────────'
say " 通过 $OK · 警告 $WARN · 失败 $FAIL"
[ "$FAIL" -gt 0 ] && say ' 有失败项：请按上面 [FAIL] 的提示处理（Go 缺失只影响"生成载荷"，服务端本身可跑）'

if [ "$CHECK" = 1 ]; then
  say ""
  say '[i] 仅检测模式结束。去掉 --check 重新运行即可按需安装依赖并启动服务端。'
  exit 0
fi

if [ "$NO_START" = 1 ]; then
  say ""
  say '[i] --no-start：已跳过启动。手动启动：'
  say "    $BIN -config configs/server.yaml"
  exit 0
fi

say ""
if ask "现在启动 ToShell Team Server？（控制台 http://localhost:$API_PORT）"; then
  say ""
  say "  控制台 : http://localhost:$API_PORT"
  say "  监听   : 0.0.0.0:$LISTEN_PORT（植入端回连）"
  say "  首次启动会在日志里打印自动生成的 admin 密码 / JWT key / 加密 key（并落盘到 configs/server.yaml）"
  say ""
  if [ "$DAEMON" = 1 ]; then
    nohup "$BIN" -config configs/server.yaml > server.log 2>&1 &
    pid=$!
    say "[+] 已后台启动（PID $pid），日志：server.log"
    say "    停止：kill $pid   查看日志：tail -f server.log"
  else
    say '[*] 前台启动（Ctrl+C 停止）…'
    exec "$BIN" -config configs/server.yaml
  fi
else
  say "[i] 已跳过启动。手动启动：  $BIN -config configs/server.yaml"
fi
