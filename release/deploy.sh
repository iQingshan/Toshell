#!/usr/bin/env bash
# =====================================================================
#  ToShell Team Server 一键启动脚本 (Linux / macOS)
#  用法:  在 release/ 目录执行  ./deploy.sh
#  首次运行会自动从 configs/server.yaml.example 生成配置(需先修改敏感项),
#  之后在后台启动服务端,日志写入 server.log。
# =====================================================================
set -e
cd "$(dirname "$0")"

VERSION="v1.2.1"
CFG_FILE="configs/server.yaml"
EXAMPLE="configs/server.yaml.example"

# 判断服务端可执行文件名
BIN=""
for c in ./toserver ./toserver.exe; do
  if [ -f "$c" ]; then BIN="$c"; break; fi
done

# 1) 配置检查
if [ ! -f "$CFG_FILE" ]; then
  echo "[*] 未找到 $CFG_FILE"
  if [ -f "$EXAMPLE" ]; then
    cp "$EXAMPLE" "$CFG_FILE"
    echo "[!] 已从 $EXAMPLE 生成 $CFG_FILE"
    echo "    请先编辑 $CFG_FILE, 修改以下敏感项后再启动:"
    echo "      - auth.api_keys          (API 调用密钥)"
    echo "      - auth.jwt_key           (留空则首次启动自动生成)"
    echo "      - listener.encryption_key(植入端加密密钥, 留空自动生成)"
    echo "      - listener.public_host   (服务器公网 IP/域名)"
    echo "      - auth.admin_password    (管理员密码)"
  else
    echo "[x] 缺少 $EXAMPLE, 无法自动生成配置。请在项目根运行:"
    echo "    cp configs/server.yaml.example release/configs/server.yaml"
    exit 1
  fi
fi

# 2) 可执行文件检查
if [ -z "$BIN" ]; then
  echo "[x] 未找到服务端可执行文件 (toserver / toserver.exe)。请先在项目根构建:"
  echo "    go build -tags webui -ldflags \"-s -w\" -o release/toserver ./cmd/server"
  exit 1
fi

# 3) 启动
mkdir -p data
echo "[*] 启动 ToShell Team Server $VERSION ($BIN) ..."
nohup "$BIN" -config "$CFG_FILE" > server.log 2>&1 &
PID=$!
echo "[+] 已启动 (PID $PID), 日志: server.log"

API_PORT=$(grep -E '^\s*api_port:' "$CFG_FILE" | sed -E 's/[^0-9]//g' | head -1)
[ -z "$API_PORT" ] && API_PORT=18081
echo "[+] Web 控制台:  http://localhost:${API_PORT}"
echo "[+] 停止:        kill $PID   (或 pkill -f toserver)"
echo "[+] 查看日志:    tail -f server.log"
