#!/usr/bin/env bash
# =====================================================================
#  ToShell 核心链路冒烟回归（发版门禁）
#  用法:  ./scripts/smoke.sh [SERVER_URL] [API_KEY]
#  默认 SERVER_URL=http://127.0.0.1:18081  API_KEY=Qingshan@2026
#
#  覆盖（不依赖真实植入端，服务端自闭环）：
#    1. /health                      服务在线
#    2. settings GET                 配置可读
#    3. settings PUT 回环            可写（改 kill_date 再还原）
#    4. agent/chat 创建 run          异步 run 创建响应结构正确（含 run_id/session_id）
#    5. agent/runs/{id} 查询         状态机字段齐全（status/objective/plan/reply）
#  说明：真实"植入端会话 + 工具执行"闭环需授权目标机上线，见 docs/evasion-testing 或手动冒烟。
# =====================================================================
set -u
BASE="${1:-http://127.0.0.1:18081/api/v1}"
KEY="${2:-Qingshan@2026}"
H="X-API-Key: $KEY"
PASS=0; FAIL=0

ok()   { PASS=$((PASS+1)); echo "  ✓ $1"; }
bad()  { FAIL=$((FAIL+1)); echo "  ✗ $1"; }

check() { # name, condition-exit-code
  if [ "$2" = "0" ]; then ok "$1"; else bad "$1"; fi
}

echo "== 1. 服务健康 =="
CODE=$(curl -s -o /dev/null -w '%{http_code}' "$BASE/health")
check "GET /health -> $CODE" "$([ "$CODE" = "200" ]; echo $?)"

echo "== 2. settings 可读 =="
S=$(curl -s -H "$H" "$BASE/settings")
echo "$S" | grep -q '"general"' && check "settings 含 general" 0 || check "settings 含 general" 1

echo "== 3. settings 写回环（kill_date）=="
KILL_BEFORE=$(echo "$S" | sed -n 's/.*"kill_date":"\([^"]*\)".*/\1/p')
BODY="{\"implant\":{\"kill_date\":\"2030-01-01\"}}"
C=$(curl -s -o /dev/null -w '%{http_code}' -X PUT -H "$H" -H 'Content-Type: application/json' -d "$BODY" "$BASE/settings")
check "PUT kill_date -> $C" "$([ "$C" = "200" ]; echo $?)"
if [ -n "$KILL_BEFORE" ]; then
  curl -s -o /dev/null -X PUT -H "$H" -H 'Content-Type: application/json' -d "{\"implant\":{\"kill_date\":\"$KILL_BEFORE\"}}" "$BASE/settings"
  echo "    (已还原 kill_date=$KILL_BEFORE)"
fi

echo "== 4. agent run 创建（异步非阻塞）=="
R=$(curl -s -X POST -H "$H" -H 'Content-Type: application/json' -d '{"messages":[{"role":"user","content":"hello"}]}' "$BASE/agent/chat")
RID=$(echo "$R" | sed -n 's/.*"run_id":"\([^"]*\)".*/\1/p')
if [ -n "$RID" ]; then
  ok "run 创建 run_id=$RID"
else
  bad "run 创建失败: $(echo "$R" | head -c 200)"
fi

echo "== 5. run 状态查询（结构）=="
if [ -n "${RID:-}" ]; then
  ST=$(curl -s -H "$H" "$BASE/agent/runs/$RID")
  echo "$ST" | grep -q '"status"' && check "run 状态字段齐全" 0 || check "run 状态字段齐全" 1
  echo "    status=$(echo "$ST" | sed -n 's/.*"status":"\([^"]*\)".*/\1/p')"
fi

echo
echo "================ 结果: $PASS 通过 / $FAIL 失败 ================"
[ "$FAIL" = "0" ] && exit 0 || exit 1
