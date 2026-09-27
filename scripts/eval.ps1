# =====================================================================
#  ToShell 离线评测门禁（v1.4.0 S2 / 计划 M4）
#
#  跑黄金集：输入 → 期望工具序列 → 期望终态/stop_reason → 期望上下文痕迹。
#  全程**不联网、不需要真实 LLM、不需要植入端**（桩 LLM + 假工具执行器），
#  因此本机与 CI 都能跑，结果确定；用例数据在
#  `internal/server/ai/testdata/golden/cases.json`（加用例只需改 JSON）。
#
#  用法：
#    powershell -NoProfile -ExecutionPolicy Bypass -File scripts/eval.ps1
#    powershell ... -File scripts/eval.ps1 -Verbose     # 逐条打印用例名
#
#  退出码：0 = 全部通过；非 0 = 有用例失败（可直接接进发版门禁）。
# =====================================================================
[CmdletBinding()]
param(
    [switch]$ShowCases
)

$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent $PSScriptRoot
Push-Location $repoRoot
try {
    $goArgs = @('test', './internal/server/ai/', '-count=1', '-run', 'TestGoldenSet')
    if ($ShowCases) { $goArgs += '-v' }
    Write-Host '=== 离线评测门禁：黄金集（桩 LLM + 假工具执行器）==='
    & go @goArgs
    $code = $LASTEXITCODE
    if ($code -eq 0) {
        Write-Host '=== 结果：黄金集全部通过 ==='
    } else {
        Write-Host ("=== 结果：有用例失败（exit {0}）—— 先看上面 --- FAIL 的用例名与 why 字段 ===" -f $code)
    }
    exit $code
} finally {
    Pop-Location
}
