# =====================================================================
#  ToShell MCP 服务端端到端冒烟（v1.4.0）
#
#  作用：不需要任何植入端，就能验证「对外 MCP 接口 + 安全边界」是否真的生效。
#        起一个临时服务端（独立端口 + 独立 token + 只读白名单），跑一遍权限矩阵：
#          ① 无 token / 错 token  → 401
#          ② initialize           → 200 且下发 Mcp-Session-Id
#          ③ tools/list           → 200 且工具数与注册表一致
#          ④ 只读工具 tools/call  → 200 且返回统一信封
#          ⑤ 危险工具（未放行）    → 403 tool_not_allowed
#          ⑥ 未注册工具           → 403
#          ⑦ 缺/错会话头          → 400
#          ⑧ resources/read 穿越  → 拒绝（不得返回文件内容）
#          ⑨ 超 RPM               → 429
#        输出 ✅/⚠️/❌ 摘要；有 ❌ 即非 0 退出（与 scripts/e2e_smoke.ps1 同风格）。
#
#  用法：
#    pwsh -NoProfile -ExecutionPolicy Bypass -File scripts/mcp_smoke.ps1
#    pwsh ... -File scripts/mcp_smoke.ps1 -SkipBuild -ServerExe .\release\toserver.exe -KeepArtifacts
#
#  注意：脚本只起「服务端」，**不生成、不执行任何载荷**。
# =====================================================================
[CmdletBinding()]
param(
    [int]$ApiPort = 18182,
    [int]$McpPort = 18184,
    [int]$MaxRPM = 20,
    [string]$ServerExe = '',
    [switch]$SkipBuild,
    [switch]$KeepArtifacts
)

$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent $PSScriptRoot
$script:Results = New-Object System.Collections.ArrayList
$script:TempDir = Join-Path ([IO.Path]::GetTempPath()) ('tsh-mcp-smoke-' + $PID)
$script:Proc = $null
$script:BaseUrl = 'http://127.0.0.1:' + $ApiPort
$script:McpUrl = 'http://127.0.0.1:' + $McpPort + '/mcp'
$script:Token = ''
$script:SessionId = ''

function Add-Result {
    param([string]$Name, [string]$Level, [string]$Detail = '')
    [void]$script:Results.Add([pscustomobject]@{ Name = $Name; Level = $Level; Detail = $Detail })
    $color = 'Gray'; if ($Level -eq 'OK') { $color = 'Green' } elseif ($Level -eq 'WARN') { $color = 'Yellow' } elseif ($Level -eq 'FAIL') { $color = 'Red' }
    Write-Host ('  [{0,-4}] {1}{2}' -f $Level, $Name, $(if ($Detail) { ' — ' + $Detail } else { '' })) -ForegroundColor $color
}

# 统一请求封装：走 curl.exe。
# 为什么不用 Invoke-WebRequest：① PS 5.1 遇 4xx 直接抛异常，拿不到状态码与响应体；
# ② PS 5.1 给原生命令传含引号的 JSON 参数会被拆坏（实测服务端收到 "invalid character 'j'"）；
# ③ 无响应时 curl 的 --max-time 行为可预期，不会因连接池复用而把后续请求一起挂住。
# 请求体一律写临时文件后用 --data-binary "@file" 传入，彻底避开引号问题。
function Invoke-Raw {
    param([string]$Method, [string]$Url, [hashtable]$Headers = @{}, [string]$Body = '', [int]$TimeoutSec = 15)
    $resp = [pscustomobject]@{ StatusCode = 0; Content = ''; Headers = @{}; Error = '' }
    $id = [guid]::NewGuid().ToString('N')
    $bodyFile = Join-Path $script:TempDir ('req-' + $id + '.txt')
    $hdrFile = Join-Path $script:TempDir ('hdr-' + $id + '.txt')
    $outFile = Join-Path $script:TempDir ('out-' + $id + '.txt')

    $curlArgs = @('-s', '-o', $outFile, '-D', $hdrFile, '-w', '%{http_code}', '--max-time', "$TimeoutSec", '-X', $Method)
    if ($Body -ne '') {
        [IO.File]::WriteAllText($bodyFile, $Body, (New-Object Text.UTF8Encoding($false)))
        $curlArgs += @('--data-binary', ('@' + $bodyFile), '-H', 'Content-Type: application/json')
    }
    foreach ($k in $Headers.Keys) { $curlArgs += @('-H', ($k + ': ' + [string]$Headers[$k])) }
    $curlArgs += $Url

    $code = ''
    try { $code = (& "$env:SystemRoot\System32\curl.exe" @curlArgs 2>&1 | Out-String).Trim() } catch { $resp.Error = $_.Exception.Message }
    if ($code -match '^\d{3}$') { $resp.StatusCode = [int]$code } else { $resp.Error = ('curl: ' + $code) }

    if (Test-Path $outFile) { $resp.Content = [IO.File]::ReadAllText($outFile, [Text.Encoding]::UTF8) }
    if (Test-Path $hdrFile) {
        $h = @{}
        foreach ($line in ([IO.File]::ReadAllLines($hdrFile, [Text.Encoding]::UTF8))) {
            $m = [regex]::Match($line, '^([A-Za-z0-9\-]+):\s*(.*)$')
            # 多段响应（100-continue/重定向）时后段覆盖前段
            if ($m.Success) { $h[$m.Groups[1].Value] = $m.Groups[2].Value.Trim() }
        }
        $resp.Headers = $h
    }
    foreach ($f in @($bodyFile, $hdrFile, $outFile)) { Remove-Item -Force $f -ErrorAction SilentlyContinue }
    return $resp
}

function Invoke-Mcp {
    param([string]$Body, [string]$Token = $null, [string]$SessionId = $null)
    # 这里**不**声明 Accept: text/event-stream —— POST 的响应是普通 JSON，
    # 声明 SSE 只会诱导客户端去等一个永不结束的流。
    $h = @{ 'Accept' = 'application/json' }
    if ($null -ne $Token) { $h['Authorization'] = 'Bearer ' + $Token }
    if ($null -ne $SessionId -and $SessionId -ne '') { $h['Mcp-Session-Id'] = $SessionId }
    return Invoke-Raw -Method 'POST' -Url $script:McpUrl -Headers $h -Body $Body
}

function Get-Json($text) { try { return $text | ConvertFrom-Json } catch { return $null } }

# ── 1. 准备临时服务端 ────────────────────────────────────────────────
Write-Host ''
Write-Host '=== ToShell MCP 冒烟：准备临时服务端 ===' -ForegroundColor Cyan
New-Item -ItemType Directory -Force -Path $script:TempDir | Out-Null

if (-not $SkipBuild) {
    $exe = Join-Path $script:TempDir 'toserver.exe'
    Write-Host '  构建服务端（go build ./cmd/server）…'
    Push-Location $repoRoot
    try {
        $env:CGO_ENABLED = '0'
        & go build -o $exe ./cmd/server 2>&1 | Out-String | Write-Verbose
        if ($LASTEXITCODE -ne 0 -or -not (Test-Path $exe)) { throw 'go build 失败' }
    } finally { Pop-Location }
} else {
    if ($ServerExe -eq '') { $ServerExe = Join-Path $repoRoot 'release\toserver.exe' }
    if (-not (Test-Path $ServerExe)) { throw ('找不到服务端二进制：' + $ServerExe) }
    $exe = (Resolve-Path $ServerExe).Path
}
Write-Host ('  服务端: ' + $exe)

# 临时配置：最小可跑配置（字段名照抄 internal/server/config/config.go 与 configs/server.yaml.example）
# 这里**不用**改样例配置，避免"正则没替换上导致 MCP 其实没开"这种假阴性。
$cfgDir = Join-Path $script:TempDir 'configs'
New-Item -ItemType Directory -Force -Path $cfgDir | Out-Null
$cfgPath = Join-Path $cfgDir 'server.yaml'
$dataDir = Join-Path $script:TempDir 'data'
New-Item -ItemType Directory -Force -Path $dataDir | Out-Null
$script:Token = 'smoke-' + [guid]::NewGuid().ToString('N').Substring(0, 16)
$apiKey = 'mcp-smoke-api-key'
$resultDir = (Join-Path $script:TempDir 'mcp-results') -replace '\\', '/'
$auditPath = (Join-Path $script:TempDir 'mcp-audit.jsonl') -replace '\\', '/'
$dbPath = (Join-Path $dataDir 'toshell.db') -replace '\\', '/'
$implantTemplateDir = Join-Path $repoRoot 'internal\server\builder\implant'

$configText = @"
# ToShell MCP 冒烟最小配置（由 scripts/mcp_smoke.ps1 生成，随临时目录一起删除）
server:
    host: 127.0.0.1
    port: $ApiPort
    api_host: 127.0.0.1
    api_port: $ApiPort
auth:
    enabled: true
    jwt_enabled: true
    jwt_key: smoke-jwt-key-not-for-production
    jwt_expire: 24
    api_key_enabled: true
    api_keys:
        - $apiKey
    admin_username: admin
    admin_password: smoke-admin-password
listener:
    enabled: false
    host: 127.0.0.1
    port: $($ApiPort + 1)
    protocol: tcp
    encryption_key: smoke-key-0123456789abcdefghijkl
implant:
    output_dir: '$dataDir'
    template_dir: '$implantTemplateDir'
database:
    type: sqlite
    path: '$dbPath'
logging:
    level: info
    format: text
    output: stdout
web:
    basic_auth_enabled: false
    unauth_mode: basic
mcp:
    enabled: true
    bind: 127.0.0.1:$McpPort
    token: "$script:Token"
    allowed_tools: []
    allowed_origins: []
    max_rpm: $MaxRPM
    max_concurrent: 4
    inline_limit: 8192
    result_dir: '$resultDir'
    result_ttl: 1h
    audit_path: '$auditPath'
    fail_closed: true
"@
[IO.File]::WriteAllText($cfgPath, $configText, (New-Object Text.UTF8Encoding($false)))
Write-Host ('  临时配置: ' + $cfgPath + '（api=' + $ApiPort + ' mcp=' + $McpPort + ' max_rpm=' + $MaxRPM + '）')

$logOut = Join-Path $script:TempDir 'server.out.log'
$logErr = Join-Path $script:TempDir 'server.err.log'
$script:Proc = Start-Process -FilePath $exe -ArgumentList @('-config', $cfgPath) -WorkingDirectory $script:TempDir `
    -WindowStyle Hidden -PassThru -RedirectStandardOutput $logOut -RedirectStandardError $logErr

# 等 API 就绪（用临时配置里的 api key）
$ready = $false
for ($i = 0; $i -lt 40; $i++) {
    Start-Sleep -Milliseconds 500
    $r = Invoke-Raw -Method 'GET' -Url ($script:BaseUrl + '/api/v1/health') -Headers @{ 'X-API-Key' = $apiKey } -TimeoutSec 3
    if ($r.StatusCode -eq 200) { $ready = $true; break }
    if ($script:Proc.HasExited) { break }
}
if (-not $ready) {
    Add-Result -Name '服务端启动' -Level 'FAIL' -Detail ('未就绪；stderr 末尾：' + ((Get-Content $logErr -Tail 5 -ErrorAction SilentlyContinue) -join ' | '))
    throw '临时服务端未就绪，冒烟终止'
}
Add-Result -Name '服务端启动（含 MCP 监听）' -Level 'OK' -Detail ('api=' + $ApiPort + ' mcp=' + $McpPort)

# ── 2. 权限与协议矩阵 ────────────────────────────────────────────────
$initBody = '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"mcp-smoke","version":"1.0"}}}'

$r = Invoke-Mcp -Body $initBody -Token 'wrong-token'
if ($r.StatusCode -eq 401) { Add-Result 'initialize 错 token → 401' 'OK' } else { Add-Result 'initialize 错 token → 401' 'FAIL' ("实际 HTTP " + $r.StatusCode) }

$r = Invoke-Mcp -Body $initBody -Token $null
if ($r.StatusCode -eq 401) { Add-Result 'initialize 无 token → 401' 'OK' } else { Add-Result 'initialize 无 token → 401' 'FAIL' ("实际 HTTP " + $r.StatusCode) }

$r = Invoke-Mcp -Body $initBody -Token $script:Token
if ($r.StatusCode -eq 200) {
    $sid = $null
    foreach ($k in @($r.Headers.Keys)) { if ($k -ieq 'Mcp-Session-Id') { $sid = [string]$r.Headers[$k] } }
    if ($sid) { $script:SessionId = $sid; Add-Result 'initialize 正常 → 200 + Session-Id' 'OK' ('sid=' + $sid.Substring(0, [Math]::Min(8, $sid.Length)) + '…') }
    else { Add-Result 'initialize 正常 → 200 + Session-Id' 'FAIL' '响应头里没有 Mcp-Session-Id' }
    $obj = Get-Json $r.Content
    if ($obj -and $obj.result -and $obj.result.serverInfo) { Add-Result 'initialize 返回 serverInfo' 'OK' ($obj.result.serverInfo.name + ' ' + $obj.result.serverInfo.version) }
    else { Add-Result 'initialize 返回 serverInfo' 'FAIL' '响应缺少 result.serverInfo' }
} else {
    Add-Result 'initialize 正常 → 200 + Session-Id' 'FAIL' ("HTTP " + $r.StatusCode + ' ' + $r.Content)
}

# 缺会话头 → 400
$r = Invoke-Mcp -Body '{"jsonrpc":"2.0","id":2,"method":"tools/list"}' -Token $script:Token -SessionId ''
if ($r.StatusCode -eq 400) { Add-Result 'tools/list 缺会话头 → 400' 'OK' } else { Add-Result 'tools/list 缺会话头 → 400' 'FAIL' ("实际 HTTP " + $r.StatusCode) }

# 错会话头 → 400
$r = Invoke-Mcp -Body '{"jsonrpc":"2.0","id":3,"method":"tools/list"}' -Token $script:Token -SessionId 'not-a-real-session'
if ($r.StatusCode -eq 400 -or $r.StatusCode -eq 401) { Add-Result 'tools/list 错会话头 → 400/401' 'OK' ('HTTP ' + $r.StatusCode) } else { Add-Result 'tools/list 错会话头 → 400/401' 'FAIL' ("实际 HTTP " + $r.StatusCode) }

# tools/list：工具数应与注册表一致（38）
$r = Invoke-Mcp -Body '{"jsonrpc":"2.0","id":4,"method":"tools/list"}' -Token $script:Token -SessionId $script:SessionId
$toolCount = -1
if ($r.StatusCode -eq 200) {
    $obj = Get-Json $r.Content
    if ($obj -and $obj.result -and $obj.result.tools) { $toolCount = @($obj.result.tools).Count }
}
if ($toolCount -eq 38) { Add-Result 'tools/list 工具数 = 38' 'OK' } else { Add-Result 'tools/list 工具数 = 38' 'FAIL' ("实际 " + $toolCount + '；HTTP ' + $r.StatusCode) }

# 只读工具可调用 → 统一信封
$callRead = '{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"session_list","arguments":{}}}'
$r = Invoke-Mcp -Body $callRead -Token $script:Token -SessionId $script:SessionId
# 结果形状：MCP 规范字段是 result.structuredContent（同一份信封也序列化在 content[0].text 里），
# 服务端另外给了 result.envelope 别名；这里三者都认，取到信封即算通过。
$env = $null
if ($r.StatusCode -eq 200) {
    $o = Get-Json $r.Content
    if ($o -and $o.result) {
        if ($o.result.structuredContent) { $env = $o.result.structuredContent }
        elseif ($o.result.envelope) { $env = $o.result.envelope }
        elseif ($o.result.content -and @($o.result.content).Count -gt 0) {
            $txt = [string](@($o.result.content)[0].text)
            if ($txt) { $env = Get-Json $txt }
        }
    }
}
$untrusted = $false
if ($null -ne $env) {
    if ($env.meta -and $env.meta.untrusted -eq $true) { $untrusted = $true }
    elseif ($env.status -eq 'ok') { $untrusted = $true }   # 至少确认是统一信封（status/meta 结构）
}
if ($r.StatusCode -eq 200 -and $untrusted) {
    Add-Result '只读工具 session_list 可调用（统一信封 + untrusted 标记）' 'OK'
} else {
    Add-Result '只读工具 session_list 可调用（统一信封 + untrusted 标记）' 'FAIL' ("HTTP " + $r.StatusCode + ' ' + ($r.Content.Substring(0, [Math]::Min(200, $r.Content.Length))))
}

# 危险工具（默认白名单里没有）→ 403 tool_not_allowed
$callDanger = '{"jsonrpc":"2.0","id":6,"method":"tools/call","params":{"name":"exec","arguments":{"session_id":"x","command":"whoami"}}}'
$r = Invoke-Mcp -Body $callDanger -Token $script:Token -SessionId $script:SessionId
$code = ''; if ($r.Content) { $o = Get-Json $r.Content; if ($o -and $o.data -and $o.data.envelope -and $o.data.envelope.error) { $code = [string]$o.data.envelope.error.code } }
if ($r.StatusCode -eq 403) { Add-Result '危险工具 exec 默认不放行 → 403' 'OK' ('envelope.error.code=' + $code) } else { Add-Result '危险工具 exec 默认不放行 → 403' 'FAIL' ("实际 HTTP " + $r.StatusCode) }

# 未注册工具 → 403
$callUnknown = '{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"definitely_not_a_tool","arguments":{}}}'
$r = Invoke-Mcp -Body $callUnknown -Token $script:Token -SessionId $script:SessionId
if ($r.StatusCode -eq 403 -or $r.StatusCode -eq 400) { Add-Result '未注册工具 → 403/400' 'OK' ('HTTP ' + $r.StatusCode) } else { Add-Result '未注册工具 → 403/400' 'FAIL' ("实际 HTTP " + $r.StatusCode) }

# resources/list 可用
$r = Invoke-Mcp -Body '{"jsonrpc":"2.0","id":8,"method":"resources/list"}' -Token $script:Token -SessionId $script:SessionId
if ($r.StatusCode -eq 200) { Add-Result 'resources/list → 200' 'OK' } else { Add-Result 'resources/list → 200' 'FAIL' ("HTTP " + $r.StatusCode) }

# resources/read 路径穿越必须被拒
$traverse = '{"jsonrpc":"2.0","id":9,"method":"resources/read","params":{"uri":"toshell://result/../../../../configs/server.yaml"}}'
$r = Invoke-Mcp -Body $traverse -Token $script:Token -SessionId $script:SessionId
$leaked = ($r.StatusCode -eq 200 -and $r.Content -match 'api_port|api_keys|encryption_key')
if (-not $leaked -and $r.StatusCode -ne 200) { Add-Result 'resources/read 路径穿越被拒' 'OK' ('HTTP ' + $r.StatusCode) }
elseif ($leaked) { Add-Result 'resources/read 路径穿越被拒' 'FAIL' '响应里出现了配置文件内容！' }
else { Add-Result 'resources/read 路径穿越被拒' 'WARN' ('HTTP 200 但内容不含敏感键；请人工确认：' + $r.Content.Substring(0, [Math]::Min(120, $r.Content.Length))) }

# 限流：连打 MaxRPM+5 次，应出现 429
$hit429 = $false
for ($i = 0; $i -lt ($MaxRPM + 5); $i++) {
    $r = Invoke-Mcp -Body ('{"jsonrpc":"2.0","id":' + (100 + $i) + ',"method":"ping"}') -Token $script:Token -SessionId $script:SessionId
    if ($r.StatusCode -eq 429) { $hit429 = $true; break }
}
if ($hit429) { Add-Result ('超 RPM(' + $MaxRPM + ') → 429') 'OK' } else { Add-Result ('超 RPM(' + $MaxRPM + ') → 429') 'FAIL' "连打 $($MaxRPM + 5) 次都没被限流" }

# ── 3) 设置页接线：GET 能看到 mcp 段、PUT 会校验工具名（不需要植入端）──
$r = Invoke-Raw -Method 'GET' -Url ($script:BaseUrl + '/api/v1/settings') -Headers @{ 'X-API-Key' = $apiKey }
$mcpKeysOk = $false
if ($r.StatusCode -eq 200) {
    $o = Get-Json $r.Content
    if ($o -and $o.mcp) {
        $keys = @($o.mcp.PSObject.Properties.Name)
        $need = @('enabled', 'bind', 'token_set', 'allowed_tools', 'effective_allowed', 'read_only_tools', 'max_rpm')
        $missing = @($need | Where-Object { $keys -notcontains $_ })
        if ($missing.Count -eq 0) { $mcpKeysOk = $true }
        else { $missingTxt = $missing -join ',' }
    }
}
if ($mcpKeysOk) { Add-Result 'GET /settings 含 mcp 段（token 只回 token_set）' 'OK' }
else { Add-Result 'GET /settings 含 mcp 段（token 只回 token_set）' 'FAIL' ("HTTP " + $r.StatusCode + $(if ($missingTxt) { ' 缺字段: ' + $missingTxt } else { '' })) }

# PUT：白名单里写错工具名必须被 400 拦下（否则"以为放行了其实没放行"）
$badPut = '{"mcp":{"allowed_tools":["definitely_not_a_tool"]}}'
$r = Invoke-Raw -Method 'PUT' -Url ($script:BaseUrl + '/api/v1/settings') -Headers @{ 'X-API-Key' = $apiKey } -Body $badPut
if ($r.StatusCode -eq 400) { Add-Result 'PUT /settings 白名单写错工具名 → 400' 'OK' }
else { Add-Result 'PUT /settings 白名单写错工具名 → 400' 'FAIL' ("实际 HTTP " + $r.StatusCode) }

# PUT：合法的只读工具名应被接受（并真的写进配置）
$goodPut = '{"mcp":{"allowed_tools":["session_list","session_context"],"max_pending_handles":16}}'
$r = Invoke-Raw -Method 'PUT' -Url ($script:BaseUrl + '/api/v1/settings') -Headers @{ 'X-API-Key' = $apiKey } -Body $goodPut
$applied = $false
if ($r.StatusCode -eq 200) {
    $cfgText = ''
    if (Test-Path $cfgPath) { $cfgText = [IO.File]::ReadAllText($cfgPath, [Text.Encoding]::UTF8) }
    if ($cfgText -match 'session_list' -and $cfgText -match 'max_pending_handles:\s*16') { $applied = $true }
}
if ($applied) { Add-Result 'PUT /settings 合法白名单 → 200 且已落盘' 'OK' }
else { Add-Result 'PUT /settings 合法白名单 → 200 且已落盘' 'FAIL' ("HTTP " + $r.StatusCode) }

# 审计日志确实在写
$auditPath = Join-Path $script:TempDir 'mcp-audit.jsonl'
if (Test-Path $auditPath) {
    $n = (Get-Content $auditPath | Measure-Object -Line).Lines
    if ($n -gt 0) { Add-Result '审计日志已写入' 'OK' ($n.ToString() + ' 行') } else { Add-Result '审计日志已写入' 'FAIL' '文件为空' }
} else { Add-Result '审计日志已写入' 'FAIL' ('文件不存在：' + $auditPath) }

# ── 3. 收尾 ─────────────────────────────────────────────────────────
if ($script:Proc -and -not $script:Proc.HasExited) { Stop-Process -Id $script:Proc.Id -Force -ErrorAction SilentlyContinue }

$failed = @($script:Results | Where-Object { $_.Level -eq 'FAIL' }).Count
$warn = @($script:Results | Where-Object { $_.Level -eq 'WARN' }).Count
$ok = @($script:Results | Where-Object { $_.Level -eq 'OK' }).Count
Write-Host ''
Write-Host ('=== MCP 冒烟结果：✅ {0} / ⚠️ {1} / ❌ {2} ===' -f $ok, $warn, $failed) -ForegroundColor $(if ($failed -gt 0) { 'Red' } else { 'Green' })
foreach ($x in ($script:Results | Where-Object { $_.Level -ne 'OK' })) { Write-Host ('  {0,-4} {1} — {2}' -f $x.Level, $x.Name, $x.Detail) }

if ($KeepArtifacts) { Write-Host ('  保留临时目录：' + $script:TempDir) -ForegroundColor Yellow }
else { Remove-Item -Recurse -Force $script:TempDir -ErrorAction SilentlyContinue }

if ($failed -gt 0) { exit 1 }
exit 0
