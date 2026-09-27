<#
=====================================================================
 ToShell Team Server —— 傻瓜式部署脚本 (Windows)
 用法（在解压出来的目录里）：
     powershell -ExecutionPolicy Bypass -File .\install.ps1
 常用参数：
     -Check          只检测环境，不安装、不启动（安全，先跑这个）
     -Yes            所有询问自动确认（无人值守）
     -NoStart        只做配置与依赖安装，不启动服务端
     -WithMingw      额外尝试在线安装 MinGW-w64（C 植入端需要，可选）
     -WithGarble     额外安装 garble 混淆器（可选，注意对 Go 版本有要求）
     -OpenFirewall   放行控制台端口与监听端口（需要管理员）
     -GoVersion 1.25.0   指定要安装的 Go 版本（默认取官方最新稳定版）

 它做什么：
   1) 检测运行环境（Go / 网络 / UPX / garble / mingw gcc / 端口 / 磁盘 / 目录权限）
   2) 缺失的依赖可以**在线安装**（Go 从官方源下载并校验 SHA-256；其余按开关可选）
   3) 缺配置时从样例生成 configs\server.yaml
   4) 直接启动打包好的 toserver.exe，并打印控制台地址
=====================================================================
#>
[CmdletBinding()]
param(
  [switch]$Check,
  [switch]$Yes,
  [switch]$NoStart,
  [switch]$WithMingw,
  [switch]$WithGarble,
  [switch]$OpenFirewall,
  [string]$GoVersion = ''
)

$ErrorActionPreference = 'Stop'
try { [Console]::OutputEncoding = [Text.Encoding]::UTF8 } catch {}

# ─── 基础工具 ────────────────────────────────────────────────────────
$Root = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $Root
$Version = 'v1.4.0'
$Results = New-Object System.Collections.ArrayList   # @{Name;Level;Detail}
function Add-Result($name, $level, $detail) {
  [void]$Results.Add([pscustomobject]@{ Name = $name; Level = $level; Detail = $detail })
  $icon = switch ($level) { 'OK' { '[ OK ]' } 'WARN' { '[WARN]' } 'FAIL' { '[FAIL]' } default { '[INFO]' } }
  Write-Host ("{0} {1,-16} {2}" -f $icon, $name, $detail)
}
function Say($msg) { Write-Host $msg }
function Ask($question) {
  if ($Yes -or $Check) { return $false }
  $a = Read-Host "$question [y/N]"
  return ($a -match '^(y|Y|yes|YES)$')
}
function Have($cmd) { return [bool](Get-Command $cmd -ErrorAction SilentlyContinue) }
function IsAdmin {
  try { $id = [Security.Principal.WindowsIdentity]::GetCurrent(); return (New-Object Security.Principal.WindowsPrincipal($id)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) } catch { return $false }
}

Say ""
Say "====================================================================="
Say " ToShell Team Server $Version  ·  一键部署（Windows）"
Say "====================================================================="
Say (" 目录   : {0}" -f $Root)
Say (" 系统   : {0} ({1})" -f ([Environment]::OSVersion.VersionString), $env:PROCESSOR_ARCHITECTURE)
Say (" 管理员 : {0}" -f (IsAdmin))
Say (" 模式   : {0}" -f $(if ($Check) { '仅检测 (-Check)' } else { '检测 → 安装（按需）→ 启动' }))
Say ""

# ─── 0) 服务端二进制 ────────────────────────────────────────────────
$Bin = $null
foreach ($c in @('toserver.exe', 'toserver')) {
  if (Test-Path (Join-Path $Root $c)) { $Bin = Join-Path $Root $c; break }
}
if (-not $Bin) {
  Add-Result '服务端二进制' 'FAIL' "未找到 toserver.exe —— 请先解压完整发布包（本脚本要在包含 toserver.exe 的目录里运行）"
  Say ""
  Say "无法继续：缺少服务端可执行文件。"
  exit 1
}
$binVer = (& $Bin -version 2>&1 | Select-Object -First 1)
Add-Result '服务端二进制' 'OK' ("{0}  ({1})" -f (Split-Path $Bin -Leaf), $binVer)

# ─── 1) 配置文件 ────────────────────────────────────────────────────
$cfgDir = Join-Path $Root 'configs'
$cfg = Join-Path $cfgDir 'server.yaml'
$example = Join-Path $cfgDir 'server.yaml.example'
if (-not (Test-Path $cfg)) {
  if (Test-Path $example) {
    Copy-Item $example $cfg
    Add-Result '配置文件' 'OK' "已从 server.yaml.example 生成 configs\server.yaml（密钥类留空时首次启动会自动生成并落盘）"
  } else {
    Add-Result '配置文件' 'FAIL' "缺少 configs\server.yaml 与样例文件，发布包可能不完整"
  }
} else {
  Add-Result '配置文件' 'OK' "configs\server.yaml 已存在（保留你的现有配置）"
}
$apiPort = 18081; $listenPort = 8080
if (Test-Path $cfg) {
  $lines = Get-Content $cfg
  $txt = $lines -join "`n"
  # api_port 在 server: 段；监听端口只取 listener: 段下的 port:（否则会误取 database.port: 5432）
  foreach ($ln in $lines) {
    if ($ln -match '^\s*api_port:\s*(\d+)') { $apiPort = [int]$Matches[1] }
  }
  $inListener = $false
  foreach ($ln in $lines) {
    if ($ln -match '^([A-Za-z_][A-Za-z0-9_]*):') { $inListener = ($Matches[1] -eq 'listener') }
    elseif ($inListener -and $ln -match '^\s+port:\s*(\d+)') { $listenPort = [int]$Matches[1] }
  }
  if ($txt -notmatch 'listener:' -or $txt -notmatch 'server:') {
    Add-Result '配置内容' 'WARN' '配置里缺少 server:/listener: 段，请检查是否被改坏'
  }
}

# ─── 2) 目录可写 ────────────────────────────────────────────────────
$dataDir = Join-Path $Root 'data'
try {
  New-Item -ItemType Directory -Force -Path $dataDir | Out-Null
  $probe = Join-Path $dataDir '.write_test'
  Set-Content -Path $probe -Value 'ok' -NoNewline
  Remove-Item $probe -Force
  Add-Result '数据目录' 'OK' "data\ 可写（数据库/载荷/工具都会写在这里）"
} catch {
  Add-Result '数据目录' 'FAIL' "data\ 不可写：$($_.Exception.Message)"
}

# ─── 3) 磁盘空间 ────────────────────────────────────────────────────
try {
  $drive = (Get-Item $Root).PSDrive
  $freeGB = [math]::Round((Get-PSDrive $drive.Name).Free / 1GB, 1)
  if ($freeGB -lt 2) { Add-Result '磁盘空间' 'WARN' "剩余 ${freeGB} GB，偏小：构建载荷与工具链需要数 GB" }
  else { Add-Result '磁盘空间' 'OK' "剩余 ${freeGB} GB" }
} catch { Add-Result '磁盘空间' 'INFO' '无法读取磁盘信息' }

# ─── 4) 端口占用 ────────────────────────────────────────────────────
foreach ($p in @($apiPort, $listenPort)) {
  $busy = $null
  try { $busy = Get-NetTCPConnection -LocalPort $p -State Listen -ErrorAction SilentlyContinue } catch {}
  if ($busy) {
    $owner = ($busy | Select-Object -First 1).OwningProcess
    $pname = (Get-Process -Id $owner -ErrorAction SilentlyContinue).ProcessName
    $level = if ($pname -eq 'toserver') { 'WARN' } else { 'WARN' }
    Add-Result "端口 $p" $level "已被占用（PID $owner $pname）—— 若就是本服务端在跑可忽略；否则请改配置或先停止该进程"
  } else {
    Add-Result "端口 $p" 'OK' '空闲'
  }
}

# ─── 5) Go 工具链（构建载荷必需） ───────────────────────────────────
function Get-GoInfo {
  if (-not (Have 'go')) { return $null }
  try {
    $raw = & go version 2>$null
    if ($raw -match 'go(\d+)\.(\d+)(\.\d+)?') {
      return [pscustomobject]@{ Path = (Get-Command go).Source; Major = [int]$Matches[1]; Minor = [int]$Matches[2]; Raw = $raw }
    }
  } catch {}
  return $null
}
$go = Get-GoInfo
if ($go) {
  if ($go.Major -gt 1 -or ($go.Major -eq 1 -and $go.Minor -ge 21)) {
    Add-Result 'Go 工具链' 'OK' "$($go.Raw)  ($($go.Path))"
  } else {
    Add-Result 'Go 工具链' 'FAIL' "$($go.Raw) 过旧：构建载荷需要 Go ≥ 1.21（会自动下载 go1.20.14 工具链编译 Windows 载荷）"
  }
} else {
  Add-Result 'Go 工具链' 'FAIL' '未检测到 go：无法构建植入端载荷（服务端本身仍可运行）'
}

function Install-Go {
  $arch = if ($env:PROCESSOR_ARCHITECTURE -match 'ARM64') { 'arm64' } else { 'amd64' }
  Say "[*] 正在获取 Go 官方版本信息…"
  $rel = Invoke-RestMethod -Uri 'https://go.dev/dl/?mode=json' -TimeoutSec 30
  $stable = $rel | Where-Object { $_.stable -eq $true } | Select-Object -First 1
  if (-not $stable) { throw '无法从 go.dev 获取稳定版本列表（检查网络/代理）' }
  $target = if ($GoVersion) { "go$GoVersion" } else { $stable.version }
  $file = $stable.files | Where-Object { $_.os -eq 'windows' -and $_.arch -eq $arch -and $_.kind -eq 'zip' -and ($_.filename -like "$target.*") } | Select-Object -First 1
  if (-not $file) {
    $file = ($rel | ForEach-Object { $_.files } | Where-Object { $_.os -eq 'windows' -and $_.arch -eq $arch -and $_.kind -eq 'zip' -and ($_.filename -like "$target.*") } | Select-Object -First 1)
  }
  if (-not $file) { throw "找不到 $target windows/$arch 的官方 zip 包" }

  $toolsDir = Join-Path $env:LOCALAPPDATA 'ToShell\tools'
  New-Item -ItemType Directory -Force -Path $toolsDir | Out-Null
  $zip = Join-Path $env:TEMP $file.filename
  Say ("[*] 下载 {0}（{1:N1} MB）…" -f $file.filename, ($file.size / 1MB))
  Invoke-WebRequest -Uri ("https://go.dev/dl/" + $file.filename) -OutFile $zip -TimeoutSec 900
  $sha = (Get-FileHash $zip -Algorithm SHA256).Hash.ToLower()
  if ($sha -ne $file.sha256) { Remove-Item $zip -Force; throw "SHA-256 校验失败：期望 $($file.sha256)，实际 $sha（已删除文件）" }
  Say "[+] SHA-256 校验通过"

  $dest = Join-Path $toolsDir ($file.filename -replace '\.zip$', '')
  if (Test-Path $dest) { Remove-Item $dest -Recurse -Force }
  Say "[*] 解压到 $dest …"
  Expand-Archive -Path $zip -DestinationPath $toolsDir -Force
  Remove-Item $zip -Force
  $goBin = Join-Path $dest 'bin'
  if (-not (Test-Path (Join-Path $goBin 'go.exe'))) { throw "解压后未找到 go.exe（$goBin）" }

  # 当前会话生效
  $env:PATH = "$goBin;$env:PATH"
  # 持久化到用户 PATH（幂等）
  try {
    $userPath = [Environment]::GetEnvironmentVariable('PATH', 'User')
    if ($userPath -notlike "*$goBin*") {
      [Environment]::SetEnvironmentVariable('PATH', ($goBin + ';' + $userPath), 'User')
      Say "[+] 已把 $goBin 写入用户 PATH（新开的终端生效）"
    }
  } catch { Say "[!] 写入用户 PATH 失败（可忽略，本次会话已生效）" }
  return (Join-Path $goBin 'go.exe')
}

if (-not $go -or ($go.Major -eq 1 -and $go.Minor -lt 21)) {
  if ($Check) {
    Say "[i] 仅检测模式：未安装 Go。去掉 -Check 重新运行会从 go.dev 在线下载安装（含 SHA-256 校验）。"
  } elseif (Ask '是否现在从 go.dev 官方源下载并安装 Go？') {
    try { $null = Install-Go; Add-Result 'Go 安装' 'OK' '安装完成（本次会话与用户 PATH 已生效）' }
    catch { Add-Result 'Go 安装' 'FAIL' $_.Exception.Message }
  } else {
    Add-Result 'Go 安装' 'WARN' '已跳过。没有 Go 只能用「下载载荷」——生成载荷需要 Go 工具链'
  }
}

# ─── 6) 模块代理可达性（构建载荷要拉依赖） ──────────────────────────
if (Have 'go') {
  try {
    $env2 = & go env GOPROXY 2>$null
    $proxy = if ($env2) { $env2 } else { 'https://proxy.golang.org,direct' }
    $first = ($proxy -split ',')[0]
    if ($first -match '^https?://') {
      $ok = $false
      try { $r = Invoke-WebRequest -Uri $first -Method Head -TimeoutSec 8 -UseBasicParsing; $ok = $r.StatusCode -lt 500 } catch { $ok = $false }
      if ($ok) { Add-Result '模块代理' 'OK' "$first 可达（GOPROXY=$proxy）" }
      else {
        Add-Result '模块代理' 'WARN' "$first 不可达：生成载荷时需要拉取依赖，建议设置国内代理（go env -w GOPROXY=https://goproxy.cn,direct）"
      }
    }
  } catch { Add-Result '模块代理' 'INFO' '无法检测 GOPROXY' }
  # go1.20.14 工具链（Windows 载荷默认用它编译，保证 Win7/2008R2 兼容）
  try {
    $tc = & go env GOTOOLCHAIN 2>$null
    Add-Result 'GOTOOLCHAIN' 'OK' "$tc（缺少 go1.20.14 时会在首次构建时自动下载）"
  } catch {}
}

# ─── 7) UPX / garble / mingw gcc ────────────────────────────────────
$upx = Join-Path $Root 'upx\win64\upx.exe'
if (Test-Path $upx) { Add-Result 'UPX 压缩' 'OK' "已随包提供：upx\win64\upx.exe（载荷压缩选项可用）" }
elseif (Have 'upx') { Add-Result 'UPX 压缩' 'OK' 'PATH 中的 upx 可用' }
else { Add-Result 'UPX 压缩' 'INFO' '未提供（可选：压缩载荷体积，用不了也不影响其它功能）' }

if (Have 'garble') {
  $gv = (& garble version 2>&1 | Select-Object -First 1)
  Add-Result 'garble 混淆' 'OK' "$gv（与当前 Go 版本不匹配时，控制台会显示「不可用」并给出原因）"
} elseif ($WithGarble) {
  if (Have 'go') {
    Say '[*] 安装 garble（go install mvdan.cc/garble@latest）…'
    try { & go install mvdan.cc/garble@latest 2>&1 | Out-Null; Add-Result 'garble 混淆' 'OK' '安装完成（注意：garble 对 Go 版本有要求，不匹配时界面会提示不可用）' }
    catch { Add-Result 'garble 混淆' 'WARN' "安装失败：$($_.Exception.Message)" }
  } else { Add-Result 'garble 混淆' 'WARN' '需要先装 Go' }
} else {
  Add-Result 'garble 混淆' 'INFO' '未安装（可选：编译期字符串混淆；加 -WithGarble 可在线安装）'
}

# mingw gcc：C 植入端（~60KB）需要；与服务端同款探测顺序
function Find-MingwGcc {
  $cands = New-Object System.Collections.ArrayList
  foreach ($e in @('TOSHELL_MINGW_GCC', 'MINGW_GCC', 'CC')) {
    $v = [Environment]::GetEnvironmentVariable($e)
    if ($v) { [void]$cands.Add($v) }
  }
  foreach ($dir in @("$Root\mingw64\bin", "$Root\mingw32\bin", 'C:\msys64\mingw64\bin', 'C:\msys64\ucrt64\bin', 'C:\msys64\mingw32\bin', 'C:\TDM-GCC-64\bin', 'C:\tools\mingw64\bin')) {
    [void]$cands.Add((Join-Path $dir 'gcc.exe'))
  }
  foreach ($c in $cands) {
    if ($c -and (Test-Path $c)) {
      try {
        $triple = (& $c -dumpmachine 2>$null)
        if ($triple -match 'mingw') { return [pscustomobject]@{ Path = $c; Triple = $triple.Trim() } }
      } catch {}
    }
  }
  if (Have 'gcc') {
    try {
      $t = (& gcc -dumpmachine 2>$null)
      if ($t -match 'mingw') { return [pscustomobject]@{ Path = (Get-Command gcc).Source; Triple = $t.Trim() } }
    } catch {}
  }
  return $null
}
$gcc = Find-MingwGcc
if ($gcc) {
  $bits = if ($gcc.Triple -like 'x86_64*') { '64 位' } else { '32 位' }
  Add-Result 'mingw gcc' 'OK' "$($gcc.Triple)  $($gcc.Path) —— C 植入端可用（产物 $bits PE）"
} else {
  if ($WithMingw) {
    if (Have 'winget') {
      Say '[*] 尝试用 winget 安装 MSYS2（含 mingw-w64 gcc）…'
      try {
        & winget install --id MSYS2.MSYS2 -e --accept-source-agreements --accept-package-agreements 2>&1 | Out-Host
        Add-Result 'mingw gcc' 'WARN' 'MSYS2 安装已发起：装完后执行 pacman -S mingw-w64-x86_64-gcc，再刷新控制台页面'
      } catch { Add-Result 'mingw gcc' 'WARN' "winget 安装失败：$($_.Exception.Message)" }
    } elseif (Have 'choco') {
      Say '[*] 尝试用 chocolatey 安装 mingw…'
      try { & choco install mingw -y 2>&1 | Out-Host; Add-Result 'mingw gcc' 'WARN' 'choco 安装已发起，装完请刷新控制台页面' }
      catch { Add-Result 'mingw gcc' 'WARN' "choco 安装失败：$($_.Exception.Message)" }
    } else {
      Add-Result 'mingw gcc' 'WARN' '本机没有 winget/choco：请手动安装 MSYS2（https://www.msys2.org/）后执行 pacman -S mingw-w64-x86_64-gcc'
    }
  } else {
    Add-Result 'mingw gcc' 'INFO' '未检测到（可选：只有 C 植入端需要；加 -WithMingw 可尝试在线安装，或把便携 MinGW 解压到本目录 mingw64\bin）'
  }
}

# ─── 8) 防火墙（可选） ──────────────────────────────────────────────
if ($OpenFirewall) {
  if (-not (IsAdmin)) {
    Add-Result '防火墙放行' 'WARN' '需要管理员权限，已跳过（请以管理员身份重跑 -OpenFirewall）'
  } else {
    foreach ($p in @($apiPort, $listenPort)) {
      try {
        & netsh advfirewall firewall add rule name="ToShell $p" dir=in action=allow protocol=TCP localport=$p 2>&1 | Out-Null
        Add-Result "防火墙 $p" 'OK' '已放行 TCP 入站'
      } catch { Add-Result "防火墙 $p" 'WARN' "放行失败：$($_.Exception.Message)" }
    }
  }
} else {
  Add-Result '防火墙' 'INFO' "未改动（生产环境请自行放行 $apiPort 控制台端口与 $listenPort 监听端口：可加 -OpenFirewall）"
}

# ─── 汇总 ───────────────────────────────────────────────────────────
Say ""
Say "───────────────── 环境检测汇总 ─────────────────"
$fails = @($Results | Where-Object { $_.Level -eq 'FAIL' })
$warns = @($Results | Where-Object { $_.Level -eq 'WARN' })
Say (" 通过 {0} · 警告 {1} · 失败 {2}" -f (@($Results | Where-Object { $_.Level -eq 'OK' }).Count), $warns.Count, $fails.Count)
if ($fails.Count) { Say " 必须处理："; $fails | ForEach-Object { Say ("   - {0}：{1}" -f $_.Name, $_.Detail) } }
if ($warns.Count) { Say " 建议处理："; $warns | ForEach-Object { Say ("   - {0}：{1}" -f $_.Name, $_.Detail) } }

if ($Check) {
  Say ""
  Say "[i] 仅检测模式结束。去掉 -Check 重新运行即可按需安装依赖并启动服务端。"
  exit 0
}

if ($fails.Count -and ($fails | Where-Object { $_.Name -eq '服务端二进制' })) { Say ""; Say '缺少服务端二进制，终止。'; exit 1 }

# ─── 启动服务端 ─────────────────────────────────────────────────────
if ($NoStart) {
  Say ""
  Say "[i] -NoStart：已跳过启动。手动启动命令："
  Say ("    .\toserver.exe -config configs\server.yaml")
  exit 0
}

Say ""
if (Ask "现在启动 ToShell Team Server？（控制台 http://localhost:$apiPort）") {
  $log = Join-Path $Root 'server.log'
  Say "[*] 启动中…（日志同时写入 server.log；关闭这个窗口/结束进程即停止服务端）"
  Say ""
  Say "  控制台 : http://localhost:$apiPort"
  Say "  监听   : 0.0.0.0:$listenPort（植入端回连）"
  Say "  首次启动会在日志里打印自动生成的 admin 密码 / JWT key / 加密 key（并落盘到 configs\server.yaml）"
  Say "  停止   : 在本窗口按 Ctrl+C"
  Say ""
  & $Bin -config (Join-Path 'configs' 'server.yaml') 2>&1 | Tee-Object -FilePath $log -Append
} else {
  Say "[i] 已跳过启动。手动启动：  .\toserver.exe -config configs\server.yaml"
}
