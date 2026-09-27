# =====================================================================
#  ToShell 免杀验收矩阵：记录与汇总（v1.4.0 S3 的 V0 元项）
#
#  为什么需要它：免杀改动的效果**只能在一台被授权使用的目标机上实测**，
#  而"我改完好像更隐蔽了"这种结论没有任何价值。这个脚本把验收过程固定下来：
#    一次只改一个变量 / 每个样本至少 3 次 / 记录拦截原文与时间线 / 结果落表；
#  并把结果汇总成可直接贴进 CHANGELOG 或写进 docs/EVASION.md 的 markdown 表格。
#
#  ⚠️ 这个脚本**只做记录与前置环境体检，绝不生成、绝不执行任何载荷**。
#     执行样本是你的动作，且必须发生在你有书面授权的目标机上。
#
#  用法：
#    # 1) 前置体检（只读，安全，随便跑）
#    powershell -NoProfile -ExecutionPolicy Bypass -File scripts/evasion_matrix.ps1 -Preflight
#
#    # 2) 记录一轮观测（交互式填字段，写入 CSV + 生成 markdown 汇总）
#    powershell ... -File scripts/evasion_matrix.ps1 -Record -Case E-L0-2 -Env win10-defender -Repeat 3 `
#        -Variant "exe-signed-selfsigned" -Verdict blocked `
#        -Evidence "进程创建阶段 Access is denied + 文件被删除" -Online $false
#
#    # 3) 只渲染已有记录的汇总表
#    powershell ... -File scripts/evasion_matrix.ps1 -Report
# =====================================================================
[CmdletBinding(DefaultParameterSetName = 'Preflight')]
param(
    # 只读前置体检：本机（或目标机）的签名策略/驱动黑名单/Defender/样本存在性
    [Parameter(ParameterSetName = 'Preflight')][switch]$Preflight,
    # 记录一轮观测
    [Parameter(ParameterSetName = 'Record')][switch]$Record,
    # 渲染汇总
    [Parameter(ParameterSetName = 'Report')][switch]$Report,

    [Parameter(ParameterSetName = 'Record')][string]$Case = '',
    [Parameter(ParameterSetName = 'Record')][string]$Env = '',
    [Parameter(ParameterSetName = 'Record')][string]$Variant = '',
    [Parameter(ParameterSetName = 'Record')][int]$Repeat = 3,
    # blocked | ran_then_killed | ran_no_beacon | beacon_ok | error
    [Parameter(ParameterSetName = 'Record')][string]$Verdict = '',
    [Parameter(ParameterSetName = 'Record')][string]$Evidence = '',
    [Parameter(ParameterSetName = 'Record')][string]$DefenderEvents = '',
    [Parameter(ParameterSetName = 'Record')][string]$Sample = '',
    [Parameter(ParameterSetName = 'Record')][string]$Operator = '',
    # 是否成功回连：true/false 或留空（留空=未观测）。
    # 刻意用字符串而不是 [switch]/[Nullable[bool]]：从命令行以 `-File` 传参时布尔字面量
    # 会被当成字符串，绑定到 Nullable[bool] 会直接失败（实测报 Cannot convert "System.String"）。
    [Parameter(ParameterSetName = 'Record')][string]$Online = ''
)

$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent $PSScriptRoot
$resultsDir = Join-Path $repoRoot 'docs\evasion-results'
$csvPath = Join-Path $resultsDir 'matrix.csv'

# ── 固定用例表：与 docs/EVASION.md 的三类口径一一对应 ──────────────────
# Layer: L0=签名/信誉/策略层, L1=落地(delivery), D=动态免杀, S=静态降特征
$script:Cases = @(
    @{ Id = 'E-L0-1'; Layer = 'L0'; Desc = '未签名 PE 直接运行（基线：证明"被拦在哪一层"）' },
    @{ Id = 'E-L0-2'; Layer = 'L0'; Desc = '签名后运行（自签 + 目标机导入受信任根）' },
    @{ Id = 'E-L0-3'; Layer = 'L0'; Desc = '签名后运行（真实证书 / EV）' },
    @{ Id = 'E-L1-1'; Layer = 'L1'; Desc = '白加黑：签名宿主 DLL 侧加载' },
    @{ Id = 'E-L1-2'; Layer = 'L1'; Desc = '计划任务 + 已签名宿主加载' },
    @{ Id = 'E-L1-3'; Layer = 'L1'; Desc = 'rundll32 / mshta / certutil 链' },
    @{ Id = 'E-L1-4'; Layer = 'L1'; Desc = '内存加载（不落 PE）：shellcode / BOF' },
    @{ Id = 'E-D-1';  Layer = 'D';  Desc = 'sleep mask：休眠窗口内搜不到明文密钥/结果' },
    @{ Id = 'E-D-2';  Layer = 'D';  Desc = '去 RWX：进程内不存在同时可写可执行的私有无映像内存' },
    @{ Id = 'E-D-3';  Layer = 'D';  Desc = '休眠节奏：不再是固定周期的 Sleep(大值)' },
    @{ Id = 'E-D-4';  Layer = 'D';  Desc = '上行/下行隧道在 sleep mask 期间不损坏（回归）' },
    @{ Id = 'E-S-1';  Layer = 'S';  Desc = '默认载荷高信号明文归零（beacon*/Go buildinf/构建 ID）' },
    @{ Id = 'E-S-2';  Layer = 'S';  Desc = 'PE 版本资源/图标/时间戳外观' }
)

function Write-Head($t) { Write-Host ''; Write-Host "=== $t ===" -ForegroundColor Cyan }

# ── 1) 前置体检（只读）──────────────────────────────────────────────
function Invoke-Preflight {
    Write-Head '免杀验收：本机前置体检（只读，不执行任何载荷）'
    Write-Host '⚠️ 以下信息只在**你拥有书面授权**的目标机上采集；本脚本不上传、不联网。' -ForegroundColor Yellow

    $rows = New-Object System.Collections.ArrayList
    function Add-Row($k, $v, $note = '') {
        [void]$rows.Add([pscustomobject]@{ 项 = $k; 值 = $v; 说明 = $note })
    }

    $os = Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue
    Add-Row 'OS' ("{0} build {1}" -f $os.Caption, $os.BuildNumber) '版本号决定可用的规避手段（如 Win10+ 才有 DXGI 捕获）'
    Add-Row 'PowerShell' $PSVersionTable.PSVersion.ToString() ''

    # 签名/信誉层的关键策略（这些直接决定"能不能跑起来"）
    $ci = 'HKLM:\SYSTEM\CurrentControlSet\Control\CI\Config'
    $vdm = $null
    try { $vdm = (Get-ItemProperty -Path $ci -Name VulnerableDriverBlocklistEnable -ErrorAction Stop).VulnerableDriverBlocklistEnable } catch { }
    Add-Row '易受攻击驱动黑名单' $(if ($null -eq $vdm) { '未设置' } else { $vdm }) '启用时内核会静默拒绝名单内驱动（StartService 报 1275）'

    $hvci = $null
    try { $hvci = (Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity' -Name Enabled -ErrorAction Stop).Enabled } catch { }
    Add-Row 'HVCI (内存完整性)' $(if ($null -eq $hvci) { '未设置/未启用' } else { $hvci }) '启用后"可写+可执行"内存与部分驱动手段都会被拒'

    $dgRunning = (Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard -ErrorAction SilentlyContinue)
    if ($dgRunning) {
        Add-Row 'VBS 状态' ("SecurityServicesRunning=" + ($dgRunning.SecurityServicesRunning -join ',')) '2=HVCI；1=Credential Guard'
    }

    $mp = Get-MpComputerStatus -ErrorAction SilentlyContinue
    if ($mp) {
        Add-Row 'Defender 实时防护' $mp.RealTimeProtectionEnabled ''
        Add-Row 'Defender 反恶意软件版本' $mp.AMEngineVersion ''
    } else {
        Add-Row 'Defender' '未安装/不可查（可能被第三方杀软接管）' '国产杀软接管时 Defender 事件日志可能为空，需看杀软自己的拦截记录'
    }

    # 第三方安全软件（决定验收结论该记到哪一层）
    $av = Get-Process -ErrorAction SilentlyContinue | Where-Object { $_.ProcessName -match '360|ZhuDongFangYu|QQPC|Huorong|wsctrl|usysdiag|kxescore|kislive|baidu|Kingsoft' } |
        Select-Object -Expand ProcessName -Unique
    Add-Row '第三方安全软件进程' $(if ($av) { ($av -join ', ') } else { '（未发现）' }) '这些产品的主动防御会在"进程创建/行为"层拦截，与文件特征无关'

    $samples = @()
    if (Test-Path (Join-Path $repoRoot 'release\implants')) {
        $samples = Get-ChildItem (Join-Path $repoRoot 'release\implants') -File -ErrorAction SilentlyContinue | Select-Object -Expand Name
    }
    Add-Row '本机待测样本' $(if ($samples) { ($samples -join ', ') } else { '（release\implants 为空）' }) '本机杀软会删除新生成的 PE，样本通常需要从构建机拷到目标机'

    $rows | Format-Table -AutoSize
    Write-Host ''
    Write-Host '判读口径（写结论时必须先回答"被拦在哪一层"）：' -ForegroundColor Cyan
    Write-Host '  · 进程创建阶段就被拒（Access is denied / 文件被删）      → L0 签名/信誉/策略层 → 只能靠签名或换落地方式'
    Write-Host '  · 落地后几秒内被杀、或杀软弹窗                           → L3 运行期行为层 → 动态免杀'
    Write-Host '  · 静态扫描命中（无执行也报毒）                           → L2 静态特征层 → 静态降特征'
    Write-Host '  · 能跑但内存被扫描/被 EDR 摘除                           → L4 内存/EDR 层 → sleep mask、去 RWX 等'
    Write-Host ''
    Write-Host '每个用例都要记录：环境、样本变体、重复次数、拦截原文、Defender 事件号(1116/1117)、是否上线。' -ForegroundColor Gray
    Write-Host '记录命令示例：' -ForegroundColor Gray
    Write-Host '  powershell -File scripts/evasion_matrix.ps1 -Record -Case E-L0-2 -Env win10-defender -Variant exe-signed-selfsigned -Verdict beacon_ok -Evidence "无拦截，30s 内上线" -Online $true' -ForegroundColor Gray
}

# ── 2) 记录一轮观测 ────────────────────────────────────────────────
function Invoke-Record {
    if (-not $Case) { throw '-Record 需要 -Case（见脚本内用例表，例如 E-L0-2）' }
    $known = $script:Cases | Where-Object { $_.Id -eq $Case }
    if (-not $known) {
        $ids = ($script:Cases | Select-Object -Expand Id) -join ', '
        throw ("未知用例 {0}。可用：{1}" -f $Case, $ids)
    }
    $verdicts = @('blocked', 'ran_then_killed', 'ran_no_beacon', 'beacon_ok', 'error')
    if ($Verdict -and $verdicts -notcontains $Verdict) {
        throw ("-Verdict 只能是：{0}" -f ($verdicts -join ' / '))
    }
    New-Item -ItemType Directory -Force -Path $resultsDir | Out-Null

    # 归一化 Online：true/1/yes → True；false/0/no → False；其它/空 → 空（未观测）
    $onlineNorm = ''
    switch -Regex ($Online.Trim().ToLower()) {
        '^(true|1|yes|y)$' { $onlineNorm = 'True' }
        '^(false|0|no|n)$' { $onlineNorm = 'False' }
        default { $onlineNorm = '' }
    }

    $row = [pscustomobject]@{
        ts              = (Get-Date).ToString('s')
        case_id         = $Case
        layer           = $known.Layer
        case_desc       = $known.Desc
        env             = $Env
        variant         = $Variant
        repeat          = $Repeat
        verdict         = $Verdict
        online          = $onlineNorm
        sample          = $Sample
        evidence        = $Evidence
        defender_events = $DefenderEvents
        operator        = $(if ($Operator) { $Operator } else { $env:USERNAME })
    }
    $exists = Test-Path $csvPath
    $row | Export-Csv -Path $csvPath -NoTypeInformation -Append -Encoding UTF8
    Write-Host ("已记录：{0} {1} → {2}" -f $Case, $Variant, $Verdict) -ForegroundColor Green
    Write-Host ("CSV: {0}{1}" -f $csvPath, $(if (-not $exists) { '（新建）' } else { '' })) -ForegroundColor Gray
    if (-not $Verdict) {
        Write-Host '⚠️ 未填 -Verdict：这行只是"观测占位"，请在拿到结论后补一条。' -ForegroundColor Yellow
    }
    Invoke-Report
}

# ── 3) 汇总渲染（markdown + 控制台）────────────────────────────────
function Invoke-Report {
    if (-not (Test-Path $csvPath)) {
        Write-Host '还没有任何记录（matrix.csv 不存在）。先跑 -Record。' -ForegroundColor Yellow
        return
    }
    $rows = Import-Csv -Path $csvPath
    Write-Head ("免杀验收矩阵汇总（{0} 条记录）" -f @($rows).Count)

    # 每个用例只看"最近一次"，避免同一用例多轮观测把表撑爆
    $latest = @{}
    foreach ($r in $rows) { $latest[$r.case_id] = $r }

    $md = New-Object System.Collections.ArrayList
    [void]$md.Add('| 用例 | 层 | 说明 | 环境 | 样本变体 | 次数 | 结论 | 上线 | 证据 |')
    [void]$md.Add('|---|---|---|---|---|---|---|---|---|')
    $verdictCn = @{
        'blocked'          = '❌ 被拦'
        'ran_then_killed'  = '⚠️ 跑起来又被杀'
        'ran_no_beacon'    = '⚠️ 跑起来但未回连'
        'beacon_ok'        = '✅ 上线成功'
        'error'            = '❓ 过程出错'
        ''                 = '（未填）'
    }
    foreach ($c in $script:Cases) {
        $r = $latest[$c.Id]
        if (-not $r) {
            [void]$md.Add(("| {0} | {1} | {2} | — | — | — | 未测 | — | — |" -f $c.Id, $c.Layer, $c.Desc))
            continue
        }
        $v = $verdictCn[$r.verdict]
        if (-not $v) { $v = $r.verdict }
        [void]$md.Add(("| {0} | {1} | {2} | {3} | {4} | {5} | {6} | {7} | {8} |" -f `
                    $c.Id, $c.Layer, $c.Desc, $r.env, $r.variant, $r.repeat, $v, $r.online, ($r.evidence -replace '\|', '/')))
    }

    $mdPath = Join-Path $resultsDir 'summary.md'
    $header = @(
        '# 免杀验收矩阵（自动生成）',
        '',
        ('> 生成时间：{0}　记录数：{1}　脚本：`scripts/evasion_matrix.ps1`' -f (Get-Date).ToString('s'), @($rows).Count),
        '> **口径**：一次只改一个变量；每个样本至少重复 3 次；必须记录拦截原文与 Defender 事件号；"未测"不等于"通过"。',
        ''
    )
    [IO.File]::WriteAllLines($mdPath, ($header + $md), (New-Object Text.UTF8Encoding($true)))
    $md -join "`n" | Write-Host
    Write-Host ''
    Write-Host ("已写入：{0}" -f $mdPath) -ForegroundColor Green
    Write-Host '提示：把表里"未测"的用例逐条补上，再把结论回填 docs/EVASION.md 与 CHANGELOG。' -ForegroundColor Gray
}

switch ($PSCmdlet.ParameterSetName) {
    'Preflight' { Invoke-Preflight }
    'Record' { Invoke-Record }
    'Report' { Invoke-Report }
}
