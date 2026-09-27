# 交付前 PE 静态体检（节表 / 熵 / 时间戳 / 资源 / overlay）——纯 PowerShell，无外部依赖
# 用法: powershell -NoProfile -File scripts/pe_footprint.ps1 -Path .\release\implants\xxx.exe
[CmdletBinding()]
param([Parameter(Mandatory = $true)][string]$Path)

$ErrorActionPreference = 'Stop'
$b = [IO.File]::ReadAllBytes((Resolve-Path -LiteralPath $Path).Path)

function Get-U32([int]$off) { [BitConverter]::ToUInt32($b, $off) }
function Get-U16([int]$off) { [BitConverter]::ToUInt16($b, $off) }

if ($b[0] -ne 0x4D -or $b[1] -ne 0x5A) { Write-Host '不是 MZ/PE 文件'; exit 1 }
$pe = Get-U32 0x3C
if ([Text.Encoding]::ASCII.GetString($b, $pe, 4) -ne "PE`0`0") { Write-Host '不是 PE32/PE32+ 文件'; exit 1 }

$nSec = Get-U16 ($pe + 6)
$optSize = Get-U16 ($pe + 20)
$ts = Get-U32 ($pe + 8)
$secOff = $pe + 24 + $optSize

function Get-Entropy([byte[]]$data) {
    if (-not $data -or $data.Length -eq 0) { return 0.0 }
    $counts = New-Object 'int[]' 256
    foreach ($x in $data) { $counts[$x]++ }
    $n = [double]$data.Length
    $h = 0.0
    foreach ($c in $counts) { if ($c -gt 0) { $p = $c / $n; $h -= $p * [Math]::Log($p, 2) } }
    return $h
}

Write-Host ("文件: {0}（{1} 字节）" -f (Split-Path -Leaf $Path), $b.Length)
Write-Host ("TimeDateStamp = {0}{1}" -f $ts, $(if ($ts -eq 0) { '（0=链接器置零，正常）' } else { '' }))
Write-Host '节表（名称 / 虚拟大小 / 原始大小 / 熵）:'
$end = 0
$hasRsrc = $false
for ($i = 0; $i -lt $nSec; $i++) {
    $s = $secOff + $i * 40
    $name = [Text.Encoding]::ASCII.GetString($b, $s, 8).TrimEnd([char]0)
    $vsize = Get-U32 ($s + 8); $rsize = Get-U32 ($s + 16); $rptr = Get-U32 ($s + 20)
    if ($name -eq '.rsrc') { $hasRsrc = $true }
    $body = if ($rsize -gt 0 -and ($rptr + $rsize) -le $b.Length) { $b[$rptr..($rptr + $rsize - 1)] } else { @() }
    Write-Host ("  {0,-9} {1,10} {2,10}   {3:N2}" -f $name, $vsize, $rsize, (Get-Entropy $body))
    if (($rptr + $rsize) -gt $end) { $end = $rptr + $rsize }
}
Write-Host ("overlay = {0} 字节（配置块等追加数据；0 表示没有）" -f ($b.Length - $end))
Write-Host ("含 .rsrc（版本信息/图标/manifest）: {0}" -f $hasRsrc)
