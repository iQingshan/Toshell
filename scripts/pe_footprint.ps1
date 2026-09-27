# 交付前 PE 静态体检（节表 / 熵 / 时间戳 / 资源 / overlay）——纯 PowerShell，无外部依赖
# 用法: powershell -NoProfile -File scripts/pe_footprint.ps1 -Path .\release\implants\xxx.exe
#
# v1.4.0 S3 第二批追加：打印 .rsrc 里的**资源细节**（公司名/产品名/文件描述/文件版本/
# 图标个数/时间戳可读形式），口径与 internal/server/builder/patch_resources.go 的
# ReadPEResourceInfo 一致（同一份目录树与 VS_VERSIONINFO 结构）。
# 注意：本文件是 UTF-8 **带 BOM**（PS 5.1 不带 BOM 会按 ANSI 解析中文而乱码）——
# 改完务必确认首三字节仍是 EF BB BF。
[CmdletBinding()]
param([Parameter(Mandatory = $true)][string]$Path)

$ErrorActionPreference = 'Stop'
$b = [IO.File]::ReadAllBytes((Resolve-Path -LiteralPath $Path).Path)
$script:Bytes = $b

function Get-U32([int]$off) { [BitConverter]::ToUInt32($b, $off) }
function Get-U16([int]$off) { [BitConverter]::ToUInt16($b, $off) }

if ($b[0] -ne 0x4D -or $b[1] -ne 0x5A) { Write-Host '不是 MZ/PE 文件'; exit 1 }
$pe = Get-U32 0x3C
if ([Text.Encoding]::ASCII.GetString($b, $pe, 4) -ne "PE`0`0") { Write-Host '不是 PE32/PE32+ 文件'; exit 1 }

$nSec = Get-U16 ($pe + 6)
$optSize = Get-U16 ($pe + 20)
$ts = Get-U32 ($pe + 8)
$secOff = $pe + 24 + $optSize
$opt = $pe + 24
$is64 = ((Get-U16 $opt) -eq 0x20B)
$ddOff = if ($is64) { $opt + 112 } else { $opt + 96 }

function Get-Entropy([byte[]]$data) {
    if (-not $data -or $data.Length -eq 0) { return 0.0 }
    $counts = New-Object 'int[]' 256
    foreach ($x in $data) { $counts[$x]++ }
    $n = [double]$data.Length
    $h = 0.0
    foreach ($c in $counts) { if ($c -gt 0) { $p = $c / $n; $h -= $p * [Math]::Log($p, 2) } }
    return $h
}

# RVA → 文件偏移（节表映射；越界返回 -1）。
function Get-RvaOffset([uint32]$rva) {
    for ($i = 0; $i -lt $nSec; $i++) {
        $s = $secOff + $i * 40
        $srva = Get-U32 ($s + 12); $vsz = Get-U32 ($s + 8); $rsz = Get-U32 ($s + 16); $rp = Get-U32 ($s + 20)
        $len = [Math]::Max($vsz, $rsz)
        if ($rva -ge $srva -and $rva -lt ($srva + $len)) { return [int]($rp + ($rva - $srva)) }
    }
    return -1
}

# 读 IMAGE_RESOURCE_DIRECTORY 的条目（返回 id + 是否子目录 + 相对资源目录起点的偏移）。
function Get-ResDirEntries([int]$off) {
    $out = @()
    $named = Get-U16 ($off + 12); $ids = Get-U16 ($off + 14)
    for ($i = 0; $i -lt ($named + $ids); $i++) {
        $p = $off + 16 + $i * 8
        $raw = Get-U32 ($p + 4)
        $out += [pscustomobject]@{
            Id    = Get-U32 $p
            IsDir = (($raw -band 0x80000000) -ne 0)
            Off   = [int]($raw -band 0x7FFFFFFF)
        }
    }
    return , $out
}

# 递归解析 VS_VERSIONINFO：depth 3（String 层）收集"键 → 值"。
function Read-VsBlock([int]$off, [int]$depth, $acc) {
    $wLength = Get-U16 $off; $wValueLength = Get-U16 ($off + 2); $wType = Get-U16 ($off + 4)
    $blockEnd = $off + $wLength
    if ($wLength -lt 6 -or $blockEnd -gt $b.Length) { return }
    $k = $off + 6; $end = $k
    while ($end + 1 -lt $blockEnd) { if ($b[$end] -eq 0 -and $b[$end + 1] -eq 0) { break }; $end += 2 }
    $key = [Text.Encoding]::Unicode.GetString($b, $k, $end - $k)
    $p = $off + ((($end + 2 - $off) + 3) -band -4)
    $vbytes = if ($wType -eq 1) { $wValueLength * 2 } else { $wValueLength }
    if ($depth -eq 3 -and $vbytes -gt 0 -and ($p + $vbytes) -le $b.Length) {
        $acc[$key] = ([Text.Encoding]::Unicode.GetString($b, $p, $vbytes)).TrimEnd([char]0)
    }
    $q = $off + ((($p - $off) + $vbytes + 3) -band -4)
    while ($q + 6 -le $blockEnd) {
        $childLen = Get-U16 $q
        if ($childLen -lt 6 -or ($q + $childLen) -gt $blockEnd) { break }
        Read-VsBlock $q ($depth + 1) $acc
        $q = $off + ((($q - $off) + $childLen + 3) -band -4)
    }
}

Write-Host ("文件: {0}（{1} 字节）" -f (Split-Path -Leaf $Path), $b.Length)
$tsText = if ($ts -eq 0) { '0（链接器置零/未覆盖）' } else {
    '{0}（{1} UTC）' -f $ts, ([DateTimeOffset]::FromUnixTimeSeconds($ts).UtcDateTime.ToString('yyyy-MM-dd HH:mm:ss'))
}
Write-Host ("TimeDateStamp = {0}" -f $tsText)
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

# ── 资源细节（v1.4.0 S3 第二批）──────────────────────────────────────────────
$resRva = Get-U32 ($ddOff + 16)   # 数据目录 index 2 = IMAGE_DIRECTORY_ENTRY_RESOURCE
Write-Host ("DataDirectory[2]（资源）RVA = 0x{0:X}" -f $resRva)
if ($resRva -eq 0) {
    Write-Host '资源细节: 无（未注入版本信息/图标）'
    exit 0
}
$resBase = Get-RvaOffset $resRva
if ($resBase -lt 0) { Write-Host "资源细节: 资源目录 RVA 0x$('{0:X}' -f $resRva) 不落在任何节内（结构可疑）"; exit 0 }
try {
    $version = @{}
    $iconCount = 0; $groupIconCount = 0
    foreach ($t in (Get-ResDirEntries $resBase)) {
        if (-not $t.IsDir) { continue }
        foreach ($n in (Get-ResDirEntries ($resBase + $t.Off))) {
            if (-not $n.IsDir) { continue }
            foreach ($l in (Get-ResDirEntries ($resBase + $n.Off))) {
                $de = $resBase + $l.Off
                $dataRva = Get-U32 $de; $dataSize = Get-U32 ($de + 4)
                $dataOff = Get-RvaOffset $dataRva
                if ($t.Id -eq 3) { $iconCount++ }                        # RT_ICON
                elseif ($t.Id -eq 14) { $groupIconCount++ }              # RT_GROUP_ICON
                elseif ($t.Id -eq 16 -and $dataOff -ge 0) {              # RT_VERSION
                    Read-VsBlock $dataOff 0 $version
                }
            }
        }
    }
    Write-Host ("资源: RT_VERSION={0} RT_ICON={1} RT_GROUP_ICON={2}" -f $version.Count, $iconCount, $groupIconCount)
    foreach ($k in @('CompanyName', 'ProductName', 'FileDescription', 'FileVersion', 'ProductVersion',
                     'LegalCopyright', 'OriginalFilename', 'InternalName')) {
        $v = if ($version.ContainsKey($k)) { $version[$k] } else { '<未写入>' }
        Write-Host ("  {0,-17} = {1}" -f $k, $v)
    }
} catch {
    Write-Host ("资源细节解析失败（脚本口径与 patch_resources.go 可能不一致）: {0}" -f $_.Exception.Message)
}
