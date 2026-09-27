# =====================================================================
#  ToShell v1.4.0 local packaging: mirrors .github/workflows/release.yml
#  Output: release/release-zips/toshell-server-<os>-<arch>.zip (6 targets)
# =====================================================================
$ErrorActionPreference = 'Stop'
$base = Split-Path -Parent $PSScriptRoot
Set-Location $base

$version = '1.4.0'
$commit = (git rev-parse --short HEAD)
$buildTime = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
$ldflags = "-s -w -X main.version=$version -X main.commit=$commit -X main.buildTime=$buildTime"

$matrix = @(
  @{ goos='windows'; goarch='amd64'; ext='.exe'; deploy='release/deploy.bat'; zip='toshell-server-windows-amd64.zip' },
  @{ goos='windows'; goarch='386';   ext='.exe'; deploy='release/deploy.bat'; zip='toshell-server-windows-386.zip' },
  @{ goos='linux';   goarch='amd64'; ext='';     deploy='release/deploy.sh';  zip='toshell-server-linux-amd64.zip' },
  @{ goos='linux';   goarch='arm64'; ext='';     deploy='release/deploy.sh';  zip='toshell-server-linux-arm64.zip' },
  @{ goos='darwin';  goarch='amd64'; ext='';     deploy='release/deploy.sh';  zip='toshell-server-darwin-amd64.zip' },
  @{ goos='darwin';  goarch='arm64'; ext='';     deploy='release/deploy.sh';  zip='toshell-server-darwin-arm64.zip' }
)

$zipDir = Join-Path $base 'release\release-zips'
New-Item -ItemType Directory -Force -Path $zipDir | Out-Null

Add-Type -AssemblyName System.IO.Compression
Add-Type -AssemblyName System.IO.Compression.FileSystem

foreach ($m in $matrix) {
  $bin = Join-Path $base ("toserver" + $m.ext)
  Write-Host "== build $($m.goos)/$($m.goarch) ==" -ForegroundColor Cyan
  $env:GOOS = $m.goos
  $env:GOARCH = $m.goarch
  $env:CGO_ENABLED = '0'
  & go build -tags webui -ldflags $ldflags -o $bin ./cmd/server
  if ($LASTEXITCODE -ne 0) { throw "build failed for $($m.goos)/$($m.goarch)" }

  # Assemble staging directory in TEMP (NOT repo pkg/ — that is tracked Go source!)
  $pkg = Join-Path $env:TEMP ("tsh-pkg-" + $PID + "-" + $m.goos + "-" + $m.goarch)
  if (Test-Path $pkg) { Remove-Item -Recurse -Force $pkg }
  New-Item -ItemType Directory -Force -Path $pkg | Out-Null
  Copy-Item $bin (Join-Path $pkg ('toserver' + $m.ext))
  Copy-Item -Recurse (Join-Path $base 'release\implant')  (Join-Path $pkg 'implant')
  Copy-Item -Recurse (Join-Path $base 'release\implant_c') (Join-Path $pkg 'implant_c')
  New-Item -ItemType Directory -Force -Path (Join-Path $pkg 'configs') | Out-Null
  Copy-Item (Join-Path $base 'configs\server.yaml.example') (Join-Path $pkg 'configs\server.yaml.example')
  Copy-Item (Join-Path $base 'README.md') (Join-Path $pkg 'README.md')
  Copy-Item (Join-Path $base 'USAGE.md')  (Join-Path $pkg 'USAGE.md')
  # 文档目录必须随包分发：README/USAGE 里大量链接指向 docs\EVASION.md、
  # docs\LOADERS.md、docs\DEPLOY-DOMAIN-CDN.md（截图也在 docs\screenshots 下），
  # 不打包就是一堆死链。与 .github\workflows\release.yml 保持一致。
  Copy-Item -Recurse (Join-Path $base 'docs') (Join-Path $pkg 'docs')
  # 许可与第三方声明（包内含 UPX(GPL) 与第三方签名驱动，需随包分发）
  Copy-Item (Join-Path $base 'LICENSE') (Join-Path $pkg 'LICENSE')
  Copy-Item (Join-Path $base 'DISCLAIMER.md') (Join-Path $pkg 'DISCLAIMER.md')
  Copy-Item (Join-Path $base 'THIRD-PARTY-NOTICES.md') (Join-Path $pkg 'THIRD-PARTY-NOTICES.md')
  Copy-Item (Join-Path $base $m.deploy)   (Join-Path $pkg (Split-Path -Leaf $m.deploy))
  # 一键部署脚本（环境检测 + 按需在线安装 + 直接启动打包好的服务端）
  Copy-Item (Join-Path $base 'release\install.sh')  (Join-Path $pkg 'install.sh')
  Copy-Item (Join-Path $base 'release\install.ps1') (Join-Path $pkg 'install.ps1')
  New-Item -ItemType Directory -Force -Path (Join-Path $pkg 'data') | Out-Null
  Copy-Item (Join-Path $base 'data\av_fingerprints.json') (Join-Path $pkg 'data\av_fingerprints.json')
  foreach ($d in @('upx','drivers','plugins')) {
    if (Test-Path (Join-Path $base "release\$d")) {
      Copy-Item -Recurse (Join-Path $base "release\$d") (Join-Path $pkg $d)
    }
  }
  # Drop runtime leftovers that must not ship inside the zip
  foreach ($junk in @('server.log','server.log.err','server_stderr.log')) {
    Remove-Item -Force (Join-Path $pkg $junk) -ErrorAction SilentlyContinue
  }

  # Zip: entries rooted at pkg content (no top-level folder), like CI's
  #   (cd pkg && zip -r ../out .)
  $outZip = Join-Path $zipDir $m.zip
  if (Test-Path $outZip) { Remove-Item -Force $outZip }
  $files = Get-ChildItem -Recurse -File $pkg
  $fs = [System.IO.Compression.ZipFile]::Open($outZip, [System.IO.Compression.ZipArchiveMode]::Create)
  try {
    foreach ($f in $files) {
      $rel = $f.FullName.Substring($pkg.Length + 1).Replace('\','/')
      [System.IO.Compression.ZipFileExtensions]::CreateEntryFromFile($fs, $f.FullName, $rel) | Out-Null
    }
  } finally { $fs.Dispose() }
  Write-Host "  -> $outZip ($([math]::Round((Get-Item $outZip).Length/1KB)) KB)" -ForegroundColor Green
  Remove-Item -Force $bin
}

Remove-Item -Recurse -Force $pkg -ErrorAction SilentlyContinue
Remove-Item Env:GOOS, Env:GOARCH, Env:CGO_ENABLED -ErrorAction SilentlyContinue

# 与 CI 一致的校验清单：只对发布 zip 求 sha256，顺序固定便于比对。
# （CI 的 checksums job 产物名同为 checksums.txt，两处逻辑保持镜像）
$sums = Join-Path $zipDir 'checksums.txt'
$lines = Get-ChildItem -File (Join-Path $zipDir '*.zip') | Sort-Object Name | ForEach-Object {
  $h = (Get-FileHash -Algorithm SHA256 $_.FullName).Hash.ToLower()
  "$h  $($_.Name)"
}
Set-Content -Path $sums -Value $lines -Encoding ASCII
Write-Host "checksums: $sums" -ForegroundColor Green
Get-Content $sums | ForEach-Object { Write-Host "  $_" }

Write-Host "All 6 packages done in $zipDir" -ForegroundColor Green
