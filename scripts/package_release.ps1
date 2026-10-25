# =====================================================================
#  ToShell v1.4.2 本地打包（与 .github/workflows/release.yml 保持镜像）
#  产物：release/release-zips/toshell-server-<os>-<arch>.zip（6 个目标）
#        release/release-zips/checksums.txt
#  用法： powershell -NoProfile -ExecutionPolicy Bypass -File scripts\package_release.ps1
# =====================================================================
$ErrorActionPreference = 'Stop'
$base = Split-Path -Parent $PSScriptRoot
Set-Location $base

$version = '1.4.2'
$commit = (git rev-parse --short HEAD)
$buildTime = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
$ldflags = "-s -w -X main.version=$version -X main.commit=$commit -X main.buildTime=$buildTime"

# 发布包必须自带可运行的最小集合：服务端 + 植入端模板 + 配置样例 + 文档/截图 + 依赖目录。
# 与 CI 的 staging 清单一致（release.yml 的 "Assemble package" 段）。
$matrix = @(
  @{ goos = 'windows'; goarch = 'amd64'; ext = '.exe'; deploy = 'release/deploy.bat'; zip = 'toshell-server-windows-amd64.zip' },
  @{ goos = 'windows'; goarch = '386'; ext = '.exe'; deploy = 'release/deploy.bat'; zip = 'toshell-server-windows-386.zip' },
  @{ goos = 'linux'; goarch = 'amd64'; ext = ''; deploy = 'release/deploy.sh'; zip = 'toshell-server-linux-amd64.zip' },
  @{ goos = 'linux'; goarch = 'arm64'; ext = ''; deploy = 'release/deploy.sh'; zip = 'toshell-server-linux-arm64.zip' },
  @{ goos = 'darwin'; goarch = 'amd64'; ext = ''; deploy = 'release/deploy.sh'; zip = 'toshell-server-darwin-amd64.zip' },
  @{ goos = 'darwin'; goarch = 'arm64'; ext = ''; deploy = 'release/deploy.sh'; zip = 'toshell-server-darwin-arm64.zip' }
)

$zipDir = Join-Path $base 'release\release-zips'
New-Item -ItemType Directory -Force -Path $zipDir | Out-Null

Add-Type -AssemblyName System.IO.Compression
Add-Type -AssemblyName System.IO.Compression.FileSystem

foreach ($m in $matrix) {
  Write-Host "== build $($m.goos)/$($m.goarch) ==" -ForegroundColor Cyan
  $bin = Join-Path $base ('toserver' + $m.ext)
  $env:GOOS = $m.goos
  $env:GOARCH = $m.goarch
  $env:CGO_ENABLED = '0'
  & go build -tags webui -ldflags $ldflags -o $bin ./cmd/server
  if ($LASTEXITCODE -ne 0) { throw "build failed for $($m.goos)/$($m.goarch)" }

  # 暂存目录放 TEMP（不要放仓库内：仓库里的 pkg/ 是被跟踪的 Go 源码目录）
  $pkg = Join-Path $env:TEMP ('tsh-pkg-' + $PID + '-' + $m.goos + '-' + $m.goarch)
  if (Test-Path $pkg) { Remove-Item -Recurse -Force $pkg }
  New-Item -ItemType Directory -Force -Path $pkg | Out-Null

  Copy-Item $bin (Join-Path $pkg ('toserver' + $m.ext))
  Copy-Item -Recurse -Force (Join-Path $base 'release\implant') (Join-Path $pkg 'implant')
  Copy-Item -Recurse -Force (Join-Path $base 'release\implant_c') (Join-Path $pkg 'implant_c')
  New-Item -ItemType Directory -Force -Path (Join-Path $pkg 'configs') | Out-Null
  Copy-Item -Force (Join-Path $base 'configs\server.yaml.example') (Join-Path $pkg 'configs\server.yaml.example')

  # 文档/截图必须随包（README/USAGE 里大量链接指向 docs/，缺了就是一堆死链）
  Copy-Item -Recurse -Force (Join-Path $base 'docs') (Join-Path $pkg 'docs')

  # 发布包不该带的东西（v1.4.2 起）：
  #   1) docs\rust-probe\out —— 探针的**构建产物**（.exe）。源码（t1/t2/t3.rs + build.ps1 +
  #      cargo-tls）随包保留，使用者可自行复现，没必要塞三个二进制进来。
  #   2) implant\*_test.go —— 模板单测。服务端构建载荷只读模板源码，测试文件是噪音。
  $probeOut = Join-Path $pkg 'docs\rust-probe\out'
  if (Test-Path $probeOut) { Remove-Item -Recurse -Force $probeOut }
  Get-ChildItem -Path (Join-Path $pkg 'implant') -Filter '*_test.go' -File -ErrorAction SilentlyContinue |
    Remove-Item -Force

  foreach ($f in @('README.md', 'USAGE.md', 'LICENSE', 'DISCLAIMER.md', 'THIRD-PARTY-NOTICES.md')) {
    Copy-Item -Force (Join-Path $base $f) (Join-Path $pkg $f)
  }
  Copy-Item -Force (Join-Path $base $m.deploy) (Join-Path $pkg (Split-Path -Leaf $m.deploy))
  Copy-Item -Force (Join-Path $base 'release\install.sh') (Join-Path $pkg 'install.sh')
  Copy-Item -Force (Join-Path $base 'release\install.ps1') (Join-Path $pkg 'install.ps1')

  # 运行期依赖目录：upx / drivers / plugins（存在才带）+ 杀软指纹库
  foreach ($d in @('upx', 'drivers', 'plugins')) {
    $src = Join-Path $base ('release\' + $d)
    if (Test-Path $src) { Copy-Item -Recurse -Force $src (Join-Path $pkg $d) }
  }
  New-Item -ItemType Directory -Force -Path (Join-Path $pkg 'data') | Out-Null
  $av = Join-Path $base 'data\av_fingerprints.json'
  if (Test-Path $av) { Copy-Item -Force $av (Join-Path $pkg 'data\av_fingerprints.json') }

  # 打包
  $outZip = Join-Path $zipDir $m.zip
  if (Test-Path $outZip) { Remove-Item -Force $outZip }
  $archive = [System.IO.Compression.ZipFile]::Open($outZip, [System.IO.Compression.ZipArchiveMode]::Create)
  try {
    foreach ($f in (Get-ChildItem -Recurse -File $pkg)) {
      $rel = $f.FullName.Substring($pkg.Length + 1).Replace('\', '/')
      [System.IO.Compression.ZipFileExtensions]::CreateEntryFromFile($archive, $f.FullName, $rel) | Out-Null
    }
  }
  finally { $archive.Dispose() }

  Write-Host ('  -> {0} ({1} KB, {2} entries)' -f $outZip, [math]::Round((Get-Item $outZip).Length / 1KB), (Get-ChildItem -Recurse -File $pkg).Count) -ForegroundColor Green

  Remove-Item -Force $bin
  Remove-Item -Recurse -Force $pkg -ErrorAction SilentlyContinue
}

Remove-Item Env:GOOS, Env:GOARCH, Env:CGO_ENABLED -ErrorAction SilentlyContinue

# 校验清单：只对发布 zip 求 sha256，按名字排序保证可比对（与 CI 的 checksums job 一致）
$sumsPath = Join-Path $zipDir 'checksums.txt'
$lines = @(Get-ChildItem -Path $zipDir -Filter '*.zip' -File | Sort-Object Name | ForEach-Object {
    $h = (Get-FileHash -Algorithm SHA256 $_.FullName).Hash.ToLower()
    "$h  $($_.Name)"
  })
if ($lines.Count -eq 0) { throw '没有生成任何 zip，检查上面的构建输出' }
Set-Content -Path $sumsPath -Value $lines -Encoding ASCII
Write-Host "checksums: $sumsPath" -ForegroundColor Green
$lines | ForEach-Object { Write-Host "  $_" }

Write-Host ('All {0} packages done in {1}' -f $matrix.Count, $zipDir) -ForegroundColor Green
