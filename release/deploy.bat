@echo off
rem =====================================================================
rem  ToShell Team Server 一键启动脚本 (Windows)
rem  用法:  在 release\ 目录双击或运行  deploy.bat
rem  首次运行会自动从 configs\server.yaml.example 生成配置(需先修改敏感项),
rem  之后在前台启动服务端, 日志显示在控制台。
rem =====================================================================
setlocal
set VERSION=v1.2.1
set CFG_FILE=configs\server.yaml
set EXAMPLE=configs\server.yaml.example

cd /d "%~dp0"

rem -- 1) 配置检查 --
if not exist "%CFG_FILE%" (
  echo [*] 未找到 %CFG_FILE%
  if exist "%EXAMPLE%" (
    copy "%EXAMPLE%" "%CFG_FILE%" >nul
    echo [!] 已从 %EXAMPLE% 生成 %CFG_FILE%
    echo     请先编辑 %CFG_FILE% 修改以下敏感项后再启动:
    echo       - auth.api_keys
    echo       - auth.jwt_key
    echo       - listener.encryption_key
    echo       - listener.public_host
    echo       - auth.admin_password
  ) else (
    echo [x] 缺少 %EXAMPLE%, 无法自动生成配置。请复制 configs\server.yaml.example 到本 configs 目录。
    pause
    exit /b 1
  )
)

rem -- 2) 可执行文件检查 --
if not exist toserver.exe (
  echo [x] 未找到 toserver.exe 。请先在项目根构建:
  echo     go build -tags webui -ldflags "-s -w" -o release\toserver.exe .\cmd\server
  pause
  exit /b 1
)

rem -- 3) 启动 --
if not exist data mkdir data
echo [*] 启动 ToShell Team Server %VERSION% ...
start "ToShell Server" toserver.exe -config %CFG_FILE%
echo [+] 已启动。关闭窗口即停止服务端。
echo [+] 日志: 见 server.log (若配置 logging.output=stdout 则在控制台窗口)

rem -- 读出 api_port 方便访问 --
for /f "tokens=2 delims=:" %%a in ('findstr /b "api_port:" %CFG_FILE%') do set APIPORT=%%a
if not defined APIPORT set APIPORT=18081
echo [+] Web 控制台:  http://localhost:%APIPORT%
pause
