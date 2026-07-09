@echo off
setlocal
REM GDID Privacy Tool - double-click launcher (auto-elevates to Administrator)
set "ARGS=%*"
if "%~1"=="" set "ARGS=install"

REM Re-launch elevated if not already running as Administrator
net session >nul 2>&1
if %errorLevel% neq 0 (
    PowerShell -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
    exit /b
)

PowerShell -NoProfile -ExecutionPolicy Bypass -File "%~dp0gdid-tool.ps1" %ARGS%
endlocal
