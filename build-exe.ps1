<#
    build-exe.ps1 — Compile gdid-tool.ps1 into a standalone gdid-tool.exe
    Requires Windows + PowerShell. Run as Administrator.

    What it does:
      1. Installs the ps2exe module (if missing)
      2. Compiles gdid-tool.ps1 -> gdid-tool.exe
         -noConsole   : no black window on double-click
         -requireAdmin : triggers a UAC prompt automatically

    The resulting gdid-tool.exe can be double-clicked. It defaults to `install`
    (the .bat-style behaviour is compiled in via the script's own param defaults),
    or run from a prompt:  gdid-tool.exe status
#>

$ErrorActionPreference = 'Stop'

if (-not (Get-Module -ListAvailable ps2exe)) {
    Install-Module ps2exe -Scope CurrentUser -Force
}

$src = Join-Path $PSScriptRoot 'gdid-tool.ps1'
$out = Join-Path $PSScriptRoot 'gdid-tool.exe'

if (-not (Test-Path $src)) {
    Write-Error "Cannot find gdid-tool.ps1 next to this script."
    exit 1
}

Invoke-PS2EXE -InputFile $src -OutputFile $out -noConsole -requireAdmin

Write-Host "Built: $out" -ForegroundColor Green
Write-Host "Keep gdid-config.json (optional) in the same folder as the .exe." -ForegroundColor Yellow
