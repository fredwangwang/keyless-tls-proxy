param(
    [switch]$Debug,
    [string]$OutputDir = "build"
)

$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $PSScriptRoot
Set-Location $Root

# Locate Go compiler
$GoCmd = Get-Command go -ErrorAction SilentlyContinue
if (-not $GoCmd) {
    $GoDefaultPath = "C:\Program Files\Go\bin\go.exe"
    if (Test-Path $GoDefaultPath) {
        $GoExe = $GoDefaultPath
    } else {
        Write-Error "Go compiler ('go.exe') not found in PATH or standard installation path."
        exit 1
    }
} else {
    $GoExe = $GoCmd.Source
}

$TargetDir = Join-Path $Root $OutputDir
New-Item -ItemType Directory -Force -Path $TargetDir | Out-Null

$OutExe = Join-Path $TargetDir "KeylessProxyKsp.exe"

# Update Windows PE resource object (.syso) if windres is available
$rcFile = Join-Path $Root "cmd\ksp-install-ui\app.rc"
$sysoFile = Join-Path $Root "cmd\ksp-install-ui\app_windows_amd64.syso"
$windresCmd = Get-Command windres -ErrorAction SilentlyContinue
if ($windresCmd -and (Test-Path $rcFile)) {
    Write-Host "Compiling Windows resource object..."
    & $windresCmd.Source -i "$rcFile" --target=pe-x86-64 -O coff -o "$sysoFile"
}

$LdFlags = ""
if (-not $Debug) {
    $LdFlags = "-s -w -H windowsgui"
    Write-Host "Building KeylessProxyKsp UI (Release GUI mode)..."
} else {
    Write-Host "Building KeylessProxyKsp UI (Debug mode with console)..."
}

$buildArgs = @("build")
if ($LdFlags -ne "") {
    $buildArgs += "-ldflags=$LdFlags"
}
$buildArgs += @("-o", $OutExe, "./cmd/ksp-install-ui")

& $GoExe $buildArgs
if ($LASTEXITCODE -ne 0) {
    Write-Error "Build failed with exit code $LASTEXITCODE"
    exit $LASTEXITCODE
}

Write-Host ""
Write-Host "Successfully built:" -ForegroundColor Green
Write-Host "  $OutExe" -ForegroundColor Cyan
Write-Host ""
Write-Host "Usage:"
Write-Host "  & '$OutExe'"
