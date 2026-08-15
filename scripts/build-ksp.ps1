param(
    [switch]$Installer,
    [string]$Version = "1.0.0"
)

$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $PSScriptRoot
Set-Location $Root

$BuildDir = Join-Path $Root "build"
New-Item -ItemType Directory -Force -Path $BuildDir | Out-Null

Write-Host "Building Go c-archive bridge..."
$env:CGO_ENABLED = "1"
go build -buildmode=c-archive -o (Join-Path $BuildDir "tpmcertclient.a") ./internal/kspbridge
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

Write-Host "Building Go tools..."
go build -o (Join-Path $BuildDir "ksp-register.exe") ./cmd/ksp-register
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
go build -o (Join-Path $BuildDir "ksp-install-cert.exe") ./cmd/ksp-install-cert
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

$rcFile = Join-Path $Root "cmd\ksp-install-ui\app.rc"
$sysoFile = Join-Path $Root "cmd\ksp-install-ui\app_windows_amd64.syso"
$windresCmd = Get-Command windres -ErrorAction SilentlyContinue
if ($windresCmd -and (Test-Path $rcFile)) {
    & $windresCmd.Source -i "$rcFile" --target=pe-x86-64 -O coff -o "$sysoFile"
}

go build -ldflags="-H windowsgui" -o (Join-Path $BuildDir "KeylessProxyKsp.exe") ./cmd/ksp-install-ui
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

$archive = Join-Path $BuildDir "tpmcertclient.a"
$dllOut = Join-Path $BuildDir "fredprx_ksp.dll"
$kspSources = @(
    (Join-Path $Root "ksp\ksp.c"),
    (Join-Path $Root "ksp\tpmcert_storage.c")
)

function Build-With-Gcc {
    param([string]$Gcc)
    Write-Host "Building KSP DLL with $Gcc..."
    $defFile = Join-Path $Root "ksp\ksp.def"
    $sources = ($kspSources | ForEach-Object { "`"$_`"" }) -join " "
    $cmd = @"
"$Gcc" -shared -O2 -Wall -I"$Root\ksp" -o "$dllOut" $sources "$archive" -lbcrypt -lncrypt -lcrypt32 -ladvapi32 -lws2_32 -lsecur32 -Wl,"$defFile"
"@
    cmd /c $cmd
    return $LASTEXITCODE
}

$gccCmd = Get-Command gcc -ErrorAction SilentlyContinue
if (-not $gccCmd) {
    Write-Error @"
No usable C compiler found (gcc required).
For Windows CGO builds, download and add llvm-mingw (MSVCRT x86_64) to your PATH:
  https://github.com/mstorsjo/llvm-mingw/releases/download/20260616/llvm-mingw-20260616-msvcrt-x86_64.zip
"@
}
if ((Build-With-Gcc -Gcc $gccCmd.Source) -ne 0) {
    exit 1
}

Write-Host ""
Write-Host "Build complete:"
Write-Host "  $dllOut"
Write-Host "  $(Join-Path $BuildDir 'ksp-register.exe')"
Write-Host "  $(Join-Path $BuildDir 'ksp-install-cert.exe')"
Write-Host "  $(Join-Path $BuildDir 'KeylessProxyKsp.exe')"

if ($Installer) {
    Write-Host ""
    & (Join-Path $PSScriptRoot "build-windows-installer.ps1") -SkipBuild -Version $Version
} else {
    Write-Host ""
    Write-Host "Next steps (run PowerShell as Administrator):"
    Write-Host "  Copy-Item -Force '$dllOut' C:\Windows\System32\"
    Write-Host "  &'$(Join-Path $BuildDir 'ksp-register.exe')' -register"
    Write-Host ""
    Write-Host "Or create the installer with:"
    Write-Host "  .\scripts\build-windows-installer.ps1"
}
