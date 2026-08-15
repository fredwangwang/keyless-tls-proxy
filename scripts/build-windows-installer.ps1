param(
    [string]$Version = "1.0.0",
    [switch]$SkipBuild,
    [string]$OutputDir = "build",
    [string]$OutputFilename = "FredProxyKSP-Setup",
    [switch]$InstallCompiler
)

$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $PSScriptRoot
Set-Location $Root

Write-Host "==========================================" -ForegroundColor Cyan
Write-Host " Building Windows KSP Installer (v$Version)" -ForegroundColor Cyan
Write-Host "==========================================" -ForegroundColor Cyan

$TargetBuildDir = Join-Path $Root $OutputDir
New-Item -ItemType Directory -Force -Path $TargetBuildDir | Out-Null

# 1. Generate icon if missing
$icoPath = Join-Path $Root "assets/AppIcon.ico"
if (-not (Test-Path $icoPath)) {
    Write-Host "Generating application icon..." -ForegroundColor Yellow
    & (Join-Path $PSScriptRoot "generate-icons.ps1")
}

# 2. Build prerequisite binaries if requested or missing
$kspDll = Join-Path $TargetBuildDir "fredprx_ksp.dll"
$kspRegister = Join-Path $TargetBuildDir "ksp-register.exe"
$kspInstallCert = Join-Path $TargetBuildDir "ksp-install-cert.exe"
$kspInstallUi = Join-Path $TargetBuildDir "ksp-install-ui.exe"

$missingBinaries = (-not (Test-Path $kspDll)) -or (-not (Test-Path $kspRegister)) -or (-not (Test-Path $kspInstallCert)) -or (-not (Test-Path $kspInstallUi))

if ((-not $SkipBuild) -or $missingBinaries) {
    Write-Host "Building KSP binaries and tools..." -ForegroundColor Yellow
    & (Join-Path $PSScriptRoot "build-ksp.ps1")
    if ($LASTEXITCODE -ne 0) {
        Write-Error "Failed to build KSP binaries."
        exit $LASTEXITCODE
    }
}

# 3. Locate Inno Setup Compiler (ISCC.exe)
$isccCmd = Get-Command "ISCC.exe" -ErrorAction SilentlyContinue
$isccPath = $null

if ($isccCmd) {
    $isccPath = $isccCmd.Source
} else {
    $candidatePaths = @(
        "$env:LOCALAPPDATA\Programs\Inno Setup 6\ISCC.exe",
        "$env:LOCALAPPDATA\Programs\Inno Setup 7\ISCC.exe",
        "${env:ProgramFiles(x86)}\Inno Setup 6\ISCC.exe",
        "${env:ProgramFiles}\Inno Setup 6\ISCC.exe",
        "${env:ProgramFiles(x86)}\Inno Setup 7\ISCC.exe",
        "${env:ProgramFiles}\Inno Setup 7\ISCC.exe"
    )
    foreach ($cand in $candidatePaths) {
        if (Test-Path $cand) {
            $isccPath = $cand
            break
        }
    }
}

if (-not $isccPath) {
    if ($InstallCompiler) {
        Write-Host "Inno Setup compiler not found. Installing via winget..." -ForegroundColor Yellow
        winget install --id JRSoftware.InnoSetup --silent --accept-source-agreements --accept-package-agreements
        # Re-check paths
        foreach ($cand in $candidatePaths) {
            if (Test-Path $cand) {
                $isccPath = $cand
                break
            }
        }
    }
}

if (-not $isccPath) {
    Write-Error @"
Inno Setup Compiler (ISCC.exe) was not found.
Please install Inno Setup 6:
  winget install --id JRSoftware.InnoSetup
or run this script with -InstallCompiler.
"@
    exit 1
}

Write-Host "Found Inno Setup Compiler at: $isccPath" -ForegroundColor Green

# 4. Compile Installer
$issScript = Join-Path $Root "installer\windows\ksp-installer.iss"
if (-not (Test-Path $issScript)) {
    Write-Error "Inno Setup script not found at: $issScript"
    exit 1
}

Write-Host "Compiling installer package..." -ForegroundColor Yellow
$isccArgs = @(
    "/DMyAppVersion=$Version",
    "/O$TargetBuildDir",
    "/F$OutputFilename",
    "/Qp",
    $issScript
)

& $isccPath $isccArgs
if ($LASTEXITCODE -ne 0) {
    Write-Error "Installer compilation failed with code $LASTEXITCODE"
    exit $LASTEXITCODE
}

$outInstallerExe = Join-Path $TargetBuildDir "$OutputFilename.exe"
if (-not (Test-Path $outInstallerExe)) {
    Write-Error "Expected installer binary was not found at $outInstallerExe"
    exit 1
}

$fileSize = (Get-Item $outInstallerExe).Length / 1MB

Write-Host ""
Write-Host "==========================================" -ForegroundColor Green
Write-Host " Installer Build Succeeded!" -ForegroundColor Green
Write-Host " Output: $outInstallerExe" -ForegroundColor Cyan
Write-Host " Size:   $([math]::Round($fileSize, 2)) MB" -ForegroundColor Cyan
Write-Host "==========================================" -ForegroundColor Green
