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

$archive = Join-Path $BuildDir "tpmcertclient.a"
$dllOut = Join-Path $BuildDir "tpmcert_ksp.dll"
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

function Build-With-Msvc {
    param([string]$Vcvars)
    Write-Host "Building KSP DLL with MSVC..."
    $sources = ($kspSources | ForEach-Object { "`"$_`"" }) -join " "
    $cmd = @"
call "$Vcvars" >nul && cl /nologo /O2 /LD /W3 /TC /I"$Root\ksp" $sources /Fe:"$dllOut" /link "$archive" bcrypt.lib ncrypt.lib crypt32.lib advapi32.lib ws2_32.lib secur32.lib /DEF:"$Root\ksp\ksp.def"
"@
    cmd /c $cmd
    return $LASTEXITCODE
}

$built = $false
$vswhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
if (Test-Path $vswhere) {
    $vsPath = & $vswhere -latest -products * -property installationPath
    if ($vsPath) {
        $vcvarsCandidates = @(
            (Join-Path $vsPath "VC\Auxiliary\Build\vcvars64.bat")
        )
        foreach ($vcvars in $vcvarsCandidates) {
            if (Test-Path $vcvars) {
                if ((Build-With-Msvc -Vcvars $vcvars) -eq 0) {
                    $built = $true
                    break
                }
            }
        }
    }
}

if (-not $built) {
    $gccCmd = Get-Command gcc -ErrorAction SilentlyContinue
    if (-not $gccCmd) {
        Write-Error "No usable C compiler found (MSVC vcvars or gcc required)."
    }
    if ((Build-With-Gcc -Gcc $gccCmd.Source) -ne 0) {
        exit 1
    }
}

Write-Host ""
Write-Host "Build complete:"
Write-Host "  $dllOut"
Write-Host "  $(Join-Path $BuildDir 'ksp-register.exe')"
Write-Host "  $(Join-Path $BuildDir 'ksp-install-cert.exe')"
Write-Host ""
Write-Host "Next steps (run PowerShell as Administrator):"
Write-Host "  Copy-Item -Force build\tpmcert_ksp.dll C:\Windows\System32\"
Write-Host "  .\build\ksp-register.exe -register"
