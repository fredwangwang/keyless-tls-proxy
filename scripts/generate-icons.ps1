param(
    [string]$SourcePng = "assets/AppIcon.png"
)

$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $PSScriptRoot
Set-Location $Root

$srcPath = Join-Path $Root $SourcePng
if (-not (Test-Path $srcPath)) {
    Write-Error "Source image '$srcPath' not found."
    exit 1
}

Add-Type -AssemblyName System.Drawing

Write-Host "Reading $srcPath..."
$src = [System.Drawing.Bitmap]::FromFile($srcPath)

$sizes = @(16, 24, 32, 48, 64, 128, 256)
$images = @()

foreach ($sz in $sizes) {
    $bmp = New-Object System.Drawing.Bitmap $sz, $sz
    $g = [System.Drawing.Graphics]::FromImage($bmp)
    $g.InterpolationMode = [System.Drawing.Drawing2D.InterpolationMode]::HighQualityBicubic
    $g.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::HighQuality
    $g.PixelOffsetMode = [System.Drawing.Drawing2D.PixelOffsetMode]::HighQuality
    $g.CompositingQuality = [System.Drawing.Drawing2D.CompositingQuality]::HighQuality
    $g.Clear([System.Drawing.Color]::Transparent)
    $g.DrawImage($src, 0, 0, $sz, $sz)
    $g.Dispose()
    
    $ms = New-Object System.IO.MemoryStream
    $bmp.Save($ms, [System.Drawing.Imaging.ImageFormat]::Png)
    $pngBytes = $ms.ToArray()
    $ms.Dispose()
    $bmp.Dispose()
    
    $images += [PSCustomObject]@{
        Width = $sz
        Height = $sz
        Bytes = $pngBytes
    }
}
$src.Dispose()

function Save-IcoFile([string]$outPath, $imgList) {
    $parent = Split-Path -Parent $outPath
    if ($parent -and -not (Test-Path $parent)) {
        New-Item -ItemType Directory -Force -Path $parent | Out-Null
    }
    $fs = [System.IO.File]::Create($outPath)
    $bw = New-Object System.IO.BinaryWriter $fs

    $bw.Write([uint16]0)
    $bw.Write([uint16]1)
    $bw.Write([uint16]$imgList.Count)

    $offset = 6 + ($imgList.Count * 16)
    foreach ($img in $imgList) {
        $w = if ($img.Width -ge 256) { [byte]0 } else { [byte]$img.Width }
        $h = if ($img.Height -ge 256) { [byte]0 } else { [byte]$img.Height }
        $bw.Write($w)
        $bw.Write($h)
        $bw.Write([byte]0)
        $bw.Write([byte]0)
        $bw.Write([uint16]1)
        $bw.Write([uint16]32)
        $bw.Write([uint32]$img.Bytes.Length)
        $bw.Write([uint32]$offset)
        $offset += $img.Bytes.Length
    }

    foreach ($img in $imgList) {
        $bw.Write($img.Bytes)
    }

    $bw.Flush()
    $bw.Close()
    $fs.Close()
}

$assetIco = Join-Path $Root "assets\AppIcon.ico"
$uiIco = Join-Path $Root "cmd\ksp-install-ui\app.ico"
$uiPng = Join-Path $Root "cmd\ksp-install-ui\ui\icon.png"

Save-IcoFile -outPath $assetIco -imgList $images
Save-IcoFile -outPath $uiIco -imgList $images
Copy-Item -Force $srcPath $uiPng

Write-Host "Generated:"
Write-Host "  $assetIco"
Write-Host "  $uiIco"
Write-Host "  $uiPng"

# Compile syso with windres if present
$rcFile = Join-Path $Root "cmd\ksp-install-ui\app.rc"
$sysoFile = Join-Path $Root "cmd\ksp-install-ui\app_windows_amd64.syso"
$windresCmd = Get-Command windres -ErrorAction SilentlyContinue
if ($windresCmd -and (Test-Path $rcFile)) {
    Write-Host "Compiling Windows resource object..."
    & $windresCmd.Source -i "$rcFile" --target=pe-x86-64 -O coff -o "$sysoFile"
    Write-Host "  $sysoFile"
}
