$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $PSScriptRoot
Set-Location $Root

$protocCmd = Get-Command protoc -ErrorAction SilentlyContinue
if (-not $protocCmd) {
    $localProtoc = Join-Path $Root "tools\protoc\bin\protoc.exe"
    if (Test-Path $localProtoc) {
        $protocCmd = $localProtoc
    } else {
        Write-Error "protoc not found. Install Protocol Buffers or run scripts/bootstrap-protoc.ps1."
    }
} else {
    $protocCmd = $protocCmd.Source
}

$goPath = go env GOPATH
$binPath = Join-Path $goPath "bin"
$env:PATH = "$binPath;$env:PATH"

if (-not (Get-Command protoc-gen-go -ErrorAction SilentlyContinue)) {
    Write-Host "Installing protoc-gen-go..."
    go install google.golang.org/protobuf/cmd/protoc-gen-go@latest
}
if (-not (Get-Command protoc-gen-go-grpc -ErrorAction SilentlyContinue)) {
    Write-Host "Installing protoc-gen-go-grpc..."
    go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest
}

New-Item -ItemType Directory -Force -Path gen | Out-Null

& $protocCmd `
    --proto_path=proto `
    --proto_path=tools/protoc/include `
    --go_out=gen --go_opt=paths=source_relative `
    --go-grpc_out=gen --go-grpc_opt=paths=source_relative `
    proto/cert/v1/cert.proto

Write-Host "Generated protobuf code in gen/cert/v1/"
