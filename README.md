# TPM Certificate gRPC Server

A Windows gRPC service that lists certificates with private keys from the Current User `MY` store and signs digests using non-exportable keys (including TPM-backed keys via CNG/NCrypt). Communication is secured with mutual TLS (mTLS).

## Requirements

- Windows (server must run on Windows)
- Go 1.26+
- `protoc` for regenerating protobuf code (bundled under `tools/protoc/` after first bootstrap, or install via `winget install Google.Protobuf`)

## Quick start

### 1. Generate mTLS transport certificates

```powershell
go run ./cmd/gencerts
```

This creates `certs/ca.crt`, `certs/server.crt`, `certs/server.key`, `certs/client.crt`, and `certs/client.key`.

### 2. Start the server

Restart the server after code or proto changes (`go run` recompiles automatically; stop any previously running instance first).

```powershell
go run ./cmd/cert-server `
  -addr 127.0.0.1:50051 `
  -ca certs/ca.crt `
  -cert certs/server.crt `
  -key certs/server.key
```

The server listens on localhost by default and requires a valid client certificate.

UDP broadcast discovery is enabled by default on port **6666** (`-discovery-addr :6666`). Clients on the same LAN can find the server without hard-coding its IP.

For LAN clients, bind gRPC to a reachable interface:

```powershell
go run ./cmd/cert-server `
  -addr 0.0.0.0:50051 `
  -ca certs/ca.crt `
  -cert certs/server.crt `
  -key certs/server.key
```

Disable discovery with `-discovery=false`. Windows Firewall may require an inbound rule for UDP 6666.

**Discovery protocol:** send a UDP broadcast (or unicast) to port 6666:

```json
{"op":"discover","service":"tpm-cert-server"}
```

The server replies unicast with:

```json
{"op":"announce","service":"tpm-cert-server","version":"1","hostname":"HOST","grpc_addr":"192.168.1.50:50051"}
```

Use `grpc_addr` for mTLS gRPC connections. Discovery only advertises the endpoint; mTLS is still required for API access.

Discover servers on the LAN:

```powershell
go run ./cmd/run-discovery
```

Optional flags: `-timeout 5s`, `-json`, `-probe 192.168.1.50:6666` (unicast to a specific host).

### 3. Run the example client

```powershell
go run ./cmd/example-client `
  -addr 127.0.0.1:50051 `
  -ca certs/ca.crt `
  -cert certs/client.crt `
  -key certs/client.key
```

The client will:

1. List all certificates in the Current User `MY` store that have accessible private keys
2. Prompt you to choose a certificate by number
3. Prompt for text to sign (or pass `-message "hello"` to skip the prompt)
4. Compute SHA-256 locally and call `SignHash` on the server
5. Print the digest and signature

## Project layout

| Path | Description |
|------|-------------|
| `proto/cert/v1/cert.proto` | gRPC API definition |
| `gen/cert/v1/` | Generated protobuf/gRPC Go code |
| `internal/certstore/` | Platform certificate store enumeration and signing (Windows NCrypt, macOS Keychain) |
| `internal/server/` | gRPC service implementation and UDP discovery |
| `internal/tlsutil/` | mTLS configuration helpers |
| `cmd/cert-server/` | gRPC server entrypoint |
| `cmd/example-client/` | Interactive example client |
| `cmd/run-discovery/` | UDP LAN discovery client |
| `cmd/gencerts/` | Dev mTLS CA/server/client certificate generator |
| `cmd/ksp-register/` | Register/unregister the CNG KSP (admin) |
| `cmd/ksp-install-cert/` | Install a remote cert into MY store and bind to the KSP |
| `ksp/` | CNG Key Storage Provider DLL sources |
| `internal/kspclient/` | gRPC client library for the KSP bridge |
| `internal/ctkbridge/` | Go c-archive exports linked into the macOS CTK provider |
| `mac-provider/` | macOS CryptoTokenKit (CTK) custom provider sources |
| `scripts/gen-proto.ps1` | Regenerate protobuf code |
| `scripts/build-ksp.ps1` | Build KSP DLL and helper tools |
| `scripts/build-mac-provider.sh` | Build macOS CryptoTokenKit provider |
| `ref/OpenSCToken/` | Reference — macOS CryptoTokenKit SmartCard provider |
| `ref/BlackICE_Connect/` | Git submodule — upstream Gradiant CNG KSP reference |

## gRPC API

- **ListCertificates** — returns thumbprint, subject, issuer, validity, key type/size, TPM flag, provider name, and certificate DER
- **SignHash** — signs a pre-computed digest (SHA-256, SHA-384, or SHA-512) with the certificate identified by thumbprint; RSA keys support `pkcs1` (default) or `pss` padding via `rsa_padding`

## TPM notes

- Certificates using **Microsoft Platform Crypto Provider** are flagged as `is_tpm=true`
- TPM keys are non-exportable; signing happens in-place via `NCryptSignHash`
- RSA signing supports PKCS#1 v1.5 (default) and PSS (`-padding pss` on the example client)
- TPM RSA keys are typically limited to 2048-bit

## Regenerating protobuf code

```powershell
powershell -ExecutionPolicy Bypass -File scripts/gen-proto.ps1
```

Install plugins if needed:

```powershell
go install google.golang.org/protobuf/cmd/protoc-gen-go@latest
go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest
```

## Security

- mTLS transport certs (`cmd/gencerts`) are separate from Windows signing keys
- The server defaults to `127.0.0.1` — bind to a broader interface only in trusted networks
- `certs/` is gitignored; regenerate for each environment

## CNG Key Storage Provider (remote client)

The KSP lets Windows apps on a **client machine** use TPM-backed keys on the cert-server host via NCrypt/CryptoAPI. Private keys never leave the server; the KSP forwards signing to cert-server over mTLS gRPC.

### Build

Requires Go 1.26+, Visual Studio C++ build tools, and CGO (`CGO_ENABLED=1`):

```powershell
powershell -ExecutionPolicy Bypass -File scripts/build-ksp.ps1
```

Outputs under `build/`:

- `fredprx_ksp.dll` — CNG Key Storage Provider
- `ksp-register.exe` — register/unregister the provider (admin)
- `ksp-install-cert.exe` — install and bind a remote certificate

### Install workflow

1. Copy `build\fredprx_ksp.dll` to `C:\Windows\System32`
2. Register the provider (elevated):

```powershell
build\ksp-register.exe -register
```

3. Install a remote certificate binding (uses the same mTLS flags as the example client):

```powershell
build\ksp-install-cert.exe `
  -addr server.example.com:50051 `
  -ca certs\ca.crt `
  -cert certs\client.crt `
  -key certs\client.key
```

This writes `%ProgramData%\fredprx-ksp\config.json`, prompts you to pick a certificate, installs it into **Current User\MY**, and records the thumbprint in `%ProgramData%\fredprx-ksp\installed.json`.

4. Windows apps can now acquire the private key via `CryptAcquireCertificatePrivateKey`; signing is delegated to cert-server.

### KSP configuration

Default config path: `%ProgramData%\fredprx-ksp\config.json`

```json
{
  "addr": "server.example.com:50051",
  "ca": "C:\\path\\ca.crt",
  "cert": "C:\\path\\client.crt",
  "key": "C:\\path\\client.key"
}
```

Only thumbprints listed in `installed.json` are exposed as KSP keys.

### Manage bindings

```powershell
build\ksp-install-cert.exe -list
build\ksp-install-cert.exe -remove <THUMBPRINT>
build\ksp-register.exe -unregister
```

### KSP limitations (v1)

- Windows x64 only
- RSA keys only (PKCS#1 and PSS signing)
- No local key creation or import
- Keys are unusable until explicitly installed with `ksp-install-cert`
