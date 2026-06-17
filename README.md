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

```powershell
go run ./cmd/cert-server `
  -addr 127.0.0.1:50051 `
  -ca certs/ca.crt `
  -cert certs/server.crt `
  -key certs/server.key
```

The server listens on localhost by default and requires a valid client certificate.

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
| `internal/winstore/` | Windows cert store enumeration and NCrypt signing |
| `internal/server/` | gRPC service implementation |
| `internal/tlsutil/` | mTLS configuration helpers |
| `cmd/cert-server/` | gRPC server entrypoint |
| `cmd/example-client/` | Interactive example client |
| `cmd/gencerts/` | Dev mTLS CA/server/client certificate generator |
| `scripts/gen-proto.ps1` | Regenerate protobuf code |

## gRPC API

- **ListCertificates** — returns thumbprint, subject, issuer, validity, key type/size, TPM flag, and provider name
- **SignHash** — signs a pre-computed digest (SHA-256, SHA-384, or SHA-512) with the certificate identified by thumbprint

## TPM notes

- Certificates using **Microsoft Platform Crypto Provider** are flagged as `is_tpm=true`
- TPM keys are non-exportable; signing happens in-place via `NCryptSignHash`
- RSA signing uses PKCS#1 v1.5 (compatible with most TPM keys)
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
