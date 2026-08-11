// Package certstore provides cross-platform access to system certificate stores
// and native key signing capabilities on Windows and macOS.
//
// Platform Support:
//
//   - Windows: Enumerates certificates with private keys in the Current User "MY"
//     system store using Windows CryptoAPI, and performs cryptographic signing
//     using CNG (Cryptography Next Generation) / NCrypt APIs. Supports hardware-backed
//     and TPM-backed non-exportable keys via the Microsoft Platform Crypto Provider.
//
//   - macOS: Enumerates identities stored in the macOS Keychain using the Security
//     framework (SecItemCopyMatching with kSecClassIdentity), and performs cryptographic
//     signing using SecKeyCreateSignature. Supports SmartCards and CryptoTokenKit (CTK)
//     providers paired via sc_auth.
//
// Key Features:
//
//   - Certificate Discovery: ListCertificates returns CertificateInfo structures containing
//     subject, issuer, validity period, key algorithm/size, DER certificate payload, and
//     provider metadata.
//
//   - Digital Signing: SignHash calculates raw digital signatures over pre-computed
//     digests (SHA-256, SHA-384, SHA-512) for RSA (PKCS#1 v1.5 or PSS padding) and ECDSA keys.
package certstore
