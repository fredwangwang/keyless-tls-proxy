// Shared cgo plumbing for the tpmcert bridge. The C ABI struct here must stay
// byte-identical to ksp/tpmcert_bridge.h. Platform-specific exports live in
// bridge.go (windows) and bridge_linux.go (!windows).

package main

/*
#include <stdint.h>
#include <stdlib.h>

typedef struct {
    char thumbprint[64];
    char subject[512];
    char key_algorithm[32];
    int32_t key_size;
    uint8_t* cert_der;
    size_t cert_der_len;
    uint8_t* rsa_public_blob;
    size_t rsa_public_blob_len;
} tpmcert_key_info;
*/
import "C"

import (
	"unsafe"

	"github.com/fredwangwang/keyless-tls-proxy/internal/kspclient"
)

const (
	codeOK             = 0
	codeErr            = -1
	codeNoMore         = -2
	codeNotFound       = -3
	codeBufferTooSmall = -4
)

func fillKeyInfo(out *C.tpmcert_key_info, k kspclient.KeyInfo) {
	copyToCChars((*C.char)(unsafe.Pointer(&out.thumbprint[0])), C.int(len(out.thumbprint)), k.Thumbprint)
	copyToCChars((*C.char)(unsafe.Pointer(&out.subject[0])), C.int(len(out.subject)), k.Subject)
	copyToCChars((*C.char)(unsafe.Pointer(&out.key_algorithm[0])), C.int(len(out.key_algorithm)), k.KeyAlgorithm)
	out.key_size = C.int32_t(k.KeySize)
	if len(k.CertificateDER) > 0 {
		out.cert_der = (*C.uint8_t)(C.malloc(C.size_t(len(k.CertificateDER))))
		out.cert_der_len = C.size_t(len(k.CertificateDER))
		buf := (*[1 << 30]byte)(unsafe.Pointer(out.cert_der))[:len(k.CertificateDER):len(k.CertificateDER)]
		copy(buf, k.CertificateDER)
	}
	if len(k.RSAPublicBlob) > 0 {
		out.rsa_public_blob = (*C.uint8_t)(C.malloc(C.size_t(len(k.RSAPublicBlob))))
		out.rsa_public_blob_len = C.size_t(len(k.RSAPublicBlob))
		buf := (*[1 << 30]byte)(unsafe.Pointer(out.rsa_public_blob))[:len(k.RSAPublicBlob):len(k.RSAPublicBlob)]
		copy(buf, k.RSAPublicBlob)
	}
}

func copyToCChars(dst *C.char, capacity C.int, s string) {
	if dst == nil || capacity <= 0 {
		return
	}
	n := int(capacity) - 1
	if n > len(s) {
		n = len(s)
	}
	buf := (*[1 << 20]byte)(unsafe.Pointer(dst))[:n+1]
	for i := 0; i < n; i++ {
		buf[i] = s[i]
	}
	buf[n] = 0
}

func main() {}
