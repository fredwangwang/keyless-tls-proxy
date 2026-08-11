//go:build windows

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
	"context"
	"time"
	"unsafe"

	"github.com/fredwangwang/keyless-tls-proxy/internal/kspclient"
)

const (
	codeOK              = 0
	codeErr             = -1
	codeNoMore          = -2
	codeNotFound        = -3
	codeBufferTooSmall  = -4
)

//export tpmcert_init
func tpmcert_init(configPath *C.char) C.int {
	path := ""
	if configPath != nil {
		path = C.GoString(configPath)
	}
	cfg, err := kspclient.LoadConfig(path)
	if err != nil {
		return codeErr
	}
	if err := kspclient.InitGlobal(cfg); err != nil {
		return codeErr
	}
	c := kspclient.Global()
	if c == nil {
		return codeErr
	}
	if err := c.ReloadManifest(); err != nil {
		return codeErr
	}
	return codeOK
}

//export tpmcert_shutdown
func tpmcert_shutdown() {
	kspclient.ShutdownGlobal()
}

//export tpmcert_reload_manifest
func tpmcert_reload_manifest() C.int {
	c := kspclient.Global()
	if c == nil {
		return codeErr
	}
	if err := c.ReloadManifest(); err != nil {
		return codeErr
	}
	return codeOK
}

//export tpmcert_installed_count
func tpmcert_installed_count() C.int {
	c := kspclient.Global()
	if c == nil {
		return 0
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	keys, err := c.InstalledKeys(ctx)
	if err != nil {
		return 0
	}
	return C.int(len(keys))
}

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

//export tpmcert_get_installed
func tpmcert_get_installed(index C.int, out *C.tpmcert_key_info) C.int {
	if out == nil {
		return codeErr
	}
	c := kspclient.Global()
	if c == nil {
		return codeErr
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	keys, err := c.InstalledKeys(ctx)
	if err != nil {
		return codeErr
	}
	if int(index) >= len(keys) {
		return codeNoMore
	}
	fillKeyInfo(out, keys[index])
	return codeOK
}

//export tpmcert_find_installed
func tpmcert_find_installed(thumbprint *C.char, out *C.tpmcert_key_info) C.int {
	if out == nil || thumbprint == nil {
		return codeErr
	}
	c := kspclient.Global()
	if c == nil {
		return codeErr
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	k, err := c.FindInstalled(ctx, C.GoString(thumbprint))
	if err != nil {
		return codeNotFound
	}
	fillKeyInfo(out, *k)
	return codeOK
}

//export tpmcert_free_key_info
func tpmcert_free_key_info(out *C.tpmcert_key_info) {
	if out == nil {
		return
	}
	if out.cert_der != nil {
		C.free(unsafe.Pointer(out.cert_der))
		out.cert_der = nil
	}
	if out.rsa_public_blob != nil {
		C.free(unsafe.Pointer(out.rsa_public_blob))
		out.rsa_public_blob = nil
	}
}

//export tpmcert_sign_hash
func tpmcert_sign_hash(
	thumbprint *C.char,
	digest *C.uint8_t,
	digestLen C.size_t,
	hashAlg C.int,
	rsaPadding C.int,
	sigOut *C.uint8_t,
	sigLen *C.size_t,
) C.int {
	if thumbprint == nil || digest == nil || sigLen == nil {
		return codeErr
	}
	c := kspclient.Global()
	if c == nil {
		return codeErr
	}
	d := C.GoBytes(unsafe.Pointer(digest), C.int(digestLen))
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	sig, err := c.SignHash(
		ctx,
		C.GoString(thumbprint),
		d,
		kspclient.HashAlgFromInt(int(hashAlg)),
		kspclient.PaddingFromInt(int(rsaPadding)),
	)
	if err != nil {
		return codeNotFound
	}
	if sigOut == nil {
		*sigLen = C.size_t(len(sig))
		return codeOK
	}
	if C.size_t(len(sig)) > *sigLen {
		*sigLen = C.size_t(len(sig))
		return C.int(codeBufferTooSmall)
	}
	dest := (*[1 << 30]byte)(unsafe.Pointer(sigOut))[:len(sig):len(sig)]
	copy(dest, sig)
	*sigLen = C.size_t(len(sig))
	return codeOK
}

func main() {}
