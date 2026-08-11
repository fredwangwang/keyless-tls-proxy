package main

/*
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>

typedef struct {
	char thumbprint[64];
	char subject[512];
	char issuer[512];
	char key_algorithm[32];
	int32_t key_size;
	uint8_t* cert_der;
	size_t cert_der_len;
} ctk_key_info;
*/
import "C"

import (
	"context"
	"fmt"
	"sync"
	"time"
	"unsafe"

	certv1 "github.com/fredwangwang/keyless-tls-proxy/gen/cert/v1"
	"github.com/fredwangwang/keyless-tls-proxy/internal/kspclient"
)

const (
	codeOK             = 0
	codeErr            = -1
	codeNoMore         = -2
	codeNotFound       = -3
	codeBufferTooSmall = -4
)

var (
	lastErrorMu  sync.Mutex
	lastErrorStr string
)

func setLastError(msg string) {
	lastErrorMu.Lock()
	defer lastErrorMu.Unlock()
	lastErrorStr = msg
}

//export ctk_bridge_last_error
func ctk_bridge_last_error() *C.char {
	lastErrorMu.Lock()
	defer lastErrorMu.Unlock()
	return C.CString(lastErrorStr)
}

//export ctk_bridge_init
func ctk_bridge_init(configPath *C.char) C.int {
	path := ""
	if configPath != nil {
		path = C.GoString(configPath)
	}
	cfg, err := kspclient.LoadConfig(path)
	if err != nil {
		setLastError(fmt.Sprintf("load config error: %v", err))
		return codeErr
	}
	if err := kspclient.InitGlobal(cfg); err != nil {
		setLastError(fmt.Sprintf("init global error: %v", err))
		return codeErr
	}
	setLastError("")
	return codeOK
}

//export ctk_bridge_init_opts
func ctk_bridge_init_opts(addr, ca, cert, key *C.char) C.int {
	if addr == nil || ca == nil || cert == nil || key == nil {
		setLastError("ctk_bridge_init_opts: null argument passed")
		fmt.Println("ctk_bridge_init_opts: null arg passed")
		return codeErr
	}
	cfg := &kspclient.Config{
		Addr: C.GoString(addr),
		CA:   C.GoString(ca),
		Cert: C.GoString(cert),
		Key:  C.GoString(key),
	}
	if err := kspclient.InitGlobal(cfg); err != nil {
		setLastError(fmt.Sprintf("%v", err))
		fmt.Printf("ctk_bridge_init_opts InitGlobal error: %v\n", err)
		return codeErr
	}
	setLastError("")
	fmt.Printf("ctk_bridge_init_opts InitGlobal success for addr: %s\n", cfg.Addr)
	return codeOK
}

//export ctk_bridge_shutdown
func ctk_bridge_shutdown() {
	kspclient.ShutdownGlobal()
}

//export ctk_bridge_ping
func ctk_bridge_ping() C.int {
	c := kspclient.Global()
	if c == nil {
		fmt.Println("ctk_bridge_ping: Global client is NIL!")
		return codeErr
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := c.Ping(ctx); err != nil {
		fmt.Printf("ctk_bridge_ping error: %v\n", err)
		return codeErr
	}
	return codeOK
}

//export ctk_bridge_installed_count
func ctk_bridge_installed_count() C.int {
	c := kspclient.Global()
	if c == nil {
		fmt.Println("ctk_bridge_installed_count: Global client is NIL!")
		return 0
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	keys, err := c.InstalledKeys(ctx)
	if err != nil {
		fmt.Printf("ctk_bridge_installed_count InstalledKeys error: %v\n", err)
		return 0
	}
	fmt.Printf("ctk_bridge_installed_count returning keys len: %d\n", len(keys))
	return C.int(len(keys))
}

func fillCtkKeyInfo(out *C.ctk_key_info, k kspclient.KeyInfo) {
	copyToCChars((*C.char)(unsafe.Pointer(&out.thumbprint[0])), C.int(len(out.thumbprint)), k.Thumbprint)
	copyToCChars((*C.char)(unsafe.Pointer(&out.subject[0])), C.int(len(out.subject)), k.Subject)
	copyToCChars((*C.char)(unsafe.Pointer(&out.issuer[0])), C.int(len(out.issuer)), k.Issuer)
	copyToCChars((*C.char)(unsafe.Pointer(&out.key_algorithm[0])), C.int(len(out.key_algorithm)), k.KeyAlgorithm)
	out.key_size = C.int32_t(k.KeySize)
	if len(k.CertificateDER) > 0 {
		out.cert_der = (*C.uint8_t)(C.malloc(C.size_t(len(k.CertificateDER))))
		out.cert_der_len = C.size_t(len(k.CertificateDER))
		buf := (*[1 << 30]byte)(unsafe.Pointer(out.cert_der))[:len(k.CertificateDER):len(k.CertificateDER)]
		copy(buf, k.CertificateDER)
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

//export ctk_bridge_get_installed
func ctk_bridge_get_installed(index C.int, out *C.ctk_key_info) C.int {
	if out == nil {
		return codeErr
	}
	c := kspclient.Global()
	if c == nil {
		return codeErr
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	keys, err := c.InstalledKeys(ctx)
	if err != nil {
		return codeErr
	}
	if int(index) >= len(keys) {
		return codeNoMore
	}
	fillCtkKeyInfo(out, keys[index])
	return codeOK
}

//export ctk_bridge_find_installed
func ctk_bridge_find_installed(thumbprint *C.char, out *C.ctk_key_info) C.int {
	if out == nil || thumbprint == nil {
		return codeErr
	}
	c := kspclient.Global()
	if c == nil {
		return codeErr
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	tp := C.GoString(thumbprint)
	keys, err := c.InstalledKeys(ctx)
	if err != nil {
		return codeNotFound
	}
	for i := range keys {
		if keys[i].Thumbprint == tp {
			fillCtkKeyInfo(out, keys[i])
			return codeOK
		}
	}
	return codeNotFound
}

//export ctk_bridge_free_key_info
func ctk_bridge_free_key_info(out *C.ctk_key_info) {
	if out == nil {
		return
	}
	if out.cert_der != nil {
		C.free(unsafe.Pointer(out.cert_der))
		out.cert_der = nil
	}
}

//export ctk_bridge_sign_hash
func ctk_bridge_sign_hash(
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
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	sig, err := c.SignHash(
		ctx,
		C.GoString(thumbprint),
		d,
		certv1.HashAlgorithm(hashAlg),
		certv1.RSAPadding(rsaPadding),
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
