//go:build !windows

// Linux bridge: exposes every certificate the cert-server reports as having a
// private key (no local installation manifest). Configuration comes from the
// KSP11_ADDR / KSP11_CA / KSP11_CERT / KSP11_KEY environment variables, or
// from a JSON config file at $XDG_CONFIG_HOME/fredprx-ksp/config.json (or the
// path passed to tpmcert_init).

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
	"os"
	"path/filepath"
	"time"
	"unsafe"

	"github.com/fredwangwang/keyless-tls-proxy/internal/kspclient"
)

func defaultConfigPath() string {
	base := os.Getenv("XDG_CONFIG_HOME")
	if base == "" {
		if home, err := os.UserHomeDir(); err == nil {
			base = filepath.Join(home, ".config")
		}
	}
	return filepath.Join(base, "fredprx-ksp", "config.json")
}

func loadConfig(configPath string) (*kspclient.Config, error) {
	if configPath != "" {
		return kspclient.LoadConfig(configPath)
	}
	if cfg := kspclient.LoadConfigFromEnv(); cfg != nil {
		return cfg, nil
	}
	return kspclient.LoadConfig(defaultConfigPath())
}

//export tpmcert_init
func tpmcert_init(configPath *C.char) C.int {
	path := ""
	if configPath != nil {
		path = C.GoString(configPath)
	}
	cfg, err := loadConfig(path)
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
	// Fail fast: make sure the cert-server is reachable before the C layer
	// advertises any keys.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := c.Ping(ctx); err != nil {
		kspclient.ShutdownGlobal()
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
	// No local manifest on Linux; nothing to reload.
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
	keys, err := c.AllKeys(ctx)
	if err != nil {
		return 0
	}
	return C.int(len(keys))
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
	keys, err := c.AllKeys(ctx)
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
	keys, err := c.AllKeys(ctx)
	if err != nil {
		return codeErr
	}
	target := normalizeThumbprint(C.GoString(thumbprint))
	for i := range keys {
		if normalizeThumbprint(keys[i].Thumbprint) == target {
			fillKeyInfo(out, keys[i])
			return codeOK
		}
	}
	return codeNotFound
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
	sig, err := c.SignHashDirect(
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

func normalizeThumbprint(s string) string {
	out := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		ch := s[i]
		if ch == ':' || ch == ' ' || ch == '-' {
			continue
		}
		if ch >= 'a' && ch <= 'f' {
			ch -= 32
		}
		out = append(out, ch)
	}
	return string(out)
}
