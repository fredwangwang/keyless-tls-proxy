//go:build windows

package certstore

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	winCertStoreProvSystem      = windows.CERT_STORE_PROV_SYSTEM
	winCertStoreCurrentUser     = windows.CERT_SYSTEM_STORE_CURRENT_USER
	winCertStoreReadOnly        = windows.CERT_STORE_READONLY_FLAG
	winEncodingX509ASN          = windows.X509_ASN_ENCODING
	winEncodingPKCS7            = windows.PKCS_7_ASN_ENCODING
	winFindHashStr              = windows.CERT_FIND_HASH_STR
)

var winMyStore = stringToUTF16Ptr("MY")

func ListCertificates() ([]CertificateInfo, error) {
	store, err := openMyStore()
	if err != nil {
		return nil, err
	}
	defer windows.CertCloseStore(store, 0)

	var (
		prev *windows.CertContext
		out  []CertificateInfo
	)
	for {
		ctx, err := windows.CertEnumCertificatesInStore(store, prev)
		if err != nil {
			if errno, ok := err.(windows.Errno); ok && errno == windows.Errno(windows.CRYPT_E_NOT_FOUND) {
				break
			}
			return nil, fmt.Errorf("enumerate certificates: %w", err)
		}
		if ctx == nil {
			break
		}

		if info, ok := certInfoFromContext(ctx); ok {
			out = append(out, info)
		}
		prev = ctx
	}
	return out, nil
}

func SignHash(thumbprint string, digest []byte, hash HashAlgorithm, padding RSAPadding) (*SignResult, error) {
	cryptoHash, err := hash.CryptoHash()
	if err != nil {
		return nil, err
	}
	expectedLen, err := hash.DigestSize()
	if err != nil {
		return nil, err
	}
	if len(digest) != expectedLen {
		return nil, ErrInvalidDigest
	}
	if padding == 0 {
		padding = RSAPaddingPKCS1
	}

	store, err := openMyStore()
	if err != nil {
		return nil, err
	}
	defer windows.CertCloseStore(store, 0)

	ctx, err := findCertByThumbprint(store, thumbprint)
	if err != nil {
		return nil, err
	}
	defer windows.CertFreeCertificateContext(ctx)

	sig, algName, err := signHashWithCert(ctx, digest, cryptoHash, padding)
	if err != nil {
		return nil, fmt.Errorf("sign hash: %w", err)
	}
	return &SignResult{
		Signature:          sig,
		SignatureAlgorithm: algName,
		Padding:            padding,
	}, nil
}

func openMyStore() (windows.Handle, error) {
	store, err := windows.CertOpenStore(
		winCertStoreProvSystem,
		0,
		0,
		winCertStoreCurrentUser|winCertStoreReadOnly,
		uintptr(unsafe.Pointer(winMyStore)),
	)
	if err != nil {
		return 0, fmt.Errorf("open certificate store: %w", err)
	}
	return store, nil
}

func certInfoFromContext(ctx *windows.CertContext) (CertificateInfo, bool) {
	if !hasPrivateKey(ctx) {
		return CertificateInfo{}, false
	}

	der := unsafe.Slice(ctx.EncodedCert, ctx.Length)
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return CertificateInfo{}, false
	}

	providerName := certProviderName(ctx)
	keyAlg, keySize := keyMetadata(cert)

	return CertificateInfo{
		Thumbprint:     thumbprintFromCert(cert),
		Subject:        cert.Subject.String(),
		Issuer:         cert.Issuer.String(),
		NotBefore:      cert.NotBefore,
		NotAfter:       cert.NotAfter,
		KeyAlgorithm:   keyAlg,
		KeySize:        keySize,
		HasPrivateKey:  true,
		IsTPM:          isTPMCert(ctx, providerName),
		ProviderName:   providerName,
		CertificateDER: append([]byte(nil), der...),
	}, true
}

func findCertByThumbprint(store windows.Handle, thumbprint string) (*windows.CertContext, error) {
	normalized := strings.ReplaceAll(strings.ToUpper(thumbprint), " ", "")
	ptr, err := windows.UTF16PtrFromString(normalized)
	if err != nil {
		return nil, ErrCertificateNotFound
	}

	ctx, err := windows.CertFindCertificateInStore(
		store,
		winEncodingX509ASN|winEncodingPKCS7,
		0,
		winFindHashStr,
		unsafe.Pointer(ptr),
		nil,
	)
	if err != nil || ctx == nil {
		return nil, ErrCertificateNotFound
	}
	return ctx, nil
}

func thumbprintFromCert(cert *x509.Certificate) string {
	sum := sha1.Sum(cert.Raw)
	return strings.ToUpper(hex.EncodeToString(sum[:]))
}

func keyMetadata(cert *x509.Certificate) (string, int) {
	switch pub := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		return "RSA", pub.N.BitLen()
	case *ecdsa.PublicKey:
		return "ECDSA", pub.Curve.Params().BitSize
	default:
		return cert.PublicKeyAlgorithm.String(), 0
	}
}
