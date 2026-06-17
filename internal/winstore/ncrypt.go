//go:build windows

package winstore

import (
	"crypto"
	"errors"
	"fmt"
	"io"
	"math/big"
	"unsafe"

	"golang.org/x/crypto/cryptobyte"
	"golang.org/x/crypto/cryptobyte/asn1"
	"golang.org/x/sys/windows"
)

const (
	winAcquireCached       = windows.CRYPT_ACQUIRE_CACHE_FLAG
	winAcquireSilent       = windows.CRYPT_ACQUIRE_SILENT_FLAG
	winAcquireOnlyNCrypt   = windows.CRYPT_ACQUIRE_ONLY_NCRYPT_KEY_FLAG
	winNcryptKeySpec       = windows.CERT_NCRYPT_KEY_SPEC
	winBCryptPadPKCS1      = 0x2
	certKeyProvInfoPropID = 22
)

var (
	providerMPCP = "Microsoft Platform Crypto Provider"

	winNCrypt = windows.NewLazySystemDLL("ncrypt.dll")
	winCrypt32Extra = windows.NewLazySystemDLL("crypt32.dll")

	winCryptAcquireCertificatePrivateKey = winCrypt32Extra.NewProc("CryptAcquireCertificatePrivateKey")
	winCertGetCertificateContextProperty = winCrypt32Extra.NewProc("CertGetCertificateContextProperty")
	winCertFindCertificateInStore        = winCrypt32Extra.NewProc("CertFindCertificateInStore")
	winNCryptSignHash                    = winNCrypt.NewProc("NCryptSignHash")
	winNCryptGetProperty                 = winNCrypt.NewProc("NCryptGetProperty")
	winNCryptFreeObject                  = winNCrypt.NewProc("NCryptFreeObject")

	winNCryptAlgorithmGroupProperty = stringToUTF16Ptr("Algorithm Group")

	winAlgIDs = map[crypto.Hash]*uint16{
		crypto.SHA256: stringToUTF16Ptr("SHA256"),
		crypto.SHA384: stringToUTF16Ptr("SHA384"),
		crypto.SHA512: stringToUTF16Ptr("SHA512"),
	}
)

type cryptKeyProvInfo struct {
	ContainerName *uint16
	ProvName      *uint16
	ProvType      uint32
	Flags         uint32
	CProvParam    uint32
	RgProvParam   uintptr
	KeySpec       uint32
}

type pkcs1PaddingInfo struct {
	pszAlgID *uint16
}

type ncryptSigner struct {
	handle         uintptr
	algorithmGroup string
}

func (s *ncryptSigner) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	switch s.algorithmGroup {
	case "ECDSA", "ECDH":
		return signECDSA(s.handle, digest)
	case "RSA":
		algID, ok := winAlgIDs[opts.HashFunc()]
		if !ok {
			return nil, fmt.Errorf("unsupported hash algorithm")
		}
		return signRSAPKCS1(s.handle, digest, algID)
	default:
		return nil, errors.New("unsupported signing algorithm")
	}
}

func acquirePrivateKey(cert *windows.CertContext) (kh uintptr, algorithmGroup string, callerMustFree bool, err error) {
	var (
		spec     uint32
		mustFree int
	)
	r, _, _ := winCryptAcquireCertificatePrivateKey.Call(
		uintptr(unsafe.Pointer(cert)),
		winAcquireCached|winAcquireSilent|winAcquireOnlyNCrypt,
		0,
		uintptr(unsafe.Pointer(&kh)),
		uintptr(unsafe.Pointer(&spec)),
		uintptr(unsafe.Pointer(&mustFree)),
	)
	if r == 0 || spec != winNcryptKeySpec {
		return 0, "", false, ErrNoPrivateKey
	}

	algGroup, err := getPropertyString(kh, winNCryptAlgorithmGroupProperty)
	if err != nil {
		algGroup = "RSA"
	}
	return kh, algGroup, mustFree != 0, nil
}

func signHashWithCert(cert *windows.CertContext, digest []byte, hash crypto.Hash) ([]byte, string, error) {
	kh, algGroup, callerMustFree, err := acquirePrivateKey(cert)
	if err != nil {
		return nil, "", err
	}
	if callerMustFree {
		defer freeNCryptObject(kh)
	}

	signer := &ncryptSigner{handle: kh, algorithmGroup: algGroup}
	sig, err := signer.Sign(nil, digest, hash)
	if err != nil {
		return nil, "", err
	}

	algName := "RSASSA-PKCS1-v1_5"
	if algGroup == "ECDSA" || algGroup == "ECDH" {
		algName = "ECDSA"
	}
	return sig, algName, nil
}

func signECDSA(kh uintptr, digest []byte) ([]byte, error) {
	var size uint32
	r, _, _ := winNCryptSignHash.Call(
		kh, 0,
		uintptr(unsafe.Pointer(&digest[0])),
		uintptr(len(digest)),
		0, 0,
		uintptr(unsafe.Pointer(&size)),
		0,
	)
	if r != 0 {
		return nil, windows.Errno(r)
	}

	buf := make([]byte, size)
	r, _, _ = winNCryptSignHash.Call(
		kh, 0,
		uintptr(unsafe.Pointer(&digest[0])),
		uintptr(len(digest)),
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(size),
		uintptr(unsafe.Pointer(&size)),
		0,
	)
	if r != 0 {
		return nil, windows.Errno(r)
	}
	return packECDSASignature(buf[:size], int(size/2))
}

func signRSAPKCS1(kh uintptr, digest []byte, algID *uint16) ([]byte, error) {
	padInfo := pkcs1PaddingInfo{pszAlgID: algID}
	var size uint32
	r, _, _ := winNCryptSignHash.Call(
		kh,
		uintptr(unsafe.Pointer(&padInfo)),
		uintptr(unsafe.Pointer(&digest[0])),
		uintptr(len(digest)),
		0, 0,
		uintptr(unsafe.Pointer(&size)),
		winBCryptPadPKCS1,
	)
	if r != 0 {
		return nil, windows.Errno(r)
	}

	sig := make([]byte, size)
	r, _, _ = winNCryptSignHash.Call(
		kh,
		uintptr(unsafe.Pointer(&padInfo)),
		uintptr(unsafe.Pointer(&digest[0])),
		uintptr(len(digest)),
		uintptr(unsafe.Pointer(&sig[0])),
		uintptr(size),
		uintptr(unsafe.Pointer(&size)),
		winBCryptPadPKCS1,
	)
	if r != 0 {
		return nil, windows.Errno(r)
	}
	return sig[:size], nil
}

func packECDSASignature(raw []byte, halfLen int) ([]byte, error) {
	if len(raw) < halfLen*2 {
		return nil, errors.New("invalid ECDSA signature length")
	}
	sigR := raw[:halfLen]
	sigS := raw[halfLen : halfLen*2]

	var b cryptobyte.Builder
	b.AddASN1(asn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddASN1BigInt(new(big.Int).SetBytes(sigR))
		b.AddASN1BigInt(new(big.Int).SetBytes(sigS))
	})
	return b.Bytes()
}

func getPropertyString(kh uintptr, property *uint16) (string, error) {
	buf, err := getProperty(kh, property)
	if err != nil {
		return "", err
	}
	if len(buf) < 2 {
		return "", errors.New("empty property value")
	}
	n := len(buf) / 2
	u16 := make([]uint16, n)
	for i := 0; i < n; i++ {
		u16[i] = uint16(buf[2*i]) | uint16(buf[2*i+1])<<8
	}
	return windows.UTF16ToString(u16), nil
}

func getProperty(kh uintptr, property *uint16) ([]byte, error) {
	var size uint32
	r, _, _ := winNCryptGetProperty.Call(
		kh,
		uintptr(unsafe.Pointer(property)),
		0, 0,
		uintptr(unsafe.Pointer(&size)),
		0,
	)
	if r != 0 {
		return nil, windows.Errno(r)
	}

	buf := make([]byte, size)
	r, _, _ = winNCryptGetProperty.Call(
		kh,
		uintptr(unsafe.Pointer(property)),
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(size),
		uintptr(unsafe.Pointer(&size)),
		0,
	)
	if r != 0 {
		return nil, windows.Errno(r)
	}
	return buf[:size], nil
}

func certProviderName(cert *windows.CertContext) string {
	var size uint32
	r, _, _ := winCertGetCertificateContextProperty.Call(
		uintptr(unsafe.Pointer(cert)),
		certKeyProvInfoPropID,
		0,
		uintptr(unsafe.Pointer(&size)),
	)
	if r == 0 || size == 0 {
		return ""
	}

	buf := make([]byte, size)
	r, _, _ = winCertGetCertificateContextProperty.Call(
		uintptr(unsafe.Pointer(cert)),
		certKeyProvInfoPropID,
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(unsafe.Pointer(&size)),
	)
	if r == 0 {
		return ""
	}

	info := (*cryptKeyProvInfo)(unsafe.Pointer(&buf[0]))
	if info.ProvName == nil {
		return ""
	}
	return windows.UTF16PtrToString(info.ProvName)
}

func isTPMCert(_ *windows.CertContext, providerName string) bool {
	return providerName == providerMPCP
}

func freeNCryptObject(handle uintptr) {
	if handle != 0 {
		winNCryptFreeObject.Call(handle)
	}
}

func stringToUTF16Ptr(s string) *uint16 {
	p, _ := windows.UTF16PtrFromString(s)
	return p
}

func hasPrivateKey(cert *windows.CertContext) bool {
	kh, _, callerMustFree, err := acquirePrivateKey(cert)
	if err != nil {
		return false
	}
	if callerMustFree {
		freeNCryptObject(kh)
	}
	return true
}
