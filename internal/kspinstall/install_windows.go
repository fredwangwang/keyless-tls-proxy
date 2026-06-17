//go:build windows

package kspinstall

import (
	"crypto/x509"
	"fmt"
	"strings"
	"unsafe"

	"tpm-cert-proxy/internal/kspcommon"

	"golang.org/x/sys/windows"
)

const (
	certKeyProvInfoPropID = 2 // CERT_KEY_PROV_INFO_PROP_ID
	certStoreProvSystem   = 0x0000000A
	certSystemStoreCurrentUser = 0x00010000
	certStoreReadWrite    = 0x00008000
	certStoreAddReplace   = 3
	atKeyExchange         = 1
	atSignature           = 2
)

var (
	crypt32 = windows.NewLazySystemDLL("crypt32.dll")

	procCertCreateCertificateContext      = crypt32.NewProc("CertCreateCertificateContext")
	procCertFreeCertificateContext        = crypt32.NewProc("CertFreeCertificateContext")
	procCertSetCertificateContextProperty = crypt32.NewProc("CertSetCertificateContextProperty")
	procCertOpenStore                     = crypt32.NewProc("CertOpenStore")
	procCertCloseStore                    = crypt32.NewProc("CertCloseStore")
	procCertAddCertificateContextToStore  = crypt32.NewProc("CertAddCertificateContextToStore")
	procCertFindCertificateInStore        = crypt32.NewProc("CertFindCertificateInStore")
	procCertDeleteCertificateFromStore    = crypt32.NewProc("CertDeleteCertificateFromStore")
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

func InferKeySpec(cert *x509.Certificate) uint32 {
	for _, u := range cert.ExtKeyUsage {
		if u == x509.ExtKeyUsageClientAuth || u == x509.ExtKeyUsageEmailProtection {
			return atSignature
		}
	}
	if cert.KeyUsage&x509.KeyUsageDigitalSignature != 0 {
		return atSignature
	}
	return atKeyExchange
}

func BindCertificateToKSP(certDER []byte, thumbprint string) error {
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return fmt.Errorf("parse certificate: %w", err)
	}
	keySpec := InferKeySpec(cert)

	ctx, err := createCertContext(certDER)
	if err != nil {
		return err
	}
	defer freeCertContext(ctx)

	tp := strings.ToUpper(strings.ReplaceAll(strings.TrimSpace(thumbprint), " ", ""))
	container, err := windows.UTF16PtrFromString(tp)
	if err != nil {
		return err
	}
	provider, err := windows.UTF16PtrFromString(kspcommon.ProviderName)
	if err != nil {
		return err
	}
	info := cryptKeyProvInfo{
		ContainerName: container,
		ProvName:      provider,
		ProvType:      0,
		Flags:         0,
		KeySpec:       keySpec,
	}
	r, _, errno := procCertSetCertificateContextProperty.Call(
		uintptr(unsafe.Pointer(ctx)),
		certKeyProvInfoPropID,
		0,
		uintptr(unsafe.Pointer(&info)),
	)
	if r == 0 {
		return fmt.Errorf("set key prov info: %w", errno)
	}

	store, err := openMyStore()
	if err != nil {
		return err
	}
	defer closeStore(store)

	r, _, errno = procCertAddCertificateContextToStore.Call(
		store,
		uintptr(unsafe.Pointer(ctx)),
		certStoreAddReplace,
		0,
	)
	if r == 0 {
		return fmt.Errorf("add certificate to store: %w", errno)
	}
	return nil
}

func RemoveCertificateFromStore(thumbprint string) error {
	store, err := openMyStore()
	if err != nil {
		return err
	}
	defer closeStore(store)

	ctx, err := findCertByThumbprint(store, thumbprint)
	if err != nil {
		return err
	}
	defer freeCertContext(ctx)

	r, _, errno := procCertDeleteCertificateFromStore.Call(uintptr(unsafe.Pointer(ctx)))
	if r == 0 {
		return fmt.Errorf("delete certificate: %w", errno)
	}
	return nil
}

func openMyStore() (uintptr, error) {
	myStore, _ := windows.UTF16PtrFromString("MY")
	r, _, errno := procCertOpenStore.Call(
		certStoreProvSystem,
		0,
		0,
		certSystemStoreCurrentUser|certStoreReadWrite,
		uintptr(unsafe.Pointer(myStore)),
	)
	if r == 0 {
		return 0, fmt.Errorf("open MY store: %w", errno)
	}
	return r, nil
}

func closeStore(store uintptr) {
	procCertCloseStore.Call(store, 0)
}

func createCertContext(der []byte) (*windows.CertContext, error) {
	if len(der) == 0 {
		return nil, fmt.Errorf("empty certificate DER")
	}
	r, _, errno := procCertCreateCertificateContext.Call(
		windows.X509_ASN_ENCODING|windows.PKCS_7_ASN_ENCODING,
		uintptr(unsafe.Pointer(&der[0])),
		uintptr(len(der)),
	)
	if r == 0 {
		return nil, fmt.Errorf("create cert context: %w", errno)
	}
	return (*windows.CertContext)(unsafe.Pointer(r)), nil
}

func freeCertContext(ctx *windows.CertContext) {
	if ctx != nil {
		procCertFreeCertificateContext.Call(uintptr(unsafe.Pointer(ctx)))
	}
}

func findCertByThumbprint(store uintptr, thumbprint string) (*windows.CertContext, error) {
	normalized := strings.ToUpper(strings.ReplaceAll(strings.TrimSpace(thumbprint), " ", ""))
	ptr, err := windows.UTF16PtrFromString(normalized)
	if err != nil {
		return nil, fmt.Errorf("certificate not found")
	}
	r, _, errno := procCertFindCertificateInStore.Call(
		store,
		windows.X509_ASN_ENCODING|windows.PKCS_7_ASN_ENCODING,
		0,
		windows.CERT_FIND_HASH_STR,
		uintptr(unsafe.Pointer(ptr)),
		0,
	)
	if r == 0 {
		return nil, fmt.Errorf("certificate not found: %w", errno)
	}
	return (*windows.CertContext)(unsafe.Pointer(r)), nil
}
