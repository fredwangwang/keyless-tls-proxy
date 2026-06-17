//go:build windows

package kspregister

/*
#cgo LDFLAGS: -lbcrypt -lncrypt
#include <windows.h>
#include <bcrypt.h>
#include <ncrypt.h>

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

NTSTATUS WINAPI BCryptRegisterProvider(LPCWSTR pszProvider, ULONG ulFlags, PCRYPT_PROVIDER_REG pReg);
NTSTATUS WINAPI BCryptUnregisterProvider(LPCWSTR pszProvider);
NTSTATUS WINAPI BCryptAddContextFunction(ULONG dwTable, LPCWSTR pszContext, ULONG dwInterface, LPCWSTR pszFunction, ULONG dwPosition);
NTSTATUS WINAPI BCryptAddContextFunctionProvider(ULONG dwTable, LPCWSTR pszContext, ULONG dwInterface, LPCWSTR pszFunction, LPCWSTR pszProvider, ULONG dwPosition);
NTSTATUS WINAPI BCryptRemoveContextFunctionProvider(ULONG dwTable, LPCWSTR pszContext, ULONG dwInterface, LPCWSTR pszFunction, LPCWSTR pszProvider);

static PWSTR tpmcertAlgorithmNames[1] = { (PWSTR)NCRYPT_KEY_STORAGE_ALGORITHM };

static CRYPT_INTERFACE_REG tpmcertAlgorithmClass = {
    NCRYPT_KEY_STORAGE_INTERFACE,
    CRYPT_LOCAL,
    1,
    tpmcertAlgorithmNames
};

static PCRYPT_INTERFACE_REG tpmcertAlgorithmClasses[1] = { &tpmcertAlgorithmClass };

static CRYPT_IMAGE_REG tpmcertKspImage = {
    (PWSTR)L"tpmcert_ksp.dll",
    1,
    tpmcertAlgorithmClasses
};

static CRYPT_PROVIDER_REG tpmcertKspProvider = {
    0,
    NULL,
    &tpmcertKspImage,
    NULL
};

static NTSTATUS tpmcertRegisterProvider(void) {
    return BCryptRegisterProvider(
        L"TPM Certificate Key Storage Provider",
        0,
        &tpmcertKspProvider);
}

static NTSTATUS tpmcertAddContextFunction(void) {
    return BCryptAddContextFunction(
        CRYPT_LOCAL,
        NULL,
        NCRYPT_KEY_STORAGE_INTERFACE,
        NCRYPT_KEY_STORAGE_ALGORITHM,
        CRYPT_PRIORITY_TOP);
}

static NTSTATUS tpmcertAddContextFunctionProvider(void) {
    return BCryptAddContextFunctionProvider(
        CRYPT_LOCAL,
        NULL,
        NCRYPT_KEY_STORAGE_INTERFACE,
        NCRYPT_KEY_STORAGE_ALGORITHM,
        L"TPM Certificate Key Storage Provider",
        CRYPT_PRIORITY_TOP);
}

static NTSTATUS tpmcertRemoveContextFunctionProvider(void) {
    return BCryptRemoveContextFunctionProvider(
        CRYPT_LOCAL,
        NULL,
        NCRYPT_KEY_STORAGE_INTERFACE,
        NCRYPT_KEY_STORAGE_ALGORITHM,
        L"TPM Certificate Key Storage Provider");
}

static NTSTATUS tpmcertUnregisterProvider(void) {
    return BCryptUnregisterProvider(L"TPM Certificate Key Storage Provider");
}
*/
import "C"

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

func Register() error {
	if st := C.tpmcertRegisterProvider(); st != 0 {
		return fmt.Errorf("BCryptRegisterProvider: NTSTATUS 0x%08X", uint32(st))
	}
	if st := C.tpmcertAddContextFunction(); st != 0 {
		return fmt.Errorf("BCryptAddContextFunction: NTSTATUS 0x%08X", uint32(st))
	}
	if st := C.tpmcertAddContextFunctionProvider(); st != 0 {
		return fmt.Errorf("BCryptAddContextFunctionProvider: NTSTATUS 0x%08X", uint32(st))
	}
	return nil
}

func Unregister() error {
	if st := C.tpmcertRemoveContextFunctionProvider(); st != 0 {
		return fmt.Errorf("BCryptRemoveContextFunctionProvider: NTSTATUS 0x%08X", uint32(st))
	}
	if st := C.tpmcertUnregisterProvider(); st != 0 {
		return fmt.Errorf("BCryptUnregisterProvider: NTSTATUS 0x%08X", uint32(st))
	}
	return nil
}

func EnumProviders() ([]string, error) {
	mod := windows.NewLazySystemDLL("bcrypt.dll")
	procEnum := mod.NewProc("BCryptEnumRegisteredProviders")
	procFree := mod.NewProc("BCryptFreeBuffer")

	type cryptProviders struct {
		cProviders     uint32
		rgpszProviders *uintptr
	}

	var cb uint32
	var buf *cryptProviders
	status, _, _ := procEnum.Call(
		uintptr(unsafe.Pointer(&cb)),
		uintptr(unsafe.Pointer(&buf)),
	)
	if status != 0 {
		return nil, fmt.Errorf("BCryptEnumRegisteredProviders: NTSTATUS 0x%08X", status)
	}
	if buf == nil {
		return nil, nil
	}
	defer procFree.Call(uintptr(unsafe.Pointer(buf)))

	count := int(buf.cProviders)
	out := make([]string, 0, count)
	for i := 0; i < count; i++ {
		ptr := *(*uintptr)(unsafe.Add(unsafe.Pointer(buf.rgpszProviders), i*int(unsafe.Sizeof(uintptr(0)))))
		out = append(out, windows.UTF16PtrToString((*uint16)(unsafe.Pointer(ptr))))
	}
	return out, nil
}
