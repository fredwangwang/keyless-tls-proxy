//go:build windows

package kspregister

import (
	"fmt"
	"unsafe"

	"tpm-cert-proxy/internal/kspcommon"

	"golang.org/x/sys/windows"
)

const (
	cryptLocal                = 0
	ncryptKeyStorageInterface = 0x00010000
	cryptPriorityTop          = 0
)

var (
	modBCrypt = windows.NewLazySystemDLL("bcrypt.dll")

	procBCryptRegisterProvider              = modBCrypt.NewProc("BCryptRegisterProvider")
	procBCryptUnregisterProvider            = modBCrypt.NewProc("BCryptUnregisterProvider")
	procBCryptAddContextFunction            = modBCrypt.NewProc("BCryptAddContextFunction")
	procBCryptAddContextFunctionProvider    = modBCrypt.NewProc("BCryptAddContextFunctionProvider")
	procBCryptRemoveContextFunctionProvider = modBCrypt.NewProc("BCryptRemoveContextFunctionProvider")
	procBCryptEnumRegisteredProviders       = modBCrypt.NewProc("BCryptEnumRegisteredProviders")
	procBCryptFreeBuffer                    = modBCrypt.NewProc("BCryptFreeBuffer")
)

type cryptInterfaceReg struct {
	dwInterface    uint32
	dwFlags        uint32
	cFunctions     uint32
	rgpszFunctions uintptr
}

type cryptImageReg struct {
	pszImage      *uint16
	cInterfaces   uint32
	rgpInterfaces uintptr
}

type cryptProviderReg struct {
	cInterfaces   uint32
	rgpInterfaces uintptr
	pImage        uintptr
	pFunction     uintptr
}

type cryptProviders struct {
	cProviders     uint32
	rgpszProviders uintptr
}

func Register() error {
	providerName, err := windows.UTF16PtrFromString(kspcommon.ProviderName)
	if err != nil {
		return err
	}
	dllName, err := windows.UTF16PtrFromString(kspcommon.KSPLibrary)
	if err != nil {
		return err
	}
	keyStorageAlg, err := windows.UTF16PtrFromString("KEY_STORAGE")
	if err != nil {
		return err
	}

	algNames := [1]*uint16{keyStorageAlg}
	algClass := cryptInterfaceReg{
		dwInterface:    ncryptKeyStorageInterface,
		dwFlags:        cryptLocal,
		cFunctions:     1,
		rgpszFunctions: uintptr(unsafe.Pointer(&algNames[0])),
	}
	algClasses := [1]cryptInterfaceReg{algClass}
	image := cryptImageReg{
		pszImage:      dllName,
		cInterfaces:   1,
		rgpInterfaces: uintptr(unsafe.Pointer(&algClasses[0])),
	}
	provider := cryptProviderReg{
		cInterfaces:   0,
		rgpInterfaces: 0,
		pImage:        uintptr(unsafe.Pointer(&image)),
		pFunction:     0,
	}

	status, _, _ := procBCryptRegisterProvider.Call(
		uintptr(unsafe.Pointer(providerName)),
		0,
		uintptr(unsafe.Pointer(&provider)),
	)
	if status != 0 {
		return fmt.Errorf("BCryptRegisterProvider: NTSTATUS 0x%08X", status)
	}

	status, _, _ = procBCryptAddContextFunction.Call(
		cryptLocal,
		0,
		ncryptKeyStorageInterface,
		uintptr(unsafe.Pointer(keyStorageAlg)),
		cryptPriorityTop,
	)
	if status != 0 {
		return fmt.Errorf("BCryptAddContextFunction: NTSTATUS 0x%08X", status)
	}

	status, _, _ = procBCryptAddContextFunctionProvider.Call(
		cryptLocal,
		0,
		ncryptKeyStorageInterface,
		uintptr(unsafe.Pointer(keyStorageAlg)),
		uintptr(unsafe.Pointer(providerName)),
		cryptPriorityTop,
	)
	if status != 0 {
		return fmt.Errorf("BCryptAddContextFunctionProvider: NTSTATUS 0x%08X", status)
	}
	return nil
}

func Unregister() error {
	providerName, err := windows.UTF16PtrFromString(kspcommon.ProviderName)
	if err != nil {
		return err
	}
	keyStorageAlg, err := windows.UTF16PtrFromString("KEY_STORAGE")
	if err != nil {
		return err
	}

	status, _, _ := procBCryptRemoveContextFunctionProvider.Call(
		cryptLocal,
		0,
		ncryptKeyStorageInterface,
		uintptr(unsafe.Pointer(keyStorageAlg)),
		uintptr(unsafe.Pointer(providerName)),
	)
	if status != 0 {
		return fmt.Errorf("BCryptRemoveContextFunctionProvider: NTSTATUS 0x%08X", status)
	}

	status, _, _ = procBCryptUnregisterProvider.Call(uintptr(unsafe.Pointer(providerName)))
	if status != 0 {
		return fmt.Errorf("BCryptUnregisterProvider: NTSTATUS 0x%08X", status)
	}
	return nil
}

func EnumProviders() ([]string, error) {
	var cb uint32
	var buf *cryptProviders
	status, _, _ := procBCryptEnumRegisteredProviders.Call(
		uintptr(unsafe.Pointer(&cb)),
		uintptr(unsafe.Pointer(&buf)),
	)
	if status != 0 {
		return nil, fmt.Errorf("BCryptEnumRegisteredProviders: NTSTATUS 0x%08X", status)
	}
	if buf == nil {
		return nil, nil
	}
	defer procBCryptFreeBuffer.Call(uintptr(unsafe.Pointer(buf)))

	count := int(buf.cProviders)
	out := make([]string, 0, count)
	for i := 0; i < count; i++ {
		ptr := *(*uintptr)(unsafe.Pointer(buf.rgpszProviders + uintptr(i)*unsafe.Sizeof(uintptr(0))))
		out = append(out, windows.UTF16PtrToString((*uint16)(unsafe.Pointer(ptr))))
	}
	return out, nil
}
