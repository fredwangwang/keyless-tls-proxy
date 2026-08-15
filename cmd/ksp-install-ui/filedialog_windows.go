//go:build windows

package main

import (
	"path/filepath"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	comdlg32             = windows.NewLazySystemDLL("comdlg32.dll")
	procGetOpenFileNameW = comdlg32.NewProc("GetOpenFileNameW")
)

type openFileNameW struct {
	lStructSize       uint32
	hwndOwner         windows.HWND
	hInstance         windows.Handle
	lpstrFilter       *uint16
	lpstrCustomFilter *uint16
	nMaxCustFilter    uint32
	nFilterIndex      uint32
	lpstrFile         *uint16
	nMaxFile          uint32
	lpstrFileTitle    *uint16
	nMaxFileTitle     uint32
	lpstrInitialDir   *uint16
	lpstrTitle        *uint16
	flags             uint32
	nFileOffset       uint16
	nFileExtension    uint16
	lpstrDefExt       *uint16
	lCustData         uintptr
	lpfnHook          uintptr
	lpTemplateName    *uint16
	pvReserved        unsafe.Pointer
	dwReserved        uint32
	flagsEx           uint32
}

const (
	ofnFileMustExist = 0x00001000
	ofnPathMustExist = 0x00000800
	ofnExplorer      = 0x00080000
	ofnNoChangeDir   = 0x00000008
	ofnHideReadOnly  = 0x00000004
)

// selectFileDialog opens a native Windows file selection dialog.
func selectFileDialog(title string, filterDesc string, filterPattern string) (string, error) {
	if title == "" {
		title = "Select File"
	}
	if filterDesc == "" {
		filterDesc = "All Files (*.*)"
		filterPattern = "*.*"
	}

	// Filter string format in Win32: "Description\0Pattern\0\0"
	var filterUTF16 []uint16
	for _, r := range filterDesc {
		filterUTF16 = append(filterUTF16, uint16(r))
	}
	filterUTF16 = append(filterUTF16, 0)
	for _, r := range filterPattern {
		filterUTF16 = append(filterUTF16, uint16(r))
	}
	filterUTF16 = append(filterUTF16, 0, 0)

	titleUTF16, err := windows.UTF16PtrFromString(title)
	if err != nil {
		return "", err
	}

	fileBuf := make([]uint16, 2048)

	var ofn openFileNameW
	ofn.lStructSize = uint32(unsafe.Sizeof(ofn))
	ofn.lpstrFilter = &filterUTF16[0]
	ofn.nFilterIndex = 1
	ofn.lpstrFile = &fileBuf[0]
	ofn.nMaxFile = uint32(len(fileBuf))
	ofn.lpstrTitle = titleUTF16
	ofn.flags = ofnFileMustExist | ofnPathMustExist | ofnExplorer | ofnNoChangeDir | ofnHideReadOnly

	r, _, _ := procGetOpenFileNameW.Call(uintptr(unsafe.Pointer(&ofn)))
	if r == 0 {
		return "", nil // user canceled or closed dialog
	}

	path := windows.UTF16ToString(fileBuf)
	return filepath.Clean(strings.TrimSpace(path)), nil
}
