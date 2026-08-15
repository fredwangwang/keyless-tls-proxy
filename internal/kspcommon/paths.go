package kspcommon

import (
	"os"
	"path/filepath"
)

const (
	ProviderName = "Fred Proxy Key Storage Provider"
	KSPLibrary   = "fredprx_ksp.dll"
	ConfigDir    = "fredprx-ksp"
)

func DataDir() string {
	base := os.Getenv("ProgramData")
	if base == "" {
		base = `C:\ProgramData`
	}
	return filepath.Join(base, ConfigDir)
}

func ConfigPath() string {
	return filepath.Join(DataDir(), "config.json")
}
