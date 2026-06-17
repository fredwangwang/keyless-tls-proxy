package kspcommon

import (
	"os"
	"path/filepath"
)

const (
	ProviderName = "TPM Certificate Key Storage Provider"
	KSPLibrary   = "tpmcert_ksp.dll"
	ConfigDir    = "tpm-cert-ksp"
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

func ManifestPath() string {
	return filepath.Join(DataDir(), "installed.json")
}
