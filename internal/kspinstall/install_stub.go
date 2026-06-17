//go:build !windows

package kspinstall

import "fmt"

func BindCertificateToKSP(certDER []byte, thumbprint string) error {
	return fmt.Errorf("kspinstall requires Windows")
}

func RemoveCertificateFromStore(thumbprint string) error {
	return fmt.Errorf("kspinstall requires Windows")
}
