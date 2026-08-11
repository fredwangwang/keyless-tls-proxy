//go:build !windows && !darwin

package certstore

// ListCertificates returns certificates from the file-backed store configured
// with SetCertDir. On platforms without a native certificate store (Linux),
// this is the only available backend.
func ListCertificates() ([]CertificateInfo, error) {
	if CertDir() == "" {
		return nil, ErrUnsupportedPlatform
	}
	return listFromFileStore(), nil
}

// SignHash signs a digest using the private key of the matching certificate
// in the file-backed store configured with SetCertDir.
func SignHash(thumbprint string, digest []byte, hash HashAlgorithm, padding RSAPadding) (*SignResult, error) {
	if CertDir() == "" {
		return nil, ErrUnsupportedPlatform
	}
	return signWithFileStore(thumbprint, digest, hash, padding)
}
