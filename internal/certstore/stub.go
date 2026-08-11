//go:build !windows && !darwin

package certstore

func ListCertificates() ([]CertificateInfo, error) {
	return nil, ErrUnsupportedPlatform
}

func SignHash(thumbprint string, digest []byte, hash HashAlgorithm, padding RSAPadding) (*SignResult, error) {
	return nil, ErrUnsupportedPlatform
}
