//go:build !windows

package winstore

func ListCertificates() ([]CertificateInfo, error) {
	return nil, ErrUnsupportedPlatform
}

func SignHash(thumbprint string, digest []byte, hash HashAlgorithm) (*SignResult, error) {
	return nil, ErrUnsupportedPlatform
}
