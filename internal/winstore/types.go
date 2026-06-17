package winstore

import (
	"crypto"
	"errors"
	"time"
)

var (
	ErrUnsupportedPlatform = errors.New("certificate store operations require Windows")
	ErrCertificateNotFound = errors.New("certificate not found")
	ErrNoPrivateKey        = errors.New("certificate has no accessible private key")
	ErrInvalidDigest       = errors.New("digest length does not match hash algorithm")
	ErrInvalidPadding      = errors.New("PSS padding is only supported for RSA keys")
)

// CertificateInfo describes a certificate in the Windows MY store.
type CertificateInfo struct {
	Thumbprint     string
	Subject        string
	Issuer         string
	NotBefore      time.Time
	NotAfter       time.Time
	KeyAlgorithm   string
	KeySize        int
	HasPrivateKey  bool
	IsTPM          bool
	ProviderName   string
}

// HashAlgorithm identifies the digest algorithm used for signing.
type HashAlgorithm int

const (
	HashSHA256 HashAlgorithm = iota + 1
	HashSHA384
	HashSHA512
)

func (h HashAlgorithm) CryptoHash() (crypto.Hash, error) {
	switch h {
	case HashSHA256:
		return crypto.SHA256, nil
	case HashSHA384:
		return crypto.SHA384, nil
	case HashSHA512:
		return crypto.SHA512, nil
	default:
		return 0, errors.New("unsupported hash algorithm")
	}
}

func (h HashAlgorithm) DigestSize() (int, error) {
	switch h {
	case HashSHA256:
		return 32, nil
	case HashSHA384:
		return 48, nil
	case HashSHA512:
		return 64, nil
	default:
		return 0, errors.New("unsupported hash algorithm")
	}
}

// RSAPadding selects the RSA signature padding scheme.
type RSAPadding int

const (
	RSAPaddingPKCS1 RSAPadding = 1
	RSAPaddingPSS   RSAPadding = 2
)

// SignResult contains the signature bytes and algorithm name.
type SignResult struct {
	Signature          []byte
	SignatureAlgorithm string
	Padding            RSAPadding
}
