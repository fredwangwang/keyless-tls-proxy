package certstore

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
)

// fileIdentity is a certificate/private-key pair loaded from a directory.
type fileIdentity struct {
	info        CertificateInfo
	thumbSHA1   string
	thumbSHA256 string
	signer      crypto.Signer
}

var (
	fileStoreMu  sync.RWMutex
	fileStoreDir string
	fileStore    []fileIdentity
)

// SetCertDir configures the file-backed certificate store. The directory is
// scanned for certificate files (*.crt, *.cer, *.pem); each certificate must
// have a private key either embedded in the same PEM file or in a sibling
// "<basename>.key" file. Passing an empty string clears the store.
func SetCertDir(dir string) error {
	if dir == "" {
		fileStoreMu.Lock()
		fileStore = nil
		fileStoreDir = ""
		fileStoreMu.Unlock()
		return nil
	}

	idents, err := loadCertDir(dir)
	if err != nil {
		return err
	}

	fileStoreMu.Lock()
	fileStore = idents
	fileStoreDir = dir
	fileStoreMu.Unlock()
	return nil
}

// CertDir returns the configured file store directory, or "" if unset.
func CertDir() string {
	fileStoreMu.RLock()
	defer fileStoreMu.RUnlock()
	return fileStoreDir
}

func loadCertDir(dir string) ([]fileIdentity, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("read cert dir: %w", err)
	}

	var files []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		switch strings.ToLower(filepath.Ext(e.Name())) {
		case ".crt", ".cer", ".pem":
			files = append(files, e.Name())
		}
	}
	sort.Strings(files)

	var out []fileIdentity
	for _, name := range files {
		path := filepath.Join(dir, name)

		der, ok, err := certFromFile(path)
		if err != nil {
			return nil, fmt.Errorf("read certificate %s: %w", name, err)
		}
		if !ok {
			continue // not a certificate file
		}

		cert, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, fmt.Errorf("parse certificate %s: %w", name, err)
		}

		priv, err := keyForFile(path)
		if err != nil {
			return nil, fmt.Errorf("certificate %s: %w", name, err)
		}

		// Verify the key actually belongs to the certificate.
		pubDER, err := x509.MarshalPKIXPublicKey(priv.Public())
		if err != nil || !bytes.Equal(pubDER, cert.RawSubjectPublicKeyInfo) {
			return nil, fmt.Errorf("certificate %s: private key does not match certificate", name)
		}

		sha1sum := sha1.Sum(der)
		sha256sum := sha256.Sum256(der)
		thumbSHA1 := strings.ToUpper(hex.EncodeToString(sha1sum[:]))
		thumbSHA256 := strings.ToUpper(hex.EncodeToString(sha256sum[:]))

		keyAlg, keySize := keyAlgSize(cert)
		out = append(out, fileIdentity{
			info: CertificateInfo{
				Thumbprint:     thumbSHA1,
				Subject:        cert.Subject.String(),
				Issuer:         cert.Issuer.String(),
				NotBefore:      cert.NotBefore,
				NotAfter:       cert.NotAfter,
				KeyAlgorithm:   keyAlg,
				KeySize:        keySize,
				HasPrivateKey:  true,
				IsTPM:          false,
				ProviderName:   "file store: " + dir,
				CertificateDER: append([]byte(nil), der...),
			},
			thumbSHA1:   thumbSHA1,
			thumbSHA256: thumbSHA256,
			signer:      priv,
		})
	}

	return out, nil
}

// certFromFile extracts the DER bytes of the first certificate found in the
// file (PEM or raw DER). ok is false when the file contains no certificate.
func certFromFile(path string) (der []byte, ok bool, err error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, false, err
	}

	rest := data
	for {
		block, r := pem.Decode(rest)
		if block == nil {
			break
		}
		rest = r
		if block.Type == "CERTIFICATE" {
			return block.Bytes, true, nil
		}
	}

	// Fall back to raw DER.
	if _, err := x509.ParseCertificate(data); err == nil {
		return data, true, nil
	}
	return nil, false, nil
}

// keyForFile loads the private key for a certificate file: first from PEM
// blocks inside the certificate file itself, then from a sibling
// "<basename>.key" file.
func keyForFile(certPath string) (crypto.Signer, error) {
	data, err := os.ReadFile(certPath)
	if err != nil {
		return nil, err
	}

	if k, ok, _ := parseKeyBytes(data); ok {
		return k, nil
	}

	sibling := strings.TrimSuffix(certPath, filepath.Ext(certPath)) + ".key"
	kdata, err := os.ReadFile(sibling)
	if err != nil {
		return nil, fmt.Errorf("no private key found in %s or %s", certPath, sibling)
	}
	k, ok, err := parseKeyBytes(kdata)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, fmt.Errorf("no private key found in %s", sibling)
	}
	return k, nil
}

func parseKeyBytes(data []byte) (crypto.Signer, bool, error) {
	rest := data
	for {
		block, r := pem.Decode(rest)
		if block == nil {
			break
		}
		rest = r
		if k, err := parseKeyBlock(block.Bytes, block.Type); err == nil && k != nil {
			return k, true, nil
		}
	}

	// Raw DER fallback.
	for _, parse := range []struct {
		fn func([]byte) (any, error)
	}{
		{func(b []byte) (any, error) { return x509.ParsePKCS8PrivateKey(b) }},
		{func(b []byte) (any, error) { return x509.ParsePKCS1PrivateKey(b) }},
		{func(b []byte) (any, error) { return x509.ParseECPrivateKey(b) }},
	} {
		if k, err := parse.fn(data); err == nil {
			if signer, ok := k.(crypto.Signer); ok {
				return signer, true, nil
			}
		}
	}
	return nil, false, nil
}

func parseKeyBlock(der []byte, blockType string) (crypto.Signer, error) {
	var k any
	var err error
	switch blockType {
	case "PRIVATE KEY":
		k, err = x509.ParsePKCS8PrivateKey(der)
	case "RSA PRIVATE KEY":
		k, err = x509.ParsePKCS1PrivateKey(der)
	case "EC PRIVATE KEY":
		k, err = x509.ParseECPrivateKey(der)
	default:
		return nil, fmt.Errorf("unsupported PEM block type %q", blockType)
	}
	if err != nil {
		return nil, err
	}
	signer, ok := k.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("private key type %T does not support signing", k)
	}
	return signer, nil
}

func keyAlgSize(cert *x509.Certificate) (string, int) {
	switch pub := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		return "RSA", pub.N.BitLen()
	case *ecdsa.PublicKey:
		return "ECDSA", pub.Curve.Params().BitSize
	default:
		return cert.PublicKeyAlgorithm.String(), 0
	}
}

func listFromFileStore() []CertificateInfo {
	fileStoreMu.RLock()
	defer fileStoreMu.RUnlock()
	out := make([]CertificateInfo, 0, len(fileStore))
	for i := range fileStore {
		out = append(out, fileStore[i].info)
	}
	return out
}

func signWithFileStore(thumbprint string, digest []byte, hash HashAlgorithm, padding RSAPadding) (*SignResult, error) {
	expectedLen, err := hash.DigestSize()
	if err != nil {
		return nil, err
	}
	if len(digest) != expectedLen {
		return nil, ErrInvalidDigest
	}
	if padding == 0 {
		padding = RSAPaddingPKCS1
	}

	fileStoreMu.RLock()
	defer fileStoreMu.RUnlock()

	target := cleanThumbprint(thumbprint)
	var matched *fileIdentity
	for i := range fileStore {
		if cleanThumbprint(fileStore[i].thumbSHA1) == target || cleanThumbprint(fileStore[i].thumbSHA256) == target {
			matched = &fileStore[i]
			break
		}
	}
	if matched == nil {
		for i := range fileStore {
			if strings.HasPrefix(cleanThumbprint(fileStore[i].thumbSHA1), target) ||
				strings.HasPrefix(cleanThumbprint(fileStore[i].thumbSHA256), target) {
				matched = &fileStore[i]
				break
			}
		}
	}
	if matched == nil {
		return nil, ErrCertificateNotFound
	}

	h, err := hash.CryptoHash()
	if err != nil {
		return nil, err
	}

	var sig []byte
	var sigAlg string
	switch k := matched.signer.(type) {
	case *rsa.PrivateKey:
		if padding == RSAPaddingPSS {
			sig, err = k.Sign(rand.Reader, digest, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: h})
			sigAlg = "RSASSA-PSS"
		} else {
			sig, err = k.Sign(rand.Reader, digest, h)
			sigAlg = "RSASSA-PKCS1-v1_5"
		}
	case *ecdsa.PrivateKey:
		if padding == RSAPaddingPSS {
			return nil, ErrInvalidPadding
		}
		sig, err = k.Sign(rand.Reader, digest, h)
		sigAlg = "ECDSA"
	default:
		return nil, fmt.Errorf("unsupported private key type %T", matched.signer)
	}
	if err != nil {
		return nil, fmt.Errorf("sign hash: %w", err)
	}

	return &SignResult{
		Signature:          sig,
		SignatureAlgorithm: sigAlg,
		Padding:            padding,
	}, nil
}
