package certstore_test

import (
	"crypto/sha256"
	"testing"

	"github.com/fredwangwang/keyless-tls-proxy/internal/certstore"
)

func TestListCertificates(t *testing.T) {
	certs, err := certstore.ListCertificates()
	if err != nil {
		t.Fatalf("ListCertificates returned error: %v", err)
	}
	t.Logf("Found %d certificates with private keys", len(certs))
	for i, c := range certs {
		t.Logf("[%d] Subject: %s, Thumbprint: %s, Alg: %s (%d-bit), Provider: %s",
			i+1, c.Subject, c.Thumbprint, c.KeyAlgorithm, c.KeySize, c.ProviderName)
	}
}

func TestSignHash(t *testing.T) {
	certs, err := certstore.ListCertificates()
	if err != nil {
		t.Fatalf("ListCertificates: %v", err)
	}
	if len(certs) == 0 {
		t.Skip("No certificates found to test SignHash")
	}

	selected := certs[0]
	t.Logf("Testing SignHash with certificate: %s (%s)", selected.Subject, selected.Thumbprint)

	data := []byte("hello cert server")
	digest := sha256.Sum256(data)

	resPKCS1, err := certstore.SignHash(selected.Thumbprint, digest[:], certstore.HashSHA256, certstore.RSAPaddingPKCS1)
	if err != nil {
		t.Fatalf("SignHash PKCS1 failed: %v", err)
	}
	t.Logf("PKCS1 Signature length: %d, SigAlg: %s", len(resPKCS1.Signature), resPKCS1.SignatureAlgorithm)

	if selected.KeyAlgorithm == "RSA" {
		resPSS, err := certstore.SignHash(selected.Thumbprint, digest[:], certstore.HashSHA256, certstore.RSAPaddingPSS)
		if err != nil {
			t.Fatalf("SignHash PSS failed: %v", err)
		}
		t.Logf("PSS Signature length: %d, SigAlg: %s", len(resPSS.Signature), resPSS.SignatureAlgorithm)
	}
}
