package certstore_test

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/fredwangwang/keyless-tls-proxy/internal/certstore"
)

// writeCertKeyPair writes a self-signed certificate and its private key as
// <name>.crt / <name>.key PEM files into dir.
func writeCertKeyPair(t *testing.T, dir, name string, isRSA bool) {
	t.Helper()

	var priv any
	var err error
	if isRSA {
		priv, err = rsa.GenerateKey(rand.Reader, 2048)
	} else {
		priv, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	}
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: name},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	signer := priv.(crypto.Signer)
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, signer.Public(), signer)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}

	certPath := filepath.Join(dir, name+".crt")
	keyPath := filepath.Join(dir, name+".key")

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	if err := os.WriteFile(certPath, certPEM, 0644); err != nil {
		t.Fatalf("write cert: %v", err)
	}

	keyDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	if err := os.WriteFile(keyPath, keyPEM, 0600); err != nil {
		t.Fatalf("write key: %v", err)
	}
}

func TestFileStoreListAndSign(t *testing.T) {
	dir := t.TempDir()
	writeCertKeyPair(t, dir, "rsa-cert", true)
	writeCertKeyPair(t, dir, "ec-cert", false)
	// A PEM file without a key should be skipped.
	if err := os.WriteFile(filepath.Join(dir, "notes.pem"), []byte("not a cert"), 0644); err != nil {
		t.Fatal(err)
	}

	if err := certstore.SetCertDir(dir); err != nil {
		t.Fatalf("SetCertDir: %v", err)
	}
	defer certstore.SetCertDir("")

	certs, err := certstore.ListCertificates()
	if err != nil {
		t.Fatalf("ListCertificates: %v", err)
	}
	if len(certs) != 2 {
		t.Fatalf("expected 2 certificates, got %d", len(certs))
	}

	digest := sha256.Sum256([]byte("hello file store"))

	for _, c := range certs {
		if !c.HasPrivateKey {
			t.Errorf("cert %s: HasPrivateKey should be true", c.Subject)
		}
		if c.ProviderName == "" {
			t.Errorf("cert %s: provider name should be set", c.Subject)
		}

		res, err := certstore.SignHash(c.Thumbprint, digest[:], certstore.HashSHA256, certstore.RSAPaddingPKCS1)
		if err != nil {
			t.Fatalf("SignHash(%s): %v", c.Subject, err)
		}
		if len(res.Signature) == 0 {
			t.Errorf("cert %s: empty signature", c.Subject)
		}

		// Verify the signature against the certificate's public key.
		cert, err := x509.ParseCertificate(c.CertificateDER)
		if err != nil {
			t.Fatalf("parse cert: %v", err)
		}
		switch pub := cert.PublicKey.(type) {
		case *rsa.PublicKey:
			if err := rsa.VerifyPKCS1v15(pub, crypto.SHA256, digest[:], res.Signature); err != nil {
				t.Errorf("cert %s: RSA signature did not verify: %v", c.Subject, err)
			}
		case *ecdsa.PublicKey:
			if !ecdsa.VerifyASN1(pub, digest[:], res.Signature) {
				t.Errorf("cert %s: ECDSA signature did not verify", c.Subject)
			}
		default:
			t.Errorf("cert %s: unexpected key type %T", c.Subject, cert.PublicKey)
		}
	}
}

func TestFileStoreMismatchedKey(t *testing.T) {
	dir := t.TempDir()
	writeCertKeyPair(t, dir, "a", true)

	// Overwrite the key with a different one.
	other, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(other)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	if err := os.WriteFile(filepath.Join(dir, "a.key"), keyPEM, 0600); err != nil {
		t.Fatal(err)
	}

	if err := certstore.SetCertDir(dir); err == nil {
		t.Fatal("SetCertDir should fail when key does not match certificate")
	}
}
