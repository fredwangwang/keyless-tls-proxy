package kspclient_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/fredwangwang/keyless-tls-proxy/internal/certstore"
	"github.com/fredwangwang/keyless-tls-proxy/internal/kspclient"
)

func writeTestCert(t *testing.T, dir, name string) string {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: name},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, priv.Public(), priv)
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

	sum := sha1.Sum(der)
	return certstore.NormalizeThumbprint(hex.EncodeToString(sum[:]))
}

func TestInstalledKeys_FileStore(t *testing.T) {
	dir := t.TempDir()
	tp1 := writeTestCert(t, dir, "ksp-cert-1")
	if err := certstore.SetCertDir(dir); err != nil {
		t.Fatalf("SetCertDir: %v", err)
	}
	defer certstore.SetCertDir("")

	client := &kspclient.Client{}
	keys, err := client.InstalledKeys(context.Background())
	if err != nil {
		t.Fatalf("InstalledKeys error: %v", err)
	}
	if len(keys) != 1 {
		t.Fatalf("expected 1 key, got %d", len(keys))
	}
	if keys[0].Thumbprint != tp1 {
		t.Fatalf("expected thumbprint %s, got %s", tp1, keys[0].Thumbprint)
	}
	if keys[0].Subject != "CN=ksp-cert-1" {
		t.Fatalf("expected subject CN=ksp-cert-1, got %s", keys[0].Subject)
	}
	if len(keys[0].RSAPublicBlob) == 0 {
		t.Fatalf("expected RSAPublicBlob to be populated for RSA key")
	}

	found, err := client.FindInstalled(context.Background(), tp1)
	if err != nil {
		t.Fatalf("FindInstalled error: %v", err)
	}
	if found.Thumbprint != tp1 {
		t.Fatalf("found thumbprint mismatch: %s vs %s", found.Thumbprint, tp1)
	}

	_, err = client.FindInstalled(context.Background(), "NONEXISTENT")
	if err != kspclient.ErrNotInstalled {
		t.Fatalf("expected ErrNotInstalled, got %v", err)
	}
}
