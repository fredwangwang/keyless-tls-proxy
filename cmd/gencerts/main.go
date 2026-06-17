package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"flag"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"
)

func main() {
	outDir := flag.String("out", "certs", "output directory for generated PEM files")
	cn := flag.String("cn", "tpm-cert-proxy", "CA common name")
	force := flag.Bool("force", false, "overwrite existing files")
	flag.Parse()

	if err := os.MkdirAll(*outDir, 0o755); err != nil {
		fatal(err)
	}

	files := []string{"ca.crt", "ca.key", "server.crt", "server.key", "client.crt", "client.key"}
	for _, name := range files {
		path := filepath.Join(*outDir, name)
		if _, err := os.Stat(path); err == nil && !*force {
			fatal(fmt.Errorf("%s already exists (use -force to overwrite)", path))
		}
	}

	caKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		fatal(err)
	}

	now := time.Now()
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: *cn + " CA"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(10 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		fatal(err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		fatal(err)
	}

	serverKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		fatal(err)
	}
	serverTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: *cn + " Server"},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(2 * 365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	serverDER, err := x509.CreateCertificate(rand.Reader, serverTemplate, caCert, &serverKey.PublicKey, caKey)
	if err != nil {
		fatal(err)
	}

	clientKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		fatal(err)
	}
	clientTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(3),
		Subject:      pkix.Name{CommonName: *cn + " Client"},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(2 * 365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	clientDER, err := x509.CreateCertificate(rand.Reader, clientTemplate, caCert, &clientKey.PublicKey, caKey)
	if err != nil {
		fatal(err)
	}

	writeCert(filepath.Join(*outDir, "ca.crt"), caDER)
	writeKey(filepath.Join(*outDir, "ca.key"), caKey)
	writeCert(filepath.Join(*outDir, "server.crt"), serverDER)
	writeKey(filepath.Join(*outDir, "server.key"), serverKey)
	writeCert(filepath.Join(*outDir, "client.crt"), clientDER)
	writeKey(filepath.Join(*outDir, "client.key"), clientKey)

	fmt.Printf("Generated mTLS certificates in %s\n\n", *outDir)
	fmt.Println("Start server:")
	fmt.Printf("  go run ./cmd/cert-server -addr 127.0.0.1:50051 -ca %s/ca.crt -cert %s/server.crt -key %s/server.key\n", *outDir, *outDir, *outDir)
	fmt.Println("Run client:")
	fmt.Printf("  go run ./cmd/example-client -addr 127.0.0.1:50051 -ca %s/ca.crt -cert %s/client.crt -key %s/client.key\n", *outDir, *outDir, *outDir)
}

func writeCert(path string, der []byte) {
	f, err := os.Create(path)
	if err != nil {
		fatal(err)
	}
	defer f.Close()
	if err := pem.Encode(f, &pem.Block{Type: "CERTIFICATE", Bytes: der}); err != nil {
		fatal(err)
	}
}

func writeKey(path string, key *rsa.PrivateKey) {
	f, err := os.Create(path)
	if err != nil {
		fatal(err)
	}
	defer f.Close()
	if err := pem.Encode(f, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	}); err != nil {
		fatal(err)
	}
}

func fatal(err error) {
	fmt.Fprintf(os.Stderr, "error: %v\n", err)
	os.Exit(1)
}
