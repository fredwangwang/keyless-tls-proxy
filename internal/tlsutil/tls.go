package tlsutil

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"strings"
)

func loadPEMOrFile(input string) ([]byte, error) {
	input = strings.TrimSpace(input)
	if strings.Contains(input, "-----BEGIN") {
		return []byte(input), nil
	}
	return os.ReadFile(input)
}

func LoadServerTLSConfig(caPath, certPath, keyPath string) (*tls.Config, error) {
	caPEM, err := loadPEMOrFile(caPath)
	if err != nil {
		return nil, fmt.Errorf("read CA cert: %w", err)
	}
	caPool := x509.NewCertPool()
	if !caPool.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("parse CA cert")
	}

	certPEM, err := loadPEMOrFile(certPath)
	if err != nil {
		return nil, fmt.Errorf("read server cert: %w", err)
	}
	keyPEM, err := loadPEMOrFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("read server key: %w", err)
	}
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("load server key pair: %w", err)
	}

	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientCAs:    caPool,
		ClientAuth:   tls.RequireAndVerifyClientCert,
		MinVersion:   tls.VersionTLS12,
	}, nil
}

func LoadClientTLSConfig(caPath, certPath, keyPath, serverName string) (*tls.Config, error) {
	caPEM, err := loadPEMOrFile(caPath)
	if err != nil {
		return nil, fmt.Errorf("read CA cert: %w", err)
	}
	caPool := x509.NewCertPool()
	if !caPool.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("parse CA cert")
	}

	certPEM, err := loadPEMOrFile(certPath)
	if err != nil {
		return nil, fmt.Errorf("read client cert: %w", err)
	}
	keyPEM, err := loadPEMOrFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("read client key: %w", err)
	}
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("load client key pair: %w", err)
	}

	return &tls.Config{
		Certificates:       []tls.Certificate{cert},
		RootCAs:            caPool,
		ServerName:         serverName,
		InsecureSkipVerify: true,
		VerifyPeerCertificate: func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
			if len(rawCerts) == 0 {
				return fmt.Errorf("no peer certificates presented")
			}
			certs := make([]*x509.Certificate, len(rawCerts))
			for i, asn1Data := range rawCerts {
				c, err := x509.ParseCertificate(asn1Data)
				if err != nil {
					return fmt.Errorf("parse peer certificate: %w", err)
				}
				certs[i] = c
			}

			opts := x509.VerifyOptions{
				Roots:         caPool,
				Intermediates: x509.NewCertPool(),
			}
			for _, c := range certs[1:] {
				opts.Intermediates.AddCert(c)
			}
			_, err := certs[0].Verify(opts)
			return err
		},
		MinVersion: tls.VersionTLS12,
	}, nil
}
