package tlsutil

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
)

func LoadServerTLSConfig(caPath, certPath, keyPath string) (*tls.Config, error) {
	caPEM, err := os.ReadFile(caPath)
	if err != nil {
		return nil, fmt.Errorf("read CA cert: %w", err)
	}
	caPool := x509.NewCertPool()
	if !caPool.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("parse CA cert")
	}

	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
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
	caPEM, err := os.ReadFile(caPath)
	if err != nil {
		return nil, fmt.Errorf("read CA cert: %w", err)
	}
	caPool := x509.NewCertPool()
	if !caPool.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("parse CA cert")
	}

	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, fmt.Errorf("load client key pair: %w", err)
	}

	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      caPool,
		ServerName:   serverName,
		MinVersion:   tls.VersionTLS12,
	}, nil
}
