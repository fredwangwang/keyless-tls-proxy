package main

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"flag"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	certv1 "tpm-cert-proxy/gen/cert/v1"
	"tpm-cert-proxy/internal/tlsutil"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

func main() {
	addr := flag.String("addr", "127.0.0.1:50051", "gRPC server address")
	ca := flag.String("ca", "certs/ca.crt", "CA certificate")
	cert := flag.String("cert", "certs/client.crt", "client TLS certificate")
	key := flag.String("key", "certs/client.key", "client TLS private key")
	message := flag.String("message", "", "message to hash and sign (prompts if empty)")
	padding := flag.String("padding", "", "RSA padding: pkcs1 or pss (prompts if empty)")
	flag.Parse()

	host, _, err := net.SplitHostPort(*addr)
	if err != nil {
		// Allow host-only addresses for default local usage.
		host = *addr
	}

	tlsConfig, err := tlsutil.LoadClientTLSConfig(*ca, *cert, *key, host)
	if err != nil {
		fatal(err)
	}

	conn, err := grpc.NewClient(
		*addr,
		grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig)),
	)
	if err != nil {
		fatal(err)
	}
	defer conn.Close()

	client := certv1.NewCertServiceClient(conn)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	resp, err := client.ListCertificates(ctx, &certv1.ListCertificatesRequest{})
	if err != nil {
		fatal(err)
	}
	if len(resp.Certificates) == 0 {
		fatal(fmt.Errorf("no certificates with private keys found"))
	}

	fmt.Println("Available certificates:")
	for i, c := range resp.Certificates {
		tpm := "no"
		if c.IsTpm {
			tpm = "yes"
		}
		fmt.Printf(
			"  [%d] %s\n      subject: %s\n      key: %s %d-bit  tpm: %s  provider: %s\n",
			i+1,
			c.Thumbprint,
			c.Subject,
			c.KeyAlgorithm,
			c.KeySize,
			tpm,
			c.ProviderName,
		)
	}

	reader := bufio.NewReader(os.Stdin)
	idx, err := readChoice(reader, len(resp.Certificates))
	if err != nil {
		fatal(err)
	}
	selected := resp.Certificates[idx]

	text := *message
	if text == "" {
		fmt.Print("Enter text to sign: ")
		text, err = reader.ReadString('\n')
		if err != nil {
			fatal(err)
		}
		text = strings.TrimSpace(text)
	}
	if text == "" {
		fatal(fmt.Errorf("message must not be empty"))
	}

	rsaPadding, err := resolvePadding(reader, *padding)
	if err != nil {
		fatal(err)
	}

	digest := sha256.Sum256([]byte(text))
	signResp, err := client.SignHash(ctx, &certv1.SignHashRequest{
		Thumbprint:    selected.Thumbprint,
		Digest:        digest[:],
		HashAlgorithm: certv1.HashAlgorithm_SHA256,
		RsaPadding:    rsaPadding,
	})
	if err != nil {
		fatal(err)
	}

	fmt.Println()
	fmt.Printf("Certificate: %s\n", selected.Subject)
	fmt.Printf("Digest (SHA-256): %s\n", hex.EncodeToString(digest[:]))
	fmt.Printf("RSA padding: %s\n", signResp.RsaPadding.String())
	fmt.Printf("Signature algorithm: %s\n", signResp.SignatureAlgorithm)
	fmt.Printf("Signature (base64): %s\n", base64.StdEncoding.EncodeToString(signResp.Signature))
	fmt.Printf("Signature (hex): %s\n", hex.EncodeToString(signResp.Signature))
}

func resolvePadding(reader *bufio.Reader, flagValue string) (certv1.RSAPadding, error) {
	value := strings.ToLower(strings.TrimSpace(flagValue))
	if value == "" {
		fmt.Print("RSA padding [pkcs1/pss] (default pkcs1): ")
		line, err := reader.ReadString('\n')
		if err != nil {
			return certv1.RSAPadding_RSA_PADDING_UNSPECIFIED, err
		}
		value = strings.ToLower(strings.TrimSpace(line))
	}
	switch value {
	case "", "pkcs1", "pkcs1v15", "pkcs#1":
		return certv1.RSAPadding_PKCS1, nil
	case "pss", "rsapss", "rsa-pss":
		return certv1.RSAPadding_PSS, nil
	default:
		return certv1.RSAPadding_RSA_PADDING_UNSPECIFIED, fmt.Errorf("padding must be pkcs1 or pss")
	}
}

func readChoice(reader *bufio.Reader, max int) (int, error) {
	for {
		fmt.Printf("Enter certificate number (1-%d): ", max)
		line, err := reader.ReadString('\n')
		if err != nil {
			return 0, err
		}
		n, err := strconv.Atoi(strings.TrimSpace(line))
		if err != nil || n < 1 || n > max {
			fmt.Println("Invalid selection, try again.")
			continue
		}
		return n - 1, nil
	}
}

func fatal(err error) {
	fmt.Fprintf(os.Stderr, "error: %v\n", err)
	os.Exit(1)
}
