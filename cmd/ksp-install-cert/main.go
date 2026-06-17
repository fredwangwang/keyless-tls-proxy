package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	certv1 "tpm-cert-proxy/gen/cert/v1"
	"tpm-cert-proxy/internal/kspclient"
	"tpm-cert-proxy/internal/kspcommon"
	"tpm-cert-proxy/internal/kspinstall"
	"tpm-cert-proxy/internal/kspmanifest"
	"tpm-cert-proxy/internal/tlsutil"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

func main() {
	addr := flag.String("addr", "127.0.0.1:50051", "gRPC server address")
	ca := flag.String("ca", "certs/ca.crt", "CA certificate")
	cert := flag.String("cert", "certs/client.crt", "client TLS certificate")
	key := flag.String("key", "certs/client.key", "client TLS private key")
	configOut := flag.String("write-config", "", "write mTLS config JSON to default or given path")
	list := flag.Bool("list", false, "list installed certificate bindings")
	remove := flag.String("remove", "", "remove installed cert by thumbprint")
	flag.Parse()

	if *list {
		if err := listInstalled(); err != nil {
			fatal(err)
		}
		return
	}
	if *remove != "" {
		if err := uninstall(*remove); err != nil {
			fatal(err)
		}
		return
	}

	cfg := &kspclient.Config{
		Addr: *addr,
		CA:   *ca,
		Cert: *cert,
		Key:  *key,
	}
	if *configOut != "" {
		path := *configOut
		if err := kspclient.SaveConfig(cfg, path); err != nil {
			fatal(fmt.Errorf("save config: %w", err))
		}
		fmt.Printf("Wrote config: %s\n", path)
	} else if err := kspclient.SaveConfig(cfg, kspcommon.ConfigPath()); err != nil {
		fatal(fmt.Errorf("save config: %w", err))
	}

	tlsConfig, err := tlsutil.LoadClientTLSConfig(cfg.CA, cfg.Cert, cfg.Key, hostFromAddr(cfg.Addr))
	if err != nil {
		fatal(err)
	}
	conn, err := grpc.NewClient(cfg.Addr, grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig)))
	if err != nil {
		fatal(err)
	}
	defer conn.Close()

	client := certv1.NewCertServiceClient(conn)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	resp, err := client.ListCertificates(ctx, &certv1.ListCertificatesRequest{})
	if err != nil {
		fatal(err)
	}
	certs := resp.Certificates
	if len(certs) == 0 {
		fatal(fmt.Errorf("no certificates with private keys found"))
	}

	fmt.Println("Available remote certificates:")
	for i, c := range certs {
		fmt.Printf("  [%d] %s\n      subject: %s\n      key: %s %d-bit\n", i+1, c.Thumbprint, c.Subject, c.KeyAlgorithm, c.KeySize)
	}

	reader := bufio.NewReader(os.Stdin)
	idx, err := readChoice(reader, len(certs))
	if err != nil {
		fatal(err)
	}
	selected := certs[idx]
	if len(selected.CertificateDer) == 0 {
		fatal(fmt.Errorf("server did not return certificate DER for selected cert"))
	}

	tp := kspmanifest.NormalizeThumbprint(selected.Thumbprint)
	if err := kspinstall.BindCertificateToKSP(selected.CertificateDer, tp); err != nil {
		fatal(err)
	}
	if err := kspmanifest.Add(tp, selected.Subject); err != nil {
		fatal(err)
	}

	fmt.Println()
	fmt.Printf("Installed certificate into Current User\\MY\n")
	fmt.Printf("  thumbprint: %s\n", tp)
	fmt.Printf("  subject:    %s\n", selected.Subject)
	fmt.Printf("  provider:   %s\n", kspcommon.ProviderName)
	fmt.Printf("  container:  %s\n", tp)
}

func listInstalled() error {
	m, err := kspmanifest.Load()
	if err != nil {
		return err
	}
	if len(m.Keys) == 0 {
		fmt.Println("No installed certificate bindings.")
		return nil
	}
	fmt.Println("Installed certificate bindings:")
	for _, e := range m.Keys {
		fmt.Printf("  %s\n    subject: %s\n    installed: %s\n", e.Thumbprint, e.Subject, e.InstalledAt.Format(time.RFC3339))
	}
	return nil
}

func uninstall(thumbprint string) error {
	tp := kspmanifest.NormalizeThumbprint(thumbprint)
	if err := kspinstall.RemoveCertificateFromStore(tp); err != nil {
		return err
	}
	if err := kspmanifest.Remove(tp); err != nil {
		return err
	}
	fmt.Printf("Removed certificate binding: %s\n", tp)
	return nil
}

func hostFromAddr(addr string) string {
	if h, _, err := net.SplitHostPort(addr); err == nil {
		return h
	}
	return addr
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
