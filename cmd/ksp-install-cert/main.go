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

	certv1 "github.com/fredwangwang/keyless-tls-proxy/gen/cert/v1"
	"github.com/fredwangwang/keyless-tls-proxy/internal/kspclient"
	"github.com/fredwangwang/keyless-tls-proxy/internal/kspcommon"
	"github.com/fredwangwang/keyless-tls-proxy/internal/kspinstall"
	"github.com/fredwangwang/keyless-tls-proxy/internal/kspmanifest"
	"github.com/fredwangwang/keyless-tls-proxy/internal/server"
	"github.com/fredwangwang/keyless-tls-proxy/internal/tlsutil"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

func main() {
	addr := flag.String("addr", "", "gRPC server address")
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

	resolvedAddr := *addr
	if resolvedAddr == "" {
		reader := bufio.NewReader(os.Stdin)
		for {
			fmt.Print("Enter server address (IP/hostname:port) or press Enter to discover: ")
			input, err := reader.ReadString('\n')
			if err != nil {
				fatal(err)
			}
			input = strings.TrimSpace(input)
			if input == "" {
				fmt.Println("Discovering servers on local network...")
				ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
				servers, err := server.DiscoverServers(ctx, server.DiscoverClientConfig{Timeout: 3 * time.Second})
				cancel()
				if err != nil {
					fmt.Printf("Discovery failed: %v\n", err)
					continue
				}
				if len(servers) == 0 {
					fmt.Println("No servers discovered. Please enter address manually.")
					continue
				}
				fmt.Println("Discovered servers:")
				for i, s := range servers {
					fmt.Printf("  [%d] %s (%s) version %s\n", i+1, s.Hostname, s.GRPCAddr, s.Version)
				}
				var choice int
				for {
					fmt.Printf("Select server (1-%d): ", len(servers))
					choiceStr, err := reader.ReadString('\n')
					if err != nil {
						fatal(err)
					}
					choiceStr = strings.TrimSpace(choiceStr)
					choiceIdx, err := strconv.Atoi(choiceStr)
					if err != nil || choiceIdx < 1 || choiceIdx > len(servers) {
						fmt.Println("Invalid selection, try again.")
						continue
					}
					choice = choiceIdx - 1
					break
				}
				selected := servers[choice]
				host, port, err := net.SplitHostPort(selected.GRPCAddr)
				if err != nil {
					host = selected.SourceIP
					port = "50051"
				}
				if host == "" {
					host = selected.SourceIP
				}
				resolvedAddr = resolveOrTestHostname(host, port, selected.Hostname)
				fmt.Printf("Selected server: %s\n", resolvedAddr)
				break
			} else {
				host, port, err := net.SplitHostPort(input)
				if err != nil {
					host = input
					if strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]") {
						host = host[1 : len(host)-1]
					}
					port = "50051"
				}
				resolvedAddr = resolveOrTestHostname(host, port, "")
				fmt.Printf("Using server: %s\n", resolvedAddr)
				break
			}
		}
	} else {
		host, port, err := net.SplitHostPort(resolvedAddr)
		if err != nil {
			host = resolvedAddr
			if strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]") {
				host = host[1 : len(host)-1]
			}
			port = "50051"
		}
		resolvedAddr = resolveOrTestHostname(host, port, "")
	}

	cfg := &kspclient.Config{
		Addr: resolvedAddr,
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

func resolveOrTestHostname(host string, port string, hostname string) string {
	// If a hostname is provided (e.g. from discovery), check if it's reachable.
	if hostname != "" {
		testAddr := net.JoinHostPort(hostname, port)
		if conn, err := net.DialTimeout("tcp", testAddr, 2*time.Second); err == nil {
			conn.Close()
			return testAddr
		}
	}
	// If no hostname, or if hostname isn't reachable, check if `host` is an IP.
	// If it is an IP, we can try reverse DNS lookup.
	ip := net.ParseIP(host)
	if ip != nil {
		names, err := net.LookupAddr(host)
		if err == nil && len(names) > 0 {
			for _, name := range names {
				name = strings.TrimSuffix(name, ".")
				testAddr := net.JoinHostPort(name, port)
				if conn, err := net.DialTimeout("tcp", testAddr, 2*time.Second); err == nil {
					conn.Close()
					return testAddr
				}
			}
		}
	}
	return net.JoinHostPort(host, port)
}
