package main

import (
	"context"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	certv1 "github.com/fredwangwang/keyless-tls-proxy/gen/cert/v1"
	"github.com/fredwangwang/keyless-tls-proxy/internal/certstore"
	"github.com/fredwangwang/keyless-tls-proxy/internal/kspclient"
	"github.com/fredwangwang/keyless-tls-proxy/internal/kspcommon"
	"github.com/fredwangwang/keyless-tls-proxy/internal/kspinstall"
	"github.com/fredwangwang/keyless-tls-proxy/internal/kspmanifest"
	"github.com/fredwangwang/keyless-tls-proxy/internal/server"
	"github.com/fredwangwang/keyless-tls-proxy/internal/tlsutil"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

type ServerInfo struct {
	Hostname  string `json:"hostname"`
	GRPCAddr  string `json:"grpc_addr"`
	Version   string `json:"version"`
	SourceIP  string `json:"source_ip"`
	LatencyMs int64  `json:"latency_ms"`
}

type ConfigData struct {
	Addr       string `json:"addr"`
	CA         string `json:"ca"`
	Cert       string `json:"cert"`
	Key        string `json:"key"`
	ConfigPath string `json:"config_path"`
}

type CertificateItem struct {
	Thumbprint    string   `json:"thumbprint"`
	Subject       string   `json:"subject"`
	Issuer        string   `json:"issuer"`
	KeyAlgorithm  string   `json:"key_algorithm"`
	KeySize       int32    `json:"key_size"`
	NotBefore     string   `json:"not_before"`
	NotAfter      string   `json:"not_after"`
	IsExpired     bool     `json:"is_expired"`
	DaysRemaining int      `json:"days_remaining"`
	SANs          []string `json:"sans"`
	KeyUsage      []string `json:"key_usage"`
	IsInstalled   bool     `json:"is_installed"`
}

type InstalledItem struct {
	Thumbprint   string `json:"thumbprint"`
	Subject      string `json:"subject"`
	Issuer       string `json:"issuer,omitempty"`
	NotAfter     string `json:"not_after,omitempty"`
	InstalledAt  string `json:"installed_at"`
	Provider     string `json:"provider"`
	Container    string `json:"container"`
	KeyAlgorithm string `json:"key_algorithm,omitempty"`
	KeySize      int    `json:"key_size,omitempty"`
	IsTPM        bool   `json:"is_tpm"`
	InStore      bool   `json:"in_store"`
}

type TestSignRequest struct {
	Thumbprint string `json:"thumbprint"`
	Message    string `json:"message"`
	InputType  string `json:"input_type"` // "text" or "hex_digest"
	HashAlgo   string `json:"hash_algo"`  // "SHA256", "SHA384", "SHA512"
	Padding    string `json:"padding"`    // "pkcs1", "pss"
}

type TestSignResult struct {
	Thumbprint         string `json:"thumbprint"`
	Subject            string `json:"subject"`
	HashAlgorithm      string `json:"hash_algorithm"`
	DigestHex          string `json:"digest_hex"`
	Padding            string `json:"padding"`
	SignatureAlgorithm string `json:"signature_algorithm"`
	SignatureBase64    string `json:"signature_base64"`
	SignatureHex       string `json:"signature_hex"`
	DurationMs         int64  `json:"duration_ms"`
}

type DiagnosticsInfo struct {
	ProviderName string `json:"provider_name"`
	DataDir      string `json:"data_dir"`
	ConfigPath   string `json:"config_path"`
	ManifestPath string `json:"manifest_path"`
	TotalKeys    int    `json:"total_keys"`
	ConfigExists bool   `json:"config_exists"`
}

type AppAPI struct{}

func NewAppAPI() *AppAPI {
	return &AppAPI{}
}

// DiscoverServers executes UDP broadcast discovery for tpm-cert-servers.
func (a *AppAPI) DiscoverServers(timeoutSec int) ([]ServerInfo, error) {
	if timeoutSec <= 0 {
		timeoutSec = 3
	}
	timeout := time.Duration(timeoutSec) * time.Second
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	start := time.Now()
	servers, err := server.DiscoverServers(ctx, server.DiscoverClientConfig{Timeout: timeout})
	elapsed := time.Since(start).Milliseconds()
	if err != nil {
		return nil, fmt.Errorf("discovery failed: %w", err)
	}

	result := make([]ServerInfo, 0, len(servers))
	for _, s := range servers {
		result = append(result, ServerInfo{
			Hostname:  s.Hostname,
			GRPCAddr:  s.GRPCAddr,
			Version:   s.Version,
			SourceIP:  s.SourceIP,
			LatencyMs: elapsed,
		})
	}
	return result, nil
}

// LoadConfig loads the mTLS config from default path (%ProgramData%\fredprx-ksp\config.json).
func (a *AppAPI) LoadConfig() (*ConfigData, error) {
	configPath := kspcommon.ConfigPath()
	cfg, err := kspclient.LoadConfig(configPath)
	if err != nil {
		// Return default empty config if file doesn't exist yet
		return &ConfigData{
			Addr:       "",
			CA:         "certs/ca.crt",
			Cert:       "certs/client.crt",
			Key:        "certs/client.key",
			ConfigPath: configPath,
		}, nil
	}

	return &ConfigData{
		Addr:       cfg.Addr,
		CA:         cfg.CA,
		Cert:       cfg.Cert,
		Key:        cfg.Key,
		ConfigPath: configPath,
	}, nil
}

// SaveConfig writes mTLS configuration JSON to %ProgramData%\fredprx-ksp\config.json or specified path.
func (a *AppAPI) SaveConfig(cfg ConfigData) error {
	path := cfg.ConfigPath
	if path == "" {
		path = kspcommon.ConfigPath()
	}

	clientCfg := &kspclient.Config{
		Addr: strings.TrimSpace(cfg.Addr),
		CA:   strings.TrimSpace(cfg.CA),
		Cert: strings.TrimSpace(cfg.Cert),
		Key:  strings.TrimSpace(cfg.Key),
	}

	return kspclient.SaveConfig(clientCfg, path)
}

// ResolveServerAddress tests and resolves the server address.
func (a *AppAPI) ResolveServerAddress(addr string, hostnameHint string) string {
	addr = strings.TrimSpace(addr)
	if addr == "" {
		return ""
	}
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
		if strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]") {
			host = host[1 : len(host)-1]
		}
		port = "50051"
	}
	return resolveOrTestHostname(host, port, hostnameHint)
}

// TestConnection verifies reachability and gRPC handshake.
func (a *AppAPI) TestConnection(cfg ConfigData) (string, error) {
	resolvedAddr := a.ResolveServerAddress(cfg.Addr, "")
	if resolvedAddr == "" {
		return "", fmt.Errorf("server address is required")
	}

	tlsConfig, err := tlsutil.LoadClientTLSConfig(cfg.CA, cfg.Cert, cfg.Key, hostFromAddr(resolvedAddr))
	if err != nil {
		return "", fmt.Errorf("TLS configuration error: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	conn, err := grpc.DialContext(ctx, resolvedAddr,
		grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig)),
		grpc.WithBlock(),
	)
	if err != nil {
		return "", fmt.Errorf("connection failed: %w", err)
	}
	defer conn.Close()

	client := certv1.NewCertServiceClient(conn)
	resp, err := client.ListCertificates(ctx, &certv1.ListCertificatesRequest{})
	if err != nil {
		return "", fmt.Errorf("gRPC query failed: %w", err)
	}

	return fmt.Sprintf("Connected successfully. Found %d remote certificate(s).", len(resp.Certificates)), nil
}

// ListRemoteCertificates connects via mTLS gRPC and retrieves available certificates with rich metadata.
func (a *AppAPI) ListRemoteCertificates(cfg ConfigData) ([]CertificateItem, error) {
	resolvedAddr := a.ResolveServerAddress(cfg.Addr, "")
	if resolvedAddr == "" {
		return nil, fmt.Errorf("server address is required")
	}

	tlsConfig, err := tlsutil.LoadClientTLSConfig(cfg.CA, cfg.Cert, cfg.Key, hostFromAddr(resolvedAddr))
	if err != nil {
		return nil, fmt.Errorf("TLS config error: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	conn, err := grpc.DialContext(ctx, resolvedAddr,
		grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig)),
		grpc.WithBlock(),
	)
	if err != nil {
		return nil, fmt.Errorf("connect to %s: %w", resolvedAddr, err)
	}
	defer conn.Close()

	client := certv1.NewCertServiceClient(conn)
	resp, err := client.ListCertificates(ctx, &certv1.ListCertificatesRequest{})
	if err != nil {
		return nil, fmt.Errorf("list certificates: %w", err)
	}

	manifest, _ := kspmanifest.Load()

	items := make([]CertificateItem, 0, len(resp.Certificates))
	for _, c := range resp.Certificates {
		tp := kspmanifest.NormalizeThumbprint(c.Thumbprint)
		isInstalled := manifest != nil && manifest.Contains(tp)

		item := CertificateItem{
			Thumbprint:   tp,
			Subject:      c.Subject,
			KeyAlgorithm: c.KeyAlgorithm,
			KeySize:      c.KeySize,
			IsInstalled:  isInstalled,
		}

		if len(c.CertificateDer) > 0 {
			if x509Cert, err := x509.ParseCertificate(c.CertificateDer); err == nil {
				item.Issuer = x509Cert.Issuer.CommonName
				if item.Issuer == "" {
					item.Issuer = x509Cert.Issuer.String()
				}
				item.NotBefore = x509Cert.NotBefore.UTC().Format("2006-01-02 15:04 UTC")
				item.NotAfter = x509Cert.NotAfter.UTC().Format("2006-01-02 15:04 UTC")
				item.IsExpired = time.Now().UTC().After(x509Cert.NotAfter)
				item.DaysRemaining = int(time.Until(x509Cert.NotAfter).Hours() / 24)

				sans := make([]string, 0)
				sans = append(sans, x509Cert.DNSNames...)
				for _, ip := range x509Cert.IPAddresses {
					sans = append(sans, ip.String())
				}
				sans = append(sans, x509Cert.EmailAddresses...)
				item.SANs = sans

				var usages []string
				if x509Cert.KeyUsage&x509.KeyUsageDigitalSignature != 0 {
					usages = append(usages, "Digital Signature")
				}
				if x509Cert.KeyUsage&x509.KeyUsageKeyEncipherment != 0 {
					usages = append(usages, "Key Encipherment")
				}
				for _, ext := range x509Cert.ExtKeyUsage {
					if ext == x509.ExtKeyUsageServerAuth {
						usages = append(usages, "Server Auth")
					} else if ext == x509.ExtKeyUsageClientAuth {
						usages = append(usages, "Client Auth")
					} else if ext == x509.ExtKeyUsageCodeSigning {
						usages = append(usages, "Code Signing")
					}
				}
				item.KeyUsage = usages
			}
		}

		items = append(items, item)
	}

	return items, nil
}

// InstallCertificate downloads the selected certificate DER from server and binds it to Windows KSP.
func (a *AppAPI) InstallCertificate(cfg ConfigData, thumbprint string) (string, error) {
	resolvedAddr := a.ResolveServerAddress(cfg.Addr, "")
	if resolvedAddr == "" {
		return "", fmt.Errorf("server address is required")
	}

	normTP := kspmanifest.NormalizeThumbprint(thumbprint)
	if normTP == "" {
		return "", fmt.Errorf("invalid thumbprint")
	}

	tlsConfig, err := tlsutil.LoadClientTLSConfig(cfg.CA, cfg.Cert, cfg.Key, hostFromAddr(resolvedAddr))
	if err != nil {
		return "", fmt.Errorf("TLS config: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	conn, err := grpc.DialContext(ctx, resolvedAddr,
		grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig)),
		grpc.WithBlock(),
	)
	if err != nil {
		return "", fmt.Errorf("connect to %s: %w", resolvedAddr, err)
	}
	defer conn.Close()

	client := certv1.NewCertServiceClient(conn)
	resp, err := client.ListCertificates(ctx, &certv1.ListCertificatesRequest{})
	if err != nil {
		return "", fmt.Errorf("list certificates: %w", err)
	}

	var target *certv1.CertificateInfo
	for _, c := range resp.Certificates {
		if kspmanifest.NormalizeThumbprint(c.Thumbprint) == normTP {
			target = c
			break
		}
	}

	if target == nil {
		return "", fmt.Errorf("certificate with thumbprint %s not found on server", normTP)
	}
	if len(target.CertificateDer) == 0 {
		return "", fmt.Errorf("server returned empty certificate DER")
	}

	// 1. Bind to Windows KSP in CurrentUser\MY store
	if err := kspinstall.BindCertificateToKSP(target.CertificateDer, normTP); err != nil {
		return "", fmt.Errorf("bind certificate to Windows store: %w", err)
	}

	// 2. Add to manifest
	if err := kspmanifest.Add(normTP, target.Subject); err != nil {
		return "", fmt.Errorf("save to installed manifest: %w", err)
	}

	// 3. Ensure client config is also saved so KSP can find the proxy server
	_ = a.SaveConfig(cfg)

	return fmt.Sprintf("Successfully installed %s into Current User\\MY and bound to %s", target.Subject, kspcommon.ProviderName), nil
}

// ListInstalledCertificates lists all installed certificate bindings from the manifest, enriched with store metadata.
func (a *AppAPI) ListInstalledCertificates() ([]InstalledItem, error) {
	m, err := kspmanifest.Load()
	if err != nil {
		return nil, fmt.Errorf("load manifest: %w", err)
	}

	// Cross-reference with Windows MY store certificates with private keys
	storeCerts, _ := certstore.ListCertificates()
	storeMap := make(map[string]certstore.CertificateInfo)
	for _, sc := range storeCerts {
		storeMap[kspmanifest.NormalizeThumbprint(sc.Thumbprint)] = sc
	}

	items := make([]InstalledItem, 0, len(m.Keys))
	for _, e := range m.Keys {
		tp := kspmanifest.NormalizeThumbprint(e.Thumbprint)
		item := InstalledItem{
			Thumbprint:  tp,
			Subject:     e.Subject,
			InstalledAt: e.InstalledAt.Local().Format("2006-01-02 15:04:05"),
			Provider:    kspcommon.ProviderName,
			Container:   tp,
		}

		if sc, found := storeMap[tp]; found {
			item.InStore = true
			item.KeyAlgorithm = sc.KeyAlgorithm
			item.KeySize = sc.KeySize
			item.IsTPM = sc.IsTPM
			item.Issuer = sc.Issuer
			if !sc.NotAfter.IsZero() {
				item.NotAfter = sc.NotAfter.UTC().Format("2006-01-02 15:04 UTC")
			}
			if sc.ProviderName != "" {
				item.Provider = sc.ProviderName
			}
		}

		items = append(items, item)
	}
	return items, nil
}

// TestSign performs a cryptographic test signature on a given payload using a certificate in Windows MY store.
func (a *AppAPI) TestSign(req TestSignRequest) (*TestSignResult, error) {
	normTP := kspmanifest.NormalizeThumbprint(req.Thumbprint)
	if normTP == "" {
		return nil, fmt.Errorf("certificate thumbprint is required")
	}

	// 1. Resolve Hash Algorithm
	var (
		hashAlgo   certstore.HashAlgorithm
		hashName   string
		digestSize int
	)
	switch strings.ToUpper(strings.TrimSpace(req.HashAlgo)) {
	case "SHA384", "SHA-384":
		hashAlgo = certstore.HashSHA384
		hashName = "SHA-384"
		digestSize = 48
	case "SHA512", "SHA-512":
		hashAlgo = certstore.HashSHA512
		hashName = "SHA-512"
		digestSize = 64
	default:
		hashAlgo = certstore.HashSHA256
		hashName = "SHA-256"
		digestSize = 32
	}

	// 2. Compute or parse digest
	var digest []byte
	inputType := strings.ToLower(strings.TrimSpace(req.InputType))
	if inputType == "hex" || inputType == "hex_digest" || inputType == "digest" {
		cleanHex := strings.ReplaceAll(strings.TrimSpace(req.Message), " ", "")
		rawDigest, err := hex.DecodeString(cleanHex)
		if err != nil {
			return nil, fmt.Errorf("invalid hex digest: %w", err)
		}
		if len(rawDigest) != digestSize {
			return nil, fmt.Errorf("hex digest length (%d bytes) does not match %s required length (%d bytes)", len(rawDigest), hashName, digestSize)
		}
		digest = rawDigest
	} else {
		msg := req.Message
		if msg == "" {
			return nil, fmt.Errorf("message to sign must not be empty")
		}
		msgBytes := []byte(msg)
		switch hashAlgo {
		case certstore.HashSHA384:
			d := sha512.Sum384(msgBytes)
			digest = d[:]
		case certstore.HashSHA512:
			d := sha512.Sum512(msgBytes)
			digest = d[:]
		default:
			d := sha256.Sum256(msgBytes)
			digest = d[:]
		}
	}

	// 3. Resolve RSA Padding
	var (
		padding     certstore.RSAPadding
		paddingName string
	)
	switch strings.ToLower(strings.TrimSpace(req.Padding)) {
	case "pss", "rsapss", "rsa-pss":
		padding = certstore.RSAPaddingPSS
		paddingName = "PSS"
	default:
		padding = certstore.RSAPaddingPKCS1
		paddingName = "PKCS#1 v1.5"
	}

	// 4. Execute SignHash via CNG / KSP
	start := time.Now()
	signResp, err := certstore.SignHash(normTP, digest, hashAlgo, padding)
	duration := time.Since(start).Milliseconds()
	if err != nil {
		return nil, fmt.Errorf("test signing failed: %w", err)
	}

	// Find subject name if possible
	subject := normTP
	if certs, err := certstore.ListCertificates(); err == nil {
		for _, c := range certs {
			if kspmanifest.NormalizeThumbprint(c.Thumbprint) == normTP {
				subject = c.Subject
				break
			}
		}
	}

	return &TestSignResult{
		Thumbprint:         normTP,
		Subject:            subject,
		HashAlgorithm:      hashName,
		DigestHex:          hex.EncodeToString(digest),
		Padding:            paddingName,
		SignatureAlgorithm: signResp.SignatureAlgorithm,
		SignatureBase64:    base64.StdEncoding.EncodeToString(signResp.Signature),
		SignatureHex:       hex.EncodeToString(signResp.Signature),
		DurationMs:         duration,
	}, nil
}

// UninstallCertificate unbinds and deletes the certificate from Windows store and manifest.
func (a *AppAPI) UninstallCertificate(thumbprint string) (string, error) {
	tp := kspmanifest.NormalizeThumbprint(thumbprint)
	if tp == "" {
		return "", fmt.Errorf("invalid thumbprint")
	}

	var storeErr error
	if err := kspinstall.RemoveCertificateFromStore(tp); err != nil {
		storeErr = err
	}

	if err := kspmanifest.Remove(tp); err != nil {
		return "", fmt.Errorf("remove from manifest: %w", err)
	}

	if storeErr != nil {
		return fmt.Sprintf("Removed from manifest (Windows store note: %v)", storeErr), nil
	}

	return fmt.Sprintf("Successfully uninstalled certificate %s", tp), nil
}

// SelectFile opens native Windows file picker dialog.
func (a *AppAPI) SelectFile(title string, filterDesc string, filterPattern string) (string, error) {
	return selectFileDialog(title, filterDesc, filterPattern)
}

// GetDiagnostics returns environment paths, provider info, and stats.
func (a *AppAPI) GetDiagnostics() (*DiagnosticsInfo, error) {
	manifest, _ := kspmanifest.Load()
	totalKeys := 0
	if manifest != nil {
		totalKeys = len(manifest.Keys)
	}

	cfgPath := kspcommon.ConfigPath()
	_, cfgErr := os.Stat(cfgPath)

	return &DiagnosticsInfo{
		ProviderName: kspcommon.ProviderName,
		DataDir:      kspcommon.DataDir(),
		ConfigPath:   cfgPath,
		ManifestPath: kspcommon.ManifestPath(),
		TotalKeys:    totalKeys,
		ConfigExists: cfgErr == nil,
	}, nil
}

func hostFromAddr(addr string) string {
	if h, _, err := net.SplitHostPort(addr); err == nil {
		return h
	}
	return addr
}

func resolveOrTestHostname(host string, port string, hostname string) string {
	if hostname != "" {
		testAddr := net.JoinHostPort(hostname, port)
		if conn, err := net.DialTimeout("tcp", testAddr, 2*time.Second); err == nil {
			conn.Close()
			return testAddr
		}
	}
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
