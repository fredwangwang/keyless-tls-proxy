package kspclient

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	certv1 "github.com/fredwangwang/keyless-tls-proxy/gen/cert/v1"
	"github.com/fredwangwang/keyless-tls-proxy/internal/certstore"
	"github.com/fredwangwang/keyless-tls-proxy/internal/kspcommon"
	"github.com/fredwangwang/keyless-tls-proxy/internal/tlsutil"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

var ErrNotInstalled = errors.New("certificate not installed in store for KSP provider")

const listCacheTTL = 30 * time.Second

type KeyInfo struct {
	Thumbprint     string
	Subject        string
	Issuer         string
	KeyAlgorithm   string
	KeySize        int32
	CertificateDER []byte
	RSAPublicBlob  []byte
}

type Client struct {
	mu         sync.Mutex
	cfg        *Config
	conn       *grpc.ClientConn
	rpc        certv1.CertServiceClient
	cachedList []KeyInfo
	cachedAt   time.Time
}

var (
	globalMu sync.Mutex
	global   *Client
)

func New(cfg *Config) (*Client, error) {
	host, _, err := net.SplitHostPort(cfg.Addr)
	if err != nil {
		host = cfg.Addr
	}
	tlsConfig, err := tlsutil.LoadClientTLSConfig(cfg.CA, cfg.Cert, cfg.Key, host)
	if err != nil {
		return nil, fmt.Errorf("tls config: %w", err)
	}
	conn, err := grpc.NewClient(
		cfg.Addr,
		grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig)),
	)
	if err != nil {
		return nil, fmt.Errorf("grpc dial: %w", err)
	}
	return &Client{
		cfg:  cfg,
		conn: conn,
		rpc:  certv1.NewCertServiceClient(conn),
	}, nil
}

func InitGlobal(cfg *Config) error {
	globalMu.Lock()
	defer globalMu.Unlock()
	if global != nil {
		_ = global.Close()
		global = nil
	}
	c, err := New(cfg)
	if err != nil {
		return err
	}
	global = c
	return nil
}

func Global() *Client {
	globalMu.Lock()
	defer globalMu.Unlock()
	return global
}

func ShutdownGlobal() {
	globalMu.Lock()
	defer globalMu.Unlock()
	if global != nil {
		_ = global.Close()
		global = nil
	}
}

func (c *Client) Close() error {
	if c.conn != nil {
		return c.conn.Close()
	}
	return nil
}

// Ping calls ListCertificates on the remote server to verify connectivity.
func (c *Client) Ping(ctx context.Context) error {
	_, err := c.rpc.ListCertificates(ctx, &certv1.ListCertificatesRequest{})
	return err
}

func (c *Client) ReloadManifest() error {
	return nil
}

func (c *Client) refreshRemoteListLocked(ctx context.Context) error {
	if time.Since(c.cachedAt) < listCacheTTL && len(c.cachedList) > 0 {
		return nil
	}
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	resp, err := c.rpc.ListCertificates(ctx, &certv1.ListCertificatesRequest{})
	if err != nil {
		return err
	}
	out := make([]KeyInfo, 0, len(resp.Certificates))
	for _, cert := range resp.Certificates {
		if !cert.HasPrivateKey {
			continue
		}
		info := KeyInfo{
			Thumbprint:     certstore.NormalizeThumbprint(cert.Thumbprint),
			Subject:        cert.Subject,
			Issuer:         cert.Issuer,
			KeyAlgorithm:   cert.KeyAlgorithm,
			KeySize:        cert.KeySize,
			CertificateDER: append([]byte(nil), cert.CertificateDer...),
		}
		if info.Issuer == "" && len(cert.CertificateDer) > 0 {
			if parsed, err := x509.ParseCertificate(cert.CertificateDer); err == nil {
				if parsed.Issuer.CommonName != "" {
					info.Issuer = "CN=" + parsed.Issuer.CommonName
				} else {
					info.Issuer = parsed.Issuer.String()
				}
			}
		}
		if cert.KeyAlgorithm == "RSA" && len(cert.CertificateDer) > 0 {
			blob, err := rsaPublicBlobFromDER(cert.CertificateDer)
			if err == nil {
				info.RSAPublicBlob = blob
			}
		}
		out = append(out, info)
	}
	c.cachedList = out
	c.cachedAt = time.Now()
	return nil
}

func (c *Client) InstalledKeys(ctx context.Context) ([]KeyInfo, error) {
	// Directly query the certificate store for certificates configured with our KSP provider.
	storeCerts, err := certstore.ListCertificatesByProvider(kspcommon.ProviderName)
	if err == nil && len(storeCerts) > 0 {
		out := make([]KeyInfo, 0, len(storeCerts))
		for _, sc := range storeCerts {
			info := KeyInfo{
				Thumbprint:     certstore.NormalizeThumbprint(sc.Thumbprint),
				Subject:        sc.Subject,
				Issuer:         sc.Issuer,
				KeyAlgorithm:   sc.KeyAlgorithm,
				KeySize:        int32(sc.KeySize),
				CertificateDER: sc.CertificateDER,
			}
			if info.KeyAlgorithm == "RSA" && len(info.CertificateDER) > 0 {
				blob, err := rsaPublicBlobFromDER(info.CertificateDER)
				if err == nil {
					info.RSAPublicBlob = blob
				}
			}
			out = append(out, info)
		}
		return out, nil
	}

	// If no certificates found in provider store or unsupported platform, fallback to remote list
	if err == certstore.ErrUnsupportedPlatform {
		return c.AllKeys(ctx)
	}
	return nil, nil
}

func (c *Client) FindInstalled(ctx context.Context, thumbprint string) (*KeyInfo, error) {
	tp := certstore.NormalizeThumbprint(thumbprint)
	keys, err := c.InstalledKeys(ctx)
	if err != nil {
		return nil, err
	}
	for i := range keys {
		if keys[i].Thumbprint == tp {
			return &keys[i], nil
		}
	}
	return nil, ErrNotInstalled
}

func (c *Client) SignHash(ctx context.Context, thumbprint string, digest []byte, hashAlg certv1.HashAlgorithm, padding certv1.RSAPadding) ([]byte, error) {
	tp := certstore.NormalizeThumbprint(thumbprint)
	if _, err := c.FindInstalled(ctx, tp); err != nil {
		return nil, err
	}
	return c.SignHashDirect(ctx, tp, digest, hashAlg, padding)
}

// SignHashDirect signs a digest with the remote server.
func (c *Client) SignHashDirect(ctx context.Context, thumbprint string, digest []byte, hashAlg certv1.HashAlgorithm, padding certv1.RSAPadding) ([]byte, error) {
	tp := certstore.NormalizeThumbprint(thumbprint)
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	resp, err := c.rpc.SignHash(ctx, &certv1.SignHashRequest{
		Thumbprint:    tp,
		Digest:        digest,
		HashAlgorithm: hashAlg,
		RsaPadding:    padding,
	})
	if err != nil {
		return nil, err
	}
	return append([]byte(nil), resp.Signature...), nil
}

// AllKeys returns every remote certificate that has a private key.
func (c *Client) AllKeys(ctx context.Context) ([]KeyInfo, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.refreshRemoteListLocked(ctx); err != nil {
		return nil, err
	}
	return c.cachedList, nil
}

func rsaPublicBlobFromDER(der []byte) ([]byte, error) {
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	pub, ok := cert.PublicKey.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("not RSA")
	}
	modulus := pub.N.Bytes()
	exp := make([]byte, 4)
	binary.BigEndian.PutUint32(exp, uint32(pub.E))

	headerSize := 24 // sizeof(BCRYPT_RSAKEY_BLOB) on Windows
	blob := make([]byte, headerSize+len(exp)+len(modulus))
	// Magic BCRYPT_RSAPUBLIC_MAGIC = 0x31415352 "RSA1"
	binary.LittleEndian.PutUint32(blob[0:4], 0x31415352)
	binary.LittleEndian.PutUint32(blob[4:8], uint32(pub.N.BitLen()))
	binary.LittleEndian.PutUint32(blob[8:12], uint32(len(exp)))
	binary.LittleEndian.PutUint32(blob[12:16], uint32(len(modulus)))
	copy(blob[headerSize:], exp)
	copy(blob[headerSize+len(exp):], modulus)
	return blob, nil
}

func HashAlgFromInt(v int) certv1.HashAlgorithm {
	switch v {
	case 2:
		return certv1.HashAlgorithm_SHA384
	case 3:
		return certv1.HashAlgorithm_SHA512
	default:
		return certv1.HashAlgorithm_SHA256
	}
}

func PaddingFromInt(v int) certv1.RSAPadding {
	if v == 2 {
		return certv1.RSAPadding_PSS
	}
	return certv1.RSAPadding_PKCS1
}
