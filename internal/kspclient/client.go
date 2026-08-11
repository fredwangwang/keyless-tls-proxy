package kspclient

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/binary"
	"fmt"
	"net"
	"sync"
	"time"

	certv1 "github.com/fredwangwang/keyless-tls-proxy/gen/cert/v1"
	"github.com/fredwangwang/keyless-tls-proxy/internal/kspmanifest"
	"github.com/fredwangwang/keyless-tls-proxy/internal/tlsutil"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

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
	manifest   []string
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
	tps, err := kspmanifest.InstalledThumbprints()
	if err != nil {
		return err
	}
	c.mu.Lock()
	c.manifest = tps
	c.mu.Unlock()
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
			Thumbprint:     kspmanifest.NormalizeThumbprint(cert.Thumbprint),
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
	c.mu.Lock()
	defer c.mu.Unlock()
	tps, err := kspmanifest.InstalledThumbprints()
	if err != nil {
		return nil, err
	}
	c.manifest = tps
	if err := c.refreshRemoteListLocked(ctx); err != nil {
		return nil, err
	}
	if len(c.manifest) == 0 {
		return c.cachedList, nil
	}
	byTP := make(map[string]KeyInfo, len(c.cachedList))
	for _, k := range c.cachedList {
		byTP[k.Thumbprint] = k
	}
	out := make([]KeyInfo, 0, len(c.manifest))
	for _, tp := range c.manifest {
		if k, ok := byTP[tp]; ok {
			out = append(out, k)
		} else {
			out = append(out, KeyInfo{Thumbprint: tp})
		}
	}
	return out, nil
}

func (c *Client) FindInstalled(ctx context.Context, thumbprint string) (*KeyInfo, error) {
	tp := kspmanifest.NormalizeThumbprint(thumbprint)
	keys, err := c.InstalledKeys(ctx)
	if err != nil {
		return nil, err
	}
	for i := range keys {
		if keys[i].Thumbprint == tp {
			return &keys[i], nil
		}
	}
	return nil, kspmanifest.ErrNotInstalled
}

func (c *Client) SignHash(ctx context.Context, thumbprint string, digest []byte, hashAlg certv1.HashAlgorithm, padding certv1.RSAPadding) ([]byte, error) {
	tp := kspmanifest.NormalizeThumbprint(thumbprint)
	if _, err := c.FindInstalled(ctx, tp); err != nil {
		return nil, err
	}
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
