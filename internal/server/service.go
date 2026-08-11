package server

import (
	"context"
	"fmt"

	certv1 "github.com/fredwangwang/keyless-tls-proxy/gen/cert/v1"
	"github.com/fredwangwang/keyless-tls-proxy/internal/certstore"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type CertService struct {
	certv1.UnimplementedCertServiceServer
}

func NewCertService() *CertService {
	return &CertService{}
}

func (s *CertService) ListCertificates(ctx context.Context, _ *certv1.ListCertificatesRequest) (*certv1.ListCertificatesResponse, error) {
	certs, err := certstore.ListCertificates()
	if err != nil {
		return nil, status.Errorf(codes.Internal, "list certificates: %v", err)
	}

	out := make([]*certv1.CertificateInfo, 0, len(certs))
	for _, c := range certs {
		out = append(out, &certv1.CertificateInfo{
			Thumbprint:     c.Thumbprint,
			Subject:        c.Subject,
			Issuer:         c.Issuer,
			NotBefore:      timestamppb.New(c.NotBefore),
			NotAfter:       timestamppb.New(c.NotAfter),
			KeyAlgorithm:   c.KeyAlgorithm,
			KeySize:        int32(c.KeySize),
			HasPrivateKey:  c.HasPrivateKey,
			IsTpm:          c.IsTPM,
			ProviderName:   c.ProviderName,
			CertificateDer: c.CertificateDER,
		})
	}
	return &certv1.ListCertificatesResponse{Certificates: out}, nil
}

func (s *CertService) SignHash(ctx context.Context, req *certv1.SignHashRequest) (*certv1.SignHashResponse, error) {
	if req.GetThumbprint() == "" {
		return nil, status.Error(codes.InvalidArgument, "thumbprint is required")
	}
	if len(req.GetDigest()) == 0 {
		return nil, status.Error(codes.InvalidArgument, "digest is required")
	}

	hash, err := protoHashToCertstore(req.GetHashAlgorithm())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}

	padding, err := protoPaddingToCertstore(req.GetRsaPadding())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}

	result, err := certstore.SignHash(req.GetThumbprint(), req.GetDigest(), hash, padding)
	if err != nil {
		switch err {
		case certstore.ErrCertificateNotFound:
			return nil, status.Error(codes.NotFound, err.Error())
		case certstore.ErrInvalidDigest, certstore.ErrNoPrivateKey, certstore.ErrInvalidPadding:
			return nil, status.Error(codes.InvalidArgument, err.Error())
		default:
			return nil, status.Errorf(codes.Internal, "sign hash: %v", err)
		}
	}

	return &certv1.SignHashResponse{
		Signature:          result.Signature,
		SignatureAlgorithm: result.SignatureAlgorithm,
		RsaPadding:         certstorePaddingToProto(result.Padding),
	}, nil
}

func certstorePaddingToProto(p certstore.RSAPadding) certv1.RSAPadding {
	switch p {
	case certstore.RSAPaddingPSS:
		return certv1.RSAPadding_PSS
	default:
		return certv1.RSAPadding_PKCS1
	}
}

func protoPaddingToCertstore(p certv1.RSAPadding) (certstore.RSAPadding, error) {
	switch p {
	case certv1.RSAPadding_RSA_PADDING_UNSPECIFIED, certv1.RSAPadding_PKCS1:
		return certstore.RSAPaddingPKCS1, nil
	case certv1.RSAPadding_PSS:
		return certstore.RSAPaddingPSS, nil
	default:
		return 0, fmt.Errorf("rsa padding must be PKCS1 or PSS")
	}
}

func protoHashToCertstore(h certv1.HashAlgorithm) (certstore.HashAlgorithm, error) {
	switch h {
	case certv1.HashAlgorithm_SHA256:
		return certstore.HashSHA256, nil
	case certv1.HashAlgorithm_SHA384:
		return certstore.HashSHA384, nil
	case certv1.HashAlgorithm_SHA512:
		return certstore.HashSHA512, nil
	default:
		return 0, fmt.Errorf("hash algorithm is required (SHA256, SHA384, or SHA512)")
	}
}
