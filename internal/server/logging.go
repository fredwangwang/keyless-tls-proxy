package server

import (
	"context"
	"fmt"
	"log"
	"time"

	certv1 "github.com/fredwangwang/keyless-tls-proxy/gen/cert/v1"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
)

func VerboseUnaryInterceptor(verbose bool) grpc.UnaryServerInterceptor {
	if !verbose {
		return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
			return handler(ctx, req)
		}
	}

	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		start := time.Now()
		client := clientInfo(ctx)

		log.Printf("grpc request: method=%s client=%s request=%s", info.FullMethod, client, formatRequest(info.FullMethod, req))

		resp, err := handler(ctx, req)
		duration := time.Since(start)

		if err != nil {
			st, _ := status.FromError(err)
			log.Printf("grpc response: method=%s client=%s duration=%s status=%s error=%q",
				info.FullMethod, client, duration, st.Code(), st.Message())
			return resp, err
		}

		log.Printf("grpc response: method=%s client=%s duration=%s status=OK %s",
			info.FullMethod, client, duration, formatResponse(info.FullMethod, resp))
		return resp, err
	}
}

func clientInfo(ctx context.Context) string {
	p, ok := peer.FromContext(ctx)
	if !ok {
		return "unknown"
	}

	addr := p.Addr.String()
	ti, ok := p.AuthInfo.(credentials.TLSInfo)
	if !ok || len(ti.State.PeerCertificates) == 0 {
		return addr
	}

	return fmt.Sprintf("%s subject=%q", addr, ti.State.PeerCertificates[0].Subject.String())
}

func formatRequest(method string, req any) string {
	switch method {
	case certv1.CertService_ListCertificates_FullMethodName:
		return "ListCertificates"
	case certv1.CertService_SignHash_FullMethodName:
		r, ok := req.(*certv1.SignHashRequest)
		if !ok {
			return fmt.Sprintf("%T", req)
		}
		return fmt.Sprintf("SignHash thumbprint=%s hash=%s padding=%s digest_len=%d",
			r.GetThumbprint(), r.GetHashAlgorithm(), r.GetRsaPadding(), len(r.GetDigest()))
	default:
		return fmt.Sprintf("%T", req)
	}
}

func formatResponse(method string, resp any) string {
	switch method {
	case certv1.CertService_ListCertificates_FullMethodName:
		r, ok := resp.(*certv1.ListCertificatesResponse)
		if !ok {
			return fmt.Sprintf("response=%T", resp)
		}
		return fmt.Sprintf("certificates=%d", len(r.GetCertificates()))
	case certv1.CertService_SignHash_FullMethodName:
		r, ok := resp.(*certv1.SignHashResponse)
		if !ok {
			return fmt.Sprintf("response=%T", resp)
		}
		return fmt.Sprintf("signature_len=%d algorithm=%s padding=%s",
			len(r.GetSignature()), r.GetSignatureAlgorithm(), r.GetRsaPadding())
	default:
		return fmt.Sprintf("response=%T", resp)
	}
}
