package main

import (
	"flag"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"

	certv1 "tpm-cert-proxy/gen/cert/v1"
	"tpm-cert-proxy/internal/server"
	"tpm-cert-proxy/internal/tlsutil"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

func main() {
	addr := flag.String("addr", "127.0.0.1:50051", "gRPC listen address")
	ca := flag.String("ca", "certs/ca.crt", "CA certificate for client verification")
	cert := flag.String("cert", "certs/server.crt", "server TLS certificate")
	key := flag.String("key", "certs/server.key", "server TLS private key")
	flag.Parse()

	tlsConfig, err := tlsutil.LoadServerTLSConfig(*ca, *cert, *key)
	if err != nil {
		log.Fatalf("tls config: %v", err)
	}

	lis, err := net.Listen("tcp", *addr)
	if err != nil {
		log.Fatalf("listen: %v", err)
	}

	grpcServer := grpc.NewServer(grpc.Creds(credentials.NewTLS(tlsConfig)))
	certv1.RegisterCertServiceServer(grpcServer, server.NewCertService())

	log.Printf("cert-server listening on %s (mTLS)", *addr)

	go func() {
		if err := grpcServer.Serve(lis); err != nil {
			log.Fatalf("serve: %v", err)
		}
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	<-stop
	grpcServer.GracefulStop()
}
