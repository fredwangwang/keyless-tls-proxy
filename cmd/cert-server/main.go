package main

import (
	"bytes"
	"context"
	"flag"
	"io"
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

const (
	logFileName = "cert-server.log"
	maxLogSize  = 5 * 1024 * 1024
)

func truncateLogFile(path string, maxSize int64) error {
	info, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	if info.Size() <= maxSize {
		return nil
	}

	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()

	if _, err := f.Seek(info.Size()-maxSize, io.SeekStart); err != nil {
		return err
	}
	tail, err := io.ReadAll(f)
	if err != nil {
		return err
	}
	if i := bytes.IndexByte(tail, '\n'); i >= 0 && i+1 < len(tail) {
		tail = tail[i+1:]
	}

	return os.WriteFile(path, tail, info.Mode().Perm())
}

func main() {
	addr := flag.String("addr", "127.0.0.1:50051", "gRPC listen address")
	ca := flag.String("ca", "certs/ca.crt", "CA certificate for client verification")
	cert := flag.String("cert", "certs/server.crt", "server TLS certificate")
	key := flag.String("key", "certs/server.key", "server TLS private key")
	verbose := flag.Bool("verbose", false, "log each gRPC call with request/response details")
	discovery := flag.Bool("discovery", true, "enable UDP broadcast discovery")
	discoveryAddr := flag.String("discovery-addr", ":6666", "UDP discovery listen address")
	flag.Parse()

	if err := truncateLogFile(logFileName, maxLogSize); err != nil {
		log.Fatalf("truncate log file: %v", err)
	}
	logFile, err := os.OpenFile(logFileName, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		log.Fatalf("open log file: %v", err)
	}
	defer logFile.Close()
	log.SetOutput(io.MultiWriter(os.Stderr, logFile))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	tlsConfig, err := tlsutil.LoadServerTLSConfig(*ca, *cert, *key)
	if err != nil {
		log.Fatalf("tls config: %v", err)
	}

	lis, err := net.Listen("tcp", *addr)
	if err != nil {
		log.Fatalf("listen: %v", err)
	}

	grpcServer := grpc.NewServer(
		grpc.Creds(credentials.NewTLS(tlsConfig)),
		grpc.UnaryInterceptor(server.VerboseUnaryInterceptor(*verbose)),
	)
	certv1.RegisterCertServiceServer(grpcServer, server.NewCertService())

	if *discovery {
		go func() {
			if err := server.RunDiscovery(ctx, server.DiscoveryConfig{
				ListenAddr: *discoveryAddr,
				GRPCAddr:   *addr,
				Verbose:    *verbose,
			}); err != nil && ctx.Err() == nil {
				log.Printf("discovery: %v", err)
			}
		}()
	}

	hostname, err := os.Hostname()
	if err != nil {
		hostname = "unknown"
	}

	if *verbose {
		if *discovery {
			log.Printf("cert-server listening on %s hostname=%s (mTLS, RSA padding: pkcs1|pss, UDP discovery on %s, verbose logging enabled)", *addr, hostname, *discoveryAddr)
		} else {
			log.Printf("cert-server listening on %s hostname=%s (mTLS, RSA padding: pkcs1|pss, verbose logging enabled)", *addr, hostname)
		}
	} else if *discovery {
		log.Printf("cert-server listening on %s hostname=%s (mTLS, RSA padding: pkcs1|pss, UDP discovery on %s)", *addr, hostname, *discoveryAddr)
	} else {
		log.Printf("cert-server listening on %s hostname=%s (mTLS, RSA padding: pkcs1|pss)", *addr, hostname)
	}

	go func() {
		if err := grpcServer.Serve(lis); err != nil {
			log.Fatalf("serve: %v", err)
		}
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	<-stop
	cancel()
	grpcServer.GracefulStop()
}
