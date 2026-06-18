package server

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"
	"time"
)

const (
	defaultDiscoveryService = "tpm-cert-server"
	discoveryVersion        = "1"
	readDeadline            = time.Second
)

type DiscoveryConfig struct {
	ListenAddr string
	GRPCAddr   string
	Service    string
	Verbose    bool
}

type discoverRequest struct {
	Op      string `json:"op"`
	Service string `json:"service"`
}

type announceResponse struct {
	Op       string `json:"op"`
	Service  string `json:"service"`
	Version  string `json:"version"`
	Hostname string `json:"hostname"`
	GRPCAddr string `json:"grpc_addr"`
}

func RunDiscovery(ctx context.Context, cfg DiscoveryConfig) error {
	if cfg.Service == "" {
		cfg.Service = defaultDiscoveryService
	}
	if cfg.ListenAddr == "" {
		cfg.ListenAddr = ":6666"
	}

	conn, err := net.ListenPacket("udp", cfg.ListenAddr)
	if err != nil {
		return fmt.Errorf("listen udp %s: %w", cfg.ListenAddr, err)
	}
	defer conn.Close()

	hostname, _ := os.Hostname()
	if cfg.Verbose {
		log.Printf("discovery listening on %s for service %q", cfg.ListenAddr, cfg.Service)
	}

	buf := make([]byte, 2048)
	for {
		if err := conn.SetReadDeadline(time.Now().Add(readDeadline)); err != nil {
			return err
		}

		n, remote, err := conn.ReadFrom(buf)
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				select {
				case <-ctx.Done():
					return nil
				default:
					continue
				}
			}
			if ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("read: %w", err)
		}

		var req discoverRequest
		if err := json.Unmarshal(buf[:n], &req); err != nil {
			continue
		}
		if req.Op != "discover" {
			continue
		}
		if req.Service != "" && req.Service != cfg.Service {
			continue
		}

		remoteUDP, ok := remote.(*net.UDPAddr)
		if !ok {
			continue
		}

		grpcAddr, err := grpcAddrForClient(cfg.GRPCAddr, remoteUDP)
		if err != nil {
			if cfg.Verbose {
				log.Printf("discovery: grpc addr for %s: %v", remoteUDP, err)
			}
			continue
		}

		resp := announceResponse{
			Op:       "announce",
			Service:  cfg.Service,
			Version:  discoveryVersion,
			Hostname: hostname,
			GRPCAddr: grpcAddr,
		}
		data, err := json.Marshal(resp)
		if err != nil {
			continue
		}

		if _, err := conn.WriteTo(data, remoteUDP); err != nil {
			if cfg.Verbose {
				log.Printf("discovery: reply to %s: %v", remoteUDP, err)
			}
			continue
		}

		if cfg.Verbose {
			log.Printf("discovery: announced %s to %s", grpcAddr, remoteUDP)
		}
	}
}

func grpcAddrForClient(grpcAddr string, remote *net.UDPAddr) (string, error) {
	host, port, err := net.SplitHostPort(grpcAddr)
	if err != nil {
		return "", err
	}

	remoteIP := remote.IP
	if remoteIP == nil {
		return "", fmt.Errorf("remote has no IP")
	}

	switch {
	case host == "" || host == "0.0.0.0" || host == "::":
		localIP, err := localIPFor(remoteIP)
		if err != nil {
			return "", err
		}
		return net.JoinHostPort(localIP.String(), port), nil
	case host == "127.0.0.1" || host == "::1":
		if !remoteIP.IsLoopback() {
			localIP, err := localIPFor(remoteIP)
			if err != nil {
				return "", err
			}
			return net.JoinHostPort(localIP.String(), port), nil
		}
		return net.JoinHostPort(host, port), nil
	default:
		return net.JoinHostPort(host, port), nil
	}
}

func localIPFor(remote net.IP) (net.IP, error) {
	remote = remote.To4()
	if remote == nil {
		return nil, fmt.Errorf("remote is not IPv4")
	}

	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return nil, err
	}

	for _, addr := range addrs {
		ipNet, ok := addr.(*net.IPNet)
		if !ok || ipNet.IP.IsLoopback() {
			continue
		}
		local := ipNet.IP.To4()
		if local == nil {
			continue
		}
		if sameSubnet(local, remote, ipNet.Mask) {
			return local, nil
		}
	}

	return nil, fmt.Errorf("no local interface on same subnet as %s", remote)
}

func sameSubnet(a, b net.IP, mask net.IPMask) bool {
	a4 := a.To4()
	b4 := b.To4()
	if a4 == nil || b4 == nil {
		return false
	}
	if len(mask) == net.IPv6len {
		mask = mask[12:]
	}
	if len(mask) != net.IPv4len {
		return false
	}
	for i := range a4 {
		if a4[i]&mask[i] != b4[i]&mask[i] {
			return false
		}
	}
	return true
}
