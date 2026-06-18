package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"sort"
	"sync"
	"syscall"
	"time"
)

const DiscoveryServiceName = defaultDiscoveryService

type DiscoveredServer struct {
	Hostname string `json:"hostname"`
	GRPCAddr string `json:"grpc_addr"`
	Version  string `json:"version"`
	Service  string `json:"service"`
	SourceIP string `json:"source_ip"`
}

type DiscoverClientConfig struct {
	Port       int
	Service    string
	Timeout    time.Duration
	ProbeAddrs []*net.UDPAddr
}

func DiscoverServers(ctx context.Context, cfg DiscoverClientConfig) ([]DiscoveredServer, error) {
	if cfg.Port == 0 {
		cfg.Port = 6666
	}
	if cfg.Service == "" {
		cfg.Service = DiscoveryServiceName
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 3 * time.Second
	}

	conn, err := net.ListenPacket("udp4", ":0")
	if err != nil {
		return nil, fmt.Errorf("listen udp: %w", err)
	}
	defer conn.Close()

	if err := enableBroadcast(conn); err != nil {
		return nil, err
	}

	probe, err := json.Marshal(discoverRequest{Op: "discover", Service: cfg.Service})
	if err != nil {
		return nil, err
	}

	targets, err := broadcastTargets(cfg.Port)
	if err != nil {
		return nil, err
	}
	targets = append(targets, cfg.ProbeAddrs...)
	for _, target := range targets {
		if _, err := conn.WriteTo(probe, target); err != nil {
			return nil, fmt.Errorf("broadcast to %s: %w", target, err)
		}
	}

	ctx, cancel := context.WithTimeout(ctx, cfg.Timeout)
	defer cancel()

	seen := make(map[string]DiscoveredServer)
	var mu sync.Mutex

	readDone := make(chan struct{})
	go func() {
		defer close(readDone)
		buf := make([]byte, 2048)
		for {
			_ = conn.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
			n, remote, err := conn.ReadFrom(buf)
			if err != nil {
				if ne, ok := err.(net.Error); ok && ne.Timeout() {
					select {
					case <-ctx.Done():
						return
					default:
						continue
					}
				}
				return
			}

			var resp announceResponse
			if err := json.Unmarshal(buf[:n], &resp); err != nil {
				continue
			}
			if resp.Op != "announce" || resp.Service != cfg.Service {
				continue
			}

			sourceIP := ""
			if udp, ok := remote.(*net.UDPAddr); ok && udp.IP != nil {
				sourceIP = udp.IP.String()
			}

			mu.Lock()
			key := resp.GRPCAddr
			if key == "" {
				key = sourceIP
			}
			seen[key] = DiscoveredServer{
				Hostname: resp.Hostname,
				GRPCAddr: resp.GRPCAddr,
				Version:  resp.Version,
				Service:  resp.Service,
				SourceIP: sourceIP,
			}
			mu.Unlock()
		}
	}()

	<-ctx.Done()
	<-readDone

	mu.Lock()
	defer mu.Unlock()
	out := make([]DiscoveredServer, 0, len(seen))
	for _, s := range seen {
		out = append(out, s)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].GRPCAddr != out[j].GRPCAddr {
			return out[i].GRPCAddr < out[j].GRPCAddr
		}
		return out[i].Hostname < out[j].Hostname
	})
	return out, nil
}

func enableBroadcast(conn net.PacketConn) error {
	udpConn, ok := conn.(*net.UDPConn)
	if !ok {
		return fmt.Errorf("expected UDP connection")
	}
	raw, err := udpConn.SyscallConn()
	if err != nil {
		return fmt.Errorf("syscall conn: %w", err)
	}
	var sockErr error
	err = raw.Control(func(fd uintptr) {
		sockErr = syscall.SetsockoptInt(syscall.Handle(fd), syscall.SOL_SOCKET, syscall.SO_BROADCAST, 1)
	})
	if err != nil {
		return fmt.Errorf("control: %w", err)
	}
	return sockErr
}

func broadcastTargets(port int) ([]*net.UDPAddr, error) {
	seen := make(map[string]struct{})
	var targets []*net.UDPAddr

	add := func(ip net.IP) {
		if ip == nil || ip.To4() == nil {
			return
		}
		key := ip.String()
		if _, ok := seen[key]; ok {
			return
		}
		seen[key] = struct{}{}
		targets = append(targets, &net.UDPAddr{IP: ip, Port: port})
	}

	add(net.IPv4bcast)

	ifaces, err := net.Interfaces()
	if err != nil {
		return targets, nil
	}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			ipNet, ok := addr.(*net.IPNet)
			if !ok {
				continue
			}
			ip4 := ipNet.IP.To4()
			if ip4 == nil {
				continue
			}
			add(broadcastAddr(ip4, ipNet.Mask))
		}
	}

	if len(targets) == 0 {
		return nil, fmt.Errorf("no broadcast targets")
	}
	return targets, nil
}

func broadcastAddr(ip net.IP, mask net.IPMask) net.IP {
	ip = ip.To4()
	if len(mask) == net.IPv6len {
		mask = mask[12:]
	}
	if len(mask) != net.IPv4len {
		return nil
	}
	bcast := make(net.IP, net.IPv4len)
	for i := range ip {
		bcast[i] = ip[i] | ^mask[i]
	}
	return bcast
}
