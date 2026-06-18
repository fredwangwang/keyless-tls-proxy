package server

import (
	"context"
	"encoding/json"
	"net"
	"testing"
	"time"
)

func TestGrpcAddrForClient_explicitHost(t *testing.T) {
	remote := &net.UDPAddr{IP: net.ParseIP("192.168.1.20"), Port: 54321}
	got, err := grpcAddrForClient("server.example.com:50051", remote)
	if err != nil {
		t.Fatal(err)
	}
	if got != "server.example.com:50051" {
		t.Fatalf("got %q, want server.example.com:50051", got)
	}
}

func TestGrpcAddrForClient_loopbackRemote(t *testing.T) {
	remote := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 54321}
	got, err := grpcAddrForClient("127.0.0.1:50051", remote)
	if err != nil {
		t.Fatal(err)
	}
	if got != "127.0.0.1:50051" {
		t.Fatalf("got %q, want 127.0.0.1:50051", got)
	}
}

func TestGrpcAddrForClient_wildcardHost(t *testing.T) {
	localIP := pickLocalIPv4(t)
	remote := &net.UDPAddr{IP: localIP, Port: 54321}

	got, err := grpcAddrForClient("0.0.0.0:50051", remote)
	if err != nil {
		t.Fatal(err)
	}
	want := net.JoinHostPort(localIP.String(), "50051")
	if got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestGrpcAddrForClient_loopbackBindLANRemote(t *testing.T) {
	localIP := pickLocalIPv4(t)
	remote := &net.UDPAddr{IP: localIP, Port: 54321}

	got, err := grpcAddrForClient("127.0.0.1:50051", remote)
	if err != nil {
		t.Fatal(err)
	}
	want := net.JoinHostPort(localIP.String(), "50051")
	if got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestSameSubnet(t *testing.T) {
	a := net.ParseIP("192.168.1.10")
	b := net.ParseIP("192.168.1.99")
	mask := net.CIDRMask(24, 32)
	if !sameSubnet(a, b, mask) {
		t.Fatal("expected same /24 subnet")
	}
	c := net.ParseIP("10.0.0.1")
	if sameSubnet(a, c, mask) {
		t.Fatal("expected different subnets")
	}
}

func TestLocalIPFor_matchesLocalInterface(t *testing.T) {
	localIP := pickLocalIPv4(t)
	got, err := localIPFor(localIP)
	if err != nil {
		t.Fatal(err)
	}
	if !got.Equal(localIP) {
		t.Fatalf("got %s, want %s", got, localIP)
	}
}

func TestRunDiscovery_roundTrip(t *testing.T) {
	tmp, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	listenAddr := tmp.LocalAddr().String()
	tmp.Close()

	clientPC, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer clientPC.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan error, 1)
	go func() {
		done <- RunDiscovery(ctx, DiscoveryConfig{
			ListenAddr: listenAddr,
			GRPCAddr:   "127.0.0.1:50051",
		})
	}()

	time.Sleep(50 * time.Millisecond)

	serverAddr, err := net.ResolveUDPAddr("udp", listenAddr)
	if err != nil {
		t.Fatal(err)
	}

	probe, err := json.Marshal(discoverRequest{Op: "discover", Service: defaultDiscoveryService})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := clientPC.WriteTo(probe, serverAddr); err != nil {
		t.Fatal(err)
	}

	_ = clientPC.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 2048)
	n, _, err := clientPC.ReadFrom(buf)
	if err != nil {
		t.Fatalf("read announce: %v", err)
	}

	var resp announceResponse
	if err := json.Unmarshal(buf[:n], &resp); err != nil {
		t.Fatal(err)
	}
	if resp.Op != "announce" {
		t.Fatalf("op=%q, want announce", resp.Op)
	}
	if resp.Service != defaultDiscoveryService {
		t.Fatalf("service=%q", resp.Service)
	}
	if resp.GRPCAddr != "127.0.0.1:50051" {
		t.Fatalf("grpc_addr=%q, want 127.0.0.1:50051", resp.GRPCAddr)
	}
	if resp.Version != discoveryVersion {
		t.Fatalf("version=%q", resp.Version)
	}

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("discovery exit: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("discovery did not stop")
	}
}

func TestRunDiscovery_ignoresInvalidProbe(t *testing.T) {
	tmp, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	listenAddr := tmp.LocalAddr().String()
	tmp.Close()

	clientPC, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer clientPC.Close()

	serverAddr, err := net.ResolveUDPAddr("udp", listenAddr)
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		_ = RunDiscovery(ctx, DiscoveryConfig{
			ListenAddr: listenAddr,
			GRPCAddr:   "127.0.0.1:50051",
		})
	}()

	time.Sleep(50 * time.Millisecond)

	if _, err := clientPC.WriteTo([]byte(`{"op":"ping"}`), serverAddr); err != nil {
		t.Fatal(err)
	}

	_ = clientPC.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
	buf := make([]byte, 2048)
	_, _, err = clientPC.ReadFrom(buf)
	if err == nil {
		t.Fatal("expected no reply for invalid probe")
	}
}

func pickLocalIPv4(t *testing.T) net.IP {
	t.Helper()
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		t.Fatal(err)
	}
	for _, addr := range addrs {
		ipNet, ok := addr.(*net.IPNet)
		if !ok || ipNet.IP.IsLoopback() {
			continue
		}
		if ip4 := ipNet.IP.To4(); ip4 != nil {
			return ip4
		}
	}
	t.Skip("no non-loopback IPv4 interface")
	return nil
}
