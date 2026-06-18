package server

import (
	"context"
	"net"
	"testing"
	"time"
)

func TestBroadcastAddr(t *testing.T) {
	ip := net.ParseIP("192.168.1.10").To4()
	mask := net.CIDRMask(24, 32)
	got := broadcastAddr(ip, mask)
	want := net.ParseIP("192.168.1.255").To4()
	if !got.Equal(want) {
		t.Fatalf("got %s, want %s", got, want)
	}
}

func TestDiscoverServers_roundTrip(t *testing.T) {
	tmp, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	listenAddr := tmp.LocalAddr().String()
	tmp.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		_ = RunDiscovery(ctx, DiscoveryConfig{
			ListenAddr: listenAddr,
			GRPCAddr:   "127.0.0.1:50051",
		})
	}()

	time.Sleep(50 * time.Millisecond)

	host, portStr, err := net.SplitHostPort(listenAddr)
	if err != nil {
		t.Fatal(err)
	}
	port, err := net.LookupPort("udp", portStr)
	if err != nil {
		t.Fatal(err)
	}

	servers, err := DiscoverServers(context.Background(), DiscoverClientConfig{
		Port:    port,
		Service: DiscoveryServiceName,
		Timeout: 2 * time.Second,
		ProbeAddrs: []*net.UDPAddr{{
			IP:   net.ParseIP(host),
			Port: port,
		}},
	})
	if err != nil {
		t.Fatal(err)
	}

	cancel()

	found := false
	for _, s := range servers {
		if s.GRPCAddr == "127.0.0.1:50051" && s.SourceIP == host {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected server on %s, got %#v", listenAddr, servers)
	}
}
