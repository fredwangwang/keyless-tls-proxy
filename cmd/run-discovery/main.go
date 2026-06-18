package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"os"
	"text/tabwriter"
	"time"

	"tpm-cert-proxy/internal/server"
)

func main() {
	port := flag.Int("port", 6666, "UDP discovery port")
	probe := flag.String("probe", "", "optional unicast probe address (host:port) in addition to broadcast")
	timeout := flag.Duration("timeout", 3*time.Second, "how long to wait for server replies")
	service := flag.String("service", server.DiscoveryServiceName, "service name to discover")
	asJSON := flag.Bool("json", false, "print results as JSON")
	flag.Parse()

	cfg := server.DiscoverClientConfig{
		Port:    *port,
		Service: *service,
		Timeout: *timeout,
	}
	if *probe != "" {
		addr, err := net.ResolveUDPAddr("udp4", *probe)
		if err != nil {
			fatal(fmt.Errorf("probe address: %w", err))
		}
		cfg.ProbeAddrs = []*net.UDPAddr{addr}
	}

	servers, err := server.DiscoverServers(context.Background(), cfg)
	if err != nil {
		fatal(err)
	}

	if *asJSON {
		data, err := json.MarshalIndent(servers, "", "  ")
		if err != nil {
			fatal(err)
		}
		fmt.Println(string(data))
		return
	}

	if len(servers) == 0 {
		fmt.Println("No cert-servers found on the LAN.")
		return
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "HOSTNAME\tGRPC_ADDR\tVERSION\tSOURCE_IP")
	for _, s := range servers {
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", s.Hostname, s.GRPCAddr, s.Version, s.SourceIP)
	}
	_ = w.Flush()
}

func fatal(err error) {
	fmt.Fprintf(os.Stderr, "error: %v\n", err)
	os.Exit(1)
}
