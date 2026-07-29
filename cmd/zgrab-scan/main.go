// zgrab-scan is a simple CLI for the internal/zgrab port scanner.
//
// Usage:
//
//	go run ./cmd/zgrab-scan -host example.com -ports 443
//	go run ./cmd/zgrab-scan -host 93.184.216.34 -ports 80,443
//	go run ./cmd/zgrab-scan -host 10.0.0.1 -ports 22,443,8000-9000
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"os"

	"github.com/CZERTAINLY/CBOM-lens/internal/zgrab"
)

func main() {
	host := flag.String("host", "", "hostname or IP address to scan (required)")
	ports := flag.String("ports", "443", "ports to scan, e.g. 443 or 80,443 or 1-1024")
	sni := flag.String("sni", "", "TLS SNI hostname (defaults to -host when it is a hostname, not an IP)")
	flag.Parse()

	if *host == "" {
		fmt.Fprintln(os.Stderr, "error: -host is required")
		flag.Usage()
		os.Exit(1)
	}

	// Resolve to an IP address.
	addr, err := resolve(*host)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error resolving %q: %v\n", *host, err)
		os.Exit(1)
	}

	// Use the hostname as SNI when it isn't already an IP, unless overridden.
	serverName := *sni
	if serverName == "" {
		if _, parseErr := netip.ParseAddr(*host); parseErr != nil {
			serverName = *host
		}
	}

	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn})))

	scanner := zgrab.New().
		WithPorts(*ports).
		WithServerName(serverName)

	fmt.Printf("Scanning %s (%s), ports %s\n\n", *host, addr, *ports)

	result, err := scanner.Scan(context.Background(), addr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "scan error: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Address : %s\n", result.Address)
	fmt.Printf("Status  : %s\n", result.Status)
	fmt.Printf("Ports   : %d open\n", len(result.Ports))

	for _, p := range result.Ports {
		fmt.Printf("\n── Port %d/%s [%s]  service=%s\n", p.PortNumber, p.Protocol, p.State, p.Service.Name)

		for _, cg := range p.Ciphers {
			fmt.Printf("   Ciphers (%s):\n", cg.Name)
			for _, c := range cg.Ciphers {
				fmt.Printf("     %s\n", c.Name)
			}
		}

		for i, hit := range p.TLSCerts {
			cert := hit.Cert
			fmt.Printf("   Certificate #%d:\n", i+1)
			fmt.Printf("     Subject  : %s\n", cert.Subject.CommonName)
			fmt.Printf("     Issuer   : %s\n", cert.Issuer.CommonName)
			fmt.Printf("     SANs     : %v\n", cert.DNSNames)
			fmt.Printf("     NotAfter : %s\n", cert.NotAfter.Format("2006-01-02"))
		}

		for i, k := range p.SSHHostKeys {
			fmt.Printf("   SSH Key #%d: type=%s bits=%s fingerprint=%s\n", i+1, k.Type, k.Bits, k.Fingerprint)
		}
	}
}

func resolve(host string) (netip.Addr, error) {
	if addr, err := netip.ParseAddr(host); err == nil {
		return addr, nil
	}
	addrs, err := net.LookupHost(host)
	if err != nil {
		return netip.Addr{}, err
	}
	for _, a := range addrs {
		if addr, err := netip.ParseAddr(a); err == nil && addr.Is4() {
			return addr, nil
		}
	}
	// Fall back to any address if no IPv4 found.
	slog.Warn("resolve: no IPv4 address found, falling back",
		slog.String("host", host),
		slog.String("addr", addrs[0]),
	)
	return netip.ParseAddr(addrs[0])
}
