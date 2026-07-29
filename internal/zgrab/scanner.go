package zgrab

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"sort"
	"strconv"
	"sync"
	"time"

	"github.com/CZERTAINLY/CBOM-lens/internal/model"
	"github.com/CZERTAINLY/CBOM-lens/internal/portscanner"
)

// Compile-time assertion: Scanner satisfies portscanner.Scanner.
var _ portscanner.Scanner = Scanner{}

const (
	tcpDialTimeout = 500 * time.Millisecond
	tcpConcurrency = 500
)

// Scanner is an alternative to internal/nmap that uses zcrypto (zgrab2's TLS library)
// for TLS/SSL and golang.org/x/crypto/ssh for SSH detection.
// It is interface-compatible with nmap.Scanner.
type Scanner struct {
	ports      []string
	rawPath    string
	serverName string // optional SNI hostname for TLS connections
}

// New creates a Scanner with default settings.
func New() Scanner {
	return Scanner{}
}

// WithNmapBinary is a no-op kept for interface compatibility with nmap.Scanner.
func (s Scanner) WithNmapBinary(_ string) Scanner {
	return s
}

// WithPorts adds port specifications (e.g. "443", "80,443", "1-1024").
func (s Scanner) WithPorts(defs ...string) Scanner {
	ret := s
	ret.ports = append(append([]string(nil), ret.ports...), defs...)
	return ret
}

// WithRawPath sets an optional path for raw output (kept for interface compatibility).
func (s Scanner) WithRawPath(path string) Scanner {
	s.rawPath = path
	return s
}

// WithServerName sets the TLS SNI hostname. Required when scanning servers that
// use SNI-based virtual hosting (e.g. CDNs). Has no effect on SSH probing.
func (s Scanner) WithServerName(name string) Scanner {
	s.serverName = name
	return s
}

// Scan performs TCP port discovery followed by TLS and SSH probing on the given address.
func (s Scanner) Scan(ctx context.Context, addr netip.Addr) (model.Nmap, error) {
	ports := s.ports
	if ports == nil {
		ports = []string{"1-65535"}
	}

	portNums, err := parsePorts(ports)
	if err != nil {
		return model.Nmap{}, fmt.Errorf("parse ports: %w", err)
	}

	slog.InfoContext(ctx, "zgrab scan started",
		slog.String("target", addr.String()),
		slog.Int("port_count", len(portNums)),
	)

	openPorts := tcpScan(ctx, addr, portNums)
	if len(openPorts) == 0 {
		slog.WarnContext(ctx, "zgrab: no open ports", "target", addr)
		return model.Nmap{Address: addr.String(), Status: "down"}, nil
	}

	nmapPorts := make([]model.NmapPort, 0, len(openPorts))
	for _, port := range openPorts {
		nmapPorts = append(nmapPorts, probePort(ctx, addr, port, s.serverName))
	}

	return model.Nmap{
		Address: addr.String(),
		Status:  "up",
		Ports:   nmapPorts,
	}, nil
}

// tcpScan does a concurrent TCP connect scan and returns sorted open port numbers.
func tcpScan(ctx context.Context, addr netip.Addr, ports []uint16) []uint16 {
	sem := make(chan struct{}, tcpConcurrency)
	var mu sync.Mutex
	var open []uint16
	var wg sync.WaitGroup

	for _, port := range ports {
		if ctx.Err() != nil {
			break
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(p uint16) {
			defer wg.Done()
			defer func() { <-sem }()

			target := net.JoinHostPort(addr.String(), strconv.Itoa(int(p)))
			d := net.Dialer{Timeout: tcpDialTimeout}
			conn, err := d.DialContext(ctx, "tcp", target)
			if err == nil {
				_ = conn.Close()
				mu.Lock()
				open = append(open, p)
				mu.Unlock()
			}
		}(port)
	}

	wg.Wait()
	sort.Slice(open, func(i, j int) bool { return open[i] < open[j] })
	return open
}

// probePort probes a single open TCP port for TLS, legacy SSL, and SSH.
// SSLv3 and SSLv2 are always probed independently of the modern TLS result
// because a server can simultaneously support both TLS 1.2 and SSLv3/SSLv2.
func probePort(ctx context.Context, addr netip.Addr, port uint16, serverName string) model.NmapPort {
	addrPort := net.JoinHostPort(addr.String(), strconv.Itoa(int(port)))

	p := model.NmapPort{
		PortNumber: int(port),
		State:      "open",
		Protocol:   "tcp",
	}

	tlsLike := false

	// Modern TLS (1.0–1.3) via zcrypto.
	if tlsRes := probeTLS(ctx, addrPort, serverName); tlsRes.detected {
		tlsLike = true
		p.Service = model.NmapService{Name: "ssl", Tunnel: "ssl"}
		p.Ciphers = append(p.Ciphers, tlsRes.ciphers...)
		for i := range tlsRes.certs {
			tlsRes.certs[i].Location = addrPort
			tlsRes.certs[i].Source = "ZGRAB"
		}
		p.TLSCerts = tlsRes.certs
	}

	// SSLv3 — raw probe; zcrypto explicitly excludes SSLv3 from its
	// supported-versions list so we craft the handshake at the byte level.
	if sslv3 := probeSSLv3(ctx, addrPort); sslv3.detected {
		tlsLike = true
		p.Service = model.NmapService{Name: "ssl", Tunnel: "ssl"}
		p.Ciphers = append(p.Ciphers, model.SSLEnumCiphers{Name: "SSLv3", Ciphers: sslv3.ciphers})
	}

	// SSLv2 — raw probe; no Go library implements the SSLv2 ClientHello sender.
	if sslv2 := probeSSLv2(ctx, addrPort); sslv2.detected {
		tlsLike = true
		p.Service = model.NmapService{Name: "ssl", Tunnel: "ssl"}
		p.Ciphers = append(p.Ciphers, model.SSLEnumCiphers{Name: "SSLv2", Ciphers: sslv2.ciphers})
	}

	if tlsLike {
		return p
	}

	// SSH.
	if sshRes := probeSSH(ctx, addrPort); sshRes.detected {
		p.Service = model.NmapService{Name: "ssh"}
		p.SSHHostKeys = sshRes.hostKeys
		return p
	}

	p.Service = model.NmapService{Name: "unknown"}
	return p
}
