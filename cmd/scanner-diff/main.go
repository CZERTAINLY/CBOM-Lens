// scanner-diff runs both the zgrab and nmap port scanners against the same
// target and prints a diff-like report highlighting where they agree and
// disagree on open ports, cipher suites, certificates, and SSH host keys.
//
// Usage:
//
//	go run ./cmd/scanner-diff -host example.com -ports 443
//	go run ./cmd/scanner-diff -host github.com  -ports 22,443
//	go run ./cmd/scanner-diff -host expired.badssl.com -ports 443
package main

import (
	"context"
	"crypto/x509"
	"flag"
	"fmt"
	"net"
	"net/netip"
	"os"
	"sort"
	"strings"
	"sync"

	"github.com/CZERTAINLY/CBOM-lens/internal/model"
	inmap "github.com/CZERTAINLY/CBOM-lens/internal/nmap"
	"github.com/CZERTAINLY/CBOM-lens/internal/zgrab"
)

const divider = "─────────────────────────────────────────────────────────────"

func main() {
	host := flag.String("host", "", "hostname or IP address to scan (required)")
	ports := flag.String("ports", "22,443,8443", "ports, e.g. 443 or 22,443 or 1-1024")
	sni := flag.String("sni", "", "TLS SNI hostname (defaults to -host when it is a hostname)")
	nmapBin := flag.String("nmap", "nmap", "path to nmap binary")
	flag.Parse()

	if *host == "" {
		fmt.Fprintln(os.Stderr, "error: -host is required")
		flag.Usage()
		os.Exit(1)
	}

	addr, err := resolve(*host)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error resolving %q: %v\n", *host, err)
		os.Exit(1)
	}

	serverName := *sni
	if serverName == "" {
		if _, parseErr := netip.ParseAddr(*host); parseErr != nil {
			serverName = *host // host is a name, not an IP — use as SNI
		}
	}

	ctx := context.Background()

	var (
		nmapResult  model.Nmap
		nmapErr     error
		zgrabResult model.Nmap
		zgrabErr    error
		wg          sync.WaitGroup
	)

	wg.Add(2)
	go func() {
		defer wg.Done()
		nmapResult, nmapErr = inmap.New().
			WithNmapBinary(*nmapBin).
			WithPorts(*ports).
			Scan(ctx, addr)
	}()
	go func() {
		defer wg.Done()
		zgrabResult, zgrabErr = zgrab.New().
			WithPorts(*ports).
			WithServerName(serverName).
			Scan(ctx, addr)
	}()
	wg.Wait()

	fmt.Printf("=== scanner-diff: %s → %s ===\n\n", *host, addr)
	fmt.Printf("nmap command:\n  %s\n\n", buildNmapCmd(*nmapBin, addr, *ports))

	if nmapErr != nil {
		fmt.Fprintf(os.Stderr, "[!] nmap error: %v\n", nmapErr)
		os.Exit(1)
	}
	if zgrabErr != nil {
		fmt.Fprintf(os.Stderr, "[!] zgrab error: %v\n", zgrabErr)
		os.Exit(1)
	}

	printReport(nmapResult, zgrabResult)
}

// buildNmapCmd reconstructs the nmap invocation that is equivalent to
// inmap.New() — same scripts, timing and service detection flags.
func buildNmapCmd(bin string, addr netip.Addr, ports string) string {
	args := []string{bin, "-sV", "-T4", "--script", "ssl-enum-ciphers,ssl-cert,ssh-hostkey"}
	if addr.Is6() {
		args = append(args, "-6")
	}
	args = append(args, "-p", ports, addr.String())
	return strings.Join(args, " ")
}

// ─── diff report ─────────────────────────────────────────────────────────────

type stats struct {
	nmapPorts, zgrabPorts, sharedPorts   int
	nmapCiphers, zgrabCiphers, sharedCiphers int
	nmapKeys, zgrabKeys, sharedKeys      int
	serviceDisagree                       int
}

func printReport(n, z model.Nmap) {
	nm := indexPorts(n.Ports)
	zm := indexPorts(z.Ports)
	allPorts := unionIntKeys(nm, zm)

	s := &stats{}

	for _, port := range allPorts {
		np, inN := nm[port]
		zp, inZ := zm[port]

		fmt.Println(divider)
		switch {
		case inN && inZ:
			s.sharedPorts++
			printPortDiff(np, zp, s)
		case inN:
			s.nmapPorts++
			fmt.Printf("N  PORT %d/%s  service:%s  (nmap only)\n",
				np.PortNumber, np.Protocol, np.Service.Name)
		default:
			s.zgrabPorts++
			fmt.Printf("Z  PORT %d/%s  service:%s  (zgrab only)\n",
				zp.PortNumber, zp.Protocol, zp.Service.Name)
		}
	}

	fmt.Println(divider)
	printSummary(s)
}

func printPortDiff(n, z model.NmapPort, s *stats) {
	svcLine := fmt.Sprintf("service: %s", n.Service.Name)
	if n.Service.Name != z.Service.Name {
		s.serviceDisagree++
		svcLine = fmt.Sprintf("service: nmap=%s  zgrab=%s  (!)", n.Service.Name, z.Service.Name)
	}
	fmt.Printf("   PORT %d/%s  %s\n", n.PortNumber, n.Protocol, svcLine)

	if len(n.Ciphers) > 0 || len(z.Ciphers) > 0 {
		printCiphersDiff(n.Ciphers, z.Ciphers, s)
	}
	if len(n.TLSCerts) > 0 || len(z.TLSCerts) > 0 {
		printCertsDiff(n.TLSCerts, z.TLSCerts)
	}
	if len(n.SSHHostKeys) > 0 || len(z.SSHHostKeys) > 0 {
		printSSHDiff(n.SSHHostKeys, z.SSHHostKeys, s)
	}
}

// ─── cipher diff ─────────────────────────────────────────────────────────────

func printCiphersDiff(nGroups, zGroups []model.SSLEnumCiphers, s *stats) {
	nByVer := indexCipherGroups(nGroups)
	zByVer := indexCipherGroups(zGroups)

	for _, ver := range unionStringKeys(nByVer, zByVer) {
		nSet := cipherSet(nByVer[ver])
		zSet := cipherSet(zByVer[ver])
		all := unionStringKeys(nSet, zSet)

		fmt.Printf("  %s ciphers  (nmap:%d  zgrab:%d):\n", ver, len(nSet), len(zSet))
		for _, name := range all {
			_, inN := nSet[name]
			_, inZ := zSet[name]
			switch {
			case inN && inZ:
				s.sharedCiphers++
				fmt.Printf("    = %s\n", name)
			case inN:
				s.nmapCiphers++
				fmt.Printf("    N %s\n", name)
			default:
				s.zgrabCiphers++
				fmt.Printf("    Z %s\n", name)
			}
		}
	}
}

func indexCipherGroups(groups []model.SSLEnumCiphers) map[string][]model.SSLCipher {
	m := make(map[string][]model.SSLCipher, len(groups))
	for _, g := range groups {
		m[g.Name] = g.Ciphers
	}
	return m
}

func cipherSet(ciphers []model.SSLCipher) map[string]struct{} {
	m := make(map[string]struct{}, len(ciphers))
	for _, c := range ciphers {
		m[strings.TrimSpace(c.Name)] = struct{}{}
	}
	return m
}

// ─── certificate diff ────────────────────────────────────────────────────────

func printCertsDiff(nCerts, zCerts []model.CertHit) {
	nc := firstCert(nCerts)
	zc := firstCert(zCerts)

	switch {
	case nc == nil && zc == nil:
		return
	case nc == nil:
		fmt.Printf("  Certificate: Z %s\n", certSummary(zc))
		return
	case zc == nil:
		fmt.Printf("  Certificate: N %s\n", certSummary(nc))
		return
	}

	if nc.Subject.CommonName == zc.Subject.CommonName && nc.NotAfter.Equal(zc.NotAfter) {
		fmt.Printf("  Certificate: = %s\n", certSummary(nc))
	} else {
		fmt.Printf("  Certificate: N %s\n", certSummary(nc))
		fmt.Printf("               Z %s\n", certSummary(zc))
	}
}

func firstCert(hits []model.CertHit) *x509.Certificate {
	for _, h := range hits {
		if h.Cert != nil {
			return h.Cert
		}
	}
	return nil
}

func certSummary(c *x509.Certificate) string {
	sans := strings.Join(c.DNSNames, ", ")
	if sans == "" {
		sans = "(none)"
	}
	return fmt.Sprintf("CN=%-30s  expires=%s  issuer=%s  SANs=[%s]",
		c.Subject.CommonName,
		c.NotAfter.Format("2006-01-02"),
		c.Issuer.CommonName,
		sans,
	)
}

// ─── SSH key diff ─────────────────────────────────────────────────────────────

func printSSHDiff(nKeys, zKeys []model.SSHHostKey, s *stats) {
	// nmap reports SHA-256 fingerprints; zgrab uses legacy MD5.
	// Match by key type rather than fingerprint.
	nByType := indexSSHKeys(nKeys)
	zByType := indexSSHKeys(zKeys)

	fmt.Printf("  SSH host keys  (nmap:%d  zgrab:%d):\n", len(nByType), len(zByType))
	for _, keyType := range unionStringKeys(nByType, zByType) {
		nk, inN := nByType[keyType]
		zk, inZ := zByType[keyType]
		switch {
		case inN && inZ:
			s.sharedKeys++
			fmt.Printf("    = %s (%s bits)  nmap-fp:%s  zgrab-fp:%s\n",
				keyType, nk.Bits, nk.Fingerprint, zk.Fingerprint)
		case inN:
			s.nmapKeys++
			fmt.Printf("    N %s (%s bits)  fp:%s\n", keyType, nk.Bits, nk.Fingerprint)
		default:
			s.zgrabKeys++
			fmt.Printf("    Z %s (%s bits)  fp:%s\n", keyType, zk.Bits, zk.Fingerprint)
		}
	}
}

func indexSSHKeys(keys []model.SSHHostKey) map[string]model.SSHHostKey {
	m := make(map[string]model.SSHHostKey, len(keys))
	for _, k := range keys {
		m[k.Type] = k
	}
	return m
}

// ─── summary ─────────────────────────────────────────────────────────────────

func printSummary(s *stats) {
	fmt.Printf("\nSUMMARY\n")

	portLine := fmt.Sprintf("%d shared", s.sharedPorts)
	if s.nmapPorts+s.zgrabPorts > 0 {
		portLine += fmt.Sprintf(", %d nmap-only, %d zgrab-only", s.nmapPorts, s.zgrabPorts)
	}
	fmt.Printf("  ports  :  %s\n", portLine)

	if s.sharedCiphers+s.nmapCiphers+s.zgrabCiphers > 0 {
		fmt.Printf("  ciphers:  %d shared, %d nmap-only, %d zgrab-only\n",
			s.sharedCiphers, s.nmapCiphers, s.zgrabCiphers)
	}
	if s.sharedKeys+s.nmapKeys+s.zgrabKeys > 0 {
		fmt.Printf("  ssh keys: %d shared, %d nmap-only, %d zgrab-only\n",
			s.sharedKeys, s.nmapKeys, s.zgrabKeys)
	}
	if s.serviceDisagree > 0 {
		fmt.Printf("  service : %d port(s) with mismatched detection\n", s.serviceDisagree)
	}
	fmt.Println()

	total := s.nmapPorts + s.zgrabPorts + s.nmapCiphers + s.zgrabCiphers + s.nmapKeys + s.zgrabKeys + s.serviceDisagree
	if total == 0 {
		fmt.Println("  ✓ scanners agree on everything")
	} else {
		fmt.Printf("  ! %d total disagreement(s)\n", total)
	}
	fmt.Println()
}

// ─── helpers ─────────────────────────────────────────────────────────────────

func indexPorts(ports []model.NmapPort) map[int]model.NmapPort {
	m := make(map[int]model.NmapPort, len(ports))
	for _, p := range ports {
		m[p.PortNumber] = p
	}
	return m
}

func unionIntKeys(a, b map[int]model.NmapPort) []int {
	seen := make(map[int]struct{}, len(a)+len(b))
	for k := range a {
		seen[k] = struct{}{}
	}
	for k := range b {
		seen[k] = struct{}{}
	}
	keys := make([]int, 0, len(seen))
	for k := range seen {
		keys = append(keys, k)
	}
	sort.Ints(keys)
	return keys
}

func unionStringKeys[V any](a, b map[string]V) []string {
	seen := make(map[string]struct{}, len(a)+len(b))
	for k := range a {
		seen[k] = struct{}{}
	}
	for k := range b {
		seen[k] = struct{}{}
	}
	keys := make([]string, 0, len(seen))
	for k := range seen {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
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
	return netip.ParseAddr(addrs[0])
}
