package zgrab

import (
	"crypto/rand"
	"crypto/rsa"
	"net/netip"
	"strconv"
	"testing"

	xssh "golang.org/x/crypto/ssh"
	ztls "github.com/zmap/zcrypto/tls"

	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// Port parsing unit tests
// ---------------------------------------------------------------------------

func TestParsePorts(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name  string
		specs []string
		want  []uint16
	}{
		{"single", []string{"443"}, []uint16{443}},
		{"comma list", []string{"80,443"}, []uint16{80, 443}},
		{"range", []string{"8080-8082"}, []uint16{8080, 8081, 8082}},
		{"mixed", []string{"80,443,8080-8082"}, []uint16{80, 443, 8080, 8081, 8082}},
		{"multi-spec dedup", []string{"443", "443,8443"}, []uint16{443, 8443}},
		{"sorted output", []string{"9000,1000"}, []uint16{1000, 9000}},
		{"range ending at 65535", []string{"65533-65535"}, []uint16{65533, 65534, 65535}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := parsePorts(tc.specs)
			require.NoError(t, err)
			require.Equal(t, tc.want, got)
		})
	}
}

func TestParsePortsErrors(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name  string
		specs []string
	}{
		{"zero port", []string{"0"}},
		{"out of range", []string{"99999"}},
		{"invalid string", []string{"abc"}},
		{"reversed range", []string{"1024-80"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := parsePorts(tc.specs)
			require.Error(t, err)
		})
	}
}

// ---------------------------------------------------------------------------
// Pure unit tests — no network
// ---------------------------------------------------------------------------

func TestScanInvalidPortSpec(t *testing.T) {
	t.Parallel()
	scanner := New().WithPorts("abc")
	_, err := scanner.Scan(t.Context(), netip.MustParseAddr("127.0.0.1"))
	require.Error(t, err)
	require.ErrorContains(t, err, "parse ports")
}

func TestWithPortsImmutability(t *testing.T) {
	t.Parallel()
	base := New().WithPorts("443")
	_ = base.WithPorts("8443") // should not mutate base

	ports, err := parsePorts(base.ports)
	require.NoError(t, err)
	require.Equal(t, []uint16{443}, ports)
}

func TestStripColons(t *testing.T) {
	t.Parallel()
	tests := []struct{ in, want string }{
		{"17:f9:a4:c3", "17f9a4c3"},
		{"abcdef", "abcdef"},
		{"", ""},
		{"::", ""},
	}
	for _, tc := range tests {
		require.Equal(t, tc.want, stripColons(tc.in))
	}
}

func TestPublicKeyBits(t *testing.T) {
	t.Parallel()

	// RSA path uses runtime introspection — exercise it with a real key.
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	pub, err := xssh.NewPublicKey(priv.Public())
	require.NoError(t, err)
	require.Equal(t, 2048, publicKeyBits(pub))
}

func TestScannerWithNmapBinaryNoOp(t *testing.T) {
	t.Parallel()
	// WithNmapBinary should be a no-op and not panic.
	s := New().WithNmapBinary("/usr/bin/nmap")
	require.NotNil(t, s)
}

// ---------------------------------------------------------------------------
// Integration tests (skipped with -short)
// ---------------------------------------------------------------------------

func TestScannerTLS_IPv4(t *testing.T) {
	if testing.Short() {
		t.Skip("skipped via -short")
	}
	t.Parallel()

	port := tlsAddr4.Port()
	addr := tlsAddr4.Addr()

	scanner := New().WithPorts(strconv.Itoa(int(port)))
	result, err := scanner.Scan(t.Context(), addr)

	require.NoError(t, err)
	require.Equal(t, addr.String(), result.Address)
	require.Equal(t, "up", result.Status)
	require.Len(t, result.Ports, 1)

	p := result.Ports[0]
	require.Equal(t, int(port), p.PortNumber)
	require.Equal(t, "open", p.State)
	require.Equal(t, "tcp", p.Protocol)
	require.Equal(t, "ssl", p.Service.Name)
	require.Equal(t, "ssl", p.Service.Tunnel)

	require.NotEmpty(t, p.Ciphers, "expected at least one cipher group")
	require.NotEmpty(t, p.Ciphers[0].Ciphers, "expected at least one cipher in group")

	require.Len(t, p.TLSCerts, 1)
	hit := p.TLSCerts[0]
	require.NotNil(t, hit.Cert)
	require.Equal(t, "localhost", hit.Cert.Subject.CommonName)
	require.Equal(t, addr.String()+":"+strconv.Itoa(int(port)), hit.Location)
	require.Equal(t, "ZGRAB", hit.Source)
}

func TestScannerTLS_IPv6(t *testing.T) {
	if testing.Short() {
		t.Skip("skipped via -short")
	}
	t.Parallel()

	port := tlsAddr6.Port()
	addr := tlsAddr6.Addr()

	scanner := New().WithPorts(strconv.Itoa(int(port)))
	result, err := scanner.Scan(t.Context(), addr)

	require.NoError(t, err)
	require.Equal(t, addr.String(), result.Address)
	require.Equal(t, "up", result.Status)
	require.Len(t, result.Ports, 1)

	p := result.Ports[0]
	require.Equal(t, "ssl", p.Service.Name)
	require.NotEmpty(t, p.Ciphers)
	require.Len(t, p.TLSCerts, 1)
	require.Equal(t, "ZGRAB", p.TLSCerts[0].Source)
}

func TestScannerSSH_IPv4(t *testing.T) {
	if testing.Short() {
		t.Skip("skipped via -short")
	}
	t.Parallel()

	port := sshAddr4.Port()
	addr := sshAddr4.Addr()

	scanner := New().WithPorts(strconv.Itoa(int(port)))
	result, err := scanner.Scan(t.Context(), addr)

	require.NoError(t, err)
	require.Equal(t, addr.String(), result.Address)
	require.Equal(t, "up", result.Status)
	require.Len(t, result.Ports, 1)

	p := result.Ports[0]
	require.Equal(t, int(port), p.PortNumber)
	require.Equal(t, "open", p.State)
	require.Equal(t, "tcp", p.Protocol)
	require.Equal(t, "ssh", p.Service.Name)

	require.NotEmpty(t, p.SSHHostKeys, "expected at least one SSH host key")
	key := p.SSHHostKeys[0]
	require.NotEmpty(t, key.Key)
	require.NotEmpty(t, key.Type)
	require.NotEmpty(t, key.Bits)
	require.NotEmpty(t, key.Fingerprint)
}

func TestScannerUnknownService(t *testing.T) {
	if testing.Short() {
		t.Skip("skipped via -short")
	}
	t.Parallel()

	port := rawAddr4.Port()
	addr := rawAddr4.Addr()

	scanner := New().WithPorts(strconv.Itoa(int(port)))
	result, err := scanner.Scan(t.Context(), addr)

	require.NoError(t, err)
	require.Equal(t, "up", result.Status)
	require.Len(t, result.Ports, 1)

	p := result.Ports[0]
	require.Equal(t, "unknown", p.Service.Name)
	require.Empty(t, p.Ciphers)
	require.Empty(t, p.TLSCerts)
	require.Empty(t, p.SSHHostKeys)
}

func TestScannerNoOpenPorts(t *testing.T) {
	if testing.Short() {
		t.Skip("skipped via -short")
	}
	t.Parallel()

	// Scan a port that is guaranteed to be closed (port 1 on loopback).
	scanner := New().WithPorts("1")
	result, err := scanner.Scan(t.Context(), tlsAddr4.Addr())

	require.NoError(t, err)
	require.Equal(t, "down", result.Status)
	require.Empty(t, result.Ports)
}

func TestKnownTLS10And11SuitesNoTLS12OnlySuites(t *testing.T) {
	t.Parallel()
	// These suite IDs are only valid in TLS 1.2+. Verify none appear in the
	// TLS 1.0/1.1 list.
	tls12Only := map[uint16]string{
		ztls.TLS_RSA_WITH_AES_128_GCM_SHA256:              "TLS_RSA_WITH_AES_128_GCM_SHA256",
		ztls.TLS_RSA_WITH_AES_256_GCM_SHA384:              "TLS_RSA_WITH_AES_256_GCM_SHA384",
		ztls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:      "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
		ztls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384:      "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
		ztls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:        "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
		ztls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:        "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
		ztls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256:  "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
		ztls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256: "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
		ztls.TLS_RSA_WITH_AES_128_CBC_SHA256:              "TLS_RSA_WITH_AES_128_CBC_SHA256",
		ztls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256:      "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256",
		ztls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256:        "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",
	}
	for _, id := range knownTLS10And11Suites() {
		if name, bad := tls12Only[id]; bad {
			t.Errorf("knownTLS10And11Suites contains TLS 1.2-only suite %s (0x%04X)", name, id)
		}
	}
	require.NotEmpty(t, knownTLS10And11Suites(), "suite list must not be empty")
}

func TestEnumTLS10CiphersNegative(t *testing.T) {
	if testing.Short() {
		t.Skip("skipped via -short")
	}
	// The test TLS server is TLS 1.2 only; enumTLS10Ciphers must return nil,
	// not panic or block.
	addr := tlsAddr4.String()
	got := enumTLS10Ciphers(t.Context(), addr, "")
	require.Nil(t, got, "expected no TLS 1.0 ciphers from a TLS 1.2-only server")
}

func TestEnumTLS11CiphersNegative(t *testing.T) {
	if testing.Short() {
		t.Skip("skipped via -short")
	}
	addr := tlsAddr4.String()
	got := enumTLS11Ciphers(t.Context(), addr, "")
	require.Nil(t, got, "expected no TLS 1.1 ciphers from a TLS 1.2-only server")
}
