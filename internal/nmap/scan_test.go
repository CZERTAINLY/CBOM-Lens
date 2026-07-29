package nmap

import (
	"bytes"
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/CZERTAINLY/CBOM-lens/internal/model"
	nmapv4 "github.com/Ullaakut/nmap/v4"
	"github.com/stretchr/testify/require"
)

// fakeNmap writes a POSIX-shell fake nmap into t.TempDir() that records its
// argv (one arg per line) to a file, optionally prints a line to stderr,
// cats the given fixture to stdout, and exits with code.
// Skips the calling test on Windows.
func fakeNmap(t *testing.T, fixturePath string, stderrLine string, exitCode int) (binPath, argsFile string) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("fake nmap is a POSIX shell script, skipping on Windows")
	}

	dir := t.TempDir()
	binPath = filepath.Join(dir, "nmap")
	argsFile = filepath.Join(dir, "args.txt")

	absFixture, err := filepath.Abs(fixturePath)
	require.NoError(t, err)

	var sb strings.Builder
	sb.WriteString("#!/bin/sh\n")
	fmt.Fprintf(&sb, "printf '%%s\\n' \"$@\" > %q\n", argsFile)
	if stderrLine != "" {
		fmt.Fprintf(&sb, "echo %q >&2\n", stderrLine)
	}
	fmt.Fprintf(&sb, "cat %q\n", absFixture)
	fmt.Fprintf(&sb, "exit %d\n", exitCode)

	require.NoError(t, os.WriteFile(binPath, []byte(sb.String()), 0o755))
	return binPath, argsFile
}

// scanFake runs s.Scan against a fakeNmap script, retrying the rare ETXTBSY
// fork/exec race: with parallel tests, a child process forked by another test
// can briefly hold this test's just-written script file descriptor between
// its fork and exec, making exec of the script fail with "text file busy"
// (see golang.org/issue/22315). The window is tiny, so a few short retries
// make the deterministic tests immune to it. Any other outcome, success or
// failure, is returned as-is.
func scanFake(t *testing.T, s Scanner, addr netip.Addr) (model.Nmap, error) {
	t.Helper()
	var got model.Nmap
	var err error
	for range 20 {
		got, err = s.Scan(t.Context(), addr)
		if err == nil || !strings.Contains(err.Error(), "text file busy") {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	return got, err
}

// recordedArgs reads back the argv recorded by the fakeNmap script,
// one argument per line.
func recordedArgs(t *testing.T, argsFile string) []string {
	t.Helper()
	data, err := os.ReadFile(argsFile)
	require.NoError(t, err)
	return strings.Split(strings.TrimSuffix(string(data), "\n"), "\n")
}

func TestScan_EmitsExpectedArgsAndParsesTLS(t *testing.T) {
	t.Parallel()
	bin, argsFile := fakeNmap(t, "testdata/nmaprun_tls.xml", "", 0)

	got, err := scanFake(t, New().WithNmapBinary(bin).WithPorts("443"),
		netip.MustParseAddr("127.0.0.1"))
	require.NoError(t, err)

	// The exact argv is an intentional parity lock on the nmap command line
	// the wrapper produces. A deliberate flag change in Scan() must update
	// this expectation.
	require.Equal(t, []string{
		"-T4",
		"-sV",
		"--script=ssl-enum-ciphers,ssl-cert,ssh-hostkey",
		"127.0.0.1",
		"-p",
		"443",
		"-oX",
		"-",
	}, recordedArgs(t, argsFile))

	require.Equal(t, "127.0.0.1", got.Address)
	require.Equal(t, "up", got.Status)

	require.Len(t, got.Ports, 1)
	port := got.Ports[0]
	require.Equal(t, 443, port.PortNumber)
	require.Equal(t, "open", port.State)
	require.Equal(t, "tcp", port.Protocol)
	require.Equal(t, model.NmapService{Name: "https", Tunnel: "ssl"}, port.Service)

	require.Equal(t, []model.SSLEnumCiphers{
		{
			Name: "TLSv1.3",
			Ciphers: []model.SSLCipher{
				{Name: "TLS_AKE_WITH_AES_128_GCM_SHA256", KexInfo: "ecdh_x25519"},
				{Name: "TLS_AKE_WITH_AES_256_GCM_SHA384", KexInfo: "ecdh_x25519"},
			},
		},
	}, port.Ciphers)

	require.Len(t, port.TLSCerts, 1)
	hit := port.TLSCerts[0]
	require.NotNil(t, hit.Cert)
	require.Equal(t, "127.0.0.1:443", hit.Location)
	require.Equal(t, "NMAP", hit.Source)

	require.Len(t, port.SSHHostKeys, 2)
	hk1 := port.SSHHostKeys[0]
	require.Equal(t, "ecdsa-sha2-nistp256", hk1.Type)
	require.Equal(t, "256", hk1.Bits)
	require.Equal(t, "17f9a4c3fbdcd558cce4c3a5147b4c38", hk1.Fingerprint)
	require.NotEmpty(t, hk1.Key)
	hk2 := port.SSHHostKeys[1]
	require.Equal(t, "ssh-ed25519", hk2.Type)
	require.Equal(t, "256", hk2.Bits)
	require.Equal(t, "e5c4e0ed917912ed385aef8514ac2781", hk2.Fingerprint)
	require.NotEmpty(t, hk2.Key)

	require.Empty(t, port.Scripts)
}

func TestScan_IPv6AddsDash6AndDefaultPorts(t *testing.T) {
	t.Parallel()
	bin, argsFile := fakeNmap(t, "testdata/nmaprun_tls.xml", "", 0)

	_, err := scanFake(t, New().WithNmapBinary(bin),
		netip.MustParseAddr("::1"))
	require.NoError(t, err)

	// The exact argv is an intentional parity lock on the nmap command line
	// the wrapper produces. A deliberate flag change in Scan() must update
	// this expectation.
	require.Equal(t, []string{
		"-T4",
		"-sV",
		"--script=ssl-enum-ciphers,ssl-cert,ssh-hostkey",
		"::1",
		"-6",
		"-p",
		"1-65535",
		"-oX",
		"-",
	}, recordedArgs(t, argsFile))
}

func TestScan_NoHostsReturnsZeroModel(t *testing.T) {
	t.Parallel()
	bin, _ := fakeNmap(t, "testdata/nmaprun_empty.xml", "", 0)

	got, err := scanFake(t, New().WithNmapBinary(bin).WithPorts("443"),
		netip.MustParseAddr("127.0.0.1"))
	require.NoError(t, err)
	require.Equal(t, model.Nmap{}, got)
}

func TestScan_WarningsLoggedOnlyForNonEmptyRuns(t *testing.T) {
	// Not parallel: swaps the process-wide default slog logger. Parallel
	// siblings are paused for the whole sequential pass, so nothing else
	// writes to the captured logger while this test runs.
	prev := slog.Default()
	t.Cleanup(func() { slog.SetDefault(prev) })
	var buf bytes.Buffer
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, nil)))

	// A run with >= 1 host must log the nmap stderr warning.
	bin, _ := fakeNmap(t, "testdata/nmaprun_tls.xml", "Warning: fake warning", 0)
	got, err := scanFake(t, New().WithNmapBinary(bin).WithPorts("443"),
		netip.MustParseAddr("127.0.0.1"))
	require.NoError(t, err)
	require.Len(t, got.Ports, 1)
	require.Contains(t, buf.String(), "fake warning")

	// Quirk lock: an empty run returns the zero-value model before the
	// warnings loop is reached, so the very same stderr warning must NOT
	// be logged.
	buf.Reset()
	bin, _ = fakeNmap(t, "testdata/nmaprun_empty.xml", "Warning: fake warning", 0)
	got, err = scanFake(t, New().WithNmapBinary(bin).WithPorts("443"),
		netip.MustParseAddr("127.0.0.1"))
	require.NoError(t, err)
	require.Equal(t, model.Nmap{}, got)
	require.NotContains(t, buf.String(), "fake warning")
}

func TestScan_BinaryExitErrorWrapped(t *testing.T) {
	t.Parallel()
	garbage := filepath.Join(t.TempDir(), "garbage.txt")
	require.NoError(t, os.WriteFile(garbage, []byte("this is not nmap XML output\n"), 0o644))
	bin, _ := fakeNmap(t, garbage, "", 1)

	got, err := scanFake(t, New().WithNmapBinary(bin).WithPorts("443"),
		netip.MustParseAddr("127.0.0.1"))
	require.Error(t, err)
	require.Contains(t, err.Error(), "nmap scan services:")
	require.Equal(t, model.Nmap{}, got)
}

func TestScan_NmapMissingFromPath(t *testing.T) {
	// Not parallel: t.Setenv manipulates process-wide state.
	t.Setenv("PATH", t.TempDir())

	got, err := New().Scan(t.Context(), netip.MustParseAddr("127.0.0.1"))
	require.Error(t, err)
	require.Contains(t, err.Error(), "creating nmap scanner")
	require.Equal(t, model.Nmap{}, got)
}

func TestScannerBuilders(t *testing.T) {
	t.Parallel()

	base := New()

	// WithNmapBinary returns a modified copy; the receiver stays untouched.
	withBin := base.WithNmapBinary("/opt/nmap/bin/nmap")
	require.Empty(t, base.nmap)
	require.Equal(t, "/opt/nmap/bin/nmap", withBin.nmap)

	// WithRawPath returns a modified copy; the receiver stays untouched.
	withRaw := base.WithRawPath("/tmp/raw.xml")
	require.Empty(t, base.rawPath)
	require.Equal(t, "/tmp/raw.xml", withRaw.rawPath)

	// WithPorts accumulates ports without mutating the receiver, including
	// its backing array: deriving two scanners from the same parent must not
	// let one derivation leak into the other.
	s1 := base.WithPorts("443")
	require.Nil(t, base.ports)
	require.Equal(t, []string{"443"}, s1.ports)

	s2 := s1.WithPorts("8443")
	s3 := s1.WithPorts("9443")
	require.Equal(t, []string{"443"}, s1.ports)
	require.Equal(t, []string{"443", "8443"}, s2.ports)
	require.Equal(t, []string{"443", "9443"}, s3.ports)
}

func TestParseScripts_UnknownScriptGoesToScripts(t *testing.T) {
	t.Parallel()

	var out model.NmapPort
	parseScripts(t.Context(), []nmapv4.Script{
		{ID: "http-title", Output: "Some title"},
	}, &out)

	require.Equal(t, []model.NmapScript{
		{ID: "http-title", Value: "Some title"},
	}, out.Scripts)
	require.Empty(t, out.Ciphers)
	require.Empty(t, out.TLSCerts)
	require.Empty(t, out.SSHHostKeys)
}

func TestCipherSuites_IgnoresNonCipherTables(t *testing.T) {
	t.Parallel()

	got := cipherSuites(t.Context(), []nmapv4.Table{
		{Key: "compressors"},
		{
			Key: "ciphers",
			Tables: []nmapv4.Table{
				{
					Elements: []nmapv4.Element{
						{Key: "name", Value: "X"},
						{Key: "kex_info", Value: "Y"},
					},
				},
			},
		},
	})

	require.Equal(t, []model.SSLCipher{{Name: "X", KexInfo: "Y"}}, got)
}

func TestSSLCerts_SkipsUnparseablePEM(t *testing.T) {
	t.Parallel()

	got := sslCerts(t.Context(), nmapv4.Script{
		ID: "ssl-cert",
		Elements: []nmapv4.Element{
			{Key: "pem", Value: "no pem here"},
		},
	})

	require.Empty(t, got)
}
