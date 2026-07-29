package zgrab

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/gliderlabs/ssh"
)

var (
	// TLS servers
	tlsAddr4 netip.AddrPort
	tlsAddr6 netip.AddrPort
	// SSH server
	sshAddr4 netip.AddrPort
	// Raw TCP server (accepts and immediately closes — neither TLS nor SSH)
	rawAddr4 netip.AddrPort
)

func TestMain(m *testing.M) {
	os.Exit(run(m))
}

func run(m *testing.M) int {
	cert, err := generateSelfSignedCert()
	if err != nil {
		log.Fatalf("generate self-signed cert: %v", err)
	}

	ln4, err := tls.Listen("tcp4", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}})
	if err != nil {
		log.Fatalf("listen tls ipv4: %v", err)
	}
	defer func() { _ = ln4.Close() }()

	ln6, err := tls.Listen("tcp6", "[::1]:0", &tls.Config{Certificates: []tls.Certificate{cert}})
	if err != nil {
		log.Fatalf("listen tls ipv6: %v", err)
	}
	defer func() { _ = ln6.Close() }()

	lnSSH, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		log.Fatalf("listen ssh ipv4: %v", err)
	}
	defer func() { _ = lnSSH.Close() }()

	lnRaw, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		log.Fatalf("listen raw tcp: %v", err)
	}
	defer func() { _ = lnRaw.Close() }()

	srv4 := startTLSServer(ln4, cert)
	defer srv4.Close()

	srv6 := startTLSServer(ln6, cert)
	defer srv6.Close()

	srvSSH := startSSHServer(lnSSH)
	defer srvSSH.close()

	srvRaw := startRawTCPServer(lnRaw)
	defer srvRaw.close()

	tlsAddr4 = netip.MustParseAddrPort(srv4.Listener.Addr().String())
	tlsAddr6 = netip.MustParseAddrPort(srv6.Listener.Addr().String())
	sshAddr4 = srvSSH.addrPort()
	rawAddr4 = srvRaw.addrPort()

	return m.Run()
}

func startTLSServer(ln net.Listener, cert tls.Certificate) *httptest.Server {
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "ok")
	}))
	srv.Config.ErrorLog = log.New(io.Discard, "", 0)
	srv.Listener = ln
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{cert}}
	srv.StartTLS()
	return srv
}

func generateSelfSignedCert() (tls.Certificate, error) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return tls.Certificate{}, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "localhost"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: priv}, nil
}

// testSSHServer is a minimal SSH server for tests.
type testSSHServer struct {
	server   *ssh.Server
	listener net.Listener
	wg       sync.WaitGroup
}

func startSSHServer(ln net.Listener) *testSSHServer {
	ts := &testSSHServer{listener: ln}
	ts.server = &ssh.Server{
		Addr: ln.Addr().String(),
		Handler: func(s ssh.Session) {
			_, _ = io.WriteString(s, "ok")
		},
	}
	ts.wg.Add(1)
	go func() {
		defer ts.wg.Done()
		err := ts.server.Serve(ln)
		if !errors.Is(err, ssh.ErrServerClosed) && err != nil {
			log.Printf("ssh server: %v", err)
		}
	}()
	return ts
}

func (ts *testSSHServer) addrPort() netip.AddrPort {
	return netip.MustParseAddrPort(ts.listener.Addr().String())
}

func (ts *testSSHServer) close() {
	_ = ts.server.Close()
	_ = ts.listener.Close()
	ts.wg.Wait()
}

// testRawServer accepts TCP connections and immediately closes them.
// It simulates a service that speaks neither TLS nor SSH.
type testRawServer struct {
	listener net.Listener
	wg       sync.WaitGroup
}

func startRawTCPServer(ln net.Listener) *testRawServer {
	ts := &testRawServer{listener: ln}
	ts.wg.Add(1)
	go func() {
		defer ts.wg.Done()
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			_ = conn.Close()
		}
	}()
	return ts
}

func (ts *testRawServer) addrPort() netip.AddrPort {
	return netip.MustParseAddrPort(ts.listener.Addr().String())
}

func (ts *testRawServer) close() {
	_ = ts.listener.Close()
	ts.wg.Wait()
}
