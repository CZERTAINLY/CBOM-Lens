package nmap

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"embed"
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
	// http server over ipv4
	http4 netip.AddrPort
	// http server over ipv6
	http6 netip.AddrPort
	// http server over ipv4
	ssh4 netip.AddrPort

	//go:embed testdata/*
	testdata embed.FS
)

func Testdata() embed.FS {
	return testdata
}

func TestMain(m *testing.M) {
	// Helper-process idiom: when re-executed with NMAP_FAKE_MODE=1 the test
	// binary acts as a fake nmap instead of running the test suite (see
	// runFakeNmap in scan_test.go).
	if os.Getenv("NMAP_FAKE_MODE") == "1" {
		os.Exit(runFakeNmap())
	}

	cert, err := generateSelfSignedCert()
	if err != nil {
		log.Fatalf("generate self-signed certificate: %v", err)
	}

	// Listener on IPv4
	ln4, err := tls.Listen("tcp4", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}})
	if err != nil {
		log.Fatalf("listen ipv4: %v", err)
	}
	defer func() {
		_ = ln4.Close()
	}()

	// Listener on IPv6
	ln6, err := tls.Listen("tcp6", "[::1]:0", &tls.Config{Certificates: []tls.Certificate{cert}})
	if err != nil {
		log.Fatalf("listen ipv6: %v", err)
	}
	defer func() {
		_ = ln6.Close()
	}()

	lnssh4, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		log.Fatalf("listen ssh ipv4: %v", err)
	}
	defer func() {
		_ = lnssh4.Close()
	}()

	srv4 := tlsServer(ln4, cert, "ipv4: ok")
	defer srv4.Close()

	srv6 := tlsServer(ln6, cert, "ipv6: ok")
	defer srv6.Close()

	srvSSH4 := sshServer(lnssh4, "ssh: ok")
	defer srvSSH4.Close()

	// store ipv4 and ipv6 addresses of the test servers
	http4 = netip.MustParseAddrPort(srv4.Listener.Addr().String())
	http6 = netip.MustParseAddrPort(srv6.Listener.Addr().String())
	ssh4 = srvSSH4.AddrPort()

	ret := m.Run()
	os.Exit(ret)
}

func tlsServer(ln net.Listener, cert tls.Certificate, msg string) *httptest.Server {
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "httptest")
		_, err := w.Write([]byte(msg))
		if err != nil {
			panic(err)
		}
	}))
	server.Config.ErrorLog = log.New(io.Discard, "", 0)
	server.Listener = ln
	server.TLS = &tls.Config{Certificates: []tls.Certificate{cert}}
	server.StartTLS()
	return server
}

// generateSelfSignedCert makes a temporary self-signed TLS cert.
func generateSelfSignedCert() (tls.Certificate, error) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return tls.Certificate{}, err
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "localhost"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"localhost"},
		IPAddresses: []net.IP{
			net.ParseIP("127.0.0.1"),
			net.ParseIP("::1"),
		},
	}

	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return tls.Certificate{}, err
	}

	cert := tls.Certificate{
		Certificate: [][]byte{der},
		PrivateKey:  priv,
	}
	return cert, nil
}

func sshServer(ln net.Listener, msg string) *SSHServer {
	srv := NewUnstartedServer(func(s ssh.Session) {
		_, err := s.Write([]byte(msg))
		if err != nil {
			panic(err)
		}
	})
	srv.Listener = ln
	srv.Start()
	return srv
}

// SSHServer is an equivalent of net/http/httptest, but for ssh servers
type SSHServer struct {
	handler   func(ssh.Session)
	server    *ssh.Server
	Listener  net.Listener
	extListen bool
	wg        sync.WaitGroup
}

func NewUnstartedServer(handler func(ssh.Session)) *SSHServer {
	return &SSHServer{handler: handler}
}

func (ts *SSHServer) Start() {
	if ts.server != nil {
		panic("already started")
	}
	if ts.Listener == nil {
		listener, err := net.Listen("tcp", ":0")
		if err != nil {
			panic("cannot listen: " + err.Error())
		}
		ts.Listener = listener
	} else {
		ts.extListen = true
	}
	ts.server = &ssh.Server{
		Addr:        ts.Listener.Addr().String(),
		Handler:     ts.handler,
		IdleTimeout: 0,
		MaxTimeout:  0,
	}
	ts.wg.Go(func() {
		err := ts.server.Serve(ts.Listener)
		if errors.Is(err, ssh.ErrServerClosed) {
			// pass
		} else if err != nil {
			panic("server error: " + err.Error())
		}
	})
}

func (ts *SSHServer) AddrPort() netip.AddrPort {
	if ts.Listener == nil {
		panic("not yet started")
	}
	n := ts.Listener.Addr()
	return netip.MustParseAddrPort(n.String())
}

func (ts *SSHServer) Close() {
	if ts.server == nil {
		panic("not yet started")
	}
	_ = ts.server.Close()
	_ = ts.Listener.Close()
	ts.wg.Wait()
}
