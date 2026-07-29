package zgrab

import (
	"context"
	"crypto/x509"
	"fmt"
	"log/slog"
	"net"
	"time"

	ztls "github.com/zmap/zcrypto/tls"

	"github.com/CZERTAINLY/CBOM-lens/internal/model"
)

const tlsProbeTimeout = 5 * time.Second

type tlsProbeResult struct {
	detected bool
	ciphers  []model.SSLEnumCiphers
	certs    []model.CertHit
}

// probeTLS attempts a TLS connection on addr. On success it enumerates
// supported cipher suites per TLS version and extracts the leaf certificate.
// serverName is passed as SNI; empty string disables SNI.
func probeTLS(ctx context.Context, addr string, serverName string) tlsProbeResult {
	conn, err := dialZTLS(ctx, addr, 0, nil, serverName)
	if err != nil {
		return tlsProbeResult{}
	}
	certs := extractCerts(conn, addr)
	_ = conn.Close()

	var groups []model.SSLEnumCiphers

	if tls10 := enumTLS10Ciphers(ctx, addr, serverName); len(tls10) > 0 {
		groups = append(groups, model.SSLEnumCiphers{Name: "TLSv1.0", Ciphers: tls10})
	}
	if tls11 := enumTLS11Ciphers(ctx, addr, serverName); len(tls11) > 0 {
		groups = append(groups, model.SSLEnumCiphers{Name: "TLSv1.1", Ciphers: tls11})
	}
	if tls12 := enumTLS12Ciphers(ctx, addr, serverName); len(tls12) > 0 {
		groups = append(groups, model.SSLEnumCiphers{Name: "TLSv1.2", Ciphers: tls12})
	}
	if tls13 := enumTLS13Ciphers(ctx, addr, serverName); len(tls13) > 0 {
		groups = append(groups, model.SSLEnumCiphers{Name: "TLSv1.3", Ciphers: tls13})
	}

	if len(groups) == 0 {
		slog.WarnContext(ctx, "zgrab: TLS detected but cipher enumeration returned no results",
			slog.String("addr", addr),
		)
	}

	return tlsProbeResult{
		detected: true,
		ciphers:  groups,
		certs:    certs,
	}
}

// enumTLS12Ciphers enumerates supported TLS 1.2 cipher suites by repeated
// handshakes, each time removing the last negotiated suite.
func enumTLS12Ciphers(ctx context.Context, addr string, serverName string) []model.SSLCipher {
	remaining := knownTLS12Suites()
	var found []model.SSLCipher

	for len(remaining) > 0 {
		if ctx.Err() != nil {
			break
		}
		conn, err := dialZTLS(ctx, addr, ztls.VersionTLS12, remaining, serverName)
		if err != nil {
			if len(found) > 0 {
				slog.WarnContext(ctx, "zgrab: TLS 1.2 cipher enumeration interrupted",
					slog.String("addr", addr),
					slog.Int("found_so_far", len(found)),
					slog.Int("remaining", len(remaining)),
					slog.String("error", err.Error()),
				)
			}
			break
		}
		log := conn.GetHandshakeLog()
		_ = conn.Close()

		if log == nil || log.ServerHello == nil {
			break
		}

		suite := log.ServerHello.CipherSuite
		found = append(found, model.SSLCipher{Name: suite.String()})

		// Remove the negotiated suite to try the next one.
		next := remaining[:0]
		for _, s := range remaining {
			if s != uint16(suite) {
				next = append(next, s)
			}
		}
		if len(next) == len(remaining) {
			break // nothing removed, avoid infinite loop
		}
		remaining = next
	}

	return found
}

// enumTLS10Ciphers enumerates supported TLS 1.0 cipher suites by repeated
// handshakes, each time removing the last negotiated suite.
func enumTLS10Ciphers(ctx context.Context, addr string, serverName string) []model.SSLCipher {
	remaining := knownTLS10And11Suites()
	var found []model.SSLCipher

	for len(remaining) > 0 {
		if ctx.Err() != nil {
			break
		}
		conn, err := dialZTLS(ctx, addr, ztls.VersionTLS10, remaining, serverName)
		if err != nil {
			if len(found) > 0 {
				slog.WarnContext(ctx, "zgrab: TLS 1.0 cipher enumeration interrupted",
					slog.String("addr", addr),
					slog.Int("found_so_far", len(found)),
					slog.Int("remaining", len(remaining)),
					slog.String("error", err.Error()),
				)
			}
			break
		}
		log := conn.GetHandshakeLog()
		_ = conn.Close()

		if log == nil || log.ServerHello == nil {
			break
		}

		suite := log.ServerHello.CipherSuite
		found = append(found, model.SSLCipher{Name: suite.String()})

		next := remaining[:0]
		for _, s := range remaining {
			if s != uint16(suite) {
				next = append(next, s)
			}
		}
		if len(next) == len(remaining) {
			break
		}
		remaining = next
	}

	return found
}

// enumTLS11Ciphers enumerates supported TLS 1.1 cipher suites by repeated
// handshakes, each time removing the last negotiated suite.
func enumTLS11Ciphers(ctx context.Context, addr string, serverName string) []model.SSLCipher {
	remaining := knownTLS10And11Suites()
	var found []model.SSLCipher

	for len(remaining) > 0 {
		if ctx.Err() != nil {
			break
		}
		conn, err := dialZTLS(ctx, addr, ztls.VersionTLS11, remaining, serverName)
		if err != nil {
			if len(found) > 0 {
				slog.WarnContext(ctx, "zgrab: TLS 1.1 cipher enumeration interrupted",
					slog.String("addr", addr),
					slog.Int("found_so_far", len(found)),
					slog.Int("remaining", len(remaining)),
					slog.String("error", err.Error()),
				)
			}
			break
		}
		log := conn.GetHandshakeLog()
		_ = conn.Close()

		if log == nil || log.ServerHello == nil {
			break
		}

		suite := log.ServerHello.CipherSuite
		found = append(found, model.SSLCipher{Name: suite.String()})

		next := remaining[:0]
		for _, s := range remaining {
			if s != uint16(suite) {
				next = append(next, s)
			}
		}
		if len(next) == len(remaining) {
			break
		}
		remaining = next
	}

	return found
}

// enumTLS13Ciphers does a single TLS 1.3 handshake and returns the negotiated
// cipher. TLS 1.3 cipher suites are fixed by the protocol and not enumerable
// by exclusion like TLS 1.2; only the suite negotiated in one handshake is
// returned.
func enumTLS13Ciphers(ctx context.Context, addr, serverName string) []model.SSLCipher {
	conn, err := dialZTLS(ctx, addr, ztls.VersionTLS13, nil, serverName)
	if err != nil {
		return nil
	}
	log := conn.GetHandshakeLog()
	_ = conn.Close()

	if log == nil || log.ServerHello == nil {
		return nil
	}

	suite := log.ServerHello.CipherSuite
	name := suite.String()
	if name == "" {
		return nil
	}
	return []model.SSLCipher{{Name: name}}
}

// extractCerts reads the leaf certificate from the zcrypto handshake log and
// converts it to a stdlib *x509.Certificate via its raw DER bytes.
func extractCerts(conn *ztls.Conn, addr string) []model.CertHit {
	log := conn.GetHandshakeLog()
	if log == nil || log.ServerCertificates == nil {
		return nil
	}

	raw := log.ServerCertificates.Certificate.Raw
	if len(raw) == 0 {
		return nil
	}

	cert, err := x509.ParseCertificate(raw)
	if err != nil {
		slog.Warn("zgrab: failed to parse leaf certificate",
			slog.String("addr", addr),
			slog.String("error", err.Error()),
		)
		return nil
	}

	return []model.CertHit{{Cert: cert, Source: "ZGRAB"}}
}

// dialZTLS opens a raw TCP connection and upgrades it to TLS using zcrypto.
// version=0 means no version constraint (server picks). suites=nil means all
// suites are offered. serverName sets TLS SNI; empty string disables it.
func dialZTLS(ctx context.Context, addr string, version uint16, suites []uint16, serverName string) (*ztls.Conn, error) {
	d := net.Dialer{Timeout: tlsProbeTimeout}
	raw, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	if err := raw.SetDeadline(time.Now().Add(tlsProbeTimeout)); err != nil {
		_ = raw.Close()
		return nil, fmt.Errorf("set deadline: %w", err)
	}

	cfg := &ztls.Config{
		InsecureSkipVerify: true,
		ServerName:         serverName,
	}
	if version != 0 {
		cfg.MinVersion = version
		cfg.MaxVersion = version
	}
	if len(suites) > 0 {
		cfg.CipherSuites = suites
	}

	tlsConn := ztls.Client(raw, cfg)
	if err := tlsConn.Handshake(); err != nil {
		_ = raw.Close()
		return nil, err
	}
	return tlsConn, nil
}

// knownTLS12Suites returns the cipher suites offered during TLS 1.2
// enumeration, from strongest to weakest.
func knownTLS12Suites() []uint16 {
	return []uint16{
		ztls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		ztls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		ztls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
		ztls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
		ztls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		ztls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		ztls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
		ztls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
		ztls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
		ztls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
		ztls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
		ztls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
		ztls.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA,
		ztls.TLS_RSA_WITH_AES_256_GCM_SHA384,
		ztls.TLS_RSA_WITH_AES_128_GCM_SHA256,
		ztls.TLS_RSA_WITH_AES_256_CBC_SHA,
		ztls.TLS_RSA_WITH_AES_128_CBC_SHA256,
		ztls.TLS_RSA_WITH_AES_128_CBC_SHA,
		ztls.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
		ztls.TLS_ECDHE_ECDSA_WITH_RC4_128_SHA,
		ztls.TLS_ECDHE_RSA_WITH_RC4_128_SHA,
		ztls.TLS_RSA_WITH_RC4_128_SHA,
		ztls.TLS_RSA_WITH_RC4_128_MD5,
	}
}

// knownTLS10And11Suites returns cipher suites offered during TLS 1.0 and
// TLS 1.1 enumeration.  Only suites tagged supportedUpToTLS12 in zcrypto's
// cipher_suites.go are included — GCM, CHACHA20, and *_CBC_SHA256/SHA384
// variants require TLS 1.2 and are absent.
func knownTLS10And11Suites() []uint16 {
	return []uint16{
		ztls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
		ztls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
		ztls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
		ztls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
		ztls.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA,
		ztls.TLS_RSA_WITH_AES_256_CBC_SHA,
		ztls.TLS_RSA_WITH_AES_128_CBC_SHA,
		ztls.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
		ztls.TLS_ECDHE_ECDSA_WITH_RC4_128_SHA,
		ztls.TLS_ECDHE_RSA_WITH_RC4_128_SHA,
		ztls.TLS_RSA_WITH_RC4_128_SHA,
	}
}
