package zgrab

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"testing"

	"github.com/stretchr/testify/require"
)

// These tests spin up minimal TCP servers that return hand-crafted SSLv3 /
// SSLv2 responses to verify the probe parsing logic, since live SSLv3/SSLv2
// servers are essentially extinct (most disabled them in 2014–2016) and cannot
// be relied upon in automated tests.

// ─── SSLv3 ───────────────────────────────────────────────────────────────────

func TestProbeSSLv3_Detected(t *testing.T) {
	t.Parallel()
	const wantSuite = uint16(0x002F) // TLS_RSA_WITH_AES_128_CBC_SHA

	addr := serveTCP(t, func(conn net.Conn) {
		drain(conn)
		_, _ = conn.Write(fakeSSLv3ServerHello(wantSuite))
	})

	result := probeSSLv3(context.Background(), addr)

	require.True(t, result.detected)
	require.Len(t, result.ciphers, 1)
	require.Equal(t, "TLS_RSA_WITH_AES_128_CBC_SHA", result.ciphers[0].Name)
}

func TestProbeSSLv3_UnknownCipher(t *testing.T) {
	t.Parallel()

	addr := serveTCP(t, func(conn net.Conn) {
		drain(conn)
		_, _ = conn.Write(fakeSSLv3ServerHello(0xFFFF)) // not in the name map
	})

	result := probeSSLv3(context.Background(), addr)

	require.True(t, result.detected)
	require.Len(t, result.ciphers, 1)
	require.Equal(t, "0xFFFF", result.ciphers[0].Name)
}

func TestProbeSSLv3_TLSAlert_NotDetected(t *testing.T) {
	t.Parallel()
	// Simulates a server that responds to SSLv3 ClientHello with a TLS 1.2
	// handshake_failure alert — the real behaviour of modern servers such as
	// badssl.com (confirmed live: response is 15 03 00 00 02 02 28).
	addr := serveTCP(t, func(conn net.Conn) {
		drain(conn)
		// Alert record: ContentType=0x15, Version=0x0300, Length=2, Fatal+HandshakeFailure
		_, _ = conn.Write([]byte{0x15, 0x03, 0x00, 0x00, 0x02, 0x02, 0x28})
	})

	result := probeSSLv3(context.Background(), addr)

	require.False(t, result.detected, "alert response must not be reported as SSLv3 support")
}

func TestProbeSSLv3_TLS12Response_NotDetected(t *testing.T) {
	t.Parallel()
	// Server responds with TLS 1.2 (version 0x0303) — not SSLv3.
	addr := serveTCP(t, func(conn net.Conn) {
		drain(conn)
		hello := fakeSSLv3ServerHello(0x002F)
		hello[2] = 0x03 // override minor version: 0x0303 = TLS 1.2
		_, _ = conn.Write(hello)
	})

	result := probeSSLv3(context.Background(), addr)

	require.False(t, result.detected)
}

func TestProbeSSLv3_ImmediateClose_NotDetected(t *testing.T) {
	t.Parallel()
	addr := serveTCP(t, func(conn net.Conn) {
		drain(conn)
		// Close without sending anything — simulate a filtered port or
		// a server that drops SSLv3 connections silently.
	})

	result := probeSSLv3(context.Background(), addr)
	require.False(t, result.detected)
}

// fakeSSLv3ServerHello returns a minimal SSL 3.0 ServerHello record
// negotiating the given cipher suite.
func fakeSSLv3ServerHello(cipherSuite uint16) []byte {
	var random [32]byte

	// ServerHello body
	body := make([]byte, 0, 2+32+1+2+1)
	body = append(body, 0x03, 0x00)                                         // server_version: SSLv3
	body = append(body, random[:]...)                                        // random
	body = append(body, 0x00)                                               // session_id_length: 0
	body = append(body, byte(cipherSuite>>8), byte(cipherSuite))             // cipher_suite
	body = append(body, 0x00)                                               // compression_method: null

	// Handshake message
	hs := make([]byte, 0, 4+len(body))
	hs = append(hs, 0x02)                                                   // ServerHello type
	hs = append(hs, byte(len(body)>>16), byte(len(body)>>8), byte(len(body)))
	hs = append(hs, body...)

	// Record
	rec := make([]byte, 0, 5+len(hs))
	rec = append(rec, 0x16, 0x03, 0x00)                                     // Handshake, SSL 3.0
	rec = append(rec, byte(len(hs)>>8), byte(len(hs)))
	rec = append(rec, hs...)
	return rec
}

// ─── SSLv2 ───────────────────────────────────────────────────────────────────

func TestProbeSSLv2_Detected(t *testing.T) {
	t.Parallel()

	addr := serveTCP(t, func(conn net.Conn) {
		drain(conn)
		_, _ = conn.Write(fakeSSLv2ServerHello([][3]byte{
			{0x07, 0x00, 0xC0}, // SSL_CK_DES_192_EDE3_CBC_WITH_MD5
			{0x01, 0x00, 0x80}, // SSL_CK_RC4_128_WITH_MD5
		}))
	})

	result := probeSSLv2(context.Background(), addr)

	require.True(t, result.detected)
	require.Len(t, result.ciphers, 2)
	require.Equal(t, "SSL_CK_DES_192_EDE3_CBC_WITH_MD5", result.ciphers[0].Name)
	require.Equal(t, "SSL_CK_RC4_128_WITH_MD5", result.ciphers[1].Name)
}

func TestProbeSSLv2_UnknownCipherSpec(t *testing.T) {
	t.Parallel()

	addr := serveTCP(t, func(conn net.Conn) {
		drain(conn)
		_, _ = conn.Write(fakeSSLv2ServerHello([][3]byte{{0xAA, 0xBB, 0xCC}}))
	})

	result := probeSSLv2(context.Background(), addr)

	require.True(t, result.detected)
	require.Len(t, result.ciphers, 1)
	require.Equal(t, "0xAABBCC", result.ciphers[0].Name)
}

func TestProbeSSLv2_TLSResponse_NotDetected(t *testing.T) {
	t.Parallel()
	// Server ignores SSLv2 and sends a TLS record — high bit NOT set in first byte.
	addr := serveTCP(t, func(conn net.Conn) {
		drain(conn)
		_, _ = conn.Write([]byte{0x16, 0x03, 0x03, 0x00, 0x00}) // TLS 1.2 record header
	})

	result := probeSSLv2(context.Background(), addr)
	require.False(t, result.detected)
}

func TestProbeSSLv2_ImmediateClose_NotDetected(t *testing.T) {
	t.Parallel()
	addr := serveTCP(t, func(conn net.Conn) { drain(conn) })

	result := probeSSLv2(context.Background(), addr)
	require.False(t, result.detected)
}

// fakeSSLv2ServerHello returns a minimal SSLv2 SERVER-HELLO message containing
// the provided cipher specs (no certificate, small connection-id).
func fakeSSLv2ServerHello(cipherSpecs [][3]byte) []byte {
	certData := []byte{}
	connID := []byte{0x01, 0x02, 0x03, 0x04}

	cipherData := make([]byte, len(cipherSpecs)*3)
	for i, cs := range cipherSpecs {
		copy(cipherData[i*3:], cs[:])
	}

	// Body (everything after the 2-byte header):
	//   msg-server-hello(1) + session-id-hit(1) + cert-type(1) +
	//   server-version(2) + cert-len(2) + cipher-len(2) + conn-id-len(2) +
	//   cert-data + cipher-data + conn-id-data
	body := make([]byte, 0)
	body = append(body, 0x04)                                                   // MSG-SERVER-HELLO
	body = append(body, 0x00)                                                   // SESSION-ID-HIT: 0
	body = append(body, 0x01)                                                   // CERTIFICATE-TYPE: X.509
	body = append(body, 0x00, 0x02)                                             // SERVER-VERSION: SSLv2
	body = append(body, byte(len(certData)>>8), byte(len(certData)))            // CERTIFICATE-LENGTH
	body = append(body, byte(len(cipherData)>>8), byte(len(cipherData)))        // CIPHER-SPECS-LENGTH
	body = append(body, byte(len(connID)>>8), byte(len(connID)))                // CONNECTION-ID-LENGTH
	body = append(body, certData...)
	body = append(body, cipherData...)
	body = append(body, connID...)

	n := len(body)
	hdr := []byte{byte(0x80 | (n >> 8)), byte(n & 0xFF)}
	return append(hdr, body...)
}

// ─── ClientHello structure tests ─────────────────────────────────────────────

func TestBuildSSLv3ClientHello_Structure(t *testing.T) {
	t.Parallel()
	rec := buildSSLv3ClientHello()

	// Record header
	require.Equal(t, byte(0x16), rec[0], "ContentType must be Handshake")
	require.Equal(t, byte(0x03), rec[1], "major version must be 3")
	require.Equal(t, byte(0x00), rec[2], "minor version must be 0 (SSL 3.0)")

	recBodyLen := int(binary.BigEndian.Uint16(rec[3:5]))
	require.Equal(t, len(rec)-5, recBodyLen, "record length field must match actual body")

	// Handshake header inside the record
	require.Equal(t, byte(0x01), rec[5], "HandshakeType must be ClientHello (1)")

	// ClientHello version inside the handshake body
	require.Equal(t, byte(0x03), rec[9], "ClientHello version major must be 3")
	require.Equal(t, byte(0x00), rec[10], "ClientHello version minor must be 0")
}

func TestBuildSSLv2ClientHello_Structure(t *testing.T) {
	t.Parallel()
	msg := buildSSLv2ClientHello()

	// 2-byte header: high bit must be set
	require.NotZero(t, msg[0]&0x80, "high bit of first byte must be set for 2-byte header")

	msgLen := int(msg[0]&0x7F)<<8 | int(msg[1])
	require.Equal(t, len(msg)-2, msgLen, "header length must match body length")

	// MSG-CLIENT-HELLO
	require.Equal(t, byte(0x01), msg[2], "message type must be CLIENT-HELLO (0x01)")

	// CLIENT-HELLO version
	require.Equal(t, byte(0x00), msg[3], "version major must be 0")
	require.Equal(t, byte(0x02), msg[4], "version minor must be 2 (SSLv2)")
}

// ─── helpers ─────────────────────────────────────────────────────────────────

// serveTCP starts a one-shot TCP server, calls handler in a goroutine, and
// returns the address.  The server is automatically closed when the test ends.
func serveTCP(t *testing.T, handler func(net.Conn)) string {
	t.Helper()
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		handler(conn)
	}()
	return ln.Addr().String()
}

// drain reads and discards all pending data from conn without blocking.
func drain(conn net.Conn) {
	buf := make([]byte, 1024)
	_, _ = io.ReadAtLeast(conn, buf, 1)
}
