package zgrab

// Raw SSLv3 and SSLv2 probes implemented without zcrypto or any other TLS
// library, because:
//
//   - zcrypto explicitly excludes SSLv3 from its supported-versions list and
//     marks it "cryptographically broken, no longer supported by this package".
//   - SSLv2 uses a completely different wire format (2-byte header, different
//     handshake structure) that no Go library — including zcrypto — implements
//     on the client side.
//
// Both probes send the minimum valid handshake over a raw net.Conn and parse
// just enough of the server response to confirm protocol support and extract
// the negotiated/offered cipher suites.

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"log/slog"
	"net"
	"time"

	"github.com/CZERTAINLY/CBOM-lens/internal/model"
)

const legacyDialTimeout = 5 * time.Second

type legacyResult struct {
	detected bool
	ciphers  []model.SSLCipher
}

// ─── SSLv3 ───────────────────────────────────────────────────────────────────

// sslv3CipherNames maps the 2-byte suite IDs most commonly found on legacy
// SSLv3 servers to their human-readable names.
var sslv3CipherNames = map[uint16]string{
	0x0004: "SSL_RSA_WITH_RC4_128_MD5",
	0x0005: "SSL_RSA_WITH_RC4_128_SHA",
	0x0009: "SSL_RSA_WITH_DES_CBC_SHA",
	0x000A: "SSL_RSA_WITH_3DES_EDE_CBC_SHA",
	0x0016: "SSL_DHE_RSA_WITH_3DES_EDE_CBC_SHA",
	0x002F: "TLS_RSA_WITH_AES_128_CBC_SHA",
	0x0035: "TLS_RSA_WITH_AES_256_CBC_SHA",
	0xC013: "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
	0xC014: "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
}

// sslv3OfferedSuites is the cipher list placed in the raw SSLv3 ClientHello.
var sslv3OfferedSuites = []uint16{
	0xC014, 0xC013,
	0x0035, 0x002F,
	0x000A, 0x0009,
	0x0005, 0x0004,
	0x0016,
}

// probeSSLv3 sends a hand-crafted SSLv3 ClientHello to addr and reports
// whether the server accepts SSLv3.  On success it returns the negotiated
// cipher suite.
//
// Detection logic: if the server's first record carries version bytes
// 0x03 0x00, it is speaking SSL 3.0.  A server that only supports TLS 1.0+
// will either refuse with an alert or reply with a higher version (≥ 0x0301),
// which is not counted as SSLv3 support.
func probeSSLv3(ctx context.Context, addr string) legacyResult {
	conn, err := dialLegacy(ctx, addr)
	if err != nil {
		return legacyResult{}
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(legacyDialTimeout))

	if _, err := conn.Write(buildSSLv3ClientHello()); err != nil {
		return legacyResult{}
	}

	// Read the 5-byte TLS/SSL3 record header:
	//   [0]    ContentType  (0x16 = Handshake)
	//   [1..2] Version      (0x03 0x00 = SSL 3.0)
	//   [3..4] Length       (big-endian)
	hdr := make([]byte, 5)
	if _, err := io.ReadFull(conn, hdr); err != nil {
		return legacyResult{}
	}
	if hdr[0] != 0x16 || hdr[1] != 0x03 || hdr[2] != 0x00 {
		// Alert (0x15), TLS version (≥ 0x0301), or garbage — not SSLv3.
		return legacyResult{}
	}

	recordLen := int(binary.BigEndian.Uint16(hdr[3:5]))
	if recordLen < 4 || recordLen > 16384 {
		return legacyResult{}
	}
	record := make([]byte, recordLen)
	if _, err := io.ReadFull(conn, record); err != nil {
		return legacyResult{}
	}

	// Handshake record layout:
	//   [0]      HandshakeType  (0x02 = ServerHello)
	//   [1..3]   24-bit length
	//   [4..5]   server_version
	//   [6..37]  random (32 bytes)
	//   [38]     session_id_length
	//   [39+n]   cipher_suite (2 bytes, where n = session_id_length)
	//   [41+n]   compression_method
	if len(record) == 0 || record[0] != 0x02 {
		return legacyResult{}
	}

	const fixedHeaderLen = 39 // up to and including session_id_length field
	if len(record) < fixedHeaderLen {
		slog.WarnContext(ctx, "zgrab: SSLv3 detected (ServerHello too short to parse cipher)",
			slog.String("addr", addr))
		return legacyResult{detected: true}
	}

	sidLen := int(record[38])
	cipherOff := fixedHeaderLen + sidLen
	if len(record) < cipherOff+2 {
		slog.WarnContext(ctx, "zgrab: SSLv3 detected (cipher field truncated)",
			slog.String("addr", addr))
		return legacyResult{detected: true}
	}

	suiteID := binary.BigEndian.Uint16(record[cipherOff : cipherOff+2])
	name, ok := sslv3CipherNames[suiteID]
	if !ok {
		name = fmt.Sprintf("0x%04X", suiteID)
	}

	slog.WarnContext(ctx, "zgrab: SSLv3 detected",
		slog.String("addr", addr),
		slog.String("cipher", name),
	)
	return legacyResult{detected: true, ciphers: []model.SSLCipher{{Name: name}}}
}

// buildSSLv3ClientHello returns a complete SSL 3.0 ClientHello record.
//
// Record structure:
//
//	Record header  (5 bytes): ContentType=0x16, Version=0x0300, Length
//	Handshake hdr  (4 bytes): Type=0x01, 24-bit body length
//	ClientHello:
//	  client_version        2 bytes  (0x03 0x00)
//	  random               32 bytes
//	  session_id_length     1 byte   (0x00)
//	  cipher_suites_length  2 bytes
//	  cipher_suites         N×2 bytes
//	  compression_methods   2 bytes  (count=1, method=null)
func buildSSLv3ClientHello() []byte {
	var random [32]byte
	_, _ = rand.Read(random[:])

	suiteBytes := make([]byte, len(sslv3OfferedSuites)*2)
	for i, s := range sslv3OfferedSuites {
		binary.BigEndian.PutUint16(suiteBytes[i*2:], s)
	}

	hello := make([]byte, 0, 2+32+1+2+len(suiteBytes)+2)
	hello = append(hello, 0x03, 0x00)                                          // client_version
	hello = append(hello, random[:]...)                                         // random
	hello = append(hello, 0x00)                                                // session_id_length
	hello = append(hello, byte(len(suiteBytes)>>8), byte(len(suiteBytes)))     // cipher_suites_length
	hello = append(hello, suiteBytes...)                                        // cipher_suites
	hello = append(hello, 0x01, 0x00)                                          // compression_methods

	hs := make([]byte, 0, 4+len(hello))
	hs = append(hs, 0x01)                                                      // HandshakeType: ClientHello
	hs = append(hs, byte(len(hello)>>16), byte(len(hello)>>8), byte(len(hello))) // 24-bit length
	hs = append(hs, hello...)

	rec := make([]byte, 0, 5+len(hs))
	rec = append(rec, 0x16)                                                    // ContentType: Handshake
	rec = append(rec, 0x03, 0x00)                                              // Version: SSL 3.0
	rec = append(rec, byte(len(hs)>>8), byte(len(hs)))                         // Length
	rec = append(rec, hs...)
	return rec
}

// ─── SSLv2 ───────────────────────────────────────────────────────────────────

// sslv2CipherSpecs lists all known SSLv2 3-byte cipher specs with names.
// The server returns the subset it supports in its SERVER-HELLO, so a single
// exchange reveals the complete list — no repeated handshakes needed.
var sslv2CipherSpecs = []struct {
	b    [3]byte
	name string
}{
	{[3]byte{0x07, 0x00, 0xC0}, "SSL_CK_DES_192_EDE3_CBC_WITH_MD5"},
	{[3]byte{0x05, 0x00, 0x80}, "SSL_CK_IDEA_128_CBC_WITH_MD5"},
	{[3]byte{0x03, 0x00, 0x80}, "SSL_CK_RC2_128_CBC_WITH_MD5"},
	{[3]byte{0x01, 0x00, 0x80}, "SSL_CK_RC4_128_WITH_MD5"},
	{[3]byte{0x06, 0x00, 0x40}, "SSL_CK_DES_64_CBC_WITH_MD5"},
	{[3]byte{0x04, 0x00, 0x80}, "SSL_CK_RC2_128_CBC_EXPORT40_WITH_MD5"},
	{[3]byte{0x02, 0x00, 0x80}, "SSL_CK_RC4_128_EXPORT40_WITH_MD5"},
}

// probeSSLv2 sends a raw SSLv2 CLIENT-HELLO to addr.  Because SSLv2 sends
// ALL supported cipher specs in its SERVER-HELLO (unlike TLS, which negotiates
// one), a single exchange is sufficient to enumerate the full cipher list.
//
// Detection: SSLv2 records start with a 2-byte length header where the MSB of
// the first byte is set (0x80 | high-nibble).  zcrypto itself uses this same
// heuristic to detect and reject incoming SSLv2 clients.
func probeSSLv2(ctx context.Context, addr string) legacyResult {
	conn, err := dialLegacy(ctx, addr)
	if err != nil {
		return legacyResult{}
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(legacyDialTimeout))

	if _, err := conn.Write(buildSSLv2ClientHello()); err != nil {
		return legacyResult{}
	}

	// SSLv2 2-byte header: [0x80|(len>>8), len&0xFF]
	hdr := make([]byte, 2)
	if _, err := io.ReadFull(conn, hdr); err != nil {
		return legacyResult{}
	}
	if hdr[0]&0x80 == 0 {
		// Not a 2-byte SSLv2 header — TLS response or unrecognised protocol.
		return legacyResult{}
	}

	msgLen := int(hdr[0]&0x7F)<<8 | int(hdr[1])
	if msgLen < 11 || msgLen > 65536 {
		return legacyResult{}
	}

	body := make([]byte, msgLen)
	if _, err := io.ReadFull(conn, body); err != nil {
		return legacyResult{}
	}

	// SSLv2 SERVER-HELLO body layout:
	//   [0]      MSG-SERVER-HELLO  = 0x04
	//   [1]      SESSION-ID-HIT
	//   [2]      CERTIFICATE-TYPE  (0x01 = X.509v3)
	//   [3..4]   SERVER-VERSION
	//   [5..6]   CERTIFICATE-LENGTH
	//   [7..8]   CIPHER-SPECS-LENGTH
	//   [9..10]  CONNECTION-ID-LENGTH
	//   [11..]   certificate_data  ||  cipher_specs_data  ||  connection_id_data
	if body[0] != 0x04 {
		return legacyResult{} // not a SERVER-HELLO
	}
	if len(body) < 11 {
		slog.WarnContext(ctx, "zgrab: SSLv2 detected (response too short to parse ciphers)",
			slog.String("addr", addr))
		return legacyResult{detected: true}
	}

	certLen := int(binary.BigEndian.Uint16(body[5:7]))
	cipherLen := int(binary.BigEndian.Uint16(body[7:9]))

	const dataOffset = 11
	if len(body) < dataOffset+certLen+cipherLen {
		slog.WarnContext(ctx, "zgrab: SSLv2 detected (cipher data truncated)",
			slog.String("addr", addr))
		return legacyResult{detected: true}
	}

	cipherData := body[dataOffset+certLen : dataOffset+certLen+cipherLen]
	var ciphers []model.SSLCipher
	for i := 0; i+3 <= len(cipherData); i += 3 {
		spec := [3]byte{cipherData[i], cipherData[i+1], cipherData[i+2]}
		ciphers = append(ciphers, model.SSLCipher{Name: sslv2SpecName(spec)})
	}

	slog.WarnContext(ctx, "zgrab: SSLv2 detected",
		slog.String("addr", addr),
		slog.Int("cipher_count", len(ciphers)),
	)
	return legacyResult{detected: true, ciphers: ciphers}
}

// buildSSLv2ClientHello returns a complete SSLv2 CLIENT-HELLO message.
//
// Message structure (2-byte header + body):
//
//	Header:  [0x80|(len>>8), len&0xFF]
//	Body:
//	  MSG-CLIENT-HELLO      1 byte  (0x01)
//	  CLIENT-HELLO-V2       2 bytes (0x00 0x02)
//	  CIPHER-SPECS-LENGTH   2 bytes
//	  SESSION-ID-LENGTH     2 bytes (0x00 0x00)
//	  CHALLENGE-LENGTH      2 bytes (0x00 0x10 = 16)
//	  cipher_specs          N×3 bytes
//	  challenge            16 bytes (random)
func buildSSLv2ClientHello() []byte {
	var challenge [16]byte
	_, _ = rand.Read(challenge[:])

	cipherData := make([]byte, len(sslv2CipherSpecs)*3)
	for i, cs := range sslv2CipherSpecs {
		copy(cipherData[i*3:], cs.b[:])
	}

	body := make([]byte, 0, 9+len(cipherData)+16)
	body = append(body, 0x01)                                                  // MSG-CLIENT-HELLO
	body = append(body, 0x00, 0x02)                                            // CLIENT-HELLO version 2
	body = append(body, byte(len(cipherData)>>8), byte(len(cipherData)))       // CIPHER-SPECS-LENGTH
	body = append(body, 0x00, 0x00)                                            // SESSION-ID-LENGTH: 0
	body = append(body, 0x00, 0x10)                                            // CHALLENGE-LENGTH: 16
	body = append(body, cipherData...)
	body = append(body, challenge[:]...)

	n := len(body)
	return append([]byte{byte(0x80 | (n >> 8)), byte(n & 0xFF)}, body...)
}

func sslv2SpecName(spec [3]byte) string {
	for _, cs := range sslv2CipherSpecs {
		if cs.b == spec {
			return cs.name
		}
	}
	return fmt.Sprintf("0x%02X%02X%02X", spec[0], spec[1], spec[2])
}

// ─── shared ──────────────────────────────────────────────────────────────────

func dialLegacy(ctx context.Context, addr string) (net.Conn, error) {
	d := net.Dialer{Timeout: legacyDialTimeout}
	return d.DialContext(ctx, "tcp", addr)
}
