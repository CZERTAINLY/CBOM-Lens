package zgrab

import (
	"context"
	"io"
	"net"
	"testing"
)

// mockSSLv3Server spins up a one-shot TCP listener that replies with a valid
// SSLv3 ServerHello.  It is used to benchmark probeSSLv3 without real network
// latency so we measure pure Go parsing overhead.
func mockSSLv3Server(b *testing.B) string {
	b.Helper()
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 512)
				_, _ = io.ReadAtLeast(c, buf, 1)
				_, _ = c.Write(fakeSSLv3ServerHello(0x002F))
			}(conn)
		}
	}()
	return ln.Addr().String()
}

// mockSSLv2Server is the SSLv2 equivalent.
func mockSSLv2Server(b *testing.B) string {
	b.Helper()
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 512)
				_, _ = io.ReadAtLeast(c, buf, 1)
				_, _ = c.Write(fakeSSLv2ServerHello([][3]byte{
					{0x07, 0x00, 0xC0},
					{0x01, 0x00, 0x80},
				}))
			}(conn)
		}
	}()
	return ln.Addr().String()
}

func BenchmarkProbeSSLv3_LocalMock(b *testing.B) {
	addr := mockSSLv3Server(b)
	ctx := context.Background()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		probeSSLv3(ctx, addr)
	}
}

func BenchmarkProbeSSLv2_LocalMock(b *testing.B) {
	addr := mockSSLv2Server(b)
	ctx := context.Background()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		probeSSLv2(ctx, addr)
	}
}
