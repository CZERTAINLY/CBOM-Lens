package cdxprops

import (
	"encoding/asn1"
	"fmt"
	"testing"
)

// TestDerOctetStringOf pins derOctetStringOf directly, bypassing the
// PKCS#8/algorithm-registry plumbing that pqc_body_shape_test.go exercises it
// through. That indirect coverage only ever drives four fixed sizes (ML-DSA-65
// seed=32/expanded=4032, ML-KEM-768 seed=64/expanded=2400), which is exactly
// the shape of gap a prior review flagged elsewhere in this file: a
// size-specific bug can hide behind tests that all reuse the same magic
// numbers. This test instead sweeps `want` across a range of sizes --
// including the DER short-form/long-form length boundaries at 128 and 256
// bytes -- and, for the trailing-byte check, across several tail lengths, for
// both call shapes the merged helper now serves (params "" and "tag:0").
func TestDerOctetStringOf(t *testing.T) {
	t.Parallel()

	sizes := []int{1, 16, 32, 64, 127, 128, 255, 256, 2400, 4032}
	tails := []int{1, 3, 16}
	params := []string{"", "tag:0"}

	// content returns n distinct, deterministic bytes so a decode that
	// silently truncates or shifts content is visible as a length mismatch
	// rather than an accidental match against zeroed bytes.
	content := func(n int) []byte {
		b := make([]byte, n)
		for i := range b {
			b[i] = byte(i)
		}
		return b
	}

	// encode DER-encodes n bytes of content under the given params, using
	// the standard library's own encoder so long-form lengths (>=128 bytes)
	// are built correctly without hand-rolled header math.
	encode := func(t *testing.T, n int, p string) []byte {
		t.Helper()
		b, err := asn1.MarshalWithParams(content(n), p)
		if err != nil {
			t.Fatalf("asn1.MarshalWithParams(%d bytes, %q): %v", n, p, err)
		}
		return b
	}

	otherParams := func(p string) string {
		if p == "tag:0" {
			return ""
		}
		return "tag:0"
	}

	for _, p := range params {
		for _, want := range sizes {
			t.Run(fmt.Sprintf("params=%s/want=%d/exact-accept", p, want), func(t *testing.T) {
				body := encode(t, want, p)
				if !derOctetStringOf(body, want, p) {
					t.Fatalf("rejected a correctly-shaped %d-byte encoding (params %q)", want, p)
				}
			})

			for _, tail := range tails {
				t.Run(fmt.Sprintf("params=%s/want=%d/trailing-%d-bytes", p, want, tail), func(t *testing.T) {
					body := encode(t, want, p)
					junk := make([]byte, tail)
					for i := range junk {
						junk[i] = 0xFF
					}
					body = append(body, junk...)
					if derOctetStringOf(body, want, p) {
						t.Fatalf("accepted a %d-byte encoding with %d trailing byte(s) (params %q)", want, tail, p)
					}
				})
			}

			t.Run(fmt.Sprintf("params=%s/want=%d/content-one-short", p, want), func(t *testing.T) {
				if want == 0 {
					t.Skip("no shorter-than-zero content to build")
				}
				body := encode(t, want-1, p)
				if derOctetStringOf(body, want, p) {
					t.Fatalf("accepted a %d-byte encoding when want=%d (params %q)", want-1, want, p)
				}
			})

			t.Run(fmt.Sprintf("params=%s/want=%d/content-one-long", p, want), func(t *testing.T) {
				body := encode(t, want+1, p)
				if derOctetStringOf(body, want, p) {
					t.Fatalf("accepted a %d-byte encoding when want=%d (params %q)", want+1, want, p)
				}
			})

			t.Run(fmt.Sprintf("params=%s/want=%d/truncated-header", p, want), func(t *testing.T) {
				body := encode(t, want, p)
				// Chop the final content byte off: the length octets still
				// claim `want` bytes follow, but fewer are present, so this
				// must fail to parse rather than silently accept a short
				// read.
				body = body[:len(body)-1]
				if derOctetStringOf(body, want, p) {
					t.Fatalf("accepted a truncated %d-byte encoding (params %q)", want, p)
				}
			})

			t.Run(fmt.Sprintf("params=%s/want=%d/wrong-tag", p, want), func(t *testing.T) {
				wrong := otherParams(p)
				body := encode(t, want, wrong)
				if derOctetStringOf(body, want, p) {
					t.Fatalf("accepted a body encoded with params %q when checking params %q", wrong, p)
				}
			})
		}
	}

	// Non-DER noise: fixed, deterministic byte patterns that are not valid
	// encodings under either call shape, at several lengths.
	noisePatterns := map[string]func(n int) []byte{
		"all-zero": func(n int) []byte { return make([]byte, n) },
		"all-0xff": func(n int) []byte {
			b := make([]byte, n)
			for i := range b {
				b[i] = 0xFF
			}
			return b
		},
		"ascending": func(n int) []byte {
			b := make([]byte, n)
			for i := range b {
				b[i] = byte(i)
			}
			return b
		},
	}
	noiseLens := []int{0, 1, 2, 5, 10, 34, 66}

	for _, p := range params {
		for name, build := range noisePatterns {
			for _, n := range noiseLens {
				t.Run(fmt.Sprintf("params=%s/noise=%s/len=%d", p, name, n), func(t *testing.T) {
					if derOctetStringOf(build(n), 32, p) {
						t.Fatalf("accepted %d bytes of %s noise as a 32-byte body (params %q)", n, name, p)
					}
				})
			}
		}
	}
}
