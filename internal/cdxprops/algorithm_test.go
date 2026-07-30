package cdxprops

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"slices"
	"testing"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/stretchr/testify/require"
)

// TestExtractAlgorithmInfo_ECDSA covers the ECDSA branch of the
// extractAlgorithmInfo switch ladder, which no registry-driven table test can
// reach (the curves are hardcoded cases, not map entries).
//
// Every expectation below is transcribed from RFC 5480, not from
// algorithm.go. RFC 5480 section 2.1.1.1 assigns the named-curve OIDs and
// section 4 ("Security Considerations") tabulates the minimum bits of
// security per curve.
func TestExtractAlgorithmInfo_ECDSA(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		curve         elliptic.Curve
		wantName      string
		wantOID       string
		wantClassical int
		wantKeySize   int
	}{
		{
			// RFC 5480 2.1.1.1: secp224r1 ::= { iso(1)
			//   identified-organization(3) certicom(132) curve(0) 33 }
			// RFC 5480 section 4: secp224r1 is listed at 112 bits of security.
			// NOTE: 1.2.840.10045.3.1.1 is secp192r1, and 80 bits is
			// secp192r1's row. Do not restore either value here.
			curve:         elliptic.P224(),
			wantName:      "ECDSA-P-224",
			wantOID:       "1.3.132.0.33",
			wantClassical: 112,
			wantKeySize:   224,
		},
		{
			// RFC 5480 2.1.1.1: secp256r1 ::= { iso(1) member-body(2)
			//   us(840) ansi-X9-62(10045) curves(3) prime(1) 7 }
			// RFC 5480 section 4: 128 bits.
			curve:         elliptic.P256(),
			wantName:      "ECDSA-P-256",
			wantOID:       "1.2.840.10045.3.1.7",
			wantClassical: 128,
			wantKeySize:   256,
		},
		{
			// RFC 5480 2.1.1.1: secp384r1 ::= { iso(1)
			//   identified-organization(3) certicom(132) curve(0) 34 }
			// RFC 5480 section 4: 192 bits.
			curve:         elliptic.P384(),
			wantName:      "ECDSA-P-384",
			wantOID:       "1.3.132.0.34",
			wantClassical: 192,
			wantKeySize:   384,
		},
		{
			// RFC 5480 2.1.1.1: secp521r1 ::= { iso(1)
			//   identified-organization(3) certicom(132) curve(0) 35 }
			// RFC 5480 section 4: 256 bits.
			curve:         elliptic.P521(),
			wantName:      "ECDSA-P-521",
			wantOID:       "1.3.132.0.35",
			wantClassical: 256,
			wantKeySize:   521,
		},
	}

	for _, tt := range testCases {
		t.Run(tt.wantName, func(t *testing.T) {
			t.Parallel()

			key := &ecdsa.PublicKey{Curve: tt.curve}
			got := extractAlgorithmInfo("ECDSA", ecKeyAdapter{key})

			require.Equal(t, tt.wantName, got.name, "component name")
			require.Equal(t, tt.wantOID, got.oid, "named-curve OID (RFC 5480 2.1.1.1)")
			require.Equal(t, tt.wantClassical, got.classicalSecurityLevel,
				"bits of security (RFC 5480 section 4)")
			require.Equal(t, tt.wantKeySize, got.keySize)
			require.Equal(t, []cdx.CryptoFunction{
				cdx.CryptoFunctionSign,
				cdx.CryptoFunctionVerify,
			}, got.cryptoFunctions)
		})
	}
}

// TestCzertainlyPqcProps_PreservesExistingProps pins the append contract.
//
// czertainlyPqcProps appends to the slice it is handed, so its result must be
// assigned, never appended again. getAlgorithmProperties used to do
// `props = append(props, czertainlyPqcProps(props, ...)...)`, which duplicates
// every property already present. That was invisible only because props was
// always empty at the call site. This test pre-seeds two properties so the
// duplication would be caught.
func TestCzertainlyPqcProps_PreservesExistingProps(t *testing.T) {
	t.Parallel()

	seed := []cdx.Property{
		{Name: "first", Value: "1"},
		{Name: "second", Value: "2"},
	}

	t.Run("with sizes appends exactly three", func(t *testing.T) {
		t.Parallel()

		got := czertainlyPqcProps(slices.Clone(seed), pqcInfo{
			privKeySize: 2560, pubKeySize: 1312, signatureSize: 2420,
		})

		require.Len(t, got, 5, "two seeded plus three size properties, with no duplication")
		require.Equal(t, seed, got[:2], "seeded properties must survive in order")
	})

	t.Run("without sizes returns the input unchanged", func(t *testing.T) {
		t.Parallel()

		// nil pqc metadata (XMSS, XMSS-MT, HSS-LMS) must not wipe the caller's
		// properties. The old implementation returned nil here.
		got := czertainlyPqcProps(slices.Clone(seed), nil)
		require.Equal(t, seed, got)
	})
}

// TestExtractAlgorithmInfo_ECDSA_DistinctOIDs guards the specific copy-paste
// class of bug that put secp192r1's row on P-224: no two named curves may
// share an OID or a security level pairing.
func TestExtractAlgorithmInfo_ECDSA_DistinctOIDs(t *testing.T) {
	t.Parallel()

	seen := make(map[string]string)
	for _, curve := range []elliptic.Curve{
		elliptic.P224(), elliptic.P256(), elliptic.P384(), elliptic.P521(),
	} {
		info := extractAlgorithmInfo("ECDSA", ecKeyAdapter{&ecdsa.PublicKey{Curve: curve}})
		if prev, dup := seen[info.oid]; dup {
			t.Fatalf("OID %s assigned to both %s and %s", info.oid, prev, info.name)
		}
		seen[info.oid] = info.name
	}
	require.Len(t, seen, 4)
}
