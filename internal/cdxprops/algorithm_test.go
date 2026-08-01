package cdxprops

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"math/big"
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
			require.Equal(t, tt.wantClassical, *got.classicalSecurityLevel,
				"bits of security (RFC 5480 section 4)")
			require.Equal(t, tt.wantKeySize, got.keySize)
			require.Equal(t, []cdx.CryptoFunction{
				cdx.CryptoFunctionSign,
				cdx.CryptoFunctionVerify,
			}, got.cryptoFunctions)
		})
	}
}

// TestExtractAlgorithmInfo_RSA_Functions pins RSA's cryptoFunctions.
//
// The RSA branch declared [encapsulate, decapsulate]. Those are the KEM
// functions; RSA as modelled here (PKCS#1 / PSS / OAEP over a plain RSA key)
// is not a KEM. CycloneDX's cryptoFunctions enum has encrypt, decrypt, sign
// and verify, which is what an RSA key can actually do, and which is what the
// ECDSA and Ed25519 branches of this same function already declare for
// themselves.
func TestExtractAlgorithmInfo_RSA_Functions(t *testing.T) {
	t.Parallel()

	key := &rsa.PublicKey{N: new(big.Int).Lsh(big.NewInt(1), 2047), E: 65537}
	got := extractAlgorithmInfo("RSA", rsaKeyAdapter{key})

	require.Equal(t, "RSA-2048", got.name)
	require.ElementsMatch(t, []cdx.CryptoFunction{
		cdx.CryptoFunctionEncrypt,
		cdx.CryptoFunctionDecrypt,
		cdx.CryptoFunctionSign,
		cdx.CryptoFunctionVerify,
	}, got.cryptoFunctions)

	require.NotContains(t, got.cryptoFunctions, cdx.CryptoFunctionEncapsulate,
		"encapsulate is a KEM function and RSA is not modelled as a KEM here")
	require.NotContains(t, got.cryptoFunctions, cdx.CryptoFunctionDecapsulate)
}

// TestIlmPqcProps_PreservesExistingProps pins the append contract.
//
// ilmPqcProps appends to the slice it is handed, so its result must be
// assigned, never appended again. getAlgorithmProperties used to do
// `props = append(props, ilmPqcProps(props, ...)...)`, which duplicates
// every property already present. That was invisible only because props was
// always empty at the call site. This test pre-seeds two properties so the
// duplication would be caught.
func TestIlmPqcProps_PreservesExistingProps(t *testing.T) {
	t.Parallel()

	seed := []cdx.Property{
		{Name: "first", Value: "1"},
		{Name: "second", Value: "2"},
	}

	t.Run("with sizes appends exactly three", func(t *testing.T) {
		t.Parallel()

		got := ilmPqcProps(slices.Clone(seed), pqcInfo{
			privKeySize: 2560, pubKeySize: 1312, signatureSize: 2420,
		})

		require.Len(t, got, 5, "two seeded plus three size properties, with no duplication")
		require.Equal(t, seed, got[:2], "seeded properties must survive in order")
	})

	t.Run("without sizes returns the input unchanged", func(t *testing.T) {
		t.Parallel()

		// nil pqc metadata (XMSS, XMSS-MT, HSS-LMS) must not wipe the caller's
		// properties. The old implementation returned nil here.
		got := ilmPqcProps(slices.Clone(seed), nil)
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

// TestGetAlgorithmProperties_PQCCryptoFunctions covers the certificate path.
//
// getAlgorithmProperties hardcoded CryptoFunctions to [sign], which silently
// overrode the registry for every PQC certificate: the algorithm component
// built from a registry hit reported [sign, verify], while the signature
// algorithm component built from the very same registry entry reported [sign].
//
// [sign] remains the default for the classical enum path, where there is no
// registry entry to consult.
func TestGetAlgorithmProperties_PQCCryptoFunctions(t *testing.T) {
	t.Parallel()

	t.Run("registry hit uses the registry functions", func(t *testing.T) {
		t.Parallel()

		c := NewConverter()
		// SLH-DSA-SHA2-128S. The signature algorithm enum is unknown to Go, so
		// the OID fallback is the only source of truth.
		props, _, hash := c.getAlgorithmProperties(
			x509.UnknownSignatureAlgorithm, "2.16.840.1.101.3.4.3.20")

		require.NotNil(t, props.CryptoFunctions)
		require.ElementsMatch(t, []cdx.CryptoFunction{
			cdx.CryptoFunctionSign,
			cdx.CryptoFunctionVerify,
		}, *props.CryptoFunctions)
		require.True(t, sortedFunctions(*props.CryptoFunctions),
			"emitted cryptoFunctions must be sorted")

		require.Equal(t, "128S", props.ParameterSetIdentifier)
		require.Equal(t, "SHA-256", hash, "SLH-DSA-SHA2 uses SHA-256 internally")

		// FIPS 205 Table 2: SLH-DSA-SHA2-128s is category 1.
		require.NotNil(t, props.NistQuantumSecurityLevel)
		require.Equal(t, 1, *props.NistQuantumSecurityLevel)
	})

	t.Run("stateful scheme omits the quantum security level", func(t *testing.T) {
		t.Parallel()

		c := NewConverter()
		// HSS-LMS: SP 800-208 assigns no category, so the field must not appear
		// on the certificate path either.
		props, _, _ := c.getAlgorithmProperties(
			x509.UnknownSignatureAlgorithm, "1.2.840.113549.1.9.16.3.17")

		require.Nil(t, props.NistQuantumSecurityLevel)
		require.ElementsMatch(t, []cdx.CryptoFunction{
			cdx.CryptoFunctionSign,
			cdx.CryptoFunctionVerify,
		}, *props.CryptoFunctions)
	})

	t.Run("classical enum path keeps the sign default", func(t *testing.T) {
		t.Parallel()

		c := NewConverter()
		props, _, _ := c.getAlgorithmProperties(x509.SHA256WithRSA, "")

		require.Equal(t, []cdx.CryptoFunction{cdx.CryptoFunctionSign},
			*props.CryptoFunctions)
	})

	t.Run("unmatched fallback oid keeps the sign default", func(t *testing.T) {
		t.Parallel()

		c := NewConverter()
		props, _, _ := c.getAlgorithmProperties(
			x509.UnknownSignatureAlgorithm, "1.2.3.4.5.6.7.8")

		require.Equal(t, []cdx.CryptoFunction{cdx.CryptoFunctionSign},
			*props.CryptoFunctions)
		require.Nil(t, props.NistQuantumSecurityLevel)
	})
}
