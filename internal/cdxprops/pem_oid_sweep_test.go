package cdxprops

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"slices"
	"strings"
	"testing"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/stretchr/testify/require"
)

// This file gets every registry OID through the real production parse path
// without a single byte of fixture key material.
//
// unsupportedPKIX and unsupportedPKCS8PrivateKey never interpret the key bits
// as key material -- they decode the AlgorithmIdentifier and measure the body
// -- so a synthetic asn1.Marshal of a SubjectPublicKeyInfo or PrivateKeyInfo
// carrying the OID plus a body of the size the registry states exercises
// exactly the same code as a real key would. The size is not a detail: both
// functions refuse to report a key from a body that cannot be one, so synthPKIX
// and synthPKCS8 size their bodies from the registry rather than filling in a
// placeholder, which would put every OID here on the rejection path.
//
// That is what makes per-parameter-set fixtures unnecessary: 21 OIDs covered,
// no 21 files, and the day someone adds a registry entry the sweep covers it
// automatically because it iterates wantRegistry.

// oidOf parses a dotted OID string into an asn1.ObjectIdentifier.
func oidOf(t *testing.T, dotted string) asn1.ObjectIdentifier {
	t.Helper()

	var oid asn1.ObjectIdentifier
	for _, part := range strings.Split(dotted, ".") {
		n := 0
		for _, r := range part {
			require.True(t, r >= '0' && r <= '9', "malformed OID %q", dotted)
			n = n*10 + int(r-'0')
		}
		oid = append(oid, n)
	}
	return oid
}

// TestOIDSweep_PKIXPublicKey drives every registry OID through
// unsupportedPKIX, the path a `PUBLIC KEY` PEM block takes when Go's stdlib
// cannot parse it.
func TestOIDSweep_PKIXPublicKey(t *testing.T) {
	t.Parallel()

	require.NotEmpty(t, wantRegistry)

	for dotted, want := range wantRegistry {
		t.Run(want.name, func(t *testing.T) {
			t.Parallel()

			c := NewConverter()
			key, algo, err := c.unsupportedPKIX(t.Context(), synthPKIX(t, oidOf(t, dotted)))
			require.NoError(t, err, "OID %s must be recognised", dotted)

			require.Equal(t, want.name, algo.Name)
			require.Equal(t, want.name, key.Name)

			// oid is emitted when assigned and omitted when not. cdx tags both
			// CryptoProperties.OID fields omitempty, so "" means absent.
			require.Equal(t, want.oid, algo.CryptoProperties.OID, "algorithm oid")
			require.Equal(t, want.oid, key.CryptoProperties.OID, "key oid")

			props := algo.CryptoProperties.AlgorithmProperties
			require.NotNil(t, props)
			require.Equal(t, want.paramSetID, props.ParameterSetIdentifier)
			require.ElementsMatch(t, want.functions, *props.CryptoFunctions)

			// The primitive must follow the registry, not a hardcoded default.
			wantPrimitive := want.primitive
			if wantPrimitive == "" {
				wantPrimitive = cdx.CryptoPrimitiveSignature
			}
			require.Equal(t, wantPrimitive, props.Primitive)

			if want.nqsl == nil {
				require.Nil(t, props.NistQuantumSecurityLevel)
			} else {
				require.NotNil(t, props.NistQuantumSecurityLevel)
				require.Equal(t, *want.nqsl, *props.NistQuantumSecurityLevel)
			}

			// The key component must reference the algorithm component that
			// was emitted alongside it, not a hardcoded ref.
			require.Equal(t, cdx.BOMReference(algo.BOMRef),
				key.CryptoProperties.RelatedCryptoMaterialProperties.AlgorithmRef)
			require.True(t,
				strings.HasPrefix(string(key.BOMRef),
					"crypto/key/"+strings.ToLower(want.name)+"@"),
				"unexpected key bom-ref %q", key.BOMRef)
		})
	}
}

// TestOIDSweep_PKCS8PrivateKey does the same for the `PRIVATE KEY` path.
//
// The key-component assertions mirror the PKIX sweep above, so every registry
// OID is covered and a newly added entry is covered automatically. They are
// what stops the private-key path silently regressing to an algorithm-only
// result, which is what it produced until a post-quantum private key was
// contributing no related-crypto-material asset at all.
func TestOIDSweep_PKCS8PrivateKey(t *testing.T) {
	t.Parallel()

	// Its sibling above has this guard and this one did not. A sweep over an
	// empty table runs zero subtests and reports PASS, so without it the day
	// wantRegistry loses its entries is the day this test stops testing and
	// says nothing.
	require.NotEmpty(t, wantRegistry)

	for dotted, want := range wantRegistry {
		t.Run(want.name, func(t *testing.T) {
			t.Parallel()

			c := NewConverter().WithIlmExtensions(true)
			key, algo, err := c.unsupportedPKCS8PrivateKey(t.Context(), synthPKCS8(t, oidOf(t, dotted)))
			require.NoError(t, err, "OID %s must be recognised", dotted)

			require.Equal(t, want.name, algo.Name)
			require.Equal(t, want.oid, algo.CryptoProperties.OID)

			require.Equal(t, want.name, key.Name)
			require.Equal(t, want.oid, key.CryptoProperties.OID, "key oid")
			require.Equal(t, cdx.CryptoAssetTypeRelatedCryptoMaterial,
				key.CryptoProperties.AssetType)

			keyProps := key.CryptoProperties.RelatedCryptoMaterialProperties
			require.NotNil(t, keyProps)
			require.Equal(t, cdx.RelatedCryptoMaterialTypePrivateKey, keyProps.Type)
			// The key must point at the algorithm emitted alongside it, not at
			// a hardcoded ref. For a post-quantum private key this is the ONLY
			// link to its public half -- the ref hashes the private DER, from
			// which the public key cannot be recovered.
			require.Equal(t, cdx.BOMReference(algo.BOMRef), keyProps.AlgorithmRef)
			// value would publish the secret: the DER this component is built
			// from is the private key itself, unlike the PKIX path where it is
			// a public key.
			require.Empty(t, keyProps.Value,
				"a private key's DER must never be emitted as a value")
			// size is in bits in the schema, and no registry entry sources one.
			// The byte-valued privKeySize/decapKeySize must not leak in here.
			require.Nil(t, keyProps.Size)

			require.True(t,
				strings.HasPrefix(key.BOMRef,
					"crypto/private_key/"+strings.ToLower(want.name)+"@"),
				"unexpected key bom-ref %q", key.BOMRef)

			props := algo.CryptoProperties.AlgorithmProperties
			require.Equal(t, want.paramSetID, props.ParameterSetIdentifier)
			require.ElementsMatch(t, want.functions, *props.CryptoFunctions)

			wantPrimitive := want.primitive
			if wantPrimitive == "" {
				wantPrimitive = cdx.CryptoPrimitiveSignature
			}
			require.Equal(t, wantPrimitive, props.Primitive,
				"the private-key path must set a primitive too")

			require.Equal(t, want.classical, *props.ClassicalSecurityLevel)

			// Size properties appear exactly when the registry has sourced
			// sizes, and carry the values from the expectation table.
			assertSizeProps(t, algo, want.pqc)

			require.True(t,
				strings.HasPrefix(algo.BOMRef,
					"crypto/algorithm/"+strings.ToLower(want.name)+"@"),
				"unexpected algorithm bom-ref %q", algo.BOMRef)
		})
	}
}

// TestOIDSweep_Negatives covers the paths that must fail, and fail loudly.
func TestOIDSweep_Negatives(t *testing.T) {
	t.Parallel()

	c := NewConverter()

	t.Run("unregistered oid is rejected, not guessed", func(t *testing.T) {
		t.Parallel()

		// 1.3.9999.6.1.1 is deliberately chosen: it used to be in the registry
		// labelled HQC-128, and it actually belongs to
		// SPHINCS+-Haraka-128f-robust in oqs-provider. It must now be an
		// honest miss rather than a confident mislabel.
		unknown := asn1.ObjectIdentifier{1, 3, 9999, 6, 1, 1}

		_, _, err := c.unsupportedPKIX(t.Context(), synthPKIX(t, unknown))
		require.ErrorContains(t, err, "unsupported fallback oid")
		require.ErrorContains(t, err, "1.3.9999.6.1.1")

		_, _, err = c.unsupportedPKCS8PrivateKey(t.Context(), synthPKCS8(t, unknown))
		require.ErrorContains(t, err, "unsupported fallback oid")
	})

	t.Run("hqc oids are not in the registry", func(t *testing.T) {
		t.Parallel()

		// HQC has no assigned OID (NIST CSOR has no HQC arc; oqs-provider
		// records every HQC OID as NULL). Nothing may claim to detect it.
		for _, dotted := range []string{
			"1.3.9999.6.1.1", "1.3.9999.6.1.2", "1.3.9999.6.1.3",
		} {
			require.NotContains(t, unsupportedAlgorithms, dotted)
		}
		for _, entry := range unsupportedAlgorithms {
			require.NotContains(t, entry.name, "HQC",
				"HQC must not be in the registry while it has no assigned OID")
		}
	})

	t.Run("truncated DER is rejected", func(t *testing.T) {
		t.Parallel()

		full := synthPKIX(t, mlKEM768OID)
		truncated := full[:len(full)/2]

		_, _, err := c.unsupportedPKIX(t.Context(), truncated)
		require.ErrorContains(t, err, "parsing PKIX via ASN.1")

		fullPK := synthPKCS8(t, mlKEM768OID)
		_, _, err = c.unsupportedPKCS8PrivateKey(t.Context(), fullPK[:len(fullPK)/2])
		require.ErrorContains(t, err, "parsing PKCS#8 via ASN.1")
	})

	t.Run("trailing data after the SPKI is rejected", func(t *testing.T) {
		t.Parallel()

		// Truncation above is caught by asn1.Unmarshal itself; a tail is not.
		// The SubjectPublicKeyInfo decodes cleanly and Unmarshal simply hands
		// back the bytes it did not consume, so without a check on those the
		// junk rides along into the ref and into the published value. Its
		// sibling has rejected exactly this since the same defect was fixed on
		// the PKCS#8 path.
		withTrailer := append(synthPKIX(t, mlKEM768OID), 0xde, 0xad, 0xbe, 0xef)

		_, _, err := c.unsupportedPKIX(withTrailer)
		require.ErrorContains(t, err, "parsing PKIX via ASN.1")
		require.ErrorContains(t, err, "trailing data")
	})

	t.Run("a tail of any size is rejected, on both key paths", func(t *testing.T) {
		t.Parallel()

		// The sibling above fixes the tail at four bytes, and every
		// trailing-data test in the repository does the same, so a threshold
		// anywhere in 1..4 -- len(rest) >= 4, len(rest) > 3, "tolerate a
		// little padding" -- keeps them all green while putting the defect
		// back: a guard that admits n bytes admits 2^(8n) distinct assets for
		// one key, and the admitted bytes are still base64'd verbatim into the
		// public key's value. One byte is enough, so one byte is tested.
		//
		// The last tail is well-formed DER rather than junk. Two keys
		// concatenated is how a tail gets there in the first place, so the rule
		// has to be "the DER ends where the structure ends" and not "the
		// leftovers do not look like DER".
		//
		// Both paths are driven because they carry the same guard written twice
		// and nothing else would notice one of them drifting: removing either
		// outright is caught, but weakening either the same way is not.
		spki := synthPKIX(t, mlKEM768OID)
		pkcs8 := synthPKCS8(t, mlKEM768OID)

		for _, tt := range []struct {
			name string
			tail []byte
		}{
			{"a single padding byte", []byte{0x00}},
			{"three bytes", []byte{0xde, 0xad, 0xbe}},
			{"a whole second DER structure", spki},
		} {
			_, _, err := c.unsupportedPKIX(slices.Concat(spki, tt.tail))
			require.ErrorContains(t, err, "trailing data", "PKIX: %s", tt.name)

			_, _, err = c.unsupportedPKCS8PrivateKey(t.Context(), slices.Concat(pkcs8, tt.tail))
			require.ErrorContains(t, err, "trailing data", "PKCS#8: %s", tt.name)
		}
	})

	t.Run("empty input is rejected", func(t *testing.T) {
		t.Parallel()

		_, _, err := c.unsupportedPKIX(t.Context(), nil)
		require.Error(t, err)

		_, _, err = c.unsupportedPKCS8PrivateKey(t.Context(), nil)
		require.Error(t, err)
	})

	t.Run("a signature algorithm identifier is not a key", func(t *testing.T) {
		t.Parallel()

		// A bare AlgorithmIdentifier, not wrapped in a SubjectPublicKeyInfo.
		der, err := asn1.Marshal(pkix.AlgorithmIdentifier{Algorithm: mlKEM768OID})
		require.NoError(t, err)

		_, _, err = c.unsupportedPKIX(t.Context(), der)
		require.Error(t, err, "a bare AlgorithmIdentifier must not parse as SPKI")
	})
}
