package cdxprops

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"strings"
	"testing"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/stretchr/testify/require"
)

// This file gets every registry OID through the real production parse path
// without a single byte of fixture key material.
//
// unsupportedPKIX and unsupportedPKCS8PrivateKey only decode the
// AlgorithmIdentifier -- neither touches the key bits -- so a synthetic
// asn1.Marshal of a SubjectPublicKeyInfo or PrivateKeyInfo carrying the OID
// plus a placeholder key exercises exactly the same code as a real key would.
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
			key, algo, err := c.unsupportedPKIX(synthPKIX(t, oidOf(t, dotted)))
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

		_, _, err := c.unsupportedPKIX(synthPKIX(t, unknown))
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

		_, _, err := c.unsupportedPKIX(truncated)
		require.ErrorContains(t, err, "parsing PKIX via ASN.1")

		fullPK := synthPKCS8(t, mlKEM768OID)
		_, _, err = c.unsupportedPKCS8PrivateKey(t.Context(), fullPK[:len(fullPK)/2])
		require.ErrorContains(t, err, "parsing PKCS#8 via ASN.1")
	})

	t.Run("empty input is rejected", func(t *testing.T) {
		t.Parallel()

		_, _, err := c.unsupportedPKIX(nil)
		require.Error(t, err)

		_, _, err = c.unsupportedPKCS8PrivateKey(t.Context(), nil)
		require.Error(t, err)
	})

	t.Run("a signature algorithm identifier is not a key", func(t *testing.T) {
		t.Parallel()

		// A bare AlgorithmIdentifier, not wrapped in a SubjectPublicKeyInfo.
		der, err := asn1.Marshal(pkix.AlgorithmIdentifier{Algorithm: mlKEM768OID})
		require.NoError(t, err)

		_, _, err = c.unsupportedPKIX(der)
		require.Error(t, err, "a bare AlgorithmIdentifier must not parse as SPKI")
	})
}
