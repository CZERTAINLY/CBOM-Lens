package cdxprops

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"

	cdx "github.com/CycloneDX/cyclonedx-go"

	"github.com/CZERTAINLY/CBOM-lens/internal/cdxprops/cdxtest"
	"github.com/CZERTAINLY/CBOM-lens/internal/model"

	"github.com/stretchr/testify/require"
)

func TestConverter_publicKeyComponents(t *testing.T) {
	t.Parallel()

	data, err := cdxtest.TestData(cdxtest.MLDSA65Certificate)
	require.NoError(t, err)
	block, _ := pem.Decode(data)
	require.NotNil(t, block)
	require.Equal(t, "CERTIFICATE", block.Type)

	cert, err := x509.ParseCertificate(block.Bytes)
	require.NoError(t, err)

	c := NewConverter()
	algo, key := c.publicKeyComponents(t.Context(), -1, cert.PublicKey, cert)

	require.Equal(t, "ML-DSA-65", algo.Name)
	require.Equal(t, "ML-DSA-65", key.Name)
}

// selfSignedRSACert builds an RSA certificate with the given KeyUsage. It exists
// so the keyEncipherment path can be exercised without committing a fixture.
func selfSignedRSACert(t *testing.T, usage x509.KeyUsage) *x509.Certificate {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "encipherment.example"},
		NotBefore:    time.Unix(0, 0),
		NotAfter:     time.Unix(1<<31, 0),
		KeyUsage:     usage,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return cert
}

// TestCertHitToComponents_RSAEnciphermentKeyIsPKE covers the classical half of
// the primitive-overwrite defect. publicKeyComponents classifies an RSA key
// whose KeyUsage is keyEncipherment only as "pke"; certHitToComponents used to
// overwrite that with "signature" after the component had been hashed.
func TestCertHitToComponents_RSAEnciphermentKeyIsPKE(t *testing.T) {
	t.Parallel()

	cert := selfSignedRSACert(t, x509.KeyUsageKeyEncipherment)

	compos, _, err := NewConverter().certHitToComponents(t.Context(), model.CertHit{Cert: cert})
	require.NoError(t, err)

	var found bool
	for _, compo := range compos {
		if compo.CryptoProperties == nil ||
			compo.CryptoProperties.AssetType != cdx.CryptoAssetTypeAlgorithm ||
			!strings.HasPrefix(compo.Name, "RSA-") {
			continue
		}
		require.NotNil(t, compo.CryptoProperties.AlgorithmProperties)
		require.Equal(t, cdx.CryptoPrimitivePKE,
			compo.CryptoProperties.AlgorithmProperties.Primitive,
			"a keyEncipherment-only RSA key must be reported as pke, not signature")
		found = true
	}
	require.True(t, found, "no RSA algorithm component emitted for the certificate")
}

// TestCertHitToComponents_BOMRefsMatchContents is the general form of the same
// defect: a BOMRef is a hash of the component it names, so mutating a component
// after BOMRefHash has run leaves a reference that no longer describes its own
// contents. Re-hashing every emitted component must reproduce its BOMRef.
func TestCertHitToComponents_BOMRefsMatchContents(t *testing.T) {
	t.Parallel()

	for name, cert := range map[string]*x509.Certificate{
		"rsa keyEncipherment": selfSignedRSACert(t, x509.KeyUsageKeyEncipherment),
		"rsa digitalSignature": selfSignedRSACert(t,
			x509.KeyUsageDigitalSignature|x509.KeyUsageCertSign),
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			c := NewConverter()
			compos, _, err := c.certHitToComponents(t.Context(), model.CertHit{Cert: cert})
			require.NoError(t, err)
			require.NotEmpty(t, compos)

			for _, compo := range compos {
				// Only crypto/algorithm refs are hashes of the component JSON.
				// crypto/key and crypto/certificate refs hash the key or the
				// DER instead, so re-hashing the component cannot reproduce
				// them and they are out of scope here.
				refName, _, ok := strings.Cut(compo.BOMRef, "@")
				if !ok || !strings.HasPrefix(refName, "crypto/algorithm/") {
					continue
				}
				want := compo.BOMRef

				rehashed := compo
				c.BOMRefHash(&rehashed, refName)
				require.Equal(t, want, rehashed.BOMRef,
					"%s: BOMRef does not match a re-hash of its own contents, "+
						"so the component was mutated after being hashed", compo.Name)
			}
		})
	}
}

// TestPublicKeyComponents_PQCKeysAreDistinct pins the fix for the collapse of
// every post-quantum key into one component.
//
// Go does not parse ML-DSA/ML-KEM/SLH-DSA public keys, so x509 leaves
// cert.PublicKey nil and MarshalPKIXPublicKey fails. hashPublicKey used to
// discard that error and return two empty strings, producing the bom-ref
// "crypto/key/<alg>@" with no digest for every PQC certificate. Builder keys
// components by bom-ref, so N distinct PQC keys merged into a single
// component and the key material was omitted entirely.
func TestPublicKeyComponents_PQCKeysAreDistinct(t *testing.T) {
	fixtures := []string{
		cdxtest.MLDSA65Certificate,
		cdxtest.SLHDSASHA2128sCertificate,
		cdxtest.MLKEM768Certificate,
	}

	conv := NewConverter()
	refs := make(map[string]string, len(fixtures))

	for _, f := range fixtures {
		raw, err := cdxtest.TestData(f)
		require.NoError(t, err)
		block, _ := pem.Decode(raw)
		require.NotNil(t, block, f)
		cert, err := x509.ParseCertificate(block.Bytes)
		require.NoError(t, err, f)

		// Precondition: this is the situation being guarded against.
		require.Nil(t, cert.PublicKey, "%s: expected an unparseable PQC key", f)
		require.NotEmpty(t, cert.RawSubjectPublicKeyInfo, "%s: no SPKI to fall back to", f)

		_, key := conv.publicKeyComponents(t.Context(), cert.PublicKeyAlgorithm, cert.PublicKey, cert)

		require.False(t, strings.HasSuffix(key.BOMRef, "@"),
			"%s: bom-ref %q has an empty digest", f, key.BOMRef)
		require.NotEmpty(t, key.CryptoProperties.RelatedCryptoMaterialProperties.Value,
			"%s: key material was dropped", f)

		if prev, dup := refs[key.BOMRef]; dup {
			t.Fatalf("%s and %s collapsed into the same bom-ref %q", prev, f, key.BOMRef)
		}
		refs[key.BOMRef] = f
	}

	require.Len(t, refs, len(fixtures), "each PQC key must get its own component")
}
