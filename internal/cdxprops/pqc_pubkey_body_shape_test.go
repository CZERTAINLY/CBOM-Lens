package cdxprops_test

import (
	"bytes"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	pemlib "encoding/pem"
	"log/slog"
	"strings"
	"testing"

	"github.com/OmniTrustILM/cbom-lens/internal/cdxprops"
	"github.com/OmniTrustILM/cbom-lens/internal/cdxprops/cdxtest"
	"github.com/OmniTrustILM/cbom-lens/internal/model"
	"github.com/OmniTrustILM/cbom-lens/internal/scanner/pem"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/stretchr/testify/require"
)

// This file is the public-key counterpart of pqc_body_shape_test.go, and it
// exists because only the private half ever got a body check. A
// SubjectPublicKeyInfo carrying the ML-DSA-65 OID and four bytes of garbage
// produced a full "an ML-DSA-65 public key exists here" component, silently,
// while the same four bytes under the same OID in a PKCS#8 wrapper had been
// refused since the private-key guard landed.
//
// The test it must pass is simpler than the private one, and deliberately so.
// RFC 9881 sec. 6 makes a PKCS#8 privateKey a CHOICE -- seed, expandedKey, or
// both -- so several lengths are legal and the encodings have to be enumerated.
// RFC 9881 sec. 4, and the SLH-DSA (RFC 9909 sec. 5) and ML-KEM (RFC 9935
// sec. 4) equivalents, put the encoded public key directly in the BIT STRING
// with no CHOICE at all. One algorithm, one legal length. So the cases below
// pin an EXACT match: one byte short and one byte long are both wrong, and
// there is no wrapper for a `derOctetStringOf`-style shape test to look at.

// The registry's public-key sizes in BYTES, from FIPS 204 Table 2, FIPS 205
// Table 2 and FIPS 203 Table 3. They are repeated here rather than read from
// the registry so that a test failure says the registry changed, instead of
// changing with it.
const (
	mlDSA65PubKey    = 1952
	mlKEM768EncapKey = 1184
	slhDSA128sPubKey = 32
)

// pkixDERBody builds a SubjectPublicKeyInfo carrying oid whose publicKey BIT
// STRING holds exactly body, so a test can state the length it means.
//
// The struct is declared here rather than reusing the production pkixStruct:
// this is an external test package, and pinning the wire shape the production
// code must read is the point. BitLength is set from body because a BIT STRING
// whose declared bit count disagrees with its content is a different defect
// from the one under test.
func pkixDERBody(t *testing.T, oid asn1.ObjectIdentifier, body []byte) []byte {
	t.Helper()

	der, err := asn1.Marshal(struct {
		Algorithm pkix.AlgorithmIdentifier
		PublicKey asn1.BitString
	}{
		Algorithm: pkix.AlgorithmIdentifier{Algorithm: oid},
		PublicKey: asn1.BitString{Bytes: body, BitLength: len(body) * 8},
	})
	require.NoError(t, err)

	return der
}

// pkixDERBodyWithBitLength is pkixDERBody with the BIT STRING's declared
// BitLength chosen independently of body's length, which pkixDERBody can
// never produce: it fixes BitLength at len(body)*8 by construction, because a
// BIT STRING whose declared bit count disagrees with its content is a
// different defect from the one that helper exists to test.
//
// encoding/asn1's BitString encoder derives the wire's one unused-bits octet
// from bitLength alone and copies body after it verbatim; it does not check
// that the two agree. Its decoder, on the far end, rejects the result unless
// the low bits the padding count claims are unused are actually zero, so a
// caller cannot hand this noise() as body and get a valid fixture out for
// every bitLength: this helper clears those bits itself, so any body
// round-trips regardless of what its last byte happened to contain.
//
// It cannot produce every (len(body), bitLength) pair a caller might ask for.
// A BIT STRING's one unused-bits octet holds 0-7, so a decodable bitLength can
// only land in [len(body)*8-7, len(body)*8] -- the same structural limit that
// makes the finding this helper exists for a narrow one (1-7 quietly unused
// bits), not an arbitrary mismatch. Asking for a bitLength outside that range
// is a test-author error, not a case worth silently reinterpreting, so it
// fails loudly here instead of building a fixture that does not test what its
// caller thinks it does.
func pkixDERBodyWithBitLength(t *testing.T, oid asn1.ObjectIdentifier, body []byte, bitLength int) []byte {
	t.Helper()

	if len(body) == 0 {
		require.Zero(t, bitLength, "an empty BIT STRING can only declare BitLength 0")
	} else {
		require.True(t, bitLength <= len(body)*8 && bitLength > (len(body)-1)*8,
			"bitLength %d is not reachable from a %d-byte BIT STRING body", bitLength, len(body))
	}

	padding := (8 - bitLength%8) % 8
	if padding > 0 {
		body = append([]byte(nil), body...)
		body[len(body)-1] &= byte(0xff << padding)
	}

	der, err := asn1.Marshal(struct {
		Algorithm pkix.AlgorithmIdentifier
		PublicKey asn1.BitString
	}{
		Algorithm: pkix.AlgorithmIdentifier{Algorithm: oid},
		PublicKey: asn1.BitString{Bytes: body, BitLength: bitLength},
	})
	require.NoError(t, err)

	return der
}

// pemPublicKey wraps DER in a `PUBLIC KEY` block. Go's stdlib cannot parse a
// post-quantum SubjectPublicKeyInfo, so the scanner routes it to ParseErrors
// and the block reaches analyzeParseError -- the production path.
func pemPublicKey(der []byte) []byte {
	return pemlib.EncodeToMemory(&pemlib.Block{Type: "PUBLIC KEY", Bytes: der})
}

// assetsOfPub splits a detection's components by asset type, asserting the zero
// Component is never appended. It is assetsOf with a `PUBLIC KEY` envelope, kept
// separate so that no private-key test changes shape when this one does.
func assetsOfPub(t *testing.T, der []byte) (algorithms, material []cdx.Component) {
	t.Helper()

	return assetsOfPubPEM(t, pemPublicKey(der))
}

// assetsOfPubPEM is assetsOfPub taking the PEM bytes directly, so a real
// fixture file can travel the same path as a synthetic one.
func assetsOfPubPEM(t *testing.T, data []byte) (algorithms, material []cdx.Component) {
	t.Helper()

	bundle, err := pem.Scanner{}.Scan(t.Context(), data, "synthetic.pem")
	require.NoError(t, err, "the PEM envelope itself is well formed")

	d := cdxprops.NewConverter().PEMBundle(t.Context(), bundle)
	require.NotNil(t, d)

	for _, compo := range d.Components {
		require.NotNil(t, compo.CryptoProperties, "the zero Component must never be appended")
		switch compo.CryptoProperties.AssetType {
		case cdx.CryptoAssetTypeAlgorithm:
			algorithms = append(algorithms, compo)
		case cdx.CryptoAssetTypeRelatedCryptoMaterial:
			material = append(material, compo)
		}
	}

	return algorithms, material
}

// certPEM wraps DER in a `CERTIFICATE` block.
func certPEM(der []byte) []byte {
	return pemlib.EncodeToMemory(&pemlib.Block{Type: "CERTIFICATE", Bytes: der})
}

// csrWithSPKIDetection is the request counterpart of assetsOfCertPEM, and it
// takes the whole detection rather than a split of it.
//
// The request component and the key component are both related crypto material
// -- a request is typed "other" -- so an asset-type split cannot tell "the key
// was dropped" from "the request was dropped", which is precisely the confusion
// the certificate helper avoids by counting certificates separately. Bom-ref
// prefixes can, and the detection carries the dependency edges too: a rejected
// body must leave the request depending on nothing, and a split of components
// would not show that.
//
// It runs the real scanner over a real `CERTIFICATE REQUEST` block, because
// that is the route this defect hides in: the scanner parses such a block
// SUCCESSFULLY even when the SPKI algorithm is one Go cannot name, so the
// request lands in CertificateRequests and never reaches ParseErrors or
// analyzeParseError.
func csrWithSPKIDetection(t *testing.T, oid asn1.ObjectIdentifier, subject string, body []byte) *model.Detection {
	t.Helper()

	csr := csrWithSPKI(t,
		pkix.Name{CommonName: subject},
		pkix.AlgorithmIdentifier{Algorithm: oid},
		asn1.BitString{Bytes: body, BitLength: len(body) * 8})
	require.Equal(t, x509.UnknownPublicKeyAlgorithm, csr.PublicKeyAlgorithm,
		"the fixture must reach the unparseable-key path, or this proves nothing")

	bundle, err := pem.Scanner{}.Scan(t.Context(),
		pemlib.EncodeToMemory(&pemlib.Block{Type: "CERTIFICATE REQUEST", Bytes: csr.Raw}),
		"synthetic.pem")
	require.NoError(t, err, "the PEM envelope itself is well formed")
	require.Len(t, bundle.CertificateRequests, 1,
		"a request under an unnameable SPKI algorithm still parses, and must reach the converter")

	d := cdxprops.NewConverter().PEMBundle(t.Context(), bundle)
	require.NotNil(t, d)
	return d
}

// refsWithPrefix lists the bom-refs of a detection's components under prefix,
// so an assertion can name what survived rather than only count it.
func refsWithPrefix(d *model.Detection, prefix string) []string {
	var refs []string
	for _, compo := range d.Components {
		if strings.HasPrefix(compo.BOMRef, prefix) {
			refs = append(refs, compo.BOMRef)
		}
	}
	return refs
}

// certWithSPKIPEM is the certificate counterpart of pemPublicKey: it puts spki
// where a certificate carries its subject public key, and wraps the result in a
// `CERTIFICATE` block, so the same bytes that reach unsupportedPKIX under one
// PEM label reach publicKeyComponents under the other.
func certWithSPKIPEM(t *testing.T, spki []byte) []byte {
	t.Helper()

	der, err := cdxtest.CertWithSPKI(spki)
	require.NoError(t, err)
	return certPEM(der)
}

// assetsOfCertPEM splits a detection's components three ways rather than two: a
// certificate produces a certificate asset as well as algorithms and material,
// and a test that only looked at the last two could not tell "the key was
// dropped" from "the certificate was dropped with it".
func assetsOfCertPEM(t *testing.T, data []byte) (certificates, algorithms, material []cdx.Component) {
	t.Helper()

	bundle, err := pem.Scanner{}.Scan(t.Context(), data, "synthetic.pem")
	require.NoError(t, err, "the PEM envelope itself is well formed")

	d := cdxprops.NewConverter().PEMBundle(t.Context(), bundle)
	require.NotNil(t, d)

	for _, compo := range d.Components {
		require.NotNil(t, compo.CryptoProperties, "the zero Component must never be appended")
		switch compo.CryptoProperties.AssetType {
		case cdx.CryptoAssetTypeCertificate:
			certificates = append(certificates, compo)
		case cdx.CryptoAssetTypeAlgorithm:
			algorithms = append(algorithms, compo)
		case cdx.CryptoAssetTypeRelatedCryptoMaterial:
			material = append(material, compo)
		}
	}

	return certificates, algorithms, material
}

// algorithmNames lists the algorithm components by name, so an assertion can
// say which algorithms a file referenced rather than only how many.
func algorithmNames(algorithms []cdx.Component) []string {
	names := make([]string, 0, len(algorithms))
	for _, algo := range algorithms {
		names = append(names, algo.Name)
	}
	return names
}

// TestPQCPipeline_CertificateSPKIUndersizedBodyYieldsAlgorithmNotKey is the
// certificate half of TestPQCPipeline_PKIXUndersizedBodyYieldsAlgorithmNotKey,
// through the whole pipeline rather than one function.
//
// The two paths read the same structure -- a SubjectPublicKeyInfo, one
// AlgorithmIdentifier and one BIT STRING -- differing only in the PEM label
// around it. Before the certificate guard, four bytes of garbage under the
// ML-DSA-65 OID were refused inside a `PUBLIC KEY` block and reported as a
// fully formed ML-DSA-65 public key inside a `CERTIFICATE` one, with its
// material published as base64 of the noise.
//
// The certificate must survive: it is a real asset, established by its own DER,
// and a scanner that reports LESS the more broken its input is would be worse
// than one that over-reports.
func TestPQCPipeline_CertificateSPKIUndersizedBodyYieldsAlgorithmNotKey(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		oid  asn1.ObjectIdentifier
		body []byte
		algo string
	}{
		{"ML-DSA-65 four bytes of garbage", mlDSA65OID, noise(4), "ML-DSA-65"},
		{"ML-KEM-768 one byte short", mlKEM768OID, noise(mlKEM768EncapKey - 1), "ML-KEM-768"},
		{"SLH-DSA-SHA2-128S one byte long", slhDSA128sOID, noise(slhDSA128sPubKey + 1), "SLH-DSA-SHA2-128S"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			certificates, algorithms, material := assetsOfCertPEM(t,
				certWithSPKIPEM(t, pkixDERBody(t, tt.oid, tt.body)))

			require.Empty(t, material,
				"a body that is not this algorithm's public key must not be reported as one")
			require.Len(t, certificates, 1,
				"the certificate is a real asset whatever its subject key holds")
			require.Contains(t, algorithmNames(algorithms), tt.algo,
				"the OID establishes the algorithm is referenced, whatever the body holds")
		})
	}
}

// TestPQCPipeline_CertificateSPKIBitLengthMismatchYieldsAlgorithmNotKey is the
// certificate half of TestPQCPipeline_PKIXBitLengthMismatchYieldsAlgorithmNotKey:
// a certificate's raw SPKI is the same structure as a standalone `PUBLIC KEY`
// block, so a body with the registry's exact byte count and a BitLength a few
// bits short of it must be refused there too, not just in the PKIX path.
func TestPQCPipeline_CertificateSPKIBitLengthMismatchYieldsAlgorithmNotKey(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name      string
		oid       asn1.ObjectIdentifier
		size      int
		bitsShort int
		algo      string
	}{
		{"ML-DSA-65 one bit short", mlDSA65OID, mlDSA65PubKey, 1, "ML-DSA-65"},
		{"ML-KEM-768 four bits short", mlKEM768OID, mlKEM768EncapKey, 4, "ML-KEM-768"},
		{"SLH-DSA-SHA2-128S seven bits short", slhDSA128sOID, slhDSA128sPubKey, 7, "SLH-DSA-SHA2-128S"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			der := pkixDERBodyWithBitLength(t, tt.oid, noise(tt.size), tt.size*8-tt.bitsShort)
			certificates, algorithms, material := assetsOfCertPEM(t, certWithSPKIPEM(t, der))

			require.Empty(t, material,
				"a body with the right byte count but the wrong declared bit count must not be reported as a key")
			require.Len(t, certificates, 1,
				"the certificate is a real asset whatever its subject key holds")
			require.Contains(t, algorithmNames(algorithms), tt.algo,
				"the OID establishes the algorithm is referenced, whatever the body holds")
		})
	}
}

// TestPQCPipeline_CSRSPKIRejectedBodyYieldsAlgorithmNotKey is the third member
// of the family: the same rule, at the same price, for a certificate REQUEST.
//
// A request reaches unsupportedPKIX through requestedKeyComponents, with its
// own RawSubjectPublicKeyInfo, so the body check is the one the `PUBLIC KEY`
// and CERTIFICATE paths already apply and the rows below are its certificate
// sibling's, unchanged. A request that had bought the key claim more cheaply
// than a bare key does would be the same defect the other two closed, moved to
// the one artefact nobody looks at twice.
//
// The algorithm must come out WHOLE, not merely present. The obvious "why
// build what we are about to reject" refactor hoists the guard above
// setAlgorithmPrimitive and BOMRefHash, and Builder.appendDetection drops a
// component with no bom-ref -- so under it a rejected request would lose the
// algorithm as well as the key, silently, and a test that only counted
// components would stay green.
//
// The dependency assertion is the request-specific half. csrToCDX emits the
// request-to-key edge only alongside the key, so an edge here would name a
// component that is not in the detection.
func TestPQCPipeline_CSRSPKIRejectedBodyYieldsAlgorithmNotKey(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		oid       asn1.ObjectIdentifier
		body      []byte
		algo      string
		dotted    string
		primitive cdx.CryptoPrimitive
	}{
		{
			name: "ML-DSA-65 four bytes of garbage", oid: mlDSA65OID, body: noise(4),
			algo: "ML-DSA-65", dotted: "2.16.840.1.101.3.4.3.18",
			primitive: cdx.CryptoPrimitiveSignature,
		},
		{
			name: "ML-KEM-768 one byte short", oid: mlKEM768OID, body: noise(mlKEM768EncapKey - 1),
			algo: "ML-KEM-768", dotted: "2.16.840.1.101.3.4.4.2",
			primitive: cdx.CryptoPrimitiveKEM,
		},
		{
			name: "SLH-DSA-SHA2-128S one byte long", oid: slhDSA128sOID, body: noise(slhDSA128sPubKey + 1),
			algo: "SLH-DSA-SHA2-128S", dotted: "2.16.840.1.101.3.4.3.20",
			primitive: cdx.CryptoPrimitiveSignature,
		},
		// XMSS is the only row where the length comparison is not what does the
		// work: RFC 9802 puts the parameter set in the key value rather than the
		// OID, so registryPublicKeyBodySize is 0 and "no encoding of any key is
		// zero bytes" is the entire check. A length comparison inlined at the
		// request's call site would pass every row above and lose only this one.
		{
			name: "XMSS empty body", oid: xmssOID, body: nil,
			algo: "XMSS", dotted: "1.3.6.1.5.5.7.6.34",
			primitive: cdx.CryptoPrimitiveSignature,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			d := csrWithSPKIDetection(t, tt.oid, "rejected-request.example", tt.body)

			require.Len(t, refsWithPrefix(d, "crypto/csr/"), 1,
				"the request is a real asset whatever its SPKI body holds")
			require.Empty(t, refsWithPrefix(d, "crypto/key/"),
				"a body that is not this algorithm's public key must not be reported as one")

			var algorithms []cdx.Component
			for _, compo := range d.Components {
				require.NotNil(t, compo.CryptoProperties, "the zero Component must never be appended")
				if compo.CryptoProperties.AssetType == cdx.CryptoAssetTypeAlgorithm {
					algorithms = append(algorithms, compo)
				}
			}
			require.Len(t, algorithms, 1,
				"the OID establishes the algorithm is referenced, whatever the body holds")
			algo := algorithms[0]

			require.Equal(t, tt.algo, algo.Name)
			require.Equal(t, tt.dotted, algo.CryptoProperties.OID,
				"the oid is what established the algorithm in the first place")
			require.NotEmpty(t, algo.BOMRef,
				"Builder.appendDetection drops a component with no bom-ref, so a "+
					"hoisted guard would cost the request its algorithm too")
			require.NotNil(t, algo.CryptoProperties.AlgorithmProperties)
			require.Equal(t, tt.primitive,
				algo.CryptoProperties.AlgorithmProperties.Primitive,
				"a KEM reported as a signature scheme is a mislabel the rejection path must not reintroduce")

			require.Empty(t, d.Dependencies,
				"the request-to-key edge must not name a key that was never built")
		})
	}
}

// TestPQCPipeline_CSRUnsizedAlgorithmStillYieldsItsKey is the other direction
// of the XMSS row above, and the two are only meaningful together.
//
// Refusing everything the registry states no size for would delete real
// hash-based signature keys from an inventory built to find them; refusing
// nothing unsized publishes key material over an empty BIT STRING. A request
// carrying an XMSS key must therefore keep it, on the same terms the
// `PUBLIC KEY` and CERTIFICATE paths keep theirs.
func TestPQCPipeline_CSRUnsizedAlgorithmStillYieldsItsKey(t *testing.T) {
	t.Parallel()

	d := csrWithSPKIDetection(t, xmssOID, "xmss-request.example", noise(1))

	keys := refsWithPrefix(d, "crypto/key/")
	require.Len(t, keys, 1,
		"with no size in the registry there is nothing to check, and dropping the key is worse")
	require.True(t, strings.HasPrefix(keys[0], "crypto/key/xmss@"),
		"the key is named by the registry entry the OID matched, got %s", keys[0])
	require.Len(t, d.Dependencies, 1,
		"a request that establishes a key depends on it")
}

// TestPQCPipeline_CertificateUnsizedAlgorithmRejectsOnlyAnEmptyBody is the
// certificate half of TestPQCPipeline_PKIXUnsizedAlgorithmRejectsOnlyAnEmptyBody,
// and it is the only certificate case where the length comparison is not what
// does the work.
//
// XMSS, XMSS-MT and HSS-LMS are named by the registry and sized by none of it:
// RFC 9802 puts the parameter set in the key value rather than the OID, so
// registryPublicKeyBodySize is 0 and "no encoding of any key is zero bytes" is
// the entire check. Every other certificate row in this file is refused by the
// length comparison as well, so a length comparison inlined at the certificate
// call site -- the one thing rejectPublicKeyBody's doc comment forbids, because
// it makes one rule into two opinions -- passes all of them and loses only this.
//
// Both halves are asserted together because either alone is satisfiable by
// something worse: refusing everything unsized would delete real hash-based
// signature keys from an inventory built to find them, and refusing nothing
// unsized publishes key material over an empty BIT STRING.
func TestPQCPipeline_CertificateUnsizedAlgorithmRejectsOnlyAnEmptyBody(t *testing.T) {
	t.Parallel()

	t.Run("empty body", func(t *testing.T) {
		t.Parallel()

		certificates, algorithms, material := assetsOfCertPEM(t,
			certWithSPKIPEM(t, pkixDERBody(t, xmssOID, nil)))

		require.Empty(t, material, "an empty body cannot hold a key of any algorithm")
		require.Len(t, certificates, 1,
			"the certificate is a real asset whatever its subject key holds")
		require.Contains(t, algorithmNames(algorithms), "XMSS",
			"the OID establishes the algorithm is referenced, whatever the body holds")
	})

	t.Run("one byte", func(t *testing.T) {
		t.Parallel()

		_, _, material := assetsOfCertPEM(t,
			certWithSPKIPEM(t, pkixDERBody(t, xmssOID, noise(1))))

		require.Len(t, material, 1,
			"with no size in the registry there is nothing to check, and dropping the key is worse")
		require.Equal(t, "XMSS", material[0].Name)
	})

	t.Run("one byte, bit-length mismatch", func(t *testing.T) {
		t.Parallel()

		_, _, material := assetsOfCertPEM(t,
			certWithSPKIPEM(t, pkixDERBodyWithBitLength(t, xmssOID, noise(1), 7)))

		require.Empty(t, material,
			"no byte count is registered for XMSS, but a bit count that disagrees with the body is still refused")
	})
}

// TestPQCPipeline_CertificateOneBadKeyDoesNotTakeTheGoodOneWithIt puts a
// garbage-SPKI certificate and a real one in a single file, for the reason its
// `PUBLIC KEY` sibling does: a one-block file cannot tell "the offending key was
// dropped" from "the file produced nothing", and over-application is the natural
// failure mode of any guard that drops a component.
func TestPQCPipeline_CertificateOneBadKeyDoesNotTakeTheGoodOneWithIt(t *testing.T) {
	t.Parallel()

	good, err := cdxtest.TestData(cdxtest.MLKEM768Certificate)
	require.NoError(t, err)

	var file []byte
	file = append(file, certWithSPKIPEM(t, pkixDERBody(t, mlDSA65OID, noise(4)))...)
	file = append(file, good...)

	certificates, algorithms, material := assetsOfCertPEM(t, file)

	require.Len(t, material, 1, "exactly one of the two certificates carries a key")
	require.Equal(t, "ML-KEM-768", material[0].Name,
		"the surviving key must be the real one, not the garbage under the ML-DSA-65 OID")
	require.Len(t, certificates, 2, "both certificates are real assets")
	require.Contains(t, algorithmNames(algorithms), "ML-DSA-65",
		"the rejected certificate still references its OID")
}

// TestPQCPipeline_CertificateRealFixturesStillYieldTheirKey is the certificate
// counterpart of TestPQCPipeline_PKIXRealFixturesStillYieldTheirKey, and it
// checks one thing that function cannot: that the certificate still POINTS at
// the key it carries.
//
// Dropping a key and leaving certificateProperties.subjectPublicKeyRef naming it
// would be a dangling reference; keeping the ref and dropping nothing would make
// this pass for the wrong reason. Asserting the ref RESOLVES to the emitted
// material is what ties the two halves together.
func TestPQCPipeline_CertificateRealFixturesStillYieldTheirKey(t *testing.T) {
	t.Parallel()

	tests := []struct {
		fixture string
		algo    string
	}{
		{cdxtest.MLDSA65Certificate, "ML-DSA-65"},
		{cdxtest.MLKEM768Certificate, "ML-KEM-768"},
		{cdxtest.SLHDSASHA2128sCertificate, "SLH-DSA-SHA2-128S"},
	}

	for _, tt := range tests {
		t.Run(tt.algo, func(t *testing.T) {
			t.Parallel()

			data, err := cdxtest.TestData(tt.fixture)
			require.NoError(t, err, "fixture %s", tt.fixture)

			certificates, _, material := assetsOfCertPEM(t, data)

			require.Len(t, material, 1, "a real %s certificate must still yield its key", tt.algo)
			require.Equal(t, tt.algo, material[0].Name)
			require.NotEmpty(t, material[0].CryptoProperties.RelatedCryptoMaterialProperties.Value,
				"a public key is not a secret and must be published")

			require.Len(t, certificates, 1)
			require.Equal(t, cdx.BOMReference(material[0].BOMRef),
				certificates[0].CryptoProperties.CertificateProperties.SubjectPublicKeyRef,
				"the certificate must point at the key it carries")
		})
	}
}

// TestPQCPipeline_CertificateRejectedBodyIsLoggedAtWarn pins the operator-facing
// half of the certificate guard, exactly as its `PUBLIC KEY` sibling does. A key
// dropped silently is indistinguishable, in the document and in the output, from
// a certificate that never held one.
//
// It cannot run in parallel: slog.SetDefault is process-wide.
func TestPQCPipeline_CertificateRejectedBodyIsLoggedAtWarn(t *testing.T) {
	var logBuf bytes.Buffer
	prev := slog.Default()
	t.Cleanup(func() { slog.SetDefault(prev) })
	slog.SetDefault(slog.New(slog.NewTextHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelWarn})))

	_, _, material := assetsOfCertPEM(t,
		certWithSPKIPEM(t, pkixDERBody(t, mlDSA65OID, noise(4))))
	require.Empty(t, material)

	logged := logBuf.String()
	require.Contains(t, logged, "level=WARN",
		"a dropped key at Debug level is a silently dropped key")
	require.Contains(t, logged, "not reporting a public key")
	require.Contains(t, logged, "algorithm=ML-DSA-65",
		"the operator has to know which key was dropped")
	require.Contains(t, logged, "body_bytes=4",
		"and what was wrong with it")
}

// TestPQCPipeline_CSRRejectedBodyIsLoggedAtWarn pins the operator-facing half
// of the guard for a request, exactly as its certificate and `PUBLIC KEY`
// siblings do. A key dropped silently is indistinguishable, in the document and
// in the output, from a request that never held one.
//
// The message and the attributes are the ones the other two paths emit, and
// that is the claim: one message class across all three, not three dialects
// that a log query has to know about separately. They come free from
// unsupportedPKIX today; this pins that they keep coming from there rather than
// being reimplemented at the request's call site the day someone wants to add
// the subject to the line.
//
// It cannot run in parallel: slog.SetDefault is process-wide.
func TestPQCPipeline_CSRRejectedBodyIsLoggedAtWarn(t *testing.T) {
	var logBuf bytes.Buffer
	prev := slog.Default()
	t.Cleanup(func() { slog.SetDefault(prev) })
	slog.SetDefault(slog.New(slog.NewTextHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelWarn})))

	d := csrWithSPKIDetection(t, mlDSA65OID, "rejected-request.example", noise(4))
	require.Empty(t, refsWithPrefix(d, "crypto/key/"))

	logged := logBuf.String()
	require.Contains(t, logged, "level=WARN",
		"a dropped key at Debug level is a silently dropped key")
	require.Contains(t, logged, "not reporting a public key")
	require.Contains(t, logged, "algorithm=ML-DSA-65",
		"the operator has to know which key was dropped")
	require.Contains(t, logged, "body_bytes=4",
		"and what was wrong with it")
}

// TestPQCPipeline_PKIXUndersizedBodyYieldsAlgorithmNotKey pins the bodies that
// cannot be the public key the OID names.
//
// The four-byte cases are the literal defect: that is the body every synthetic
// SubjectPublicKeyInfo in this package carried, and every one of them was
// reported as a fully formed public key. The one-byte-short and one-byte-long
// cases are what makes this an equality rather than a floor -- a floor would
// pass the long one, and would pass the short one at every threshold below the
// real size.
func TestPQCPipeline_PKIXUndersizedBodyYieldsAlgorithmNotKey(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		oid  asn1.ObjectIdentifier
		body []byte
	}{
		{"ML-DSA-65 four bytes of garbage", mlDSA65OID, noise(4)},
		{"ML-KEM-768 four bytes of garbage", mlKEM768OID, noise(4)},
		{"ML-DSA-65 one byte short", mlDSA65OID, noise(mlDSA65PubKey - 1)},
		{"ML-KEM-768 one byte short", mlKEM768OID, noise(mlKEM768EncapKey - 1)},
		// Too long is as wrong as too short: the BIT STRING is the key, with
		// no CHOICE and nothing to pad, so an extra byte means these are not
		// the bytes of an ML-DSA-65 public key.
		{"ML-DSA-65 one byte long", mlDSA65OID, noise(mlDSA65PubKey + 1)},
		{"SLH-DSA-SHA2-128S empty", slhDSA128sOID, nil},
		{"SLH-DSA-SHA2-128S one byte short", slhDSA128sOID, noise(slhDSA128sPubKey - 1)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			algorithms, material := assetsOfPub(t, pkixDERBody(t, tt.oid, tt.body))

			require.Len(t, algorithms, 1,
				"the OID establishes the algorithm is referenced, whatever the body holds")
			require.Empty(t, material,
				"a body that is not this algorithm's public key must not be reported as one")
		})
	}
}

// TestPQCPipeline_PKIXBitLengthMismatchYieldsAlgorithmNotKey covers the case
// TestPQCPipeline_PKIXUndersizedBodyYieldsAlgorithmNotKey cannot reach: a body
// with the registry's EXACT byte count, but a BitLength a few bits short of
// it.
//
// encoding/asn1's BIT STRING decoder keeps BitLength independent of Bytes: it
// requires only that the bits a padding octet declares unused are actually
// zero, never that BitLength == len(Bytes)*8. So a body can decode with the
// right byte count and a BitLength 1-7 bits short of it -- the range the wire
// format's one unused-bits octet can express -- and a check that only reads
// len(Bytes) accepts that as a full key. RFC 9909 sec. 5 (SLH-DSA), RFC 9881
// sec. 4 (ML-DSA) and RFC 9935 sec. 4 (ML-KEM) all map a whole OCTET STRING
// bit-for-bit into the BIT STRING with nothing left unused, so this is not a
// legal encoding of any of them.
func TestPQCPipeline_PKIXBitLengthMismatchYieldsAlgorithmNotKey(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name      string
		oid       asn1.ObjectIdentifier
		size      int
		bitsShort int
		algo      string
	}{
		{"ML-DSA-65 one bit short", mlDSA65OID, mlDSA65PubKey, 1, "ML-DSA-65"},
		{"ML-KEM-768 four bits short", mlKEM768OID, mlKEM768EncapKey, 4, "ML-KEM-768"},
		{"SLH-DSA-SHA2-128S seven bits short", slhDSA128sOID, slhDSA128sPubKey, 7, "SLH-DSA-SHA2-128S"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			der := pkixDERBodyWithBitLength(t, tt.oid, noise(tt.size), tt.size*8-tt.bitsShort)
			algorithms, material := assetsOfPub(t, der)
			require.Contains(t, algorithmNames(algorithms), tt.algo)
			require.Empty(t, material,
				"a body with the right byte count but the wrong declared bit count must not be reported as a key")
		})
	}
}

// TestPQCPipeline_PKIXRejectedBodyStillYieldsAUsableAlgorithm pins the half of
// the claim that survives a rejection. The OID establishes that the algorithm
// is referenced whatever the body holds, so the algorithm component still has
// to come out WHOLE -- not merely present.
//
// The rejection test above counts components, and a count cannot tell a usable
// algorithm from a broken one. Building the component before rejecting the body
// is load-bearing ordering: the obvious "why build what we are about to reject"
// refactor hoists the guard above setAlgorithmPrimitive and BOMRefHash, and
// leaves an algorithm with an empty primitive and no bom-ref.
// Builder.appendDetection drops a component that has no bom-ref, so under that
// refactor a rejected block contributes NOTHING to the CBOM -- the same silent
// disappearance this guard exists to prevent, moved one component over, and
// invisible to every assertion that only counts. That reordering passed the
// entire package before this test existed; each case below fails against it.
//
// The primitive is asserted per algorithm because algorithmPrimitive falls back
// to signature: an ML-KEM encapsulation key taking that fallback is reported as
// something that signs, which is the defect the fallback was added to stop.
func TestPQCPipeline_PKIXRejectedBodyStillYieldsAUsableAlgorithm(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		oid       asn1.ObjectIdentifier
		body      []byte
		dotted    string
		refPrefix string
		primitive cdx.CryptoPrimitive
	}{
		{
			name: "ML-DSA-65", oid: mlDSA65OID, body: noise(4),
			dotted: "2.16.840.1.101.3.4.3.18", refPrefix: "crypto/algorithm/ml-dsa-65@",
			primitive: cdx.CryptoPrimitiveSignature,
		},
		{
			name: "ML-KEM-768", oid: mlKEM768OID, body: noise(4),
			dotted: "2.16.840.1.101.3.4.4.2", refPrefix: "crypto/algorithm/ml-kem-768@",
			primitive: cdx.CryptoPrimitiveKEM,
		},
		// The unsized entries reach the same rejection through the empty-body
		// branch instead of the length comparison, so their algorithm has to
		// survive it too.
		{
			name: "XMSS", oid: xmssOID, body: nil,
			dotted: "1.3.6.1.5.5.7.6.34", refPrefix: "crypto/algorithm/xmss@",
			primitive: cdx.CryptoPrimitiveSignature,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			algorithms, material := assetsOfPub(t, pkixDERBody(t, tt.oid, tt.body))

			require.Empty(t, material, "this body is not a key")
			require.Len(t, algorithms, 1)
			algo := algorithms[0]

			require.Equal(t, tt.name, algo.Name)
			require.Equal(t, tt.dotted, algo.CryptoProperties.OID,
				"the oid is what established the algorithm in the first place")
			require.NotNil(t, algo.CryptoProperties.AlgorithmProperties)
			require.Equal(t, tt.primitive, algo.CryptoProperties.AlgorithmProperties.Primitive,
				"a KEM reported as a signature scheme is a mislabel the rejection path must not reintroduce")
			require.True(t, strings.HasPrefix(string(algo.BOMRef), tt.refPrefix),
				"Builder.appendDetection drops a component with no bom-ref, so a rejected block would vanish from the CBOM entirely: got %q",
				algo.BOMRef)
		})
	}
}

// TestPQCPipeline_PKIXOneBadKeyDoesNotTakeTheGoodOneWithIt puts a garbage
// public key and a well-sized one in a single file.
//
// Every other case here holds one block, and a one-block file cannot tell "the
// offending key was dropped" from "the file produced nothing" -- both look like
// an empty material list. Over-application is the natural failure mode of any
// guard that drops a component, and PEM bundles are routinely concatenations,
// so the claim that has to hold is that the drop is per-KEY: the garbage under
// the ML-DSA-65 OID vanishes and the well-sized ML-KEM-768 key beside it is
// still reported, from the same file, in the same pass.
//
// It also pins that the block a rejection is applied to is the block it was
// read from -- restOfPEMBundleToCDX picks that by index, an index that only has
// to be right when there is more than one block. Pinning the OID of the
// surviving key rather than just counting is what makes that visible.
func TestPQCPipeline_PKIXOneBadKeyDoesNotTakeTheGoodOneWithIt(t *testing.T) {
	t.Parallel()

	var file []byte
	file = append(file, pemPublicKey(pkixDERBody(t, mlDSA65OID, noise(4)))...)
	file = append(file, pemPublicKey(pkixDERBody(t, mlKEM768OID, noise(mlKEM768EncapKey)))...)

	algorithms, material := assetsOfPubPEM(t, file)

	require.Len(t, material, 1, "exactly one of the two blocks carries a key")
	require.Equal(t, "ML-KEM-768", material[0].Name,
		"the surviving key must be the well-sized one, not the garbage under the ML-DSA-65 OID")

	names := make([]string, 0, len(algorithms))
	for _, algo := range algorithms {
		names = append(names, algo.Name)
	}
	require.ElementsMatch(t, []string{"ML-DSA-65", "ML-KEM-768"}, names,
		"both OIDs are referenced by the file, whatever their bodies hold")
}

// TestPQCPipeline_PKIXExactSizeBodyYieldsItsKey is the other direction: a body
// of exactly the registry's size is the key, and must be reported as one.
//
// The bodies are noise of the right length, not real keys. Nothing
// distinguishes a valid ML-DSA public key from 1952 arbitrary bytes -- there is
// no content test to make -- so the length is all this can check, and that is
// exactly what it must accept.
func TestPQCPipeline_PKIXExactSizeBodyYieldsItsKey(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		oid  asn1.ObjectIdentifier
		algo string
		size int
	}{
		{"ML-DSA-65", mlDSA65OID, "ML-DSA-65", mlDSA65PubKey},
		{"ML-KEM-768", mlKEM768OID, "ML-KEM-768", mlKEM768EncapKey},
		{"SLH-DSA-SHA2-128S", slhDSA128sOID, "SLH-DSA-SHA2-128S", slhDSA128sPubKey},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			_, material := assetsOfPub(t, pkixDERBody(t, tt.oid, noise(tt.size)))

			require.Len(t, material, 1, "a %d-byte body is a %s public key", tt.size, tt.algo)
			require.Equal(t, tt.algo, material[0].Name)
			// The inverted assertion of the private-key sibling, which
			// requires Value to be EMPTY. A public key is not a secret and
			// must be published: dropping it here would cost consumers the
			// only copy of the key material the document carries.
			require.NotEmpty(t, material[0].CryptoProperties.RelatedCryptoMaterialProperties.Value,
				"a public key is not a secret and must be published")
		})
	}
}

// TestPQCPipeline_PKIXUnsizedAlgorithmRejectsOnlyAnEmptyBody covers the entries
// the registry states no size for: XMSS, XMSS-MT and HSS-LMS put their
// parameters in the key value rather than the OID (RFC 9802), so there is no
// length to compare against.
//
// Nothing can be validated there, and refusing those keys would be the worse
// error. An EMPTY body is still refused: no encoding of any key is zero bytes,
// so it is the one thing that can be ruled out without knowing the algorithm.
func TestPQCPipeline_PKIXUnsizedAlgorithmRejectsOnlyAnEmptyBody(t *testing.T) {
	t.Parallel()

	t.Run("empty body", func(t *testing.T) {
		t.Parallel()

		algorithms, material := assetsOfPub(t, pkixDERBody(t, xmssOID, nil))

		require.Len(t, algorithms, 1)
		require.Empty(t, material, "an empty body cannot hold a key of any algorithm")
	})

	t.Run("one byte", func(t *testing.T) {
		t.Parallel()

		_, material := assetsOfPub(t, pkixDERBody(t, xmssOID, noise(1)))

		require.Len(t, material, 1,
			"with no size in the registry there is nothing to check, and dropping the key is worse")
	})

	t.Run("one byte, bit-length mismatch", func(t *testing.T) {
		t.Parallel()

		_, material := assetsOfPub(t, pkixDERBodyWithBitLength(t, xmssOID, noise(1), 7))
		require.Empty(t, material,
			"no byte count is registered for XMSS, but a bit count that disagrees with the body is still refused")
	})
}

// TestPQCPipeline_PKIXRealFixturesStillYieldTheirKey is the guard against
// getting the field or the unit wrong in a way synthetic bodies would paper
// over.
//
// Every size in the registry has a sibling in bits (the schema's
// relatedCryptoMaterialProperties.size) and a sibling for the other half of the
// keypair, and a check written against any of those would still pass a test
// whose synthetic bodies were sized from the same wrong field. Real fixtures
// cannot be talked into agreeing: their BIT STRING content is 1952, 1184 and 32
// bytes because OpenSSL wrote a real key there.
func TestPQCPipeline_PKIXRealFixturesStillYieldTheirKey(t *testing.T) {
	t.Parallel()

	tests := []struct {
		fixture string
		algo    string
	}{
		{cdxtest.MLDSA65PublicKey, "ML-DSA-65"},
		{cdxtest.MLKEM768PublicKey, "ML-KEM-768"},
		{cdxtest.SLHDSASHA2128sPublicKey, "SLH-DSA-SHA2-128S"},
	}

	for _, tt := range tests {
		t.Run(tt.algo, func(t *testing.T) {
			t.Parallel()

			data, err := cdxtest.TestData(tt.fixture)
			require.NoError(t, err, "fixture %s", tt.fixture)

			_, material := assetsOfPubPEM(t, data)

			require.Len(t, material, 1, "a real %s public key must still be reported", tt.algo)
			require.Equal(t, tt.algo, material[0].Name)
		})
	}
}

// TestPQCPipeline_PKIXRejectedBodyIsLoggedAtWarn pins the operator-facing half
// of the guard, exactly as its private-key sibling does.
//
// A key dropped silently is indistinguishable, in the document and in the
// output, from a file that never held a key: the operator is told "no public
// key here" about a file they believe holds one, and nothing says why. Debug
// level is silence in a tool whose default output is not verbose.
//
// It cannot run in parallel: slog.SetDefault is process-wide.
func TestPQCPipeline_PKIXRejectedBodyIsLoggedAtWarn(t *testing.T) {
	var logBuf bytes.Buffer
	prev := slog.Default()
	t.Cleanup(func() { slog.SetDefault(prev) })
	slog.SetDefault(slog.New(slog.NewTextHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelWarn})))

	_, material := assetsOfPub(t, pkixDERBody(t, mlDSA65OID, noise(100)))
	require.Empty(t, material)

	logged := logBuf.String()
	require.Contains(t, logged, "level=WARN",
		"a dropped key at Debug level is a silently dropped key")
	require.Contains(t, logged, "not reporting a public key")
	require.Contains(t, logged, "algorithm=ML-DSA-65",
		"the operator has to know which key was dropped")
	require.Contains(t, logged, "body_bytes=100",
		"and what was wrong with it")
}
