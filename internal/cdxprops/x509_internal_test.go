package cdxprops

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"strings"
	"testing"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/OmniTrustILM/cbom-lens/internal/cdxprops/cdxtest"
	"github.com/OmniTrustILM/cbom-lens/internal/cdxprops/ilm"
	"github.com/OmniTrustILM/cbom-lens/internal/model"

	"github.com/stretchr/testify/require"
)

func Test_certSPKI(t *testing.T) {
	t.Parallel()

	selfSigned, err := cdxtest.GenSelfSignedCert()
	require.NoError(t, err)

	spki, ok := certSPKI(selfSigned.Cert)
	require.True(t, ok)
	require.Equal(t, "1.2.840.113549.1.1.1", spki.Algorithm.Algorithm.String())
	// The body is the half spkiOID could not return, and the half the guard in
	// publicKeyComponents rests on: a decode that reported the OID and dropped
	// the BIT STRING would leave that guard measuring nothing.
	require.NotEmpty(t, spki.PublicKey.Bytes)

	selfSigned.Cert.RawSubjectPublicKeyInfo = []byte("garbage")
	spki, ok = certSPKI(selfSigned.Cert)
	require.False(t, ok)
	require.Equal(t, pkixStruct{}, spki,
		"a failed decode must not hand back a half-filled structure for a "+
			"caller to read an OID or a length out of")
}

// Test_certSPKI_RealCertificateFixturesMatchTheRegistry is the units check the
// certificate guard rests on, made a committed assertion.
//
// registryPublicKeyBodySize returns byte counts, and the BIT STRING inside a
// certificate is one byte longer on the wire than its content because DER puts
// an unused-bits octet in front of it. asn1.BitString.Bytes excludes that octet,
// so the two are directly comparable -- but "directly comparable" is a claim
// about a decoder, and the way to retire it is to measure three real
// certificates OpenSSL wrote real keys into. Their subjectPublicKey BIT STRINGs
// are 1953, 1185 and 33 bytes on the wire; the wants below are those minus one.
//
// The wants are literals rather than reads from the registry, for the same
// reason the constants in pqc_pubkey_body_shape_test.go are: a failure has to
// say the registry changed, not change with it.
//
// require.Nil on cert.PublicKey is a precondition, not an observation. These
// three fixtures reach the guarded branch precisely because Go did not parse
// their keys; if a future Go learns ML-DSA, they stop exercising the branch and
// this test would go on passing while measuring a path nothing takes.
func Test_certSPKI_RealCertificateFixturesMatchTheRegistry(t *testing.T) {
	t.Parallel()

	for name, tt := range map[string]struct {
		fixture string
		algo    string
		// want is the registry's byte count for this algorithm's public key:
		// FIPS 204 Table 2 for ML-DSA-65, FIPS 203 Table 3 for ML-KEM-768's
		// encapsulation key, FIPS 205 Table 2 for SLH-DSA-SHA2-128s.
		want int
	}{
		"ML-DSA-65":         {cdxtest.MLDSA65Certificate, "ML-DSA-65", 1952},
		"ML-KEM-768":        {cdxtest.MLKEM768Certificate, "ML-KEM-768", 1184},
		"SLH-DSA-SHA2-128S": {cdxtest.SLHDSASHA2128sCertificate, "SLH-DSA-SHA2-128S", 32},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			data, err := cdxtest.TestData(tt.fixture)
			require.NoError(t, err)
			block, _ := pem.Decode(data)
			require.NotNil(t, block)
			require.Equal(t, "CERTIFICATE", block.Type)

			cert, err := x509.ParseCertificate(block.Bytes)
			require.NoError(t, err)
			require.Nil(t, cert.PublicKey,
				"this fixture is here for the branch Go's parser leaves empty")

			spki, ok := certSPKI(cert)
			require.True(t, ok, "a certificate's SPKI decodes by construction")

			info, ok := unsupportedAlgorithms[spki.Algorithm.Algorithm.String()]
			require.True(t, ok, "the registry must name %s", tt.algo)
			require.Equal(t, tt.algo, info.name)

			require.Equal(t, tt.want, registryPublicKeyBodySize(info),
				"the registry's byte count for %s", tt.algo)
			require.Equal(t, tt.want, len(spki.PublicKey.Bytes),
				"the fixture's BIT STRING content, with the unused-bits octet excluded")
			require.Equal(t, tt.want*8, spki.PublicKey.BitLength,
				"the fixture's declared bit count, with no unused bits")
			require.Empty(t, rejectPublicKeyBody(info, spki.PublicKey),
				"a real %s certificate must survive the check its garbage twin fails", tt.algo)
		})
	}
}

// Test_rejectPublicKeyBody_BitLengthMustMatchBytes pins the guard directly
// against the unit rejectPublicKeyBody is: a BitLength that disagrees with
// len(Bytes)*8 must be refused even when len(Bytes) alone is exactly the
// registry's want, because encoding/asn1's BIT STRING decoder never requires
// the two to agree (it only requires the padding octet's declared-unused bits
// to be zero -- see parseBitString in GOROOT's encoding/asn1/asn1.go).
//
// Built by hand rather than through a DER round-trip: asn1.BitString{Bytes,
// BitLength} is exactly the shape rejectPublicKeyBody reads, and the internal
// test package can call it directly without going through unsupportedPKIX or
// a PEM envelope.
func Test_rejectPublicKeyBody_BitLengthMustMatchBytes(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name  string
		oid   asn1.ObjectIdentifier
		delta int // relative to byteWant*8
	}{
		{"ML-DSA-65 one bit short", mlDSA65OID, -1},
		{"ML-KEM-768 four bits short", mlKEM768OID, -4},
		{"ML-DSA-65 one bit long (unreachable off the wire, checked anyway)", mlDSA65OID, 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			info, ok := unsupportedAlgorithms[tt.oid.String()]
			require.True(t, ok)
			byteWant := registryPublicKeyBodySize(info)
			require.NotZero(t, byteWant)

			body := asn1.BitString{Bytes: make([]byte, byteWant), BitLength: byteWant*8 + tt.delta}
			reason := rejectPublicKeyBody(info, body)
			require.NotEmpty(t, reason)
			require.NotEqual(t, fmt.Sprintf("not a %d-byte public key", byteWant), reason,
				"a right-byte-count body failing for the OLD reason means the bit-length check never ran")
		})
	}
}

// TestOIDPlaceholder_IsTheSentinelEveryProducerStamps pins the VALUE of
// oidPlaceholder, which nothing else in the package does.
//
// csrToCDX's guard reads algo.CryptoProperties.OID == oidPlaceholder and
// extractAlgorithmInfo's default branch writes meta.oid = oidPlaceholder, so
// the suppression stays correct under any value the two happen to share:
// rewriting the constant to "0.0.0.1" leaves the whole cdxprops suite green.
// That is not the same as the value being free. It is wire-visible. Every path
// that keeps the placeholder still ships it as cryptoProperties.oid -- a
// standalone X25519 PUBLIC KEY block does exactly that today, because
// ParsePKIXPublicKey succeeds on it, getPublicKeyAlgorithm has no case for
// *ecdh.PublicKey, and restOfPEMBundleToCDX appends the algorithm
// unconditionally -- so the constant is part of what a consumer reads, and
// moving it silently moves documents.
//
// It is also copied. hash.go's unsupportedInfo carries its own "0.0.0.0"
// literal for a hash nothing names, and Test_readSignatureAlgorithmRef below
// and signature_algorithm_test.go hand the literal in by hand as an oidFallback;
// not one of them moves with the constant. The doc comment on oidPlaceholder
// tells the next producer to TEST for this value, so the day the copies diverge
// that test stops matching and the fabricated component it exists to catch
// sails past it -- with every other assertion still green, exactly as they were
// while this constant was rewritten.
func TestOIDPlaceholder_IsTheSentinelEveryProducerStamps(t *testing.T) {
	t.Parallel()

	require.Equal(t, "0.0.0.0", oidPlaceholder,
		"the sentinel is emitted, not private: changing it changes every "+
			"document that still carries a placeholder")

	require.Equal(t, oidPlaceholder, unsupportedInfo.OID,
		"hash.go keeps its own copy of the literal, so a hash nothing names "+
			"and a key algorithm nothing names must not drift apart")

	// The two ends of csrToCDX's guard, stated at the seam rather than left to
	// the end-to-end tests that catch it only incidentally, via the name.
	require.Equal(t, oidPlaceholder,
		extractAlgorithmInfo("no key type maps to this", nil).oid,
		"the default branch must stamp the value the guard tests for")
	require.Equal(t, oidPlaceholder,
		publicKeyAlgorithmInfo(x509.UnknownPublicKeyAlgorithm, nil).oid,
		"and this is the exact call csrToCDX makes for a request Go could "+
			"not read")
}

func Test_readSignatureAlgorithmRef(t *testing.T) {
	t.Parallel()

	selfSigned, err := cdxtest.GenSelfSignedCert()
	require.NoError(t, err)

	res := readSignatureAlgorithmRef(t.Context(), selfSigned.Cert, "")
	exp := cdx.BOMReference("crypto/algorithm/sha-256-rsa@1.2.840.113549.1.1.11")
	require.Equal(t, exp, res)

	selfSigned.Cert.SignatureAlgorithm = -1
	res = readSignatureAlgorithmRef(t.Context(), selfSigned.Cert, "2.16.840.1.101.3.4.3.17")
	exp = cdx.BOMReference("crypto/algorithm/ml-dsa-44@2.16.840.1.101.3.4.3.17")
	require.Equal(t, exp, res)

	res = readSignatureAlgorithmRef(t.Context(), selfSigned.Cert, "")
	exp = cdx.BOMReference("crypto/algorithm/unknown@unknown")
	require.Equal(t, exp, res)

	res = readSignatureAlgorithmRef(t.Context(), selfSigned.Cert, "0.0.0.0")
	exp = cdx.BOMReference("crypto/algorithm/unknown@unknown")
	require.Equal(t, exp, res)
}

func Test_sigAlgOID(t *testing.T) {
	t.Parallel()
	selfSigned, err := cdxtest.GenSelfSignedCert()
	require.NoError(t, err)

	res := sigAlgOID(selfSigned.Cert)
	require.Equal(t, "1.2.840.113549.1.1.11", res)

	selfSigned.Cert.Raw = []byte("broken")
	res = sigAlgOID(selfSigned.Cert)
	require.Equal(t, "", res)

}

func TestConverter_certConverter(t *testing.T) {
	t.Parallel()
	c := NewConverter().WithIlmExtensions(true)

	selfSigned, err := cdxtest.GenSelfSignedCert()
	require.NoError(t, err)

	compo := c.certComponent(t.Context(), model.CertHit{
		Cert:     selfSigned.Cert,
		Source:   "cdxtest",
		Location: t.Name(),
	})

	require.NotZero(t, compo)
}

// TestCertComponent_PublishesItsKeyUsage is where the fact this fix takes off
// the algorithm asset has to reappear, and it is stated over the VANILLA
// document on purpose.
//
// KeyUsage used to be published, lossily, as the RSA algorithm's primitive:
// signature or pke, on the algorithm component, in every non-ILM document, and
// hashed into that component's bom-ref. Moving it here has to keep it in the
// plain CycloneDX output or the fix would REMOVE information from every non-ILM
// consumer -- which is why it is not behind --ilm the way
// ilm.CertificateProperties is. That gate is right for ILM-specific enrichment;
// a keyUsage extension parsed out of a standard X.509 certificate is not
// enrichment. pem_type, subject, issuer and revoked_count are already emitted
// un-namespaced and ungated for the same reason.
//
// The value is asserted as one exact string, which is the assertion a map-based
// implementation cannot pass: with nine bits to name, Go's randomised map
// iteration would deliver this order roughly once in 24 runs. RFC 5280 sec.
// 4.2.1.3's BIT STRING bit order is the emitted order, and the identifiers are
// that section's ASN.1 names -- nonRepudiation for bit 1, which Go calls
// KeyUsageContentCommitment after the newer spelling.
//
// A certificate with no keyUsage extension carries no such property rather than
// an empty-valued one: RFC 5280 requires at least one bit set when the extension
// is present, so zero bits means the certificate asserts nothing, and a property
// whose value is "" asserts nothing while looking like an assertion.
func TestCertComponent_PublishesItsKeyUsage(t *testing.T) {
	t.Parallel()

	const allFour = x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment |
		x509.KeyUsageCertSign | x509.KeyUsageCRLSign

	// Spelled out rather than taken from propKeyUsage. The emitted name is the
	// contract with every consumer of the document, so renaming the constant
	// must fail here rather than silently rename the property.
	const wantName = "key_usage"

	countNamed := func(compo cdx.Component, name string) (int, string) {
		var n int
		var value string
		if compo.Properties == nil {
			return 0, ""
		}
		for _, p := range *compo.Properties {
			if p.Name == name {
				n++
				value = p.Value
			}
		}
		return n, value
	}

	certComponentFor := func(t *testing.T, c Converter, cert *x509.Certificate) cdx.Component {
		t.Helper()
		compos, _, err := c.certHitToComponents(t.Context(),
			model.CertHit{Cert: cert, Source: "PEM", Location: "/etc/ssl/certs/fixture.pem"})
		require.NoError(t, err)
		for _, compo := range compos {
			if compo.CryptoProperties != nil &&
				compo.CryptoProperties.AssetType == cdx.CryptoAssetTypeCertificate {
				return compo
			}
		}
		t.Fatal("no certificate component emitted")
		return cdx.Component{}
	}

	t.Run("vanilla", func(t *testing.T) {
		t.Parallel()

		compo := certComponentFor(t, NewConverter(), selfSignedRSACert(t, allFour))

		n, value := countNamed(compo, wantName)
		require.Equal(t, 1, n, "exactly one key_usage property")
		require.Equal(t, "digitalSignature,keyEncipherment,keyCertSign,cRLSign", value,
			"RFC 5280 sec. 4.2.1.3 identifiers, in that section's bit order, "+
				"comma-separated with no spaces")

		require.NotNil(t, compo.Properties)
		require.Len(t, *compo.Properties, 1,
			"--ilm is off, so key_usage is the only property a certificate carries")
	})

	t.Run("ilm", func(t *testing.T) {
		t.Parallel()

		compo := certComponentFor(t,
			NewConverter().WithIlmExtensions(true), selfSignedRSACert(t, allFour))

		n, value := countNamed(compo, wantName)
		require.Equal(t, 1, n)
		require.Equal(t, "digitalSignature,keyEncipherment,keyCertSign,cRLSign", value)

		// The ILM properties are additional, not alternative: turning --ilm on
		// must not displace the vanilla fact, and turning it off must not take
		// the ILM ones' place.
		for _, name := range []string{
			ilm.CertificateSourceFormat,
			ilm.CertificateBase64Content,
			ilm.CertificateFingerprint,
		} {
			got, _ := countNamed(compo, name)
			require.Equal(t, 1, got, "%s", name)
		}
	})

	t.Run("no keyUsage extension", func(t *testing.T) {
		t.Parallel()

		compo := certComponentFor(t, NewConverter(), selfSignedRSACert(t, 0))

		require.Nil(t, compo.Properties,
			"a certificate that constrains nothing must publish no constraint, "+
				"and an empty properties array is not the same as no claim")
	})
}

// TestCertHitToComponents_NoMaterialPropsOnCertificate pins the removal of
// certificateRelatedProperties (#213).
//
// That helper created an empty relatedCryptoMaterialProperties on every
// certificate and wrote nothing into it, which is what produced the
// "relatedCryptoMaterialProperties": {} blocks in the goldens and made every
// certificate answer "yes" to "is this key material?". The certificate's own
// properties -- including the two refs certHitToComponents writes right after
// the deleted call -- must be untouched by its removal.
//
// This is deliberately at the certHitToComponents level rather than per
// caller. Every certificate in the tool comes through here: the PEM bundle via
// Converter.PEMBundle, a scanned file via Converter.CertHit, and a TLS service
// via Converter.NMAP -> tlsToCompos, which forwards TLSCerts to CertHit. So the
// deletion's whole blast radius is one function, pinned once. The golden corpus
// covers the emitted end of it, including a certificate lifted from the nmap
// fixture (see buildRepresentativeCorpus in internal/bom).
func TestCertHitToComponents_NoMaterialPropsOnCertificate(t *testing.T) {
	t.Parallel()

	selfSigned, err := cdxtest.GenSelfSignedCert()
	require.NoError(t, err)

	compos, _, err := NewConverter().certHitToComponents(
		t.Context(),
		model.CertHit{Cert: selfSigned.Cert, Source: "cdxtest", Location: t.Name()},
	)
	require.NoError(t, err)

	var found bool
	for _, compo := range compos {
		if compo.CryptoProperties == nil ||
			compo.CryptoProperties.AssetType != cdx.CryptoAssetTypeCertificate {
			continue
		}
		found = true

		require.Nil(t, compo.CryptoProperties.RelatedCryptoMaterialProperties,
			"a certificate is not key material: its encoding belongs in "+
				"certificateProperties.certificateFormat (#213)")

		certProps := compo.CryptoProperties.CertificateProperties
		require.NotNil(t, certProps)
		require.NotEmpty(t, certProps.SignatureAlgorithmRef)
		require.NotEmpty(t, certProps.SubjectPublicKeyRef)
	}
	require.True(t, found, "no certificate component emitted")
}

// TestPKCS8Struct_ParsesRFC5958TrailingFields pins the assumption that made it
// safe to add PrivateKey to pkcs8Struct.
//
// RFC 5958's OneAsymmetricKey extends RFC 5208's PrivateKeyInfo with two
// trailing optional elements, attributes [0] and publicKey [1]. pkcs8Struct
// declares neither, so if Go's asn1 rejected undeclared trailing elements the
// size check would reject every key encoded that way -- and the failure would
// be the exact one the check exists to prevent, only inverted: a real key
// reported as absent.
//
// It does not: encoding/asn1 tolerates extra elements at the end of a SEQUENCE
// so sequences can be extended. The three corpus fixtures do not exercise this
// (all three unmarshal with zero trailing bytes), so it is pinned explicitly
// here rather than left to a fixture that might be regenerated.
func TestPKCS8Struct_ParsesRFC5958TrailingFields(t *testing.T) {
	t.Parallel()

	body := make([]byte, 4032)
	der, err := asn1.Marshal(struct {
		Version    int
		Algo       pkix.AlgorithmIdentifier
		PrivateKey []byte
		PublicKey  asn1.BitString `asn1:"tag:1,optional"`
	}{
		Version:    0,
		Algo:       pkix.AlgorithmIdentifier{Algorithm: asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 18}},
		PrivateKey: body,
		PublicKey:  asn1.BitString{Bytes: make([]byte, 1952), BitLength: 1952 * 8},
	})
	require.NoError(t, err)

	var pkcs8 pkcs8Struct
	rest, err := asn1.Unmarshal(der, &pkcs8)
	require.NoError(t, err, "a OneAsymmetricKey encoding must still parse")
	require.Empty(t, rest)
	require.Equal(t, "2.16.840.1.101.3.4.3.18", pkcs8.Algo.Algorithm.String())
	require.Len(t, pkcs8.PrivateKey, len(body),
		"the trailing publicKey must not bleed into the measured body")

	// And it must survive the size check rather than be discarded as too small.
	key, algo, err := NewConverter().unsupportedPKCS8PrivateKey(t.Context(), der)
	require.NoError(t, err)
	require.Equal(t, "ML-DSA-65", algo.Name)
	require.NotNil(t, key, "a full-size body must yield a key component")
	require.NotEmpty(t, key.BOMRef)
}

// wantSignatureAlg is a hand-written expectation for one call to
// signatureAlgorithmComponents: the algorithm component's Name, the identity
// half of its bom-ref, the OID read out of the DER, and the name of the hash it
// decomposes into -- empty when it decomposes into none.
//
// The digest half of the bom-ref is deliberately not stated. BOMRefHash hashes
// the component's own JSON, which carries implementationPlatform, so the digest
// is a function of the machine the test runs on and pinning it here would pin
// GOARCH. What the two paths below share is asserted by comparing them to each
// other, digest included.
type wantSignatureAlg struct {
	name    string
	refName string
	oid     string
	hash    string
}

// ecdsaSHA256Components is the expectation a P-256 certificate and a revocation
// list signed by it must BOTH meet, stated once so that "both paths agree" and
// "both paths are right" are the same assertion.
var ecdsaSHA256Components = wantSignatureAlg{
	name:    "ECDSA-SHA256",
	refName: "crypto/algorithm/sha-256-ecdsa",
	oid:     "1.2.840.10045.4.3.2",
	hash:    "SHA-256",
}

// TestSignatureAlgorithmComponents_PinsAlgorithmAndHash writes down what the
// shared core puts in a document for a signed PKIX structure.
//
// Its predecessor asserted signatureAlgorithmComponents against
// certHitToSignatureAlgComponent, a one-line delegation to it. That equality
// holds for any body the pair could have -- one that names every algorithm
// "MUTANT", or ignores the OID fallback, or reads no OID at all -- so it went
// green under mutations of everything it appeared to cover. Values written by
// hand are the only ones that go red when the core is wrong.
//
// The four rows are chosen for the paths they reach. ECDSA is answered by Go's
// enum alone. Ed25519 is answered by the enum too and still decomposes into
// SHA-512, because RFC 8032 builds it on SHA-512 -- it is not the no-hash case,
// and two production comments used to say it was. ML-DSA and SLH-DSA are real
// fixtures whose algorithms Go's enum does not name, so their names, their refs
// and their parameters all have to come from the OID in the certificate's own
// DER; ML-DSA is the row with no hash, and SLH-DSA-SHA2 is the one that takes
// that same OID-only route and still decomposes, into the SHA-256 its parameter
// set is built on.
//
// Those two rows are also where the registry's two name-like fields have to be
// told apart. An entry carries a name, "ML-DSA-65", which is what a reader of
// the document sees, and an algorithmName, "crypto/algorithm/ml-dsa-65", which
// is the path BOMRefHash turns into a bom-ref. The sigAlg.String()=="0"
// fallback assigned the latter where the former belonged, so every
// post-quantum-signed structure named its algorithm by its own ref path. Name
// and refName are stated separately below because they are separate things: the
// name moves when that is fixed, the ref path does not.
func TestSignatureAlgorithmComponents_PinsAlgorithmAndHash(t *testing.T) {
	t.Parallel()

	for name, tt := range map[string]struct {
		cert func(t *testing.T) *x509.Certificate
		want wantSignatureAlg
	}{
		"ECDSA": {
			cert: func(t *testing.T) *x509.Certificate {
				return certSignedWith(t, x509.ECDSAWithSHA256)
			},
			want: ecdsaSHA256Components,
		},
		"Ed25519": {
			cert: func(t *testing.T) *x509.Certificate {
				return certSignedWith(t, x509.PureEd25519)
			},
			want: wantSignatureAlg{
				name:    "Ed25519",
				refName: "crypto/algorithm/ed25519",
				oid:     "1.3.101.112",
				hash:    "SHA-512",
			},
		},
		"ML-DSA": {
			cert: mlDSA65Cert,
			want: wantSignatureAlg{
				name:    "ML-DSA-65",
				refName: "crypto/algorithm/ml-dsa-65",
				oid:     "2.16.840.1.101.3.4.3.18",
				hash:    "",
			},
		},
		"SLH-DSA": {
			cert: slhDSASHA2128sCert,
			want: wantSignatureAlg{
				name:    "SLH-DSA-SHA2-128S",
				refName: "crypto/algorithm/slh-dsa-sha2-128s",
				oid:     "2.16.840.1.101.3.4.3.20",
				hash:    "SHA-256",
			},
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			cert := tt.cert(t)
			sigAlgCompo, hashAlgCompo := NewConverter().certHitToSignatureAlgComponent(
				t.Context(),
				model.CertHit{Cert: cert, Source: "cdxtest", Location: t.Name()},
			)
			requireSignatureAlgComponents(t, tt.want, sigAlgCompo, hashAlgCompo)
		})
	}
}

// TestSignatureAlgorithmComponents_OIDOnlyEdgeCases states the other two ends
// of the same fallback the table above enters, neither of which any fixture in
// the tree reaches: the OID misses the registry entirely, and the OID hits an
// entry that is not a signature scheme at all.
//
// A miss leaves the Name as the string x509.SignatureAlgorithm(0) prints for
// itself, "0". That is a poor name for an algorithm and it is pinned as one
// deliberately: it is produced one line above the assignment this commit
// changed, and the value it could drift to is the empty string -- which Builder
// drops, leaving the signed structure's algorithm ref pointing at a component
// that is not in the document.
//
// The three ML-KEM OIDs are keys in the registry the fallback reads, so a
// malformed certificate or list declaring one where a signature scheme belongs
// is named for the KEM it is, and carries a KEM's primitive and functions
// rather than a half-answer of `primitive: signature` beside
// `cryptoFunctions: [decapsulate, encapsulate]`. Its ref stem stays
// crypto/algorithm/unknown either way, because pqcSigOIDRef excludes the KEM
// OIDs -- which makes it the one input proving the Name and the ref come from
// different lookups and are free to disagree.
func TestSignatureAlgorithmComponents_OIDOnlyEdgeCases(t *testing.T) {
	t.Parallel()

	c := NewConverter()

	for name, tt := range map[string]struct {
		sigAlgOID []byte
		want      wantSignatureAlg
		primitive cdx.CryptoPrimitive
		functions []cdx.CryptoFunction
	}{
		"registry miss": {
			// 2.16.840.1.101.3.4.3.99, unassigned: the arc the ML-DSA and
			// SLH-DSA identifiers live on, in neither pqcSigOIDRef nor
			// unsupportedAlgorithms.
			sigAlgOID: []byte{0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x63},
			want: wantSignatureAlg{
				name:    "0",
				refName: "crypto/algorithm/unknown",
				oid:     "2.16.840.1.101.3.4.3.99",
				hash:    "",
			},
			primitive: cdx.CryptoPrimitiveSignature,
			functions: []cdx.CryptoFunction{cdx.CryptoFunctionSign},
		},
		"KEM in the signature slot": {
			// 2.16.840.1.101.3.4.4.1, id-alg-ml-kem-512.
			sigAlgOID: []byte{0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x04, 0x01},
			want: wantSignatureAlg{
				name:    "ML-KEM-512",
				refName: "crypto/algorithm/unknown",
				oid:     "2.16.840.1.101.3.4.4.1",
				hash:    "",
			},
			primitive: cdx.CryptoPrimitiveKEM,
			functions: []cdx.CryptoFunction{
				cdx.CryptoFunctionDecapsulate,
				cdx.CryptoFunctionEncapsulate,
			},
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			sigAlgCompo, hashAlgCompo := c.signatureAlgorithmComponents(
				t.Context(),
				x509.UnknownSignatureAlgorithm,
				certDERWithSignatureOID(t, tt.sigAlgOID),
			)
			requireSignatureAlgComponents(t, tt.want, sigAlgCompo, hashAlgCompo)

			algoProps := sigAlgCompo.CryptoProperties.AlgorithmProperties
			require.NotNil(t, algoProps)
			require.Equal(t, tt.primitive, algoProps.Primitive)
			require.NotNil(t, algoProps.CryptoFunctions)
			require.Equal(t, tt.functions, *algoProps.CryptoFunctions,
				"the primitive and the functions must come from one entry")
		})
	}
}

// certDERWithSignatureOID rewrites the ML-DSA-65 OID in the fixture
// certificate's DER with the one given.
//
// It is crlWithSubstitutedSignatureOID's technique applied to a certificate and
// for the same reason: the replacement encodes to the same nine bytes, so every
// enclosing ASN.1 length stays correct, and nothing on this path verifies the
// signature the substitution invalidates. Generating the certificate instead is
// not an option, because x509.CreateCertificate will not sign with an algorithm
// it cannot name, and an algorithm Go cannot name is the state under test.
//
// The self-signed fixture carries the OID three times: tbsCertificate.signature,
// the SubjectPublicKeyInfo and the outer signatureAlgorithm. All three are
// replaced and only the last is read, which is why this returns DER rather than
// a parsed certificate -- signatureAlgorithmComponents takes the enum and the
// bytes, so nothing has to accept the result as a certificate again.
func certDERWithSignatureOID(t *testing.T, oid []byte) []byte {
	t.Helper()

	// 2.16.840.1.101.3.4.3.18, id-ml-dsa-65.
	from := []byte{0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x12}
	require.Len(t, oid, len(from),
		"a replacement of a different length moves every enclosing ASN.1 length")

	raw := mlDSA65Cert(t).Raw
	require.Equal(t, 3, bytes.Count(raw, from),
		"the OID must appear exactly three times, or the substitution is not the one described")
	return bytes.ReplaceAll(raw, from, oid)
}

// TestSignatureAlgorithmComponents_CertificateAndCRLShareTheCore states the
// property the extraction was for: a certificate and a revocation list signed
// with the same algorithm describe that algorithm identically, down to the
// content-addressed bom-ref, because both hand the same two values -- the
// algorithm enum and the DER -- to one function.
//
// Equality alone would be satisfied by two identically wrong components, so
// both sides are also held to ecdsaSHA256Components. If crlToCDX ever passed
// something else -- the TBS bytes, the issuing certificate's algorithm, a
// constant -- one side moves and the pair of components in a document holding
// both a certificate and its CRL becomes two refs for one algorithm.
func TestSignatureAlgorithmComponents_CertificateAndCRLShareTheCore(t *testing.T) {
	t.Parallel()

	ca, err := cdxtest.CertBuilder{}.
		WithIsCA(true).
		WithSignatureAlgorithm(x509.ECDSAWithSHA256).
		WithKeyUsage(x509.KeyUsageCRLSign | x509.KeyUsageCertSign).
		Generate()
	require.NoError(t, err)
	signer, ok := ca.Key.(crypto.Signer)
	require.True(t, ok)

	crl, _, err := cdxtest.GenCRL(ca.Cert, signer)
	require.NoError(t, err)
	require.Equal(t, x509.ECDSAWithSHA256, crl.SignatureAlgorithm,
		"the list must be signed with the algorithm under test, or the two "+
			"paths are being compared on different inputs")

	c := NewConverter()
	certSig, certHash := c.certHitToSignatureAlgComponent(
		t.Context(),
		model.CertHit{Cert: ca.Cert, Source: "cdxtest", Location: t.Name()},
	)
	requireSignatureAlgComponents(t, ecdsaSHA256Components, certSig, certHash)

	compos, deps := c.crlToCDX(t.Context(), crl)
	var crlSig, crlHash cdx.Component
	for _, compo := range compos {
		if compo.CryptoProperties == nil || compo.CryptoProperties.AlgorithmProperties == nil {
			continue
		}
		if compo.CryptoProperties.AlgorithmProperties.Primitive == cdx.CryptoPrimitiveHash {
			crlHash = compo
			continue
		}
		crlSig = compo
	}
	requireSignatureAlgComponents(t, ecdsaSHA256Components, crlSig, &crlHash)

	require.Equal(t, certSig, crlSig,
		"one algorithm, one component: a list and a certificate signed the same "+
			"way must not produce two")
	require.Equal(t, *certHash, crlHash)

	require.Len(t, deps, 1)
	require.Equal(t, crlSig.BOMRef, deps[0].Ref)
	require.NotNil(t, deps[0].Dependencies)
	require.Equal(t, []string{crlHash.BOMRef}, *deps[0].Dependencies,
		"the edge must name the hash component the list actually carries")
}

// requireSignatureAlgComponents states want over one pair of returns from
// signatureAlgorithmComponents.
func requireSignatureAlgComponents(t *testing.T, want wantSignatureAlg, sigAlgCompo cdx.Component, hashAlgCompo *cdx.Component) {
	t.Helper()

	require.Equal(t, want.name, sigAlgCompo.Name)
	require.NotNil(t, sigAlgCompo.CryptoProperties)
	require.Equal(t, want.oid, sigAlgCompo.CryptoProperties.OID)

	refName, digest, found := strings.Cut(sigAlgCompo.BOMRef, "@")
	require.True(t, found, "a bom-ref is name@digest, got %q", sigAlgCompo.BOMRef)
	require.Equal(t, want.refName, refName)
	require.Regexp(t, `^sha256:[0-9a-f]{64}$`, digest)

	if want.hash == "" {
		require.Nil(t, hashAlgCompo, "%s decomposes into nothing", want.name)
		return
	}
	require.NotNil(t, hashAlgCompo, "%s decomposes into %s", want.name, want.hash)
	require.Equal(t, want.hash, hashAlgCompo.Name)
	require.Equal(t, "crypto/algorithm/"+strings.ToLower(want.hash),
		strings.Split(hashAlgCompo.BOMRef, "@")[0])
}

// certSignedWith generates a self-signed certificate carrying the given
// signature algorithm, and checks that it really carries it: CertBuilder falls
// back to RSA for anything it cannot key, which would silently turn a row of
// the table above into a second copy of the RSA row.
func certSignedWith(t *testing.T, algo x509.SignatureAlgorithm) *x509.Certificate {
	t.Helper()

	gen, err := cdxtest.CertBuilder{}.WithSignatureAlgorithm(algo).Generate()
	require.NoError(t, err)
	require.Equal(t, algo, gen.Cert.SignatureAlgorithm)
	return gen.Cert
}

// mlDSA65Cert loads the ML-DSA-65 certificate fixture. Go parses it and leaves
// SignatureAlgorithm at UnknownSignatureAlgorithm, which is the state that
// makes the OID in the DER the only thing left to identify the algorithm by.
func mlDSA65Cert(t *testing.T) *x509.Certificate {
	t.Helper()

	data, err := cdxtest.TestData(cdxtest.MLDSA65Certificate)
	require.NoError(t, err)
	block, _ := pem.Decode(data)
	require.NotNil(t, block)

	cert, err := x509.ParseCertificate(block.Bytes)
	require.NoError(t, err)
	require.Equal(t, x509.UnknownSignatureAlgorithm, cert.SignatureAlgorithm,
		"the fixture is here for the algorithm Go's enum does not name")
	return cert
}

// slhDSASHA2128sCert loads the SLH-DSA-SHA2-128s certificate fixture, which is
// self-signed and so is signed with the scheme its subject key names. It is the
// second unnamed-by-Go algorithm, and unlike ML-DSA it decomposes into a hash,
// so it covers the OID-only path in the shape that also returns a hash
// component.
func slhDSASHA2128sCert(t *testing.T) *x509.Certificate {
	t.Helper()

	data, err := cdxtest.TestData(cdxtest.SLHDSASHA2128sCertificate)
	require.NoError(t, err)
	block, _ := pem.Decode(data)
	require.NotNil(t, block)

	cert, err := x509.ParseCertificate(block.Bytes)
	require.NoError(t, err)
	require.Equal(t, x509.UnknownSignatureAlgorithm, cert.SignatureAlgorithm,
		"the fixture is here for the algorithm Go's enum does not name")
	return cert
}

func Test_hashRawPublicKey(t *testing.T) {
	t.Parallel()
	data, err := cdxtest.TestData(cdxtest.MLDSA65PublicKey)
	require.NoError(t, err)
	block, _ := pem.Decode(data)
	require.Equal(t, "PUBLIC KEY", block.Type)

	c := NewConverter()
	value, hash := c.hashRawPublicKey(block.Bytes)
	require.NotEmpty(t, value)
	require.Equal(t, cdxtest.MLDSA65PublicKeyHash, hash)
}
