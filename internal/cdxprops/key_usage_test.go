package cdxprops

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"testing"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/OmniTrustILM/cbom-lens/internal/model"

	"github.com/stretchr/testify/require"
)

// allNineKeyUsages is every bit RFC 5280 sec. 4.2.1.3 defines, OR-ed together.
// Go's constants are 1<<0 .. 1<<8 in the RFC's own bit order, so this is 511,
// and x509.CreateCertificate round-trips all nine.
const allNineKeyUsages = x509.KeyUsageDigitalSignature |
	x509.KeyUsageContentCommitment |
	x509.KeyUsageKeyEncipherment |
	x509.KeyUsageDataEncipherment |
	x509.KeyUsageKeyAgreement |
	x509.KeyUsageCertSign |
	x509.KeyUsageCRLSign |
	x509.KeyUsageEncipherOnly |
	x509.KeyUsageDecipherOnly

// TestCertificateKeyUsage_NamesEveryRFC5280BitCorrectly pins the identifier
// this package publishes for each of the nine keyUsage bits.
//
// The value of the key_usage property is a wire contract: it is the whole of
// what #217 left of the certificate's declared intent, after that intent stopped
// being smuggled through the RSA algorithm's primitive. Its shape is chosen so a
// later 1.7 promotion can reuse it verbatim as a certificateExtensions
// commonExtensionValue, which means the spelling of each name matters as much as
// the set of names.
//
// Four bits were pinned before this test and five were not. Renaming
// nonRepudiation, dataEncipherment, keyAgreement, encipherOnly or decipherOnly to
// anything at all passed the entire suite, because no fixture and no test sets
// them: the golden corpus's one key_usage-bearing certificate declares
// digitalSignature and keyEncipherment, and the only other test adds keyCertSign
// and cRLSign.
//
// The expected names are RFC 5280 sec. 4.2.1.3's own ASN.1 identifiers, read off
// the RFC and not off the implementation. Two are easy to get wrong and are
// therefore the point of this table:
//
//   - bit 1 is nonRepudiation. That is the identifier in the RFC's BIT STRING
//     definition; the RFC notes in prose that recent editions of X.509 renamed
//     it to contentCommitment, and Go named its constant after the newer
//     spelling. Following Go's constant name here would publish a name RFC 5280
//     does not define.
//   - bit 6 is cRLSign, with a lowercase c and an uppercase RL. Neither crlSign
//     nor CRLSign is the identifier, and Go's KeyUsageCRLSign invites both.
//
// Testing certificateKeyUsage directly, one bit at a time, is deliberate. A
// certificate per row would cost nine key generations to exercise a function
// that reads exactly one field, and single-bit rows are what isolate a wrong
// NAME from a wrong ORDER -- the order is pinned by the test below, which sets
// every bit at once and can therefore see nothing about which name belongs to
// which bit.
func TestCertificateKeyUsage_NamesEveryRFC5280BitCorrectly(t *testing.T) {
	t.Parallel()

	for name, tt := range map[string]struct {
		usage x509.KeyUsage
		want  string
	}{
		"bit 0 digitalSignature": {x509.KeyUsageDigitalSignature, "digitalSignature"},
		"bit 1 nonRepudiation":   {x509.KeyUsageContentCommitment, "nonRepudiation"},
		"bit 2 keyEncipherment":  {x509.KeyUsageKeyEncipherment, "keyEncipherment"},
		"bit 3 dataEncipherment": {x509.KeyUsageDataEncipherment, "dataEncipherment"},
		"bit 4 keyAgreement":     {x509.KeyUsageKeyAgreement, "keyAgreement"},
		"bit 5 keyCertSign":      {x509.KeyUsageCertSign, "keyCertSign"},
		"bit 6 cRLSign":          {x509.KeyUsageCRLSign, "cRLSign"},
		"bit 7 encipherOnly":     {x509.KeyUsageEncipherOnly, "encipherOnly"},
		"bit 8 decipherOnly":     {x509.KeyUsageDecipherOnly, "decipherOnly"},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			got := certificateKeyUsage(&x509.Certificate{KeyUsage: tt.usage})
			require.Equal(t, tt.want, got,
				"RFC 5280 sec. 4.2.1.3 names this bit %q", tt.want)
		})
	}

	t.Run("the table covers every bit the RFC defines", func(t *testing.T) {
		t.Parallel()

		// Without this, a tenth bit added to keyUsageBits -- or one of the nine
		// silently dropped -- would leave every row above passing.
		require.Len(t, keyUsageBits, 9,
			"RFC 5280 sec. 4.2.1.3 defines exactly nine bits")

		var union x509.KeyUsage
		for _, ku := range keyUsageBits {
			union |= ku.bit
		}
		require.Equal(t, allNineKeyUsages, union,
			"every defined bit must be mapped, and none twice")
	})
}

// TestCertComponent_KeyUsageOfARealCertificateIsInRFC5280BitOrder is the order
// half of the contract, stated over a real certificate and the real producer
// rather than over certificateKeyUsage alone.
//
// The nine names are asserted as ONE string, in one order, which is the
// assertion no map-based implementation can pass: with nine names to emit, Go's
// randomised map iteration would deliver this order once in 362880 runs. The
// existing coverage sets four bits, where the same mistake survives one run in
// 24 -- often enough to be caught, but by a test that would go green again on a
// re-run, which is the worst way for a wire contract to be defended.
//
// The order is RFC 5280 sec. 4.2.1.3's BIT STRING order, which is also the order
// of Go's constants (1<<0 through 1<<8), so a reader can check the expected
// string against either.
//
// It goes through certHitToComponents so that the round trip is real: the bits
// are encoded into a certificate by x509.CreateCertificate, parsed back out by
// x509.ParseCertificate, and read off the parsed certificate by the producer. A
// bit that failed to survive that trip -- encipherOnly and decipherOnly are the
// plausible candidates, being the two that RFC 5280 only permits alongside
// keyAgreement -- would be invisible to a test that poked the field directly.
func TestCertComponent_KeyUsageOfARealCertificateIsInRFC5280BitOrder(t *testing.T) {
	t.Parallel()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	cert := selfSignedCertFor(t, &key.PublicKey, key, "all-bits.example")
	// selfSignedCertFor sets digitalSignature only, so re-issue with the full
	// set. Asserting the parsed value first keeps this test honest about what
	// the certificate really carries.
	cert = reissueWithKeyUsage(t, cert, key, allNineKeyUsages)
	require.Equal(t, allNineKeyUsages, cert.KeyUsage,
		"all nine bits must survive encoding and parsing, or the assertion below "+
			"is about a certificate this test did not build")

	compos, _, err := NewConverter().certHitToComponents(t.Context(),
		model.CertHit{Cert: cert, Source: "PEM", Location: "/etc/ssl/certs/all-bits.pem"})
	require.NoError(t, err)

	var certCompo cdx.Component
	for _, compo := range compos {
		if compo.CryptoProperties != nil &&
			compo.CryptoProperties.AssetType == cdx.CryptoAssetTypeCertificate {
			certCompo = compo
		}
	}
	require.NotEmpty(t, certCompo.BOMRef, "no certificate component emitted")
	require.NotNil(t, certCompo.Properties)

	var got string
	var n int
	for _, p := range *certCompo.Properties {
		if p.Name == "key_usage" {
			n++
			got = p.Value
		}
	}
	require.Equal(t, 1, n, "exactly one key_usage property")
	require.Equal(t,
		"digitalSignature,nonRepudiation,keyEncipherment,dataEncipherment,"+
			"keyAgreement,keyCertSign,cRLSign,encipherOnly,decipherOnly",
		got,
		"RFC 5280 sec. 4.2.1.3 bit order, that section's ASN.1 identifiers, "+
			"comma-separated with no spaces")
}

// reissueWithKeyUsage re-signs cert's template with a different KeyUsage,
// returning the parsed result. It exists so the caller states the bits it wants
// and reads back the bits a certificate really carries, rather than assigning
// to the parsed struct's field -- which would test the formatter against a
// value no encoder ever produced.
func reissueWithKeyUsage(t *testing.T, cert *x509.Certificate, key *ecdsa.PrivateKey, usage x509.KeyUsage) *x509.Certificate {
	t.Helper()

	tmpl := *cert
	tmpl.KeyUsage = usage
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	out, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return out
}
