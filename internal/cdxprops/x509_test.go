package cdxprops_test

import (
	"crypto/x509"
	"strings"
	"testing"

	"github.com/OmniTrustILM/cbom-lens/internal/cdxprops"
	"github.com/OmniTrustILM/cbom-lens/internal/cdxprops/cdxtest"
	"github.com/OmniTrustILM/cbom-lens/internal/cdxprops/ilm"
	"github.com/OmniTrustILM/cbom-lens/internal/model"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/stretchr/testify/require"
)

func TestConverter_CertHit(t *testing.T) {
	ctx := t.Context()

	selfSigned, err := cdxtest.GenSelfSignedCert()
	require.NoError(t, err)
	cert := selfSigned.Cert

	tests := []struct {
		name               string
		hit                model.CertHit
		wantNil            bool
		wantComponentCount int
		wantDepCount       int
		wantType           model.DetectionType
		wantSource         string
		wantLocation       string
	}{
		{
			name: "valid self-signed certificate",
			hit: model.CertHit{
				Cert:     cert,
				Source:   "PEM",
				Location: "/test/cert.pem",
			},
			wantNil:            false,
			wantComponentCount: 5,
			wantDepCount:       1,
			wantType:           model.DetectionTypeCertificate,
			wantSource:         "PEM",
			wantLocation:       "/test/cert.pem",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := cdxprops.NewConverter()
			detection := c.CertHit(ctx, tt.hit)

			if tt.wantNil {
				require.Nil(t, detection)
				return
			}

			require.NotNil(t, detection)
			require.Equal(t, tt.wantComponentCount, len(detection.Components))
			require.Equal(t, tt.wantDepCount, len(detection.Dependencies))
			require.Equal(t, tt.wantType, detection.Type)
			require.Equal(t, tt.wantSource, detection.Source)
			require.Equal(t, tt.wantLocation, detection.Location)

			// Verify the first component (main certificate) has a BOM ref
			require.NotEmpty(t, detection.Components[0].BOMRef)
		})
	}
}

// TestCertHit_OneCertTwoSourcesShareARefAndDisagreeOnSourceFormat documents the
// precondition that makes ilm:component:certificate:source_format
// nondeterministic in a delivered BOM, and shows it is STRUCTURAL rather than a
// race: the same certificate run through Converter.CertHit twice yields two
// certificate components with one identical bom-ref, disagreeing on exactly the
// one property that records where the certificate was found.
//
// The ref is a digest of cert.Raw alone (certComponent) -- no path, no port and
// no source enter it, which is deliberate, because that is what lets one
// certificate found in three places dedupe to one asset. The other two ILM
// properties cannot disagree for the same reason: base64_content is
// base64(cert.Raw) and fingerprint is sha256(cert.Raw), so two components under
// one ref carry the same bytes modulo a SHA-256 collision.
//
// Nothing here is wrong on its own: this test asserts the collision, not a
// defect. The Converter is called once per hit and is copied across the scanning
// goroutines, so it cannot see that another source found the same certificate.
// Reconciling it is bom.Builder.appendDetection's job, since that is the only
// place both detections meet -- see mergeCertificateSourceFormat and
// TestBuilder_AppendDetections_CertificateSourceFormatOrderIndependent.
func TestCertHit_OneCertTwoSourcesShareARefAndDisagreeOnSourceFormat(t *testing.T) {
	t.Parallel()

	selfSigned, err := cdxtest.GenSelfSignedCert()
	require.NoError(t, err)

	c := cdxprops.NewConverter().WithIlmExtensions(true)

	// The certificate as the filesystem scanner reads it off disk...
	diskDetection := c.CertHit(t.Context(), model.CertHit{
		Cert:     selfSigned.Cert,
		Source:   "PEM",
		Location: "/etc/ssl/certs/server.pem",
	})
	require.NotNil(t, diskDetection)

	// ...and the same certificate as nmap sees it served on 443: same bytes,
	// same key, a different answer to "where did this come from".
	wireDetection := c.CertHit(t.Context(), model.CertHit{
		Cert:     selfSigned.Cert,
		Source:   "NMAP",
		Location: "23.88.35.44:443",
	})
	require.NotNil(t, wireDetection)

	diskCert := certificateComponent(t, diskDetection.Components)
	wireCert := certificateComponent(t, wireDetection.Components)

	// Checked before the equality: two refless components are also "equal", so
	// without this the collision could be asserted by a path where no collision
	// exists.
	require.NotEmpty(t, diskCert.BOMRef)
	require.Equal(t, diskCert.BOMRef, wireCert.BOMRef,
		"one certificate is one bom-ref regardless of where it was found; that "+
			"is what makes the two detections collide in the Builder")

	require.Equal(t, "PEM", cdxtest.GetProp(diskCert, ilm.CertificateSourceFormat),
		"the filesystem path reports the encoding it parsed")
	require.Equal(t, "NMAP", cdxtest.GetProp(wireCert, ilm.CertificateSourceFormat),
		"the nmap path reports the scanner, and both claims are true")

	base64Content := cdxtest.GetProp(diskCert, ilm.CertificateBase64Content)
	require.NotEmpty(t, base64Content)
	require.Equal(t, base64Content, cdxtest.GetProp(wireCert, ilm.CertificateBase64Content),
		"base64_content is base64(cert.Raw) and the ref is a digest of cert.Raw, "+
			"so it cannot differ between two components sharing a ref")

	fingerprint := cdxtest.GetProp(diskCert, ilm.CertificateFingerprint)
	require.NotEmpty(t, fingerprint)
	require.Equal(t, fingerprint, cdxtest.GetProp(wireCert, ilm.CertificateFingerprint),
		"fingerprint is sha256(cert.Raw), so it cannot differ either -- "+
			"source_format is the only ILM certificate property that can")
}

// TestCertHit_TwoRSACertificatesShareOneRSA2048Algorithm is the converter-level
// statement of this fix, and it is the exact negation of what this test used to
// assert.
//
// A signature algorithm's bom-ref is a pure function of the enum and the OID
// (signatureAlgorithmComponents), so any two SHA256WithRSA certificates land on
// one ref. What each of them names as that ref's public-key-algorithm target is
// a hash of the algorithm COMPONENT -- and publicKeyComponents used to stamp the
// primitive onto that component, read off the certificate's KeyUsage, before
// hashing it. RSA with digitalSignature became a signature scheme, RSA with
// keyEncipherment became pke, and the two certificates named two different
// crypto/algorithm/rsa-2048 assets. This test asserted that collision as
// intended behaviour and documented it as such; it was the defect.
//
// A primitive is a property of the algorithm. RSA is a public-key encryption
// scheme -- the schema's own example for pke -- whatever a given certificate
// permits its key to do, and the "this certificate is signed with RSA" fact is
// already carried by the separate sha-256-rsa asset both certificates share. So
// the two RSA-2048 assets are one asset, and this test says so.
//
// Both certificates keep DIFFERENT keys, deliberately. The algorithm asset must
// be the same for two unrelated 2048-bit RSA keys, since the component states the
// algorithm and its parameters and nothing about the key material; asserting it
// over one shared key would be the weaker claim.
func TestCertHit_TwoRSACertificatesShareOneRSA2048Algorithm(t *testing.T) {
	t.Parallel()

	signing, err := cdxtest.CertBuilder{}.
		WithSignatureAlgorithm(x509.SHA256WithRSA).
		WithKeyUsage(x509.KeyUsageDigitalSignature).
		Generate()
	require.NoError(t, err)

	encipherment, err := cdxtest.CertBuilder{}.
		WithSignatureAlgorithm(x509.SHA256WithRSA).
		WithKeyUsage(x509.KeyUsageKeyEncipherment).
		Generate()
	require.NoError(t, err)

	c := cdxprops.NewConverter()

	signingDetection := c.CertHit(t.Context(), model.CertHit{
		Cert:     signing.Cert,
		Source:   "PEM",
		Location: "/etc/ssl/certs/rsa-signing.pem",
	})
	require.NotNil(t, signingDetection)

	enciphermentDetection := c.CertHit(t.Context(), model.CertHit{
		Cert:     encipherment.Cert,
		Source:   "PEM",
		Location: "/etc/ssl/certs/rsa-encipherment.pem",
	})
	require.NotNil(t, enciphermentDetection)

	signingDeps := signingDetection.Dependencies
	enciphermentDeps := enciphermentDetection.Dependencies
	require.Len(t, signingDeps, 1, "the certificate names one signature algorithm")
	require.Len(t, enciphermentDeps, 1, "so does the other")

	// Checked before the equality: two empty refs are also "equal".
	require.NotEmpty(t, signingDeps[0].Ref)
	require.Equal(t, signingDeps[0].Ref, enciphermentDeps[0].Ref,
		"one signature algorithm is one bom-ref regardless of what the subject "+
			"key is used for; that is what makes the two detections collide in "+
			"the Builder")

	require.NotNil(t, signingDeps[0].Dependencies)
	require.NotNil(t, enciphermentDeps[0].Dependencies)
	signingTarget := publicKeyAlgorithmTarget(t, *signingDeps[0].Dependencies)
	enciphermentTarget := publicKeyAlgorithmTarget(t, *enciphermentDeps[0].Dependencies)

	require.Equal(t, signingTarget, enciphermentTarget,
		"one RSA-2048 algorithm is one asset: the certificate's KeyUsage is a "+
			"fact about the certificate and must not reach the component whose "+
			"ref is a hash of itself")

	sharedName, _, ok := strings.Cut(signingTarget, "@")
	require.True(t, ok)
	require.Equal(t, "crypto/algorithm/rsa-2048", sharedName)
}

// publicKeyAlgorithmTarget picks the RSA target out of a signature algorithm's
// edge set, which certHitToComponents builds as {public-key algorithm, hash
// algorithm}.
func publicKeyAlgorithmTarget(t *testing.T, targets []string) string {
	t.Helper()

	var found []string
	for _, target := range targets {
		if strings.HasPrefix(target, "crypto/algorithm/rsa-") {
			found = append(found, target)
		}
	}
	require.Len(t, found, 1, "expected exactly one public-key-algorithm target in %v", targets)
	return found[0]
}

// certificateComponent returns the single certificate component among compos,
// failing if there is not exactly one. Each detection above carries a signature
// algorithm, a public key and a hash algorithm too, and the assertion is only
// about the certificate.
func certificateComponent(t *testing.T, compos []cdx.Component) cdx.Component {
	t.Helper()

	var found []cdx.Component
	for _, compo := range compos {
		if compo.CryptoProperties == nil {
			continue
		}
		if compo.CryptoProperties.AssetType != cdx.CryptoAssetTypeCertificate {
			continue
		}
		found = append(found, compo)
	}
	require.Len(t, found, 1, "expected exactly one certificate component")
	return found[0]
}
