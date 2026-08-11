package cdxprops_test

import (
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
