package cdxprops_test

import (
	"bytes"
	"context"
	"crypto"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"maps"
	"slices"
	"strings"
	"testing"

	"github.com/OmniTrustILM/cbom-lens/internal/bom"
	"github.com/OmniTrustILM/cbom-lens/internal/cdxprops"
	"github.com/OmniTrustILM/cbom-lens/internal/cdxprops/cdxtest"
	"github.com/OmniTrustILM/cbom-lens/internal/model"
	pemscan "github.com/OmniTrustILM/cbom-lens/internal/scanner/pem"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/stretchr/testify/require"
)

// pemBundleLocation is the location every comprehensivePEMBundle carries.
const pemBundleLocation = "/test/bundle.pem"

// comprehensivePEMBundle builds a bundle exercising every branch of
// Converter.PEMBundle: a certificate, two private keys, a CSR, a standalone
// public key, a CRL, and raw blocks that only analyzeParseError can make sense
// of (two ML-DSA-65 keys and two garbage blocks). It yields 20 components:
// 10 algorithm, 9 related-crypto-material and 1 certificate. No protocol asset
// -- PEMBundle cannot produce one. More than one test wants this bundle, which
// is why it is a helper.
func comprehensivePEMBundle(t *testing.T) model.PEMBundle {
	t.Helper()

	// Generate test certificate
	selfSigned, err := cdxtest.CertBuilder{}.
		WithSignatureAlgorithm(x509.SHA256WithRSA).
		Generate()
	require.NoError(t, err)

	// Generate CSR
	csrKey, err := cdxtest.GenECPrivateKey(elliptic.P224())
	require.NoError(t, err)
	csr, _, err := cdxtest.GenCSR(csrKey)
	require.NoError(t, err)

	// Generate CRL
	crlCert, err := cdxtest.CertBuilder{}.
		WithIsCA(true).
		WithKeyUsage(x509.KeyUsageCRLSign | x509.KeyUsageCertSign).
		Generate()
	require.NoError(t, err)
	signer, ok := crlCert.Key.(crypto.Signer)
	require.True(t, ok)
	crl, _, err := cdxtest.GenCRL(crlCert.Cert, signer)
	require.NoError(t, err)

	// Generate public key
	pubKey, _, err := cdxtest.GenEd25519Keys()
	require.NoError(t, err)

	// ML-DSA-65 private and public keys
	mldsa65PrivateKey, err := cdxtest.TestData(cdxtest.MLDSA65PrivateKey)
	require.NoError(t, err)
	mldsa65PrivateKeyPEM, _ := pem.Decode(mldsa65PrivateKey)
	require.NotNil(t, mldsa65PrivateKeyPEM)
	mldsa65PublicKey, err := cdxtest.TestData(cdxtest.MLDSA65PublicKey)
	require.NoError(t, err)
	mldsa65PublicKeyPEM, _ := pem.Decode(mldsa65PublicKey)
	require.NotNil(t, mldsa65PublicKeyPEM)

	// Create comprehensive PEM bundle
	return model.PEMBundle{
		Certificates: []model.CertHit{
			{
				Cert:     selfSigned.Cert,
				Source:   "PEM",
				Location: pemBundleLocation,
			},
		},
		PrivateKeys: []model.PrivateKeyInfo{
			{
				Key:        selfSigned.Key,
				Type:       "RSA",
				Source:     "PEM",
				BlockIndex: -1,
			},
			{
				Key:        csrKey,
				Type:       "ECDSA",
				Source:     "PEM",
				BlockIndex: -1,
			},
		},
		CertificateRequests: []*x509.CertificateRequest{csr},
		PublicKeys:          []crypto.PublicKey{pubKey},
		CRLs:                []*x509.RevocationList{crl},
		RawBlocks: []model.PEMBlock{
			{
				Type:    mldsa65PrivateKeyPEM.Type,
				Headers: map[string]string{},
				Bytes:   mldsa65PrivateKeyPEM.Bytes,
				Order:   0,
			},
			{
				Type:    mldsa65PublicKeyPEM.Type,
				Headers: map[string]string{},
				Bytes:   mldsa65PublicKeyPEM.Bytes,
				Order:   1,
			},
			{
				Type:    mldsa65PrivateKeyPEM.Type,
				Headers: map[string]string{},
				Bytes:   []byte("garbage"),
				Order:   2,
			},
			{
				Type:    mldsa65PublicKeyPEM.Type,
				Headers: map[string]string{},
				Bytes:   []byte("garbage"),
				Order:   3,
			},
		},
		ParseErrors: map[int]error{
			0: errors.New("ml-dsa-65"),
			1: errors.New("ml-dsa-65"),
			2: errors.New("garbage"),
			3: errors.New("garbage"),
		},
	}
}

func TestConverter_PEM(t *testing.T) {
	ctx := context.Background()

	bundle := comprehensivePEMBundle(t)

	// Execute
	c := cdxprops.NewConverter()
	detection := c.PEMBundle(ctx, bundle)
	require.NotNil(t, detection)

	components := detection.Components
	// Verify we got all expected components
	require.Len(t, components, 20)

	for idx, c := range components {
		t.Logf("%d: name=%s, description=%s", idx, c.Name, c.Description)
	}
}

// TestPEMBundle_MaterialPropertiesOnlyOnMaterial pins #213.
//
// relatedCryptoMaterialProperties describes a serialised object. PEMBundle used
// to stamp format=PEM onto every component it produced, manufacturing the
// struct where it was absent, so an algorithm and a certificate both answered
// "yes" to "is this key material?". A consumer filtering on the presence of
// that field saw 32 assets where 12 existed.
func TestPEMBundle_MaterialPropertiesOnlyOnMaterial(t *testing.T) {
	t.Parallel()

	bundle := comprehensivePEMBundle(t)

	detection := cdxprops.NewConverter().PEMBundle(t.Context(), bundle)
	require.NotNil(t, detection)

	// Counted per asset type rather than material/other, so that neither side
	// can be satisfied by something that asserts nothing. A catch-all "other"
	// would be fed by a component with no CryptoProperties at all, which skips
	// every assertion below; nilCryptoProps keeps that visible instead.
	byType := map[cdx.CryptoAssetType]int{}
	var nilCryptoProps int
	for _, compo := range detection.Components {
		if compo.CryptoProperties == nil {
			nilCryptoProps++
			continue
		}
		assetType := compo.CryptoProperties.AssetType
		byType[assetType]++
		rcmp := compo.CryptoProperties.RelatedCryptoMaterialProperties
		if assetType == cdx.CryptoAssetTypeRelatedCryptoMaterial {
			require.NotNil(t, rcmp,
				"%s (%s): key material must carry relatedCryptoMaterialProperties",
				compo.Name, assetType)
			require.Equal(t, "PEM", rcmp.Format,
				"%s (%s): key material from a PEM bundle must record format=PEM",
				compo.Name, assetType)
			continue
		}
		require.Nil(t, rcmp,
			"%s (%s): relatedCryptoMaterialProperties describes a serialised "+
				"object, so a %s asset must not carry it (#213)",
			compo.Name, assetType, assetType)
	}

	require.Zero(t, nilCryptoProps,
		"a component reached the detection with no CryptoProperties, so it was "+
			"neither checked nor counted")
	// Both defect classes in #213 -- the algorithm and the certificate -- must
	// actually be present, alongside the material the fix must not disturb.
	for _, assetType := range []cdx.CryptoAssetType{
		cdx.CryptoAssetTypeRelatedCryptoMaterial,
		cdx.CryptoAssetTypeAlgorithm,
		cdx.CryptoAssetTypeCertificate,
	} {
		require.NotZero(t, byType[assetType],
			"no %s component examined, so this test proved nothing about it "+
				"-- got %v", assetType, byType)
	}
}

// TestPEMBundle_BOMRefsMatchContents covers the crypto/algorithm refs, which
// are the only ones this can be stated for, and the same invariant
// certHitToComponents already declares: a crypto/algorithm BOMRef is a hash of
// the component it names, so mutating a component after BOMRefHash has run
// leaves a reference that no longer describes its contents.
//
// The other three ref families are deliberately out of range rather than
// overlooked. crypto/key and crypto/private_key hash the key, and
// crypto/certificate hashes cert.Raw, so none of them ever claimed to cover
// component contents and re-hashing cannot reproduce them. Those are exactly
// the components setPEMFormat still writes to -- which is safe for that reason,
// and is why the fix gates on the asset type: it excludes precisely the family
// whose refs this test can check.
//
// The blanket format=PEM loop did exactly that, and the corpus golden shows the
// consequence: the bundle's public-key algorithm hashed to the same ref as an
// unmutated algorithm from a certificate detection, so the Builder deduplicated
// two different contents onto one ref.
func TestPEMBundle_BOMRefsMatchContents(t *testing.T) {
	t.Parallel()

	c := cdxprops.NewConverter()
	detection := c.PEMBundle(t.Context(), comprehensivePEMBundle(t))
	require.NotNil(t, detection)
	require.NotEmpty(t, detection.Components)

	// Counted so a ref-naming change cannot make this test vacuously green.
	var checked int
	for _, compo := range detection.Components {
		// Only crypto/algorithm refs are hashes of the component JSON.
		// crypto/key, crypto/private_key and crypto/certificate refs hash the
		// key or the DER instead, so re-hashing cannot reproduce them.
		refName, _, ok := strings.Cut(compo.BOMRef, "@")
		if !ok || !strings.HasPrefix(refName, "crypto/algorithm/") {
			continue
		}
		want := compo.BOMRef

		rehashed := compo
		c.BOMRefHash(&rehashed, refName)
		checked++
		require.Equal(t, want, rehashed.BOMRef,
			"%s: BOMRef does not match a re-hash of its own contents, "+
				"so the component was mutated after being hashed", compo.Name)
	}
	require.NotZero(t, checked,
		"no crypto/algorithm component was examined, so this test proved "+
			"nothing -- has the ref naming changed?")
}

// TestPEMBundle_StandaloneDSAPublicKeyDoesNotPanic covers the crash that
// shipped undetected because nothing fed a *dsa.PublicKey through
// bundle.PublicKeys.
//
// Go parses a DSA PUBLIC KEY block happily but refuses to marshal
// *dsa.PublicKey, so publicKeyComponents cannot identify the key and returns no
// key component. restOfPEMBundleToCDX then dereferenced its CryptoProperties
// unconditionally and panicked, aborting the whole scan on one input file.
func TestPEMBundle_StandaloneDSAPublicKeyDoesNotPanic(t *testing.T) {
	t.Parallel()

	data, err := cdxtest.TestData(cdxtest.DSA2048PublicKey)
	require.NoError(t, err)

	bundle, err := pemscan.Scanner{}.Scan(t.Context(), data, cdxtest.DSA2048PublicKey)
	require.NoError(t, err)
	require.NotEmpty(t, bundle.PublicKeys, "fixture must reach bundle.PublicKeys, or this proves nothing")

	var d *model.Detection
	require.NotPanics(t, func() {
		d = cdxprops.NewConverter().PEMBundle(t.Context(), bundle)
	})
	require.NotNil(t, d)

	// Whatever is emitted must be well formed: no component may carry a nil
	// CryptoProperties, and none may have an empty name or ref.
	for _, compo := range d.Components {
		require.NotEmpty(t, compo.Name, "component with no name")
		require.NotEmpty(t, compo.BOMRef, "component with no bom-ref")
		require.NotNil(t, compo.CryptoProperties, "%s has nil CryptoProperties", compo.Name)
	}
}

// csrCRLBundle builds the smallest bundle that carries one CSR and one CRL,
// signed by the same CA so the CRL parses. location is what the detection will
// report, so callers can build the same bytes at two paths.
func csrCRLBundle(t *testing.T, location string) model.PEMBundle {
	t.Helper()

	csrKey, err := cdxtest.GenECPrivateKey(elliptic.P256())
	require.NoError(t, err)
	csr, _, err := cdxtest.GenCSR(csrKey)
	require.NoError(t, err)

	ca, err := cdxtest.CertBuilder{}.
		WithIsCA(true).
		WithKeyUsage(x509.KeyUsageCRLSign | x509.KeyUsageCertSign).
		Generate()
	require.NoError(t, err)
	signer, ok := ca.Key.(crypto.Signer)
	require.True(t, ok)
	crl, _, err := cdxtest.GenCRL(ca.Cert, signer)
	require.NoError(t, err)

	return model.PEMBundle{
		Location:            location,
		CertificateRequests: []*x509.CertificateRequest{csr},
		CRLs:                []*x509.RevocationList{crl},
	}
}

// emitDocument runs a detection through the real Builder for the given spec
// version and returns the emitted document, unmarshalled.
func emitDocument(t *testing.T, version string, detections ...model.Detection) cdx.BOM {
	t.Helper()

	b, err := bom.NewBuilder(model.CBOM{Version: version})
	require.NoError(t, err)

	var buf bytes.Buffer
	require.NoError(t, b.AppendDetections(t.Context(), detections...).AsJSON(t.Context(), &buf))

	var doc cdx.BOM
	require.NoError(t, json.Unmarshal(buf.Bytes(), &doc))
	return doc
}

// componentsByName indexes an emitted document by component name.
func componentsByName(doc cdx.BOM) map[string]cdx.Component {
	byName := map[string]cdx.Component{}
	if doc.Components == nil {
		return byName
	}
	for _, compo := range *doc.Components {
		byName[compo.Name] = compo
	}
	return byName
}

// TestPEMBundle_CSRAndCRLReachTheBOM is the end of the path a scanned .csr or
// .crl actually takes. csrToCDX and crlToCDX built components with no bom-ref,
// and Builder.appendDetection drops those, so the file was parsed, converted,
// and then thrown away: an empty BOM and exit 0.
//
// It asserts on the EMITTED DOCUMENT rather than on detection.Components. The
// components were always present in the detection -- asserting that would have
// been green on the broken tree. The Builder is where the loss happened, so the
// Builder has to be in the picture. Both spec versions are covered because the
// 1.7 emitter maps components independently of 1.6.
func TestPEMBundle_CSRAndCRLReachTheBOM(t *testing.T) {
	t.Parallel()

	for _, version := range []string{"1.6", "1.7"} {
		t.Run(version, func(t *testing.T) {
			t.Parallel()

			bundle := csrCRLBundle(t, "/test/pki.pem")
			d := cdxprops.NewConverter().PEMBundle(t.Context(), bundle)
			require.NotNil(t, d)

			byName := componentsByName(emitDocument(t, version, *d))

			csrCompo, ok := byName["CSR: Test CSR"]
			require.True(t, ok, "the CSR never reached the document, got %v", slices.Sorted(maps.Keys(byName)))
			require.NotEmpty(t, csrCompo.BOMRef)
			require.Equal(t, "CSR", cdxtest.GetProp(csrCompo, "pem_type"))

			var crlCompo cdx.Component
			for name, compo := range byName {
				if strings.HasPrefix(name, "CRL: ") {
					crlCompo = compo
				}
			}
			require.NotEmpty(t, crlCompo.Name, "the CRL never reached the document, got %v", slices.Sorted(maps.Keys(byName)))
			require.NotEmpty(t, crlCompo.BOMRef)
			require.Equal(t, "1", cdxtest.GetProp(crlCompo, "revoked_count"))

			// The location moved to evidence.occurrences, where the Builder can
			// record every path the same content was found at.
			require.Empty(t, cdxtest.GetProp(crlCompo, "location"),
				"location is the Builder's to record, not a property on a content-addressed component")
			require.NoError(t, cdxtest.HasEvidencePath(crlCompo, "/test/pki.pem"))
		})
	}
}

// TestPEMBundle_TwoCSRsSameSubjectStayDistinct is what fails if someone
// replaces the DER digest with Converter.BOMRefHash.
//
// BOMRefHash hashes the component's own JSON, and a CSR component carries the
// subject but nothing of the key. Two requests for the same subject with
// different keys would therefore hash to one ref, and the Builder's first-wins
// dedup would silently discard the second -- one real asset short, with no
// warning. Hashing the request's DER keeps them apart because the DER covers
// the key.
func TestPEMBundle_TwoCSRsSameSubjectStayDistinct(t *testing.T) {
	t.Parallel()

	// cdxtest.GenCSR always uses CN "Test CSR", so two calls differ only in the
	// key -- exactly the collision under test.
	newCSR := func(t *testing.T) *x509.CertificateRequest {
		t.Helper()
		key, err := cdxtest.GenECPrivateKey(elliptic.P256())
		require.NoError(t, err)
		csr, _, err := cdxtest.GenCSR(key)
		require.NoError(t, err)
		return csr
	}

	first, second := newCSR(t), newCSR(t)
	require.Equal(t, first.Subject.String(), second.Subject.String(),
		"the fixtures must share a subject, or this proves nothing")

	d := cdxprops.NewConverter().PEMBundle(t.Context(), model.PEMBundle{
		Location:            "/test/requests.pem",
		CertificateRequests: []*x509.CertificateRequest{first, second},
	})
	require.NotNil(t, d)

	doc := emitDocument(t, "1.6", *d)
	require.NotNil(t, doc.Components)

	var refs []string
	for _, compo := range *doc.Components {
		if strings.HasPrefix(compo.Name, "CSR: ") {
			refs = append(refs, compo.BOMRef)
		}
	}
	require.Len(t, refs, 2,
		"two requests for the same subject with different keys collapsed into one component")
	require.NotEqual(t, refs[0], refs[1])
}

// TestPEMBundle_SameCRLTwoLocationsDedupes is the other half of dropping the
// "location" property. The ref is a digest of the list's DER, so the same CRL
// found at two paths is one component -- and a stored "location" property would
// have frozen whichever path was seen first, quietly claiming the asset lives
// only there. evidence.occurrences carries both.
func TestPEMBundle_SameCRLTwoLocationsDedupes(t *testing.T) {
	t.Parallel()

	ca, err := cdxtest.CertBuilder{}.
		WithIsCA(true).
		WithKeyUsage(x509.KeyUsageCRLSign | x509.KeyUsageCertSign).
		Generate()
	require.NoError(t, err)
	signer, ok := ca.Key.(crypto.Signer)
	require.True(t, ok)
	crl, _, err := cdxtest.GenCRL(ca.Cert, signer)
	require.NoError(t, err)

	c := cdxprops.NewConverter()
	var detections []model.Detection
	for _, location := range []string{"/etc/pki/ca.crl", "/var/backup/ca.crl"} {
		d := c.PEMBundle(t.Context(), model.PEMBundle{
			Location: location,
			CRLs:     []*x509.RevocationList{crl},
		})
		require.NotNil(t, d)
		detections = append(detections, *d)
	}

	doc := emitDocument(t, "1.6", detections...)
	require.NotNil(t, doc.Components)

	var crls []cdx.Component
	for _, compo := range *doc.Components {
		if strings.HasPrefix(compo.Name, "CRL: ") {
			crls = append(crls, compo)
		}
	}
	require.Len(t, crls, 1, "the same CRL at two paths must be one component")

	require.NotNil(t, crls[0].Evidence)
	require.NotNil(t, crls[0].Evidence.Occurrences)
	var locations []string
	for _, occ := range *crls[0].Evidence.Occurrences {
		locations = append(locations, occ.Location)
	}
	require.ElementsMatch(t, []string{"/etc/pki/ca.crl", "/var/backup/ca.crl"}, locations,
		"both paths the CRL was found at must survive as occurrences")
}
