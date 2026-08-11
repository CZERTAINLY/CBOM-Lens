package cdxprops_test

import (
	"bytes"
	"context"
	"crypto"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"log/slog"
	"maps"
	"math/big"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/OmniTrustILM/cbom-lens/internal/bom"
	"github.com/OmniTrustILM/cbom-lens/internal/cdxprops"
	"github.com/OmniTrustILM/cbom-lens/internal/cdxprops/cdxtest"
	"github.com/OmniTrustILM/cbom-lens/internal/log"
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
// of (two ML-DSA-65 keys and two garbage blocks). It yields 21 components:
// 10 algorithm, 10 related-crypto-material and 1 certificate. No protocol asset
// -- PEMBundle cannot produce one. More than one test wants this bundle, which
// is why it is a helper.
//
// The count was 20 until the post-quantum PRIVATE KEY block started
// contributing key material as well as an algorithm. The two garbage blocks
// still error out and contribute nothing.
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
	require.Len(t, components, 21)

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

// TestPEMBundle_PKIXPublicKeyWithTrailingDataYieldsNothing walks the whole
// pipeline a `PUBLIC KEY` block takes when the stdlib refuses it, because the
// two halves of the defect only meet there.
//
// x509.ParsePKIXPublicKey rejects a SubjectPublicKeyInfo with anything appended
// to it, so the scanner files the block under ParseErrors and analyzeParseError
// hands it to unsupportedPKIX -- the fallback that exists for keys Go cannot
// parse, and which is therefore reached by every key Go rejects, including the
// ones it rejects for being malformed. Whatever it accepts is published: the
// bom-ref digests the block it was given, so one key plus n tails is n assets
// that a reader cannot tell from n keys, and the tail itself is base64'd
// verbatim into relatedCryptoMaterialProperties.value.
//
// The fixture is a real ML-DSA-65 key so the OID lookup succeeds and the only
// thing standing between the input and a component is the trailing-data guard.
func TestPEMBundle_PKIXPublicKeyWithTrailingDataYieldsNothing(t *testing.T) {
	t.Parallel()

	data, err := cdxtest.TestData(cdxtest.MLDSA65PublicKey)
	require.NoError(t, err)
	block, _ := pem.Decode(data)
	require.NotNil(t, block)
	require.Equal(t, "PUBLIC KEY", block.Type)

	withTrailer := pem.EncodeToMemory(&pem.Block{
		Type:  block.Type,
		Bytes: append(slices.Clone(block.Bytes), 0xde, 0xad, 0xbe, 0xef),
	})

	bundle, err := pemscan.Scanner{}.Scan(t.Context(), withTrailer, cdxtest.MLDSA65PublicKey)
	require.NoError(t, err)
	// The block has to reach the fallback path, or this test proves nothing
	// about it: a bundle whose public key parsed normally never calls
	// analyzeParseError at all.
	require.Empty(t, bundle.PublicKeys, "the stdlib must refuse the tail")
	require.NotEmpty(t, bundle.ParseErrors, "the block must reach analyzeParseError")

	d := cdxprops.NewConverter().PEMBundle(t.Context(), bundle)
	require.NotNil(t, d)
	require.Empty(t, d.Components,
		"a public key with bytes appended to it must yield no asset at all")
}

// TestPEMBundle_OneKeyWithTwoTailsIsOneAsset states the invariant the
// single-tail test above cannot.
//
// "A block with a tail yields nothing" and "one key cannot become n assets" are
// different claims, and only the second one is the defect. A guard that rejects
// the four-byte tail every other test uses but admits a shorter one satisfies
// the first claim and violates the second: len(rest) >= 4 leaves the whole
// suite green while a single appended 0x00 still mints a second ML-DSA-65
// public key, with a ref no reader can tell from a real second key's. So the
// file here holds ONE key three times -- untouched, plus one byte, plus two
// other bytes -- and the count is what is asserted.
//
// It doubles as the only test where a good block shares a file with bad ones.
// restOfPEMBundleToCDX collects each block's error and continues, and if it ever
// stopped at the first one, a single malformed key would take every later key in
// the file down with it.
func TestPEMBundle_OneKeyWithTwoTailsIsOneAsset(t *testing.T) {
	t.Parallel()

	data, err := cdxtest.TestData(cdxtest.MLDSA65PublicKey)
	require.NoError(t, err)
	block, _ := pem.Decode(data)
	require.NotNil(t, block)

	tailed := func(tail ...byte) []byte {
		return pem.EncodeToMemory(&pem.Block{
			Type:  block.Type,
			Bytes: slices.Concat(block.Bytes, tail),
		})
	}

	var raw bytes.Buffer
	raw.Write(tailed())           // the key exactly as it is on disk
	raw.Write(tailed(0x00))       // the same key, one padding byte appended
	raw.Write(tailed(0xde, 0xad)) // the same key, two other bytes appended

	bundle, err := pemscan.Scanner{}.Scan(t.Context(), raw.Bytes(), "/test/one-key-three-blocks.pem")
	require.NoError(t, err)
	// Go cannot parse an ML-DSA SubjectPublicKeyInfo at all, so all three
	// blocks -- the intact one included -- take the fallback path. If any of
	// them parsed normally it would never reach the guard and this would prove
	// nothing about it.
	require.Empty(t, bundle.PublicKeys)
	require.Len(t, bundle.ParseErrors, 3,
		"every block must reach analyzeParseError, or this proves nothing")

	d := cdxprops.NewConverter().PEMBundle(t.Context(), bundle)
	require.NotNil(t, d)

	var keys []cdx.Component
	for _, compo := range d.Components {
		if strings.HasPrefix(compo.BOMRef, "crypto/key/") {
			keys = append(keys, compo)
		}
	}
	require.Len(t, keys, 1,
		"one key with two different tails appended is one asset, not three")
	// Which one survived, and what it published. hashRawPublicKey base64s the
	// DER it is handed straight into the value, so a guard that let a tail
	// through would ship the appended bytes verbatim as the key's value --
	// asserting the exact encoding of the intact block is what rules that out.
	require.Equal(t, base64.StdEncoding.EncodeToString(block.Bytes),
		keys[0].CryptoProperties.RelatedCryptoMaterialProperties.Value,
		"the published value must be the key's own DER, with nothing appended")
}

// TestPEMBundle_RejectedPublicKeyBlockIsLoggedAtWarn pins the other half of the
// rejection: that it is a rejection and not a disappearance.
//
// PEMBundle has no error return, so this Warn is the only thing an operator
// ever sees about a `PUBLIC KEY` block the converter refused. "No components"
// is satisfied equally by a loud refusal and by a silent one, so every
// trailing-data test above stays green if analyzeParseError's PUBLIC KEY branch
// swallows the error, or if this line is demoted to Debug -- which in a tool
// whose default output is not verbose is silence. The document would then say
// "no key here" about a file the operator believes holds one, with nothing
// anywhere to contradict it, which is the failure mode #213 shipped.
//
// The PRIVATE KEY branch of the same switch is pinned by
// TestPEMBundle_BundleErrorLogIdentifiesFileAndBlock; this is the public half,
// and nothing covered it.
//
// Not parallel: it swaps the process-wide slog default. See the note on
// TestPEMBundle_BundleErrorLogIdentifiesFileAndBlock.
func TestPEMBundle_RejectedPublicKeyBlockIsLoggedAtWarn(t *testing.T) {
	var logBuf bytes.Buffer
	restore := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelWarn})))
	t.Cleanup(func() { slog.SetDefault(restore) })

	data, err := cdxtest.TestData(cdxtest.MLDSA65PublicKey)
	require.NoError(t, err)
	block, _ := pem.Decode(data)
	require.NotNil(t, block)

	withTrailer := pem.EncodeToMemory(&pem.Block{
		Type:  block.Type,
		Bytes: slices.Concat(block.Bytes, []byte{0xde, 0xad, 0xbe, 0xef}),
	})

	bundle, err := pemscan.Scanner{}.Scan(t.Context(), withTrailer, "/test/tailed-public-key.pem")
	require.NoError(t, err)
	require.Len(t, bundle.ParseErrors, 1,
		"the block must reach analyzeParseError, or this proves nothing")

	d := cdxprops.NewConverter().PEMBundle(t.Context(), bundle)
	require.NotNil(t, d)
	require.Empty(t, d.Components)

	logged := logBuf.String()
	require.Contains(t, logged, "level=WARN",
		"a key dropped below the default log level is a silently dropped key")
	require.Contains(t, logged, "analyzing bundle returned an error")
	require.Contains(t, logged, "pem block 0 (PUBLIC KEY)",
		"the operator has to know which block was refused")
	require.Contains(t, logged, "trailing data",
		"and why -- a tail is an operator-fixable input problem, unlike an OID "+
			"the registry does not carry")
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

// TestPEMBundle_CRLWithoutNextUpdateOmitsTheProperty covers the branch nothing
// else reaches: RFC 5280 makes nextUpdate OPTIONAL, and crlToCDX used to format
// it unconditionally, so a CRL without one reported
// next_update=0001-01-01T00:00:00Z -- a fabricated expiry, indistinguishable
// from a real one to anything consuming the property.
//
// The CRL is built by the generator and then has the field cleared, because
// x509.CreateRevocationList refuses to marshal a zero NextUpdate (it compares
// against ThisUpdate), so a genuinely field-less CRL cannot be produced with
// Go's own encoder. Clearing it after parsing exercises crlToCDX on exactly the
// struct a third-party CRL would yield, and keeps Raw realistic so the
// content-addressed bom-ref stays meaningful.
func TestPEMBundle_CRLWithoutNextUpdateOmitsTheProperty(t *testing.T) {
	t.Parallel()

	bundle := csrCRLBundle(t, "/test/no-next-update.pem")
	require.Len(t, bundle.CRLs, 1)
	require.False(t, bundle.CRLs[0].NextUpdate.IsZero(),
		"the generator must set NextUpdate, or clearing it proves nothing")
	bundle.CRLs[0].NextUpdate = time.Time{}

	d := cdxprops.NewConverter().PEMBundle(t.Context(), bundle)
	require.NotNil(t, d)

	var found bool
	for _, compo := range d.Components {
		if !strings.HasPrefix(compo.BOMRef, "crypto/crl/") {
			continue
		}
		found = true
		require.NotNil(t, compo.Properties)
		names := make([]string, 0, len(*compo.Properties))
		for _, p := range *compo.Properties {
			names = append(names, p.Name)
			require.NotEqual(t, "next_update", p.Name,
				"a CRL with no nextUpdate must omit the property, not invent %q", p.Value)
		}
		// The rest must survive, or "omitted" could just mean the property set
		// was dropped wholesale. That includes pem_type: type: other is the only
		// schema-native marker both csrToCDX and crlToCDX share, so pem_type is
		// the sole machine-readable way to tell a CRL component from a CSR one,
		// and it must actually say "CRL" rather than merely be present.
		require.Subset(t, names, []string{"pem_type", "issuer", "this_update", "revoked_count"})
		require.Equal(t, "CRL", cdxtest.GetProp(compo, "pem_type"))
	}
	require.True(t, found, "no CRL component emitted")
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
			require.Equal(t, "CRL", cdxtest.GetProp(crlCompo, "pem_type"))
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

// TestPEMBundle_BundleErrorLogIdentifiesFileAndBlock pins the only information
// an operator ever gets about a key the converter could not describe.
//
// PEMBundle has no error return, so restOfPEMBundleToCDX's joined error dies in
// this one Warn. It used to carry "error" and nothing else, and the join
// discarded which block produced which line -- so a host whose keys sit under
// OIDs the registry does not carry (no LMS, no XMSS, no composite arcs) lost
// every one of them from the CBOM, and the evidence was an anonymous
// multi-line blob per file next to statistics showing nothing amiss.
//
// The location reaches the record from the context, not from this call site:
// service.scan installs it with log.ContextAttrs for every log emitted about
// that file. So the handler here is the production ContextHandler -- with a
// plain one the attribute would be dropped and this test would pass or fail for
// a reason that has nothing to do with the code under test -- and the location
// is asserted to appear ONCE. Adding it at the call site as well emitted a
// duplicate "location" key in every JSON record, which is last-wins in most
// parsers and a validation error in some log pipelines.
//
// Not parallel: it swaps the process-wide slog default, and a parallel sibling
// emitting a Warn would land in this buffer. Go resumes parallel tests only
// after the sequential ones finish, so staying sequential is the isolation.
func TestPEMBundle_BundleErrorLogIdentifiesFileAndBlock(t *testing.T) {
	var logBuf bytes.Buffer
	restore := slog.Default()
	handler := log.NewContextHandler(slog.NewTextHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelWarn}))
	slog.SetDefault(slog.New(handler))
	t.Cleanup(func() { slog.SetDefault(restore) })

	// 1.3.9999.6.1.1 is not in the registry. It is a real OID -- oqs-provider
	// assigns it to SPHINCS+-Haraka-128f-robust -- so this is exactly the
	// "PQC key under an OID we do not carry" case, not a synthetic impossibility.
	unregistered := asn1.ObjectIdentifier{1, 3, 9999, 6, 1, 1}

	// Two blocks, so an index that is merely always-zero cannot pass.
	var raw bytes.Buffer
	raw.Write(pkcs8PEM(t, unregistered, 32))
	raw.Write(pkcs8PEM(t, unregistered, 64))

	const location = "/etc/pki/unknown-algorithms.pem"
	// The context service.scan builds, so the record carries what it carries in
	// production and no more.
	ctx := log.ContextAttrs(t.Context(), slog.String("location", location))

	bundle, err := pemscan.Scanner{}.Scan(ctx, raw.Bytes(), location)
	require.NoError(t, err, "the PEM envelopes themselves are well formed")
	require.Len(t, bundle.ParseErrors, 2,
		"both blocks must reach analyzeParseError, or this proves nothing")

	d := cdxprops.NewConverter().PEMBundle(ctx, bundle)
	require.NotNil(t, d)
	require.Empty(t, d.Components,
		"an unregistered OID must not be guessed at")

	logged := logBuf.String()
	require.Contains(t, logged, "analyzing bundle returned an error")
	require.Equal(t, 1, strings.Count(logged, "location="+location),
		"the warning must name the file exactly once; a second copy is a duplicate JSON key")
	require.Contains(t, logged, "pem block 0 (PRIVATE KEY)")
	require.Contains(t, logged, "pem block 1 (PRIVATE KEY)",
		"the join must keep the blocks apart, not merge them into one blob")
	require.Contains(t, logged, "1.3.9999.6.1.1",
		"the underlying cause must survive the wrapping")
}

// TestPEMBundle_TwoCRLsSameIssuerStayDistinct is the CRL twin of
// TestPEMBundle_TwoCSRsSameSubjectStayDistinct, and the only thing that fails
// if someone swaps crlToCDX's DER digest for Converter.BOMRefHash.
//
// Until now that swap was caught only by the byte goldens, which stop
// defending it the moment someone runs -update.
//
// The two lists are built with identical issuer, thisUpdate, nextUpdate and
// revoked COUNT, differing only in the CRL number and which serial is revoked
// -- none of which the component records. So the two components are
// byte-identical JSON, and BOMRefHash would give them one ref and the
// Builder's first-wins dedup would silently discard the second. Hashing the
// DER keeps them apart because the DER covers the revoked entries.
func TestPEMBundle_TwoCRLsSameIssuerStayDistinct(t *testing.T) {
	t.Parallel()

	ca, err := cdxtest.CertBuilder{}.
		WithIsCA(true).
		WithKeyUsage(x509.KeyUsageCRLSign | x509.KeyUsageCertSign).
		Generate()
	require.NoError(t, err)
	signer, ok := ca.Key.(crypto.Signer)
	require.True(t, ok)

	// Fixed timestamps. time.Now() would differ between the two calls only
	// below RFC3339's one-second resolution, so the collision this test is
	// about would be reintroduced or not depending on how fast the machine is.
	thisUpdate := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	nextUpdate := thisUpdate.Add(24 * time.Hour)

	newCRL := func(t *testing.T, number, serial int64) *x509.RevocationList {
		t.Helper()

		der, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
			Number:     big.NewInt(number),
			ThisUpdate: thisUpdate,
			NextUpdate: nextUpdate,
			RevokedCertificateEntries: []x509.RevocationListEntry{
				{SerialNumber: big.NewInt(serial), RevocationTime: thisUpdate},
			},
		}, ca.Cert, signer)
		require.NoError(t, err)

		crl, err := x509.ParseRevocationList(der)
		require.NoError(t, err)
		return crl
	}

	first, second := newCRL(t, 1, 42), newCRL(t, 2, 43)
	require.Equal(t, first.Issuer.String(), second.Issuer.String(),
		"the fixtures must share an issuer, or this proves nothing")
	require.Len(t, second.RevokedCertificateEntries, len(first.RevokedCertificateEntries),
		"the revoked count is what the component records, so it must not differ")

	d := cdxprops.NewConverter().PEMBundle(t.Context(), model.PEMBundle{
		Location: "/test/revocations.pem",
		CRLs:     []*x509.RevocationList{first, second},
	})
	require.NotNil(t, d)

	doc := emitDocument(t, "1.6", *d)
	require.NotNil(t, doc.Components)

	var refs []string
	for _, compo := range *doc.Components {
		if strings.HasPrefix(compo.Name, "CRL: ") {
			refs = append(refs, compo.BOMRef)
		}
	}
	require.Len(t, refs, 2,
		"two lists from the same issuer with different revocations collapsed into one component")
	require.NotEqual(t, refs[0], refs[1])
}

// TestPEMBundle_EmptyDNFallsBackToUnknown pins the "unknown" fallbacks in
// csrSubjectName and crlIssuerName, which nothing exercised -- deleting either
// broke no test.
//
// They are not there to stop Builder.appendDetection dropping an empty Name,
// which is what their comment used to claim: the "CSR: " and "CRL: " prefixes
// make Name non-empty regardless. They are there for the ref, which is
// crypto/csr/<name>@<digest>; without them an empty DN yields
// "crypto/csr/@sha256:..." -- indistinguishable from a truncation.
//
// Both DNs here are genuinely empty in real DER, not hand-built structs: Go
// will issue a certificate and a request with no subject at all.
func TestPEMBundle_EmptyDNFallsBackToUnknown(t *testing.T) {
	t.Parallel()

	key, err := cdxtest.GenECPrivateKey(elliptic.P256())
	require.NoError(t, err)

	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
	require.NoError(t, err)
	csr, err := x509.ParseCertificateRequest(csrDER)
	require.NoError(t, err)
	require.Empty(t, csr.Subject.String(), "the request's subject must really be empty")

	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		NotBefore:             time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:              time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCRLSign | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, key.Public(), key)
	require.NoError(t, err)
	ca, err := x509.ParseCertificate(caDER)
	require.NoError(t, err)
	require.Empty(t, ca.Subject.String(), "the issuer's subject must really be empty")

	crlDER, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
		Number:     big.NewInt(1),
		ThisUpdate: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		NextUpdate: time.Date(2026, 1, 2, 0, 0, 0, 0, time.UTC),
	}, ca, key)
	require.NoError(t, err)
	crl, err := x509.ParseRevocationList(crlDER)
	require.NoError(t, err)
	require.Empty(t, crl.Issuer.String(), "the list's issuer must really be empty")

	d := cdxprops.NewConverter().PEMBundle(t.Context(), model.PEMBundle{
		Location:            "/test/anonymous.pem",
		CertificateRequests: []*x509.CertificateRequest{csr},
		CRLs:                []*x509.RevocationList{crl},
	})
	require.NotNil(t, d)

	byName := map[string]cdx.Component{}
	for _, compo := range d.Components {
		byName[compo.Name] = compo
	}

	for prefix, refPrefix := range map[string]string{
		"CSR: ": "crypto/csr/unknown@",
		"CRL: ": "crypto/crl/unknown@",
	} {
		compo, ok := byName[prefix+"unknown"]
		require.True(t, ok, "no %qunknown component; got %v", prefix, slices.Sorted(maps.Keys(byName)))
		require.True(t, strings.HasPrefix(compo.BOMRef, refPrefix),
			"an empty DN must not produce a ref with a hole in it: %q", compo.BOMRef)
	}
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
