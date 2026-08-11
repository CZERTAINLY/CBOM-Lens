package cdxprops_test

import (
	"bytes"
	"context"
	"crypto"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
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
// of (two ML-DSA-65 keys and two garbage blocks). It yields 25 components:
// 13 algorithm, 11 related-crypto-material and 1 certificate. No protocol asset
// -- PEMBundle cannot produce one. More than one test wants this bundle, which
// is why it is a helper.
//
// That is the count BEFORE the Builder dedupes by bom-ref; only 18 of the 25
// are distinct, because the bundle deliberately holds the CSR's key twice (once
// as a private key, once as the request's subject) and both ML-DSA blocks name
// the same algorithm.
//
// The count was 20 until the post-quantum PRIVATE KEY block started
// contributing key material as well as an algorithm, and 21 until the CSR and
// the CRL started reporting their own cryptography: the request now contributes
// its requested key and that key's algorithm, and the list contributes the
// algorithm it was signed with and the hash that decomposes into. The two
// garbage blocks still error out and contribute nothing.
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
	require.Len(t, components, 25)

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

// TestPEMBundle_OneKeyTwoSourcesShareARefAndDisagreeOnFormat documents the
// precondition that makes format nondeterministic in a delivered BOM, and shows
// it is STRUCTURAL rather than a race: the same certificate run through
// Converter.PEMBundle and through Converter.CertHit yields two public-key
// components with one identical bom-ref, and only the PEM one carries a format.
//
// The ref is a digest of the marshalled SPKI alone (publicKeyComponents /
// hashPublicKey) -- no path, no source and no encoding enter it, which is
// deliberate, because that is what lets one key found at three paths dedupe to
// one asset. setPEMFormat, by contrast, runs only over what Converter.PEMBundle
// collected.
//
// Nothing here is wrong on its own: this test asserts the collision, not a
// defect. Reconciling it is bom.Builder.appendDetection's job, since that is the
// only place both detections meet -- see mergeRelatedCryptoMaterialFormat and
// TestBuilder_AppendDetections_RelatedCryptoMaterialFormatOrderIndependent.
func TestPEMBundle_OneKeyTwoSourcesShareARefAndDisagreeOnFormat(t *testing.T) {
	t.Parallel()

	selfSigned, err := cdxtest.CertBuilder{}.
		WithSignatureAlgorithm(x509.SHA256WithRSA).
		Generate()
	require.NoError(t, err)

	c := cdxprops.NewConverter()

	pemDetection := c.PEMBundle(t.Context(), model.PEMBundle{
		Location: pemBundleLocation,
		Certificates: []model.CertHit{
			{Cert: selfSigned.Cert, Source: "PEM", Location: pemBundleLocation},
		},
	})
	require.NotNil(t, pemDetection)

	// The same certificate as it arrives from a PKCS#12 store: same bytes, same
	// key, a source setPEMFormat never runs for.
	storeDetection := c.CertHit(t.Context(), model.CertHit{
		Cert:     selfSigned.Cert,
		Source:   "PKCS12",
		Location: "/etc/ssl/store.p12",
	})
	require.NotNil(t, storeDetection)

	pemKey := publicKeyComponent(t, pemDetection.Components)
	storeKey := publicKeyComponent(t, storeDetection.Components)

	// Checked before the equality: two refless components are also "equal", and
	// publicKeyComponents does return a component with no ref for a key it
	// cannot identify, so without this the collision could be asserted by a
	// path where no collision exists. Same guard, same reason, as
	// TestPEMBundle_BOMRefsMatchContents' checked counter.
	require.NotEmpty(t, pemKey.BOMRef)
	require.Equal(t, pemKey.BOMRef, storeKey.BOMRef,
		"one key is one bom-ref regardless of where it was found; that is what "+
			"makes the two detections collide in the Builder")

	require.Equal(t, "PEM", pemKey.CryptoProperties.RelatedCryptoMaterialProperties.Format,
		"the PEM path knows the encoding")
	require.Empty(t, storeKey.CryptoProperties.RelatedCryptoMaterialProperties.Format,
		"the PKCS12 path does not, so the two components differ in exactly one "+
			"field while sharing a ref")
}

// publicKeyComponent returns the single public-key component among compos,
// failing if there is not exactly one. The two detections above carry an
// algorithm and a certificate too, and the assertion is only about the key.
func publicKeyComponent(t *testing.T, compos []cdx.Component) cdx.Component {
	t.Helper()

	var found []cdx.Component
	for _, compo := range compos {
		if compo.CryptoProperties == nil {
			continue
		}
		rcmp := compo.CryptoProperties.RelatedCryptoMaterialProperties
		if rcmp == nil || rcmp.Type != cdx.RelatedCryptoMaterialTypePublicKey {
			continue
		}
		found = append(found, compo)
	}
	require.Len(t, found, 1, "expected exactly one public-key component")
	return found[0]
}

// TestPEMBundle_CRLAndCertificateShareASignatureAlgorithmRefAndDisagreeOnItsEdges
// is the edge-shaped twin of the test above: it documents the precondition that
// made a certificate's dependsOn array nondeterministic, and shows it is
// STRUCTURAL rather than a race.
//
// A signature algorithm's bom-ref is derived from the x509.SignatureAlgorithm
// enum and the OID alone (signatureAlgorithmComponents), so one CA certificate
// and a CRL that CA signed land on the same ref -- deliberately, since they
// really are the same algorithm. What differs is what each producer can say
// about it. certHitToComponents decomposes a certificate's signature into the
// subject's public-key algorithm AND the hash, while crlToCDX names only the
// hash, because a revocation list has no subject key to name. Two true claims
// about one ref, made by two producers neither of which can see the other.
//
// Nothing here is wrong on its own: this test asserts the collision, not a
// defect. Reconciling it is bom.Builder.appendDetection's job -- see
// mergeDependsOn and
// TestBuilder_AppendDetections_DependsOnSurvivesEveryArrivalPermutation.
func TestPEMBundle_CRLAndCertificateShareASignatureAlgorithmRefAndDisagreeOnItsEdges(t *testing.T) {
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
	require.Equal(t, ca.Cert.SignatureAlgorithm, crl.SignatureAlgorithm,
		"the two fixtures must be signed with the same algorithm, or there is no "+
			"collision to assert")

	c := cdxprops.NewConverter()

	certDetection := c.CertHit(t.Context(), model.CertHit{
		Cert:     ca.Cert,
		Source:   "PEM",
		Location: "/etc/ssl/certs/ca.pem",
	})
	require.NotNil(t, certDetection)

	crlDetection := c.PEMBundle(t.Context(), model.PEMBundle{
		Location: "/etc/ssl/crl/revocations.pem",
		CRLs:     []*x509.RevocationList{crl},
	})
	require.NotNil(t, crlDetection)

	certDeps := certDetection.Dependencies
	crlDeps := crlDetection.Dependencies
	require.Len(t, certDeps, 1, "the certificate names one signature algorithm")
	require.Len(t, crlDeps, 1, "so does the revocation list")

	// Checked before the equality: two empty refs are also "equal", and both
	// producers do return without a dependency entry for an algorithm that names
	// no hash, so without this the collision could be asserted by a path where no
	// collision exists.
	require.NotEmpty(t, certDeps[0].Ref)
	require.Equal(t, certDeps[0].Ref, crlDeps[0].Ref,
		"one algorithm is one bom-ref regardless of what it signed; that is what "+
			"makes the two detections collide in the Builder")

	require.NotNil(t, certDeps[0].Dependencies)
	require.NotNil(t, crlDeps[0].Dependencies)
	require.NotEqual(t, *crlDeps[0].Dependencies, *certDeps[0].Dependencies,
		"the two producers describe the same ref's edges differently, which is "+
			"what a first-wins store had to choose between")

	require.Len(t, *certDeps[0].Dependencies, 2,
		"a certificate's signature decomposes into the subject's public-key "+
			"algorithm and the hash")
	require.Len(t, *crlDeps[0].Dependencies, 1,
		"a revocation list has no subject key, so it names only the hash")
	require.Subset(t, *certDeps[0].Dependencies, *crlDeps[0].Dependencies,
		"the CRL's claim is a subset of the certificate's here, which is the only "+
			"reason the golden corpus survived first-wins: the certificate is "+
			"appended first and the CRL took nothing away")
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

// materialAlgorithmRefs returns the algorithm refs a component's key material
// points at, in whichever way the emitted document expresses them: 1.6 writes
// relatedCryptoMaterialProperties.algorithmRef, and 1.7 deprecates that field
// in favour of relatedCryptographicAssets entries typed "algorithm". A test
// that read only one of the two would silently prove nothing in the other
// version.
func materialAlgorithmRefs(compo cdx.Component) []string {
	if compo.CryptoProperties == nil || compo.CryptoProperties.RelatedCryptoMaterialProperties == nil {
		return nil
	}
	rcmp := compo.CryptoProperties.RelatedCryptoMaterialProperties
	var refs []string
	if rcmp.AlgorithmRef != "" {
		refs = append(refs, string(rcmp.AlgorithmRef))
	}
	if rcmp.RelatedCryptographicAssets == nil {
		return refs
	}
	for _, rca := range *rcmp.RelatedCryptographicAssets {
		if rca.Type == "algorithm" {
			refs = append(refs, rca.Ref)
		}
	}
	return refs
}

// certificateKeyRefs returns the key material a certificate component points
// at, in whichever way the emitted document expresses it. It is
// materialAlgorithmRefs for the other end of the same edge: 1.6 writes
// certificateProperties.subjectPublicKeyRef, and emit17 CLEARS that field --
// deliberately, since relatedCryptographicAssets supersedes it with structural
// ref integrity -- and writes a relatedCryptographicAssets entry typed
// "publicKey" instead. A test that read only subjectPublicKeyRef would
// therefore not merely prove less in 1.7, it would fail there on a correct
// document.
func certificateKeyRefs(compo cdx.Component) []string {
	if compo.CryptoProperties == nil || compo.CryptoProperties.CertificateProperties == nil {
		return nil
	}
	certp := compo.CryptoProperties.CertificateProperties
	var refs []string
	if certp.SubjectPublicKeyRef != "" {
		refs = append(refs, string(certp.SubjectPublicKeyRef))
	}
	if certp.RelatedCryptographicAssets == nil {
		return refs
	}
	for _, rca := range *certp.RelatedCryptographicAssets {
		if rca.Type == "publicKey" {
			refs = append(refs, rca.Ref)
		}
	}
	return refs
}

// dependsOn returns what the emitted document says ref depends on.
func dependsOn(doc cdx.BOM, ref string) []string {
	if doc.Dependencies == nil {
		return nil
	}
	for _, dep := range *doc.Dependencies {
		if dep.Ref != ref || dep.Dependencies == nil {
			continue
		}
		return *dep.Dependencies
	}
	return nil
}

// componentsByRef indexes an emitted document by bom-ref.
func componentsByRef(doc cdx.BOM) map[string]cdx.Component {
	byRef := map[string]cdx.Component{}
	if doc.Components == nil {
		return byRef
	}
	for _, compo := range *doc.Components {
		byRef[compo.BOMRef] = compo
	}
	return byRef
}

// TestPEMBundle_CSRPublicKeyReachesTheBOM covers the whole point of scanning a
// certificate request: the key someone is asking to have certified.
//
// x509.ParseCertificateRequest hands over PublicKey and PublicKeyAlgorithm, and
// csrToCDX read neither. So a .csr contributed one asset carrying a subject
// string and a revocation-less "other" material type -- a CBOM entry that names
// a PKI artefact and says nothing about the cryptography in it, which is the
// one thing a CBOM exists to record. An inventory built from such a scan cannot
// answer "which requests carry a key we must migrate", the question a request
// is the earliest possible place to answer.
//
// It asserts on the EMITTED DOCUMENT because that is where a component with no
// ref, or an edge to a component that was dropped, actually disappears; and in
// both spec versions, because 1.7 maps material-to-algorithm edges through a
// different field than 1.6.
func TestPEMBundle_CSRPublicKeyReachesTheBOM(t *testing.T) {
	t.Parallel()

	for _, version := range []string{"1.6", "1.7"} {
		t.Run(version, func(t *testing.T) {
			t.Parallel()

			key, err := cdxtest.GenECPrivateKey(elliptic.P256())
			require.NoError(t, err)
			csr, _, err := cdxtest.GenCSR(key)
			require.NoError(t, err)

			d := cdxprops.NewConverter().PEMBundle(t.Context(), model.PEMBundle{
				Location:            "/test/request.pem",
				CertificateRequests: []*x509.CertificateRequest{csr},
			})
			require.NotNil(t, d)

			doc := emitDocument(t, version, *d)
			byRef := componentsByRef(doc)

			var csrRef string
			var keyCompo cdx.Component
			for ref, compo := range byRef {
				switch {
				case strings.HasPrefix(ref, "crypto/csr/"):
					csrRef = ref
				case strings.HasPrefix(ref, "crypto/key/"):
					keyCompo = compo
				}
			}
			require.NotEmpty(t, csrRef,
				"no CSR component, got %v", slices.Sorted(maps.Keys(byRef)))
			require.NotEmpty(t, keyCompo.BOMRef,
				"the requested public key never reached the document, got %v",
				slices.Sorted(maps.Keys(byRef)))

			rcmp := keyCompo.CryptoProperties.RelatedCryptoMaterialProperties
			require.NotNil(t, rcmp)
			require.Equal(t, cdx.RelatedCryptoMaterialTypePublicKey, rcmp.Type)
			require.NotEmpty(t, rcmp.Value,
				"the key asset must carry the SPKI it was identified by")

			// The key's algorithm must be a real, resolvable asset -- a ref to a
			// component the Builder dropped is worse than no ref at all.
			algRefs := materialAlgorithmRefs(keyCompo)
			require.Len(t, algRefs, 1, "the requested key must name exactly one algorithm")
			algCompo, ok := byRef[algRefs[0]]
			require.True(t, ok, "the key's algorithm ref %q resolves to nothing", algRefs[0])
			require.Equal(t, cdx.CryptoAssetTypeAlgorithm, algCompo.CryptoProperties.AssetType)
			// The curve is in the name, so this fails if the algorithm were
			// derived from anything but the key actually in the request.
			require.Equal(t, "ECDSA-P-256", algCompo.Name,
				"the algorithm must be the one the request actually asks for")

			require.Contains(t, dependsOn(doc, csrRef), keyCompo.BOMRef,
				"the request must depend on the key it requests certification for")
		})
	}
}

// TestPEMBundle_CRLSignatureAlgorithmReachesTheBOM is the CSR test's twin for
// the other artefact crlToCDX described without describing its cryptography.
//
// x509.ParseRevocationList fills in SignatureAlgorithm and crlToCDX never read
// it, so a scanned .crl reported an issuer, two timestamps and a count. The
// signature algorithm is the only cryptographic claim a revocation list makes,
// and it is precisely the claim a migration inventory needs: a CRL still signed
// with SHA-1 or RSA-1024 is an operational finding, and this tool reported the
// file without reporting that.
func TestPEMBundle_CRLSignatureAlgorithmReachesTheBOM(t *testing.T) {
	t.Parallel()

	for _, version := range []string{"1.6", "1.7"} {
		t.Run(version, func(t *testing.T) {
			t.Parallel()

			// An EC issuer, so the list is signed with something other than the
			// RSA default every other fixture in this file uses: a component
			// naming the algorithm the CRL was really signed with cannot be
			// confused with one naming a hardcoded favourite.
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
				"the fixture must be signed with the algorithm asserted below")

			d := cdxprops.NewConverter().PEMBundle(t.Context(), model.PEMBundle{
				Location: "/test/revocations.pem",
				CRLs:     []*x509.RevocationList{crl},
			})
			require.NotNil(t, d)

			doc := emitDocument(t, version, *d)
			byRef := componentsByRef(doc)

			var crlCompo cdx.Component
			for ref, compo := range byRef {
				if strings.HasPrefix(ref, "crypto/crl/") {
					crlCompo = compo
				}
			}
			require.NotEmpty(t, crlCompo.BOMRef,
				"no CRL component, got %v", slices.Sorted(maps.Keys(byRef)))

			algRefs := materialAlgorithmRefs(crlCompo)
			require.Len(t, algRefs, 1, "the list must name exactly one signature algorithm")
			algCompo, ok := byRef[algRefs[0]]
			require.True(t, ok, "the CRL's algorithm ref %q resolves to nothing", algRefs[0])
			require.Equal(t, cdx.CryptoAssetTypeAlgorithm, algCompo.CryptoProperties.AssetType)
			require.Equal(t, "ECDSA-SHA256", algCompo.Name,
				"the algorithm named must be the one the list was actually signed with")

			// A hash-then-sign scheme decomposes, exactly as it does for a
			// certificate: the signature algorithm depends on its hash, and the
			// hash is a component in its own right.
			var hashRef string
			for ref, compo := range byRef {
				if compo.CryptoProperties != nil &&
					compo.CryptoProperties.AlgorithmProperties != nil &&
					compo.CryptoProperties.AlgorithmProperties.Primitive == cdx.CryptoPrimitiveHash {
					hashRef = ref
				}
			}
			require.NotEmpty(t, hashRef,
				"SHA-384 is a component of the signature, got %v", slices.Sorted(maps.Keys(byRef)))
			require.Contains(t, dependsOn(doc, algCompo.BOMRef), hashRef,
				"the signature algorithm must depend on the hash it decomposes into")
		})
	}
}

// TestPEMBundle_CSRWithUnregisteredOIDStaysWellFormed covers the input that
// makes reading the requested key dangerous.
//
// x509.ParseCertificateRequest does NOT fail on an SPKI algorithm it does not
// recognise: it returns successfully with PublicKeyAlgorithm =
// UnknownPublicKeyAlgorithm and PublicKey nil. publicKeyComponents then cannot
// marshal the key, so it yields an algorithm and a ZERO key component -- and
// appending that would give the Builder a component with no ref to drop, while
// an unguarded dependency edge would point at a ref that exists nowhere in the
// document. Every post-quantum request in the wild takes this path today, so it
// is the common case for exactly the keys this tool exists to find.
//
// This test used to require that the algorithm survived, on the reasoning that
// "the request references SOME algorithm" stays true whatever the SPKI holds.
// That decision is reversed, and the assertions below are its negation, because
// the proposition emitted was not that one. publicKeyAlgorithmInfo's default
// branch names the asset "Unknown", stamps it with the OID 0.0.0.0 and takes
// publicKeyComponents' own default primitive "signature", and not one of the
// three is a fact about the request: an ML-KEM or an X25519 request was
// published to the inventory as a signature scheme under an OID nothing is
// registered under, which the consumer cannot tell from a real one. The part
// that was true was not expressible anyway -- the request component carries no
// algorithmRef and the key that would have carried one was never built, so the
// component arrived pointed at by nothing. And its bom-ref is a content hash
// over a component byte-identical for every such request, so forty pending PQC
// requests on a host collapsed onto one asset that merely accumulated an
// occurrence per file. Nothing is lost by dropping it: the SPKI's real OID is
// read off the DER and handed to the operator at WARN, which is where a value
// that names nothing belongs.
//
// Both spec versions are covered, for the reason given on
// TestPEMBundle_CSRAndCRLReachTheBOM: the 1.7 emitter maps the IR into
// components on its own, so a suppression proved only against 1.6 says nothing
// about what a 1.7 document carries -- and "the fabricated asset is absent" is
// exactly the claim a second emitter can quietly fail to honour.
func TestPEMBundle_CSRWithUnregisteredOIDStaysWellFormed(t *testing.T) {
	t.Parallel()

	for _, version := range []string{"1.6", "1.7"} {
		t.Run(version, func(t *testing.T) {
			t.Parallel()

			// 1.3.9999.6.1.1 is a real OID -- oqs-provider assigns it to
			// SPHINCS+-Haraka-128f-robust -- and is not one Go or the registry
			// knows, so this is a plausible request and not a synthetic
			// impossibility.
			csr := csrWithSPKIAlgorithm(t, asn1.ObjectIdentifier{1, 3, 9999, 6, 1, 1})
			require.Equal(t, x509.UnknownPublicKeyAlgorithm, csr.PublicKeyAlgorithm,
				"the fixture must reach the unparseable-key path, or this proves nothing")
			require.Nil(t, csr.PublicKey)

			var d *model.Detection
			require.NotPanics(t, func() {
				d = cdxprops.NewConverter().PEMBundle(t.Context(), model.PEMBundle{
					Location:            "/test/pqc-request.pem",
					CertificateRequests: []*x509.CertificateRequest{csr},
				})
			})
			require.NotNil(t, d)

			doc := emitDocument(t, version, *d)
			byRef := componentsByRef(doc)

			// Stated over the values in the document rather than over a count of
			// components: a count is satisfied by whichever asset happens to be
			// there, and what shipped was an asset that was well-formed and untrue.
			for ref, compo := range byRef {
				require.False(t, strings.HasPrefix(ref, "crypto/key/"),
					"a key that could not be identified must not be reported as an asset: %s", ref)
				require.NotEqual(t, "Unknown", compo.Name,
					"%q names no algorithm; it is the placeholder the enum falls through to", ref)
				require.False(t, strings.HasPrefix(ref, "crypto/algorithm/unknown"),
					"the placeholder algorithm reached the document: %s", ref)
				require.NotNil(t, compo.CryptoProperties)
				require.NotEqual(t, "0.0.0.0", compo.CryptoProperties.OID,
					"nothing is registered under 0.0.0.0, and a consumer cannot tell it "+
						"from an OID that is: %s", ref)
				require.NotEqual(t, cdx.CryptoAssetTypeAlgorithm, compo.CryptoProperties.AssetType,
					"nothing in this request names an algorithm: %s", ref)
			}

			// Everything the request itself asserts must survive. Refusing to
			// invent the cryptography is not a licence to drop the artefact it was
			// hung on: a pending PQC request is still a migration finding, and the
			// file it was found in is the actionable part of it.
			refs := csrRefs(doc)
			require.Len(t, refs, 1, "got %v", slices.Sorted(maps.Keys(byRef)))
			csrCompo := byRef[refs[0]]
			require.Equal(t, "CSR: pqc-request.example", csrCompo.Name)
			// By PREFIX, not by whole ref: the Builder rewrites the @sha256:... tail
			// into a UUIDv5 before emission, so the digest csrToCDX computed is not
			// what arrives here.
			require.True(t, strings.HasPrefix(csrCompo.BOMRef, "crypto/csr/pqc-request.example@"),
				"the request must keep its own identity: %s", csrCompo.BOMRef)
			require.Equal(t, cdx.CryptoAssetTypeRelatedCryptoMaterial,
				csrCompo.CryptoProperties.AssetType)

			require.NotNil(t, csrCompo.Properties)
			props := map[string]string{}
			for _, prop := range *csrCompo.Properties {
				props[prop.Name] = prop.Value
			}
			require.Equal(t, "CSR", props["pem_type"],
				"pem_type is the only machine-readable thing telling a CSR from a CRL")
			require.Equal(t, "CN=pqc-request.example", props["subject"])

			require.NotNil(t, csrCompo.Evidence)
			require.NotNil(t, csrCompo.Evidence.Occurrences)
			var locations []string
			for _, occ := range *csrCompo.Evidence.Occurrences {
				locations = append(locations, occ.Location)
			}
			require.Equal(t, []string{"/test/pqc-request.pem"}, locations)

			// No edge may name a component that is not in the document. The Builder
			// drops such edges with a warning, so this is stated over the emitted
			// dependencies rather than over the detection.
			if doc.Dependencies != nil {
				for _, dep := range *doc.Dependencies {
					require.Contains(t, byRef, dep.Ref)
					if dep.Dependencies == nil {
						continue
					}
					for _, to := range *dep.Dependencies {
						require.Contains(t, byRef, to, "dangling dependency edge %s -> %s", dep.Ref, to)
					}
				}
			}
		})
	}
}

// csrWithSPKIAlgorithm builds the DER of a certificate request whose
// subjectPublicKeyInfo carries algorithm, and parses it back.
//
// x509.CreateCertificateRequest cannot produce this: it only marshals keys Go
// implements, which is the whole point -- the request under test is one Go
// cannot make and can still parse. The signature is not a real one; nothing on
// this path verifies it, and ParseCertificateRequest does not either.
//
// The subject is a real CN because the emitted request is asserted on by value:
// its Name, its crypto/csr/<name>@ ref prefix and its subject property all read
// it, and an empty DN would send csrSubjectName down its "unknown" fallback and
// leave all three saying nothing that distinguishes this request from the
// fabrication under test. TestPEMBundle_EmptyDNFallsBackToUnknown builds its own
// subject-less request, so that fallback keeps its coverage.
func csrWithSPKIAlgorithm(t *testing.T, algorithm asn1.ObjectIdentifier) *x509.CertificateRequest {
	t.Helper()

	return csrWithSPKI(t,
		pkix.Name{CommonName: "pqc-request.example"},
		pkix.AlgorithmIdentifier{Algorithm: algorithm},
		asn1.BitString{Bytes: make([]byte, 32), BitLength: 32 * 8})
}

// csrWithSPKI is csrWithSPKIAlgorithm over the whole subjectPublicKeyInfo
// rather than just its OID: the AlgorithmIdentifier with its parameters, and
// the key body. A DSA request needs both -- Go's parsePublicKey reads p, q and
// g out of the parameters and y out of the BIT STRING -- and neither is
// expressible when the algorithm is a bare OID and the body is 32 zero bytes.
func csrWithSPKI(t *testing.T, subject pkix.Name, algorithm pkix.AlgorithmIdentifier, keyBody asn1.BitString) *x509.CertificateRequest {
	t.Helper()

	type tbsCSR struct {
		Version   int
		Subject   asn1.RawValue
		PublicKey struct {
			Algorithm pkix.AlgorithmIdentifier
			PublicKey asn1.BitString
		}
		Attributes []asn1.RawValue `asn1:"tag:0"`
	}

	subjectDER, err := asn1.Marshal(subject.ToRDNSequence())
	require.NoError(t, err)

	tbs := tbsCSR{
		Subject:    asn1.RawValue{FullBytes: subjectDER},
		Attributes: []asn1.RawValue{},
	}
	tbs.PublicKey.Algorithm = algorithm
	tbs.PublicKey.PublicKey = keyBody
	tbsDER, err := asn1.Marshal(tbs)
	require.NoError(t, err)

	der, err := asn1.Marshal(struct {
		TBS       asn1.RawValue
		SigAlg    pkix.AlgorithmIdentifier
		Signature asn1.BitString
	}{
		TBS:       asn1.RawValue{FullBytes: tbsDER},
		SigAlg:    algorithm,
		Signature: asn1.BitString{Bytes: make([]byte, 8), BitLength: 8 * 8},
	})
	require.NoError(t, err)

	csr, err := x509.ParseCertificateRequest(der)
	require.NoError(t, err, "an unrecognised SPKI algorithm must still parse")
	return csr
}

// csrWithDSAKey builds a certificate request asking for a 2048-bit DSA key to
// be certified, as real DER round-tripped through ParseCertificateRequest.
//
// Go will not create one: MarshalPKIXPublicKey refuses *dsa.PublicKey, which is
// the very refusal that leaves the request key-less downstream. Parsing has no
// such scruple. parsePublicKey's DSA arm wants an ASN.1 INTEGER in the BIT
// STRING and a SEQUENCE{p,q,g} in the parameters, rejects only non-positive
// values and checks nothing for primality, so p = 1<<2047 is a 2048-bit modulus
// as far as dsaKeyAdapter and the "DSA-2048" it names are concerned. The
// numbers are therefore not a pretend key: they are the smallest input that
// exercises the same code Go runs on a real one.
func csrWithDSAKey(t *testing.T) *x509.CertificateRequest {
	t.Helper()

	params, err := asn1.Marshal(struct{ P, Q, G *big.Int }{
		P: new(big.Int).Lsh(big.NewInt(1), 2047),
		Q: big.NewInt(0xFFFFFFFF),
		G: big.NewInt(2),
	})
	require.NoError(t, err)

	y, err := asn1.Marshal(big.NewInt(3))
	require.NoError(t, err)

	return csrWithSPKI(t,
		pkix.Name{CommonName: "dsa-request.example"},
		pkix.AlgorithmIdentifier{
			Algorithm:  asn1.ObjectIdentifier{1, 2, 840, 10040, 4, 1},
			Parameters: asn1.RawValue{FullBytes: params},
		},
		asn1.BitString{Bytes: y, BitLength: len(y) * 8})
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

// keyComponents returns the emitted public-key material, indexed by bom-ref.
func keyComponents(doc cdx.BOM) map[string]cdx.Component {
	keys := map[string]cdx.Component{}
	for ref, compo := range componentsByRef(doc) {
		if strings.HasPrefix(ref, "crypto/key/") {
			keys[ref] = compo
		}
	}
	return keys
}

// csrRefs returns the bom-refs of the emitted certificate-request components.
func csrRefs(doc cdx.BOM) []string {
	var refs []string
	for ref := range componentsByRef(doc) {
		if strings.HasPrefix(ref, "crypto/csr/") {
			refs = append(refs, ref)
		}
	}
	slices.Sort(refs)
	return refs
}

// spkiOfCSR is the base64 SPKI the emitted key component must carry for a
// request: the DER of the very key that request asks to have certified.
func spkiOfCSR(t *testing.T, csr *x509.CertificateRequest) string {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(csr.PublicKey)
	require.NoError(t, err)
	return base64.StdEncoding.EncodeToString(der)
}

// csrFor builds a request for key, with the given common name so that two
// requests can be told apart by something other than their key.
func csrFor(t *testing.T, commonName string, key crypto.PrivateKey) *x509.CertificateRequest {
	t.Helper()
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: commonName},
	}, key)
	require.NoError(t, err)
	csr, err := x509.ParseCertificateRequest(der)
	require.NoError(t, err)
	return csr
}

// TestPEMBundle_CSRRequestedKeyByAlgorithm is the requested-key assertion over
// the key types a scan actually meets, rather than over the one the fixtures
// happen to use.
//
// Every fixture that exercises the CSR path -- comprehensivePEMBundle, the
// corpus golden, and TestPEMBundle_CSRPublicKeyReachesTheBOM -- requests an EC
// key. So "the requested key reaches the BOM" was pinned for exactly one key
// family, and hardcoding x509.ECDSA in the call to publicKeyComponents left the
// whole suite green. The finding this change answers was written about an
// RSA-1024 request, and an RSA request is the one whose SIZE is the migration
// signal: "RSA" alone says nothing, "RSA-1024" is the finding.
//
// The SPKI is compared against the request's own key rather than merely
// required to be non-empty, which is what makes the row for one algorithm
// unable to pass on another algorithm's key material.
func TestPEMBundle_CSRRequestedKeyByAlgorithm(t *testing.T) {
	t.Parallel()

	rsa1024, err := cdxtest.GenRSAPrivateKey(1024)
	require.NoError(t, err)
	rsa2048, err := cdxtest.GenRSAPrivateKey(2048)
	require.NoError(t, err)
	ecP256, err := cdxtest.GenECPrivateKey(elliptic.P256())
	require.NoError(t, err)
	ecP384, err := cdxtest.GenECPrivateKey(elliptic.P384())
	require.NoError(t, err)
	_, ed25519Key, err := cdxtest.GenEd25519Keys()
	require.NoError(t, err)

	for name, tt := range map[string]struct {
		key     crypto.PrivateKey
		keyName string
		size    int
		oid     string
	}{
		// The finding's own example. 80 bits of classical security, and the
		// document has to say 1024 for anyone to know that.
		"RSA-1024":    {key: rsa1024, keyName: "RSA-1024", size: 1024, oid: "1.2.840.113549.1.1.1"},
		"RSA-2048":    {key: rsa2048, keyName: "RSA-2048", size: 2048, oid: "1.2.840.113549.1.1.1"},
		"ECDSA-P-256": {key: ecP256, keyName: "ECDSA-P-256", size: 256, oid: "1.2.840.10045.3.1.7"},
		"ECDSA-P-384": {key: ecP384, keyName: "ECDSA-P-384", size: 384, oid: "1.3.132.0.34"},
		"Ed25519":     {key: ed25519Key, keyName: "Ed25519", size: 256, oid: "1.3.101.112"},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			csr := csrFor(t, "request."+name, tt.key)
			d := cdxprops.NewConverter().PEMBundle(t.Context(), model.PEMBundle{
				Location:            "/test/" + name + ".csr",
				CertificateRequests: []*x509.CertificateRequest{csr},
			})
			require.NotNil(t, d)

			doc := emitDocument(t, "1.6", *d)
			byRef := componentsByRef(doc)
			keys := keyComponents(doc)
			require.Len(t, keys, 1,
				"one request asks to certify exactly one key, got %v",
				slices.Sorted(maps.Keys(byRef)))

			keyRef := slices.Sorted(maps.Keys(keys))[0]
			key := keys[keyRef]
			require.Equal(t, tt.keyName, key.Name)

			rcmp := key.CryptoProperties.RelatedCryptoMaterialProperties
			require.NotNil(t, rcmp)
			require.Equal(t, cdx.RelatedCryptoMaterialTypePublicKey, rcmp.Type)
			require.Equal(t, spkiOfCSR(t, csr), rcmp.Value,
				"the emitted key material must be this request's own SPKI")
			require.NotNil(t, rcmp.Size,
				"a key with no size cannot be triaged: %s", tt.keyName)
			require.Equal(t, tt.size, *rcmp.Size)

			algRefs := materialAlgorithmRefs(key)
			require.Len(t, algRefs, 1)
			algo, ok := byRef[algRefs[0]]
			require.True(t, ok, "the key's algorithm ref %q resolves to nothing", algRefs[0])
			require.Equal(t, cdx.CryptoAssetTypeAlgorithm, algo.CryptoProperties.AssetType)
			require.Equal(t, tt.keyName, algo.Name,
				"the algorithm must be derived from the key in the request")
			require.Equal(t, tt.oid, algo.CryptoProperties.OID)

			require.Equal(t, []string{keyRef}, dependsOn(doc, csrRefs(doc)[0]),
				"the request must depend on exactly the key it requests")

			// A request carries no private material and the converter is never
			// handed any, so nothing on this path may publish a private key.
			for ref, compo := range byRef {
				require.False(t, strings.HasPrefix(ref, "crypto/private_key/"),
					"a request published private key material: %s", ref)
				if compo.CryptoProperties == nil ||
					compo.CryptoProperties.RelatedCryptoMaterialProperties == nil {
					continue
				}
				require.NotEqual(t, cdx.RelatedCryptoMaterialTypePrivateKey,
					compo.CryptoProperties.RelatedCryptoMaterialProperties.Type, ref)
				require.NotEqual(t, cdx.RelatedCryptoMaterialTypeSecretKey,
					compo.CryptoProperties.RelatedCryptoMaterialProperties.Type, ref)
			}
		})
	}
}

// TestPEMBundle_TwoCSRsRequestedKeysAreNotCrossWired covers what
// TestPEMBundle_TwoCSRsSameSubjectStayDistinct cannot see.
//
// That test pins that two requests for one subject keep two bom-refs. It says
// nothing about the keys, because when it was written the requests carried
// none. Now each request also emits a key and an edge to it, and a loop that
// built the components per request but wired every edge to the last key -- or
// to the first -- would still leave two distinct request components and two
// distinct key components. Every count in the document would be right and every
// answer to "which key is this request asking us to certify" would be wrong.
//
// The two requests use different key families so that a swapped edge is visible
// as a wrong ALGORITHM and not only as a wrong digest, and different subjects
// because the subject is what names the request component -- it is how the test
// says WHICH request an edge starts at. Distinctness under a shared subject is
// TestPEMBundle_TwoCSRsSameSubjectStayDistinct's job and is not restated here.
func TestPEMBundle_TwoCSRsRequestedKeysAreNotCrossWired(t *testing.T) {
	t.Parallel()

	ecKey, err := cdxtest.GenECPrivateKey(elliptic.P256())
	require.NoError(t, err)
	rsaKey, err := cdxtest.GenRSAPrivateKey(2048)
	require.NoError(t, err)

	requests := map[string]*x509.CertificateRequest{
		"crypto/csr/ec.fixture.test@":  csrFor(t, "ec.fixture.test", ecKey),
		"crypto/csr/rsa.fixture.test@": csrFor(t, "rsa.fixture.test", rsaKey),
	}

	d := cdxprops.NewConverter().PEMBundle(t.Context(), model.PEMBundle{
		Location: "/test/requests.pem",
		CertificateRequests: []*x509.CertificateRequest{
			requests["crypto/csr/ec.fixture.test@"],
			requests["crypto/csr/rsa.fixture.test@"],
		},
	})
	require.NotNil(t, d)

	doc := emitDocument(t, "1.6", *d)
	byRef := componentsByRef(doc)
	require.Len(t, csrRefs(doc), 2)
	require.Len(t, keyComponents(doc), 2,
		"two requests for different keys must publish two keys, got %v",
		slices.Sorted(maps.Keys(byRef)))

	// Each request's edge must land on the key holding that request's own SPKI.
	for prefix, csr := range requests {
		var csrRef string
		for _, ref := range csrRefs(doc) {
			if strings.HasPrefix(ref, prefix) {
				csrRef = ref
			}
		}
		require.NotEmpty(t, csrRef, "no component for %s, got %v",
			prefix, slices.Sorted(maps.Keys(byRef)))

		targets := dependsOn(doc, csrRef)
		require.Len(t, targets, 1, "%s", csrRef)
		got, ok := byRef[targets[0]]
		require.True(t, ok, "the request's edge target %q resolves to nothing", targets[0])
		require.NotNil(t, got.CryptoProperties.RelatedCryptoMaterialProperties,
			"%s depends on %s, which is not key material", csrRef, got.BOMRef)
		require.Equal(t, spkiOfCSR(t, csr),
			got.CryptoProperties.RelatedCryptoMaterialProperties.Value,
			"%s is wired to the wrong key: it points at %s", csrRef, got.BOMRef)
	}
}

// TestPEMBundle_TwoCSRsSharingAKeyShareOneKeyComponent is the other half of the
// same question: a re-key request and a renewal request for the same key are
// two requests over ONE key, and reporting that key twice would inflate the
// inventory and split the migration work for it in two.
//
// The key component is content-addressed over the key, so the Builder's
// first-wins dedup is what has to collapse them -- and both requests must still
// end up pointing at the surviving ref rather than one of them pointing at a
// ref that was dropped.
func TestPEMBundle_TwoCSRsSharingAKeyShareOneKeyComponent(t *testing.T) {
	t.Parallel()

	key, err := cdxtest.GenECPrivateKey(elliptic.P256())
	require.NoError(t, err)

	// Distinct subjects, so the two requests cannot dedup as requests and the
	// test is about the key alone.
	first := csrFor(t, "renewal.fixture.test", key)
	second := csrFor(t, "rekey.fixture.test", key)

	d := cdxprops.NewConverter().PEMBundle(t.Context(), model.PEMBundle{
		Location:            "/test/requests.pem",
		CertificateRequests: []*x509.CertificateRequest{first, second},
	})
	require.NotNil(t, d)

	doc := emitDocument(t, "1.6", *d)
	refs := csrRefs(doc)
	require.Len(t, refs, 2, "the two requests must stay distinct")

	keys := keyComponents(doc)
	require.Len(t, keys, 1,
		"one key requested by two requests must be one component, got %v",
		slices.Sorted(maps.Keys(keys)))
	keyRef := slices.Sorted(maps.Keys(keys))[0]

	for _, ref := range refs {
		require.Equal(t, []string{keyRef}, dependsOn(doc, ref),
			"%s must point at the surviving key component", ref)
	}
}

// crlSignedWith issues a self-signed CA with algo and returns a revocation list
// that CA signed, so the list's signature algorithm is chosen rather than
// inherited from whatever cdxtest happens to default to.
func crlSignedWith(t *testing.T, algo x509.SignatureAlgorithm) *x509.RevocationList {
	t.Helper()

	ca, err := cdxtest.CertBuilder{}.
		WithIsCA(true).
		WithSignatureAlgorithm(algo).
		WithKeyUsage(x509.KeyUsageCRLSign | x509.KeyUsageCertSign).
		Generate()
	require.NoError(t, err)
	signer, ok := ca.Key.(crypto.Signer)
	require.True(t, ok)

	der, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
		Number:             big.NewInt(1),
		ThisUpdate:         time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		NextUpdate:         time.Date(2026, 1, 2, 0, 0, 0, 0, time.UTC),
		SignatureAlgorithm: algo,
		RevokedCertificateEntries: []x509.RevocationListEntry{
			{SerialNumber: big.NewInt(1), RevocationTime: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)},
		},
	}, ca.Cert, signer)
	require.NoError(t, err)

	crl, err := x509.ParseRevocationList(der)
	require.NoError(t, err)
	require.Equal(t, algo, crl.SignatureAlgorithm,
		"the fixture must be signed with the algorithm under test")
	return crl
}

// TestPEMBundle_CRLSignatureAlgorithmByIssuerKey is the CRL half of the same
// coverage hole. Every CRL fixture in the tree is signed by whatever key its
// issuing CA happened to get: the corpus golden and the dedicated CRL test use
// ECDSA, comprehensivePEMBundle uses RSA and asserts only a component count.
// Nothing pins that the algorithm a list reports is the algorithm it was
// actually signed with, across more than one family.
//
// The Ed25519 row also pins the hash decomposition, which reads like the
// exception and is not one: getAlgorithmProperties maps x509.PureEd25519 to
// SHA-512 (RFC 8032 builds Ed25519 on SHA-512), so the second return is NOT nil
// for Ed25519 and the list does emit an ed25519 -> SHA-512 edge. The nil branch
// is reached only by a signature algorithm Go does not recognise -- see
// TestPEMBundle_CRLWithUnrecognisedSignatureAlgorithm, which is what actually
// covers it.
func TestPEMBundle_CRLSignatureAlgorithmByIssuerKey(t *testing.T) {
	t.Parallel()

	for name, tt := range map[string]struct {
		algo     x509.SignatureAlgorithm
		algoName string
		hashName string
	}{
		"RSA":     {algo: x509.SHA256WithRSA, algoName: "SHA256-RSA", hashName: "SHA-256"},
		"ECDSA":   {algo: x509.ECDSAWithSHA384, algoName: "ECDSA-SHA384", hashName: "SHA-384"},
		"Ed25519": {algo: x509.PureEd25519, algoName: "Ed25519", hashName: "SHA-512"},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			crl := crlSignedWith(t, tt.algo)
			d := cdxprops.NewConverter().PEMBundle(t.Context(), model.PEMBundle{
				Location: "/test/" + name + ".crl",
				CRLs:     []*x509.RevocationList{crl},
			})
			require.NotNil(t, d)

			doc := emitDocument(t, "1.6", *d)
			byRef := componentsByRef(doc)

			var crlCompo cdx.Component
			for ref, compo := range byRef {
				if strings.HasPrefix(ref, "crypto/crl/") {
					crlCompo = compo
				}
			}
			require.NotEmpty(t, crlCompo.BOMRef,
				"no CRL component, got %v", slices.Sorted(maps.Keys(byRef)))

			algRefs := materialAlgorithmRefs(crlCompo)
			require.Len(t, algRefs, 1)
			algo, ok := byRef[algRefs[0]]
			require.True(t, ok, "the list's algorithm ref %q resolves to nothing", algRefs[0])
			require.Equal(t, tt.algoName, algo.Name,
				"the list must report the algorithm it was signed with")

			var hashRef string
			for ref, compo := range byRef {
				if compo.CryptoProperties.AlgorithmProperties != nil &&
					compo.CryptoProperties.AlgorithmProperties.Primitive == cdx.CryptoPrimitiveHash {
					hashRef = ref
					require.Equal(t, tt.hashName, compo.Name)
				}
			}
			require.NotEmpty(t, hashRef,
				"%s decomposes into %s, got %v", tt.algoName, tt.hashName,
				slices.Sorted(maps.Keys(byRef)))
			require.Contains(t, dependsOn(doc, algo.BOMRef), hashRef,
				"the signature algorithm must depend on the hash it decomposes into")
		})
	}
}

// crlWithSubstitutedSignatureOID rewrites the ecdsa-with-SHA256 OID in a real
// revocation list's DER with one nothing recognises, in both the places RFC
// 5280 puts it: TBSCertList.signature and CertificateList.signatureAlgorithm.
//
// The replacement is the same length, so every enclosing ASN.1 length stays
// correct and Go still parses the list -- with SignatureAlgorithm =
// UnknownSignatureAlgorithm, which is the state under test. Nothing on the
// converter's path verifies the signature, and neither does
// ParseRevocationList, so the now-wrong signature bytes do not matter.
//
// Building the DER by hand was the alternative and is worse: ParseRevocationList
// enforces rather more of RFC 5280 than ParseCertificateRequest does, so a
// hand-built list would be testing the fixture.
func crlWithSubstitutedSignatureOID(t *testing.T) *x509.RevocationList {
	t.Helper()

	signed := crlSignedWith(t, x509.ECDSAWithSHA256)

	// 1.2.840.10045.4.3.2 (ecdsa-with-SHA256) -> 1.2.840.10045.4.3.99, which is
	// unassigned: same arc, same encoded length, no meaning to Go or to the
	// registry.
	from := []byte{0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02}
	to := []byte{0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x63}
	require.Equal(t, 2, bytes.Count(signed.Raw, from),
		"the OID must appear exactly twice, or the substitution is not the one described")
	patched := bytes.ReplaceAll(signed.Raw, from, to)

	crl, err := x509.ParseRevocationList(patched)
	require.NoError(t, err, "an unrecognised signature OID must still parse")
	require.Equal(t, x509.UnknownSignatureAlgorithm, crl.SignatureAlgorithm,
		"the fixture must reach the unrecognised-algorithm path")
	return crl
}

// TestPEMBundle_CRLWithUnrecognisedSignatureAlgorithm covers the CRL input that
// makes reading the signature algorithm dangerous, and it is the only test in
// the tree that reaches the nil-hash branch of crlToCDX.
//
// getAlgorithmProperties returns a hash name for every signature algorithm Go's
// enum knows -- including Ed25519, which maps to SHA-512 -- so the branch that
// guards against a nil second return is reachable ONLY through an algorithm the
// enum does not cover. Dropping that guard leaves the whole suite green and
// panics on the first such list a scan meets; post-quantum CRLs are exactly
// that input, and they are the ones this tool exists to find.
//
// It also pins that the OID reaches the document from the list's own DER. The
// enum lookup answers first for every recognised algorithm, so sigAlgOIDFromRaw
// is unobservable on the CRL path until the enum misses.
func TestPEMBundle_CRLWithUnrecognisedSignatureAlgorithm(t *testing.T) {
	t.Parallel()

	crl := crlWithSubstitutedSignatureOID(t)

	var d *model.Detection
	require.NotPanics(t, func() {
		d = cdxprops.NewConverter().PEMBundle(t.Context(), model.PEMBundle{
			Location: "/test/pqc.crl",
			CRLs:     []*x509.RevocationList{crl},
		})
	})
	require.NotNil(t, d)

	doc := emitDocument(t, "1.6", *d)
	byRef := componentsByRef(doc)

	var crlCompo cdx.Component
	for ref, compo := range byRef {
		if strings.HasPrefix(ref, "crypto/crl/") {
			crlCompo = compo
		}
	}
	require.NotEmpty(t, crlCompo.BOMRef,
		"no CRL component, got %v", slices.Sorted(maps.Keys(byRef)))

	algRefs := materialAlgorithmRefs(crlCompo)
	require.Len(t, algRefs, 1,
		"a list whose algorithm cannot be named still names one asset")
	algo, ok := byRef[algRefs[0]]
	require.True(t, ok,
		"the list's algorithm ref %q resolves to nothing -- a dangling ref is "+
			"worse than an unnamed algorithm", algRefs[0])
	require.Equal(t, "1.2.840.10045.4.3.99", algo.CryptoProperties.OID,
		"the OID must be the one in the list's own DER, which is all that is "+
			"left to identify the algorithm by once the enum has missed")

	// No hash: this is the branch that exists so the nil second return is not
	// dereferenced, and so no edge names a component that was never built.
	for ref, compo := range byRef {
		if compo.CryptoProperties.AlgorithmProperties == nil {
			continue
		}
		require.NotEqual(t, cdx.CryptoPrimitiveHash,
			compo.CryptoProperties.AlgorithmProperties.Primitive,
			"an unrecognised signature algorithm decomposes into nothing: %s", ref)
	}
	require.Empty(t, dependsOn(doc, algo.BOMRef),
		"an algorithm with no hash must not claim to depend on one")

	requireNoDanglingEdges(t, doc)
}

// requireNoDanglingEdges states over an emitted document that every dependency
// names components that are in it.
func requireNoDanglingEdges(t *testing.T, doc cdx.BOM) {
	t.Helper()

	byRef := componentsByRef(doc)
	if doc.Dependencies == nil {
		return
	}
	for _, dep := range *doc.Dependencies {
		require.Contains(t, byRef, dep.Ref)
		if dep.Dependencies == nil {
			continue
		}
		for _, to := range *dep.Dependencies {
			require.Contains(t, byRef, to, "dangling dependency edge %s -> %s", dep.Ref, to)
		}
	}
}

// TestPEMBundle_CSRWithUnidentifiableKeyHandsTheBuilderNothingToDrop states the
// guard in csrToCDX where the guard lives, which is the only place it is
// observable.
//
// TestPEMBundle_CSRWithUnregisteredOIDStaysWellFormed asserts on the EMITTED
// document, and the Builder cleans up after the converter: it drops a component
// with no bom-ref, and it drops an edge whose target has no component, warning
// on both. So removing the guard entirely -- appending the zero Component and
// its dangling edge unconditionally -- leaves that test, the goldens and the
// referential-integrity check all green. The only visible consequence is two
// WARN lines per unparseable request, in a log nobody reads, saying the tool
// threw an asset away.
//
// Stating it on the DETECTION is what makes the guard's removal fail: the
// detection is the converter's output, before the Builder's clean-up.
func TestPEMBundle_CSRWithUnidentifiableKeyHandsTheBuilderNothingToDrop(t *testing.T) {
	t.Parallel()

	csr := csrWithSPKIAlgorithm(t, asn1.ObjectIdentifier{1, 3, 9999, 6, 1, 1})
	require.Equal(t, x509.UnknownPublicKeyAlgorithm, csr.PublicKeyAlgorithm,
		"the fixture must reach the unparseable-key path, or this proves nothing")

	d := cdxprops.NewConverter().PEMBundle(t.Context(), model.PEMBundle{
		Location:            "/test/pqc-request.pem",
		CertificateRequests: []*x509.CertificateRequest{csr},
	})
	require.NotNil(t, d)

	refs := map[string]struct{}{}
	for _, compo := range d.Components {
		require.NotEmpty(t, compo.BOMRef,
			"the converter built a component the Builder can only drop: %+v", compo)
		refs[compo.BOMRef] = struct{}{}

		// The same three claims the emitted document is checked for, asserted
		// one stage earlier. A fabricated component is well-formed, so the
		// Builder passes it through untouched and nothing downstream objects;
		// this is the only place the converter can be caught building it.
		require.NotEqual(t, "Unknown", compo.Name,
			"the converter built an algorithm named after the enum's fallthrough")
		require.False(t, strings.HasPrefix(compo.BOMRef, "crypto/algorithm/unknown"),
			"the converter built the placeholder algorithm: %s", compo.BOMRef)
		require.NotNil(t, compo.CryptoProperties)
		require.NotEqual(t, "0.0.0.0", compo.CryptoProperties.OID,
			"the converter stamped an OID nothing is registered under onto %s",
			compo.BOMRef)
	}
	require.Len(t, d.Components, 1,
		"an unreadable SPKI leaves the request and nothing else, got %v",
		slices.Sorted(maps.Keys(refs)))
	require.True(t, strings.HasPrefix(d.Components[0].BOMRef, "crypto/csr/"),
		"the one component must be the request itself: %s", d.Components[0].BOMRef)

	require.Empty(t, d.Dependencies,
		"the request depends on nothing: the key it asks for was never built")
	for _, dep := range d.Dependencies {
		require.Contains(t, refs, dep.Ref,
			"an edge starts at a component this detection does not carry")
		require.NotNil(t, dep.Dependencies)
		for _, to := range *dep.Dependencies {
			require.Contains(t, refs, to,
				"the converter built the edge %s -> %s, and nothing it emitted "+
					"has that ref", dep.Ref, to)
		}
	}
}

// TestPEMBundle_CSRWithDSAKeyKeepsItsTruthfulAlgorithm is what fails if the
// guard in csrToCDX is ever "simplified" back to keying off key.BOMRef == "".
//
// That condition is a strict superset of the one that matters. Go's
// getPublicKeyAlgorithmFromOID maps the DSA OID and parsePublicKey builds a
// *dsa.PublicKey out of the request, so publicKeyAlgorithmInfo has the real
// name and the real OID in hand -- but MarshalPKIXPublicKey refuses to marshal
// a *dsa.PublicKey, so hashPublicKey fails and no key asset is emitted. The
// request therefore reaches the same refless-key state as an unreadable SPKI
// while carrying a genuine migration finding, and restOfPEMBundleToCDX already
// publishes exactly this algorithm for the same key found in a PUBLIC KEY
// block. Suppressing it here would make the document contradict itself
// depending on which PEM block the key turned up in.
func TestPEMBundle_CSRWithDSAKeyKeepsItsTruthfulAlgorithm(t *testing.T) {
	t.Parallel()

	csr := csrWithDSAKey(t)
	require.Equal(t, x509.DSA, csr.PublicKeyAlgorithm,
		"the fixture must reach the DSA path, or this proves nothing")
	require.NotNil(t, csr.PublicKey)
	_, err := x509.MarshalPKIXPublicKey(csr.PublicKey)
	require.Error(t, err,
		"the refusal to marshal is the whole reason this looks like the "+
			"unreadable-SPKI case")

	d := cdxprops.NewConverter().PEMBundle(t.Context(), model.PEMBundle{
		Location:            "/test/dsa-request.pem",
		CertificateRequests: []*x509.CertificateRequest{csr},
	})
	require.NotNil(t, d)

	doc := emitDocument(t, "1.6", *d)
	byRef := componentsByRef(doc)

	// Collected rather than assigned in the loop, and required to be exactly
	// one. Keeping the last match over a map means a regression that emitted a
	// second algorithm -- the placeholder alongside the real one, say -- would
	// be caught or missed depending on Go's map iteration order, turning a
	// failure into a flake; requiring the count states the stronger claim this
	// test is actually about, which is the DSA algorithm and nothing else.
	var algorithms []cdx.Component
	for _, compo := range byRef {
		if compo.CryptoProperties != nil &&
			compo.CryptoProperties.AssetType == cdx.CryptoAssetTypeAlgorithm {
			algorithms = append(algorithms, compo)
		}
	}
	require.Len(t, algorithms, 1,
		"the request asks for exactly one algorithm, got %v",
		slices.Sorted(maps.Keys(byRef)))
	algo := algorithms[0]
	require.NotEmpty(t, algo.BOMRef,
		"the algorithm the request really asks for was dropped, got %v",
		slices.Sorted(maps.Keys(byRef)))
	require.Equal(t, "DSA-2048", algo.Name,
		"the modulus is in the name, so this fails if the algorithm came from "+
			"anywhere but the key in the request")
	require.Equal(t, "1.2.840.10040.4.1", algo.CryptoProperties.OID,
		"a real OID, read from a key Go really parsed")

	// No key asset: MarshalPKIXPublicKey refuses *dsa.PublicKey and there is no
	// certificate to fall back on, so there is no digest to keep this key apart
	// from every other DSA key.
	for ref := range byRef {
		require.False(t, strings.HasPrefix(ref, "crypto/key/"),
			"a key that could not be marshalled must not be reported: %s", ref)
	}

	requireNoDanglingEdges(t, doc)
}

// TestPEMBundle_CSRWithUnnameableAlgorithmIsLoggedAtWarn pins the other half of
// the suppression: that it is a refusal and not a disappearance.
//
// The document is the wrong place for 0.0.0.0, but the SPKI's real OID is a
// fact, and it is the only handle an operator has on a request the tool
// declines to describe -- it is what identifies the request as, say, an
// oqs-provider SPHINCS+ one. Reading it off the DER is not fabrication;
// publishing it as a registry entry would be, which is why it goes here and not
// into a component. Demoting this to Debug, in a tool whose default output is
// not verbose, is silence: the request would appear in the BOM with no
// cryptography and nothing anywhere would say why.
//
// Not parallel: it swaps the process-wide slog default. See the note on
// TestPEMBundle_BundleErrorLogIdentifiesFileAndBlock.
func TestPEMBundle_CSRWithUnnameableAlgorithmIsLoggedAtWarn(t *testing.T) {
	var logBuf bytes.Buffer
	restore := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelWarn})))
	t.Cleanup(func() { slog.SetDefault(restore) })

	csr := csrWithSPKIAlgorithm(t, asn1.ObjectIdentifier{1, 3, 9999, 6, 1, 1})
	require.Equal(t, x509.UnknownPublicKeyAlgorithm, csr.PublicKeyAlgorithm,
		"the fixture must reach the unparseable-key path, or this proves nothing")

	d := cdxprops.NewConverter().PEMBundle(t.Context(), model.PEMBundle{
		Location:            "/test/pqc-request.pem",
		CertificateRequests: []*x509.CertificateRequest{csr},
	})
	require.NotNil(t, d)

	logged := logBuf.String()
	// The level is stated as part of ONE record rather than as a substring of
	// the buffer. publicKeyComponents logs its own "cannot identify public key"
	// Warn into the same buffer on this exact input, so a bare
	// Contains("level=WARN") is satisfied by that record and stays green with
	// the Warn under test deleted outright -- the two halves of the claim,
	// "this is reported" and "it is reported loudly enough to be seen", would
	// be met by two different lines. TextHandler writes one record per line, so
	// requiring the level immediately followed by the message pins them to the
	// same one.
	require.Regexp(t, `level=WARN msg="not reporting an algorithm for a certificate request`, logged,
		"an asset dropped below the default log level is a silently dropped asset")
	require.Contains(t, logged, "not reporting an algorithm for a certificate request")
	require.Contains(t, logged, "CN=pqc-request.example",
		"the operator has to know WHICH request was not described")
	require.Contains(t, logged, "spki_oid=1.3.9999.6.1.1",
		"and the OID in its DER, which is the only thing that identifies the "+
			"algorithm the tool refused to name")
}

// TestPEMBundle_CSRWarnNamesItsAttributes states the same Warn over slog's
// attributes rather than over a rendering of them.
//
// The test above reads a TextHandler's output as one string, and
// "CN=pqc-request.example" appears in that string however the subject got
// there: under any attribute key, under none, or interpolated into the message.
// Renaming "subject" to anything at all therefore leaves it green -- while
// "spki_oid", one line down, is pinned as key AND value. The two halves of one
// log line are held to different standards, and the weaker half is the half
// naming WHICH request was refused.
//
// The key is the contract, not a decoration on it. Nobody greps a Warn out of a
// scan across ten thousand files by eye; these are attributes rather than a
// sentence precisely so that a handler can index them, and an attribute whose
// name moved is an attribute that is gone as far as any query is concerned,
// with the value still sitting in the rendered line to make it look present.
//
// Not parallel: it swaps the process-wide slog default. See the note on
// TestPEMBundle_BundleErrorLogIdentifiesFileAndBlock.
func TestPEMBundle_CSRWarnNamesItsAttributes(t *testing.T) {
	var logBuf bytes.Buffer
	restore := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelWarn})))
	t.Cleanup(func() { slog.SetDefault(restore) })

	csr := csrWithSPKIAlgorithm(t, asn1.ObjectIdentifier{1, 3, 9999, 6, 1, 1})
	require.Equal(t, x509.UnknownPublicKeyAlgorithm, csr.PublicKeyAlgorithm,
		"the fixture must reach the unparseable-key path, or this proves nothing")

	d := cdxprops.NewConverter().PEMBundle(t.Context(), model.PEMBundle{
		Location:            "/test/pqc-request.pem",
		CertificateRequests: []*x509.CertificateRequest{csr},
	})
	require.NotNil(t, d)

	// More than one Warn reaches the buffer on this path -- publicKeyComponents
	// reports the unmarshallable key first -- so the record is picked by its
	// message rather than by position.
	var record map[string]any
	for _, line := range strings.Split(strings.TrimSpace(logBuf.String()), "\n") {
		var got map[string]any
		require.NoError(t, json.Unmarshal([]byte(line), &got), "log line: %s", line)
		if msg, _ := got["msg"].(string); strings.HasPrefix(msg,
			"not reporting an algorithm for a certificate request") {
			record = got
		}
	}
	require.NotNil(t, record,
		"nothing was logged about the refusal at WARN: %s", logBuf.String())

	require.Equal(t, "WARN", record["level"])
	require.Equal(t, "CN=pqc-request.example", record["subject"],
		"the subject has to be queryable under its own key, not merely present "+
			"somewhere in the rendered line")
	require.Equal(t, "1.3.9999.6.1.1", record["spki_oid"],
		"and the OID read off this request's own SubjectPublicKeyInfo")
}

// TestPEMBundle_CSRWithRegisteredPQCOIDYieldsItsKey is the request half of the
// registry fallback, and the gap it closes is the one a PQC migration cares
// about most: a request is the EARLIEST place a key that will have to be
// migrated becomes visible, and it was the only place this tool could not see
// one.
//
// publicKeyComponents reaches the registry only for a CERTIFICATE -- the OID
// fallback is guarded by cert != nil, because the OID is read off
// certSPKI(cert) -- and a request has no x509.Certificate to hang its
// SubjectPublicKeyInfo on. So a request under a registered ML-DSA, ML-KEM or
// SLH-DSA arc never consulted the registry at all: Go returns it successfully
// with UnknownPublicKeyAlgorithm and a nil PublicKey, the algorithm fell
// through to the placeholder, csrToCDX suppressed it, and the key was never
// built. The identical SubjectPublicKeyInfo in a `PUBLIC KEY` block or a
// CERTIFICATE beside it produced a full algorithm and key. The SPKI is on the
// request, byte for byte, in RawSubjectPublicKeyInfo.
//
// The Value assertion is the load-bearing one and it is deliberately not
// spkiOfCSR: that helper marshals csr.PublicKey, which is nil on exactly this
// path. Comparing against base64 of csr.RawSubjectPublicKeyInfo is what pins
// "the key published is the key in THIS request" -- it fails if someone hashes
// csr.Raw or the tbsCertificateRequest instead, both of which would still
// produce a plausible-looking, per-request, content-addressed ref.
//
// The DEPENDENCY assertion is what holds the return order. unsupportedPKIX
// returns (key, algo, err) while publicKeyComponents returns (algo, key), and
// both are cdx.Component, so swapping them compiles. What that does is subtler
// than "the key is published as the algorithm": each component still carries
// the AssetType and the bom-ref prefix it was built with, so both still emit
// correctly typed and the AssetType assertions below stay green. What moves is
// everything csrToCDX reads OFF the two variables -- the request's dependency
// edge, which it builds from key.BOMRef, comes to name the ALGORITHM instead of
// the key. So the swap surfaces here as `dependsOn(doc, csrRef)` holding
// crypto/algorithm/... where crypto/key/... belongs, and nowhere else in this
// test. The AssetType assertions earn their place against a different mutation
// -- a recovery that returns two components of the same kind -- not this one.
//
// Both spec versions are required: the 1.7 emitter builds its components from
// the IR and maps relatedCryptoMaterialProperties.algorithmRef onto
// relatedCryptographicAssets, so the key-to-algorithm edge is a different field
// there, and a recovery proved only against 1.6 says nothing about what a 1.7
// document carries. materialAlgorithmRefs reads both shapes.
//
// The SLH-DSA row is not redundant with the ML-DSA one. Its 32-byte public key
// is a size nothing else in its registry entry shares, so it is what catches a
// body check written against the wrong field.
func TestPEMBundle_CSRWithRegisteredPQCOIDYieldsItsKey(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		oid     asn1.ObjectIdentifier
		body    int
		algo    string
		dotted  string
		subject string
	}{
		{
			name: "ML-DSA-65", oid: mlDSA65OID, body: mlDSA65PubKey,
			algo: "ML-DSA-65", dotted: "2.16.840.1.101.3.4.3.18",
			subject: "ml-dsa-request.example",
		},
		{
			name: "SLH-DSA-SHA2-128S", oid: slhDSA128sOID, body: slhDSA128sPubKey,
			algo: "SLH-DSA-SHA2-128S", dotted: "2.16.840.1.101.3.4.3.20",
			subject: "slh-dsa-request.example",
		},
	}

	for _, tt := range tests {
		for _, version := range []string{"1.6", "1.7"} {
			t.Run(tt.name+"/"+version, func(t *testing.T) {
				t.Parallel()

				csr := csrWithSPKI(t,
					pkix.Name{CommonName: tt.subject},
					pkix.AlgorithmIdentifier{Algorithm: tt.oid},
					asn1.BitString{Bytes: noise(tt.body), BitLength: tt.body * 8})
				require.Equal(t, x509.UnknownPublicKeyAlgorithm, csr.PublicKeyAlgorithm,
					"the fixture must reach the unparseable-key path, or this proves nothing")
				require.Nil(t, csr.PublicKey,
					"Go leaves the key nil for an SPKI algorithm it cannot name")

				d := cdxprops.NewConverter().PEMBundle(t.Context(), model.PEMBundle{
					Location:            "/test/pqc-request.pem",
					CertificateRequests: []*x509.CertificateRequest{csr},
				})
				require.NotNil(t, d)

				doc := emitDocument(t, version, *d)
				byRef := componentsByRef(doc)

				require.Len(t, csrRefs(doc), 1,
					"the request is one asset, got %v", slices.Sorted(maps.Keys(byRef)))
				csrRef := csrRefs(doc)[0]

				var keys []cdx.Component
				for ref, compo := range byRef {
					if strings.HasPrefix(ref, "crypto/key/") {
						keys = append(keys, compo)
					}
				}
				require.Len(t, keys, 1,
					"the requested key is recoverable from the request's own SPKI, got %v",
					slices.Sorted(maps.Keys(byRef)))
				keyCompo := keys[0]

				require.Equal(t, tt.algo, keyCompo.Name,
					"the name comes from the registry entry the OID matched")
				require.NotNil(t, keyCompo.CryptoProperties)
				require.Equal(t, cdx.CryptoAssetTypeRelatedCryptoMaterial,
					keyCompo.CryptoProperties.AssetType,
					"unsupportedPKIX returns (key, algo); a swapped return compiles")
				rcmp := keyCompo.CryptoProperties.RelatedCryptoMaterialProperties
				require.NotNil(t, rcmp)
				require.Equal(t, cdx.RelatedCryptoMaterialTypePublicKey, rcmp.Type)
				require.Equal(t,
					base64.StdEncoding.EncodeToString(csr.RawSubjectPublicKeyInfo),
					rcmp.Value,
					"the key published must be the key in THIS request, not a digest "+
						"of the request or of its tbs")

				algoRefs := materialAlgorithmRefs(keyCompo)
				require.Len(t, algoRefs, 1,
					"the key names exactly one algorithm, got %v", algoRefs)
				algoCompo, ok := byRef[algoRefs[0]]
				require.True(t, ok,
					"the key points at an algorithm that is not in the document: %s", algoRefs[0])
				require.NotNil(t, algoCompo.CryptoProperties)
				require.Equal(t, cdx.CryptoAssetTypeAlgorithm,
					algoCompo.CryptoProperties.AssetType)
				require.Equal(t, tt.algo, algoCompo.Name)
				require.Equal(t, tt.dotted, algoCompo.CryptoProperties.OID,
					"the oid is what established the algorithm in the first place")

				require.Contains(t, dependsOn(doc, csrRef), keyCompo.BOMRef,
					"the request must depend on the key it asks to have certified")

				requireNoDanglingEdges(t, doc)
			})
		}
	}
}

// TestPEMBundle_CSRForMLKEMIsNotReportedAsASignatureScheme states where the
// primitive of a recovered key's algorithm comes from: the registry entry, and
// nowhere else.
//
// The key component carries no primitive at all -- it is related crypto
// material of type publicKey -- so the primitive lives on the algorithm it
// points at, and unsupportedPKIX takes it from algorithmPrimitive(info) (named
// registryPrimitive when this was written, before every producer was routed
// through it). Nothing derives it from KeyUsage, and a request has no KeyUsage
// to derive it from in any case. Without this, the natural "just call
// publicKeyComponents with the recovered info" refactor silently reintroduces
// the defect that function was written to close: the Unknown placeholder's
// primitive is "signature", so an
// ML-KEM encapsulation key someone asked to have certified would be published
// as something that signs -- and a consumer counting signature schemes to plan
// a migration would be counting the wrong thing, in the wrong bucket, with
// nothing in the document to say so.
//
// The negative half is asserted as well as the positive one. "The algorithm is
// a kem" is satisfiable by a document that also carries a stray placeholder
// signature component beside it, which is exactly what a recovery bolted on
// after publicKeyComponents would produce.
func TestPEMBundle_CSRForMLKEMIsNotReportedAsASignatureScheme(t *testing.T) {
	t.Parallel()

	for _, version := range []string{"1.6", "1.7"} {
		t.Run(version, func(t *testing.T) {
			t.Parallel()

			csr := csrWithSPKI(t,
				pkix.Name{CommonName: "ml-kem-request.example"},
				pkix.AlgorithmIdentifier{Algorithm: mlKEM768OID},
				asn1.BitString{Bytes: noise(mlKEM768EncapKey), BitLength: mlKEM768EncapKey * 8})
			require.Equal(t, x509.UnknownPublicKeyAlgorithm, csr.PublicKeyAlgorithm,
				"the fixture must reach the unparseable-key path, or this proves nothing")

			d := cdxprops.NewConverter().PEMBundle(t.Context(), model.PEMBundle{
				Location:            "/test/ml-kem-request.pem",
				CertificateRequests: []*x509.CertificateRequest{csr},
			})
			require.NotNil(t, d)

			doc := emitDocument(t, version, *d)
			byRef := componentsByRef(doc)

			var keyCompo cdx.Component
			for ref, compo := range byRef {
				if strings.HasPrefix(ref, "crypto/key/") {
					keyCompo = compo
				}
			}
			require.NotEmpty(t, keyCompo.BOMRef,
				"the encapsulation key must be recovered, got %v",
				slices.Sorted(maps.Keys(byRef)))

			algoRefs := materialAlgorithmRefs(keyCompo)
			require.Len(t, algoRefs, 1, "the key names exactly one algorithm, got %v", algoRefs)
			algoCompo, ok := byRef[algoRefs[0]]
			require.True(t, ok, "the key points at an algorithm not in the document: %s", algoRefs[0])

			require.Equal(t, "ML-KEM-768", algoCompo.Name)
			require.NotNil(t, algoCompo.CryptoProperties.AlgorithmProperties)
			props := algoCompo.CryptoProperties.AlgorithmProperties
			require.Equal(t, cdx.CryptoPrimitiveKEM, props.Primitive,
				"a KEM reported as a signature scheme is the mislabel algorithmPrimitive exists to stop")
			require.Equal(t, "768", props.ParameterSetIdentifier)
			require.NotNil(t, props.CryptoFunctions)
			require.Subset(t, *props.CryptoFunctions,
				[]cdx.CryptoFunction{cdx.CryptoFunctionEncapsulate, cdx.CryptoFunctionDecapsulate},
				"what an encapsulation key is FOR is the reason it is in the inventory")

			for ref, compo := range byRef {
				if compo.CryptoProperties == nil ||
					compo.CryptoProperties.AlgorithmProperties == nil {
					continue
				}
				require.NotEqual(t, cdx.CryptoPrimitiveSignature,
					compo.CryptoProperties.AlgorithmProperties.Primitive,
					"nothing in an ML-KEM request signs anything: %s", ref)
			}
		})
	}
}

// TestPEMBundle_CSRWithRegisteredOIDIsSilent is the composition test: the
// recovery happens INSTEAD of the two refusals, not after them.
//
// TestPEMBundle_CSRWithRegisteredPQCOIDYieldsItsKey cannot tell the difference.
// A recovery bolted on downstream of publicKeyComponents -- on the placeholder
// branch, which is where the review comment's literal phrasing puts it --
// produces exactly the same document while leaving "cannot identify public key:
// omitting key component algorithm=Unknown" in the operator's log, one call
// before a document that carries the key it says was dropped. A recovery bolted
// on after the suppression's own Warn adds a second such line. In a package
// whose tests pin Warn ATTRIBUTES as an operator contract -- see
// TestPEMBundle_CSRWarnNamesItsAttributes -- shipping a Warn the same call then
// falsifies is a new defect, not a wart: an operator triaging a scan of ten
// thousand files reads those lines as the list of things the tool refused to
// describe, and a request that WAS described has no business in it.
//
// The component assertions are the other half. Silence alone is satisfiable by
// a tool that fabricates quietly, so the placeholder's three fingerprints --
// the name "Unknown", the OID 0.0.0.0, and the crypto/algorithm/unknown ref --
// are each required to be absent from what the converter produced.
//
// It is stated on the DETECTION rather than an emitted document because the
// Warns are the converter's and the Builder is not in the picture; and at
// converter level in one spec version, because a log line is not something an
// emitter can change.
//
// Not parallel: it swaps the process-wide slog default. See the note on
// TestPEMBundle_BundleErrorLogIdentifiesFileAndBlock.
func TestPEMBundle_CSRWithRegisteredOIDIsSilent(t *testing.T) {
	var logBuf bytes.Buffer
	restore := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelWarn})))
	t.Cleanup(func() { slog.SetDefault(restore) })

	csr := csrWithSPKI(t,
		pkix.Name{CommonName: "ml-dsa-request.example"},
		pkix.AlgorithmIdentifier{Algorithm: mlDSA65OID},
		asn1.BitString{Bytes: noise(mlDSA65PubKey), BitLength: mlDSA65PubKey * 8})
	require.Equal(t, x509.UnknownPublicKeyAlgorithm, csr.PublicKeyAlgorithm,
		"the fixture must reach the unparseable-key path, or this proves nothing")

	d := cdxprops.NewConverter().PEMBundle(t.Context(), model.PEMBundle{
		Location:            "/test/ml-dsa-request.pem",
		CertificateRequests: []*x509.CertificateRequest{csr},
	})
	require.NotNil(t, d)

	// Both claims below are of the form "nothing said X", and both are
	// satisfied by a converter that produced nothing at all -- a recovery that
	// returned the algorithm and dropped the key would be silent too, and this
	// test would have called that a pass while asserting the OPPOSITE of what
	// its name and its comment promise. The recovery has to be established
	// first, in the same run, or the silence is not evidence of anything.
	var recovered []string
	for _, compo := range d.Components {
		if strings.HasPrefix(compo.BOMRef, "crypto/key/") {
			recovered = append(recovered, compo.BOMRef)
		}
	}
	require.Len(t, recovered, 1,
		"the silence has to be the silence of a request that WAS described")

	logged := logBuf.String()
	require.NotContains(t, logged, "not reporting an algorithm for a certificate request",
		"the algorithm was reported, so nothing may say it was refused")
	require.NotContains(t, logged, "cannot identify public key",
		"the key was identified, from this request's own SubjectPublicKeyInfo")

	for _, compo := range d.Components {
		require.NotEqual(t, "Unknown", compo.Name,
			"the registry named this algorithm: %s", compo.BOMRef)
		require.False(t, strings.HasPrefix(compo.BOMRef, "crypto/algorithm/unknown"),
			"the placeholder's ref must not be in the detection: %s", compo.BOMRef)
		if compo.CryptoProperties == nil {
			continue
		}
		require.NotEqual(t, "0.0.0.0", compo.CryptoProperties.OID,
			"an arc nothing is registered under is a fabrication, not a finding: %s",
			compo.BOMRef)
	}
}

// TestPEMBundle_CSRAndItsCertificateShareOneKeyAsset states that the request
// path reuses the certificate path's IDENTITY rather than inventing a parallel
// one: the same SubjectPublicKeyInfo, met under two PEM labels in one file,
// dedups onto one key component and one algorithm component.
//
// This is the regression net for the whole recovery. Everything the request
// path emits is built by unsupportedPKIX, and everything the certificate path
// emits is built by publicKeyComponents, and the two agree today only because
// they read the same registry entry, take the primitive from the same place,
// hash the same DER and mint the same crypto/key/<name>@<digest> ref. Any
// divergence -- a primitive derived differently, a name taken from elsewhere, a
// digest over the request rather than over its SPKI -- shows up here as two
// components where there must be one, and nowhere else: the per-path tests all
// pass with two parallel identities, and a consumer counting keys to size a
// migration would count this one twice.
//
// The claim is about the same SubjectPublicKeyInfo, NOT about a request and the
// certificate a CA really issued from it. Both fixtures marshal the identical
// {AlgorithmIdentifier, BIT STRING} shape, so the DER is byte-identical, and
// that is asserted directly -- a real CA re-encodes from the parsed key, which
// yields identical DER for canonical inputs but is guaranteed by nothing this
// repo controls. Without the assertion the test would pass vacuously the day
// the two fixtures stopped agreeing.
//
// Both spec versions: dedup is the Builder's, but which components it is asked
// to dedup is the emitter's, and 1.7 rebuilds them from the IR.
func TestPEMBundle_CSRAndItsCertificateShareOneKeyAsset(t *testing.T) {
	t.Parallel()

	for _, version := range []string{"1.6", "1.7"} {
		t.Run(version, func(t *testing.T) {
			t.Parallel()

			spki := pkixDERBody(t, mlDSA65OID, noise(mlDSA65PubKey))

			csr := csrWithSPKI(t,
				pkix.Name{CommonName: "ml-dsa-request.example"},
				pkix.AlgorithmIdentifier{Algorithm: mlDSA65OID},
				asn1.BitString{Bytes: noise(mlDSA65PubKey), BitLength: mlDSA65PubKey * 8})
			require.Equal(t, spki, csr.RawSubjectPublicKeyInfo,
				"the two fixtures must carry the SAME SubjectPublicKeyInfo, or this "+
					"test proves nothing about dedup")

			certDER, err := cdxtest.CertWithSPKI(spki)
			require.NoError(t, err)

			var file []byte
			file = append(file, pem.EncodeToMemory(&pem.Block{
				Type: "CERTIFICATE REQUEST", Bytes: csr.Raw})...)
			file = append(file, pem.EncodeToMemory(&pem.Block{
				Type: "CERTIFICATE", Bytes: certDER})...)

			bundle, err := pemscan.Scanner{}.Scan(t.Context(), file, "/test/request-and-cert.pem")
			require.NoError(t, err)
			require.Len(t, bundle.CertificateRequests, 1)
			require.Len(t, bundle.Certificates, 1)

			d := cdxprops.NewConverter().PEMBundle(t.Context(), bundle)
			require.NotNil(t, d)

			doc := emitDocument(t, version, *d)
			byRef := componentsByRef(doc)

			var keys, algorithms, certificates []cdx.Component
			for _, compo := range byRef {
				if compo.CryptoProperties == nil {
					continue
				}
				switch compo.CryptoProperties.AssetType {
				case cdx.CryptoAssetTypeAlgorithm:
					if compo.Name == "ML-DSA-65" {
						algorithms = append(algorithms, compo)
					}
				case cdx.CryptoAssetTypeRelatedCryptoMaterial:
					if compo.Name == "ML-DSA-65" {
						keys = append(keys, compo)
					}
				case cdx.CryptoAssetTypeCertificate:
					certificates = append(certificates, compo)
				}
			}

			require.Len(t, keys, 1,
				"one SubjectPublicKeyInfo is one key asset, however many artefacts "+
					"carry it, got %v", slices.Sorted(maps.Keys(byRef)))
			require.Len(t, algorithms, 1,
				"and one algorithm asset, got %v", slices.Sorted(maps.Keys(byRef)))
			require.Len(t, certificates, 1)
			require.Len(t, csrRefs(doc), 1)

			require.Equal(t, []string{keys[0].BOMRef}, certificateKeyRefs(certificates[0]),
				"the certificate must point at that one key")
			require.Contains(t, dependsOn(doc, csrRefs(doc)[0]), keys[0].BOMRef,
				"and the request must depend on the same one, not on a second copy")

			requireNoDanglingEdges(t, doc)
		})
	}
}

// TestPEMBundle_CSRWhoseAlgorithmGoNamedKeepsIt pins the GATE on the recovery:
// the SPKI-OID lookup is a fallback for a request Go could not name, not an
// override of one it could.
//
// requestedKeyComponents consults the registry only when
// csr.PublicKeyAlgorithm is UnknownPublicKeyAlgorithm. Delete that condition
// and every request -- RSA, ECDSA, Ed25519, DSA -- gets its
// SubjectPublicKeyInfo run through unsupportedPKIX first, and today NOTHING
// else in the suite notices, because no OID in the fallback registry is one
// Go's enum can name: every lookup misses, the error is returned, and control
// falls through to publicKeyComponents exactly as before. The gate is a no-op
// on every input the package currently has, which is precisely why it needs a
// test of its own -- an unpinned condition that costs nothing to delete is the
// one a later refactor deletes.
//
// What it costs is paid later. The registry is hand-maintained and grows: the
// day it gains an entry Go's getPublicKeyAlgorithmFromOID also recognises --
// a composite or hybrid arc wrapping a classical key is the obvious candidate,
// and it is the direction the drafts are going -- an ungated recovery takes
// over a request whose key Go PARSED. It would then be described from the OID
// alone: no keySize off the parsed key, and none of publicKeyComponents'
// KeyUsage logic, which is the only thing that reports an RSA key as pke
// rather than signature. The document would still look well formed. Nothing
// would say the tool had stopped reading the key it was handed.
//
// The fixture is deliberately one x509.ParseCertificateRequest cannot produce.
// A parsed request derives PublicKeyAlgorithm FROM the SPKI's OID, so the two
// can never disagree in the wild and no realistic file can separate "gated"
// from "ungated" today -- that is the same fact that lets the mutation
// survive. Overwriting RawSubjectPublicKeyInfo on a real RSA request states
// the rule directly instead: whatever the raw SPKI says, when Go has named the
// algorithm, Go's answer is the one the document carries. The converter takes
// *x509.CertificateRequest structs from the bundle, so this is the same entry
// point every other request reaches it by.
//
// Both spec versions, because the claim is about the emitted document.
func TestPEMBundle_CSRWhoseAlgorithmGoNamedKeepsIt(t *testing.T) {
	t.Parallel()

	for _, version := range []string{"1.6", "1.7"} {
		t.Run(version, func(t *testing.T) {
			t.Parallel()

			rsaKey, err := cdxtest.GenRSAPrivateKey(2048)
			require.NoError(t, err)
			csr := csrFor(t, "classical-request.example", rsaKey)
			require.Equal(t, x509.RSA, csr.PublicKeyAlgorithm,
				"the fixture must be a request Go DID name, or this proves nothing")
			require.NotNil(t, csr.PublicKey)

			// The disagreement the gate is the only thing standing between.
			csr.RawSubjectPublicKeyInfo = pkixDERBody(t, mlDSA65OID, noise(mlDSA65PubKey))

			d := cdxprops.NewConverter().PEMBundle(t.Context(), model.PEMBundle{
				Location:            "/test/classical-request.pem",
				CertificateRequests: []*x509.CertificateRequest{csr},
			})
			require.NotNil(t, d)

			doc := emitDocument(t, version, *d)
			byRef := componentsByRef(doc)

			keys := keyComponents(doc)
			require.Len(t, keys, 1,
				"one request asks to certify one key, got %v", slices.Sorted(maps.Keys(byRef)))
			keyRef := slices.Sorted(maps.Keys(keys))[0]
			keyCompo := keys[keyRef]

			require.Equal(t, "RSA-2048", keyCompo.Name,
				"the key Go parsed is the key the document describes")
			rcmp := keyCompo.CryptoProperties.RelatedCryptoMaterialProperties
			require.NotNil(t, rcmp)
			require.Equal(t, spkiOfCSR(t, csr), rcmp.Value,
				"the value must be the PARSED key re-marshalled, not the raw SPKI "+
					"the registry would have matched")

			algRefs := materialAlgorithmRefs(keyCompo)
			require.Len(t, algRefs, 1, "the key names exactly one algorithm, got %v", algRefs)
			algoCompo, ok := byRef[algRefs[0]]
			require.True(t, ok, "the key points at an algorithm not in the document: %s", algRefs[0])
			require.Equal(t, "RSA-2048", algoCompo.Name)
			require.Equal(t, "1.2.840.113549.1.1.1", algoCompo.CryptoProperties.OID)

			// The negative half. "An RSA key is present" is satisfiable by a
			// document that carries the registry's answer beside it.
			for ref, compo := range byRef {
				require.NotEqual(t, "ML-DSA-65", compo.Name,
					"the registry described a request Go had already named: %s", ref)
				require.NotContains(t, ref, "ml-dsa-65",
					"nothing recovered from the raw SPKI may reach the document: %s", ref)
				if compo.CryptoProperties == nil {
					continue
				}
				require.NotEqual(t, "2.16.840.1.101.3.4.3.18", compo.CryptoProperties.OID,
					"the SPKI OID must not have been consulted at all: %s", ref)
			}

			require.Equal(t, []string{keyRef}, dependsOn(doc, csrRefs(doc)[0]),
				"the request depends on the key Go parsed for it")
			requireNoDanglingEdges(t, doc)
		})
	}
}
