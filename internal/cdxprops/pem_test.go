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
func TestPEMBundle_CSRWithUnregisteredOIDStaysWellFormed(t *testing.T) {
	t.Parallel()

	// 1.3.9999.6.1.1 is a real OID -- oqs-provider assigns it to
	// SPHINCS+-Haraka-128f-robust -- and is not one Go or the registry knows,
	// so this is a plausible request and not a synthetic impossibility.
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

	doc := emitDocument(t, "1.6", *d)
	byRef := componentsByRef(doc)

	for ref := range byRef {
		require.False(t, strings.HasPrefix(ref, "crypto/key/"),
			"a key that could not be identified must not be reported as an asset: %s", ref)
	}
	// The algorithm still survives: that the request references SOME algorithm
	// is true whatever the SPKI turns out to hold, and dropping it too would
	// lose the request's only cryptographic content.
	var algorithms int
	for _, compo := range byRef {
		if compo.CryptoProperties != nil &&
			compo.CryptoProperties.AssetType == cdx.CryptoAssetTypeAlgorithm {
			algorithms++
		}
	}
	require.Equal(t, 1, algorithms, "got %v", slices.Sorted(maps.Keys(byRef)))

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
}

// csrWithSPKIAlgorithm builds the DER of a certificate request whose
// subjectPublicKeyInfo carries algorithm, and parses it back.
//
// x509.CreateCertificateRequest cannot produce this: it only marshals keys Go
// implements, which is the whole point -- the request under test is one Go
// cannot make and can still parse. The signature is not a real one; nothing on
// this path verifies it, and ParseCertificateRequest does not either.
func csrWithSPKIAlgorithm(t *testing.T, algorithm asn1.ObjectIdentifier) *x509.CertificateRequest {
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

	var subject pkix.RDNSequence
	subjectDER, err := asn1.Marshal(subject)
	require.NoError(t, err)

	tbs := tbsCSR{
		Subject:    asn1.RawValue{FullBytes: subjectDER},
		Attributes: []asn1.RawValue{},
	}
	tbs.PublicKey.Algorithm = pkix.AlgorithmIdentifier{Algorithm: algorithm}
	tbs.PublicKey.PublicKey = asn1.BitString{Bytes: make([]byte, 32), BitLength: 32 * 8}
	tbsDER, err := asn1.Marshal(tbs)
	require.NoError(t, err)

	der, err := asn1.Marshal(struct {
		TBS       asn1.RawValue
		SigAlg    pkix.AlgorithmIdentifier
		Signature asn1.BitString
	}{
		TBS:       asn1.RawValue{FullBytes: tbsDER},
		SigAlg:    pkix.AlgorithmIdentifier{Algorithm: algorithm},
		Signature: asn1.BitString{Bytes: make([]byte, 8), BitLength: 8 * 8},
	})
	require.NoError(t, err)

	csr, err := x509.ParseCertificateRequest(der)
	require.NoError(t, err, "an unrecognised SPKI algorithm must still parse")
	return csr
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
	}
	require.NotEmpty(t, refs)

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
