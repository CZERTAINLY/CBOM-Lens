package cdxprops

import (
	"context"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"slices"
	"strings"
	"time"

	"github.com/OmniTrustILM/cbom-lens/internal/model"

	cdx "github.com/CycloneDX/cyclonedx-go"
)

// restOfPEMBundleToCDX converts the parts of a PEM bundle Converter.PEMBundle
// does not handle itself -- certificate requests, standalone public keys, CRLs,
// and the blocks the scanner could not parse -- into CycloneDX components.
//
// PEMBundle takes the certificates and the keypairs, and calls this for the
// rest; the name says which half is which.
func (c Converter) restOfPEMBundleToCDX(ctx context.Context, bundle model.PEMBundle) ([]cdx.Component, error) {
	components := make([]cdx.Component, 0)
	var errs []error

	// Convert certificate requests
	for _, csr := range bundle.CertificateRequests {
		components = append(components, c.csrToCDX(csr))
	}

	// Convert public keys
	for _, pubKey := range bundle.PublicKeys {
		algo, pubKeyCompo := c.publicKeyComponents(ctx, getPublicKeyAlgorithm(pubKey), pubKey, nil)
		components = append(components, algo)
		// publicKeyComponents yields no key component when the key cannot be
		// identified — a DSA PUBLIC KEY block parses via ParsePKIXPublicKey but
		// MarshalPKIXPublicKey refuses *dsa.PublicKey, and with no certificate
		// there is no SPKI to hash instead. Appending the zero Component here
		// and setting Format on it dereferenced a nil CryptoProperties and took
		// the whole scan down, which is why the assignment stays out of the
		// producers. The Format assignment was redundant anyway: PEMBundle's
		// central setPEMFormat applies it to every component whose asset type is
		// related-crypto-material, and only those (#213).
		if pubKeyCompo.BOMRef == "" {
			continue
		}
		components = append(components, pubKeyCompo)
	}

	// Convert CRLs
	for _, crl := range bundle.CRLs {
		components = append(components, c.crlToCDX(crl))
	}

	// try to parse unrecognized parts of a PEM
	for _, i := range slices.Sorted(maps.Keys(bundle.ParseErrors)) {
		parseErr := bundle.ParseErrors[i]
		block := bundle.RawBlocks[i]
		compos, err := c.analyzeParseError(ctx, block, parseErr)
		if err != nil {
			// Say WHICH block failed. errors.Join below flattens every block's
			// error into one multi-line blob, and PEMBundle logs that blob and
			// drops it -- so for a file holding several keys under OIDs outside
			// the registry (no LMS, no XMSS, no composite arcs) the operator got
			// a wall of "unsupported fallback oid" naming neither the file nor
			// which key in it, while the BOM's statistics showed nothing amiss.
			// The index and type are both in hand here and nowhere afterwards.
			errs = append(errs, fmt.Errorf("pem block %d (%s): %w", i, block.Type, err))
			continue
		}
		components = append(components, compos...)
	}

	return components, errors.Join(errs...)
}

// csrToCDX converts a certificate signing request into a component.
//
// The bom-ref is content-addressed over the request's own DER, mirroring
// crypto/certificate/<name>@<hash(cert.Raw)>. Without a bom-ref at all
// Builder.appendDetection dropped the component, so scanning a .csr reported
// nothing and exited 0; an empty Name would have done the same, hence the
// csrSubjectName fallback.
//
// It deliberately does NOT use Converter.BOMRefHash. That hashes the
// component's JSON, and this component carries the subject but nothing of the
// key, so two requests for the same subject with different keys would hash to
// one ref and the Builder's first-wins dedup would silently discard the
// second. The DER covers the key.
func (c Converter) csrToCDX(csr *x509.CertificateRequest) cdx.Component {
	name := csrSubjectName(csr)
	compo := cdx.Component{
		Type:   cdx.ComponentTypeCryptographicAsset,
		Name:   "CSR: " + name,
		BOMRef: "crypto/csr/" + name + "@" + c.bomRefHasher(csr.Raw),
		CryptoProperties: &cdx.CryptoProperties{
			AssetType: cdx.CryptoAssetTypeRelatedCryptoMaterial,
			RelatedCryptoMaterialProperties: &cdx.RelatedCryptoMaterialProperties{
				Type: cdx.RelatedCryptoMaterialTypeOther,
			},
		},
		Properties: &[]cdx.Property{
			{Name: "pem_type", Value: "CSR"},
			{Name: "subject", Value: csr.Subject.String()},
		},
	}
	return compo
}

// crlToCDX converts a certificate revocation list into a component.
//
// The bom-ref is content-addressed over the list's own DER, mirroring
// crypto/certificate/<name>@<hash(cert.Raw)>. Without a bom-ref at all
// Builder.appendDetection dropped the component, so scanning a .crl reported
// nothing and exited 0.
//
// It deliberately does NOT use Converter.BOMRefHash, for the reason given on
// csrToCDX: hashing the component's JSON would let two distinct lists with the
// same issuer and timestamps collapse onto one ref.
//
// There is no "location" property. Now that the ref is content-addressed, the
// same CRL found at two paths dedups to one component and the stored copy
// would have kept only the first location -- a property that quietly lies
// about where the asset was seen. evidence.occurrences already carries every
// location, and populating it is the Builder's job.
//
// It DOES carry pem_type=CRL, mirroring csrToCDX's pem_type=CSR. Both
// components declare relatedCryptoMaterialProperties.type as "other" because
// CycloneDX's RelatedCryptoMaterialType enum has no CSR or CRL variant, so
// "other" is the only schema-native shape either can take -- which also makes
// it useless for telling the two apart. pem_type is the sole machine-readable
// discriminator between them, so leaving it off here was not asymmetry by
// design, it silently made every CRL indistinguishable from a CSR to anything
// reading properties instead of guessing from the Name string.
func (c Converter) crlToCDX(crl *x509.RevocationList) cdx.Component {
	name := crlIssuerName(crl)
	props := []cdx.Property{
		{Name: "pem_type", Value: "CRL"},
		{Name: "issuer", Value: crl.Issuer.String()},
		{Name: "this_update", Value: crl.ThisUpdate.Format(time.RFC3339)},
	}
	// RFC 5280 makes nextUpdate OPTIONAL. Formatting it unconditionally
	// published the zero time, "0001-01-01T00:00:00Z", as a real expiry.
	if !crl.NextUpdate.IsZero() {
		props = append(props, cdx.Property{Name: "next_update", Value: crl.NextUpdate.Format(time.RFC3339)})
	}
	props = append(props, cdx.Property{Name: "revoked_count", Value: fmt.Sprintf("%d", len(crl.RevokedCertificateEntries))})

	compo := cdx.Component{
		Type:   cdx.ComponentTypeCryptographicAsset,
		Name:   "CRL: " + name,
		BOMRef: "crypto/crl/" + name + "@" + c.bomRefHasher(crl.Raw),
		CryptoProperties: &cdx.CryptoProperties{
			AssetType: cdx.CryptoAssetTypeRelatedCryptoMaterial,
			RelatedCryptoMaterialProperties: &cdx.RelatedCryptoMaterialProperties{
				Type: cdx.RelatedCryptoMaterialTypeOther,
			},
		},
		Properties: &props,
	}
	return compo
}

// csrSubjectName names a certificate request for its bom-ref and Name, the way
// formatCertificateName names a certificate: CN if there is one, else the full
// subject DN. A request has no serial number to fall back on, so an entirely
// empty subject yields "unknown".
//
// That fallback is about the REF, not about the drop. It does not exist to
// keep Builder.appendDetection from discarding an empty Name -- the "CSR: "
// prefix already guarantees the Name is non-empty whatever this returns. It
// exists because the ref is crypto/csr/<name>@<digest>, and without it an
// empty subject produces "crypto/csr/@sha256:..." -- a ref a reader cannot
// tell from a truncation or a formatting bug.
func csrSubjectName(csr *x509.CertificateRequest) string {
	return nameOrFallback(csr.Subject, func() string { return "unknown" })
}

// crlIssuerName names a revocation list for its bom-ref and Name. A CRL has no
// subject, so it is named after its issuer, otherwise following
// csrSubjectName -- including why the "unknown" fallback is there.
func crlIssuerName(crl *x509.RevocationList) string {
	return nameOrFallback(crl.Issuer, func() string { return "unknown" })
}

// Helper functions
func (c Converter) analyzeParseError(ctx context.Context, block model.PEMBlock, origErr error) ([]cdx.Component, error) {
	switch block.Type {
	case "PRIVATE KEY":
		key, algo, err := c.unsupportedPKCS8PrivateKey(ctx, block.Bytes)
		if err != nil {
			return nil, errors.Join(origErr, err)
		}
		// A PKCS#8 body that is not a legal encoding of the key the registry
		// describes yields no key: unsupportedPKCS8PrivateKey returns nil for
		// it, and the algorithm stands on the OID alone.
		//
		// The empty-BOMRef sentinel restOfPEMBundleToCDX uses above expresses the
		// same decision and is deliberately left alone. publicKeyComponents has
		// three production callers -- that loop, Converter.PEMBundle's keypair
		// loop, and certHitToComponents -- and each reads .BOMRef off its result
		// through a field selector, which Go applies to a pointer just as happily
		// as to a value, so the same conversion there would compile silently at
		// all three. PEMBundle does that read through strings.Cut before it guards
		// on anything, so it would trade an inert sentinel for a nil dereference.
		//
		// unsupportedPKIX still hands its key back as a value, and that is not
		// an endorsement of the sentinel: a no-key branch added there owes this
		// caller the same pointer rather than another empty component to
		// recognise.
		if key == nil {
			return []cdx.Component{algo}, nil
		}
		return []cdx.Component{*key, algo}, nil
	case "PUBLIC KEY":
		key, algo, err := c.unsupportedPKIX(ctx, block.Bytes)
		if err != nil {
			return nil, errors.Join(origErr, err)
		}
		// unsupportedPKIX yields the algorithm alone when the PKIX body is not
		// exactly the size the registry states for this algorithm's public
		// key. The zero Component must not be appended: it has neither ref nor
		// crypto properties, so the Builder would drop it with a warning and
		// setPEMFormat would walk it for nothing. Same guard, same reason, as
		// the PRIVATE KEY branch above and the zero public-key component in
		// restOfPEMBundleToCDX.
		if key.BOMRef == "" {
			return []cdx.Component{algo}, nil
		}
		return []cdx.Component{key, algo}, nil
	}
	return nil, origErr
}

// ********** PQC support **********

// unsupportedPKCS8PrivateKey handles a `PRIVATE KEY` PEM block Go's stdlib
// cannot parse, returning the key material component and the algorithm
// component that describes it.
//
// It used to return the algorithm alone, while its sibling unsupportedPKIX
// returned a key and an algorithm. Since #213 stopped stamping
// relatedCryptoMaterialProperties onto everything, an ML-DSA, SLH-DSA or ML-KEM
// private key contributed no related-crypto-material asset at all: a CBOM that
// named the algorithm but never said a key existed.
//
// The two claims it can make are not equally supported by the input, which is
// why they are decided separately. The OID establishes that the algorithm is
// REFERENCED here -- true whatever the bytes after it turn out to be. That a
// KEY exists is a claim about the body, and validating the wrapper alone did
// not check the body at all: a SEQUENCE carrying the ML-DSA-65 OID and four
// bytes of garbage asserted a full private key, silently. So a body too small
// to be the key the registry describes yields the algorithm and no key, which
// is exactly what this function returned before it learned to emit key
// material.
//
// That "no key" case is why the key is a pointer: nil is how this function says
// the body is not a legal encoding of a key, so the caller reads the answer
// rather than re-deriving it from an empty component. The two claims ride the
// return type the way the input supports them -- the algorithm as a value,
// because the OID establishes it whatever follows, and the key behind a
// pointer, because the body may establish nothing at all.
func (c Converter) unsupportedPKCS8PrivateKey(ctx context.Context, der []byte) (key *cdx.Component, algo cdx.Component, err error) {
	var pkcs8 pkcs8Struct
	rest, uerr := asn1.Unmarshal(der, &pkcs8)
	if uerr != nil {
		err = fmt.Errorf("parsing PKCS#8 via ASN.1: %w", uerr)
		return
	}
	// asn1.Unmarshal returns what it did not consume, and discarding that
	// accepted anything appended after the PrivateKeyInfo. Since the ref is a
	// digest of the whole block, one key plus n different tails is n distinct
	// private-key assets all claiming to be the same key -- unbounded, and
	// indistinguishable in the document from n real keys.
	// x509.ParsePKCS8PrivateKey rejects trailing data for the same reason.
	if len(rest) > 0 {
		err = fmt.Errorf("parsing PKCS#8 via ASN.1: %d bytes of trailing data", len(rest))
		return
	}
	// RFC 5208 defines version 0, RFC 5958 adds 1 for a OneAsymmetricKey that
	// carries a publicKey. Any other value means this is not a structure whose
	// layout is known, so the field measured below need not be the private key
	// at all -- and the field was decoded and then never looked at, so version
	// -1 was reported as a full private key.
	if pkcs8.Version != 0 && pkcs8.Version != 1 {
		err = fmt.Errorf("unsupported PKCS#8 version %d", pkcs8.Version)
		return
	}
	info, ok := unsupportedAlgorithms[pkcs8.Algo.Algorithm.String()]
	if !ok {
		err = fmt.Errorf("unsupported fallback oid %q", pkcs8.Algo.Algorithm.String())
		return
	}

	algo = info.componentWOBomRef(c.ilm)
	// This path set no primitive at all, so every PQC private key produced an
	// algorithm component with the field missing, while the public-key path
	// produced one with it set. Both now take it from the registry.
	setAlgorithmPrimitive(&algo, registryPrimitive(info))
	c.BOMRefHash(&algo, info.algorithmName)

	// Check the ENCODING, not a length floor. RFC 9881 sec. 6 makes the ML-DSA
	// privateKey field a CHOICE -- seed [0] (32 bytes), expandedKey, or both --
	// and names the seed the RECOMMENDED form; ML-KEM has the same shape with a
	// 64-byte (d, z) seed. So one algorithm has several legal body lengths that
	// differ by two orders of magnitude, and neither bound works alone:
	//
	//   - A floor at the expanded size rejected real keys. Every PQC fixture in
	//     the corpus is OpenSSL's default "both" encoding, so 4032/2400 passed
	//     all of them and looked correct, while a genuine seed-only key from
	//     `openssl genpkey -provparam ml-dsa.output_formats=seed-only` (body 34)
	//     was reported as no key at all. Node.js exports seed-only by default,
	//     so those are keys in the wild.
	//   - A floor at the seed accepted 32 bytes of noise under an ML-DSA OID as
	//     a full private key -- the exact confident-report-over-garbage this
	//     guard exists to prevent, back one alternative lower.
	//
	// There is no content test to make: nothing distinguishes a valid seed from
	// 32 arbitrary bytes. But the legal encodings are enumerable, so the tags
	// and declared lengths can be checked, and that rules out every body between
	// the alternatives without rejecting any of the alternatives themselves.
	if reason := rejectPrivateKeyBody(info, pkcs8.PrivateKey); reason != "" {
		slog.WarnContext(ctx, "not reporting a private key: the PKCS#8 body is not a legal encoding of one",
			"algorithm", info.name,
			"oid", info.oid,
			"body_bytes", len(pkcs8.PrivateKey),
			"reason", reason)
		// The OID established that the algorithm is referenced here, whatever
		// the body turned out to hold, so algo stands. Nothing in this block
		// establishes that a key exists: nil IS the answer, not a component
		// that happens to be empty.
		return nil, algo, nil
	}

	relatedProps := &cdx.RelatedCryptoMaterialProperties{
		Type:         cdx.RelatedCryptoMaterialTypePrivateKey,
		AlgorithmRef: cdx.BOMReference(algo.BOMRef),
		// No Value. unsupportedPKIX sets it because the DER it holds is a
		// PUBLIC key; the same field here would publish the secret into a
		// document that gets uploaded and shared. Converter.PrivateKey sets
		// none either.
	}

	// Size only when the registry states one, exactly mirroring the guard in
	// unsupportedPKIX so the two post-quantum paths cannot drift. Every
	// registry keySize is currently 0, so no size is emitted.
	//
	// It deliberately does NOT fall back to pqcInfo.privKeySize or
	// kemInfo.decapKeySize. The schema's relatedCryptoMaterialProperties.size
	// is in BITS, while those are the byte counts from FIPS 204 and FIPS 203 --
	// 4032 for ML-DSA-65 would understate the key eightfold AND validate, so
	// nothing downstream would ever catch it.
	if info.keySize > 0 {
		relatedProps.Size = &info.keySize
	}

	key = &cdx.Component{
		Type:        cdx.ComponentTypeCryptographicAsset,
		Name:        info.name,
		Description: "Private Key",
		// The ref hashes the PRIVATE DER, because pkcs8Struct decodes only
		// version and privateKeyAlgorithm -- the public key is not recoverable
		// here. So the correlation Converter.PrivateKey deliberately buys, the
		// private and public halves of one keypair sharing a digest, is NOT
		// available for post-quantum keys: these pair with their public
		// counterpart only through AlgorithmRef, i.e. by algorithm and not by
		// keypair. Do not read the classical invariant into the shared
		// crypto/private_key/ prefix.
		//
		// Accepted trade-off, recorded because it is the only ref in a
		// cbom-lens document derived from secret material. Builder.safeRef
		// rewrites this to <prefix>@<uuidv5>, which hides the digest but does
		// NOT break the derivation -- uuid.NewSHA1 is deterministic over the
		// raw ref, so the emitted UUID is reconstructible from a candidate key
		// file. The CBOM is therefore a confirmation oracle: someone who
		// already holds a key can prove it was scanned, and
		// evidence.occurrences tells them where. Judged acceptable because it
		// discloses nothing to anyone who does not already have the key, and
		// content addressing is what lets the same key found at two paths
		// dedupe to one asset. The alternative, hashing the location, trades
		// that away and makes refs move when the scan root changes.
		BOMRef: fmt.Sprintf("crypto/private_key/%s@%s", strings.ToLower(info.name), c.bomRefHasher(der)),
		CryptoProperties: &cdx.CryptoProperties{
			AssetType:                       cdx.CryptoAssetTypeRelatedCryptoMaterial,
			OID:                             info.oid,
			RelatedCryptoMaterialProperties: relatedProps,
		},
	}

	return key, algo, nil
}

// registryKeyBodySizes returns the two sizes in BYTES that a PKCS#8 privateKey
// body for this algorithm can declare: the seed, when the scheme has a seed
// alternative, and the expanded private key. Either is 0 when the registry
// states none.
//
// A KEM's private half is its decapsulation key and a signature scheme's is its
// private key, carried by different registry shapes (kemInfo vs pqcInfo), so
// reading only privKeySize would silently return 0 -- no check at all -- for
// every ML-KEM parameter set.
//
// These are byte counts from FIPS 203/204/205, RFC 9881 and RFC 9909. They are
// NOT the schema's relatedCryptoMaterialProperties.size, which is in bits; see
// the comment on that field's guard above.
func registryKeyBodySizes(info algorithmInfo) (seed, expanded int) {
	switch sizes := info.pqc.(type) {
	case kemInfo:
		return sizes.seedSize, sizes.decapKeySize
	case pqcInfo:
		return sizes.seedSize, sizes.privKeySize
	}
	return 0, 0
}

// rejectPrivateKeyBody returns why body cannot be a private key for info, or ""
// when it is one of the legal encodings.
//
// The accepted set is, in the order tried:
//
//   - the raw key, unwrapped. This is how SLH-DSA is stored (RFC 9909 sec. 7
//     gives it no seed alternative) and it is what the fixtures hold: 64 bytes
//     for SHA2-128s, not 66. It is also accepted for the seed-bearing schemes,
//     where RFC 9881 does not define it: a producer that skips the CHOICE
//     wrapper emits a real key, and reporting a real key as absent is the
//     failure this check exists to avoid, inverted.
//   - expandedKey, a plain OCTET STRING of the expanded size.
//   - seed, `[0] OCTET STRING` of the seed size -- the RECOMMENDED form, and
//     what Node.js writes by default.
//   - both, SEQUENCE { seed, expandedKey } -- OpenSSL's default.
//
// An empty body is refused whatever the algorithm. For XMSS, XMSS-MT and
// HSS-LMS that is ALL that is refused, and the reason is not a missing size but
// a missing ENCODING: no RFC defines what the PKCS#8 privateKey field holds
// under those three OIDs, so there is no tag, no length and no structure to
// check. RFC 8554 sec. 3.3: "The private key format is not included as it is
// not needed for interoperability and an implementation MAY use any private key
// format." Sec. 4.2 and sec. 5.2 say it again per level -- "The format of the
// LM-OTS private key is an internal matter to the implementation, and this
// document does not attempt to define it", and the same sentence for the LMS
// private key. RFC 8391 sec. 4.1.7: "Note that we do not define any specific
// format or handling for the XMSS private key SK by introducing this
// algorithm"; sec. 4.2.2: "This document does not define any specific format
// for the XMSS^MT private key SK_MT as it is not required for
// interoperability." The one byte layout RFC 8554 does print is the private key
// data in Test Case 2 of Appendix F, which sec. 3.3 offers "for clarity" as an
// example -- it is an illustration, NOT a format, and nothing may be validated
// against it.
//
// A minimum-length floor was tried and rejected. The only candidate number is
// m: RFC 9858 Table 2 registers LMS_SHA256_M24_H5..H25 and
// LMS_SHAKE_M24_H5..H25, all m=24, the smallest of any registered LMS parameter
// set (RFC 8554 Table 2's baseline is m=32). But that MUST -- RFC 8554 sec.
// 5.2, "An LMS private key MAY be generated pseudorandomly from a secret value;
// in this case, the secret value MUST be at least m bytes long ..." -- bounds an
// OPTIONAL, internal, explicitly non-interoperable key-GENERATION input, not
// the bytes a producer places in a transmitted privateKey OCTET STRING; the
// same paragraph adds "The details of how this process is done do not affect
// interoperability". And RFC 8391 states no equivalent number for XMSS at all,
// so the floor could not be applied uniformly to the three entries even if it
// were sound. One arbitrary byte is therefore accepted under these OIDs, on
// purpose: with no defined encoding, dropping a real key is the worse error.
// TestPQCPipeline_UndefinedPrivateKeyEncodingRejectsOnlyEmptyBody pins both the
// one-byte case and the rejected 24-byte floor.
func rejectPrivateKeyBody(info algorithmInfo, body []byte) string {
	if len(body) == 0 {
		return "empty body"
	}

	seed, expanded := registryKeyBodySizes(info)
	// No size in the registry means no defined encoding either: XMSS, XMSS-MT
	// and HSS-LMS reach here, and the doc comment above records why nothing
	// past the emptiness check can be asserted about their bodies.
	if expanded == 0 {
		return ""
	}

	if len(body) == expanded ||
		derOctetStringOf(body, expanded, "") ||
		(seed > 0 && derOctetStringOf(body, seed, "tag:0")) ||
		(seed > 0 && derSeedAndExpandedOf(body, seed, expanded)) {
		return ""
	}

	if seed > 0 {
		return fmt.Sprintf("not a %d-byte seed, a %d-byte expanded key, or both", seed, expanded)
	}
	return fmt.Sprintf("not a %d-byte key", expanded)
}

// derOctetStringOf reports whether body is exactly one OCTET STRING -- or,
// with params "tag:0", one implicitly-tagged `[0] OCTET STRING` -- carrying
// want bytes. The trailing-byte check is what makes this a shape test rather
// than a prefix test: raw noise whose first bytes happen to read as a valid
// header does not end where the header says it does.
//
// params is passed straight to asn1.UnmarshalWithParams; "" reproduces plain
// asn1.Unmarshal. "tag:0" is the seed alternative, `[0] OCTET STRING` of want
// bytes -- 0x80 0x20 followed by 32 bytes for ML-DSA.
func derOctetStringOf(body []byte, want int, params string) bool {
	var content []byte
	rest, err := asn1.UnmarshalWithParams(body, &content, params)
	return err == nil && len(rest) == 0 && len(content) == want
}

// derSeedAndExpandedOf reports whether body is the `both` alternative. The two
// lengths are checked in position: swapping the halves gives a SEQUENCE whose
// members are individually the right size and which encodes no key.
func derSeedAndExpandedOf(body []byte, wantSeed, wantExpanded int) bool {
	var both struct {
		Seed     []byte
		Expanded []byte
	}
	rest, err := asn1.Unmarshal(body, &both)
	return err == nil && len(rest) == 0 &&
		len(both.Seed) == wantSeed && len(both.Expanded) == wantExpanded
}

// registryPrimitive returns the primitive a registry entry declares, falling
// back to signature for entries that do not state one.
func registryPrimitive(info algorithmInfo) cdx.CryptoPrimitive {
	if info.primitive != "" {
		return info.primitive
	}
	return cdx.CryptoPrimitiveSignature
}

// unsupportedPKIX handles a `PUBLIC KEY` PEM block Go's stdlib cannot parse,
// returning the key material component and the algorithm component that
// describes it.
//
// The two claims it can make are not equally supported by the input, for the
// same reason unsupportedPKCS8PrivateKey's are not (see that function's
// comment): the OID establishes that the algorithm is REFERENCED here, which is
// true whatever the bytes after it turn out to be, but that a KEY exists is a
// claim about the body. Validating only the wrapper let a SEQUENCE carrying the
// ML-DSA-65 OID and four bytes of garbage assert a full public key, silently --
// the guard that closed exactly this on the private half was never written for
// this one, so the same four bytes were refused under a PKCS#8 wrapper and
// accepted under a SubjectPublicKeyInfo.
func (c Converter) unsupportedPKIX(ctx context.Context, der []byte) (key, algo cdx.Component, err error) {
	var pubKey pkixStruct
	rest, uerr := asn1.Unmarshal(der, &pubKey)
	if uerr != nil {
		err = fmt.Errorf("parsing PKIX via ASN.1: %w", uerr)
		return
	}
	// asn1.Unmarshal returns what it did not consume, and discarding that
	// accepted anything appended after the SubjectPublicKeyInfo. Since the ref
	// below is a digest of the whole block, one key plus n different tails is n
	// distinct public-key assets all claiming to be the same key -- unbounded,
	// and indistinguishable in the document from n real keys. The tail is
	// published too: hashRawPublicKey base64s the whole der into
	// relatedCryptoMaterialProperties.value, so the garbage goes out verbatim as
	// the key's value. x509.ParsePKIXPublicKey rejects trailing data for the
	// same reason -- which is what routes such a block here in the first place,
	// this being the fallback for keys the stdlib refuses -- and
	// unsupportedPKCS8PrivateKey enforces the identical rule, so the two paths
	// cannot drift.
	if len(rest) > 0 {
		err = fmt.Errorf("parsing PKIX via ASN.1: %d bytes of trailing data", len(rest))
		return
	}
	info, ok := unsupportedAlgorithms[pubKey.Algorithm.Algorithm.String()]
	if !ok {
		err = fmt.Errorf("unsupported fallback oid %q", pubKey.Algorithm.Algorithm.String())
		return
	}

	algo = info.componentWOBomRef(c.ilm)
	// Trust the registry's primitive. Hardcoding "signature" here reported an
	// ML-KEM encapsulation key as a signature algorithm.
	setAlgorithmPrimitive(&algo, registryPrimitive(info))
	c.BOMRefHash(&algo, info.algorithmName)

	// Check the LENGTH, and check it exactly. Unlike the private half there is
	// no CHOICE to enumerate: RFC 9881 sec. 4, and the SLH-DSA and ML-KEM
	// equivalents, put the encoded public key directly in the BIT STRING, so
	// one algorithm has exactly one legal body length rather than several.
	if reason := rejectPublicKeyBody(info, pubKey.PublicKey); reason != "" {
		slog.WarnContext(ctx, "not reporting a public key: the PKIX body is not this algorithm's public key",
			"algorithm", info.name,
			"oid", info.oid,
			"body_bytes", len(pubKey.PublicKey.Bytes),
			"reason", reason)
		return
	}

	pubKeyValue, pubKeyHash := c.hashRawPublicKey(der)
	// public key properties
	var bomRef = fmt.Sprintf(
		"crypto/key/%s@%s",
		strings.ToLower(info.name),
		pubKeyHash,
	)

	relatedProps := &cdx.RelatedCryptoMaterialProperties{
		Type:         cdx.RelatedCryptoMaterialTypePublicKey,
		AlgorithmRef: cdx.BOMReference(algo.BOMRef),
		Value:        pubKeyValue,
	}

	if info.keySize > 0 {
		relatedProps.Size = &info.keySize
	}

	key = cdx.Component{
		Type:   cdx.ComponentTypeCryptographicAsset,
		Name:   info.name,
		BOMRef: bomRef,
		CryptoProperties: &cdx.CryptoProperties{
			AssetType:                       cdx.CryptoAssetTypeRelatedCryptoMaterial,
			OID:                             info.oid,
			RelatedCryptoMaterialProperties: relatedProps,
		},
	}

	return
}

// registryPublicKeyBodySize returns the size in BYTES that a
// SubjectPublicKeyInfo's publicKey BIT STRING holds for this algorithm -- the
// encapsulation key for a KEM, the public key for a signature scheme --
// mirroring registryKeyBodySizes on the private half. It is 0 when the registry
// states none.
//
// A KEM's public half is its encapsulation key and a signature scheme's is its
// public key, carried by different registry shapes (kemInfo vs pqcInfo), so
// reading only pubKeySize would silently return 0 -- no check at all -- for
// every ML-KEM parameter set.
//
// These are byte counts from FIPS 203/204/205. They are NOT the schema's
// relatedCryptoMaterialProperties.size, which is in bits, and they are not
// algorithmInfo.keySize either: that field is in bits and is 0 on every
// registry entry, so measuring the body against it would be no check at all.
func registryPublicKeyBodySize(info algorithmInfo) int {
	switch sizes := info.pqc.(type) {
	case kemInfo:
		return sizes.encapKeySize
	case pqcInfo:
		return sizes.pubKeySize
	}
	return 0
}

// rejectPublicKeyBody returns why pubKey cannot be info's public key, or ""
// when it is.
//
// A PKCS#8 privateKey admits several legal lengths because RFC 9881 sec. 6
// makes it a CHOICE of seed, expandedKey, or both, which is why
// rejectPrivateKeyBody enumerates encodings and needs derOctetStringOf and its
// siblings to tell them apart. A SubjectPublicKeyInfo has no such CHOICE: RFC
// 9881 sec. 4, and the SLH-DSA and ML-KEM equivalents, put the encoded key
// directly in the BIT STRING, so there is exactly one legal length per
// algorithm and nothing wrapping it to inspect. That is why this side has no
// shape helpers -- there is no shape, only a length.
//
// The comparison is an EXACT match rather than a floor. A floor at the registry
// size would still pass a body one byte short of a real key, and the four-byte
// 0xdeadbeef this check exists to catch is a floor's blind spot at every
// threshold below the real size. Too long is refused for the same reason too
// short is: with the key encoded directly there is nothing to pad it with, so
// an extra byte means these are not that key's bytes.
//
// asn1.BitString.Bytes excludes the leading unused-bits octet, so it is
// directly comparable to the registry's byte counts: the ML-DSA-65 fixture's
// BIT STRING is 1953 bytes on the wire and 1952 here.
//
// An empty body is refused whatever the algorithm, for the same reason
// rejectPrivateKeyBody refuses one: no encoding of any key is zero bytes, so
// that much can be ruled out without knowing the algorithm, including for the
// three entries the registry states no size for (XMSS, XMSS-MT, HSS-LMS: RFC
// 9802 puts the parameters in the key value, not in the OID).
func rejectPublicKeyBody(info algorithmInfo, pubKey asn1.BitString) string {
	if len(pubKey.Bytes) == 0 {
		return "empty body"
	}

	want := registryPublicKeyBodySize(info)
	if want == 0 {
		return ""
	}

	if len(pubKey.Bytes) != want {
		return fmt.Sprintf("not a %d-byte public key", want)
	}
	return ""
}

func (c Converter) hashRawPublicKey(der []byte) (value, hash string) {
	value = base64.StdEncoding.EncodeToString(der)
	hash = c.bomRefHasher(der)
	return
}
