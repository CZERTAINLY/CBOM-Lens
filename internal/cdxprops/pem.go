package cdxprops

import (
	"context"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"
	"time"

	"github.com/OmniTrustILM/cbom-lens/internal/model"

	cdx "github.com/CycloneDX/cyclonedx-go"
)

// PEMBundleToCDX converts a PEM bundle to CycloneDX components
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
		compos, err := c.analyzeParseError(block, parseErr)
		if err != nil {
			errs = append(errs, err)
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
func (c Converter) crlToCDX(crl *x509.RevocationList) cdx.Component {
	name := crlIssuerName(crl)
	props := []cdx.Property{
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
// empty subject yields "unknown" -- an empty Name is the other half of what
// Builder.appendDetection drops.
func csrSubjectName(csr *x509.CertificateRequest) string {
	if csr.Subject.CommonName != "" {
		return csr.Subject.CommonName
	}
	if subject := csr.Subject.String(); subject != "" {
		return subject
	}
	return "unknown"
}

// crlIssuerName names a revocation list for its bom-ref and Name. A CRL has no
// subject, so it is named after its issuer, otherwise following
// csrSubjectName.
func crlIssuerName(crl *x509.RevocationList) string {
	if crl.Issuer.CommonName != "" {
		return crl.Issuer.CommonName
	}
	if issuer := crl.Issuer.String(); issuer != "" {
		return issuer
	}
	return "unknown"
}

// Helper functions
func (c Converter) analyzeParseError(block model.PEMBlock, origErr error) ([]cdx.Component, error) {
	switch block.Type {
	case "PRIVATE KEY":
		key, algo, err := c.unsupportedPKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, errors.Join(origErr, err)
		}
		return []cdx.Component{key, algo}, nil
	case "PUBLIC KEY":
		key, algo, err := c.unsupportedPKIX(block.Bytes)
		if err != nil {
			return nil, errors.Join(origErr, err)
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
func (c Converter) unsupportedPKCS8PrivateKey(der []byte) (key, algo cdx.Component, err error) {
	var pkcs8 pkcs8Struct
	if _, err = asn1.Unmarshal(der, &pkcs8); err != nil {
		err = fmt.Errorf("parsing PKCS#8 via ASN.1: %w", err)
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

	key = cdx.Component{
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
		BOMRef: fmt.Sprintf("crypto/private_key/%s@%s", strings.ToLower(info.name), c.bomRefHasher(der)),
		CryptoProperties: &cdx.CryptoProperties{
			AssetType:                       cdx.CryptoAssetTypeRelatedCryptoMaterial,
			OID:                             info.oid,
			RelatedCryptoMaterialProperties: relatedProps,
		},
	}

	return
}

// registryPrimitive returns the primitive a registry entry declares, falling
// back to signature for entries that do not state one.
func registryPrimitive(info algorithmInfo) cdx.CryptoPrimitive {
	if info.primitive != "" {
		return info.primitive
	}
	return cdx.CryptoPrimitiveSignature
}

func (c Converter) unsupportedPKIX(der []byte) (key, algo cdx.Component, err error) {
	var pubKey pkixStruct
	_, err = asn1.Unmarshal(der, &pubKey)
	if err != nil {
		err = fmt.Errorf("parsing PKIX via ASN.1: %w", err)
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

func (c Converter) hashRawPublicKey(der []byte) (value, hash string) {
	value = base64.StdEncoding.EncodeToString(der)
	hash = c.bomRefHasher(der)
	return
}
