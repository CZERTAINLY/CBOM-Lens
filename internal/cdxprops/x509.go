package cdxprops

import (
	"context"
	"crypto/sha1" //nolint:staticcheck // cbom-lens is going to recognize even obsoleted crypto
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"path/filepath"
	"strings"
	"time"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/OmniTrustILM/cbom-lens/internal/cdxprops/ilm"
	"github.com/OmniTrustILM/cbom-lens/internal/model"
)

// ---------- constants & shared lookups ----------

const (
	refUnknownKey       cdx.BOMReference = "crypto/key/unknown@unknown"
	refUnknownAlgorithm cdx.BOMReference = "crypto/algorithm/unknown@unknown"

	// oidPlaceholder is what extractAlgorithmInfo's default branch writes into
	// algorithmInfo.oid when nothing named the algorithm. It is a sentinel, not
	// an OID: nothing is registered under 0.0.0.0, and cryptoProperties.oid has
	// no in-band UNKNOWN. The field is omitempty and componentWOBomRef writes it
	// only when the algorithm states an arc, so a component built that way
	// either names one or carries no oid at all -- saying nothing is a shape the
	// field already has.
	// A sentinel is neither of those: it travels to the consumer through the
	// very channel a real arc does and cannot be told apart from one there. A
	// producer that can reach that branch therefore tests for this value and
	// emits nothing rather than a component built around it -- see csrToCDX.
	oidPlaceholder = "0.0.0.0"
)

// ---------- ASN.1 helpers (declared once) ----------

type certOuterStruct struct {
	TBSCert   asn1.RawValue
	SigAlg    pkix.AlgorithmIdentifier
	Signature asn1.BitString
}

// public key infrastructure (X) - used for x509.Certificates and public keys
type pkixStruct struct {
	Algorithm pkix.AlgorithmIdentifier
	PublicKey asn1.BitString
}

// PKCS#8 structure for extracting raw key bytes
//
// PrivateKey is RFC 5208's mandatory privateKey OCTET STRING. It is decoded
// because without it nothing ever looked at the key body: a PEM block wrapping
// a well-formed wrapper, a registry OID and four bytes of garbage produced a
// full "an ML-DSA-65 private key exists here" assertion. See
// unsupportedPKCS8PrivateKey for the size check it feeds.
//
// The trailing attributes [0] and publicKey [1] that RFC 5958 adds to
// OneAsymmetricKey are deliberately not declared. Go's asn1 allows extra
// elements at the end of a SEQUENCE, so real keys carrying them still parse;
// TestPKCS8Struct_ParsesRFC5958TrailingFields pins that.
type pkcs8Struct struct {
	Version    int
	Algo       pkix.AlgorithmIdentifier
	PrivateKey []byte
}

// sigAlgOIDFromRaw returns the signature algorithm OID declared in the DER of a
// signed PKIX structure, or "" when the bytes do not have that shape.
//
// It takes the raw DER rather than a certificate because a revocation list
// needs the same answer and is not a certificate. RFC 5280 gives
// CertificateList the same top-level SEQUENCE as Certificate -- the signed
// body, then the signatureAlgorithm, then the signature -- which is exactly
// what certOuterStruct describes, so one parse serves both.
func sigAlgOIDFromRaw(raw []byte) string {
	var outer certOuterStruct
	if _, err := asn1.Unmarshal(raw, &outer); err != nil {
		return ""
	}
	return outer.SigAlg.Algorithm.String()
}

// spkiFromRaw decodes a SubjectPublicKeyInfo into the two things this package
// reads from it: the algorithm OID, which names the key when Go's own enum
// could not, and the publicKey BIT STRING, which is the only evidence that a
// key of that algorithm is present at all. ok is false when those bytes are not
// a SubjectPublicKeyInfo.
//
// It takes bytes, not an x509.Certificate. A certificate request carries the
// same structure with no certificate to hang it on, and the predecessor that
// took one made the SPKI fallback a property of callers that happened to have
// a certificate.
//
// It returns the whole structure rather than just the OID, so that
// publicKeyComponents decodes this field ONCE and reads it twice. Two decodes
// of one field are two chances to disagree about what it holds, and a body
// check reading a different decode from the OID lookup beside it is the shape
// of the defect the body check exists to close.
//
// asn1.BitString.Bytes excludes the leading unused-bits octet, so the length of
// PublicKey.Bytes is directly comparable to the byte counts
// registryPublicKeyBodySize returns. rejectPublicKeyBody does the comparing.
func spkiFromRaw(raw []byte) (pkixStruct, bool) {
	var info pkixStruct
	if _, err := asn1.Unmarshal(raw, &info); err != nil {
		return pkixStruct{}, false
	}
	return info, true
}

// spkiOIDFromRaw names the algorithm a SubjectPublicKeyInfo declares, or "" if
// the structure does not decode. It reads the OID off the same decode
// spkiFromRaw performs rather than repeating the unmarshal, which is what keeps
// a rule enforced on one path from going missing on the other.
func spkiOIDFromRaw(raw []byte) string {
	info, ok := spkiFromRaw(raw)
	if !ok {
		return ""
	}
	return info.Algorithm.Algorithm.String()
}

// readSignatureAlgorithmRefFor names the algorithm asset a signed PKIX
// structure's signature belongs to. It takes the enum rather than the
// certificate that happens to hold it, because x509.RevocationList carries a
// SignatureAlgorithm of the same type and no certificate, so a CRL can reach
// the lookup only this way.
func readSignatureAlgorithmRefFor(ctx context.Context, sigAlg x509.SignatureAlgorithm, oidFallback string) cdx.BOMReference {
	// Prefer Go’s typed enum first (covers all classic algs cleanly).
	if ref, ok := sigAlgRef[sigAlg]; ok {
		return ref
	}

	if oidFallback == "" {
		slog.DebugContext(ctx, "Failed to parse signatureAlgorithm OID")
		return refUnknownAlgorithm
	}

	if ref, ok := pqcSigOIDRef[oidFallback]; ok {
		return ref
	}

	slog.DebugContext(ctx, "Unknown signature algorithm OID", "oid", oidFallback)
	return refUnknownAlgorithm
}

// certHitToComponents converts an X.509 certificate to a CycloneDX component
func (c Converter) certHitToComponents(ctx context.Context, hit model.CertHit) ([]cdx.Component, []cdx.Dependency, error) {
	if hit.Cert == nil {
		return nil, nil, errors.New("x509.Certificate is nil")
	}

	mainCertCompo := c.certComponent(ctx, hit)
	signatureAlgCompo, hashAlgCompo := c.certHitToSignatureAlgComponent(ctx, hit)
	publicKeyAlgCompo, publicKeyCompo := c.publicKeyComponents(
		ctx,
		hit.Cert.PublicKeyAlgorithm,
		hit.Cert.PublicKey,
		hit.Cert.RawSubjectPublicKeyInfo,
	)
	mainCertCompo.CryptoProperties.CertificateProperties.SignatureAlgorithmRef = cdx.BOMReference(signatureAlgCompo.BOMRef)
	// The subject public key reference names the KEY, not the algorithm that
	// key uses (#204). The specification's own 1.7 conformance fixtures make
	// the distinction visible: a certificate relates to an "algorithm" and a
	// "publicKey", and those are different assets. Pointing this at the
	// algorithm component collapsed the two into one kind, so a consumer
	// walking certificate-to-key edges landed on an algorithm.
	if publicKeyCompo != nil {
		mainCertCompo.CryptoProperties.CertificateProperties.SubjectPublicKeyRef = cdx.BOMReference(publicKeyCompo.BOMRef)
	}

	// Each component's primitive is set by whichever function built it, before
	// that function hashed it into a BOMRef. Do not re-stamp primitives here: a
	// BOMRef is a hash of the component's own contents, so mutating a component
	// after it has been hashed leaves a reference that no longer describes what
	// it names. TestCertHitToComponents_BOMRefsMatchContents pins this.
	//
	// This previously forced "signature" onto both components. It was a no-op
	// for the signature algorithm, which getAlgorithmProperties already builds
	// as a signature, but it silently discarded the public key's real primitive
	// -- reporting a keyEncipherment RSA key as a signature scheme and an
	// ML-KEM key as a signature rather than a kem.
	compos := []cdx.Component{mainCertCompo, signatureAlgCompo}
	// publicKeyComponents yields no key when the certificate's SPKI body cannot
	// be this algorithm's public key. Nothing is left dangling:
	// SubjectPublicKeyRef above is conditional on the same nil.
	if publicKeyCompo != nil {
		compos = append(compos, *publicKeyCompo)
	}
	compos = append(compos, publicKeyAlgCompo)

	var deps []cdx.Dependency

	if hashAlgCompo != nil {
		compos = append(compos, *hashAlgCompo)

		deps = []cdx.Dependency{
			{
				Ref: signatureAlgCompo.BOMRef,
				Dependencies: &[]string{
					publicKeyAlgCompo.BOMRef,
					hashAlgCompo.BOMRef,
				},
			},
		}
	}

	return compos, deps, nil
}

func (c Converter) certComponent(_ context.Context, hit model.CertHit) cdx.Component {
	cert := hit.Cert

	certHash := c.bomRefHasher(cert.Raw)
	// Extract fingerprints
	fingerprints := extractFingerprints(cert)
	// Extract subject alternative names
	name := formatCertificateName(cert)

	// Build certificate properties
	certProps := cdx.CertificateProperties{
		SubjectName:          cert.Subject.String(),
		IssuerName:           cert.Issuer.String(),
		NotValidBefore:       cert.NotBefore.Format(time.RFC3339),
		NotValidAfter:        cert.NotAfter.Format(time.RFC3339),
		CertificateFormat:    "X.509",
		CertificateExtension: filepath.Ext(hit.Location),
	}

	// Build the certificate component
	certComponent := cdx.Component{
		BOMRef: "crypto/certificate/" + name + "@" + certHash,
		Type:   cdx.ComponentTypeCryptographicAsset,
		Name:   name,
		Hashes: &fingerprints,
		CryptoProperties: &cdx.CryptoProperties{
			AssetType:             cdx.CryptoAssetTypeCertificate,
			CertificateProperties: &certProps,
		},
	}

	// key_usage is NOT behind c.ilm, and the two properties below are, and the
	// difference is not an oversight. ilm.CertificateProperties is enrichment
	// this tool adds; the keyUsage extension is a field parsed out of a standard
	// X.509 certificate, and -- decisively -- the vanilla document ALREADY
	// carried it before this change, lossily, as the RSA algorithm's primitive.
	// Gating it would make this fix delete information from every non-ILM
	// consumer's output. pem_type, subject, issuer and revoked_count are
	// un-namespaced and ungated for the same reason.
	var props []cdx.Property
	if usage := certificateKeyUsage(cert); usage != "" {
		props = append(props, cdx.Property{Name: propKeyUsage, Value: usage})
	}
	if c.ilm {
		props = append(props, ilm.CertificateProperties(
			hit.Source,
			cert,
			"sha256:"+fingerprints[0].Value,
		)...)
	}
	if len(props) > 0 {
		certComponent.Properties = &props
	}

	return certComponent
}

func (c Converter) certHitToSignatureAlgComponent(ctx context.Context, hit model.CertHit) (sigAlgCompo cdx.Component, hashAlgCompo *cdx.Component) {
	return c.signatureAlgorithmComponents(ctx, hit.Cert.SignatureAlgorithm, hit.Cert.Raw)
}

// signatureAlgorithmComponents describes the algorithm a signed PKIX structure
// was signed with: the algorithm asset, and the hash it decomposes into. The
// hash is nil only when nothing names one -- every algorithm Go's enum knows
// has one, Ed25519 included, since RFC 8032 builds it on SHA-512 and
// getAlgorithmProperties maps it that way. A nil therefore means an
// UnknownSignatureAlgorithm whose OID either misses the registry or hits an
// entry that carries no hash: ML-DSA and the stateful hash-based schemes, but
// not SLH-DSA, whose entries map to SHA-256 or SHAKE-256.
//
// It takes the algorithm enum and the DER rather than a certificate because
// those two values are all the certificate ever supplied, and a CRL carries
// both. Before the split, a scanned .crl reached the document naming its issuer
// and its revocation count and saying nothing at all about the cryptography in
// it -- the signature algorithm was parsed by Go, sat in the struct, and was
// dropped.
func (c Converter) signatureAlgorithmComponents(ctx context.Context, sigAlg x509.SignatureAlgorithm, raw []byte) (sigAlgCompo cdx.Component, hashAlgCompo *cdx.Component) {
	algName := sigAlg.String()
	oid := sigAlgOIDFromRaw(raw)
	bomRef := readSignatureAlgorithmRefFor(ctx, sigAlg, oid)
	bomName, _, _ := strings.Cut(string(bomRef), "@")
	if oid == "" {
		oid = "unknown"
	}

	cryptoProps, props, hashName := c.getAlgorithmProperties(sigAlg, oid)
	// x509.SignatureAlgorithm.String() is a table lookup that falls through to
	// strconv.Itoa for a value the table does not carry, so an algorithm Go
	// could not identify stringifies to "0" -- the enum's integer, published as
	// the name of a cryptographic asset. Nothing downstream catches it: the
	// Builder's missingIdentity rejects an empty name and this one is not
	// empty, and algorithmFamily17 simply finds no family for it.
	//
	// The registry answers for a post-quantum OID, which is the case worth
	// recovering. Past that there is nothing left to name the algorithm by, and
	// the ref already says as much -- readSignatureAlgorithmRefFor returned
	// refUnknownAlgorithm -- so the name is made to agree with the ref rather
	// than to invent an identity. The OID stays on the component either way,
	// which is the part a reader can act on.
	if sigAlg == x509.UnknownSignatureAlgorithm {
		if info, ok := unsupportedAlgorithms[oid]; ok {
			algName = info.name
		} else {
			algName = "Unknown"
		}
	}

	sigAlgCompo = cdx.Component{
		Type: cdx.ComponentTypeCryptographicAsset,
		Name: algName,
		CryptoProperties: &cdx.CryptoProperties{
			AssetType:           cdx.CryptoAssetTypeAlgorithm,
			AlgorithmProperties: &cryptoProps,
			OID:                 oid,
		},
	}
	if len(props) > 0 {
		sigAlgCompo.Properties = &props
	}

	c.BOMRefHash(&sigAlgCompo, bomName)

	if hashName != "" {
		compo := c.hashAlgorithmCompo(hashName)
		hashAlgCompo = &compo
	}
	return
}

// nameOrFallback returns a human-readable name for a pkix.Name -- a
// certificate's subject, a CSR's subject, or a CRL's issuer: the Common Name
// if one is set, else the full DN from pkix.Name.String(), else fallback().
//
// fallback is a func() rather than an already-formatted string so that
// formatCertificateName's serial-number fallback -- an fmt.Sprintf plus a
// big.Int-to-decimal conversion -- runs only for the rare certificate whose
// subject is entirely empty, not for every certificate this is called for.
// nameOrUnknown, which is the CSR and CRL path, pays nothing extra for the
// indirection: a func literal that captures nothing compiles to the same
// zero-cost value as the string literal it returns.
func nameOrFallback(name pkix.Name, fallback func() string) string {
	if name.CommonName != "" {
		return name.CommonName
	}
	if s := name.String(); s != "" {
		return s
	}
	return fallback()
}

// propKeyUsage is the property name under which a certificate publishes its
// RFC 5280 sec. 4.2.1.3 keyUsage extension.
//
// It is a component property and not certificateProperties.certificateExtensions
// -- 1.7's purpose-built home for exactly this (bom-1.7.schema.json:5692-5736)
// -- because 1.6's certificateProperties is additionalProperties:false with no
// such field, and emit16.Emit copies every component through verbatim with no
// per-component mapping, so a producer-set CertificateExtensions would make
// every 1.6 document fail the validator AsJSON runs on each emit. Promoting it
// means giving emit16 a clone-and-strip pass whose only user would be this one
// field. The value below is formatted so that such a promotion can reuse it
// verbatim as a commonExtensionValue.
const propKeyUsage = "key_usage"

// keyUsageBits is a slice and not a map, and its order is RFC 5280 sec.
// 4.2.1.3's KeyUsage BIT STRING bit order, because that order IS the order
// certificateKeyUsage emits. A map would make the emitted value depend on Go's
// randomised iteration, so the same certificate would publish the same set of
// bits in a different string on almost every run -- and the certificate
// component's ref is a digest of cert.Raw, so nothing downstream would notice
// the value churning under a stable ref.
//
// Bit 1 is spelled nonRepudiation, which is RFC 5280's own ASN.1 identifier for
// it; Go names the constant KeyUsageContentCommitment after the newer spelling
// the same RFC mentions in prose.
var keyUsageBits = []struct {
	bit  x509.KeyUsage
	name string
}{
	{x509.KeyUsageDigitalSignature, "digitalSignature"},
	{x509.KeyUsageContentCommitment, "nonRepudiation"},
	{x509.KeyUsageKeyEncipherment, "keyEncipherment"},
	{x509.KeyUsageDataEncipherment, "dataEncipherment"},
	{x509.KeyUsageKeyAgreement, "keyAgreement"},
	{x509.KeyUsageCertSign, "keyCertSign"},
	{x509.KeyUsageCRLSign, "cRLSign"},
	{x509.KeyUsageEncipherOnly, "encipherOnly"},
	{x509.KeyUsageDecipherOnly, "decipherOnly"},
}

// certificateKeyUsage renders a certificate's keyUsage extension as the RFC 5280
// identifiers of the bits it sets, comma-separated and in bit order, or "" when
// the certificate sets none.
//
// This is where the fact the algorithm asset used to carry lives now. The
// placement is what makes it safe: the certificate's bom-ref is a digest of
// cert.Raw, the keyUsage extension is inside cert.Raw, so two components sharing
// that ref carry the same extension and therefore the same value here. Order
// independence is structural rather than merged, which is why the Builder needs
// no rule for this property -- the same argument mergeCertificateSourceFormat
// makes for base64_content and fingerprint.
//
// "" rather than an empty-valued property for KeyUsage == 0: RFC 5280 requires
// at least one bit set when the extension is present, so zero means the
// certificate makes no assertion, and a property with an empty value asserts
// nothing while looking like an assertion.
func certificateKeyUsage(cert *x509.Certificate) string {
	if cert == nil || cert.KeyUsage == 0 {
		return ""
	}
	var names []string
	for _, ku := range keyUsageBits {
		if cert.KeyUsage&ku.bit != 0 {
			names = append(names, ku.name)
		}
	}
	return strings.Join(names, ",")
}

// formatCertificateName creates a human-readable name for the certificate:
// CN if there is one, else the full subject DN, else the serial number.
func formatCertificateName(cert *x509.Certificate) string {
	return nameOrFallback(cert.Subject, func() string {
		return fmt.Sprintf("Certificate %s", cert.SerialNumber.String())
	})
}

// extractFingerprints calculates certificate fingerprints
func extractFingerprints(cert *x509.Certificate) []cdx.Hash {
	hashes := []cdx.Hash{
		{
			Algorithm: cdx.HashAlgoSHA256,
			Value:     hex.EncodeToString(sha256Hash(cert.Raw)),
		},
		{
			Algorithm: cdx.HashAlgoSHA1,
			Value:     hex.EncodeToString(sha1Hash(cert.Raw)),
		},
	}
	return hashes
}

// sha256Hash computes SHA-256 hash
func sha256Hash(data []byte) []byte {
	hash := sha256.Sum256(data)
	return hash[:]
}

// sha1Hash computes SHA-1 hash
func sha1Hash(data []byte) []byte {
	hash := sha1.Sum(data) // NOSONAR - we provide sha1 and sha256 hashes
	return hash[:]
}
