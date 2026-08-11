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

// sigAlgOID returns oid of a signature algorithm for x509 Certificate
// or empty string if it fails
func sigAlgOID(cert *x509.Certificate) string {
	return sigAlgOIDFromRaw(cert.Raw)
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

func spkiOID(cert *x509.Certificate) string {
	var info pkixStruct
	if _, err := asn1.Unmarshal(cert.RawSubjectPublicKeyInfo, &info); err != nil {
		return ""
	}
	return info.Algorithm.Algorithm.String()
}

func readSignatureAlgorithmRef(ctx context.Context, cert *x509.Certificate, oidFallback string) cdx.BOMReference {
	return readSignatureAlgorithmRefFor(ctx, cert.SignatureAlgorithm, oidFallback)
}

// readSignatureAlgorithmRefFor is readSignatureAlgorithmRef over the one field
// it ever read. x509.RevocationList carries a SignatureAlgorithm of the same
// type and no certificate, so the lookup is reachable for a CRL only once the
// parameter is the enum rather than the structure that happens to hold it.
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
		hit.Cert,
	)
	mainCertCompo.CryptoProperties.CertificateProperties.SignatureAlgorithmRef = cdx.BOMReference(signatureAlgCompo.BOMRef)
	// The subject public key reference names the KEY, not the algorithm that
	// key uses (#204). The specification's own 1.7 conformance fixtures make
	// the distinction visible: a certificate relates to an "algorithm" and a
	// "publicKey", and those are different assets. Pointing this at the
	// algorithm component collapsed the two into one kind, so a consumer
	// walking certificate-to-key edges landed on an algorithm.
	if publicKeyCompo.BOMRef != "" {
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
	compos := []cdx.Component{
		mainCertCompo,
		signatureAlgCompo,
		publicKeyCompo,
		publicKeyAlgCompo,
	}

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

	if c.ilm {
		props := ilm.CertificateProperties(
			hit.Source,
			cert,
			"sha256:"+fingerprints[0].Value,
		)
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
	if algName == "0" {
		info, ok := unsupportedAlgorithms[oid]
		if ok {
			algName = info.name
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
// csrSubjectName and crlIssuerName pay nothing extra for the indirection: a
// func literal that captures nothing compiles to the same zero-cost value as
// the string literal it returns.
func nameOrFallback(name pkix.Name, fallback func() string) string {
	if name.CommonName != "" {
		return name.CommonName
	}
	if s := name.String(); s != "" {
		return s
	}
	return fallback()
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
