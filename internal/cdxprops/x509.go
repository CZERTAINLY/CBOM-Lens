package cdxprops

import (
	"context"
	"crypto/dsa" //nolint:staticcheck // cbom-lens is going to recognize even obsoleted crypto
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"path/filepath"
	"strings"
	"time"

	"github.com/CZERTAINLY/CBOM-lens/internal/cdxprops/czertainly"
	"github.com/CZERTAINLY/CBOM-lens/internal/model"
	cdx "github.com/CycloneDX/cyclonedx-go"
)

// ---------- constants & shared lookups ----------

const (
	refUnknownKey       cdx.BOMReference = "crypto/key/unknown@unknown"
	refUnknownAlgorithm cdx.BOMReference = "crypto/algorithm/unknown@unknown"
)

// ---------- ASN.1 helpers (declared once) ----------

type algorithmIdentifier struct {
	Algorithm  asn1.ObjectIdentifier
	Parameters asn1.RawValue `asn1:"optional"`
}

type certOuter struct {
	TBSCert   asn1.RawValue
	SigAlg    algorithmIdentifier
	Signature asn1.BitString
}

type spki struct {
	Algorithm     algorithmIdentifier
	SubjectPubKey asn1.BitString
}

func sigAlgOID(cert *x509.Certificate) (string, bool) {
	var outer certOuter
	if _, err := asn1.Unmarshal(cert.Raw, &outer); err != nil {
		return "", false
	}
	return outer.SigAlg.Algorithm.String(), true
}

func spkiOID(cert *x509.Certificate) (string, bool) {
	var info spki
	if _, err := asn1.Unmarshal(cert.RawSubjectPublicKeyInfo, &info); err != nil {
		return "", false
	}
	return info.Algorithm.Algorithm.String(), true
}

func ReadSignatureAlgorithmRef(ctx context.Context, cert *x509.Certificate) cdx.BOMReference {
	// Prefer Go’s typed enum first (covers all classic algs cleanly).
	if ref, ok := sigAlgRef[cert.SignatureAlgorithm]; ok {
		return ref
	}

	// Fall back to OID (PQC / unknown to stdlib).
	oid, ok := sigAlgOID(cert)
	if !ok {
		slog.DebugContext(ctx, "Failed to parse signatureAlgorithm OID")
		return refUnknownAlgorithm
	}
	if ref, ok := pqcSigOIDRef[oid]; ok {
		return ref
	}

	slog.DebugContext(ctx, "Unknown signature algorithm OID", "oid", oid)
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
		hit.Cert.KeyUsage,
	)
	certificateRelatedProperties(&mainCertCompo, hit.Cert)
	mainCertCompo.CryptoProperties.CertificateProperties.SignatureAlgorithmRef = cdx.BOMReference(signatureAlgCompo.BOMRef)
	mainCertCompo.CryptoProperties.CertificateProperties.SubjectPublicKeyRef = cdx.BOMReference(publicKeyAlgCompo.BOMRef)

	setAlgorithmPrimitive(&signatureAlgCompo, cdx.CryptoPrimitiveSignature)
	setAlgorithmPrimitive(&hashAlgCompo, cdx.CryptoPrimitiveHash)
	setAlgorithmPrimitive(&publicKeyAlgCompo, cdx.CryptoPrimitiveSignature)

	compos := []cdx.Component{
		mainCertCompo,
		signatureAlgCompo,
		hashAlgCompo,
		publicKeyCompo,
		publicKeyAlgCompo,
	}

	deps := []cdx.Dependency{
		{
			Ref: signatureAlgCompo.BOMRef,
			Dependencies: &[]string{
				publicKeyAlgCompo.BOMRef,
				hashAlgCompo.BOMRef,
			},
		},
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

	if c.czertainly {
		props := czertainly.CertificateProperties(
			hit.Source,
			cert,
			"sha256:"+fingerprints[0].Value,
		)
		certComponent.Properties = &props
	}

	return certComponent
}

func (c Converter) certHitToSignatureAlgComponent(ctx context.Context, hit model.CertHit) (sigAlgCompo cdx.Component, hashAlgCompo cdx.Component) {
	sigAlg := hit.Cert.SignatureAlgorithm
	algName := sigAlg.String()
	bomRef := ReadSignatureAlgorithmRef(ctx, hit.Cert)
	bomName, _, _ := strings.Cut(string(bomRef), "@")
	oid, ok := sigAlgOID(hit.Cert)
	if !ok {
		oid = "unknown"
	}

	cryptoProps, props, hashName := c.getAlgorithmProperties(sigAlg)

	sigAlgCompo = cdx.Component{
		Type: cdx.ComponentTypeCryptographicAsset,
		Name: algName,
		CryptoProperties: &cdx.CryptoProperties{
			AssetType:           cdx.CryptoAssetTypeAlgorithm,
			AlgorithmProperties: &cryptoProps,
			OID:                 oid,
		},
		Properties: &props,
	}

	hashAlgCompo = c.hashAlgorithmCompo(hashName)
	c.BOMRefHash(&sigAlgCompo, bomName)
	return
}

func certificateRelatedProperties(compo *cdx.Component, cert *x509.Certificate) {
	// Use certificate serial number as ID if available
	if compo == nil || cert == nil {
		return
	}
	if compo.CryptoProperties == nil {
		compo.CryptoProperties = &cdx.CryptoProperties{}
	}
	if compo.CryptoProperties.RelatedCryptoMaterialProperties == nil {
		compo.CryptoProperties.RelatedCryptoMaterialProperties = &cdx.RelatedCryptoMaterialProperties{}
	}
}

// formatCertificateName creates a human-readable name for the certificate
func formatCertificateName(cert *x509.Certificate) string {
	// Try to use CN (Common Name) if available
	if cert.Subject.CommonName != "" {
		return cert.Subject.CommonName
	}

	// Fallback to full subject DN
	subject := cert.Subject.String()
	if subject != "" {
		return subject
	}

	// Last resort: use serial number
	return fmt.Sprintf("Certificate %s", cert.SerialNumber.String())
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

func ReadSubjectPublicKeyRef(ctx context.Context, cert *x509.Certificate) cdx.BOMReference {
	// First try concrete key types the stdlib understands.
	switch pub := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		return cdx.BOMReference(fmt.Sprintf("crypto/key/rsa-%d@1.2.840.113549.1.1.1", pub.N.BitLen()))
	case *ecdsa.PublicKey:
		switch pub.Params().BitSize {
		case 256:
			return "crypto/key/ecdsa-p256@1.2.840.10045.3.1.7"
		case 384:
			return "crypto/key/ecdsa-p384@1.3.132.0.34"
		case 521:
			return "crypto/key/ecdsa-p521@1.3.132.0.35"
		default:
			return "crypto/key/ecdsa-unknown@1.2.840.10045.2.1"
		}
	case ed25519.PublicKey:
		return "crypto/key/ed25519-256@1.3.101.112"
	case *dsa.PublicKey:
		return cdx.BOMReference(fmt.Sprintf("crypto/key/dsa-%d@1.2.840.10040.4.1", pub.P.BitLen()))
	}

	// Otherwise parse SPKI.algorithm OID (PQC & other non-stdlib types).
	oid, ok := spkiOID(cert)
	if !ok {
		slog.DebugContext(ctx, "Failed to parse SPKI OID")
		return refUnknownKey
	}
	if ref, ok := spkiOIDRef[oid]; ok {
		return ref
	}

	slog.DebugContext(ctx, "Unknown public key algorithm OID", "oid", oid)
	return refUnknownKey
}
