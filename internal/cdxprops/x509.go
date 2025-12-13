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
type pkcs8Struct struct {
	Version int
	Algo    pkix.AlgorithmIdentifier
}

// sigAlgOID returns oid of a signature algorithm for x509 Certificate
// or empty string if it fails
func sigAlgOID(cert *x509.Certificate) string {
	var outer certOuterStruct
	if _, err := asn1.Unmarshal(cert.Raw, &outer); err != nil {
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
	// Prefer Go’s typed enum first (covers all classic algs cleanly).
	if ref, ok := sigAlgRef[cert.SignatureAlgorithm]; ok {
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
	certificateRelatedProperties(&mainCertCompo, hit.Cert)
	mainCertCompo.CryptoProperties.CertificateProperties.SignatureAlgorithmRef = cdx.BOMReference(signatureAlgCompo.BOMRef)
	mainCertCompo.CryptoProperties.CertificateProperties.SubjectPublicKeyRef = cdx.BOMReference(publicKeyAlgCompo.BOMRef)

	setAlgorithmPrimitive(&signatureAlgCompo, cdx.CryptoPrimitiveSignature)
	setAlgorithmPrimitive(&publicKeyAlgCompo, cdx.CryptoPrimitiveSignature)

	compos := []cdx.Component{
		mainCertCompo,
		signatureAlgCompo,
		publicKeyCompo,
		publicKeyAlgCompo,
	}

	var deps []cdx.Dependency

	if hashAlgCompo != nil {
		setAlgorithmPrimitive(hashAlgCompo, cdx.CryptoPrimitiveHash)
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

func (c Converter) certHitToSignatureAlgComponent(ctx context.Context, hit model.CertHit) (sigAlgCompo cdx.Component, hashAlgCompo *cdx.Component) {
	sigAlg := hit.Cert.SignatureAlgorithm
	algName := sigAlg.String()
	oid := sigAlgOID(hit.Cert)
	bomRef := readSignatureAlgorithmRef(ctx, hit.Cert, oid)
	bomName, _, _ := strings.Cut(string(bomRef), "@")
	if oid == "" {
		oid = "unknown"
	}

	cryptoProps, props, hashName := c.getAlgorithmProperties(sigAlg, oid)
	if algName == "0" {
		info, ok := unsupportedAlgorithms[oid]
		if ok {
			algName = info.algorithmName
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
		Properties: &props,
	}

	c.BOMRefHash(&sigAlgCompo, bomName)

	if hashName != "" {
		compo := c.hashAlgorithmCompo(hashName)
		hashAlgCompo = &compo
	}
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
