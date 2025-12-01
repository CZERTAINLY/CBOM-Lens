// czertainly package contains constants and helpers for extended properties provided by CZERTAINLY project
package czertainly

import (
	"crypto/x509"
	"encoding/base64"

	"github.com/CZERTAINLY/CBOM-lens/internal/model"
	cdx "github.com/CycloneDX/cyclonedx-go"
)

const (
	CertificateSourceFormat  = "czertainly:component:certificate:source_format"
	CertificateBase64Content = "czertainly:component:certificate:base64_content"
	CertificateFingerprint   = "czertainly:component:certificate:fingerprint"

	SSHHostKeyFingerprintContent = "czertainly:component:ssh_hostkey:fingerprint_content"
	SSHHostKeyContent            = "czertainly:component:ssh_hostkey:content"
	PrivateKeyType               = "czertainly:component:private_key:type"
	PrivateKeyBase64Content      = "czertainly:component:private_key:base64_content"
	SignatureAlgorithmFamily     = "czertainly:component:algorithm:family"

	// additional PQC data
	AlgorithmPrivateKeySize = "czertainly:component:algorithm:pqc:private_key_size"
	AlgorithmPublicKeySize  = "czertainly:component:algorithm:pqc:public_key_size"
	AlgorithmSignatureSize  = "czertainly:component:algorithm:pqc:signature_size"
)

func CertificateProperties(
	source string,
	cert *x509.Certificate,
	fingerprint string,
) []cdx.Property {

	var props = make([]cdx.Property, 0, 20)
	props = append(props, cdx.Property{
		Name:  CertificateSourceFormat,
		Value: source,
	})
	props = append(props, cdx.Property{
		Name:  CertificateBase64Content,
		Value: base64.StdEncoding.EncodeToString(cert.Raw),
	})
	props = append(props, cdx.Property{
		Name:  CertificateFingerprint,
		Value: fingerprint,
	})
	return props
}

func SSHHostKeyProperties(props []cdx.Property, key model.SSHHostKey) []cdx.Property {
	p1 := cdx.Property{
		Name:  SSHHostKeyContent,
		Value: key.Key,
	}
	p2 := cdx.Property{
		Name:  SSHHostKeyFingerprintContent,
		Value: key.Fingerprint,
	}
	return append(props, []cdx.Property{p1, p2}...)
}
