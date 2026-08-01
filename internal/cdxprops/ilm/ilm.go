// ilm package contains constants and helpers for extended properties provided by OmniTrust project
package ilm

import (
	"crypto/x509"
	"encoding/base64"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/OmniTrustILM/cbom-lens/internal/model"
)

const (
	CertificateSourceFormat  = "ilm:component:certificate:source_format"
	CertificateBase64Content = "ilm:component:certificate:base64_content"
	CertificateFingerprint   = "ilm:component:certificate:fingerprint"

	SSHHostKeyFingerprintContent = "ilm:component:ssh_hostkey:fingerprint_content"
	SSHHostKeyContent            = "ilm:component:ssh_hostkey:content"
	PrivateKeyType               = "ilm:component:private_key:type"
	PrivateKeyBase64Content      = "ilm:component:private_key:base64_content"
	SignatureAlgorithmFamily     = "ilm:component:algorithm:family"

	// additional PQC data
	AlgorithmPrivateKeySize = "ilm:component:algorithm:pqc:private_key_size"
	AlgorithmPublicKeySize  = "ilm:component:algorithm:pqc:public_key_size"
	AlgorithmSignatureSize  = "ilm:component:algorithm:pqc:signature_size"

	// AlgorithmCiphertextSize is the KEM ciphertext size in bytes. KEMs reuse
	// AlgorithmPublicKeySize for the encapsulation key and
	// AlgorithmPrivateKeySize for the decapsulation key, and never emit
	// AlgorithmSignatureSize, because a KEM cannot sign.
	AlgorithmCiphertextSize = "ilm:component:algorithm:pqc:ciphertext_size"
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
