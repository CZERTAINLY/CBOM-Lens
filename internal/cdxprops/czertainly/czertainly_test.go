package czertainly_test

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"net"
	"testing"

	"github.com/CZERTAINLY/CBOM-lens/internal/cdxprops/czertainly"
	"github.com/CZERTAINLY/CBOM-lens/internal/model"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/stretchr/testify/require"
)

func TestCertificateProperties(t *testing.T) {
	_, ipNet1, err := net.ParseCIDR("192.0.2.0/24")
	require.NoError(t, err)
	_, ipNet2, err := net.ParseCIDR("198.51.100.0/24")
	require.NoError(t, err)

	cert := &x509.Certificate{
		Raw:                         []byte("rawderp"),
		MaxPathLen:                  0,
		MaxPathLenZero:              true,
		OCSPServer:                  []string{"http://ocsp.example"},
		IssuingCertificateURL:       []string{"http://issuing.example"},
		CRLDistributionPoints:       []string{"http://crl.example"},
		Version:                     3,
		Issuer:                      pkix.Name{CommonName: "Issuer CN"},
		Subject:                     pkix.Name{CommonName: "Subject CN"},
		BasicConstraintsValid:       true,
		IsCA:                        true,
		SubjectKeyId:                []byte{0x01, 0x02},
		AuthorityKeyId:              []byte{0x0a, 0x0b},
		PermittedDNSDomains:         []string{"allowed.example"},
		PermittedDNSDomainsCritical: true,
		ExcludedDNSDomains:          []string{"excluded.example"},
		PermittedIPRanges:           []*net.IPNet{ipNet1},
		ExcludedIPRanges:            []*net.IPNet{ipNet2},
		PermittedEmailAddresses:     []string{"allowed@example.com"},
		ExcludedEmailAddresses:      []string{"excluded@example.com"},
		PermittedURIDomains:         []string{"allowed.uri"},
		ExcludedURIDomains:          []string{"excluded.uri"},
		PolicyIdentifiers:           []asn1.ObjectIdentifier{{1, 2, 3}},
		Policies:                    nil,
		InhibitAnyPolicyZero:        true,
		InhibitAnyPolicy:            0,
		InhibitPolicyMappingZero:    true,
		InhibitPolicyMapping:        0,
		RequireExplicitPolicyZero:   true,
		RequireExplicitPolicy:       0,
		PolicyMappings:              nil,
		UnhandledCriticalExtensions: []asn1.ObjectIdentifier{{2, 5, 29, 15}},
		UnknownExtKeyUsage:          []asn1.ObjectIdentifier{{1, 2, 840}},
		Extensions: []pkix.Extension{
			{
				Id:       asn1.ObjectIdentifier{1, 2, 3},
				Critical: true,
				Value:    []byte{0x0a},
			},
		},
		ExtraExtensions: []pkix.Extension{
			{
				Id:       asn1.ObjectIdentifier{1, 2, 4},
				Critical: false,
				Value:    []byte{0x0b},
			},
		},
	}

	props := czertainly.CertificateProperties("PEM", cert, "sha256:fingerprint")

	// build map of properties for assertions
	values := make(map[string]string, len(props))
	for _, p := range props {
		values[p.Name] = p.Value
	}

	require.Equal(t, "PEM", values[czertainly.CertificateSourceFormat])
	require.Equal(t, base64.StdEncoding.EncodeToString(cert.Raw), values[czertainly.CertificateBase64Content])
	require.Equal(t, "sha256:fingerprint", values[czertainly.CertificateFingerprint])
}

func TestSSHHostKeyProperties(t *testing.T) {
	initial := []cdx.Property{
		{Name: "initial", Value: "v"},
	}
	key := model.SSHHostKey{
		Key:         "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC",
		Fingerprint: "aa:bb:cc:dd",
	}

	props := czertainly.SSHHostKeyProperties(initial, key)
	require.Len(t, props, 3)
	// initial preserved
	require.Equal(t, "initial", props[0].Name)
	require.Equal(t, "v", props[0].Value)
	// appended properties
	require.Equal(t, czertainly.SSHHostKeyContent, props[1].Name)
	require.Equal(t, key.Key, props[1].Value)
	require.Equal(t, czertainly.SSHHostKeyFingerprintContent, props[2].Name)
	require.Equal(t, key.Fingerprint, props[2].Value)
}
