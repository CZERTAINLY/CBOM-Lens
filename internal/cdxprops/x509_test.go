package cdxprops_test

import (
	"testing"

	"github.com/CZERTAINLY/CBOM-lens/internal/cdxprops"
	"github.com/CZERTAINLY/CBOM-lens/internal/cdxprops/cdxtest"
	"github.com/CZERTAINLY/CBOM-lens/internal/model"

	"github.com/stretchr/testify/require"
)

func TestConverter_CertHit(t *testing.T) {
	ctx := t.Context()

	selfSigned, err := cdxtest.GenSelfSignedCert()
	require.NoError(t, err)
	cert := selfSigned.Cert

	tests := []struct {
		name               string
		hit                model.CertHit
		wantNil            bool
		wantComponentCount int
		wantDepCount       int
		wantType           model.DetectionType
		wantSource         string
		wantLocation       string
	}{
		{
			name: "valid self-signed certificate",
			hit: model.CertHit{
				Cert:     cert,
				Source:   "PEM",
				Location: "/test/cert.pem",
			},
			wantNil:            false,
			wantComponentCount: 5,
			wantDepCount:       1,
			wantType:           model.DetectionTypeCertificate,
			wantSource:         "PEM",
			wantLocation:       "/test/cert.pem",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := cdxprops.NewConverter()
			detection := c.CertHit(ctx, tt.hit)

			if tt.wantNil {
				require.Nil(t, detection)
				return
			}

			require.NotNil(t, detection)
			require.Equal(t, tt.wantComponentCount, len(detection.Components))
			require.Equal(t, tt.wantDepCount, len(detection.Dependencies))
			require.Equal(t, tt.wantType, detection.Type)
			require.Equal(t, tt.wantSource, detection.Source)
			require.Equal(t, tt.wantLocation, detection.Location)

			// Verify the first component (main certificate) has a BOM ref
			require.NotEmpty(t, detection.Components[0].BOMRef)
		})
	}
}

// TODO: cover other cases too
/*
func Test_Component_Edge_Cases(t *testing.T) {
	t.Parallel()

	// Test edge cases for component creation to improve coverage

	// Test with certificate that has no serial number (edge case)
	selfSigned, err := cdxtest.GenSelfSignedCert()
	require.NoError(t, err)
	cert := selfSigned.Cert

	// Create a certificate with some edge cases
	cert.SerialNumber = big.NewInt(0) // Edge case: zero serial number

	testPath, _ := filepath.Abs("testpath")

	hit := model.CertHit{
		Cert:     cert,
		Source:   "TEST",
		Location: testPath,
	}
	c := cdxprops.NewConverter()
	detection := c.CertHit(t.Context(), hit)
	require.NotNil(t, detection)
	require.Len(t, detection.Components, 4)
	compo := detection.Components[0]

	require.Equal(t, cdx.ComponentTypeCryptographicAsset, compo.Type)
	require.NotNil(t, compo.Evidence)
	require.NotNil(t, compo.Evidence.Occurrences)
	require.GreaterOrEqual(t, len(*compo.Evidence.Occurrences), 1)
	loc := (*compo.Evidence.Occurrences)[0].Location
	require.NotEmpty(t, loc)
	require.True(t, filepath.IsAbs(loc))
	requireFormatAndDERBase64(t, compo)

	// Check that certificate extension is properly set
	require.NotNil(t, compo.CryptoProperties)
	require.NotNil(t, compo.CryptoProperties.CertificateProperties)
	require.Equal(t, "", compo.CryptoProperties.CertificateProperties.CertificateExtension)
}

// Test_Component_UnsupportedKeys tests handling of key types for better coverage
func Test_Component_UnsupportedKeys(t *testing.T) {
	t.Parallel()

	// Test with actual Ed25519 certificate to exercise that path
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "Ed25519 Test Certificate",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		SignatureAlgorithm:    x509.PureEd25519,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, priv.Public(), priv)
	require.NoError(t, err)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)
	testPath, err := filepath.Abs("testpath")
	require.NoError(t, err)

	hit := model.CertHit{
		Cert:     cert,
		Location: testPath,
		Source:   "TEST",
	}

	c := cdxprops.NewConverter()
	detection := c.CertHit(t.Context(), hit)
	require.NotNil(t, detection)
	require.Len(t, detection.Components, 4)
	comp := detection.Components[0]

	require.Equal(t, cdx.ComponentTypeCryptographicAsset, comp.Type)
	err = cdxtest.HasEvidencePath(comp, testPath)
	require.NoError(t, err)
	requireFormatAndDERBase64(t, comp)

	// Should have Ed25519 algorithm and key references
	require.Equal(t, "crypto/algorithm/ed25519@1.3.101.112", string(comp.CryptoProperties.CertificateProperties.SignatureAlgorithmRef))
	require.Equal(t, "crypto/key/ed25519-256@1.3.101.112", string(comp.CryptoProperties.CertificateProperties.SubjectPublicKeyRef))
}

// Test_Component_ECDSA_Keys tests ECDSA key handling for better coverage
func Test_Component_ECDSA_Keys(t *testing.T) {
	t.Parallel()

	// Test P-256 ECDSA certificate
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "ECDSA P-256 Test Certificate",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		SignatureAlgorithm:    x509.ECDSAWithSHA256,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)
	testPath, err := filepath.Abs("testpath")
	require.NoError(t, err)

	comp, err := cdxprops.CertHitToComponent(t.Context(), model.CertHit{
		Cert:     cert,
		Location: testPath,
		Source:   "TEST",
	})
	require.NoError(t, err)
	require.Equal(t, cdx.ComponentTypeCryptographicAsset, comp.Type)
	err = cdxtest.HasEvidencePath(comp, testPath)
	require.NoError(t, err)
	requireFormatAndDERBase64(t, comp)

	// Should have ECDSA key reference
	require.Contains(t, string(comp.CryptoProperties.CertificateProperties.SubjectPublicKeyRef), "ecdsa")

	// Test P-384 as well
	priv384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(t, err)

	template.SignatureAlgorithm = x509.ECDSAWithSHA384
	certDER384, err := x509.CreateCertificate(rand.Reader, template, template, &priv384.PublicKey, priv384)
	require.NoError(t, err)

	cert384, err := x509.ParseCertificate(certDER384)
	require.NoError(t, err)
	comp384, err := cdxprops.CertHitToComponent(t.Context(), model.CertHit{
		Cert:     cert384,
		Location: testPath,
		Source:   "TEST",
	})
	require.NoError(t, err)

	require.Equal(t, cdx.ComponentTypeCryptographicAsset, comp384.Type)
	err = cdxtest.HasEvidencePath(comp384, testPath)
	require.NoError(t, err)
	requireFormatAndDERBase64(t, comp384)

	// Should have ECDSA P-384 key reference
	require.Contains(t, string(comp384.CryptoProperties.CertificateProperties.SubjectPublicKeyRef), "ecdsa-p384")

	// --- P-521 ---
	priv521, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	require.NoError(t, err)

	template.SignatureAlgorithm = x509.ECDSAWithSHA512
	certDER521, err := x509.CreateCertificate(rand.Reader, template, template, &priv521.PublicKey, priv521)
	require.NoError(t, err)

	cert521, err := x509.ParseCertificate(certDER521)
	require.NoError(t, err)
	comp521, err := cdxprops.CertHitToComponent(t.Context(), model.CertHit{
		Cert:     cert521,
		Location: testPath,
		Source:   "TEST",
	})
	require.NoError(t, err)

	require.Equal(t, cdx.ComponentTypeCryptographicAsset, comp521.Type)
	err = cdxtest.HasEvidencePath(comp521, testPath)
	require.NoError(t, err)
	requireFormatAndDERBase64(t, comp521)

	// Should have ECDSA P-521 key reference
	require.Contains(t, string(comp521.CryptoProperties.CertificateProperties.SubjectPublicKeyRef), "ecdsa-p521")
}

// Test_Component_DSA_Keys tests DSA key handling for better coverage
// Disabled due to DSA cert creation issues with crypto.Signer interface
/*
func Test_Component_DSA_Keys(t *testing.T) {
	t.Parallel()

	// Test DSA certificate to exercise the DSA path in readSubjectPublicKeyRef
	var params dsa.Parameters
	err := dsa.GenerateParameters(&params, rand.Reader, dsa.L1024N160)
	require.NoError(t, err)

	priv := &dsa.PrivateKey{}
	priv.Parameters = params
	err = dsa.GenerateKey(priv, rand.Reader)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "DSA Test Certificate",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		SignatureAlgorithm:    x509.DSAWithSHA1,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, dsaPrivateKey{priv})
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)
	testPath, _ := filepath.Abs("testpath")

	comp, err := cdxprops.CertHitToComponent(t.Context(), model.CertHit{
		Cert:     cert,
		Location: testPath,
		Source:   "TEST",
	})
	require.NoError(t, err)

	require.Equal(t, cdx.ComponentTypeCryptographicAsset, comp.Type)
	err = cdxtest.HasEvidencePath(comp)
	require.NoError(t, err)
	requireFormatAndDERBase64(t, comp)

	// Check DSA signature algorithm reference
	require.Equal(t, "crypto/algorithm/sha-1-dsa@1.2.840.10040.4.3", string(comp.CryptoProperties.CertificateProperties.SignatureAlgorithmRef))
}

// Test_Component_MoreAlgorithms tests additional signature algorithms for coverage
func Test_Component_MoreAlgorithms(t *testing.T) {
	t.Parallel()

	algorithms := []x509.SignatureAlgorithm{
		x509.SHA256WithRSAPSS,
		x509.SHA384WithRSAPSS,
		x509.SHA512WithRSAPSS,
	}

	for _, alg := range algorithms {
		t.Run(alg.String(), func(t *testing.T) {
			// Create RSA key
			priv, err := rsa.GenerateKey(rand.Reader, 2048)
			require.NoError(t, err)

			template := &x509.Certificate{
				SerialNumber: big.NewInt(1),
				Subject: pkix.Name{
					CommonName: "Algorithm Test Certificate",
				},
				NotBefore:             time.Now(),
				NotAfter:              time.Now().Add(365 * 24 * time.Hour),
				KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
				BasicConstraintsValid: true,
				SignatureAlgorithm:    alg,
			}

			certDER, err := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
			require.NoError(t, err)
			cert, err := x509.ParseCertificate(certDER)
			require.NoError(t, err)
			testPath, err := filepath.Abs("testpath")
			require.NoError(t, err)

			comp, err := cdxprops.CertHitToComponent(t.Context(), model.CertHit{
				Cert:     cert,
				Location: testPath,
				Source:   "TEST",
			})
			require.NoError(t, err)

			require.Equal(t, cdx.ComponentTypeCryptographicAsset, comp.Type)
			err = cdxtest.HasEvidencePath(comp, testPath)
			require.NoError(t, err)
			requireFormatAndDERBase64(t, comp)

			// Exercise RSA SubjectPublicKeyRef (should include bit length)
			require.Contains(t, string(comp.CryptoProperties.CertificateProperties.SubjectPublicKeyRef), "rsa-")
		})
	}
}

// Test_Component_UnknownAlgorithm tests handling of unknown signature algorithms
func Test_Component_UnknownAlgorithm(t *testing.T) {
	t.Parallel()

	// Create a normal certificate first - this will exercise the normal paths
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "Algorithm Test Certificate",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		SignatureAlgorithm:    x509.SHA256WithRSA,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)
	testPath, err := filepath.Abs("testpath")
	require.NoError(t, err)

	comp, err := cdxprops.CertHitToComponent(t.Context(), model.CertHit{
		Cert:     cert,
		Location: testPath,
		Source:   "TEST",
	})
	require.NoError(t, err)

	require.Equal(t, cdx.ComponentTypeCryptographicAsset, comp.Type)
	err = cdxtest.HasEvidencePath(comp, testPath)
	require.NoError(t, err)
	requireFormatAndDERBase64(t, comp)

	// Should have proper signature algorithm reference
	require.NotEmpty(t, comp.CryptoProperties.CertificateProperties.SignatureAlgorithmRef)
}

// Test_Component_Ed25519_Keys tests Ed25519 key handling for better coverage
func Test_Component_Ed25519_Keys(t *testing.T) {
	t.Parallel()

	// Test Ed25519 certificate to exercise the Ed25519 path in readSubjectPublicKeyRef
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "Ed25519 Test Certificate",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		SignatureAlgorithm:    x509.PureEd25519,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, priv.Public(), priv)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)
	testPath, err := filepath.Abs("testpath")
	require.NoError(t, err)

	comp, err := cdxprops.CertHitToComponent(t.Context(), model.CertHit{
		Cert:     cert,
		Location: testPath,
		Source:   "TEST",
	})
	require.NoError(t, err)
	require.Equal(t, cdx.ComponentTypeCryptographicAsset, comp.Type)
	err = cdxtest.HasEvidencePath(comp, testPath)
	require.NoError(t, err)
	requireFormatAndDERBase64(t, comp)

	// Check Ed25519 signature algorithm reference
	require.Equal(t, "crypto/algorithm/ed25519@1.3.101.112", string(comp.CryptoProperties.CertificateProperties.SignatureAlgorithmRef))
	// Check Ed25519 key reference
	require.Equal(t, "crypto/key/ed25519-256@1.3.101.112", string(comp.CryptoProperties.CertificateProperties.SubjectPublicKeyRef))
}

// Test_readSignatureAlgorithmRef_DirectCalls tests signature algorithm mapping directly
func Test_readSignatureAlgorithmRef_DirectCalls(t *testing.T) {
	t.Parallel()

	// This test verifies that the signature algorithm field in the parsed certificate
	// gets mapped correctly. Since x509.CreateCertificate will override the SignatureAlgorithm
	// field based on the actual signature used, we need to test this differently.

	// Test with normal certificate creation to exercise the common paths
	cert, err := cdxtest.GenSelfSignedCert()
	require.NoError(t, err)
	testPath, _ := filepath.Abs("testpath")

	comp, err := cdxprops.CertHitToComponent(t.Context(), model.CertHit{
		Cert:     cert.Cert,
		Location: testPath,
		Source:   "TEST",
	})
	require.NoError(t, err)

	// The generated certificate should have some signature algorithm
	require.NotEmpty(t, comp.CryptoProperties.CertificateProperties.SignatureAlgorithmRef)

	// For RSA certificates, it should be one of the RSA algorithms
	sigAlgRef := string(comp.CryptoProperties.CertificateProperties.SignatureAlgorithmRef)
	require.Contains(t, sigAlgRef, "rsa")
}

// --- Minimal ASN.1 structs for crafting PQC OID test certs ---
type tAlgorithmIdentifier struct {
	Algorithm  asn1.ObjectIdentifier
	Parameters asn1.RawValue `asn1:"optional"`
}
type tCertOuter struct {
	TBSCert   asn1.RawValue
	SigAlg    tAlgorithmIdentifier
	Signature asn1.BitString
}
type tSPKI struct {
	Algorithm     tAlgorithmIdentifier
	SubjectPubKey asn1.BitString
}

func parseOID(oidStr string) asn1.ObjectIdentifier {
	parts := strings.Split(oidStr, ".")
	oid := make(asn1.ObjectIdentifier, len(parts))
	for i, p := range parts {
		var v int
		_, err := fmt.Sscanf(p, "%d", &v)
		if err != nil {
			return nil
		}
		oid[i] = v
	}
	return oid
}

func mkCertWithSigOID(oid string) *x509.Certificate {
	outer := tCertOuter{
		TBSCert:   asn1.RawValue{FullBytes: []byte{0x30, 0x00}}, // empty SEQUENCE
		SigAlg:    tAlgorithmIdentifier{Algorithm: parseOID(oid)},
		Signature: asn1.BitString{Bytes: []byte{0x00}},
	}
	raw, _ := asn1.Marshal(outer)
	return &x509.Certificate{Raw: raw}
}

func mkCertWithSPKIOID(oid string) *x509.Certificate {
	spki := tSPKI{
		Algorithm:     tAlgorithmIdentifier{Algorithm: parseOID(oid)},
		SubjectPubKey: asn1.BitString{Bytes: []byte{0x00}},
	}
	rawSPKI, _ := asn1.Marshal(spki)
	return &x509.Certificate{RawSubjectPublicKeyInfo: rawSPKI}
}

func Test_PQC_SignatureAlgorithm_OIDs(t *testing.T) {
	t.Parallel()
	ctx := t.Context()

	// ML-DSA (FIPS 204)
	for oid, want := range map[string]cdx.BOMReference{
		"2.16.840.1.101.3.4.3.17": "crypto/algorithm/ml-dsa-44@2.16.840.1.101.3.4.3.17",
		"2.16.840.1.101.3.4.3.18": "crypto/algorithm/ml-dsa-65@2.16.840.1.101.3.4.3.18",
		"2.16.840.1.101.3.4.3.19": "crypto/algorithm/ml-dsa-87@2.16.840.1.101.3.4.3.19",
	} {
		c := mkCertWithSigOID(oid)
		got := cdxprops.ReadSignatureAlgorithmRef(ctx, c)
		require.Equal(t, want, got)
	}

	// SLH-DSA (FIPS 205)
	for oid, want := range map[string]cdx.BOMReference{
		"2.16.840.1.101.3.4.3.20": "crypto/algorithm/slh-dsa-sha2-128s@2.16.840.1.101.3.4.3.20",
		"2.16.840.1.101.3.4.3.25": "crypto/algorithm/slh-dsa-sha2-256f@2.16.840.1.101.3.4.3.25",
		"2.16.840.1.101.3.4.3.26": "crypto/algorithm/slh-dsa-shake-128s@2.16.840.1.101.3.4.3.26",
		"2.16.840.1.101.3.4.3.31": "crypto/algorithm/slh-dsa-shake-256f@2.16.840.1.101.3.4.3.31",
	} {
		c := mkCertWithSigOID(oid)
		got := cdxprops.ReadSignatureAlgorithmRef(ctx, c)
		require.Equal(t, want, got)
	}

	// XMSS / XMSS-MT / HSS-LMS
	for oid, want := range map[string]cdx.BOMReference{
		"1.3.6.1.5.5.7.6.34":         "crypto/algorithm/xmss-hashsig@1.3.6.1.5.5.7.6.34",
		"1.3.6.1.5.5.7.6.35":         "crypto/algorithm/xmssmt-hashsig@1.3.6.1.5.5.7.6.35",
		"1.2.840.113549.1.9.16.3.17": "crypto/algorithm/hss-lms-hashsig@1.2.840.113549.1.9.16.3.17",
	} {
		c := mkCertWithSigOID(oid)
		got := cdxprops.ReadSignatureAlgorithmRef(ctx, c)
		require.Equal(t, want, got)
	}

	// Unknown and parse-failure paths
	require.Equal(t, cdx.BOMReference("crypto/algorithm/unknown@unknown"), cdxprops.ReadSignatureAlgorithmRef(ctx, mkCertWithSigOID("1.2.3.4.5")))
	require.Equal(t, cdx.BOMReference("crypto/algorithm/unknown@unknown"), cdxprops.ReadSignatureAlgorithmRef(ctx, &x509.Certificate{Raw: []byte{0xff}}))
}

func Test_PQC_SPKI_OIDs(t *testing.T) {
	t.Parallel()
	ctx := t.Context()

	// ML-DSA and ML-KEM
	for oid, want := range map[string]cdx.BOMReference{
		"2.16.840.1.101.3.4.3.17": "crypto/key/ml-dsa-44@2.16.840.1.101.3.4.3.17",
		"2.16.840.1.101.3.4.3.19": "crypto/key/ml-dsa-87@2.16.840.1.101.3.4.3.19",
		"2.16.840.1.101.3.4.4.1":  "crypto/key/ml-kem-512@2.16.840.1.101.3.4.4.1",
		"2.16.840.1.101.3.4.4.3":  "crypto/key/ml-kem-1024@2.16.840.1.101.3.4.4.3",
	} {
		c := mkCertWithSPKIOID(oid)
		got := cdxprops.ReadSubjectPublicKeyRef(ctx, c)
		require.Equal(t, want, got)
	}

	// SLH-DSA, XMSS, XMSS-MT, HSS/LMS, HQC
	for oid, want := range map[string]cdx.BOMReference{
		"2.16.840.1.101.3.4.3.20":    "crypto/key/slh-dsa-sha2-128s@2.16.840.1.101.3.4.3.20",
		"2.16.840.1.101.3.4.3.31":    "crypto/key/slh-dsa-shake-256f@2.16.840.1.101.3.4.3.31",
		"1.3.6.1.5.5.7.6.34":         "crypto/key/xmss@1.3.6.1.5.5.7.6.34",
		"1.3.6.1.5.5.7.6.35":         "crypto/key/xmss-mt@1.3.6.1.5.5.7.6.35",
		"1.2.840.113549.1.9.16.3.17": "crypto/key/hss-lms@1.2.840.113549.1.9.16.3.17",
		"1.3.9999.6.1.1":             "crypto/key/hqc-128@1.3.9999.6.1.1",
	} {
		c := mkCertWithSPKIOID(oid)
		got := cdxprops.ReadSubjectPublicKeyRef(ctx, c)
		require.Equal(t, want, got)
	}

	// Unknown and parse-failure paths
	require.Equal(t, cdx.BOMReference("crypto/key/unknown@unknown"), cdxprops.ReadSubjectPublicKeyRef(ctx, mkCertWithSPKIOID("1.2.3.4.5")))
	require.Equal(t, cdx.BOMReference("crypto/key/unknown@unknown"), cdxprops.ReadSubjectPublicKeyRef(ctx, &x509.Certificate{RawSubjectPublicKeyInfo: []byte{0xff}}))
}

func requireFormatAndDERBase64(t *testing.T, compo cdx.Component) {
	t.Helper()
	err := cdxtest.HasFormatAndDERBase64(compo, czertainly.ComponentCertificateSourceFormat, czertainly.ComponentCertificateBase64Content)
	require.NoError(t, err)
}
*/
