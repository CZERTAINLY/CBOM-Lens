package cdxtest

import (
	"crypto/x509"
	"embed"
	"encoding/base64"
	"fmt"

	cdx "github.com/CycloneDX/cyclonedx-go"
)

//go:embed testdata/*
var data embed.FS

const MLDSA65PrivateKey = "testdata/ml-dsa-65-private-key.pem"
const MLDSA65PublicKey = "testdata/ml-dsa-65-public-key.pem"
const MLDSA65Certificate = "testdata/ml-dsa-65-cert.pem"

// MLDSA65MalformedPrivateKey is a valid PEM envelope wrapping truncated DER.
// It exercises the analyzeParseError negative path: the PEM scanner accepts
// the block, then ASN.1 parsing of the PKCS#8 structure fails.
const MLDSA65MalformedPrivateKey = "testdata/ml-dsa-65-malformed-private-key.pem"

// MLDSA65SeedOnlyPrivateKey and MLKEM768SeedOnlyPrivateKey are real keys stored
// in the seed form. RFC 9881 sec. 6 makes the ML-DSA privateKey field a CHOICE
// of seed [0] (32 bytes), expandedKey, or both, and calls the seed the
// RECOMMENDED form; ML-KEM has the same shape with a 64-byte (d, z) seed.
//
// Every other post-quantum fixture here is OpenSSL's default "both" encoding,
// so the expanded and seed lengths differ by two orders of magnitude and a
// size check calibrated on the expanded form rejects these while passing all
// the others. Generated with
// `openssl genpkey -algorithm ML-DSA-65 -provparam ml-dsa.output_formats=seed-only`
// on OpenSSL 3.5.3; Node.js exports this form by default.
const MLDSA65SeedOnlyPrivateKey = "testdata/ml-dsa-65-seed-only-private-key.pem"

// MLKEM768SeedOnlyPrivateKey is the ML-KEM counterpart of
// MLDSA65SeedOnlyPrivateKey.
const MLKEM768SeedOnlyPrivateKey = "testdata/ml-kem-768-seed-only-private-key.pem"

// SLH-DSA-SHA2-128s: the smallest SLH-DSA parameter set, and the one RFC 9909
// App. C uses for its own examples.
const SLHDSASHA2128sPrivateKey = "testdata/slh-dsa-sha2-128s-private-key.pem"
const SLHDSASHA2128sPublicKey = "testdata/slh-dsa-sha2-128s-public-key.pem"
const SLHDSASHA2128sCertificate = "testdata/slh-dsa-sha2-128s-cert.pem"

// ML-KEM-768, the parameter set FIPS 203 recommends as the default. The
// certificate's subjectPublicKeyInfo is ML-KEM-768 but it is signed with
// ML-DSA-65, because a KEM cannot sign anything, including itself.
const MLKEM768PrivateKey = "testdata/ml-kem-768-private-key.pem"
const MLKEM768PublicKey = "testdata/ml-kem-768-public-key.pem"
const MLKEM768Certificate = "testdata/ml-kem-768-cert.pem"

// DSA2048PublicKey is a standalone DSA public key. Go parses it via
// x509.ParsePKIXPublicKey but x509.MarshalPKIXPublicKey refuses *dsa.PublicKey,
// which is the asymmetry that crashed restOfPEMBundleToCDX.
const DSA2048PublicKey = "testdata/dsa-2048-public-key.pem"

// can be validated via openssl
// openssl pkey -pubin -in internal/cdxprops/cdxtest/testdata/ml-dsa-65-public-key.pem -outform DER | openssl dgst -sha256
const MLDSA65PublicKeyHash = "sha256:bbf687535068e46b92b1a13fddb94cf59149624484986b8435bda6e1ee1536a3"

func TestData(path string) ([]byte, error) {
	return data.ReadFile(path)
}

// getProp gets a property value from a CDX component
func GetProp(comp cdx.Component, name string) string {
	if comp.Properties == nil {
		return ""
	}
	for _, p := range *comp.Properties {
		if p.Name == name {
			return p.Value
		}
	}
	return ""
}

// HasEvidencePath checks that the component has the expected evidence path
func HasEvidencePath(comp cdx.Component, location string) error {
	if comp.Evidence == nil {
		return fmt.Errorf("evidence is nil")
	}
	if comp.Evidence.Occurrences == nil {
		return fmt.Errorf("evidence occurrences is nil")
	}
	if len(*comp.Evidence.Occurrences) < 1 {
		return fmt.Errorf("evidence occurrences is empty")
	}

	loc := (*comp.Evidence.Occurrences)[0].Location
	if loc == "" {
		return fmt.Errorf("location is empty")
	}

	if loc != location {
		return fmt.Errorf("unexpected location: got %s, expected: %s", loc, location)
	}

	return nil
}

func HasFormatAndDERBase64(comp cdx.Component, formatKey, base64Key string) error {
	format := GetProp(comp, formatKey)
	if format == "" {
		return fmt.Errorf("certificate format property is empty")
	}

	b64 := GetProp(comp, base64Key)
	if b64 == "" {
		return fmt.Errorf("certificate base64 content property is empty")
	}

	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return fmt.Errorf("failed to decode base64 content: %w", err)
	}

	_, err = x509.ParseCertificate(raw)
	if err != nil {
		return fmt.Errorf("failed to parse certificate: %w", err)
	}

	return nil
}
