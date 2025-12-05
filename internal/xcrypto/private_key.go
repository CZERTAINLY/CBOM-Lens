package xcrypto

import (
	"crypto"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding"
	"encoding/asn1"
	"errors"
	"fmt"

	"github.com/cloudflare/circl/sign/mldsa/mldsa44"
	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
	"github.com/cloudflare/circl/sign/mldsa/mldsa87"
)

// PKCS#8 structure for extracting raw key bytes
type pkcs8Info struct {
	Version    int
	Algo       pkix.AlgorithmIdentifier
	PrivateKey []byte
}

type privateKeyInfo struct {
	Seed       []byte
	PrivateKey []byte
}

// ParsePKCS8PrivateKey parses a PKCS#8-encoded private key.
//
// This function first attempts to parse the private key using the standard
// x509.ParsePKCS8PrivateKey function. If that fails, it falls back to a
// custom unmarshalPKCS8 function to handle non-standard or Post-Quantum
// Cryptography (PQC) algorithms, such as ML-DSA-65.
//
// If both parsing attempts fail, it returns a combined error containing
// details from both attempts.
//
// Parameters:
// - b: The PKCS#8-encoded private key as a byte slice.
//
// Returns:
// - crypto.PrivateKey: The parsed private key if successful.
// - error: An error if parsing fails.
func ParsePKCS8PrivateKey(b []byte) (crypto.PrivateKey, error) {
	key, err := x509.ParsePKCS8PrivateKey(b)
	if err != nil {
		key, fbErr := unmarshalPKCS8(b)
		if fbErr != nil {
			return nil, fmt.Errorf("parsing PKCS#8: %w", errors.Join(err, fbErr))
		}
		return key, nil
	}
	return key, nil
}

func unmarshalPKCS8(b []byte) (crypto.PrivateKey, error) {
	var pkcs8 pkcs8Info
	_, err := asn1.Unmarshal(b, &pkcs8)
	if err != nil {
		return nil, fmt.Errorf("PKCS#8 asn.1 unmarshal: %w", err)
	}

	switch pkcs8.Algo.Algorithm.String() {
	case MLDSA44.String():
		return parsePrivateKey[mldsa44.PrivateKey](pkcs8)
	case MLDSA65.String():
		return parsePrivateKey[mldsa65.PrivateKey](pkcs8)
	case MLDSA87.String():
		return parsePrivateKey[mldsa87.PrivateKey](pkcs8)
	}
	return nil, fmt.Errorf("unsupported algorithm %s", pkcs8.Algo.Algorithm.String())
}

func parsePrivateKey[T any, PT interface {
	*T
	encoding.BinaryUnmarshaler
}](pkcs8 pkcs8Info) (crypto.PrivateKey, error) {
	var pki privateKeyInfo
	_, err := asn1.Unmarshal(pkcs8.PrivateKey, &pki)
	if err != nil {
		return nil, fmt.Errorf("asn.1 unmarshal of private key: %w", err)
	}

	var x T
	privKey := PT(&x)
	err = privKey.UnmarshalBinary(pki.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("parsing private key: %w", err)
	}
	return privKey, nil
}
