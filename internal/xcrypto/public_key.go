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

const (
	MLDSA44Algo x509.PublicKeyAlgorithm = -1
	MLDSA65Algo x509.PublicKeyAlgorithm = -2
	MLDSA87Algo x509.PublicKeyAlgorithm = -3
)

type publicKeyInfo struct {
	Algorithm pkix.AlgorithmIdentifier
	PublicKey asn1.BitString
}

// ParsePKIXPublicKey() parses a PKIX-encoded public key.
//
// This function first attempts to parse the private key using the standard
// x509.ParsePKIXPublicKey function. If that fails, it falls back to a
// custom unmarshalPKIX function to handle non-standard or Post-Quantum
// Cryptography (PQC) algorithms, such as ML-DSA-65.
//
// If both parsing attempts fail, it returns a combined error containing
// details from both attempts.
//
// Parameters:
// - b: The PKIX-encoded private key as a byte slice.
//
// Returns:
// - crypto.PublicKey: The parsed private key if successful.
// - error: An error if parsing fails.
func ParsePKIXPublicKey(b []byte) (crypto.PublicKey, error) {
	key, err := x509.ParsePKIXPublicKey(b)
	if err != nil {
		key, fbErr := unmarshalPKIX(b)
		if fbErr != nil {
			return nil, fmt.Errorf("parsing PKIX: %w", errors.Join(err, fbErr))
		}
		return key, nil
	}
	return key, nil
}

func unmarshalPKIX(b []byte) (crypto.PublicKey, error) {
	var pkix publicKeyInfo
	_, err := asn1.Unmarshal(b, &pkix)
	if err != nil {
		return nil, fmt.Errorf("PKIX asn.1 unmarshal: %w", err)
	}

	pk := pkix.PublicKey.Bytes
	switch pkix.Algorithm.Algorithm.String() {
	case MLDSA44.String():
		return parsePublicKey[mldsa44.PublicKey](pk)
	case MLDSA65.String():
		return parsePublicKey[mldsa65.PublicKey](pk)
	case MLDSA87.String():
		return parsePublicKey[mldsa87.PublicKey](pk)
	}
	return nil, fmt.Errorf("unsupported algorithm %s", pkix.Algorithm.Algorithm.String())
}

// MarshalPKIXPublicKey marshals public key in a DER format.
//
// This function first attempts to marshal the public key using the standard
// x509.MarshalPKIXPublicKey function. If that fails, it falls back to a
// custom marshalPKIXPublicKey function to handle non-standard or Post-Quantum
// Cryptography (PQC) algorithms, such as ML-DSA-65.
//
// If both marshaling attempts fail, it returns a combined error containing
// details from both attempts.
//
// Parameters:
// - b: The crypto.Public key (including PQC types from circl)
//
// Returns:
// - public key in DER encoded format
// - error: An error if marshaling fails.
func MarshalPKIXPublicKey(pubKey crypto.PublicKey) ([]byte, error) {
	derBytes, err := x509.MarshalPKIXPublicKey(pubKey)
	if err != nil {
		derBytes, fbErr := marshalPKIXPublicKey(pubKey)
		if fbErr != nil {
			return nil, fmt.Errorf("marshalling PKIX public key: %w", errors.Join(err, fbErr))
		}
		return derBytes, nil
	}
	return derBytes, nil
}

func marshalPKIXPublicKey(pubKey crypto.PublicKey) ([]byte, error) {
	var oid asn1.ObjectIdentifier
	var b []byte
	switch k := pubKey.(type) {
	case *mldsa44.PublicKey:
		oid = MLDSA44
		b = k.Bytes()
	case *mldsa65.PublicKey:
		oid = MLDSA65
		b = k.Bytes()
	case *mldsa87.PublicKey:
		oid = MLDSA65
		b = k.Bytes()
	default:
		return nil, fmt.Errorf("unsupported public key: %T", pubKey)
	}
	pubKeyInfo := publicKeyInfo{
		Algorithm: pkix.AlgorithmIdentifier{
			Algorithm: oid,
		},
		PublicKey: asn1.BitString{
			Bytes:     b,
			BitLength: len(b) * 8,
		},
	}
	return asn1.Marshal(pubKeyInfo)
}

func parsePublicKey[T any, PT interface {
	*T
	encoding.BinaryUnmarshaler
}](b []byte) (crypto.PublicKey, error) {
	var x T
	pubKey := PT(&x)
	err := pubKey.UnmarshalBinary(b)
	if err != nil {
		return nil, fmt.Errorf("parsing public key: %w", err)
	}
	return pubKey, nil
}
