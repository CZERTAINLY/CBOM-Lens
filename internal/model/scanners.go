package model

import (
	"crypto"
	"crypto/x509"

	"github.com/zricethezav/gitleaks/v8/report"
)

// Leak are data returned by gitleaks module
type Leaks struct {
	Location string
	Findings []report.Finding
}

// CertHit is a detected x509 certificate
type CertHit struct {
	Cert     *x509.Certificate
	Source   string // e.g., "PEM", "DER", "PKCS7-PEM", "PKCS7-DER", "PKCS12", "JKS", "JCEKS", "ZIP/<subsource>", "NMAP"
	Location string // path or port or image name or any similar identifier
}

// PEMBundle represents all data that can be extracted from a PEM file
type PEMBundle struct {
	// Certificates in order of appearance (leaf cert typically first, then intermediates, then root)
	Certificates []CertHit

	// Private keys found in the file (RSA, ECDSA, Ed25519, etc.)
	PrivateKeys []PrivateKeyInfo

	// Certificate requests
	CertificateRequests []*x509.CertificateRequest

	// Public keys (if present without corresponding certificates)
	PublicKeys []crypto.PublicKey

	// CRLs (Certificate Revocation Lists)
	CRLs []*x509.RevocationList

	// RawBlocks contains PEM blocks that couldn't be parsed into strongly-typed structures
	// or blocks with unrecognized types. The slice preserves the original order and encoding
	// from the source data, enabling round-trip serialization.
	RawBlocks []PEMBlock

	// ParseErrors maps indices in RawBlocks to their corresponding parse errors.
	// These are non-fatal errors encountered during parsing, such as unsupported
	// cryptographic algorithms or malformed key data. A block at RawBlocks[i] will
	// have its error (if any) stored at ParseErrors[i].
	ParseErrors map[int]error

	Location string
}

// PEMBlock represents a single PEM block with metadata
type PEMBlock struct {
	Type    string            // e.g., "CERTIFICATE", "PRIVATE KEY", "RSA PRIVATE KEY"
	Headers map[string]string // PEM headers (rarely used but possible)
	Bytes   []byte            // DER-encoded data
	Order   int               // Position in original file (0-based)
}

// PrivateKeyInfo wraps a private key with its type information
type PrivateKeyInfo struct {
	Key        crypto.PrivateKey // Actual key (*rsa.PrivateKey, *ecdsa.PrivateKey, ed25519.PrivateKey)
	Source     string            // "PEM"
	BlockIndex int               // index of a PemBlock.RawBlocks with a related PEM block data
}
