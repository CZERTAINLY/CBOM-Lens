package pem

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log/slog"

	"github.com/CZERTAINLY/CBOM-lens/internal/model"
	czx509 "github.com/CZERTAINLY/CBOM-lens/internal/scanner/x509"

	"golang.org/x/crypto/ssh"
)

// Scanner handles PEM block detection for all possible data
type Scanner struct{}

// Scan parses all PEM blocks and returns a comprehensive bundle containing certificates, keys, and other cryptographic materials
func (d Scanner) Scan(ctx context.Context, b []byte, path string) (model.PEMBundle, error) {
	slog.DebugContext(ctx, "Detecting ALL PEM blocks anywhere in the blob (handles leading text)")

	hits := func(certs []*x509.Certificate, source string) []model.CertHit {
		ret := make([]model.CertHit, len(certs))
		for idx, c := range certs {
			ret[idx] = model.CertHit{
				Cert:     c,
				Source:   source,
				Location: path,
			}
		}
		return ret
	}

	bundle := model.PEMBundle{
		ParseErrors: make(map[int]error),
	}

	order := 0
	rest := b

	for {
		block, r := pem.Decode(rest)
		if block == nil {
			break
		}

		rawBlock := model.PEMBlock{
			Type:    block.Type,
			Headers: block.Headers,
			Bytes:   block.Bytes,
			Order:   order,
		}
		bundle.RawBlocks = append(bundle.RawBlocks, rawBlock)

		switch block.Type {
		/*********** CERTIFICATES ***********/
		case "CERTIFICATE", "TRUSTED CERTIFICATE":
			if cs, err := x509.ParseCertificates(block.Bytes); err != nil {
				bundle.ParseErrors[order] =
					fmt.Errorf("failed to parse certificate at position %d: %w", order, err)
			} else {
				bundle.Certificates = append(bundle.Certificates, hits(cs, "PEM")...)
			}
		case "PKCS7", "CMS":
			if cs := czx509.ParsePKCS7Safe(ctx, block.Bytes, true /*permissive for PEM*/); len(cs) > 0 {
				bundle.Certificates = append(bundle.Certificates, hits(cs, "PKCS7-PEM")...)
			}
		case "PKCS12":
			if cs := czx509.ParsePKCS12(ctx, block.Bytes); len(cs) > 0 {
				bundle.Certificates = append(bundle.Certificates, hits(cs, "PKCS12-PEM")...)
			}

		/*********** PRIVATE KEYS ***********/
		case "PRIVATE KEY":
			// PKCS#8 format - can be RSA, ECDSA, Ed25519
			if key, err := x509.ParsePKCS8PrivateKey(block.Bytes); err != nil {
				bundle.ParseErrors[order] =
					fmt.Errorf("failed to parse PKCS#8 private key at position %d: %w", order, err)
			} else {
				pki := model.PrivateKeyInfo{
					Key:        key,
					Type:       keyType(key),
					Source:     "PKCS8-PEM",
					BlockIndex: len(bundle.RawBlocks) - 1,
				}
				bundle.PrivateKeys = append(bundle.PrivateKeys, pki)
			}

		case "RSA PRIVATE KEY":
			// PKCS#1 RSA format
			if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err != nil {
				bundle.ParseErrors[order] =
					fmt.Errorf("failed to parse RSA private key at position %d: %w", order, err)
			} else {
				pki := model.PrivateKeyInfo{
					Key:        key,
					Type:       keyType(key),
					Source:     "PKCS1-PEM",
					BlockIndex: len(bundle.RawBlocks) - 1,
				}
				bundle.PrivateKeys = append(bundle.PrivateKeys, pki)
			}

		case "EC PRIVATE KEY":
			// SEC 1 EC format
			if key, err := x509.ParseECPrivateKey(block.Bytes); err != nil {
				bundle.ParseErrors[order] =
					fmt.Errorf("failed to parse EC private key at position %d: %w", order, err)
			} else {
				pki := model.PrivateKeyInfo{
					Key:        key,
					Type:       keyType(key),
					Source:     "EC-PEM",
					BlockIndex: len(bundle.RawBlocks) - 1,
				}
				bundle.PrivateKeys = append(bundle.PrivateKeys, pki)
			}

		case "CERTIFICATE REQUEST", "NEW CERTIFICATE REQUEST":
			if csr, err := x509.ParseCertificateRequest(block.Bytes); err != nil {
				bundle.ParseErrors[order] =
					fmt.Errorf("failed to parse certificate request at position %d: %w", order, err)
			} else {
				bundle.CertificateRequests = append(bundle.CertificateRequests, csr)
			}

		case "PUBLIC KEY":
			if pubKey, err := x509.ParsePKIXPublicKey(block.Bytes); err != nil {
				bundle.ParseErrors[order] =
					fmt.Errorf("failed to parse public key at position %d: %w", order, err)
			} else {
				bundle.PublicKeys = append(bundle.PublicKeys, pubKey)
			}

		case "RSA PUBLIC KEY":
			if pubKey, err := x509.ParsePKCS1PublicKey(block.Bytes); err != nil {
				bundle.ParseErrors[order] =
					fmt.Errorf("failed to parse RSA public key at position %d: %w", order, err)
			} else {
				bundle.PublicKeys = append(bundle.PublicKeys, pubKey)
			}

		case "X509 CRL":
			if crl, err := x509.ParseRevocationList(block.Bytes); err != nil {
				bundle.ParseErrors[order] =
					fmt.Errorf("failed to parse CRL at position %d: %w", order, err)
			} else {
				bundle.CRLs = append(bundle.CRLs, crl)
			}

		case "OPENSSH PRIVATE KEY":
			if key, err := ssh.ParseRawPrivateKey(pem.EncodeToMemory(block)); err != nil {
				bundle.ParseErrors[order] =
					fmt.Errorf("failed to parse OpenSSH private key at position %d: %w", order, err)
			} else {
				// x/crypto/ssh returns a pointer for ed25519 keys; we normalize it to a value type for consistency.
				if keyp, ok := key.(*ed25519.PrivateKey); ok {
					key = *keyp
				}
				pki := model.PrivateKeyInfo{
					Key:        key,
					Type:       keyType(key),
					Source:     "PEM",
					BlockIndex: len(bundle.RawBlocks) - 1,
				}
				bundle.PrivateKeys = append(bundle.PrivateKeys, pki)
			}

		default:
			// Unknown block type - already stored in RawBlocks
			bundle.ParseErrors[order] =
				fmt.Errorf("unknown PEM block type at position %d: %s", order, block.Type)
		}

		rest = r
		order++
	}

	if order == 0 {
		return bundle, model.ErrNoMatch
	}

	bundle.Location = path
	if len(bundle.ParseErrors) == 0 {
		bundle.ParseErrors = nil
	}
	slog.DebugContext(
		ctx,
		"Result of PEM detection",
		"certificates", len(bundle.Certificates),
		"privateKeys", len(bundle.PrivateKeys),
		"certificateRequests", len(bundle.CertificateRequests),
		"publicKeys", len(bundle.PublicKeys),
		"crls", len(bundle.CRLs),
		"rawBlocks", len(bundle.RawBlocks),
		"parseErrors", len(bundle.ParseErrors),
		"location", bundle.Location,
	)
	return bundle, nil
}

func keyType(key crypto.PrivateKey) string {
	switch key.(type) {
	case *rsa.PrivateKey:
		return "RSA"
	case *ecdsa.PrivateKey:
		return "ECDSA"
	case ed25519.PrivateKey:
		return "Ed25519"
	default:
		return fmt.Sprintf("Unknown (%T)", key)
	}
}
