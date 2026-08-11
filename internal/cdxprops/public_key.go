package cdxprops

import (
	"context"
	"crypto"
	"crypto/dsa" //nolint:staticcheck
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"log/slog"
	"strings"

	cdx "github.com/CycloneDX/cyclonedx-go"
)

// publicKeyAlgComponent creates a CycloneDX component for a public key algorithm
func (c Converter) publicKeyComponents(ctx context.Context, pubKeyAlg x509.PublicKeyAlgorithm, pubKey crypto.PublicKey, cert *x509.Certificate) (algo, key cdx.Component) {
	info := publicKeyAlgorithmInfo(pubKeyAlg, pubKey)

	// One decode of the certificate's subjectPublicKeyInfo, read in two places
	// below: the OID names the algorithm when Go's enum could not, and the BIT
	// STRING is the body the key claim rests on. Decoding it separately at each
	// of those two points is how a rule enforced at one of them comes to be
	// absent at the other.
	var spki pkixStruct
	var haveSPKI bool
	if cert != nil {
		spki, haveSPKI = certSPKI(cert)
	}

	if info.oid == oidPlaceholder && haveSPKI {
		oidFallback := spki.Algorithm.Algorithm.String()
		// Only overwrite info on a hit. The previous two-value assignment
		// replaced it with the zero algorithmInfo on a miss, so both returned
		// components got an empty Name and Builder.appendDetection dropped
		// them, leaving the certificate's subjectPublicKeyRef dangling.
		if fallback, ok := unsupportedAlgorithms[oidFallback]; ok {
			info = fallback
		} else if oidFallback != "" {
			slog.WarnContext(ctx, "can't find public key components", "oid", oidFallback)
		}
	}

	var primitive = cdx.CryptoPrimitiveSignature
	if info.primitive != "" {
		// A registry entry knows its own primitive. This is the only way an
		// ML-KEM key gets reported as a "kem" rather than a signature scheme:
		// no KeyUsage inspection can derive that.
		primitive = info.primitive
	}

	var keyUsage x509.KeyUsage
	if cert != nil {
		keyUsage = cert.KeyUsage
	}

	if strings.Contains(info.name, "RSA") {
		if keyUsage != 0 &&
			(keyUsage&x509.KeyUsageDigitalSignature+
				keyUsage&x509.KeyUsageCRLSign+
				keyUsage&x509.KeyUsageCertSign > 0) &&
			(keyUsage&x509.KeyUsageKeyEncipherment == 0) {
			primitive = cdx.CryptoPrimitiveSignature
		} else {
			primitive = cdx.CryptoPrimitivePKE
		}
	}

	algo = info.componentWOBomRef(c.ilm)
	setAlgorithmPrimitive(&algo, primitive)
	if primitive == cdx.CryptoPrimitivePKE {
		addAlgorithmCrpyoFunctions(&algo, cdx.CryptoFunctionSign)
	}
	c.BOMRefHash(&algo, info.algorithmName)

	pubKeyValue, pubKeyHash, err := c.hashPublicKey(pubKey)
	if err != nil && cert != nil {
		// Go does not parse post-quantum keys, so cert.PublicKey is nil for
		// ML-DSA/ML-KEM/SLH-DSA and marshalling fails. The DER is still on the
		// certificate, and hashing that is what keeps each key distinct — the
		// same fallback unsupportedPKIX already uses.
		slog.DebugContext(ctx, "public key is not marshallable; hashing the certificate's SPKI instead",
			"algorithm", info.name, "error", err.Error())

		// Hashing that DER is also ASSERTING it. Everything below says a public
		// key of info's algorithm exists here, and on this branch the only
		// evidence for that is the SPKI's own body -- Go did not parse the key,
		// so nothing has looked at those bytes. x509.ParseCertificate reads the
		// subjectPublicKey BIT STRING, finds an algorithm OID its enum does not
		// name, leaves PublicKey nil and returns successfully; it never
		// interprets the body. So the four bytes of garbage unsupportedPKIX
		// refuses under a `PUBLIC KEY` block arrive here intact under a
		// `CERTIFICATE` block, and a certificate must not buy the key claim more
		// cheaply than a bare key does. Same registry sizes, same function,
		// deliberately not a second copy of the rule.
		if !haveSPKI {
			slog.WarnContext(ctx, "not reporting a public key: the certificate's subjectPublicKeyInfo could not be decoded",
				"algorithm", info.name,
				"oid", info.oid)
			return algo, cdx.Component{}
		}
		if reason := rejectPublicKeyBody(info, spki.PublicKey); reason != "" {
			slog.WarnContext(ctx, "not reporting a public key: the certificate's SPKI body is not this algorithm's public key",
				"algorithm", info.name,
				"oid", info.oid,
				"body_bytes", len(spki.PublicKey.Bytes),
				"reason", reason)
			return algo, cdx.Component{}
		}

		pubKeyValue, pubKeyHash = c.hashRawPublicKey(cert.RawSubjectPublicKeyInfo)
	} else if err != nil {
		// No certificate to fall back on: a digest-less bom-ref would merge
		// this key with every other key of the same algorithm.
		slog.WarnContext(ctx, "cannot identify public key: omitting key component",
			"algorithm", info.name, "error", err.Error())
		return algo, cdx.Component{}
	}
	// public key properties
	var bomRef = fmt.Sprintf(
		"crypto/key/%s@%s",
		strings.ToLower(info.name),
		pubKeyHash,
	)

	relatedProps := &cdx.RelatedCryptoMaterialProperties{
		Type:         cdx.RelatedCryptoMaterialTypePublicKey,
		AlgorithmRef: cdx.BOMReference(algo.BOMRef),
		Value:        pubKeyValue,
	}

	if info.keySize > 0 {
		relatedProps.Size = &info.keySize
	}

	key = cdx.Component{
		Type:   cdx.ComponentTypeCryptographicAsset,
		Name:   info.name,
		BOMRef: bomRef,
		CryptoProperties: &cdx.CryptoProperties{
			AssetType:                       cdx.CryptoAssetTypeRelatedCryptoMaterial,
			OID:                             info.oid,
			RelatedCryptoMaterialProperties: relatedProps,
		},
	}
	return
}

// hashPublicKey encodes and hashes a parsed public key. It reports an error
// when the key cannot be marshalled, which callers must handle: returning empty
// strings silently produced the bom-ref "crypto/key/<alg>@" with no digest, and
// because Builder keys components by bom-ref every such key collapsed into one
// component. See hashRawPublicKey for the fallback.
func (c Converter) hashPublicKey(pubKey crypto.PublicKey) (value, hash string, err error) {
	// Marshal to PKIX/SPKI format (standard DER encoding)
	pubKeyBytes, err := x509.MarshalPKIXPublicKey(pubKey)
	if err != nil {
		return "", "", err
	}

	value = base64.StdEncoding.EncodeToString(pubKeyBytes)
	hash = c.bomRefHasher(pubKeyBytes)
	return value, hash, nil
}

func publicKeyAlgorithmInfo(pubKeyAlg x509.PublicKeyAlgorithm, pubKey crypto.PublicKey) algorithmInfo {
	var keyType string
	var key any

	switch pubKeyAlg {
	case x509.RSA:
		keyType = "RSA"
		if rsaKey, ok := pubKey.(*rsa.PublicKey); ok {
			key = rsaKeyAdapter{rsaKey}
		}
	case x509.ECDSA:
		keyType = "ECDSA"
		if ecKey, ok := pubKey.(*ecdsa.PublicKey); ok {
			key = ecKeyAdapter{ecKey}
		}
	case x509.Ed25519:
		keyType = "Ed25519"
	case x509.DSA:
		keyType = "DSA"
		if dsaKey, ok := pubKey.(*dsa.PublicKey); ok {
			key = dsaKeyAdapter{dsaKey}
		}
	default:
		keyType = "Unknown"
	}

	return extractAlgorithmInfo(keyType, key)
}

func getPublicKeyAlgorithm(pubKey crypto.PublicKey) x509.PublicKeyAlgorithm {
	switch pubKey.(type) {
	case *rsa.PublicKey:
		return x509.RSA
	case *ecdsa.PublicKey:
		return x509.ECDSA
	case ed25519.PublicKey:
		return x509.Ed25519
	case *dsa.PublicKey:
		return x509.DSA
	default:
		return x509.UnknownPublicKeyAlgorithm
	}
}
