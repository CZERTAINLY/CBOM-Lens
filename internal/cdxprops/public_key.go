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
	switch {
	case cert != nil:
		spki, haveSPKI = certSPKI(cert)
	case pubKey != nil:
		// A standalone `PUBLIC KEY` block has no certificate to hang its
		// SubjectPublicKeyInfo on, and reading the OID only off a certificate
		// is what made the two paths disagree: the same X25519 key published
		// oid "1.3.101.110" inside a certificate and the "0.0.0.0" sentinel on
		// its own. Go parsed this key, so marshalling it back recovers the
		// same structure certSPKI decodes -- the algorithm identifier is
		// exactly what x509.MarshalPKIXPublicKey writes from the key's type.
		//
		// The error is dropped deliberately. It is returned for the key types
		// Go cannot marshal -- *dsa.PublicKey above all -- and those have a
		// real name from the enum already, so they never reach the placeholder
		// this fallback exists to replace. Nothing is lost by leaving haveSPKI
		// false for them, and hashPublicKey below reports the same failure
		// where a caller can act on it.
		if der, err := x509.MarshalPKIXPublicKey(pubKey); err == nil {
			spki, haveSPKI = spkiFromRaw(der)
		}
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
			// The registry cannot NAME this algorithm, but the certificate
			// still states which one it is, and the placeholder threw that
			// away: extractAlgorithmInfo's Unknown branch leaves oid at
			// oidPlaceholder, the literal "0.0.0.0", which the constant's own
			// comment calls not an OID. An X25519 certificate -- 1.3.101.110,
			// outside the registry because the registry is post-quantum --
			// published `"oid": "0.0.0.0"` on both the key and the algorithm,
			// and the arc that would have identified it was written to a log
			// line and dropped. A consumer cannot tell that component from any
			// other unnameable key, and "0.0.0.0" is a claim no registry
			// resolves.
			//
			// The primitive goes for the same reason, one step further: the
			// Unknown placeholder's is "signature", so a key-agreement
			// algorithm was published as something that signs -- a false
			// claim, not merely a missing one, and one an inventory counting
			// signature schemes for a migration would count. Both schemas
			// carry "unknown" in the primitive enum for exactly this case.
			//
			// csrToCDX refuses to publish this placeholder at all (#217), and
			// a certificate reaching the same placeholder by the same route
			// must not be more credulous than a request. It publishes more
			// than the request can because it has more: the request's
			// suppression fires when nothing names the algorithm AND there is
			// no asset worth emitting, whereas here the certificate is a real
			// asset whose subjectPublicKeyRef must resolve.
			info.oid = oidFallback
			info.primitive = cdx.CryptoPrimitiveUnknown
			slog.WarnContext(ctx, "can't find public key components", "oid", oidFallback)
		}
	}

	// The primitive comes from the algorithm and from nothing else. This block
	// used to read cert.KeyUsage and, for any info whose name contained "RSA",
	// stamp "signature" when the certificate signed without enciphering and
	// "pke" otherwise -- and it did so BEFORE BOMRefHash below digested the
	// component. A bom-ref is a hash of the component's own contents, so one
	// RSA-2048 key was crypto/algorithm/rsa-2048@<digest A> when found in a
	// signing certificate and @<digest B> when found in a CSR, a bare PUBLIC KEY
	// block or an encipherment certificate; Builder dedups by ref and keeps the
	// first, so which of the two the delivered document carried was decided by
	// the order the scanners happened to report in.
	//
	// A cryptographic primitive is a property of the algorithm. Both schemas
	// describe the enum with RSA as their own example of pke and ECDSA as their
	// example of signature, and the specification's 1.7 certificate conformance
	// fixture models a TLS leaf exactly this way: rsaEncryption asset with
	// primitive pke, SHA512withRSA asset with primitive signature, two OIDs and
	// two assets. This package already emits that second asset -- every RSA
	// certificate here also produces crypto/algorithm/sha-256-rsa -- so "this
	// key signs" was never lost by removing it from here; it was duplicated onto
	// the wrong asset, and that duplicate is what made the asset's identity
	// depend on where it was found.
	//
	// What the certificate does declare about its key now travels with the
	// certificate: certComponent publishes the keyUsage extension as a key_usage
	// property, on a component whose ref is a digest of cert.Raw, which the
	// extension is part of.
	//
	// The strings.Contains(info.name, "RSA") test that gated all of this was a
	// substring match against a name that can come from the PQC registry. No
	// entry contains "RSA" today, but a composite like MLDSA44-RSA2048-PSS-SHA256
	// would have had its primitive hijacked by a certificate's KeyUsage.
	algo = info.componentWOBomRef(c.ilm)
	setAlgorithmPrimitive(&algo, algorithmPrimitive(info))
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
