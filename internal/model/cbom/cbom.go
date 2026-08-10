package cbom

import cdx "github.com/CycloneDX/cyclonedx-go"

// AssetRef is the canonical, wire-ready identity of an Asset. Emitters stamp
// it onto the emitted component's bom-ref, so it is the single source of
// truth for cross-references.
type AssetRef string

// KeyMeta carries key material metadata the Builder needs back out of a
// component in a version-neutral form. At most one of Bits or Curve should be
// set: Bits for sized keys (RSA/DSA modulus bits), Curve for named-curve keys.
// The zero value (Bits == 0 and Curve == "") means unknown.
type KeyMeta struct {
	Bits  int    // e.g. 2048 for RSA
	Curve string // e.g. "secp256r1" for EC
}

// Asset is one crypto asset. Component carries the full payload; it must not
// have version-specific relationship fields set (SignatureAlgorithmRef,
// SubjectPublicKeyRef, AlgorithmRef, CryptoRefArray) once converters emit
// Rels instead — emitters own all wire-version mapping.
type Asset struct {
	Ref       AssetRef
	Component cdx.Component
	Key       *KeyMeta
}

type RelationshipKind string

const (
	RelSignatureAlgorithm RelationshipKind = "signature-algorithm"
	RelSubjectPublicKey   RelationshipKind = "subject-public-key"
	RelMaterialAlgorithm  RelationshipKind = "material-algorithm"
	RelProtocolCrypto     RelationshipKind = "protocol-crypto"
	RelDependsOn          RelationshipKind = "depends-on"
)

type Relationship struct {
	From AssetRef
	To   AssetRef
	Kind RelationshipKind
}

// DetectionType duplicates internal/model.DetectionType (same wire strings)
// until the converter migration removes the old copy; keep the two in sync.
type DetectionType string

const (
	DetectionTypeUNKNOWN      DetectionType = "UNKNOWN"
	DetectionTypeLeakJWT      DetectionType = "JWT"
	DetectionTypeLeakTOKEN    DetectionType = "TOKEN"
	DetectionTypeLeakKEY      DetectionType = "KEY"
	DetectionTypeLeakPASSWORD DetectionType = "PASSWORD"
	DetectionTypeCertificate  DetectionType = "CERTIFICATE"
	DetectionTypePort         DetectionType = "PORT"
	DetectionTypePEM          DetectionType = "PEM"
	// DetectionTypeLeakPrivateKey is the value Converter.Leak has always
	// produced for the gitleaks "private-key" rule: the uppercase of
	// cdx.RelatedCryptoMaterialTypePrivateKey. It was never declared, so the
	// vocabulary above looked closed while the field carried a ninth value.
	//
	// It is deliberately not folded into DetectionTypeLeakKEY: that would merge
	// a leaked private key with an api-key finding and change a value tests
	// already assert.
	DetectionTypeLeakPrivateKey DetectionType = "PRIVATE-KEY"
)

type Detection struct {
	Source   string
	Type     DetectionType
	Location string
	Assets   []Asset
	Services []cdx.Service
	Rels     []Relationship
}

// BOMModel is the ref-canonicalized structure Emitters consume. Producers
// must uphold the ordering contract emitters rely on for deterministic,
// byte-stable output:
//
//   - Assets: deduped by Ref, sorted ascending by Ref.
//   - Rels: stable-sorted by From; within-From order is meaningful and
//     preserved. Rels are not deduplicated by (From, To, Kind).
//   - StatsProps: nil means "no stats counter attached" and suppresses the
//     metadata properties section; a non-nil empty slice renders as [].
//
// SerialNumber and Timestamp are pre-formatted wire strings (urn:uuid URN,
// RFC 3339).
type BOMModel struct {
	Assets       []Asset
	Rels         []Relationship
	Services     []cdx.Service
	SerialNumber string
	Timestamp    string
	StatsProps   []cdx.Property
}
