package model

import (
	cdx "github.com/CycloneDX/cyclonedx-go"

	"github.com/OmniTrustILM/cbom-lens/internal/model/cbom"
)

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

// Detection is CycloneDX data converted from scanners
type Detection struct {
	// Source is the scanner or crypto type
	// can be "PEM", "LEAKS", "DER", "NMAP", ...
	Source string
	// Type identifies the type of a crypto material
	// can be the rule-id for gitleaks
	// or private-key or pem-bundle in a case of other scanners
	Type DetectionType
	// Location is an identifier of the source data
	// eg /path/to/cert.pem, unix:///var/run/docker.sock:image:/path/to/cert.pem
	Location     string
	Components   []cdx.Component
	Dependencies []cdx.Dependency
	Services     []cdx.Service
	// Rels are crypto relationships the converter states directly, for edges no
	// 1.6 reference field can carry. Endpoints are the converter's own raw
	// bom-refs; the Builder canonicalises them with everything else.
	//
	// Everything else a converter knows about crypto relationships travels in
	// the components themselves and is recovered by Builder.cryptoRels, which
	// reads the 1.6 ref fields back off them. That works because those edges
	// have a field to live in. A certificate request's edge to the key it asks
	// to have certified does not, so it is stated here instead of being
	// squeezed into algorithmRef, which is typed to an algorithm.
	Rels []cbom.Relationship
}
