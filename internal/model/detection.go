package model

import (
	cdx "github.com/CycloneDX/cyclonedx-go"
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
}
