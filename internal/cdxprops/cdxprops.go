package cdxprops

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"log/slog"
	"maps"
	"os"
	"runtime"
	"slices"
	"strings"

	"github.com/CZERTAINLY/CBOM-lens/internal/model"
	cdx "github.com/CycloneDX/cyclonedx-go"
)

type Converter struct {
	// czertainly control if extra czertainly properties will be included or not
	czertainly bool
	// bomRefHasher controls which algorithm will be used
	// to generate non-algorithm BOMRef. Defaults to sha256
	bomRefHasher func([]byte) string
}

func NewConverter() Converter {
	return Converter{
		czertainly: false,
		bomRefHasher: func(b []byte) string {
			hash := sha256.Sum256(b)
			return "sha256:" + hex.EncodeToString(hash[:])
		},
	}
}

// WithCzertainlyExtensions configures the mode in which CZERTAINLY specific properties will be included in Components or not
// Default is yes
func (c Converter) WithCzertainlyExtensions(czertainly bool) Converter {
	c.czertainly = czertainly
	return c
}

// Leak converts the finding to detection.
// Supports jwt, token, key and password.
// Returns nil if given Leak should be ignored
// safe to be used by different go routines
func (c Converter) Leak(ctx context.Context, leaks model.Leaks) *model.Detection {
	var compos = make([]cdx.Component, 0, len(leaks.Findings))
	for _, finding := range leaks.Findings {
		compo, skip := c.leakToComponent(ctx, leaks.Location, finding)
		if skip {
			continue
		}
		compos = append(compos, compo)
	}

	if len(compos) == 0 {
		return nil
	}

	typ := strings.ToUpper(string(compos[0].CryptoProperties.RelatedCryptoMaterialProperties.Type))
	return &model.Detection{
		Source:     "LEAKS",
		Type:       model.DetectionType(typ),
		Location:   leaks.Location,
		Components: compos,
	}
}

func (c Converter) CertHit(ctx context.Context, hit model.CertHit) *model.Detection {
	if hit.Cert == nil {
		return nil
	}

	compos, deps, err := c.certHitToComponents(ctx, hit)
	// TODO: figure out the PQC
	if err != nil {
		slog.ErrorContext(ctx, "can't parse certificate", "error", err)
		return nil
	}
	if compos == nil {
		return nil
	}

	return &model.Detection{
		Source:       hit.Source,
		Type:         model.DetectionTypeCertificate,
		Location:     hit.Location,
		Components:   compos,
		Dependencies: deps,
	}
}

func (c Converter) Nmap(ctx context.Context, nmap model.Nmap) *model.Detection {

	hostname, err := os.Hostname()
	if err != nil {
		hostname = "N/A"
	}

	compos, deps, services, err := c.parseNmap(ctx, nmap)
	if err != nil {
		slog.WarnContext(ctx, "failed to parse nmap", "error", err)
		return nil
	}

	return &model.Detection{
		Source:       "NMAP",
		Type:         model.DetectionTypePort,
		Location:     hostname,
		Components:   compos,
		Dependencies: deps,
		Services:     services,
	}
}

func (c Converter) PEMBundle(ctx context.Context, bundle model.PEMBundle) *model.Detection {
	var compos []cdx.Component
	var deps []cdx.Dependency

	for _, cert := range bundle.Certificates {
		d := c.CertHit(ctx, cert)
		if d == nil {
			continue
		}
		compos = append(compos, d.Components...)
		deps = append(deps, d.Dependencies...)
	}

	for _, privKey := range bundle.PrivateKeys {
		pubKey, err := getPublicKey(privKey)
		if err != nil {
			slog.WarnContext(ctx, "can't extract a publicKey from a privateKey: skipping", "error", err, "bundle.location", bundle.Location)
			continue
		}
		pubKeyAlgo, pubKeyCompo := c.publicKeyComponents(
			ctx,
			getPublicKeyAlgorithm(pubKey),
			pubKey,
			nil,
		)
		_, pubKeyID, _ := strings.Cut(pubKeyCompo.BOMRef, "@")
		privKeyAlgo, privKeyCompo := c.PrivateKey(ctx, pubKeyID, privKey)

		compos = append(compos, []cdx.Component{
			pubKeyAlgo, pubKeyCompo,
			privKeyAlgo, privKeyCompo,
		}...)
	}

	bundleCompos, err := c.restOfPEMBundleToCDX(ctx, bundle, bundle.Location)
	if err != nil {
		slog.WarnContext(ctx, "analyzing bundle returned an error", "error", err)
	}
	compos = append(compos, bundleCompos...)

	for i := range compos {
		if compos[i].CryptoProperties == nil {
			compos[i].CryptoProperties = &cdx.CryptoProperties{}
		}
		if compos[i].CryptoProperties.RelatedCryptoMaterialProperties == nil {
			compos[i].CryptoProperties.RelatedCryptoMaterialProperties = &cdx.RelatedCryptoMaterialProperties{}
		}
		compos[i].CryptoProperties.RelatedCryptoMaterialProperties.Format = "PEM"
	}

	return &model.Detection{
		Source:       "PEM",
		Type:         model.DetectionTypePort,
		Location:     bundle.Location,
		Components:   compos,
		Dependencies: deps,
	}
}

func (c Converter) ImplementationPlatform() cdx.ImplementationPlatform {
	switch runtime.GOARCH {
	case "amd64":
		return cdx.ImplementationPlatformX86_64
	case "386":
		return cdx.ImplementationPlatformX86_32
	case "ppc64", "ppc64le":
		return cdx.ImplementationPlatformPPC64
	case "s390x":
		return cdx.ImplementationPlatformS390x
	default:
		return cdx.ImplementationPlatform(runtime.GOARCH)
	}
}

// BOMRefHash generates a unique BOM reference for components that lack inherent
// identification (e.g., crypto/algorithm, crypto/hash). The reference is computed
// by hashing the JSON representation of the component itself (with BOMRef cleared)
// and formatting it as "name@hash". This ensures deterministic, collision-resistant
// identifiers for components defined solely by their properties.
func (c Converter) BOMRefHash(compo *cdx.Component, name string) {
	if compo == nil {
		return
	}
	compo.BOMRef = ""
	compo.Evidence = nil
	b, _ := json.Marshal(compo)
	h := c.bomRefHasher(b)
	compo.BOMRef = name + "@" + h
}

func setAlgorithmPrimitive(compo *cdx.Component, primitive cdx.CryptoPrimitive) {
	if compo == nil {
		return
	}
	if compo.CryptoProperties == nil {
		compo.CryptoProperties = &cdx.CryptoProperties{}
	}
	if compo.CryptoProperties.AlgorithmProperties == nil {
		compo.CryptoProperties.AlgorithmProperties = &cdx.CryptoAlgorithmProperties{}
	}
	compo.CryptoProperties.AlgorithmProperties.Primitive = primitive
}

func addAlgorithmCrpyoFunctions(compo *cdx.Component, functions ...cdx.CryptoFunction) {
	if compo == nil {
		return
	}
	if compo.CryptoProperties == nil {
		compo.CryptoProperties = &cdx.CryptoProperties{}
	}
	if compo.CryptoProperties.AlgorithmProperties == nil {
		compo.CryptoProperties.AlgorithmProperties = &cdx.CryptoAlgorithmProperties{}
	}

	set := make(map[cdx.CryptoFunction]struct{})
	for _, f := range *compo.CryptoProperties.AlgorithmProperties.CryptoFunctions {
		set[f] = struct{}{}
	}
	for _, f := range functions {
		set[f] = struct{}{}
	}
	funcs := slices.Collect(maps.Keys(set))
	var p *[]cdx.CryptoFunction
	if len(funcs) != 0 {
		p = &funcs
	}
	compo.CryptoProperties.AlgorithmProperties.CryptoFunctions = p
}
