package bom

import (
	"context"
	"fmt"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/OmniTrustILM/cbom-lens/internal/model/cbom"
)

// Emitter renders the version-neutral BOMModel into a cdx.BOM for one spec version.
type Emitter interface {
	SpecVersion() cdx.SpecVersion
	Emit(ctx context.Context, m cbom.BOMModel) cdx.BOM
}

// emitterFor returns the Emitter for a supported spec version.
func emitterFor(v cdx.SpecVersion) (Emitter, error) {
	switch v {
	case cdx.SpecVersion1_6:
		return emit16{}, nil
	case cdx.SpecVersion1_7:
		return emit17{}, nil
	default:
		return nil, fmt.Errorf("no emitter for spec version %s", v)
	}
}
