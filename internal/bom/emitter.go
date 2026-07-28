package bom

import (
	"context"
	"fmt"

	"github.com/CZERTAINLY/CBOM-lens/internal/model/cbom"
	cdx "github.com/CycloneDX/cyclonedx-go"
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
	default:
		return nil, fmt.Errorf("no emitter for spec version %s", v)
	}
}
