package bom

import (
	"context"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/OmniTrustILM/cbom-lens/internal/model/cbom"
)

// emit16 renders the BOMModel as CycloneDX 1.6.
type emit16 struct{}

func (emit16) SpecVersion() cdx.SpecVersion { return cdx.SpecVersion1_6 }

// Emit renders the version-neutral BOMModel into a CycloneDX 1.6 cdx.BOM. It
// reproduces the exact structure pinned by the golden corpus
// (testdata/golden/corpus-1.6.json, TestGolden_1_6) byte for byte.
func (emit16) Emit(ctx context.Context, m cbom.BOMModel) cdx.BOM {
	// Components: m.Assets is already sorted by Ref (see cbom.BOMModel's
	// ordering contract). Asset.Ref is the canonical identity — stamp it onto
	// the wire component so the two cannot drift.
	components := make([]cdx.Component, 0, len(m.Assets))
	for _, a := range m.Assets {
		c := a.Component
		c.BOMRef = string(a.Ref)
		components = append(components, c)
	}

	dependencies := regroupDependsOn(m.Rels)

	// Metadata.Properties is non-nil only when a stats counter was attached
	// (a fresh counter yields a non-nil empty slice, rendered as []).
	var mp *[]cdx.Property
	if m.StatsProps != nil {
		mp = &m.StatsProps
	}

	return cdx.BOM{
		JSONSchema:   "https://cyclonedx.org/schema/bom-1.6.schema.json",
		BOMFormat:    cdx.BOMFormat,
		SpecVersion:  cdx.SpecVersion1_6,
		SerialNumber: m.SerialNumber,
		Version:      1,
		Metadata: &cdx.Metadata{
			Timestamp: m.Timestamp,
			Lifecycles: &[]cdx.Lifecycle{
				{
					Name:        "",
					Phase:       cdx.LifecyclePhaseOperations,
					Description: "",
				},
			},
			// Identifies CBOM-Lens as the producing tool; part of the golden
			// 1.6 output.
			Component: &cdx.Component{
				Type:    cdx.ComponentTypeApplication,
				Name:    "CBOM-Lens",
				Version: programVersion,
				Manufacturer: &cdx.OrganizationalEntity{
					Name:    "OmniTrust",
					Address: &cdx.PostalAddress{},
					URL: &[]string{
						"https://www.omnitrust.com",
					},
				},
			},
			Properties: mp,
		},
		Components:   &components,
		Dependencies: &dependencies,
		Properties:   &[]cdx.Property{},
	}
}

// regroupDependsOn renders RelDependsOn edges into cdx dependency rows,
// regrouping consecutive same-From edges (m.Rels ordering contract) into one
// dependsOn array. m.Rels is stable-sorted by From, so same-From edges are
// consecutive and in original order; the resulting slice is ordered by Ref.
// Shared by emit16 and emit17.
func regroupDependsOn(rels []cbom.Relationship) []cdx.Dependency {
	dependencies := make([]cdx.Dependency, 0)
	var (
		curFrom  cbom.AssetRef
		curDeps  []string
		haveFrom bool
	)
	flush := func() {
		if !haveFrom {
			return
		}
		deps := curDeps
		dependencies = append(dependencies, cdx.Dependency{Ref: string(curFrom), Dependencies: &deps})
	}
	for _, r := range rels {
		if r.Kind != cbom.RelDependsOn {
			continue
		}
		if !haveFrom || r.From != curFrom {
			flush()
			curFrom = r.From
			curDeps = nil
			haveFrom = true
		}
		curDeps = append(curDeps, string(r.To))
	}
	flush()
	return dependencies
}
