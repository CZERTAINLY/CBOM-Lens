package bom

import (
	"context"
	"io"
	"log/slog"
	"maps"
	"runtime/debug"
	"slices"
	"time"

	"github.com/CZERTAINLY/CBOM-lens/internal/model"
	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/google/uuid"
)

var version string

func init() {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		version = "unknown"
	} else {
		version = info.Main.Version
	}
}

// Builder is a builder pattern for a CycloneDX BOM structure
type Builder struct {
	components   map[string]*cdx.Component
	dependencies map[string]*[]string
	properties   []cdx.Property
}

func NewBuilder() *Builder {
	return &Builder{
		components:   make(map[string]*cdx.Component),
		dependencies: make(map[string]*[]string),
		properties:   []cdx.Property{},
	}
}

func (b *Builder) AppendDetections(ctx context.Context, detections ...model.Detection) *Builder {
	for _, d := range detections {
		b.appendDetection(ctx, d)
	}
	return b
}

func (b *Builder) appendDetection(ctx context.Context, detection model.Detection) {
	for _, dep := range detection.Dependencies {
		if dep.Ref == "" {
			continue
		}
		_, ok := b.dependencies[dep.Ref]
		if ok {
			slog.DebugContext(ctx, "ignoring dependency: already stored", "ref", dep.Ref)
			continue
		}
		b.dependencies[dep.Ref] = dep.Dependencies
	}

	for _, compo := range detection.Components {
		if compo.BOMRef == "" || compo.Name == "" {
			continue
		}
		stored, ok := b.components[compo.BOMRef]
		if ok {
			addEvidenceLocation(stored, detection.Location)
			continue
		}
		addEvidenceLocation(&compo, detection.Location)
		b.components[compo.BOMRef] = &compo
	}
}

// BOM returns a cdx.BOM based on a data inside the Builder
func (b *Builder) BOM() cdx.BOM {
	components := make([]cdx.Component, 0, len(b.components))
	for _, compop := range b.components {
		if compop == nil {
			continue
		}
		components = append(components, *compop)
	}

	dependencies := make([]cdx.Dependency, 0, len(b.dependencies))
	for bomRef, depsp := range b.dependencies {
		dep := cdx.Dependency{
			Ref:          bomRef,
			Dependencies: depsp,
		}
		dependencies = append(dependencies, dep)
	}

	bom := cdx.BOM{
		JSONSchema:   "https://cyclonedx.org/schema/bom-1.6.schema.json",
		BOMFormat:    "CycloneDX",
		SpecVersion:  cdx.SpecVersion1_6,
		SerialNumber: "urn:uuid:" + uuid.New().String(),
		Version:      1,
		Metadata: &cdx.Metadata{
			Timestamp: time.Now().UTC().Format(time.RFC3339),
			Lifecycles: &[]cdx.Lifecycle{
				{
					Name:        "",
					Phase:       "operations",
					Description: "",
				},
			},
			// This can't be not nil otherwise this error will happen
			// json: error calling MarshalJSON for type *cyclonedx.ToolsChoice: unexpected end of JSON input
			Component: &cdx.Component{
				Type:    "application",
				Name:    "CBOM-Lens",
				Version: version,
				Manufacturer: &cdx.OrganizationalEntity{
					Name:    "CZERTAINLY",
					Address: &cdx.PostalAddress{},
					URL: &[]string{
						"https://www.czertainly.com",
					},
				},
			},
		},
		Components:   &components,
		Dependencies: &dependencies,
		Properties:   &b.properties,
	}
	return bom
}

// AsJSON encode the BOM into JSON format
func (b *Builder) AsJSON(w io.Writer) error {
	bom := b.BOM()
	return cdx.NewBOMEncoder(w, cdx.BOMFileFormatJSON).SetPretty(true).Encode(&bom)
}

// Add (append) an evidence.occurrence location if non-empty.
// ensures location is present only once
func addEvidenceLocation(c *cdx.Component, locations ...string) {
	if c == nil || locations == nil {
		return
	}
	if c.Evidence == nil {
		c.Evidence = &cdx.Evidence{}
	}
	if c.Evidence.Occurrences == nil {
		c.Evidence.Occurrences = &[]cdx.EvidenceOccurrence{}
	}

	stored := make(map[string]struct{})
	for _, occ := range *c.Evidence.Occurrences {
		stored[occ.Location] = struct{}{}
	}
	for _, loc := range locations {
		stored[loc] = struct{}{}
	}

	if len(stored) == 0 {
		return
	}

	occurences := make([]cdx.EvidenceOccurrence, 0, len(stored))
	for _, loc := range slices.Sorted(maps.Keys(stored)) {
		occurences = append(occurences, cdx.EvidenceOccurrence{
			Location: loc,
		})
	}

	c.Evidence.Occurrences = &occurences
}
