package bom

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"regexp"
	"sort"
	"testing"
	"time"

	"github.com/CZERTAINLY/CBOM-lens/internal/model"
	"github.com/CZERTAINLY/CBOM-lens/internal/model/cbom"
	"github.com/CZERTAINLY/CBOM-lens/internal/stats"
	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/stretchr/testify/require"
)

func TestNewBuilder(t *testing.T) {
	tests := []struct {
		name        string
		config      model.CBOM
		wantVersion cdx.SpecVersion
		wantErr     bool
		errMsg      string
	}{
		{
			name:        "valid version 1.6",
			config:      model.CBOM{Version: "1.6"},
			wantVersion: cdx.SpecVersion1_6,
			wantErr:     false,
		},
		{
			name:    "unsupported version",
			config:  model.CBOM{Version: "2.0"},
			wantErr: true,
			errMsg:  "unsupported cbom spec version 2.0",
		},
		{
			name:    "empty version",
			config:  model.CBOM{Version: ""},
			wantErr: true,
			errMsg:  "unsupported cbom spec version",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			builder, err := NewBuilder(tt.config)

			if tt.wantErr {
				require.Error(t, err)
				require.Contains(t, err.Error(), tt.errMsg)
				require.Nil(t, builder)
			} else {
				require.NoError(t, err)
				require.NotNil(t, builder)
				require.Equal(t, tt.wantVersion, builder.version)
				require.NotNil(t, builder.components)
				require.NotNil(t, builder.dependencies)
				require.Empty(t, builder.components)
				require.Empty(t, builder.dependencies)
			}
		})
	}
}

func TestBuilder_DeterministicMetadata(t *testing.T) {
	fixed := time.Date(2024, 1, 2, 3, 4, 5, 0, time.UTC)
	b, err := NewBuilder(model.CBOM{Version: "1.6"})
	require.NoError(t, err)
	b = b.WithClock(func() time.Time { return fixed }).
		WithSerial(func() string { return "urn:uuid:00000000-0000-0000-0000-000000000000" })

	bom := b.BOM(context.Background())
	require.Equal(t, "urn:uuid:00000000-0000-0000-0000-000000000000", bom.SerialNumber)
	require.Equal(t, "2024-01-02T03:04:05Z", bom.Metadata.Timestamp)
}

func TestBuilder_WithCounter(t *testing.T) {
	builder, err := NewBuilder(model.CBOM{Version: "1.6"})
	require.NoError(t, err)
	require.Nil(t, builder.counter)

	// expvar registers globally and panics on duplicate prefix (e.g. under
	// -count=2), so derive a unique prefix per run.
	counter := stats.New(fmt.Sprintf("%s_%d", t.Name(), time.Now().UnixNano()))
	result := builder.WithCounter(counter)

	require.Equal(t, builder, result) // Check fluent interface
	require.Equal(t, counter, builder.counter)
}

func TestBuilder_AppendDetections(t *testing.T) {
	ctx := context.Background()

	t.Run("single detection with components", func(t *testing.T) {
		builder, err := NewBuilder(model.CBOM{Version: "1.6"})
		require.NoError(t, err)

		detection := model.Detection{
			Location: "/test/path",
			Components: []cdx.Component{
				{
					BOMRef: "comp-1",
					Name:   "test-component",
					Type:   cdx.ComponentTypeLibrary,
				},
			},
		}

		builder.AppendDetections(ctx, detection)

		require.Len(t, builder.components, 1)
		require.Contains(t, builder.components, "comp-1")
		require.Equal(t, "test-component", builder.components["comp-1"].Name)
	})

	t.Run("multiple detections", func(t *testing.T) {
		builder, err := NewBuilder(model.CBOM{Version: "1.6"})
		require.NoError(t, err)

		detections := []model.Detection{
			{
				Location: "/path1",
				Components: []cdx.Component{
					{BOMRef: "comp-1", Name: "component-1", Type: cdx.ComponentTypeLibrary},
				},
			},
			{
				Location: "/path2",
				Components: []cdx.Component{
					{BOMRef: "comp-2", Name: "component-2", Type: cdx.ComponentTypeLibrary},
				},
			},
		}

		builder.AppendDetections(ctx, detections...)

		require.Len(t, builder.components, 2)
		require.Contains(t, builder.components, "comp-1")
		require.Contains(t, builder.components, "comp-2")
	})

	t.Run("detection with dependencies", func(t *testing.T) {
		builder, err := NewBuilder(model.CBOM{Version: "1.6"})
		require.NoError(t, err)

		deps := []string{"dep-1", "dep-2"}
		detection := model.Detection{
			Dependencies: []cdx.Dependency{
				{
					Ref:          "comp-1",
					Dependencies: &deps,
				},
			},
		}

		builder.AppendDetections(ctx, detection)

		require.Len(t, builder.dependencies, 1)
		require.Contains(t, builder.dependencies, "comp-1")
		require.Equal(t, &deps, builder.dependencies["comp-1"])
	})

	t.Run("ignore component without BOMRef", func(t *testing.T) {
		builder, err := NewBuilder(model.CBOM{Version: "1.6"})
		require.NoError(t, err)

		detection := model.Detection{
			Components: []cdx.Component{
				{Name: "component-without-ref", Type: cdx.ComponentTypeLibrary},
			},
		}

		builder.AppendDetections(ctx, detection)

		require.Empty(t, builder.components)
	})

	t.Run("ignore component without Name", func(t *testing.T) {
		builder, err := NewBuilder(model.CBOM{Version: "1.6"})
		require.NoError(t, err)

		detection := model.Detection{
			Components: []cdx.Component{
				{BOMRef: "comp-1", Type: cdx.ComponentTypeLibrary},
			},
		}

		builder.AppendDetections(ctx, detection)

		require.Empty(t, builder.components)
	})

	t.Run("ignore dependency without Ref", func(t *testing.T) {
		builder, err := NewBuilder(model.CBOM{Version: "1.6"})
		require.NoError(t, err)

		deps := []string{"dep-1"}
		detection := model.Detection{
			Dependencies: []cdx.Dependency{
				{Dependencies: &deps},
			},
		}

		builder.AppendDetections(ctx, detection)

		require.Empty(t, builder.dependencies)
	})

	t.Run("duplicate component adds evidence location", func(t *testing.T) {
		builder, err := NewBuilder(model.CBOM{Version: "1.6"})
		require.NoError(t, err)

		detection1 := model.Detection{
			Location: "/path1",
			Components: []cdx.Component{
				{BOMRef: "comp-1", Name: "test", Type: cdx.ComponentTypeLibrary},
			},
		}
		detection2 := model.Detection{
			Location: "/path2",
			Components: []cdx.Component{
				{BOMRef: "comp-1", Name: "test", Type: cdx.ComponentTypeLibrary},
			},
		}

		builder.AppendDetections(ctx, detection1, detection2)

		require.Len(t, builder.components, 1)
		comp := builder.components["comp-1"]
		require.NotNil(t, comp.Evidence)
		require.NotNil(t, comp.Evidence.Occurrences)
		require.Len(t, *comp.Evidence.Occurrences, 2)
	})

	t.Run("duplicate dependency is ignored", func(t *testing.T) {
		builder, err := NewBuilder(model.CBOM{Version: "1.6"})
		require.NoError(t, err)

		deps := []string{"dep-1"}
		detection1 := model.Detection{
			Dependencies: []cdx.Dependency{
				{Ref: "comp-1", Dependencies: &deps},
			},
		}
		detection2 := model.Detection{
			Dependencies: []cdx.Dependency{
				{Ref: "comp-1", Dependencies: &deps},
			},
		}

		builder.AppendDetections(ctx, detection1, detection2)

		require.Len(t, builder.dependencies, 1)
	})
}

func TestBuilder_BOM(t *testing.T) {
	t.Run("basic BOM structure", func(t *testing.T) {
		builder, err := NewBuilder(model.CBOM{Version: "1.6"})
		require.NoError(t, err)

		bom := builder.BOM(t.Context())

		require.Equal(t, "https://cyclonedx.org/schema/bom-1.6.schema.json", bom.JSONSchema)
		require.Equal(t, "CycloneDX", bom.BOMFormat)
		require.Equal(t, cdx.SpecVersion1_6, bom.SpecVersion)
		require.NotEmpty(t, bom.SerialNumber)
		require.Equal(t, 1, bom.Version)
		require.NotNil(t, bom.Metadata)
		require.NotNil(t, bom.Components)
		require.NotNil(t, bom.Dependencies)
	})

	t.Run("BOM with components", func(t *testing.T) {
		builder, err := NewBuilder(model.CBOM{Version: "1.6"})
		require.NoError(t, err)

		var components = []cdx.Component{
			{
				BOMRef: "comp-1",
				Name:   "test-component-1",
				Type:   cdx.ComponentTypeLibrary,
			},
			{
				BOMRef: "crypt/library@sha256:this-is-a-hash",
				Name:   "test-component-2",
				Type:   cdx.ComponentTypeLibrary,
			},
		}

		builder.AppendDetections(t.Context(),
			model.Detection{Components: components},
		)

		bom := builder.BOM(t.Context())

		require.Len(t, *bom.Components, 2)

		var uuidSuffix = regexp.MustCompile(`[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
		require.Regexp(t, uuidSuffix, (*bom.Components)[0].BOMRef)
		require.Regexp(t, uuidSuffix, (*bom.Components)[1].BOMRef)
	})

	t.Run("BOM metadata", func(t *testing.T) {
		builder, err := NewBuilder(model.CBOM{Version: "1.6"})
		require.NoError(t, err)

		bom := builder.BOM(t.Context())

		require.NotNil(t, bom.Metadata)
		require.NotEmpty(t, bom.Metadata.Timestamp)
		require.NotNil(t, bom.Metadata.Lifecycles)
		require.Len(t, *bom.Metadata.Lifecycles, 1)
		require.EqualValues(t, "operations", (*bom.Metadata.Lifecycles)[0].Phase)
		require.NotNil(t, bom.Metadata.Component)
		require.Equal(t, "CBOM-Lens", bom.Metadata.Component.Name)
		require.Equal(t, "application", string(bom.Metadata.Component.Type))
	})
}

func TestBuilder_AsJSON(t *testing.T) {
	t.Run("valid JSON output", func(t *testing.T) {
		builder, err := NewBuilder(model.CBOM{Version: "1.6"})
		require.NoError(t, err)

		var buf bytes.Buffer
		err = builder.AsJSON(t.Context(), &buf)

		require.NoError(t, err)
		require.NotEmpty(t, buf.String())

		// Verify it's valid JSON
		var bom cdx.BOM
		err = json.Unmarshal(buf.Bytes(), &bom)
		require.NoError(t, err)
	})
}

func TestAddEvidenceLocation(t *testing.T) {
	t.Run("add location to empty component", func(t *testing.T) {
		comp := &cdx.Component{
			BOMRef: "test",
			Name:   "test",
		}

		addEvidenceLocation(comp, "/path1")

		require.NotNil(t, comp.Evidence)
		require.NotNil(t, comp.Evidence.Occurrences)
		require.Len(t, *comp.Evidence.Occurrences, 1)
		require.Equal(t, "/path1", (*comp.Evidence.Occurrences)[0].Location)
	})

	t.Run("add multiple locations", func(t *testing.T) {
		comp := &cdx.Component{
			BOMRef: "test",
			Name:   "test",
		}

		addEvidenceLocation(comp, "/path1", "/path2")

		require.NotNil(t, comp.Evidence)
		require.NotNil(t, comp.Evidence.Occurrences)
		require.Len(t, *comp.Evidence.Occurrences, 2)
	})

	t.Run("avoid duplicate locations", func(t *testing.T) {
		comp := &cdx.Component{
			BOMRef: "test",
			Name:   "test",
		}

		addEvidenceLocation(comp, "/path1")
		addEvidenceLocation(comp, "/path1")

		require.Len(t, *comp.Evidence.Occurrences, 1)
	})

	t.Run("locations are sorted", func(t *testing.T) {
		comp := &cdx.Component{
			BOMRef: "test",
			Name:   "test",
		}

		addEvidenceLocation(comp, "/path3", "/path1", "/path2")

		occurrences := *comp.Evidence.Occurrences
		require.Equal(t, "/path1", occurrences[0].Location)
		require.Equal(t, "/path2", occurrences[1].Location)
		require.Equal(t, "/path3", occurrences[2].Location)
	})

	t.Run("nil component", func(t *testing.T) {
		require.NotPanics(t, func() {
			addEvidenceLocation(nil, "/path1")
		})
	})

	t.Run("nil locations", func(t *testing.T) {
		comp := &cdx.Component{
			BOMRef: "test",
			Name:   "test",
		}

		require.NotPanics(t, func() {
			addEvidenceLocation(comp)
		})
	})
}

func TestSafeRef(t *testing.T) {
	tests := []struct {
		name     string
		bomRef   string
		wantLen  int
		contains string
	}{
		{
			name:     "ref with @ separator",
			bomRef:   "component@version",
			wantLen:  46, // "component@" + 36-char UUID
			contains: "component@",
		},
		{
			name:    "ref without @ separator",
			bomRef:  "component-ref",
			wantLen: 36, // Just UUID
		},
		{
			name:    "empty ref",
			bomRef:  "",
			wantLen: 36, // Just UUID
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := safeRef(tt.bomRef)

			require.Len(t, result, tt.wantLen)
			if tt.contains != "" {
				require.Contains(t, result, tt.contains)
			}
		})
	}
}

func TestSafeRefs_Component(t *testing.T) {
	t.Run("replace BOMRef in component", func(t *testing.T) {
		refs := safeRefs{
			refs: map[string]string{
				"old-ref": "new-ref",
			},
		}

		comp := cdx.Component{
			BOMRef: "old-ref",
			Name:   "test",
		}

		result := refs.component(t.Context(), comp)

		require.Equal(t, "new-ref", result.BOMRef)
		require.Equal(t, "test", result.Name)
	})
}

func TestReplaceBOMReferences(t *testing.T) {
	t.Run("replace BOMReference in struct", func(t *testing.T) {
		refs := safeRefs{
			refs: map[string]string{
				"old-ref": "new-ref",
			},
		}

		compo := cdx.Component{
			BOMRef: "old-ref",
		}

		compo = refs.component(t.Context(), compo)

		require.EqualValues(t, cdx.BOMReference("new-ref"), compo.BOMRef)
	})

	t.Run("replace nested BOMReference", func(t *testing.T) {
		refs := map[string]string{
			"crypto-ref": "safe-crypto-ref",
		}

		certProps := &cdx.CertificateProperties{
			SignatureAlgorithmRef: "crypto-ref",
		}
		cryptoProps := &cdx.CryptoProperties{
			CertificateProperties: certProps,
		}
		comp := cdx.Component{
			CryptoProperties: cryptoProps,
		}

		replaceBOMReferences(refs, reflect.ValueOf(&comp))

		require.Equal(t, cdx.BOMReference("safe-crypto-ref"), comp.CryptoProperties.CertificateProperties.SignatureAlgorithmRef)
	})

	t.Run("handle nil pointer", func(t *testing.T) {
		refs := map[string]string{
			"ref": "safe-ref",
		}

		var comp *cdx.Component

		require.NotPanics(t, func() {
			replaceBOMReferences(refs, reflect.ValueOf(comp))
		})
	})

	t.Run("handle slice of components", func(t *testing.T) {
		refs := safeRefs{
			refs: map[string]string{
				"old-ref-1": "new-ref-1",
				"old-ref-2": "new-ref-2",
			},
		}

		compos := []cdx.Component{
			{BOMRef: "old-ref-1"},
			{BOMRef: "old-ref-2"},
		}

		for idx, compo := range compos {
			compos[idx] = refs.component(t.Context(), compo)
		}

		require.EqualValues(t, cdx.BOMReference("new-ref-1"), compos[0].BOMRef)
		require.EqualValues(t, cdx.BOMReference("new-ref-2"), compos[1].BOMRef)
	})

	t.Run("handle invalid value", func(t *testing.T) {
		refs := map[string]string{}

		require.NotPanics(t, func() {
			replaceBOMReferences(refs, reflect.Value{})
		})
	})
}

func TestBuilder_SafeRefs(t *testing.T) {
	t.Run("generate safe refs for all components", func(t *testing.T) {
		builder, err := NewBuilder(model.CBOM{Version: "1.6"})
		require.NoError(t, err)

		builder.components["comp-1"] = &cdx.Component{BOMRef: "comp-1", Name: "test1"}
		builder.components["comp-2"] = &cdx.Component{BOMRef: "comp-2", Name: "test2"}

		safeRefs := builder.safeRefs()

		require.Len(t, safeRefs.refs, 2)
		require.Contains(t, safeRefs.refs, "comp-1")
		require.Contains(t, safeRefs.refs, "comp-2")
		require.NotEqual(t, "comp-1", safeRefs.refs["comp-1"])
		require.NotEqual(t, "comp-2", safeRefs.refs["comp-2"])
	})

	t.Run("skip nil components", func(t *testing.T) {
		builder, err := NewBuilder(model.CBOM{Version: "1.6"})
		require.NoError(t, err)

		builder.components["comp-1"] = &cdx.Component{BOMRef: "comp-1", Name: "test1"}
		builder.components["comp-2"] = nil

		safeRefs := builder.safeRefs()

		require.Len(t, safeRefs.refs, 1)
		require.Contains(t, safeRefs.refs, "comp-1")
		require.NotContains(t, safeRefs.refs, "comp-2")
	})
}

func TestBuilder_StableOrdering(t *testing.T) {
	newB := func() *Builder {
		b, err := NewBuilder(model.CBOM{Version: "1.6"})
		require.NoError(t, err)
		// two components + one dependency; map iteration order is randomized per range
		b.components["b@2"] = &cdx.Component{BOMRef: "b@2", Name: "b"}
		b.components["a@1"] = &cdx.Component{BOMRef: "a@1", Name: "a"}
		deps := []string{"a@1"}
		b.dependencies["b@2"] = &deps
		return b
	}
	first := newB().BOM(context.Background())
	for i := 0; i < 20; i++ {
		got := newB().BOM(context.Background())
		require.Equal(t, *first.Components, *got.Components, "components order must be stable")
		require.Equal(t, *first.Dependencies, *got.Dependencies, "dependencies order must be stable")
	}
	// and it is sorted ascending by ref
	refs := []string{(*first.Components)[0].BOMRef, (*first.Components)[1].BOMRef}
	require.True(t, sort.StringsAreSorted(refs), "components sorted by BOMRef")
}

func TestBuilder_StatsProperties(t *testing.T) {
	// expvar registers globally and panics on duplicate prefix, so derive a
	// unique prefix per run and build the expected names from it.
	prefix := fmt.Sprintf("bom_stats_%d", time.Now().UnixNano())
	counter := stats.New(prefix)
	counter.IncFiles()
	counter.IncFiles()
	counter.IncErrSources()

	b, err := NewBuilder(model.CBOM{Version: "1.6"})
	require.NoError(t, err)
	b = b.WithCounter(counter)

	want := []cdx.Property{
		{Name: prefix + "_files_errors", Value: "0"},
		{Name: prefix + "_files_excluded", Value: "0"},
		{Name: prefix + "_files_total", Value: "2"},
		{Name: prefix + "_sources_errors", Value: "1"},
		{Name: prefix + "_sources_total", Value: "0"},
	}

	m := b.model(context.Background())
	require.Equal(t, want, m.StatsProps)

	bom := b.BOM(context.Background())
	require.NotNil(t, bom.Metadata.Properties)
	require.Equal(t, want, *bom.Metadata.Properties)
}

func TestBuilder_NoCounterOmitsMetadataProperties(t *testing.T) {
	b, err := NewBuilder(model.CBOM{Version: "1.6"})
	require.NoError(t, err)

	bom := b.BOM(context.Background())
	require.Nil(t, bom.Metadata.Properties)
}

func TestBuilder_BOMDeterministic(t *testing.T) {
	newB := func() *Builder {
		b, err := NewBuilder(model.CBOM{Version: "1.6"})
		require.NoError(t, err)
		b.components["b@2"] = &cdx.Component{BOMRef: "b@2", Name: "b"}
		b.components["a@1"] = &cdx.Component{BOMRef: "a@1", Name: "a"}
		b.components["c@3"] = &cdx.Component{BOMRef: "c@3", Name: "c"}
		b.dependencies["b@2"] = &[]string{"a@1", "c@3"}
		b.dependencies["a@1"] = &[]string{"c@3"}
		fixed := time.Date(2024, 1, 2, 3, 4, 5, 0, time.UTC)
		return b.WithClock(func() time.Time { return fixed }).
			WithSerial(func() string { return "urn:uuid:11111111-1111-1111-1111-111111111111" })
	}

	var first bytes.Buffer
	require.NoError(t, newB().AsJSON(context.Background(), &first))
	for i := 0; i < 10; i++ {
		var got bytes.Buffer
		require.NoError(t, newB().AsJSON(context.Background(), &got))
		require.Equal(t, first.String(), got.String(), "full JSON output must be byte-identical across runs")
	}
}

func TestBuilder_NilClockAndSerialKeepDefaults(t *testing.T) {
	b, err := NewBuilder(model.CBOM{Version: "1.6"})
	require.NoError(t, err)
	b = b.WithClock(nil).WithSerial(nil)

	require.NotPanics(t, func() {
		bom := b.BOM(context.Background())
		require.NotEmpty(t, bom.SerialNumber)
		require.NotEmpty(t, bom.Metadata.Timestamp)
	})
}

// TestBuilder_ModelDependencyEdgeSemantics verifies that dependency entries
// without edges are omitted and must be modeled explicitly when needed.
func TestBuilder_ModelDependencyEdgeSemantics(t *testing.T) {
	t.Run("nil dependsOn entry is omitted", func(t *testing.T) {
		b, err := NewBuilder(model.CBOM{Version: "1.6"})
		require.NoError(t, err)
		b.components["a@1"] = &cdx.Component{BOMRef: "a@1", Name: "a"}
		b.dependencies["a@1"] = nil

		m := b.model(context.Background())
		require.Empty(t, m.Rels)

		bom := b.BOM(context.Background())
		require.Empty(t, *bom.Dependencies)
	})

	t.Run("empty dependsOn entry is omitted", func(t *testing.T) {
		b, err := NewBuilder(model.CBOM{Version: "1.6"})
		require.NoError(t, err)
		b.components["a@1"] = &cdx.Component{BOMRef: "a@1", Name: "a"}
		b.dependencies["a@1"] = &[]string{}

		m := b.model(context.Background())
		require.Empty(t, m.Rels)

		bom := b.BOM(context.Background())
		require.Empty(t, *bom.Dependencies)
	})
}

// TestBuilder_DanglingDependencyRefs verifies unresolved refs are dropped
// because minting replacements with uuid.New would make output
// nondeterministic.
func TestBuilder_DanglingDependencyRefs(t *testing.T) {
	newB := func() *Builder {
		b, err := NewBuilder(model.CBOM{Version: "1.6"})
		require.NoError(t, err)
		b.components["a@1"] = &cdx.Component{BOMRef: "a@1", Name: "a"}
		b.components["b@2"] = &cdx.Component{BOMRef: "b@2", Name: "b"}
		fixed := time.Date(2024, 1, 2, 3, 4, 5, 0, time.UTC)
		return b.WithClock(func() time.Time { return fixed }).
			WithSerial(func() string { return "urn:uuid:11111111-1111-1111-1111-111111111111" })
	}

	t.Run("dangling To edge is dropped", func(t *testing.T) {
		b := newB()
		b.dependencies["a@1"] = &[]string{"ghost@7", "b@2"}

		m := b.model(context.Background())
		require.Len(t, m.Rels, 1, "only the resolvable edge survives")
		require.Equal(t, cbom.AssetRef(safeRef("b@2")), m.Rels[0].To)
	})

	t.Run("dangling From entry is dropped", func(t *testing.T) {
		b := newB()
		b.dependencies["ghost@0"] = &[]string{"a@1"}

		m := b.model(context.Background())
		require.Empty(t, m.Rels)
	})

	t.Run("output is deterministic with dangling refs present", func(t *testing.T) {
		build := func() string {
			b := newB()
			b.dependencies["a@1"] = &[]string{"ghost@7"}
			b.dependencies["ghost@0"] = &[]string{"a@1"}
			var buf bytes.Buffer
			require.NoError(t, b.AsJSON(context.Background(), &buf))
			return buf.String()
		}
		first := build()
		for i := 0; i < 5; i++ {
			require.Equal(t, first, build(), "dangling refs must not introduce nondeterminism")
		}
	})
}

func TestBuilder_BOMPanicsWithoutEmitter(t *testing.T) {
	// Builder constructed without NewBuilder validation: BOM() must panic on a
	// version that has no emitter rather than emit a wrong-version document.
	b := &Builder{version: cdx.SpecVersion1_5}
	require.Panics(t, func() { b.BOM(context.Background()) })
}

func TestBuilder_ModelCanonicalRefs(t *testing.T) {
	b, err := NewBuilder(model.CBOM{Version: "1.6"})
	require.NoError(t, err)

	b.components["sig@raw"] = &cdx.Component{BOMRef: "sig@raw", Name: "sig"}
	b.components["key@raw"] = &cdx.Component{BOMRef: "key@raw", Name: "key"}
	b.dependencies["sig@raw"] = &[]string{"key@raw"}

	m := b.model(context.Background())

	require.Len(t, m.Assets, 2)
	require.Len(t, m.Rels, 1)

	var sigRef, keyRef cbom.AssetRef
	for _, a := range m.Assets {
		switch a.Component.Name {
		case "sig":
			sigRef = a.Ref
		case "key":
			keyRef = a.Ref
		}
	}
	require.NotEmpty(t, sigRef)
	require.NotEmpty(t, keyRef)

	// Raw refs must NOT survive canonicalization.
	require.NotEqual(t, cbom.AssetRef("sig@raw"), sigRef)
	require.NotEqual(t, cbom.AssetRef("key@raw"), keyRef)

	rel := m.Rels[0]
	require.Equal(t, cbom.RelDependsOn, rel.Kind)
	// Relationship endpoints must match the SAME canonical refs as the assets.
	require.Equal(t, sigRef, rel.From)
	require.Equal(t, keyRef, rel.To)
}
