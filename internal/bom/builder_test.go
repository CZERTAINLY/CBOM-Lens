package bom

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"reflect"
	"regexp"
	"sort"
	"testing"
	"time"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/OmniTrustILM/cbom-lens/internal/model"
	"github.com/OmniTrustILM/cbom-lens/internal/model/cbom"
	"github.com/OmniTrustILM/cbom-lens/internal/stats"
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
			name:        "valid version 1.7",
			config:      model.CBOM{Version: "1.7"},
			wantVersion: cdx.SpecVersion1_7,
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

// publicKeyDetection builds a detection carrying one public-key component under
// sharedKeyRef, with the given relatedCryptoMaterialProperties.format.
//
// It rebuilds the component on every call on purpose. Two detections that shared
// one *cdx.RelatedCryptoMaterialProperties would make the merge look correct
// through aliasing alone -- which is exactly what the real converters do NOT do,
// since each Converter call allocates its own struct.
func publicKeyDetection(source, location, format string) model.Detection {
	return model.Detection{
		Source:   source,
		Type:     model.DetectionTypeCertificate,
		Location: location,
		Components: []cdx.Component{
			{
				BOMRef: sharedKeyRef,
				Name:   "RSA-2048",
				Type:   cdx.ComponentTypeCryptographicAsset,
				CryptoProperties: &cdx.CryptoProperties{
					AssetType: cdx.CryptoAssetTypeRelatedCryptoMaterial,
					RelatedCryptoMaterialProperties: &cdx.RelatedCryptoMaterialProperties{
						Type:   cdx.RelatedCryptoMaterialTypePublicKey,
						Format: format,
					},
				},
			},
		},
	}
}

// sharedKeyRef is the bom-ref both detections below resolve to. Its shape is the
// real one: crypto/key/<alg>@<digest of the marshalled SPKI>, which carries no
// path, no source and no encoding, so one key reached two ways is one ref.
const sharedKeyRef = "crypto/key/rsa-2048@sha256:deadbeef"

// TestBuilder_AppendDetections_RelatedCryptoMaterialFormatOrderIndependent pins
// the invariant that a component's emitted relatedCryptoMaterialProperties.
// format is decided by the SET of detections resolving to its bom-ref and never
// by the order appendDetection observes them in.
//
// The two detections below are the real pair -- one key found as a PEM file and
// inside a PKCS#12 store -- and mergeRelatedCryptoMaterialFormat's doc comment
// explains why they collide on one ref and why only one of them knows the
// encoding. Under first-wins that made format appear and disappear between
// otherwise identical runs of the same scan.
func TestBuilder_AppendDetections_RelatedCryptoMaterialFormatOrderIndependent(t *testing.T) {
	const (
		pemLocation    = "/etc/ssl/certs/ca.pem"
		pkcs12Location = "/etc/ssl/store.p12"
	)

	tests := []struct {
		name       string
		detections []model.Detection
	}{
		{
			name: "PEM arrives first",
			detections: []model.Detection{
				publicKeyDetection("PEM", pemLocation, "PEM"),
				publicKeyDetection("PKCS12", pkcs12Location, ""),
			},
		},
		{
			name: "non-PEM arrives first",
			detections: []model.Detection{
				publicKeyDetection("PKCS12", pkcs12Location, ""),
				publicKeyDetection("PEM", pemLocation, "PEM"),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			builder, err := NewBuilder(model.CBOM{Version: "1.6"})
			require.NoError(t, err)

			builder.AppendDetections(t.Context(), tt.detections...)

			require.Len(t, builder.components, 1,
				"one key is one asset: both detections hash to the same bom-ref")
			stored := builder.components[sharedKeyRef]
			require.NotNil(t, stored)
			require.NotNil(t, stored.CryptoProperties)
			require.NotNil(t, stored.CryptoProperties.RelatedCryptoMaterialProperties)
			require.Equal(t, "PEM", stored.CryptoProperties.RelatedCryptoMaterialProperties.Format,
				"format must be a function of the detection set, not of arrival order")

			// The merge must not cost what the branch already did.
			require.NotNil(t, stored.Evidence)
			require.NotNil(t, stored.Evidence.Occurrences)
			require.Len(t, *stored.Evidence.Occurrences, 2,
				"both locations must still reach evidence.occurrences")
		})
	}
}

// TestAppendDetection_FormatReachesStoredWithoutMaterialProperties covers the
// case the stored component has no relatedCryptoMaterialProperties to merge
// into. Returning early there would drop a format the incoming detection knows,
// reinstating the order dependence for that pair; allocating unconditionally
// would be #213. See mergeRelatedCryptoMaterialFormat for why the gate is the
// asset type.
func TestAppendDetection_FormatReachesStoredWithoutMaterialProperties(t *testing.T) {
	tests := []struct {
		name       string
		stored     cdx.Component
		wantFormat string
		wantProps  bool
	}{
		{
			name: "material asset gains the struct",
			stored: cdx.Component{
				BOMRef: sharedKeyRef,
				Name:   "RSA-2048",
				Type:   cdx.ComponentTypeCryptographicAsset,
				CryptoProperties: &cdx.CryptoProperties{
					AssetType: cdx.CryptoAssetTypeRelatedCryptoMaterial,
				},
			},
			wantFormat: "PEM",
			wantProps:  true,
		},
		{
			name: "algorithm asset does not (#213)",
			stored: cdx.Component{
				BOMRef: sharedKeyRef,
				Name:   "RSA-2048",
				Type:   cdx.ComponentTypeCryptographicAsset,
				CryptoProperties: &cdx.CryptoProperties{
					AssetType: cdx.CryptoAssetTypeAlgorithm,
				},
			},
			wantProps: false,
		},
		{
			name: "component without cryptoProperties does not",
			stored: cdx.Component{
				BOMRef: sharedKeyRef,
				Name:   "RSA-2048",
				Type:   cdx.ComponentTypeLibrary,
			},
			wantProps: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			builder, err := NewBuilder(model.CBOM{Version: "1.6"})
			require.NoError(t, err)

			first := model.Detection{
				Source:     "PKCS12",
				Location:   "/etc/ssl/store.p12",
				Components: []cdx.Component{tt.stored},
			}

			require.NotPanics(t, func() {
				builder.AppendDetections(t.Context(), first,
					publicKeyDetection("PEM", "/etc/ssl/certs/ca.pem", "PEM"))
			})

			require.Len(t, builder.components, 1)
			stored := builder.components[sharedKeyRef]
			require.NotNil(t, stored)
			if !tt.wantProps {
				if stored.CryptoProperties != nil {
					require.Nil(t, stored.CryptoProperties.RelatedCryptoMaterialProperties,
						"relatedCryptoMaterialProperties describes a serialised object "+
							"and must not be invented on a %s asset (#213)",
						stored.CryptoProperties.AssetType)
				}
				return
			}
			require.NotNil(t, stored.CryptoProperties)
			require.NotNil(t, stored.CryptoProperties.RelatedCryptoMaterialProperties)
			require.Equal(t, tt.wantFormat,
				stored.CryptoProperties.RelatedCryptoMaterialProperties.Format)
		})
	}
}

// TestAppendDetection_ConflictingFormatsResolveDeterministically covers two
// differing non-empty formats on one ref: both orders must land on the same
// value and both must report the disagreement. No producer can reach this today;
// mergeRelatedCryptoMaterialFormat says why the tie-break exists anyway.
func TestAppendDetection_ConflictingFormatsResolveDeterministically(t *testing.T) {
	orders := [][2]string{{"DER", "PEM"}, {"PEM", "DER"}}

	for _, order := range orders {
		t.Run(order[0]+" then "+order[1], func(t *testing.T) {
			var logBuf bytes.Buffer
			restore := slog.Default()
			slog.SetDefault(slog.New(slog.NewTextHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelWarn})))
			t.Cleanup(func() { slog.SetDefault(restore) })

			builder, err := NewBuilder(model.CBOM{Version: "1.6"})
			require.NoError(t, err)

			builder.AppendDetections(t.Context(),
				publicKeyDetection("PKCS12", "/etc/ssl/store.p12", order[0]),
				publicKeyDetection("PEM", "/etc/ssl/certs/ca.pem", order[1]))

			stored := builder.components[sharedKeyRef]
			require.NotNil(t, stored)
			require.Equal(t, "DER", stored.CryptoProperties.RelatedCryptoMaterialProperties.Format,
				"the tie-break must not depend on which detection arrived first")

			logged := logBuf.String()
			require.Contains(t, logged, "detections disagree on the format of one component")
			require.Contains(t, logged, "ref="+sharedKeyRef)
			require.Contains(t, logged, "kept=DER")
			require.Contains(t, logged, "discarded=PEM")
		})
	}
}

// TestAppendDetection_AgreeingFormatsAreNotReportedAsDisagreement pins the
// no-op arm, which the tie-break silently swallows: min("PEM","PEM") is "PEM",
// so deleting `case format: return` leaves every emitted document byte-identical
// and only the log changes. That log is the whole point -- "detections disagree
// on the format of one component" is a claim that a producer is broken, and the
// case it would fire on is the ordinary one: the same CA key shipped in two
// .pem files under /etc/ssl/certs, where both detections come from PEMBundle
// and both carry setPEMFormat's single constant. A warning on the common path
// is a warning nobody reads.
func TestAppendDetection_AgreeingFormatsAreNotReportedAsDisagreement(t *testing.T) {
	var logBuf bytes.Buffer
	restore := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelWarn})))
	t.Cleanup(func() { slog.SetDefault(restore) })

	builder, err := NewBuilder(model.CBOM{Version: "1.6"})
	require.NoError(t, err)

	builder.AppendDetections(t.Context(),
		publicKeyDetection("PEM", "/etc/ssl/certs/ca.pem", "PEM"),
		publicKeyDetection("PEM", "/etc/ssl/certs/ca-bundle.pem", "PEM"))

	stored := builder.components[sharedKeyRef]
	require.NotNil(t, stored)
	require.Equal(t, "PEM", stored.CryptoProperties.RelatedCryptoMaterialProperties.Format)

	require.NotContains(t, logBuf.String(), "detections disagree",
		"two detections carrying the same format agree; reporting them as a "+
			"conflict would fire on every key found in two PEM files")
}

// TestBuilder_AppendDetections_FormatSurvivesEveryArrivalPermutation raises the
// order-independence claim from a pair to a set. Its sibling proves the merge
// survives ONE reordering, which a merge that simply preferred the later
// detection would also pass; three arrivals with the format in the middle
// distinguish first-wins, last-wins and set semantics, and only set semantics
// gives the same answer for all six permutations.
//
// Three is not a contrived count: one host key routinely appears as
// /etc/ssl/certs/ca.pem, inside a PKCS#12 store and inside a JKS truststore, and
// only the first of those reaches setPEMFormat.
func TestBuilder_AppendDetections_FormatSurvivesEveryArrivalPermutation(t *testing.T) {
	arrivals := []model.Detection{
		publicKeyDetection("PKCS12", "/etc/ssl/store.p12", ""),
		publicKeyDetection("PEM", "/etc/ssl/certs/ca.pem", "PEM"),
		publicKeyDetection("JKS", "/etc/ssl/truststore.jks", ""),
	}

	// Written out rather than generated: the point of the test is that every
	// arrangement is checked, and a permutation generator with an off-by-one
	// would quietly check fewer.
	permutations := [][3]int{
		{0, 1, 2}, {0, 2, 1}, {1, 0, 2}, {1, 2, 0}, {2, 0, 1}, {2, 1, 0},
	}

	for _, p := range permutations {
		name := fmt.Sprintf("%d%d%d", p[0], p[1], p[2])
		t.Run(name, func(t *testing.T) {
			builder, err := NewBuilder(model.CBOM{Version: "1.6"})
			require.NoError(t, err)

			// Rebuilt per permutation: the merge writes through a pointer the
			// caller's model.Detection still holds (see the last paragraph of
			// mergeRelatedCryptoMaterialFormat), so reusing one arrivals slice
			// across subtests would let permutation 012 seed 021.
			ordered := make([]model.Detection, 0, len(p))
			for _, i := range p {
				d := arrivals[i]
				ordered = append(ordered, publicKeyDetection(d.Source, d.Location,
					d.Components[0].CryptoProperties.RelatedCryptoMaterialProperties.Format))
			}
			builder.AppendDetections(t.Context(), ordered...)

			require.Len(t, builder.components, 1)
			stored := builder.components[sharedKeyRef]
			require.NotNil(t, stored)
			require.NotNil(t, stored.CryptoProperties.RelatedCryptoMaterialProperties)
			require.Equal(t, "PEM",
				stored.CryptoProperties.RelatedCryptoMaterialProperties.Format,
				"the one detection that knows the encoding must win from any position")

			require.NotNil(t, stored.Evidence)
			require.NotNil(t, stored.Evidence.Occurrences)
			require.Equal(t, []cdx.EvidenceOccurrence{
				{Location: "/etc/ssl/certs/ca.pem"},
				{Location: "/etc/ssl/store.p12"},
				{Location: "/etc/ssl/truststore.jks"},
			}, *stored.Evidence.Occurrences,
				"the merge runs before addEvidenceLocation and must not disturb it")
		})
	}
}

// TestBuilder_AppendDetections_EmittedDocumentIsOrderIndependent states the
// invariant where the user meets it: the delivered JSON, not builder.components.
// Comparing the whole encoded document catches a merge that fixes format while
// perturbing something else -- evidence.occurrences order, a dropped field, an
// extra property -- which an assertion on one field cannot.
//
// It goes through AsJSON rather than BOM so the reordered document is also put
// through schema validation, and it fixes the clock and the serial because those
// are the only two intentionally non-reproducible parts of the output
// (TestBuilder_BOMDeterministic uses the same pair for the same reason).
func TestBuilder_AppendDetections_EmittedDocumentIsOrderIndependent(t *testing.T) {
	fixed := time.Date(2024, 1, 2, 3, 4, 5, 0, time.UTC)
	render := func(t *testing.T, detections ...model.Detection) string {
		t.Helper()

		b, err := NewBuilder(model.CBOM{Version: "1.6"})
		require.NoError(t, err)
		b = b.WithClock(func() time.Time { return fixed }).
			WithSerial(func() string { return "urn:uuid:22222222-2222-2222-2222-222222222222" })
		b.AppendDetections(t.Context(), detections...)

		var buf bytes.Buffer
		require.NoError(t, b.AsJSON(t.Context(), &buf))
		return buf.String()
	}

	pemFirst := render(t,
		publicKeyDetection("PEM", "/etc/ssl/certs/ca.pem", "PEM"),
		publicKeyDetection("PKCS12", "/etc/ssl/store.p12", ""))
	storeFirst := render(t,
		publicKeyDetection("PKCS12", "/etc/ssl/store.p12", ""),
		publicKeyDetection("PEM", "/etc/ssl/certs/ca.pem", "PEM"))

	require.Equal(t, pemFirst, storeFirst,
		"two scans that found the same key in the same two places must deliver "+
			"byte-identical CBOMs regardless of which scanner reported first")
	require.Contains(t, pemFirst, `"format": "PEM"`,
		"a document with no format at all would satisfy the equality above "+
			"while still having lost what the PEM detection knew")
}

// TestAppendDetection_FormatIsNeverInventedOnNonMaterialAssets widens the #213
// gate past the one asset type its sibling checks. #213 was a blanket
// format=PEM loop that made 20 of 32 assets in a real scan answer "yes" to "is
// this key material?", and re-deriving the gate as an algorithm-only deny-list
// -- the obvious simplification, since algorithm is the family that actually
// collided -- would reintroduce it on certificates and protocols while leaving
// the sibling green.
//
// The bare component pins the other half: cryptoProperties carries the
// assetType, so inventing one here would assign an asset type no producer chose.
// setPEMFormat refuses for the same reason.
func TestAppendDetection_FormatIsNeverInventedOnNonMaterialAssets(t *testing.T) {
	tests := []struct {
		name   string
		stored cdx.Component
	}{
		{
			name: "certificate",
			stored: cdx.Component{
				BOMRef: sharedKeyRef,
				Name:   "example.com",
				Type:   cdx.ComponentTypeCryptographicAsset,
				CryptoProperties: &cdx.CryptoProperties{
					AssetType: cdx.CryptoAssetTypeCertificate,
				},
			},
		},
		{
			name: "protocol",
			stored: cdx.Component{
				BOMRef: sharedKeyRef,
				Name:   "TLSv1.3",
				Type:   cdx.ComponentTypeCryptographicAsset,
				CryptoProperties: &cdx.CryptoProperties{
					AssetType: cdx.CryptoAssetTypeProtocol,
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			builder, err := NewBuilder(model.CBOM{Version: "1.6"})
			require.NoError(t, err)

			builder.AppendDetections(t.Context(),
				model.Detection{
					Source:     "NMAP",
					Location:   "tcp://localhost:443",
					Components: []cdx.Component{tt.stored},
				},
				publicKeyDetection("PEM", "/etc/ssl/certs/ca.pem", "PEM"))

			stored := builder.components[sharedKeyRef]
			require.NotNil(t, stored)
			require.NotNil(t, stored.CryptoProperties)
			require.Equal(t, tt.stored.CryptoProperties.AssetType,
				stored.CryptoProperties.AssetType,
				"the merge must not restate the asset type either")
			require.Nil(t, stored.CryptoProperties.RelatedCryptoMaterialProperties,
				"relatedCryptoMaterialProperties describes a serialised object and "+
					"must not appear on a %s asset (#213)", tt.name)
		})
	}

	t.Run("no cryptoProperties at all", func(t *testing.T) {
		builder, err := NewBuilder(model.CBOM{Version: "1.6"})
		require.NoError(t, err)

		builder.AppendDetections(t.Context(),
			model.Detection{
				Source:   "LEAKS",
				Location: "/srv/app/config.yaml",
				Components: []cdx.Component{{
					BOMRef: sharedKeyRef,
					Name:   "RSA-2048",
					Type:   cdx.ComponentTypeLibrary,
				}},
			},
			publicKeyDetection("PEM", "/etc/ssl/certs/ca.pem", "PEM"))

		stored := builder.components[sharedKeyRef]
		require.NotNil(t, stored)
		require.Nil(t, stored.CryptoProperties,
			"cryptoProperties carries the assetType, so allocating one here "+
				"would invent an asset type no producer chose")
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

		builder.components["comp-1"] = &cdx.Component{BOMRef: "comp-1", Name: "test1", Type: cdx.ComponentTypeCryptographicAsset}
		builder.components["comp-2"] = &cdx.Component{BOMRef: "comp-2", Name: "test2", Type: cdx.ComponentTypeCryptographicAsset}

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

		builder.components["comp-1"] = &cdx.Component{BOMRef: "comp-1", Name: "test1", Type: cdx.ComponentTypeCryptographicAsset}
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
		b.components["b@2"] = &cdx.Component{BOMRef: "b@2", Name: "b", Type: cdx.ComponentTypeCryptographicAsset}
		b.components["a@1"] = &cdx.Component{BOMRef: "a@1", Name: "a", Type: cdx.ComponentTypeCryptographicAsset}
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
		b.components["b@2"] = &cdx.Component{BOMRef: "b@2", Name: "b", Type: cdx.ComponentTypeCryptographicAsset}
		b.components["a@1"] = &cdx.Component{BOMRef: "a@1", Name: "a", Type: cdx.ComponentTypeCryptographicAsset}
		b.components["c@3"] = &cdx.Component{BOMRef: "c@3", Name: "c", Type: cdx.ComponentTypeCryptographicAsset}
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
		b.components["a@1"] = &cdx.Component{BOMRef: "a@1", Name: "a", Type: cdx.ComponentTypeCryptographicAsset}
		b.dependencies["a@1"] = nil

		m := b.model(context.Background())
		require.Empty(t, m.Rels)

		bom := b.BOM(context.Background())
		require.Empty(t, *bom.Dependencies)
	})

	t.Run("empty dependsOn entry is omitted", func(t *testing.T) {
		b, err := NewBuilder(model.CBOM{Version: "1.6"})
		require.NoError(t, err)
		b.components["a@1"] = &cdx.Component{BOMRef: "a@1", Name: "a", Type: cdx.ComponentTypeCryptographicAsset}
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
		b.components["a@1"] = &cdx.Component{BOMRef: "a@1", Name: "a", Type: cdx.ComponentTypeCryptographicAsset}
		b.components["b@2"] = &cdx.Component{BOMRef: "b@2", Name: "b", Type: cdx.ComponentTypeCryptographicAsset}
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

	b.components["sig@raw"] = &cdx.Component{BOMRef: "sig@raw", Name: "sig", Type: cdx.ComponentTypeCryptographicAsset}
	b.components["key@raw"] = &cdx.Component{BOMRef: "key@raw", Name: "key", Type: cdx.ComponentTypeCryptographicAsset}
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

// relsOfKind filters m.Rels by kind.
func relsOfKind(m cbom.BOMModel, kind cbom.RelationshipKind) []cbom.Relationship {
	var out []cbom.Relationship
	for _, r := range m.Rels {
		if r.Kind == kind {
			out = append(out, r)
		}
	}
	return out
}

func TestBuilder_ModelExtractsCryptoRels(t *testing.T) {
	newB := func() *Builder {
		b, err := NewBuilder(model.CBOM{Version: "1.6"})
		require.NoError(t, err)
		b.components["alg@raw"] = &cdx.Component{BOMRef: "alg@raw", Name: "alg", Type: cdx.ComponentTypeCryptographicAsset}
		b.components["key@raw"] = &cdx.Component{BOMRef: "key@raw", Name: "key", Type: cdx.ComponentTypeCryptographicAsset}
		return b
	}

	t.Run("certificate refs become sig-alg and subject-public-key rels", func(t *testing.T) {
		b := newB()
		b.components["cert@raw"] = &cdx.Component{
			BOMRef: "cert@raw", Name: "cert",
			CryptoProperties: &cdx.CryptoProperties{
				CertificateProperties: &cdx.CertificateProperties{
					SignatureAlgorithmRef: cdx.BOMReference("alg@raw"),
					SubjectPublicKeyRef:   cdx.BOMReference("key@raw"),
				},
			},
		}
		m := b.model(context.Background())

		sig := relsOfKind(m, cbom.RelSignatureAlgorithm)
		pub := relsOfKind(m, cbom.RelSubjectPublicKey)
		require.Len(t, sig, 1)
		require.Len(t, pub, 1)
		require.Equal(t, cbom.AssetRef(safeRef("cert@raw")), sig[0].From)
		require.Equal(t, cbom.AssetRef(safeRef("alg@raw")), sig[0].To)
		require.Equal(t, cbom.AssetRef(safeRef("key@raw")), pub[0].To)
	})

	t.Run("material algorithmRef becomes material-algorithm rel", func(t *testing.T) {
		b := newB()
		b.components["mat@raw"] = &cdx.Component{
			BOMRef: "mat@raw", Name: "mat",
			CryptoProperties: &cdx.CryptoProperties{
				RelatedCryptoMaterialProperties: &cdx.RelatedCryptoMaterialProperties{
					AlgorithmRef: cdx.BOMReference("alg@raw"),
				},
			},
		}
		m := b.model(context.Background())
		rels := relsOfKind(m, cbom.RelMaterialAlgorithm)
		require.Len(t, rels, 1)
		require.Equal(t, cbom.AssetRef(safeRef("alg@raw")), rels[0].To)
	})

	t.Run("cryptoRefArray becomes protocol-crypto rels preserving order", func(t *testing.T) {
		b := newB()
		refs := []cdx.BOMReference{"alg@raw", "key@raw"}
		b.components["proto@raw"] = &cdx.Component{
			BOMRef: "proto@raw", Name: "proto",
			CryptoProperties: &cdx.CryptoProperties{
				ProtocolProperties: &cdx.CryptoProtocolProperties{CryptoRefArray: &refs},
			},
		}
		m := b.model(context.Background())
		rels := relsOfKind(m, cbom.RelProtocolCrypto)
		require.Len(t, rels, 2)
		require.Equal(t, cbom.AssetRef(safeRef("alg@raw")), rels[0].To)
		require.Equal(t, cbom.AssetRef(safeRef("key@raw")), rels[1].To)
	})

	t.Run("dangling crypto ref is dropped, not minted", func(t *testing.T) {
		b := newB()
		b.components["cert@raw"] = &cdx.Component{
			BOMRef: "cert@raw", Name: "cert",
			CryptoProperties: &cdx.CryptoProperties{
				CertificateProperties: &cdx.CertificateProperties{
					SignatureAlgorithmRef: cdx.BOMReference("ghost@raw"),
				},
			},
		}
		m := b.model(context.Background())
		require.Empty(t, relsOfKind(m, cbom.RelSignatureAlgorithm))
	})

	t.Run("already-canonical ref resolves via identity", func(t *testing.T) {
		// model() mutates shared nested pointers on first run (pre-existing
		// quirk): a second run sees already-canonical refs. They must still
		// resolve, keeping model() idempotent for crypto rels.
		b := newB()
		b.components["cert@raw"] = &cdx.Component{
			BOMRef: "cert@raw", Name: "cert",
			CryptoProperties: &cdx.CryptoProperties{
				CertificateProperties: &cdx.CertificateProperties{
					SignatureAlgorithmRef: cdx.BOMReference("alg@raw"),
				},
			},
		}
		first := b.model(context.Background())
		second := b.model(context.Background())
		require.Equal(t, relsOfKind(first, cbom.RelSignatureAlgorithm),
			relsOfKind(second, cbom.RelSignatureAlgorithm))
	})
}

// TestAsJSON_RefusesInvalidDocument proves the validator is on the emit path
// and not merely available. 1.7's registry fields are closed enumerations and
// CBOM-Lens is the only producer emitting them, so an out-of-vocabulary value
// would reach consumers unchallenged; AsJSON is the last place to stop it.
func TestAsJSON_RefusesInvalidDocument(t *testing.T) {
	for _, version := range []string{"1.6", "1.7"} {
		t.Run(version, func(t *testing.T) {
			b, err := NewBuilder(model.CBOM{Version: version})
			require.NoError(t, err)

			// assetType is a closed enum in both versions, so this is invalid
			// for either schema without depending on a 1.7-only field.
			b.components["crypto/algorithm/bogus@0"] = &cdx.Component{
				Type:   cdx.ComponentTypeCryptographicAsset,
				Name:   "bogus",
				BOMRef: "crypto/algorithm/bogus@0",
				CryptoProperties: &cdx.CryptoProperties{
					AssetType: cdx.CryptoAssetType("not-a-real-asset-type"),
				},
			}

			var buf bytes.Buffer
			err = b.AsJSON(t.Context(), &buf)
			require.Error(t, err, "an invalid document must not be emitted")
			require.Contains(t, err.Error(), "refusing to emit")
			require.Zero(t, buf.Len(), "nothing may be written when validation fails")
		})
	}
}

// TestAsJSON_EmitsValidDocument is the positive half: the guard must not reject
// what the emitters actually produce.
func TestAsJSON_EmitsValidDocument(t *testing.T) {
	for _, version := range []string{"1.6", "1.7"} {
		t.Run(version, func(t *testing.T) {
			b, err := NewBuilder(model.CBOM{Version: version})
			require.NoError(t, err)
			var buf bytes.Buffer
			require.NoError(t, b.AsJSON(t.Context(), &buf))
			require.NotZero(t, buf.Len())
		})
	}
}

// TestValidateAs_RejectsVersionMismatch pins the declared-version check.
//
// The check is defence in depth rather than a reachable path: AsJSON derives
// both the emitter and the expected version from b.version, so the two cannot
// currently disagree. It exists because they are independent concepts -- the
// emitter decides what specVersion to write, the Builder decides what to
// validate against -- and cbom-repository rejects any upload where the declared
// version and the document's specVersion differ. Exercised directly, since the
// Builder offers no way to construct the mismatch.
func TestValidateAs_RejectsVersionMismatch(t *testing.T) {
	b, err := NewBuilder(model.CBOM{Version: "1.7"})
	require.NoError(t, err)

	doc := []byte(`{"bomFormat":"CycloneDX","specVersion":"1.6","version":1}`)
	err = b.validateAs(cdx.SpecVersion1_7, doc)
	require.Error(t, err)
	require.Contains(t, err.Error(), "builder is 1.7 but the document declares 1.6")
}

// TestValidateAs_RejectsUnreadableSpecVersion covers the payload that is not
// JSON at all, so the failure names the cause instead of surfacing as a schema
// error.
func TestValidateAs_RejectsUnreadableSpecVersion(t *testing.T) {
	b, err := NewBuilder(model.CBOM{Version: "1.7"})
	require.NoError(t, err)

	err = b.validateAs(cdx.SpecVersion1_7, []byte("not json"))
	require.Error(t, err)
	require.Contains(t, err.Error(), "reading specVersion")
}

// TestAppendDetection_DropsAndLogsUnidentifiableComponent pins the drop that
// used to be silent.
//
// A component with no bom-ref cannot be stored (the map is keyed by ref) and
// one with no name is unreadable in the emitted document, so both are dropped.
// That is correct; doing it without a word in the log is not. csrToCDX and
// crlToCDX produced refless components, so scanning a .csr or a .crl reported
// nothing and exited 0, and nothing in the run said an asset had been thrown
// away. The warning names which half of the identity is missing, so it says
// what is wrong with the component rather than reading as a Builder failure.
//
// The "neither" case is why the line carries more than name and ref: with both
// empty those two fields are empty strings and the warning identified nothing
// at all. Type, asset type and description are what remain.
func TestAppendDetection_DropsAndLogsUnidentifiableComponent(t *testing.T) {
	tests := []struct {
		name       string
		component  cdx.Component
		wantReason string
	}{
		{
			name: "no bom-ref",
			component: cdx.Component{
				Name:        "CSR: Test CSR",
				Type:        cdx.ComponentTypeCryptographicAsset,
				Description: "Certificate Signing Request",
				CryptoProperties: &cdx.CryptoProperties{
					AssetType: cdx.CryptoAssetTypeRelatedCryptoMaterial,
				},
			},
			wantReason: "no bom-ref",
		},
		{
			name: "no name",
			component: cdx.Component{
				BOMRef:      "crypto/csr/x@sha256:abc",
				Type:        cdx.ComponentTypeCryptographicAsset,
				Description: "Certificate Signing Request",
				CryptoProperties: &cdx.CryptoProperties{
					AssetType: cdx.CryptoAssetTypeRelatedCryptoMaterial,
				},
			},
			wantReason: "no name",
		},
		{
			name: "neither",
			component: cdx.Component{
				Type:        cdx.ComponentTypeCryptographicAsset,
				Description: "Certificate Signing Request",
				CryptoProperties: &cdx.CryptoProperties{
					AssetType: cdx.CryptoAssetTypeRelatedCryptoMaterial,
				},
			},
			wantReason: "no bom-ref and no name",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var logBuf bytes.Buffer
			restore := slog.Default()
			slog.SetDefault(slog.New(slog.NewTextHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelWarn})))
			t.Cleanup(func() { slog.SetDefault(restore) })

			b, err := NewBuilder(model.CBOM{Version: "1.6"})
			require.NoError(t, err)

			b.AppendDetections(context.Background(), model.Detection{
				Source:     "PEM",
				Type:       model.DetectionTypePEM,
				Location:   "/test/bundle.pem",
				Components: []cdx.Component{tt.component},
			})

			require.Empty(t, b.components, "an unidentifiable component must not be stored")

			logged := logBuf.String()
			require.Contains(t, logged, "dropping component: cannot be identified",
				"the drop must be visible at Warn: an operator has to be able to "+
					"explain a missing asset in a delivered BOM")
			require.Contains(t, logged, `reason="`+tt.wantReason+`"`)
			require.Contains(t, logged, "detection.source=PEM")
			require.Contains(t, logged, "detection.location=/test/bundle.pem")

			// What the component IS, which is all a reader has for the case
			// where name and ref are both empty.
			require.Contains(t, logged, "component.type=cryptographic-asset")
			require.Contains(t, logged, "component.asset_type=related-crypto-material")
			require.Contains(t, logged, `component.description="Certificate Signing Request"`)
		})
	}
}

// TestAppendDetection_DropWarningSurvivesNilCryptoProperties guards the nil
// dereference the added asset-type field would otherwise be.
//
// CryptoProperties is a pointer and plenty of components have none -- a plain
// library component, or any component built by a producer that failed early.
// Reading AssetType off it unguarded would turn a warning about a dropped
// component into a panic that takes the whole scan down, which is the same
// class of defect as the zero public-key component that once crashed
// restOfPEMBundleToCDX.
func TestAppendDetection_DropWarningSurvivesNilCryptoProperties(t *testing.T) {
	var logBuf bytes.Buffer
	restore := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelWarn})))
	t.Cleanup(func() { slog.SetDefault(restore) })

	b, err := NewBuilder(model.CBOM{Version: "1.6"})
	require.NoError(t, err)

	require.NotPanics(t, func() {
		b.AppendDetections(context.Background(), model.Detection{
			Source:     "LEAKS",
			Type:       model.DetectionTypeLeakPrivateKey,
			Location:   "/test/secrets.env",
			Components: []cdx.Component{{Type: cdx.ComponentTypeLibrary}},
		})
	})

	require.Contains(t, logBuf.String(), "dropping component: cannot be identified")
	require.Empty(t, b.components)
}

// The tests below pin one property: nothing the Builder does after
// AppendDetections returns is observable through the model.Detection the caller
// handed it.
//
// appendDetection used to store a shallow struct copy of each cdx.Component,
// which shares every pointer field with the caller's memory, and four separate
// Builder writes then reached back through those pointers: addEvidenceLocation
// replaced the caller's evidence.occurrences (dropping the line number gitleaks
// had recorded), mergeRelatedCryptoMaterialFormat wrote -- and on one arm
// allocated -- the caller's relatedCryptoMaterialProperties, and the bom-ref
// canonicalisation replaceBOMReferences performs on every BOM()/AsJSON() call
// rewrote the caller's reference fields, including ones no comment named.
// cmd/cbom-lens drains detections and drops them, so no shipped path observed
// it; the property is pinned anyway, because "the Builder does not write
// through its input" is what makes a Detection safe to hold on to, log, assert
// on or feed to a second Builder.
//
// They are deliberately four tests and not one. A clone that forgets Evidence,
// or forgets securedBy, must fail exactly one of them and name the field it
// forgot -- a single end-to-end assertion would only say "the detection
// changed".

// TestAppendDetection_DoesNotMutateCallerEvidence targets addEvidenceLocation,
// which allocates an Evidence only when the component has none. Converter.Leak
// (internal/cdxprops/leaks.go) always brings its own, carrying the finding's
// start line, so the allocation is skipped and the occurrence-set rebuild lands
// on the caller's struct.
//
// The first case is the shape Leak actually produces -- Detection.Location and
// the occurrence's Location are both leaks.Location, so the rebuilt set has the
// same single entry and only the line number silently disappears. The second
// case is the one where the caller's slice visibly grows.
func TestAppendDetection_DoesNotMutateCallerEvidence(t *testing.T) {
	const leakLocation = "/src/config.yaml"

	tests := []struct {
		name              string
		detectionLocation string
		wantStored        []string
	}{
		{
			name:              "detection reports the occurrence's own file",
			detectionLocation: leakLocation,
			wantStored:        []string{leakLocation},
		},
		{
			name:              "detection reports a second file",
			detectionLocation: "/src/config.yaml.bak",
			// addEvidenceLocation emits the location set in sorted order.
			wantStored: []string{leakLocation, "/src/config.yaml.bak"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			line := 42
			detection := model.Detection{
				Source:   "LEAKS",
				Type:     model.DetectionTypeLeakPrivateKey,
				Location: tt.detectionLocation,
				Components: []cdx.Component{{
					BOMRef: sharedKeyRef,
					Name:   "private-key",
					Type:   cdx.ComponentTypeCryptographicAsset,
					Evidence: &cdx.Evidence{
						Occurrences: &[]cdx.EvidenceOccurrence{
							{Location: leakLocation, Line: &line},
						},
					},
				}},
			}

			b, err := NewBuilder(model.CBOM{Version: "1.6"})
			require.NoError(t, err)
			b.AppendDetections(t.Context(), detection)

			callerEvidence := detection.Components[0].Evidence
			require.NotNil(t, callerEvidence.Occurrences)
			require.Len(t, *callerEvidence.Occurrences, 1,
				"the Builder's own evidence locations must not appear in the caller's component")
			caller := (*callerEvidence.Occurrences)[0]
			require.Equal(t, leakLocation, caller.Location)
			require.NotNil(t, caller.Line,
				"addEvidenceLocation rebuilds occurrences from locations alone, so "+
					"writing through the caller's Evidence erases the finding's line number")
			require.Equal(t, 42, *caller.Line)

			// The Builder must still do its job on its own copy: isolating the
			// caller is worthless if it also stops evidence being recorded.
			stored := b.components[sharedKeyRef]
			require.NotNil(t, stored)
			require.NotSame(t, callerEvidence, stored.Evidence,
				"the stored component must own its Evidence struct")
			var storedLocations []string
			for _, occ := range *stored.Evidence.Occurrences {
				storedLocations = append(storedLocations, occ.Location)
			}
			require.Equal(t, tt.wantStored, storedLocations)
		})
	}
}

// TestAppendDetection_MergeDoesNotMutateFirstDetection targets
// mergeRelatedCryptoMaterialFormat, which runs only when a second detection
// collides on a stored bom-ref and writes format into the STORED component --
// which, before the clone, was the first detection's own
// relatedCryptoMaterialProperties.
//
// The second case forces the allocating arm: with the struct absent the merge
// assigns a fresh one onto stored.CryptoProperties, so the leak is not a
// changed string but a caller pointer that turns non-nil, and the caller's
// component acquires a sub-struct describing a serialisation it never saw.
func TestAppendDetection_MergeDoesNotMutateFirstDetection(t *testing.T) {
	tests := []struct {
		name         string
		withMaterial bool
	}{
		{name: "format is written on the stored copy only", withMaterial: true},
		{name: "the allocating arm allocates on the stored copy only", withMaterial: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cp := &cdx.CryptoProperties{AssetType: cdx.CryptoAssetTypeRelatedCryptoMaterial}
			if tt.withMaterial {
				cp.RelatedCryptoMaterialProperties = &cdx.RelatedCryptoMaterialProperties{
					Type: cdx.RelatedCryptoMaterialTypePublicKey,
				}
			}
			first := model.Detection{
				Source:   "PKCS12",
				Location: "/etc/ssl/store.p12",
				Components: []cdx.Component{{
					BOMRef:           sharedKeyRef,
					Name:             "RSA-2048",
					Type:             cdx.ComponentTypeCryptographicAsset,
					CryptoProperties: cp,
				}},
			}

			b, err := NewBuilder(model.CBOM{Version: "1.6"})
			require.NoError(t, err)
			b.AppendDetections(t.Context(), first,
				publicKeyDetection("PEM", "/etc/ssl/certs/ca.pem", "PEM"))

			callerProps := first.Components[0].CryptoProperties.RelatedCryptoMaterialProperties
			if tt.withMaterial {
				require.NotNil(t, callerProps)
				require.Empty(t, callerProps.Format,
					"the PKCS#12 detection never knew an encoding; the PEM detection's "+
						"format belongs to the merged component, not to it")
			} else {
				require.Nil(t, callerProps,
					"the merge allocates the struct it needs on the Builder's copy, "+
						"not on the detection that arrived without one")
			}

			// The merge itself must still happen, or this test would pass on a
			// Builder that simply stopped merging.
			stored := b.components[sharedKeyRef]
			require.NotNil(t, stored)
			require.NotNil(t, stored.CryptoProperties.RelatedCryptoMaterialProperties)
			require.Equal(t, "PEM", stored.CryptoProperties.RelatedCryptoMaterialProperties.Format)
		})
	}
}

// componentByRef returns the emitted component with the given bom-ref, failing
// the test if the document does not carry one.
func componentByRef(t *testing.T, bom cdx.BOM, ref string) cdx.Component {
	t.Helper()
	require.NotNil(t, bom.Components)
	for _, c := range *bom.Components {
		if c.BOMRef == ref {
			return c
		}
	}
	require.FailNowf(t, "component not emitted", "no component with bom-ref %q", ref)
	return cdx.Component{}
}

// TestBuilder_BOMDoesNotMutateCallerRefs targets the widest writer of the four:
// safeRefs.component -> replaceBOMReferences, a reflect walk that rewrites every
// cdx.BOMReference-typed struct field in place, on every stored component, on
// every BOM() call. It is the only writer that fires without a second detection
// and without pre-set evidence, so a caller that appends one detection and never
// touches the Builder again still saw its raw refs replaced by UUID ones the
// moment the document was rendered.
//
// securedBy.algorithmRef is here because it is reachable and was named in no
// comment: it sits two structs below cryptoProperties and a clone that stopped
// at relatedCryptoMaterialProperties would leave it aliased. The ikev2 subtest
// is the same story one level deeper -- the transform-type structs each carry a
// BOMRef field, so the walk descends into the caller's *[]IKEv2Enc backing
// array. No producer in this repo emits ikev2TransformTypes today, which is
// precisely why nothing would have noticed.
func TestBuilder_BOMDoesNotMutateCallerRefs(t *testing.T) {
	const (
		algRef   = "crypto/algorithm/sha-256-rsa@0"
		keyRef   = "crypto/key/rsa-2048@0"
		certRef  = "crypto/certificate/leaf@0"
		matRef   = "crypto/key/wrapped@0"
		protoRef = "crypto/protocol/ike@0"
	)

	// The referenced components must be stored too: safeRefs only carries
	// entries for components the Builder knows, so without them the walk would
	// find nothing to substitute and the test would pass on the broken Builder.
	targets := func() []cdx.Component {
		return []cdx.Component{
			{BOMRef: algRef, Name: "sha-256-rsa", Type: cdx.ComponentTypeCryptographicAsset},
			{BOMRef: keyRef, Name: "rsa-2048", Type: cdx.ComponentTypeCryptographicAsset},
		}
	}

	t.Run("certificate, material and securedBy refs", func(t *testing.T) {
		detection := model.Detection{
			Source:   "PEM",
			Location: "/etc/ssl/certs/ca.pem",
			Components: append(targets(),
				cdx.Component{
					BOMRef: certRef, Name: "leaf", Type: cdx.ComponentTypeCryptographicAsset,
					CryptoProperties: &cdx.CryptoProperties{
						AssetType: cdx.CryptoAssetTypeCertificate,
						CertificateProperties: &cdx.CertificateProperties{
							SignatureAlgorithmRef: cdx.BOMReference(algRef),
							SubjectPublicKeyRef:   cdx.BOMReference(keyRef),
						},
					},
				},
				cdx.Component{
					BOMRef: matRef, Name: "wrapped", Type: cdx.ComponentTypeCryptographicAsset,
					CryptoProperties: &cdx.CryptoProperties{
						AssetType: cdx.CryptoAssetTypeRelatedCryptoMaterial,
						RelatedCryptoMaterialProperties: &cdx.RelatedCryptoMaterialProperties{
							Type:         cdx.RelatedCryptoMaterialTypePrivateKey,
							AlgorithmRef: cdx.BOMReference(algRef),
							SecuredBy: &cdx.SecuredBy{
								Mechanism:    "PBKDF2",
								AlgorithmRef: cdx.BOMReference(algRef),
							},
						},
					},
				}),
		}

		b, err := NewBuilder(model.CBOM{Version: "1.6"})
		require.NoError(t, err)
		b.AppendDetections(t.Context(), detection)
		bom := b.BOM(t.Context())

		certProps := detection.Components[2].CryptoProperties.CertificateProperties
		require.Equal(t, cdx.BOMReference(algRef), certProps.SignatureAlgorithmRef,
			"rendering a document must not renumber the caller's certificate refs")
		require.Equal(t, cdx.BOMReference(keyRef), certProps.SubjectPublicKeyRef)

		matProps := detection.Components[3].CryptoProperties.RelatedCryptoMaterialProperties
		require.Equal(t, cdx.BOMReference(algRef), matProps.AlgorithmRef)
		require.NotNil(t, matProps.SecuredBy)
		require.Equal(t, cdx.BOMReference(algRef), matProps.SecuredBy.AlgorithmRef,
			"securedBy sits two structs deep; a clone that stops at "+
				"relatedCryptoMaterialProperties leaves it aliased")

		// Canonicalisation must still reach the document, or the refs it emits
		// would dangle against the renamed components.
		emittedCert := componentByRef(t, bom, safeRef(certRef))
		require.Equal(t, cdx.BOMReference(safeRef(algRef)),
			emittedCert.CryptoProperties.CertificateProperties.SignatureAlgorithmRef)
		require.Equal(t, cdx.BOMReference(safeRef(keyRef)),
			emittedCert.CryptoProperties.CertificateProperties.SubjectPublicKeyRef)

		emittedMat := componentByRef(t, bom, safeRef(matRef))
		emittedProps := emittedMat.CryptoProperties.RelatedCryptoMaterialProperties
		require.Equal(t, cdx.BOMReference(safeRef(algRef)), emittedProps.AlgorithmRef)
		require.NotNil(t, emittedProps.SecuredBy)
		require.Equal(t, cdx.BOMReference(safeRef(algRef)), emittedProps.SecuredBy.AlgorithmRef)
	})

	t.Run("ikev2 transform type refs", func(t *testing.T) {
		encr := []cdx.IKEv2Enc{{BOMRef: cdx.BOMReference(algRef), Name: "aes"}}
		prf := []cdx.IKEv2Prf{{BOMRef: cdx.BOMReference(algRef), Name: "prf"}}
		integ := []cdx.IKEv2Integ{{BOMRef: cdx.BOMReference(algRef), Name: "integ"}}
		ke := []cdx.IKEv2Ke{{BOMRef: cdx.BOMReference(keyRef)}}
		auth := []cdx.IKEv2Auth{{BOMRef: cdx.BOMReference(algRef), Name: "auth"}}

		detection := model.Detection{
			Source:   "NMAP",
			Location: "10.0.0.1:500",
			Components: append(targets(),
				cdx.Component{
					BOMRef: protoRef, Name: "ike", Type: cdx.ComponentTypeCryptographicAsset,
					CryptoProperties: &cdx.CryptoProperties{
						AssetType: cdx.CryptoAssetTypeProtocol,
						ProtocolProperties: &cdx.CryptoProtocolProperties{
							Type: cdx.CryptoProtocolTypeIKE,
							IKEv2TransformTypes: &cdx.IKEv2TransformTypes{
								Encr: &encr, PRF: &prf, Integ: &integ, KE: &ke, Auth: &auth,
							},
						},
					},
				}),
		}

		b, err := NewBuilder(model.CBOM{Version: "1.6"})
		require.NoError(t, err)
		b.AppendDetections(t.Context(), detection)
		bom := b.BOM(t.Context())

		caller := detection.Components[2].CryptoProperties.ProtocolProperties.IKEv2TransformTypes
		require.Equal(t, cdx.BOMReference(algRef), (*caller.Encr)[0].BOMRef)
		require.Equal(t, cdx.BOMReference(algRef), (*caller.PRF)[0].BOMRef)
		require.Equal(t, cdx.BOMReference(algRef), (*caller.Integ)[0].BOMRef)
		require.Equal(t, cdx.BOMReference(keyRef), (*caller.KE)[0].BOMRef)
		require.Equal(t, cdx.BOMReference(algRef), (*caller.Auth)[0].BOMRef)

		// The slice headers the caller declared are the same backing arrays, so
		// check them directly: a clone that copied the IKEv2TransformTypes
		// struct but shared its five slices would pass the reads above only if
		// they went through a fresh array, which they do not.
		require.Equal(t, cdx.BOMReference(algRef), encr[0].BOMRef)
		require.Equal(t, cdx.BOMReference(keyRef), ke[0].BOMRef)

		emitted := componentByRef(t, bom, safeRef(protoRef)).
			CryptoProperties.ProtocolProperties.IKEv2TransformTypes
		require.Equal(t, cdx.BOMReference(safeRef(algRef)), (*emitted.Encr)[0].BOMRef)
		require.Equal(t, cdx.BOMReference(safeRef(keyRef)), (*emitted.KE)[0].BOMRef)
	})
}

// TestAppendDetection_DoesNotMutateCallerDetection is the catch-all: it puts
// every sub-struct the Builder is known to reach into one detection, drives the
// full path (store, collide, merge, render, validate), and compares the whole
// caller-side component slice against an independently built expectation.
//
// The three tests above each name the field they defend, which is what makes a
// forgotten one diagnosable; this one is what catches a field nobody thought to
// name -- including one added to cdx.Component by a future cyclonedx-go bump.
//
// want is rebuilt by calling the same constructor a second time rather than
// deep-copied from the input, for the reason publicKeyDetection gives: a copy
// taken by reflection would share whatever the constructor shares, so an
// aliased sub-struct would compare equal to itself and the test would pass on
// exactly the defect it exists to catch.
func TestAppendDetection_DoesNotMutateCallerDetection(t *testing.T) {
	line := 7
	size := 2048

	components := func() []cdx.Component {
		encr := []cdx.IKEv2Enc{{BOMRef: cdx.BOMReference("crypto/algorithm/aes@0"), Name: "aes"}}
		suiteAlgs := []cdx.BOMReference{"crypto/algorithm/aes@0"}
		suites := []cdx.CipherSuite{{Name: "TLS_AES_128_GCM_SHA256", Algorithms: &suiteAlgs}}
		cryptoRefs := []cdx.BOMReference{"crypto/algorithm/aes@0"}
		occurrences := []cdx.EvidenceOccurrence{{Location: "/etc/ssl/certs/ca.pem", Line: &line}}

		return []cdx.Component{
			{
				BOMRef: "crypto/algorithm/aes@0", Name: "AES-128",
				Type: cdx.ComponentTypeCryptographicAsset,
				CryptoProperties: &cdx.CryptoProperties{
					AssetType: cdx.CryptoAssetTypeAlgorithm,
					AlgorithmProperties: &cdx.CryptoAlgorithmProperties{
						Primitive:              cdx.CryptoPrimitiveBlockCipher,
						ParameterSetIdentifier: "128",
					},
				},
			},
			{
				BOMRef: "crypto/key/rsa-2048@0", Name: "RSA-2048",
				Type: cdx.ComponentTypeCryptographicAsset,
				CryptoProperties: &cdx.CryptoProperties{
					AssetType: cdx.CryptoAssetTypeRelatedCryptoMaterial,
					RelatedCryptoMaterialProperties: &cdx.RelatedCryptoMaterialProperties{
						Type:         cdx.RelatedCryptoMaterialTypePrivateKey,
						AlgorithmRef: cdx.BOMReference("crypto/algorithm/aes@0"),
						Size:         &size,
						SecuredBy: &cdx.SecuredBy{
							Mechanism:    "PBKDF2",
							AlgorithmRef: cdx.BOMReference("crypto/algorithm/aes@0"),
						},
					},
				},
				Evidence: &cdx.Evidence{Occurrences: &occurrences},
			},
			{
				BOMRef: "crypto/certificate/leaf@0", Name: "leaf",
				Type: cdx.ComponentTypeCryptographicAsset,
				CryptoProperties: &cdx.CryptoProperties{
					AssetType: cdx.CryptoAssetTypeCertificate,
					CertificateProperties: &cdx.CertificateProperties{
						SubjectName:           "CN=leaf",
						SignatureAlgorithmRef: cdx.BOMReference("crypto/algorithm/aes@0"),
						SubjectPublicKeyRef:   cdx.BOMReference("crypto/key/rsa-2048@0"),
					},
				},
			},
			{
				BOMRef: "crypto/protocol/tls@0", Name: "tls",
				Type: cdx.ComponentTypeCryptographicAsset,
				CryptoProperties: &cdx.CryptoProperties{
					AssetType: cdx.CryptoAssetTypeProtocol,
					ProtocolProperties: &cdx.CryptoProtocolProperties{
						Type:                cdx.CryptoProtocolTypeTLS,
						Version:             "1.3",
						CipherSuites:        &suites,
						CryptoRefArray:      &cryptoRefs,
						IKEv2TransformTypes: &cdx.IKEv2TransformTypes{Encr: &encr},
					},
				},
			},
		}
	}

	detection := model.Detection{
		Source:     "PEM",
		Type:       model.DetectionTypeCertificate,
		Location:   "/etc/ssl/certs/ca.pem",
		Components: components(),
	}
	want := components()

	b, err := NewBuilder(model.CBOM{Version: "1.6"})
	require.NoError(t, err)
	b.AppendDetections(t.Context(), detection)

	// A second detection on the same refs, so the merge branch runs too: the
	// store path and the merge path write different fields.
	b.AppendDetections(t.Context(), model.Detection{
		Source:   "PKCS12",
		Location: "/etc/ssl/store.p12",
		Components: []cdx.Component{{
			BOMRef: "crypto/key/rsa-2048@0", Name: "RSA-2048",
			Type: cdx.ComponentTypeCryptographicAsset,
			CryptoProperties: &cdx.CryptoProperties{
				AssetType: cdx.CryptoAssetTypeRelatedCryptoMaterial,
				RelatedCryptoMaterialProperties: &cdx.RelatedCryptoMaterialProperties{
					Type:   cdx.RelatedCryptoMaterialTypePrivateKey,
					Format: "PEM",
				},
			},
		}},
	})

	var buf bytes.Buffer
	require.NoError(t, b.AsJSON(t.Context(), &buf))
	require.NotZero(t, buf.Len())

	require.Equal(t, want, detection.Components,
		"a detection handed to AppendDetections must come back unchanged")
}

// TestAppendDetection_DoesNotMutateCollidingDetection carries the property the
// four tests above pin for the FIRST detection over to every later one.
//
// cloneOnStore runs on the first-store path only. A detection that collides on
// an already-stored bom-ref is never cloned and never stored: it is read by
// mergeRelatedCryptoMaterialFormat and then dropped. That is safe exactly as
// long as the merge stays a READER. The moment it assigns a sub-struct out of
// incoming into stored, the Builder has adopted caller memory on the one path
// where no clone runs, and every write that follows -- a third detection's
// merge, and the bom-ref canonicalisation replaceBOMReferences performs on
// every BOM()/AsJSON() call -- lands in the second detection instead. The merge
// names that hazard in its own doc comment and nothing enforced it: mutating
// the allocating arm to adopt incoming's struct, and mutating the tie-break to
// write the kept value back into incoming, both passed the suite untouched.
//
// The cases are the merge's four arms, chosen by what the STORED component
// carries; the colliding detection is byte-identical across them so the arm is
// the only variable. It carries algorithmRef and securedBy.algorithmRef, and
// their target is stored too, because those are the fields a render rewrites --
// an adopted struct is invisible until something writes through it.
func TestAppendDetection_DoesNotMutateCollidingDetection(t *testing.T) {
	const algRef = "crypto/algorithm/sha-256-rsa@0"

	// Rebuilt per call and never copied out of the value under test: a want
	// lifted from the same memory would share whatever the input shares and
	// compare equal to itself. Same reasoning as publicKeyDetection's.
	colliding := func() []cdx.Component {
		return []cdx.Component{{
			BOMRef: sharedKeyRef,
			Name:   "RSA-2048",
			Type:   cdx.ComponentTypeCryptographicAsset,
			CryptoProperties: &cdx.CryptoProperties{
				AssetType: cdx.CryptoAssetTypeRelatedCryptoMaterial,
				RelatedCryptoMaterialProperties: &cdx.RelatedCryptoMaterialProperties{
					Type:         cdx.RelatedCryptoMaterialTypePublicKey,
					Format:       "PEM",
					AlgorithmRef: cdx.BOMReference(algRef),
					SecuredBy: &cdx.SecuredBy{
						Mechanism:    "PBKDF2",
						AlgorithmRef: cdx.BOMReference(algRef),
					},
				},
			},
		}}
	}

	tests := []struct {
		name string
		// stored is the related-crypto-material half of the FIRST detection's
		// component. nil selects the arm on which the merge has to allocate.
		stored     *cdx.RelatedCryptoMaterialProperties
		wantFormat string
	}{
		{
			name:       "the merge allocates its own struct",
			stored:     nil,
			wantFormat: "PEM",
		},
		{
			name:       "the merge fills in a missing format",
			stored:     &cdx.RelatedCryptoMaterialProperties{Type: cdx.RelatedCryptoMaterialTypePublicKey},
			wantFormat: "PEM",
		},
		{
			// min("DER", "PEM"); which value wins is pinned elsewhere. What
			// matters here is that the winner is not written back into the
			// detection that lost.
			name: "the merge tie-breaks two disagreeing formats",
			stored: &cdx.RelatedCryptoMaterialProperties{
				Type: cdx.RelatedCryptoMaterialTypePublicKey, Format: "DER",
			},
			wantFormat: "DER",
		},
		{
			// The arm that returns without writing anything. It can catch no
			// mutant today; it is here so that an arm which STARTS writing is
			// covered by construction rather than by someone remembering.
			name: "the merge has nothing to do",
			stored: &cdx.RelatedCryptoMaterialProperties{
				Type: cdx.RelatedCryptoMaterialTypePublicKey, Format: "PEM",
			},
			wantFormat: "PEM",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			first := model.Detection{
				Source:   "PKCS12",
				Location: "/etc/ssl/store.p12",
				Components: []cdx.Component{
					// The algorithm has to be stored, or safeRefs holds no
					// entry for algRef, replaceBOMReferences finds nothing to
					// substitute and an adopted struct stays invisible.
					{BOMRef: algRef, Name: "sha-256-rsa", Type: cdx.ComponentTypeCryptographicAsset},
					{
						BOMRef: sharedKeyRef,
						Name:   "RSA-2048",
						Type:   cdx.ComponentTypeCryptographicAsset,
						CryptoProperties: &cdx.CryptoProperties{
							AssetType:                       cdx.CryptoAssetTypeRelatedCryptoMaterial,
							RelatedCryptoMaterialProperties: tt.stored,
						},
					},
				},
			}
			second := model.Detection{
				Source:     "PEM",
				Location:   "/etc/ssl/certs/ca.pem",
				Components: colliding(),
			}
			want := colliding()

			b, err := NewBuilder(model.CBOM{Version: "1.6"})
			require.NoError(t, err)
			b.AppendDetections(t.Context(), first, second)

			// Rendering is what makes an adopted struct observable: it is the
			// only Builder write reaching algorithmRef and securedBy.
			bom := b.BOM(t.Context())

			require.Equal(t, want, second.Components,
				"a detection that collided with a stored bom-ref must come back unchanged")

			storedProps := b.components[sharedKeyRef].CryptoProperties.RelatedCryptoMaterialProperties
			require.NotNil(t, storedProps)
			require.NotSame(t,
				second.Components[0].CryptoProperties.RelatedCryptoMaterialProperties, storedProps,
				"the Builder must not go on holding the colliding detection's struct")

			// The merge must still do its job, or this test would pass on a
			// Builder that simply stopped merging.
			emitted := componentByRef(t, bom, safeRef(sharedKeyRef))
			require.Equal(t, tt.wantFormat,
				emitted.CryptoProperties.RelatedCryptoMaterialProperties.Format)

			if tt.stored == nil {
				// The allocating arm allocates an EMPTY struct and sets only
				// the format, so it cannot be carrying the incoming
				// component's other fields.
				require.Empty(t, storedProps.AlgorithmRef,
					"the allocated struct describes an encoding, not the incoming component")
				require.Nil(t, storedProps.SecuredBy)
				require.Empty(t, string(storedProps.Type))
			}
		})
	}
}

// TestAppendDetection_CloneLeavesTransformSlicesAsTheyCame pins the one thing
// cloneTransforms must not do: change the value it is copying.
//
// The three shapes a *[]T arrives in are not interchangeable in the emitted
// document. A nil POINTER omits the field, a non-nil pointer to a NIL slice
// emits null, and a non-nil pointer to an EMPTY slice emits []. cloneTransforms
// has to detach the backing array of a populated slice without promoting either
// of the other two, and its guard returns both untouched precisely because
// there is no backing array to protect.
//
// Dropping the `*p == nil` half of that guard was the single mutation of the
// clone the rest of the suite did not notice, and it is not cosmetic: encr/prf/
// integ/ke/auth are all cryptoRefArray, which is `"type": "array"`, so null
// fails schema validation and [] passes. A clone that quietly turns one into
// the other repairs a producer's mistake in the one place nobody is looking,
// and AsJSON -- whose whole job is to refuse a document like that -- would then
// emit it. A clone changes ownership, never content.
func TestAppendDetection_CloneLeavesTransformSlicesAsTheyCame(t *testing.T) {
	const (
		protoRef = "crypto/protocol/ike@0"
		algRef   = "crypto/algorithm/aes@0"
	)

	// One of each shape. KE and Auth are left out entirely, so they arrive as
	// nil POINTERS -- the third shape.
	populated := []cdx.IKEv2Enc{{BOMRef: cdx.BOMReference(algRef), Name: "aes"}}
	var nilSlice []cdx.IKEv2Prf // non-nil POINTER to a nil slice
	empty := []cdx.IKEv2Integ{} // non-nil pointer to an EMPTY slice

	detection := model.Detection{
		Source:   "NMAP",
		Location: "10.0.0.1:500",
		Components: []cdx.Component{
			{BOMRef: algRef, Name: "aes", Type: cdx.ComponentTypeCryptographicAsset},
			{
				BOMRef: protoRef, Name: "ike", Type: cdx.ComponentTypeCryptographicAsset,
				CryptoProperties: &cdx.CryptoProperties{
					AssetType: cdx.CryptoAssetTypeProtocol,
					ProtocolProperties: &cdx.CryptoProtocolProperties{
						Type: cdx.CryptoProtocolTypeIKE,
						IKEv2TransformTypes: &cdx.IKEv2TransformTypes{
							Encr: &populated, PRF: &nilSlice, Integ: &empty,
						},
					},
				},
			},
		},
	}

	b, err := NewBuilder(model.CBOM{Version: "1.6"})
	require.NoError(t, err)
	b.AppendDetections(t.Context(), detection)
	emitted := componentByRef(t, b.BOM(t.Context()), safeRef(protoRef)).
		CryptoProperties.ProtocolProperties.IKEv2TransformTypes

	// The populated slice is the one the clone must detach; that half is pinned
	// by TestBuilder_BOMDoesNotMutateCallerRefs. Here it only has to still hold
	// its element, so a cloneTransforms that dropped content would be caught.
	require.NotNil(t, emitted.Encr)
	require.Len(t, *emitted.Encr, 1)
	require.Equal(t, cdx.BOMReference(safeRef(algRef)), (*emitted.Encr)[0].BOMRef)

	// Asserted through the encoding rather than the Go value, because null and
	// [] are the same `len == 0` in Go and different documents on the wire.
	raw, err := json.Marshal(emitted)
	require.NoError(t, err)

	tests := []struct {
		name     string
		fragment string
		present  bool
	}{
		{
			name:     "a pointer to a nil slice still emits null",
			fragment: `"prf":null`,
			present:  true,
		},
		{
			name:     "a pointer to a nil slice is not promoted to an empty array",
			fragment: `"prf":[]`,
			present:  false,
		},
		{
			name:     "a pointer to an empty slice still emits an empty array",
			fragment: `"integ":[]`,
			present:  true,
		},
		{
			name:     "a nil pointer emits no key exchange field at all",
			fragment: `"ke"`,
			present:  false,
		},
		{
			name:     "a nil pointer emits no auth field at all",
			fragment: `"auth"`,
			present:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.present {
				require.Contains(t, string(raw), tt.fragment)
				return
			}
			require.NotContains(t, string(raw), tt.fragment)
		})
	}
}
