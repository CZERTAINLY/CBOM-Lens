package bom

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"reflect"
	"regexp"
	"slices"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/OmniTrustILM/cbom-lens/internal/cdxprops/ilm"
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

	t.Run("duplicate dependency unions to one entry", func(t *testing.T) {
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
				{Ref: "comp-1", Dependencies: &[]string{"dep-2"}},
			},
		}

		builder.AppendDetections(ctx, detection1, detection2)

		// Len alone said only that no second KEY appeared, which first-wins and
		// the union both satisfy. The contents are what tells them apart: the
		// second detection's edge has to be there too.
		require.Len(t, builder.dependencies, 1)
		require.Equal(t, []string{"dep-1", "dep-2"}, *builder.dependencies["comp-1"])
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

// sharedSigAlgRef is the bom-ref every ECDSA-SHA256 signature in a scan lands
// on, whichever signed object it was read off. Its shape is the real one:
// cdxprops.signatureAlgorithmComponents derives the ref from the
// x509.SignatureAlgorithm enum and the OID alone, so neither the signed bytes
// nor the file they came from enter it -- which is what makes a certificate and
// a CRL signed the same way collide here.
const sharedSigAlgRef = "crypto/algorithm/sha-256-ecdsa@sha256:deadbeef"

// The edge targets the colliding detections disagree about. Two certificates
// signed with one algorithm name different public-key algorithms when their
// subject keys sit on different curves, and a CRL names only the hash, so no
// single detection sees all three.
const (
	p256AlgRef   = "crypto/algorithm/ecdsa-p-256@sha256:aa"
	p384AlgRef   = "crypto/algorithm/ecdsa-p-384@sha256:bb"
	sha256AlgRef = "crypto/algorithm/sha-256@sha256:cc"
)

// Two more targets, sharing EVERYTHING before the "@". The three above all
// differ there, so no test built from them can see a sort that stops at the
// "@" -- and this pair is not a contrivance: publicKeyComponents stamps the
// primitive onto the algorithm component before BOMRefHash hashes it, and RSA's
// primitive is read off the certificate's KeyUsage, so a signing RSA-2048
// certificate and an encipherment RSA-2048 certificate produce two components
// both named crypto/algorithm/rsa-2048 and hashed differently. Both are
// SHA256WithRSA, so both name ONE signature-algorithm ref as the source of their
// edges and the union under it holds the pair.
// TestCertHit_TwoRSACertificatesShareASigAlgRefAndNameTwoRSA2048Algorithms
// proves that reachable through the real converter.
//
// The digests are chosen so the RAW order and the CANONICAL order DISAGREE:
// safeRef keeps everything before the "@" and replaces the digest with a UUIDv5
// of the whole ref, so it is order-preserving only for refs that differ BEFORE
// the "@". mergeDependsOn's doc comment documents exactly this pair as the
// reason the raw order and the wire order can come apart; this is the fixture
// that keeps that statement honest, and the reason the assertion below pins an
// array that is deterministic without being ascending on the wire.
const (
	rsaSignAlgRef = "crypto/algorithm/rsa-2048@sha256:5aae0a557fa226ac7cfb9d20b247b928e3ef3bc96f588b3b1c8ea78c94057a1d"
	rsaPKEAlgRef  = "crypto/algorithm/rsa-2048@sha256:ab09ade06648b93dea6a87a57e49dfc04293b7f024af7cdfec61ebcfd992d49a"
)

// algorithmNames gives every ref above the component name it is emitted under.
// A nameless component is dropped by missingIdentity before it can anchor an
// edge, so the endpoints these tests assert on have to be real assets.
var algorithmNames = map[string]string{
	sharedSigAlgRef: "ECDSA-SHA256",
	p256AlgRef:      "ECDSA-P-256",
	p384AlgRef:      "ECDSA-P-384",
	sha256AlgRef:    "SHA-256",
	// One name, two assets: that is what the shared prefix means.
	rsaSignAlgRef: "RSA-2048",
	rsaPKEAlgRef:  "RSA-2048",
}

// algorithmComponent builds the minimal algorithm asset a dependency endpoint
// needs in order to survive Builder.model, which drops -- with a warning -- any
// edge whose From or To resolves to no stored component. The edges are what
// these tests are about, so every ref one names carries a component.
func algorithmComponent(ref string) cdx.Component {
	return cdx.Component{
		BOMRef: ref,
		Name:   algorithmNames[ref],
		Type:   cdx.ComponentTypeCryptographicAsset,
		CryptoProperties: &cdx.CryptoProperties{
			AssetType: cdx.CryptoAssetTypeAlgorithm,
			AlgorithmProperties: &cdx.CryptoAlgorithmProperties{
				Primitive: cdx.CryptoPrimitiveSignature,
			},
		},
	}
}

// sigAlgEdgeDetection builds a detection whose dependency entry names
// sharedSigAlgRef and depends on targets, carrying a component for the ref and
// for every target so Builder.model does not drop the edges as dangling.
//
// It rebuilds everything on every call, for the reason publicKeyDetection
// gives: two detections sharing one backing array would make a merge that
// appends in place look correct through aliasing alone -- which is exactly what
// the real producers do NOT do, since certHitToComponents and crlToCDX each
// build their own []string literal.
func sigAlgEdgeDetection(location string, targets ...string) model.Detection {
	compos := make([]cdx.Component, 0, len(targets)+1)
	compos = append(compos, algorithmComponent(sharedSigAlgRef))
	for _, target := range targets {
		compos = append(compos, algorithmComponent(target))
	}

	deps := make([]string, 0, len(targets))
	deps = append(deps, targets...)

	return model.Detection{
		Source:     "PEM",
		Type:       model.DetectionTypeCertificate,
		Location:   location,
		Components: compos,
		Dependencies: []cdx.Dependency{
			{Ref: sharedSigAlgRef, Dependencies: &deps},
		},
	}
}

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

// TestBuilder_AppendDetections_DependsOnSurvivesEveryArrivalPermutation pins the
// invariant that the dependency edges stored under a bom-ref are the UNION of
// what every detection resolving to that ref claimed, sorted, and never a
// function of the order appendDetection observed them in.
//
// The three arrivals are the real collision. One ECDSA-SHA256 signature
// algorithm is one asset -- the ref is a pure function of the enum and the OID
// -- so a P-256 certificate, a P-384 certificate and a CRL all name it as the
// source of their edges, and each of them knows a different part of the answer.
// Scanning fans out over goroutines (internal/parallel) onto one channel
// (cmd/cbom-lens/lens.go), so which of them lands first is a coin flip; under
// first-wins a certificate lost the edge to its own public-key algorithm
// whenever a CRL signed the same way happened to arrive ahead of it, and nothing
// dangled, because the components themselves were still stored by somebody else.
//
// Three arrivals with three distinct targets is the smallest set that separates
// first-wins (which emits the first arrival's targets), last-wins (the last
// arrival's) and a union (all three, from every position). Asserting the ORDERED
// slice is what additionally separates a sorted union from an arrival-order one:
// Builder.model stable-sorts the flattened edges by From ONLY and
// regroupDependsOn never reorders within a From, so this slice IS the byte order
// of the delivered dependsOn array.
func TestBuilder_AppendDetections_DependsOnSurvivesEveryArrivalPermutation(t *testing.T) {
	arrivals := []model.Detection{
		sigAlgEdgeDetection("/etc/ssl/certs/p256.pem", p256AlgRef, sha256AlgRef),
		sigAlgEdgeDetection("/etc/ssl/certs/p384.pem", p384AlgRef, sha256AlgRef),
		sigAlgEdgeDetection("/etc/ssl/crl/revocations.crl", sha256AlgRef),
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

			// Rebuilt per permutation for the reason sigAlgEdgeDetection gives:
			// a merge that grew the caller's slice in place would otherwise let
			// permutation 012 seed 021.
			ordered := make([]model.Detection, 0, len(p))
			for _, i := range p {
				d := arrivals[i]
				ordered = append(ordered,
					sigAlgEdgeDetection(d.Location, *d.Dependencies[0].Dependencies...))
			}
			builder.AppendDetections(t.Context(), ordered...)

			require.Len(t, builder.dependencies, 1,
				"one algorithm is one ref: every detection here names the same source")
			stored := builder.dependencies[sharedSigAlgRef]
			require.NotNil(t, stored)
			require.Equal(t, []string{p256AlgRef, p384AlgRef, sha256AlgRef}, *stored,
				"every edge any detection claimed must survive, ascending, from any "+
					"arrival order: the slice order here is the delivered byte order")
		})
	}
}

// TestBuilder_AppendDetections_EmittedDependsOnIsOrderIndependent states the
// dependency-edge invariant where the user meets it: the delivered JSON, not
// builder.dependencies. This is where the sort earns its place -- the map
// assertion above would also be satisfied by a union that stored arrival order,
// since a set comparison cannot see order, and only the encoded document shows
// that Builder.model's sort-by-From-only and regroupDependsOn's regrouping pass
// this slice through to the wire untouched.
func TestBuilder_AppendDetections_EmittedDependsOnIsOrderIndependent(t *testing.T) {
	fixed := time.Date(2024, 1, 2, 3, 4, 5, 0, time.UTC)
	render := func(t *testing.T, detections ...model.Detection) string {
		t.Helper()

		b, err := NewBuilder(model.CBOM{Version: "1.6"})
		require.NoError(t, err)
		b = b.WithClock(func() time.Time { return fixed }).
			WithSerial(func() string { return "urn:uuid:44444444-4444-4444-4444-444444444444" })
		b.AppendDetections(t.Context(), detections...)

		var buf bytes.Buffer
		require.NoError(t, b.AsJSON(t.Context(), &buf))
		return buf.String()
	}

	certFirst := render(t,
		sigAlgEdgeDetection("/etc/ssl/certs/p384.pem", p384AlgRef, sha256AlgRef),
		sigAlgEdgeDetection("/etc/ssl/crl/revocations.crl", sha256AlgRef))
	crlFirst := render(t,
		sigAlgEdgeDetection("/etc/ssl/crl/revocations.crl", sha256AlgRef),
		sigAlgEdgeDetection("/etc/ssl/certs/p384.pem", p384AlgRef, sha256AlgRef))

	require.Equal(t, certFirst, crlFirst,
		"two scans that found the same certificate and the same CRL must deliver "+
			"byte-identical CBOMs regardless of which scanner reported first")

	// A document that dropped the certificate's edge would satisfy the equality
	// above, so the emitted array itself is asserted. Decoded rather than matched
	// as a substring: the p-384 ref appears in the document either way, because
	// the ALGORITHM is stored as a component by the same detection that claimed
	// the edge -- that is precisely why first-wins was invisible -- so a
	// require.Contains on the ref would pass against the defect it is guarding.
	require.Equal(t, []string{safeRef(p384AlgRef), safeRef(sha256AlgRef)},
		emittedDependsOn(t, certFirst, safeRef(sharedSigAlgRef)),
		"the delivered dependsOn array must be the sorted union of both detections' "+
			"claims, in the order builder.dependencies holds them")
}

// emittedDependsOn returns the dependsOn array the delivered document carries
// for ref, or nil when the document has no dependency row naming it.
func emittedDependsOn(t *testing.T, doc, ref string) []string {
	t.Helper()

	var bom cdx.BOM
	require.NoError(t, json.Unmarshal([]byte(doc), &bom))
	require.NotNil(t, bom.Dependencies)

	for _, d := range *bom.Dependencies {
		if d.Ref != ref {
			continue
		}
		if d.Dependencies == nil {
			return nil
		}
		return *d.Dependencies
	}
	return nil
}

// renderDependsOnBOM encodes detections as a whole document at version, with the
// clock and the serial pinned so that two renderings differ only where the
// Builder made them differ.
func renderDependsOnBOM(t *testing.T, version string, detections ...model.Detection) string {
	t.Helper()

	fixed := time.Date(2024, 1, 2, 3, 4, 5, 0, time.UTC)
	b, err := NewBuilder(model.CBOM{Version: version})
	require.NoError(t, err)
	b = b.WithClock(func() time.Time { return fixed }).
		WithSerial(func() string { return "urn:uuid:55555555-5555-5555-5555-555555555555" })
	b.AppendDetections(t.Context(), detections...)

	var buf bytes.Buffer
	require.NoError(t, b.AsJSON(t.Context(), &buf))
	return buf.String()
}

// TestBuilder_AppendDetections_DependsOnOrdersTargetsThatShareARefPrefix closes
// the one case the dependsOn tests above cannot see: two targets of one ref that
// are identical up to the "@".
//
// Every other fixture here pairs targets with distinct names -- ecdsa-p-256
// against sha-256 -- so a union that sorted only by the part of the ref safeRef
// preserves, and left refs agreeing on that part in arrival order, would satisfy
// all of them and still deliver a different byte sequence per permutation for the
// pair below. The const block above says why that pair occurs in a real scan.
//
// It also states the invariant in 1.7, not only in 1.6. model() is
// version-neutral and regroupDependsOn is shared by emit16 and emit17, so the two
// have to agree here by construction -- which is exactly the kind of claim that
// stops being true silently the day an emitter grows its own dependency
// rendering.
func TestBuilder_AppendDetections_DependsOnOrdersTargetsThatShareARefPrefix(t *testing.T) {
	// Rebuilt per use, for the reason sigAlgEdgeDetection gives: two detections
	// sharing one backing array would let a merge that appends in place look
	// correct through aliasing alone.
	signing := func() model.Detection {
		return sigAlgEdgeDetection("/etc/ssl/certs/rsa-signing.pem", rsaSignAlgRef, sha256AlgRef)
	}
	encipherment := func() model.Detection {
		return sigAlgEdgeDetection("/etc/ssl/certs/rsa-encipherment.pem", rsaPKEAlgRef, sha256AlgRef)
	}

	// Ascending over the WHOLE raw ref: "rsa-2048@sha256:5aae" < "...@sha256:ab09"
	// < "sha-256@...". A sort that stopped at the "@" would leave the first two
	// in whichever order they arrived.
	wantStored := []string{rsaSignAlgRef, rsaPKEAlgRef, sha256AlgRef}

	t.Run("stored", func(t *testing.T) {
		for _, tt := range []struct {
			name  string
			first model.Detection
			last  model.Detection
		}{
			{"signing first", signing(), encipherment()},
			{"encipherment first", encipherment(), signing()},
		} {
			t.Run(tt.name, func(t *testing.T) {
				builder, err := NewBuilder(model.CBOM{Version: "1.6"})
				require.NoError(t, err)
				builder.AppendDetections(t.Context(), tt.first, tt.last)

				stored := builder.dependencies[sharedSigAlgRef]
				require.NotNil(t, stored)
				require.Equal(t, wantStored, *stored,
					"targets sharing everything before the \"@\" must still be "+
						"ordered by the whole ref, or their relative order is the "+
						"arrival order the union exists to erase")
			})
		}
	})

	for _, version := range []string{"1.6", "1.7"} {
		t.Run("emitted "+version, func(t *testing.T) {
			signingFirst := renderDependsOnBOM(t, version, signing(), encipherment())
			enciphermentFirst := renderDependsOnBOM(t, version, encipherment(), signing())
			require.Equal(t, signingFirst, enciphermentFirst,
				"two scans that found the same two certificates must deliver "+
					"byte-identical CBOMs whichever was reported first")

			// Decoded rather than matched as a substring: both rsa-2048 refs are
			// in the document either way, because each detection stores the
			// algorithm COMPONENT it names -- which is why a lost edge here was
			// invisible in the first place.
			emitted := emittedDependsOn(t, signingFirst, safeRef(sharedSigAlgRef))
			require.Equal(t,
				[]string{safeRef(rsaSignAlgRef), safeRef(rsaPKEAlgRef), safeRef(sha256AlgRef)},
				emitted,
				"the raw order mergeDependsOn stored is the wire order; nothing "+
					"between the map and the encoder re-sorts")

			// And this is what makes the case worth a test of its own: the wire
			// order is NOT ascending. safeRef preserves order only for refs that
			// differ before the "@", so sorting the CANONICAL refs instead -- the
			// plausible "sort what you actually emit" refactor -- would reorder
			// this array and change the delivered bytes.
			require.False(t, slices.IsSorted(emitted),
				"if the canonical refs are ascending here this test has stopped "+
					"separating a raw sort from a canonical one; pick two digests "+
					"whose UUIDv5s invert again")
		})
	}
}

// TestBuilder_AppendDetections_DependsOnIsDeterministicUnderConcurrentProducers
// runs the merge in the shape production uses it: many scanning goroutines
// (internal/parallel, service.New) writing detections into one channel, and ONE
// consumer goroutine draining that channel into the Builder
// (cmd/cbom-lens/lens.go). That single consumer is the entire reason
// mergeDependsOn needs no lock, and nothing else in this package says so.
//
// The assertion is not "no race" -- -race says that, and this test exists to be
// run under it -- but that the DOCUMENT equals the one a sequential append
// produces. Four producers each claiming one distinct target means the union has
// to grow four times, from four separate detections, in an order the scheduler
// picks and the test does not.
func TestBuilder_AppendDetections_DependsOnIsDeterministicUnderConcurrentProducers(t *testing.T) {
	targets := []string{p256AlgRef, p384AlgRef, sha256AlgRef, rsaSignAlgRef}
	detections := func() []model.Detection {
		out := make([]model.Detection, 0, len(targets))
		for i, target := range targets {
			out = append(out, sigAlgEdgeDetection(fmt.Sprintf("/etc/ssl/certs/%d.pem", i), target))
		}
		return out
	}

	sequential := renderDependsOnBOM(t, "1.6", detections()...)

	// Every edge reached the document, so the equality below cannot be two
	// equally truncated renderings agreeing with each other.
	require.Equal(t,
		[]string{
			safeRef(p256AlgRef), safeRef(p384AlgRef),
			safeRef(rsaSignAlgRef), safeRef(sha256AlgRef),
		},
		emittedDependsOn(t, sequential, safeRef(sharedSigAlgRef)),
		"four detections each claiming one target must union to four edges")

	// Repeated, because one pass through a scheduler proves one interleaving.
	for range 8 {
		fixed := time.Date(2024, 1, 2, 3, 4, 5, 0, time.UTC)
		b, err := NewBuilder(model.CBOM{Version: "1.6"})
		require.NoError(t, err)
		b = b.WithClock(func() time.Time { return fixed }).
			WithSerial(func() string { return "urn:uuid:55555555-5555-5555-5555-555555555555" })

		found := make(chan model.Detection)
		drained := make(chan struct{})
		go func() {
			defer close(drained)
			for d := range found {
				b.AppendDetections(t.Context(), d)
			}
		}()

		var wg sync.WaitGroup
		for _, d := range detections() {
			wg.Add(1)
			go func() {
				defer wg.Done()
				found <- d
			}()
		}
		wg.Wait()
		close(found)
		<-drained

		var buf bytes.Buffer
		require.NoError(t, b.AsJSON(t.Context(), &buf))
		require.Equal(t, sequential, buf.String(),
			"the delivered CBOM must not depend on which scanner goroutine won")
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

	// The dependency half, built by the same constructor idiom and for the same
	// reason: the catch-all compared only Components, so it could not see a merge
	// that wrote back through the *[]string a detection carries. The slice is
	// given spare capacity because that is the shape in which an in-place append
	// is observable at all.
	dependencies := func() []cdx.Dependency {
		deps := make([]string, 0, 8)
		deps = append(deps, "crypto/algorithm/aes@0", "crypto/key/rsa-2048@0")
		return []cdx.Dependency{{Ref: "crypto/certificate/leaf@0", Dependencies: &deps}}
	}

	detection := model.Detection{
		Source:       "PEM",
		Type:         model.DetectionTypeCertificate,
		Location:     "/etc/ssl/certs/ca.pem",
		Components:   components(),
		Dependencies: dependencies(),
	}
	want := components()
	wantDeps := dependencies()

	b, err := NewBuilder(model.CBOM{Version: "1.6"})
	require.NoError(t, err)
	b.AppendDetections(t.Context(), detection)

	// A second detection on the same refs, so the merge branch runs too: the
	// store path and the merge path write different fields. Its dependency entry
	// names the same ref with a target the first one did not, so the union really
	// rebuilds rather than short-circuiting on slices.Equal.
	secondDeps := []string{"crypto/protocol/tls@0"}
	b.AppendDetections(t.Context(), model.Detection{
		Source:       "PKCS12",
		Location:     "/etc/ssl/store.p12",
		Dependencies: []cdx.Dependency{{Ref: "crypto/certificate/leaf@0", Dependencies: &secondDeps}},
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
	require.Equal(t, wantDeps, detection.Dependencies,
		"including its dependency edges: the merge unions into a slice it "+
			"allocated itself and never through the one the detection carries")

	// The union really did run, so the comparison above is not passing because
	// the merge was never reached.
	require.Equal(t, []string{
		"crypto/algorithm/aes@0", "crypto/key/rsa-2048@0", "crypto/protocol/tls@0",
	}, *b.dependencies["crypto/certificate/leaf@0"])
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

// sharedCertRef is the bom-ref every certificate detection below resolves to.
// Its shape is the real one -- crypto/certificate/<name>@<digest of cert.Raw>,
// built by cdxprops.certComponent -- and it carries no path, no port and no
// source, which is deliberate: that is what lets one certificate found on disk
// and served on a socket dedupe to one asset.
const sharedCertRef = "crypto/certificate/www.example.com@sha256:deadbeef"

// The two ILM certificate properties that CANNOT differ between two components
// sharing sharedCertRef. base64_content is base64(cert.Raw) and fingerprint is
// sha256(cert.Raw), while the ref itself is name@sha256(cert.Raw), so two
// components stored under one ref carry the same cert.Raw modulo a SHA-256
// collision. They are held constant here for the same reason the merge does not
// touch them: source_format is the only one of the three that can disagree.
const (
	sharedCertBase64      = "MIIBkzCCATmgAwIBAgIUZGVhZGJlZWY="
	sharedCertFingerprint = "sha256:deadbeef"
)

// ilmCertificateProperties reproduces ilm.CertificateProperties' output for a
// certificate observed in source: source_format first, then base64_content,
// then fingerprint.
//
// It allocates a fresh slice on every call on purpose. Two detections sharing
// one backing array would make the merge look correct through aliasing alone --
// which is exactly what the real producer does NOT do, since every
// Converter.CertHit call runs ilm.CertificateProperties again and gets its own
// slice.
//
// The capacity is the producer's, not the literal's. ilm.CertificateProperties
// builds its result as make([]cdx.Property, 0, 20) and appends three entries, so
// the real slice has seventeen spare cells behind its length -- room an in-place
// append would quietly write into WITHOUT reallocating, which is the only shape
// in which that bug is observable. A composite literal is len 3 cap 3, where any
// append reallocates and the caller's slice survives by accident;
// TestAppendDetection_CertificateSourceFormatMergeDoesNotMutateTheDetections
// inspects the spare tail and would prove nothing against it.
func ilmCertificateProperties(source string) []cdx.Property {
	props := make([]cdx.Property, 0, 20)
	return append(props,
		cdx.Property{Name: ilm.CertificateSourceFormat, Value: source},
		cdx.Property{Name: ilm.CertificateBase64Content, Value: sharedCertBase64},
		cdx.Property{Name: ilm.CertificateFingerprint, Value: sharedCertFingerprint},
	)
}

// certificateDetection builds a detection carrying one certificate component
// under sharedCertRef, stamped with the ILM property block --ilm turns on.
func certificateDetection(source, location string) model.Detection {
	props := ilmCertificateProperties(source)
	return certificateDetectionWithProperties(source, location, &props)
}

// certificateDetectionWithProperties is certificateDetection with the property
// block chosen by the caller. A nil props is the --ilm-off shape, where
// certComponent never assigns Properties at all.
func certificateDetectionWithProperties(source, location string, props *[]cdx.Property) model.Detection {
	return model.Detection{
		Source:   source,
		Type:     model.DetectionTypeCertificate,
		Location: location,
		Components: []cdx.Component{
			{
				BOMRef:     sharedCertRef,
				Name:       "www.example.com",
				Type:       cdx.ComponentTypeCryptographicAsset,
				Properties: props,
				CryptoProperties: &cdx.CryptoProperties{
					AssetType: cdx.CryptoAssetTypeCertificate,
				},
			},
		},
	}
}

// storedCertificate returns the one component the Builder holds under
// sharedCertRef, asserting on the way that the detections really did collide --
// without that, a merge assertion could be satisfied by a Builder holding two
// separate assets.
func storedCertificate(t *testing.T, b *Builder) *cdx.Component {
	t.Helper()

	require.Len(t, b.components, 1,
		"one certificate is one asset: every detection here hashes to the same bom-ref")
	stored := b.components[sharedCertRef]
	require.NotNil(t, stored)
	return stored
}

// storedCertificateProperties returns the stored component's WHOLE property
// list, or nil when it has none. Whole rather than filtered to source_format:
// the assertions below pin the untouched neighbours and their order too, and a
// filtered view would hide a merge that re-sorted base64_content.
func storedCertificateProperties(t *testing.T, b *Builder) []cdx.Property {
	t.Helper()

	stored := storedCertificate(t, b)
	if stored.Properties == nil {
		return nil
	}
	return *stored.Properties
}

// TestBuilder_AppendDetections_CertificateSourceFormatOrderIndependent pins the
// invariant that a certificate's emitted ilm:component:certificate:source_format
// properties are decided by the SET of detections resolving to its bom-ref and
// never by the order appendDetection observes them in.
//
// The pair below is the ordinary deployment, not a corner case: the server
// certificate sits in /etc/ssl/certs as PEM and is also served on 443, where the
// nmap scanner reports it as NMAP. Both facts are true, so unlike
// mergeRelatedCryptoMaterialFormat the merge keeps BOTH -- see
// mergeCertificateSourceFormat for why provenance unions where an object's
// encoding tie-breaks.
func TestBuilder_AppendDetections_CertificateSourceFormatOrderIndependent(t *testing.T) {
	const (
		diskLocation = "/etc/ssl/certs/server.pem"
		wireLocation = "23.88.35.44:443"
	)

	want := []cdx.Property{
		{Name: ilm.CertificateSourceFormat, Value: "NMAP"},
		{Name: ilm.CertificateSourceFormat, Value: "PEM"},
		{Name: ilm.CertificateBase64Content, Value: sharedCertBase64},
		{Name: ilm.CertificateFingerprint, Value: sharedCertFingerprint},
	}

	tests := []struct {
		name       string
		detections []model.Detection
	}{
		{
			name: "disk arrives first",
			detections: []model.Detection{
				certificateDetection("PEM", diskLocation),
				certificateDetection("NMAP", wireLocation),
			},
		},
		{
			name: "wire arrives first",
			detections: []model.Detection{
				certificateDetection("NMAP", wireLocation),
				certificateDetection("PEM", diskLocation),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			builder, err := NewBuilder(model.CBOM{Version: "1.6"})
			require.NoError(t, err)

			builder.AppendDetections(t.Context(), tt.detections...)

			require.Equal(t, want, storedCertificateProperties(t, builder),
				"both observed source formats must survive, sorted, and the two "+
					"properties that cannot disagree must be left exactly as they were")

			// The merge must not cost what the branch already did.
			stored := storedCertificate(t, builder)
			require.NotNil(t, stored.Evidence)
			require.NotNil(t, stored.Evidence.Occurrences)
			require.Equal(t, []cdx.EvidenceOccurrence{
				{Location: diskLocation},
				{Location: wireLocation},
			}, *stored.Evidence.Occurrences,
				"both locations must still reach evidence.occurrences")
		})
	}
}

// TestBuilder_AppendDetections_CertificateSourceFormatSurvivesEveryArrivalPermutation
// raises the order-independence claim from a pair to a set. A pair cannot
// distinguish set semantics from last-wins -- both give "the other one" when the
// order flips -- but three distinct sources in every position can: only a set
// union yields the identical list for all six permutations.
//
// Three is not a contrived count. One certificate routinely sits in
// /etc/ssl/certs as PEM, inside a PKCS#12 bundle shipped to the same host, and
// is served on 443 where nmap reports it; the three detections reach the Builder
// from three scanners over one channel, in whatever order they finish.
func TestBuilder_AppendDetections_CertificateSourceFormatSurvivesEveryArrivalPermutation(t *testing.T) {
	arrivals := []model.Detection{
		certificateDetection("PEM", "/etc/ssl/certs/server.pem"),
		certificateDetection("PKCS12", "/etc/ssl/store.p12"),
		certificateDetection("NMAP", "23.88.35.44:443"),
	}

	// Written out rather than generated: the point of the test is that every
	// arrangement is checked, and a permutation generator with an off-by-one
	// would quietly check fewer.
	permutations := [][3]int{
		{0, 1, 2}, {0, 2, 1}, {1, 0, 2}, {1, 2, 0}, {2, 0, 1}, {2, 1, 0},
	}

	want := []cdx.Property{
		{Name: ilm.CertificateSourceFormat, Value: "NMAP"},
		{Name: ilm.CertificateSourceFormat, Value: "PEM"},
		{Name: ilm.CertificateSourceFormat, Value: "PKCS12"},
		{Name: ilm.CertificateBase64Content, Value: sharedCertBase64},
		{Name: ilm.CertificateFingerprint, Value: sharedCertFingerprint},
	}

	for _, p := range permutations {
		name := fmt.Sprintf("%d%d%d", p[0], p[1], p[2])
		t.Run(name, func(t *testing.T) {
			builder, err := NewBuilder(model.CBOM{Version: "1.6"})
			require.NoError(t, err)

			// Rebuilt per permutation for the same reason
			// ilmCertificateProperties allocates per call: reusing one arrivals
			// slice across subtests would let permutation 012 seed 021.
			ordered := make([]model.Detection, 0, len(p))
			for _, i := range p {
				d := arrivals[i]
				ordered = append(ordered, certificateDetection(d.Source, d.Location))
			}
			builder.AppendDetections(t.Context(), ordered...)

			require.Equal(t, want, storedCertificateProperties(t, builder),
				"the emitted source formats must be the sorted union of what the "+
					"detection set observed, identical from any arrival order")

			stored := storedCertificate(t, builder)
			require.NotNil(t, stored.Evidence)
			require.NotNil(t, stored.Evidence.Occurrences)
			require.Equal(t, []cdx.EvidenceOccurrence{
				{Location: "/etc/ssl/certs/server.pem"},
				{Location: "/etc/ssl/store.p12"},
				{Location: "23.88.35.44:443"},
			}, *stored.Evidence.Occurrences,
				"the merge runs before addEvidenceLocation and must not disturb it")
		})
	}
}

// renderCertificateBOM encodes a Builder fed with detections through AsJSON, so
// the assertion lands on the delivered document rather than on builder.
// components. It goes through AsJSON rather than BOM so the merged document is
// also put through schema validation -- repeated property names are legal in
// both schemas ("Duplicate names are allowed, each potentially having a
// different value") and this is what proves it -- and it fixes the clock and the
// serial because those are the only two intentionally non-reproducible parts of
// the output.
func renderCertificateBOM(t *testing.T, version string, detections ...model.Detection) string {
	t.Helper()

	fixed := time.Date(2024, 1, 2, 3, 4, 5, 0, time.UTC)
	b, err := NewBuilder(model.CBOM{Version: version})
	require.NoError(t, err)
	b = b.WithClock(func() time.Time { return fixed }).
		WithSerial(func() string { return "urn:uuid:33333333-3333-3333-3333-333333333333" })
	b.AppendDetections(t.Context(), detections...)

	var buf bytes.Buffer
	require.NoError(t, b.AsJSON(t.Context(), &buf))
	return buf.String()
}

// TestBuilder_AppendDetections_EmittedCertificateSourceFormatIsOrderIndependent
// states the invariant where the user meets it: the delivered JSON. Comparing
// whole documents catches a merge that fixes source_format while perturbing
// something else -- occurrence order, a dropped field, a duplicated property --
// which an assertion on one field cannot.
//
// Run for both spec versions because the merge happens once, in the Builder,
// and each emitter then has to carry Properties through untouched: emit16 copies
// the component wholesale, emit17 clones only cryptoProperties and mapComponent17
// never reads Properties. A regression in either would show up here.
func TestBuilder_AppendDetections_EmittedCertificateSourceFormatIsOrderIndependent(t *testing.T) {
	arrivals := []model.Detection{
		certificateDetection("PEM", "/etc/ssl/certs/server.pem"),
		certificateDetection("PKCS12", "/etc/ssl/store.p12"),
		certificateDetection("NMAP", "23.88.35.44:443"),
	}
	permutations := [][3]int{
		{0, 1, 2}, {1, 2, 0}, {2, 1, 0},
	}

	for _, version := range []string{"1.6", "1.7"} {
		t.Run(version, func(t *testing.T) {
			var first string
			for _, p := range permutations {
				ordered := make([]model.Detection, 0, len(p))
				for _, i := range p {
					d := arrivals[i]
					ordered = append(ordered, certificateDetection(d.Source, d.Location))
				}
				got := renderCertificateBOM(t, version, ordered...)

				if first == "" {
					first = got
					continue
				}
				require.Equal(t, first, got,
					"permutation %d%d%d delivered a different document: two scans "+
						"that found the same certificate in the same three places "+
						"must deliver byte-identical CBOMs", p[0], p[1], p[2])
			}

			// A document that lost all three source formats would satisfy the
			// equality above while having discarded everything the scanners knew.
			// Decoded rather than matched as text: the values are what is being
			// asserted, and a substring built from the pretty-printer's current
			// indentation would fail opaquely the day the encoder or the nesting
			// depth changes.
			require.Equal(t, []string{"NMAP", "PEM", "PKCS12"},
				emittedSourceFormats(t, first),
				"the emitted document must carry one source_format property per "+
					"observed source, in ascending order")
		})
	}
}

// emittedSourceFormats decodes a rendered CBOM and returns the values of every
// ilm:component:certificate:source_format property on its single certificate
// component, in document order.
func emittedSourceFormats(t *testing.T, doc string) []string {
	t.Helper()

	var bom cdx.BOM
	require.NoError(t, json.Unmarshal([]byte(doc), &bom))
	require.NotNil(t, bom.Components)
	require.Len(t, *bom.Components, 1)

	compo := (*bom.Components)[0]
	require.NotNil(t, compo.Properties)

	var out []string
	for _, p := range *compo.Properties {
		if p.Name == ilm.CertificateSourceFormat {
			out = append(out, p.Value)
		}
	}
	return out
}

// withoutEvidence re-encodes doc with every component's evidence removed, so two
// documents can be compared on everything EXCEPT the occurrence list.
func withoutEvidence(t *testing.T, doc string) string {
	t.Helper()

	var bom cdx.BOM
	require.NoError(t, json.Unmarshal([]byte(doc), &bom))
	require.NotNil(t, bom.Components)
	for i := range *bom.Components {
		(*bom.Components)[i].Evidence = nil
	}
	out, err := json.MarshalIndent(bom, "", "  ")
	require.NoError(t, err)
	return string(out)
}

// TestAppendDetection_IdenticalCertificateSourceFormatIsNotRepeated covers the
// common case the union must NOT inflate: one CA certificate shipped in two
// files under /etc/ssl/certs, both read by the PEM scanner, both reporting
// source PEM. The set has one element, so the document must be the
// single-detection document plus one occurrence -- nothing else.
//
// It also asserts silence at WARN. mergeRelatedCryptoMaterialFormat reports a
// disagreement because two encodings of one key mean a producer is wrong; two
// sources for one certificate mean the certificate is deployed twice, which is
// not a defect and must never reach an operator's log.
func TestAppendDetection_IdenticalCertificateSourceFormatIsNotRepeated(t *testing.T) {
	var logBuf bytes.Buffer
	restore := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelWarn})))
	t.Cleanup(func() { slog.SetDefault(restore) })

	builder, err := NewBuilder(model.CBOM{Version: "1.6"})
	require.NoError(t, err)
	builder.AppendDetections(t.Context(),
		certificateDetection("PEM", "/etc/ssl/certs/server.pem"),
		certificateDetection("PEM", "/etc/ssl/certs/ca-bundle.pem"))

	require.Equal(t, []cdx.Property{
		{Name: ilm.CertificateSourceFormat, Value: "PEM"},
		{Name: ilm.CertificateBase64Content, Value: sharedCertBase64},
		{Name: ilm.CertificateFingerprint, Value: sharedCertFingerprint},
	}, storedCertificateProperties(t, builder),
		"one distinct source is one property: a union that appended unconditionally "+
			"would emit source_format twice with the same value")

	one := renderCertificateBOM(t, "1.6",
		certificateDetection("PEM", "/etc/ssl/certs/server.pem"))
	two := renderCertificateBOM(t, "1.6",
		certificateDetection("PEM", "/etc/ssl/certs/server.pem"),
		certificateDetection("PEM", "/etc/ssl/certs/ca-bundle.pem"))
	require.Equal(t, withoutEvidence(t, one), withoutEvidence(t, two),
		"finding the same certificate in the same format twice must change nothing "+
			"but evidence.occurrences")

	require.NotContains(t, logBuf.String(), "source format",
		"a certificate deployed in two places is normal and must not be reported "+
			"as a producer defect")
	require.NotContains(t, logBuf.String(), "disagree")
}

// TestAppendDetection_CertificateSourceFormatIsNeverInventedOnOtherAssets is the
// #213 gate one field over. source_format is an ILM CERTIFICATE property; a
// merge that appended it to whatever component happened to be stored under the
// ref would stamp certificate provenance onto an algorithm, and #213 is exactly
// that mistake made once already.
//
// The bare component pins the other half: with no cryptoProperties there is no
// asset type to check, so the merge has nothing that says this is a certificate
// and must refuse.
func TestAppendDetection_CertificateSourceFormatIsNeverInventedOnOtherAssets(t *testing.T) {
	tests := []struct {
		name   string
		stored cdx.Component
	}{
		{
			name: "algorithm",
			stored: cdx.Component{
				BOMRef: sharedCertRef,
				Name:   "www.example.com",
				Type:   cdx.ComponentTypeCryptographicAsset,
				CryptoProperties: &cdx.CryptoProperties{
					AssetType: cdx.CryptoAssetTypeAlgorithm,
				},
			},
		},
		{
			name: "related-crypto-material",
			stored: cdx.Component{
				BOMRef: sharedCertRef,
				Name:   "www.example.com",
				Type:   cdx.ComponentTypeCryptographicAsset,
				CryptoProperties: &cdx.CryptoProperties{
					AssetType: cdx.CryptoAssetTypeRelatedCryptoMaterial,
				},
			},
		},
		{
			name: "protocol",
			stored: cdx.Component{
				BOMRef: sharedCertRef,
				Name:   "www.example.com",
				Type:   cdx.ComponentTypeCryptographicAsset,
				CryptoProperties: &cdx.CryptoProperties{
					AssetType: cdx.CryptoAssetTypeProtocol,
				},
			},
		},
		{
			name: "no cryptoProperties at all",
			stored: cdx.Component{
				BOMRef: sharedCertRef,
				Name:   "www.example.com",
				Type:   cdx.ComponentTypeLibrary,
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
					Location:   "23.88.35.44:443",
					Components: []cdx.Component{tt.stored},
				},
				certificateDetection("PEM", "/etc/ssl/certs/server.pem"))

			stored := storedCertificate(t, builder)
			require.Nil(t, stored.Properties,
				"%s is not a certificate, so it must not gain a certificate's "+
					"provenance property (#213)", tt.name)
			if tt.stored.CryptoProperties != nil {
				require.Equal(t, tt.stored.CryptoProperties.AssetType,
					stored.CryptoProperties.AssetType,
					"the merge must not restate the asset type either")
			} else {
				require.Nil(t, stored.CryptoProperties,
					"cryptoProperties carries the assetType, so allocating one here "+
						"would invent an asset type no producer chose")
			}
		})
	}

	// The positive arm: a certificate stored by a producer that did not write
	// the property at all still gains it, because the asset type says the
	// property belongs. Returning early here would drop what the incoming
	// detection knew, reinstating the order dependence for that pair.
	positives := []struct {
		name       string
		storedProp *[]cdx.Property
		want       []cdx.Property
	}{
		{
			name:       "certificate with no properties at all",
			storedProp: nil,
			want: []cdx.Property{
				{Name: ilm.CertificateSourceFormat, Value: "PEM"},
			},
		},
		{
			name: "certificate with properties but no source_format",
			storedProp: &[]cdx.Property{
				{Name: ilm.CertificateBase64Content, Value: sharedCertBase64},
				{Name: ilm.CertificateFingerprint, Value: sharedCertFingerprint},
			},
			want: []cdx.Property{
				{Name: ilm.CertificateBase64Content, Value: sharedCertBase64},
				{Name: ilm.CertificateFingerprint, Value: sharedCertFingerprint},
				{Name: ilm.CertificateSourceFormat, Value: "PEM"},
			},
		},
	}

	for _, tt := range positives {
		t.Run(tt.name, func(t *testing.T) {
			builder, err := NewBuilder(model.CBOM{Version: "1.6"})
			require.NoError(t, err)

			builder.AppendDetections(t.Context(),
				certificateDetectionWithProperties("NMAP", "23.88.35.44:443", tt.storedProp),
				certificateDetection("PEM", "/etc/ssl/certs/server.pem"))

			require.Equal(t, tt.want, storedCertificateProperties(t, builder),
				"a certificate that had no source_format gains the run at the end, "+
					"leaving the properties it did have where they were")
		})
	}
}

// TestAppendDetection_EmptyCertificateSourceFormat covers the value the union
// must not treat as an observation. model.CertHit.Source is a plain string and
// nothing forces a scanner to fill it, so ilm.CertificateProperties happily
// writes source_format="". An empty string sorts before every real vocabulary
// entry, so a union that admitted it would emit a valueless property first on
// every certificate one scanner failed to label.
func TestAppendDetection_EmptyCertificateSourceFormat(t *testing.T) {
	tests := []struct {
		name           string
		storedSource   string
		incomingSource string
		want           []cdx.Property
	}{
		{
			name:           "empty stored is replaced by a real value",
			storedSource:   "",
			incomingSource: "PEM",
			want: []cdx.Property{
				{Name: ilm.CertificateSourceFormat, Value: "PEM"},
				{Name: ilm.CertificateBase64Content, Value: sharedCertBase64},
				{Name: ilm.CertificateFingerprint, Value: sharedCertFingerprint},
			},
		},
		{
			name:           "empty on both leaves the valueless property alone",
			storedSource:   "",
			incomingSource: "",
			want: []cdx.Property{
				{Name: ilm.CertificateSourceFormat, Value: ""},
				{Name: ilm.CertificateBase64Content, Value: sharedCertBase64},
				{Name: ilm.CertificateFingerprint, Value: sharedCertFingerprint},
			},
		},
		{
			name:           "empty incoming does not erase a real stored value",
			storedSource:   "PEM",
			incomingSource: "",
			want: []cdx.Property{
				{Name: ilm.CertificateSourceFormat, Value: "PEM"},
				{Name: ilm.CertificateBase64Content, Value: sharedCertBase64},
				{Name: ilm.CertificateFingerprint, Value: sharedCertFingerprint},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			builder, err := NewBuilder(model.CBOM{Version: "1.6"})
			require.NoError(t, err)

			builder.AppendDetections(t.Context(),
				certificateDetection(tt.storedSource, "/etc/ssl/certs/server.pem"),
				certificateDetection(tt.incomingSource, "23.88.35.44:443"))

			require.Equal(t, tt.want, storedCertificateProperties(t, builder))
		})
	}
}

// TestAppendDetection_CertificateSourceFormatMergeLeavesOtherPropertiesAlone
// pins that first-wins still governs every property except the one name the
// merge is scoped to. A generic property-set union would look like a tidier
// implementation and would also re-sort base64_content, drop the stored one in
// favour of the incoming one, and import whatever unrelated property a future
// producer attaches.
//
// The stored block deliberately does NOT start with source_format: the run has
// to land at the index of the FIRST source_format property, not at the head or
// the tail, or a producer that ordered its properties differently would see them
// shuffled.
func TestAppendDetection_CertificateSourceFormatMergeLeavesOtherPropertiesAlone(t *testing.T) {
	stored := []cdx.Property{
		{Name: ilm.CertificateBase64Content, Value: sharedCertBase64},
		{Name: ilm.CertificateSourceFormat, Value: "PEM"},
		{Name: ilm.CertificateFingerprint, Value: sharedCertFingerprint},
	}
	incoming := []cdx.Property{
		{Name: "ilm:component:certificate:unrelated", Value: "from the second detection"},
		{Name: ilm.CertificateSourceFormat, Value: "PKCS12"},
		{Name: ilm.CertificateBase64Content, Value: "a-different-base64-body"},
		{Name: ilm.CertificateFingerprint, Value: "sha256:different"},
	}

	builder, err := NewBuilder(model.CBOM{Version: "1.6"})
	require.NoError(t, err)
	builder.AppendDetections(t.Context(),
		certificateDetectionWithProperties("PEM", "/etc/ssl/certs/server.pem", &stored),
		certificateDetectionWithProperties("PKCS12", "/etc/ssl/store.p12", &incoming))

	require.Equal(t, []cdx.Property{
		{Name: ilm.CertificateBase64Content, Value: sharedCertBase64},
		{Name: ilm.CertificateSourceFormat, Value: "PEM"},
		{Name: ilm.CertificateSourceFormat, Value: "PKCS12"},
		{Name: ilm.CertificateFingerprint, Value: sharedCertFingerprint},
	}, storedCertificateProperties(t, builder),
		"only the source_format run may change: the stored base64_content and "+
			"fingerprint keep their values and their positions, and the incoming "+
			"detection's unrelated property is discarded like the rest of it")
}

// TestAppendDetection_CertificateSourceFormatMergeDoesNotMutateTheDetections
// pins the reason mergeCertificateSourceFormat allocates a fresh list instead of
// appending through the one it found. ilm.CertificateProperties hands out a
// slice with capacity 20 and length 3, so appending in place would land inside
// the backing array the caller's model.Detection still holds, and the stored
// component is only a shallow copy of it (appendDetection stores &compo), so its
// Properties pointer starts out aliasing the first detection's.
//
// Both detections must come out of AppendDetections exactly as they went in --
// including the FIRST one, whose slice the merge is standing on.
//
// Comparing lengths alone would not see it. An in-place append writes PAST the
// length into the producer's seventeen spare cells, leaving len and every indexed
// element unchanged, so the caller's slice still compares equal while its
// backing array now holds the merged run. The tail assertion is what catches
// that: everything from len to cap must still be the zero Property.
func TestAppendDetection_CertificateSourceFormatMergeDoesNotMutateTheDetections(t *testing.T) {
	first := certificateDetection("PEM", "/etc/ssl/certs/server.pem")
	second := certificateDetection("NMAP", "23.88.35.44:443")

	builder, err := NewBuilder(model.CBOM{Version: "1.6"})
	require.NoError(t, err)
	builder.AppendDetections(t.Context(), first, second)

	require.Equal(t, ilmCertificateProperties("PEM"), *first.Components[0].Properties,
		"the merged run must not be written into the first detection's slice")
	require.Equal(t, ilmCertificateProperties("NMAP"), *second.Components[0].Properties,
		"the incoming detection is only read")

	for _, tc := range []struct {
		name  string
		props []cdx.Property
	}{
		{"stored", *first.Components[0].Properties},
		{"incoming", *second.Components[0].Properties},
	} {
		spare := tc.props[:cap(tc.props)][len(tc.props):]
		require.NotEmpty(t, spare,
			"%s: the fixture must carry the producer's spare capacity, or an "+
				"in-place append would reallocate and this test would prove nothing",
			tc.name)
		require.Equal(t, make([]cdx.Property, len(spare)), spare,
			"%s: the merge wrote the run into the detection's spare capacity", tc.name)
	}

	// And the merge really did happen, so the assertions above are not passing
	// because nothing ran.
	require.Equal(t, []cdx.Property{
		{Name: ilm.CertificateSourceFormat, Value: "NMAP"},
		{Name: ilm.CertificateSourceFormat, Value: "PEM"},
		{Name: ilm.CertificateBase64Content, Value: sharedCertBase64},
		{Name: ilm.CertificateFingerprint, Value: sharedCertFingerprint},
	}, storedCertificateProperties(t, builder))
}

// TestAppendDetection_DependsOnMergeDoesNotMutateTheDetections pins the copy
// discipline mergeDependsOn's doc comment names. The Builder holds a *[]string,
// so there are three ways to write the union that all leave the tests above
// green: storing dep.Dependencies adopts the caller's pointer outright;
// appending through the stored *[]string grows the CALLER's slice header; and
// appending into a fresh pointer clobbers the caller's backing array wherever it
// has spare capacity.
//
// Comparing lengths alone would not see the third. An in-place append writes
// PAST the length into the producer's spare cells, leaving len and every indexed
// element unchanged, so the caller's slice still compares equal while its
// backing array now holds the merged run. The tail assertion is what catches
// that.
//
// Before this change the property held for a reason that no longer applies:
// first-wins never wrote at all. It is now load-bearing, and it is the
// dependency half of the promise AppendDetections makes and cloneOnStore keeps
// for components.
func TestAppendDetection_DependsOnMergeDoesNotMutateTheDetections(t *testing.T) {
	// Spare capacity on purpose. The literal a producer writes is len 2 cap 2,
	// where any append reallocates and the caller's slice survives by accident;
	// only room behind the length makes an in-place append observable.
	targets := make([]string, 0, 8)
	targets = append(targets, p384AlgRef, sha256AlgRef)

	first := model.Detection{
		Source:   "PEM",
		Type:     model.DetectionTypeCertificate,
		Location: "/etc/ssl/certs/p384.pem",
		Components: []cdx.Component{
			algorithmComponent(sharedSigAlgRef),
			algorithmComponent(p384AlgRef),
			algorithmComponent(sha256AlgRef),
		},
		Dependencies: []cdx.Dependency{{Ref: sharedSigAlgRef, Dependencies: &targets}},
	}
	second := sigAlgEdgeDetection("/etc/ssl/certs/p256.pem", p256AlgRef, sha256AlgRef)

	builder, err := NewBuilder(model.CBOM{Version: "1.6"})
	require.NoError(t, err)
	builder.AppendDetections(t.Context(), first, second)

	stored := builder.dependencies[sharedSigAlgRef]
	require.NotNil(t, stored)

	require.NotSame(t, &targets, stored,
		"the Builder adopted the first detection's slice pointer; every later "+
			"merge and every render would then write into the caller's detection")
	require.NotSame(t, second.Dependencies[0].Dependencies, stored,
		"the Builder adopted the second detection's slice pointer")

	require.Equal(t, []string{p384AlgRef, sha256AlgRef}, targets,
		"the merged run must not be written into the first detection's slice")
	require.Equal(t, []string{p256AlgRef, sha256AlgRef}, *second.Dependencies[0].Dependencies,
		"the incoming detection is only read")

	spare := targets[:cap(targets)][len(targets):]
	require.NotEmpty(t, spare,
		"the fixture must carry spare capacity, or an in-place append would "+
			"reallocate and this test would prove nothing")
	require.Equal(t, make([]string, len(spare)), spare,
		"the merge wrote into the first detection's backing array")

	// And the merge really did happen, so the assertions above are not passing
	// because nothing ran.
	require.Equal(t, []string{p256AlgRef, p384AlgRef, sha256AlgRef}, *stored)
}

// TestAppendDetection_DependsOnMergeSemantics enumerates what the merge does to
// every shape a dependency entry can arrive in, against every shape the map can
// already hold. The permutation test above pins the behaviour that matters to a
// user; this pins the arms that get there, including the ones no producer
// reaches today and which a refactor would therefore delete without a failure.
//
// Everything is driven through AppendDetections rather than by calling
// mergeDependsOn directly: the empty-ref guard, the loop and the merge together
// are the unit that has to be right, and a test that poked the map would prove
// nothing about the caller. The two rows whose starting state cannot be produced
// by AppendDetections at all -- a nil value, and a stored run that is out of
// order -- are seeded by poking, because after this change nothing else can
// create them, and they are exactly the states a future writer might.
//
// The pointer assertions are half the point. "Unchanged" has two meanings here:
// the same contents, which a rebuild would also give, and the same POINTER,
// which only the slices.Equal short-circuit gives. That short-circuit is what
// keeps the ordinary case -- one certificate found in three files re-presenting
// one edge set -- from allocating three times, so it is worth pinning as
// identity rather than as equality.
func TestAppendDetection_DependsOnMergeSemantics(t *testing.T) {
	const (
		a     = "crypto/algorithm/aaa@0"
		b     = "crypto/algorithm/bbb@0"
		c     = "crypto/algorithm/ccc@0"
		ghost = "crypto/algorithm/ghost@0"
	)
	// The ref the entry names, reused below as its own target.
	self := sharedSigAlgRef

	// appendDeps drives one dependency entry through the whole public path.
	appendDeps := func(t *testing.T, builder *Builder, targets *[]string) {
		t.Helper()
		builder.AppendDetections(t.Context(), model.Detection{
			Location:     "/etc/ssl/certs/server.pem",
			Dependencies: []cdx.Dependency{{Ref: self, Dependencies: targets}},
		})
	}
	seedWith := func(targets ...string) func(*testing.T, *Builder) {
		return func(t *testing.T, builder *Builder) {
			t.Helper()
			deps := targets
			appendDeps(t, builder, &deps)
		}
	}
	pokeWith := func(p *[]string) func(*testing.T, *Builder) {
		return func(_ *testing.T, builder *Builder) {
			builder.dependencies[self] = p
		}
	}

	tests := []struct {
		name string
		// seed prepares the state under self; nil leaves the ref absent.
		seed func(*testing.T, *Builder)
		// arrive is what the arriving detection's entry carries.
		arrive *[]string
		// want is the expected stored slice. wantAbsent overrides it: the key
		// must not have been created at all.
		want       []string
		wantAbsent bool
		// wantSame requires the stored POINTER to be untouched, which only the
		// slices.Equal short-circuit produces.
		wantSame bool
	}{
		{
			name:       "absent ref, nil targets, creates nothing",
			arrive:     nil,
			wantAbsent: true,
		},
		{
			name:       "absent ref, empty targets, creates nothing",
			arrive:     &[]string{},
			wantAbsent: true,
		},
		{
			name:       "absent ref, one empty target, creates nothing",
			arrive:     &[]string{""},
			wantAbsent: true,
		},
		{
			name:   "absent ref, two targets, stored sorted",
			arrive: &[]string{a, b},
			want:   []string{a, b},
		},
		{
			name:   "absent ref, unsorted targets, normalised on entry",
			arrive: &[]string{b, a},
			want:   []string{a, b},
		},
		{
			name:   "absent ref, repeated target, deduped",
			arrive: &[]string{a, a},
			want:   []string{a},
		},
		{
			name:   "nil value under the ref is treated as no edges",
			seed:   pokeWith(nil),
			arrive: &[]string{a},
			want:   []string{a},
		},
		{
			name:     "nil targets add nothing and rebuild nothing",
			seed:     seedWith(a, c),
			arrive:   nil,
			want:     []string{a, c},
			wantSame: true,
		},
		{
			name:     "empty targets add nothing and rebuild nothing",
			seed:     seedWith(a, c),
			arrive:   &[]string{},
			want:     []string{a, c},
			wantSame: true,
		},
		{
			name:     "a subset of what is stored rebuilds nothing",
			seed:     seedWith(a, c),
			arrive:   &[]string{c},
			want:     []string{a, c},
			wantSame: true,
		},
		{
			name:   "a superset of what is stored widens it",
			seed:   seedWith(c),
			arrive: &[]string{a, c},
			want:   []string{a, c},
		},
		{
			name:   "a disjoint target is folded into the middle",
			seed:   seedWith(a, c),
			arrive: &[]string{b},
			want:   []string{a, b, c},
		},
		{
			name:   "an out-of-order stored run is normalised even by a subset",
			seed:   pokeWith(&[]string{c, a}),
			arrive: &[]string{c},
			want:   []string{a, c},
		},
		{
			// The merge does not know what a self-edge means and does not decide.
			// model() resolves both endpoints and would emit it; no producer
			// builds one.
			name:   "a self-edge is not filtered",
			seed:   seedWith(a),
			arrive: &[]string{self},
			want:   []string{a, self},
		},
		{
			// At merge time "this target has no component" is not knowable: the
			// component resolving it is routinely in a detection not yet
			// appended. model() drops it later with its own warning.
			name:   "a target with no component is not filtered here",
			seed:   seedWith(a),
			arrive: &[]string{ghost},
			want:   []string{a, ghost},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			builder, err := NewBuilder(model.CBOM{Version: "1.6"})
			require.NoError(t, err)

			if tt.seed != nil {
				tt.seed(t, builder)
			}
			before, seeded := builder.dependencies[self]

			appendDeps(t, builder, tt.arrive)

			got, ok := builder.dependencies[self]
			if tt.wantAbsent {
				require.False(t, ok,
					"an empty union must create no key at all, so a nil entry and an "+
						"empty one converge: model() skips a nil silently but warns "+
						"about dropping a non-nil empty one, i.e. about zero edges")
				return
			}

			require.True(t, ok)
			require.NotNil(t, got)
			require.Equal(t, tt.want, *got)

			switch {
			case tt.wantSame:
				require.Same(t, before, got,
					"a detection that adds nothing must be a no-op down to the "+
						"allocation, not a rebuild that happens to compare equal")
			case seeded && before != nil:
				require.NotSame(t, before, got,
					"a rebuilt union must be a fresh allocation and never an append "+
						"through the pointer already stored")
			}

			if tt.arrive != nil {
				require.NotSame(t, tt.arrive, got,
					"the Builder must never adopt the detection's own slice pointer")
			}
		})
	}
}

// TestAppendDetection_DependsOnUnionIsLoggedAtDebugNotWarn pins the severity and
// the guard on the one line mergeDependsOn emits.
//
// The severity is the assertion, not decoration. Two detections describing one
// signature algorithm's edges is the ordinary scan -- a host with a certificate
// and the CRL that revokes its peers hits it every time -- and both are RIGHT,
// which is why this merge unions where mergeRelatedCryptoMaterialFormat
// tie-breaks and warns. A warning here would fire on almost every real scan and
// train operators past the one warning that means a producer is broken. The line
// still has to EXIST at DEBUG: it is what explains, to whoever is reading a
// delivered BOM, why one algorithm's dependsOn array is wider than any single
// detection claimed.
//
// The two silent cases are the guard, and neither is visible from the noisy one.
// A second detection re-presenting an edge set already stored adds no fact, and
// a rebuild that merely re-sorted adds no fact either -- announcing "came from
// more than one detection" for either would be a false statement in the log,
// and the first of them is the common case of one certificate found in three
// files.
func TestAppendDetection_DependsOnUnionIsLoggedAtDebugNotWarn(t *testing.T) {
	const line = "one ref's dependency edges came from more than one detection"

	capture := func(t *testing.T, level slog.Level, want []string, run func(*testing.T, *Builder)) string {
		t.Helper()

		var logBuf bytes.Buffer
		restore := slog.Default()
		slog.SetDefault(slog.New(slog.NewTextHandler(&logBuf, &slog.HandlerOptions{Level: level})))
		t.Cleanup(func() { slog.SetDefault(restore) })

		builder, err := NewBuilder(model.CBOM{Version: "1.6"})
		require.NoError(t, err)
		run(t, builder)

		// The merge really did reach its end state, so an empty log below means
		// the merge was silent and not that nothing happened.
		stored := builder.dependencies[sharedSigAlgRef]
		require.NotNil(t, stored)
		require.Equal(t, want, *stored)

		return logBuf.String()
	}

	// Two detections that genuinely disagree: the certificate names its own
	// public-key algorithm and the hash, the CRL names only the hash.
	widening := func(t *testing.T, builder *Builder) {
		t.Helper()
		builder.AppendDetections(t.Context(),
			sigAlgEdgeDetection("/etc/ssl/crl/revocations.crl", sha256AlgRef),
			sigAlgEdgeDetection("/etc/ssl/certs/p384.pem", p384AlgRef, sha256AlgRef))
	}
	wantWidened := []string{p384AlgRef, sha256AlgRef}

	t.Run("silent at warn", func(t *testing.T) {
		require.Empty(t, capture(t, slog.LevelWarn, wantWidened, widening),
			"a certificate and a CRL signed with one algorithm are both right; "+
				"reporting them at WARN would fire on the common path")
	})

	t.Run("explained at debug", func(t *testing.T) {
		logged := capture(t, slog.LevelDebug, wantWidened, widening)
		require.Contains(t, logged, "level=DEBUG")
		require.Equal(t, 1, strings.Count(logged, line),
			"the first store is not a union and must not be announced; only the "+
				"arrival that widened an existing set is")
		require.Contains(t, logged, "ref="+sharedSigAlgRef)
		require.Contains(t, logged, "edges="+p384AlgRef+","+sha256AlgRef,
			"the line names every edge that survived, in the order emitted")
		require.Contains(t, logged, "added=1")
	})

	t.Run("a repeated edge set is not announced", func(t *testing.T) {
		logged := capture(t, slog.LevelDebug, wantWidened, func(t *testing.T, builder *Builder) {
			t.Helper()
			builder.AppendDetections(t.Context(),
				sigAlgEdgeDetection("/etc/ssl/certs/ca.pem", p384AlgRef, sha256AlgRef),
				sigAlgEdgeDetection("/etc/ssl/certs/ca-bundle.pem", p384AlgRef, sha256AlgRef))
		})
		require.NotContains(t, logged, line,
			"one certificate found in two files re-presents the identical edge "+
				"set; nothing was folded in and the merge did not even allocate")
	})

	t.Run("a rebuild that only re-sorted is not announced", func(t *testing.T) {
		logged := capture(t, slog.LevelDebug, wantWidened, func(t *testing.T, builder *Builder) {
			t.Helper()
			// Only a poke can produce an out-of-order stored run now, which is
			// why this arm has no reachable producer -- and why nothing else
			// would catch a log statement moved above the widening guard.
			builder.dependencies[sharedSigAlgRef] = &[]string{sha256AlgRef, p384AlgRef}
			builder.AppendDetections(t.Context(),
				sigAlgEdgeDetection("/etc/ssl/crl/revocations.crl", sha256AlgRef))
		})
		require.NotContains(t, logged, line,
			"the run was rewritten, but no edge was added: saying it came from "+
				"more than one detection would be untrue")
	})
}

// TestAppendDetection_CertificateSourceFormatAbsentWhenIlmIsOff guards the
// vanilla-CycloneDX contract. --ilm off means certComponent never assigns
// Properties, so the merge reads no source formats off the incoming component
// and must be a total no-op: no allocation, no empty "properties": [] array, no
// property name that exists only because ILM extensions were compiled in.
//
// This is also what keeps the golden corpus still: golden_test.go builds its
// Converter without WithIlmExtensions, so every corpus merge takes this path.
func TestAppendDetection_CertificateSourceFormatAbsentWhenIlmIsOff(t *testing.T) {
	for _, version := range []string{"1.6", "1.7"} {
		t.Run(version, func(t *testing.T) {
			builder, err := NewBuilder(model.CBOM{Version: version})
			require.NoError(t, err)

			builder.AppendDetections(t.Context(),
				certificateDetectionWithProperties("PEM", "/etc/ssl/certs/server.pem", nil),
				certificateDetectionWithProperties("NMAP", "23.88.35.44:443", nil))

			require.Nil(t, storedCertificate(t, builder).Properties,
				"a merge that allocated here would put an empty properties array "+
					"into every non-ILM document")

			doc := renderCertificateBOM(t, version,
				certificateDetectionWithProperties("PEM", "/etc/ssl/certs/server.pem", nil),
				certificateDetectionWithProperties("NMAP", "23.88.35.44:443", nil))

			var bom cdx.BOM
			require.NoError(t, json.Unmarshal([]byte(doc), &bom))
			require.NotNil(t, bom.Components)
			require.Len(t, *bom.Components, 1)
			require.Nil(t, (*bom.Components)[0].Properties,
				"the certificate component must carry no properties at all")
			require.NotContains(t, doc, ilm.CertificateSourceFormat,
				"the ILM property name must not appear anywhere in a non-ILM document")
		})
	}
}

// TestAppendDetection_CertificateSourceFormatRunLandsAtTheFirstIndex pins WHICH
// source_format property the merged run replaces, which its sibling above cannot:
// every certificate the Builder itself produces carries the run contiguously, and
// when a run is contiguous, rewriting it at its first entry and rewriting it at
// its last entry produce the same list. Only a stored block whose source_format
// properties are SEPARATED by another property tells the two apart.
//
// Repeated property names are explicitly legal in both schemas ("Duplicate names
// are allowed, each potentially having a different value") and nothing obliges a
// producer to keep them adjacent, so the shape below is a legal component, not a
// corrupted one. mergeCertificateSourceFormat promises such a producer that its
// ordering survives: the run lands where the FIRST source_format was and every
// later one is dropped. Appending at the end instead -- or at the last index --
// would move base64_content and fingerprint ahead of the provenance the producer
// deliberately put between them, which is the property shuffling the merge
// exists to avoid.
func TestAppendDetection_CertificateSourceFormatRunLandsAtTheFirstIndex(t *testing.T) {
	stored := []cdx.Property{
		{Name: ilm.CertificateBase64Content, Value: sharedCertBase64},
		{Name: ilm.CertificateSourceFormat, Value: "PEM"},
		{Name: ilm.CertificateFingerprint, Value: sharedCertFingerprint},
		{Name: ilm.CertificateSourceFormat, Value: "DER"},
	}

	builder, err := NewBuilder(model.CBOM{Version: "1.6"})
	require.NoError(t, err)
	builder.AppendDetections(t.Context(),
		certificateDetectionWithProperties("PEM", "/etc/ssl/certs/server.pem", &stored),
		certificateDetection("PKCS12", "/etc/ssl/store.p12"))

	require.Equal(t, []cdx.Property{
		{Name: ilm.CertificateBase64Content, Value: sharedCertBase64},
		{Name: ilm.CertificateSourceFormat, Value: "DER"},
		{Name: ilm.CertificateSourceFormat, Value: "PEM"},
		{Name: ilm.CertificateSourceFormat, Value: "PKCS12"},
		{Name: ilm.CertificateFingerprint, Value: sharedCertFingerprint},
	}, storedCertificateProperties(t, builder),
		"the whole run replaces the FIRST source_format and the trailing one is "+
			"dropped, so fingerprint keeps the position its producer gave it "+
			"instead of being overtaken by the provenance run")
}

// TestAppendDetection_DetectionAddingNoNewSourceLeavesTheStoredRunAlone pins the
// two early returns that make a detection observing nothing NEW a total no-op
// rather than a rewrite: the merge is a union, and a union with nothing to add
// must not touch the list at all.
//
// The two returns are not the same condition and neither implies the other.
// The first fires when the incoming component carries no source_format at all
// (cases 1 and 2 below), which is where an --ilm-off detection and an unlabelled
// hit both land. The second, slices.Equal(merged, storedValues), fires only when
// the stored run ALREADY reads as the sorted union in document order (case 3).
//
// That second condition is deliberately narrower than "the set did not change",
// and the distinction is the whole reason its sibling
// TestAppendDetection_CertificateSourceFormatRebuildNormalisesTheStoredRun
// exists: a stored run that is out of order or repeats a value is NOT equal to
// the sorted union even when the union adds nothing, so it is rebuilt and
// normalised. Nothing here contradicts that -- cases 1 and 2 keep their
// disordered runs because the incoming detection never reaches slices.Equal at
// all, and case 3's run is already ascending.
//
// "Not touch" needs a stored list a rewrite would visibly disturb, because a
// merge that simply re-derived the run would reproduce an already-sorted,
// already-deduped, already-contiguous run byte for byte and look correct. The
// blocks below are the ones that betray it: one orders its run descending, one
// repeats a value, one puts base64_content between its two source formats. None
// is a shape the Builder emits, and that is the point -- they are what another
// producer's list can legally look like, since repeated property names are
// explicitly allowed and nothing requires them to be adjacent.
//
// The last case is the one the pair test cannot reach: two detections that agree
// on PEM against a stored component that already knows DER and PEM. The set does
// not change and the stored run is already ascending, so slices.Equal holds and
// nothing is rewritten -- and because that run is INTERLEAVED with the other
// properties, a merge that rebuilt anyway would compact it and be caught.
func TestAppendDetection_DetectionAddingNoNewSourceLeavesTheStoredRunAlone(t *testing.T) {
	// The incoming block for the first two cases. detection.Source still says
	// NMAP, but the component does not CARRY a source_format: the merge reads
	// the producer's property and never the scanner's label, so this has to be
	// the same no-op as a detection with no properties at all.
	sourceless := []cdx.Property{
		{Name: ilm.CertificateBase64Content, Value: sharedCertBase64},
		{Name: ilm.CertificateFingerprint, Value: sharedCertFingerprint},
	}

	tests := []struct {
		name     string
		stored   []cdx.Property
		incoming []cdx.Property
	}{
		{
			name: "no source_format on the detection: descending run is not re-sorted",
			stored: []cdx.Property{
				{Name: ilm.CertificateSourceFormat, Value: "PEM"},
				{Name: ilm.CertificateSourceFormat, Value: "DER"},
				{Name: ilm.CertificateBase64Content, Value: sharedCertBase64},
				{Name: ilm.CertificateFingerprint, Value: sharedCertFingerprint},
			},
			incoming: sourceless,
		},
		{
			name: "no source_format on the detection: repeated value is not collapsed",
			stored: []cdx.Property{
				{Name: ilm.CertificateSourceFormat, Value: "PEM"},
				{Name: ilm.CertificateSourceFormat, Value: "PEM"},
				{Name: ilm.CertificateBase64Content, Value: sharedCertBase64},
				{Name: ilm.CertificateFingerprint, Value: sharedCertFingerprint},
			},
			incoming: sourceless,
		},
		{
			name: "source already recorded: interleaved run is not compacted",
			stored: []cdx.Property{
				{Name: ilm.CertificateBase64Content, Value: sharedCertBase64},
				{Name: ilm.CertificateSourceFormat, Value: "DER"},
				{Name: ilm.CertificateFingerprint, Value: sharedCertFingerprint},
				{Name: ilm.CertificateSourceFormat, Value: "PEM"},
			},
			incoming: ilmCertificateProperties("PEM"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			want := append([]cdx.Property(nil), tt.stored...)

			builder, err := NewBuilder(model.CBOM{Version: "1.6"})
			require.NoError(t, err)
			builder.AppendDetections(t.Context(),
				certificateDetectionWithProperties("PEM", "/etc/ssl/certs/server.pem", &tt.stored),
				certificateDetectionWithProperties("NMAP", "23.88.35.44:443", &tt.incoming))

			require.Equal(t, want, storedCertificateProperties(t, builder),
				"this detection never reaches the rebuild, so the stored list must "+
					"come through byte for byte: not reordered, not deduped, not "+
					"compacted")

			// And the detection was really merged, so the no-op above is the
			// merge declining to change anything rather than the two components
			// never having collided.
			stored := storedCertificate(t, builder)
			require.NotNil(t, stored.Evidence)
			require.NotNil(t, stored.Evidence.Occurrences)
			require.Equal(t, []cdx.EvidenceOccurrence{
				{Location: "/etc/ssl/certs/server.pem"},
				{Location: "23.88.35.44:443"},
			}, *stored.Evidence.Occurrences)
		})
	}
}

// TestAppendDetection_CertificateSourceFormatRebuildNormalisesTheStoredRun is the
// other half of its sibling above, and states the bound on how far that no-op
// reaches: the early return is slices.Equal(merged, storedValues), an
// order-sensitive comparison against DOCUMENT order, not a test of set
// membership. A stored run that is out of order or repeats a value is therefore
// NOT equal to the sorted union even when the incoming detection adds nothing to
// the set, so it is rebuilt -- and the rebuild always emits the run ascending and
// deduped.
//
// Both cases below add nothing to the SET (stored already knows DER) while
// differing from the sorted union as a SEQUENCE, which is exactly the gap
// between the two notions. Without them slices.Equal is only ever exercised in
// its already-canonical form, where the cheaper and WRONG
// len(merged) == len(storedValues) is indistinguishable from it: against a
// stored run of [PEM, PEM] with DER arriving, that comparison sees 2 == 2,
// returns early and silently drops DER -- losing a source the scan really
// observed, which is the defect this whole merge exists to prevent.
func TestAppendDetection_CertificateSourceFormatRebuildNormalisesTheStoredRun(t *testing.T) {
	tests := []struct {
		name   string
		stored []cdx.Property
		want   []cdx.Property
	}{
		{
			name: "descending run is re-sorted",
			stored: []cdx.Property{
				{Name: ilm.CertificateSourceFormat, Value: "PEM"},
				{Name: ilm.CertificateSourceFormat, Value: "DER"},
				{Name: ilm.CertificateBase64Content, Value: sharedCertBase64},
				{Name: ilm.CertificateFingerprint, Value: sharedCertFingerprint},
			},
			want: []cdx.Property{
				{Name: ilm.CertificateSourceFormat, Value: "DER"},
				{Name: ilm.CertificateSourceFormat, Value: "PEM"},
				{Name: ilm.CertificateBase64Content, Value: sharedCertBase64},
				{Name: ilm.CertificateFingerprint, Value: sharedCertFingerprint},
			},
		},
		{
			// The case the length comparison cannot tell from the real one: the
			// stored run and the sorted union are both two entries long, but the
			// stored one says PEM twice and knows nothing of DER.
			name: "repeated value is deduped and the new source still lands",
			stored: []cdx.Property{
				{Name: ilm.CertificateSourceFormat, Value: "PEM"},
				{Name: ilm.CertificateSourceFormat, Value: "PEM"},
				{Name: ilm.CertificateBase64Content, Value: sharedCertBase64},
				{Name: ilm.CertificateFingerprint, Value: sharedCertFingerprint},
			},
			want: []cdx.Property{
				{Name: ilm.CertificateSourceFormat, Value: "DER"},
				{Name: ilm.CertificateSourceFormat, Value: "PEM"},
				{Name: ilm.CertificateBase64Content, Value: sharedCertBase64},
				{Name: ilm.CertificateFingerprint, Value: sharedCertFingerprint},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			builder, err := NewBuilder(model.CBOM{Version: "1.6"})
			require.NoError(t, err)
			builder.AppendDetections(t.Context(),
				certificateDetectionWithProperties("PEM", "/etc/ssl/certs/server.pem", &tt.stored),
				certificateDetection("DER", "/etc/ssl/certs/server.der"))

			require.Equal(t, tt.want, storedCertificateProperties(t, builder),
				"a detection that reaches the rebuild gets the sorted, deduped "+
					"union, and DER must survive it")
		})
	}
}

// TestAppendDetection_CertificateSourceFormatMatchesOneExactPropertyName pins
// that the merge is keyed on ilm:component:certificate:source_format by exact,
// case-sensitive, whole-string comparison. Property names are opaque strings in
// both schemas, so a name that merely resembles this one is a DIFFERENT
// property belonging to someone else.
//
// The two decoys are the two ways the comparison plausibly rots. A prefix match
// on "ilm:component:certificate:" would swallow base64_content and fingerprint
// as if they were provenance -- emitting a certificate's own bytes as a source
// format. A case-insensitive match would read the differently-cased name as
// ours, fold its value into the run, and then leave the original in place
// because the rebuild loop still compares exactly, emitting the value twice.
// Both decoys must come through untouched, in their original positions, and
// neither may contribute a value to the run.
func TestAppendDetection_CertificateSourceFormatMatchesOneExactPropertyName(t *testing.T) {
	const (
		differentCase = "ILM:Component:Certificate:Source_Format"
		longerName    = ilm.CertificateSourceFormat + "_legacy"
	)

	stored := []cdx.Property{
		{Name: ilm.CertificateSourceFormat, Value: "PEM"},
		{Name: differentCase, Value: "DER"},
		{Name: longerName, Value: "JKS"},
		{Name: ilm.CertificateBase64Content, Value: sharedCertBase64},
		{Name: ilm.CertificateFingerprint, Value: sharedCertFingerprint},
	}

	builder, err := NewBuilder(model.CBOM{Version: "1.6"})
	require.NoError(t, err)
	builder.AppendDetections(t.Context(),
		certificateDetectionWithProperties("PEM", "/etc/ssl/certs/server.pem", &stored),
		certificateDetection("PKCS12", "/etc/ssl/store.p12"))

	require.Equal(t, []cdx.Property{
		{Name: ilm.CertificateSourceFormat, Value: "PEM"},
		{Name: ilm.CertificateSourceFormat, Value: "PKCS12"},
		{Name: differentCase, Value: "DER"},
		{Name: longerName, Value: "JKS"},
		{Name: ilm.CertificateBase64Content, Value: sharedCertBase64},
		{Name: ilm.CertificateFingerprint, Value: sharedCertFingerprint},
	}, storedCertificateProperties(t, builder),
		"only the exactly-named property is merged: DER and JKS belong to other "+
			"properties and must neither join the run nor lose their places")
}

// TestAppendDetection_CertificateSourceFormatUnionIsLoggedAtDebugNotWarn pins
// the severity of the one line the merge emits. Its sibling
// TestAppendDetection_IdenticalCertificateSourceFormatIsNotRepeated asserts
// silence at WARN, but it feeds ONE distinct source, where len(merged) is 1 and
// no line is emitted at any level -- so it would still pass if the union logged
// at WARN, ERROR or not at all. Only two distinct sources reach the log
// statement.
//
// The severity is the assertion, not decoration. A certificate that sits in
// /etc/ssl/certs and is also served on 443 is the ordinary deployment, not a
// producer defect: mergeRelatedCryptoMaterialFormat warns because two encodings
// of one key mean somebody is wrong, whereas two sources for one certificate
// mean the certificate is deployed twice. Warning here would fire on almost
// every real scan and train operators to ignore the one warning that matters.
// The line still has to EXIST at DEBUG, because it is what explains a
// certificate carrying two provenance values to whoever is reading the BOM.
//
// The third subtest pins the len(merged) > 1 guard on that line, which the two
// above cannot see: they merge two sources, so the guard holds either way. A
// merge that rebuilds a run of ONE -- an unlabelled hit later given a real
// source -- still reaches the log statement, and unguarded it would announce
// "certificate observed in more than one source format" with a single value
// beside it, which is simply untrue.
func TestAppendDetection_CertificateSourceFormatUnionIsLoggedAtDebugNotWarn(t *testing.T) {
	capture := func(t *testing.T, level slog.Level, detections []model.Detection, want []cdx.Property) string {
		t.Helper()

		var logBuf bytes.Buffer
		restore := slog.Default()
		slog.SetDefault(slog.New(slog.NewTextHandler(&logBuf, &slog.HandlerOptions{Level: level})))
		t.Cleanup(func() { slog.SetDefault(restore) })

		builder, err := NewBuilder(model.CBOM{Version: "1.6"})
		require.NoError(t, err)
		builder.AppendDetections(t.Context(), detections...)

		// The merge really did run and rewrite the list, so an empty log below
		// means the merge was silent and not that nothing happened.
		require.Equal(t, want, storedCertificateProperties(t, builder))

		return logBuf.String()
	}

	// Two distinct sources: the union really is plural.
	twoSources := []model.Detection{
		certificateDetection("PEM", "/etc/ssl/certs/server.pem"),
		certificateDetection("NMAP", "23.88.35.44:443"),
	}
	wantTwo := []cdx.Property{
		{Name: ilm.CertificateSourceFormat, Value: "NMAP"},
		{Name: ilm.CertificateSourceFormat, Value: "PEM"},
		{Name: ilm.CertificateBase64Content, Value: sharedCertBase64},
		{Name: ilm.CertificateFingerprint, Value: sharedCertFingerprint},
	}

	// One distinct source, but the rebuild still runs: the stored detection was
	// never labelled (model.CertHit.Source empty, so source_format=""), and the
	// second one supplies the real value. The empty string is not an observation,
	// so the union has exactly one element -- and the log statement is reached.
	oneSource := []model.Detection{
		certificateDetection("", "/etc/ssl/certs/server.pem"),
		certificateDetection("PEM", "23.88.35.44:443"),
	}
	wantOne := []cdx.Property{
		{Name: ilm.CertificateSourceFormat, Value: "PEM"},
		{Name: ilm.CertificateBase64Content, Value: sharedCertBase64},
		{Name: ilm.CertificateFingerprint, Value: sharedCertFingerprint},
	}

	t.Run("silent at warn", func(t *testing.T) {
		require.Empty(t, capture(t, slog.LevelWarn, twoSources, wantTwo),
			"a certificate found on disk and on the wire is normal operations; "+
				"reporting it at WARN would fire on the common path")
	})

	t.Run("explained at debug", func(t *testing.T) {
		logged := capture(t, slog.LevelDebug, twoSources, wantTwo)
		require.Contains(t, logged, "level=DEBUG")
		require.Contains(t, logged, "certificate observed in more than one source format")
		require.Contains(t, logged, "ref="+sharedCertRef)
		require.Contains(t, logged, "source_formats=NMAP,PEM",
			"the line names every source that was folded in, in the order emitted")
	})

	t.Run("a single source is not announced as more than one", func(t *testing.T) {
		logged := capture(t, slog.LevelDebug, oneSource, wantOne)
		require.NotContains(t, logged, "certificate observed in more than one source format",
			"the merge rewrote the list but folded in exactly one source; saying "+
				"it observed more than one would be a false statement in the log")
		require.NotContains(t, logged, "source_formats=")
	})
}

// TestMergeCertificateSourceFormat_NilComponentsAreIgnored pins the guard that
// mirrors mergeRelatedCryptoMaterialFormat's. appendDetection cannot pass nil
// today -- stored comes from a map hit and incoming is &compo -- so the guard
// exists for the next caller, and a guard no test exercises is a guard the next
// refactor deletes. Dropping it does not fail loudly either: a nil incoming
// still returns early through certificateSourceFormats' own nil check, and a nil
// stored survives that same check, so it runs on to panic on the first READ of
// stored.Properties -- several statements after the point that actually went
// wrong, and only once some detection carries a source_format at all, since an
// --ilm-off run returns before ever reaching it.
//
// Called directly rather than through AppendDetections because there is no
// detection shape that produces a nil component pointer.
func TestMergeCertificateSourceFormat_NilComponentsAreIgnored(t *testing.T) {
	props := ilmCertificateProperties("PEM")
	compo := cdx.Component{
		BOMRef:     sharedCertRef,
		Name:       "www.example.com",
		Type:       cdx.ComponentTypeCryptographicAsset,
		Properties: &props,
		CryptoProperties: &cdx.CryptoProperties{
			AssetType: cdx.CryptoAssetTypeCertificate,
		},
	}

	require.NotPanics(t, func() {
		mergeCertificateSourceFormat(t.Context(), nil, &compo)
	}, "a nil stored component has no property list to write the run into")
	require.NotPanics(t, func() {
		mergeCertificateSourceFormat(t.Context(), &compo, nil)
	}, "a nil incoming component observed nothing")
	require.NotPanics(t, func() {
		mergeCertificateSourceFormat(t.Context(), nil, nil)
	})

	require.Equal(t, ilmCertificateProperties("PEM"), *compo.Properties,
		"the component that was not nil must come back untouched")
}
