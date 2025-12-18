package bom_test

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"

	"github.com/CZERTAINLY/CBOM-lens/internal/bom"
	"github.com/CZERTAINLY/CBOM-lens/internal/model"
	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/stretchr/testify/require"
)

func TestNewBuilder(t *testing.T) {
	b, err := bom.NewBuilder(model.CBOM{Version: "1.6"})

	require.NoError(t, err)
	require.NotNil(t, b)
}

func TestNewBuilder_Fail(t *testing.T) {
	b, err := bom.NewBuilder(model.CBOM{Version: "45.2"})

	require.Error(t, err)
	require.Nil(t, b)
}

func TestBuilder_AppendDetections(t *testing.T) {
	ctx := context.Background()

	tests := []struct {
		name         string
		detections   []model.Detection
		wantBOMCheck func(t *testing.T, result cdx.BOM)
	}{
		{
			name: "single detection with one component",
			detections: []model.Detection{
				{
					Source:   "PEM",
					Type:     model.DetectionTypeCertificate,
					Location: "/test/cert.pem",
					Components: []cdx.Component{
						{
							Type:   cdx.ComponentTypeCryptographicAsset,
							Name:   "Test-Cert",
							BOMRef: "crypto/cert/test@123",
						},
					},
					Dependencies: []cdx.Dependency{
						{
							Ref:          "crypto/cert/test@123",
							Dependencies: &[]string{},
						},
					},
				},
			},
			wantBOMCheck: func(t *testing.T, result cdx.BOM) {
				require.NotNil(t, result.Components)
				require.NotEmpty(t, *result.Components)

				// Find the component
				var found bool
				for _, c := range *result.Components {
					if c.BOMRef == "crypto/cert/test@123" {
						found = true
						require.NotNil(t, c.Evidence)
						require.NotNil(t, c.Evidence.Occurrences)
						require.Len(t, *c.Evidence.Occurrences, 1)
						require.Equal(t, "/test/cert.pem", (*c.Evidence.Occurrences)[0].Location)
					}
				}
				require.True(t, found, "component not found")
			},
		},
		{
			name: "multiple detections with same component from different locations",
			detections: []model.Detection{
				{
					Source:   "PEM",
					Type:     model.DetectionTypeCertificate,
					Location: "/test/cert1.pem",
					Components: []cdx.Component{
						{
							Type:   cdx.ComponentTypeCryptographicAsset,
							Name:   "Test-Cert",
							BOMRef: "crypto/cert/test@123",
						},
					},
					Dependencies: []cdx.Dependency{
						{
							Ref:          "crypto/cert/test@123",
							Dependencies: &[]string{},
						},
					},
				},
				{
					Source:   "PEM",
					Type:     model.DetectionTypeCertificate,
					Location: "/test/cert2.pem",
					Components: []cdx.Component{
						{
							Type:   cdx.ComponentTypeCryptographicAsset,
							Name:   "Test-Cert",
							BOMRef: "crypto/cert/test@123",
						},
					},
					Dependencies: []cdx.Dependency{
						{
							Ref:          "crypto/cert/test@123",
							Dependencies: &[]string{},
						},
					},
				},
			},
			wantBOMCheck: func(t *testing.T, result cdx.BOM) {
				require.NotNil(t, result.Components)

				// Find the component and verify it has both locations
				var found bool
				for _, c := range *result.Components {
					if c.BOMRef == "crypto/cert/test@123" {
						found = true
						require.NotNil(t, c.Evidence)
						require.NotNil(t, c.Evidence.Occurrences)
						require.Len(t, *c.Evidence.Occurrences, 2)

						locations := make([]string, 0, 2)
						for _, occ := range *c.Evidence.Occurrences {
							locations = append(locations, occ.Location)
						}
						require.ElementsMatch(t, []string{"/test/cert1.pem", "/test/cert2.pem"}, locations)
					}
				}
				require.True(t, found, "component not found")
			},
		},
		{
			name: "multiple detections with different components",
			detections: []model.Detection{
				{
					Source:   "PEM",
					Type:     model.DetectionTypeCertificate,
					Location: "/test/cert1.pem",
					Components: []cdx.Component{
						{
							Type:   cdx.ComponentTypeCryptographicAsset,
							Name:   "Test-Cert-1",
							BOMRef: "crypto/cert/test1@123",
						},
					},
					Dependencies: []cdx.Dependency{
						{
							Ref:          "crypto/cert/test1@123",
							Dependencies: &[]string{},
						},
					},
				},
				{
					Source:   "PEM",
					Type:     model.DetectionTypeCertificate,
					Location: "/test/cert2.pem",
					Components: []cdx.Component{
						{
							Type:   cdx.ComponentTypeCryptographicAsset,
							Name:   "Test-Cert-2",
							BOMRef: "crypto/cert/test2@456",
						},
					},
					Dependencies: []cdx.Dependency{
						{
							Ref:          "crypto/cert/test2@456",
							Dependencies: &[]string{},
						},
					},
				},
			},
			wantBOMCheck: func(t *testing.T, result cdx.BOM) {
				require.NotNil(t, result.Components)
				require.GreaterOrEqual(t, len(*result.Components), 2)

				foundRefs := make(map[string]bool)
				for _, c := range *result.Components {
					foundRefs[c.BOMRef] = true
				}

				require.True(t, foundRefs["crypto/cert/test1@123"], "component test1 not found")
				require.True(t, foundRefs["crypto/cert/test2@456"], "component test2 not found")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b, err := bom.NewBuilder(model.CBOM{Version: "1.6"})
			require.NoError(t, err)
			b.AppendDetections(ctx, tt.detections...)
			result := b.BOM()

			tt.wantBOMCheck(t, result)
		})
	}
}

func TestBuilder_BOM(t *testing.T) {
	ctx := context.Background()
	b, err := bom.NewBuilder(model.CBOM{Version: "1.6"})
	require.NoError(t, err)

	detection := model.Detection{
		Source:   "PEM",
		Type:     model.DetectionTypeCertificate,
		Location: "/test/cert.pem",
		Components: []cdx.Component{
			{
				Type:   cdx.ComponentTypeCryptographicAsset,
				Name:   "Test-Cert",
				BOMRef: "crypto/cert/test@123",
			},
		},
		Dependencies: []cdx.Dependency{
			{
				Ref:          "crypto/cert/test@123",
				Dependencies: &[]string{"crypto/key/test@456"},
			},
		},
	}

	b.AppendDetections(ctx, detection)
	result := b.BOM()

	// Basic structure checks
	require.Equal(t, "https://cyclonedx.org/schema/bom-1.6.schema.json", result.JSONSchema)
	require.Equal(t, "CycloneDX", result.BOMFormat)
	require.Equal(t, cdx.SpecVersion1_6, result.SpecVersion)
	require.NotEmpty(t, result.SerialNumber)
	require.Contains(t, result.SerialNumber, "urn:uuid:")
	require.Equal(t, 1, result.Version)

	// Metadata checks
	require.NotNil(t, result.Metadata)
	require.NotEmpty(t, result.Metadata.Timestamp)
	require.NotNil(t, result.Metadata.Component)
	require.Equal(t, "application", string(result.Metadata.Component.Type))
	require.Equal(t, "CBOM-Lens", result.Metadata.Component.Name)

	// Components check
	require.NotNil(t, result.Components)
	require.NotEmpty(t, *result.Components)

	// Dependencies check
	require.NotNil(t, result.Dependencies)
	require.NotEmpty(t, *result.Dependencies)
}

func TestBuilder_AsJSON(t *testing.T) {
	ctx := context.Background()
	b, err := bom.NewBuilder(model.CBOM{Version: "1.6"})
	require.NoError(t, err)

	detection := model.Detection{
		Source:   "PEM",
		Type:     model.DetectionTypeCertificate,
		Location: "/test/cert.pem",
		Components: []cdx.Component{
			{
				Type:   cdx.ComponentTypeCryptographicAsset,
				Name:   "Test-Cert",
				BOMRef: "crypto/cert/test@123",
			},
		},
		Dependencies: []cdx.Dependency{
			{
				Ref:          "crypto/cert/test@123",
				Dependencies: &[]string{},
			},
		},
	}

	b.AppendDetections(ctx, detection)

	var buf bytes.Buffer
	err = b.AsJSON(&buf)
	require.NoError(t, err)
	require.NotEmpty(t, buf.String())

	// Verify it's valid JSON
	var jsonResult map[string]any
	err = json.Unmarshal(buf.Bytes(), &jsonResult)
	require.NoError(t, err)

	// Check basic JSON structure
	require.Equal(t, "CycloneDX", jsonResult["bomFormat"])
	require.Equal(t, "1.6", jsonResult["specVersion"])
}
