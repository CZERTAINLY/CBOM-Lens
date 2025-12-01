package bom_test

import (
	"bytes"
	"testing"

	"github.com/CZERTAINLY/CBOM-lens/internal/bom"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/stretchr/testify/require"
)

func TestValidator_Validate_Errors(t *testing.T) {
	// given
	validator, err := bom.NewValidator(cdx.SpecVersion1_6)
	require.NoError(t, err)

	tests := []struct {
		scenario string
		given    func(*cdx.BOM)
		then     string
	}{
		{
			scenario: "when components is empty",
			given: func(bom *cdx.BOM) {
				var empty []cdx.Component
				bom.Components = &empty
			},
			then: "BOM validation failed:\nproperties: Property 'components' does not match the schema",
		},
	}

	for _, tt := range tests {
		t.Run(tt.scenario, func(t *testing.T) {
			// when bom
			b := bom.NewBuilder()
			bom := b.BOM()
			tt.given(&bom)

			// and when []byte
			var buf bytes.Buffer
			enc := cdx.NewBOMEncoder(&buf, cdx.BOMFileFormatJSON)
			require.NoError(t, enc.Encode(&bom))

			errBOM := validator.Validate(&bom)
			errBytes := validator.ValidateBytes(buf.Bytes())

			if errBOM == nil {
				t.Logf("%s", buf.String())
			}

			// then
			require.Error(t, errBOM)
			require.Contains(t, errBOM.Error(), tt.then)
			require.Error(t, errBytes)
			require.Contains(t, errBytes.Error(), tt.then)
		})
	}
}

func TestValidator_Validate(t *testing.T) {
	// given
	validator, err := bom.NewValidator(cdx.SpecVersion1_6)
	require.NoError(t, err)

	tests := []struct {
		scenario string
		given    bom.Builder
	}{
		{
			scenario: "empty builder",
			given:    *bom.NewBuilder(),
		},
	}

	for _, tt := range tests {
		t.Run(tt.scenario, func(t *testing.T) {
			// when
			bom := tt.given.BOM()
			var buf bytes.Buffer
			enc := cdx.NewBOMEncoder(&buf, cdx.BOMFileFormatJSON)
			require.NoError(t, enc.Encode(&bom))

			errBOM := validator.Validate(&bom)
			errBytes := validator.ValidateBytes(buf.Bytes())

			if errBOM != nil {
				t.Logf("%s", buf.String())
			}
			// then
			require.NoError(t, errBOM)
			require.NoError(t, errBytes)
		})
	}
}

func TestValidator_UnsupportedVersion(t *testing.T) {
	_, err := bom.NewValidator(cdx.SpecVersion1_0)
	require.Error(t, err)
	require.EqualError(t, err, "unknown schema version: 1.0")

	validator, err := bom.NewValidator(cdx.SpecVersion1_6)
	require.NoError(t, err)
	b := bom.NewBuilder()
	bom := b.BOM()

	bom.SpecVersion = cdx.SpecVersion1_5

	var buf bytes.Buffer
	enc := cdx.NewBOMEncoder(&buf, cdx.BOMFileFormatJSON)
	require.NoError(t, enc.Encode(&bom))

	errBOM := validator.Validate(&bom)
	errBytes := validator.ValidateBytes(buf.Bytes())

	require.Error(t, errBOM)
	require.EqualError(t, errBOM, "unsupported BOM specification version: supported 1.6: got: 1.5")
	require.Error(t, errBytes)
	require.EqualError(t, errBytes, "unsupported BOM specification version: supported 1.6: got: 1.5")

}
