package cdxprops_test

import (
	"testing"

	"github.com/CZERTAINLY/CBOM-lens/internal/cdxprops"
	"github.com/CZERTAINLY/CBOM-lens/internal/cdxprops/cdxtest"
	"github.com/CZERTAINLY/CBOM-lens/internal/model"

	"github.com/stretchr/testify/require"
)

func TestConverter_CertHit(t *testing.T) {
	ctx := t.Context()

	selfSigned, err := cdxtest.GenSelfSignedCert()
	require.NoError(t, err)
	cert := selfSigned.Cert

	tests := []struct {
		name               string
		hit                model.CertHit
		wantNil            bool
		wantComponentCount int
		wantDepCount       int
		wantType           model.DetectionType
		wantSource         string
		wantLocation       string
	}{
		{
			name: "valid self-signed certificate",
			hit: model.CertHit{
				Cert:     cert,
				Source:   "PEM",
				Location: "/test/cert.pem",
			},
			wantNil:            false,
			wantComponentCount: 5,
			wantDepCount:       1,
			wantType:           model.DetectionTypeCertificate,
			wantSource:         "PEM",
			wantLocation:       "/test/cert.pem",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := cdxprops.NewConverter()
			detection := c.CertHit(ctx, tt.hit)

			if tt.wantNil {
				require.Nil(t, detection)
				return
			}

			require.NotNil(t, detection)
			require.Equal(t, tt.wantComponentCount, len(detection.Components))
			require.Equal(t, tt.wantDepCount, len(detection.Dependencies))
			require.Equal(t, tt.wantType, detection.Type)
			require.Equal(t, tt.wantSource, detection.Source)
			require.Equal(t, tt.wantLocation, detection.Location)

			// Verify the first component (main certificate) has a BOM ref
			require.NotEmpty(t, detection.Components[0].BOMRef)
		})
	}
}
