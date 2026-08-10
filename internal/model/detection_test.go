package model_test

import (
	"testing"

	"github.com/OmniTrustILM/cbom-lens/internal/model"
	"github.com/OmniTrustILM/cbom-lens/internal/model/cbom"

	"github.com/stretchr/testify/require"
)

// TestDetectionTypesMatchCBOMTwins enforces the "keep the two in sync" note on
// cbom.DetectionType. The 1.7 IR duplicates model.DetectionType with the same
// wire strings until the converter migration removes the old copy, and until
// now nothing checked that they still agreed -- a value added to one side only,
// or a typo in either string, would have surfaced as a detection type that
// changes when a converter migrates.
//
// The table is written out by hand rather than reflected over, so adding a
// constant to one package and not the other leaves an obvious hole here.
func TestDetectionTypesMatchCBOMTwins(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		model model.DetectionType
		cbom  cbom.DetectionType
	}{
		{"UNKNOWN", model.DetectionTypeUNKNOWN, cbom.DetectionTypeUNKNOWN},
		{"JWT", model.DetectionTypeLeakJWT, cbom.DetectionTypeLeakJWT},
		{"TOKEN", model.DetectionTypeLeakTOKEN, cbom.DetectionTypeLeakTOKEN},
		{"KEY", model.DetectionTypeLeakKEY, cbom.DetectionTypeLeakKEY},
		{"PASSWORD", model.DetectionTypeLeakPASSWORD, cbom.DetectionTypeLeakPASSWORD},
		{"CERTIFICATE", model.DetectionTypeCertificate, cbom.DetectionTypeCertificate},
		{"PORT", model.DetectionTypePort, cbom.DetectionTypePort},
		{"PEM", model.DetectionTypePEM, cbom.DetectionTypePEM},
		{"PRIVATE-KEY", model.DetectionTypeLeakPrivateKey, cbom.DetectionTypeLeakPrivateKey},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			require.Equal(t, tt.name, string(tt.model))
			require.Equal(t, string(tt.model), string(tt.cbom))
		})
	}
}
