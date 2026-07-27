package bom

import (
	"testing"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/stretchr/testify/require"
)

func TestEmitterFor(t *testing.T) {
	t.Run("returns emitter for SpecVersion1_6", func(t *testing.T) {
		emitter, err := emitterFor(cdx.SpecVersion1_6)
		require.NoError(t, err)
		require.NotNil(t, emitter)
		require.Equal(t, cdx.SpecVersion1_6, emitter.SpecVersion())
	})

	t.Run("returns error for unsupported version", func(t *testing.T) {
		emitter, err := emitterFor(cdx.SpecVersion1_5)
		require.Error(t, err)
		require.Nil(t, emitter)
	})
}
