package cdxprops_test

import (
	"testing"

	"github.com/CZERTAINLY/CBOM-lens/internal/cdxprops"
	"github.com/CZERTAINLY/CBOM-lens/internal/cdxprops/cdxtest"
	"github.com/CZERTAINLY/CBOM-lens/internal/scanner/pem"

	"github.com/stretchr/testify/require"
)

func TestMLMKEMPrivateKey(t *testing.T) {
	pk, err := cdxtest.TestData(cdxtest.MLDSA65PrivateKey)
	require.NoError(t, err)

	bundle, err := pem.Scanner{}.Scan(t.Context(), pk, cdxtest.MLDSA65PrivateKey)
	require.NoError(t, err)

	c := cdxprops.NewConverter()
	detection := c.PEMBundle(t.Context(), bundle)
	require.NotNil(t, detection)
	compos := detection.Components
	require.Len(t, compos, 1)
	require.Equal(t, "ML-DSA-65", compos[0].Name)
}
