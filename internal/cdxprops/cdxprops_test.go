package cdxprops_test

import (
	"strings"
	"testing"

	"github.com/CZERTAINLY/CBOM-lens/internal/cdxprops"
	"github.com/CZERTAINLY/CBOM-lens/internal/cdxprops/cdxtest"
	"github.com/CZERTAINLY/CBOM-lens/internal/scanner/pem"

	"github.com/stretchr/testify/require"
)

func TestMLDSAPrivateKey(t *testing.T) {
	pk, err := cdxtest.TestData(cdxtest.MLDSA65PrivateKey)
	require.NoError(t, err)

	bundle, err := pem.Scanner{}.Scan(t.Context(), pk, cdxtest.MLDSA65PrivateKey)
	require.NoError(t, err)

	c := cdxprops.NewConverter()
	detection := c.PEMBundle(t.Context(), bundle)
	require.NotNil(t, detection)
	compos := detection.Components

	bomRefs := make([]string, len(compos))
	hashes := 0
	for i, compo := range compos {
		bomRefs[i] = compo.BOMRef
		if strings.Contains(compo.BOMRef, cdxtest.MLDSA65PublicKeyHash) {
			hashes++
		}
	}
	require.Equal(t, 2, hashes, "There should be two components with a public key hash")
	t.Logf("bomRefs: %v", bomRefs)
}
