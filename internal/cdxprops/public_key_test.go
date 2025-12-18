package cdxprops

import (
	"crypto/x509"
	"encoding/pem"
	"testing"

	"github.com/CZERTAINLY/CBOM-lens/internal/cdxprops/cdxtest"

	"github.com/stretchr/testify/require"
)

func TestConverter_publicKeyComponents(t *testing.T) {
	t.Parallel()

	data, err := cdxtest.TestData(cdxtest.MLDSA65Certificate)
	require.NoError(t, err)
	block, _ := pem.Decode(data)
	require.NotNil(t, block)
	require.Equal(t, "CERTIFICATE", block.Type)

	cert, err := x509.ParseCertificate(block.Bytes)
	require.NoError(t, err)

	c := NewConverter()
	algo, key := c.publicKeyComponents(t.Context(), -1, cert.PublicKey, cert)

	require.Equal(t, "ML-DSA-65", algo.Name)
	require.Equal(t, "ML-DSA-65", key.Name)
}
