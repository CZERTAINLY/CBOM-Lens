package cdxprops

import (
	"encoding/pem"
	"testing"

	"github.com/CZERTAINLY/CBOM-lens/internal/cdxprops/cdxtest"
	"github.com/CZERTAINLY/CBOM-lens/internal/model"
	cdx "github.com/CycloneDX/cyclonedx-go"

	"github.com/stretchr/testify/require"
)

func Test_spkiOID(t *testing.T) {
	t.Parallel()

	selfSigned, err := cdxtest.GenSelfSignedCert()
	require.NoError(t, err)

	res := spkiOID(selfSigned.Cert)
	require.Equal(t, "1.2.840.113549.1.1.1", res)

	selfSigned.Cert.RawSubjectPublicKeyInfo = []byte("garbage")
	res = spkiOID(selfSigned.Cert)
	require.Equal(t, "", res)
}

func Test_readSignatureAlgorithmRef(t *testing.T) {
	t.Parallel()

	selfSigned, err := cdxtest.GenSelfSignedCert()
	require.NoError(t, err)

	res := readSignatureAlgorithmRef(t.Context(), selfSigned.Cert, "")
	exp := cdx.BOMReference("crypto/algorithm/sha-256-rsa@1.2.840.113549.1.1.11")
	require.Equal(t, exp, res)

	selfSigned.Cert.SignatureAlgorithm = -1
	res = readSignatureAlgorithmRef(t.Context(), selfSigned.Cert, "2.16.840.1.101.3.4.3.17")
	exp = cdx.BOMReference("crypto/algorithm/ml-dsa-44@2.16.840.1.101.3.4.3.17")
	require.Equal(t, exp, res)

	res = readSignatureAlgorithmRef(t.Context(), selfSigned.Cert, "")
	exp = cdx.BOMReference("crypto/algorithm/unknown@unknown")
	require.Equal(t, exp, res)

	res = readSignatureAlgorithmRef(t.Context(), selfSigned.Cert, "0.0.0.0")
	exp = cdx.BOMReference("crypto/algorithm/unknown@unknown")
	require.Equal(t, exp, res)
}

func Test_sigAlgOID(t *testing.T) {
	t.Parallel()
	selfSigned, err := cdxtest.GenSelfSignedCert()
	require.NoError(t, err)

	res := sigAlgOID(selfSigned.Cert)
	require.Equal(t, "1.2.840.113549.1.1.11", res)

	selfSigned.Cert.Raw = []byte("broken")
	res = sigAlgOID(selfSigned.Cert)
	require.Equal(t, "", res)

}

func TestConverter_certConverter(t *testing.T) {
	t.Parallel()
	c := NewConverter().WithCzertainlyExtensions(true)

	selfSigned, err := cdxtest.GenSelfSignedCert()
	require.NoError(t, err)

	compo := c.certComponent(t.Context(), model.CertHit{
		Cert:     selfSigned.Cert,
		Source:   "cdxtest",
		Location: t.Name(),
	})

	require.NotZero(t, compo)
}

func Test_hashRawPublicKey(t *testing.T) {
	t.Parallel()
	data, err := cdxtest.TestData(cdxtest.MLDSA65PublicKey)
	require.NoError(t, err)
	block, _ := pem.Decode(data)
	require.Equal(t, "PUBLIC KEY", block.Type)

	c := NewConverter()
	value, hash := c.hashRawPublicKey(block.Bytes)
	require.NotEmpty(t, value)
	require.Equal(t, cdxtest.MLDSA65PublicKeyHash, hash)
}
