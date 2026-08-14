package cdxprops_test

import (
	"testing"

	"github.com/OmniTrustILM/cbom-lens/internal/cdxprops"
	"github.com/OmniTrustILM/cbom-lens/internal/cdxprops/cdxtest"
	"github.com/OmniTrustILM/cbom-lens/internal/model"
	"github.com/OmniTrustILM/cbom-lens/internal/scanner/pem"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/stretchr/testify/require"
)

func TestMLDSA65PrivateKey(t *testing.T) {
	pk, err := cdxtest.TestData(cdxtest.MLDSA65PrivateKey)
	require.NoError(t, err)

	bundle, err := pem.Scanner{}.Scan(t.Context(), pk, cdxtest.MLDSA65PrivateKey)
	require.NoError(t, err)

	c := cdxprops.NewConverter()
	detection := c.PEMBundle(t.Context(), bundle)
	require.NotNil(t, detection)
	compos := detection.Components
	// The key component and the algorithm that describes it. Until the
	// private-key path was fixed this was the algorithm alone, so a scan of an
	// ML-DSA private key named the algorithm and never said a key existed.
	require.Len(t, compos, 2)
	require.Equal(t, "ML-DSA-65", compos[0].Name)

	keyProps := compos[0].CryptoProperties.RelatedCryptoMaterialProperties
	require.NotNil(t, keyProps)
	require.Equal(t, cdx.RelatedCryptoMaterialTypePrivateKey, keyProps.Type)
	require.Equal(t, "Private Key", compos[0].Description)
	require.Equal(t, cdx.BOMReference(compos[1].BOMRef), keyProps.AlgorithmRef)
	require.Empty(t, keyProps.Value, "a private key's DER must never be emitted as a value")
	require.Nil(t, keyProps.Size)
}

func TestConverter_Nmap(t *testing.T) {
	t.Run("empty ports returns empty slice", func(t *testing.T) {
		c := cdxprops.NewConverter()

		nmap := model.Nmap{
			Ports: []model.NmapPort{},
		}

		detections := c.Nmap(t.Context(), nmap)

		require.NotNil(t, detections)
		require.Len(t, detections, 0)
	})

	t.Run("single port creates single detection", func(t *testing.T) {
		c := cdxprops.NewConverter()

		nmap := model.Nmap{
			Ports: []model.NmapPort{
				{
					PortNumber: 443,
				},
			},
		}

		detections := c.Nmap(t.Context(), nmap)

		require.NotNil(t, detections)
		require.Len(t, detections, 1)

		detection := detections[0]
		require.Equal(t, "NMAP", detection.Source)
		require.Equal(t, model.DetectionTypePort, detection.Type)
		require.NotEmpty(t, detection.Location)
		require.Contains(t, detection.Location, "443")
	})

	t.Run("multiple ports create multiple detections", func(t *testing.T) {
		c := cdxprops.NewConverter()

		nmap := model.Nmap{
			Ports: []model.NmapPort{
				{PortNumber: 80},
				{PortNumber: 443},
				{PortNumber: 8080},
			},
		}

		detections := c.Nmap(t.Context(), nmap)

		require.NotNil(t, detections)
		require.Len(t, detections, 3)

		expectedPorts := []string{"80", "443", "8080"}
		for i, detection := range detections {
			require.Equal(t, "NMAP", detection.Source, "detection #%d", i)
			require.Equal(t, model.DetectionTypePort, detection.Type, "detection #%d", i)
			require.NotEmpty(t, detection.Location, "detection #%d", i)
			require.Contains(t, detection.Location, expectedPorts[i], "detection #%d", i)
		}
	})
}

func TestConverter_WithImplementationPlatform(t *testing.T) {
	c := cdxprops.NewConverter().WithImplementationPlatform(cdx.ImplementationPlatformARMv8A)
	require.Equal(t, cdx.ImplementationPlatformARMv8A, c.ImplementationPlatform())

	// Without the override the platform still derives from runtime.GOARCH.
	require.NotEmpty(t, cdxprops.NewConverter().ImplementationPlatform())
}
