package cdxprops_test

import (
	"testing"

	"github.com/CZERTAINLY/CBOM-lens/internal/cdxprops"
	"github.com/CZERTAINLY/CBOM-lens/internal/cdxprops/cdxtest"
	"github.com/CZERTAINLY/CBOM-lens/internal/model"
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
