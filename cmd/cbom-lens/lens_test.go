package main

import (
	"reflect"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/CZERTAINLY/CBOM-lens/internal/model"
)

func TestNmaps_AppliesConfiguredBinary(t *testing.T) {
	scanners, ips := nmaps(t.Context(), model.Ports{
		Enabled: true,
		IPv4:    true,
		Binary:  "/opt/custom/nmap",
		Ports:   "443",
	})
	require.Len(t, scanners, 1)
	require.Len(t, ips, 1)

	// Scanner's fields are unexported in internal/nmap; read them via
	// reflection rather than widening the production API for a test.
	// FieldByName returns a zero Value for an unknown name, which would
	// otherwise panic and hide the real cause: a renamed field.
	v := reflect.ValueOf(scanners[0])
	binary := v.FieldByName("nmap")
	require.True(t, binary.IsValid(), "internal/nmap.Scanner field renamed — update this test")
	require.Equal(t, "/opt/custom/nmap", binary.String(),
		"configured nmap.binary must reach the scanner")
	ports := v.FieldByName("ports")
	require.True(t, ports.IsValid(), "internal/nmap.Scanner field renamed — update this test")
	require.Equal(t, 1, ports.Len())
	require.Equal(t, "443", ports.Index(0).String())
}
