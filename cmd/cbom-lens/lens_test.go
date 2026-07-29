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
	v := reflect.ValueOf(scanners[0])
	require.Equal(t, "/opt/custom/nmap", v.FieldByName("nmap").String(),
		"configured nmap.binary must reach the scanner (issue #186)")
	ports := v.FieldByName("ports")
	require.Equal(t, 1, ports.Len())
	require.Equal(t, "443", ports.Index(0).String())
}
