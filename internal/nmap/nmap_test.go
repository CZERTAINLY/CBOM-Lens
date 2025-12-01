package nmap

import (
	"bytes"
	"encoding/json"
	"net/netip"
	"os/exec"
	"strconv"
	"testing"

	"github.com/CZERTAINLY/CBOM-lens/internal/model"
	nmapv3 "github.com/Ullaakut/nmap/v3"
	"github.com/stretchr/testify/require"
)

func TestScanner(t *testing.T) {
	if testing.Short() {
		t.Skipf("%s is skipped via -short", t.Name())
	}
	t.Parallel()
	nmapPath, err := exec.LookPath("nmap")
	require.NoError(t, err, "nmap binary is missing in PATH, please install it first")

	scanner := New().
		WithNmapBinary(nmapPath)

	type given struct {
		addrPort netip.AddrPort
		scanner  Scanner
	}

	var testCases = []struct {
		scenario string
		given    given
		then     model.Nmap
	}{
		{
			scenario: "tls: ipv4",
			given: given{
				addrPort: http4,
				scanner:  scanner,
			},
			then: model.Nmap{
				Address: "127.0.0.1",
				Status:  "up",
				Ports: []model.NmapPort{
					{
						State:    "open",
						Protocol: "tcp",
						Service: model.NmapService{
							Name: "ssl",
						},
					},
				},
			},
		},
		{
			scenario: "tls: ipv6",
			given: given{
				addrPort: http6,
				scanner:  scanner,
			},
			then: model.Nmap{
				Address: "::1",
				Status:  "up",
				Ports: []model.NmapPort{
					{
						State:    "open",
						Protocol: "tcp",
						Service: model.NmapService{
							Name: "ssl",
						},
					},
				},
			},
		},
		{
			scenario: "ssh: ipv4",
			given: given{
				addrPort: ssh4,
				scanner:  scanner,
			},
			then: model.Nmap{
				Address: "127.0.0.1",
				Status:  "up",
				Ports: []model.NmapPort{
					{
						State:    "open",
						Protocol: "tcp",
						Service: model.NmapService{
							Name:    "ssh",
							Product: "Golang x/crypto/ssh server",
						},
					},
				},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.scenario, func(t *testing.T) {
			t.Parallel()
			port := tc.given.addrPort.Port()
			addr := tc.given.addrPort.Addr()

			tcScanner := tc.given.scanner.WithPorts(strconv.Itoa(int(port)))
			got, err := tcScanner.Scan(t.Context(), addr)
			require.NoError(t, err)
			require.NotZero(t, got)

			t.Logf("got:%#+v", got)

			require.Equal(t, tc.then.Address, got.Address)
			require.Equal(t, tc.then.Status, got.Status)
			require.Len(t, got.Ports, 1)
			gotPort := got.Ports[0]
			expPort := tc.then.Ports[0]
			require.NotZero(t, gotPort.ID)
			require.Equal(t, expPort.State, gotPort.State)
			require.Equal(t, expPort.Protocol, gotPort.Protocol)
			require.Equal(t, expPort.Service.Name, gotPort.Service.Name)

			if gotPort.Service.Name == "ssl" {
				require.Len(t, gotPort.Ciphers, 2)
				require.Len(t, gotPort.TLSCerts, 1)
				gotHit := gotPort.TLSCerts[0]
				require.NotNil(t, gotHit.Cert)
				require.NotEmpty(t, gotHit.Location)
				require.Equal(t, got.Address+":"+strconv.Itoa(gotPort.ID), gotHit.Location)
				require.Equal(t, "NMAP", gotHit.Source)
			}

			if gotPort.Service.Name == "ssh" {
				require.Len(t, gotPort.SSHHostKeys, 1)
			}
		})
	}
}

func TestHostToModel(t *testing.T) {
	t.Parallel()
	rawJSON, err := testdata.ReadFile("testdata/raw.json")
	require.NoError(t, err)
	require.NotEmpty(t, rawJSON)

	var raw struct {
		Info nmapv3.Host `json:"Info"`
	}
	err = json.NewDecoder(bytes.NewReader(rawJSON)).Decode(&raw)
	require.NoError(t, err)

	got := HostToModel(t.Context(), raw.Info)

	require.Equal(t, "23.88.35.44", got.Address)
	require.Equal(t, "up", got.Status)

	// Ports
	require.Len(t, got.Ports, 1)
	p := got.Ports[0]
	require.Equal(t, 443, p.ID)
	require.Equal(t, "open", p.State)
	require.Equal(t, "tcp", p.Protocol)

	// Service
	require.Equal(t, "https", p.Service.Name)
	require.Empty(t, p.Service.Product)
	require.Empty(t, p.Service.Version)

	// Cipher groups
	require.Len(t, p.Ciphers, 1)
	require.Equal(t, "TLSv1.3", p.Ciphers[0].Name)

	// TLS certs
	require.Len(t, p.TLSCerts, 1)
	hit := p.TLSCerts[0]
	require.NotNil(t, hit.Cert)
	require.Equal(t, "23.88.35.44:443", hit.Location)
	require.Equal(t, "NMAP", hit.Source)

	require.Len(t, got.Ports, 1)
	gotPort := got.Ports[0]

	// SSH host keys
	require.Len(t, gotPort.SSHHostKeys, 2)
	hk1 := gotPort.SSHHostKeys[0]
	require.Equal(t, "ecdsa-sha2-nistp256", hk1.Type)
	require.Equal(t, "256", hk1.Bits)
	require.Equal(t, "17f9a4c3fbdcd558cce4c3a5147b4c38", hk1.Fingerprint)
	require.NotEmpty(t, hk1.Key)

	hk2 := gotPort.SSHHostKeys[1]
	require.Equal(t, "ssh-ed25519", hk2.Type)
	require.Equal(t, "256", hk2.Bits)
	require.Equal(t, "e5c4e0ed917912ed385aef8514ac2781", hk2.Fingerprint)
	require.NotEmpty(t, hk2.Key)

	// Scripts
	require.Empty(t, gotPort.Scripts)
}
