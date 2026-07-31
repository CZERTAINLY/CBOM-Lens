package cdxprops

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestConverter_hashAlgorithmCompo(t *testing.T) {
	t.Parallel()

	var testCases = []struct {
		scenario string
		then     string
	}{
		{
			scenario: "MD2",
			then:     "1.2.840.113549.2.2",
		},
		{
			scenario: "SHA-256",
			then:     "2.16.840.1.101.3.4.2.1",
		},
		{
			scenario: "SHA256",
			then:     "2.16.840.1.101.3.4.2.1",
		},
		{
			// RFC 8702 section 2: id-shake128 OBJECT IDENTIFIER ::=
			//   { joint-iso-itu-t(2) country(16) us(840) organization(1)
			//     gov(101) csor(3) nistAlgorithm(4) 2 11 }
			scenario: "SHAKE128",
			then:     "2.16.840.1.101.3.4.2.11",
		},
		{
			// RFC 8702 section 2: id-shake256 OBJECT IDENTIFIER ::=
			//   { joint-iso-itu-t(2) country(16) us(840) organization(1)
			//     gov(101) csor(3) nistAlgorithm(4) 2 12 }
			scenario: "SHAKE256",
			then:     "2.16.840.1.101.3.4.2.12",
		},
		{
			scenario: "SHA3-384",
			then:     "2.16.840.1.101.3.4.2.9",
		},
	}

	for _, tt := range testCases {
		t.Run(tt.scenario, func(t *testing.T) {
			t.Parallel()

			c := NewConverter()
			compo := c.hashAlgorithmCompo(tt.scenario)
			require.NotNil(t, compo.CryptoProperties)
			require.Equal(t, tt.then, compo.CryptoProperties.OID)
		})
	}

}
