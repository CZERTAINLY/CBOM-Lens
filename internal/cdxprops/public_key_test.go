package cdxprops

import (
	"crypto"
	"crypto/x509"
	"testing"
)

func Test_publicKeyAlgorithmInfo(t *testing.T) {
	tests := []struct {
		name string // description of this test case
		// Named input parameters for target function.
		pubKeyAlg x509.PublicKeyAlgorithm
		pubKey    crypto.PublicKey
		want      algorithmInfo
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := publicKeyAlgorithmInfo(tt.pubKeyAlg, tt.pubKey)
			// TODO: update the condition below to compare got with tt.want.
			if true {
				t.Errorf("publicKeyAlgorithmInfo() = %v, want %v", got, tt.want)
			}
		})
	}
}
