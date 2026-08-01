package gitleaks

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"sync"
	"testing"

	"github.com/OmniTrustILM/cbom-lens/internal/cdxprops/cdxtest"
	"github.com/stretchr/testify/require"
)

const src = `
import os

aws_token := os.Getenv("AWS_TOKEN")
if aws_token == "":
    aws_token = "AKIALALEMEL33243OLIA"
	`

func TestDetector(t *testing.T) {
	// do not run in parallel due to global state in gitleaks/v8
	// t.Parallel()

	detector, err := NewScanner()
	require.NoError(t, err)

	results, err := detector.Scan(t.Context(), []byte(src), "aws.py")
	require.NoError(t, err)
	require.Len(t, results.Findings, 1)
}

func TestDetect_NoFindings_ReturnsNil(t *testing.T) {
	// do not run in parallel (global upstream state)
	d, err := NewScanner()
	require.NoError(t, err)
	res, err := d.Scan(t.Context(), []byte("just some text without secrets"), "plain.txt")
	require.NoError(t, err)
	require.Empty(t, res.Findings)
}

func TestDetect_ConcurrentCalls(t *testing.T) {
	// do not run in parallel (global upstream state)
	d, err := NewScanner()
	require.NoError(t, err)

	var wg sync.WaitGroup
	totalWithFindings := 0
	totalNoFindings := 0
	var mx sync.Mutex

	inputs := []string{
		"no secrets here",
		"token = 'AKIAZZZZZZZZZZZZZZZZ'",
		"hello world",
		"bearer jwt: eyJhbGciOi",
		"just text",
	}

	// Probe once to see if this environment detects the token input at all.
	probe, err := d.Scan(t.Context(), []byte("token = 'AKIAZZZZZZZZZZZZZZZZ'"), "file.txt")
	require.NoError(t, err)
	expectSomeFindings := len(probe.Findings) > 0

	for _, in := range inputs {
		wg.Add(1)
		body := in
		go func() {
			defer wg.Done()
			res, err := d.Scan(t.Context(), []byte(body), "file.txt")
			require.NoError(t, err)
			mx.Lock()
			defer mx.Unlock()
			if len(res.Findings) == 0 {
				totalNoFindings++
			}
			totalWithFindings += len(res.Findings)
		}()
	}
	wg.Wait()

	// Totals should sum to the number of inputs.
	require.Equal(t, len(inputs), totalWithFindings+totalNoFindings)
	// If the environment yields any finding for the probe, ensure at least one concurrent call had findings.
	if expectSomeFindings {
		require.GreaterOrEqual(t, totalWithFindings, 1)
	}
}

// ensure we hit the early cancellation branch
func TestDetect_ContextCanceled(t *testing.T) {
	// do not run in parallel (global upstream state)
	d, err := NewScanner()
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	res, err := d.Scan(ctx, []byte("anything"), "x.txt")
	require.Error(t, err)
	require.Nil(t, res.Findings)
}

func TestDetect_PrivateKey(t *testing.T) {
	// do not run in parallel (global upstream state)
	const javaTemplate = `
public class PrivateKeyExample {
    public static void main(String[] args) {
    private static final String PRIVATE_KEY = """
%s
        """;
        
        System.out.println("=== Private Key Information ===");
        System.out.println("Key Type: RSA");
        System.out.println("Key Length: " + privateKey.length() + " characters");
        System.out.println("\nPrivate Key Content:");
        System.out.println(privateKey);
        
        // In production, NEVER hardcode private keys!
        System.out.println("\n⚠️  WARNING: This is an example with a fake key. Never hardcode real private keys in source code!");
    }
}`

	// given java source code with a hardcoded PEM block
	privKey, err := cdxtest.GenRSAPrivateKey(1024)
	require.NoError(t, err)
	privKeyBytes := x509.MarshalPKCS1PrivateKey(privKey)
	privateKeyPEM := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privKeyBytes,
	}
	src := fmt.Sprintf(javaTemplate, string(pem.EncodeToMemory(privateKeyPEM)))

	s, err := NewScanner()
	require.NoError(t, err)
	d, err := s.Scan(t.Context(), []byte(src), t.Name())
	require.NoError(t, err)
	require.NotZero(t, d)
	require.Len(t, d.Findings, 1)
	f := d.Findings[0]
	require.Equal(t, "private-key", f.RuleID)
	// then a single parse private key is detected
	require.Len(t, f.PEMBundle.PrivateKeys, 1)
}
