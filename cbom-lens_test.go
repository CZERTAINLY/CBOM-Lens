package lens_test

import (
	"bytes"
	"context"
	"embed"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/CZERTAINLY/CBOM-lens/internal/bom"
	"github.com/CZERTAINLY/CBOM-lens/internal/cdxprops/cdxtest"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/stretchr/testify/require"
)

var (
	//go:embed testing/*
	testingFS    embed.FS
	lensPath     string
	privKeyBytes []byte
	certDER      []byte
	validator    bom.Validator

	// tmpDir is a function used to create a tempdir
	// -test.keepdir flag tells the test to use os.MkdirTemp
	// default is t.TempDir, which will be cleaned up
	tmpDir func(t *testing.T) string
)

func TestMain(m *testing.M) {
	var keepTestDir bool
	flag.BoolVar(&keepTestDir, "test.keepdir", false, "use os.TempDir instead of t.TempDir to keep test artifacts")

	flag.Parse()

	if testing.Short() {
		slog.Warn("integration tests with -short are ignored")
		os.Exit(0)
	}

	if !keepTestDir {
		tmpDir = func(t *testing.T) string {
			t.Helper()
			return t.TempDir()
		}
	} else {
		tmpDir = func(t *testing.T) string {
			t.Helper()
			dir, err := os.MkdirTemp("", t.Name()+"*")
			require.NoError(t, err)
			_, err = fmt.Fprintf(t.Output(), "TEMPDIR %s: -test.keepdir used, so it won't be automatically deleted", dir)
			require.NoError(t, err)
			return dir
		}
	}

	if !isExecutable("cbom-lens-ci") {
		slog.Error("cannot locate cbom-lens-ci binary: run go build -race -cover -covermode=atomic -o cbom-lens-ci ./cmd/cbom-lens/ first")
		os.Exit(1)
	}

	var err error
	lensPath, err = filepath.Abs("cbom-lens-ci")
	if err != nil {
		slog.Error("can't get abspath for cbom-lens-ci", "error", err)
		os.Exit(1)
	}
	coverDir, err := filepath.Abs("coverage")
	if err != nil {
		slog.Error("can't get value for GOCOVERDIR for cbom-lens-ci", "error", err)
		os.Exit(1)
	}
	err = rmRfMkdirp(coverDir)
	if err != nil {
		slog.Error("can't reset GOCOVERDIR for cbom-lens-ci", "error", err, "coverdir", coverDir)
		os.Exit(1)
	}

	err = os.Setenv("GOCOVERDIR", coverDir)
	if err != nil {
		slog.Error("can't set GOCOVERDIR env variable", "error", err)
		os.Exit(1)
	}

	privKeyBytes, certDER, err = generateRSACert()
	if err != nil {
		slog.Error("can't generate RSA certificate", "error", err)
		os.Exit(1)
	}

	validator, err = bom.NewValidator(cdx.SpecVersion1_6)
	if err != nil {
		slog.Error("can't initialize BOM validator", "error", err)
		os.Exit(1)
	}

	os.Exit(m.Run())
}

func TestManual(t *testing.T) {
	_ = chDir(t)

	const config = `
version: 0
filesystem:
    enabled: true
    paths: 
        - .
service:
    mode: "manual"
    verbose: false
`
	creat(t, "cbom-lens.yaml", []byte(config))
	fixture(t, "testing/leaks/aws_token.py")
	creat(t, "priv.key", privKeyBytes)
	creat(t, "pem.cert", certDER)

	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	t.Cleanup(cancel)
	var stdout, stderr bytes.Buffer
	cmd := exec.CommandContext(ctx, lensPath, "run", "--config", "cbom-lens.yaml")
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	t.Logf("./cbom-lens-ci run: %#+v", cmd)
	err := cmd.Run()
	if err != nil {
		t.Logf("%s", stderr.String())
		require.NoError(t, err)
	}

	// store the $TEST_NAME json
	creat(t, t.Name()+".json", stdout.Bytes())

	// validate result against JSON schema
	require.NoError(t, validator.ValidateBytes(stdout.Bytes()))

	dec := cdx.NewBOMDecoder(&stdout, cdx.BOMFileFormatJSON)
	bom := cdx.BOM{}
	err = dec.Decode(&bom)
	require.NoError(t, err)

	require.True(t, len(*bom.Components) >= 7)
}

func TestTimer(t *testing.T) {
	_ = chDir(t)

	const config = `
version: 0
filesystem:
    enabled: true
    paths: 
        - .
service:
    mode: "timer"
    schedule:
       cron: "@every 1s"
    dir: .
    verbose: false
`
	creat(t, "cbom-lens.yaml", []byte(config))
	fixture(t, "testing/leaks/aws_token.py")
	creat(t, "priv.key", privKeyBytes)
	creat(t, "pem.cert", certDER)
	err := rmrf("cbom-lens*json")
	require.NoError(t, err)

	runCtx, cancelRun := context.WithTimeout(t.Context(), 30*time.Second)
	t.Cleanup(cancelRun)
	// wait on new scan file to appear and cancel the context
	// which kills the cbom-lens - this will speedup the test
	go func(ctx context.Context, cancel context.CancelFunc) {
		t := time.NewTicker(5 * time.Second)
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				results, _ := filepath.Glob("cbom-lens*.json")
				if len(results) >= 1 {
					cancel()
				}
				return
			}
		}
	}(runCtx, cancelRun)

	var stdout, stderr bytes.Buffer
	cmd := exec.CommandContext(runCtx, lensPath, "run", "--config", "cbom-lens.yaml")
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	t.Logf("./cbom-lens-ci run: %#+v", cmd)
	err = cmd.Run()
	if err != nil {
		t.Logf("%s", stderr.String())
		var exitErr *exec.ExitError
		if !errors.As(err, &exitErr) {
			require.NoError(t, err)
		}
	}

	results, err := filepath.Glob("cbom-lens*.json")
	require.NoError(t, err)
	require.True(t, len(results) > 0)
	f, err := os.Open(results[0])
	require.NoError(t, err)
	t.Cleanup(func() {
		err = f.Close()
		require.NoError(t, err)
	})

	var buf bytes.Buffer
	var r = io.TeeReader(f, &buf)

	dec := cdx.NewBOMDecoder(r, cdx.BOMFileFormatJSON)
	bom := cdx.BOM{}
	err = dec.Decode(&bom)
	require.NoError(t, err)

	// validate result against JSON schema
	require.NoError(t, validator.ValidateBytes(buf.Bytes()))

	require.True(t, len(*bom.Components) >= 7)
}

func isExecutable(path string) bool {
	info, err := os.Stat(path)
	if err != nil {
		return false
	}
	return info.Mode().Perm()&0111 != 0
}

func rmRfMkdirp(dir string) error {
	if err := os.RemoveAll(dir); err != nil {
		return fmt.Errorf("failed to remove directory: %w", err)
	}
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create directory: %w", err)
	}
	return nil
}

func chDir(t *testing.T) string {
	t.Helper()
	tempdir := tmpDir(t)
	err := os.Chdir(tempdir)
	require.NoError(t, err)
	return tempdir
}

func creat(t *testing.T, path string, content []byte) {
	t.Helper()
	f, err := os.Create(path)
	require.NoError(t, err)
	defer func() {
		require.NoError(t, f.Close())
	}()
	_, err = f.Write(content)
	require.NoError(t, err)
	err = f.Sync()
	require.NoError(t, err)
}

func rmrf(pattern string) error {
	matches, err := filepath.Glob(pattern)
	if err != nil {
		return fmt.Errorf("glob pattern error: %w", err)
	}

	for _, match := range matches {
		if err := os.RemoveAll(match); err != nil {
			return fmt.Errorf("failed to remove %s: %w", match, err)
		}
	}
	return nil
}

func fixture(t *testing.T, inPath string) string {
	t.Helper()
	b, err := testingFS.ReadFile(inPath)
	require.NoError(t, err)
	path := filepath.Base(inPath)
	creat(t, path, b)
	return path
}

func generateRSACert() (privKeyBytes []byte, certDER []byte, err error) {
	selfSigned, err := cdxtest.GenSelfSignedCert()
	if err != nil {
		return nil, nil, err
	}
	privKeyPEM, err := selfSigned.PrivKeyPEM()
	if err != nil {
		return nil, nil, err
	}
	certPEM, err := selfSigned.CertPEM()
	if err != nil {
		return nil, nil, err
	}
	return privKeyPEM, certPEM, nil
}
