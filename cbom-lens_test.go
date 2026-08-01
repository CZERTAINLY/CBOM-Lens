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
	"regexp"
	"testing"
	"text/template"
	"time"

	"github.com/OmniTrustILM/cbom-lens/internal/bom"
	"github.com/OmniTrustILM/cbom-lens/internal/cdxprops/cdxtest"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
)

var (
	//go:embed testing/*
	testingFS  embed.FS
	lensPath   string
	privKeyPEM []byte
	certPEM    []byte
	validator  bom.Validator

	keepTestDir bool

	// tmpDir is a function used to create a tempdir
	// -test.keepdir flag tells the test to use os.MkdirTemp
	// default is t.TempDir, which will be cleaned up
	tmpDir func(t *testing.T) string
)

func TestMain(m *testing.M) {
	flag.BoolVar(&keepTestDir, "test.keepdir", false, "use os.TempDir instead of t.TempDir to keep test artifacts")

	flag.Parse()

	if testing.Short() {
		slog.Warn("integration tests are ignored with -short")
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
			_, err = fmt.Fprintf(t.Output(), "TEMPDIR %s: -test.keepdir used, so it won't be automatically deleted\n", dir)
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

	privKeyPEM, certPEM, err = generateRSACert()
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
	creat(t, "priv.key", privKeyPEM)
	creat(t, "pem.cert", certPEM)

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
	creat(t, "priv.key", privKeyPEM)
	creat(t, "pem.cert", certPEM)
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

func TestAllSources(t *testing.T) {
	const configTemplate = `
version: 0
filesystem:
    enabled: true
    paths: 
        - .
containers:
    enabled: true
    config:
        - name: docker-test
          type: docker
          host: {{.Host}}
          images: 
              - {{.Image}}
ports:
    enabled: true
    ports: "{{.Port}}"
    ipv4: true
    ipv6: false
service:
    mode: "manual"
    verbose: false
`

	tempdir := chDir(t)

	// given RSA private key and certificate exists
	creat(t, "key.pem", privKeyPEM)
	creat(t, "cert.pem", certPEM)

	// given there's a TLS server
	fixture(t, "testing/tlsserver/main.go")
	run(t, "go", "mod", "init", "tlsserver")
	run(t, "go", "mod", "tidy")
	cmd := exec.CommandContext(t.Context(), "go", "build", "-o", "tlsserver")
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0")
	cmd.Stderr = t.Output()
	err := cmd.Run()
	require.NoError(t, err)

	// given there is a docker file and a tls server in a container
	fixture(t, "testing/tlsserver/Dockerfile")

	req := testcontainers.ContainerRequest{
		Name: "tlsserver",
		FromDockerfile: testcontainers.FromDockerfile{
			Tag:        "lensci",
			Context:    tempdir,
			Dockerfile: "Dockerfile",
		},
		ExposedPorts: []string{"8443/tcp"},
		WaitingFor:   wait.ForListeningPort("8443/tcp").WithStartupTimeout(30 * time.Second),
	}

	c, err := testcontainers.GenericContainer(t.Context(), testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
		Reuse:            false,
	})
	require.NoError(t, err)
	info, err := c.Inspect(t.Context())
	require.NoError(t, err)
	var image string
	if info.Config != nil && info.Config.Image != "" {
		image = info.Config.Image
	} else {
		image = info.Image
	}
	require.NotEmpty(t, image)

	mp, err := c.MappedPort(t.Context(), "8443/tcp")
	require.NoError(t, err)

	t.Logf("port: %s", mp.Port())
	if keepTestDir {
		_, err = fmt.Fprintf(t.Output(), "IMAGE %s: -test.keepdir used, so docker image and container won't be deleted\n", image)
		require.NoError(t, err)
	}

	t.Cleanup(func() {
		if keepTestDir {
			return
		}
		err = c.Terminate(context.Background())
		require.NoError(t, err)
	})

	host := os.Getenv("DOCKER_HOST")
	if host == "" {
		host = "unix:///var/run/docker.sock"
	}
	t.Logf("using DOCKER_HOST=%s", host)

	// given there is a config
	var config = struct {
		Image string
		Port  string
		Host  string
	}{
		Image: image,
		Port:  mp.Port(),
		Host:  host,
	}
	tmpl, err := template.New("config").Parse(configTemplate)
	require.NoError(t, err)
	var buf bytes.Buffer
	err = tmpl.Execute(&buf, config)
	require.NoError(t, err)
	creat(t, "cbom-lens.yaml", buf.Bytes())

	// then: run a scan
	var stdout, stderr bytes.Buffer
	runCtx, cancelRun := context.WithTimeout(t.Context(), 5*time.Minute)
	t.Cleanup(cancelRun)
	cmd = exec.CommandContext(runCtx, lensPath, "run", "--config", "cbom-lens.yaml")
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	t.Logf("./cbom-lens-ci run: %#+v", cmd)
	err = cmd.Run()
	creat(t, t.Name()+".stderr", stderr.Bytes())
	if err != nil {
		t.Logf("%s", stderr.String())
		var exitErr *exec.ExitError
		if !errors.As(err, &exitErr) {
			require.NoError(t, err)
		}
	}

	// store the $TEST_NAME.json
	if keepTestDir {
		creat(t, t.Name()+".json", stdout.Bytes())
	}

	if testing.Verbose() {
		t.Logf("%s", stderr.String())
	}

	// validate result against JSON schema
	require.NoError(t, validator.ValidateBytes(stdout.Bytes()))

	dec := cdx.NewBOMDecoder(&stdout, cdx.BOMFileFormatJSON)
	bom := cdx.BOM{}
	err = dec.Decode(&bom)
	require.NoError(t, err)
	require.NotNil(t, bom.Components)

	// the: certificate is correctly mapped and linked from all three sources. An example is
	/*
		  {
			"location": "container://docker-test/lensci/cert.pem"
		  },
		  {
			"location": "filesystem:///tmp/TestAllSources3351907987/cert.pem"
		  },
		  {
			"location": "tcp://localhost:37257"
		  }
	*/
	matchIdx := -1
	for i, compo := range *bom.Components {
		if compo.Type == cdx.ComponentTypeCryptographicAsset &&
			compo.CryptoProperties != nil &&
			compo.CryptoProperties.AssetType == cdx.CryptoAssetTypeCertificate {
			// Ensure there is exactly one matching certificate component
			require.Equal(t, -1, matchIdx, "expected exactly one certificate component, found multiple")
			matchIdx = i
		}
	}
	require.NotEqual(t, -1, matchIdx, "no certificate component found")
	cert := &(*bom.Components)[matchIdx]
	require.NotNil(t, cert.Evidence)
	require.NotNil(t, cert.Evidence.Occurrences)
	require.Len(t, *cert.Evidence.Occurrences, 3)

	containerRe := regexp.MustCompile(`^container://.+/cert\.pem$`)
	filesystemRe := regexp.MustCompile(`^filesystem://.*/cert\.pem$`)
	portRe := regexp.MustCompile(`^tcp://.+:` + regexp.QuoteMeta(mp.Port()) + `$`)
	var cCount, fCount, pCount int
	for _, occ := range *cert.Evidence.Occurrences {
		t.Logf("occ.Location=%v", occ.Location)
		if containerRe.MatchString(occ.Location) {
			cCount++
		}
		if filesystemRe.MatchString(occ.Location) {
			fCount++
		}
		if portRe.MatchString(occ.Location) {
			pCount++
		}
	}
	require.Equal(t, 1, cCount)
	require.Equal(t, 1, fCount)
	require.Equal(t, 1, pCount)
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

func generateRSACert() ([]byte, []byte, error) {
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

func run(t *testing.T, name string, args ...string) {
	t.Helper()
	cmd := exec.CommandContext(t.Context(), name, args...)
	cmd.Stderr = t.Output()
	err := cmd.Run()
	require.NoError(t, err)
}
