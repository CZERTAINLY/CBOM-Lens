package model_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/CZERTAINLY/CBOM-lens/internal/model"

	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

func TestLoadConfig(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("not supported on Windows")
	}

	var testCases = []struct {
		scenario     string
		yml          string
		expectedJSON string
	}{
		{
			scenario: "manual mode with repository",
			yml: `
version: 0
service:
  mode: manual
  log: stderr
  repository:
    base_url: https://example.com/repo
`,
			expectedJSON: `
				{
				"version": 0,
				"service": {
					"mode": "manual",
					"log": "stderr",
					"repository": {
						"base_url": "https://example.com/repo"
					}
				},
				"containers": {
					"enabled": false,
					"Config": null
				},
				"filesystem": {
					"enabled": false
				},
				"ports": {
					"enabled": false,
					"ipv4": false,
					"ipv6": false
				},
				"cbom": {
					"version": "1.6",
					"extensions": null
				}
			}`,
		},
		{
			scenario: "discovery mode with repository and core",
			yml: `
version: 0
service:
  mode: discovery
  log: stderr
  repository:
    base_url: https://example.com/repo
  server:
    addr: :8080
    base_url: https://cbom-lens.example.net/api
  core:
    base_url: https://core-demo.example.net/api
`,
			expectedJSON: `{
				"version": 0,
				"service": {
					"mode": "discovery",
					"log": "stderr",
					"repository": {
						"base_url": "https://example.com/repo"
					},
					"server": {
						"addr": ":8080",
						"base_url": "https://cbom-lens.example.net/api",
						"state_file": "./cbom-lens-state-file"
					},
					"core": {
						"base_url": "https://core-demo.example.net/api"
					}
				},
				"containers": {
					"enabled": false,
					"Config": null
				},
				"filesystem": {
					"enabled": false
				},
				"ports": {
					"enabled": false,
					"ipv4": false,
					"ipv6": false
				},
				"cbom": {
					"version": "1.6",
					"extensions": null
				}
			}`,
		},
		{
			scenario: "discovery mode with repository, core and non-default state file",
			yml: `
version: 0
service:
  mode: discovery
  log: stderr
  repository:
    base_url: https://example.com/repo
  server:
    addr: :8080
    base_url: https://cbom-lens.example.net/api
    state_file: /tmp/some/path/cbom-lens-sqlite
  core:
    base_url: https://core-demo.example.net/api
`,
			expectedJSON: `{
				"version": 0,
				"service": {
					"mode": "discovery",
					"log": "stderr",
					"repository": {
						"base_url": "https://example.com/repo"
					},
					"server": {
						"addr": ":8080",
						"base_url": "https://cbom-lens.example.net/api",
						"state_file": "/tmp/some/path/cbom-lens-sqlite"
					},
					"core": {
						"base_url": "https://core-demo.example.net/api"
					}
				},
				"containers": {
					"enabled": false,
					"Config": null
				},
				"filesystem": {
					"enabled": false
				},
				"ports": {
					"enabled": false,
					"ipv4": false,
					"ipv6": false
				},
				"cbom": {
					"version": "1.6",
					"extensions": null
				}
			}`,
		},
		{
			scenario: "fix docker socket",
			yml: `
version: 0
service:
  mode: manual
  log: stderr
containers:
  enabled: true
  config:
    - name: docker
      type: docker
      host: /var/run/docker.sock
`,
			expectedJSON: `{
"version": 0,
"containers": {
    "Config": [
      {
        "host": "unix:///var/run/docker.sock",
        "name": "docker",
        "type": "docker"
      }
    ],
    "enabled": true
  },
  "filesystem": {
    "enabled": false
  },
  "ports": {
    "enabled": false,
    "ipv4": false,
    "ipv6": false
  },
  "service": {
    "log": "stderr",
    "mode": "manual"
  },
  "cbom": {
    "version": "1.6",
    "extensions": null
  }
}`,
		},
		{
			scenario: "defaults",
			yml: `
version: 0
service:
  mode: manual
  log: stderr
cbom:
  extensions:
    - czertainly
`,
			expectedJSON: `{
"containers": {
    "Config": null,
    "enabled": false
  },
  "filesystem": {
    "enabled": false
  },
  "ports": {
    "enabled": false,
    "ipv4": false,
    "ipv6": false
  },
  "service": {
    "log": "stderr",
    "mode": "manual"
  },
  "version": 0,
  "cbom": {
    "version": "1.6",
    "extensions": ["czertainly"]
  }
}`,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.scenario, func(t *testing.T) {
			tmpDir := t.TempDir()

			t.Run("reader", func(t *testing.T) {
				cfg, err := model.LoadConfig(strings.NewReader(tc.yml))
				require.NoError(t, err)
				require.NotNil(t, cfg)

				actualJSON, err := json.Marshal(cfg)
				require.NoError(t, err)
				require.JSONEq(t, tc.expectedJSON, string(actualJSON))
			})

			t.Run("path", func(t *testing.T) {
				abspath := filepath.Join(tmpDir, "config.yml")
				err := os.WriteFile(abspath, []byte(tc.yml), 0644)
				require.NoError(t, err)

				cfg, err := model.LoadConfigFromPath(abspath)
				require.NoError(t, err)
				require.NotNil(t, cfg)

				actualJSON, err := json.Marshal(cfg)
				require.NoError(t, err)
				require.JSONEq(t, tc.expectedJSON, string(actualJSON))
			})
		})
	}
}

func TestLoadScanConfig_Minimal(t *testing.T) {
	yml := `
version: 0
`
	sc, err := model.LoadScanConfig(strings.NewReader(yml))
	require.NoError(t, err)
	require.Equal(t, 0, sc.Version)
	// If Filesystem defaulting logic exists, assert it here, e.g.:
	// require.Nil(t, sc.Filesystem) or require.False(t, sc.Filesystem.Enabled)
}

func TestLoadScanConfig_WithFilesystem(t *testing.T) {
	yml := `
version: 0
filesystem:
  enabled: true
  paths:
    - /tmp
    - /var/log
`

	abspath := saveYaml(t, yml)
	var testCases = []struct {
		scenario string
		then     func() (model.Config, error)
	}{
		{
			scenario: "reader",
			then: func() (model.Config, error) {
				return model.LoadConfig(strings.NewReader(yml))
			},
		},
		{
			scenario: "path",
			then: func() (model.Config, error) {
				return model.LoadConfigFromPath(abspath)
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.scenario, func(t *testing.T) {
			sc, err := tc.then()
			require.NoError(t, err)
			require.Equal(t, 0, sc.Version)
			require.NotNil(t, sc.Filesystem)
			require.True(t, sc.Filesystem.Enabled)
			require.Equal(t, []string{"/tmp", "/var/log"}, sc.Filesystem.Paths)
		})
	}
}

func TestLoadScanConfig_Full(t *testing.T) {
	yml := `
version: 0
filesystem:
  enabled: true
  paths: [/opt/app]
containers:
  enabled: true
  config:
    - name: docker
      type: docker
      host: host
      images: ["alpine:latest","ubuntu:22.04"]
ports:
  enabled: true
  ports: 22,443
`
	sc, err := model.LoadScanConfig(strings.NewReader(yml))
	require.NoError(t, err)
	require.Equal(t, 0, sc.Version)

	require.True(t, sc.Filesystem.Enabled)
	require.Equal(t, []string{"/opt/app"}, sc.Filesystem.Paths)

	require.True(t, sc.Containers.Enabled)
	require.Len(t, sc.Containers.Config, 1)
	cc := sc.Containers.Config[0]
	require.Equal(t, "docker", cc.Name)
	require.Equal(t, "docker", cc.Type)
	require.Equal(t, "host", cc.Host)
	require.Equal(t, []string{"alpine:latest", "ubuntu:22.04"}, cc.Images)

	require.True(t, sc.Ports.Enabled)
	require.Equal(t, "22,443", sc.Ports.Ports)
}

func TestLoadScanConfig_InvalidYAML(t *testing.T) {
	yml := `
version: 0
ports: foo
`
	_, err := model.LoadScanConfig(strings.NewReader(yml))
	require.Error(t, err)

	path := saveYaml(t, yml)
	slog.Warn("Following line will log ERROR validation error, this is expected and confirm test is working")
	_, err = model.LoadScanConfigFromPath(path)
	require.Error(t, err)
}

func TestLoadScanConfig_Empty(t *testing.T) {
	const yml = ``
	_, err := model.LoadScanConfig(strings.NewReader(yml))
	require.NoError(t, err)
}

func TestLoadConfig_Fail(t *testing.T) {
	var testCases = []struct {
		scenario string
		given    string
		then     []model.CueErrorDetail
	}{
		{
			scenario: "extra",
			given: `
version: 0
service:
  mode: manual
extra: true
`,
			then: []model.CueErrorDetail{
				{
					Path:    "extra",
					Code:    model.CodeUnknownField,
					Message: "Field extra is not allowed",
					Pos: model.CueErrorPosition{
						Filename: "config.yaml",
						Line:     5,
						Column:   1,
					},
					Raw: "#Config.extra: field not allowed",
				},
			},
		},
		{
			scenario: "Additional field",
			given: `
version: 0
service:
  mode: manual
  x: true
`,
			then: []model.CueErrorDetail{
				{
					Path:    "service.x",
					Code:    model.CodeUnknownField,
					Message: "Field x is not allowed",
					Pos: model.CueErrorPosition{
						Filename: "config.yaml",
						Line:     5,
						Column:   3,
					},
					Raw: "#Config.service.x: field not allowed",
				},
			},
		},
		{
			scenario: "service.mode missing",
			given: `
version: 0
service:
`,
			then: []model.CueErrorDetail{
				{
					Path:    "service",
					Code:    model.CodeConflictingValues,
					Message: "Conflicting values for service: expected type struct: got null",
					Pos: model.CueErrorPosition{
						Filename: "config.yaml",
						Line:     3,
						Column:   9,
					},
					Raw: "#Config.service: conflicting values null and {verbose?:(bool|*false),log?:(*\"stderr\"|\"stdout\"|\"discard\"|string)} (mismatched types null and struct)",
				},
			},
		},
		{
			scenario: "version 1",
			given: `
version: 1
service:
  mode: manual
`,
			then: []model.CueErrorDetail{
				{
					Path:    "version",
					Code:    model.CodeConflictingValues,
					Message: "Conflicting values for version: possible values (0): got 1",
					Pos: model.CueErrorPosition{
						Filename: "config.yaml",
						Line:     2,
						Column:   10,
					},
					Raw: "#Config.version: conflicting values 1 and 0",
				},
			},
		},
		{
			scenario: "service.dir wrong type",
			given: `
version: 0
service:
  mode: manual
  dir: 123
`,
			then: []model.CueErrorDetail{
				{
					Path:    "service.dir",
					Code:    model.CodeConflictingValues,
					Message: "Conflicting values for dir: expected type string: got int",
					Pos: model.CueErrorPosition{
						Filename: "config.yaml",
						Line:     5,
						Column:   8,
					},
					Raw: `#Config.service.dir: conflicting values 123 and string (mismatched types int and string)`,
				},
			},
		},
		{
			scenario: "service.mode",
			given: `
version: 0
service:
  mode: automatic_gear
`,
			then: []model.CueErrorDetail{
				{
					Path:    "service.mode",
					Code:    model.CodeConflictingValues,
					Message: "Conflicting values for mode: possible values (manual,timer,discovery) (default manual): got automatic_gear",
					Pos: model.CueErrorPosition{
						Filename: "config.yaml",
						Line:     4,
						Column:   9,
					},
					Raw: "#Config.service.mode: 3 errors in empty disjunction: (and 3 more errors)",
				},
			},
		},
		{
			scenario: "service.verbose",
			given: `
version: 0
service:
  mode: manual
  verbose: "yes"
`,
			then: []model.CueErrorDetail{
				{
					Path:    "service.verbose",
					Code:    model.CodeConflictingValues,
					Message: "Conflicting values for verbose: expected type bool: got string",
					Pos: model.CueErrorPosition{
						Filename: "config.yaml",
						Line:     5,
						Column:   12,
					},
					Raw: `#Config.service.verbose: 2 errors in empty disjunction: (and 2 more errors)`,
				},
			},
		},
		{
			scenario: "service.verbose type",
			given: `
version: 0
service:
  mode: manual
  verbose: "true"
`,
			then: []model.CueErrorDetail{
				{
					Path:    "service.verbose",
					Code:    model.CodeConflictingValues,
					Message: "Conflicting values for verbose: expected type bool: got string",
					Pos: model.CueErrorPosition{
						Filename: "config.yaml",
						Line:     5,
						Column:   12,
					},
					Raw: `#Config.service.verbose: 2 errors in empty disjunction: (and 2 more errors)`,
				},
			},
		},
		{
			scenario: "service.mode timer and missing schedule",
			given: `
version: 0
service:
  mode: timer
`,
			then: []model.CueErrorDetail{
				{
					Path:    "service.schedule",
					Code:    model.CodeMissingRequired,
					Message: "Field schedule is required",
					Pos: model.CueErrorPosition{
						Filename: "",
						Line:     0,
						Column:   0,
					},
					Raw: "#Config.service.schedule: incomplete value {cron?:=~\"^(@(yearly|annually|monthly|weekly|daily|midnight|hourly)|@every.*|(?:\\\\S+\\\\s+){4}\\\\S+)$\"} | {duration?:=~\"^P(?:\\\\d+W|(?:\\\\d+Y)?(?:\\\\d+M)?(?:\\\\d+D)?(?:T(?:\\\\d+H)?(?:\\\\d+M)?(?:\\\\d+S)?)?)$\"}",
				},
			},
		},
		{
			scenario: "service.mode timer and empty schedule",
			given: `
version: 0
service:
  mode: timer
  schedule:
`,
			then: []model.CueErrorDetail{
				{
					Path:    "service.schedule",
					Code:    model.CodeConflictingValues,
					Message: "Conflicting values for schedule: expected type struct: got null",
					Pos: model.CueErrorPosition{
						Filename: "config.yaml",
						Line:     5,
						Column:   12,
					},
					Raw: "#Config.service.schedule: 2 errors in empty disjunction: (and 2 more errors)",
				},
			},
		},
		{
			scenario: "service.mode timer and empty schedule values",
			given: `
version: 0
service:
  mode: timer
  schedule:
    cron: ""
    duration: ""
`,
			then: []model.CueErrorDetail{
				{
					Path:    "service.schedule.cron",
					Code:    "validation_error",
					Message: "Field cron is invalid: invalid value \"\" (out of bound =~\"^(@(yearly|annually|monthly|weekly|daily|midnight|hourly)|@every.*|(?:\\\\S+\\\\s+){4}\\\\S+)$\")",
					Pos: model.CueErrorPosition{
						Filename: "config.yaml",
						Line:     6,
						Column:   11,
					},
					Raw: "#Config.service.schedule: 2 errors in empty disjunction: (and 2 more errors)",
				},
				{
					Path:    "service.schedule.duration",
					Code:    "validation_error",
					Message: "Field duration is invalid: invalid value \"\" (out of bound =~\"^P(?:\\\\d+W|(?:\\\\d+Y)?(?:\\\\d+M)?(?:\\\\d+D)?(?:T(?:\\\\d+H)?(?:\\\\d+M)?(?:\\\\d+S)?)?)$\")",
					Pos: model.CueErrorPosition{
						Filename: "config.yaml",
						Line:     7,
						Column:   15,
					},
					Raw: "#Config.service.schedule: 2 errors in empty disjunction: (and 2 more errors)",
				},
			},
		},
		{
			scenario: "service.mode timer and both schedule values",
			given: `
version: 0
service:
  mode: timer
  schedule:
    cron: "@hourly"
    duration: "PT1S"
`,
			then: []model.CueErrorDetail{
				{
					Path:    "service.schedule.cron",
					Code:    model.CodeUnknownField,
					Message: "Field cron is not allowed",
					Pos: model.CueErrorPosition{
						Filename: "config.yaml",
						Line:     6,
						Column:   5,
					},
					Raw: "#Config.service.schedule: 2 errors in empty disjunction: (and 2 more errors)",
				},
				{
					Path:    "service.schedule.duration",
					Code:    "unknown_field",
					Message: "Field duration is not allowed",
					Pos: model.CueErrorPosition{
						Filename: "config.yaml",
						Line:     7,
						Column:   5,
					},
					Raw: "#Config.service.schedule: 2 errors in empty disjunction: (and 2 more errors)",
				},
			},
		},
		{
			scenario: "service.repository.base_url is missing",
			given: `
version: 0
service:
  mode: manual
  repository:
`,
			then: []model.CueErrorDetail{
				{
					Path:    "service.repository",
					Code:    model.CodeConflictingValues,
					Message: "Conflicting values for repository: expected type struct: got null",
					Pos: model.CueErrorPosition{
						Filename: "config.yaml",
						Line:     5,
						Column:   14,
					},
					Raw: "#Config.service.repository: conflicting values null and {base_url:#URL} (mismatched types null and struct)",
				},
			},
		},
		{
			scenario: "service.repository.base_url not url",
			given: `
version: 0
service:
  mode: manual
  repository:
    base_url: ""
`,
			then: []model.CueErrorDetail{
				{
					Path:    "service.repository.base_url",
					Code:    model.CodeValidationError,
					Message: "Field base_url is invalid: value must be a valid http(s) URL",
					Pos: model.CueErrorPosition{
						Filename: "config.yaml",
						Line:     6,
						Column:   15,
					},
					Raw: `#Config.service.repository.base_url: invalid value "" (out of bound =~"^https?://.+")`,
				},
			},
		},
		{
			scenario: "service.repository.base_url is ftp",
			given: `
version: 0
service:
  mode: manual
  repository:
    base_url: "ftp://example.com"
`,
			then: []model.CueErrorDetail{
				{
					Path:    "service.repository.base_url",
					Code:    model.CodeValidationError,
					Message: "Field base_url is invalid: value must be a valid http(s) URL",
					Pos: model.CueErrorPosition{
						Filename: "config.yaml",
						Line:     6,
						Column:   15,
					},
					Raw: `#Config.service.repository.base_url: invalid value "ftp://example.com" (out of bound =~"^https?://.+")`,
				},
			},
		},
		{
			scenario: "service.repository.base_url is prefix only",
			given: `
version: 0
service:
  mode: manual
  repository:
    base_url: "https://"
`,
			then: []model.CueErrorDetail{
				{
					Path:    "service.repository.base_url",
					Code:    model.CodeValidationError,
					Message: "Field base_url is invalid: value must be a valid http(s) URL",
					Pos: model.CueErrorPosition{
						Filename: "config.yaml",
						Line:     6,
						Column:   15,
					},
					Raw: `#Config.service.repository.base_url: invalid value "https://" (out of bound =~"^https?://.+")`,
				},
			},
		},
		{
			scenario: "containers.config wrong yaml",
			// this is funny case - the config is recognized as
			// "config": {"-name" : "c1"}} by YAML parser
			given: `
version: 0
service:
  mode: manual
containers:
  enabled: true
  config:
    -name: c1
`,
			then: []model.CueErrorDetail{
				{
					Path:    "containers.config",
					Code:    model.CodeConflictingValues,
					Message: "Conflicting values for config: expected type struct: got list",
					Pos: model.CueErrorPosition{
						Filename: "",
						Line:     0,
						Column:   0,
					},
					Raw: `#Config.containers.config: conflicting values [...#ContainerConfig] and {"-name":"c1"} (mismatched types list and struct)`,
				},
			},
		},
		{
			scenario: "containers.config no host",
			given: `
version: 0
service:
  mode: manual
containers:
  enabled: true
  config:
    -
      name: c1
`,
			then: []model.CueErrorDetail{
				{
					Path:    "containers.config.0.host",
					Code:    model.CodeMissingRequired,
					Message: "Field host is required",
					Pos: model.CueErrorPosition{
						Filename: "",
						Line:     0,
						Column:   0,
					},
					Raw: `#Config.containers.config.0.host: incomplete value string`,
				},
			},
		},
		{
			scenario: "ports.ports number",
			given: `
version: 0
service:
  mode: manual
ports:
  ports: 8080
`,
			then: []model.CueErrorDetail{
				{
					Path:    "ports.ports",
					Code:    model.CodeConflictingValues,
					Message: "Conflicting values for ports: expected type string: got int",
					Pos: model.CueErrorPosition{
						Filename: "config.yaml",
						Line:     6,
						Column:   10,
					},
					Raw: `#Config.ports.ports: 2 errors in empty disjunction: (and 2 more errors)`,
				},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.scenario, func(t *testing.T) {
			_, err := model.LoadConfig(strings.NewReader(tc.given))
			require.Error(t, err)
			var cuerr model.CueError
			ok := errors.As(err, &cuerr)
			require.Truef(t, ok, "%q is not model.CueError", err)
			for _, f := range cuerr.Details() {
				t.Logf("%#+v", f)
			}
			require.Equal(t, tc.then, cuerr.Details())
			require.NotEmpty(t, cuerr.Details()[0].Attr("test"))
		})
	}
}

func TestDefaultConfig(t *testing.T) {
	cfg := model.DefaultConfig(t.Context())
	require.NotZero(t, cfg)

	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	err := enc.Encode(cfg)
	require.NoError(t, err)

	cfg2, err := model.LoadConfig(&buf)
	if err != nil {
		var cuerr model.CueError
		ok := errors.As(err, &cuerr)
		require.True(t, ok)
		for _, d := range cuerr.Details() {
			t.Logf("%+v", d)
		}
	}
	require.NoError(t, err)

	require.Equal(t, cfg, cfg2)
}

func TestIsZero(t *testing.T) {
	t.Parallel()

	var f model.Filesystem
	var cc model.ContainersConfig
	var p model.Ports
	var s model.Service
	var c model.Config

	for _, z := range []interface{ IsZero() bool }{f, cc, p, s, c} {
		require.True(t, z.IsZero())
	}
}

func TestExpandEnv(t *testing.T) {
	// this must not be parallel
	const inp = `
version: 0
service:
  mode: manual
  dir: ${TEST_EE_SERVICE_DIR}
filesystem:
  paths:
    - $TEST_EE_FILESYSTEM_PATH_1
    - $TEST_EE_FILESYSTEM_PATH_2
    - $TEST_EE_FILESYSTEM_PATH_undefined
containers:
  config:
    - name: ${TEST_EE_CONTAINERS1_NAME}
      host: ${TEST_EE_CONTAINERS1_HOST}
      images: 
        - $TEST_EE_CONTAINERS1_IMAGE_1
ports:
  binary: ${TEST_EE_NMAP_BINARY}
`

	var names = []string{
		"TEST_EE_SERVICE_DIR",
		"TEST_EE_FILESYSTEM_PATH_1",
		"TEST_EE_FILESYSTEM_PATH_2",
		"TEST_EE_CONTAINERS1_NAME",
		"TEST_EE_CONTAINERS1_HOST",
		"TEST_EE_CONTAINERS1_IMAGE_1",
		"TEST_EE_NMAP_BINARY",
	}

	for _, name := range names {
		require.NoError(t, os.Setenv(name, strings.ToLower(name)))
	}

	t.Cleanup(func() {
		for _, name := range names {
			require.NoError(t, os.Unsetenv(name))
		}
	})

	cfg, err := model.LoadConfig(strings.NewReader(inp))
	require.NoError(t, err)

	require.Equal(t, "test_ee_service_dir", cfg.Service.Dir)
	require.Len(t, cfg.Filesystem.Paths, 3)
	require.Equal(t, "test_ee_filesystem_path_1", cfg.Filesystem.Paths[0])
	require.Equal(t, "test_ee_filesystem_path_2", cfg.Filesystem.Paths[1])
	require.Equal(t, "", cfg.Filesystem.Paths[2])

	require.Len(t, cfg.Containers.Config, 1)
	c0 := cfg.Containers.Config[0]
	require.Equal(t, "test_ee_containers1_name", c0.Name)
	require.Equal(t, "test_ee_containers1_host", c0.Host)
	require.Len(t, c0.Images, 1)
	require.Equal(t, "test_ee_containers1_image_1", c0.Images[0])

	require.Equal(t, "test_ee_nmap_binary", cfg.Ports.Binary)

}

func saveYaml(t *testing.T, yml string) (abspath string) {
	t.Helper()
	root, err := os.OpenRoot(t.TempDir())
	require.NoError(t, err)
	t.Cleanup(func() {
		require.NoError(t, root.Close())
	})
	path := t.Name() + ".yaml"
	f, err := root.Create(path)
	require.NoError(t, err)
	_, err = f.WriteString(yml)
	require.NoError(t, err)
	require.NoError(t, f.Close())
	abspath = filepath.Join(root.Name(), path)
	return
}
