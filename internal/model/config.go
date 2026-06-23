package model

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"time"

	"github.com/CZERTAINLY/CBOM-lens/internal/log"

	"cuelang.org/go/cue"
	"cuelang.org/go/cue/cuecontext"
	"cuelang.org/go/encoding/yaml"
	"github.com/creasty/defaults"
	"github.com/docker/docker/client"

	_ "embed"
)

// Enum helpers (optional).
const (
	ContainerTypeDocker = "docker"
	ContainerTypePodman = "podman"

	AuthTypeNone        = "none"
	AuthTypeStaticToken = "static_token"

	ServiceModeManual    = "manual"
	ServiceModeTimer     = "timer"
	ServiceModeDiscovery = "discovery"

	LogStderr  = "stderr"
	LogStdout  = "stdout"
	LogDiscard = "discard"
)

// Scan is a scanning related config
type Scan struct {
	Version    int           `json:"version"` // fixed 0 for now
	Filesystem Filesystem    `json:"filesystem"`
	Containers Containers    `json:"containers"`
	Ports      Ports         `json:"ports"`
	Registry   Registry      `json:"registry"`
	Service    ServiceFields `json:"service"`
	CBOM       CBOM          `json:"cbom"`
}

// Config is a supervisor + scan related config
type Config struct {
	Version    int        `json:"version"` // fixed 0 for now
	Filesystem Filesystem `json:"filesystem"`
	Containers Containers `json:"containers"`
	Ports      Ports      `json:"ports"`
	Registry   Registry   `json:"registry"`
	Service    Service    `json:"service"`
	CBOM       CBOM       `json:"cbom"`
}

// Filesystem scanning settings.
type Filesystem struct {
	Enabled bool     `json:"enabled"`
	Paths   []string `json:"paths,omitempty"` // nil/empty => use CWD
}

type Containers struct {
	Enabled bool `json:"enabled"`
	Config  ContainersConfig
}

type ContainersConfig []ContainerConfig

// Container daemon configuration list element.
type ContainerConfig struct {
	Name   string   `json:"name,omitempty"`
	Type   string   `json:"type"`             // "docker" | "podman"
	Host   string   `json:"host,omitempty"`   // e.g. /var/run/docker.sock or ${DOCKER_HOST}
	Images []string `json:"images,omitempty"` // explicit images (empty => discover)
}

// Local ports scanning module configuration.
type Ports struct {
	Enabled bool   `json:"enabled"`
	Binary  string `json:"binary,omitempty"` // path or name (e.g. nmap)
	Ports   string `json:"ports,omitempty"`  // "1-65535", "22,80,8000-8100", etc.
	IPv4    bool   `json:"ipv4"`
	IPv6    bool   `json:"ipv6"`
}

type Registry struct {
	Enabled      bool           `json:"enabled"        yaml:"enabled"`
	Paths        []RegistryPath `json:"paths"          yaml:"paths,omitempty"`
	MaxDepth     int            `json:"max_depth"      yaml:"max_depth"` // 0 = unlimited
	MaxValueSize int            `json:"max_value_size" yaml:"max_value_size" default:"1048576"`
	WOW64        bool           `json:"wow64"          yaml:"wow64"`
	Include      RegistryFilter `json:"include"        yaml:"include,omitempty"`
	Exclude      RegistryFilter `json:"exclude"        yaml:"exclude,omitempty"`
}

func (r Registry) IsZero() bool { return isZero(r) }

type RegistryPath struct {
	Hive string `json:"hive" yaml:"hive"` // "HKLM", "HKCU", "HKCR", "HKU", "HKCC"
	Key  string `json:"key"  yaml:"key"`
}

type RegistryFilter struct {
	Keys   []string `json:"keys"   yaml:"keys,omitempty"`
	Values []string `json:"values" yaml:"values,omitempty"`
}

type ServiceFields struct {
	Verbose bool   `json:"verbose,omitempty"`
	Log     string `json:"log,omitempty"` // "stderr"|"stdout"|"discard"|path - defaults to stderr
}

// Service configuration
type Service struct {
	ServiceFields `yaml:",inline"`

	Mode       string         `json:"mode"`                                             // must be "manual", "timer" or "discovery"
	Dir        string         `json:"dir,omitempty"`                                    // output directory
	Repository *Repository    `json:"repository,omitempty" yaml:"repository,omitempty"` // remote publication
	Schedule   *TimerSchedule `json:"schedule,omitempty"`                               // only for mode timer
	Server     *LensServer    `json:"server,omitempty"`
	Core       *Core          `json:"core,omitempty"`
}

// TimerSchedule defines the duration for a timer mode
type TimerSchedule struct {
	Cron     string `json:"cron,omitempty"`
	Duration string `json:"duration,omitempty"`
}

// Repository publication settings.
type Repository struct {
	URL URL `json:"base_url"`
}

// LensServer is configuration for the discovery mode server.
type LensServer struct {
	Addr      TCPAddr `json:"addr"` // :port or ip:port
	BaseURL   URL     `json:"base_url"`
	StateFile string  `json:"state_file"`
}

// Core is configuration for CZERTAINLY Core API integration.
type Core struct {
	BaseURL URL `json:"base_url"`
}

type CBOM struct {
	Version    string   `json:"version" default:"1.6"`
	Extensions []string `json:"extensions"`
}

func (c Config) IsZero() bool {
	return c.Filesystem.IsZero() &&
		c.Containers.Config.IsZero() &&
		c.Ports.IsZero() &&
		c.Registry.IsZero() &&
		c.Service.IsZero()
}

func (c Containers) IsZero() bool {
	return isZero(c)
}

func (c Filesystem) IsZero() bool {
	return isZero(c)
}
func (c ContainersConfig) IsZero() bool {
	return len(c) == 0
}
func (c Ports) IsZero() bool {
	return isZero(c)
}
func (c Service) IsZero() bool {
	return isZero(c)
}

func expandEnv[PT configPT](pt PT) {
	var v any = pt
	rv := reflect.ValueOf(v)
	if rv.Kind() != reflect.Pointer {
		// require pointer so we can mutate
		return
	}
	rv = rv.Elem()
	postProcessRecursive(rv)
}

func postProcessRecursive(v reflect.Value) {
	if !v.IsValid() {
		return
	}
	switch v.Kind() {
	case reflect.String:
		if v.CanSet() {
			v.SetString(os.ExpandEnv(v.String()))

		}
	case reflect.Struct:
		for i := 0; i < v.NumField(); i++ {
			f := v.Field(i)
			// only exported (CanSet)
			if f.CanSet() {
				postProcessRecursive(f)
			} else {
				// still allow recursive into addressable nested structs
				if f.Kind() == reflect.Struct {
					postProcessRecursive(f)
				}
			}
		}
	case reflect.Pointer:
		if !v.IsNil() {
			postProcessRecursive(v.Elem())
		}
	case reflect.Slice:
		et := v.Type().Elem()
		switch et.Kind() {
		case reflect.String:
			if v.CanSet() {
				// copy to []string
				strs := make([]string, v.Len())
				for i := 0; i < v.Len(); i++ {
					strs[i] = v.Index(i).String()
				}
				strs = expandStrings(strs)
				// write back
				for i := 0; i < v.Len() && i < len(strs); i++ {
					v.Index(i).SetString(strs[i])
				}
				// if lengths differ, rebuild slice
				if len(strs) != v.Len() {
					newSlice := reflect.MakeSlice(v.Type(), len(strs), len(strs))
					for i := range strs {
						newSlice.Index(i).SetString(strs[i])
					}
					v.Set(newSlice)
				}
			}
		case reflect.Struct, reflect.Pointer:
			for i := 0; i < v.Len(); i++ {
				postProcessRecursive(v.Index(i))
			}
		default:
			// other slice types ignored
		}
	default:
		// other kinds ignored
	}
}

func expandStrings(slice []string) []string {
	ret := make([]string, len(slice))
	for idx, s := range slice {
		ret[idx] = os.ExpandEnv(s)
	}
	return ret
}

//go:embed config.cue
var cueSource []byte

var (
	cueCtx    *cue.Context
	cueConfig cue.Value
	cueScan   cue.Value
)

func init() {
	if len(cueSource) == 0 {
		panic("variable cueSource is empty")
	}
	cueCtx = cuecontext.New()
	compiled := cueCtx.CompileBytes(cueSource)
	if compiled.Err() != nil {
		panic(compiled.Err())
	}

	if err := compiled.Validate(); err != nil {
		panic(err)
	}

	cueConfig = compiled.LookupPath(cue.ParsePath("#Config"))
	if cueConfig.Err() != nil {
		panic(cueConfig.Err())
	}
	if err := cueConfig.Validate(); err != nil {
		panic(err)
	}

	cueScan = compiled.LookupPath(cue.ParsePath("#ScanConfig"))
	if cueScan.Err() != nil {
		panic(cueScan.Err())
	}
	if err := cueScan.Validate(); err != nil {
		panic(err)
	}
}

// LoadConfig validates YAML from r against CUE schema and decodes to Config.
// NOT SAFE for multiple goroutines
// Return CueError in a case validation phase fails
func LoadConfig(r io.Reader) (Config, error) {
	var ret Config
	if err := loadConfig1(r, &ret, cueConfig); err != nil {
		return ret, err
	}
	fixContainersConfig(ret.Containers.Config)
	fixRegistryConfig(&ret.Registry)
	return ret, nil
}

func LoadConfigFromPath(path string) (Config, error) {
	var ret Config
	if err := loadConfigFromFile1(path, &ret, cueConfig); err != nil {
		return ret, err
	}
	fixContainersConfig(ret.Containers.Config)
	fixRegistryConfig(&ret.Registry)
	return ret, nil
}

// LoadScanConfig loads a scan configuration from io.Reader
// like LoadConfig validates against CUE schema
func LoadScanConfig(r io.Reader) (Scan, error) {
	var ret Scan
	if err := loadConfig1(r, &ret, cueScan); err != nil {
		return ret, err
	}
	fixContainersConfig(ret.Containers.Config)
	fixRegistryConfig(&ret.Registry)
	return ret, nil
}

func LoadScanConfigFromPath(path string) (Scan, error) {
	var ret Scan
	if err := loadConfigFromFile1(path, &ret, cueScan); err != nil {
		return ret, err
	}
	fixContainersConfig(ret.Containers.Config)
	fixRegistryConfig(&ret.Registry)
	return ret, nil
}

type configPT interface {
	*Config | *Scan
}

func loadConfigFromFile1[PT configPT](path string, pt PT, schema cue.Value) error {
	var r io.Reader
	if path == "-" {
		r = os.Stdin
	} else {
		if !filepath.IsAbs(path) {
			var err error
			path, err = filepath.Abs(path)
			if err != nil {
				return fmt.Errorf("determining absolute path: %w", err)
			}
		}
		f, err := os.Open(path)
		if err != nil {
			return fmt.Errorf("opening config file: %w", err)
		}
		r = f
		defer func() {
			err := f.Close()
			if err != nil {
				slog.Error("can't close config file", "path", path, "error", err)
			}
		}()
	}
	err := loadConfig1(r, pt, schema)
	if err != nil {
		var cuerr CueError
		ok := errors.As(err, &cuerr)
		if ok {
			for _, d := range cuerr.Details() {
				slog.Error("validation error", d.Attr("detail"))
			}
		}
		return fmt.Errorf("parsing config: %w", err)
	}

	configRoot := filepath.Dir(path)

	var paths []string
	switch cfg := any(pt).(type) {
	case *Scan:
		paths = cfg.Filesystem.Paths
		if paths == nil {
			cfg.Filesystem.Paths = []string{configRoot}
		}
	case *Config:
		paths = cfg.Filesystem.Paths
		if paths == nil {
			cfg.Filesystem.Paths = []string{configRoot}
		}
	default:
		return fmt.Errorf("unsupported config type %T", any(pt))
	}

	for i, path := range paths {
		if !filepath.IsAbs(path) {
			paths[i] = filepath.Join(configRoot, path)
		}
	}

	return nil
}

func loadConfig1[PT configPT](r io.Reader, pt PT, schema cue.Value) error {
	b, err := io.ReadAll(r)
	if err != nil {
		return err
	}
	r = bytes.NewReader(b)

	yamlFile, err := yaml.Extract("config.yaml", r)
	if err != nil {
		return err
	}
	yamlValue := cueCtx.BuildFile(yamlFile)

	unified := schema.Unify(yamlValue)
	if err := unified.Validate(
		cue.All(),          // all constraints
		cue.Concrete(true), // no incomplete values
	); err != nil {
		return CueError{cuerr: err, config: yamlValue, schema: schema}
	}

	if err := unified.Decode(pt); err != nil {
		return err
	}

	expandEnv(pt)
	return defaults.Set(pt)
}

// CueError provides more user friendly validation errors on top of
// those generated by cuelang itself
type CueError struct {
	cuerr  error
	config cue.Value // content of --config file
	schema cue.Value // loaded cue schema
}

// Error implements error interface, returns the string content of underlying
// cue error
func (e CueError) Error() string {
	return e.cuerr.Error()
}

// Unwrap allows one to get the original error via errors.As
func (e CueError) Unwrap() error {
	return e.cuerr
}

// Details provide human-friendlier error messages
func (e CueError) Details() []CueErrorDetail {
	return humanize(e.cuerr, e.config, e.schema)
}

// DefaultConfig returns a default configuration for cbom-lens
// It tries to discover and ping docker/podman sockets, so those
// scans can be added to the list
// NOT SAFE for multiple goroutines
func DefaultConfig(ctx context.Context) Config {
	var portsEnabled = true
	nmap, err := exec.LookPath("nmap")
	if err != nil {
		portsEnabled = false
		slog.WarnContext(ctx, "nmap binary not found")
	}

	var cfg = Config{
		Version: 0,
		Filesystem: Filesystem{
			Enabled: true,
			Paths:   []string{},
		},
		Ports: Ports{
			Enabled: portsEnabled,
			Binary:  nmap,
			Ports:   "1-65535",
			IPv4:    true,
			IPv6:    true,
		},
		Service: Service{
			ServiceFields: ServiceFields{
				Verbose: true,
				Log:     "stderr",
			},
			Mode: ServiceModeManual,
			Dir:  ".",
		},
	}

	var containers ContainersConfig
	slog.DebugContext(ctx, "probing docker/podman sockets")
	// detect docker socket
	for _, path := range []string{"${DOCKER_HOST}", "/run/docker.sock", "/var/run/docker.sock"} {
		ctx = log.ContextAttrs(ctx, slog.String("path", path))
		cc, err := containerConfig(ctx, ContainerTypeDocker, path)
		if err != nil {
			slog.DebugContext(ctx, "probe failed", "error", err)
			continue
		}
		containers = append(containers, cc)
	}
	// detect podman sockets
	for _, path := range []string{"${PODMAN_SOCKET}", "/run/podman/podman.sock", "/var/run/podman/podman.sock"} {
		ctx = log.ContextAttrs(ctx, slog.String("path", path))
		cc, err := containerConfig(ctx, ContainerTypePodman, path)
		if err != nil {
			slog.DebugContext(ctx, "probe failed", "error", err)
			continue
		}
		containers = append(containers, cc)
	}

	if len(containers) > 0 {
		cfg.Containers.Enabled = true
		cfg.Containers.Config = containers
	}

	if err = defaults.Set(&cfg); err != nil {
		slog.ErrorContext(ctx, "can't set default values in config: continuing with empty values", "error", err)
	}

	cfg.CBOM.Extensions = append(cfg.CBOM.Extensions, "czertainly")
	return cfg
}

func containerConfig(ctx context.Context, typ string, sockPath string) (ContainerConfig, error) {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	sockPath = os.ExpandEnv(sockPath)
	realHost, err := probeDockerLikeSocket(ctx, sockPath)
	if err != nil {
		return ContainerConfig{}, err
	}
	return ContainerConfig{
		Name:   typ,
		Type:   typ,
		Host:   realHost,
		Images: []string{},
	}, nil
}

func fixDockerHost(sockPath string) string {
	// Only apply unix:// prefix on Unix-like systems
	if runtime.GOOS == "windows" {
		return sockPath
	}
	if strings.HasPrefix(sockPath, "/") && !strings.Contains(sockPath, "://") {
		return "unix://" + sockPath
	}
	return sockPath
}

func fixContainersConfig(configs ContainersConfig) {
	for idx := range configs {
		host := configs[idx].Host
		configs[idx].Host = fixDockerHost(host)
	}
}

// defaultRegistryPaths are scanned when the registry scanner is enabled but no
// explicit paths are configured. HKLM and HKCU cover machine-wide and
// current-user crypto material; HKCR and HKCC are views of subtrees already
// reachable from those two, so scanning them as well would only duplicate
// results. An empty Key means the hive root is walked.
func defaultRegistryPaths() []RegistryPath {
	return []RegistryPath{
		{Hive: "HKLM", Key: ""},
		{Hive: "HKCU", Key: ""},
	}
}

// fixRegistryConfig applies defaults to a Registry config. When the scanner is
// enabled but no paths are given it falls back to scanning the HKLM and HKCU
// hive roots, mirroring how an empty filesystem path list defaults to the
// working directory rather than scanning nothing.
func fixRegistryConfig(r *Registry) {
	if r.Enabled && len(r.Paths) == 0 {
		r.Paths = defaultRegistryPaths()
	}
}

func probeDockerLikeSocket(ctx context.Context, sockPath string) (string, error) {
	// Build host URL
	var host = fixDockerHost(sockPath)

	cli, err := client.NewClientWithOpts(
		client.WithHost(host),
		client.WithAPIVersionNegotiation(), // negotiate highest mutually supported
	)
	if err != nil {
		return "", fmt.Errorf("new client: %w", err)
	}
	defer func() { _ = cli.Close() }()

	if _, err = cli.Ping(ctx); err != nil {
		// Distinguish dial errors
		var netErr net.Error
		if errors.As(err, &netErr) && netErr.Timeout() {
			return "", fmt.Errorf("ping timeout: %w", err)
		}
		return "", fmt.Errorf("ping failed: %w", err)
	}

	return host, nil
}

func isZero[T any](v T) bool {
	return reflect.ValueOf(v).IsZero()
}
