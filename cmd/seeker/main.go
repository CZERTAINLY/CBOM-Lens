package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"runtime/debug"
	"strings"
	"time"

	"github.com/CZERTAINLY/Seeker/internal/dscvr"
	"github.com/CZERTAINLY/Seeker/internal/log"
	"github.com/CZERTAINLY/Seeker/internal/model"
	"github.com/CZERTAINLY/Seeker/internal/service"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
)

const defaultHttpServerGracefulPeriod = 5 * time.Second

var (
	userConfigPath string // /default/config/path/seeker on given OS
	configPath     string // actual config file used (if loaded)

	flagConfigFilePath string // value of --config flag
	flagVerbose        bool   // value of --verbose flag
)

var rootCmd = &cobra.Command{
	Use:          "seeker",
	Short:        "Tool detecting secrets and providing BOM",
	SilenceUsage: true,
}

var runCmd = &cobra.Command{
	Use:   "run",
	Short: "run command reads the configuration and executes the scan",
	RunE:  doRun,
}

var scanCmd = &cobra.Command{
	Use:    "_scan",
	Short:  "internal scan command",
	RunE:   doScan,
	Hidden: true,
}

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "version provide version of a seeker",
	RunE:  doVersion,
}

func init() {
	// user configuration
	d, err := os.UserConfigDir()
	if err != nil {
		panic(err)
	}
	userConfigPath = filepath.Join(d, "seeker")
}

func main() {
	// root flags
	rootCmd.PersistentFlags().StringVar(&flagConfigFilePath, "config", "", "Config file to load - default is seeker.yaml in current directory or in "+userConfigPath)
	rootCmd.PersistentFlags().BoolVar(&flagVerbose, "verbose", false, "verbose logging")

	// never print messages and usage
	rootCmd.SilenceErrors = true
	rootCmd.SilenceUsage = true

	rootCmd.AddCommand(runCmd)
	rootCmd.AddCommand(scanCmd)
	rootCmd.AddCommand(versionCmd)

	if cmd, err := rootCmd.ExecuteC(); err != nil {
		slog.Error("seeker failed", "err", err)
		if strings.HasPrefix(err.Error(), "unknown command") {
			_ = rootCmd.Help() // ./cmd bflmp
		} else {
			_ = cmd.Help() // ./cmd run gfagf (extra arg)
		}
		os.Exit(1)
	}
}

func doVersion(cmd *cobra.Command, args []string) error {
	info, ok := debug.ReadBuildInfo()
	if !ok || info == nil {
		return fmt.Errorf("seeker: version info not available")
	}

	if configPath != "" {
		fmt.Printf("config: %s\n", configPath)
	}
	fmt.Printf("seeker: %s\n", info.Main.Version)
	fmt.Printf("go:     %s\n", info.GoVersion)
	for _, s := range info.Settings {
		switch s.Key {
		case "vcs.revision":
			fmt.Printf("commit: %s\n", s.Value)
		case "vcs.time":
			fmt.Printf("date:   %s\n", s.Value)
		case "vcs.modified":
			fmt.Printf("dirty:  %s\n", s.Value)
		}
	}
	fmt.Println()

	return nil
}

func doScan(cmd *cobra.Command, args []string) error {
	if flagConfigFilePath == "" {
		return fmt.Errorf("--config is mandatory flag for this command")
	}
	configPath = flagConfigFilePath
	ctx := cmd.Context()

	if flagVerbose {
		// initialize logging
		ctx = initDoScanLog(ctx, flagVerbose)
	}

	config, err := model.LoadScanConfigFromPath(configPath)
	if err != nil {
		// fallback to the service config - if config does not come from stdin
		// this allows one to debug the scanning part directly while using the same
		// seeker.yaml as with the supervisor.
		if configPath != "-" {
			serviceConfig, fallbackErr := model.LoadConfigFromPath(configPath)
			if fallbackErr != nil {
				return fmt.Errorf("loading config fail: %w", errors.Join(err, fallbackErr))
			}
			config = model.Scan{
				Version:    0,
				Filesystem: serviceConfig.Filesystem,
				Containers: serviceConfig.Containers,
				Ports:      serviceConfig.Ports,
				Service:    serviceConfig.Service.ServiceFields,
			}
		}
	}

	// --verbose has a precedence over config file
	if flagVerbose {
		config.Service.Verbose = true
	} else if !flagVerbose && config.Service.Verbose {
		ctx = initDoScanLog(ctx, true)
	} else {
		ctx = initDoScanLog(ctx, false)
	}

	slog.DebugContext(ctx, "_scan", "configPath", configPath)
	slog.DebugContext(ctx, "_scan", "config", config)

	seeker, err := NewSeeker(ctx, config)
	if err != nil {
		return err
	}
	return seeker.Do(ctx, os.Stdout)
}

func initDoScanLog(ctx context.Context, verbose bool) context.Context {
	slog.SetDefault(log.New(verbose))
	attrs := slog.Group("seeker",
		slog.String("cmd", "_scan"),
		slog.Int("pid", os.Getpid()),
	)
	return log.ContextAttrs(ctx, attrs)
}

func doRun(cmd *cobra.Command, args []string) error {
	if len(args) > 0 {
		return fmt.Errorf("unsupported arguments: %s", strings.Join(args, ", "))
	}
	config, err := loadConfig(cmd, args)
	if err != nil {
		return err
	}

	ctx := cmd.Context()

	attrs := slog.Group("seeker",
		slog.String("cmd", "run"),
		slog.Int("pid", os.Getpid()),
	)
	ctx = log.ContextAttrs(ctx, attrs)
	slog.DebugContext(ctx, "", "environ", os.Environ())
	slog.DebugContext(ctx, "", "config", config)

	supervisor, err := service.NewSupervisor(ctx, config)
	if err != nil {
		return err
	}

	errChan := make(chan error, 1)
	go func() {
		defer close(errChan)
		errChan <- supervisor.Do(ctx)
	}()
	supervisor.AddJob(ctx, configPath, model.Scan{
		Version:    0,
		Filesystem: config.Filesystem,
		Containers: config.Containers,
		Ports:      config.Ports,
		Service: model.ServiceFields{
			Verbose: flagVerbose || config.Service.Verbose,
			Log:     config.Service.Log,
		},
	})

	var discoveryHttp *http.Server
	var dscvrSrv *dscvr.Server

	switch config.Service.Mode {
	case model.ServiceModeManual:
		supervisor.Start("**")

	case model.ServiceModeDiscovery:
		if dscvrSrv, err = dscvr.New(ctx, config.Service, supervisor, configPath); err != nil {
			return err
		}

		var uploaders []model.Uploader
		if config.Service.Dir != "" {
			u, err := service.NewOSRootUploader(config.Service.Dir)
			if err != nil {
				return err
			}
			uploaders = append(uploaders, u)
		}
		bomUploader, err := service.NewBOMRepoUploader(config.Service.Repository.URL)
		if err != nil {
			return err
		}
		bomUploader = bomUploader.WithUploadCallback(dscvrSrv.UploadedCallback)
		uploaders = append(uploaders, bomUploader)

		supervisor = supervisor.WithUploaders(ctx, uploaders...)
		discoveryHttp = &http.Server{
			Addr:    config.Service.Seeker.Addr.String(),
			Handler: dscvrSrv.Handler(),
		}

		go func() {
			slog.InfoContext(ctx, "Starting http server.", slog.String("addr", config.Service.Seeker.Addr.String()))
			if err := discoveryHttp.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				slog.Error("`ListenAndServe()` failed.", slog.String("error", err.Error()))
			}
		}()
		if err := dscvrSrv.RegisterConnector(ctx); err != nil {
			return err
		}
	}

	retErr := <-errChan

	if discoveryHttp != nil {
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), defaultHttpServerGracefulPeriod)
		defer shutdownCancel()

		if err := discoveryHttp.Shutdown(shutdownCtx); err != nil {
			slog.InfoContext(ctx, "Discovery server shutdown error.", slog.String("error", err.Error()))
		} else {
			slog.InfoContext(ctx, "Discovery server shutdown gracefully.")
		}
	}
	if dscvrSrv != nil {
		dscvrSrv.Close(ctx)
	}

	return retErr
}

func loadConfig(_ *cobra.Command, _ []string) (model.Config, error) {
	if envConfig, ok := os.LookupEnv("SEEKERCONFIG"); ok {
		configPath = envConfig
	} else if flagConfigFilePath != "" {
		configPath = flagConfigFilePath
	} else {
		for _, d := range []string{userConfigPath, "."} {
			path := filepath.Join(d, "seeker.yaml")
			if exists(path) {
				configPath = path
				break
			}
		}
	}

	var config model.Config

	// store default configuration
	if configPath == "" {
		config = model.DefaultConfig(context.Background())
		configPath = filepath.Join(userConfigPath, "seeker.yaml")
		err := os.MkdirAll(filepath.Dir(configPath), 0755)
		if err != nil {
			return config, fmt.Errorf("creating directory %s: %w", filepath.Dir(configPath), err)
		}

		f, err := os.Create(configPath)
		if err != nil {
			return config, fmt.Errorf("creating file %s: %w", configPath, err)
		}
		defer func() {
			_ = f.Close()
		}()
		enc := yaml.NewEncoder(f)
		err = enc.Encode(config)
		if err != nil {
			return config, fmt.Errorf("storing configuration: %w", err)
		}
	} else {
		var err error
		config, err = model.LoadConfigFromPath(configPath)
		if err != nil {
			return config, err
		}
	}

	// --verbose has a precedence over config file
	if flagVerbose {
		config.Service.Verbose = true
	}

	// initialize logging
	slog.SetDefault(log.New(config.Service.Verbose))

	slog.Debug("seeker run", "configPath", configPath)
	slog.Debug("seeker run", "config", config)
	return config, nil
}

func exists(path string) bool {
	info, err := os.Stat(path)
	if err != nil {
		return false
	}
	return info.Mode().IsRegular()
}
