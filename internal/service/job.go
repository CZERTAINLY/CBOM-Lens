package service

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"sync"

	"github.com/CZERTAINLY/CBOM-lens/internal/log"
	"github.com/CZERTAINLY/CBOM-lens/internal/model"

	"gopkg.in/yaml.v3"
)

// Job is a unit of work executed by supervisor
type Job struct {
	name        string
	oneshot     bool
	cmd         Command
	runner      *Runner
	start       chan struct{}
	cfgMx       sync.Mutex
	config      model.Scan
	resultsChan chan<- Result
}

func NewJob(name string, oneshot bool, config model.Scan, results chan<- Result) (*Job, error) {
	lens, err := os.Executable()
	if err != nil {
		return nil, fmt.Errorf("cannot determine path to executable: %w", err)
	}

	args := []string{
		"_scan",
		"--config",
		"-",
	}
	if config.Service.Verbose {
		args = append(args, "--verbose")
	}

	cmd := Command{
		JobName: name,
		Path:    lens,
		Args:    args,
		Env: append(
			os.Environ(),
			"GODEBUG=tlssha1=1,x509rsacrt=0,x509negativeserial=1",
		),
		// TODO: scan timeout
		Timeout: 0,
	}

	return &Job{
		name:        name,
		oneshot:     oneshot,
		cmd:         cmd,
		runner:      NewRunner(nil),
		start:       make(chan struct{}, 1),
		config:      config,
		resultsChan: results,
	}, nil
}

func (j *Job) WithTestData(stdout, stderr string) {
	if stdout != "" {
		j.cmd.Env = append(j.cmd.Env,
			"_LENS_PRINT_STDOUT="+stdout,
		)
	}
	if stderr != "" {
		j.cmd.Env = append(j.cmd.Env,
			"_LENS_PRINT_STDERR="+stderr,
		)
	}
}

func (j *Job) Close() {
	if j.start != nil {
		close(j.start)
		j.start = nil
	}
	if j.runner != nil {
		j.runner.Close()
		j.runner = nil
	}
}

func (j *Job) Name() string {
	return j.name
}

func (j *Job) Start() {
	if j.start == nil || j.runner == nil {
		slog.Error("Run can't be called after Close: ignoring", "job_name", j.name)
		return
	}
	j.start <- struct{}{}
}

func (j *Job) MergeConfig(cfg model.Scan) {
	j.cfgMx.Lock()
	defer j.cfgMx.Unlock()
	j.config.Merge(cfg)
}

// Config returns a copy of the current job configuration.
func (j *Job) Config() model.Scan {
	var cpy model.Scan

	j.cfgMx.Lock()
	cpy = j.config
	j.cfgMx.Unlock()

	return cpy
}

func (j *Job) LogAttrs() []slog.Attr {
	attrs := []slog.Attr{
		slog.String("name", j.name),
		slog.Bool("oneshot", j.oneshot),
	}
	group := slog.GroupAttrs("job", attrs...)
	return []slog.Attr{group}
}

func (j *Job) Activate(ctx context.Context) error {
	if j.start == nil || j.runner == nil {
		return errors.New("method Activate can't be called after Close")
	}

	ctx = log.ContextAttrs(ctx, j.LogAttrs()[0])

	for {
		select {
		case <-ctx.Done():
			return nil
		case result := <-j.runner.ResultsChan():
			slog.DebugContext(ctx, "finished")
			j.resultsChan <- result
			if j.oneshot {
				return nil
			}
		case <-j.start:
			slog.DebugContext(ctx, "about to start")
			if err := j.callStart(ctx); err != nil {
				r := j.runner.LastResult()
				r.Err = err
				j.resultsChan <- r
				if j.oneshot {
					return err
				}
			}
		}
	}
}

func (j *Job) callStart(ctx context.Context) error {
	j.cfgMx.Lock()
	defer j.cfgMx.Unlock()
	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	err := enc.Encode(j.config)
	if err != nil {
		return fmt.Errorf("encoding configuration for scan: %w", err)
	}
	j.cmd.Stdin = append([]byte{}, buf.Bytes()...)
	return j.runner.Start(ctx, j.cmd)
}
