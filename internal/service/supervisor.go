package service

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strconv"
	"sync"
	"time"

	gocron "github.com/go-co-op/gocron/v2"

	"github.com/CZERTAINLY/Seeker/internal/model"
)

type Supervisor struct {
	uploaders []model.Uploader
	cfg       model.Service
	scheduler gocron.Scheduler
	duration  time.Duration
	results   chan Result
	jobsChan  chan isJob
	jobsMx    sync.Mutex
	jobs      map[string]*Job
	wg        sync.WaitGroup
}

func NewSupervisor(ctx context.Context, cfg model.Config) (*Supervisor, error) {
	var supervisor = &Supervisor{
		cfg: cfg.Service,
	}
	uploaders, err := uploaders(ctx, supervisor.cfg)
	if err != nil {
		return nil, fmt.Errorf("initializing uploaders: %w", err)
	}

	var scheduler gocron.Scheduler
	if supervisor.cfg.Mode == "timer" {
		var err error
		var d time.Duration
		d, scheduler, err = newScheduler(ctx, supervisor.cfg.Schedule, func() { supervisor.Start("**") })
		supervisor.duration = d
		if err != nil {
			return nil, fmt.Errorf("timer mode failed: %w", err)
		}
	}

	supervisor.uploaders = uploaders
	supervisor.scheduler = scheduler

	supervisor.results = make(chan Result, 1)
	supervisor.jobsChan = make(chan isJob, 1)
	supervisor.jobs = make(map[string]*Job)

	return supervisor, nil
}

// WithUploaders changes a command and uploaders for a initialized Supervisor.
// This method exists for a unit testing only.
func (s *Supervisor) WithUploaders(ctx context.Context, uploaders ...model.Uploader) *Supervisor {
	s.closeUploaders(ctx)
	s.uploaders = uploaders
	return s
}

// AddJob registers a new job which will be started in Do routine
// optional testData sets test override standard outputs for an existing job. Non-empty values make the job emit them and skip the real scan
// (hidden integration test protocol). For spawning / stream capture tests only;
// not for production use.
func (s *Supervisor) AddJob(ctx context.Context, name string, cfg model.Scan, testData ...string) {
	j, err := NewJob(name, s.cfg.Mode == model.ServiceModeManual, cfg, s.results)
	if err != nil {
		slog.ErrorContext(ctx, "job can't be created: ignoring", "job_name", name, "error", err)
		return
	}
	// internal test harness protocol
	if len(testData) == 1 {
		j.WithTestData(testData[0], "")
	} else if len(testData) == 2 {
		j.WithTestData(testData[0], testData[1])
	}

	s.jobsChan <- jobAdd{name: name, job: j}
}

// ConfigureJob allows added job to change its configuration
func (s *Supervisor) ConfigureJob(_ context.Context, name string, cfg model.Scan) {
	s.jobsChan <- jobConfigure{name: name, config: &cfg}
}

// Start tells supervisor to start a new scan - this hints as a signal, so this
// ends immediately and without any error.
// start "**" will trigger all registered jobs
func (s *Supervisor) Start(name string) {
	s.jobsChan <- jobStart{name: name}
}

// Do runs the supervisor event loop.
// It multiplexes four concerns:
//  1. Start triggers (job names/patterns received on s.start) – callStart launches those jobs.
//  2. Dynamic job additions (received on s.jobsChan) – handleJob registers and prepares them to be started.
//  3. Job results (from s.results) – validates process exit state; on success uploads stdout; on failure logs.
//  4. Context cancellation – terminates the loop and begins shutdown.
//
// Modes:
//   - Oneshot (manual): a wildcard start "**" is triggered once on entry; the first scan or upload error is returned.
//   - Other modes: errors are only logged; the loop runs until ctx is cancelled.
//
// Startup: starts the scheduler (if present).
// Shutdown (deferred order): closeJobs -> closeUploaders -> wait on s.wg (job goroutines).
// Returns nil on graceful cancellation, or the first error in oneshot mode.
func (s *Supervisor) Do(ctx context.Context) error {
	slog.DebugContext(ctx, "starting a supervisor")

	if s.scheduler != nil {
		s.scheduler.Start()
		defer func() {
			err := s.scheduler.Shutdown()
			if err != nil {
				slog.ErrorContext(ctx, "shutting down gocron has failed", "error", err)
			}
		}()
	}

	defer func() {
		s.closeJobs()
	}()

	defer func() {
		s.closeUploaders(ctx)
	}()

	defer func() {
		s.wg.Wait()
	}()

	for {
		select {
		case <-ctx.Done():
			return nil
		case x, ok := <-s.jobsChan:
			if !ok {
				continue
			}
			switch j := x.(type) {
			case jobAdd:
				s.handleJobAdd(ctx, j)
				if s.cfg.Mode == model.ServiceModeTimer {
					slog.InfoContext(ctx, "adding new timer job", "job_name", j.job.Name(), "interval", s.duration.String())
				}
			case jobConfigure:
				if j.config == nil {
					slog.WarnContext(ctx, "can't configure job: config is nil", "job_name", j.name)
					continue
				}
				s.handleJobConfigure(ctx, j.name, *j.config)
			case jobStart:
				err := s.callStart(ctx, j.name)
				if err != nil {
					if s.cfg.Mode == model.ServiceModeManual {
						return err
					}
					slog.ErrorContext(ctx, "start returned", "error", err)
				}
			default:
				continue
			}
		case result := <-s.results:
			var reason string
			switch {
			case result.Err != nil:
				reason = "err: " + result.Err.Error()
			case result.State == nil:
				reason = "state is nil"
			case result.State.ExitCode() != 0:
				reason = "exit code " + strconv.Itoa(result.State.ExitCode())
			}
			if reason != "" {
				slog.ErrorContext(ctx, "scan have failed", "reason", reason, "result", result)
				continue
			}

			slog.DebugContext(ctx, "scan succeeded: uploading", slog.String("job-name", result.JobName))
			err := s.upload(ctx, result.JobName, result.Stdout)
			if s.cfg.Mode == model.ServiceModeManual {
				return err
			}
			if err != nil {
				slog.ErrorContext(ctx, "upload failed", "error", err)
				continue
			}
		}
	}
}

// JobConfiguration returns a copy of configuration for job 'name' on success,
// error otherwise.
func (s *Supervisor) JobConfiguration(ctx context.Context, name string) (model.Scan, error) {
	s.jobsMx.Lock()
	defer s.jobsMx.Unlock()

	j, ok := s.jobs[name]
	if !ok {
		slog.WarnContext(ctx, "Job does not exist.", slog.String("job-name", name))
		return model.Scan{}, fmt.Errorf("job %q does not exist", name)
	}
	return j.Config(), nil
}

func (s *Supervisor) closeUploaders(ctx context.Context) {
	for _, uploader := range s.uploaders {
		if closer, ok := uploader.(model.UploadCloser); ok {
			err := closer.Close()
			if err != nil {
				slog.ErrorContext(ctx, "closing uploader have failed", "error", err)
			}
		}
	}
}

func (s *Supervisor) closeJobs() {
	s.jobsMx.Lock()
	defer s.jobsMx.Unlock()

	for name, job := range s.jobs {
		job.Close()
		delete(s.jobs, name)
	}
}

func (s *Supervisor) handleJobAdd(ctx context.Context, j jobAdd) {
	s.jobsMx.Lock()
	defer s.jobsMx.Unlock()

	job := j.job
	if _, ok := s.jobs[job.Name()]; ok {
		slog.WarnContext(ctx, "job already added: ignoring", "job_name", job.Name())
		return
	}

	s.wg.Go(func() {
		err := job.Activate(ctx)
		if err != nil {
			slog.ErrorContext(ctx, "job run failed", "job_name", job.Name(), "error", err)
		}
	})
	s.jobs[job.Name()] = job
}

func (s *Supervisor) handleJobConfigure(ctx context.Context, name string, config model.Scan) {
	s.jobsMx.Lock()
	defer s.jobsMx.Unlock()
	if jobp, ok := s.jobs[name]; !ok {
		slog.WarnContext(ctx, "job not added: ignoring configure", "job_name", name)
		return
	} else {
		jobp.MergeConfig(config)
	}
}

func (s *Supervisor) callStart(ctx context.Context, name string) error {
	s.jobsMx.Lock()
	defer s.jobsMx.Unlock()

	if name == "**" {
		slog.DebugContext(ctx, "triggering all jobs")
		for jobName, job := range s.jobs {
			slog.DebugContext(ctx, "starting a job", "job_name", jobName)
			job.Start()
		}
		return nil
	}

	if job, ok := s.jobs[name]; !ok {
		slog.WarnContext(ctx, "cannot start job: not known", "job_name", name)
	} else {
		slog.DebugContext(ctx, "starting a job", "job_name", name)
		job.Start()
	}

	return nil
}

func (s *Supervisor) upload(ctx context.Context, jobName string, stdout []byte) error {
	var errs []error
	for _, u := range s.uploaders {
		err := u.Upload(ctx, jobName, stdout)
		if err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func newScheduler(ctx context.Context, cfgp *model.TimerSchedule, startFunc func()) (time.Duration, gocron.Scheduler, error) {
	if cfgp == nil {
		return 0, nil, fmt.Errorf("service.schedule is nil")
	}
	cfg := *cfgp
	var job gocron.JobDefinition
	var d time.Duration
	var err error
	switch {
	case cfg.Cron != "":
		d, err = model.ParseCron(cfg.Cron)
		if err != nil {
			return 0, nil, fmt.Errorf("parsing service.scheduler.cron: %w", err)
		}
		job = gocron.CronJob(cfg.Cron, false)
		slog.DebugContext(ctx, "successfully parsed", "cron", cfg.Cron, "job", job)
	case cfg.Duration != "":
		d, err = model.ParseISODuration(cfg.Duration)
		if err != nil {
			return 0, nil, fmt.Errorf("parsing service.scheduler.duration: %w", err)
		}
		job = gocron.DurationJob(d)
		slog.DebugContext(ctx, "successfully parsed", "duration", d.String(), "job", job)
	default:
		return 0, nil, errors.New("both cron and duration are empty")
	}

	s, err := gocron.NewScheduler()
	if err != nil {
		return 0, nil, fmt.Errorf("initializing gocron scheduler: %w", err)
	}
	_, err = s.NewJob(
		job,
		gocron.NewTask(startFunc),
	)
	if err != nil {
		return 0, nil, fmt.Errorf("initializing gocron job: %w", err)
	}
	return d, s, nil
}

func uploaders(_ context.Context, cfg model.Service) ([]model.Uploader, error) {
	if cfg.Dir == "" && cfg.Repository == nil {
		return []model.Uploader{NewWriteUploader(os.Stdout)}, nil
	}
	var uploaders []model.Uploader
	if cfg.Dir != "" {
		u, err := NewOSRootUploader(cfg.Dir)
		if err != nil {
			return nil, err
		}
		uploaders = append(uploaders, u)
	}

	if cfg.Repository != nil {
		u, err := NewBOMRepoUploader(cfg.Repository.URL)
		if err != nil {
			return nil, err
		}
		uploaders = append(uploaders, u)
	}
	return uploaders, nil
}

type WriteUploader struct {
	w io.Writer
}

func NewWriteUploader(w io.Writer) WriteUploader {
	return WriteUploader{w: w}
}

func (u WriteUploader) Upload(_ context.Context, _ string, raw []byte) error {
	if u.w == nil {
		u.w = os.Stdout
	}
	_, err := u.w.Write(raw)
	return err
}

type OSRootUploader struct {
	root *os.Root
}

func NewOSRootUploader(path string) (*OSRootUploader, error) {
	root, err := os.OpenRoot(path)
	if err != nil {
		return nil, err
	}
	return &OSRootUploader{root: root}, nil
}

func (u *OSRootUploader) Upload(ctx context.Context, _ string, b []byte) error {
	if u.root == nil {
		return errors.New("root already closed")
	}

	path := "seeker-" + time.Now().Format("2006-01-02-15-04-05") + ".json"

	f, err := u.root.Create(path)
	if err != nil {
		return fmt.Errorf("creating seeker results: %w", err)
	}
	_, err = f.Write(b)
	if err != nil {
		return fmt.Errorf("saving seeker results: %w", err)
	}
	err = f.Close()
	if err != nil {
		return fmt.Errorf("closing seeker result: %w", err)
	}
	slog.InfoContext(ctx, "bom saved", "path", path)
	return nil
}

func (u *OSRootUploader) Close() error {
	if u.root == nil {
		return errors.New("uploader already closed")
	}
	err := u.root.Close()
	u.root = nil
	return err
}

// isJob is a sum-like type implementing the protocol for
// async scan job execution
type isJob interface {
	isJob()
}

type jobAdd struct {
	name string
	job  *Job
}

func (jobAdd) isJob() {}

type jobConfigure struct {
	name   string
	config *model.Scan
}

func (jobConfigure) isJob() {}

type jobStart struct {
	name string
}

func (jobStart) isJob() {}
