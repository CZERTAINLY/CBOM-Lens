// Runner is a minimal single‑slot external command executor specialized for a narrow
// supervision use case. It enforces “at most one process at a time” and exposes
// only the most recent Result.
//
// Lifecycle / usage pattern:
//
//	runner := NewRunner()
//	defer runner.Close()
//	_ = r.Start(ctx, cmd, stderrFunc)
//	// supervision code
//	for {
//		select {
//			switch {
//				case ctx.Done():
//					return
//				case <-startChan:
//					_ = runner.Start(ctx)
//				case result := <-runner.ResultsChan():
//					// process results here
//
// Key behaviors and caveats:
//   - Single run: Start returns ErrScanInProgress if a previous command is still running.
//   - Result delivery: Exactly one Result is sent per successful Start, but ONLY if
//     ResultsChan() was called before the process finishes. Otherwise the result is dropped.
//   - Channel reuse: The same buffered (size 1) channel is reused across runs; it is never
//     closed. Do not range over it. Always perform a single receive per run.
//   - Back‑pressure / deadlock risk: The process completion goroutine sends the Result
//     while holding the internal lock. If the previous run’s Result is still sitting unread
//     in the channel, the send blocks and stops further use (deadlock). Always drain the
//     channel before starting another run.
//   - Close semantics: Close is supposed to be called via defer on a shutdown. It invalidates
//     runner for further Start anyway.
//   - Cancellation / timeouts: It is a good hygiene to bound the process wall clock via
//     context. Runner warns if this is not the case.
//   - Stdout capture: Entire stdout is accumulated in memory (bytes.Buffer). Large outputs
//     raise memory usage; no streaming or size limit is enforced.
//   - Stderr handling: If a StderrFunc is provided, stderr is scanned line‑by‑line with
//     bufio.Scanner (64K token limit). Very long lines will error or be truncated.
//   - Environment: The provided Env replaces (does not merge with) the parent process
//     environment; supply os.Environ() yourself if needed.
//   - Concurrency: LastResult() returns a snapshot under read lock; it should be never called
//     if program is still running. It exists only to support the unit testing.
package service

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"sync"
	"sync/atomic"
	"time"
)

var (
	ErrScanNotStarted = errors.New("scan not started")
	ErrScanInProgress = errors.New("scan in progress")
	ErrRunnerClosed   = errors.New("runner is closed, cannot start new command")
)

type StderrFunc func(ctx context.Context, line string)

type Runner struct {
	mx                sync.RWMutex
	cmd               *exec.Cmd
	cancelFunc        context.CancelFunc
	result            Result
	resultsChanCalled atomic.Bool
	results           chan Result
	closing           bool
	stderrFunc        StderrFunc
}

func NewRunner(f StderrFunc) *Runner {
	return &Runner{
		stderrFunc: f,
		result: Result{
			Err: ErrScanNotStarted,
		},
		results: make(chan Result, 1),
	}
}

type Command struct {
	JobName string
	Path    string
	Args    []string
	Env     []string
	Timeout time.Duration
	Stdin   []byte
}

type Result struct {
	JobName string
	Path    string
	Args    []string
	Env     []string
	Started time.Time
	Stopped time.Time
	State   *os.ProcessState
	Stdout  []byte
	Err     error
}

// Start run the underlying process, it ensure only single instance of a binary is active
// returns ErrScanInProgress or an exec error, otherwise nil. Does NOT wait on
// command to finish, use ResultsChan instead.
// Note it spawns an internal goroutine(w) which monitors the started command and stderr
func (r *Runner) Start(ctx context.Context, proto Command) error {
	r.mx.Lock()
	defer r.mx.Unlock()
	if r.closing {
		return ErrRunnerClosed
	}
	if r.cmd != nil {
		return ErrScanInProgress
	}

	r.result = Result{
		JobName: proto.JobName,
		Path:    proto.Path,
		Args:    append([]string(nil), proto.Args...),
		Env:     append([]string(nil), proto.Env...),
		Err:     nil,
	}

	if proto.Timeout == 0 {
		slog.WarnContext(ctx, "command has no timeout", "path", proto.Path)
		ctx, r.cancelFunc = context.WithCancel(ctx)
	} else {
		ctx, r.cancelFunc = context.WithTimeout(ctx, proto.Timeout)
	}

	r.cmd = exec.CommandContext(ctx, r.result.Path, r.result.Args...)
	r.cmd.Env = r.result.Env
	var stderr io.ReadCloser
	if r.stderrFunc != nil {
		var err error
		stderr, err = r.cmd.StderrPipe()
		if err != nil {
			return err
		}
	} else {
		r.cmd.Stderr = os.Stderr
	}
	var buf bytes.Buffer
	r.cmd.Stdout = &buf

	if proto.Stdin != nil {
		r.cmd.Stdin = bytes.NewReader(proto.Stdin)
	}

	r.result.Started = time.Now().UTC()
	if err := r.cmd.Start(); err != nil {
		r.result.Stopped = time.Now().UTC()
		r.result.Err = err
		r.cmd = nil
		return err
	}

	if r.stderrFunc != nil {
		go r.processStderr(ctx, stderr)
	}

	go r.wait(r.cmd, &buf)
	return nil
}

// ResultsChan is channel which contains results of a running program
// calling this method ensures results are sent to the channel
func (r *Runner) ResultsChan() <-chan Result {
	r.mx.Lock()
	r.resultsChanCalled.Store(true)
	ret := r.results
	r.mx.Unlock()
	return ret
}

// LastResult returns a last command result
// or result with ErrScanNotStarted or ErrScanInProgress
// if no results are available
func (r *Runner) LastResult() Result {
	r.mx.RLock()
	defer r.mx.RUnlock()
	return r.result
}

// Close kills a currently running program, deactivates and closes results channel
// and prevents further Start to be called. The result of this command is never send,
// but can be obtained via LastResult.
// However this method is supposed to be called on a shutdown only.
func (r *Runner) Close() {
	r.mx.Lock()
	defer r.mx.Unlock()
	if r.cancelFunc != nil {
		r.cancelFunc()
	}
	r.closing = true
	r.resultsChanCalled.Store(false)
	close(r.results)
}

func (r *Runner) processStderr(ctx context.Context, stderr io.Reader) {
	scanner := bufio.NewScanner(stderr)
	for scanner.Scan() {
		r.stderrFunc(ctx, scanner.Text())
	}
	err := scanner.Err()
	if err != nil && !errors.Is(err, io.EOF) {
		slog.ErrorContext(ctx, "processing stderr", "error", err)
	}
}

func (r *Runner) wait(cmd *exec.Cmd, bufp *bytes.Buffer) {
	err := cmd.Wait()
	if r.cancelFunc != nil {
		r.cancelFunc()
	}
	stopped := time.Now().UTC()

	r.mx.Lock()
	// forces a copy of a stdout buffer, so Result owns
	// the data
	r.result.Stdout = append([]byte(nil), bufp.Bytes()...)
	r.result.Stopped = stopped
	r.result.State = cmd.ProcessState
	r.result.Err = err
	r.cmd = nil
	r.mx.Unlock()

	if r.resultsChanCalled.CompareAndSwap(true, true) {
		r.results <- r.result
	}
}
