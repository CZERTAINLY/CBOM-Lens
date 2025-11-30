package service_test

import (
	"context"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/CZERTAINLY/Seeker/internal/service"
	"github.com/stretchr/testify/require"
)

func TestRunner(t *testing.T) {
	t.Parallel()
	yes, err := exec.LookPath("yes")
	if err != nil {
		t.Skipf("skipped, binary yes not available: %v", err)
	}

	runner := service.NewRunner(nil)
	t.Cleanup(runner.Close)
	t.Run("not yet started", func(t *testing.T) {
		res := runner.LastResult()
		require.ErrorIs(t, res.Err, service.ErrScanNotStarted)
	})

	cmd := service.Command{
		JobName: "seeker.yaml",
		Path:    yes,
		Args:    []string{"golang"},
		Env:     []string{"LC_ALL=C"},
		Timeout: 100 * time.Millisecond,
	}
	ctx := t.Context()

	t.Run("start", func(t *testing.T) {
		err = runner.Start(ctx, cmd)
		require.NoError(t, err)
		res := runner.LastResult()
		require.NoError(t, res.Err)
		require.Equal(t, "seeker.yaml", res.JobName)
	})
	t.Run("in progress", func(t *testing.T) {
		err = runner.Start(ctx, cmd)
		require.Error(t, err)
		require.ErrorIs(t, err, service.ErrScanInProgress)
	})
	t.Run("results chan", func(t *testing.T) {
		res := <-runner.ResultsChan()
		require.Equal(t, yes, res.Path)
		require.Equal(t, []string{"golang"}, res.Args)
		require.NotZero(t, res.Started)
		require.NotZero(t, res.Stopped)
		require.Equal(t, "seeker.yaml", res.JobName)
		// on GHA command `yes` finishes up earlier with
		// ERROR processing stderr error="read |0: file already closed"
		// lets not make this a fatal error
		require.GreaterOrEqual(t, res.Stopped.Sub(res.Started), 80*time.Millisecond)
		require.Error(t, res.Err)
		var exitErr *exec.ExitError
		require.ErrorAs(t, res.Err, &exitErr)

		require.Greater(t, len(res.Stdout), 1024)
		require.True(t, strings.HasPrefix(
			string(res.Stdout[:256]),
			"golang\ngolang\n",
		))
	})
	t.Run("exec error", func(t *testing.T) {
		noCmd := service.Command{
			JobName: "seeker.yaml",
			Path:    "does not exist",
		}
		err := runner.Start(ctx, noCmd)
		require.Error(t, err)
		var execErr *exec.Error
		require.ErrorAs(t, err, &execErr)
		require.Equal(t, noCmd.Path, execErr.Name)
		require.EqualError(t, execErr.Err, "executable file not found in $PATH")
	})
}

func TestStderr(t *testing.T) {
	t.Parallel()
	sh, err := exec.LookPath("sh")
	if err != nil {
		t.Skipf("skipped, binary sh not available: %v", err)
	}

	cmd := service.Command{
		JobName: "something",
		Path:    sh,
		Args:    []string{"-c", "echo stdout; echo 1>&2 'stderr\nstderr\n'"},
		Timeout: 50 * time.Second,
	}

	stderrChan := make(chan string, 3)
	handle := func(_ context.Context, line string) {
		stderrChan <- line
	}

	runner := service.NewRunner(handle)
	t.Cleanup(runner.Close)
	err = runner.Start(t.Context(), cmd)
	require.NoError(t, err)
	res := <-runner.ResultsChan()
	require.Equal(t, "stdout\n", string(res.Stdout))
	require.Equal(t, "something", res.JobName)

	var stderr = []string{
		<-stderrChan,
		<-stderrChan,
		<-stderrChan,
	}
	require.Equal(t, []string{"stderr", "stderr", ""}, stderr)
}
