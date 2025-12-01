package service_test

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/CZERTAINLY/CBOM-lens/internal/model"
	"github.com/CZERTAINLY/CBOM-lens/internal/service"

	"github.com/stretchr/testify/require"
	"go.uber.org/goleak"
)

func TestMain(m *testing.M) {
	// Hidden service code unit testing protocol.
	// If _LENS_PRINT_STDOUT or _LENS_PRINT_STDERR are set, emit their values to the
	// respective stream and return immediately.
	// Used by test harnesses to exercise process spawning, stdout/stderr capture
	var testingCode bool
	if x := os.Getenv("_LENS_PRINT_STDOUT"); x != "" {
		fmt.Println(x)
		testingCode = true
	}
	if x := os.Getenv("_LENS_PRINT_STDERR"); x != "" {
		fmt.Fprintln(os.Stderr, x)
		testingCode = true
	}
	if testingCode {
		os.Exit(0)
	}

	goleak.VerifyTestMain(m)
	os.Exit(m.Run())
}

func TestSupervisor(t *testing.T) {
	t.Parallel()
	t.Run("timer", func(t *testing.T) {
		var testCases = []struct {
			scenario string
			given    string
		}{
			{
				scenario: "cron",
				given: `
version: 0

service:
    mode: timer
    schedule:
       cron: "@every 1s"
`,
			},
			{
				scenario: "duration",
				given: `
version: 0

service:
    mode: timer
    schedule:
       duration: "PT1S"
`,
			},
		}

		for _, tc := range testCases {
			t.Run(tc.scenario, func(t *testing.T) {
				cfg, err := model.LoadConfig(strings.NewReader(tc.given))
				require.NoError(t, err)
				var buf bytes.Buffer
				u := service.NewWriteUploader(&buf)
				supervisor, err := service.NewSupervisor(t.Context(), cfg)
				require.NoError(t, err)
				supervisor = supervisor.WithUploaders(t.Context(), u)

				ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
				t.Cleanup(cancel)

				var g sync.WaitGroup
				g.Go(func() {
					err := supervisor.Do(ctx)
					require.NoError(t, err)
				})
				// wait a little to let the supervisor to settle
				time.Sleep(200 * time.Millisecond)
				supervisor.AddJob(t.Context(), t.Name(), model.Scan{}, "Stdout")
				require.NoError(t, err)

				g.Wait()
				stdout := buf.String()
				require.NotEmpty(t, stdout)
				require.True(t, strings.HasPrefix(stdout, "Stdout\nStdout\n"))
			})
		}
	})

	t.Run("oneshot", func(t *testing.T) {
		const config = `
version: 0

service:
    mode: manual
`
		cfg, err := model.LoadConfig(strings.NewReader(config))
		require.NoError(t, err)
		var buf bytes.Buffer
		u := service.NewWriteUploader(&buf)
		supervisor, err := service.NewSupervisor(t.Context(), cfg)
		require.NoError(t, err)
		supervisor = supervisor.WithUploaders(t.Context(), u)

		var wg sync.WaitGroup
		ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
		t.Cleanup(cancel)
		start := time.Now()
		wg.Go(func() {
			err := supervisor.Do(ctx)
			require.NoError(t, err)
		})
		// wait a little to let the supervisor to settle
		time.Sleep(200 * time.Millisecond)

		supervisor.AddJob(t.Context(), t.Name(), model.Scan{}, "stdout")
		require.NoError(t, err)
		supervisor.Start("**")
		supervisor.ConfigureJob(t.Context(), t.Name(), model.Scan{})
		supervisor.ConfigureJob(t.Context(), "not"+t.Name(), model.Scan{})

		wg.Wait()
		// Job should complete well before the 10s service timeout since it only prints to stdout.
		// Use an 8s cap to leave headroom for a slow / overloaded CI before hitting the real timeout.
		require.WithinDuration(t, start, time.Now(), 8*time.Second)
		stdout := buf.String()
		require.NotEmpty(t, stdout)
		require.Equal(t, "stdout\n", stdout)
	})
}

func TestSupervisorFromConfig(t *testing.T) {
	cfg := model.Config{
		Service: model.Service{
			ServiceFields: model.ServiceFields{
				Verbose: true,
			},
		},
	}
	supervisor, err := service.NewSupervisor(t.Context(), cfg)
	require.NoError(t, err)
	require.NotEmpty(t, supervisor)
}

func TestOSRootUploader(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	u, err := service.NewOSRootUploader(dir)
	require.NoError(t, err)
	err = u.Upload(t.Context(), "cbom-lens.yaml", []byte("raw"))
	require.NoError(t, err)
}
