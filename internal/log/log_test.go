package log_test

import (
	"bytes"
	"log/slog"
	"testing"

	"github.com/CZERTAINLY/CBOM-lens/internal/log"
	"github.com/stretchr/testify/require"
)

func TestContextAttrs(t *testing.T) {
	t.Parallel()
	tests := []struct {
		scenario string // description of this test case
		// Named input parameters for target function.
		given []slog.Attr
		then  string
	}{
		{
			scenario: "nil; attrs",
			given:    nil,
			then:     `{"level":"INFO","msg":"testing message","foo":"bar"}`,
		},
		{
			scenario: "empty attrs",
			given:    []slog.Attr{},
			then:     `{"level":"INFO","msg":"testing message","foo":"bar"}`,
		},
		{
			scenario: "ham/spam attrs",
			given: []slog.Attr{
				slog.String("ham", "spam"),
			},
			then: `{"level":"INFO","msg":"testing message","foo":"bar", "ham":"spam"}`,
		},
		{
			scenario: "slog.Group",
			given: []slog.Attr{
				slog.Group("group", slog.String("ham", "spam")),
			},
			then: `{"level":"INFO","msg":"testing message","foo":"bar", "group": {"ham":"spam"}}`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.scenario, func(t *testing.T) {
			t.Parallel()
			var buf bytes.Buffer
			base := slog.NewJSONHandler(&buf, &slog.HandlerOptions{
				AddSource: false,
				Level:     slog.LevelDebug,
				ReplaceAttr: func(groups []string, a slog.Attr) slog.Attr {
					if a.Key == slog.TimeKey {
						return slog.Attr{}
					}
					return a
				},
			})
			ctxHandler := log.NewContextHandler(base)
			logger := slog.New(ctxHandler)

			ctx := log.ContextAttrs(t.Context(), tt.given...)
			logger.InfoContext(ctx, "testing message", slog.String("foo", "bar"))

			t.Logf("log output: %s", buf.String())
			require.JSONEq(t, tt.then, buf.String())
		})
	}
}

func TestNew(t *testing.T) {
	t.Parallel()
	require.NotNil(t, log.New(true))
	require.NotNil(t, log.New(false))
}
