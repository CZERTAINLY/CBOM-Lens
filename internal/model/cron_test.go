package model_test

import (
	"errors"
	"testing"
	"time"

	"github.com/CZERTAINLY/CBOM-lens/internal/model"

	"github.com/stretchr/testify/require"
)

func TestParseCron(t *testing.T) {
	t.Parallel()
	type then struct {
		duration time.Duration
		err      error
	}
	cases := []struct {
		scenario string
		given    string
		then     then
	}{
		{"valid_5_fields", "*/15 * * * *", then{duration: 15 * time.Minute}},
		{"macro_hourly", "@hourly", then{duration: 60 * time.Minute}},
		{"macro_every", "@every 5m", then{duration: 5 * time.Minute}},
		{"invalid_field_count_4", "* * * *", then{err: errors.New("expected exactly 5 fields, found 4: [* * * *]")}},
		{"invalid_field_count_7", "* * * * * * *", then{err: errors.New("expected exactly 5 fields, found 7: [* * * * * * *]")}},

		{"invalid_token_5_fields", "* * 32 * *", then{err: errors.New("end of range (32) above maximum (31): 32")}},
		{"empty", "", then{err: errors.New("empty cron expression")}},
	}

	for _, tc := range cases {
		t.Run(tc.scenario, func(t *testing.T) {
			got, err := model.ParseCron(tc.given)
			if tc.then.err != nil {
				require.Error(t, err)
				require.EqualError(t, err, tc.then.err.Error())
			} else {
				require.NoError(t, err)
				require.Equal(t, tc.then.duration, got)
			}
		})
	}
}

func TestParseISODuration(t *testing.T) {
	expected := map[string]time.Duration{
		"PT20.345S":              20*time.Second + 345*time.Millisecond,
		"PT15M":                  15 * time.Minute,
		"PT10H":                  10 * time.Hour,
		"P2D":                    48 * time.Hour,
		"P2DT3H4M":               48*time.Hour + 3*time.Hour + 4*time.Minute,
		"P-6H3M":                 (-6 * time.Hour) + (3 * time.Minute),
		"PT5S":                   5 * time.Second,
		"PT1.5S":                 1*time.Second + 500*time.Millisecond,
		"PT0.250S":               250 * time.Millisecond,
		"PT1,25S":                1*time.Second + 250*time.Millisecond,
		"PT100H":                 100 * time.Hour,
		"P1DT1H":                 24*time.Hour + time.Hour,
		"PT0.000000001S":         time.Nanosecond,
		"PT123456789.123456789S": 123456789*time.Second + 123456789*time.Nanosecond,
		"-PT2H":                  -2 * time.Hour,
		"PT-2H":                  -2 * time.Hour,
		"PT+2H":                  2 * time.Hour,
		"PT-1M":                  -1 * time.Minute,
		"PT1M":                   1 * time.Minute,
		"P3DT-4H":                72*time.Hour - 4*time.Hour,
		"P3DT4H":                 72*time.Hour + 4*time.Hour,
		"PT-20.345S":             -(20*time.Second + 345*time.Millisecond),
	}

	errInvalid := errors.New("invalid ISO-8601 duration")

	cases := []struct {
		scenario string
		given    string
		then     error
	}{
		// Success cases
		{"fractional seconds", "PT20.345S", nil},
		{"minutes", "PT15M", nil},
		{"hours", "PT10H", nil},
		{"days", "P2D", nil},
		{"days time combo", "P2DT3H4M", nil},
		{"mixed signs no T (hours/minutes)", "P-6H3M", nil},
		{"simple seconds", "PT5S", nil},
		{"fraction dot", "PT1.5S", nil},
		{"fraction padding", "PT0.250S", nil},
		{"fraction comma", "PT1,25S", nil},
		{"large hours", "PT100H", nil},
		{"day hour", "P1DT1H", nil},
		{"nanos min", "PT0.000000001S", nil},
		{"big with fraction", "PT123456789.123456789S", nil},
		{"component negative hours", "PT-2H", nil},
		{"component positive hours", "PT+2H", nil},
		{"component negative minutes", "PT-1M", nil},
		{"component positive minutes", "PT1M", nil},
		{"day with negative hour", "P3DT-4H", nil},
		{"day with hour", "P3DT4H", nil},
		{"negative fractional seconds component", "PT-20.345S", nil},
		{"empty", "", errInvalid},
		{"just P", "P", errInvalid},
		{"just PT", "PT", errInvalid},
		{"unsupported years", "P1Y", errInvalid},
		{"unsupported months", "P2M", errInvalid},
		{"unsupported weeks", "P3W", errInvalid},
		{"bad fraction too long", "PT1.1234567891S", errInvalid},
		{"missing unit letter", "PT20.345", errInvalid},
		{"no P prefix", "T10H", errInvalid},
		{"letters only", "PTXS", errInvalid},
		{"double sign overall", "--PT1S", errInvalid},
		{"sign after P wrong place", "P+-1H", errInvalid},
		{"negative days and time sign conflict", "-P-1D-2H", errInvalid},
		{"time designator without components", "P2DT", errInvalid},
		{"seconds without S", "PT20", errInvalid},
		{"invalid separator space", "PT20 S", errInvalid},
	}

	for _, tc := range cases {
		t.Run(tc.scenario, func(t *testing.T) {
			dur, err := model.ParseISODuration(tc.given)
			if tc.then == nil {
				require.NoError(t, err)
				exp, ok := expected[tc.given]
				require.True(t, ok)
				require.Equal(t, exp, dur)
			} else {
				require.Error(t, err, "expected error for %q", tc.given)
			}
		})
	}
}
