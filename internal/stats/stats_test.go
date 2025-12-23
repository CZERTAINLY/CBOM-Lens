package stats_test

import (
	"maps"
	"testing"

	"github.com/CZERTAINLY/CBOM-lens/internal/stats"

	"github.com/stretchr/testify/require"
)

func TestNew(t *testing.T) {
	s := stats.New(t.Name())

	require.NotNil(t, s)

	// Verify initial values are set to 0
	result := maps.Collect(s.Stats())
	require.Equal(t, "0", result[t.Name()+"_files_errors"])
	require.Equal(t, "0", result[t.Name()+"_files_excluded"])
	require.Equal(t, "0", result[t.Name()+"_files_total"])
	require.Equal(t, "0", result[t.Name()+"_sources_errors"])
	require.Equal(t, "0", result[t.Name()+"_sources_total"])
}

func TestIncSources(t *testing.T) {
	s := stats.New(t.Name())

	s.IncSources()
	result := maps.Collect(s.Stats())
	require.Equal(t, "1", result[t.Name()+"_sources_total"])

	s.IncSources()
	s.IncSources()
	result = maps.Collect(s.Stats())
	require.Equal(t, "3", result[t.Name()+"_sources_total"])
}

func TestIncErrSources(t *testing.T) {
	s := stats.New(t.Name())

	s.IncErrSources()
	result := maps.Collect(s.Stats())
	require.Equal(t, "1", result[t.Name()+"_sources_errors"])

	s.IncErrSources()
	result = maps.Collect(s.Stats())
	require.Equal(t, "2", result[t.Name()+"_sources_errors"])
}

func TestIncFiles(t *testing.T) {
	s := stats.New(t.Name())

	s.IncFiles()
	result := maps.Collect(s.Stats())
	require.Equal(t, "1", result[t.Name()+"_files_total"])

	s.IncFiles()
	s.IncFiles()
	result = maps.Collect(s.Stats())
	require.Equal(t, "3", result[t.Name()+"_files_total"])
}

func TestIncExcludedFiles(t *testing.T) {
	s := stats.New(t.Name())

	s.IncExcludedFiles()
	result := maps.Collect(s.Stats())
	require.Equal(t, "1", result[t.Name()+"_files_excluded"])

	s.IncExcludedFiles()
	result = maps.Collect(s.Stats())
	require.Equal(t, "2", result[t.Name()+"_files_excluded"])
}

func TestIncErrFiles(t *testing.T) {
	s := stats.New(t.Name())

	s.IncErrFiles()
	result := maps.Collect(s.Stats())
	require.Equal(t, "1", result[t.Name()+"_files_errors"])

	s.IncErrFiles()
	result = maps.Collect(s.Stats())
	require.Equal(t, "2", result[t.Name()+"_files_errors"])
}

func TestStats_AlphabeticOrder(t *testing.T) {
	s := stats.New(t.Name())

	var keys []string
	for key := range s.Stats() {
		keys = append(keys, key)
	}

	// Verify alphabetic order
	expectedOrder := []string{
		t.Name() + "_files_errors",
		t.Name() + "_files_excluded",
		t.Name() + "_files_total",
		t.Name() + "_sources_errors",
		t.Name() + "_sources_total",
	}
	require.Equal(t, expectedOrder, keys)
}

func TestStats_Integration(t *testing.T) {
	s := stats.New(t.Name())

	// Simulate scanning workflow
	s.IncSources()
	s.IncSources()
	s.IncErrSources()

	s.IncFiles()
	s.IncFiles()
	s.IncFiles()
	s.IncExcludedFiles()
	s.IncErrFiles()

	result := maps.Collect(s.Stats())
	require.Equal(t, "2", result[t.Name()+"_sources_total"])
	require.Equal(t, "1", result[t.Name()+"_sources_errors"])
	require.Equal(t, "3", result[t.Name()+"_files_total"])
	require.Equal(t, "1", result[t.Name()+"_files_excluded"])
	require.Equal(t, "1", result[t.Name()+"_files_errors"])
}
