package stats_test

import (
	"maps"
	"testing"

	"github.com/CZERTAINLY/CBOM-lens/internal/model"
	"github.com/CZERTAINLY/CBOM-lens/internal/stats"
	"github.com/stretchr/testify/require"
)

func TestNew(t *testing.T) {
	s := stats.New(t.Name())
	require.NotNil(t, s)
}

func TestIncSources(t *testing.T) {
	s := stats.New(t.Name())

	s.IncSources()
	s.IncSources()

	collected := maps.Collect(s.Stats())
	require.Equal(t, "2", collected[t.Name()+model.StatsSourcesTotal])
}

func TestIncSkippedSources(t *testing.T) {
	s := stats.New(t.Name())

	s.IncErrSources()
	s.IncErrSources()
	s.IncErrSources()

	collected := maps.Collect(s.Stats())
	require.Equal(t, "3", collected[t.Name()+model.StatsErrSkipped])
}

func TestIncFiles(t *testing.T) {
	s := stats.New(t.Name())

	for i := 0; i < 10; i++ {
		s.IncFiles()
	}

	collected := maps.Collect(s.Stats())
	require.Equal(t, "10", collected[t.Name()+model.StatsFilesTotal])
}

func TestIncExcludedFiles(t *testing.T) {
	s := stats.New(t.Name())

	s.IncExcludedFiles()
	s.IncExcludedFiles()

	collected := maps.Collect(s.Stats())
	require.Equal(t, "2", collected[t.Name()+model.StatsFilesExcluded])
}

func TestIncSkippedFiles(t *testing.T) {
	s := stats.New(t.Name())

	s.IncErrFiles()
	s.IncErrFiles()
	s.IncErrFiles()
	s.IncErrFiles()

	collected := maps.Collect(s.Stats())
	require.Equal(t, "4", collected[t.Name()+model.StatsFilesErr])
}

func TestStatsIterator(t *testing.T) {
	s := stats.New(t.Name())

	s.IncSources()
	s.IncSources()
	s.IncErrSources()
	s.IncFiles()
	s.IncExcludedFiles()
	s.IncErrFiles()

	collected := maps.Collect(s.Stats())

	require.Len(t, collected, 5)
	require.Equal(t, "2", collected[t.Name()+model.StatsSourcesTotal])
	require.Equal(t, "1", collected[t.Name()+model.StatsErrSkipped])
	require.Equal(t, "1", collected[t.Name()+model.StatsFilesTotal])
	require.Equal(t, "1", collected[t.Name()+model.StatsFilesExcluded])
	require.Equal(t, "1", collected[t.Name()+model.StatsFilesErr])
}

func TestStatsIteratorFiltersPrefix(t *testing.T) {
	s1 := stats.New("prefix-1")
	s2 := stats.New("prefix-2")

	s1.IncSources()
	s2.IncSources()
	s2.IncSources()

	collected := maps.Collect(s1.Stats())

	require.Len(t, collected, 5)
	for k := range collected {
		require.True(t, len(k) > 0 && k[:8] == "prefix-1", "key %s should start with prefix-1", k)
	}
}

func TestStatsInterfaceImplementation(t *testing.T) {
	var _ model.Stats = (*stats.Stats)(nil)
}

func TestConcurrentIncrements(t *testing.T) {
	s := stats.New(t.Name())

	done := make(chan bool)
	for range 10 {
		go func() {
			for range 100 {
				s.IncSources()
				s.IncFiles()
				s.IncExcludedFiles()
			}
			done <- true
		}()
	}

	for range 10 {
		<-done
	}

	collected := maps.Collect(s.Stats())
	require.Equal(t, "1000", collected[t.Name()+model.StatsSourcesTotal])
	require.Equal(t, "1000", collected[t.Name()+model.StatsFilesTotal])
	require.Equal(t, "1000", collected[t.Name()+model.StatsFilesExcluded])
}
