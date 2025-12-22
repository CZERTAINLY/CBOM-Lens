package stats

import (
	"expvar"
	"iter"
	"strings"

	"github.com/CZERTAINLY/CBOM-lens/internal/model"
)

// Stats holds expvar-backed counters for the scanning process and publishes
// them under a common key prefix. All counters are expvar.Int and are safe for
// concurrent updates. When the standard expvar HTTP handler is registered,
// these values are available at /debug/vars.
//
// - /cbom-lens/sources/total — count of all top-level sources (filesystem roots, Docker engines, Nmap)
// - /cbom-lens/sources/err — top-level sources that could not be accessed (e.g., Nmap scan failure)
// - /cbom-lens/files/total — total file paths considered across all sources
// - /cbom-lens/files/excluded — files successfully accessed but excluded (e.g., size limit, ignore rules)
// - /cbom-lens/files/err — files that could not be accessed (e.g., open/read/permission errors)
type Stats struct {
	prefix        string
	totalSources  *expvar.Int
	errSources    *expvar.Int
	totalFiles    *expvar.Int
	errFiles      *expvar.Int
	excludedFiles *expvar.Int
}

var _ model.Stats = (*Stats)(nil)

// New publishes new set of metrics. Registering the same metrics twice causes panic, so for tests, the prefix should be unique.
func New(prefix string) *Stats {
	return &Stats{
		prefix:        prefix,
		totalSources:  expvar.NewInt(prefix + model.StatsSourcesTotal),
		errSources:    expvar.NewInt(prefix + model.StatsErrSources),
		totalFiles:    expvar.NewInt(prefix + model.StatsFilesTotal),
		excludedFiles: expvar.NewInt(prefix + model.StatsFilesExcluded),
		errFiles:      expvar.NewInt(prefix + model.StatsFilesErr),
	}
}

func (s *Stats) IncSources() {
	s.totalSources.Add(1)
}
func (s *Stats) IncErrSources() {
	s.errSources.Add(1)
}
func (s *Stats) IncFiles() {
	s.totalFiles.Add(1)
}
func (s *Stats) IncExcludedFiles() {
	s.excludedFiles.Add(1)
}
func (s *Stats) IncErrFiles() {
	s.errFiles.Add(1)
}

// Stats returns a name, value iterator across registered metrics. This uses expvar.Do under the hood, so is safe to be called concurrently.
func (s Stats) Stats() iter.Seq2[string, string] {
	var doBreak bool
	return func(yield func(string, string) bool) {
		expvar.Do(func(kv expvar.KeyValue) {
			if doBreak || !strings.HasPrefix(kv.Key, s.prefix+"/") {
				return
			}
			if !yield(kv.Key, kv.Value.String()) {
				doBreak = true
			}
		})
	}
}
