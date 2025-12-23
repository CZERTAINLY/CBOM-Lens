package stats

import (
	"expvar"
	"iter"
	"maps"
	"slices"
)

// Stats holds expvar-backed counters for the scanning process and publishes
// them under a common key prefix. All counters are expvar.Map and are safe for
// concurrent updates. When the standard expvar HTTP handler is registered,
// these values are available at /debug/vars.
//
// - cbom_lens_sources_total — count of all top-level sources (filesystem roots, Docker engines, Nmap)
// - cbom_lens_sources_errors — top-level sources that could not be accessed (e.g., Nmap scan failure)
// - cbom_lens_files_total — total file paths considered across all sources
// - cbom_lens_files_excluded — files successfully accessed but excluded (e.g., size limit, ignore rules)
// - cbom_lens_files_errors — files that could not be accessed (e.g., open/read/permission errors)
type Stats struct {
	prefix  string
	root    *expvar.Map
	sources *expvar.Map
	files   *expvar.Map
}

// New publishes new set of metrics. Registering the same metrics twice causes panic, so for tests, the prefix should be unique.
func New(prefix string) *Stats {
	root := expvar.NewMap(prefix)
	sources := new(expvar.Map).Init()
	files := new(expvar.Map).Init()

	sources.Add("total", 0)
	sources.Add("errors", 0)

	files.Add("total", 0)
	files.Add("errors", 0)
	files.Add("excluded", 0)

	root.Set("sources", sources)
	root.Set("files", files)

	return &Stats{
		prefix:  prefix,
		root:    root,
		sources: sources,
		files:   files,
	}
}

func (s *Stats) IncSources() {
	s.sources.Add("total", 1)
}
func (s *Stats) IncErrSources() {
	s.sources.Add("errors", 1)
}
func (s *Stats) IncFiles() {
	s.files.Add("total", 1)
}
func (s *Stats) IncExcludedFiles() {
	s.files.Add("excluded", 1)
}
func (s *Stats) IncErrFiles() {
	s.files.Add("errors", 1)
}

// Stats returns a name, value iterator across registered metrics. This uses expvar.Do under the hood, so is safe to be called concurrently.
// Stats are returned in an alphabetic order.
func (s Stats) Stats() iter.Seq2[string, string] {
	stats := make(map[string]string, 5)
	s.sources.Do(func(kv expvar.KeyValue) {
		stats["sources_"+kv.Key] = kv.Value.String()
	})
	s.files.Do(func(kv expvar.KeyValue) {
		stats["files_"+kv.Key] = kv.Value.String()
	})

	keys := slices.Sorted(maps.Keys(stats))
	return func(yield func(string, string) bool) {
		for _, key := range keys {
			if !yield(s.prefix+"_"+key, stats[key]) {
				return
			}
		}
	}
}
