package model

import "iter"

const (
	StatsSourcesTotal   = "/sources/total"
	StatsSourcesSkipped = "/sources/skipped"
	StatsFilesTotal     = "/files/total"
	StatsFilesExcluded  = "/files/excluded"
	StatsFilesSkipped   = "/files/skipped"
)

type Stats interface {
	IncSources()
	IncSkippedSources()
	IncFiles()
	IncExcludedFiles()
	IncSkippedFiles()
	Stats() iter.Seq2[string, string]
}
