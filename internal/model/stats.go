package model

import "iter"

const (
	StatsSourcesTotal  = "/sources/total"
	StatsErrSources    = "/sources/err"
	StatsFilesTotal    = "/files/total"
	StatsFilesExcluded = "/files/excluded"
	StatsFilesErr      = "/files/err"
)

type Stats interface {
	IncSources()
	IncErrSources()
	IncFiles()
	IncExcludedFiles()
	IncErrFiles()
	Stats() iter.Seq2[string, string]
}
