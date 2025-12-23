package model

import (
	"io"
	"io/fs"
)

// Entry abstracts the filesystem entry - it does not matter if a file is from
// filesystem or OCI image. It allows to get the path, Open the file and do stat
type Entry interface {
	Path() string
	Open() (io.ReadCloser, error)
	Stat() (fs.FileInfo, error)
}
