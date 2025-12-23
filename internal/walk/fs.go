package walk

import (
	"context"
	"io"
	"io/fs"
	"iter"
	"log/slog"
	"os"
	"path/filepath"

	"github.com/CZERTAINLY/CBOM-lens/internal/model"
	"github.com/CZERTAINLY/CBOM-lens/internal/stats"
)

// Roots is a convenience wrapper around FS for os.Root. See FS for details.
func Roots(ctx context.Context, counter *stats.Stats, roots ...*os.Root) iter.Seq2[model.Entry, error] {
	return func(yield func(model.Entry, error) bool) {
		for _, root := range roots {
			for entry, err := range FS(ctx, counter, root.FS(), root.Name()) {
				if !yield(entry, err) {
					return
				}
			}
		}
	}
}

// FS recursively walks the filesystem rooted at root and return a handle for every regular file found.
// Or an error if file information retrieval fails.
// Each model.Entry's Path() is prefixed with name of a filesystem. In most cases it'll be an absolute
// path to the file. It does not follow symlinks.
func FS(ctx context.Context, counter *stats.Stats, root fs.FS, name string) iter.Seq2[model.Entry, error] {
	if root == nil {
		slog.WarnContext(ctx, "root is nil: not iterating")
		return nil
	}

	return func(yield func(model.Entry, error) bool) {
		fn := func(path string, d fs.DirEntry, err error) error {
			if ctx.Err() != nil {
				return fs.SkipAll
			}
			if !d.IsDir() {
				counter.IncFiles()
			}
			var entry = fsEntry{
				root:    root,
				abspath: filepath.Join(name, path),
				path:    path,
			}
			var yieldErr error
			if err != nil {
				yieldErr = err
			} else {
				info, err := d.Info()
				if err != nil {
					counter.IncErrFiles()
					entry.infoErr = err
					yieldErr = err
				} else {
					if !info.Mode().IsRegular() {
						if !info.IsDir() {
							counter.IncExcludedFiles()
						}
						return nil
					}
					entry.info = info
					yieldErr = nil
				}
			}

			if !yield(entry, yieldErr) {
				return fs.SkipAll
			}
			return nil
		}
		_ = fs.WalkDir(root, ".", fn)
	}
}

// fsEntry implements model.Entry for a filesystem
// it uses root.Open to open the file
type fsEntry struct {
	root    fs.FS
	abspath string
	path    string
	info    fs.FileInfo
	infoErr error
}

// returns the absolute path to the file
func (e fsEntry) Path() string {
	return e.abspath
}

func (e fsEntry) Open() (io.ReadCloser, error) {
	if e.infoErr != nil {
		return nil, e.infoErr
	}
	return e.root.Open(e.path)
}

func (e fsEntry) Stat() (fs.FileInfo, error) {
	return e.info, e.infoErr
}
