package walk

import (
	"context"
	"errors"
	"io"
	"io/fs"
	"iter"
	"log/slog"

	"github.com/CZERTAINLY/CBOM-lens/internal/log"
	"github.com/CZERTAINLY/CBOM-lens/internal/model"

	"github.com/anchore/stereoscope"
	"github.com/anchore/stereoscope/pkg/file"
	"github.com/anchore/stereoscope/pkg/filetree"
	"github.com/anchore/stereoscope/pkg/filetree/filenode"
	"github.com/anchore/stereoscope/pkg/image"

	dimage "github.com/docker/docker/api/types/image"
	"github.com/docker/docker/client"
)

// FS recursively walks the squashed layers of an OCI image.
// Each Entry's Path() is a real path of file inside.
func Image(ctx context.Context, image *image.Image) iter.Seq2[Entry, error] {
	if image == nil {
		return func(yield func(Entry, error) bool) {
			yield(nil, errors.New("image is nil"))
		}
	}

	return func(yield func(Entry, error) bool) {
		done := make(chan struct{})
		fn := func(path file.Path, node filenode.FileNode) error {
			if node.FileType != file.TypeRegular {
				return nil
			}
			if !yield(dentry{node: node, image: image}, nil) {
				close(done)
			}
			return nil
		}
		cond := filetree.WalkConditions{
			ShouldTerminate: func(_ file.Path, _ filenode.FileNode) bool {
				select {
				case <-ctx.Done():
					return true
				case <-done:
					return true
				default:
					return false
				}
			},
			ShouldVisit: func(path file.Path, node filenode.FileNode) bool {
				return !node.IsLink()
			},
			ShouldContinueBranch: func(_ file.Path, node filenode.FileNode) bool {
				return !node.IsLink()
			},
			LinkOptions: nil,
		}
		_ = image.SquashedTree().Walk(fn, &cond)
	}
}

// Images traverse through all defined containers and their images and all files inside
func Images(parentContext context.Context, configs model.ContainersConfig) iter.Seq2[Entry, error] {
	return func(yield func(Entry, error) bool) {
		for _, cc := range configs {
			ctx := log.ContextAttrs(parentContext, slog.String("host", cc.Host))
			cli, err := newClient(ctx, cc)
			if err != nil {
				slog.WarnContext(ctx, "can't connect to container host, skipping", "error", err)
				if !yield(nil, err) {
					return
				}
				continue
			}
			slog.DebugContext(ctx, "connected to container host")
			defer func() {
				if cli != nil {
					_ = cli.Close()
				}
			}()
			for img := range images(ctx, cli, cc) {
				if img == nil {
					slog.DebugContext(ctx, "img is nil skipping")
					continue
				}

				var ident string
				if img.Metadata.Tags != nil {
					ident = img.Metadata.Tags[0].String()
				} else {
					ident = img.Metadata.ID
				}

				slog.DebugContext(ctx, "scanning", "image", ident)
				for entry, err := range Image(ctx, img) {
					if !yield(entry, err) {
						return
					}
				}
			}
		}
	}
}

func newClient(_ context.Context, cfg model.ContainerConfig) (*client.Client, error) {
	cli, err := client.NewClientWithOpts(
		client.WithHost(cfg.Host),
		client.WithAPIVersionNegotiation(),
	)
	if err != nil {
		return nil, err
	}
	return cli, nil
}

func images(ctx context.Context, cli *client.Client, cfg model.ContainerConfig) iter.Seq2[*image.Image, error] {
	if len(cfg.Images) == 0 {
		return imagesAll(ctx, cli)
	}

	return func(yield func(*image.Image, error) bool) {
		for _, name := range cfg.Images {
			img, err := stereoscope.GetImageFromSource(
				ctx,
				name,
				image.DockerDaemonSource,
				nil,
			)
			if !yield(img, err) {
				return
			}
		}
	}
}

func imagesAll(ctx context.Context, cli *client.Client) iter.Seq2[*image.Image, error] {
	return func(yield func(*image.Image, error) bool) {
		images, err := cli.ImageList(
			ctx,
			dimage.ListOptions{All: false},
		)
		if err != nil {
			if !yield(nil, err) {
				return
			}
		}

		for _, dimg := range images {
			img, err := stereoscope.GetImageFromSource(
				ctx,
				dimg.ID,
				image.DockerDaemonSource,
				nil,
			)
			if !yield(img, err) {
				return
			}
		}
	}
}

// dentry implements Entry for an image file node
// uses OpenReference and FileCatalog.Get for Open/Stat operations
type dentry struct {
	node  filenode.FileNode
	image *image.Image
}

func (e dentry) Path() string {
	return string(e.node.RealPath)
}

func (e dentry) Open() (io.ReadCloser, error) {
	return e.image.OpenReference(*e.node.Reference)
}

func (e dentry) Stat() (fs.FileInfo, error) {
	entry, err := e.image.FileCatalog.Get(*e.node.Reference)
	if err != nil {
		return nil, err
	}
	return entry.FileInfo, nil
}
