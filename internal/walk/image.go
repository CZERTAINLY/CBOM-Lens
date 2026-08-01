package walk

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"iter"
	"log/slog"

	"github.com/OmniTrustILM/cbom-lens/internal/log"
	"github.com/OmniTrustILM/cbom-lens/internal/model"
	"github.com/OmniTrustILM/cbom-lens/internal/stats"

	"github.com/anchore/stereoscope"
	"github.com/anchore/stereoscope/pkg/file"
	"github.com/anchore/stereoscope/pkg/filetree"
	"github.com/anchore/stereoscope/pkg/filetree/filenode"
	"github.com/anchore/stereoscope/pkg/image"

	"github.com/moby/moby/client"
)

// Images traverse through all defined containers and their images and all files inside
func Images(parentContext context.Context, counter *stats.Stats, configs model.ContainersConfig) iter.Seq2[model.Entry, error] {
	return func(yield func(model.Entry, error) bool) {
		for _, cc := range configs {
			counter.IncSources()
			ctx := log.ContextAttrs(parentContext,
				slog.Group("container",
					slog.String("name", cc.Name),
					slog.String("host", cc.Host),
				),
			)
			cli, err := newClient(ctx, cc)
			if err != nil {
				counter.IncErrSources()
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

			// Failing to enumerate the images makes the whole host
			// unusable, so it counts as a source failure, like a refused
			// connection.
			names, err := imageNames(ctx, cli, cc)
			if err != nil {
				counter.IncErrSources()
				slog.WarnContext(ctx, "can't list images on container host, skipping", "error", err)
				if !yield(nil, err) {
					return
				}
				continue
			}

			for _, name := range names {
				img, err := stereoscope.GetImageFromSource(ctx, name, image.DockerDaemonSource, nil)
				if err != nil {
					// One unreadable image does not invalidate the
					// host, the remaining images are still scanned.
					counter.IncErrFiles()
					slog.DebugContext(ctx, "can't load image, skipping", "image", name, "error", err)
					if !yield(nil, err) {
						return
					}
					continue
				}
				if img == nil {
					slog.DebugContext(ctx, "img is nil skipping")
					continue
				}

				var ident string
				if len(img.Metadata.Tags) >= 1 {
					ident = img.Metadata.Tags[0].String()
				} else {
					ident = img.Metadata.ID
				}

				slog.DebugContext(ctx, "scanning", "image", ident)
				for entry, err := range image1(ctx, counter, cc.Name, img) {
					if !yield(entry, err) {
						return
					}
				}
			}
		}
	}
}

// FS recursively walks the squashed layers of an OCI image.
// Each model.Entry's Path() is a real path of file inside.
func image1(ctx context.Context, counter *stats.Stats, name string, image *image.Image) iter.Seq2[model.Entry, error] {
	if image == nil {
		return func(yield func(model.Entry, error) bool) {
			yield(nil, errors.New("image is nil"))
		}
	}

	return func(yield func(model.Entry, error) bool) {
		done := make(chan struct{})
		fn := func(path file.Path, node filenode.FileNode) error {
			counter.IncFiles()
			if node.FileType != file.TypeRegular {
				counter.IncExcludedFiles()
				return nil
			}
			if !yield(dentry{name: name, node: node, image: image}, nil) {
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

func newClient(ctx context.Context, cfg model.ContainerConfig) (*client.Client, error) {
	cli, err := client.New(client.WithHost(cfg.Host))
	if err != nil {
		return nil, err
	}

	// client.New starts at the client's maximum API version and negotiates
	// lazily inside the first request, where the negotiation error is
	// discarded — an unreachable or too old daemon would then fail with a
	// confusing "client version is too new" instead of a connection error.
	// Negotiate here so an unusable host is reported as one.
	//
	// A daemon answering the ping without an Api-Version header (a proxy,
	// typically) keeps the client at its maximum version: the moby client
	// offers no way to detect that, so such a host is treated as usable.
	if _, err := cli.Ping(ctx, client.PingOptions{NegotiateAPIVersion: true}); err != nil {
		_ = cli.Close()
		return nil, fmt.Errorf("ping %s: %w", cfg.Host, err)
	}
	return cli, nil
}

// imageNames returns the images to scan on the host: the configured ones, or
// everything the daemon reports when none are configured.
func imageNames(ctx context.Context, cli *client.Client, cfg model.ContainerConfig) ([]string, error) {
	if len(cfg.Images) > 0 {
		return cfg.Images, nil
	}

	res, err := cli.ImageList(ctx, client.ImageListOptions{All: false})
	if err != nil {
		return nil, fmt.Errorf("listing images: %w", err)
	}

	names := make([]string, 0, len(res.Items))
	for _, dimg := range res.Items {
		names = append(names, dimg.ID)
	}
	return names, nil
}

// dentry implements model.Entry for an image file node
// uses OpenReference and FileCatalog.Get for Open/Stat operations
type dentry struct {
	name  string
	node  filenode.FileNode
	image *image.Image
}

func (e dentry) Location() string {
	var imageRef string

	if len(e.image.Metadata.Tags) >= 1 {
		imageRef = e.image.Metadata.Tags[0].Identifier()
	} else {
		imageRef = e.image.Metadata.ManifestDigest
	}

	return "container://" + e.name + "/" + imageRef + string(e.node.RealPath)
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
