// Package dockertest provides a stub Docker Engine API daemon for tests.
//
// It answers just enough of the Engine API for the container walker and the
// socket probe: the /_ping endpoint used for API version negotiation and the
// image list endpoint. The daemon listens on TCP rather than a unix socket so
// the tests using it also run on Windows.
package dockertest

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// APIVersion is the API version the stub daemon reports from /_ping. It is
// below the client's MaxAPIVersion so tests also cover the downgrade path.
const APIVersion = "1.51"

// Daemon is a running stub Docker Engine API daemon.
type Daemon struct {
	// Host is the daemon address in tcp:// form, directly usable as
	// model.ContainerConfig.Host, as DOCKER_HOST and as client.WithHost.
	Host string
}

type config struct {
	images         http.HandlerFunc
	omitAPIVersion bool
}

// Option configures the stub daemon.
type Option func(*config)

// WithImages installs h as the handler for the image list endpoint. Use it to
// return a failure; for a successful listing prefer WithImagesJSON.
func WithImages(h http.HandlerFunc) Option {
	return func(c *config) { c.images = h }
}

// WithImagesJSON makes the image list endpoint return body as JSON.
func WithImagesJSON(body string) Option {
	return WithImages(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(body))
	})
}

// WithoutAPIVersion makes /_ping answer without the Api-Version header, as
// reverse proxies and pre-negotiation daemons do.
func WithoutAPIVersion() Option {
	return func(c *config) { c.omitAPIVersion = true }
}

// New starts a stub daemon and stops it when the test ends. Without options
// the image list endpoint reports an empty list.
func New(t *testing.T, opts ...Option) *Daemon {
	t.Helper()

	var cfg config
	WithImagesJSON("[]")(&cfg)
	for _, opt := range opts {
		opt(&cfg)
	}

	// The client prefixes requests with /v{version}, so match on suffixes.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/_ping"):
			if !cfg.omitAPIVersion {
				w.Header().Set("Api-Version", APIVersion)
			}
			w.WriteHeader(http.StatusOK)
		case strings.HasSuffix(r.URL.Path, "/images/json"):
			cfg.images(w, r)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)

	return &Daemon{Host: "tcp://" + srv.Listener.Addr().String()}
}
