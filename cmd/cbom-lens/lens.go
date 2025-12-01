package main

import (
	"context"
	"fmt"
	"io"
	"iter"
	"log/slog"
	"net/netip"
	"os"

	"github.com/CZERTAINLY/CBOM-lens/internal/bom"
	"github.com/CZERTAINLY/CBOM-lens/internal/cdxprops"
	"github.com/CZERTAINLY/CBOM-lens/internal/model"
	"github.com/CZERTAINLY/CBOM-lens/internal/nmap"
	"github.com/CZERTAINLY/CBOM-lens/internal/scanner/gitleaks"
	"github.com/CZERTAINLY/CBOM-lens/internal/scanner/pem"
	"github.com/CZERTAINLY/CBOM-lens/internal/scanner/x509"
	"github.com/CZERTAINLY/CBOM-lens/internal/service"
	"github.com/CZERTAINLY/CBOM-lens/internal/walk"

	"golang.org/x/sync/errgroup"
)

// Lens is a component, which encapsulates the scan functionality and executes it.
type Lens struct {
	detectors   []service.Detector
	filesystems iter.Seq2[walk.Entry, error]
	containers  iter.Seq2[walk.Entry, error]
	nmaps       []nmap.Scanner
	ips         []netip.Addr
	converter   cdxprops.Converter
}

func NewLens(ctx context.Context, config model.Scan) (Lens, error) {
	if config.Version != 0 {
		return Lens{}, fmt.Errorf("config version %d is not supported, expected 0", config.Version)
	}

	// initialize inputs (filesystem, containers)
	filesystems, err := filesystems(ctx, config.Filesystem)
	if err != nil {
		slog.WarnContext(ctx, "initializing filesytem scan failed", "error", err)
		filesystems = nil
	}

	containers := containers(ctx, config.Containers)

	// initialize nmap scanner
	nmaps, ips := nmaps(ctx, config.Ports)

	// initialize scanners
	x509Scanner := x509.Scanner{}
	pemScanner := pem.Scanner{}
	leaksScanner, err := gitleaks.NewScanner()
	if err != nil {
		return Lens{}, fmt.Errorf("can't create gitleaks scanner: %w", err)
	}

	// scan result to cyclonedx-go converter
	converter := cdxprops.NewConverter()

	detectors := []service.Detector{
		x509Detector{
			s:       x509Scanner,
			convert: converter.CertHit,
		},
		detector[model.PEMBundle]{
			name:    "pem",
			scanner: pemScanner,
			convert: converter.PEMBundle,
		},
	}

	if leaksScanner != nil {
		detectors = append(detectors,
			detector[model.Leaks]{
				name:    "leaks",
				scanner: leaksScanner,
				convert: converter.Leak,
			})
	}

	return Lens{
		detectors:   detectors,
		filesystems: filesystems,
		containers:  containers,
		nmaps:       nmaps,
		ips:         ips,
		converter:   converter,
	}, nil
}

func (s Lens) Do(ctx context.Context, out io.Writer) error {
	g, ctx := errgroup.WithContext(ctx)

	b := bom.NewBuilder()
	detections := make(chan model.Detection)
	processed := make(chan struct{})
	go func() {
		defer close(processed)
		for d := range detections { // will be closed after g.Wait()
			b.AppendDetections(ctx, d)
		}
	}()

	// TODO: configure a parallelism
	// filesystem scanners
	if s.filesystems != nil {
		scanner := service.New(4, s.detectors)
		g.Go(func() error {
			goScan(ctx, scanner, s.filesystems, detections)
			return nil
		})
	}

	// containers scanners
	if s.containers != nil {
		scanner := service.New(2, s.detectors)
		g.Go(func() error {
			goScan(ctx, scanner, s.containers, detections)
			return nil
		})
	}

	// nmap scans
	for _, ip := range s.ips {
		g.Go(func() error {
			for _, n := range s.nmaps {
				nmapScan(ctx, n, ip, s.converter, detections)
			}
			return nil
		})
	}

	_ = g.Wait()
	close(detections)

	<-processed
	err := b.AsJSON(out)
	if err != nil {
		return fmt.Errorf("formatting BOM as JSON: %w", err)
	}
	return nil
}

func goScan(ctx context.Context, scanner *service.Scan, seq iter.Seq2[walk.Entry, error], detections chan<- model.Detection) {
	for results, err := range scanner.Do(ctx, seq) {
		if err != nil {
			slog.DebugContext(ctx, "error on filesystem scan", "error", err)
			continue
		}
		for _, detection := range results {
			detections <- detection
		}
	}
}

func nmapScan(ctx context.Context, scanner nmap.Scanner, ip netip.Addr, c cdxprops.Converter, detections chan<- model.Detection) {
	nmapScan, err := scanner.Scan(ctx, ip)
	if err != nil {
		slog.ErrorContext(ctx, "nmap scan failed", "error", err)
		return
	}
	d := c.Nmap(ctx, nmapScan)
	if d == nil {
		return
	}

	detections <- *d
}

func filesystems(ctx context.Context, cfg model.Filesystem) (iter.Seq2[walk.Entry, error], error) {
	var filesystems iter.Seq2[walk.Entry, error]
	if !cfg.Enabled {
		return filesystems, nil
	}

	paths := cfg.Paths
	if len(paths) == 0 {
		cwd, err := os.Getwd()
		if err != nil {
			return filesystems, fmt.Errorf("getting working directory: %w", err)
		}
		paths = []string{cwd}
	}

	roots := make([]*os.Root, 0, len(paths))
	for _, path := range paths {
		root, err := os.OpenRoot(path)
		if err != nil {
			slog.WarnContext(ctx, "can't open dir, skipping", "dir", path, "error", err)
			continue
		}
		roots = append(roots, root)
	}
	ret := walk.Roots(ctx, roots...)
	return ret, nil
}

func containers(ctx context.Context, config model.Containers) iter.Seq2[walk.Entry, error] {
	if !config.Enabled {
		return nil
	}

	ret := walk.Images(ctx, config.Config)
	return ret
}

func nmaps(_ context.Context, cfg model.Ports) ([]nmap.Scanner, []netip.Addr) {
	if !cfg.Enabled {
		return nil, nil
	}

	if !cfg.IPv4 && !cfg.IPv6 {
		return nil, nil
	}

	var ips []netip.Addr
	if cfg.IPv4 {
		ips = append(ips, netip.MustParseAddr("127.0.0.1"))
	}
	if cfg.IPv6 {
		ips = append(ips, netip.IPv6Loopback())
	}

	var scanner = nmap.New()

	if cfg.Binary != "" {
		scanner.WithNmapBinary(cfg.Binary)
	}
	if cfg.Ports != "" {
		scanner = scanner.WithPorts(cfg.Ports)
	}

	return []nmap.Scanner{scanner}, ips
}

type scanner[T any] interface {
	Scan(context.Context, []byte, string) (T, error)
}

// detector joins the scanner with converter which produces
// the model.Detection
type detector[T any] struct {
	name    string
	scanner scanner[T]
	convert func(context.Context, T) *model.Detection
}

type x509Detector struct {
	s       x509.Scanner
	convert func(context.Context, model.CertHit) *model.Detection
}

func (x x509Detector) LogAttrs() []slog.Attr {
	return []slog.Attr{
		slog.String("detector", "x509"),
	}
}

func (w x509Detector) Detect(ctx context.Context, b []byte, s string) ([]model.Detection, error) {
	hits, err := w.s.Scan(ctx, b, s)
	if err != nil {
		return nil, err
	}

	var ret = make([]model.Detection, 0, len(hits))
	for _, hit := range hits {
		dp := w.convert(ctx, hit)
		if dp == nil {
			continue
		}
		ret = append(ret, *dp)
	}
	return ret, nil
}

func (d detector[T]) LogAttrs() []slog.Attr {
	return []slog.Attr{
		slog.String("detector", d.name),
	}
}

func (d detector[T]) Detect(ctx context.Context, b []byte, path string) ([]model.Detection, error) {
	results, err := d.scanner.Scan(ctx, b, path)
	if err != nil {
		return nil, err
	}

	dp := d.convert(ctx, results)
	if dp == nil {
		return nil, nil
	}

	return []model.Detection{*dp}, nil
}
