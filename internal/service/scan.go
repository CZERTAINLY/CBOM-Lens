package service

import (
	"context"
	"errors"
	"fmt"
	"iter"
	"log/slog"
	"sync"
	"sync/atomic"

	"github.com/CZERTAINLY/CBOM-lens/internal/log"
	"github.com/CZERTAINLY/CBOM-lens/internal/model"
	"github.com/CZERTAINLY/CBOM-lens/internal/parallel"
	"github.com/CZERTAINLY/CBOM-lens/internal/stats"
)

// Detector provides content analysis for a single file.
// Detect receives the file content (b) and its path, returning any detections found.
// ctx may be used to cancel long-running work.
// It returns a slice of model.Detection (possibly empty) or an error.
// Implementations should avoid modifying b and be concurrency-safe if used in parallel.
type Detector interface {
	// Detect analyzes the provided file content.
	//
	// Parameters:
	//   ctx  - cancellation / deadline context; implementations must honor ctx.Done().
	//   b    - complete file contents (immutable; do not modify).
	//   path - logical or filesystem path to the content; treat only as a string
	//          for allow/ignore pattern evaluation (avoid parsing or resolving).
	//
	// Returns:
	//   []model.Detection - zero or more findings (empty slice if none; may be nil if implementations choose).
	//   error             - non-nil if the analysis failed; return partial results only if clearly documented.
	//
	// Concurrency:
	//   Implementations should be safe for concurrent use (no shared mutable state without synchronization).
	//
	// Side effects:
	//   Must not mutate input b, and should avoid I/O other than what is required for analysis.
	Detect(ctx context.Context, b []byte, path string) ([]model.Detection, error)
}

type Scan struct {
	limit             int
	skipIfBigger      int64
	detectors         []Detector
	counter           *stats.Stats
	pool              sync.Pool
	poolNewCounter    atomic.Int32
	poolPutCounter    atomic.Int32
	poolPutErrCounter atomic.Int32
}

type Stats struct {
	PoolNewCounter    int
	PoolPutCounter    int
	PoolPutErrCounter int
}

func New(limit int, counter *stats.Stats, detectors []Detector) *Scan {
	const skipIfBigger = 10 * 1024 * 1024
	s := &Scan{
		counter:      counter,
		limit:        limit,
		skipIfBigger: skipIfBigger,
		detectors:    detectors,
	}
	s.pool = sync.Pool{
		New: func() any {
			s.poolNewCounter.Add(1)
			b := make([]byte, skipIfBigger)
			return &b
		},
	}
	return s
}

// Do reads the content of the seq iterator and runs scanning on the entries
// 1. If entry has a stat error, it's ignored
// 2. If is bigger than 10MB, it's ignored and ErrTooBig is returned
// 3. Otherwise the data are passed to the worker pool for running a detections
// 4. Returns an iterator with a detections or Open/Read error or a ErrNoMatch if not match is found
func (s *Scan) Do(parentCtx context.Context, seq iter.Seq2[model.Entry, error]) iter.Seq2[[]model.Detection, error] {
	return parallel.NewMap(parentCtx, s.limit, s.scan).Iter(seq)
}

func (s *Scan) scan(ctx context.Context, entry model.Entry) ([]model.Detection, error) {
	ctx = log.ContextAttrs(ctx, slog.String("path", entry.Path()))
	slog.DebugContext(ctx, "scanning")
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	info, err := entry.Stat()
	if err != nil {
		s.counter.IncErrFiles()
		return nil, fmt.Errorf("scan Stat: %w", err)
	}
	if info.Size() > s.skipIfBigger {
		slog.DebugContext(ctx, "excluded too big", "path", entry.Path(), "size", info.Size())
		s.counter.IncExcludedFiles()
		return nil, fmt.Errorf("entry too big (%d bytes): %w", info.Size(), model.ErrTooBig)
	}

	f, err := entry.Open()
	if err != nil {
		s.counter.IncErrFiles()
		return nil, fmt.Errorf("scan Open: %w", err)
	}
	defer func() {
		_ = f.Close() // ignoring close error for CLI tool
	}()

	bp := s.pool.Get().(*[]byte)
	buf := *bp
	clear(buf)
	n, err := f.Read(buf)
	if err != nil {
		s.counter.IncErrFiles()
		s.poolPutErrCounter.Add(1)
		s.pool.Put(bp)
		return nil, fmt.Errorf("scan ReadAll: %w", err)
	}
	defer func() {
		s.poolPutCounter.Add(1)
		s.pool.Put(bp)
	}()
	// IMPORTANT: data must be passed as buf[:n] otherwise data from a previous
	// file will be passed in
	buf = buf[:n]

	var detectionErrors []error
	res := make([]model.Detection, 0, 10)
	for _, detector := range s.detectors {
		var detectCtx = ctx
		if ld, ok := detector.(interface{ LogAttrs() []slog.Attr }); ok {
			detectCtx = log.ContextAttrs(ctx, ld.LogAttrs()...)
		}
		d, err := detector.Detect(detectCtx, buf, entry.Path())

		switch {
		case err == nil:
			res = append(res, d...)
			// file was detected, so no point in trying other detectors
			if len(d) > 0 {
				goto detectionEnd
			}
		case errors.Is(err, model.ErrNoMatch):
			// ignore ErrNoMatch
		default:
			detectionErrors = append(detectionErrors, err)
		}
	}

detectionEnd:

	if len(res) == 0 {
		return nil, nil
	} else if len(detectionErrors) > 0 {
		return nil, errors.Join(detectionErrors...)
	}

	return res, nil
}

func (s *Scan) Stats() Stats {
	return Stats{
		PoolNewCounter:    int(s.poolNewCounter.Load()),
		PoolPutCounter:    int(s.poolPutCounter.Load()),
		PoolPutErrCounter: int(s.poolPutErrCounter.Load()),
	}
}
