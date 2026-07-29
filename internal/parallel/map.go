package parallel

import (
	"context"
	"iter"

	"golang.org/x/sync/errgroup"
)

type result[D any] struct {
	d D
	e error
}

// Map is a parallel mapping function, which can run the mapFuncs in a parallel and wait for
// completions. The input and output are represented as iterators, so the typical usage is.
// Map is context aware, so canceled context ends the processing.
//
//	for result, err := range pmap.Iter(input) {}
type Map[E, D any] struct {
	parentCtx    context.Context
	cancelParent context.CancelFunc
	g            *errgroup.Group
	gctx         context.Context
	mapped       chan result[D]
	mapFunc      func(context.Context, E) (D, error)
}

func NewMap[E, D any](parentCtx context.Context, limit int, mapFunc func(context.Context, E) (D, error)) *Map[E, D] {
	parentCtx, cancelParent := context.WithCancel(parentCtx)
	g, gctx := errgroup.WithContext(parentCtx)
	g.SetLimit(limit + 1)

	detects := make(chan result[D], limit)

	return &Map[E, D]{
		parentCtx:    parentCtx,
		cancelParent: cancelParent,
		g:            g,
		gctx:         gctx,
		mapped:       detects,
		mapFunc:      mapFunc,
	}
}

func (s *Map[E, D]) goWorkers(seq iter.Seq2[E, error]) {
	s.g.Go(func() error {
		for entry, nerr := range seq {
			if nerr != nil {
				// There is nothing to map, but the error must not be
				// dropped: it is how a walker reports a source or an
				// entry it could not read. The send is guarded like the
				// one below, otherwise a consumer abandoning the
				// iterator would leave this goroutine blocked forever.
				select {
				case <-s.gctx.Done():
					return s.gctx.Err()
				case s.mapped <- result[D]{e: nerr}:
				}
				continue
			}
			s.g.Go(func() error {
				d, scanErr := s.mapFunc(s.gctx, entry)
				select {
				case <-s.gctx.Done():
					return s.gctx.Err()
				default:
					s.mapped <- result[D]{d: d, e: scanErr}
				}
				return nil
			})
		}
		return nil
	})
}

func (s *Map[E, D]) Iter(seq iter.Seq2[E, error]) iter.Seq2[D, error] {
	return func(yield func(D, error) bool) {
		defer s.cancelParent()
		s.goWorkers(seq)

		go func() {
			_ = s.g.Wait()
			close(s.mapped)
		}()

		for r := range s.mapped {
			if s.parentCtx.Err() != nil {
				return
			}
			if !yield(r.d, r.e) {
				return
			}
		}
	}
}
