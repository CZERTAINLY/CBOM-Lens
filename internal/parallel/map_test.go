package parallel_test

import (
	"context"
	"errors"
	"iter"
	"testing"
	"testing/synctest"
	"time"

	"github.com/CZERTAINLY/CBOM-lens/internal/parallel"
	"github.com/stretchr/testify/require"
)

func TestMap(t *testing.T) {
	t.Parallel()

	f := func(ctx context.Context, d time.Duration) (int, error) {
		select {
		case <-ctx.Done():
			return int(d), ctx.Err()
		case <-time.After(d):
			return int(d), nil
		}
	}

	input := []time.Duration{1 * time.Second, 2 * time.Second, 5 * time.Second, 10 * time.Second}
	expected := []int{
		int(1 * time.Second),
		int(2 * time.Second),
		int(5 * time.Second),
		int(10 * time.Second),
	}

	tCtx := func(t *testing.T) context.Context {
		t.Helper()
		return t.Context()
	}
	tmout1s := func(t *testing.T) context.Context {
		t.Helper()
		ctx, cancel := context.WithTimeout(t.Context(), 1500*time.Millisecond)
		t.Cleanup(cancel)
		return ctx
	}

	type given struct {
		limit int
		ctx   func(t *testing.T) context.Context
	}
	type then struct {
		d      time.Duration
		values []int
	}
	var testCases = []struct {
		scenario string
		given    given
		then     then
	}{
		{"limit 1", given{1, tCtx}, then{18 * time.Second, expected}},
		{"limit 10", given{10, tCtx}, then{10 * time.Second, expected}},
		{"limit 1, cancel 1.5s", given{1, tmout1s}, then{1500 * time.Millisecond, []int{int(1 * time.Second)}}},
		{"limit 10, cancel 1.5s", given{10, tmout1s}, then{1500 * time.Millisecond, []int{int(1 * time.Second)}}},
	}

	for _, tt := range testCases {
		t.Run(tt.scenario, func(t *testing.T) {
			t.Parallel()
			synctest.Test(t, func(t *testing.T) {
				start := time.Now()
				m1 := parallel.NewMap(tt.given.ctx(t), tt.given.limit, f).Iter(all(input))
				require.ElementsMatch(t, tt.then.values, values(m1))
				require.Equal(t, tt.then.d, time.Since(start))
			})
		})
	}
}

// TestMap_ForwardsInputErrors pins that an error yielded by the input
// sequence reaches the consumer instead of being dropped: a walker reporting
// an unreadable source must not disappear between the walk and the caller.
func TestMap_ForwardsInputErrors(t *testing.T) {
	t.Parallel()

	f := func(_ context.Context, d time.Duration) (int, error) {
		return int(d), nil
	}

	errBroken := errors.New("broken source")
	// one good entry, one error, one good entry
	seq := func(yield func(time.Duration, error) bool) {
		if !yield(1*time.Second, nil) {
			return
		}
		if !yield(0, errBroken) {
			return
		}
		yield(2*time.Second, nil)
	}

	var got []int
	var errs []error
	for d, err := range parallel.NewMap(t.Context(), 2, f).Iter(seq) {
		if err != nil {
			errs = append(errs, err)
			continue
		}
		got = append(got, d)
	}

	require.Len(t, errs, 1)
	require.ErrorIs(t, errs[0], errBroken)
	// the error entry is not mapped, the healthy ones still are
	require.ElementsMatch(t, []int{int(1 * time.Second), int(2 * time.Second)}, got)
}

// TestMap_AbandonedIterWithInputError guards the forwarding send: a consumer
// that stops early must not leave the producer blocked on the channel.
func TestMap_AbandonedIterWithInputError(t *testing.T) {
	t.Parallel()

	f := func(_ context.Context, d time.Duration) (int, error) {
		return int(d), nil
	}

	// an endless stream of errors, so the channel stays full
	seq := func(yield func(time.Duration, error) bool) {
		for {
			if !yield(0, errors.New("broken source")) {
				return
			}
		}
	}

	// break out immediately; the deferred cancel must release the producer
	done := make(chan struct{})
	go func() {
		defer close(done)
		for range parallel.NewMap(t.Context(), 1, f).Iter(seq) {
			break
		}
	}()

	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("Iter did not return after the consumer stopped: the producer is blocked forwarding an error")
	}
}

func all[T any](s []T) iter.Seq2[T, error] {
	return func(yield func(T, error) bool) {
		for _, x := range s {
			if !yield(x, nil) {
				return
			}
		}
	}
}

func values[T any](i iter.Seq2[T, error]) []T {
	var ret []T
	for k := range i {
		ret = append(ret, k)
	}
	return ret
}
