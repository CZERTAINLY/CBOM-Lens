package bom

import (
	"fmt"
	"slices"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestPermutations_YieldsEveryOrderingExactlyOnce pins the generator that
// decides how much TestGolden_OneRSAKeyIsOneAlgorithmAssetInEveryArrivalOrder
// actually covers.
//
// That test's strength is entirely a function of this helper. Its own comment
// names the risk -- "a generator that quietly produced fewer would weaken the
// assertion above without failing anything" -- and then nothing checks it. A
// permutations() that returned only the identity ordering would leave the whole
// arrival-order suite green while asserting that one document equals itself,
// and the half-fix it exists to catch (Converter.PrivateKey stamping no
// primitive) would sail through.
//
// The three assertions are separately falsifiable. The count catches a generator
// that stops early -- Heap's algorithm loses whole subtrees to an off-by-one in
// its swap parity, and does so silently. The set membership catches one that
// corrupts the working slice, which Heap's in-place swapping makes possible and
// which would produce n! orderings that are not permutations. The distinctness
// catches one that emits the same ordering repeatedly, which is what a missing
// slices.Clone would do: every appended row would alias one backing array and
// the caller would test the last ordering n! times.
//
// n runs to 5 rather than stopping at the 4 the caller uses, because the swap
// parity that Heap's algorithm turns on differs between even and odd k, and 4
// alone exercises only one arm of the recursion's top level.
func TestPermutations_YieldsEveryOrderingExactlyOnce(t *testing.T) {
	t.Parallel()

	factorial := func(n int) int {
		f := 1
		for i := 2; i <= n; i++ {
			f *= i
		}
		return f
	}

	for n := 1; n <= 5; n++ {
		t.Run(fmt.Sprintf("n=%d", n), func(t *testing.T) {
			t.Parallel()

			want := make([]int, n)
			for i := range want {
				want[i] = i
			}

			got := permutations(n)
			require.Len(t, got, factorial(n),
				"every ordering of %d detections, and %d is what makes an "+
					"arrival-order-sensitive union impossible to hide", n, factorial(n))

			seen := make(map[string]struct{}, len(got))
			for _, order := range got {
				sorted := slices.Clone(order)
				slices.Sort(sorted)
				require.Equal(t, want, sorted,
					"%v is not a permutation of 0..%d", order, n-1)

				key := fmt.Sprint(order)
				_, dup := seen[key]
				require.False(t, dup,
					"%v was produced twice, so the coverage is smaller than the count", order)
				seen[key] = struct{}{}
			}
		})
	}

	t.Run("the caller's fixture size is the one that matters", func(t *testing.T) {
		t.Parallel()

		// Stated here so that shrinking the golden fixture to a pair -- which
		// cannot distinguish a set from last-wins, nor either from a stable but
		// arrival-ordered accumulator -- has to be a deliberate edit to a
		// number with a reason attached, not a quiet one.
		require.Len(t, permutations(4), 24,
			"four detections describing one RSA key, in all 24 arrival orders")
	})
}
