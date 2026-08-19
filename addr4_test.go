package xnetip_test

import (
	"cmp"
	"encoding/binary"
	"math"
	"net/netip"
	"slices"
	"testing"

	"github.com/stretchr/testify/require"
	"pgregory.net/rapid"

	"github.com/yanet-platform/xnetip"
)

// verifies that the byte constructor reads the octets most significant
// first, so the first octet lands in the top byte of the integer.
func Test_IPv4Addr_From4_PinsByteOrder(t *testing.T) {
	require.Equal(t, uint32(0xC0A80001), xnetip.IPv4AddrFrom4([4]byte{192, 168, 0, 1}).Bits())
}

// verifies that the bits constructor writes the top byte of the integer
// into the first octet.
func Test_IPv4Addr_FromBits_PinsByteOrder(t *testing.T) {
	require.Equal(t, [4]byte{10, 0, 0, 1}, xnetip.IPv4AddrFromBits(0x0A000001).As4())
}

// verifies that the zero value is the unspecified address under both
// views and equals the address built from zero inputs.
func Test_IPv4Addr_ZeroValue_IsUnspecified(t *testing.T) {
	var zero xnetip.IPv4Addr
	require.Equal(t, [4]byte{}, zero.As4())
	require.Equal(t, uint32(0), zero.Bits())
	require.Equal(t, xnetip.IPv4AddrFrom4([4]byte{}), zero)
	require.Equal(t, xnetip.IPv4AddrFromBits(0), zero)
}

// verifies that the all-ones address maps to the largest 32-bit integer.
func Test_IPv4Addr_AllOnes_IsMaxUint32(t *testing.T) {
	require.Equal(t, uint32(math.MaxUint32), xnetip.IPv4AddrFrom4([4]byte{255, 255, 255, 255}).Bits())
}

// verifies that the == operator itself compares addresses by bit pattern,
// whichever constructor built them.
func Test_IPv4Addr_Equality_IsStructural(t *testing.T) {
	address := xnetip.IPv4AddrFromBits(1)
	sameBits := address == xnetip.IPv4AddrFrom4([4]byte{0, 0, 0, 1})
	otherBits := address == xnetip.IPv4AddrFromBits(2)
	require.True(t, sameBits)
	require.False(t, otherBits)
}

// verifies that the type is usable as a map key, with distinct addresses
// occupying distinct entries and equal ones sharing an entry.
func Test_IPv4Addr_MapKey_DistinguishesAddresses(t *testing.T) {
	seen := map[xnetip.IPv4Addr]int{}
	seen[xnetip.IPv4AddrFrom4([4]byte{10, 0, 0, 1})]++
	seen[xnetip.IPv4AddrFrom4([4]byte{10, 0, 0, 2})]++
	seen[xnetip.IPv4AddrFromBits(0x0A000001)]++
	require.Len(t, seen, 2)
	require.Equal(t, 2, seen[xnetip.IPv4AddrFrom4([4]byte{10, 0, 0, 1})])
}

// verifies that the byte view round-trips every 4-byte input.
func Test_IPv4Addr_From4_RoundTrips(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		octets := [4]byte(rapid.SliceOfN(rapid.Byte(), 4, 4).Draw(t, "octets"))
		require.Equal(t, octets, xnetip.IPv4AddrFrom4(octets).As4())
	})
}

// verifies that the integer view round-trips every 32-bit input.
func Test_IPv4Addr_FromBits_RoundTrips(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		bits := rapid.Uint32().Draw(t, "bits")
		require.Equal(t, bits, xnetip.IPv4AddrFromBits(bits).Bits())
	})
}

// verifies that the two views agree through big-endian encoding in both
// directions: octets to integer and integer to octets.
func Test_IPv4Addr_Views_AgreeWithBigEndian(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		octets := [4]byte(rapid.SliceOfN(rapid.Byte(), 4, 4).Draw(t, "octets"))
		require.Equal(t, binary.BigEndian.Uint32(octets[:]), xnetip.IPv4AddrFrom4(octets).Bits())
		address := genIPv4Addr.Draw(t, "address")
		require.Equal(t, [4]byte(binary.BigEndian.AppendUint32(nil, address.Bits())), address.As4())
	})
}

// verifies that the byte view agrees with net/netip for every 4-byte
// input, pinning the byte-order convention against the standard library.
func Test_IPv4Addr_From4_MatchesNetip(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		octets := [4]byte(rapid.SliceOfN(rapid.Byte(), 4, 4).Draw(t, "octets"))
		require.Equal(t, netip.AddrFrom4(octets).As4(), xnetip.IPv4AddrFrom4(octets).As4())
	})
}

// verifies that construction and the accessors do not allocate.
func Test_IPv4Addr_Construction_DoesNotAllocate(t *testing.T) {
	octets := [4]byte{192, 168, 0, 1}
	requireNoAllocs(t, func() {
		address := xnetip.IPv4AddrFrom4(octets)
		wordSink = xnetip.IPv4AddrFromBits(address.Bits()).Bits()
		octets = address.As4()
	})
}

// verifies that compare is the numeric order of the 32-bit pattern.
//
// The first octet dominates, lower octets break ties, the top bit is not
// a sign bit, and swapping the operands mirrors the sign.
func Test_IPv4Addr_Compare_OrdersNumerically(t *testing.T) {
	cases := []struct {
		name        string
		left, right [4]byte
		want        int
	}{
		{name: "equal addresses compare 0", left: [4]byte{10, 0, 0, 1}, right: [4]byte{10, 0, 0, 1}, want: 0},
		{name: "lower octet chain sorts first", left: [4]byte{192, 168, 0, 1}, right: [4]byte{192, 168, 1, 0}, want: -1},
		{name: "first octet dominates", left: [4]byte{9, 255, 255, 255}, right: [4]byte{10, 0, 0, 0}, want: -1},
		{name: "minimum sorts before maximum", left: [4]byte{0, 0, 0, 0}, right: [4]byte{255, 255, 255, 255}, want: -1},
		{name: "high-bit addresses are not negative", left: [4]byte{127, 255, 255, 255}, right: [4]byte{128, 0, 0, 0}, want: -1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			left, right := xnetip.IPv4AddrFrom4(tc.left), xnetip.IPv4AddrFrom4(tc.right)
			require.Equal(t, tc.want, left.Compare(right))
			require.Equal(t, -tc.want, right.Compare(left))
		})
	}
}

// verifies that the method expression is a comparator the standard sort
// accepts and that it yields ascending numeric order.
func Test_IPv4Addr_Compare_SortsWithSliceSortFunc(t *testing.T) {
	addrs := []xnetip.IPv4Addr{
		xnetip.IPv4AddrFrom4([4]byte{255, 0, 0, 0}),
		xnetip.IPv4AddrFrom4([4]byte{0, 0, 0, 1}),
		xnetip.IPv4AddrFrom4([4]byte{10, 0, 0, 0}),
	}
	slices.SortFunc(addrs, xnetip.IPv4Addr.Compare)
	require.Equal(t, []xnetip.IPv4Addr{
		xnetip.IPv4AddrFrom4([4]byte{0, 0, 0, 1}),
		xnetip.IPv4AddrFrom4([4]byte{10, 0, 0, 0}),
		xnetip.IPv4AddrFrom4([4]byte{255, 0, 0, 0}),
	}, addrs)
}

// verifies that compare is antisymmetric and that every address compares
// equal to itself.
func Test_IPv4Addr_Compare_AntisymmetricAndReflexive(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		left := genIPv4Addr.Draw(t, "left")
		right := genIPv4Addr.Draw(t, "right")
		require.Equal(t, -right.Compare(left), left.Compare(right))
		require.Equal(t, 0, left.Compare(left))
	})
}

// verifies that compare is transitive: once three addresses are sorted by
// it, the first also sorts no later than the last.
func Test_IPv4Addr_Compare_Transitive(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		addrs := []xnetip.IPv4Addr{
			genIPv4Addr.Draw(t, "first"),
			genIPv4Addr.Draw(t, "second"),
			genIPv4Addr.Draw(t, "third"),
		}
		slices.SortFunc(addrs, xnetip.IPv4Addr.Compare)
		require.LessOrEqual(t, addrs[0].Compare(addrs[1]), 0)
		require.LessOrEqual(t, addrs[1].Compare(addrs[2]), 0)
		require.LessOrEqual(t, addrs[0].Compare(addrs[2]), 0)
	})
}

// verifies that compare reports 0 exactly when the two addresses are equal
// under ==, so order and structural equality never disagree.
func Test_IPv4Addr_Compare_ZeroIffEqual(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		left := genIPv4Addr.Draw(t, "left")
		right := genIPv4Addr.Draw(t, "right")
		if rapid.Bool().Draw(t, "same") {
			right = left
		}
		require.Equal(t, left == right, left.Compare(right) == 0)
	})
}

// verifies that compare is the numeric order of the integer view, the
// contract the network order and the slice algorithms build on.
func Test_IPv4Addr_Compare_IsNumericOrderOfBits(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		left := genIPv4Addr.Draw(t, "left")
		right := genIPv4Addr.Draw(t, "right")
		require.Equal(t, cmp.Compare(left.Bits(), right.Bits()), left.Compare(right))
	})
}

// verifies that compare agrees with net/netip on every pair of IPv4
// addresses, pinning the order against the standard library.
func Test_IPv4Addr_Compare_MatchesNetip(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		left := genIPv4Addr.Draw(t, "left")
		right := genIPv4Addr.Draw(t, "right")
		want := netip.AddrFrom4(left.As4()).Compare(netip.AddrFrom4(right.As4()))
		require.Equal(t, want, left.Compare(right))
	})
}

// verifies that compare does not allocate.
func Test_IPv4Addr_Compare_DoesNotAllocate(t *testing.T) {
	left := xnetip.IPv4AddrFrom4([4]byte{192, 168, 0, 1})
	right := xnetip.IPv4AddrFrom4([4]byte{192, 168, 1, 0})
	requireNoAllocs(t, func() { intSink = left.Compare(right) })
}

func BenchmarkIPv4Addr_Compare(b *testing.B) {
	fixture := benchIPv4Addrs(2)
	left, right := fixture[0], fixture[1]
	b.ReportAllocs()
	for b.Loop() {
		intSink = left.Compare(right)
	}
}

// Sorts a fresh copy of the fixture on every iteration, the refresh
// included in the timed region.
//
// A 4 KiB copy is well under one percent of the sort, and pausing the
// timer inside a b.Loop body keeps the loop from ever reaching its
// benchtime on Go 1.24.
func BenchmarkIPv4Addr_SortFunc_1024(b *testing.B) {
	fixture := benchIPv4Addrs(1024)
	scratch := make([]xnetip.IPv4Addr, len(fixture))
	b.ReportAllocs()
	for b.Loop() {
		copy(scratch, fixture)
		slices.SortFunc(scratch, xnetip.IPv4Addr.Compare)
	}
}

// benchIPv4Addrs returns count addresses in a fixed, unsorted "random-ish"
// order, the same fixture on every run.
//
// Each address is its index multiplied by Knuth's multiplicative hash
// constant, the recipe of the Rust crate's sort benchmark
// (../netip/benches/net.rs:2293), so the two sort benchmarks see the same
// input shape.
func benchIPv4Addrs(count int) []xnetip.IPv4Addr {
	addrs := make([]xnetip.IPv4Addr, count)
	for idx := range addrs {
		addrs[idx] = xnetip.IPv4AddrFromBits(uint32(idx) * 2_654_435_761)
	}
	return addrs
}
