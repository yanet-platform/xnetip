package xnetip_test

import (
	"bytes"
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
// first, the first eight into the high half and the last eight into the low.
func Test_IPv6Addr_From16_PinsByteOrderAndHalfSplit(t *testing.T) {
	octets := [16]byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}
	hi, lo := xnetip.IPv6AddrFrom16(octets).Bits()
	require.Equal(t, uint64(0x20010db800000000), hi)
	require.Equal(t, uint64(1), lo)
}

// verifies that the halves constructor writes the high half into the first
// eight octets and the low half into the last eight, top byte first.
func Test_IPv6Addr_FromBits_PinsByteOrder(t *testing.T) {
	octets := [16]byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}
	require.Equal(t, octets, xnetip.IPv6AddrFromBits(0x20010db800000000, 1).As16())
}

// verifies that the group constructor builds the same address as the
// byte constructor fed the groups serialized big-endian in order.
func Test_IPv6Addr_From8_MatchesFrom16(t *testing.T) {
	octets := [16]byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}
	require.Equal(t, xnetip.IPv6AddrFrom16(octets), xnetip.IPv6AddrFrom8(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1))
}

// verifies that the half boundary falls between the fourth and the fifth
// group: the fourth ends the high half and the fifth opens the low half.
func Test_IPv6Addr_From8_SplitsHalvesBetweenFourthAndFifthGroup(t *testing.T) {
	hi, lo := xnetip.IPv6AddrFrom8(0, 0, 0, 1, 0x8000, 0, 0, 0).Bits()
	require.Equal(t, uint64(1), hi)
	require.Equal(t, uint64(0x8000000000000000), lo)
}

// verifies that the zero value is the unspecified address under both
// views and equals the address every constructor builds from zero inputs.
func Test_IPv6Addr_ZeroValue_IsUnspecified(t *testing.T) {
	var zero xnetip.IPv6Addr
	hi, lo := zero.Bits()
	require.Equal(t, [16]byte{}, zero.As16())
	require.Equal(t, uint64(0), hi)
	require.Equal(t, uint64(0), lo)
	require.Equal(t, xnetip.IPv6AddrFrom16([16]byte{}), zero)
	require.Equal(t, xnetip.IPv6AddrFromBits(0, 0), zero)
	require.Equal(t, xnetip.IPv6AddrFrom8(0, 0, 0, 0, 0, 0, 0, 0), zero)
}

// verifies that the all-ones address fills both halves with the largest
// 64-bit integer.
func Test_IPv6Addr_AllOnes_IsMaxUint64Pair(t *testing.T) {
	hi, lo := xnetip.IPv6AddrFrom8(0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff).Bits()
	require.Equal(t, uint64(math.MaxUint64), hi)
	require.Equal(t, uint64(math.MaxUint64), lo)
}

// verifies that an IPv4-mapped address is an ordinary 128-bit value with
// an empty high half and the mapped prefix in bits 32 through 47 of the low.
func Test_IPv6Addr_IPv4Mapped_IsPlainValue(t *testing.T) {
	hi, lo := xnetip.IPv6AddrFrom8(0, 0, 0, 0, 0, 0xffff, 0x0102, 0x0304).Bits()
	require.Equal(t, uint64(0), hi)
	require.Equal(t, uint64(0x0000ffff01020304), lo)
}

// verifies that the == operator itself compares addresses by bit pattern,
// whichever constructor built them.
func Test_IPv6Addr_Equality_IsStructural(t *testing.T) {
	address := xnetip.IPv6AddrFromBits(0, 1)
	sameBits := address == xnetip.IPv6AddrFrom8(0, 0, 0, 0, 0, 0, 0, 1)
	otherBits := address == xnetip.IPv6AddrFromBits(1, 0)
	require.True(t, sameBits)
	require.False(t, otherBits)
}

// verifies that the type is usable as a map key, with distinct addresses
// occupying distinct entries and equal ones sharing an entry.
func Test_IPv6Addr_MapKey_DistinguishesAddresses(t *testing.T) {
	seen := map[xnetip.IPv6Addr]int{}
	seen[xnetip.IPv6AddrFrom8(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)]++
	seen[xnetip.IPv6AddrFrom8(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2)]++
	seen[xnetip.IPv6AddrFromBits(0x20010db800000000, 1)]++
	require.Len(t, seen, 2)
	require.Equal(t, 2, seen[xnetip.IPv6AddrFrom8(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)])
}

// verifies that the byte view round-trips every 16-byte input.
func Test_IPv6Addr_From16_RoundTrips(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		octets := [16]byte(rapid.SliceOfN(rapid.Byte(), 16, 16).Draw(t, "octets"))
		require.Equal(t, octets, xnetip.IPv6AddrFrom16(octets).As16())
	})
}

// verifies that the halves view round-trips every pair of 64-bit inputs.
func Test_IPv6Addr_FromBits_RoundTrips(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		hi := rapid.Uint64().Draw(t, "hi")
		lo := rapid.Uint64().Draw(t, "lo")
		gotHi, gotLo := xnetip.IPv6AddrFromBits(hi, lo).Bits()
		require.Equal(t, hi, gotHi)
		require.Equal(t, lo, gotLo)
	})
}

// verifies that the two views agree through big-endian encoding in both
// directions: octets to halves and halves to octets.
func Test_IPv6Addr_Views_AgreeWithBigEndian(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		octets := [16]byte(rapid.SliceOfN(rapid.Byte(), 16, 16).Draw(t, "octets"))
		hi, lo := xnetip.IPv6AddrFrom16(octets).Bits()
		require.Equal(t, binary.BigEndian.Uint64(octets[:8]), hi)
		require.Equal(t, binary.BigEndian.Uint64(octets[8:]), lo)
		address := genIPv6Addr.Draw(t, "address")
		hi, lo = address.Bits()
		encoded := binary.BigEndian.AppendUint64(binary.BigEndian.AppendUint64(nil, hi), lo)
		require.Equal(t, [16]byte(encoded), address.As16())
	})
}

// verifies that the group constructor agrees with the byte constructor
// for every choice of eight groups, each group serialized big-endian.
func Test_IPv6Addr_From8_MatchesBigEndianGroups(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		groups := rapid.SliceOfN(rapid.Uint16(), 8, 8).Draw(t, "groups")
		var octets [16]byte
		for idx, group := range groups {
			binary.BigEndian.PutUint16(octets[2*idx:], group)
		}
		fromGroups := xnetip.IPv6AddrFrom8(
			groups[0], groups[1], groups[2], groups[3],
			groups[4], groups[5], groups[6], groups[7],
		)
		require.Equal(t, xnetip.IPv6AddrFrom16(octets), fromGroups)
	})
}

// verifies that the byte view agrees with net/netip for every 16-byte
// input, pinning the byte-order convention against the standard library.
func Test_IPv6Addr_From16_MatchesNetip(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		octets := [16]byte(rapid.SliceOfN(rapid.Byte(), 16, 16).Draw(t, "octets"))
		require.Equal(t, netip.AddrFrom16(octets).As16(), xnetip.IPv6AddrFrom16(octets).As16())
	})
}

// verifies that construction and the accessors do not allocate.
func Test_IPv6Addr_Construction_DoesNotAllocate(t *testing.T) {
	octets := [16]byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}
	var hi, lo uint64
	requireNoAllocs(t, func() {
		hi, lo = xnetip.IPv6AddrFrom16(octets).Bits()
		octets = xnetip.IPv6AddrFrom8(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1).As16()
		wordSink = uint32(xnetip.IPv6AddrFromBits(hi, lo).As16()[15])
	})
}

// verifies that compare is the numeric order of the 128-bit pattern.
//
// The high half is compared first and the low half only breaks its ties,
// the top bit is not a sign bit, an all-ones low half still sorts below
// the next high half, and swapping the operands mirrors the sign.
func Test_IPv6Addr_Compare_OrdersNumerically(t *testing.T) {
	cases := []struct {
		name        string
		left, right xnetip.IPv6Addr
		want        int
	}{
		{
			name:  "equal addresses compare 0",
			left:  xnetip.IPv6AddrFrom8(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1),
			right: xnetip.IPv6AddrFrom8(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1),
			want:  0,
		},
		{
			name:  "low half decides when high halves tie",
			left:  xnetip.IPv6AddrFrom8(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1),
			right: xnetip.IPv6AddrFrom8(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2),
			want:  -1,
		},
		{
			name:  "high half dominates the low half",
			left:  xnetip.IPv6AddrFrom8(0x2001, 0xdb8, 0, 0, 0xffff, 0xffff, 0xffff, 0xffff),
			right: xnetip.IPv6AddrFrom8(0x2001, 0xdb9, 0, 0, 0, 0, 0, 0),
			want:  -1,
		},
		{
			name:  "minimum sorts before maximum",
			left:  xnetip.IPv6AddrFrom8(0, 0, 0, 0, 0, 0, 0, 0),
			right: xnetip.IPv6AddrFrom8(0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff),
			want:  -1,
		},
		{
			name:  "high-bit addresses are not negative",
			left:  xnetip.IPv6AddrFrom8(0x7fff, 0, 0, 0, 0, 0, 0, 0),
			right: xnetip.IPv6AddrFrom8(0x8000, 0, 0, 0, 0, 0, 0, 0),
			want:  -1,
		},
		{
			name:  "all-ones low half sorts below the next high half",
			left:  xnetip.IPv6AddrFrom8(0, 0, 0, 0, 0xffff, 0xffff, 0xffff, 0xffff),
			right: xnetip.IPv6AddrFrom8(0, 0, 0, 1, 0, 0, 0, 0),
			want:  -1,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.want, tc.left.Compare(tc.right))
			require.Equal(t, -tc.want, tc.right.Compare(tc.left))
		})
	}
}

// verifies that IPv4-mapped addresses sort among the other addresses by
// their full 128-bit value, with no special casing.
//
// The mapped block sits right above ::fffe:ffff:ffff and right below
// ::1:0:0:0, the same place core::net and netip's 16-byte form give it.
func Test_IPv6Addr_Compare_MappedSortsByFullValue(t *testing.T) {
	chain := []xnetip.IPv6Addr{
		xnetip.IPv6AddrFrom8(0, 0, 0, 0, 0, 0xfffe, 0xffff, 0xffff),
		xnetip.IPv6AddrFrom8(0, 0, 0, 0, 0, 0xffff, 0, 0),
		xnetip.IPv6AddrFrom8(0, 0, 0, 0, 0, 0xffff, 0xffff, 0xffff),
		xnetip.IPv6AddrFrom8(0, 0, 0, 0, 1, 0, 0, 0),
	}
	for idx := range len(chain) - 1 {
		require.Equal(t, -1, chain[idx].Compare(chain[idx+1]), "link %d", idx)
	}
}

// verifies that the method expression is a comparator the standard sort
// accepts and that it yields ascending numeric order.
func Test_IPv6Addr_Compare_SortsWithSliceSortFunc(t *testing.T) {
	addrs := []xnetip.IPv6Addr{
		xnetip.IPv6AddrFrom8(0xff00, 0, 0, 0, 0, 0, 0, 0),
		xnetip.IPv6AddrFrom8(0, 0, 0, 0, 0, 0, 0, 1),
		xnetip.IPv6AddrFrom8(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0),
	}
	slices.SortFunc(addrs, xnetip.IPv6Addr.Compare)
	require.Equal(t, []xnetip.IPv6Addr{
		xnetip.IPv6AddrFrom8(0, 0, 0, 0, 0, 0, 0, 1),
		xnetip.IPv6AddrFrom8(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0),
		xnetip.IPv6AddrFrom8(0xff00, 0, 0, 0, 0, 0, 0, 0),
	}, addrs)
}

// verifies that compare is antisymmetric and that every address compares
// equal to itself.
func Test_IPv6Addr_Compare_AntisymmetricAndReflexive(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		left := genIPv6Addr.Draw(t, "left")
		right := genIPv6Addr.Draw(t, "right")
		require.Equal(t, -right.Compare(left), left.Compare(right))
		require.Equal(t, 0, left.Compare(left))
	})
}

// verifies that compare is transitive: once three addresses are sorted by
// it, the first also sorts no later than the last.
func Test_IPv6Addr_Compare_Transitive(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		addrs := []xnetip.IPv6Addr{
			genIPv6Addr.Draw(t, "first"),
			genIPv6Addr.Draw(t, "second"),
			genIPv6Addr.Draw(t, "third"),
		}
		slices.SortFunc(addrs, xnetip.IPv6Addr.Compare)
		require.LessOrEqual(t, addrs[0].Compare(addrs[1]), 0)
		require.LessOrEqual(t, addrs[1].Compare(addrs[2]), 0)
		require.LessOrEqual(t, addrs[0].Compare(addrs[2]), 0)
	})
}

// verifies that compare reports 0 exactly when the two addresses are equal
// under ==, so order and structural equality never disagree.
func Test_IPv6Addr_Compare_ZeroIffEqual(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		left := genIPv6Addr.Draw(t, "left")
		right := genIPv6Addr.Draw(t, "right")
		if rapid.Bool().Draw(t, "same") {
			right = left
		}
		require.Equal(t, left == right, left.Compare(right) == 0)
	})
}

// verifies that compare is the numeric order of the halves view, high
// half first and low half on a tie.
//
// This is the contract the network order and the slice algorithms build
// on. Half of the pairs share the high half on purpose, so the tie-break
// runs as often as the high-half decision.
func Test_IPv6Addr_Compare_IsNumericOrderOfHalves(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		left := genIPv6Addr.Draw(t, "left")
		right := genIPv6Addr.Draw(t, "right")
		if rapid.Bool().Draw(t, "shareHigh") {
			hi, _ := left.Bits()
			_, lo := right.Bits()
			right = xnetip.IPv6AddrFromBits(hi, lo)
		}
		leftHi, leftLo := left.Bits()
		rightHi, rightLo := right.Bits()
		want := cmp.Or(cmp.Compare(leftHi, rightHi), cmp.Compare(leftLo, rightLo))
		require.Equal(t, want, left.Compare(right))
	})
}

// verifies that compare agrees with the lexicographic order of the
// network-order bytes.
//
// This is the fact that lets the numeric order stand in for the
// group-by-group order of the textual form (../netip/src/net.rs:3726).
func Test_IPv6Addr_Compare_IsBigEndianByteOrder(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		left := genIPv6Addr.Draw(t, "left")
		right := genIPv6Addr.Draw(t, "right")
		if rapid.Bool().Draw(t, "shareHigh") {
			hi, _ := left.Bits()
			_, lo := right.Bits()
			right = xnetip.IPv6AddrFromBits(hi, lo)
		}
		leftBytes, rightBytes := left.As16(), right.As16()
		require.Equal(t, bytes.Compare(leftBytes[:], rightBytes[:]), left.Compare(right))
	})
}

// verifies that compare agrees with net/netip on every pair of IPv6
// addresses, pinning the order against the standard library.
func Test_IPv6Addr_Compare_MatchesNetip(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		left := genIPv6Addr.Draw(t, "left")
		right := genIPv6Addr.Draw(t, "right")
		if rapid.Bool().Draw(t, "shareHigh") {
			hi, _ := left.Bits()
			_, lo := right.Bits()
			right = xnetip.IPv6AddrFromBits(hi, lo)
		}
		want := netip.AddrFrom16(left.As16()).Compare(netip.AddrFrom16(right.As16()))
		require.Equal(t, want, left.Compare(right))
	})
}

// verifies that compare does not allocate.
func Test_IPv6Addr_Compare_DoesNotAllocate(t *testing.T) {
	left := xnetip.IPv6AddrFrom8(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)
	right := xnetip.IPv6AddrFrom8(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2)
	requireNoAllocs(t, func() { intSink = left.Compare(right) })
}

func BenchmarkIPv6Addr_Compare(b *testing.B) {
	fixture := benchIPv6Addrs(1024)
	left, right := fixture[1], fixture[1023]
	b.ReportAllocs()
	for b.Loop() {
		intSink = left.Compare(right)
	}
}

// Equal high halves push the decision into the low half, the branchy
// path of the two-word compare.
func BenchmarkIPv6Addr_Compare_EqualHighHalves(b *testing.B) {
	left := benchIPv6Addrs(1024)[1023]
	hi, lo := left.Bits()
	right := xnetip.IPv6AddrFromBits(hi, lo^1)
	b.ReportAllocs()
	for b.Loop() {
		intSink = left.Compare(right)
	}
}

// Sorts a fresh copy of the fixture on every iteration, the refresh
// included in the timed region.
//
// A 16 KiB copy is well under one percent of the sort, and pausing the
// timer inside a b.Loop body keeps the loop from ever reaching its
// benchtime on Go 1.24.
func BenchmarkIPv6Addr_SortFunc_1024(b *testing.B) {
	fixture := benchIPv6Addrs(1024)
	scratch := make([]xnetip.IPv6Addr, len(fixture))
	b.ReportAllocs()
	for b.Loop() {
		copy(scratch, fixture)
		slices.SortFunc(scratch, xnetip.IPv6Addr.Compare)
	}
}

// benchIPv6Addrs returns count addresses in a fixed, unsorted "random-ish"
// order, the same fixture on every run.
//
// Each address is its index multiplied by Knuth's 64-bit multiplicative
// hash constant, wrapping, in the high half and zero in the low half: the
// high-half-only shape of the Rust crate's IPv6 sort benchmark
// (../netip/benches/net.rs:2320) scrambled the way the IPv4 fixture is.
// The full 128-bit product the Rust bench takes its groups from is not
// used, because its high half grows monotonically with the index and
// would hand the sort a nearly sorted input.
func benchIPv6Addrs(count int) []xnetip.IPv6Addr {
	addrs := make([]xnetip.IPv6Addr, count)
	for idx := range addrs {
		addrs[idx] = xnetip.IPv6AddrFromBits(uint64(idx)*0x9E37_79B9_7F4A_7C15, 0)
	}
	return addrs
}
