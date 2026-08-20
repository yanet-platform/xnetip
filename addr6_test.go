package xnetip_test

import (
	"bytes"
	"cmp"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"math"
	"net/netip"
	"slices"
	"strings"
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

// verifies that the text form is the RFC 5952 canonical one.
//
// The longest run of two or more zero groups collapses to "::", the
// leftmost run wins a tie, a single zero group stays, hex is lowercase
// without leading zeros, and the IPv4-mapped range ends in a dotted quad.
func Test_IPv6Addr_String_FormatsCanonicalRFC5952(t *testing.T) {
	cases := []struct {
		name   string
		groups [8]uint16
		want   string
	}{
		{name: "unspecified address is a bare double colon", groups: [8]uint16{}, want: "::"},
		{name: "loopback compresses the leading zeros", groups: [8]uint16{0, 0, 0, 0, 0, 0, 0, 1}, want: "::1"},
		{name: "trailing zeros compress", groups: [8]uint16{0x2001, 0xdb8, 0, 0, 0, 0, 0, 0}, want: "2001:db8::"},
		{name: "leading zeros compress", groups: [8]uint16{0, 0, 1, 2, 3, 4, 5, 6}, want: "::1:2:3:4:5:6"},
		{name: "single leading zero group is not compressed", groups: [8]uint16{0, 1, 2, 3, 4, 5, 6, 7}, want: "0:1:2:3:4:5:6:7"},
		{name: "longest zero run wins", groups: [8]uint16{1, 0, 0, 1, 0, 0, 0, 1}, want: "1:0:0:1::1"},
		{name: "leftmost zero run wins on tie", groups: [8]uint16{1, 0, 0, 1, 0, 0, 1, 1}, want: "1::1:0:0:1:1"},
		{name: "single zero group is not compressed", groups: [8]uint16{0x2001, 0xdb8, 0, 1, 1, 1, 1, 1}, want: "2001:db8:0:1:1:1:1:1"},
		{name: "hex is lowercase without leading zeros", groups: [8]uint16{0xABCD, 0xEF01, 0, 0, 0, 0, 0, 0}, want: "abcd:ef01::"},
		{name: "IPv4-mapped address prints a dotted tail", groups: [8]uint16{0, 0, 0, 0, 0, 0xffff, 0x0102, 0x0304}, want: "::ffff:1.2.3.4"},
		{name: "IPv4-compatible address is not special", groups: [8]uint16{0, 0, 0, 0, 0, 0, 0x0102, 0x0304}, want: "::102:304"},
		{name: "all ones is the longest form", groups: [8]uint16{0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff}, want: "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			address := xnetip.IPv6AddrFrom8(
				tc.groups[0], tc.groups[1], tc.groups[2], tc.groups[3],
				tc.groups[4], tc.groups[5], tc.groups[6], tc.groups[7],
			)
			require.Equal(t, tc.want, address.String())
		})
	}
}

// verifies that the expanded form prints all eight groups as four hex
// digits each, with no compression, mapped addresses included.
func Test_IPv6Addr_StringExpanded_PadsEveryGroup(t *testing.T) {
	cases := []struct {
		name   string
		groups [8]uint16
		want   string
	}{
		{name: "compressible address is written in full", groups: [8]uint16{0x2001, 0xdb8, 0, 0, 0, 0, 0, 1}, want: "2001:0db8:0000:0000:0000:0000:0000:0001"},
		{name: "IPv4-mapped address is written as hex groups", groups: [8]uint16{0, 0, 0, 0, 0, 0xffff, 0x0102, 0x0304}, want: "0000:0000:0000:0000:0000:ffff:0102:0304"},
		{name: "unspecified address is all zero digits", groups: [8]uint16{}, want: "0000:0000:0000:0000:0000:0000:0000:0000"},
		{name: "all ones keeps its length", groups: [8]uint16{0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff}, want: "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			address := xnetip.IPv6AddrFrom8(
				tc.groups[0], tc.groups[1], tc.groups[2], tc.groups[3],
				tc.groups[4], tc.groups[5], tc.groups[6], tc.groups[7],
			)
			require.Equal(t, tc.want, address.StringExpanded())
		})
	}
}

// verifies that the text form is appended after the buffer's existing
// content rather than overwriting it.
func Test_IPv6Addr_AppendTo_AppendsAfterExistingContent(t *testing.T) {
	address := xnetip.IPv6AddrFrom8(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)
	got := address.AppendTo([]byte("a="))
	require.Equal(t, "a=2001:db8::1", string(got))
}

// verifies that a buffer with spare capacity is extended in place: the
// returned slice shares the caller's backing array.
func Test_IPv6Addr_AppendTo_KeepsBackingArray(t *testing.T) {
	address := xnetip.IPv6AddrFrom8(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)
	buffer := make([]byte, 0, 64)
	got := address.AppendTo(buffer)
	require.Equal(t, "2001:db8::1", string(got))
	require.Same(t, &buffer[:1][0], &got[0])
}

// verifies that the appending form and the string form agree on every
// address.
func Test_IPv6Addr_AppendTo_AgreesWithString(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		address := genIPv6Addr.Draw(t, "address")
		require.Equal(t, address.String(), string(address.AppendTo(nil)))
	})
}

// verifies that the expanded form equals the eight groups printed as
// four hex digits each and joined by colons, the simplest oracle.
func Test_IPv6Addr_StringExpanded_MatchesGroupOracle(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		address := genIPv6Addr.Draw(t, "address")
		hi, lo := address.Bits()
		want := fmt.Sprintf(
			"%04x:%04x:%04x:%04x:%04x:%04x:%04x:%04x",
			uint16(hi>>48), uint16(hi>>32), uint16(hi>>16), uint16(hi),
			uint16(lo>>48), uint16(lo>>32), uint16(lo>>16), uint16(lo),
		)
		require.Equal(t, want, address.StringExpanded())
	})
}

// verifies that the text form keeps the canonical alphabet and shape
// on every address.
//
// Only lowercase hex digits, colons and dots appear, "::" occurs at most
// once, and the length never exceeds the eight-group width.
func Test_IPv6Addr_String_HasCanonicalAlphabetAndShape(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		address := genIPv6Addr.Draw(t, "address")
		text := address.String()
		require.LessOrEqual(t, len(text), len("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"))
		require.LessOrEqual(t, strings.Count(text, "::"), 1)
		require.LessOrEqual(t, strings.Count(text, ":"), 7+1)
		require.Empty(t, strings.Trim(text, "0123456789abcdef:."))
	})
}

// verifies that the canonical and the expanded forms are byte for byte
// what net/netip prints for the same sixteen bytes, mapped included.
func Test_IPv6Addr_String_MatchesNetip(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		address := genIPv6Addr.Draw(t, "address")
		oracle := netip.AddrFrom16(address.As16())
		require.Equal(t, oracle.String(), address.String())
		require.Equal(t, oracle.StringExpanded(), address.StringExpanded())
	})
}

// verifies that appending into a buffer with enough capacity does not
// allocate, which is the contract every network formatter builds on.
func Test_IPv6Addr_AppendTo_DoesNotAllocate(t *testing.T) {
	address := xnetip.IPv6AddrFrom8(0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff)
	buffer := make([]byte, 0, 64)
	requireNoAllocs(t, func() { bytesSink = address.AppendTo(buffer[:0]) })
}

// verifies that the string forms allocate at most once each, for the
// result itself.
func Test_IPv6Addr_String_AllocatesAtMostOnce(t *testing.T) {
	address := xnetip.IPv6AddrFrom8(0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff)
	allocs := testing.AllocsPerRun(100, func() { stringSink = address.String() })
	require.LessOrEqual(t, allocs, 1.0)
	allocs = testing.AllocsPerRun(100, func() { stringSink = address.StringExpanded() })
	require.LessOrEqual(t, allocs, 1.0)
}

func BenchmarkIPv6Addr_String_Compressed(b *testing.B) {
	address := xnetip.IPv6AddrFrom8(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)
	b.ReportAllocs()
	for b.Loop() {
		stringSink = address.String()
	}
}

func BenchmarkIPv6Addr_String_Full(b *testing.B) {
	address := xnetip.IPv6AddrFrom8(0x2001, 0xdb8, 1, 2, 3, 4, 5, 6)
	b.ReportAllocs()
	for b.Loop() {
		stringSink = address.String()
	}
}

func BenchmarkIPv6Addr_String_Mapped(b *testing.B) {
	address := xnetip.IPv6AddrFrom8(0, 0, 0, 0, 0, 0xffff, 0xc000, 0x0201)
	b.ReportAllocs()
	for b.Loop() {
		stringSink = address.String()
	}
}

func BenchmarkIPv6Addr_AppendTo_Compressed(b *testing.B) {
	address := xnetip.IPv6AddrFrom8(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)
	buffer := make([]byte, 0, 64)
	b.ReportAllocs()
	for b.Loop() {
		bytesSink = address.AppendTo(buffer[:0])
	}
}

func BenchmarkIPv6Addr_AppendTo_Full(b *testing.B) {
	address := xnetip.IPv6AddrFrom8(0x2001, 0xdb8, 1, 2, 3, 4, 5, 6)
	buffer := make([]byte, 0, 64)
	b.ReportAllocs()
	for b.Loop() {
		bytesSink = address.AppendTo(buffer[:0])
	}
}

func BenchmarkIPv6Addr_AppendTo_Mapped(b *testing.B) {
	address := xnetip.IPv6AddrFrom8(0, 0, 0, 0, 0, 0xffff, 0xc000, 0x0201)
	buffer := make([]byte, 0, 64)
	b.ReportAllocs()
	for b.Loop() {
		bytesSink = address.AppendTo(buffer[:0])
	}
}

func BenchmarkIPv6Addr_StringExpanded(b *testing.B) {
	address := xnetip.IPv6AddrFrom8(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)
	b.ReportAllocs()
	for b.Loop() {
		stringSink = address.StringExpanded()
	}
}

// verifies that the marshalled text is exactly the canonical string form
// of the address, with a nil error.
func Test_IPv6Addr_MarshalText_EmitsStringForm(t *testing.T) {
	address := xnetip.MustParseIPv6Addr("2001:db8::1")
	got, err := address.MarshalText()
	require.NoError(t, err)
	require.Equal(t, []byte("2001:db8::1"), got)
}

// verifies that the zero value marshals as the unspecified address rather
// than as empty text, because the zero value is a real address.
func Test_IPv6Addr_MarshalText_ZeroValueIsUnspecified(t *testing.T) {
	var zero xnetip.IPv6Addr
	got, err := zero.MarshalText()
	require.NoError(t, err)
	require.Equal(t, "::", string(got))
}

// verifies that an IPv4-mapped address marshals in its dotted-quad text
// form, staying an IPv6 value rather than unmapping.
func Test_IPv6Addr_MarshalText_MappedStaysMapped(t *testing.T) {
	address := xnetip.MustParseIPv6Addr("::ffff:1.2.3.4")
	got, err := address.MarshalText()
	require.NoError(t, err)
	require.Equal(t, "::ffff:1.2.3.4", string(got))
}

// verifies that the appending marshal form writes the text after the
// buffer's existing content rather than overwriting it.
func Test_IPv6Addr_AppendText_AppendsAfterExistingContent(t *testing.T) {
	address := xnetip.MustParseIPv6Addr("2001:db8::1")
	got, err := address.AppendText([]byte("x="))
	require.NoError(t, err)
	require.Equal(t, "x=2001:db8::1", string(got))
}

// verifies that unmarshalling accepts what the parser accepts and stores
// the parsed address into the receiver, mapped text staying its 16 bytes.
func Test_IPv6Addr_UnmarshalText_AcceptsValidText(t *testing.T) {
	cases := []struct {
		name  string
		input string
		want  xnetip.IPv6Addr
	}{
		{name: "compressed address", input: "2001:db8::1", want: xnetip.MustParseIPv6Addr("2001:db8::1")},
		{name: "uppercase mapped address stays mapped", input: "::FFFF:1.2.3.4", want: xnetip.MustParseIPv6Addr("::ffff:1.2.3.4")},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var address xnetip.IPv6Addr
			require.NoError(t, address.UnmarshalText([]byte(tc.input)))
			require.Equal(t, tc.want, address)
		})
	}
}

// verifies that empty text is a parse error and leaves the receiver
// untouched.
//
// This diverges from net/netip on purpose: there the zero value marks an
// invalid address, here it is the valid unspecified address, so empty
// text must not silently decode into it.
func Test_IPv6Addr_UnmarshalText_RejectsEmptyText(t *testing.T) {
	address := xnetip.MustParseIPv6Addr("2001:db8::1")
	err := address.UnmarshalText([]byte(""))
	require.ErrorIs(t, err, xnetip.ErrParse)
	require.Equal(t, xnetip.MustParseIPv6Addr("2001:db8::1"), address)
}

// verifies that text carrying a zone suffix fails unmarshalling with the
// zone sentinel and leaves the receiver untouched.
func Test_IPv6Addr_UnmarshalText_RejectsZone(t *testing.T) {
	address := xnetip.MustParseIPv6Addr("2001:db8::1")
	err := address.UnmarshalText([]byte("fe80::1%eth0"))
	require.ErrorIs(t, err, xnetip.ErrZone)
	require.Equal(t, xnetip.MustParseIPv6Addr("2001:db8::1"), address)
}

// verifies that dotted-decimal IPv4 text fails unmarshalling as a family
// mismatch and leaves the receiver untouched.
func Test_IPv6Addr_UnmarshalText_RejectsIPv4Text(t *testing.T) {
	address := xnetip.MustParseIPv6Addr("2001:db8::1")
	err := address.UnmarshalText([]byte("1.2.3.4"))
	require.ErrorIs(t, err, xnetip.ErrAddrFamilyMismatch)
	require.Equal(t, xnetip.MustParseIPv6Addr("2001:db8::1"), address)
}

// verifies that text the parser rejects fails unmarshalling and leaves
// the receiver untouched, whatever the reason for the rejection.
func Test_IPv6Addr_UnmarshalText_RejectsInvalidText(t *testing.T) {
	cases := []struct {
		name  string
		input string
	}{
		{name: "double compression", input: "1::2::3"},
		{name: "leading space", input: " ::1"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			address := xnetip.MustParseIPv6Addr("2001:db8::1")
			require.Error(t, address.UnmarshalText([]byte(tc.input)))
			require.Equal(t, xnetip.MustParseIPv6Addr("2001:db8::1"), address)
		})
	}
}

// verifies that a failed unmarshal does not clobber a previously stored
// address.
func Test_IPv6Addr_UnmarshalText_KeepsReceiverOnError(t *testing.T) {
	address := xnetip.MustParseIPv6Addr("2001:db8::1")
	require.Error(t, address.UnmarshalText([]byte("x")))
	require.Equal(t, xnetip.MustParseIPv6Addr("2001:db8::1"), address)
}

// verifies that a struct field of the address type round-trips through
// JSON as a quoted canonical string.
func Test_IPv6Addr_MarshalText_JSONRoundTripsStructField(t *testing.T) {
	type record struct{ A xnetip.IPv6Addr }
	original := record{A: xnetip.MustParseIPv6Addr("2001:db8::1")}
	encoded, err := json.Marshal(original)
	require.NoError(t, err)
	require.JSONEq(t, `{"A":"2001:db8::1"}`, string(encoded))
	var decoded record
	require.NoError(t, json.Unmarshal(encoded, &decoded))
	require.Equal(t, original, decoded)
}

// verifies that a JSON number does not decode into the address type,
// which accepts text only.
func Test_IPv6Addr_UnmarshalText_JSONRejectsNumber(t *testing.T) {
	var decoded struct{ A xnetip.IPv6Addr }
	require.Error(t, json.Unmarshal([]byte(`{"A":1}`), &decoded))
}

// verifies that unmarshalling the marshalled text yields the address
// back, for every address including the mapped shapes.
func Test_IPv6Addr_MarshalText_RoundTripsThroughUnmarshal(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		address := genIPv6Addr.Draw(t, "address")
		text, err := address.MarshalText()
		require.NoError(t, err)
		var decoded xnetip.IPv6Addr
		require.NoError(t, decoded.UnmarshalText(text))
		require.Equal(t, address, decoded)
	})
}

// verifies that the marshalled text and the string form agree on every
// address.
func Test_IPv6Addr_MarshalText_AgreesWithString(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		address := genIPv6Addr.Draw(t, "address")
		text, err := address.MarshalText()
		require.NoError(t, err)
		require.Equal(t, address.String(), string(text))
	})
}

// verifies that the marshalled text is byte for byte what net/netip
// marshals for the same 16 bytes.
func Test_IPv6Addr_MarshalText_MatchesNetip(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		address := genIPv6Addr.Draw(t, "address")
		want, wantErr := netip.AddrFrom16(address.As16()).MarshalText()
		require.NoError(t, wantErr)
		got, err := address.MarshalText()
		require.NoError(t, err)
		require.Equal(t, want, got)
	})
}

// verifies that marshalling allocates exactly once, for the returned
// text itself, even in the longest all-groups form.
func Test_IPv6Addr_MarshalText_AllocatesOnce(t *testing.T) {
	address := xnetip.MustParseIPv6Addr("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff")
	allocs := int(testing.AllocsPerRun(100, func() { bytesSink, errSink = address.MarshalText() }))
	require.Equal(t, 1, allocs)
}

// verifies that the appending marshal form into a buffer with enough
// capacity does not allocate.
func Test_IPv6Addr_AppendText_DoesNotAllocate(t *testing.T) {
	address := xnetip.MustParseIPv6Addr("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff")
	buffer := make([]byte, 0, 64)
	requireNoAllocs(t, func() { bytesSink, errSink = address.AppendText(buffer[:0]) })
}

// verifies that the eight-group form parses to the address it spells,
// at the two extremes and for a typical address.
func Test_ParseIPv6Addr_AcceptsFullForm(t *testing.T) {
	cases := []struct {
		name  string
		input string
		want  xnetip.IPv6Addr
	}{
		{name: "typical address with explicit zero groups", input: "2001:db8:0:0:0:0:0:1", want: xnetip.IPv6AddrFrom8(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)},
		{name: "unspecified address spelled out", input: "0:0:0:0:0:0:0:0", want: xnetip.IPv6AddrFrom8(0, 0, 0, 0, 0, 0, 0, 0)},
		{name: "all ones", input: "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", want: xnetip.IPv6AddrFrom8(0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := xnetip.ParseIPv6Addr(tc.input)
			require.NoError(t, err)
			require.Equal(t, tc.want, got)
		})
	}
}

// verifies that one "::" stands for the run of zero groups that brings
// the count to eight, wherever it sits.
//
// The cases put the compression alone, in front, in the middle and at
// the end, standing for one group and for seven.
func Test_ParseIPv6Addr_AcceptsCompressedForms(t *testing.T) {
	cases := []struct {
		name  string
		input string
		want  xnetip.IPv6Addr
	}{
		{name: "only the compression is the unspecified address", input: "::", want: xnetip.IPv6AddrFrom8(0, 0, 0, 0, 0, 0, 0, 0)},
		{name: "leading compression before one group", input: "::1", want: xnetip.IPv6AddrFrom8(0, 0, 0, 0, 0, 0, 0, 1)},
		{name: "trailing compression after two groups", input: "2001:db8::", want: xnetip.IPv6AddrFrom8(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0)},
		{name: "compression between single groups", input: "2001::1", want: xnetip.IPv6AddrFrom8(0x2001, 0, 0, 0, 0, 0, 0, 1)},
		{name: "compression between two groups and one", input: "2001:db8::1", want: xnetip.IPv6AddrFrom8(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)},
		{name: "trailing compression standing for one group", input: "1:2:3:4:5:6:7::", want: xnetip.IPv6AddrFrom8(1, 2, 3, 4, 5, 6, 7, 0)},
		{name: "leading compression standing for one group", input: "::1:2:3:4:5:6:7", want: xnetip.IPv6AddrFrom8(0, 1, 2, 3, 4, 5, 6, 7)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := xnetip.ParseIPv6Addr(tc.input)
			require.NoError(t, err)
			require.Equal(t, tc.want, got)
		})
	}
}

// verifies that a second "::" is rejected as unparseable text, whether
// separated by groups, glued together or wrapped around one group.
func Test_ParseIPv6Addr_RejectsDoubleCompression(t *testing.T) {
	cases := []struct {
		name  string
		input string
	}{
		{name: "two compressions separated by a group", input: "1::2::3"},
		{name: "three colons", input: ":::"},
		{name: "compression on both sides of a group", input: "::1::"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := xnetip.ParseIPv6Addr(tc.input)
			require.ErrorIs(t, err, xnetip.ErrParse)
		})
	}
}

// verifies that a "::" next to eight explicit groups is rejected as
// unparseable text: the compression must stand for at least one group.
func Test_ParseIPv6Addr_RejectsFullFormPlusCompression(t *testing.T) {
	cases := []struct {
		name  string
		input string
	}{
		{name: "eight groups then compression", input: "1:2:3:4:5:6:7:8::"},
		{name: "compression then eight groups", input: "::1:2:3:4:5:6:7:8"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := xnetip.ParseIPv6Addr(tc.input)
			require.ErrorIs(t, err, xnetip.ErrParse)
		})
	}
}

// verifies that without a compression exactly eight groups are required.
//
// Seven groups, nine groups, empty input and a lone colon are all
// rejected as unparseable text.
func Test_ParseIPv6Addr_RejectsWrongGroupCount(t *testing.T) {
	cases := []struct {
		name  string
		input string
	}{
		{name: "seven groups", input: "1:2:3:4:5:6:7"},
		{name: "nine groups", input: "1:2:3:4:5:6:7:8:9"},
		{name: "empty input", input: ""},
		{name: "single colon", input: ":"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := xnetip.ParseIPv6Addr(tc.input)
			require.ErrorIs(t, err, xnetip.ErrParse)
		})
	}
}

// verifies that a group of five hex digits is rejected as unparseable
// text wherever it stands, even when its value would fit in a group.
func Test_ParseIPv6Addr_RejectsTooManyHexDigits(t *testing.T) {
	cases := []struct {
		name  string
		input string
	}{
		{name: "five digits in the first group", input: "12345::"},
		{name: "five digits in the last group", input: "::12345"},
		{name: "five digits in a middle group", input: "1:22222:3::"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := xnetip.ParseIPv6Addr(tc.input)
			require.ErrorIs(t, err, xnetip.ErrParse)
		})
	}
}

// verifies that uppercase hex digits are accepted and denote the same
// address as their lowercase spelling.
func Test_ParseIPv6Addr_AcceptsUppercaseHex(t *testing.T) {
	upper, err := xnetip.ParseIPv6Addr("ABCD:EF01::")
	require.NoError(t, err)
	require.Equal(t, xnetip.IPv6AddrFrom8(0xABCD, 0xEF01, 0, 0, 0, 0, 0, 0), upper)
	lower, err := xnetip.ParseIPv6Addr("abcd:ef01::")
	require.NoError(t, err)
	require.Equal(t, lower, upper)
}

// verifies that a dotted IPv4 quad in place of the last two groups is
// accepted and fills those two groups.
//
// The quad is tested after a compression and after six explicit groups
// alike.
func Test_ParseIPv6Addr_AcceptsEmbeddedIPv4InLastPosition(t *testing.T) {
	cases := []struct {
		name  string
		input string
		want  xnetip.IPv6Addr
	}{
		{name: "IPv4-mapped address", input: "::ffff:1.2.3.4", want: xnetip.IPv6AddrFrom8(0, 0, 0, 0, 0, 0xffff, 0x0102, 0x0304)},
		{name: "six groups then the quad", input: "1:2:3:4:5:6:1.2.3.4", want: xnetip.IPv6AddrFrom8(1, 2, 3, 4, 5, 6, 0x0102, 0x0304)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := xnetip.ParseIPv6Addr(tc.input)
			require.NoError(t, err)
			require.Equal(t, tc.want, got)
		})
	}
}

// verifies that an embedded IPv4 quad is rejected as unparseable text
// when it is malformed or stands anywhere but in the last two groups.
func Test_ParseIPv6Addr_RejectsEmbeddedIPv4NotInLastPosition(t *testing.T) {
	cases := []struct {
		name  string
		input string
	}{
		{name: "quad with an octet above 255", input: "64:ff9b::1.2.3.300"},
		{name: "quad before the compression", input: "1.2.3.4::"},
		{name: "quad in the second position", input: "1:1.2.3.4:2:3:4:5:6"},
		{name: "quad followed by a group", input: "::1.2.3.4:5"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := xnetip.ParseIPv6Addr(tc.input)
			require.ErrorIs(t, err, xnetip.ErrParse)
		})
	}
}

// verifies that the whole input must be the address, so any surrounding
// or trailing byte is rejected as unparseable text.
//
// The cases cover whitespace, non-hex letters, a CIDR suffix, a
// multibyte character and a zone marker with no address in front of it.
func Test_ParseIPv6Addr_RejectsGarbageAndWhitespace(t *testing.T) {
	cases := []struct {
		name  string
		input string
	}{
		{name: "leading space", input: " ::1"},
		{name: "trailing space", input: "::1 "},
		{name: "trailing newline", input: "::1\n"},
		{name: "letters beyond the hex range", input: "gggg::"},
		{name: "CIDR suffix", input: "2001:db8::1/32"},
		{name: "multibyte character in the last group", input: "::é"},
		{name: "bare zone without an address", input: "%eth0"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := xnetip.ParseIPv6Addr(tc.input)
			require.ErrorIs(t, err, xnetip.ErrParse)
		})
	}
}

// verifies that well-formed dotted-decimal IPv4 text is rejected as a
// family mismatch, not as unparseable text.
func Test_ParseIPv6Addr_RejectsIPv4AsFamilyMismatch(t *testing.T) {
	cases := []struct {
		name  string
		input string
	}{
		{name: "private IPv4 literal", input: "192.168.1.1"},
		{name: "unspecified IPv4 address", input: "0.0.0.0"},
		{name: "broadcast IPv4 address", input: "255.255.255.255"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := xnetip.ParseIPv6Addr(tc.input)
			require.ErrorIs(t, err, xnetip.ErrAddrFamilyMismatch)
			require.NotErrorIs(t, err, xnetip.ErrParse)
		})
	}
}

// verifies that an otherwise valid address carrying a zone suffix is
// rejected with the zone sentinel alone.
//
// The address type has no zone to keep it in. The cases cover a link-local address with an interface name, the
// loopback with a numeric zone, the unspecified address with a
// single-letter zone and an IPv4-mapped address with a zone.
func Test_ParseIPv6Addr_RejectsZone(t *testing.T) {
	cases := []struct {
		name  string
		input string
	}{
		{name: "link-local with interface name", input: "fe80::1%eth0"},
		{name: "loopback with numeric zone", input: "::1%0"},
		{name: "unspecified with single-letter zone", input: "::%x"},
		{name: "IPv4-mapped with zone", input: "::ffff:1.2.3.4%eth0"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := xnetip.ParseIPv6Addr(tc.input)
			require.ErrorIs(t, err, xnetip.ErrZone)
			require.NotErrorIs(t, err, xnetip.ErrParse)
			require.NotErrorIs(t, err, xnetip.ErrAddrFamilyMismatch)
		})
	}
}

// verifies that the error message names the parser, echoes the input in
// quotes and carries the cause, so a log line identifies the failed text.
func Test_ParseIPv6Addr_ErrorEchoesInput(t *testing.T) {
	_, err := xnetip.ParseIPv6Addr(":::")
	require.Error(t, err)
	require.True(t, strings.HasPrefix(err.Error(), `xnetip.ParseIPv6Addr(":::"): `), err.Error())
	require.Contains(t, err.Error(), xnetip.ErrParse.Error())
	_, err = xnetip.ParseIPv6Addr("fe80::1%eth0")
	require.Error(t, err)
	require.Equal(t, `xnetip.ParseIPv6Addr("fe80::1%eth0"): `+xnetip.ErrZone.Error(), err.Error())
	_, err = xnetip.ParseIPv6Addr("192.168.1.1")
	require.Error(t, err)
	require.Equal(t, `xnetip.ParseIPv6Addr("192.168.1.1"): `+xnetip.ErrAddrFamilyMismatch.Error(), err.Error())
}

// verifies that the panicking variant panics on unparseable text with the
// parse error itself.
func Test_MustParseIPv6Addr_PanicsOnError(t *testing.T) {
	require.PanicsWithError(t, `xnetip.ParseIPv6Addr("x"): `+xnetip.ErrParse.Error()+`: ParseAddr("x"): unable to parse IP`, func() {
		xnetip.MustParseIPv6Addr("x")
	})
}

// verifies that the panicking variant returns the parsed address on valid
// text.
func Test_MustParseIPv6Addr_ReturnsOnSuccess(t *testing.T) {
	require.Equal(t, xnetip.IPv6AddrFrom8(0, 0, 0, 0, 0, 0, 0, 1), xnetip.MustParseIPv6Addr("::1"))
}

// verifies that parsing the canonical text of an address yields the
// address back, for every address including the IPv4-mapped ones.
func Test_ParseIPv6Addr_RoundTripsThroughString(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		address := genIPv6Addr.Draw(t, "address")
		got, err := xnetip.ParseIPv6Addr(address.String())
		require.NoError(t, err)
		require.Equal(t, address, got)
	})
}

// verifies that parsing the expanded text of an address yields the
// address back, for every address.
func Test_ParseIPv6Addr_RoundTripsThroughStringExpanded(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		address := genIPv6Addr.Draw(t, "address")
		got, err := xnetip.ParseIPv6Addr(address.StringExpanded())
		require.NoError(t, err)
		require.Equal(t, address, got)
	})
}

// verifies accept/reject parity with net/netip on strings drawn from the
// characters of the address grammar plus a few easy-to-confuse extras.
//
// Drawing from that alphabet rather than from arbitrary bytes exercises
// the parity close to the accept boundary, the zone marker included.
func Test_ParseIPv6Addr_NearMissParityWithNetip(t *testing.T) {
	alphabet := []byte(".:/%+ x0123456789abcdefABCDEF")
	rapid.Check(t, func(t *rapid.T) {
		text := string(rapid.SliceOfN(rapid.SampledFrom(alphabet), 0, 48).Draw(t, "text"))
		requireParseIPv6AddrMatchesNetip(t, text)
	})
}

// verifies accept/reject parity with net/netip on the text of a valid
// address with one byte deleted or replaced by an arbitrary byte.
func Test_ParseIPv6Addr_MutationParityWithNetip(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		text := []byte(genIPv6Addr.Draw(t, "address").String())
		position := rapid.IntRange(0, len(text)-1).Draw(t, "position")
		if rapid.Bool().Draw(t, "delete") {
			text = slices.Delete(text, position, position+1)
		} else {
			text[position] = rapid.Byte().Draw(t, "replacement")
		}
		requireParseIPv6AddrMatchesNetip(t, string(text))
	})
}

// verifies accept/reject parity and value agreement with net/netip on
// arbitrary text, seeded with the unit tables and the benchmark shapes.
func FuzzParseIPv6Addr(f *testing.F) {
	seeds := []string{
		"2001:db8:0:0:0:0:0:1", "0:0:0:0:0:0:0:0", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
		"::", "::1", "2001:db8::", "2001::1", "2001:db8::1", "1:2:3:4:5:6:7::", "::1:2:3:4:5:6:7",
		"1::2::3", ":::", "::1::",
		"1:2:3:4:5:6:7:8::", "::1:2:3:4:5:6:7:8",
		"1:2:3:4:5:6:7", "1:2:3:4:5:6:7:8:9", "", ":",
		"12345::", "::12345", "1:22222:3::",
		"ABCD:EF01::", "abcd:ef01::",
		"::ffff:1.2.3.4", "1:2:3:4:5:6:1.2.3.4",
		"64:ff9b::1.2.3.300", "1.2.3.4::", "1:1.2.3.4:2:3:4:5:6", "::1.2.3.4:5",
		" ::1", "::1 ", "::1\n", "gggg::", "2001:db8::1/32", "::é", "%eth0",
		"192.168.1.1", "0.0.0.0", "255.255.255.255",
		"fe80::1%eth0", "::1%0", "::%x", "::ffff:1.2.3.4%eth0", "::1%", "x",
		"2001:db8:1:2:3:4:5:6", "2a02:6b8::c00:1", "::ffff:192.0.2.1",
	}
	for _, seed := range seeds {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, text string) {
		requireParseIPv6AddrMatchesNetip(t, text)
	})
}

// requireParseIPv6AddrMatchesNetip asserts that the parser accepts text
// exactly when net/netip parses it as zone-free IPv6, with the same bytes.
func requireParseIPv6AddrMatchesNetip(t require.TestingT, text string) {
	if helper, ok := t.(interface{ Helper() }); ok {
		helper.Helper()
	}
	got, err := xnetip.ParseIPv6Addr(text)
	want, wantErr := netip.ParseAddr(text)
	if wantErr != nil || !want.Is6() || want.Zone() != "" {
		require.Error(t, err, "input %q", text)
		return
	}
	require.NoError(t, err, "input %q", text)
	require.Equal(t, want.As16(), got.As16(), "input %q", text)
}

// verifies that parsing valid text does not allocate in the compressed,
// the full and the IPv4-mapped form: only the error wrapping allocates.
func Test_ParseIPv6Addr_DoesNotAllocate(t *testing.T) {
	for _, text := range []string{"2001:db8::1", "2001:db8:1:2:3:4:5:6", "::ffff:192.0.2.1"} {
		requireNoAllocs(t, func() { ipv6AddrSink, errSink = xnetip.ParseIPv6Addr(text) })
	}
}

func BenchmarkParseIPv6Addr_Compressed(b *testing.B) {
	text := "2001:db8::1"
	b.ReportAllocs()
	for b.Loop() {
		ipv6AddrSink, errSink = xnetip.ParseIPv6Addr(text)
	}
}

func BenchmarkParseIPv6Addr_Full(b *testing.B) {
	text := "2001:db8:1:2:3:4:5:6"
	b.ReportAllocs()
	for b.Loop() {
		ipv6AddrSink, errSink = xnetip.ParseIPv6Addr(text)
	}
}

func BenchmarkParseIPv6Addr_CompressedMiddle(b *testing.B) {
	text := "2a02:6b8::c00:1"
	b.ReportAllocs()
	for b.Loop() {
		ipv6AddrSink, errSink = xnetip.ParseIPv6Addr(text)
	}
}

func BenchmarkParseIPv6Addr_Mapped(b *testing.B) {
	text := "::ffff:192.0.2.1"
	b.ReportAllocs()
	for b.Loop() {
		ipv6AddrSink, errSink = xnetip.ParseIPv6Addr(text)
	}
}

func BenchmarkParseIPv6Addr_Reject(b *testing.B) {
	text := "1::2::3"
	b.ReportAllocs()
	for b.Loop() {
		ipv6AddrSink, errSink = xnetip.ParseIPv6Addr(text)
	}
}
