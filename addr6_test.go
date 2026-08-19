package xnetip_test

import (
	"encoding/binary"
	"math"
	"net/netip"
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
