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
