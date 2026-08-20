package xnetip

import (
	"math"
	"net/netip"
	"testing"

	"github.com/stretchr/testify/require"
	"pgregory.net/rapid"
)

// genIPv6Addr draws an IPv6 kernel address: uniform over the 128-bit
// space, with three draws in ten on a boundary or mapped shape.
//
// The fixed shapes are the two extremes, each half alone at its extreme,
// the top bit alone, the bottom bit alone, and a mapped address with a
// random IPv4 part — the patterns the IPv6 mask generators later build
// from. They are drawn explicitly because shrinking walks towards zero
// and rarely stops at the other boundaries.
var genIPv6Addr = rapid.Custom(func(t *rapid.T) ipv6Addr {
	switch rapid.IntRange(0, 9).Draw(t, "shape") {
	case 0, 1:
		boundaries := [][2]uint64{
			{0, 0},
			{math.MaxUint64, math.MaxUint64},
			{0, math.MaxUint64},
			{math.MaxUint64, 0},
			{1 << 63, 0},
			{0, 1},
		}
		halves := rapid.SampledFrom(boundaries).Draw(t, "boundary")
		return ipv6AddrFromBits(halves[0], halves[1])
	case 2:
		mapped := ipv4MappedPrefix | uint64(rapid.Uint32().Draw(t, "mapped"))
		return ipv6AddrFromBits(0, mapped)
	default:
		return ipv6AddrFromBits(rapid.Uint64().Draw(t, "hi"), rapid.Uint64().Draw(t, "lo"))
	}
})

// verifies that the halves constructor places the first eight bytes in
// the high half and the last eight in the low half.
func Test_IPv6Addr_FromBits_PlacesHalves(t *testing.T) {
	address := ipv6AddrFromBits(0x20010DB800000000, 1)
	require.Equal(t, netip.MustParseAddr("2001:db8::1").As16(), address.As16())
	hi, lo := address.Bits()
	require.Equal(t, uint64(0x20010DB800000000), hi)
	require.Equal(t, uint64(1), lo)
}

// verifies that the 16-byte constructor and the byte view invert each
// other over the whole value space.
func Test_IPv6Addr_From16_RoundTripsAs16(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		address := genIPv6Addr.Draw(t, "address")
		require.Equal(t, address, ipv6AddrFrom16(address.As16()))
	})
}

// verifies that the netip constructor accepts exactly the IPv6 family:
// mapped stays 16-byte, IPv4 and invalid inputs are rejected.
func Test_IPv6Addr_FromNetip_AcceptsOnlyIs6(t *testing.T) {
	address, ok := ipv6AddrFromNetip(netip.MustParseAddr("2001:db8::1"))
	require.True(t, ok)
	require.Equal(t, netip.MustParseAddr("2001:db8::1").As16(), address.As16())
	mapped, ok := ipv6AddrFromNetip(netip.MustParseAddr("::ffff:1.2.3.4"))
	require.True(t, ok)
	require.True(t, mapped.Is4In6())
	_, ok = ipv6AddrFromNetip(netip.MustParseAddr("1.2.3.4"))
	require.False(t, ok)
	_, ok = ipv6AddrFromNetip(netip.Addr{})
	require.False(t, ok)
}

// verifies that a zone is discarded silently: the conversion succeeds
// and yields the zone-free bytes.
func Test_IPv6Addr_FromNetip_DropsZone(t *testing.T) {
	address, ok := ipv6AddrFromNetip(netip.MustParseAddr("fe80::1%eth0"))
	require.True(t, ok)
	require.Equal(t, netip.MustParseAddr("fe80::1").As16(), address.As16())
}

// verifies that the netip view is a valid zone-free IPv6 address and
// that converting it back restores the value.
func Test_IPv6Addr_Netip_RoundTrips(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		address := genIPv6Addr.Draw(t, "address")
		view := address.Netip()
		require.True(t, view.Is6())
		require.Empty(t, view.Zone())
		restored, ok := ipv6AddrFromNetip(view)
		require.True(t, ok)
		require.Equal(t, address, restored)
	})
}

// verifies that the mapped-range test agrees with net/netip on every
// address.
func Test_IPv6Addr_Is4In6_MatchesNetip(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		address := genIPv6Addr.Draw(t, "address")
		require.Equal(t, netip.AddrFrom16(address.As16()).Is4In6(), address.Is4In6())
	})
}

// verifies that the extraction agrees with netip.Addr.Unmap: it succeeds
// exactly when unmapping changes the family, with the same four bytes.
func Test_IPv6Addr_ToIPv4Mapped_MatchesNetipUnmap(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		address := genIPv6Addr.Draw(t, "address")
		oracle := netip.AddrFrom16(address.As16()).Unmap()
		extracted, ok := address.ToIPv4Mapped()
		require.Equal(t, oracle.Is4(), ok)
		if ok {
			require.Equal(t, oracle.As4(), extracted.As4())
		}
	})
}

// verifies that the deprecated IPv4-compatible form is not treated as
// mapped.
func Test_IPv6Addr_ToIPv4Mapped_RejectsIPv4Compatible(t *testing.T) {
	_, ok := ipv6AddrFromBits(0, 0xC00A02FF).ToIPv4Mapped()
	require.False(t, ok)
}

// verifies that the order is the numeric order net/netip gives two IPv6
// addresses without zones.
func Test_IPv6Addr_Compare_MatchesNetip(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		left := genIPv6Addr.Draw(t, "left")
		right := genIPv6Addr.Draw(t, "right")
		oracle := netip.AddrFrom16(left.As16()).Compare(netip.AddrFrom16(right.As16()))
		require.Equal(t, oracle, left.Compare(right))
	})
}

// verifies that the text kernel prints exactly the RFC 5952 form
// net/netip prints, mapped addresses included.
func Test_IPv6Addr_AppendTo_MatchesNetipString(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		address := genIPv6Addr.Draw(t, "address")
		require.Equal(t, netip.AddrFrom16(address.As16()).String(), string(address.AppendTo(nil)))
	})
}

// verifies that the text kernel appends after existing content instead
// of overwriting it.
func Test_IPv6Addr_AppendTo_AppendsAfterExistingContent(t *testing.T) {
	buffer := ipv6AddrFromBits(0x20010DB800000000, 1).AppendTo([]byte("addr="))
	require.Equal(t, "addr=2001:db8::1", string(buffer))
}

// verifies that the kernel operations the networks build on do not
// allocate, the text kernel measured with a preallocated buffer.
func Test_IPv6Addr_Kernel_AllocationFree(t *testing.T) {
	address := ipv6AddrFromBits(0, ipv4MappedPrefix|0x01020304)
	view := address.Netip()
	buffer := make([]byte, 0, 64)
	allocs := testing.AllocsPerRun(100, func() {
		address16Sink = address.As16()
		compareSink = address.Compare(address)
		okSink = address.Is4In6()
		_, okSink = address.ToIPv4Mapped()
		bytesKernelSink = address.AppendTo(buffer[:0])
		_, okSink = ipv6AddrFromNetip(view)
		netipKernelSink = address.Netip()
	})
	require.Zero(t, int(allocs), "allocations per call")
}

// address16Sink keeps the measured byte view alive, so the compiler
// cannot optimise the work under test away.
var address16Sink [16]byte
