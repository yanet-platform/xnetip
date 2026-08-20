package xnetip_test

import (
	"net/netip"
	"testing"

	"github.com/stretchr/testify/require"
	"pgregory.net/rapid"

	"github.com/yanet-platform/xnetip"
)

// verifies that an address built from an IPv4 value reports the IPv4
// family under every accessor.
func Test_IPAddr_From4_ReportsIPv4(t *testing.T) {
	address := xnetip.IPAddrFrom4(xnetip.MustParseIPv4Addr("192.168.1.0"))
	require.True(t, address.Is4())
	require.False(t, address.Is6())
	v4, ok := address.IPv4()
	require.True(t, ok)
	require.Equal(t, xnetip.MustParseIPv4Addr("192.168.1.0"), v4)
	_, ok = address.IPv6()
	require.False(t, ok)
	require.Equal(t, 32, address.BitLen())
}

// verifies that an address built from an IPv6 value reports the IPv6
// family under every accessor.
func Test_IPAddr_From6_ReportsIPv6(t *testing.T) {
	address := xnetip.IPAddrFrom6(xnetip.MustParseIPv6Addr("2001:db8::"))
	require.True(t, address.Is6())
	require.False(t, address.Is4())
	v6, ok := address.IPv6()
	require.True(t, ok)
	require.Equal(t, xnetip.MustParseIPv6Addr("2001:db8::"), v6)
	_, ok = address.IPv4()
	require.False(t, ok)
	require.Equal(t, 128, address.BitLen())
}

// verifies that an IPv4-mapped IPv6 value stays IPv6: the constructor
// never reinterprets the mapped range as the IPv4 family.
func Test_IPAddr_From6_MappedStaysIPv6(t *testing.T) {
	address := xnetip.IPAddrFrom6(xnetip.MustParseIPv6Addr("::ffff:1.2.3.4"))
	require.False(t, address.Is4())
	require.True(t, address.Is6())
	_, ok := address.IPv4()
	require.False(t, ok)
}

// verifies that an IPv4 address and its mapped IPv6 twin are distinct
// values: they share the 16-byte form but differ in family.
func Test_IPAddr_From4AndFrom6Mapped_Differ(t *testing.T) {
	four := xnetip.IPAddrFrom4(xnetip.MustParseIPv4Addr("1.2.3.4"))
	six := xnetip.IPAddrFrom6(xnetip.MustParseIPv6Addr("::ffff:1.2.3.4"))
	require.NotEqual(t, four, six)
	require.Equal(t, four.As16(), six.As16())
}

// verifies that the 16-byte form of an IPv4 address is the IPv4-mapped
// layout, as netip.Addr.As16 returns it.
func Test_IPAddr_As16_OfIPv4IsMapped(t *testing.T) {
	address := xnetip.IPAddrFrom4(xnetip.MustParseIPv4Addr("1.2.3.4"))
	require.Equal(t, [16]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 1, 2, 3, 4}, address.As16())
}

// verifies the 16-byte form of an IPv6 address.
func Test_IPAddr_As16_OfIPv6(t *testing.T) {
	address := xnetip.IPAddrFrom6(xnetip.MustParseIPv6Addr("2001:db8::1"))
	require.Equal(t, [16]byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}, address.As16())
}

// verifies that the zero value is the IPv6 unspecified address ::, a
// real address with no invalid state.
func Test_IPAddr_ZeroValue_IsIPv6Unspecified(t *testing.T) {
	var address xnetip.IPAddr
	require.True(t, address.Is6())
	require.False(t, address.Is4())
	require.Equal(t, [16]byte{}, address.As16())
	require.Equal(t, 128, address.BitLen())
	v6, ok := address.IPv6()
	require.True(t, ok)
	require.Equal(t, xnetip.IPv6Addr{}, v6)
}

// verifies that the IPv4 unspecified address is not the zero value: it
// is an IPv4 address stored in the mapped form.
func Test_IPAddr_From4Zero_IsNotZeroValue(t *testing.T) {
	address := xnetip.IPAddrFrom4(xnetip.MustParseIPv4Addr("0.0.0.0"))
	require.NotEqual(t, xnetip.IPAddr{}, address)
	require.True(t, address.Is4())
	require.Equal(t, [16]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 0, 0, 0, 0}, address.As16())
}

// verifies that a non-contiguous mask value survives the round trip
// through the family-agnostic type, the way network mask accessors use it.
func Test_IPAddr_From4_KeepsNonContiguousMaskValue(t *testing.T) {
	mask := xnetip.MustParseIPv4Addr("255.255.0.255")
	v4, ok := xnetip.IPAddrFrom4(mask).IPv4()
	require.True(t, ok)
	require.Equal(t, mask, v4)
}

// verifies that the type is usable as a map key and that an IPv4 address
// and its mapped IPv6 twin are distinct keys.
func Test_IPAddr_MapKey_DistinguishesFamilies(t *testing.T) {
	seen := map[xnetip.IPAddr]string{}
	seen[xnetip.IPAddrFrom4(xnetip.MustParseIPv4Addr("1.2.3.4"))] = "four"
	seen[xnetip.IPAddrFrom6(xnetip.MustParseIPv6Addr("::ffff:1.2.3.4"))] = "six"
	require.Len(t, seen, 2)
	require.Equal(t, "four", seen[xnetip.IPAddrFrom4(xnetip.MustParseIPv4Addr("1.2.3.4"))])
}

// verifies that the IPv4 accessor inverts the IPv4 constructor for every
// address.
func Test_IPAddr_IPv4_RoundTripsFrom4(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		address := genIPv4Addr.Draw(t, "address")
		v4, ok := xnetip.IPAddrFrom4(address).IPv4()
		require.True(t, ok)
		require.Equal(t, address, v4)
	})
}

// verifies that the IPv6 accessor inverts the IPv6 constructor for every
// address.
func Test_IPAddr_IPv6_RoundTripsFrom6(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		address := genIPv6Addr.Draw(t, "address")
		v6, ok := xnetip.IPAddrFrom6(address).IPv6()
		require.True(t, ok)
		require.Equal(t, address, v6)
	})
}

// verifies that exactly one family holds for every value and that the
// bit length reports the family.
func Test_IPAddr_Family_IsExclusive(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		address := genIPAddr.Draw(t, "address")
		require.NotEqual(t, address.Is6(), address.Is4())
		require.Equal(t, address.Is4(), address.BitLen() == 32)
		require.Equal(t, address.Is6(), address.BitLen() == 128)
	})
}

// verifies that the 16-byte form agrees with net/netip for both
// families: mapped for IPv4, verbatim for IPv6.
func Test_IPAddr_As16_MatchesNetip(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		if rapid.Bool().Draw(t, "four") {
			address := genIPv4Addr.Draw(t, "address")
			require.Equal(t, netip.AddrFrom4(address.As4()).As16(), xnetip.IPAddrFrom4(address).As16())
			return
		}
		address := genIPv6Addr.Draw(t, "address")
		require.Equal(t, address.As16(), xnetip.IPAddrFrom6(address).As16())
	})
}

// verifies that the constructors and the accessors do not allocate.
func Test_IPAddr_Construction_DoesNotAllocate(t *testing.T) {
	four := xnetip.MustParseIPv4Addr("192.168.1.0")
	six := xnetip.MustParseIPv6Addr("2001:db8::1")
	var octets [16]byte
	requireNoAllocs(t, func() {
		ipAddrSink = xnetip.IPAddrFrom4(four)
		boolSink = ipAddrSink.Is4()
		boolSink = ipAddrSink.Is6()
		ipv4AddrSink, boolSink = ipAddrSink.IPv4()
		ipv6AddrSink, boolSink = xnetip.IPAddrFrom6(six).IPv6()
		octets = ipAddrSink.As16()
		intSink = ipAddrSink.BitLen()
	})
	_ = octets
}
