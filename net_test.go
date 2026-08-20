package xnetip_test

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/yanet-platform/xnetip"
	"pgregory.net/rapid"
)

// verifies that wrapping an IPv4 network reports the IPv4 family,
// round-trips through the IPv4 extractor and declines the IPv6 one.
func Test_IPNetworkFrom4_RoundTripsThroughIPv4(t *testing.T) {
	network4, err := xnetip.IPv4NetworkFrom(
		netip.MustParseAddr("192.168.1.0"),
		netip.MustParseAddr("255.255.255.0"),
	)
	require.NoError(t, err)
	wrapped := xnetip.IPNetworkFrom4(network4)
	require.True(t, wrapped.Is4())
	require.False(t, wrapped.Is6())
	extracted, ok := wrapped.IPv4()
	require.True(t, ok)
	require.Equal(t, network4, extracted)
	rejected, ok := wrapped.IPv6()
	require.False(t, ok)
	require.Equal(t, xnetip.IPv6Network{}, rejected)
}

// verifies that wrapping an IPv6 network reports the IPv6 family,
// round-trips through the IPv6 extractor and declines the IPv4 one.
func Test_IPNetworkFrom6_RoundTripsThroughIPv6(t *testing.T) {
	network6, err := xnetip.IPv6NetworkFrom(
		netip.MustParseAddr("2001:db8::"),
		netip.MustParseAddr("ffff:ffff::"),
	)
	require.NoError(t, err)
	wrapped := xnetip.IPNetworkFrom6(network6)
	require.True(t, wrapped.Is6())
	require.False(t, wrapped.Is4())
	extracted, ok := wrapped.IPv6()
	require.True(t, ok)
	require.Equal(t, network6, extracted)
	rejected, ok := wrapped.IPv4()
	require.False(t, ok)
	require.Equal(t, xnetip.IPv4Network{}, rejected)
}

// verifies that an IPv4-mapped IPv6 network stays IPv6 when wrapped,
// the way an IPv4-mapped netip.Addr reports Is6 and not Is4.
func Test_IPNetworkFrom6_KeepsMappedNetworkIPv6(t *testing.T) {
	mapped, err := xnetip.IPv6NetworkFrom(
		netip.MustParseAddr("::ffff:192.168.1.0"),
		netip.MustParseAddr("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ff00"),
	)
	require.NoError(t, err)
	wrapped := xnetip.IPNetworkFrom6(mapped)
	require.True(t, wrapped.Is6())
	require.False(t, wrapped.Is4())
	_, ok := wrapped.IPv4()
	require.False(t, ok)
	extracted, ok := wrapped.IPv6()
	require.True(t, ok)
	require.Equal(t, mapped, extracted)
}

// verifies that the address accessor of an IPv4 network returns the
// unmapped Is4 view of the stored address.
func Test_IPNetwork_Addr_IPv4(t *testing.T) {
	network4, err := xnetip.IPv4NetworkFrom(
		netip.MustParseAddr("192.168.1.0"),
		netip.MustParseAddr("255.255.255.0"),
	)
	require.NoError(t, err)
	addr := xnetip.IPNetworkFrom4(network4).Addr()
	require.Equal(t, netip.MustParseAddr("192.168.1.0"), addr)
	require.True(t, addr.Is4())
}

// verifies that the address accessor of an IPv6 network returns the
// Is6 view of the stored address.
func Test_IPNetwork_Addr_IPv6(t *testing.T) {
	network6, err := xnetip.IPv6NetworkFrom(
		netip.MustParseAddr("2001:db8::"),
		netip.MustParseAddr("ffff:ffff::"),
	)
	require.NoError(t, err)
	addr := xnetip.IPNetworkFrom6(network6).Addr()
	require.Equal(t, netip.MustParseAddr("2001:db8::"), addr)
	require.True(t, addr.Is6())
}

// verifies that the mask accessor of an IPv4 network returns the
// unmapped Is4 view of the stored mask.
func Test_IPNetwork_Mask_IPv4(t *testing.T) {
	network4, err := xnetip.IPv4NetworkFrom(
		netip.MustParseAddr("10.0.0.0"),
		netip.MustParseAddr("255.0.0.0"),
	)
	require.NoError(t, err)
	mask := xnetip.IPNetworkFrom4(network4).Mask()
	require.Equal(t, netip.MustParseAddr("255.0.0.0"), mask)
	require.True(t, mask.Is4())
}

// verifies that the mask accessor of an IPv6 network returns the Is6
// view of the stored mask.
func Test_IPNetwork_Mask_IPv6(t *testing.T) {
	network6, err := xnetip.IPv6NetworkFrom(
		netip.MustParseAddr("2001:db8::"),
		netip.MustParseAddr("ffff:ffff::"),
	)
	require.NoError(t, err)
	mask := xnetip.IPNetworkFrom6(network6).Mask()
	require.Equal(t, netip.MustParseAddr("ffff:ffff::"), mask)
	require.True(t, mask.Is6())
}

// verifies that a non-contiguous IPv4 mask and the address bits it
// keeps come back verbatim through the family-agnostic accessors.
func Test_IPNetwork_Mask_NonContiguousIPv4(t *testing.T) {
	network4, err := xnetip.IPv4NetworkFrom(
		netip.MustParseAddr("192.168.0.1"),
		netip.MustParseAddr("255.255.0.255"),
	)
	require.NoError(t, err)
	wrapped := xnetip.IPNetworkFrom4(network4)
	require.Equal(t, netip.MustParseAddr("255.255.0.255"), wrapped.Mask())
	require.Equal(t, netip.MustParseAddr("192.168.0.1"), wrapped.Addr())
}

// verifies that a non-contiguous IPv6 mask with a hole spanning the
// 64-bit half boundary comes back verbatim through the mask accessor.
func Test_IPNetwork_Mask_NonContiguousIPv6(t *testing.T) {
	network6, err := xnetip.IPv6NetworkFrom(
		netip.MustParseAddr("2001:db8::1"),
		netip.MustParseAddr("ffff:ffff::ffff:ffff:0:0"),
	)
	require.NoError(t, err)
	wrapped := xnetip.IPNetworkFrom6(network6)
	require.Equal(t, netip.MustParseAddr("ffff:ffff::ffff:ffff:0:0"), wrapped.Mask())
}

// verifies that the alternating-bit mask, the extreme non-contiguous
// shape, survives the wrap and extract cycle bit for bit.
func Test_IPNetworkFrom4_AlternatingMaskRoundTrips(t *testing.T) {
	network4, err := xnetip.IPv4NetworkFrom(
		netip.MustParseAddr("170.85.170.85"),
		netip.MustParseAddr("170.85.170.85"),
	)
	require.NoError(t, err)
	extracted, ok := xnetip.IPNetworkFrom4(network4).IPv4()
	require.True(t, ok)
	require.Equal(t, network4, extracted)
}

// verifies that the zero value is the IPv6 network ::/0, giving the
// family-agnostic type a valid default like the concrete types have.
func Test_IPNetwork_ZeroValue_IsUnspecifiedIPv6Network(t *testing.T) {
	var network xnetip.IPNetwork
	require.True(t, network.Is6())
	require.False(t, network.Is4())
	extracted, ok := network.IPv6()
	require.True(t, ok)
	require.Equal(t, xnetip.IPv6Network{}, extracted)
	require.Equal(t, netip.MustParseAddr("::"), network.Addr())
	require.Equal(t, netip.MustParseAddr("::"), network.Mask())
}

// verifies that the conversion method on the IPv4 network type builds
// the same value as the corresponding constructor.
func Test_IPv4Network_IPNetwork_EqualsConstructor(t *testing.T) {
	network4, err := xnetip.IPv4NetworkFrom(
		netip.MustParseAddr("192.168.1.0"),
		netip.MustParseAddr("255.255.255.0"),
	)
	require.NoError(t, err)
	require.Equal(t, xnetip.IPNetworkFrom4(network4), network4.IPNetwork())
}

// verifies that the conversion method on the IPv6 network type builds
// the same value as the corresponding constructor.
func Test_IPv6Network_IPNetwork_EqualsConstructor(t *testing.T) {
	network6, err := xnetip.IPv6NetworkFrom(
		netip.MustParseAddr("2001:db8::"),
		netip.MustParseAddr("ffff:ffff::"),
	)
	require.NoError(t, err)
	require.Equal(t, xnetip.IPNetworkFrom6(network6), network6.IPNetwork())
}

// verifies that wrapped networks compare with == and the family flag
// splits an IPv4 network from the IPv6 image sharing its storage.
func Test_IPNetwork_Equality_DistinguishesFamilies(t *testing.T) {
	universe4, err := xnetip.IPv4NetworkFrom(
		netip.MustParseAddr("0.0.0.0"),
		netip.MustParseAddr("0.0.0.0"),
	)
	require.NoError(t, err)
	first := xnetip.IPNetworkFrom4(universe4)
	second := xnetip.IPNetworkFrom4(universe4)
	require.Equal(t, first, second)
	mappedImage, err := xnetip.IPv6NetworkFrom(
		netip.MustParseAddr("::ffff:0:0"),
		netip.MustParseAddr("ffff:ffff:ffff:ffff:ffff:ffff::"),
	)
	require.NoError(t, err)
	require.NotEqual(t, xnetip.IPNetworkFrom4(universe4), xnetip.IPNetworkFrom6(mappedImage))
}

// verifies that wrapping and extracting an IPv4 network is the
// identity for every mask shape.
//
// The property also exercises the mapped-storage invariant: a wrap
// whose stored form were not IPv4-mapped could not extract back into
// the network it came from.
func Test_IPNetworkFrom4_RoundTripProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		network := genIPv4Network.Draw(t, "network")
		wrapped := xnetip.IPNetworkFrom4(network)
		require.True(t, wrapped.Is4())
		require.False(t, wrapped.Is6())
		extracted, ok := wrapped.IPv4()
		require.True(t, ok)
		require.Equal(t, network, extracted)
		_, ok = wrapped.IPv6()
		require.False(t, ok)
	})
}

// verifies that wrapping and extracting an IPv6 network is the
// identity for every mask shape, IPv4-mapped draws included.
func Test_IPNetworkFrom6_RoundTripProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		network := genIPv6Network.Draw(t, "network")
		wrapped := xnetip.IPNetworkFrom6(network)
		require.True(t, wrapped.Is6())
		require.False(t, wrapped.Is4())
		extracted, ok := wrapped.IPv6()
		require.True(t, ok)
		require.Equal(t, network, extracted)
		_, ok = wrapped.IPv4()
		require.False(t, ok)
	})
}

// verifies that the family-agnostic accessors return exactly the
// address and mask of the wrapped IPv4 network, for every mask shape.
func Test_IPNetwork_Accessors_AgreeWithIPv4Network(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		network := genIPv4Network.Draw(t, "network")
		wrapped := xnetip.IPNetworkFrom4(network)
		require.Equal(t, network.Addr(), wrapped.Addr())
		require.Equal(t, network.Mask(), wrapped.Mask())
	})
}

// verifies that the family-agnostic accessors return exactly the
// address and mask of the wrapped IPv6 network, for every mask shape.
func Test_IPNetwork_Accessors_AgreeWithIPv6Network(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		network := genIPv6Network.Draw(t, "network")
		wrapped := xnetip.IPNetworkFrom6(network)
		require.Equal(t, network.Addr(), wrapped.Addr())
		require.Equal(t, network.Mask(), wrapped.Mask())
	})
}

// verifies that every drawn family-agnostic network is coherent.
//
// The family flags are complementary, exactly the matching extractor
// succeeds and the accessors answer in the network's own family.
func Test_IPNetwork_FamilyViews_Coherent(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		network := genIPNetwork.Draw(t, "network")
		require.NotEqual(t, network.Is4(), network.Is6())
		_, ok4 := network.IPv4()
		require.Equal(t, network.Is4(), ok4)
		_, ok6 := network.IPv6()
		require.Equal(t, network.Is6(), ok6)
		require.Equal(t, network.Is4(), network.Addr().Is4())
		require.Equal(t, network.Is4(), network.Mask().Is4())
		require.Equal(t, network.Is6(), network.Addr().Is6())
		require.Equal(t, network.Is6(), network.Mask().Is6())
	})
}

// verifies that both constructors perform no allocation.
func Test_IPNetwork_Constructors_AllocationFree(t *testing.T) {
	network4, err := xnetip.IPv4NetworkFrom(
		netip.MustParseAddr("192.168.1.0"),
		netip.MustParseAddr("255.255.0.255"),
	)
	require.NoError(t, err)
	network6, err := xnetip.IPv6NetworkFrom(
		netip.MustParseAddr("2001:db8::"),
		netip.MustParseAddr("ffff:0:ffff::"),
	)
	require.NoError(t, err)
	requireNoAllocs(t, func() { ipNetworkSink = xnetip.IPNetworkFrom4(network4) })
	requireNoAllocs(t, func() { ipNetworkSink = xnetip.IPNetworkFrom6(network6) })
}

// verifies that the extractors and the address and mask accessors
// perform no allocation in either family.
func Test_IPNetwork_Accessors_AllocationFree(t *testing.T) {
	network4, err := xnetip.IPv4NetworkFrom(
		netip.MustParseAddr("192.168.1.0"),
		netip.MustParseAddr("255.255.0.255"),
	)
	require.NoError(t, err)
	network6, err := xnetip.IPv6NetworkFrom(
		netip.MustParseAddr("2001:db8::"),
		netip.MustParseAddr("ffff:0:ffff::"),
	)
	require.NoError(t, err)
	wrapped4 := xnetip.IPNetworkFrom4(network4)
	wrapped6 := xnetip.IPNetworkFrom6(network6)
	requireNoAllocs(t, func() { networkSink, okSink = wrapped4.IPv4() })
	requireNoAllocs(t, func() { network6Sink, okSink = wrapped6.IPv6() })
	requireNoAllocs(t, func() { addrSink = wrapped4.Addr() })
	requireNoAllocs(t, func() { addrSink = wrapped6.Addr() })
	requireNoAllocs(t, func() { addrSink = wrapped4.Mask() })
	requireNoAllocs(t, func() { addrSink = wrapped6.Mask() })
}

// verifies that the CIDR constructor dispatches on the address family
// and equals the same-family typed construction, views included.
func Test_IPNetworkFromCIDR_DispatchesByFamily(t *testing.T) {
	cases := []struct {
		name     string
		addr     string
		bits     int
		wantIs4  bool
		wantAddr string
		wantMask string
	}{
		{name: "IPv4 host bits cleared", addr: "192.168.1.5", bits: 24, wantIs4: true, wantAddr: "192.168.1.0", wantMask: "255.255.255.0"},
		{name: "IPv6 host bits cleared", addr: "2001:db8::1", bits: 64, wantIs4: false, wantAddr: "2001:db8::", wantMask: "ffff:ffff:ffff:ffff::"},
		{name: "IPv4 host route", addr: "192.168.1.5", bits: 32, wantIs4: true, wantAddr: "192.168.1.5", wantMask: "255.255.255.255"},
		{name: "IPv4 universe", addr: "192.168.1.5", bits: 0, wantIs4: true, wantAddr: "0.0.0.0", wantMask: "0.0.0.0"},
		{name: "IPv6 host route", addr: "2001:db8::1", bits: 128, wantIs4: false, wantAddr: "2001:db8::1", wantMask: "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"},
		{name: "IPv6 universe", addr: "2001:db8::1", bits: 0, wantIs4: false, wantAddr: "::", wantMask: "::"},
		{name: "IPv4-mapped address stays IPv6", addr: "::ffff:192.168.1.5", bits: 120, wantIs4: false, wantAddr: "::ffff:192.168.1.0", wantMask: "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ff00"},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			addr := netip.MustParseAddr(testCase.addr)
			network, err := xnetip.IPNetworkFromCIDR(addr, testCase.bits)
			require.NoError(t, err)
			require.Equal(t, testCase.wantIs4, network.Is4())
			require.Equal(t, !testCase.wantIs4, network.Is6())
			require.Equal(t, netip.MustParseAddr(testCase.wantAddr), network.Addr())
			require.Equal(t, netip.MustParseAddr(testCase.wantMask), network.Mask())
			if testCase.wantIs4 {
				typed, typedErr := xnetip.IPv4NetworkFromCIDR(addr, testCase.bits)
				require.NoError(t, typedErr)
				require.Equal(t, xnetip.IPNetworkFrom4(typed), network)
			} else {
				typed, typedErr := xnetip.IPv6NetworkFromCIDR(addr, testCase.bits)
				require.NoError(t, typedErr)
				require.Equal(t, xnetip.IPNetworkFrom6(typed), network)
			}
		})
	}
}

// verifies that the length limit is the family's own: 33 overflows
// IPv4, 129 IPv6, 64 splits the two and negatives overflow both.
func Test_IPNetworkFromCIDR_FamilySetsTheLimit(t *testing.T) {
	cases := []struct {
		name    string
		addr    string
		bits    int
		wantErr bool
	}{
		{name: "IPv4 33 overflows", addr: "192.168.1.5", bits: 33, wantErr: true},
		{name: "IPv6 129 overflows", addr: "2001:db8::1", bits: 129, wantErr: true},
		{name: "IPv4 64 overflows", addr: "192.168.1.5", bits: 64, wantErr: true},
		{name: "IPv6 64 is valid", addr: "2001:db8::1", bits: 64, wantErr: false},
		{name: "IPv4 negative overflows", addr: "192.168.1.5", bits: -1, wantErr: true},
		{name: "IPv6 negative overflows", addr: "2001:db8::1", bits: -1, wantErr: true},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			network, err := xnetip.IPNetworkFromCIDR(netip.MustParseAddr(testCase.addr), testCase.bits)
			if testCase.wantErr {
				require.ErrorIs(t, err, xnetip.ErrCIDROverflow)
				require.Equal(t, xnetip.IPNetwork{}, network)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

// verifies that the invalid zero address, having no family, yields
// the family-mismatch sentinel and the zero network.
func Test_IPNetworkFromCIDR_RejectsInvalidAddr(t *testing.T) {
	network, err := xnetip.IPNetworkFromCIDR(netip.Addr{}, 0)
	require.ErrorIs(t, err, xnetip.ErrAddrFamilyMismatch)
	require.Equal(t, xnetip.IPNetwork{}, network)
}

// verifies that the constructor equals the wrapped IPv4 typed
// constructor across the whole length range, overflow included.
//
// The length range deliberately extends one past the family limit so
// the error case is drawn every run. Non-contiguous masks cannot
// arise here — both delegates only build contiguous masks — and the
// success branch checks the concrete view normalized.
func Test_IPNetworkFromCIDR_MatchesTypedConstructorIPv4(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		addr := genNetipAddr4.Draw(t, "addr")
		bits := rapid.IntRange(0, 33).Draw(t, "bits")
		network, err := xnetip.IPNetworkFromCIDR(addr, bits)
		typed, typedErr := xnetip.IPv4NetworkFromCIDR(addr, bits)
		if typedErr != nil {
			require.ErrorIs(t, err, xnetip.ErrCIDROverflow)
			require.ErrorIs(t, typedErr, xnetip.ErrCIDROverflow)
			require.Equal(t, xnetip.IPNetwork{}, network)
			return
		}
		require.NoError(t, err)
		require.Equal(t, xnetip.IPNetworkFrom4(typed), network)
		require.True(t, network.Is4())
		concrete, ok := network.IPv4()
		require.True(t, ok)
		addrBytes := concrete.Addr().As4()
		maskBytes := concrete.Mask().As4()
		addrBits := binary.BigEndian.Uint32(addrBytes[:])
		maskBits := binary.BigEndian.Uint32(maskBytes[:])
		require.Equal(t, addrBits, addrBits&maskBits)
	})
}

// verifies that the constructor equals the wrapped IPv6 typed
// constructor across the whole length range, overflow included.
//
// The length range deliberately extends one past the family limit so
// the error case is drawn every run. Non-contiguous masks cannot
// arise here — both delegates only build contiguous masks — and the
// success branch checks the concrete view normalized.
func Test_IPNetworkFromCIDR_MatchesTypedConstructorIPv6(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		addr := genNetipAddr6.Draw(t, "addr")
		bits := rapid.IntRange(0, 129).Draw(t, "bits")
		network, err := xnetip.IPNetworkFromCIDR(addr, bits)
		typed, typedErr := xnetip.IPv6NetworkFromCIDR(addr, bits)
		if typedErr != nil {
			require.ErrorIs(t, err, xnetip.ErrCIDROverflow)
			require.ErrorIs(t, typedErr, xnetip.ErrCIDROverflow)
			require.Equal(t, xnetip.IPNetwork{}, network)
			return
		}
		require.NoError(t, err)
		require.Equal(t, xnetip.IPNetworkFrom6(typed), network)
		require.True(t, network.Is6())
		concrete, ok := network.IPv6()
		require.True(t, ok)
		addrBytes := concrete.Addr().As16()
		maskBytes := concrete.Mask().As16()
		require.Equal(t, binary.BigEndian.Uint64(addrBytes[:8]), binary.BigEndian.Uint64(addrBytes[:8])&binary.BigEndian.Uint64(maskBytes[:8]))
		require.Equal(t, binary.BigEndian.Uint64(addrBytes[8:]), binary.BigEndian.Uint64(addrBytes[8:])&binary.BigEndian.Uint64(maskBytes[8:]))
	})
}

// verifies that the CIDR constructor allocates nothing on the success
// path of either family, per the allocation-free runtime contract.
func Test_IPNetworkFromCIDR_AllocationFree(t *testing.T) {
	addr4 := netip.MustParseAddr("192.168.1.5")
	addr6 := netip.MustParseAddr("2001:db8::1")
	var err error
	requireNoAllocs(t, func() { ipNetworkSink, err = xnetip.IPNetworkFromCIDR(addr4, 24) })
	require.NoError(t, err)
	requireNoAllocs(t, func() { ipNetworkSink, err = xnetip.IPNetworkFromCIDR(addr6, 64) })
	require.NoError(t, err)
}

// verifies that the host-route constructor answers in the family of
// its argument, with the address preserved and the mask all ones.
//
// A non-contiguous mask table is not applicable to this constructor:
// the mask is fixed to all ones, the universe of bits of the address's
// own family.
func Test_IPNetworkFromAddr_BuildsHostRouteInOwnFamily(t *testing.T) {
	cases := []struct {
		name     string
		addr     string
		wantIs4  bool
		wantMask string
	}{
		{name: "IPv4 host route", addr: "192.168.1.1", wantIs4: true, wantMask: "255.255.255.255"},
		{name: "IPv6 host route", addr: "2001:db8::1", wantIs4: false, wantMask: "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"},
		{name: "IPv4 mask is all ones through the accessor", addr: "10.0.0.1", wantIs4: true, wantMask: "255.255.255.255"},
		{name: "IPv6 mask is all ones through the accessor", addr: "::1", wantIs4: false, wantMask: "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"},
		{name: "IPv4-mapped address stays IPv6", addr: "::ffff:192.168.0.1", wantIs4: false, wantMask: "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"},
		{name: "unspecified IPv4", addr: "0.0.0.0", wantIs4: true, wantMask: "255.255.255.255"},
		{name: "unspecified IPv6", addr: "::", wantIs4: false, wantMask: "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			network, err := xnetip.IPNetworkFromAddr(netip.MustParseAddr(testCase.addr))
			require.NoError(t, err)
			require.Equal(t, testCase.wantIs4, network.Is4())
			require.Equal(t, netip.MustParseAddr(testCase.addr), network.Addr())
			require.Equal(t, netip.MustParseAddr(testCase.wantMask), network.Mask())
		})
	}
}

// verifies that the IPv4 host route round-trips through the IPv4
// extractor and declines the IPv6 one.
func Test_IPNetworkFromAddr_RoundTripsThroughIPv4(t *testing.T) {
	network, err := xnetip.IPNetworkFromAddr(netip.MustParseAddr("192.168.1.1"))
	require.NoError(t, err)
	extracted, ok := network.IPv4()
	require.True(t, ok)
	expected, err := xnetip.IPv4NetworkFromAddr(netip.MustParseAddr("192.168.1.1"))
	require.NoError(t, err)
	require.Equal(t, expected, extracted)
	_, ok = network.IPv6()
	require.False(t, ok)
}

// verifies that the host route of an IPv4-mapped address round-trips
// through the IPv6 extractor and declines the IPv4 one.
func Test_IPNetworkFromAddr_MappedAddressRoundTripsThroughIPv6(t *testing.T) {
	network, err := xnetip.IPNetworkFromAddr(netip.MustParseAddr("::ffff:192.168.0.1"))
	require.NoError(t, err)
	extracted, ok := network.IPv6()
	require.True(t, ok)
	expected, err := xnetip.IPv6NetworkFromAddr(netip.MustParseAddr("::ffff:192.168.0.1"))
	require.NoError(t, err)
	require.Equal(t, expected, extracted)
	_, ok = network.IPv4()
	require.False(t, ok)
}

// verifies that an IPv4 host route equals the lift of the concrete
// IPv4 host route.
//
// Equality of the whole values pins the IPv4-mapped stored form with
// the all-ones 128-bit mask, because the lift performs that encoding.
func Test_IPNetworkFromAddr_StoredFormEqualsIPv4Lift(t *testing.T) {
	network, err := xnetip.IPNetworkFromAddr(netip.MustParseAddr("192.168.1.1"))
	require.NoError(t, err)
	concrete, err := xnetip.IPv4NetworkFromAddr(netip.MustParseAddr("192.168.1.1"))
	require.NoError(t, err)
	require.Equal(t, xnetip.IPNetworkFrom4(concrete), network)
}

// verifies that a zone is dropped silently and the zone-free host
// route is built.
func Test_IPNetworkFromAddr_DropsZone(t *testing.T) {
	network, err := xnetip.IPNetworkFromAddr(netip.MustParseAddr("fe80::1%eth0"))
	require.NoError(t, err)
	require.True(t, network.Is6())
	require.Equal(t, netip.MustParseAddr("fe80::1"), network.Addr())
	require.Empty(t, network.Addr().Zone())
}

// verifies that the invalid zero address yields the family-mismatch
// sentinel and the zero network.
func Test_IPNetworkFromAddr_RejectsInvalidZeroAddr(t *testing.T) {
	network, err := xnetip.IPNetworkFromAddr(netip.Addr{})
	require.ErrorIs(t, err, xnetip.ErrAddrFamilyMismatch)
	require.Equal(t, xnetip.IPNetwork{}, network)
}

// verifies that every valid address of either family lifts into a
// host route of the same family with the address preserved.
//
// The result must also equal the lift of the concrete constructor of
// its family, so the family-agnostic entry point adds no behaviour.
func Test_IPNetworkFromAddr_AgreesWithConcreteConstructorsProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		var addr netip.Addr
		if rapid.Bool().Draw(t, "is4") {
			addr = genNetipAddr4.Draw(t, "addr4")
		} else {
			addr = genNetipAddr6.Draw(t, "addr6")
		}
		network, err := xnetip.IPNetworkFromAddr(addr)
		require.NoError(t, err)
		require.Equal(t, addr.Is4(), network.Is4())
		require.Equal(t, addr, network.Addr())
		if addr.Is4() {
			concrete, err := xnetip.IPv4NetworkFromAddr(addr)
			require.NoError(t, err)
			require.Equal(t, xnetip.IPNetworkFrom4(concrete), network)
		} else {
			concrete, err := xnetip.IPv6NetworkFromAddr(addr)
			require.NoError(t, err)
			require.Equal(t, xnetip.IPNetworkFrom6(concrete), network)
		}
	})
}

// verifies that the host-route constructor allocates nothing on the
// success path of either family.
func Test_IPNetworkFromAddr_AllocationFree(t *testing.T) {
	addr4 := netip.MustParseAddr("192.168.1.5")
	addr6 := netip.MustParseAddr("2001:db8::1")
	var err error
	requireNoAllocs(t, func() { ipNetworkSink, err = xnetip.IPNetworkFromAddr(addr4) })
	require.NoError(t, err)
	requireNoAllocs(t, func() { ipNetworkSink, err = xnetip.IPNetworkFromAddr(addr6) })
	require.NoError(t, err)
}

// verifies that a same-family pair is accepted, the address bits
// outside the mask are cleared and the pair's own family is kept.
func Test_IPNetworkFrom_NormalizesAddressByMask(t *testing.T) {
	cases := []struct {
		name     string
		addr     string
		mask     string
		wantAddr string
		wantIs4  bool
	}{
		{name: "IPv4 contiguous mask clears host bits", addr: "192.168.1.1", mask: "255.255.255.0", wantAddr: "192.168.1.0", wantIs4: true},
		{name: "IPv6 contiguous mask clears host bits", addr: "2001:db8::1", mask: "ffff:ffff::", wantAddr: "2001:db8::", wantIs4: false},
		{name: "IPv4 universe from the all-zero mask", addr: "10.1.2.3", mask: "0.0.0.0", wantAddr: "0.0.0.0", wantIs4: true},
		{name: "IPv6 universe from the all-zero mask", addr: "2001:db8::1", mask: "::", wantAddr: "::", wantIs4: false},
		{name: "IPv4 mask 255.255.0.255 clears the hole in the third octet", addr: "192.168.7.1", mask: "255.255.0.255", wantAddr: "192.168.0.1", wantIs4: true},
		{name: "IPv4 non-contiguous mask comes back verbatim", addr: "192.168.0.1", mask: "255.255.0.255", wantAddr: "192.168.0.1", wantIs4: true},
		{name: "IPv6 two-run mask clears the low groups", addr: "2001:db8::1", mask: "ffff:ffff::ffff:ffff:0:0", wantAddr: "2001:db8::", wantIs4: false},
		{name: "IPv4 alternating mask keeps every second bit", addr: "255.255.255.255", mask: "170.85.170.85", wantAddr: "170.85.170.85", wantIs4: true},
		{name: "IPv6 hole straddling bit 64 is cleared", addr: "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", mask: "ffff:ffff:ffff:ff00:00ff:ffff:ffff:ffff", wantAddr: "ffff:ffff:ffff:ff00:ff:ffff:ffff:ffff", wantIs4: false},
		{name: "IPv4-mapped address with an IPv6 mask stays IPv6", addr: "::ffff:192.168.0.1", mask: "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ff00", wantAddr: "::ffff:192.168.0.0", wantIs4: false},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			network, err := xnetip.IPNetworkFrom(
				netip.MustParseAddr(testCase.addr),
				netip.MustParseAddr(testCase.mask),
			)
			require.NoError(t, err)
			require.Equal(t, testCase.wantIs4, network.Is4())
			require.Equal(t, netip.MustParseAddr(testCase.wantAddr), network.Addr())
			require.Equal(t, netip.MustParseAddr(testCase.mask), network.Mask())
		})
	}
}

// verifies that pairing an address with the all-ones mask of its
// family builds the same host route as the host-route constructor.
func Test_IPNetworkFrom_HostRouteEqualsFromAddr(t *testing.T) {
	cases := []struct {
		name string
		addr string
		mask string
	}{
		{name: "IPv4 host route", addr: "10.0.0.1", mask: "255.255.255.255"},
		{name: "IPv6 host route", addr: "::1", mask: "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			network, err := xnetip.IPNetworkFrom(
				netip.MustParseAddr(testCase.addr),
				netip.MustParseAddr(testCase.mask),
			)
			require.NoError(t, err)
			hostRoute, err := xnetip.IPNetworkFromAddr(netip.MustParseAddr(testCase.addr))
			require.NoError(t, err)
			require.Equal(t, hostRoute, network)
		})
	}
}

// verifies that a mixed-family pair or the invalid zero address
// yields the family-mismatch sentinel and the zero network.
func Test_IPNetworkFrom_RejectsFamilyMismatch(t *testing.T) {
	cases := []struct {
		name string
		addr netip.Addr
		mask netip.Addr
	}{
		{name: "IPv4 address with IPv6 mask", addr: netip.MustParseAddr("10.0.0.1"), mask: netip.MustParseAddr("ffff::")},
		{name: "IPv6 address with IPv4 mask", addr: netip.MustParseAddr("2001:db8::1"), mask: netip.MustParseAddr("255.0.0.0")},
		{name: "IPv4-mapped address with IPv4 mask", addr: netip.MustParseAddr("::ffff:10.0.0.1"), mask: netip.MustParseAddr("255.0.0.0")},
		{name: "invalid zero address", addr: netip.Addr{}, mask: netip.MustParseAddr("255.0.0.0")},
		{name: "invalid zero mask", addr: netip.MustParseAddr("10.0.0.1"), mask: netip.Addr{}},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			network, err := xnetip.IPNetworkFrom(testCase.addr, testCase.mask)
			require.ErrorIs(t, err, xnetip.ErrAddrFamilyMismatch)
			require.Equal(t, xnetip.IPNetwork{}, network)
		})
	}
}

// verifies that an IPv4 pair equals the lift of the concrete IPv4
// constructor, pinning the mapped encoding, all-zero mask included.
func Test_IPNetworkFrom_MatchesIPv4Lift(t *testing.T) {
	cases := []struct {
		name string
		addr string
		mask string
	}{
		{name: "contiguous half mask", addr: "192.168.0.0", mask: "255.255.0.0"},
		{name: "all-zero mask stays mapped", addr: "10.1.2.3", mask: "0.0.0.0"},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			addr := netip.MustParseAddr(testCase.addr)
			mask := netip.MustParseAddr(testCase.mask)
			network, err := xnetip.IPNetworkFrom(addr, mask)
			require.NoError(t, err)
			require.True(t, network.Is4())
			concrete, err := xnetip.IPv4NetworkFrom(addr, mask)
			require.NoError(t, err)
			require.Equal(t, xnetip.IPNetworkFrom4(concrete), network)
		})
	}
}

// verifies that every same-family pair of either family succeeds and
// equals the lift of its family's concrete checked constructor.
func Test_IPNetworkFrom_AgreesWithConcreteConstructorsProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		if rapid.Bool().Draw(t, "is4") {
			addr := genNetipAddr4.Draw(t, "addr4")
			mask := genNetipAddr4.Draw(t, "mask4")
			network, err := xnetip.IPNetworkFrom(addr, mask)
			require.NoError(t, err)
			concrete, err := xnetip.IPv4NetworkFrom(addr, mask)
			require.NoError(t, err)
			require.Equal(t, xnetip.IPNetworkFrom4(concrete), network)
		} else {
			addr := genNetipAddr6.Draw(t, "addr6")
			mask := genNetipAddr6.Draw(t, "mask6")
			network, err := xnetip.IPNetworkFrom(addr, mask)
			require.NoError(t, err)
			concrete, err := xnetip.IPv6NetworkFrom(addr, mask)
			require.NoError(t, err)
			require.Equal(t, xnetip.IPNetworkFrom6(concrete), network)
		}
	})
}

// verifies that every result is masked in its family's width and
// that rebuilding a result from its own accessors is the identity.
func Test_IPNetworkFrom_NormalizationIdempotentProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		var addr, mask, wantAddr netip.Addr
		if rapid.Bool().Draw(t, "is4") {
			addressBits := rapid.Uint32().Draw(t, "addr bits")
			maskBits := rapid.Uint32().Draw(t, "mask bits")
			addr = netipAddrFrom4Bits(addressBits)
			mask = netipAddrFrom4Bits(maskBits)
			wantAddr = netipAddrFrom4Bits(addressBits & maskBits)
		} else {
			addressHi := rapid.Uint64().Draw(t, "addr hi")
			addressLo := rapid.Uint64().Draw(t, "addr lo")
			maskHi := rapid.Uint64().Draw(t, "mask hi")
			maskLo := rapid.Uint64().Draw(t, "mask lo")
			addr = netipAddrFrom6Bits(addressHi, addressLo)
			mask = netipAddrFrom6Bits(maskHi, maskLo)
			wantAddr = netipAddrFrom6Bits(addressHi&maskHi, addressLo&maskLo)
		}
		network, err := xnetip.IPNetworkFrom(addr, mask)
		require.NoError(t, err)
		require.Equal(t, wantAddr, network.Addr())
		require.Equal(t, mask, network.Mask())
		rebuilt, err := xnetip.IPNetworkFrom(network.Addr(), network.Mask())
		require.NoError(t, err)
		require.Equal(t, network, rebuilt)
	})
}

// verifies that a mixed-family pair, in either order, always yields
// the family-mismatch sentinel and the zero network.
func Test_IPNetworkFrom_RejectsMixedFamilyProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		addr4 := genNetipAddr4.Draw(t, "addr4")
		addr6 := genNetipAddr6.Draw(t, "addr6")
		addr, mask := addr4, addr6
		if rapid.Bool().Draw(t, "v6 first") {
			addr, mask = addr6, addr4
		}
		network, err := xnetip.IPNetworkFrom(addr, mask)
		require.ErrorIs(t, err, xnetip.ErrAddrFamilyMismatch)
		require.Equal(t, xnetip.IPNetwork{}, network)
	})
}

// verifies that normalization by a contiguous mask agrees with the
// net/netip oracle for masking a prefix, in both families.
func Test_IPNetworkFrom_MatchesNetipMaskedForPrefixMasks(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		var addr, mask netip.Addr
		var bits int
		if rapid.Bool().Draw(t, "is4") {
			addr = genNetipAddr4.Draw(t, "addr4")
			bits = rapid.IntRange(0, 32).Draw(t, "bits")
			mask = netipAddrFrom4Bits(^uint32(0) << (32 - bits))
		} else {
			addr = genNetipAddr6.Draw(t, "addr6")
			bits = rapid.IntRange(0, 128).Draw(t, "bits")
			if bits <= 64 {
				mask = netipAddrFrom6Bits(^uint64(0)<<(64-bits), 0)
			} else {
				mask = netipAddrFrom6Bits(^uint64(0), ^uint64(0)<<(128-bits))
			}
		}
		network, err := xnetip.IPNetworkFrom(addr, mask)
		require.NoError(t, err)
		require.Equal(t, netip.PrefixFrom(addr, bits).Masked().Addr(), network.Addr())
	})
}

// verifies that the pair constructor allocates nothing on the success
// path of either family.
func Test_IPNetworkFrom_AllocationFree(t *testing.T) {
	addr4 := netip.MustParseAddr("192.168.1.1")
	mask4 := netip.MustParseAddr("255.255.0.255")
	addr6 := netip.MustParseAddr("2001:db8::1")
	mask6 := netip.MustParseAddr("ffff:ffff::")
	var err error
	requireNoAllocs(t, func() { ipNetworkSink, err = xnetip.IPNetworkFrom(addr4, mask4) })
	require.NoError(t, err)
	requireNoAllocs(t, func() { ipNetworkSink, err = xnetip.IPNetworkFrom(addr6, mask6) })
	require.NoError(t, err)
}

// verifies that an IPv4 network embeds as its IPv4-mapped IPv6 image
// and an IPv6 network passes through unchanged, whatever its shape.
func Test_IPNetwork_ToIPv6Mapped_EmbedsIntoIPv6Space(t *testing.T) {
	cases := []struct {
		name     string
		network  xnetip.IPNetwork
		wantAddr string
		wantMask string
	}{
		{name: "IPv4 contiguous", network: mustIPNetwork4(t, "192.168.1.0", "255.255.255.0"), wantAddr: "::ffff:c0a8:100", wantMask: "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ff00"},
		{name: "IPv6 identity contiguous", network: mustIPNetwork6(t, "2001:db8::", "ffff:ffff::"), wantAddr: "2001:db8::", wantMask: "ffff:ffff::"},
		{name: "IPv4 universe pins only the mapped prefix", network: mustIPNetwork4(t, "0.0.0.0", "0.0.0.0"), wantAddr: "::ffff:0:0", wantMask: "ffff:ffff:ffff:ffff:ffff:ffff::"},
		{name: "IPv4 host route becomes a /128", network: mustIPNetwork4(t, "10.0.0.1", "255.255.255.255"), wantAddr: "::ffff:a00:1", wantMask: "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"},
		{name: "IPv6 universe identity", network: mustIPNetwork6(t, "::", "::"), wantAddr: "::", wantMask: "::"},
		{name: "IPv6 mapped network stays as is", network: mustIPNetwork6(t, "::ffff:c0a8:100", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ff00"), wantAddr: "::ffff:c0a8:100", wantMask: "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ff00"},
		{name: "IPv4 non-contiguous keeps the low mask hole", network: mustIPNetwork4(t, "192.168.0.1", "255.255.0.255"), wantAddr: "::ffff:c0a8:1", wantMask: "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ff"},
		{name: "IPv6 non-contiguous identity", network: mustIPNetwork6(t, "2a02:6b8:c00::1234:abcd:0:0", "ffff:ffff:ff00::ffff:ffff:0:0"), wantAddr: "2a02:6b8:c00::1234:abcd:0:0", wantMask: "ffff:ffff:ff00::ffff:ffff:0:0"},
		{name: "IPv4 alternating mask carries into the low bits", network: mustIPNetwork4(t, "170.85.170.85", "170.85.170.85"), wantAddr: "::ffff:aa55:aa55", wantMask: "ffff:ffff:ffff:ffff:ffff:ffff:aa55:aa55"},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			mapped := testCase.network.ToIPv6Mapped()
			require.Equal(t, mustIPv6Network(t, testCase.wantAddr, testCase.wantMask), mapped)
		})
	}
}

// verifies that the family-agnostic embedding equals the IPv4 type's
// own embedding for an IPv4 network.
func Test_IPNetwork_ToIPv6Mapped_EqualsIPv4NetworkMethod(t *testing.T) {
	network, err := xnetip.IPv4NetworkFrom(
		netip.MustParseAddr("192.168.1.0"),
		netip.MustParseAddr("255.255.255.0"),
	)
	require.NoError(t, err)
	require.Equal(t, network.ToIPv6Mapped(), xnetip.IPNetworkFrom4(network).ToIPv6Mapped())
}

// verifies that embedding an IPv4 network agrees with the concrete
// method, lands in the mapped range and round-trips back.
func Test_IPNetwork_ToIPv6Mapped_IPv4RoundTripProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		network := genIPv4Network.Draw(t, "network")
		mapped := xnetip.IPNetworkFrom4(network).ToIPv6Mapped()
		require.Equal(t, network.ToIPv6Mapped(), mapped)
		require.True(t, mapped.IsIPv4MappedIPv6())
		recovered, ok := mapped.ToIPv4Mapped()
		require.True(t, ok)
		require.Equal(t, network, recovered)
	})
}

// verifies that embedding an IPv6 network is the identity, whatever
// the mask shape.
func Test_IPNetwork_ToIPv6Mapped_IPv6IdentityProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		network := genIPv6Network.Draw(t, "network")
		require.Equal(t, network, xnetip.IPNetworkFrom6(network).ToIPv6Mapped())
	})
}

// verifies that the address of an embedded IPv4 network unmaps back to
// the original address, with net/netip as the unmapping oracle.
func Test_IPNetwork_ToIPv6Mapped_MatchesNetipUnmap(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		network := genIPv4Network.Draw(t, "network")
		mapped := xnetip.IPNetworkFrom4(network).ToIPv6Mapped()
		require.Equal(t, network.Addr(), mapped.Addr().Unmap())
	})
}

// verifies that the embedding allocates nothing for either family.
func Test_IPNetwork_ToIPv6Mapped_AllocationFree(t *testing.T) {
	network4 := mustIPNetwork4(t, "192.168.1.0", "255.255.255.0")
	network6 := mustIPNetwork6(t, "2001:db8::", "ffff:ffff::")
	requireNoAllocs(t, func() { network6Sink = network4.ToIPv6Mapped() })
	requireNoAllocs(t, func() { network6Sink = network6.ToIPv6Mapped() })
}

// verifies that an IPv4 network and a non-mapped IPv6 network come
// back unchanged while a mapped IPv6 network collapses to IPv4.
func Test_IPNetwork_ToCanonical_CollapsesOnlyMappedIPv6(t *testing.T) {
	cases := []struct {
		name    string
		network xnetip.IPNetwork
		want    xnetip.IPNetwork
	}{
		{name: "IPv4 unchanged", network: mustIPNetwork4(t, "192.168.0.0", "255.255.255.0"), want: mustIPNetwork4(t, "192.168.0.0", "255.255.255.0")},
		{name: "mapped IPv6 contiguous collapses", network: mustIPNetwork6(t, "::ffff:c0a8:100", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ff00"), want: mustIPNetwork4(t, "192.168.1.0", "255.255.255.0")},
		{name: "plain IPv6 unchanged", network: mustIPNetwork6(t, "2001:db8::", "ffff:ffff::"), want: mustIPNetwork6(t, "2001:db8::", "ffff:ffff::")},
		{name: "IPv4-compatible address is not mapped", network: mustIPNetwork6(t, "::c00a:2ff", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"), want: mustIPNetwork6(t, "::c00a:2ff", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff")},
		{name: "mapped address under an unpinned mask stays IPv6", network: mustIPNetwork6(t, "::ffff:c0a8:1", "0:ffff:ffff:ffff:ffff:ffff:ffff:ffff"), want: mustIPNetwork6(t, "::ffff:c0a8:1", "0:ffff:ffff:ffff:ffff:ffff:ffff:ffff")},
		{name: "mapped universe collapses to the IPv4 universe", network: mustIPNetwork6(t, "::ffff:0:0", "ffff:ffff:ffff:ffff:ffff:ffff::"), want: mustIPNetwork4(t, "0.0.0.0", "0.0.0.0")},
		{name: "mapped host route collapses", network: mustIPNetwork6(t, "::ffff:a00:1", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"), want: mustIPNetwork4(t, "10.0.0.1", "255.255.255.255")},
		{name: "mask one bit short of the mapped pin stays IPv6", network: mustIPNetwork6(t, "::ffff:0:0", "ffff:ffff:ffff:ffff:ffff:fffe::"), want: mustIPNetwork6(t, "::fffe:0:0", "ffff:ffff:ffff:ffff:ffff:fffe::")},
		{name: "IPv6 universe unchanged", network: mustIPNetwork6(t, "::", "::"), want: mustIPNetwork6(t, "::", "::")},
		{name: "mapped with non-contiguous low mask collapses", network: mustIPNetwork6(t, "::ffff:c0a8:1", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ff"), want: mustIPNetwork4(t, "192.168.0.1", "255.255.0.255")},
		{name: "hole inside the pinned region stays IPv6", network: mustIPNetwork6(t, "::ffff:c0a8:1", "ffff:0:ffff:ffff:ffff:ffff:ffff:ffff"), want: mustIPNetwork6(t, "::ffff:c0a8:1", "ffff:0:ffff:ffff:ffff:ffff:ffff:ffff")},
		{name: "mapped with alternating low mask collapses", network: mustIPNetwork6(t, "::ffff:aa55:aa55", "ffff:ffff:ffff:ffff:ffff:ffff:aa55:aa55"), want: mustIPNetwork4(t, "170.85.170.85", "170.85.170.85")},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			require.Equal(t, testCase.want, testCase.network.ToCanonical())
		})
	}
}

// verifies that canonicalizing twice equals canonicalizing once, for
// networks of every family and mask shape.
func Test_IPNetwork_ToCanonical_IdempotentProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		network := genIPNetwork.Draw(t, "network")
		canonical := network.ToCanonical()
		require.Equal(t, canonical, canonical.ToCanonical())
	})
}

// verifies that canonicalization preserves the IPv6 embedding: the
// canonical form embeds into the same 128-bit network.
func Test_IPNetwork_ToCanonical_PreservesEmbeddingProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		network := genIPNetwork.Draw(t, "network")
		require.Equal(t, network.ToIPv6Mapped(), network.ToCanonical().ToIPv6Mapped())
	})
}

// verifies that an IPv4 network survives the round trip through its
// mapped IPv6 lift and back through canonicalization.
func Test_IPNetwork_ToCanonical_RoundTripsMappedIPv4Property(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		network := genIPv4Network.Draw(t, "network")
		lifted := xnetip.IPNetworkFrom6(xnetip.IPNetworkFrom4(network).ToIPv6Mapped())
		require.Equal(t, xnetip.IPNetworkFrom4(network), lifted.ToCanonical())
	})
}

// verifies that an IPv6 network collapses exactly when the concrete
// mapped predicate holds, and collapses to the concrete truncation.
func Test_IPNetwork_ToCanonical_AgreesWithConcretePredicateProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		network := genIPv6Network.Draw(t, "network")
		canonical := xnetip.IPNetworkFrom6(network).ToCanonical()
		require.Equal(t, network.IsIPv4MappedIPv6(), canonical.Is4())
		if canonical.Is4() {
			extracted, ok := canonical.IPv4()
			require.True(t, ok)
			truncated, ok := network.ToIPv4Mapped()
			require.True(t, ok)
			require.Equal(t, truncated, extracted)
		}
	})
}

// verifies the address half of the collapse against net/netip: a
// collapsed network's address unmaps to Is4, an unmappable one blocks.
func Test_IPNetwork_ToCanonical_MatchesNetipUnmapOnAddress(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		network := genIPv6Network.Draw(t, "network")
		canonical := xnetip.IPNetworkFrom6(network).ToCanonical()
		if canonical.Is4() {
			require.True(t, network.Addr().Unmap().Is4())
		}
		if !network.Addr().Unmap().Is4() {
			require.True(t, canonical.Is6())
		}
	})
}

// verifies that canonicalization allocates nothing for an IPv4, a
// mapped IPv6 and a plain IPv6 network alike.
func Test_IPNetwork_ToCanonical_AllocationFree(t *testing.T) {
	network4 := mustIPNetwork4(t, "192.168.1.0", "255.255.255.0")
	mapped := mustIPNetwork6(t, "::ffff:c0a8:100", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ff00")
	network6 := mustIPNetwork6(t, "2001:db8::", "ffff:ffff::")
	requireNoAllocs(t, func() { ipNetworkSink = network4.ToCanonical() })
	requireNoAllocs(t, func() { ipNetworkSink = mapped.ToCanonical() })
	requireNoAllocs(t, func() { ipNetworkSink = network6.ToCanonical() })
}

// verifies that every IPv4 network sorts before every IPv6 network
// and that within a family the concrete lexicographic order applies.
func Test_IPNetwork_Compare_FamilyFirstThenConcreteOrder(t *testing.T) {
	cases := []struct {
		name  string
		left  xnetip.IPNetwork
		right xnetip.IPNetwork
		want  int
	}{
		{name: "IPv4 max before IPv6 universe", left: mustIPNetwork4(t, "255.255.255.255", "255.255.255.255"), right: mustIPNetwork6(t, "::", "::"), want: -1},
		{name: "IPv6 universe after IPv4 universe", left: mustIPNetwork6(t, "::", "::"), right: mustIPNetwork4(t, "0.0.0.0", "0.0.0.0"), want: 1},
		{name: "within IPv4 address dominates mask", left: mustIPNetwork4(t, "10.0.0.0", "255.255.255.255"), right: mustIPNetwork4(t, "11.0.0.0", "255.0.0.0"), want: -1},
		{name: "within IPv4 mask decides", left: mustIPNetwork4(t, "10.0.0.0", "255.255.0.0"), right: mustIPNetwork4(t, "10.0.0.0", "255.255.255.0"), want: -1},
		{name: "within IPv6 address dominates mask", left: mustIPNetwork6(t, "2001::", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"), right: mustIPNetwork6(t, "2001:db9::", "ffff:ffff::"), want: -1},
		{name: "within IPv6 mask decides", left: mustIPNetwork6(t, "2001:db8::", "ffff:ffff::"), right: mustIPNetwork6(t, "2001:db8::", "ffff:ffff:ffff:ffff::"), want: -1},
		{name: "IPv4-mapped IPv6 sorts after its IPv4 twin", left: mustIPNetwork4(t, "192.168.1.0", "255.255.255.0"), right: mustIPNetwork6(t, "::ffff:c0a8:100", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ff00"), want: -1},
		{name: "IPv4 non-contiguous mask decides", left: mustIPNetwork4(t, "10.0.0.5", "255.0.0.255"), right: mustIPNetwork4(t, "10.0.0.5", "255.255.0.255"), want: -1},
		{name: "IPv6 non-contiguous mask decides", left: mustIPNetwork6(t, "2001:db8::5", "ffff:ffff:ff00:ff00:ffff:ffff:ffff:ffff"), right: mustIPNetwork6(t, "2001:db8::5", "ffff:ffff:ff00:ffff:ffff:ffff:ffff:ffff"), want: -1},
		{name: "IPv4 non-contiguous still before any IPv6", left: mustIPNetwork4(t, "255.255.255.255", "170.85.170.85"), right: mustIPNetwork6(t, "::", "::"), want: -1},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			require.Equal(t, testCase.want, testCase.left.Compare(testCase.right))
		})
	}
}

// verifies that equal networks of either family compare as zero.
func Test_IPNetwork_Compare_EqualityIsZero(t *testing.T) {
	require.Equal(t, 0, mustIPNetwork4(t, "192.168.1.0", "255.255.255.0").Compare(mustIPNetwork4(t, "192.168.1.0", "255.255.255.0")))
	require.Equal(t, 0, mustIPNetwork6(t, "2001:db8::", "ffff:ffff::").Compare(mustIPNetwork6(t, "2001:db8::", "ffff:ffff::")))
}

// verifies that sorting a mixed fixture yields the family blocks in
// order, each internally sorted by its concrete order.
func Test_IPNetwork_Compare_SortPinsFamilyThenOrder(t *testing.T) {
	shuffled := []xnetip.IPNetwork{
		mustIPNetwork6(t, "2001:db8::", "ffff:ffff::"),
		mustIPNetwork4(t, "10.0.0.0", "255.0.0.0"),
		mustIPNetwork6(t, "::", "::"),
		mustIPNetwork4(t, "0.0.0.0", "0.0.0.0"),
		mustIPNetwork4(t, "10.0.0.5", "255.0.0.255"),
		mustIPNetwork6(t, "::ffff:c0a8:100", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ff00"),
	}
	want := []xnetip.IPNetwork{
		mustIPNetwork4(t, "0.0.0.0", "0.0.0.0"),
		mustIPNetwork4(t, "10.0.0.0", "255.0.0.0"),
		mustIPNetwork4(t, "10.0.0.5", "255.0.0.255"),
		mustIPNetwork6(t, "::", "::"),
		mustIPNetwork6(t, "::ffff:c0a8:100", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ff00"),
		mustIPNetwork6(t, "2001:db8::", "ffff:ffff::"),
	}
	slices.SortFunc(shuffled, xnetip.IPNetwork.Compare)
	require.Equal(t, want, shuffled)
}

// verifies that within a family the lifted order agrees with the
// concrete type's order, the check behind the stored-form compare.
func Test_IPNetwork_Compare_AgreesWithConcreteOrdersProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		if rapid.Bool().Draw(t, "is4") {
			left := genIPv4Network.Draw(t, "left")
			right := genIPv4Network.Draw(t, "right")
			require.Equal(t, left.Compare(right), xnetip.IPNetworkFrom4(left).Compare(xnetip.IPNetworkFrom4(right)))
		} else {
			left := genIPv6Network.Draw(t, "left")
			right := genIPv6Network.Draw(t, "right")
			require.Equal(t, left.Compare(right), xnetip.IPNetworkFrom6(left).Compare(xnetip.IPNetworkFrom6(right)))
		}
	})
}

// verifies the family rule on mixed pairs, antisymmetry, zero exactly
// on equality and transitivity on random triples.
func Test_IPNetwork_Compare_TotalOrderProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		left := genIPNetwork.Draw(t, "left")
		right := genIPNetwork.Draw(t, "right")
		third := genIPNetwork.Draw(t, "third")
		if left.Is4() && right.Is6() {
			require.Equal(t, -1, left.Compare(right))
		}
		if left.Is6() && right.Is4() {
			require.Equal(t, 1, left.Compare(right))
		}
		require.Equal(t, -left.Compare(right), right.Compare(left))
		require.Equal(t, left == right, left.Compare(right) == 0)
		if left.Compare(right) <= 0 && right.Compare(third) <= 0 {
			require.LessOrEqual(t, left.Compare(third), 0)
		}
	})
}

// verifies that sorting a random mixed slice puts every IPv4 network
// before every IPv6 network with each family block sorted.
func Test_IPNetwork_Compare_SortFuncProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		networks := rapid.SliceOfN(genIPNetwork, 0, 32).Draw(t, "networks")
		sorted := slices.Clone(networks)
		slices.SortFunc(sorted, xnetip.IPNetwork.Compare)
		require.True(t, slices.IsSortedFunc(sorted, xnetip.IPNetwork.Compare))
		require.ElementsMatch(t, networks, sorted)
		seenIPv6 := false
		for _, network := range sorted {
			if network.Is6() {
				seenIPv6 = true
			} else {
				require.False(t, seenIPv6, "IPv4 network after an IPv6 one")
			}
		}
	})
}

// verifies that on host routes the order agrees with netip.Addr's
// family-first address order.
func Test_IPNetwork_Compare_MatchesNetipAddrOrderOnHostRoutes(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		var left, right netip.Addr
		if rapid.Bool().Draw(t, "left is4") {
			left = genNetipAddr4.Draw(t, "left4")
		} else {
			left = genNetipAddr6.Draw(t, "left6")
		}
		if rapid.Bool().Draw(t, "right is4") {
			right = genNetipAddr4.Draw(t, "right4")
		} else {
			right = genNetipAddr6.Draw(t, "right6")
		}
		leftRoute, err := xnetip.IPNetworkFromAddr(left)
		require.NoError(t, err)
		rightRoute, err := xnetip.IPNetworkFromAddr(right)
		require.NoError(t, err)
		require.Equal(t, left.Compare(right), leftRoute.Compare(rightRoute))
	})
}

// verifies that comparing allocates nothing for same-family and
// mixed-family pairs alike.
func Test_IPNetwork_Compare_AllocationFree(t *testing.T) {
	network4 := mustIPNetwork4(t, "10.0.0.0", "255.0.0.0")
	other4 := mustIPNetwork4(t, "10.0.0.0", "255.255.255.0")
	network6 := mustIPNetwork6(t, "2001:db8::", "ffff:ffff::")
	requireNoAllocs(t, func() { intSink = network4.Compare(other4) })
	requireNoAllocs(t, func() { intSink = network6.Compare(network6) })
	requireNoAllocs(t, func() { intSink = network4.Compare(network6) })
}

// verifies that contiguity is judged in the network's own family, the
// concrete types' positive and negative pins lifted through the wrap.
func Test_IPNetwork_IsContiguous_JudgedInOwnFamily(t *testing.T) {
	cases := []struct {
		name    string
		network xnetip.IPNetwork
		want    bool
	}{
		{name: "IPv4 universe", network: mustIPNetwork4(t, "0.0.0.0", "0.0.0.0"), want: true},
		{name: "IPv4 /19", network: mustIPNetwork4(t, "213.180.192.0", "255.255.224.0"), want: true},
		{name: "IPv4 host route", network: mustIPNetwork4(t, "10.0.0.1", "255.255.255.255"), want: true},
		{name: "IPv6 universe", network: mustIPNetwork6(t, "::", "::"), want: true},
		{name: "IPv6 /40", network: mustIPNetwork6(t, "2a02:6b8:c00::", "ffff:ffff:ff00::"), want: true},
		{name: "IPv6 run ends at the half boundary", network: mustIPNetwork6(t, "2001:db8::", "ffff:ffff:ffff:ffff::"), want: true},
		{name: "IPv6 run crosses the half boundary", network: mustIPNetwork6(t, "2001:db8::", "ffff:ffff:ffff:ffff:8000::"), want: true},
		{name: "zero value is the IPv6 universe", network: xnetip.IPNetwork{}, want: true},
		{name: "mapped IPv6 with contiguous low mask", network: mustIPNetwork6(t, "::ffff:c0a8:100", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ff00"), want: true},
		{name: "IPv4 top mask bit clear", network: mustIPNetwork4(t, "0.0.0.0", "127.255.255.255"), want: false},
		{name: "IPv4 hole in the third octet", network: mustIPNetwork4(t, "213.180.0.192", "255.255.0.255"), want: false},
		{name: "IPv4 two runs", network: mustIPNetwork4(t, "192.168.0.1", "255.0.255.0"), want: false},
		{name: "IPv4 alternating", network: mustIPNetwork4(t, "170.85.170.85", "170.85.170.85"), want: false},
		{name: "IPv6 two runs", network: mustIPNetwork6(t, "2a02:6b8:c00::f800:0:0", "ffff:ffff:ff00::ffff:ffff:0:0"), want: false},
		{name: "IPv6 hole at bits 64..95", network: mustIPNetwork6(t, "2a02:6b8:0:0:1234:5678::", "ffff:ffff:0:0:ffff:ffff:0:0"), want: false},
		{name: "IPv6 hole straddling bit 64", network: mustIPNetwork6(t, "::", "ffff:ffff:ffff:fffe:8000::"), want: false},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			require.Equal(t, testCase.want, testCase.network.IsContiguous())
		})
	}
}

// verifies that the lifted predicate always equals the concrete IPv4
// one, the equivalence that licenses the branch-free stored form.
func Test_IPNetwork_IsContiguous_AgreesWithIPv4Property(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		network := genIPv4Network.Draw(t, "network")
		require.Equal(t, network.IsContiguous(), xnetip.IPNetworkFrom4(network).IsContiguous())
	})
}

// verifies that the lifted predicate always equals the concrete IPv6
// one.
func Test_IPNetwork_IsContiguous_AgreesWithIPv6Property(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		network := genIPv6Network.Draw(t, "network")
		require.Equal(t, network.IsContiguous(), xnetip.IPNetworkFrom6(network).IsContiguous())
	})
}

// verifies that the predicate agrees with the brute-force scan of the
// family-typed mask bytes, whatever the family.
func Test_IPNetwork_IsContiguous_MatchesBitScanProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		network := genIPNetwork.Draw(t, "network")
		want := true
		seenZero := false
		for _, maskByte := range network.Mask().AsSlice() {
			for idx := range 8 {
				bit := maskByte>>(7-idx)&1 == 1
				if bit && seenZero {
					want = false
				}
				if !bit {
					seenZero = true
				}
			}
		}
		require.Equal(t, want, network.IsContiguous())
	})
}

// verifies that the predicate allocates nothing for either family.
func Test_IPNetwork_IsContiguous_AllocationFree(t *testing.T) {
	network4 := mustIPNetwork4(t, "192.168.0.0", "255.255.0.0")
	network6 := mustIPNetwork6(t, "2001:db8::", "ffff:ffff::")
	requireNoAllocs(t, func() { okSink = network4.IsContiguous() })
	requireNoAllocs(t, func() { okSink = network6.IsContiguous() })
}

// verifies that a contiguous mask reports its family-native prefix
// length.
//
// IPv4 answers 0 through 32 despite the mapped storage, IPv6 answers
// 0 through 128, mapped IPv6 networks included.
func Test_IPNetwork_PrefixLen_FamilyNativeLength(t *testing.T) {
	cases := []struct {
		name    string
		network xnetip.IPNetwork
		want    int
	}{
		{name: "IPv4 /24", network: mustIPNetwork4(t, "192.168.1.0", "255.255.255.0"), want: 24},
		{name: "IPv6 /40", network: mustIPNetwork6(t, "2a02:6b8::", "ffff:ffff:ff00::"), want: 40},
		{name: "IPv6 host route /128", network: mustIPNetwork6(t, "2a02:6b8::1", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"), want: 128},
		{name: "IPv4 universe /0", network: mustIPNetwork4(t, "0.0.0.0", "0.0.0.0"), want: 0},
		{name: "IPv4 host route /32", network: mustIPNetwork4(t, "10.0.0.1", "255.255.255.255"), want: 32},
		{name: "IPv4 single leading bit /1", network: mustIPNetwork4(t, "128.0.0.0", "128.0.0.0"), want: 1},
		{name: "IPv6 universe /0", network: mustIPNetwork6(t, "::", "::"), want: 0},
		{name: "zero value is the IPv6 universe", network: xnetip.IPNetwork{}, want: 0},
		{name: "mapped IPv6 network keeps its 128-bit length", network: mustIPNetwork6(t, "::ffff:8.8.8.0", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ff00"), want: 120},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			prefix, ok := testCase.network.PrefixLen()
			require.True(t, ok)
			require.Equal(t, testCase.want, prefix)
		})
	}
}

// verifies that a non-contiguous mask has no prefix length in either
// family and reports zero.
func Test_IPNetwork_PrefixLen_NonContiguousHasNone(t *testing.T) {
	cases := []struct {
		name    string
		network xnetip.IPNetwork
	}{
		{name: "IPv4 hole in the middle", network: mustIPNetwork4(t, "10.0.0.1", "255.0.0.255")},
		{name: "IPv4 alternating", network: mustIPNetwork4(t, "170.85.170.85", "170.85.170.85")},
		{name: "IPv6 two runs", network: mustIPNetwork6(t, "2001:db8::1", "ffff:ffff::ffff")},
		{name: "IPv6 hole ending at the half boundary", network: mustIPNetwork6(t, "2001:db8::", "ffff:ffff:ff00::ffff:ffff:0:0")},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			prefix, ok := testCase.network.PrefixLen()
			require.False(t, ok)
			require.Zero(t, prefix)
		})
	}
}

// verifies that wrapping an IPv4 network reports exactly the concrete
// IPv4 length, value and presence alike.
//
// The mapped storage width must never leak into the answer.
func Test_IPNetwork_PrefixLen_AgreesWithIPv4Property(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		network := genIPv4Network.Draw(t, "network")
		wantPrefix, wantOk := network.PrefixLen()
		prefix, ok := xnetip.IPNetworkFrom4(network).PrefixLen()
		require.Equal(t, wantOk, ok)
		require.Equal(t, wantPrefix, prefix)
	})
}

// verifies that wrapping an IPv6 network reports exactly the concrete
// IPv6 length, value and presence alike.
func Test_IPNetwork_PrefixLen_AgreesWithIPv6Property(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		network := genIPv6Network.Draw(t, "network")
		wantPrefix, wantOk := network.PrefixLen()
		prefix, ok := xnetip.IPNetworkFrom6(network).PrefixLen()
		require.Equal(t, wantOk, ok)
		require.Equal(t, wantPrefix, prefix)
	})
}

// verifies that a prefix length exists exactly for contiguous masks,
// whatever the family, and that the absent case reports zero.
func Test_IPNetwork_PrefixLen_SomeIffContiguousProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		network := genIPNetwork.Draw(t, "network")
		prefix, ok := network.PrefixLen()
		require.Equal(t, network.IsContiguous(), ok)
		if !ok {
			require.Zero(t, prefix)
		}
	})
}

// verifies that a network built from any address and length in either
// family reports that same family-native length back.
//
// The sweep covers the whole 0 through 32 and 0 through 128 ranges
// every run rather than sampling them.
func Test_IPNetwork_PrefixLen_RoundTripsCIDRProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		addr4 := genNetipAddr4.Draw(t, "addr4")
		for cidr := range 33 {
			network, err := xnetip.IPNetworkFromCIDR(addr4, cidr)
			require.NoError(t, err)
			prefix, ok := network.PrefixLen()
			require.True(t, ok)
			require.Equal(t, cidr, prefix)
		}
		addr6 := genNetipAddr6.Draw(t, "addr6")
		for cidr := range 129 {
			network, err := xnetip.IPNetworkFromCIDR(addr6, cidr)
			require.NoError(t, err)
			prefix, ok := network.PrefixLen()
			require.True(t, ok)
			require.Equal(t, cidr, prefix)
		}
	})
}

// verifies that computing the prefix allocates nothing for either
// family and either outcome.
func Test_IPNetwork_PrefixLen_AllocationFree(t *testing.T) {
	contiguous4 := mustIPNetwork4(t, "192.168.0.0", "255.255.0.0")
	nonContiguous4 := mustIPNetwork4(t, "192.168.0.1", "255.255.0.255")
	contiguous6 := mustIPNetwork6(t, "2001:db8::", "ffff:ffff::")
	nonContiguous6 := mustIPNetwork6(t, "2001:db8::1", "ffff:ffff::ffff")
	requireNoAllocs(t, func() { intSink, okSink = contiguous4.PrefixLen() })
	requireNoAllocs(t, func() { intSink, okSink = nonContiguous4.PrefixLen() })
	requireNoAllocs(t, func() { intSink, okSink = contiguous6.PrefixLen() })
	requireNoAllocs(t, func() { intSink, okSink = nonContiguous6.PrefixLen() })
}

// verifies that a network prints in its own family's text form: IPv4
// unmapped with a family-native suffix, IPv6 as the wrapped network.
func Test_IPNetwork_String_PrintsFamilyForm(t *testing.T) {
	cases := []struct {
		name    string
		network xnetip.IPNetwork
		want    string
	}{
		{name: "IPv4 CIDR", network: mustIPNetwork4(t, "10.0.0.0", "255.0.0.0"), want: "10.0.0.0/8"},
		{name: "IPv6 CIDR", network: mustIPNetwork6(t, "2001:db8::", "ffff:ffff::"), want: "2001:db8::/32"},
		{name: "IPv4 host route keeps /32", network: mustIPNetwork4(t, "127.0.0.1", "255.255.255.255"), want: "127.0.0.1/32"},
		{name: "IPv4 universe hides the stored /96", network: mustIPNetwork4(t, "0.0.0.0", "0.0.0.0"), want: "0.0.0.0/0"},
		{name: "IPv6 universe", network: mustIPNetwork6(t, "::", "::"), want: "::/0"},
		{name: "zero value", network: xnetip.IPNetwork{}, want: "::/0"},
		{name: "IPv6 mapped stays IPv6 text", network: xnetip.IPNetworkFrom6(mustIPv6Network(t, "::ffff:192.0.2.0", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ff00")), want: "::ffff:192.0.2.0/120"},
		{name: "IPv4 wrapped explicitly", network: xnetip.IPNetworkFrom4(mustIPv4Network(t, "192.0.2.0", "255.255.255.0")), want: "192.0.2.0/24"},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			require.Equal(t, testCase.want, testCase.network.String())
		})
	}
}

// verifies that a non-contiguous mask prints in its family's mask
// form, the IPv4 one unmapped from the 128-bit storage.
func Test_IPNetwork_String_NonContiguousUsesMaskForm(t *testing.T) {
	cases := []struct {
		name    string
		network xnetip.IPNetwork
		want    string
	}{
		{name: "IPv4 two-run", network: mustIPNetwork4(t, "192.168.0.1", "255.255.0.255"), want: "192.168.0.1/255.255.0.255"},
		{name: "IPv6 two-run", network: mustIPNetwork6(t, "2a02:6b8:0:0:0:1234::", "ffff:ffff:0:0:ffff:ffff:0:0"), want: "2a02:6b8::1234:0:0/ffff:ffff::ffff:ffff:0:0"},
		{name: "IPv4 alternating", network: mustIPNetwork4(t, "170.85.170.85", "170.85.170.85"), want: "170.85.170.85/170.85.170.85"},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			require.Equal(t, testCase.want, testCase.network.String())
		})
	}
}

// verifies that appending writes after the caller's bytes and leaves
// them intact.
func Test_IPNetwork_AppendTo_KeepsExistingBytes(t *testing.T) {
	network := mustIPNetwork4(t, "10.0.0.0", "255.0.0.0")
	require.Equal(t, "x 10.0.0.0/8", string(network.AppendTo([]byte("x "))))
}

// verifies that wrapping an IPv4 network changes nothing in its text.
func Test_IPNetwork_String_MatchesIPv4Property(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		network := genIPv4Network.Draw(t, "network")
		require.Equal(t, network.String(), xnetip.IPNetworkFrom4(network).String())
	})
}

// verifies that wrapping an IPv6 network changes nothing in its text.
func Test_IPNetwork_String_MatchesIPv6Property(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		network := genIPv6Network.Draw(t, "network")
		require.Equal(t, network.String(), xnetip.IPNetworkFrom6(network).String())
	})
}

// verifies that appending to an empty buffer yields the same bytes the
// string form has, and that drawn buffer content survives untouched.
func Test_IPNetwork_AppendTo_MatchesStringProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		network := genIPNetwork.Draw(t, "network")
		prefix := rapid.SliceOf(rapid.Byte()).Draw(t, "buffer")
		require.Equal(t, network.String(), string(network.AppendTo(nil)))
		extended := network.AppendTo(slices.Clone(prefix))
		require.True(t, bytes.Equal(prefix, extended[:len(prefix)]))
		require.Equal(t, network.String(), string(extended[len(prefix):]))
	})
}

// verifies that appending into a buffer with enough capacity allocates
// nothing for either family, the IPv4 extraction included.
func Test_IPNetwork_AppendTo_AllocationFree(t *testing.T) {
	network4 := mustIPNetwork4(t, "192.168.0.1", "255.255.0.255")
	network6 := mustIPNetwork6(t, "2001:db8::", "ffff:ffff:ff00::ffff:ffff:0:0")
	buffer := make([]byte, 0, 128)
	requireNoAllocs(t, func() { bytesSink = network4.AppendTo(buffer[:0]) })
	requireNoAllocs(t, func() { bytesSink = network6.AppendTo(buffer[:0]) })
}

// verifies that rendering to a string costs exactly the one string
// conversion for either family.
func Test_IPNetwork_String_SingleAllocation(t *testing.T) {
	network4 := mustIPNetwork4(t, "10.0.0.0", "255.0.0.0")
	network6 := mustIPNetwork6(t, "2001:db8::", "ffff:ffff::")
	require.Equal(t, 1, int(testing.AllocsPerRun(100, func() { stringSink = network4.String() })))
	require.Equal(t, 1, int(testing.AllocsPerRun(100, func() { stringSink = network6.String() })))
}

func BenchmarkIPNetwork_String_IPv4(b *testing.B) {
	network := mustIPNetwork4(b, "10.0.0.0", "255.0.0.0")
	b.ReportAllocs()
	for b.Loop() {
		stringSink = network.String()
	}
}

func BenchmarkIPNetwork_String_IPv6(b *testing.B) {
	network := mustIPNetwork6(b, "2001:db8::", "ffff:ffff::")
	b.ReportAllocs()
	for b.Loop() {
		stringSink = network.String()
	}
}

func BenchmarkIPNetwork_AppendTo_IPv4(b *testing.B) {
	network := mustIPNetwork4(b, "10.0.0.0", "255.0.0.0")
	buffer := make([]byte, 0, 32)
	b.ReportAllocs()
	for b.Loop() {
		bytesSink = network.AppendTo(buffer[:0])
	}
}

// verifies that the address part selects the family: every accepted
// form lands on the concrete network of its own family.
func Test_ParseIPNetwork_AcceptsBothFamilies(t *testing.T) {
	cases := []struct {
		name     string
		input    string
		wantAddr string
		wantMask string
		want4    bool
	}{
		{name: "IPv4 CIDR", input: "192.168.1.0/24", wantAddr: "192.168.1.0", wantMask: "255.255.255.0", want4: true},
		{name: "IPv4 /8", input: "10.0.0.0/8", wantAddr: "10.0.0.0", wantMask: "255.0.0.0", want4: true},
		{name: "IPv4 dotted mask", input: "10.0.0.0/255.0.0.0", wantAddr: "10.0.0.0", wantMask: "255.0.0.0", want4: true},
		{name: "IPv4 normalizes host bits", input: "77.88.55.242/16", wantAddr: "77.88.0.0", wantMask: "255.255.0.0", want4: true},
		{name: "bare IPv4 is a host route", input: "192.168.1.1", wantAddr: "192.168.1.1", wantMask: "255.255.255.255", want4: true},
		{name: "IPv6 CIDR", input: "2a02:6b8:c00::/40", wantAddr: "2a02:6b8:c00::", wantMask: "ffff:ffff:ff00::", want4: false},
		{name: "IPv6 /32", input: "2001:db8::/32", wantAddr: "2001:db8::", wantMask: "ffff:ffff::", want4: false},
		{name: "IPv6 full mask", input: "2001:db8::1/ffff:ffff::ffff", wantAddr: "2001:db8::1", wantMask: "ffff:ffff::ffff", want4: false},
		{name: "bare IPv6 is a host route", input: "2001:db8::1", wantAddr: "2001:db8::1", wantMask: "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", want4: false},
		{name: "mapped text with short prefix", input: "::ffff:1.2.3.4/24", wantAddr: "::", wantMask: "ffff:ff00::", want4: false},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			network, err := xnetip.ParseIPNetwork(testCase.input)
			require.NoError(t, err)
			if testCase.want4 {
				require.Equal(t, mustIPNetwork4(t, testCase.wantAddr, testCase.wantMask), network)
			} else {
				require.Equal(t, mustIPNetwork6(t, testCase.wantAddr, testCase.wantMask), network)
			}
		})
	}
}

// verifies that all six documented forms parse and print back to their
// canonical text, the family following the address part.
func Test_ParseIPNetwork_SixDocumentedForms(t *testing.T) {
	cases := []struct {
		name  string
		input string
		want  string
		want4 bool
	}{
		{name: "bare IPv4", input: "77.88.55.242", want: "77.88.55.242/32", want4: true},
		{name: "IPv4 CIDR", input: "77.88.0.0/16", want: "77.88.0.0/16", want4: true},
		{name: "IPv4 dotted mask", input: "77.88.0.0/255.255.0.0", want: "77.88.0.0/16", want4: true},
		{name: "bare IPv6", input: "2a02:6b8::2:242", want: "2a02:6b8::2:242/128", want4: false},
		{name: "IPv6 CIDR", input: "2a02:6b8:c00::/40", want: "2a02:6b8:c00::/40", want4: false},
		{name: "IPv6 colon mask", input: "2a02:6b8:c00::/ffff:ffff:ff00::", want: "2a02:6b8:c00::/40", want4: false},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			network, err := xnetip.ParseIPNetwork(testCase.input)
			require.NoError(t, err)
			require.Equal(t, testCase.want4, network.Is4())
			require.Equal(t, testCase.want, network.String())
		})
	}
}

// verifies that IPv4-mapped text is an IPv6 network, exactly as the
// mapped address itself reports the IPv6 family.
func Test_ParseIPNetwork_MappedTextIsIPv6(t *testing.T) {
	network, err := xnetip.ParseIPNetwork("::ffff:192.0.2.0/120")
	require.NoError(t, err)
	require.True(t, network.Is6())
	_, ok := network.IPv4()
	require.False(t, ok)
	require.Equal(t, "::ffff:192.0.2.0/120", network.String())
}

// verifies that each family's universe parses into its own family: the
// IPv4 one is not the IPv6 zero value and reports a zero prefix.
func Test_ParseIPNetwork_UniversePerFamily(t *testing.T) {
	network4, err := xnetip.ParseIPNetwork("0.0.0.0/0")
	require.NoError(t, err)
	require.True(t, network4.Is4())
	bits, ok := network4.PrefixLen()
	require.True(t, ok)
	require.Equal(t, 0, bits)
	network6, err := xnetip.ParseIPNetwork("::/0")
	require.NoError(t, err)
	require.True(t, network6.Is6())
	require.Equal(t, xnetip.IPNetwork{}, network6)
}

// verifies that a digits-only suffix past the family's own limit is a
// prefix-length overflow in either family.
func Test_ParseIPNetwork_RejectsPrefixOverflow(t *testing.T) {
	cases := []struct {
		name  string
		input string
	}{
		{name: "IPv4 one past the limit", input: "192.168.1.0/33"},
		{name: "IPv6 one past the limit", input: "::/129"},
		{name: "IPv6 with address past the limit", input: "2a02:6b8:c00::/129"},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			network, err := xnetip.ParseIPNetwork(testCase.input)
			require.ErrorIs(t, err, xnetip.ErrCIDROverflow)
			require.Equal(t, xnetip.IPNetwork{}, network)
		})
	}
}

// verifies that the strict prefix grammar and the same-family mask rule
// hold through the family-agnostic entry point.
func Test_ParseIPNetwork_RejectsBadSuffix(t *testing.T) {
	cases := []struct {
		name  string
		input string
	}{
		{name: "IPv4 leading zero in prefix", input: "10.0.0.0/08"},
		{name: "IPv4 plus sign in prefix", input: "10.0.0.0/+8"},
		{name: "IPv6 leading zero in prefix", input: "2001:db8::/032"},
		{name: "IPv6 mask on IPv4 address", input: "10.0.0.1/2001:db8::1"},
		{name: "IPv4 mask on IPv6 address", input: "2001:db8::1/255.255.255.0"},
		{name: "empty suffix", input: "10.0.0.1/"},
		{name: "double slash", input: "10.0.0.1//24"},
		{name: "trailing space in suffix", input: "10.0.0.1/24 "},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			network, err := xnetip.ParseIPNetwork(testCase.input)
			require.ErrorIs(t, err, xnetip.ErrInvalidMask)
			require.Equal(t, xnetip.IPNetwork{}, network)
		})
	}
}

// verifies that a cross-family mask keeps the family sentinel in the
// chain behind the mask sentinel.
func Test_ParseIPNetwork_CrossFamilyMaskKeepsBothSentinels(t *testing.T) {
	_, err := xnetip.ParseIPNetwork("2001:db8::1/255.255.255.0")
	require.ErrorIs(t, err, xnetip.ErrInvalidMask)
	require.ErrorIs(t, err, xnetip.ErrAddrFamilyMismatch)
}

// verifies that text whose address part is no address of either family
// is rejected with the parse sentinel.
func Test_ParseIPNetwork_RejectsBadAddress(t *testing.T) {
	cases := []struct {
		name  string
		input string
	}{
		{name: "empty input", input: ""},
		{name: "lone slash", input: "/"},
		{name: "missing address", input: "/24"},
		{name: "garbage", input: "hello"},
		{name: "garbage with suffix", input: "zz/24"},
		{name: "leading whitespace", input: " 10.0.0.1/24"},
		{name: "port-like suffix", input: "1.2.3.4:80"},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			network, err := xnetip.ParseIPNetwork(testCase.input)
			require.ErrorIs(t, err, xnetip.ErrParse)
			require.Equal(t, xnetip.IPNetwork{}, network)
		})
	}
}

// verifies that a zone suffix is rejected with the zone sentinel
// through the family-agnostic entry point.
func Test_ParseIPNetwork_RejectsZone(t *testing.T) {
	network, err := xnetip.ParseIPNetwork("fe80::1%eth0/64")
	require.ErrorIs(t, err, xnetip.ErrZone)
	require.Equal(t, xnetip.IPNetwork{}, network)
}

// verifies that non-contiguous masks of both families flow through the
// family-agnostic parser verbatim.
func Test_ParseIPNetwork_NonContiguousMasks(t *testing.T) {
	cases := []struct {
		name     string
		input    string
		wantAddr string
		wantMask string
		want4    bool
	}{
		{name: "IPv4 two-run mask", input: "192.168.0.1/255.255.0.255", wantAddr: "192.168.0.1", wantMask: "255.255.0.255", want4: true},
		{name: "IPv4 alternating mask", input: "170.85.170.85/170.85.170.85", wantAddr: "170.85.170.85", wantMask: "170.85.170.85", want4: true},
		{name: "IPv6 geo mask", input: "2a02:6b8:c00::1234:0:0/ffff:ffff:ff00::ffff:ffff:0:0", wantAddr: "2a02:6b8:c00::1234:0:0", wantMask: "ffff:ffff:ff00:0:ffff:ffff::", want4: false},
		{name: "IPv6 alternating groups", input: "2001:0:db8:0:1:0:2:0/ffff:0:ffff:0:ffff:0:ffff:0", wantAddr: "2001:0:db8:0:1:0:2:0", wantMask: "ffff:0:ffff:0:ffff:0:ffff:0", want4: false},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			network, err := xnetip.ParseIPNetwork(testCase.input)
			require.NoError(t, err)
			if testCase.want4 {
				require.Equal(t, mustIPNetwork4(t, testCase.wantAddr, testCase.wantMask), network)
			} else {
				require.Equal(t, mustIPNetwork6(t, testCase.wantAddr, testCase.wantMask), network)
			}
		})
	}
}

// verifies that the must variant panics on invalid input instead of
// returning an error.
func Test_MustParseIPNetwork_PanicsOnInvalidInput(t *testing.T) {
	require.Panics(t, func() { xnetip.MustParseIPNetwork("hello") })
}

// verifies that the must variant passes a valid parse through.
func Test_MustParseIPNetwork_ReturnsParsedNetwork(t *testing.T) {
	network := xnetip.MustParseIPNetwork("10.0.0.0/8")
	require.Equal(t, mustIPNetwork4(t, "10.0.0.0", "255.0.0.0"), network)
}

// verifies that every parse error names this parser and echoes the
// rejected input in quotes.
func Test_ParseIPNetwork_ErrorEchoesInput(t *testing.T) {
	_, err := xnetip.ParseIPNetwork("192.168.1.0/33")
	require.Error(t, err)
	require.True(t, strings.HasPrefix(err.Error(), "xnetip.ParseIPNetwork("))
	require.Contains(t, err.Error(), `"192.168.1.0/33"`)
}

// verifies that the dispatcher never disagrees with the family parsers
// on text either of them accepts.
func Test_ParseIPNetwork_AgreesWithFamilyParsersProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		if rapid.Bool().Draw(t, "is4") {
			text := genIPv4Network.Draw(t, "network4").String()
			concrete, err := xnetip.ParseIPv4Network(text)
			require.NoError(t, err)
			agnostic, err := xnetip.ParseIPNetwork(text)
			require.NoError(t, err)
			require.Equal(t, xnetip.IPNetworkFrom4(concrete), agnostic)
		} else {
			text := genIPv6Network.Draw(t, "network6").String()
			concrete, err := xnetip.ParseIPv6Network(text)
			require.NoError(t, err)
			agnostic, err := xnetip.ParseIPNetwork(text)
			require.NoError(t, err)
			require.Equal(t, xnetip.IPNetworkFrom6(concrete), agnostic)
		}
	})
}

// verifies that parsing the string form recovers the network exactly,
// family flag included.
func Test_ParseIPNetwork_StringRoundTripProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		network := genIPNetwork.Draw(t, "network")
		parsed, err := xnetip.ParseIPNetwork(network.String())
		require.NoError(t, err)
		require.Equal(t, network, parsed)
	})
}

// verifies that the dispatcher rejects a string exactly when both
// family parsers reject it, and never panics on any byte string.
func Test_ParseIPNetwork_RejectAgreementProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		input := string(rapid.SliceOfN(rapid.Byte(), 0, 60).Draw(t, "input"))
		_, err := xnetip.ParseIPNetwork(input)
		_, err4 := xnetip.ParseIPv4Network(input)
		_, err6 := xnetip.ParseIPv6Network(input)
		require.Equal(t, err4 != nil && err6 != nil, err != nil)
	})
}

// verifies that on CIDR-shaped text of either family the accept set,
// the family and the parsed value are those of the std prefix parser.
func Test_ParseIPNetwork_MatchesNetipParsePrefixProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		var addr netip.Addr
		if rapid.Bool().Draw(t, "is4") {
			addr = genNetipAddr4.Draw(t, "addr4")
		} else {
			addr = genNetipAddr6.Draw(t, "addr6")
		}
		limit := 140
		input := addr.String() + "/" + strconv.Itoa(rapid.IntRange(0, limit).Draw(t, "bits"))
		parsed, err := xnetip.ParseIPNetwork(input)
		stdPrefix, stdErr := netip.ParsePrefix(input)
		if stdErr != nil {
			require.Error(t, err)
			return
		}
		require.NoError(t, err)
		require.Equal(t, stdPrefix.Addr().Is4(), parsed.Is4())
		require.Equal(t, stdPrefix.Masked().Addr(), parsed.Addr())
		bits, ok := parsed.PrefixLen()
		require.True(t, ok)
		require.Equal(t, stdPrefix.Bits(), bits)
	})
}

// verifies that accepting a network of either family allocates
// nothing: the input is only ever sliced, never copied.
func Test_ParseIPNetwork_AllocationFree(t *testing.T) {
	requireNoAllocs(t, func() { ipNetworkSink, errSink = xnetip.ParseIPNetwork("10.0.0.0/8") })
	requireNoAllocs(t, func() { ipNetworkSink, errSink = xnetip.ParseIPNetwork("2001:db8::/32") })
}

func FuzzParseIPNetwork(f *testing.F) {
	seeds := []string{
		"192.168.1.0/24", "10.0.0.0/8", "10.0.0.0/255.0.0.0", "77.88.55.242/16",
		"192.168.1.1", "2a02:6b8:c00::/40", "2001:db8::/32", "2001:db8::1/ffff:ffff::ffff",
		"2001:db8::1", "2a02:6b8::2:242", "77.88.0.0/255.255.0.0", "2a02:6b8:c00::/ffff:ffff:ff00::",
		"::ffff:192.0.2.0/120", "::ffff:1.2.3.4/24", "0.0.0.0/0", "::/0",
		"192.168.1.0/33", "::/129", "2a02:6b8:c00::/129", "10.0.0.0/08", "10.0.0.0/+8",
		"2001:db8::/032", "10.0.0.1/2001:db8::1", "2001:db8::1/255.255.255.0",
		"", "/", "10.0.0.1/", "/24", "10.0.0.1//24", "hello", "zz/24",
		" 10.0.0.1/24", "10.0.0.1/24 ", "fe80::1%eth0/64", "1.2.3.4:80",
		"192.168.0.1/255.255.0.255", "170.85.170.85/170.85.170.85",
		"2a02:6b8:c00::1234:0:0/ffff:ffff:ff00::ffff:ffff:0:0",
		"2001:0:db8:0:1:0:2:0/ffff:0:ffff:0:ffff:0:ffff:0",
	}
	for _, seed := range seeds {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, input string) {
		network, err := xnetip.ParseIPNetwork(input)
		if err == nil {
			back, err := xnetip.ParseIPNetwork(network.String())
			if err != nil {
				t.Fatalf("round trip of %q rejected %q: %v", input, network.String(), err)
			}
			if back != network {
				t.Fatalf("round trip of %q changed the network: %v != %v", input, back, network)
			}
			addrText, _, _ := strings.Cut(input, "/")
			addr, err := netip.ParseAddr(addrText)
			if err != nil {
				t.Fatalf("accepted %q, whose address part %q std rejects", input, addrText)
			}
			if addr.Is4() != network.Is4() {
				t.Fatalf("parsed %q into the wrong family", input)
			}
		}
		slash := strings.IndexByte(input, '/')
		if slash < 0 || strings.IndexByte(input[slash+1:], '/') >= 0 || !digitsOnly(input[slash+1:]) {
			return
		}
		stdPrefix, stdErr := netip.ParsePrefix(input)
		if stdErr != nil {
			if err == nil {
				t.Fatalf("accepted %q, which std rejects", input)
			}
			return
		}
		if err != nil {
			t.Fatalf("rejected %q, which std accepts: %v", input, err)
		}
		if bits, ok := network.PrefixLen(); !ok || bits != stdPrefix.Bits() || network.Addr() != stdPrefix.Masked().Addr() {
			t.Fatalf("parsed %q as %v, std says %v", input, network, stdPrefix.Masked())
		}
	})
}

func BenchmarkParseIPNetwork_IPv4CIDR(b *testing.B) {
	b.ReportAllocs()
	for b.Loop() {
		ipNetworkSink, errSink = xnetip.ParseIPNetwork("10.0.0.0/8")
	}
}

func BenchmarkParseIPNetwork_IPv6CIDR(b *testing.B) {
	b.ReportAllocs()
	for b.Loop() {
		ipNetworkSink, errSink = xnetip.ParseIPNetwork("2001:db8::/32")
	}
}

func BenchmarkParseIPNetwork_IPv4Bare(b *testing.B) {
	b.ReportAllocs()
	for b.Loop() {
		ipNetworkSink, errSink = xnetip.ParseIPNetwork("10.0.0.1")
	}
}

func BenchmarkParseIPNetwork_Reject(b *testing.B) {
	b.ReportAllocs()
	for b.Loop() {
		ipNetworkSink, errSink = xnetip.ParseIPNetwork("hello")
	}
}

// verifies that the marshaled text is the string form in the network's
// own family: the IPv4-mapped storage form never leaks.
func Test_IPNetwork_MarshalText_MatchesStringForm(t *testing.T) {
	cases := []struct {
		name  string
		input string
		want  string
	}{
		{name: "IPv4 prints in dotted form", input: "77.88.0.0/16", want: "77.88.0.0/16"},
		{name: "IPv4 host route keeps the suffix", input: "77.88.55.242", want: "77.88.55.242/32"},
		{name: "IPv6 prefix", input: "2a02:6b8:c00::/40", want: "2a02:6b8:c00::/40"},
		{name: "IPv6 host route", input: "2a02:6b8::2:242", want: "2a02:6b8::2:242/128"},
		{name: "IPv4 universe is not the mapped form", input: "0.0.0.0/0", want: "0.0.0.0/0"},
		{name: "IPv4 dotted contiguous mask contracts", input: "77.88.0.0/255.255.0.0", want: "77.88.0.0/16"},
		{name: "IPv4 non-contiguous mask", input: "10.0.0.0/255.0.255.0", want: "10.0.0.0/255.0.255.0"},
		{name: "IPv6 non-contiguous mask", input: "2a02:6b8:c00::1234:0:0/ffff:ffff:ff00::ffff:ffff:0:0", want: "2a02:6b8:c00::1234:0:0/ffff:ffff:ff00:0:ffff:ffff::"},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			text, err := xnetip.MustParseIPNetwork(testCase.input).MarshalText()
			require.NoError(t, err)
			require.Equal(t, testCase.want, string(text))
		})
	}
}

// verifies that the zero value marshals as the IPv6 universe.
func Test_IPNetwork_MarshalText_ZeroValueIsIPv6Universe(t *testing.T) {
	text, err := xnetip.IPNetwork{}.MarshalText()
	require.NoError(t, err)
	require.Equal(t, "::/0", string(text))
}

// verifies that unmarshaling detects the family from the address part
// and lands on the concrete network of that family.
func Test_IPNetwork_UnmarshalText_SetsFamilyFromText(t *testing.T) {
	cases := []struct {
		name     string
		input    string
		wantAddr string
		wantMask string
		want4    bool
	}{
		{name: "IPv4 text sets the IPv4 family", input: "192.168.0.0/24", wantAddr: "192.168.0.0", wantMask: "255.255.255.0", want4: true},
		{name: "IPv6 text", input: "2001:db8::/32", wantAddr: "2001:db8::", wantMask: "ffff:ffff::", want4: false},
		{name: "IPv4 non-contiguous mask sets the IPv4 family", input: "10.0.0.1/255.0.0.255", wantAddr: "10.0.0.1", wantMask: "255.0.0.255", want4: true},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			var network xnetip.IPNetwork
			require.NoError(t, network.UnmarshalText([]byte(testCase.input)))
			if testCase.want4 {
				require.Equal(t, mustIPNetwork4(t, testCase.wantAddr, testCase.wantMask), network)
			} else {
				require.Equal(t, mustIPNetwork6(t, testCase.wantAddr, testCase.wantMask), network)
			}
		})
	}
}

// verifies that IPv4-mapped text unmarshals as an IPv6 network, never
// collapsing into the IPv4 family.
func Test_IPNetwork_UnmarshalText_MappedTextIsIPv6(t *testing.T) {
	var network xnetip.IPNetwork
	require.NoError(t, network.UnmarshalText([]byte("::ffff:10.0.0.0/104")))
	require.True(t, network.Is6())
	_, ok := network.IPv4()
	require.False(t, ok)
}

// verifies that empty text is an error, because the zero value is the
// valid universe network and must not appear out of a missing field.
func Test_IPNetwork_UnmarshalText_EmptyTextIsError(t *testing.T) {
	network := xnetip.MustParseIPNetwork("10.0.0.0/8")
	err := network.UnmarshalText(nil)
	require.ErrorIs(t, err, xnetip.ErrEmptyInput)
	require.Equal(t, xnetip.MustParseIPNetwork("10.0.0.0/8"), network)
}

// verifies that a failed unmarshal reports the parser's sentinel and
// leaves the receiver untouched.
func Test_IPNetwork_UnmarshalText_KeepsReceiverOnError(t *testing.T) {
	cases := []struct {
		name     string
		input    string
		sentinel error
	}{
		{name: "zone", input: "fe80::1%eth0/64", sentinel: xnetip.ErrZone},
		{name: "cross-family mask", input: "1.2.3.4/ffff::", sentinel: xnetip.ErrInvalidMask},
		{name: "prefix overflow", input: "10.0.0.0/33", sentinel: xnetip.ErrCIDROverflow},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			network := xnetip.MustParseIPNetwork("192.168.0.0/24")
			err := network.UnmarshalText([]byte(testCase.input))
			require.ErrorIs(t, err, testCase.sentinel)
			require.Equal(t, xnetip.MustParseIPNetwork("192.168.0.0/24"), network)
		})
	}
}

// verifies that a slice mixing both families round-trips through JSON
// with each element's family preserved.
func Test_IPNetwork_MarshalText_JSONMixedFamilies(t *testing.T) {
	value := []xnetip.IPNetwork{
		xnetip.MustParseIPNetwork("10.0.0.0/8"),
		xnetip.MustParseIPNetwork("2001:db8::/32"),
	}
	encoded, err := json.Marshal(value)
	require.NoError(t, err)
	require.Equal(t, `["10.0.0.0/8","2001:db8::/32"]`, string(encoded))
	var decoded []xnetip.IPNetwork
	require.NoError(t, json.Unmarshal(encoded, &decoded))
	require.Equal(t, value, decoded)
	require.True(t, decoded[0].Is4())
	require.True(t, decoded[1].Is6())
}

// verifies that the type works as a JSON map key, which encoding/json
// routes through the text marshaler pair.
func Test_IPNetwork_MarshalText_JSONMapKeyRoundTrip(t *testing.T) {
	value := map[xnetip.IPNetwork]int{xnetip.MustParseIPNetwork("10.0.0.0/8"): 1}
	encoded, err := json.Marshal(value)
	require.NoError(t, err)
	require.Equal(t, `{"10.0.0.0/8":1}`, string(encoded))
	var decoded map[xnetip.IPNetwork]int
	require.NoError(t, json.Unmarshal(encoded, &decoded))
	require.Equal(t, value, decoded)
}

// verifies that unmarshaling the marshaled text recovers the network
// exactly, the family flag included.
func Test_IPNetwork_MarshalText_RoundTripProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		network := genIPNetwork.Draw(t, "network")
		text, err := network.MarshalText()
		require.NoError(t, err)
		require.Equal(t, []byte(network.String()), text)
		var back xnetip.IPNetwork
		require.NoError(t, back.UnmarshalText(text))
		require.Equal(t, network, back)
	})
}

// verifies that the family-agnostic text never differs from the
// concrete type's text for the same network.
func Test_IPNetwork_MarshalText_AgreesWithConcreteTypesProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		if rapid.Bool().Draw(t, "is4") {
			network := genIPv4Network.Draw(t, "network4")
			concreteText, err := network.MarshalText()
			require.NoError(t, err)
			agnosticText, err := xnetip.IPNetworkFrom4(network).MarshalText()
			require.NoError(t, err)
			require.Equal(t, concreteText, agnosticText)
		} else {
			network := genIPv6Network.Draw(t, "network6")
			concreteText, err := network.MarshalText()
			require.NoError(t, err)
			agnosticText, err := xnetip.IPNetworkFrom6(network).MarshalText()
			require.NoError(t, err)
			require.Equal(t, concreteText, agnosticText)
		}
	})
}

// verifies that a JSON round trip of a slice mixing families preserves
// every element for every mask shape.
func Test_IPNetwork_MarshalText_JSONRoundTripProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		value := rapid.SliceOfN(genIPNetwork, 0, 8).Draw(t, "networks")
		encoded, err := json.Marshal(value)
		require.NoError(t, err)
		var decoded []xnetip.IPNetwork
		require.NoError(t, json.Unmarshal(encoded, &decoded))
		if len(value) == 0 {
			require.Empty(t, decoded)
			return
		}
		require.Equal(t, value, decoded)
	})
}

// verifies that on contiguous networks of either family the marshaled
// text is byte-identical to the netip prefix marshaling.
func Test_IPNetwork_MarshalText_MatchesNetipPrefixProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		network := genIPNetwork.Draw(t, "network")
		bits, ok := network.PrefixLen()
		if !ok {
			return
		}
		stdText, err := netip.PrefixFrom(network.Addr(), bits).MarshalText()
		require.NoError(t, err)
		text, err := network.MarshalText()
		require.NoError(t, err)
		require.Equal(t, stdText, text)
	})
}

// verifies the deliberate divergence from std: empty text unmarshals
// into a zero netip prefix but is an error here.
//
// The zero netip prefix is invalid and safe to produce, while the zero
// network here is the whole IPv6 universe.
func Test_IPNetwork_UnmarshalText_EmptyTextDivergesFromNetip(t *testing.T) {
	var stdPrefix netip.Prefix
	require.NoError(t, stdPrefix.UnmarshalText(nil))
	var network xnetip.IPNetwork
	require.Error(t, network.UnmarshalText(nil))
}

// verifies that marshaling allocates exactly the returned slice in
// both families.
func Test_IPNetwork_MarshalText_SingleAllocation(t *testing.T) {
	network4 := xnetip.MustParseIPNetwork("10.0.0.0/8")
	network6 := xnetip.MustParseIPNetwork("2001:db8::/32")
	require.Equal(t, 1, int(testing.AllocsPerRun(100, func() { bytesSink, errSink = network4.MarshalText() })))
	require.Equal(t, 1, int(testing.AllocsPerRun(100, func() { bytesSink, errSink = network6.MarshalText() })))
}
