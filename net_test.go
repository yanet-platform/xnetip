package xnetip_test

import (
	"encoding/binary"
	"net/netip"
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

// mustIPNetwork4 builds the IPNetwork of an Is4 address and mask pair
// given in string form, stopping the test on any constructor error.
func mustIPNetwork4(t require.TestingT, addr, mask string) xnetip.IPNetwork {
	if helper, ok := t.(interface{ Helper() }); ok {
		helper.Helper()
	}
	network, err := xnetip.IPNetworkFrom(netip.MustParseAddr(addr), netip.MustParseAddr(mask))
	require.NoError(t, err)
	require.True(t, network.Is4())
	return network
}

// mustIPNetwork6 builds the IPNetwork of an Is6 address and mask pair
// given in string form, stopping the test on any constructor error.
func mustIPNetwork6(t require.TestingT, addr, mask string) xnetip.IPNetwork {
	if helper, ok := t.(interface{ Helper() }); ok {
		helper.Helper()
	}
	network, err := xnetip.IPNetworkFrom(netip.MustParseAddr(addr), netip.MustParseAddr(mask))
	require.NoError(t, err)
	require.True(t, network.Is6())
	return network
}

// mustIPv6Network builds an IPv6Network from an address and mask pair
// given in string form, stopping the test on any constructor error.
func mustIPv6Network(t require.TestingT, addr, mask string) xnetip.IPv6Network {
	if helper, ok := t.(interface{ Helper() }); ok {
		helper.Helper()
	}
	network, err := xnetip.IPv6NetworkFrom(netip.MustParseAddr(addr), netip.MustParseAddr(mask))
	require.NoError(t, err)
	return network
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
