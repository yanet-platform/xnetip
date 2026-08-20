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
