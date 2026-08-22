package xnetip_test

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"math/bits"
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
func Test_NetworkFrom4_RoundTripsThroughIPv4(t *testing.T) {
	network4, err := xnetip.Network4From(
		netip.MustParseAddr("192.168.1.0"),
		netip.MustParseAddr("255.255.255.0"),
	)
	require.NoError(t, err)
	wrapped := xnetip.NetworkFrom4(network4)
	require.True(t, wrapped.Is4())
	require.False(t, wrapped.Is6())
	extracted, ok := wrapped.IPv4()
	require.True(t, ok)
	require.Equal(t, network4, extracted)
	rejected, ok := wrapped.IPv6()
	require.False(t, ok)
	require.Equal(t, xnetip.Network6{}, rejected)
}

// verifies that wrapping an IPv6 network reports the IPv6 family,
// round-trips through the IPv6 extractor and declines the IPv4 one.
func Test_NetworkFrom6_RoundTripsThroughIPv6(t *testing.T) {
	network6, err := xnetip.Network6From(
		netip.MustParseAddr("2001:db8::"),
		netip.MustParseAddr("ffff:ffff::"),
	)
	require.NoError(t, err)
	wrapped := xnetip.NetworkFrom6(network6)
	require.True(t, wrapped.Is6())
	require.False(t, wrapped.Is4())
	extracted, ok := wrapped.IPv6()
	require.True(t, ok)
	require.Equal(t, network6, extracted)
	rejected, ok := wrapped.IPv4()
	require.False(t, ok)
	require.Equal(t, xnetip.Network4{}, rejected)
}

// verifies that an IPv4-mapped IPv6 network stays IPv6 when wrapped,
// the way an IPv4-mapped netip.Addr reports Is6 and not Is4.
func Test_NetworkFrom6_KeepsMappedNetworkIPv6(t *testing.T) {
	mapped, err := xnetip.Network6From(
		netip.MustParseAddr("::ffff:192.168.1.0"),
		netip.MustParseAddr("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ff00"),
	)
	require.NoError(t, err)
	wrapped := xnetip.NetworkFrom6(mapped)
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
func Test_Network_Addr_IPv4(t *testing.T) {
	network4, err := xnetip.Network4From(
		netip.MustParseAddr("192.168.1.0"),
		netip.MustParseAddr("255.255.255.0"),
	)
	require.NoError(t, err)
	addr := xnetip.NetworkFrom4(network4).Addr()
	require.Equal(t, netip.MustParseAddr("192.168.1.0"), addr)
	require.True(t, addr.Is4())
}

// verifies that the address accessor of an IPv6 network returns the
// Is6 view of the stored address.
func Test_Network_Addr_IPv6(t *testing.T) {
	network6, err := xnetip.Network6From(
		netip.MustParseAddr("2001:db8::"),
		netip.MustParseAddr("ffff:ffff::"),
	)
	require.NoError(t, err)
	addr := xnetip.NetworkFrom6(network6).Addr()
	require.Equal(t, netip.MustParseAddr("2001:db8::"), addr)
	require.True(t, addr.Is6())
}

// verifies that the mask accessor of an IPv4 network returns the
// unmapped Is4 view of the stored mask.
func Test_Network_Mask_IPv4(t *testing.T) {
	network4, err := xnetip.Network4From(
		netip.MustParseAddr("10.0.0.0"),
		netip.MustParseAddr("255.0.0.0"),
	)
	require.NoError(t, err)
	mask := xnetip.NetworkFrom4(network4).Mask()
	require.Equal(t, netip.MustParseAddr("255.0.0.0"), mask)
	require.True(t, mask.Is4())
}

// verifies that the mask accessor of an IPv6 network returns the Is6
// view of the stored mask.
func Test_Network_Mask_IPv6(t *testing.T) {
	network6, err := xnetip.Network6From(
		netip.MustParseAddr("2001:db8::"),
		netip.MustParseAddr("ffff:ffff::"),
	)
	require.NoError(t, err)
	mask := xnetip.NetworkFrom6(network6).Mask()
	require.Equal(t, netip.MustParseAddr("ffff:ffff::"), mask)
	require.True(t, mask.Is6())
}

// verifies that a non-contiguous IPv4 mask and the address bits it
// keeps come back verbatim through the family-agnostic accessors.
func Test_Network_Mask_NonContiguousIPv4(t *testing.T) {
	network4, err := xnetip.Network4From(
		netip.MustParseAddr("192.168.0.1"),
		netip.MustParseAddr("255.255.0.255"),
	)
	require.NoError(t, err)
	wrapped := xnetip.NetworkFrom4(network4)
	require.Equal(t, netip.MustParseAddr("255.255.0.255"), wrapped.Mask())
	require.Equal(t, netip.MustParseAddr("192.168.0.1"), wrapped.Addr())
}

// verifies that a non-contiguous IPv6 mask with a hole spanning the
// 64-bit half boundary comes back verbatim through the mask accessor.
func Test_Network_Mask_NonContiguousIPv6(t *testing.T) {
	network6, err := xnetip.Network6From(
		netip.MustParseAddr("2001:db8::1"),
		netip.MustParseAddr("ffff:ffff::ffff:ffff:0:0"),
	)
	require.NoError(t, err)
	wrapped := xnetip.NetworkFrom6(network6)
	require.Equal(t, netip.MustParseAddr("ffff:ffff::ffff:ffff:0:0"), wrapped.Mask())
}

// verifies that the alternating-bit mask, the extreme non-contiguous
// shape, survives the wrap and extract cycle bit for bit.
func Test_NetworkFrom4_AlternatingMaskRoundTrips(t *testing.T) {
	network4, err := xnetip.Network4From(
		netip.MustParseAddr("170.85.170.85"),
		netip.MustParseAddr("170.85.170.85"),
	)
	require.NoError(t, err)
	extracted, ok := xnetip.NetworkFrom4(network4).IPv4()
	require.True(t, ok)
	require.Equal(t, network4, extracted)
}

// verifies that the zero value is the IPv6 network ::/0, giving the
// family-agnostic type a valid default like the concrete types have.
func Test_Network_ZeroValue_IsUnspecifiedNetwork6(t *testing.T) {
	var network xnetip.Network
	require.True(t, network.Is6())
	require.False(t, network.Is4())
	extracted, ok := network.IPv6()
	require.True(t, ok)
	require.Equal(t, xnetip.Network6{}, extracted)
	require.Equal(t, netip.MustParseAddr("::"), network.Addr())
	require.Equal(t, netip.MustParseAddr("::"), network.Mask())
}

// verifies that the conversion method on the IPv4 network type builds
// the same value as the corresponding constructor.
func Test_Network4_Network_EqualsConstructor(t *testing.T) {
	network4, err := xnetip.Network4From(
		netip.MustParseAddr("192.168.1.0"),
		netip.MustParseAddr("255.255.255.0"),
	)
	require.NoError(t, err)
	require.Equal(t, xnetip.NetworkFrom4(network4), network4.Network())
}

// verifies that the conversion method on the IPv6 network type builds
// the same value as the corresponding constructor.
func Test_Network6_Network_EqualsConstructor(t *testing.T) {
	network6, err := xnetip.Network6From(
		netip.MustParseAddr("2001:db8::"),
		netip.MustParseAddr("ffff:ffff::"),
	)
	require.NoError(t, err)
	require.Equal(t, xnetip.NetworkFrom6(network6), network6.Network())
}

// verifies that wrapped networks compare with == and the family flag
// splits an IPv4 network from the IPv6 image sharing its storage.
func Test_Network_Equality_DistinguishesFamilies(t *testing.T) {
	universe4, err := xnetip.Network4From(
		netip.MustParseAddr("0.0.0.0"),
		netip.MustParseAddr("0.0.0.0"),
	)
	require.NoError(t, err)
	first := xnetip.NetworkFrom4(universe4)
	second := xnetip.NetworkFrom4(universe4)
	require.Equal(t, first, second)
	mappedImage, err := xnetip.Network6From(
		netip.MustParseAddr("::ffff:0:0"),
		netip.MustParseAddr("ffff:ffff:ffff:ffff:ffff:ffff::"),
	)
	require.NoError(t, err)
	require.NotEqual(t, xnetip.NetworkFrom4(universe4), xnetip.NetworkFrom6(mappedImage))
}

// verifies that wrapping and extracting an IPv4 network is the
// identity for every mask shape.
//
// The property also exercises the mapped-storage invariant: a wrap
// whose stored form were not IPv4-mapped could not extract back into
// the network it came from.
func Test_NetworkFrom4_RoundTripProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		network := genNetwork4.Draw(t, "network")
		wrapped := xnetip.NetworkFrom4(network)
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
func Test_NetworkFrom6_RoundTripProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		network := genNetwork6.Draw(t, "network")
		wrapped := xnetip.NetworkFrom6(network)
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
func Test_Network_Accessors_AgreeWithNetwork4(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		network := genNetwork4.Draw(t, "network")
		wrapped := xnetip.NetworkFrom4(network)
		require.Equal(t, network.Addr(), wrapped.Addr())
		require.Equal(t, network.Mask(), wrapped.Mask())
	})
}

// verifies that the family-agnostic accessors return exactly the
// address and mask of the wrapped IPv6 network, for every mask shape.
func Test_Network_Accessors_AgreeWithNetwork6(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		network := genNetwork6.Draw(t, "network")
		wrapped := xnetip.NetworkFrom6(network)
		require.Equal(t, network.Addr(), wrapped.Addr())
		require.Equal(t, network.Mask(), wrapped.Mask())
	})
}

// verifies that every drawn family-agnostic network is coherent.
//
// The family flags are complementary, exactly the matching extractor
// succeeds and the accessors answer in the network's own family.
func Test_Network_FamilyViews_Coherent(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		network := genNetwork.Draw(t, "network")
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
func Test_Network_Constructors_AllocationFree(t *testing.T) {
	network4, err := xnetip.Network4From(
		netip.MustParseAddr("192.168.1.0"),
		netip.MustParseAddr("255.255.0.255"),
	)
	require.NoError(t, err)
	network6, err := xnetip.Network6From(
		netip.MustParseAddr("2001:db8::"),
		netip.MustParseAddr("ffff:0:ffff::"),
	)
	require.NoError(t, err)
	requireNoAllocs(t, func() { ipNetworkSink = xnetip.NetworkFrom4(network4) })
	requireNoAllocs(t, func() { ipNetworkSink = xnetip.NetworkFrom6(network6) })
}

// verifies that the extractors and the address and mask accessors
// perform no allocation in either family.
func Test_Network_Accessors_AllocationFree(t *testing.T) {
	network4, err := xnetip.Network4From(
		netip.MustParseAddr("192.168.1.0"),
		netip.MustParseAddr("255.255.0.255"),
	)
	require.NoError(t, err)
	network6, err := xnetip.Network6From(
		netip.MustParseAddr("2001:db8::"),
		netip.MustParseAddr("ffff:0:ffff::"),
	)
	require.NoError(t, err)
	wrapped4 := xnetip.NetworkFrom4(network4)
	wrapped6 := xnetip.NetworkFrom6(network6)
	requireNoAllocs(t, func() { networkSink, okSink = wrapped4.IPv4() })
	requireNoAllocs(t, func() { network6Sink, okSink = wrapped6.IPv6() })
	requireNoAllocs(t, func() { addrSink = wrapped4.Addr() })
	requireNoAllocs(t, func() { addrSink = wrapped6.Addr() })
	requireNoAllocs(t, func() { addrSink = wrapped4.Mask() })
	requireNoAllocs(t, func() { addrSink = wrapped6.Mask() })
}

// verifies that the CIDR constructor dispatches on the address family
// and equals the same-family typed construction, views included.
func Test_NetworkFromCIDR_DispatchesByFamily(t *testing.T) {
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
			network, err := xnetip.NetworkFromCIDR(addr, testCase.bits)
			require.NoError(t, err)
			require.Equal(t, testCase.wantIs4, network.Is4())
			require.Equal(t, !testCase.wantIs4, network.Is6())
			require.Equal(t, netip.MustParseAddr(testCase.wantAddr), network.Addr())
			require.Equal(t, netip.MustParseAddr(testCase.wantMask), network.Mask())
			if testCase.wantIs4 {
				typed, typedErr := xnetip.Network4FromCIDR(addr, testCase.bits)
				require.NoError(t, typedErr)
				require.Equal(t, xnetip.NetworkFrom4(typed), network)
			} else {
				typed, typedErr := xnetip.Network6FromCIDR(addr, testCase.bits)
				require.NoError(t, typedErr)
				require.Equal(t, xnetip.NetworkFrom6(typed), network)
			}
		})
	}
}

// verifies that the length limit is the family's own: 33 overflows
// IPv4, 129 IPv6, 64 splits the two and negatives overflow both.
func Test_NetworkFromCIDR_FamilySetsTheLimit(t *testing.T) {
	cases := []struct {
		name      string
		addr      string
		bits      int
		wantError string
	}{
		{
			name:      "IPv4 33 overflows",
			addr:      "192.168.1.5",
			bits:      33,
			wantError: `xnetip.NetworkFromCIDR("192.168.1.5/33"): prefix length out of range`,
		},
		{
			name:      "IPv6 129 overflows",
			addr:      "2001:db8::1",
			bits:      129,
			wantError: `xnetip.NetworkFromCIDR("2001:db8::1/129"): prefix length out of range`,
		},
		{
			name:      "IPv4 64 overflows",
			addr:      "192.168.1.5",
			bits:      64,
			wantError: `xnetip.NetworkFromCIDR("192.168.1.5/64"): prefix length out of range`,
		},
		{name: "IPv6 64 is valid", addr: "2001:db8::1", bits: 64},
		{
			name:      "IPv4 negative overflows",
			addr:      "192.168.1.5",
			bits:      -1,
			wantError: `xnetip.NetworkFromCIDR("192.168.1.5/-1"): prefix length out of range`,
		},
		{
			name:      "IPv6 negative overflows",
			addr:      "2001:db8::1",
			bits:      -1,
			wantError: `xnetip.NetworkFromCIDR("2001:db8::1/-1"): prefix length out of range`,
		},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			network, err := xnetip.NetworkFromCIDR(netip.MustParseAddr(testCase.addr), testCase.bits)
			if testCase.wantError != "" {
				require.ErrorIs(t, err, xnetip.ErrCIDROverflow)
				require.Equal(t, testCase.wantError, err.Error())
				require.Equal(t, xnetip.Network{}, network)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

// verifies that the invalid zero address, having no family, yields
// the family-mismatch sentinel and the zero network.
func Test_NetworkFromCIDR_RejectsInvalidAddr(t *testing.T) {
	network, err := xnetip.NetworkFromCIDR(netip.Addr{}, 0)
	require.ErrorIs(t, err, xnetip.ErrAddrFamilyMismatch)
	require.Equal(t, `xnetip.NetworkFromCIDR("invalid IP/0"): address family mismatch`, err.Error())
	require.Equal(t, xnetip.Network{}, network)
}

// verifies that the constructor equals the wrapped IPv4 typed
// constructor across the whole length range, overflow included.
//
// The length range deliberately extends one past the family limit so
// the error case is drawn every run. Non-contiguous masks cannot
// arise here — both delegates only build contiguous masks — and the
// success branch checks the concrete view normalized.
func Test_NetworkFromCIDR_MatchesTypedConstructorIPv4(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		addr := genNetipAddr4.Draw(t, "addr")
		bits := rapid.IntRange(0, 33).Draw(t, "bits")
		network, err := xnetip.NetworkFromCIDR(addr, bits)
		typed, typedErr := xnetip.Network4FromCIDR(addr, bits)
		if typedErr != nil {
			require.ErrorIs(t, err, xnetip.ErrCIDROverflow)
			require.ErrorIs(t, typedErr, xnetip.ErrCIDROverflow)
			require.Equal(t, xnetip.Network{}, network)
			return
		}
		require.NoError(t, err)
		require.Equal(t, xnetip.NetworkFrom4(typed), network)
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
func Test_NetworkFromCIDR_MatchesTypedConstructorIPv6(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		addr := genNetipAddr6.Draw(t, "addr")
		bits := rapid.IntRange(0, 129).Draw(t, "bits")
		network, err := xnetip.NetworkFromCIDR(addr, bits)
		typed, typedErr := xnetip.Network6FromCIDR(addr, bits)
		if typedErr != nil {
			require.ErrorIs(t, err, xnetip.ErrCIDROverflow)
			require.ErrorIs(t, typedErr, xnetip.ErrCIDROverflow)
			require.Equal(t, xnetip.Network{}, network)
			return
		}
		require.NoError(t, err)
		require.Equal(t, xnetip.NetworkFrom6(typed), network)
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
func Test_NetworkFromCIDR_AllocationFree(t *testing.T) {
	addr4 := netip.MustParseAddr("192.168.1.5")
	addr6 := netip.MustParseAddr("2001:db8::1")
	var err error
	requireNoAllocs(t, func() { ipNetworkSink, err = xnetip.NetworkFromCIDR(addr4, 24) })
	require.NoError(t, err)
	requireNoAllocs(t, func() { ipNetworkSink, err = xnetip.NetworkFromCIDR(addr6, 64) })
	require.NoError(t, err)
}

// verifies that the host-route constructor answers in the family of
// its argument, with the address preserved and the mask all ones.
//
// A non-contiguous mask table is not applicable to this constructor:
// the mask is fixed to all ones, the universe of bits of the address's
// own family.
func Test_NetworkFromAddr_BuildsHostRouteInOwnFamily(t *testing.T) {
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
			network, err := xnetip.NetworkFromAddr(netip.MustParseAddr(testCase.addr))
			require.NoError(t, err)
			require.Equal(t, testCase.wantIs4, network.Is4())
			require.Equal(t, netip.MustParseAddr(testCase.addr), network.Addr())
			require.Equal(t, netip.MustParseAddr(testCase.wantMask), network.Mask())
		})
	}
}

// verifies that the IPv4 host route round-trips through the IPv4
// extractor and declines the IPv6 one.
func Test_NetworkFromAddr_RoundTripsThroughIPv4(t *testing.T) {
	network, err := xnetip.NetworkFromAddr(netip.MustParseAddr("192.168.1.1"))
	require.NoError(t, err)
	extracted, ok := network.IPv4()
	require.True(t, ok)
	expected, err := xnetip.Network4FromAddr(netip.MustParseAddr("192.168.1.1"))
	require.NoError(t, err)
	require.Equal(t, expected, extracted)
	_, ok = network.IPv6()
	require.False(t, ok)
}

// verifies that the host route of an IPv4-mapped address round-trips
// through the IPv6 extractor and declines the IPv4 one.
func Test_NetworkFromAddr_MappedAddressRoundTripsThroughIPv6(t *testing.T) {
	network, err := xnetip.NetworkFromAddr(netip.MustParseAddr("::ffff:192.168.0.1"))
	require.NoError(t, err)
	extracted, ok := network.IPv6()
	require.True(t, ok)
	expected, err := xnetip.Network6FromAddr(netip.MustParseAddr("::ffff:192.168.0.1"))
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
func Test_NetworkFromAddr_StoredFormEqualsIPv4Lift(t *testing.T) {
	network, err := xnetip.NetworkFromAddr(netip.MustParseAddr("192.168.1.1"))
	require.NoError(t, err)
	concrete, err := xnetip.Network4FromAddr(netip.MustParseAddr("192.168.1.1"))
	require.NoError(t, err)
	require.Equal(t, xnetip.NetworkFrom4(concrete), network)
}

// verifies that a zone is dropped silently and the zone-free host
// route is built.
func Test_NetworkFromAddr_DropsZone(t *testing.T) {
	network, err := xnetip.NetworkFromAddr(netip.MustParseAddr("fe80::1%eth0"))
	require.NoError(t, err)
	require.True(t, network.Is6())
	require.Equal(t, netip.MustParseAddr("fe80::1"), network.Addr())
	require.Empty(t, network.Addr().Zone())
}

// verifies that the invalid zero address yields the family-mismatch
// sentinel and the zero network.
func Test_NetworkFromAddr_RejectsInvalidZeroAddr(t *testing.T) {
	network, err := xnetip.NetworkFromAddr(netip.Addr{})
	require.ErrorIs(t, err, xnetip.ErrAddrFamilyMismatch)
	require.Equal(t, xnetip.Network{}, network)
}

// verifies that every valid address of either family lifts into a
// host route of the same family with the address preserved.
//
// The result must also equal the lift of the concrete constructor of
// its family, so the family-agnostic entry point adds no behaviour.
func Test_NetworkFromAddr_AgreesWithConcreteConstructorsProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		var addr netip.Addr
		if rapid.Bool().Draw(t, "is4") {
			addr = genNetipAddr4.Draw(t, "addr4")
		} else {
			addr = genNetipAddr6.Draw(t, "addr6")
		}
		network, err := xnetip.NetworkFromAddr(addr)
		require.NoError(t, err)
		require.Equal(t, addr.Is4(), network.Is4())
		require.Equal(t, addr, network.Addr())
		if addr.Is4() {
			concrete, err := xnetip.Network4FromAddr(addr)
			require.NoError(t, err)
			require.Equal(t, xnetip.NetworkFrom4(concrete), network)
		} else {
			concrete, err := xnetip.Network6FromAddr(addr)
			require.NoError(t, err)
			require.Equal(t, xnetip.NetworkFrom6(concrete), network)
		}
	})
}

// verifies that the host-route constructor allocates nothing on the
// success path of either family.
func Test_NetworkFromAddr_AllocationFree(t *testing.T) {
	addr4 := netip.MustParseAddr("192.168.1.5")
	addr6 := netip.MustParseAddr("2001:db8::1")
	var err error
	requireNoAllocs(t, func() { ipNetworkSink, err = xnetip.NetworkFromAddr(addr4) })
	require.NoError(t, err)
	requireNoAllocs(t, func() { ipNetworkSink, err = xnetip.NetworkFromAddr(addr6) })
	require.NoError(t, err)
}

// verifies that a same-family pair is accepted, the address bits
// outside the mask are cleared and the pair's own family is kept.
func Test_NetworkFrom_NormalizesAddressByMask(t *testing.T) {
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
			network, err := xnetip.NetworkFrom(
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
func Test_NetworkFrom_HostRouteEqualsFromAddr(t *testing.T) {
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
			network, err := xnetip.NetworkFrom(
				netip.MustParseAddr(testCase.addr),
				netip.MustParseAddr(testCase.mask),
			)
			require.NoError(t, err)
			hostRoute, err := xnetip.NetworkFromAddr(netip.MustParseAddr(testCase.addr))
			require.NoError(t, err)
			require.Equal(t, hostRoute, network)
		})
	}
}

// verifies that a mixed-family pair or the invalid zero address
// yields the family-mismatch sentinel and the zero network.
func Test_NetworkFrom_RejectsFamilyMismatch(t *testing.T) {
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
			network, err := xnetip.NetworkFrom(testCase.addr, testCase.mask)
			require.ErrorIs(t, err, xnetip.ErrAddrFamilyMismatch)
			require.Equal(t, xnetip.Network{}, network)
		})
	}
}

// verifies that an IPv4 pair equals the lift of the concrete IPv4
// constructor, pinning the mapped encoding, all-zero mask included.
func Test_NetworkFrom_MatchesIPv4Lift(t *testing.T) {
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
			network, err := xnetip.NetworkFrom(addr, mask)
			require.NoError(t, err)
			require.True(t, network.Is4())
			concrete, err := xnetip.Network4From(addr, mask)
			require.NoError(t, err)
			require.Equal(t, xnetip.NetworkFrom4(concrete), network)
		})
	}
}

// verifies that every same-family pair of either family succeeds and
// equals the lift of its family's concrete checked constructor.
func Test_NetworkFrom_AgreesWithConcreteConstructorsProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		if rapid.Bool().Draw(t, "is4") {
			addr := genNetipAddr4.Draw(t, "addr4")
			mask := genNetipAddr4.Draw(t, "mask4")
			network, err := xnetip.NetworkFrom(addr, mask)
			require.NoError(t, err)
			concrete, err := xnetip.Network4From(addr, mask)
			require.NoError(t, err)
			require.Equal(t, xnetip.NetworkFrom4(concrete), network)
		} else {
			addr := genNetipAddr6.Draw(t, "addr6")
			mask := genNetipAddr6.Draw(t, "mask6")
			network, err := xnetip.NetworkFrom(addr, mask)
			require.NoError(t, err)
			concrete, err := xnetip.Network6From(addr, mask)
			require.NoError(t, err)
			require.Equal(t, xnetip.NetworkFrom6(concrete), network)
		}
	})
}

// verifies that every result is masked in its family's width and
// that rebuilding a result from its own accessors is the identity.
func Test_NetworkFrom_NormalizationIdempotentProperty(t *testing.T) {
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
		network, err := xnetip.NetworkFrom(addr, mask)
		require.NoError(t, err)
		require.Equal(t, wantAddr, network.Addr())
		require.Equal(t, mask, network.Mask())
		rebuilt, err := xnetip.NetworkFrom(network.Addr(), network.Mask())
		require.NoError(t, err)
		require.Equal(t, network, rebuilt)
	})
}

// verifies that a mixed-family pair, in either order, always yields
// the family-mismatch sentinel and the zero network.
func Test_NetworkFrom_RejectsMixedFamilyProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		addr4 := genNetipAddr4.Draw(t, "addr4")
		addr6 := genNetipAddr6.Draw(t, "addr6")
		addr, mask := addr4, addr6
		if rapid.Bool().Draw(t, "v6 first") {
			addr, mask = addr6, addr4
		}
		network, err := xnetip.NetworkFrom(addr, mask)
		require.ErrorIs(t, err, xnetip.ErrAddrFamilyMismatch)
		require.Equal(t, xnetip.Network{}, network)
	})
}

// verifies that normalization by a contiguous mask agrees with the
// net/netip oracle for masking a prefix, in both families.
func Test_NetworkFrom_MatchesNetipMaskedForPrefixMasks(t *testing.T) {
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
		network, err := xnetip.NetworkFrom(addr, mask)
		require.NoError(t, err)
		require.Equal(t, netip.PrefixFrom(addr, bits).Masked().Addr(), network.Addr())
	})
}

// verifies that the pair constructor allocates nothing on the success
// path of either family.
func Test_NetworkFrom_AllocationFree(t *testing.T) {
	addr4 := netip.MustParseAddr("192.168.1.1")
	mask4 := netip.MustParseAddr("255.255.0.255")
	addr6 := netip.MustParseAddr("2001:db8::1")
	mask6 := netip.MustParseAddr("ffff:ffff::")
	var err error
	requireNoAllocs(t, func() { ipNetworkSink, err = xnetip.NetworkFrom(addr4, mask4) })
	require.NoError(t, err)
	requireNoAllocs(t, func() { ipNetworkSink, err = xnetip.NetworkFrom(addr6, mask6) })
	require.NoError(t, err)
}

// verifies that an IPv4 network embeds as its IPv4-mapped IPv6 image
// and an IPv6 network passes through unchanged, whatever its shape.
func Test_Network_ToIPv6Mapped_EmbedsIntoIPv6Space(t *testing.T) {
	cases := []struct {
		name     string
		network  xnetip.Network
		wantAddr string
		wantMask string
	}{
		{name: "IPv4 contiguous", network: mustNetworkIs4(t, "192.168.1.0", "255.255.255.0"), wantAddr: "::ffff:c0a8:100", wantMask: "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ff00"},
		{name: "IPv6 identity contiguous", network: mustNetworkIs6(t, "2001:db8::", "ffff:ffff::"), wantAddr: "2001:db8::", wantMask: "ffff:ffff::"},
		{name: "IPv4 universe pins only the mapped prefix", network: mustNetworkIs4(t, "0.0.0.0", "0.0.0.0"), wantAddr: "::ffff:0:0", wantMask: "ffff:ffff:ffff:ffff:ffff:ffff::"},
		{name: "IPv4 host route becomes a /128", network: mustNetworkIs4(t, "10.0.0.1", "255.255.255.255"), wantAddr: "::ffff:a00:1", wantMask: "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"},
		{name: "IPv6 universe identity", network: mustNetworkIs6(t, "::", "::"), wantAddr: "::", wantMask: "::"},
		{name: "IPv6 mapped network stays as is", network: mustNetworkIs6(t, "::ffff:c0a8:100", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ff00"), wantAddr: "::ffff:c0a8:100", wantMask: "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ff00"},
		{name: "IPv4 non-contiguous keeps the low mask hole", network: mustNetworkIs4(t, "192.168.0.1", "255.255.0.255"), wantAddr: "::ffff:c0a8:1", wantMask: "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ff"},
		{name: "IPv6 non-contiguous identity", network: mustNetworkIs6(t, "2a02:6b8:c00::1234:abcd:0:0", "ffff:ffff:ff00::ffff:ffff:0:0"), wantAddr: "2a02:6b8:c00::1234:abcd:0:0", wantMask: "ffff:ffff:ff00::ffff:ffff:0:0"},
		{name: "IPv4 alternating mask carries into the low bits", network: mustNetworkIs4(t, "170.85.170.85", "170.85.170.85"), wantAddr: "::ffff:aa55:aa55", wantMask: "ffff:ffff:ffff:ffff:ffff:ffff:aa55:aa55"},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			mapped := testCase.network.ToIPv6Mapped()
			require.Equal(t, mustNetwork6(t, testCase.wantAddr, testCase.wantMask), mapped)
		})
	}
}

// verifies that the family-agnostic embedding equals the IPv4 type's
// own embedding for an IPv4 network.
func Test_Network_ToIPv6Mapped_EqualsNetwork4Method(t *testing.T) {
	network, err := xnetip.Network4From(
		netip.MustParseAddr("192.168.1.0"),
		netip.MustParseAddr("255.255.255.0"),
	)
	require.NoError(t, err)
	require.Equal(t, network.ToIPv6Mapped(), xnetip.NetworkFrom4(network).ToIPv6Mapped())
}

// verifies that embedding an IPv4 network agrees with the concrete
// method, lands in the mapped range and round-trips back.
func Test_Network_ToIPv6Mapped_IPv4RoundTripProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		network := genNetwork4.Draw(t, "network")
		mapped := xnetip.NetworkFrom4(network).ToIPv6Mapped()
		require.Equal(t, network.ToIPv6Mapped(), mapped)
		require.True(t, mapped.IsIPv4MappedIPv6())
		recovered, ok := mapped.ToIPv4Mapped()
		require.True(t, ok)
		require.Equal(t, network, recovered)
	})
}

// verifies that embedding an IPv6 network is the identity, whatever
// the mask shape.
func Test_Network_ToIPv6Mapped_IPv6IdentityProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		network := genNetwork6.Draw(t, "network")
		require.Equal(t, network, xnetip.NetworkFrom6(network).ToIPv6Mapped())
	})
}

// verifies that the address of an embedded IPv4 network unmaps back to
// the original address, with net/netip as the unmapping oracle.
func Test_Network_ToIPv6Mapped_MatchesNetipUnmap(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		network := genNetwork4.Draw(t, "network")
		mapped := xnetip.NetworkFrom4(network).ToIPv6Mapped()
		require.Equal(t, network.Addr(), mapped.Addr().Unmap())
	})
}

// verifies that the embedding allocates nothing for either family.
func Test_Network_ToIPv6Mapped_AllocationFree(t *testing.T) {
	network4 := mustNetworkIs4(t, "192.168.1.0", "255.255.255.0")
	network6 := mustNetworkIs6(t, "2001:db8::", "ffff:ffff::")
	requireNoAllocs(t, func() { network6Sink = network4.ToIPv6Mapped() })
	requireNoAllocs(t, func() { network6Sink = network6.ToIPv6Mapped() })
}

// verifies that an IPv4 network and a non-mapped IPv6 network come
// back unchanged while a mapped IPv6 network collapses to IPv4.
func Test_Network_ToCanonical_CollapsesOnlyMappedIPv6(t *testing.T) {
	cases := []struct {
		name    string
		network xnetip.Network
		want    xnetip.Network
	}{
		{name: "IPv4 unchanged", network: mustNetworkIs4(t, "192.168.0.0", "255.255.255.0"), want: mustNetworkIs4(t, "192.168.0.0", "255.255.255.0")},
		{name: "mapped IPv6 contiguous collapses", network: mustNetworkIs6(t, "::ffff:c0a8:100", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ff00"), want: mustNetworkIs4(t, "192.168.1.0", "255.255.255.0")},
		{name: "plain IPv6 unchanged", network: mustNetworkIs6(t, "2001:db8::", "ffff:ffff::"), want: mustNetworkIs6(t, "2001:db8::", "ffff:ffff::")},
		{name: "IPv4-compatible address is not mapped", network: mustNetworkIs6(t, "::c00a:2ff", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"), want: mustNetworkIs6(t, "::c00a:2ff", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff")},
		{name: "mapped address under an unpinned mask stays IPv6", network: mustNetworkIs6(t, "::ffff:c0a8:1", "0:ffff:ffff:ffff:ffff:ffff:ffff:ffff"), want: mustNetworkIs6(t, "::ffff:c0a8:1", "0:ffff:ffff:ffff:ffff:ffff:ffff:ffff")},
		{name: "mapped universe collapses to the IPv4 universe", network: mustNetworkIs6(t, "::ffff:0:0", "ffff:ffff:ffff:ffff:ffff:ffff::"), want: mustNetworkIs4(t, "0.0.0.0", "0.0.0.0")},
		{name: "mapped host route collapses", network: mustNetworkIs6(t, "::ffff:a00:1", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"), want: mustNetworkIs4(t, "10.0.0.1", "255.255.255.255")},
		{name: "mask one bit short of the mapped pin stays IPv6", network: mustNetworkIs6(t, "::ffff:0:0", "ffff:ffff:ffff:ffff:ffff:fffe::"), want: mustNetworkIs6(t, "::fffe:0:0", "ffff:ffff:ffff:ffff:ffff:fffe::")},
		{name: "IPv6 universe unchanged", network: mustNetworkIs6(t, "::", "::"), want: mustNetworkIs6(t, "::", "::")},
		{name: "mapped with non-contiguous low mask collapses", network: mustNetworkIs6(t, "::ffff:c0a8:1", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ff"), want: mustNetworkIs4(t, "192.168.0.1", "255.255.0.255")},
		{name: "hole inside the pinned region stays IPv6", network: mustNetworkIs6(t, "::ffff:c0a8:1", "ffff:0:ffff:ffff:ffff:ffff:ffff:ffff"), want: mustNetworkIs6(t, "::ffff:c0a8:1", "ffff:0:ffff:ffff:ffff:ffff:ffff:ffff")},
		{name: "mapped with alternating low mask collapses", network: mustNetworkIs6(t, "::ffff:aa55:aa55", "ffff:ffff:ffff:ffff:ffff:ffff:aa55:aa55"), want: mustNetworkIs4(t, "170.85.170.85", "170.85.170.85")},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			require.Equal(t, testCase.want, testCase.network.ToCanonical())
		})
	}
}

// verifies that canonicalizing twice equals canonicalizing once, for
// networks of every family and mask shape.
func Test_Network_ToCanonical_IdempotentProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		network := genNetwork.Draw(t, "network")
		canonical := network.ToCanonical()
		require.Equal(t, canonical, canonical.ToCanonical())
	})
}

// verifies that canonicalization preserves the IPv6 embedding: the
// canonical form embeds into the same 128-bit network.
func Test_Network_ToCanonical_PreservesEmbeddingProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		network := genNetwork.Draw(t, "network")
		require.Equal(t, network.ToIPv6Mapped(), network.ToCanonical().ToIPv6Mapped())
	})
}

// verifies that an IPv4 network survives the round trip through its
// mapped IPv6 lift and back through canonicalization.
func Test_Network_ToCanonical_RoundTripsMappedIPv4Property(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		network := genNetwork4.Draw(t, "network")
		lifted := xnetip.NetworkFrom6(xnetip.NetworkFrom4(network).ToIPv6Mapped())
		require.Equal(t, xnetip.NetworkFrom4(network), lifted.ToCanonical())
	})
}

// verifies that an IPv6 network collapses exactly when the concrete
// mapped predicate holds, and collapses to the concrete truncation.
func Test_Network_ToCanonical_AgreesWithConcretePredicateProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		network := genNetwork6.Draw(t, "network")
		canonical := xnetip.NetworkFrom6(network).ToCanonical()
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
func Test_Network_ToCanonical_MatchesNetipUnmapOnAddress(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		network := genNetwork6.Draw(t, "network")
		canonical := xnetip.NetworkFrom6(network).ToCanonical()
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
func Test_Network_ToCanonical_AllocationFree(t *testing.T) {
	network4 := mustNetworkIs4(t, "192.168.1.0", "255.255.255.0")
	mapped := mustNetworkIs6(t, "::ffff:c0a8:100", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ff00")
	network6 := mustNetworkIs6(t, "2001:db8::", "ffff:ffff::")
	requireNoAllocs(t, func() { ipNetworkSink = network4.ToCanonical() })
	requireNoAllocs(t, func() { ipNetworkSink = mapped.ToCanonical() })
	requireNoAllocs(t, func() { ipNetworkSink = network6.ToCanonical() })
}

// verifies that every IPv4 network sorts before every IPv6 network
// and that within a family the concrete lexicographic order applies.
func Test_Network_Compare_FamilyFirstThenConcreteOrder(t *testing.T) {
	cases := []struct {
		name  string
		left  xnetip.Network
		right xnetip.Network
		want  int
	}{
		{name: "IPv4 max before IPv6 universe", left: mustNetworkIs4(t, "255.255.255.255", "255.255.255.255"), right: mustNetworkIs6(t, "::", "::"), want: -1},
		{name: "IPv6 universe after IPv4 universe", left: mustNetworkIs6(t, "::", "::"), right: mustNetworkIs4(t, "0.0.0.0", "0.0.0.0"), want: 1},
		{name: "within IPv4 address dominates mask", left: mustNetworkIs4(t, "10.0.0.0", "255.255.255.255"), right: mustNetworkIs4(t, "11.0.0.0", "255.0.0.0"), want: -1},
		{name: "within IPv4 mask decides", left: mustNetworkIs4(t, "10.0.0.0", "255.255.0.0"), right: mustNetworkIs4(t, "10.0.0.0", "255.255.255.0"), want: -1},
		{name: "within IPv6 address dominates mask", left: mustNetworkIs6(t, "2001::", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"), right: mustNetworkIs6(t, "2001:db9::", "ffff:ffff::"), want: -1},
		{name: "within IPv6 mask decides", left: mustNetworkIs6(t, "2001:db8::", "ffff:ffff::"), right: mustNetworkIs6(t, "2001:db8::", "ffff:ffff:ffff:ffff::"), want: -1},
		{name: "IPv4-mapped IPv6 sorts after its IPv4 twin", left: mustNetworkIs4(t, "192.168.1.0", "255.255.255.0"), right: mustNetworkIs6(t, "::ffff:c0a8:100", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ff00"), want: -1},
		{name: "IPv4 non-contiguous mask decides", left: mustNetworkIs4(t, "10.0.0.5", "255.0.0.255"), right: mustNetworkIs4(t, "10.0.0.5", "255.255.0.255"), want: -1},
		{name: "IPv6 non-contiguous mask decides", left: mustNetworkIs6(t, "2001:db8::5", "ffff:ffff:ff00:ff00:ffff:ffff:ffff:ffff"), right: mustNetworkIs6(t, "2001:db8::5", "ffff:ffff:ff00:ffff:ffff:ffff:ffff:ffff"), want: -1},
		{name: "IPv4 non-contiguous still before any IPv6", left: mustNetworkIs4(t, "255.255.255.255", "170.85.170.85"), right: mustNetworkIs6(t, "::", "::"), want: -1},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			require.Equal(t, testCase.want, testCase.left.Compare(testCase.right))
		})
	}
}

// verifies that equal networks of either family compare as zero.
func Test_Network_Compare_EqualityIsZero(t *testing.T) {
	require.Equal(t, 0, mustNetworkIs4(t, "192.168.1.0", "255.255.255.0").Compare(mustNetworkIs4(t, "192.168.1.0", "255.255.255.0")))
	require.Equal(t, 0, mustNetworkIs6(t, "2001:db8::", "ffff:ffff::").Compare(mustNetworkIs6(t, "2001:db8::", "ffff:ffff::")))
}

// verifies that sorting a mixed fixture yields the family blocks in
// order, each internally sorted by its concrete order.
func Test_Network_Compare_SortPinsFamilyThenOrder(t *testing.T) {
	shuffled := []xnetip.Network{
		mustNetworkIs6(t, "2001:db8::", "ffff:ffff::"),
		mustNetworkIs4(t, "10.0.0.0", "255.0.0.0"),
		mustNetworkIs6(t, "::", "::"),
		mustNetworkIs4(t, "0.0.0.0", "0.0.0.0"),
		mustNetworkIs4(t, "10.0.0.5", "255.0.0.255"),
		mustNetworkIs6(t, "::ffff:c0a8:100", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ff00"),
	}
	want := []xnetip.Network{
		mustNetworkIs4(t, "0.0.0.0", "0.0.0.0"),
		mustNetworkIs4(t, "10.0.0.0", "255.0.0.0"),
		mustNetworkIs4(t, "10.0.0.5", "255.0.0.255"),
		mustNetworkIs6(t, "::", "::"),
		mustNetworkIs6(t, "::ffff:c0a8:100", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ff00"),
		mustNetworkIs6(t, "2001:db8::", "ffff:ffff::"),
	}
	slices.SortFunc(shuffled, xnetip.Network.Compare)
	require.Equal(t, want, shuffled)
}

// verifies that within a family the lifted order agrees with the
// concrete type's order, the check behind the stored-form compare.
func Test_Network_Compare_AgreesWithConcreteOrdersProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		if rapid.Bool().Draw(t, "is4") {
			left := genNetwork4.Draw(t, "left")
			right := genNetwork4.Draw(t, "right")
			require.Equal(t, left.Compare(right), xnetip.NetworkFrom4(left).Compare(xnetip.NetworkFrom4(right)))
		} else {
			left := genNetwork6.Draw(t, "left")
			right := genNetwork6.Draw(t, "right")
			require.Equal(t, left.Compare(right), xnetip.NetworkFrom6(left).Compare(xnetip.NetworkFrom6(right)))
		}
	})
}

// verifies the family rule on mixed pairs, antisymmetry, zero exactly
// on equality and transitivity on random triples.
func Test_Network_Compare_TotalOrderProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		left := genNetwork.Draw(t, "left")
		right := genNetwork.Draw(t, "right")
		third := genNetwork.Draw(t, "third")
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
func Test_Network_Compare_SortFuncProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		networks := rapid.SliceOfN(genNetwork, 0, 32).Draw(t, "networks")
		sorted := slices.Clone(networks)
		slices.SortFunc(sorted, xnetip.Network.Compare)
		require.True(t, slices.IsSortedFunc(sorted, xnetip.Network.Compare))
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
func Test_Network_Compare_MatchesNetipAddrOrderOnHostRoutes(t *testing.T) {
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
		leftRoute, err := xnetip.NetworkFromAddr(left)
		require.NoError(t, err)
		rightRoute, err := xnetip.NetworkFromAddr(right)
		require.NoError(t, err)
		require.Equal(t, left.Compare(right), leftRoute.Compare(rightRoute))
	})
}

// verifies that comparing allocates nothing for same-family and
// mixed-family pairs alike.
func Test_Network_Compare_AllocationFree(t *testing.T) {
	network4 := mustNetworkIs4(t, "10.0.0.0", "255.0.0.0")
	other4 := mustNetworkIs4(t, "10.0.0.0", "255.255.255.0")
	network6 := mustNetworkIs6(t, "2001:db8::", "ffff:ffff::")
	requireNoAllocs(t, func() { intSink = network4.Compare(other4) })
	requireNoAllocs(t, func() { intSink = network6.Compare(network6) })
	requireNoAllocs(t, func() { intSink = network4.Compare(network6) })
}

// verifies that containment delegates within a family and is false
// across families.
//
// The family rule comes first: the IPv6 universe contains every IPv6
// network, the IPv4-mapped ones included, but no IPv4 network, and an
// IPv4-mapped IPv6 network never contains the IPv4 network with the
// same bytes.
func Test_Network_Contains_FamiliesAndBoundary(t *testing.T) {
	cases := []struct {
		name  string
		outer xnetip.Network
		inner xnetip.Network
		want  bool
	}{
		{name: "IPv4 nested", outer: xnetip.MustParseNetwork("192.168.0.0/16"), inner: xnetip.MustParseNetwork("192.168.1.0/24"), want: true},
		{name: "IPv4 nested reversed", outer: xnetip.MustParseNetwork("192.168.1.0/24"), inner: xnetip.MustParseNetwork("192.168.0.0/16"), want: false},
		{name: "IPv6 nested", outer: xnetip.MustParseNetwork("2001:db8::/32"), inner: xnetip.MustParseNetwork("2001:db8:1::/48"), want: true},
		{name: "IPv6 nested reversed", outer: xnetip.MustParseNetwork("2001:db8:1::/48"), inner: xnetip.MustParseNetwork("2001:db8::/32"), want: false},
		{name: "different families", outer: xnetip.MustParseNetwork("10.0.0.0/8"), inner: xnetip.MustParseNetwork("2001:db8::/32"), want: false},
		{name: "different families reversed", outer: xnetip.MustParseNetwork("2001:db8::/32"), inner: xnetip.MustParseNetwork("10.0.0.0/8"), want: false},
		{name: "IPv6 universe does not contain an IPv4 network", outer: xnetip.Network{}, inner: xnetip.MustParseNetwork("10.0.0.0/8"), want: false},
		{name: "IPv4 network does not contain the IPv6 universe", outer: xnetip.MustParseNetwork("10.0.0.0/8"), inner: xnetip.Network{}, want: false},
		{name: "IPv6 universe contains a mapped IPv6 network", outer: xnetip.Network{}, inner: xnetip.MustParseNetwork("::ffff:10.0.0.0/104"), want: true},
		{name: "mapped IPv6 network does not contain the universe", outer: xnetip.MustParseNetwork("::ffff:10.0.0.0/104"), inner: xnetip.Network{}, want: false},
		{name: "IPv4 universe contains an IPv4 host", outer: xnetip.MustParseNetwork("0.0.0.0/0"), inner: xnetip.MustParseNetwork("127.0.0.1"), want: true},
		{name: "IPv4 universe does not contain an IPv6 host", outer: xnetip.MustParseNetwork("0.0.0.0/0"), inner: xnetip.MustParseNetwork("::1"), want: false},
		{name: "mapped IPv6 vs IPv4 with the same bytes", outer: xnetip.MustParseNetwork("::ffff:10.0.0.0/104"), inner: xnetip.MustParseNetwork("10.0.0.0/8"), want: false},
		{name: "IPv4 vs mapped IPv6 with the same bytes", outer: xnetip.MustParseNetwork("10.0.0.0/8"), inner: xnetip.MustParseNetwork("::ffff:10.0.0.0/104"), want: false},
		{name: "IPv4 host contains itself", outer: xnetip.MustParseNetwork("10.0.0.1/32"), inner: xnetip.MustParseNetwork("10.0.0.1/32"), want: true},
		{name: "IPv6 host contains itself", outer: xnetip.MustParseNetwork("::1/128"), inner: xnetip.MustParseNetwork("::1/128"), want: true},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			require.Equal(t, testCase.want, testCase.outer.Contains(testCase.inner))
		})
	}
}

// verifies that non-contiguous containment of both families flows
// through the wrapper.
//
// The family rule is unaffected by mask shape: a non-contiguous
// pattern of one family never contains one of the other.
func Test_Network_Contains_NonContiguousMasks(t *testing.T) {
	cases := []struct {
		name  string
		outer xnetip.Network
		inner xnetip.Network
		want  bool
	}{
		{name: "IPv4 pattern contains narrower pattern", outer: xnetip.MustParseNetwork("10.0.0.0/255.0.0.0"), inner: xnetip.MustParseNetwork("10.0.0.1/255.0.0.255"), want: true},
		{name: "IPv4 narrower pattern does not contain wider", outer: xnetip.MustParseNetwork("10.0.0.1/255.0.0.255"), inner: xnetip.MustParseNetwork("10.0.0.0/255.0.0.0"), want: false},
		{name: "IPv6 pattern contains narrower pattern", outer: xnetip.MustParseNetwork("2001:db8::/ffff:ffff::"), inner: xnetip.MustParseNetwork("2001:db8::1/ffff:ffff::ffff"), want: true},
		{name: "IPv6 narrower pattern does not contain wider", outer: xnetip.MustParseNetwork("2001:db8::1/ffff:ffff::ffff"), inner: xnetip.MustParseNetwork("2001:db8::/ffff:ffff::"), want: false},
		{name: "pattern 10.*.0.* contains matching host", outer: xnetip.MustParseNetwork("10.0.0.0/255.0.255.0"), inner: xnetip.MustParseNetwork("10.42.0.99"), want: true},
		{name: "IPv4 pattern vs IPv6 pattern", outer: xnetip.MustParseNetwork("10.0.0.0/255.0.255.0"), inner: xnetip.MustParseNetwork("2001:db8::/ffff:ffff::"), want: false},
		{name: "IPv6 pattern vs IPv4 pattern", outer: xnetip.MustParseNetwork("2001:db8::/ffff:ffff::"), inner: xnetip.MustParseNetwork("10.0.0.0/255.0.255.0"), want: false},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			require.Equal(t, testCase.want, testCase.outer.Contains(testCase.inner))
		})
	}
}

// verifies that wrapped IPv4 containment equals the concrete IPv4
// answer, so the IPv4-mapped storage form preserves the relation.
func Test_Network_Contains_AgreesWithIPv4Property(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		outer := genNetwork4.Draw(t, "outer")
		inner := genNetwork4.Draw(t, "inner")
		require.Equal(
			t,
			outer.Contains(inner),
			xnetip.NetworkFrom4(outer).Contains(xnetip.NetworkFrom4(inner)),
		)
	})
}

// verifies that wrapped IPv6 containment equals the concrete IPv6
// answer.
func Test_Network_Contains_AgreesWithIPv6Property(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		outer := genNetwork6.Draw(t, "outer")
		inner := genNetwork6.Draw(t, "inner")
		require.Equal(
			t,
			outer.Contains(inner),
			xnetip.NetworkFrom6(outer).Contains(xnetip.NetworkFrom6(inner)),
		)
	})
}

// verifies that networks of different families never contain each
// other, whatever their masks.
func Test_Network_Contains_CrossFamilyAlwaysFalseProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		network4 := xnetip.NetworkFrom4(genNetwork4.Draw(t, "network4"))
		network6 := xnetip.NetworkFrom6(genNetwork6.Draw(t, "network6"))
		require.False(t, network4.Contains(network6))
		require.False(t, network6.Contains(network4))
	})
}

// verifies that every network contains itself, whatever the family
// and the mask shape.
func Test_Network_Contains_ReflexiveProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		network := genNetwork.Draw(t, "network")
		require.True(t, network.Contains(network))
	})
}

// verifies that mutual containment holds exactly for equal networks.
func Test_Network_Contains_AntisymmetryProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		left := genNetwork.Draw(t, "left")
		right := genNetwork.Draw(t, "right")
		mutual := left.Contains(right) && right.Contains(left)
		require.Equal(t, left == right, mutual)
	})
}

// verifies that containment is transitive on random triples.
func Test_Network_Contains_TransitivityProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		first := genNetwork.Draw(t, "first")
		second := genNetwork.Draw(t, "second")
		third := genNetwork.Draw(t, "third")
		if first.Contains(second) && second.Contains(third) {
			require.True(t, first.Contains(third))
		}
	})
}

// verifies that on contiguous networks of either family containment
// agrees with the net/netip rule.
//
// The oracle is the prefix pair: the outer prefix covers the inner
// address and its length does not exceed the inner one. It answers
// false across families exactly as the wrapper does, so mixed draws
// stay in the comparison.
func Test_Network_Contains_MatchesNetipPrefixProperty(t *testing.T) {
	drawPrefix := func(t *rapid.T, label string) netip.Prefix {
		if rapid.Bool().Draw(t, label+" is4") {
			return genIPv4Prefix.Draw(t, label+" v4").Masked()
		}
		return genIPv6Prefix.Draw(t, label+" v6").Masked()
	}
	rapid.Check(t, func(t *rapid.T) {
		outerPrefix := drawPrefix(t, "outer")
		innerPrefix := drawPrefix(t, "inner")
		outer, ok := xnetip.NetworkFromPrefix(outerPrefix)
		require.True(t, ok)
		inner, ok := xnetip.NetworkFromPrefix(innerPrefix)
		require.True(t, ok)
		want := outerPrefix.Contains(innerPrefix.Addr()) && outerPrefix.Bits() <= innerPrefix.Bits()
		require.Equal(t, want, outer.Contains(inner))
	})
}

// verifies that the containment check allocates nothing in either
// family and across families.
func Test_Network_Contains_AllocationFree(t *testing.T) {
	outer4 := xnetip.MustParseNetwork("10.0.0.0/8")
	inner4 := xnetip.MustParseNetwork("10.1.0.0/16")
	outer6 := xnetip.MustParseNetwork("2001:db8::/32")
	inner6 := xnetip.MustParseNetwork("2001:db8:1::/48")
	requireNoAllocs(t, func() { okSink = outer4.Contains(inner4) })
	requireNoAllocs(t, func() { okSink = outer6.Contains(inner6) })
	requireNoAllocs(t, func() { okSink = outer4.Contains(inner6) })
}

func BenchmarkNetwork_Contains_V4(b *testing.B) {
	outer := xnetip.MustParseNetwork("10.0.0.0/8")
	inner := xnetip.MustParseNetwork("10.1.0.0/16")
	b.ReportAllocs()
	for b.Loop() {
		okSink = outer.Contains(inner)
	}
}

func BenchmarkNetwork_Contains_V6(b *testing.B) {
	outer := xnetip.MustParseNetwork("2001:db8::/32")
	inner := xnetip.MustParseNetwork("2001:db8:1::/48")
	b.ReportAllocs()
	for b.Loop() {
		okSink = outer.Contains(inner)
	}
}

func BenchmarkNetwork_Contains_CrossFamily(b *testing.B) {
	outer := xnetip.MustParseNetwork("10.0.0.0/8")
	inner := xnetip.MustParseNetwork("2001:db8::/32")
	b.ReportAllocs()
	for b.Loop() {
		okSink = outer.Contains(inner)
	}
}

// verifies that address membership requires the address's own family
// and follows the netip.Prefix.Contains rule within it.
//
// The family, not the bit pattern, decides first: an IPv4-mapped
// IPv6 address is not in any IPv4 network and an Is4 address is not
// in any IPv6 network, the mapped storage form notwithstanding. A
// zoned address and the invalid zero value are never contained.
func Test_Network_ContainsAddr_FamiliesAndBoundary(t *testing.T) {
	cases := []struct {
		name    string
		network xnetip.Network
		addr    netip.Addr
		want    bool
	}{
		{name: "IPv4 member", network: xnetip.MustParseNetwork("10.0.0.0/8"), addr: netip.MustParseAddr("10.1.2.3"), want: true},
		{name: "IPv4 non-member", network: xnetip.MustParseNetwork("10.0.0.0/8"), addr: netip.MustParseAddr("11.0.0.0"), want: false},
		{name: "IPv6 member", network: xnetip.MustParseNetwork("2001:db8::/32"), addr: netip.MustParseAddr("2001:db8::1"), want: true},
		{name: "IPv6 non-member", network: xnetip.MustParseNetwork("2001:db8::/32"), addr: netip.MustParseAddr("2001:db9::"), want: false},
		{name: "IPv6 address against IPv4 network", network: xnetip.MustParseNetwork("10.0.0.0/8"), addr: netip.MustParseAddr("2001:db8::1"), want: false},
		{name: "IPv4 address against IPv6 network", network: xnetip.MustParseNetwork("2001:db8::/32"), addr: netip.MustParseAddr("10.1.2.3"), want: false},
		{name: "IPv4-mapped address against IPv4 network", network: xnetip.MustParseNetwork("10.0.0.0/8"), addr: netip.MustParseAddr("::ffff:10.1.2.3"), want: false},
		{name: "IPv4 address against mapped IPv6 network", network: xnetip.MustParseNetwork("::ffff:10.0.0.0/104"), addr: netip.MustParseAddr("10.1.2.3"), want: false},
		{name: "IPv4-mapped address in mapped IPv6 network", network: xnetip.MustParseNetwork("::ffff:10.0.0.0/104"), addr: netip.MustParseAddr("::ffff:10.1.2.3"), want: true},
		{name: "IPv4 universe excludes IPv6", network: xnetip.MustParseNetwork("0.0.0.0/0"), addr: netip.MustParseAddr("::ffff:1.2.3.4"), want: false},
		{name: "IPv6 universe excludes IPv4", network: xnetip.MustParseNetwork("::/0"), addr: netip.MustParseAddr("1.2.3.4"), want: false},
		{name: "IPv6 universe contains IPv4-mapped", network: xnetip.MustParseNetwork("::/0"), addr: netip.MustParseAddr("::ffff:1.2.3.4"), want: true},
		{name: "zoned member address", network: xnetip.MustParseNetwork("fe80::/10"), addr: netip.MustParseAddr("fe80::1%eth0"), want: false},
		{name: "invalid zero Addr against IPv4 network", network: xnetip.MustParseNetwork("10.0.0.0/8"), addr: netip.Addr{}, want: false},
		{name: "invalid zero Addr against IPv6 network", network: xnetip.MustParseNetwork("2001:db8::/32"), addr: netip.Addr{}, want: false},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			require.Equal(t, testCase.want, testCase.network.ContainsAddr(testCase.addr))
		})
	}
}

// verifies that membership under a non-contiguous mask is agreement
// on every mask bit in both families.
func Test_Network_ContainsAddr_NonContiguousMasks(t *testing.T) {
	cases := []struct {
		name    string
		network xnetip.Network
		addr    netip.Addr
		want    bool
	}{
		{name: "IPv4 free middle octet varies", network: xnetip.MustParseNetwork("10.0.0.0/255.0.255.0"), addr: netip.MustParseAddr("10.77.0.5"), want: true},
		{name: "IPv4 constrained third octet differs", network: xnetip.MustParseNetwork("10.0.0.0/255.0.255.0"), addr: netip.MustParseAddr("10.0.1.0"), want: false},
		{name: "IPv6 alternating groups keep both halves", network: xnetip.MustParseNetwork("aaaa:0:bbbb:0:cccc:0:dddd:0/ffff:0:ffff:0:ffff:0:ffff:0"), addr: netip.MustParseAddr("aaaa:1111:bbbb:2222:cccc:3333:dddd:4444"), want: true},
		{name: "IPv6 alternating groups broken in the low half", network: xnetip.MustParseNetwork("aaaa:0:bbbb:0:cccc:0:dddd:0/ffff:0:ffff:0:ffff:0:ffff:0"), addr: netip.MustParseAddr("aaaa:1111:bbbb:2222:cccd:3333:dddd:4444"), want: false},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			require.Equal(t, testCase.want, testCase.network.ContainsAddr(testCase.addr))
		})
	}
}

// verifies that wrapped IPv4 membership equals the concrete IPv4
// answer over arguments of every shape.
func Test_Network_ContainsAddr_AgreesWithIPv4Property(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		network := genNetwork4.Draw(t, "network")
		address := drawMembershipProbe(t)
		require.Equal(
			t,
			network.ContainsAddr(address),
			xnetip.NetworkFrom4(network).ContainsAddr(address),
		)
	})
}

// verifies that wrapped IPv6 membership equals the concrete IPv6
// answer over arguments of every shape.
func Test_Network_ContainsAddr_AgreesWithIPv6Property(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		network := genNetwork6.Draw(t, "network")
		address := drawMembershipProbe(t)
		require.Equal(
			t,
			network.ContainsAddr(address),
			xnetip.NetworkFrom6(network).ContainsAddr(address),
		)
	})
}

// drawMembershipProbe draws a netip.Addr covering every membership
// argument shape.
//
// The shapes are both families with IPv4-mapped included, a zoned
// IPv6 address and the invalid zero value.
func drawMembershipProbe(t *rapid.T) netip.Addr {
	switch rapid.IntRange(0, 3).Draw(t, "argument shape") {
	case 0:
		return genNetipAddr4.Draw(t, "address4")
	case 1:
		return genNetipAddr6.Draw(t, "address6")
	case 2:
		return genNetipAddr6.Draw(t, "zoned").WithZone("eth0")
	default:
		return netip.Addr{}
	}
}

// verifies that address membership equals containing the address's
// host route in the address's own family, over every mask shape.
func Test_Network_ContainsAddr_HostRouteEquivalenceProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		network := genNetwork.Draw(t, "network")
		var address netip.Addr
		if rapid.Bool().Draw(t, "probe is4") {
			address = genNetipAddr4.Draw(t, "address4")
		} else {
			address = genNetipAddr6.Draw(t, "address6")
		}
		host, err := xnetip.NetworkFromAddr(address)
		require.NoError(t, err)
		require.Equal(t, network.Contains(host), network.ContainsAddr(address))
	})
}

// verifies that membership is total over arguments of every shape.
//
// A foreign-family, zoned or invalid argument answers false, never a
// panic.
func Test_Network_ContainsAddr_TotalityProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		network := genNetwork.Draw(t, "network")
		address := drawMembershipProbe(t)
		contained := network.ContainsAddr(address)
		if network.Is4() && !address.Is4() {
			require.False(t, contained)
		}
		if network.Is6() && (!address.Is6() || address.Zone() != "") {
			require.False(t, contained)
		}
	})
}

// verifies that on contiguous networks of either family address
// membership agrees with the net/netip prefix rule.
//
// Mixed families and zoned addresses stay in the comparison without
// a carve-out: both sides answer false for them.
func Test_Network_ContainsAddr_MatchesNetipPrefixProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		var prefix netip.Prefix
		if rapid.Bool().Draw(t, "prefix is4") {
			prefix = genIPv4Prefix.Draw(t, "prefix4").Masked()
		} else {
			prefix = genIPv6Prefix.Draw(t, "prefix6").Masked()
		}
		network, ok := xnetip.NetworkFromPrefix(prefix)
		require.True(t, ok)
		address := drawMembershipProbe(t)
		require.Equal(t, prefix.Contains(address), network.ContainsAddr(address))
	})
}

// verifies that the membership check allocates nothing in either
// family and across families.
func Test_Network_ContainsAddr_AllocationFree(t *testing.T) {
	network4 := xnetip.MustParseNetwork("10.0.0.0/255.0.255.0")
	network6 := xnetip.MustParseNetwork("2001:db8::/32")
	address4 := netip.MustParseAddr("10.77.0.5")
	address6 := netip.MustParseAddr("2001:db8::1")
	requireNoAllocs(t, func() { okSink = network4.ContainsAddr(address4) })
	requireNoAllocs(t, func() { okSink = network6.ContainsAddr(address6) })
	requireNoAllocs(t, func() { okSink = network4.ContainsAddr(address6) })
}

func BenchmarkNetwork_ContainsAddr_V4Member(b *testing.B) {
	network := xnetip.MustParseNetwork("10.0.0.0/8")
	address := netip.MustParseAddr("10.1.2.3")
	b.ReportAllocs()
	for b.Loop() {
		okSink = network.ContainsAddr(address)
	}
}

func BenchmarkNetwork_ContainsAddr_V6Member(b *testing.B) {
	network := xnetip.MustParseNetwork("2001:db8::/32")
	address := netip.MustParseAddr("2001:db8::1")
	b.ReportAllocs()
	for b.Loop() {
		okSink = network.ContainsAddr(address)
	}
}

func BenchmarkNetwork_ContainsAddr_CrossFamily(b *testing.B) {
	network := xnetip.MustParseNetwork("10.0.0.0/8")
	address := netip.MustParseAddr("2001:db8::1")
	b.ReportAllocs()
	for b.Loop() {
		okSink = network.ContainsAddr(address)
	}
}

// verifies that intersection delegates within a family, keeps the
// family tag and is empty across families.
//
// The family rule comes first: the IPv6 universe intersects every
// IPv6 network, the IPv4-mapped ones included, but no IPv4 network.
// A failing pair answers the zero network so a caller ignoring the
// flag cannot pick up plausible garbage.
func Test_Network_Intersection_FamiliesAndBoundary(t *testing.T) {
	cases := []struct {
		name   string
		left   xnetip.Network
		right  xnetip.Network
		want   xnetip.Network
		wantOK bool
	}{
		{name: "IPv4 containment yields the inner network", left: xnetip.MustParseNetwork("192.168.0.0/16"), right: xnetip.MustParseNetwork("192.168.1.0/24"), want: xnetip.MustParseNetwork("192.168.1.0/24"), wantOK: true},
		{name: "IPv4 containment reversed", left: xnetip.MustParseNetwork("192.168.1.0/24"), right: xnetip.MustParseNetwork("192.168.0.0/16"), want: xnetip.MustParseNetwork("192.168.1.0/24"), wantOK: true},
		{name: "IPv6 containment yields the inner network", left: xnetip.MustParseNetwork("2001:db8::/32"), right: xnetip.MustParseNetwork("2001:db8:1::/48"), want: xnetip.MustParseNetwork("2001:db8:1::/48"), wantOK: true},
		{name: "IPv4 disjoint answers the zero network", left: xnetip.MustParseNetwork("192.168.0.0/16"), right: xnetip.MustParseNetwork("10.0.0.0/8"), want: xnetip.Network{}, wantOK: false},
		{name: "IPv6 disjoint answers the zero network", left: xnetip.MustParseNetwork("2001:db8::/32"), right: xnetip.MustParseNetwork("fe80::/10"), want: xnetip.Network{}, wantOK: false},
		{name: "different families", left: xnetip.MustParseNetwork("10.0.0.0/8"), right: xnetip.MustParseNetwork("2001:db8::/32"), want: xnetip.Network{}, wantOK: false},
		{name: "different families reversed", left: xnetip.MustParseNetwork("2001:db8::/32"), right: xnetip.MustParseNetwork("10.0.0.0/8"), want: xnetip.Network{}, wantOK: false},
		{name: "IPv6 universe vs IPv4 network", left: xnetip.Network{}, right: xnetip.MustParseNetwork("10.0.0.0/8"), want: xnetip.Network{}, wantOK: false},
		{name: "IPv4 network vs IPv6 universe", left: xnetip.MustParseNetwork("10.0.0.0/8"), right: xnetip.Network{}, want: xnetip.Network{}, wantOK: false},
		{name: "IPv6 universe vs mapped IPv6 network", left: xnetip.Network{}, right: xnetip.MustParseNetwork("::ffff:10.0.0.0/104"), want: xnetip.MustParseNetwork("::ffff:10.0.0.0/104"), wantOK: true},
		{name: "IPv4 universe vs IPv4 host", left: xnetip.MustParseNetwork("0.0.0.0/0"), right: xnetip.MustParseNetwork("10.0.0.1/32"), want: xnetip.MustParseNetwork("10.0.0.1/32"), wantOK: true},
		{name: "IPv4 host vs IPv4 universe", left: xnetip.MustParseNetwork("10.0.0.1/32"), right: xnetip.MustParseNetwork("0.0.0.0/0"), want: xnetip.MustParseNetwork("10.0.0.1/32"), wantOK: true},
		{name: "mapped IPv6 vs IPv4 with the same bytes", left: xnetip.MustParseNetwork("::ffff:10.0.0.0/104"), right: xnetip.MustParseNetwork("10.0.0.0/8"), want: xnetip.Network{}, wantOK: false},
		{name: "identical IPv4", left: xnetip.MustParseNetwork("10.0.0.0/8"), right: xnetip.MustParseNetwork("10.0.0.0/8"), want: xnetip.MustParseNetwork("10.0.0.0/8"), wantOK: true},
		{name: "identical IPv6", left: xnetip.MustParseNetwork("2001:db8::/32"), right: xnetip.MustParseNetwork("2001:db8::/32"), want: xnetip.MustParseNetwork("2001:db8::/32"), wantOK: true},
		{name: "IPv4 host routes differ", left: xnetip.MustParseNetwork("10.0.0.1/32"), right: xnetip.MustParseNetwork("10.0.0.2/32"), want: xnetip.Network{}, wantOK: false},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			got, ok := testCase.left.Intersection(testCase.right)
			require.Equal(t, testCase.wantOK, ok)
			require.Equal(t, testCase.want, got)
			require.Equal(t, testCase.want.Is4(), got.Is4())
		})
	}
}

// verifies that non-contiguous intersection of both families flows
// through the wrapper.
//
// The family rule is unaffected by mask shape: a non-contiguous
// pattern of one family never intersects one of the other.
func Test_Network_Intersection_NonContiguousMasks(t *testing.T) {
	cases := []struct {
		name   string
		left   xnetip.Network
		right  xnetip.Network
		want   xnetip.Network
		wantOK bool
	}{
		{name: "IPv4 one non-contiguous", left: xnetip.MustParseNetwork("10.0.0.1/255.0.0.255"), right: xnetip.MustParseNetwork("10.1.0.0/255.255.0.0"), want: xnetip.MustParseNetwork("10.1.0.1/255.255.0.255"), wantOK: true},
		{name: "IPv4 single common address", left: xnetip.MustParseNetwork("10.0.0.0/255.0.255.0"), right: xnetip.MustParseNetwork("10.5.0.0/255.255.0.255"), want: xnetip.MustParseNetwork("10.5.0.0/32"), wantOK: true},
		{name: "IPv4 alternating masks always intersect", left: xnetip.MustParseNetwork("170.0.170.0/170.85.170.85"), right: xnetip.MustParseNetwork("0.170.0.170/85.170.85.170"), want: xnetip.MustParseNetwork("170.170.170.170/32"), wantOK: true},
		{name: "IPv6 one non-contiguous", left: xnetip.MustParseNetwork("2001::1/ffff::ffff"), right: xnetip.MustParseNetwork("2001:1::/ffff:ffff::"), want: xnetip.MustParseNetwork("2001:1::1/ffff:ffff::ffff"), wantOK: true},
		{name: "IPv6 alternating masks always intersect", left: xnetip.MustParseNetwork("aa00:0:aa00:0:aa00:0:aa00:0/ff00:ff:ff00:ff:ff00:ff:ff00:ff"), right: xnetip.MustParseNetwork("bb:0:bb:0:bb:0:bb:0/ff:ff00:ff:ff00:ff:ff00:ff:ff00"), want: xnetip.MustParseNetwork("aabb:0:aabb:0:aabb:0:aabb:0/128"), wantOK: true},
		{name: "IPv4 pattern vs IPv6 pattern", left: xnetip.MustParseNetwork("10.0.0.0/255.0.255.0"), right: xnetip.MustParseNetwork("2001:db8::/ffff:ffff::"), want: xnetip.Network{}, wantOK: false},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			got, ok := testCase.left.Intersection(testCase.right)
			require.Equal(t, testCase.wantOK, ok)
			require.Equal(t, testCase.want, got)
		})
	}
}

// verifies that wrapped IPv4 intersection equals the concrete IPv4
// answer, so the IPv4-mapped storage form preserves the relation.
//
// The result keeps the IPv4 family tag and the mapped storage
// invariant.
func Test_Network_Intersection_AgreesWithIPv4Property(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		left := genNetwork4.Draw(t, "left")
		right := genNetwork4.Draw(t, "right")
		got, gotOK := xnetip.NetworkFrom4(left).Intersection(xnetip.NetworkFrom4(right))
		want, wantOK := left.Intersection(right)
		require.Equal(t, wantOK, gotOK)
		if !gotOK {
			require.Equal(t, xnetip.Network{}, got)
			return
		}
		require.Equal(t, xnetip.NetworkFrom4(want), got)
		require.True(t, got.Is4())
		require.True(t, got.ToIPv6Mapped().IsIPv4MappedIPv6())
	})
}

// verifies that wrapped IPv6 intersection equals the concrete IPv6
// answer.
func Test_Network_Intersection_AgreesWithIPv6Property(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		left := genNetwork6.Draw(t, "left")
		right := genNetwork6.Draw(t, "right")
		got, gotOK := xnetip.NetworkFrom6(left).Intersection(xnetip.NetworkFrom6(right))
		want, wantOK := left.Intersection(right)
		require.Equal(t, wantOK, gotOK)
		if !gotOK {
			require.Equal(t, xnetip.Network{}, got)
			return
		}
		require.Equal(t, xnetip.NetworkFrom6(want), got)
		require.True(t, got.Is6())
	})
}

// verifies that networks of different families never intersect and
// always answer the zero network, whatever their masks.
func Test_Network_Intersection_CrossFamilyAlwaysFalseProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		network4 := xnetip.NetworkFrom4(genNetwork4.Draw(t, "network4"))
		network6 := xnetip.NetworkFrom6(genNetwork6.Draw(t, "network6"))
		got, ok := network4.Intersection(network6)
		require.False(t, ok)
		require.Equal(t, xnetip.Network{}, got)
		got, ok = network6.Intersection(network4)
		require.False(t, ok)
		require.Equal(t, xnetip.Network{}, got)
	})
}

// verifies that intersection is commutative in both the value and the
// flag, whatever the families.
func Test_Network_Intersection_CommutativityProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		left := genNetwork.Draw(t, "left")
		right := genNetwork.Draw(t, "right")
		leftValue, leftOK := left.Intersection(right)
		rightValue, rightOK := right.Intersection(left)
		require.Equal(t, leftOK, rightOK)
		require.Equal(t, leftValue, rightValue)
	})
}

// verifies that every network intersected with itself is itself.
func Test_Network_Intersection_SelfIntersectionProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		network := genNetwork.Draw(t, "network")
		got, ok := network.Intersection(network)
		require.True(t, ok)
		require.Equal(t, network, got)
	})
}

// verifies that an existing intersection is contained in both inputs.
func Test_Network_Intersection_SubsetOfBothProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		left := genNetwork.Draw(t, "left")
		right := genNetwork.Draw(t, "right")
		if got, ok := left.Intersection(right); ok {
			require.True(t, left.Contains(got))
			require.True(t, right.Contains(got))
		}
	})
}

// verifies that on contiguous networks of either family the
// intersection agrees with the net/netip overlap rule.
//
// Two prefixes overlap exactly when the networks intersect, and the
// oracle answers false across families exactly as the wrapper does,
// so mixed draws stay in the comparison.
func Test_Network_Intersection_MatchesNetipOverlapsProperty(t *testing.T) {
	drawPrefix := func(t *rapid.T, label string) netip.Prefix {
		if rapid.Bool().Draw(t, label+" is4") {
			return genIPv4Prefix.Draw(t, label+" v4").Masked()
		}
		return genIPv6Prefix.Draw(t, label+" v6").Masked()
	}
	rapid.Check(t, func(t *rapid.T) {
		leftPrefix := drawPrefix(t, "left")
		rightPrefix := drawPrefix(t, "right")
		left, ok := xnetip.NetworkFromPrefix(leftPrefix)
		require.True(t, ok)
		right, ok := xnetip.NetworkFromPrefix(rightPrefix)
		require.True(t, ok)
		_, ok = left.Intersection(right)
		require.Equal(t, leftPrefix.Overlaps(rightPrefix), ok)
	})
}

// verifies that the intersection allocates nothing in either family
// and across families.
func Test_Network_Intersection_AllocationFree(t *testing.T) {
	left4 := xnetip.MustParseNetwork("10.0.0.1/255.0.0.255")
	right4 := xnetip.MustParseNetwork("10.1.0.0/255.255.0.0")
	left6 := xnetip.MustParseNetwork("2001::1/ffff::ffff")
	right6 := xnetip.MustParseNetwork("2001:1::/ffff:ffff::")
	requireNoAllocs(t, func() { ipNetworkSink, okSink = left4.Intersection(right4) })
	requireNoAllocs(t, func() { ipNetworkSink, okSink = left6.Intersection(right6) })
	requireNoAllocs(t, func() { ipNetworkSink, okSink = left4.Intersection(right6) })
}

// verifies that the intersection predicate delegates within a family
// and is false across families.
//
// The family rule comes first: each family universe intersects every
// network of its family and nothing else, and an IPv4-mapped IPv6
// network never intersects the IPv4 network with the same bytes.
func Test_Network_Intersects_FamiliesAndBoundary(t *testing.T) {
	cases := []struct {
		name  string
		left  xnetip.Network
		right xnetip.Network
		want  bool
	}{
		{name: "IPv4 overlapping", left: xnetip.MustParseNetwork("192.168.0.0/16"), right: xnetip.MustParseNetwork("192.168.1.0/24"), want: true},
		{name: "IPv4 disjoint", left: xnetip.MustParseNetwork("192.168.0.0/16"), right: xnetip.MustParseNetwork("10.0.0.0/8"), want: false},
		{name: "mixed families", left: xnetip.MustParseNetwork("192.168.0.0/16"), right: xnetip.MustParseNetwork("2001:db8::/32"), want: false},
		{name: "mixed families reversed", left: xnetip.MustParseNetwork("2001:db8::/32"), right: xnetip.MustParseNetwork("192.168.0.0/16"), want: false},
		{name: "IPv6 overlapping", left: xnetip.MustParseNetwork("2001:db8::/32"), right: xnetip.MustParseNetwork("2001:db8:1::/48"), want: true},
		{name: "IPv4 universe vs IPv6 universe", left: xnetip.MustParseNetwork("0.0.0.0/0"), right: xnetip.Network{}, want: false},
		{name: "mapped IPv6 vs IPv4 with the same bytes", left: xnetip.MustParseNetwork("::ffff:10.0.0.0/104"), right: xnetip.MustParseNetwork("10.0.0.0/8"), want: false},
		{name: "IPv4 self", left: xnetip.MustParseNetwork("10.0.0.0/8"), right: xnetip.MustParseNetwork("10.0.0.0/8"), want: true},
		{name: "IPv6 self", left: xnetip.MustParseNetwork("2001:db8::/32"), right: xnetip.MustParseNetwork("2001:db8::/32"), want: true},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			require.Equal(t, testCase.want, testCase.left.Intersects(testCase.right))
		})
	}
}

// verifies that non-contiguous intersection checks of both families
// flow through the wrapper.
func Test_Network_Intersects_NonContiguousMasks(t *testing.T) {
	cases := []struct {
		name  string
		left  xnetip.Network
		right xnetip.Network
		want  bool
	}{
		{name: "IPv4 pattern overlaps block", left: xnetip.MustParseNetwork("10.0.0.1/255.0.0.255"), right: xnetip.MustParseNetwork("10.1.0.0/255.255.0.0"), want: true},
		{name: "IPv6 pattern disjoint from block", left: xnetip.MustParseNetwork("2001::1/ffff::ffff"), right: xnetip.MustParseNetwork("2002::/16"), want: false},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			require.Equal(t, testCase.want, testCase.left.Intersects(testCase.right))
		})
	}
}

// verifies that the wrapped predicate equals the concrete answer in
// each family.
func Test_Network_Intersects_AgreesWithConcreteProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		left4 := genNetwork4.Draw(t, "left4")
		right4 := genNetwork4.Draw(t, "right4")
		require.Equal(
			t,
			left4.Intersects(right4),
			xnetip.NetworkFrom4(left4).Intersects(xnetip.NetworkFrom4(right4)),
		)
		left6 := genNetwork6.Draw(t, "left6")
		right6 := genNetwork6.Draw(t, "right6")
		require.Equal(
			t,
			left6.Intersects(right6),
			xnetip.NetworkFrom6(left6).Intersects(xnetip.NetworkFrom6(right6)),
		)
	})
}

// verifies that networks of different families never intersect,
// whatever their masks.
func Test_Network_Intersects_CrossFamilyAlwaysFalseProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		network4 := xnetip.NetworkFrom4(genNetwork4.Draw(t, "network4"))
		network6 := xnetip.NetworkFrom6(genNetwork6.Draw(t, "network6"))
		require.False(t, network4.Intersects(network6))
		require.False(t, network6.Intersects(network4))
	})
}

// verifies that the predicate is symmetric, reflexive and answers
// exactly whether the intersection exists, whatever the families.
func Test_Network_Intersects_SymmetryAndEquivalenceProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		left := genNetwork.Draw(t, "left")
		right := genNetwork.Draw(t, "right")
		require.Equal(t, left.Intersects(right), right.Intersects(left))
		require.True(t, left.Intersects(left))
		_, ok := left.Intersection(right)
		require.Equal(t, ok, left.Intersects(right))
	})
}

// verifies that the predicate allocates nothing in either family and
// across families.
func Test_Network_Intersects_AllocationFree(t *testing.T) {
	left4 := xnetip.MustParseNetwork("10.0.0.1/255.0.0.255")
	right4 := xnetip.MustParseNetwork("10.1.0.0/255.255.0.0")
	left6 := xnetip.MustParseNetwork("2001::1/ffff::ffff")
	right6 := xnetip.MustParseNetwork("2001:1::/32")
	requireNoAllocs(t, func() { okSink = left4.Intersects(right4) })
	requireNoAllocs(t, func() { okSink = left6.Intersects(right6) })
	requireNoAllocs(t, func() { okSink = left4.Intersects(right6) })
}

// verifies that disjointness delegates within a family and always
// holds across families.
//
// The family universes of the two families are disjoint even though
// the stored 128-bit sets overlap — family first.
func Test_Network_IsDisjoint_FamiliesAndBoundary(t *testing.T) {
	cases := []struct {
		name  string
		left  xnetip.Network
		right xnetip.Network
		want  bool
	}{
		{name: "IPv4 disjoint", left: xnetip.MustParseNetwork("192.168.0.0/16"), right: xnetip.MustParseNetwork("10.0.0.0/8"), want: true},
		{name: "IPv4 overlapping", left: xnetip.MustParseNetwork("192.168.0.0/16"), right: xnetip.MustParseNetwork("192.168.1.0/24"), want: false},
		{name: "mixed families", left: xnetip.MustParseNetwork("192.168.0.0/16"), right: xnetip.MustParseNetwork("2001:db8::/32"), want: true},
		{name: "mixed families reversed", left: xnetip.MustParseNetwork("2001:db8::/32"), right: xnetip.MustParseNetwork("192.168.0.0/16"), want: true},
		{name: "IPv6 disjoint", left: xnetip.MustParseNetwork("2001:db8::/32"), right: xnetip.MustParseNetwork("fe80::/10"), want: true},
		{name: "universes of different families", left: xnetip.MustParseNetwork("0.0.0.0/0"), right: xnetip.Network{}, want: true},
		{name: "IPv4 self", left: xnetip.MustParseNetwork("10.0.0.0/8"), right: xnetip.MustParseNetwork("10.0.0.0/8"), want: false},
		{name: "IPv6 self", left: xnetip.MustParseNetwork("2001:db8::/32"), right: xnetip.MustParseNetwork("2001:db8::/32"), want: false},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			require.Equal(t, testCase.want, testCase.left.IsDisjoint(testCase.right))
		})
	}
}

// verifies that non-contiguous disjointness checks of both families
// flow through the wrapper.
func Test_Network_IsDisjoint_NonContiguousMasks(t *testing.T) {
	cases := []struct {
		name  string
		left  xnetip.Network
		right xnetip.Network
		want  bool
	}{
		{name: "IPv4 pattern disjoint from block", left: xnetip.MustParseNetwork("10.0.0.1/255.0.0.255"), right: xnetip.MustParseNetwork("11.0.0.0/255.0.0.0"), want: true},
		{name: "IPv6 pattern overlapping block", left: xnetip.MustParseNetwork("2001::1/ffff::ffff"), right: xnetip.MustParseNetwork("2001:1::/32"), want: false},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			require.Equal(t, testCase.want, testCase.left.IsDisjoint(testCase.right))
		})
	}
}

// verifies that disjointness is the exact complement of intersection,
// mixed families included.
//
// Within a family the wrapped answer equals the concrete one, so the
// mapped storage form preserves the relation.
func Test_Network_IsDisjoint_ComplementOfIntersectsProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		left := genNetwork.Draw(t, "left")
		right := genNetwork.Draw(t, "right")
		require.Equal(t, !left.Intersects(right), left.IsDisjoint(right))
		left4 := genNetwork4.Draw(t, "left4")
		right4 := genNetwork4.Draw(t, "right4")
		require.Equal(
			t,
			left4.IsDisjoint(right4),
			xnetip.NetworkFrom4(left4).IsDisjoint(xnetip.NetworkFrom4(right4)),
		)
		left6 := genNetwork6.Draw(t, "left6")
		right6 := genNetwork6.Draw(t, "right6")
		require.Equal(
			t,
			left6.IsDisjoint(right6),
			xnetip.NetworkFrom6(left6).IsDisjoint(xnetip.NetworkFrom6(right6)),
		)
	})
}

// verifies that the predicate allocates nothing in either family and
// across families.
func Test_Network_IsDisjoint_AllocationFree(t *testing.T) {
	left4 := xnetip.MustParseNetwork("10.0.0.1/255.0.0.255")
	right4 := xnetip.MustParseNetwork("11.0.0.0/255.0.0.0")
	left6 := xnetip.MustParseNetwork("2001::1/ffff::ffff")
	right6 := xnetip.MustParseNetwork("2001:1::/32")
	requireNoAllocs(t, func() { okSink = left4.IsDisjoint(right4) })
	requireNoAllocs(t, func() { okSink = left6.IsDisjoint(right6) })
	requireNoAllocs(t, func() { okSink = left4.IsDisjoint(right6) })
}

// verifies that an IPv4 pair delegates to the IPv4 peel.
//
// The parts equal the concrete result wrapped, every one carrying
// the IPv4 family.
func Test_Network_Difference_IPv4Superset(t *testing.T) {
	source := xnetip.MustParseNetwork("192.168.0.0/16")
	other := xnetip.MustParseNetwork("192.168.1.0/24")
	parts := slices.Collect(source.Difference(other))
	require.Len(t, parts, 8)
	source4 := xnetip.MustParseNetwork4("192.168.0.0/16")
	other4 := xnetip.MustParseNetwork4("192.168.1.0/24")
	expected := []xnetip.Network{}
	for part := range source4.Difference(other4) {
		expected = append(expected, xnetip.NetworkFrom4(part))
	}
	require.Equal(t, expected, parts)
	for _, part := range parts {
		require.True(t, part.Is4(), "part %v not IPv4", part)
	}
}

// verifies that an IPv6 pair delegates to the IPv6 peel with every
// part carrying the IPv6 family.
func Test_Network_Difference_IPv6Superset(t *testing.T) {
	source := xnetip.MustParseNetwork("2001:db8::/48")
	other := xnetip.MustParseNetwork("2001:db8::/64")
	parts := slices.Collect(source.Difference(other))
	require.Len(t, parts, 16)
	for _, part := range parts {
		require.True(t, part.Is6(), "part %v not IPv6", part)
	}
}

// verifies that a disjoint IPv4 pair yields the source once.
func Test_Network_Difference_IPv4Disjoint(t *testing.T) {
	source := xnetip.MustParseNetwork("10.0.0.0/8")
	other := xnetip.MustParseNetwork("192.168.0.0/16")
	require.Equal(t, []xnetip.Network{source}, slices.Collect(source.Difference(other)))
}

// verifies that an IPv6 subset leaves nothing.
func Test_Network_Difference_IPv6Subset(t *testing.T) {
	source := xnetip.MustParseNetwork("2001:db8::/64")
	other := xnetip.MustParseNetwork("2001:db8::/48")
	require.Empty(t, slices.Collect(source.Difference(other)))
}

// verifies the cross-family rule that operands of different
// families share no address, so the difference is the source.
//
// Adjust if D2 resolves differently.
func Test_Network_Difference_CrossFamilyYieldsSource(t *testing.T) {
	cases := []struct {
		name   string
		source string
		other  string
	}{
		{name: "IPv4 minus IPv6", source: "10.0.0.0/8", other: "2001:db8::/32"},
		{name: "IPv6 minus IPv4", source: "2001:db8::/32", other: "10.0.0.0/8"},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			source := xnetip.MustParseNetwork(testCase.source)
			other := xnetip.MustParseNetwork(testCase.other)
			require.Equal(t, []xnetip.Network{source}, slices.Collect(source.Difference(other)))
		})
	}
}

// verifies that an IPv4-mapped IPv6 network and an IPv4 network are
// different families.
//
// The difference is the IPv6 source, not the arithmetic overlap of
// the mapped storage forms.
//
// Adjust if D2 resolves differently.
func Test_Network_Difference_MappedIPv6VersusIPv4(t *testing.T) {
	source := xnetip.MustParseNetwork("::ffff:10.0.0.0/104")
	other := xnetip.MustParseNetwork("10.0.0.0/8")
	require.True(t, source.Is6())
	require.True(t, other.Is4())
	require.Equal(t, []xnetip.Network{source}, slices.Collect(source.Difference(other)))
}

// verifies the documented peel order through the family-agnostic
// type on the hand-checked case.
//
// The universe minus one host yields the 32 contiguous networks /1
// through /32 wrapped as IPv4 networks, most significant differing
// bit first.
func Test_Network_Difference_ExactOrderThroughNetwork(t *testing.T) {
	source := xnetip.MustParseNetwork("0.0.0.0/0")
	other := xnetip.MustParseNetwork("8.8.8.8/32")
	expectedTexts := []string{
		"128.0.0.0/1", "64.0.0.0/2", "32.0.0.0/3", "16.0.0.0/4",
		"0.0.0.0/5", "12.0.0.0/6", "10.0.0.0/7", "9.0.0.0/8",
		"8.128.0.0/9", "8.64.0.0/10", "8.32.0.0/11", "8.16.0.0/12",
		"8.0.0.0/13", "8.12.0.0/14", "8.10.0.0/15", "8.9.0.0/16",
		"8.8.128.0/17", "8.8.64.0/18", "8.8.32.0/19", "8.8.16.0/20",
		"8.8.0.0/21", "8.8.12.0/22", "8.8.10.0/23", "8.8.9.0/24",
		"8.8.8.128/25", "8.8.8.64/26", "8.8.8.32/27", "8.8.8.16/28",
		"8.8.8.0/29", "8.8.8.12/30", "8.8.8.10/31", "8.8.8.9/32",
	}
	expected := []xnetip.Network{}
	for _, text := range expectedTexts {
		expected = append(expected, xnetip.MustParseNetwork(text))
	}
	require.Equal(t, expected, slices.Collect(source.Difference(other)))
}

// verifies that breaking out of the loop stops the sequence after
// exactly the consumed items.
func Test_Network_Difference_EarlyBreakStops(t *testing.T) {
	source := xnetip.MustParseNetwork("192.168.0.0/16")
	other := xnetip.MustParseNetwork("192.168.1.0/24")
	consumed := 0
	for range source.Difference(other) {
		consumed++
		if consumed == 2 {
			break
		}
	}
	require.Equal(t, 2, consumed)
}

// verifies the exact non-contiguous IPv4 peel through the
// family-agnostic type, every part carrying the IPv4 family.
func Test_Network_Difference_IPv4NonContiguous(t *testing.T) {
	source := xnetip.MustParseNetwork("10.0.0.0/255.0.0.0")
	other := xnetip.MustParseNetwork("10.0.0.1/255.0.0.255")
	expectedTexts := []string{
		"10.0.0.128/255.0.0.128", "10.0.0.64/255.0.0.192",
		"10.0.0.32/255.0.0.224", "10.0.0.16/255.0.0.240",
		"10.0.0.8/255.0.0.248", "10.0.0.4/255.0.0.252",
		"10.0.0.2/255.0.0.254", "10.0.0.0/255.0.0.255",
	}
	expected := []xnetip.Network{}
	for _, text := range expectedTexts {
		expected = append(expected, xnetip.MustParseNetwork(text))
	}
	parts := slices.Collect(source.Difference(other))
	require.Equal(t, expected, parts)
	for _, part := range parts {
		require.True(t, part.Is4(), "part %v not IPv4", part)
	}
}

// verifies the non-contiguous IPv6 peel through the family-agnostic
// type.
//
// The eight IPv6 parts end at the subtrahend's address under the
// fully extended mask.
func Test_Network_Difference_IPv6NonContiguous(t *testing.T) {
	source := xnetip.MustParseNetwork("2001::/ffff::")
	other := xnetip.MustParseNetwork("2001::1/ffff::ff")
	parts := slices.Collect(source.Difference(other))
	require.Len(t, parts, 8)
	for _, part := range parts {
		require.True(t, part.Is6(), "part %v not IPv6", part)
	}
	require.Equal(t, xnetip.MustParseNetwork("2001::/ffff::ff"), parts[7])
}

// verifies delegation on random same-family pairs.
//
// The collected result equals the concrete family result wrapped, in
// the same order, so every part carries the source's family.
func Test_Network_Difference_DelegationProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		if rapid.Bool().Draw(t, "is4") {
			source := genNetwork4.Draw(t, "source4")
			other := genNetwork4.Draw(t, "other4")
			var expected []xnetip.Network
			for part := range source.Difference(other) {
				expected = append(expected, xnetip.NetworkFrom4(part))
			}
			collected := slices.Collect(xnetip.NetworkFrom4(source).Difference(xnetip.NetworkFrom4(other)))
			require.Equal(t, expected, collected)
			return
		}
		source := genNetwork6.Draw(t, "source6")
		other := genNetwork6.Draw(t, "other6")
		var expected []xnetip.Network
		for part := range source.Difference(other) {
			expected = append(expected, xnetip.NetworkFrom6(part))
		}
		collected := slices.Collect(xnetip.NetworkFrom6(source).Difference(xnetip.NetworkFrom6(other)))
		require.Equal(t, expected, collected)
	})
}

// verifies the cross-family rule on random pairs in both orders:
// the result is always the source alone.
//
// Adjust if D2 resolves differently.
func Test_Network_Difference_CrossFamilyProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		network4 := xnetip.NetworkFrom4(genNetwork4.Draw(t, "network4"))
		network6 := xnetip.NetworkFrom6(genNetwork6.Draw(t, "network6"))
		require.Equal(t, []xnetip.Network{network4}, slices.Collect(network4.Difference(network6)))
		require.Equal(t, []xnetip.Network{network6}, slices.Collect(network6.Difference(network4)))
	})
}

// verifies through the family-agnostic operations that every part
// lies inside the source and is disjoint from the subtrahend.
func Test_Network_Difference_PartsInvariantsProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		source := genNetwork.Draw(t, "source")
		other := genNetwork.Draw(t, "other")
		for part := range source.Difference(other) {
			require.True(t, source.Contains(part), "part %v not in source %v", part, source)
			require.False(t, other.Intersects(part), "part %v intersects %v", part, other)
		}
	})
}

// verifies that consuming the sequence with a range loop allocates
// nothing in either family.
func Test_Network_Difference_AllocationFree(t *testing.T) {
	source := xnetip.MustParseNetwork("0.0.0.0/0")
	other := xnetip.MustParseNetwork("8.8.8.8/32")
	requireNoAllocs(t, func() {
		for part := range source.Difference(other) {
			ipNetworkSink = part
		}
	})
}

// verifies that adjacency delegates within a family and is false
// across families.
//
// The family rule is absolute: even the IPv4-mapped IPv6 siblings of
// two adjacent IPv4 networks are not adjacent to the IPv4 originals.
func Test_Network_IsAdjacent_FamiliesAndBoundary(t *testing.T) {
	cases := []struct {
		name  string
		left  xnetip.Network
		right xnetip.Network
		want  bool
	}{
		{name: "IPv4 siblings", left: xnetip.MustParseNetwork("192.168.0.0/24"), right: xnetip.MustParseNetwork("192.168.1.0/24"), want: true},
		{name: "IPv6 siblings", left: xnetip.MustParseNetwork("2001:db8::/48"), right: xnetip.MustParseNetwork("2001:db8:1::/48"), want: true},
		{name: "mixed families", left: xnetip.MustParseNetwork("10.0.0.0/8"), right: xnetip.MustParseNetwork("2001:db8::/32"), want: false},
		{name: "mixed families reversed", left: xnetip.MustParseNetwork("2001:db8::/32"), right: xnetip.MustParseNetwork("10.0.0.0/8"), want: false},
		{name: "IPv4 identical", left: xnetip.MustParseNetwork("192.168.0.0/24"), right: xnetip.MustParseNetwork("192.168.0.0/24"), want: false},
		{name: "IPv4 universe vs IPv6 universe", left: xnetip.MustParseNetwork("0.0.0.0/0"), right: xnetip.Network{}, want: false},
		{name: "mapped IPv6 sibling vs the IPv4 sibling", left: xnetip.MustParseNetwork("::ffff:10.0.0.0/120"), right: xnetip.MustParseNetwork("10.0.1.0/24"), want: false},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			require.Equal(t, testCase.want, testCase.left.IsAdjacent(testCase.right))
		})
	}
}

// verifies that non-contiguous adjacency of both families flows
// through the wrapper.
func Test_Network_IsAdjacent_NonContiguousMasks(t *testing.T) {
	cases := []struct {
		name  string
		left  xnetip.Network
		right xnetip.Network
		want  bool
	}{
		{name: "IPv4 pattern siblings", left: xnetip.MustParseNetwork("10.0.0.1/255.255.0.255"), right: xnetip.MustParseNetwork("10.1.0.1/255.255.0.255"), want: true},
		{name: "IPv6 two-run siblings", left: xnetip.MustParseNetwork("::/ffff:ffff::ffff"), right: xnetip.MustParseNetwork("::1/ffff:ffff::ffff"), want: true},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			require.Equal(t, testCase.want, testCase.left.IsAdjacent(testCase.right))
		})
	}
}

// verifies that the wrapped predicate equals the concrete answer in
// each family, on random pairs and on constructed siblings.
//
// A sibling flips the lowest set mask bit of the address, so every
// draw with a non-empty mask exercises the adjacent case that random
// pairs almost never hit.
func Test_Network_IsAdjacent_AgreesWithConcreteProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		left4 := genNetwork4.Draw(t, "left4")
		right4 := genNetwork4.Draw(t, "right4")
		require.Equal(
			t,
			left4.IsAdjacent(right4),
			xnetip.NetworkFrom4(left4).IsAdjacent(xnetip.NetworkFrom4(right4)),
		)
		maskBytes := left4.Mask().As4()
		maskBits := binary.BigEndian.Uint32(maskBytes[:])
		if maskBits != 0 {
			addrBytes := left4.Addr().As4()
			addrBits := binary.BigEndian.Uint32(addrBytes[:])
			sibling, err := xnetip.Network4From(
				netipAddrFrom4Bits(addrBits^(maskBits&-maskBits)),
				netipAddrFrom4Bits(maskBits),
			)
			require.NoError(t, err)
			require.True(t, left4.IsAdjacent(sibling))
			require.True(t, xnetip.NetworkFrom4(left4).IsAdjacent(xnetip.NetworkFrom4(sibling)))
		}
		left6 := genNetwork6.Draw(t, "left6")
		right6 := genNetwork6.Draw(t, "right6")
		require.Equal(
			t,
			left6.IsAdjacent(right6),
			xnetip.NetworkFrom6(left6).IsAdjacent(xnetip.NetworkFrom6(right6)),
		)
	})
}

// verifies that networks of different families are never adjacent,
// whatever their masks.
func Test_Network_IsAdjacent_CrossFamilyAlwaysFalseProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		network4 := xnetip.NetworkFrom4(genNetwork4.Draw(t, "network4"))
		network6 := xnetip.NetworkFrom6(genNetwork6.Draw(t, "network6"))
		require.False(t, network4.IsAdjacent(network6))
		require.False(t, network6.IsAdjacent(network4))
	})
}

// verifies that adjacency is symmetric and irreflexive, whatever the
// families.
func Test_Network_IsAdjacent_SymmetryProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		left := genNetwork.Draw(t, "left")
		right := genNetwork.Draw(t, "right")
		require.Equal(t, left.IsAdjacent(right), right.IsAdjacent(left))
		require.False(t, left.IsAdjacent(left))
	})
}

// verifies that the predicate allocates nothing in either family and
// across families.
func Test_Network_IsAdjacent_AllocationFree(t *testing.T) {
	left4 := xnetip.MustParseNetwork("10.0.0.1/255.255.0.255")
	right4 := xnetip.MustParseNetwork("10.1.0.1/255.255.0.255")
	left6 := xnetip.MustParseNetwork("::/ffff:ffff::ffff")
	right6 := xnetip.MustParseNetwork("::1/ffff:ffff::ffff")
	requireNoAllocs(t, func() { okSink = left4.IsAdjacent(right4) })
	requireNoAllocs(t, func() { okSink = left6.IsAdjacent(right6) })
	requireNoAllocs(t, func() { okSink = left4.IsAdjacent(right6) })
}

// verifies that contiguity is judged in the network's own family, the
// concrete types' positive and negative pins lifted through the wrap.
func Test_Network_IsContiguous_JudgedInOwnFamily(t *testing.T) {
	cases := []struct {
		name    string
		network xnetip.Network
		want    bool
	}{
		{name: "IPv4 universe", network: mustNetworkIs4(t, "0.0.0.0", "0.0.0.0"), want: true},
		{name: "IPv4 /19", network: mustNetworkIs4(t, "213.180.192.0", "255.255.224.0"), want: true},
		{name: "IPv4 host route", network: mustNetworkIs4(t, "10.0.0.1", "255.255.255.255"), want: true},
		{name: "IPv6 universe", network: mustNetworkIs6(t, "::", "::"), want: true},
		{name: "IPv6 /40", network: mustNetworkIs6(t, "2a02:6b8:c00::", "ffff:ffff:ff00::"), want: true},
		{name: "IPv6 run ends at the half boundary", network: mustNetworkIs6(t, "2001:db8::", "ffff:ffff:ffff:ffff::"), want: true},
		{name: "IPv6 run crosses the half boundary", network: mustNetworkIs6(t, "2001:db8::", "ffff:ffff:ffff:ffff:8000::"), want: true},
		{name: "zero value is the IPv6 universe", network: xnetip.Network{}, want: true},
		{name: "mapped IPv6 with contiguous low mask", network: mustNetworkIs6(t, "::ffff:c0a8:100", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ff00"), want: true},
		{name: "IPv4 top mask bit clear", network: mustNetworkIs4(t, "0.0.0.0", "127.255.255.255"), want: false},
		{name: "IPv4 hole in the third octet", network: mustNetworkIs4(t, "213.180.0.192", "255.255.0.255"), want: false},
		{name: "IPv4 two runs", network: mustNetworkIs4(t, "192.168.0.1", "255.0.255.0"), want: false},
		{name: "IPv4 alternating", network: mustNetworkIs4(t, "170.85.170.85", "170.85.170.85"), want: false},
		{name: "IPv6 two runs", network: mustNetworkIs6(t, "2a02:6b8:c00::f800:0:0", "ffff:ffff:ff00::ffff:ffff:0:0"), want: false},
		{name: "IPv6 hole at bits 64..95", network: mustNetworkIs6(t, "2a02:6b8:0:0:1234:5678::", "ffff:ffff:0:0:ffff:ffff:0:0"), want: false},
		{name: "IPv6 hole straddling bit 64", network: mustNetworkIs6(t, "::", "ffff:ffff:ffff:fffe:8000::"), want: false},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			require.Equal(t, testCase.want, testCase.network.IsContiguous())
		})
	}
}

// verifies that the lifted predicate always equals the concrete IPv4
// one, the equivalence that licenses the branch-free stored form.
func Test_Network_IsContiguous_AgreesWithIPv4Property(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		network := genNetwork4.Draw(t, "network")
		require.Equal(t, network.IsContiguous(), xnetip.NetworkFrom4(network).IsContiguous())
	})
}

// verifies that the lifted predicate always equals the concrete IPv6
// one.
func Test_Network_IsContiguous_AgreesWithIPv6Property(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		network := genNetwork6.Draw(t, "network")
		require.Equal(t, network.IsContiguous(), xnetip.NetworkFrom6(network).IsContiguous())
	})
}

// verifies that the predicate agrees with the brute-force scan of the
// family-typed mask bytes, whatever the family.
func Test_Network_IsContiguous_MatchesBitScanProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		network := genNetwork.Draw(t, "network")
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
func Test_Network_IsContiguous_AllocationFree(t *testing.T) {
	network4 := mustNetworkIs4(t, "192.168.0.0", "255.255.0.0")
	network6 := mustNetworkIs6(t, "2001:db8::", "ffff:ffff::")
	requireNoAllocs(t, func() { okSink = network4.IsContiguous() })
	requireNoAllocs(t, func() { okSink = network6.IsContiguous() })
}

// verifies that a contiguous mask reports its family-native prefix
// length.
//
// IPv4 answers 0 through 32 despite the mapped storage, IPv6 answers
// 0 through 128, mapped IPv6 networks included.
func Test_Network_PrefixLen_FamilyNativeLength(t *testing.T) {
	cases := []struct {
		name    string
		network xnetip.Network
		want    int
	}{
		{name: "IPv4 /24", network: mustNetworkIs4(t, "192.168.1.0", "255.255.255.0"), want: 24},
		{name: "IPv6 /40", network: mustNetworkIs6(t, "2a02:6b8::", "ffff:ffff:ff00::"), want: 40},
		{name: "IPv6 host route /128", network: mustNetworkIs6(t, "2a02:6b8::1", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"), want: 128},
		{name: "IPv4 universe /0", network: mustNetworkIs4(t, "0.0.0.0", "0.0.0.0"), want: 0},
		{name: "IPv4 host route /32", network: mustNetworkIs4(t, "10.0.0.1", "255.255.255.255"), want: 32},
		{name: "IPv4 single leading bit /1", network: mustNetworkIs4(t, "128.0.0.0", "128.0.0.0"), want: 1},
		{name: "IPv6 universe /0", network: mustNetworkIs6(t, "::", "::"), want: 0},
		{name: "zero value is the IPv6 universe", network: xnetip.Network{}, want: 0},
		{name: "mapped IPv6 network keeps its 128-bit length", network: mustNetworkIs6(t, "::ffff:8.8.8.0", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ff00"), want: 120},
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
func Test_Network_PrefixLen_NonContiguousHasNone(t *testing.T) {
	cases := []struct {
		name    string
		network xnetip.Network
	}{
		{name: "IPv4 hole in the middle", network: mustNetworkIs4(t, "10.0.0.1", "255.0.0.255")},
		{name: "IPv4 alternating", network: mustNetworkIs4(t, "170.85.170.85", "170.85.170.85")},
		{name: "IPv6 two runs", network: mustNetworkIs6(t, "2001:db8::1", "ffff:ffff::ffff")},
		{name: "IPv6 hole ending at the half boundary", network: mustNetworkIs6(t, "2001:db8::", "ffff:ffff:ff00::ffff:ffff:0:0")},
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
func Test_Network_PrefixLen_AgreesWithIPv4Property(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		network := genNetwork4.Draw(t, "network")
		wantPrefix, wantOk := network.PrefixLen()
		prefix, ok := xnetip.NetworkFrom4(network).PrefixLen()
		require.Equal(t, wantOk, ok)
		require.Equal(t, wantPrefix, prefix)
	})
}

// verifies that wrapping an IPv6 network reports exactly the concrete
// IPv6 length, value and presence alike.
func Test_Network_PrefixLen_AgreesWithIPv6Property(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		network := genNetwork6.Draw(t, "network")
		wantPrefix, wantOk := network.PrefixLen()
		prefix, ok := xnetip.NetworkFrom6(network).PrefixLen()
		require.Equal(t, wantOk, ok)
		require.Equal(t, wantPrefix, prefix)
	})
}

// verifies that a prefix length exists exactly for contiguous masks,
// whatever the family, and that the absent case reports zero.
func Test_Network_PrefixLen_SomeIffContiguousProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		network := genNetwork.Draw(t, "network")
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
func Test_Network_PrefixLen_RoundTripsCIDRProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		addr4 := genNetipAddr4.Draw(t, "addr4")
		for cidr := range 33 {
			network, err := xnetip.NetworkFromCIDR(addr4, cidr)
			require.NoError(t, err)
			prefix, ok := network.PrefixLen()
			require.True(t, ok)
			require.Equal(t, cidr, prefix)
		}
		addr6 := genNetipAddr6.Draw(t, "addr6")
		for cidr := range 129 {
			network, err := xnetip.NetworkFromCIDR(addr6, cidr)
			require.NoError(t, err)
			prefix, ok := network.PrefixLen()
			require.True(t, ok)
			require.Equal(t, cidr, prefix)
		}
	})
}

// verifies that computing the prefix allocates nothing for either
// family and either outcome.
func Test_Network_PrefixLen_AllocationFree(t *testing.T) {
	contiguous4 := mustNetworkIs4(t, "192.168.0.0", "255.255.0.0")
	nonContiguous4 := mustNetworkIs4(t, "192.168.0.1", "255.255.0.255")
	contiguous6 := mustNetworkIs6(t, "2001:db8::", "ffff:ffff::")
	nonContiguous6 := mustNetworkIs6(t, "2001:db8::1", "ffff:ffff::ffff")
	requireNoAllocs(t, func() { intSink, okSink = contiguous4.PrefixLen() })
	requireNoAllocs(t, func() { intSink, okSink = nonContiguous4.PrefixLen() })
	requireNoAllocs(t, func() { intSink, okSink = contiguous6.PrefixLen() })
	requireNoAllocs(t, func() { intSink, okSink = nonContiguous6.PrefixLen() })
}

// verifies that a network prints in its own family's text form: IPv4
// unmapped with a family-native suffix, IPv6 as the wrapped network.
func Test_Network_String_PrintsFamilyForm(t *testing.T) {
	cases := []struct {
		name    string
		network xnetip.Network
		want    string
	}{
		{name: "IPv4 CIDR", network: mustNetworkIs4(t, "10.0.0.0", "255.0.0.0"), want: "10.0.0.0/8"},
		{name: "IPv6 CIDR", network: mustNetworkIs6(t, "2001:db8::", "ffff:ffff::"), want: "2001:db8::/32"},
		{name: "IPv4 host route keeps /32", network: mustNetworkIs4(t, "127.0.0.1", "255.255.255.255"), want: "127.0.0.1/32"},
		{name: "IPv4 universe hides the stored /96", network: mustNetworkIs4(t, "0.0.0.0", "0.0.0.0"), want: "0.0.0.0/0"},
		{name: "IPv6 universe", network: mustNetworkIs6(t, "::", "::"), want: "::/0"},
		{name: "zero value", network: xnetip.Network{}, want: "::/0"},
		{name: "IPv6 mapped stays IPv6 text", network: xnetip.NetworkFrom6(mustNetwork6(t, "::ffff:192.0.2.0", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ff00")), want: "::ffff:192.0.2.0/120"},
		{name: "IPv4 wrapped explicitly", network: xnetip.NetworkFrom4(mustNetwork4(t, "192.0.2.0", "255.255.255.0")), want: "192.0.2.0/24"},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			require.Equal(t, testCase.want, testCase.network.String())
		})
	}
}

// verifies that a non-contiguous mask prints in its family's mask
// form, the IPv4 one unmapped from the 128-bit storage.
func Test_Network_String_NonContiguousUsesMaskForm(t *testing.T) {
	cases := []struct {
		name    string
		network xnetip.Network
		want    string
	}{
		{name: "IPv4 two-run", network: mustNetworkIs4(t, "192.168.0.1", "255.255.0.255"), want: "192.168.0.1/255.255.0.255"},
		{name: "IPv6 two-run", network: mustNetworkIs6(t, "2a02:6b8:0:0:0:1234::", "ffff:ffff:0:0:ffff:ffff:0:0"), want: "2a02:6b8::1234:0:0/ffff:ffff::ffff:ffff:0:0"},
		{name: "IPv4 alternating", network: mustNetworkIs4(t, "170.85.170.85", "170.85.170.85"), want: "170.85.170.85/170.85.170.85"},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			require.Equal(t, testCase.want, testCase.network.String())
		})
	}
}

// verifies that appending writes after the caller's bytes and leaves
// them intact.
func Test_Network_AppendTo_KeepsExistingBytes(t *testing.T) {
	network := mustNetworkIs4(t, "10.0.0.0", "255.0.0.0")
	require.Equal(t, "x 10.0.0.0/8", string(network.AppendTo([]byte("x "))))
}

// verifies that wrapping an IPv4 network changes nothing in its text.
func Test_Network_String_MatchesIPv4Property(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		network := genNetwork4.Draw(t, "network")
		require.Equal(t, network.String(), xnetip.NetworkFrom4(network).String())
	})
}

// verifies that wrapping an IPv6 network changes nothing in its text.
func Test_Network_String_MatchesIPv6Property(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		network := genNetwork6.Draw(t, "network")
		require.Equal(t, network.String(), xnetip.NetworkFrom6(network).String())
	})
}

// verifies that appending to an empty buffer yields the same bytes the
// string form has, and that drawn buffer content survives untouched.
func Test_Network_AppendTo_MatchesStringProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		network := genNetwork.Draw(t, "network")
		prefix := rapid.SliceOf(rapid.Byte()).Draw(t, "buffer")
		require.Equal(t, network.String(), string(network.AppendTo(nil)))
		extended := network.AppendTo(slices.Clone(prefix))
		require.True(t, bytes.Equal(prefix, extended[:len(prefix)]))
		require.Equal(t, network.String(), string(extended[len(prefix):]))
	})
}

// verifies that appending into a buffer with enough capacity allocates
// nothing for either family, the IPv4 extraction included.
func Test_Network_AppendTo_AllocationFree(t *testing.T) {
	network4 := mustNetworkIs4(t, "192.168.0.1", "255.255.0.255")
	network6 := mustNetworkIs6(t, "2001:db8::", "ffff:ffff:ff00::ffff:ffff:0:0")
	buffer := make([]byte, 0, 128)
	requireNoAllocs(t, func() { bytesSink = network4.AppendTo(buffer[:0]) })
	requireNoAllocs(t, func() { bytesSink = network6.AppendTo(buffer[:0]) })
}

// verifies that rendering to a string costs exactly the one string
// conversion for either family.
func Test_Network_String_SingleAllocation(t *testing.T) {
	network4 := mustNetworkIs4(t, "10.0.0.0", "255.0.0.0")
	network6 := mustNetworkIs6(t, "2001:db8::", "ffff:ffff::")
	require.Equal(t, 1, int(testing.AllocsPerRun(100, func() { stringSink = network4.String() })))
	require.Equal(t, 1, int(testing.AllocsPerRun(100, func() { stringSink = network6.String() })))
}

func BenchmarkNetwork_String_IPv4(b *testing.B) {
	network := mustNetworkIs4(b, "10.0.0.0", "255.0.0.0")
	b.ReportAllocs()
	for b.Loop() {
		stringSink = network.String()
	}
}

func BenchmarkNetwork_String_IPv6(b *testing.B) {
	network := mustNetworkIs6(b, "2001:db8::", "ffff:ffff::")
	b.ReportAllocs()
	for b.Loop() {
		stringSink = network.String()
	}
}

func BenchmarkNetwork_AppendTo_IPv4(b *testing.B) {
	network := mustNetworkIs4(b, "10.0.0.0", "255.0.0.0")
	buffer := make([]byte, 0, 32)
	b.ReportAllocs()
	for b.Loop() {
		bytesSink = network.AppendTo(buffer[:0])
	}
}

// verifies that the address part selects the family: every accepted
// form lands on the concrete network of its own family.
func Test_ParseNetwork_AcceptsBothFamilies(t *testing.T) {
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
			network, err := xnetip.ParseNetwork(testCase.input)
			require.NoError(t, err)
			if testCase.want4 {
				require.Equal(t, mustNetworkIs4(t, testCase.wantAddr, testCase.wantMask), network)
			} else {
				require.Equal(t, mustNetworkIs6(t, testCase.wantAddr, testCase.wantMask), network)
			}
		})
	}
}

// verifies that all six documented forms parse and print back to their
// canonical text, the family following the address part.
func Test_ParseNetwork_SixDocumentedForms(t *testing.T) {
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
			network, err := xnetip.ParseNetwork(testCase.input)
			require.NoError(t, err)
			require.Equal(t, testCase.want4, network.Is4())
			require.Equal(t, testCase.want, network.String())
		})
	}
}

// verifies that IPv4-mapped text is an IPv6 network, exactly as the
// mapped address itself reports the IPv6 family.
func Test_ParseNetwork_MappedTextIsIPv6(t *testing.T) {
	network, err := xnetip.ParseNetwork("::ffff:192.0.2.0/120")
	require.NoError(t, err)
	require.True(t, network.Is6())
	_, ok := network.IPv4()
	require.False(t, ok)
	require.Equal(t, "::ffff:192.0.2.0/120", network.String())
}

// verifies that each family's universe parses into its own family: the
// IPv4 one is not the IPv6 zero value and reports a zero prefix.
func Test_ParseNetwork_UniversePerFamily(t *testing.T) {
	network4, err := xnetip.ParseNetwork("0.0.0.0/0")
	require.NoError(t, err)
	require.True(t, network4.Is4())
	bits, ok := network4.PrefixLen()
	require.True(t, ok)
	require.Equal(t, 0, bits)
	network6, err := xnetip.ParseNetwork("::/0")
	require.NoError(t, err)
	require.True(t, network6.Is6())
	require.Equal(t, xnetip.Network{}, network6)
}

// verifies that a digits-only suffix past the family's own limit is a
// prefix-length overflow in either family.
func Test_ParseNetwork_RejectsPrefixOverflow(t *testing.T) {
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
			network, err := xnetip.ParseNetwork(testCase.input)
			require.ErrorIs(t, err, xnetip.ErrCIDROverflow)
			require.Equal(t, xnetip.Network{}, network)
		})
	}
}

// verifies that the strict prefix grammar and the same-family mask rule
// hold through the family-agnostic entry point.
func Test_ParseNetwork_RejectsBadSuffix(t *testing.T) {
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
			network, err := xnetip.ParseNetwork(testCase.input)
			require.ErrorIs(t, err, xnetip.ErrInvalidMask)
			require.Equal(t, xnetip.Network{}, network)
		})
	}
}

// verifies that a cross-family mask keeps the family sentinel in the
// chain behind the mask sentinel.
func Test_ParseNetwork_CrossFamilyMaskKeepsBothSentinels(t *testing.T) {
	_, err := xnetip.ParseNetwork("2001:db8::1/255.255.255.0")
	require.ErrorIs(t, err, xnetip.ErrInvalidMask)
	require.ErrorIs(t, err, xnetip.ErrAddrFamilyMismatch)
}

// verifies that text whose address part is no address of either family
// is rejected with the parse sentinel.
func Test_ParseNetwork_RejectsBadAddress(t *testing.T) {
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
			network, err := xnetip.ParseNetwork(testCase.input)
			require.ErrorIs(t, err, xnetip.ErrParse)
			require.Equal(t, xnetip.Network{}, network)
		})
	}
}

// verifies that a zone suffix is rejected with the zone sentinel
// through the family-agnostic entry point.
func Test_ParseNetwork_RejectsZone(t *testing.T) {
	network, err := xnetip.ParseNetwork("fe80::1%eth0/64")
	require.ErrorIs(t, err, xnetip.ErrZone)
	require.Equal(t, xnetip.Network{}, network)
}

// verifies that non-contiguous masks of both families flow through the
// family-agnostic parser verbatim.
func Test_ParseNetwork_NonContiguousMasks(t *testing.T) {
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
			network, err := xnetip.ParseNetwork(testCase.input)
			require.NoError(t, err)
			if testCase.want4 {
				require.Equal(t, mustNetworkIs4(t, testCase.wantAddr, testCase.wantMask), network)
			} else {
				require.Equal(t, mustNetworkIs6(t, testCase.wantAddr, testCase.wantMask), network)
			}
		})
	}
}

// verifies that the must variant panics on invalid input instead of
// returning an error.
func Test_MustParseNetwork_PanicsOnInvalidInput(t *testing.T) {
	require.Panics(t, func() { xnetip.MustParseNetwork("hello") })
}

// verifies that the must variant passes a valid parse through.
func Test_MustParseNetwork_ReturnsParsedNetwork(t *testing.T) {
	network := xnetip.MustParseNetwork("10.0.0.0/8")
	require.Equal(t, mustNetworkIs4(t, "10.0.0.0", "255.0.0.0"), network)
}

// verifies that every parse error names this parser and echoes the
// rejected input in quotes.
func Test_ParseNetwork_ErrorEchoesInput(t *testing.T) {
	_, err := xnetip.ParseNetwork("192.168.1.0/33")
	require.Error(t, err)
	require.True(t, strings.HasPrefix(err.Error(), "xnetip.ParseNetwork("))
	require.Contains(t, err.Error(), `"192.168.1.0/33"`)
}

// verifies that the dispatcher never disagrees with the family parsers
// on text either of them accepts.
func Test_ParseNetwork_AgreesWithFamilyParsersProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		if rapid.Bool().Draw(t, "is4") {
			text := genNetwork4.Draw(t, "network4").String()
			concrete, err := xnetip.ParseNetwork4(text)
			require.NoError(t, err)
			agnostic, err := xnetip.ParseNetwork(text)
			require.NoError(t, err)
			require.Equal(t, xnetip.NetworkFrom4(concrete), agnostic)
		} else {
			text := genNetwork6.Draw(t, "network6").String()
			concrete, err := xnetip.ParseNetwork6(text)
			require.NoError(t, err)
			agnostic, err := xnetip.ParseNetwork(text)
			require.NoError(t, err)
			require.Equal(t, xnetip.NetworkFrom6(concrete), agnostic)
		}
	})
}

// verifies that parsing the string form recovers the network exactly,
// family flag included.
func Test_ParseNetwork_StringRoundTripProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		network := genNetwork.Draw(t, "network")
		parsed, err := xnetip.ParseNetwork(network.String())
		require.NoError(t, err)
		require.Equal(t, network, parsed)
	})
}

// verifies that the dispatcher rejects a string exactly when both
// family parsers reject it, and never panics on any byte string.
func Test_ParseNetwork_RejectAgreementProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		input := string(rapid.SliceOfN(rapid.Byte(), 0, 60).Draw(t, "input"))
		_, err := xnetip.ParseNetwork(input)
		_, err4 := xnetip.ParseNetwork4(input)
		_, err6 := xnetip.ParseNetwork6(input)
		require.Equal(t, err4 != nil && err6 != nil, err != nil)
	})
}

// verifies that on CIDR-shaped text of either family the accept set,
// the family and the parsed value are those of the std prefix parser.
func Test_ParseNetwork_MatchesNetipParsePrefixProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		var addr netip.Addr
		if rapid.Bool().Draw(t, "is4") {
			addr = genNetipAddr4.Draw(t, "addr4")
		} else {
			addr = genNetipAddr6.Draw(t, "addr6")
		}
		limit := 140
		input := addr.String() + "/" + strconv.Itoa(rapid.IntRange(0, limit).Draw(t, "bits"))
		parsed, err := xnetip.ParseNetwork(input)
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
func Test_ParseNetwork_AllocationFree(t *testing.T) {
	requireNoAllocs(t, func() { ipNetworkSink, errSink = xnetip.ParseNetwork("10.0.0.0/8") })
	requireNoAllocs(t, func() { ipNetworkSink, errSink = xnetip.ParseNetwork("2001:db8::/32") })
}

func FuzzParseNetwork(f *testing.F) {
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
		network, err := xnetip.ParseNetwork(input)
		if err == nil {
			back, err := xnetip.ParseNetwork(network.String())
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

func BenchmarkParseNetwork_IPv4CIDR(b *testing.B) {
	b.ReportAllocs()
	for b.Loop() {
		ipNetworkSink, errSink = xnetip.ParseNetwork("10.0.0.0/8")
	}
}

func BenchmarkParseNetwork_IPv6CIDR(b *testing.B) {
	b.ReportAllocs()
	for b.Loop() {
		ipNetworkSink, errSink = xnetip.ParseNetwork("2001:db8::/32")
	}
}

func BenchmarkParseNetwork_IPv4Bare(b *testing.B) {
	b.ReportAllocs()
	for b.Loop() {
		ipNetworkSink, errSink = xnetip.ParseNetwork("10.0.0.1")
	}
}

func BenchmarkParseNetwork_Reject(b *testing.B) {
	b.ReportAllocs()
	for b.Loop() {
		ipNetworkSink, errSink = xnetip.ParseNetwork("hello")
	}
}

// verifies that the marshaled text is the string form in the network's
// own family: the IPv4-mapped storage form never leaks.
func Test_Network_MarshalText_MatchesStringForm(t *testing.T) {
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
			text, err := xnetip.MustParseNetwork(testCase.input).MarshalText()
			require.NoError(t, err)
			require.Equal(t, testCase.want, string(text))
		})
	}
}

// verifies that the zero value marshals as the IPv6 universe.
func Test_Network_MarshalText_ZeroValueIsIPv6Universe(t *testing.T) {
	text, err := xnetip.Network{}.MarshalText()
	require.NoError(t, err)
	require.Equal(t, "::/0", string(text))
}

// verifies that unmarshaling detects the family from the address part
// and lands on the concrete network of that family.
func Test_Network_UnmarshalText_SetsFamilyFromText(t *testing.T) {
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
			var network xnetip.Network
			require.NoError(t, network.UnmarshalText([]byte(testCase.input)))
			if testCase.want4 {
				require.Equal(t, mustNetworkIs4(t, testCase.wantAddr, testCase.wantMask), network)
			} else {
				require.Equal(t, mustNetworkIs6(t, testCase.wantAddr, testCase.wantMask), network)
			}
		})
	}
}

// verifies that IPv4-mapped text unmarshals as an IPv6 network, never
// collapsing into the IPv4 family.
func Test_Network_UnmarshalText_MappedTextIsIPv6(t *testing.T) {
	var network xnetip.Network
	require.NoError(t, network.UnmarshalText([]byte("::ffff:10.0.0.0/104")))
	require.True(t, network.Is6())
	_, ok := network.IPv4()
	require.False(t, ok)
}

// verifies that empty text is an error, because the zero value is the
// valid universe network and must not appear out of a missing field.
func Test_Network_UnmarshalText_EmptyTextIsError(t *testing.T) {
	network := xnetip.MustParseNetwork("10.0.0.0/8")
	err := network.UnmarshalText(nil)
	require.ErrorIs(t, err, xnetip.ErrEmptyInput)
	require.Equal(t, xnetip.MustParseNetwork("10.0.0.0/8"), network)
}

// verifies that a failed unmarshal reports the parser's sentinel and
// leaves the receiver untouched.
func Test_Network_UnmarshalText_KeepsReceiverOnError(t *testing.T) {
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
			network := xnetip.MustParseNetwork("192.168.0.0/24")
			err := network.UnmarshalText([]byte(testCase.input))
			require.ErrorIs(t, err, testCase.sentinel)
			require.Equal(t, xnetip.MustParseNetwork("192.168.0.0/24"), network)
		})
	}
}

// verifies that a slice mixing both families round-trips through JSON
// with each element's family preserved.
func Test_Network_MarshalText_JSONMixedFamilies(t *testing.T) {
	value := []xnetip.Network{
		xnetip.MustParseNetwork("10.0.0.0/8"),
		xnetip.MustParseNetwork("2001:db8::/32"),
	}
	encoded, err := json.Marshal(value)
	require.NoError(t, err)
	require.Equal(t, `["10.0.0.0/8","2001:db8::/32"]`, string(encoded))
	var decoded []xnetip.Network
	require.NoError(t, json.Unmarshal(encoded, &decoded))
	require.Equal(t, value, decoded)
	require.True(t, decoded[0].Is4())
	require.True(t, decoded[1].Is6())
}

// verifies that the type works as a JSON map key, which encoding/json
// routes through the text marshaler pair.
func Test_Network_MarshalText_JSONMapKeyRoundTrip(t *testing.T) {
	value := map[xnetip.Network]int{xnetip.MustParseNetwork("10.0.0.0/8"): 1}
	encoded, err := json.Marshal(value)
	require.NoError(t, err)
	require.Equal(t, `{"10.0.0.0/8":1}`, string(encoded))
	var decoded map[xnetip.Network]int
	require.NoError(t, json.Unmarshal(encoded, &decoded))
	require.Equal(t, value, decoded)
}

// verifies that unmarshaling the marshaled text recovers the network
// exactly, the family flag included.
func Test_Network_MarshalText_RoundTripProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		network := genNetwork.Draw(t, "network")
		text, err := network.MarshalText()
		require.NoError(t, err)
		require.Equal(t, []byte(network.String()), text)
		var back xnetip.Network
		require.NoError(t, back.UnmarshalText(text))
		require.Equal(t, network, back)
	})
}

// verifies that the family-agnostic text never differs from the
// concrete type's text for the same network.
func Test_Network_MarshalText_AgreesWithConcreteTypesProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		if rapid.Bool().Draw(t, "is4") {
			network := genNetwork4.Draw(t, "network4")
			concreteText, err := network.MarshalText()
			require.NoError(t, err)
			agnosticText, err := xnetip.NetworkFrom4(network).MarshalText()
			require.NoError(t, err)
			require.Equal(t, concreteText, agnosticText)
		} else {
			network := genNetwork6.Draw(t, "network6")
			concreteText, err := network.MarshalText()
			require.NoError(t, err)
			agnosticText, err := xnetip.NetworkFrom6(network).MarshalText()
			require.NoError(t, err)
			require.Equal(t, concreteText, agnosticText)
		}
	})
}

// verifies that a JSON round trip of a slice mixing families preserves
// every element for every mask shape.
func Test_Network_MarshalText_JSONRoundTripProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		value := rapid.SliceOfN(genNetwork, 0, 8).Draw(t, "networks")
		encoded, err := json.Marshal(value)
		require.NoError(t, err)
		var decoded []xnetip.Network
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
func Test_Network_MarshalText_MatchesNetipPrefixProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		network := genNetwork.Draw(t, "network")
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
func Test_Network_UnmarshalText_EmptyTextDivergesFromNetip(t *testing.T) {
	var stdPrefix netip.Prefix
	require.NoError(t, stdPrefix.UnmarshalText(nil))
	var network xnetip.Network
	require.Error(t, network.UnmarshalText(nil))
}

// verifies that marshaling allocates exactly the returned slice in
// both families.
func Test_Network_MarshalText_SingleAllocation(t *testing.T) {
	network4 := xnetip.MustParseNetwork("10.0.0.0/8")
	network6 := xnetip.MustParseNetwork("2001:db8::/32")
	require.Equal(t, 1, int(testing.AllocsPerRun(100, func() { bytesSink, errSink = network4.MarshalText() })))
	require.Equal(t, 1, int(testing.AllocsPerRun(100, func() { bytesSink, errSink = network6.MarshalText() })))
}

// verifies that a valid netip.Prefix converts into the network of its
// address's family, host bits cleared.
func Test_NetworkFromPrefix_ConvertsValidPrefixes(t *testing.T) {
	cases := []struct {
		name   string
		prefix netip.Prefix
		want   xnetip.Network
	}{
		{
			name:   "IPv4 prefix",
			prefix: netip.MustParsePrefix("10.0.0.0/8"),
			want:   xnetip.MustParseNetwork("10.0.0.0/8"),
		},
		{
			name:   "IPv6 prefix",
			prefix: netip.MustParsePrefix("2001:db8::/32"),
			want:   xnetip.MustParseNetwork("2001:db8::/32"),
		},
		{
			name:   "IPv4 host bits cleared",
			prefix: netip.MustParsePrefix("10.1.2.3/8"),
			want:   xnetip.MustParseNetwork("10.0.0.0/8"),
		},
		{
			name:   "IPv6 host bits cleared",
			prefix: netip.MustParsePrefix("2001:db8::1/32"),
			want:   xnetip.MustParseNetwork("2001:db8::/32"),
		},
		{
			name:   "IPv6 /0 is the zero value",
			prefix: netip.MustParsePrefix("::/0"),
			want:   xnetip.Network{},
		},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			network, ok := xnetip.NetworkFromPrefix(testCase.prefix)
			require.True(t, ok)
			require.Equal(t, testCase.want, network)
		})
	}
}

// verifies that an IPv4-mapped prefix converts into an IPv6 network,
// never into its IPv4 counterpart, the netip family rule.
func Test_NetworkFromPrefix_MappedPrefixStaysIPv6(t *testing.T) {
	network, ok := xnetip.NetworkFromPrefix(netip.MustParsePrefix("::ffff:10.0.0.0/104"))
	require.True(t, ok)
	require.True(t, network.Is6())
	_, isIPv4 := network.IPv4()
	require.False(t, isIPv4)
	require.Equal(t, xnetip.MustParseNetwork("::ffff:10.0.0.0/104"), network)
}

// verifies that the IPv4 universe converts with its family length,
// not the 96-bit one of the mapped storage form.
func Test_NetworkFromPrefix_IPv4UniverseKeepsFamilyLength(t *testing.T) {
	network, ok := xnetip.NetworkFromPrefix(netip.MustParsePrefix("0.0.0.0/0"))
	require.True(t, ok)
	require.True(t, network.Is4())
	prefixLen, ok := network.PrefixLen()
	require.True(t, ok)
	require.Zero(t, prefixLen)
}

// verifies that the invalid zero prefix is rejected.
func Test_NetworkFromPrefix_RejectsInvalidPrefix(t *testing.T) {
	network, ok := xnetip.NetworkFromPrefix(netip.Prefix{})
	require.False(t, ok)
	require.Equal(t, xnetip.Network{}, network)
}

// verifies that a contiguous network converts to the already-masked
// netip.Prefix of its own family, never the mapped storage form.
func Test_Network_Prefix_OwnFamilyForms(t *testing.T) {
	cases := []struct {
		name    string
		network xnetip.Network
		want    netip.Prefix
	}{
		{
			name:    "IPv4 network yields an IPv4 prefix",
			network: xnetip.MustParseNetwork("192.168.0.0/24"),
			want:    netip.MustParsePrefix("192.168.0.0/24"),
		},
		{
			name:    "IPv4 universe stays 0.0.0.0/0",
			network: xnetip.MustParseNetwork("0.0.0.0/0"),
			want:    netip.MustParsePrefix("0.0.0.0/0"),
		},
		{
			name:    "IPv6 network",
			network: xnetip.MustParseNetwork("2a02:6b8:c00::/40"),
			want:    netip.MustParsePrefix("2a02:6b8:c00::/40"),
		},
		{
			name:    "IPv4-mapped IPv6 network stays IPv6",
			network: xnetip.MustParseNetwork("::ffff:10.0.0.0/104"),
			want:    netip.MustParsePrefix("::ffff:10.0.0.0/104"),
		},
		{
			name:    "zero value is the IPv6 universe",
			network: xnetip.Network{},
			want:    netip.MustParsePrefix("::/0"),
		},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			prefix, ok := testCase.network.Prefix()
			require.True(t, ok)
			require.Equal(t, testCase.want, prefix)
			require.Equal(t, prefix.Masked(), prefix)
		})
	}
	mapped, ok := xnetip.MustParseNetwork("::ffff:10.0.0.0/104").Prefix()
	require.True(t, ok)
	require.True(t, mapped.Addr().Is4In6())
	plain, ok := xnetip.MustParseNetwork("192.168.0.0/24").Prefix()
	require.True(t, ok)
	require.True(t, plain.Addr().Is4())
	require.Equal(t, 24, plain.Bits())
}

// verifies that a non-contiguous mask of either family has no prefix
// form and answers the invalid zero netip.Prefix.
func Test_Network_Prefix_NonContiguousHasNone(t *testing.T) {
	cases := []struct {
		name    string
		network xnetip.Network
	}{
		{name: "IPv4 two runs", network: xnetip.MustParseNetwork("10.0.0.0/255.0.255.0")},
		{name: "IPv6 two runs", network: xnetip.MustParseNetwork("2001:db8::/ffff:ffff::ffff:ffff:0:0")},
		{name: "IPv4 alternating", network: xnetip.MustParseNetwork("170.85.170.85/170.85.170.85")},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			prefix, ok := testCase.network.Prefix()
			require.False(t, ok)
			require.Equal(t, netip.Prefix{}, prefix)
		})
	}
}

// verifies that any valid prefix of either family converts into a
// network of that family and back to its masked self.
func Test_NetworkFromPrefix_FamilyFollowsAddressProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		var stdPrefix netip.Prefix
		if rapid.Bool().Draw(t, "is4") {
			stdPrefix = genIPv4Prefix.Draw(t, "prefix4")
		} else {
			stdPrefix = genIPv6Prefix.Draw(t, "prefix6")
		}
		network, ok := xnetip.NetworkFromPrefix(stdPrefix)
		require.True(t, ok)
		require.Equal(t, stdPrefix.Addr().Is4(), network.Is4())
		back, ok := network.Prefix()
		require.True(t, ok)
		require.Equal(t, stdPrefix.Masked(), back)
	})
}

// verifies that a prefix form exists exactly for contiguous masks,
// whatever the drawn family and mask shape.
func Test_Network_Prefix_SomeIffContiguousProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		network := genNetwork.Draw(t, "network")
		prefix, ok := network.Prefix()
		require.Equal(t, network.IsContiguous(), ok)
		if !ok {
			require.Equal(t, netip.Prefix{}, prefix)
		}
	})
}

// verifies that a contiguous network survives the round trip through
// netip.Prefix unchanged, its family included.
func Test_Network_Prefix_RoundTripProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		network := genNetwork.Draw(t, "network")
		stdPrefix, ok := network.Prefix()
		if !ok {
			return
		}
		back, ok := xnetip.NetworkFromPrefix(stdPrefix)
		require.True(t, ok)
		require.Equal(t, network, back)
	})
}

// verifies that wrapping a concrete network changes neither the
// prefix form nor its existence.
func Test_Network_Prefix_AgreesWithConcreteTypesProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		network4 := genNetwork4.Draw(t, "network4")
		concrete4, concrete4Ok := network4.Prefix()
		wrapped4, wrapped4Ok := xnetip.NetworkFrom4(network4).Prefix()
		require.Equal(t, concrete4Ok, wrapped4Ok)
		require.Equal(t, concrete4, wrapped4)
		network6 := genNetwork6.Draw(t, "network6")
		concrete6, concrete6Ok := network6.Prefix()
		wrapped6, wrapped6Ok := xnetip.NetworkFrom6(network6).Prefix()
		require.Equal(t, concrete6Ok, wrapped6Ok)
		require.Equal(t, concrete6, wrapped6)
	})
}

// verifies that both conversion directions allocate nothing for
// either family on any outcome.
func Test_NetworkFromPrefix_AllocationFree(t *testing.T) {
	prefix4 := netip.MustParsePrefix("10.0.0.0/8")
	prefix6 := netip.MustParsePrefix("2001:db8::/32")
	requireNoAllocs(t, func() { ipNetworkSink, okSink = xnetip.NetworkFromPrefix(prefix4) })
	requireNoAllocs(t, func() { ipNetworkSink, okSink = xnetip.NetworkFromPrefix(prefix6) })
	requireNoAllocs(t, func() { ipNetworkSink, okSink = xnetip.NetworkFromPrefix(netip.Prefix{}) })
}

// verifies that converting out to a netip.Prefix allocates nothing
// for either family, whatever the mask's shape.
func Test_Network_Prefix_AllocationFree(t *testing.T) {
	network4 := xnetip.MustParseNetwork("192.168.0.0/24")
	network6 := xnetip.MustParseNetwork("2a02:6b8:c00::/40")
	nonContiguous := xnetip.MustParseNetwork("10.0.0.0/255.0.255.0")
	requireNoAllocs(t, func() { prefixSink, okSink = network4.Prefix() })
	requireNoAllocs(t, func() { prefixSink, okSink = network6.Prefix() })
	requireNoAllocs(t, func() { prefixSink, okSink = nonContiguous.Prefix() })
}

// verifies that the last address comes back in the network's own
// family: an Is4 address for IPv4, an Is6 one for IPv6.
func Test_Network_LastAddr_FamilyPreserved(t *testing.T) {
	cases := []struct {
		name    string
		network xnetip.Network
		want    netip.Addr
	}{
		{name: "IPv4 /24 broadcast", network: xnetip.MustParseNetwork("192.168.1.0/24"), want: netip.MustParseAddr("192.168.1.255")},
		{name: "IPv4 host route", network: xnetip.MustParseNetwork("10.0.0.1"), want: netip.MustParseAddr("10.0.0.1")},
		{name: "IPv4 default route", network: xnetip.MustParseNetwork("0.0.0.0/0"), want: netip.MustParseAddr("255.255.255.255")},
		{name: "IPv6 /64", network: xnetip.MustParseNetwork("2001:db8:1::/64"), want: netip.MustParseAddr("2001:db8:1::ffff:ffff:ffff:ffff")},
		{name: "IPv6 host route", network: xnetip.MustParseNetwork("2a02:6b8::1"), want: netip.MustParseAddr("2a02:6b8::1")},
		{name: "IPv6 default route", network: xnetip.MustParseNetwork("::/0"), want: netip.MustParseAddr("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff")},
		{name: "zero value is the IPv6 default route", network: xnetip.Network{}, want: netip.MustParseAddr("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff")},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			last := testCase.network.LastAddr()
			require.Equal(t, testCase.want, last)
			require.Equal(t, testCase.network.Is4(), last.Is4())
		})
	}
}

// verifies that a non-contiguous mask sets every host bit in either
// family, holes outside the trailing run included.
func Test_Network_LastAddr_NonContiguousMasks(t *testing.T) {
	cases := []struct {
		name    string
		network xnetip.Network
		want    netip.Addr
	}{
		{name: "IPv4 two-run mask", network: mustNetworkIs4(t, "192.168.0.1", "255.255.0.255"), want: netip.MustParseAddr("192.168.255.1")},
		{name: "IPv6 two-run mask", network: mustNetworkIs6(t, "2a02:6b8:c00::1234:0:0", "ffff:ffff:ff00::ffff:ffff:0:0"), want: netip.MustParseAddr("2a02:6b8:cff:ffff:0:1234:ffff:ffff")},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			require.Equal(t, testCase.want, testCase.network.LastAddr())
		})
	}
}

// verifies that a wrapped IPv4 network answers exactly what the
// concrete type answers, as an Is4 address.
func Test_Network_LastAddr_MatchesIPv4Property(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		network := genNetwork4.Draw(t, "network")
		last := xnetip.NetworkFrom4(network).LastAddr()
		require.Equal(t, network.LastAddr(), last)
		require.True(t, last.Is4())
	})
}

// verifies that a wrapped IPv6 network answers exactly what the
// concrete type answers.
func Test_Network_LastAddr_MatchesIPv6Property(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		network := genNetwork6.Draw(t, "network")
		require.Equal(t, network.LastAddr(), xnetip.NetworkFrom6(network).LastAddr())
	})
}

// verifies that the stored mapped form of an IPv4 network computes the
// mapped image of the IPv4 last address.
//
// The mapped mask pins the top 96 bits, so setting the host bits of
// the stored form touches only the low 32 and the 128-bit result is
// the mapped IPv4 result — the encoding invariant the method relies
// on to compute once and only unmap the view.
func Test_Network_LastAddr_StoredFormEquivalenceProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		network := genNetwork4.Draw(t, "network")
		wrapped := xnetip.NetworkFrom4(network)
		storedLast := wrapped.ToIPv6Mapped().LastAddr()
		lastBytes := wrapped.LastAddr().As4()
		mappedLast := netipAddrFrom6Bits(0, 0x0000ffff00000000|uint64(binary.BigEndian.Uint32(lastBytes[:])))
		require.Equal(t, mappedLast, storedLast)
	})
}

// verifies that the last address is computed without allocating in
// either family, whatever the mask's shape.
func Test_Network_LastAddr_AllocationFree(t *testing.T) {
	four := xnetip.MustParseNetwork("192.168.0.1/255.255.0.255")
	six := xnetip.MustParseNetwork("2a02:6b8:c00::1234:0:0/ffff:ffff:ff00::ffff:ffff:0:0")
	requireNoAllocs(t, func() { addrSink = four.LastAddr() })
	requireNoAllocs(t, func() { addrSink = six.LastAddr() })
}

// verifies that the count is family-native: the mapped storage of an
// IPv4 network contributes no host bits above its 32 family bits.
func Test_Network_NumHostBits_FamilyNativeCount(t *testing.T) {
	cases := []struct {
		name    string
		network xnetip.Network
		want    int
	}{
		{name: "IPv4 default route frees 32 bits", network: xnetip.MustParseNetwork("0.0.0.0/0"), want: 32},
		{name: "IPv4 /24", network: xnetip.MustParseNetwork("192.168.1.0/24"), want: 8},
		{name: "IPv4 host route", network: xnetip.MustParseNetwork("10.0.0.1"), want: 0},
		{name: "IPv6 default route frees 128 bits", network: xnetip.MustParseNetwork("::/0"), want: 128},
		{name: "IPv6 /64", network: xnetip.MustParseNetwork("2001:db8::/64"), want: 64},
		{name: "IPv6 host route", network: xnetip.MustParseNetwork("2a02:6b8::1"), want: 0},
		{name: "mapped /96 stays IPv6 and frees 32 bits", network: xnetip.MustParseNetwork("::ffff:0.0.0.0/96"), want: 32},
		{name: "zero value is the IPv6 default route", network: xnetip.Network{}, want: 128},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			require.Equal(t, testCase.want, testCase.network.NumHostBits())
		})
	}
}

// verifies that host bits are counted wherever the mask leaves them
// in either family, not only in a trailing run.
func Test_Network_NumHostBits_NonContiguousMasks(t *testing.T) {
	cases := []struct {
		name    string
		network xnetip.Network
		want    int
	}{
		{name: "IPv4 two-run mask", network: mustNetworkIs4(t, "10.0.0.0", "255.0.255.0"), want: 16},
		{name: "IPv6 two-run mask", network: mustNetworkIs6(t, "2a02:6b8:c00::1234:0:0", "ffff:ffff:ff00::ffff:ffff:0:0"), want: 56},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			require.Equal(t, testCase.want, testCase.network.NumHostBits())
		})
	}
}

// verifies that a wrapped IPv4 network answers exactly what the
// concrete type answers, and that the stored 128-bit count equals it.
//
// The second check pins the encoding invariant the delegation relies
// on: the mapped mask's top 96 bits are ones and contribute nothing,
// so the whole-word count of the stored form is the IPv4 count.
func Test_Network_NumHostBits_MatchesIPv4Property(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		network := genNetwork4.Draw(t, "network")
		wrapped := xnetip.NetworkFrom4(network)
		require.Equal(t, network.NumHostBits(), wrapped.NumHostBits())
		storedMaskBytes := wrapped.ToIPv6Mapped().Mask().As16()
		storedHostBits := 0
		for _, maskByte := range storedMaskBytes {
			storedHostBits += bits.OnesCount8(^maskByte)
		}
		require.Equal(t, storedHostBits, wrapped.NumHostBits())
	})
}

// verifies that a wrapped IPv6 network answers exactly what the
// concrete type answers.
func Test_Network_NumHostBits_MatchesIPv6Property(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		network := genNetwork6.Draw(t, "network")
		require.Equal(t, network.NumHostBits(), xnetip.NetworkFrom6(network).NumHostBits())
	})
}

// verifies that the count stays inside the family's word width.
func Test_Network_NumHostBits_WithinFamilyRangeProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		network := genNetwork.Draw(t, "network")
		width := 128
		if network.Is4() {
			width = 32
		}
		require.GreaterOrEqual(t, network.NumHostBits(), 0)
		require.LessOrEqual(t, network.NumHostBits(), width)
	})
}

// verifies that the count is computed without allocating in either
// family, whatever the mask's shape.
func Test_Network_NumHostBits_AllocationFree(t *testing.T) {
	four := xnetip.MustParseNetwork("10.0.0.0/255.0.255.0")
	six := xnetip.MustParseNetwork("2a02:6b8:c00::1234:0:0/ffff:ffff:ff00::ffff:ffff:0:0")
	requireNoAllocs(t, func() { intSink = four.NumHostBits() })
	requireNoAllocs(t, func() { intSink = six.NumHostBits() })
}

// verifies that a wrapped IPv4 network yields its addresses in host
// index order with every item in the IPv4 family.
func Test_Network_Addrs_IPv4FamilyAndOrder(t *testing.T) {
	network := xnetip.MustParseNetwork("10.0.0.0/30")
	collected := slices.Collect(network.Addrs())
	require.Equal(t, []netip.Addr{
		netip.MustParseAddr("10.0.0.0"),
		netip.MustParseAddr("10.0.0.1"),
		netip.MustParseAddr("10.0.0.2"),
		netip.MustParseAddr("10.0.0.3"),
	}, collected)
	for _, addr := range collected {
		require.True(t, addr.Is4())
	}
}

// verifies that a wrapped IPv6 network yields its addresses in host
// index order with every item in the IPv6 family.
func Test_Network_Addrs_IPv6FamilyAndOrder(t *testing.T) {
	network := xnetip.MustParseNetwork("2001:db8::/126")
	collected := slices.Collect(network.Addrs())
	require.Equal(t, []netip.Addr{
		netip.MustParseAddr("2001:db8::"),
		netip.MustParseAddr("2001:db8::1"),
		netip.MustParseAddr("2001:db8::2"),
		netip.MustParseAddr("2001:db8::3"),
	}, collected)
	for _, addr := range collected {
		require.True(t, addr.Is6())
	}
}

// verifies that an IPv4 host route yields exactly its single address.
func Test_Network_Addrs_IPv4HostRouteSingle(t *testing.T) {
	network := xnetip.MustParseNetwork("1.2.3.4/32")
	collected := slices.Collect(network.Addrs())
	require.Equal(t, []netip.Addr{netip.MustParseAddr("1.2.3.4")}, collected)
	require.True(t, collected[0].Is4())
}

// verifies that an IPv4-mapped IPv6 network stays IPv6: its items
// keep the mapped 16-byte form and never unmap to the IPv4 family.
func Test_Network_Addrs_MappedIPv6StaysIPv6(t *testing.T) {
	network := xnetip.MustParseNetwork("::ffff:1.2.3.4/126")
	require.True(t, network.Is6())
	collected := slices.Collect(network.Addrs())
	require.Len(t, collected, 4)
	require.Equal(t, netip.MustParseAddr("::ffff:1.2.3.4"), collected[0])
	for _, addr := range collected {
		require.True(t, addr.Is6())
		require.False(t, addr.Is4())
	}
}

// verifies that the IPv4 default route starts at the unspecified
// address and steps to its successor, in the IPv4 family.
func Test_Network_Addrs_IPv4UniverseHead(t *testing.T) {
	network := xnetip.MustParseNetwork("0.0.0.0/0")
	head := collectHead(network.Addrs(), 2)
	require.Equal(t, []netip.Addr{
		netip.MustParseAddr("0.0.0.0"),
		netip.MustParseAddr("0.0.0.1"),
	}, head)
}

// verifies that breaking out of the loop stops the sequence after
// exactly the consumed items.
func Test_Network_Addrs_EarlyBreakStops(t *testing.T) {
	network := xnetip.MustParseNetwork("2001:db8::/120")
	consumed := 0
	for range network.Addrs() {
		consumed++
		if consumed == 3 {
			break
		}
	}
	require.Equal(t, 3, consumed)
}

// verifies the pinned IPv4 non-contiguous order through the wrapper:
// the four-bit hole steps the third octet by sixteen, in Is4 items.
func Test_Network_Addrs_IPv4NonContiguousPinnedOrder(t *testing.T) {
	network := xnetip.MustParseNetwork("10.0.0.1/255.255.15.255")
	expected := make([]netip.Addr, 0, 16)
	for value := range 16 {
		expected = append(expected, netip.AddrFrom4([4]byte{10, 0, byte(16 * value), 1}))
	}
	require.Equal(t, expected, slices.Collect(network.Addrs()))
}

// verifies the pinned IPv6 two-run order through the wrapper.
//
// The host bits sit at positions 12 through 15 and 80 through 83, so
// index bits 0 through 3 fill the lower run and index bits 4 through
// 7 the upper one, exactly as in the concrete IPv6 sequence.
func Test_Network_Addrs_IPv6NonContiguousTwoRunOrder(t *testing.T) {
	network := xnetip.MustParseNetwork("2001:db8::1/ffff:ffff:fff0:ffff:ffff:ffff:ffff:0fff")
	expected := make([]netip.Addr, 0, 256)
	for value := range 256 {
		expected = append(expected, netipAddrFrom6Bits(
			0x2001_0db8_0000_0000|uint64(value>>4)<<16,
			uint64(1|(value&0xf)<<12),
		))
	}
	require.Equal(t, expected, slices.Collect(network.Addrs()))
}

// verifies that the wrapper's sequence equals the concrete type's
// sequence element by element, for either family.
func Test_Network_Addrs_DelegatesToFamilyProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		if rapid.Bool().Draw(t, "is4") {
			network := drawBoundedNetwork4(t, 14)
			require.Equal(
				t,
				slices.Collect(network.Addrs()),
				slices.Collect(xnetip.NetworkFrom4(network).Addrs()),
			)
		} else {
			network := drawBoundedNetwork6(t, 14)
			require.Equal(
				t,
				slices.Collect(network.Addrs()),
				slices.Collect(xnetip.NetworkFrom6(network).Addrs()),
			)
		}
	})
}

// verifies that every yielded address carries the network's own
// address family, probing the head of unbounded draws.
func Test_Network_Addrs_FamilyMatchesNetworkProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		network := genNetwork.Draw(t, "network")
		for _, addr := range collectHead(network.Addrs(), 8) {
			require.Equal(t, network.Is4(), addr.Is4())
			require.Equal(t, network.Is6(), addr.Is6())
		}
	})
}

// verifies on bounded spaces that the yielded count is exactly two to
// the number of host bits, in either family.
func Test_Network_Addrs_CountMatchesHostBitsProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		var network xnetip.Network
		if rapid.Bool().Draw(t, "is4") {
			network = xnetip.NetworkFrom4(drawBoundedNetwork4(t, 14))
		} else {
			network = xnetip.NetworkFrom6(drawBoundedNetwork6(t, 14))
		}
		count := 0
		for range network.Addrs() {
			count++
		}
		require.Equal(t, 1<<network.NumHostBits(), count)
	})
}

// verifies that a full drain of the sequence performs no allocation
// in either family.
func Test_Network_Addrs_AllocationFree(t *testing.T) {
	four := xnetip.MustParseNetwork("192.168.1.0/24")
	six := xnetip.MustParseNetwork("2a02:6b8:c00::1234:0:0/120")
	requireNoAllocs(t, func() {
		for addr := range four.Addrs() {
			addrSink = addr
		}
	})
	requireNoAllocs(t, func() {
		for addr := range six.Addrs() {
			addrSink = addr
		}
	})
}

// verifies that a wrapped IPv4 network yields its addresses in
// reverse host-index order with every item in the IPv4 family.
func Test_Network_AddrsBackward_IPv4FamilyAndReverseOrder(t *testing.T) {
	network := xnetip.MustParseNetwork("10.0.0.0/30")
	collected := slices.Collect(network.AddrsBackward())
	require.Equal(t, []netip.Addr{
		netip.MustParseAddr("10.0.0.3"),
		netip.MustParseAddr("10.0.0.2"),
		netip.MustParseAddr("10.0.0.1"),
		netip.MustParseAddr("10.0.0.0"),
	}, collected)
	for _, addr := range collected {
		require.True(t, addr.Is4())
	}
}

// verifies that a wrapped IPv6 network yields its addresses in
// reverse host-index order with every item in the IPv6 family.
func Test_Network_AddrsBackward_IPv6FamilyAndReverseOrder(t *testing.T) {
	network := xnetip.MustParseNetwork("2001:db8::/126")
	collected := slices.Collect(network.AddrsBackward())
	require.Equal(t, []netip.Addr{
		netip.MustParseAddr("2001:db8::3"),
		netip.MustParseAddr("2001:db8::2"),
		netip.MustParseAddr("2001:db8::1"),
		netip.MustParseAddr("2001:db8::"),
	}, collected)
	for _, addr := range collected {
		require.True(t, addr.Is6())
	}
}

// verifies that an IPv4 host route yields exactly its single address.
func Test_Network_AddrsBackward_IPv4HostRouteSingle(t *testing.T) {
	network := xnetip.MustParseNetwork("1.2.3.4/32")
	collected := slices.Collect(network.AddrsBackward())
	require.Equal(t, []netip.Addr{netip.MustParseAddr("1.2.3.4")}, collected)
	require.True(t, collected[0].Is4())
}

// verifies that an IPv4-mapped IPv6 network stays IPv6: its items
// keep the mapped 16-byte form and never unmap to the IPv4 family.
func Test_Network_AddrsBackward_MappedIPv6StaysIPv6(t *testing.T) {
	network := xnetip.MustParseNetwork("::ffff:1.2.3.4/126")
	require.True(t, network.Is6())
	collected := slices.Collect(network.AddrsBackward())
	require.Len(t, collected, 4)
	require.Equal(t, netip.MustParseAddr("::ffff:1.2.3.7"), collected[0])
	for _, addr := range collected {
		require.True(t, addr.Is6())
		require.False(t, addr.Is4())
	}
}

// verifies that the IPv4 default route starts at the all-ones
// address and steps to its predecessor, in the IPv4 family.
func Test_Network_AddrsBackward_IPv4UniverseHead(t *testing.T) {
	network := xnetip.MustParseNetwork("0.0.0.0/0")
	head := collectHead(network.AddrsBackward(), 2)
	require.Equal(t, []netip.Addr{
		netip.MustParseAddr("255.255.255.255"),
		netip.MustParseAddr("255.255.255.254"),
	}, head)
}

// verifies that breaking out of the loop stops the sequence after
// exactly the consumed items.
func Test_Network_AddrsBackward_EarlyBreakStops(t *testing.T) {
	network := xnetip.MustParseNetwork("2001:db8::/120")
	consumed := 0
	for range network.AddrsBackward() {
		consumed++
		if consumed == 3 {
			break
		}
	}
	require.Equal(t, 3, consumed)
}

// verifies through the wrapper that the IPv4 four-bit hole steps
// the third octet down by sixteen, in Is4 items.
func Test_Network_AddrsBackward_IPv4NonContiguousPinnedReverseOrder(t *testing.T) {
	network := xnetip.MustParseNetwork("10.0.0.1/255.255.15.255")
	expected := make([]netip.Addr, 0, 16)
	for value := range 16 {
		expected = append(expected, netip.AddrFrom4([4]byte{10, 0, byte(16 * (15 - value)), 1}))
	}
	require.Equal(t, expected, slices.Collect(network.AddrsBackward()))
}

// verifies the pinned IPv6 two-run reverse order through the wrapper.
//
// The host bits sit at positions 12 through 15 and 80 through 83, so
// descending host indices drain the upper run's value first and step
// the lower run down within each of its values, exactly as in the
// concrete IPv6 sequence.
func Test_Network_AddrsBackward_IPv6NonContiguousTwoRunReverseOrder(t *testing.T) {
	network := xnetip.MustParseNetwork("2001:db8::1/ffff:ffff:fff0:ffff:ffff:ffff:ffff:0fff")
	expected := make([]netip.Addr, 0, 256)
	for value := range 256 {
		index := 255 - value
		expected = append(expected, netipAddrFrom6Bits(
			0x2001_0db8_0000_0000|uint64(index>>4)<<16,
			uint64(1|(index&0xf)<<12),
		))
	}
	require.Equal(t, expected, slices.Collect(network.AddrsBackward()))
}

// verifies on bounded spaces that the backward sequence is exactly
// the reverse of the forward one, in either family.
func Test_Network_AddrsBackward_ExactReverseOfAddrsProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		var network xnetip.Network
		if rapid.Bool().Draw(t, "is4") {
			network = xnetip.NetworkFrom4(drawBoundedNetwork4(t, 14))
		} else {
			network = xnetip.NetworkFrom6(drawBoundedNetwork6(t, 14))
		}
		expected := slices.Collect(network.Addrs())
		slices.Reverse(expected)
		require.Equal(t, expected, slices.Collect(network.AddrsBackward()))
	})
}

// verifies that the wrapper's backward sequence equals the concrete
// type's backward sequence element by element, for either family.
func Test_Network_AddrsBackward_DelegatesToFamilyProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		if rapid.Bool().Draw(t, "is4") {
			network := drawBoundedNetwork4(t, 14)
			require.Equal(
				t,
				slices.Collect(network.AddrsBackward()),
				slices.Collect(xnetip.NetworkFrom4(network).AddrsBackward()),
			)
		} else {
			network := drawBoundedNetwork6(t, 14)
			require.Equal(
				t,
				slices.Collect(network.AddrsBackward()),
				slices.Collect(xnetip.NetworkFrom6(network).AddrsBackward()),
			)
		}
	})
}

// verifies that every yielded address carries the network's own
// address family, probing the head of unbounded draws.
func Test_Network_AddrsBackward_FamilyMatchesNetworkProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		network := genNetwork.Draw(t, "network")
		for _, addr := range collectHead(network.AddrsBackward(), 8) {
			require.Equal(t, network.Is4(), addr.Is4())
			require.Equal(t, network.Is6(), addr.Is6())
		}
	})
}

// verifies that the first yielded address is the last address for
// every generated network.
func Test_Network_AddrsBackward_FirstIsLastAddrProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		network := genNetwork.Draw(t, "network")
		head := collectHead(network.AddrsBackward(), 1)
		require.Equal(t, []netip.Addr{network.LastAddr()}, head)
	})
}

// verifies that a full drain of the backward sequence performs no
// allocation in either family.
func Test_Network_AddrsBackward_AllocationFree(t *testing.T) {
	four := xnetip.MustParseNetwork("192.168.1.0/24")
	six := xnetip.MustParseNetwork("2a02:6b8:c00::1234:0:0/120")
	requireNoAllocs(t, func() {
		for addr := range four.AddrsBackward() {
			addrSink = addr
		}
	})
	requireNoAllocs(t, func() {
		for addr := range six.AddrsBackward() {
			addrSink = addr
		}
	})
}

// verifies that merging works within a family, never across families,
// and keeps the family of its inputs.
func Test_Network_Merge_FamiliesAndBoundary(t *testing.T) {
	cases := []struct {
		name  string
		left  xnetip.Network
		right xnetip.Network
		want  xnetip.Network
		ok    bool
	}{
		{name: "IPv4 siblings", left: xnetip.MustParseNetwork("192.168.0.0/24"), right: xnetip.MustParseNetwork("192.168.1.0/24"), want: xnetip.MustParseNetwork("192.168.0.0/23"), ok: true},
		{name: "IPv6 siblings", left: xnetip.MustParseNetwork("2001:db8::/48"), right: xnetip.MustParseNetwork("2001:db8:1::/48"), want: xnetip.MustParseNetwork("2001:db8::/47"), ok: true},
		{name: "mixed families", left: xnetip.MustParseNetwork("192.168.0.0/24"), right: xnetip.MustParseNetwork("2001:db8::/32"), ok: false},
		{name: "mixed families reversed", left: xnetip.MustParseNetwork("2001:db8::/32"), right: xnetip.MustParseNetwork("192.168.0.0/24"), ok: false},
		{name: "IPv4 containment", left: xnetip.MustParseNetwork("10.0.0.0/8"), right: xnetip.MustParseNetwork("10.1.0.0/16"), want: xnetip.MustParseNetwork("10.0.0.0/8"), ok: true},
		{name: "IPv4 non-mergeable", left: xnetip.MustParseNetwork("192.168.0.0/24"), right: xnetip.MustParseNetwork("192.168.3.0/24"), ok: false},
		{name: "IPv4 universe vs IPv6 universe", left: xnetip.MustParseNetwork("0.0.0.0/0"), right: xnetip.Network{}, ok: false},
		{name: "mapped IPv6 network vs the IPv4 it encodes", left: xnetip.MustParseNetwork("::ffff:10.0.0.0/104"), right: xnetip.MustParseNetwork("10.0.0.0/8"), ok: false},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			merged, ok := testCase.left.Merge(testCase.right)
			require.Equal(t, testCase.ok, ok)
			require.Equal(t, testCase.want, merged)
		})
	}
}

// verifies that an IPv4 sibling merge at a higher bit stays an IPv4
// network even though the result mask turns non-contiguous.
func Test_Network_Merge_NonContiguousResultKeepsFamily(t *testing.T) {
	left := xnetip.MustParseNetwork("10.0.0.0/24")
	right := xnetip.MustParseNetwork("10.0.2.0/24")
	merged, ok := left.Merge(right)
	require.True(t, ok)
	require.Equal(t, xnetip.MustParseNetwork("10.0.0.0/255.255.253.0"), merged)
	require.True(t, merged.Is4())
}

// verifies that non-contiguous sibling merges of both families flow
// through the wrapper.
func Test_Network_Merge_NonContiguousMasks(t *testing.T) {
	cases := []struct {
		name  string
		left  xnetip.Network
		right xnetip.Network
		want  xnetip.Network
	}{
		{name: "IPv4 pattern siblings", left: xnetip.MustParseNetwork("10.0.0.1/255.255.0.255"), right: xnetip.MustParseNetwork("10.1.0.1/255.255.0.255"), want: xnetip.MustParseNetwork("10.0.0.1/255.254.0.255")},
		{name: "IPv6 pattern siblings", left: xnetip.MustParseNetwork("2001::1/ffff:ff00::ffff"), right: xnetip.MustParseNetwork("2001:100::1/ffff:ff00::ffff"), want: xnetip.MustParseNetwork("2001::1/ffff:fe00::ffff")},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			merged, ok := testCase.left.Merge(testCase.right)
			require.True(t, ok)
			require.Equal(t, testCase.want, merged)
		})
	}
}

// verifies that the wrapped merge equals the concrete answer lifted
// into the wrapper, on random pairs and on constructed siblings.
//
// A successful result must keep the inputs' family. The sibling flips
// the lowest set mask bit of the address, so every draw with a
// non-empty mask exercises the merge case that random pairs almost
// never hit.
func Test_Network_Merge_AgreesWithConcreteProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		left4 := genNetwork4.Draw(t, "left4")
		right4 := genNetwork4.Draw(t, "right4")
		want4, wantOK4 := left4.Merge(right4)
		merged4, ok4 := xnetip.NetworkFrom4(left4).Merge(xnetip.NetworkFrom4(right4))
		require.Equal(t, wantOK4, ok4)
		if ok4 {
			require.Equal(t, xnetip.NetworkFrom4(want4), merged4)
			require.True(t, merged4.Is4())
		}
		addrBits, maskBits := ipv4NetworkBits(left4)
		if maskBits != 0 {
			sibling, err := xnetip.Network4From(
				netipAddrFrom4Bits(addrBits^(maskBits&-maskBits)),
				netipAddrFrom4Bits(maskBits),
			)
			require.NoError(t, err)
			wantSibling, wantSiblingOK := left4.Merge(sibling)
			require.True(t, wantSiblingOK)
			mergedSibling, ok := xnetip.NetworkFrom4(left4).Merge(xnetip.NetworkFrom4(sibling))
			require.True(t, ok)
			require.Equal(t, xnetip.NetworkFrom4(wantSibling), mergedSibling)
			require.True(t, mergedSibling.Is4())
		}
		left6 := genNetwork6.Draw(t, "left6")
		right6 := genNetwork6.Draw(t, "right6")
		want6, wantOK6 := left6.Merge(right6)
		merged6, ok6 := xnetip.NetworkFrom6(left6).Merge(xnetip.NetworkFrom6(right6))
		require.Equal(t, wantOK6, ok6)
		if ok6 {
			require.Equal(t, xnetip.NetworkFrom6(want6), merged6)
			require.True(t, merged6.Is6())
		}
	})
}

// verifies that networks of different families never merge, whatever
// their masks.
func Test_Network_Merge_CrossFamilyNeverMergesProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		network4 := xnetip.NetworkFrom4(genNetwork4.Draw(t, "network4"))
		network6 := xnetip.NetworkFrom6(genNetwork6.Draw(t, "network6"))
		_, ok := network4.Merge(network6)
		require.False(t, ok)
		_, ok = network6.Merge(network4)
		require.False(t, ok)
	})
}

// verifies that merging is commutative in both the value and the
// flag, whatever the families.
func Test_Network_Merge_CommutativityProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		left := genNetwork.Draw(t, "left")
		right := genNetwork.Draw(t, "right")
		leftMerged, leftOK := left.Merge(right)
		rightMerged, rightOK := right.Merge(left)
		require.Equal(t, leftOK, rightOK)
		require.Equal(t, leftMerged, rightMerged)
	})
}

// verifies that merging allocates nothing in either family.
func Test_Network_Merge_AllocationFree(t *testing.T) {
	four := xnetip.MustParseNetwork("192.168.0.0/24")
	fourBuddy := xnetip.MustParseNetwork("192.168.1.0/24")
	six := xnetip.MustParseNetwork("2001:db8::/48")
	sixBuddy := xnetip.MustParseNetwork("2001:db8:1::/48")
	requireNoAllocs(t, func() { ipNetworkSink, okSink = four.Merge(fourBuddy) })
	requireNoAllocs(t, func() { ipNetworkSink, okSink = six.Merge(sixBuddy) })
}

// verifies that lowest-mask-bit adjacency works within a family and
// never across families, the IPv4 default route included.
//
// Two IPv4 default routes are the pitfall of mapped storage: their
// stored /96 masks are equal and non-empty, but their addresses are
// equal too, so the 128-bit predicate still refuses them.
func Test_Network_IsAdjacentByLowestMaskBit_FamiliesAndBoundary(t *testing.T) {
	cases := []struct {
		name  string
		left  xnetip.Network
		right xnetip.Network
		want  bool
	}{
		{name: "IPv4 CIDR siblings", left: xnetip.MustParseNetwork("192.168.0.0/24"), right: xnetip.MustParseNetwork("192.168.1.0/24"), want: true},
		{name: "IPv6 CIDR siblings", left: xnetip.MustParseNetwork("2001:db8::/48"), right: xnetip.MustParseNetwork("2001:db8:1::/48"), want: true},
		{name: "mixed families", left: xnetip.MustParseNetwork("10.0.0.0/8"), right: xnetip.MustParseNetwork("2001:db8::/32"), want: false},
		{name: "mixed families reversed", left: xnetip.MustParseNetwork("2001:db8::/32"), right: xnetip.MustParseNetwork("10.0.0.0/8"), want: false},
		{name: "IPv4 adjacent at the top bit", left: xnetip.MustParseNetwork("0.0.0.0/2"), right: xnetip.MustParseNetwork("128.0.0.0/2"), want: false},
		{name: "IPv4 default route with itself", left: xnetip.MustParseNetwork("0.0.0.0/0"), right: xnetip.MustParseNetwork("0.0.0.0/0"), want: false},
		{name: "IPv6 default route with itself", left: xnetip.MustParseNetwork("::/0"), right: xnetip.MustParseNetwork("::/0"), want: false},
		{name: "IPv4 universe vs IPv6 universe", left: xnetip.MustParseNetwork("0.0.0.0/0"), right: xnetip.Network{}, want: false},
		{name: "mapped IPv6 siblings vs IPv4 siblings", left: xnetip.MustParseNetwork("::ffff:10.0.0.0/120"), right: xnetip.MustParseNetwork("10.0.0.0/24"), want: false},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			require.Equal(t, testCase.want, testCase.left.IsAdjacentByLowestMaskBit(testCase.right))
		})
	}
}

// verifies that non-contiguous lowest-bit adjacency of both families
// flows through the wrapper.
func Test_Network_IsAdjacentByLowestMaskBit_NonContiguousMasks(t *testing.T) {
	cases := []struct {
		name  string
		left  xnetip.Network
		right xnetip.Network
		want  bool
	}{
		{name: "IPv4 two-run mask at its lowest bit", left: xnetip.MustParseNetwork("10.0.0.0/255.255.0.255"), right: xnetip.MustParseNetwork("10.0.0.1/255.255.0.255"), want: true},
		{name: "IPv4 two-run mask at the higher boundary", left: xnetip.MustParseNetwork("10.0.0.0/255.255.0.255"), right: xnetip.MustParseNetwork("10.1.0.0/255.255.0.255"), want: false},
		{name: "IPv6 two-run mask at its lowest bit", left: xnetip.MustParseNetwork("::/ffff:ffff::ffff"), right: xnetip.MustParseNetwork("::1/ffff:ffff::ffff"), want: true},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			require.Equal(t, testCase.want, testCase.left.IsAdjacentByLowestMaskBit(testCase.right))
		})
	}
}

// verifies that the wrapped predicate equals the concrete answer in
// each family, on random pairs and on constructed buddies.
//
// The buddy flips the lowest set mask bit of the address, so every
// draw with a non-empty mask exercises the accepting case that
// random pairs almost never hit.
func Test_Network_IsAdjacentByLowestMaskBit_AgreesWithConcreteProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		left4 := genNetwork4.Draw(t, "left4")
		right4 := genNetwork4.Draw(t, "right4")
		require.Equal(
			t,
			left4.IsAdjacentByLowestMaskBit(right4),
			xnetip.NetworkFrom4(left4).IsAdjacentByLowestMaskBit(xnetip.NetworkFrom4(right4)),
		)
		addrBits, maskBits := ipv4NetworkBits(left4)
		if maskBits != 0 {
			buddy, err := xnetip.Network4From(
				netipAddrFrom4Bits(addrBits^(maskBits&-maskBits)),
				netipAddrFrom4Bits(maskBits),
			)
			require.NoError(t, err)
			require.True(t, left4.IsAdjacentByLowestMaskBit(buddy))
			require.True(t, xnetip.NetworkFrom4(left4).IsAdjacentByLowestMaskBit(xnetip.NetworkFrom4(buddy)))
		}
		left6 := genNetwork6.Draw(t, "left6")
		right6 := genNetwork6.Draw(t, "right6")
		require.Equal(
			t,
			left6.IsAdjacentByLowestMaskBit(right6),
			xnetip.NetworkFrom6(left6).IsAdjacentByLowestMaskBit(xnetip.NetworkFrom6(right6)),
		)
	})
}

// verifies that networks of different families never qualify,
// whatever their masks.
func Test_Network_IsAdjacentByLowestMaskBit_CrossFamilyAlwaysFalseProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		network4 := xnetip.NetworkFrom4(genNetwork4.Draw(t, "network4"))
		network6 := xnetip.NetworkFrom6(genNetwork6.Draw(t, "network6"))
		require.False(t, network4.IsAdjacentByLowestMaskBit(network6))
		require.False(t, network6.IsAdjacentByLowestMaskBit(network4))
	})
}

// verifies that the predicate is symmetric and irreflexive, whatever
// the families of the operands.
func Test_Network_IsAdjacentByLowestMaskBit_SymmetryProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		left := genNetwork.Draw(t, "left")
		right := genNetwork.Draw(t, "right")
		require.Equal(t, left.IsAdjacentByLowestMaskBit(right), right.IsAdjacentByLowestMaskBit(left))
		require.False(t, left.IsAdjacentByLowestMaskBit(left))
	})
}

// verifies that the predicate allocates nothing in either family.
func Test_Network_IsAdjacentByLowestMaskBit_AllocationFree(t *testing.T) {
	four := xnetip.MustParseNetwork("10.0.0.0/255.255.0.255")
	fourBuddy := xnetip.MustParseNetwork("10.0.0.1/255.255.0.255")
	six := xnetip.MustParseNetwork("::/ffff:ffff::ffff")
	sixBuddy := xnetip.MustParseNetwork("::1/ffff:ffff::ffff")
	requireNoAllocs(t, func() { okSink = four.IsAdjacentByLowestMaskBit(fourBuddy) })
	requireNoAllocs(t, func() { okSink = six.IsAdjacentByLowestMaskBit(sixBuddy) })
}

// verifies that the class-closed merge works within a family, never
// across families, and keeps the family of its inputs.
func Test_Network_MergeByLowestMaskBit_FamiliesAndBoundary(t *testing.T) {
	cases := []struct {
		name  string
		left  xnetip.Network
		right xnetip.Network
		want  xnetip.Network
		ok    bool
	}{
		{name: "IPv4 siblings", left: xnetip.MustParseNetwork("192.168.0.0/24"), right: xnetip.MustParseNetwork("192.168.1.0/24"), want: xnetip.MustParseNetwork("192.168.0.0/23"), ok: true},
		{name: "IPv6 siblings", left: xnetip.MustParseNetwork("2001:db8::/48"), right: xnetip.MustParseNetwork("2001:db8:1::/48"), want: xnetip.MustParseNetwork("2001:db8::/47"), ok: true},
		{name: "mixed families", left: xnetip.MustParseNetwork("10.0.0.0/8"), right: xnetip.MustParseNetwork("2001:db8::/32"), ok: false},
		{name: "mixed families reversed", left: xnetip.MustParseNetwork("2001:db8::/32"), right: xnetip.MustParseNetwork("10.0.0.0/8"), ok: false},
		{name: "IPv4 default route absorbs an IPv4 network", left: xnetip.MustParseNetwork("0.0.0.0/0"), right: xnetip.MustParseNetwork("10.0.0.0/8"), want: xnetip.MustParseNetwork("0.0.0.0/0"), ok: true},
		{name: "IPv4 higher-bit adjacency refused", left: xnetip.MustParseNetwork("0.0.0.0/2"), right: xnetip.MustParseNetwork("128.0.0.0/2"), ok: false},
		{name: "mapped IPv6 network vs IPv4 network stay foreign", left: xnetip.MustParseNetwork("::ffff:10.0.0.0/104"), right: xnetip.MustParseNetwork("10.0.0.0/8"), ok: false},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			merged, ok := testCase.left.MergeByLowestMaskBit(testCase.right)
			require.Equal(t, testCase.ok, ok)
			require.Equal(t, testCase.want, merged)
		})
	}
}

// verifies that an IPv4 default-route containment result keeps the
// IPv4 family through the mapped storage form.
func Test_Network_MergeByLowestMaskBit_ContainmentKeepsFamily(t *testing.T) {
	universe := xnetip.MustParseNetwork("0.0.0.0/0")
	contained := xnetip.MustParseNetwork("10.0.0.0/8")
	merged, ok := universe.MergeByLowestMaskBit(contained)
	require.True(t, ok)
	require.True(t, merged.Is4())
	require.Equal(t, universe, merged)
}

// verifies that non-contiguous merges of both families flow through
// the wrapper with their family preserved.
func Test_Network_MergeByLowestMaskBit_NonContiguousMasks(t *testing.T) {
	fourLeft := xnetip.MustParseNetwork("10.0.0.0/255.255.0.255")
	fourRight := xnetip.MustParseNetwork("10.0.0.1/255.255.0.255")
	merged, ok := fourLeft.MergeByLowestMaskBit(fourRight)
	require.True(t, ok)
	require.Equal(t, xnetip.MustParseNetwork("10.0.0.0/255.255.0.254"), merged)
	require.True(t, merged.Is4())
	sixLeft := xnetip.MustParseNetwork("2001::1/ffff:ff00::ffff")
	sixRight := xnetip.MustParseNetwork("2001:100::1/ffff:ff00::ffff")
	_, ok = sixLeft.MergeByLowestMaskBit(sixRight)
	require.False(t, ok)
}

// verifies that the wrapped merge equals the concrete answer lifted
// into the wrapper, on random pairs and on constructed buddies.
//
// A successful result must keep the inputs' family. The buddy pairs
// exercise the sibling case that random pairs almost never hit.
func Test_Network_MergeByLowestMaskBit_AgreesWithConcreteProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		left4 := genNetwork4.Draw(t, "left4")
		right4 := genNetwork4.Draw(t, "right4")
		want4, wantOK4 := left4.MergeByLowestMaskBit(right4)
		merged4, ok4 := xnetip.NetworkFrom4(left4).MergeByLowestMaskBit(xnetip.NetworkFrom4(right4))
		require.Equal(t, wantOK4, ok4)
		if ok4 {
			require.Equal(t, xnetip.NetworkFrom4(want4), merged4)
			require.True(t, merged4.Is4())
		}
		pair4 := genIPv4LowestBitSiblingPair.Draw(t, "pair4")
		wantSibling4, wantSiblingOK4 := pair4[0].MergeByLowestMaskBit(pair4[1])
		require.True(t, wantSiblingOK4)
		mergedSibling4, ok := xnetip.NetworkFrom4(pair4[0]).MergeByLowestMaskBit(xnetip.NetworkFrom4(pair4[1]))
		require.True(t, ok)
		require.Equal(t, xnetip.NetworkFrom4(wantSibling4), mergedSibling4)
		require.True(t, mergedSibling4.Is4())
		left6 := genNetwork6.Draw(t, "left6")
		right6 := genNetwork6.Draw(t, "right6")
		want6, wantOK6 := left6.MergeByLowestMaskBit(right6)
		merged6, ok6 := xnetip.NetworkFrom6(left6).MergeByLowestMaskBit(xnetip.NetworkFrom6(right6))
		require.Equal(t, wantOK6, ok6)
		if ok6 {
			require.Equal(t, xnetip.NetworkFrom6(want6), merged6)
			require.True(t, merged6.Is6())
		}
		pair6 := genIPv6LowestBitSiblingPair.Draw(t, "pair6")
		wantSibling6, wantSiblingOK6 := pair6[0].MergeByLowestMaskBit(pair6[1])
		require.True(t, wantSiblingOK6)
		mergedSibling6, ok := xnetip.NetworkFrom6(pair6[0]).MergeByLowestMaskBit(xnetip.NetworkFrom6(pair6[1]))
		require.True(t, ok)
		require.Equal(t, xnetip.NetworkFrom6(wantSibling6), mergedSibling6)
		require.True(t, mergedSibling6.Is6())
	})
}

// verifies that networks of different families never merge, whatever
// their masks.
func Test_Network_MergeByLowestMaskBit_CrossFamilyNeverMergesProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		network4 := xnetip.NetworkFrom4(genNetwork4.Draw(t, "network4"))
		network6 := xnetip.NetworkFrom6(genNetwork6.Draw(t, "network6"))
		_, ok := network4.MergeByLowestMaskBit(network6)
		require.False(t, ok)
		_, ok = network6.MergeByLowestMaskBit(network4)
		require.False(t, ok)
	})
}

// verifies that the merge allocates nothing in either family.
func Test_Network_MergeByLowestMaskBit_AllocationFree(t *testing.T) {
	four := xnetip.MustParseNetwork("192.168.0.0/24")
	fourBuddy := xnetip.MustParseNetwork("192.168.1.0/24")
	six := xnetip.MustParseNetwork("2001:db8::/48")
	sixBuddy := xnetip.MustParseNetwork("2001:db8:1::/48")
	requireNoAllocs(t, func() { ipNetworkSink, okSink = four.MergeByLowestMaskBit(fourBuddy) })
	requireNoAllocs(t, func() { ipNetworkSink, okSink = six.MergeByLowestMaskBit(sixBuddy) })
}

// verifies that the fold works within either family, never across
// families, and keeps the family of its inputs.
func Test_Network_SupernetFor_FamiliesAndBoundary(t *testing.T) {
	cases := []struct {
		name     string
		receiver xnetip.Network
		nets     []xnetip.Network
		want     xnetip.Network
		ok       bool
	}{
		{name: "IPv4 halves fold to the /24", receiver: xnetip.MustParseNetwork("192.0.2.0/25"), nets: []xnetip.Network{xnetip.MustParseNetwork("192.0.2.128/25")}, want: xnetip.MustParseNetwork("192.0.2.0/24"), ok: true},
		{name: "IPv6 pair folds to the shared /32", receiver: xnetip.MustParseNetwork("2001:db8:1::/32"), nets: []xnetip.Network{xnetip.MustParseNetwork("2001:db8:2::/39")}, want: xnetip.MustParseNetwork("2001:db8::/32"), ok: true},
		{name: "empty slice returns the IPv4 receiver", receiver: xnetip.MustParseNetwork("10.0.0.0/8"), nets: nil, want: xnetip.MustParseNetwork("10.0.0.0/8"), ok: true},
		{name: "empty slice returns the IPv6 receiver", receiver: xnetip.MustParseNetwork("2001:db8::/32"), nets: nil, want: xnetip.MustParseNetwork("2001:db8::/32"), ok: true},
		{name: "mixed slice with an IPv4 receiver", receiver: xnetip.MustParseNetwork("10.0.0.0/8"), nets: []xnetip.Network{xnetip.MustParseNetwork("10.1.0.0/16"), xnetip.MustParseNetwork("2001:db8::/32")}, ok: false},
		{name: "mixed slice with an IPv6 receiver", receiver: xnetip.MustParseNetwork("2001:db8::/32"), nets: []xnetip.Network{xnetip.MustParseNetwork("10.0.0.0/8")}, ok: false},
		{name: "mapped IPv6 element is foreign to an IPv4 receiver", receiver: xnetip.MustParseNetwork("10.0.0.0/8"), nets: []xnetip.Network{xnetip.MustParseNetwork("::ffff:10.0.0.0/104")}, ok: false},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			result, ok := testCase.receiver.SupernetFor(testCase.nets)
			require.Equal(t, testCase.ok, ok)
			require.Equal(t, testCase.want, result)
		})
	}
}

// verifies that an IPv4 fold whose result mask turns non-contiguous
// stays an IPv4 network.
func Test_Network_SupernetFor_NonContiguousResultKeepsFamily(t *testing.T) {
	receiver := xnetip.MustParseNetwork("10.0.0.0/24")
	result, ok := receiver.SupernetFor([]xnetip.Network{xnetip.MustParseNetwork("10.1.0.0/24")})
	require.True(t, ok)
	require.Equal(t, xnetip.MustParseNetwork("10.0.0.0/255.254.255.0"), result)
	require.True(t, result.Is4())
}

// verifies that non-contiguous folds of both families flow through
// the wrapper.
func Test_Network_SupernetFor_NonContiguousMasks(t *testing.T) {
	cases := []struct {
		name     string
		receiver xnetip.Network
		nets     []xnetip.Network
		want     xnetip.Network
	}{
		{name: "IPv4 two-run networks crossing the first octet", receiver: xnetip.MustParseNetwork("10.40.0.1/255.255.0.255"), nets: []xnetip.Network{xnetip.MustParseNetwork("10.40.0.2/255.255.0.255"), xnetip.MustParseNetwork("11.40.0.3/255.255.0.255")}, want: xnetip.MustParseNetwork("10.40.0.0/254.255.0.252")},
		{name: "IPv6 two-run networks sharing the high runs", receiver: xnetip.MustParseNetwork("2a02:6b8:c00::48aa:0:0/ffff:ffff:ff00::ffff:ffff:0:0"), nets: []xnetip.Network{xnetip.MustParseNetwork("2a02:6b8:c00::4707:0:0/ffff:ffff:ff00::ffff:ffff:0:0")}, want: xnetip.MustParseNetwork("2a02:6b8:c00::4002:0:0/ffff:ffff:ff00:0:ffff:f052::")},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			result, ok := testCase.receiver.SupernetFor(testCase.nets)
			require.True(t, ok)
			require.Equal(t, testCase.want, result)
		})
	}
}

// verifies that the wrapped fold equals the concrete answer lifted
// into the wrapper, keeps the family and contains every input.
//
// The equality is bit-exact on the stored form, so for IPv4 it also
// pins the mapped-storage invariant of the result.
func Test_Network_SupernetFor_AgreesWithConcreteProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		receiver4 := genNetwork4.Draw(t, "receiver4")
		nets4 := rapid.SliceOfN(genNetwork4, 0, 32).Draw(t, "nets4")
		wrapped4 := make([]xnetip.Network, len(nets4))
		for idx, network := range nets4 {
			wrapped4[idx] = xnetip.NetworkFrom4(network)
		}
		result4, ok4 := xnetip.NetworkFrom4(receiver4).SupernetFor(wrapped4)
		require.True(t, ok4)
		require.Equal(t, xnetip.NetworkFrom4(receiver4.SupernetFor(nets4)), result4)
		require.True(t, result4.Is4())
		require.True(t, result4.Contains(xnetip.NetworkFrom4(receiver4)))
		for _, network := range wrapped4 {
			require.True(t, result4.Contains(network), "element %v", network)
		}
		receiver6 := genNetwork6.Draw(t, "receiver6")
		nets6 := rapid.SliceOfN(genNetwork6, 0, 32).Draw(t, "nets6")
		wrapped6 := make([]xnetip.Network, len(nets6))
		for idx, network := range nets6 {
			wrapped6[idx] = xnetip.NetworkFrom6(network)
		}
		result6, ok6 := xnetip.NetworkFrom6(receiver6).SupernetFor(wrapped6)
		require.True(t, ok6)
		require.Equal(t, xnetip.NetworkFrom6(receiver6.SupernetFor(nets6)), result6)
		require.True(t, result6.Is6())
		require.True(t, result6.Contains(xnetip.NetworkFrom6(receiver6)))
		for _, network := range wrapped6 {
			require.True(t, result6.Contains(network), "element %v", network)
		}
	})
}

// verifies that one foreign-family element anywhere in the slice
// makes the fold report false, in both family directions.
func Test_Network_SupernetFor_MixedSliceProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		nets4 := rapid.SliceOfN(genNetwork4, 0, 31).Draw(t, "nets4")
		mixed4 := make([]xnetip.Network, len(nets4))
		for idx, network := range nets4 {
			mixed4[idx] = xnetip.NetworkFrom4(network)
		}
		foreign6 := xnetip.NetworkFrom6(genNetwork6.Draw(t, "foreign6"))
		position4 := rapid.IntRange(0, len(mixed4)).Draw(t, "position4")
		mixed4 = slices.Insert(mixed4, position4, foreign6)
		result, ok := xnetip.NetworkFrom4(genNetwork4.Draw(t, "receiver4")).SupernetFor(mixed4)
		require.False(t, ok)
		require.Equal(t, xnetip.Network{}, result)
		nets6 := rapid.SliceOfN(genNetwork6, 0, 31).Draw(t, "nets6")
		mixed6 := make([]xnetip.Network, len(nets6))
		for idx, network := range nets6 {
			mixed6[idx] = xnetip.NetworkFrom6(network)
		}
		foreign4 := xnetip.NetworkFrom4(genNetwork4.Draw(t, "foreign4"))
		position6 := rapid.IntRange(0, len(mixed6)).Draw(t, "position6")
		mixed6 = slices.Insert(mixed6, position6, foreign4)
		result, ok = xnetip.NetworkFrom6(genNetwork6.Draw(t, "receiver6")).SupernetFor(mixed6)
		require.False(t, ok)
		require.Equal(t, xnetip.Network{}, result)
	})
}

// verifies that the fold allocates nothing over a 64-element
// same-family slice, in either family.
func Test_Network_SupernetFor_AllocationFree(t *testing.T) {
	four := make([]xnetip.Network, 0, 64)
	for _, network := range ipv4RelatedNetworks(t, 64) {
		four = append(four, xnetip.NetworkFrom4(network))
	}
	six := make([]xnetip.Network, 0, 64)
	for _, network := range ipv6RelatedNetworks(t, 64) {
		six = append(six, xnetip.NetworkFrom6(network))
	}
	requireNoAllocs(t, func() { ipNetworkSink, okSink = four[0].SupernetFor(four[1:]) })
	requireNoAllocs(t, func() { ipNetworkSink, okSink = six[0].SupernetFor(six[1:]) })
}

// verifies that the mask is truncated at its first zero bit with the
// address family preserved.
func Test_Network_ToContiguous_TruncatesKeepingFamily(t *testing.T) {
	cases := []struct {
		name    string
		input   string
		want    string
		wantIs4 bool
	}{
		{name: "IPv4 two-run mask", input: "192.168.0.1/255.255.0.255", want: "192.168.0.0/16", wantIs4: true},
		{name: "IPv6 geo mask", input: "2001:db8::1/ffff:ffff:ff00::ffff:ffff:0:0", want: "2001:db8::/40", wantIs4: false},
		{name: "IPv4 already contiguous", input: "10.0.0.0/8", want: "10.0.0.0/8", wantIs4: true},
		{name: "IPv6 already contiguous", input: "2001:db8::/32", want: "2001:db8::/32", wantIs4: false},
		{name: "IPv4 universe", input: "0.0.0.0/0", want: "0.0.0.0/0", wantIs4: true},
		{name: "IPv6 universe", input: "::/0", want: "::/0", wantIs4: false},
		{name: "IPv4 mask with empty leading run", input: "0.0.0.1/0.0.0.255", want: "0.0.0.0/0", wantIs4: true},
		{name: "IPv4-mapped network stays IPv6", input: "::ffff:192.168.0.1/ffff:ffff:ffff:ffff:ffff:ffff:ffff:ff0f", want: "::ffff:192.168.0.0/120", wantIs4: false},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			block := xnetip.MustParseNetwork(testCase.input).ToContiguous()
			require.Equal(t, xnetip.MustParseContiguous(testCase.want), block)
			require.Equal(t, testCase.wantIs4, block.Network().Is4())
		})
	}
}

// verifies that the zero network truncates to the zero wrapper.
func Test_Network_ToContiguous_ZeroValue(t *testing.T) {
	require.Equal(t, xnetip.Contiguous[xnetip.Network]{}, xnetip.Network{}.ToContiguous())
}

// verifies that a non-contiguous mask of either family keeps only
// its leading run of ones.
func Test_Network_ToContiguous_NonContiguousMasks(t *testing.T) {
	cases := []struct {
		name  string
		input string
		want  string
	}{
		{name: "IPv4 alternating mask", input: "170.85.170.85/170.85.170.85", want: "128.0.0.0/1"},
		{name: "IPv6 alternating groups", input: "2001:0:db8:0:1:0:2:0/ffff:0:ffff:0:ffff:0:ffff:0", want: "2001::/16"},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			network := xnetip.MustParseNetwork(testCase.input)
			require.Equal(t, xnetip.MustParseContiguous(testCase.want), network.ToContiguous())
		})
	}
}

// verifies that truncating the family-agnostic form is exactly the
// concrete truncation lifted into it, for both families.
//
// The IPv4 half is the delegation argument of the mapped storage:
// the stored mask pins its top 96 bits, so truncating the stored
// form truncates the IPv4 mask exactly.
func Test_Network_ToContiguous_MatchesConcreteProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		network4 := genNetwork4.Draw(t, "network4")
		require.Equal(
			t,
			xnetip.NetworkFrom4(network4.ToContiguous().Network()),
			xnetip.NetworkFrom4(network4).ToContiguous().Network(),
		)
		network6 := genNetwork6.Draw(t, "network6")
		require.Equal(
			t,
			xnetip.NetworkFrom6(network6.ToContiguous().Network()),
			xnetip.NetworkFrom6(network6).ToContiguous().Network(),
		)
	})
}

// verifies that every truncation keeps the address family and yields
// a contiguous network, pinning the blind wrap.
func Test_Network_ToContiguous_FamilyAndContiguityProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		network := genNetwork.Draw(t, "network")
		block := network.ToContiguous()
		require.Equal(t, network.Is4(), block.Network().Is4())
		require.True(t, block.Network().IsContiguous())
	})
}

// verifies that truncating an already truncated network changes
// nothing.
func Test_Network_ToContiguous_IdempotentProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		network := genNetwork.Draw(t, "network")
		block := network.ToContiguous()
		require.Equal(t, block, block.Network().ToContiguous())
	})
}

// verifies that the block always contains the network it widened.
func Test_Network_ToContiguous_ContainsOriginalProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		network := genNetwork.Draw(t, "network")
		require.True(t, network.ToContiguous().Network().Contains(network))
	})
}

// verifies that on contiguous input the widening conversion equals
// the exact one and changes nothing.
func Test_Network_ToContiguous_AgreesWithContiguousFromProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		block := genContiguous.Draw(t, "block")
		require.Equal(t, block, block.Network().ToContiguous())
		exact, ok := xnetip.ContiguousFrom(block.Network())
		require.True(t, ok)
		require.Equal(t, exact, block.Network().ToContiguous())
	})
}

// verifies that truncation allocates nothing for either family.
func Test_Network_ToContiguous_AllocationFree(t *testing.T) {
	ipv4 := xnetip.MustParseNetwork("192.168.0.1/255.255.0.255")
	ipv6 := xnetip.MustParseNetwork("2001:db8::1/ffff:ffff:ff00::ffff:ffff:0:0")
	requireNoAllocs(t, func() { contiguousSink = ipv4.ToContiguous() })
	requireNoAllocs(t, func() { contiguousSink = ipv6.ToContiguous() })
}
