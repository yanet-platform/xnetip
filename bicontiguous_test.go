package xnetip_test

import (
	"math"
	"net/netip"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/yanet-platform/xnetip"
	"pgregory.net/rapid"
)

// mustBiContiguous wraps a parsed IPv6 network fixture, stopping the
// test when either its text or its per-half mask shape is invalid.
func mustBiContiguous(t require.TestingT, text string) xnetip.BiContiguous {
	if helper, ok := t.(interface{ Helper() }); ok {
		helper.Helper()
	}
	wrapper, ok := xnetip.BiContiguousFrom(xnetip.MustParseNetwork6(text))
	require.True(t, ok, "fixture mask is not bi-contiguous")
	return wrapper
}

// verifies that the bi-contiguous shape rejection has its own stable
// sentinel text, distinct from the stricter CIDR shape rejection.
func Test_ErrNonBiContiguousMask_HasDedicatedText(t *testing.T) {
	require.Equal(t, "mask not bi-contiguous", xnetip.ErrNonBiContiguousMask.Error())
	require.NotEqual(t, xnetip.ErrNonContiguousMask, xnetip.ErrNonBiContiguousMask)
}

// verifies that the representative two-run, degenerate and half-boundary
// mask shapes enter through the exact conversion unchanged.
func Test_BiContiguousFrom_AcceptsUnitAndBoundaryShapes(t *testing.T) {
	cases := []struct {
		name string
		text string
	}{
		{
			name: "motivating two-run mask",
			text: "2a02:6b8:c00::1234:abcd:0:0/ffff:ffff:ff00::ffff:ffff:0:0",
		},
		{name: "empty mask", text: "::/::"},
		{name: "host route", text: "::1/128"},
		{name: "low-half-only run", text: "::/::8000:0:0:0"},
		{name: "globally contiguous below half", text: "2001:db8::/40"},
		{name: "globally contiguous above half", text: "2001:db8::/96"},
		{name: "one-bit gap at half boundary", text: "::/ffff:ffff:ffff:fffe:8000::"},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			network := xnetip.MustParseNetwork6(testCase.text)
			wrapper, ok := xnetip.BiContiguousFrom(network)
			require.True(t, ok)
			require.Equal(t, network, wrapper.Network())
		})
	}
}

// verifies that an interior hole in either half and an isolated tail bit
// are rejected by the exact conversion with the zero wrapper returned.
func Test_BiContiguousFrom_RejectsInvalidShapes(t *testing.T) {
	cases := []struct {
		name string
		text string
	}{
		{name: "hole in high half", text: "::/ffff:0:ffff::"},
		{name: "hole in low half", text: "::/ffff:ffff::f0f0:f0f0:f0f0:f0f0"},
		{name: "isolated low tail bit", text: "::/::1"},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			wrapper, ok := xnetip.BiContiguousFrom(xnetip.MustParseNetwork6(testCase.text))
			require.False(t, ok)
			require.Equal(t, xnetip.BiContiguous{}, wrapper)
		})
	}
}

// verifies that the zero wrapper is the valid IPv6 universe network.
func Test_BiContiguous_ZeroValueIsUniverse(t *testing.T) {
	require.Equal(t, xnetip.MustParseNetwork6("::/0"), xnetip.BiContiguous{}.Network())

	wrapper, ok := xnetip.BiContiguousFrom(xnetip.Network6{})
	require.True(t, ok)
	require.Equal(t, xnetip.BiContiguous{}, wrapper)
}

// verifies that checked address-pair construction normalizes host bits,
// accepts mapped IPv6, and drops zones from either input.
func Test_BiContiguousFromAddrs_NormalizesAndAcceptsIPv6Forms(t *testing.T) {
	cases := []struct {
		name string
		addr netip.Addr
		mask netip.Addr
		want xnetip.Network6
	}{
		{
			name: "host bits under two runs",
			addr: netip.MustParseAddr("2a02:6b8:cff:1234:ffff:ffff:abcd:ef01"),
			mask: netip.MustParseAddr("ffff:ffff:ff00::ffff:ffff:0:0"),
			want: mustNetwork6(t, "2a02:6b8:c00::ffff:ffff:0:0", "ffff:ffff:ff00::ffff:ffff:0:0"),
		},
		{
			name: "IPv4-mapped IPv6",
			addr: netip.MustParseAddr("::ffff:192.0.2.129"),
			mask: netip.MustParseAddr("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ff00"),
			want: xnetip.MustParseNetwork6("::ffff:192.0.2.0/120"),
		},
		{
			name: "zone on address",
			addr: netip.MustParseAddr("fe80::1234%eth0"),
			mask: netip.MustParseAddr("ffff:ffff:ffff:ffff::"),
			want: xnetip.MustParseNetwork6("fe80::/64"),
		},
		{
			name: "zone on mask",
			addr: netip.MustParseAddr("2001:db8::1234"),
			mask: netip.MustParseAddr("ffff:ffff:ffff:ffff::%mask"),
			want: xnetip.MustParseNetwork6("2001:db8::/64"),
		},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			wrapper, err := xnetip.BiContiguousFromAddrs(testCase.addr, testCase.mask)
			require.NoError(t, err)
			require.Equal(t, testCase.want, wrapper.Network())
			require.Empty(t, wrapper.Network().Addr().Zone())
			require.Empty(t, wrapper.Network().Mask().Zone())
		})
	}
}

// verifies that either non-IPv6 input is rejected under the constructor's
// own name with the family sentinel, exact input and zero result.
func Test_BiContiguousFromAddrs_RejectsFamilyMismatch(t *testing.T) {
	cases := []struct {
		name        string
		addr        netip.Addr
		mask        netip.Addr
		wantMessage string
	}{
		{
			name:        "IPv4 address",
			addr:        netip.MustParseAddr("192.0.2.1"),
			mask:        netip.MustParseAddr("ffff::"),
			wantMessage: `xnetip.BiContiguousFromAddrs("192.0.2.1/ffff::"): address family mismatch`,
		},
		{
			name:        "IPv4 mask",
			addr:        netip.MustParseAddr("2001:db8::1"),
			mask:        netip.MustParseAddr("192.0.2.1"),
			wantMessage: `xnetip.BiContiguousFromAddrs("2001:db8::1/192.0.2.1"): address family mismatch`,
		},
		{
			name:        "invalid zero address",
			addr:        netip.Addr{},
			mask:        netip.MustParseAddr("ffff::"),
			wantMessage: `xnetip.BiContiguousFromAddrs("invalid IP/ffff::"): address family mismatch`,
		},
		{
			name:        "invalid zero mask",
			addr:        netip.MustParseAddr("2001:db8::1"),
			mask:        netip.Addr{},
			wantMessage: `xnetip.BiContiguousFromAddrs("2001:db8::1/invalid IP"): address family mismatch`,
		},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			wrapper, err := xnetip.BiContiguousFromAddrs(testCase.addr, testCase.mask)
			require.ErrorIs(t, err, xnetip.ErrAddrFamilyMismatch)
			require.Equal(t, testCase.wantMessage, err.Error())
			require.Equal(t, xnetip.BiContiguous{}, wrapper)
		})
	}
}

// verifies that valid IPv6 masks with an interior hole wrap the dedicated
// shape sentinel under the checked constructor's own name.
func Test_BiContiguousFromAddrs_RejectsInvalidShapes(t *testing.T) {
	cases := []struct {
		name        string
		mask        netip.Addr
		wantMessage string
	}{
		{
			name:        "hole in high half",
			mask:        netip.MustParseAddr("ffff:0:ffff::"),
			wantMessage: `xnetip.BiContiguousFromAddrs("2001:db8::1/ffff:0:ffff::"): mask not bi-contiguous`,
		},
		{
			name:        "hole in low half",
			mask:        netip.MustParseAddr("ffff:ffff::f0f0:f0f0:f0f0:f0f0"),
			wantMessage: `xnetip.BiContiguousFromAddrs("2001:db8::1/ffff:ffff::f0f0:f0f0:f0f0:f0f0"): mask not bi-contiguous`,
		},
		{
			name:        "isolated low tail bit",
			mask:        netip.MustParseAddr("::1"),
			wantMessage: `xnetip.BiContiguousFromAddrs("2001:db8::1/::1"): mask not bi-contiguous`,
		},
	}
	addr := netip.MustParseAddr("2001:db8::1")
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			wrapper, err := xnetip.BiContiguousFromAddrs(addr, testCase.mask)
			require.ErrorIs(t, err, xnetip.ErrNonBiContiguousMask)
			require.Equal(t, testCase.wantMessage, err.Error())
			require.Equal(t, xnetip.BiContiguous{}, wrapper)
		})
	}
}

// verifies that all 4,225 products of per-half prefix masks construct,
// normalize, unwrap and rewrap without changing the network.
func Test_BiContiguousFromAddrs_AcceptsEveryShape(t *testing.T) {
	addr := netipAddrFrom6Bits(math.MaxUint64, math.MaxUint64)
	for highPrefix := 0; highPrefix <= 64; highPrefix++ {
		for lowPrefix := 0; lowPrefix <= 64; lowPrefix++ {
			mask := netipAddrFrom6Bits(prefixMask64(highPrefix), prefixMask64(lowPrefix))
			wrapper, err := xnetip.BiContiguousFromAddrs(addr, mask)
			require.NoError(t, err, "high prefix %d, low prefix %d", highPrefix, lowPrefix)

			expected, err := xnetip.Network6From(addr, mask)
			require.NoError(t, err)
			require.Equal(t, expected, wrapper.Network(), "high prefix %d, low prefix %d", highPrefix, lowPrefix)

			rewrapped, ok := xnetip.BiContiguousFrom(expected)
			require.True(t, ok, "high prefix %d, low prefix %d", highPrefix, lowPrefix)
			require.Equal(t, wrapper, rewrapped, "high prefix %d, low prefix %d", highPrefix, lowPrefix)
		}
	}
}

// verifies that punching any non-tail bit out of either full half leaves
// a later set bit and is rejected as an interior hole.
func Test_BiContiguousFromAddrs_RejectsEveryInteriorHole(t *testing.T) {
	addr := netipAddrFrom6Bits(math.MaxUint64, math.MaxUint64)
	for bit := 1; bit < 64; bit++ {
		highMask := math.MaxUint64 &^ (uint64(1) << bit)
		wrapper, err := xnetip.BiContiguousFromAddrs(
			addr,
			netipAddrFrom6Bits(highMask, math.MaxUint64),
		)
		require.ErrorIs(t, err, xnetip.ErrNonBiContiguousMask, "high-half bit %d", bit)
		require.Equal(t, xnetip.BiContiguous{}, wrapper)

		lowMask := math.MaxUint64 &^ (uint64(1) << bit)
		wrapper, err = xnetip.BiContiguousFromAddrs(
			addr,
			netipAddrFrom6Bits(math.MaxUint64, lowMask),
		)
		require.ErrorIs(t, err, xnetip.ErrNonBiContiguousMask, "low-half bit %d", bit)
		require.Equal(t, xnetip.BiContiguous{}, wrapper)
	}
}

// verifies that every boundary CIDR length lifts without validation and
// keeps the wrapped IPv6 network byte-for-byte equal.
func Test_BiContiguousFromContiguous_LiftsBoundaryPrefixes(t *testing.T) {
	addr := netip.MustParseAddr("2001:db8:ffff:ffff:ffff:ffff:ffff:ffff")
	for _, bits := range []int{0, 40, 64, 96, 128} {
		block, err := xnetip.ContiguousFromCIDR6(addr, bits)
		require.NoError(t, err)

		wrapper := xnetip.BiContiguousFromContiguous(block)
		require.Equal(t, block.Network(), wrapper.Network(), "prefix length %d", bits)
		rewrapped, ok := xnetip.BiContiguousFrom(wrapper.Network())
		require.True(t, ok)
		require.Equal(t, wrapper, rewrapped)
	}
}

// verifies that normalization defines wrapper equality and therefore map-key
// identity even when the source addresses differ only in host bits.
func Test_BiContiguous_EqualityAndMapKeyFollowNetwork(t *testing.T) {
	mask := netip.MustParseAddr("ffff:ffff:ff00::ffff:ffff:0:0")
	first, err := xnetip.BiContiguousFromAddrs(
		netip.MustParseAddr("2a02:6b8:c01:1111:1234:5678:aaaa:bbbb"),
		mask,
	)
	require.NoError(t, err)
	second, err := xnetip.BiContiguousFromAddrs(
		netip.MustParseAddr("2a02:6b8:cfe:2222:1234:5678:cccc:dddd"),
		mask,
	)
	require.NoError(t, err)
	require.Equal(t, first, second)

	values := map[xnetip.BiContiguous]string{first: "normalized"}
	require.Equal(t, "normalized", values[second])
}

// verifies that representative wrapper comparisons use address first and
// mask second exactly as the wrapped network order does.
func Test_BiContiguous_CompareMatchesNetworkOrder(t *testing.T) {
	cases := []struct {
		name   string
		first  xnetip.BiContiguous
		second xnetip.BiContiguous
		want   int
	}{
		{
			name:   "shorter mask sorts first",
			first:  mustBiContiguous(t, "::/0"),
			second: mustBiContiguous(t, "::/ffff::"),
			want:   -1,
		},
		{
			name:   "equal networks",
			first:  mustBiContiguous(t, "2001:db8::/32"),
			second: mustBiContiguous(t, "2001:db8::/32"),
			want:   0,
		},
		{
			name:   "higher address sorts after",
			first:  mustBiContiguous(t, "2001:db9::/32"),
			second: mustBiContiguous(t, "2001:db8::/32"),
			want:   1,
		},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			require.Equal(t, testCase.want, testCase.first.Compare(testCase.second))
			require.Equal(
				t,
				testCase.first.Network().Compare(testCase.second.Network()),
				testCase.first.Compare(testCase.second),
			)
		})
	}
}

// verifies that exact conversion succeeds precisely for networks whose
// two mask halves are individually contiguous.
func Test_BiContiguousFrom_MatchesPredicateProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		network := genNetwork6.Draw(t, "network")
		wrapper, ok := xnetip.BiContiguousFrom(network)
		require.Equal(t, network.IsBicontiguous(), ok)
		if ok {
			require.Equal(t, network, wrapper.Network())
		} else {
			require.Equal(t, xnetip.BiContiguous{}, wrapper)
		}
	})
}

// verifies that every generated IPv6 CIDR block lifts unchanged and still
// passes the exact bi-contiguous conversion.
func Test_BiContiguousFromContiguous_PreservesNetworkProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		block := genContiguous6.Draw(t, "block")
		wrapper := xnetip.BiContiguousFromContiguous(block)
		require.Equal(t, block.Network(), wrapper.Network())

		exact, ok := xnetip.BiContiguousFrom(wrapper.Network())
		require.True(t, ok)
		require.Equal(t, wrapper, exact)
	})
}

// verifies that checked address-pair construction equals plain normalized
// construction followed by exact conversion for every valid IPv6 pair.
func Test_BiContiguousFromAddrs_MatchesTwoStepProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		addr := genNetipAddr6.Draw(t, "addr")
		mask := genNetipAddr6.Draw(t, "mask")
		network, err := xnetip.Network6From(addr, mask)
		require.NoError(t, err)
		expected, ok := xnetip.BiContiguousFrom(network)

		actual, err := xnetip.BiContiguousFromAddrs(addr, mask)
		if ok {
			require.NoError(t, err)
			require.Equal(t, expected, actual)
		} else {
			require.ErrorIs(t, err, xnetip.ErrNonBiContiguousMask)
			require.Equal(t, xnetip.BiContiguous{}, actual)
		}
	})
}

// verifies that random wrapper comparisons equal the wrapped result and
// report equality exactly for equal wrapper values.
func Test_BiContiguous_CompareMatchesNetworkProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		first := genBiContiguous.Draw(t, "first")
		second := genBiContiguous.Draw(t, "second")
		comparison := first.Compare(second)
		require.Equal(t, first.Network().Compare(second.Network()), comparison)
		require.Equal(t, first == second, comparison == 0)
	})
}

// verifies that every successful construction, view and comparison hot path
// allocates no heap memory.
func Test_BiContiguous_OperationsAllocationFree(t *testing.T) {
	network := mustNetwork6(t, "2a02:6b8:c00::1234:abcd:0:0", "ffff:ffff:ff00::ffff:ffff:0:0")
	block := mustContiguous6(t, "2001:db8::/32")
	first := mustBiContiguous(t, "2a02:6b8:c00::1234:abcd:0:0/ffff:ffff:ff00::ffff:ffff:0:0")
	second := mustBiContiguous(t, "2001:db8::/32")
	addr := netip.MustParseAddr("2a02:6b8:c00::1234:abcd:0:0")
	mask := netip.MustParseAddr("ffff:ffff:ff00::ffff:ffff:0:0")

	requireNoAllocs(t, func() { biContiguousSink, okSink = xnetip.BiContiguousFrom(network) })
	requireNoAllocs(t, func() { biContiguousSink, errSink = xnetip.BiContiguousFromAddrs(addr, mask) })
	requireNoAllocs(t, func() { biContiguousSink = xnetip.BiContiguousFromContiguous(block) })
	requireNoAllocs(t, func() { network6Sink = first.Network() })
	requireNoAllocs(t, func() { intSink = first.Compare(second) })
}
