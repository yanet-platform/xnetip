package xnetip_test

import (
	"encoding/json"
	"errors"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/yanet-platform/xnetip"
	"pgregory.net/rapid"
)

// mustContiguous4 wraps a parsed IPv4 network fixture, stopping the
// test when its mask is not contiguous.
func mustContiguous4(t require.TestingT, text string) xnetip.Contiguous[xnetip.Network4] {
	if helper, ok := t.(interface{ Helper() }); ok {
		helper.Helper()
	}
	wrapped, ok := xnetip.ContiguousFrom(xnetip.MustParseNetwork4(text))
	require.True(t, ok, "fixture mask is not contiguous")
	return wrapped
}

// mustContiguous6 wraps a parsed IPv6 network fixture, stopping the
// test when its mask is not contiguous.
func mustContiguous6(t require.TestingT, text string) xnetip.Contiguous[xnetip.Network6] {
	if helper, ok := t.(interface{ Helper() }); ok {
		helper.Helper()
	}
	wrapped, ok := xnetip.ContiguousFrom(xnetip.MustParseNetwork6(text))
	require.True(t, ok, "fixture mask is not contiguous")
	return wrapped
}

// mustContiguous wraps a parsed family-agnostic network fixture,
// stopping the test when its mask is not contiguous.
func mustContiguous(t require.TestingT, text string) xnetip.Contiguous[xnetip.Network] {
	if helper, ok := t.(interface{ Helper() }); ok {
		helper.Helper()
	}
	wrapped, ok := xnetip.ContiguousFrom(xnetip.MustParseNetwork(text))
	require.True(t, ok, "fixture mask is not contiguous")
	return wrapped
}

// verifies that every IPv4 prefix length wraps exactly, with the
// wrapped network round-tripping unchanged through the view.
func Test_Contiguous_From4AcceptsEveryPrefix(t *testing.T) {
	for bits := 0; bits <= 32; bits++ {
		network, err := xnetip.Network4FromCIDR(netip.MustParseAddr("10.20.30.40"), bits)
		require.NoError(t, err)
		wrapped, ok := xnetip.ContiguousFrom(network)
		require.True(t, ok, "prefix length %d", bits)
		require.Equal(t, network, wrapped.Network())
	}
}

// verifies that every IPv6 prefix length wraps exactly, with the
// wrapped network round-tripping unchanged through the view.
func Test_Contiguous_From6AcceptsEveryPrefix(t *testing.T) {
	for bits := 0; bits <= 128; bits++ {
		network, err := xnetip.Network6FromCIDR(netip.MustParseAddr("2a02:6b8::a:b:c:d"), bits)
		require.NoError(t, err)
		wrapped, ok := xnetip.ContiguousFrom(network)
		require.True(t, ok, "prefix length %d", bits)
		require.Equal(t, network, wrapped.Network())
	}
}

// verifies that the zero network of every instantiation wraps, because
// the all-zero mask is the empty leading run of ones.
func Test_Contiguous_FromAcceptsZeroValues(t *testing.T) {
	wrapped4, ok := xnetip.ContiguousFrom(xnetip.Network4{})
	require.True(t, ok)
	require.Equal(t, xnetip.Network4{}, wrapped4.Network())
	wrapped6, ok := xnetip.ContiguousFrom(xnetip.Network6{})
	require.True(t, ok)
	require.Equal(t, xnetip.Network6{}, wrapped6.Network())
	wrapped, ok := xnetip.ContiguousFrom(xnetip.Network{})
	require.True(t, ok)
	require.Equal(t, xnetip.Network{}, wrapped.Network())
}

// verifies that the zero wrapper is valid and views the universe
// network of its instantiation.
func Test_Contiguous_ZeroWrapperIsUniverse(t *testing.T) {
	require.Equal(t, xnetip.MustParseNetwork4("0.0.0.0/0"), xnetip.Contiguous[xnetip.Network4]{}.Network())
	require.Equal(t, xnetip.MustParseNetwork6("::/0"), xnetip.Contiguous[xnetip.Network6]{}.Network())
	require.Equal(t, xnetip.MustParseNetwork("::/0"), xnetip.Contiguous[xnetip.Network]{}.Network())
}

// verifies that every non-contiguous IPv4 mask shape is refused with
// the zero wrapper as the result.
func Test_Contiguous_FromRejectsNonContiguous4(t *testing.T) {
	cases := []struct {
		name    string
		network xnetip.Network4
	}{
		{name: "two-run mask", network: xnetip.MustParseNetwork4("10.0.0.0/255.0.255.0")},
		{name: "alternating mask", network: xnetip.MustParseNetwork4("170.85.170.85/170.85.170.85")},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			wrapped, ok := xnetip.ContiguousFrom(testCase.network)
			require.False(t, ok)
			require.Equal(t, xnetip.Contiguous[xnetip.Network4]{}, wrapped)
		})
	}
}

// verifies that every non-contiguous IPv6 mask shape is refused,
// the hole at the half boundary included.
func Test_Contiguous_FromRejectsNonContiguous6(t *testing.T) {
	cases := []struct {
		name    string
		network xnetip.Network6
	}{
		{name: "two-run mask", network: xnetip.MustParseNetwork6("2a02:6b8::/ffff:ffff::ffff:ffff:0:0")},
		{name: "alternating mask", network: xnetip.MustParseNetwork6("2001:db8::/aaaa:aaaa:aaaa:aaaa:aaaa:aaaa:aaaa:aaaa")},
		{name: "hole at bit 64", network: xnetip.MustParseNetwork6("2001:db8::/ffff:ffff:ffff:fffe:8000::")},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			wrapped, ok := xnetip.ContiguousFrom(testCase.network)
			require.False(t, ok)
			require.Equal(t, xnetip.Contiguous[xnetip.Network6]{}, wrapped)
		})
	}
}

// verifies that the family-agnostic instantiation refuses
// non-contiguous masks in both families.
func Test_Contiguous_FromRejectsNonContiguousNetwork(t *testing.T) {
	cases := []struct {
		name    string
		network xnetip.Network
	}{
		{name: "IPv4 two-run mask", network: xnetip.MustParseNetwork("192.168.0.1/255.255.0.255")},
		{name: "IPv6 alternating mask", network: xnetip.MustParseNetwork("2001:db8::/aaaa:aaaa:aaaa:aaaa:aaaa:aaaa:aaaa:aaaa")},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			wrapped, ok := xnetip.ContiguousFrom(testCase.network)
			require.False(t, ok)
			require.Equal(t, xnetip.Contiguous[xnetip.Network]{}, wrapped)
		})
	}
}

// verifies that wrapping a family-agnostic network preserves its
// family, an IPv4-mapped IPv6 network staying IPv6.
func Test_Contiguous_FromDualKeepsFamily(t *testing.T) {
	wrappedIs4, ok := xnetip.ContiguousFrom(mustNetworkIs4(t, "10.0.0.0", "255.255.0.0"))
	require.True(t, ok)
	require.True(t, wrappedIs4.Network().Is4())
	wrappedIs6, ok := xnetip.ContiguousFrom(xnetip.MustParseNetwork("::ffff:1.2.3.0/104"))
	require.True(t, ok)
	require.True(t, wrappedIs6.Network().Is6())
}

// verifies that comparing IPv4 blocks is exactly the wrapped order:
// by address first, then by mask.
func Test_Contiguous_Compare4MatchesInner(t *testing.T) {
	cases := []struct {
		name   string
		first  xnetip.Contiguous[xnetip.Network4]
		second xnetip.Contiguous[xnetip.Network4]
		want   int
	}{
		{name: "shorter mask sorts first", first: mustContiguous4(t, "10.0.0.0/8"), second: mustContiguous4(t, "10.0.0.0/24"), want: -1},
		{name: "equal blocks", first: mustContiguous4(t, "10.0.0.0/24"), second: mustContiguous4(t, "10.0.0.0/24"), want: 0},
		{name: "higher address sorts after", first: mustContiguous4(t, "192.168.0.0/16"), second: mustContiguous4(t, "10.0.0.0/8"), want: 1},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			require.Equal(t, testCase.want, testCase.first.Compare(testCase.second))
			require.Equal(t, testCase.first.Network().Compare(testCase.second.Network()), testCase.first.Compare(testCase.second))
		})
	}
}

// verifies that comparing IPv6 blocks is exactly the wrapped order:
// by address first, then by mask.
func Test_Contiguous_Compare6MatchesInner(t *testing.T) {
	cases := []struct {
		name   string
		first  xnetip.Contiguous[xnetip.Network6]
		second xnetip.Contiguous[xnetip.Network6]
		want   int
	}{
		{name: "shorter mask sorts first", first: mustContiguous6(t, "2001:db8::/32"), second: mustContiguous6(t, "2001:db8::/48"), want: -1},
		{name: "equal blocks", first: mustContiguous6(t, "2001:db8::/32"), second: mustContiguous6(t, "2001:db8::/32"), want: 0},
		{name: "higher address sorts after", first: mustContiguous6(t, "2001:db9::/32"), second: mustContiguous6(t, "2001:db8::/32"), want: 1},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			require.Equal(t, testCase.want, testCase.first.Compare(testCase.second))
			require.Equal(t, testCase.first.Network().Compare(testCase.second.Network()), testCase.first.Compare(testCase.second))
		})
	}
}

// verifies that the family-agnostic comparison keeps the wrapped
// order, IPv4 before IPv6.
func Test_Contiguous_CompareNetworkOrdersIPv4First(t *testing.T) {
	ipv4 := mustContiguous(t, "10.0.0.0/8")
	ipv6 := mustContiguous(t, "::/0")
	require.Equal(t, -1, ipv4.Compare(ipv6))
	require.Equal(t, 1, ipv6.Compare(ipv4))
	require.Equal(t, 0, ipv4.Compare(ipv4))
	require.Equal(t, ipv4.Network().Compare(ipv6.Network()), ipv4.Compare(ipv6))
}

// verifies that IPv4 wrapping succeeds exactly on contiguous masks,
// round-tripping on success and yielding the zero wrapper otherwise.
func Test_Contiguous_From4MatchesIsContiguousProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		network := genNetwork4.Draw(t, "network")
		wrapped, ok := xnetip.ContiguousFrom(network)
		require.Equal(t, network.IsContiguous(), ok)
		if ok {
			require.Equal(t, network, wrapped.Network())
		} else {
			require.Equal(t, xnetip.Contiguous[xnetip.Network4]{}, wrapped)
		}
	})
}

// verifies that IPv6 wrapping succeeds exactly on contiguous masks,
// round-tripping on success and yielding the zero wrapper otherwise.
func Test_Contiguous_From6MatchesIsContiguousProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		network := genNetwork6.Draw(t, "network")
		wrapped, ok := xnetip.ContiguousFrom(network)
		require.Equal(t, network.IsContiguous(), ok)
		if ok {
			require.Equal(t, network, wrapped.Network())
		} else {
			require.Equal(t, xnetip.Contiguous[xnetip.Network6]{}, wrapped)
		}
	})
}

// verifies that family-agnostic wrapping wraps exactly the contiguous
// masks, round-tripping on success and yielding the zero wrapper otherwise.
func Test_Contiguous_FromNetworkMatchesIsContiguousProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		network := genNetwork.Draw(t, "network")
		wrapped, ok := xnetip.ContiguousFrom(network)
		require.Equal(t, network.IsContiguous(), ok)
		if ok {
			require.Equal(t, network, wrapped.Network())
		} else {
			require.Equal(t, xnetip.Contiguous[xnetip.Network]{}, wrapped)
		}
	})
}

// verifies that the wrapper comparison agrees with the wrapped
// comparison on random pairs, in all three instantiations.
func Test_Contiguous_CompareAgreesWithInnerProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		first4 := genContiguous4.Draw(t, "first4")
		second4 := genContiguous4.Draw(t, "second4")
		require.Equal(t, first4.Network().Compare(second4.Network()), first4.Compare(second4))
		first6 := genContiguous6.Draw(t, "first6")
		second6 := genContiguous6.Draw(t, "second6")
		require.Equal(t, first6.Network().Compare(second6.Network()), first6.Compare(second6))
		first := genContiguous.Draw(t, "first")
		second := genContiguous.Draw(t, "second")
		require.Equal(t, first.Network().Compare(second.Network()), first.Compare(second))
	})
}

// verifies that wrapping, viewing and comparing allocate nothing in
// all three instantiations.
func Test_Contiguous_OperationsAllocationFree(t *testing.T) {
	network4 := xnetip.MustParseNetwork4("10.0.0.0/24")
	other4 := mustContiguous4(t, "10.0.0.0/8")
	requireNoAllocs(t, func() { contiguous4Sink, okSink = xnetip.ContiguousFrom(network4) })
	requireNoAllocs(t, func() { networkSink = other4.Network() })
	requireNoAllocs(t, func() { intSink = other4.Compare(contiguous4Sink) })
	network6 := xnetip.MustParseNetwork6("2001:db8::/32")
	other6 := mustContiguous6(t, "2001:db8::/48")
	requireNoAllocs(t, func() { contiguous6Sink, okSink = xnetip.ContiguousFrom(network6) })
	requireNoAllocs(t, func() { network6Sink = other6.Network() })
	requireNoAllocs(t, func() { intSink = other6.Compare(contiguous6Sink) })
	network := xnetip.MustParseNetwork("10.0.0.0/24")
	other := mustContiguous(t, "2001:db8::/32")
	requireNoAllocs(t, func() { contiguousSink, okSink = xnetip.ContiguousFrom(network) })
	requireNoAllocs(t, func() { ipNetworkSink = other.Network() })
	requireNoAllocs(t, func() { intSink = other.Compare(contiguousSink) })
}

// verifies that the total prefix length equals the block's CIDR
// length in both concrete families.
func Test_Contiguous_PrefixLen_PlainBlocks(t *testing.T) {
	require.Equal(t, 8, xnetip.MustParseContiguous4("10.0.0.0/8").PrefixLen())
	require.Equal(t, 32, xnetip.MustParseContiguous6("2001:db8::/32").PrefixLen())
}

// verifies that the boundary prefix lengths are reported exactly,
// the zero wrappers reporting the universe length zero.
func Test_Contiguous_PrefixLen_Boundaries(t *testing.T) {
	require.Equal(t, 0, xnetip.MustParseContiguous4("0.0.0.0/0").PrefixLen())
	require.Equal(t, 32, xnetip.MustParseContiguous4("255.255.255.255/32").PrefixLen())
	require.Equal(t, 0, xnetip.MustParseContiguous6("::/0").PrefixLen())
	require.Equal(t, 128, xnetip.MustParseContiguous6("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/128").PrefixLen())
	require.Equal(t, 0, xnetip.Contiguous[xnetip.Network4]{}.PrefixLen())
	require.Equal(t, 0, xnetip.Contiguous[xnetip.Network6]{}.PrefixLen())
	require.Equal(t, 0, xnetip.Contiguous[xnetip.Network]{}.PrefixLen())
}

// verifies that an IPv4 block of the dual instantiation reports the
// family-native length and an unmapped Is4 prefix.
func Test_Contiguous_PrefixLen_DualIsFamilyNative(t *testing.T) {
	block := xnetip.MustParseContiguous("10.20.0.0/16")
	require.Equal(t, 16, block.PrefixLen())
	require.True(t, block.Prefix().Addr().Is4())
	require.Equal(t, netip.MustParsePrefix("10.20.0.0/16"), block.Prefix())
}

// verifies that the total prefix view equals the netip form of the
// block in both concrete families.
func Test_Contiguous_Prefix_PlainBlocks(t *testing.T) {
	require.Equal(t, netip.MustParsePrefix("10.0.0.0/8"), xnetip.MustParseContiguous4("10.0.0.0/8").Prefix())
	require.Equal(t, netip.MustParsePrefix("2001:db8::/32"), xnetip.MustParseContiguous6("2001:db8::/32").Prefix())
}

// verifies that an IPv4-mapped IPv6 block of the dual instantiation
// stays IPv6: the 128-bit length and an Is6 prefix.
func Test_Contiguous_Prefix_DualMappedStaysIPv6(t *testing.T) {
	block := xnetip.MustParseContiguous("::ffff:10.0.0.0/104")
	require.Equal(t, 104, block.PrefixLen())
	prefix := block.Prefix()
	require.False(t, prefix.Addr().Is4())
	require.True(t, prefix.Addr().Is4In6())
	require.Equal(t, 104, prefix.Bits())
}

// verifies that the prefix view is already masked for every fixture
// shape: the wrapped address carries no host bits.
func Test_Contiguous_Prefix_AlreadyMasked(t *testing.T) {
	for _, text := range []string{"10.0.0.0/8", "192.168.1.128/25", "8.8.8.8/32"} {
		prefix := xnetip.MustParseContiguous4(text).Prefix()
		require.Equal(t, prefix.Masked(), prefix, text)
	}
	for _, text := range []string{"2001:db8::/32", "2001:db8:0:0:8000::/65", "::1/128"} {
		prefix := xnetip.MustParseContiguous6(text).Prefix()
		require.Equal(t, prefix.Masked(), prefix, text)
	}
}

// verifies that the total accessors equal the inner comma-ok values
// with ok always true, in all three instantiations.
func Test_Contiguous_PrefixLen_MatchesInnerProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		block4 := genContiguous4.Draw(t, "block4")
		innerLen4, ok := block4.Network().PrefixLen()
		require.True(t, ok)
		require.Equal(t, innerLen4, block4.PrefixLen())
		innerPrefix4, ok := block4.Network().Prefix()
		require.True(t, ok)
		require.Equal(t, innerPrefix4, block4.Prefix())
		block6 := genContiguous6.Draw(t, "block6")
		innerLen6, ok := block6.Network().PrefixLen()
		require.True(t, ok)
		require.Equal(t, innerLen6, block6.PrefixLen())
		innerPrefix6, ok := block6.Network().Prefix()
		require.True(t, ok)
		require.Equal(t, innerPrefix6, block6.Prefix())
		block := genContiguous.Draw(t, "block")
		innerLen, ok := block.Network().PrefixLen()
		require.True(t, ok)
		require.Equal(t, innerLen, block.PrefixLen())
		innerPrefix, ok := block.Network().Prefix()
		require.True(t, ok)
		require.Equal(t, innerPrefix, block.Prefix())
	})
}

// verifies that the prefix length equals the leading-ones count of
// the wrapped mask, counted bit by bit.
func Test_Contiguous_PrefixLen_LeadingOnesOracleProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		block4 := genContiguous4.Draw(t, "block4")
		_, mask4 := ipv4NetworkBits(block4.Network())
		count4 := 0
		for count4 < 32 && mask4&(1<<(31-count4)) != 0 {
			count4++
		}
		require.Equal(t, count4, block4.PrefixLen())
		block6 := genContiguous6.Draw(t, "block6")
		_, _, maskHi, maskLo := ipv6NetworkBits(block6.Network())
		count6 := 0
		for count6 < 64 && maskHi&(1<<(63-count6)) != 0 {
			count6++
		}
		if count6 == 64 {
			for count6 < 128 && maskLo&(1<<(127-count6)) != 0 {
				count6++
			}
		}
		require.Equal(t, count6, block6.PrefixLen())
	})
}

// verifies that rebuilding the prefix from the block's address and
// total length lands on the prefix view, netip doing the masking.
func Test_Contiguous_Prefix_RebuildRoundTripProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		block4 := genContiguous4.Draw(t, "block4")
		require.Equal(t, netip.PrefixFrom(block4.Network().Addr(), block4.PrefixLen()).Masked(), block4.Prefix())
		block6 := genContiguous6.Draw(t, "block6")
		require.Equal(t, netip.PrefixFrom(block6.Network().Addr(), block6.PrefixLen()).Masked(), block6.Prefix())
		block := genContiguous.Draw(t, "block")
		require.Equal(t, netip.PrefixFrom(block.Network().Addr(), block.PrefixLen()).Masked(), block.Prefix())
	})
}

// verifies that an IPv4 block contains its nested block and not the
// other way around.
func Test_Contiguous_Contains_Nested4(t *testing.T) {
	container := xnetip.MustParseContiguous4("10.0.0.0/8")
	nested := xnetip.MustParseContiguous4("10.1.0.0/16")
	require.True(t, container.Contains(nested))
	require.False(t, nested.Contains(container))
}

// verifies that an IPv6 block contains its nested block and not the
// other way around.
func Test_Contiguous_Contains_Nested6(t *testing.T) {
	container := xnetip.MustParseContiguous6("2001:db8::/32")
	nested := xnetip.MustParseContiguous6("2001:db8:1::/48")
	require.True(t, container.Contains(nested))
	require.False(t, nested.Contains(container))
}

// verifies that equal blocks contain each other in both families.
func Test_Contiguous_Contains_EqualBlocks(t *testing.T) {
	first4 := xnetip.MustParseContiguous4("172.16.0.0/12")
	second4 := xnetip.MustParseContiguous4("172.16.0.0/12")
	require.True(t, first4.Contains(second4))
	require.True(t, second4.Contains(first4))
	first6 := xnetip.MustParseContiguous6("2001:db8::/32")
	second6 := xnetip.MustParseContiguous6("2001:db8::/32")
	require.True(t, first6.Contains(second6))
	require.True(t, second6.Contains(first6))
}

// verifies the boundary prefixes: the universe contains a host route
// and itself, a host route contains only itself.
func Test_Contiguous_Contains_BoundaryPrefixes(t *testing.T) {
	universe4 := xnetip.MustParseContiguous4("0.0.0.0/0")
	host4 := xnetip.MustParseContiguous4("8.8.8.8/32")
	require.True(t, universe4.Contains(host4))
	require.False(t, host4.Contains(universe4))
	require.True(t, universe4.Contains(universe4))
	require.True(t, host4.Contains(host4))
	require.False(t, host4.Contains(xnetip.MustParseContiguous4("8.8.4.4/32")))
	universe6 := xnetip.MustParseContiguous6("::/0")
	host6 := xnetip.MustParseContiguous6("::1/128")
	require.True(t, universe6.Contains(host6))
	require.False(t, host6.Contains(universe6))
	require.True(t, universe6.Contains(universe6))
	require.True(t, host6.Contains(host6))
	require.False(t, host6.Contains(xnetip.MustParseContiguous6("::2/128")))
}

// verifies that disjoint sibling halves contain each other in
// neither direction, in both families.
func Test_Contiguous_Contains_DisjointSiblings(t *testing.T) {
	low4 := xnetip.MustParseContiguous4("10.0.0.0/9")
	high4 := xnetip.MustParseContiguous4("10.128.0.0/9")
	require.False(t, low4.Contains(high4))
	require.False(t, high4.Contains(low4))
	low6 := xnetip.MustParseContiguous6("2001:db8::/33")
	high6 := xnetip.MustParseContiguous6("2001:db8:8000::/33")
	require.False(t, low6.Contains(high6))
	require.False(t, high6.Contains(low6))
}

// verifies that same-family pairs of the dual instantiation answer
// exactly as the wrapped networks do.
func Test_Contiguous_Contains_DualSameFamilyMatchesInner(t *testing.T) {
	container4 := xnetip.MustParseContiguous("10.0.0.0/8")
	nested4 := xnetip.MustParseContiguous("10.1.0.0/16")
	require.True(t, container4.Contains(nested4))
	require.False(t, nested4.Contains(container4))
	require.Equal(t, container4.Network().Contains(nested4.Network()), container4.Contains(nested4))
	container6 := xnetip.MustParseContiguous("2001:db8::/32")
	nested6 := xnetip.MustParseContiguous("2001:db8:1::/48")
	require.True(t, container6.Contains(nested6))
	require.False(t, nested6.Contains(container6))
	require.Equal(t, container6.Network().Contains(nested6.Network()), container6.Contains(nested6))
}

// verifies that blocks of different families never contain each
// other, the IPv4-mapped IPv6 form against IPv4 included.
func Test_Contiguous_Contains_DualMixedFamilyIsFalse(t *testing.T) {
	ipv4 := xnetip.MustParseContiguous("10.0.0.0/8")
	ipv6 := xnetip.MustParseContiguous("2001:db8::/32")
	require.False(t, ipv4.Contains(ipv6))
	require.False(t, ipv6.Contains(ipv4))
	mapped := xnetip.MustParseContiguous("::ffff:10.0.0.0/104")
	require.False(t, ipv4.Contains(mapped))
	require.False(t, mapped.Contains(ipv4))
}

// verifies that the collapsed formula agrees with the general
// containment of the unwrapped networks, in all three instantiations.
func Test_Contiguous_Contains_MatchesInnerProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		first4 := genContiguous4.Draw(t, "first4")
		second4 := genContiguous4.Draw(t, "second4")
		require.Equal(t, first4.Network().Contains(second4.Network()), first4.Contains(second4))
		first6 := genContiguous6.Draw(t, "first6")
		second6 := genContiguous6.Draw(t, "second6")
		require.Equal(t, first6.Network().Contains(second6.Network()), first6.Contains(second6))
		first := genContiguous.Draw(t, "first")
		second := genContiguous.Draw(t, "second")
		require.Equal(t, first.Network().Contains(second.Network()), first.Contains(second))
	})
}

// verifies the partial order: containment is reflexive,
// antisymmetric up to equality and transitive on drawn blocks.
func Test_Contiguous_Contains_PartialOrderProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		first := genContiguous.Draw(t, "first")
		second := genContiguous.Draw(t, "second")
		third := genContiguous.Draw(t, "third")
		require.True(t, first.Contains(first))
		if first.Contains(second) && second.Contains(first) {
			require.Equal(t, first, second)
		}
		if first.Contains(second) && second.Contains(third) {
			require.True(t, first.Contains(third))
		}
	})
}

// verifies against net/netip: containment equals prefix overlap
// with the length condition, and base-address containment likewise.
func Test_Contiguous_Contains_MatchesNetipPrefixProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		first4 := genContiguous4.Draw(t, "first4")
		second4 := genContiguous4.Draw(t, "second4")
		nested4 := first4.Prefix().Overlaps(second4.Prefix()) && first4.PrefixLen() <= second4.PrefixLen()
		require.Equal(t, nested4, first4.Contains(second4))
		byAddr4 := first4.Prefix().Contains(second4.Network().Addr()) && first4.PrefixLen() <= second4.PrefixLen()
		require.Equal(t, byAddr4, first4.Contains(second4))
		first6 := genContiguous6.Draw(t, "first6")
		second6 := genContiguous6.Draw(t, "second6")
		nested6 := first6.Prefix().Overlaps(second6.Prefix()) && first6.PrefixLen() <= second6.PrefixLen()
		require.Equal(t, nested6, first6.Contains(second6))
		byAddr6 := first6.Prefix().Contains(second6.Network().Addr()) && first6.PrefixLen() <= second6.PrefixLen()
		require.Equal(t, byAddr6, first6.Contains(second6))
	})
}

// verifies that intersecting nested blocks yields the nested block
// in both orders, in both families.
func Test_Contiguous_Intersection_Nested(t *testing.T) {
	container4 := xnetip.MustParseContiguous4("10.0.0.0/8")
	nested4 := xnetip.MustParseContiguous4("10.1.0.0/16")
	intersected4, ok := container4.Intersection(nested4)
	require.True(t, ok)
	require.Equal(t, nested4, intersected4)
	intersected4, ok = nested4.Intersection(container4)
	require.True(t, ok)
	require.Equal(t, nested4, intersected4)
	container6 := xnetip.MustParseContiguous6("2001:db8::/32")
	nested6 := xnetip.MustParseContiguous6("2001:db8:1::/48")
	intersected6, ok := container6.Intersection(nested6)
	require.True(t, ok)
	require.Equal(t, nested6, intersected6)
	intersected6, ok = nested6.Intersection(container6)
	require.True(t, ok)
	require.Equal(t, nested6, intersected6)
}

// verifies that disjoint sibling blocks report no intersection with
// the zero wrapper as the result.
func Test_Contiguous_Intersection_Disjoint(t *testing.T) {
	low := xnetip.MustParseContiguous4("10.0.0.0/9")
	high := xnetip.MustParseContiguous4("10.128.0.0/9")
	intersected, ok := low.Intersection(high)
	require.False(t, ok)
	require.Equal(t, xnetip.Contiguous[xnetip.Network4]{}, intersected)
	low6 := xnetip.MustParseContiguous6("2001:db8::/33")
	high6 := xnetip.MustParseContiguous6("2001:db8:8000::/33")
	intersected6, ok := low6.Intersection(high6)
	require.False(t, ok)
	require.Equal(t, xnetip.Contiguous[xnetip.Network6]{}, intersected6)
}

// verifies that a block intersected with itself is itself.
func Test_Contiguous_Intersection_Self(t *testing.T) {
	block4 := xnetip.MustParseContiguous4("192.168.0.0/16")
	intersected4, ok := block4.Intersection(block4)
	require.True(t, ok)
	require.Equal(t, block4, intersected4)
	block6 := xnetip.MustParseContiguous6("2001:db8::/32")
	intersected6, ok := block6.Intersection(block6)
	require.True(t, ok)
	require.Equal(t, block6, intersected6)
}

// verifies that the universe absorbs any block of its family: the
// intersection is the other operand.
func Test_Contiguous_Intersection_UniverseAbsorbs(t *testing.T) {
	block4 := xnetip.MustParseContiguous4("10.1.0.0/16")
	intersected4, ok := xnetip.MustParseContiguous4("0.0.0.0/0").Intersection(block4)
	require.True(t, ok)
	require.Equal(t, block4, intersected4)
	block6 := xnetip.MustParseContiguous6("2001:db8:1::/48")
	intersected6, ok := xnetip.MustParseContiguous6("::/0").Intersection(block6)
	require.True(t, ok)
	require.Equal(t, block6, intersected6)
}

// verifies that blocks of different families never intersect in the
// dual instantiation.
func Test_Contiguous_Intersection_DualCrossFamily(t *testing.T) {
	ipv4 := xnetip.MustParseContiguous("10.0.0.0/8")
	ipv6 := xnetip.MustParseContiguous("2001:db8::/32")
	intersected, ok := ipv4.Intersection(ipv6)
	require.False(t, ok)
	require.Equal(t, xnetip.Contiguous[xnetip.Network]{}, intersected)
	intersected, ok = ipv6.Intersection(ipv4)
	require.False(t, ok)
	require.Equal(t, xnetip.Contiguous[xnetip.Network]{}, intersected)
}

// verifies that CIDR buddies at the prefix boundary bit merge into
// their parent block.
func Test_Contiguous_MergeByLowestMaskBit_Buddies(t *testing.T) {
	low := xnetip.MustParseContiguous4("10.0.0.0/9")
	high := xnetip.MustParseContiguous4("10.128.0.0/9")
	merged, ok := low.MergeByLowestMaskBit(high)
	require.True(t, ok)
	require.Equal(t, xnetip.MustParseContiguous4("10.0.0.0/8"), merged)
	merged, ok = high.MergeByLowestMaskBit(low)
	require.True(t, ok)
	require.Equal(t, xnetip.MustParseContiguous4("10.0.0.0/8"), merged)
}

// verifies that two adjacent host routes merge into their /31.
func Test_Contiguous_MergeByLowestMaskBit_HostRouteBuddies(t *testing.T) {
	even := xnetip.MustParseContiguous4("10.0.0.0/32")
	odd := xnetip.MustParseContiguous4("10.0.0.1/32")
	merged, ok := even.MergeByLowestMaskBit(odd)
	require.True(t, ok)
	require.Equal(t, xnetip.MustParseContiguous4("10.0.0.0/31"), merged)
}

// verifies that containment merges to the larger block in both
// orders.
func Test_Contiguous_MergeByLowestMaskBit_Containment(t *testing.T) {
	container := xnetip.MustParseContiguous4("10.0.0.0/8")
	nested := xnetip.MustParseContiguous4("10.1.0.0/16")
	merged, ok := container.MergeByLowestMaskBit(nested)
	require.True(t, ok)
	require.Equal(t, container, merged)
	merged, ok = nested.MergeByLowestMaskBit(container)
	require.True(t, ok)
	require.Equal(t, container, merged)
}

// verifies that non-adjacent same-length blocks refuse to merge with
// the zero wrapper as the result.
func Test_Contiguous_MergeByLowestMaskBit_NonAdjacentRefuse(t *testing.T) {
	first := xnetip.MustParseContiguous4("10.0.0.0/24")
	second := xnetip.MustParseContiguous4("10.0.2.0/24")
	merged, ok := first.MergeByLowestMaskBit(second)
	require.False(t, ok)
	require.Equal(t, xnetip.Contiguous[xnetip.Network4]{}, merged)
}

// verifies that IPv6 buddies whose boundary bit sits in the high
// half, one step above bit 64, merge into their parent.
func Test_Contiguous_MergeByLowestMaskBit_BuddiesAcrossBit64(t *testing.T) {
	low := xnetip.MustParseContiguous6("2001:db8:0:0::/63")
	high := xnetip.MustParseContiguous6("2001:db8:0:2::/63")
	merged, ok := low.MergeByLowestMaskBit(high)
	require.True(t, ok)
	require.Equal(t, xnetip.MustParseContiguous6("2001:db8::/62"), merged)
}

// verifies that blocks of different families never merge in the dual
// instantiation.
func Test_Contiguous_MergeByLowestMaskBit_DualCrossFamily(t *testing.T) {
	ipv4 := xnetip.MustParseContiguous("10.0.0.0/8")
	ipv6 := xnetip.MustParseContiguous("2001:db8::/32")
	merged, ok := ipv4.MergeByLowestMaskBit(ipv6)
	require.False(t, ok)
	require.Equal(t, xnetip.Contiguous[xnetip.Network]{}, merged)
}

// verifies that both class-closed operations equal the unwrapped
// operations, result and flag alike, in all three instantiations.
func Test_Contiguous_Intersection_MatchesInnerProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		first4 := genContiguous4.Draw(t, "first4")
		second4 := genContiguous4.Draw(t, "second4")
		requireClassClosedMatchInner4(t, first4, second4)
		first6 := genContiguous6.Draw(t, "first6")
		second6 := genContiguous6.Draw(t, "second6")
		requireClassClosedMatchInner6(t, first6, second6)
		first := genContiguous.Draw(t, "first")
		second := genContiguous.Draw(t, "second")
		requireClassClosedMatchInner(t, first, second)
	})
}

// requireClassClosedMatchInner4 asserts that the typed intersection
// and merge of two IPv4 blocks equal the unwrapped operations.
//
// Every ok result must also survive revalidation through the exact
// constructor, precisely because the implementation skips it.
func requireClassClosedMatchInner4(t require.TestingT, first, second xnetip.Contiguous[xnetip.Network4]) {
	if helper, ok := t.(interface{ Helper() }); ok {
		helper.Helper()
	}
	innerIntersected, innerOk := first.Network().Intersection(second.Network())
	intersected, ok := first.Intersection(second)
	require.Equal(t, innerOk, ok)
	if ok {
		require.Equal(t, innerIntersected, intersected.Network())
		_, stillOk := xnetip.ContiguousFrom(intersected.Network())
		require.True(t, stillOk)
	}
	innerMerged, innerOk := first.Network().MergeByLowestMaskBit(second.Network())
	merged, ok := first.MergeByLowestMaskBit(second)
	require.Equal(t, innerOk, ok)
	if ok {
		require.Equal(t, innerMerged, merged.Network())
		_, stillOk := xnetip.ContiguousFrom(merged.Network())
		require.True(t, stillOk)
	}
}

// requireClassClosedMatchInner6 asserts that the typed intersection
// and merge of two IPv6 blocks equal the unwrapped operations.
//
// Every ok result must also survive revalidation through the exact
// constructor, precisely because the implementation skips it.
func requireClassClosedMatchInner6(t require.TestingT, first, second xnetip.Contiguous[xnetip.Network6]) {
	if helper, ok := t.(interface{ Helper() }); ok {
		helper.Helper()
	}
	innerIntersected, innerOk := first.Network().Intersection(second.Network())
	intersected, ok := first.Intersection(second)
	require.Equal(t, innerOk, ok)
	if ok {
		require.Equal(t, innerIntersected, intersected.Network())
		_, stillOk := xnetip.ContiguousFrom(intersected.Network())
		require.True(t, stillOk)
	}
	innerMerged, innerOk := first.Network().MergeByLowestMaskBit(second.Network())
	merged, ok := first.MergeByLowestMaskBit(second)
	require.Equal(t, innerOk, ok)
	if ok {
		require.Equal(t, innerMerged, merged.Network())
		_, stillOk := xnetip.ContiguousFrom(merged.Network())
		require.True(t, stillOk)
	}
}

// requireClassClosedMatchInner asserts that the typed intersection
// and merge of two dual blocks equal the unwrapped operations.
//
// Every ok result must also survive revalidation through the exact
// constructor, precisely because the implementation skips it.
func requireClassClosedMatchInner(t require.TestingT, first, second xnetip.Contiguous[xnetip.Network]) {
	if helper, ok := t.(interface{ Helper() }); ok {
		helper.Helper()
	}
	innerIntersected, innerOk := first.Network().Intersection(second.Network())
	intersected, ok := first.Intersection(second)
	require.Equal(t, innerOk, ok)
	if ok {
		require.Equal(t, innerIntersected, intersected.Network())
		_, stillOk := xnetip.ContiguousFrom(intersected.Network())
		require.True(t, stillOk)
	}
	innerMerged, innerOk := first.Network().MergeByLowestMaskBit(second.Network())
	merged, ok := first.MergeByLowestMaskBit(second)
	require.Equal(t, innerOk, ok)
	if ok {
		require.Equal(t, innerMerged, merged.Network())
		_, stillOk := xnetip.ContiguousFrom(merged.Network())
		require.True(t, stillOk)
	}
}

// verifies that intersection and merge are commutative on random
// pairs, in all three instantiations.
func Test_Contiguous_Intersection_CommutativeProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		first := genContiguous.Draw(t, "first")
		second := genContiguous.Draw(t, "second")
		intersected, ok := first.Intersection(second)
		intersectedBack, okBack := second.Intersection(first)
		require.Equal(t, ok, okBack)
		require.Equal(t, intersected, intersectedBack)
		merged, ok := first.MergeByLowestMaskBit(second)
		mergedBack, okBack := second.MergeByLowestMaskBit(first)
		require.Equal(t, ok, okBack)
		require.Equal(t, merged, mergedBack)
	})
}

// verifies that a wrapped sibling pair always merges into the parent
// block one prefix bit shorter, in both families.
func Test_Contiguous_MergeByLowestMaskBit_SiblingsMergeToParentProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		pair4 := genIPv4ContiguousSiblingPair.Draw(t, "pair4")
		first4, ok := xnetip.ContiguousFrom(pair4[0])
		require.True(t, ok)
		second4, ok := xnetip.ContiguousFrom(pair4[1])
		require.True(t, ok)
		merged4, ok := first4.MergeByLowestMaskBit(second4)
		require.True(t, ok)
		require.Equal(t, first4.PrefixLen()-1, merged4.PrefixLen())
		require.True(t, merged4.Contains(first4))
		require.True(t, merged4.Contains(second4))
		pair6 := genIPv6ContiguousSiblingPair.Draw(t, "pair6")
		first6, ok := xnetip.ContiguousFrom(pair6[0])
		require.True(t, ok)
		second6, ok := xnetip.ContiguousFrom(pair6[1])
		require.True(t, ok)
		merged6, ok := first6.MergeByLowestMaskBit(second6)
		require.True(t, ok)
		require.Equal(t, first6.PrefixLen()-1, merged6.PrefixLen())
		require.True(t, merged6.Contains(first6))
		require.True(t, merged6.Contains(second6))
	})
}

// verifies the CIDR laminar fact: two blocks intersect exactly when
// one contains the other.
func Test_Contiguous_Intersection_OkIffContainmentProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		first := genContiguous.Draw(t, "first")
		second := genContiguous.Draw(t, "second")
		_, ok := first.Intersection(second)
		require.Equal(t, first.Contains(second) || second.Contains(first), ok)
	})
}

// verifies against net/netip: the intersection flag agrees with
// prefix overlap in both families.
func Test_Contiguous_Intersection_MatchesNetipOverlapsProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		first4 := genContiguous4.Draw(t, "first4")
		second4 := genContiguous4.Draw(t, "second4")
		_, ok := first4.Intersection(second4)
		require.Equal(t, first4.Prefix().Overlaps(second4.Prefix()), ok)
		first6 := genContiguous6.Draw(t, "first6")
		second6 := genContiguous6.Draw(t, "second6")
		_, ok = first6.Intersection(second6)
		require.Equal(t, first6.Prefix().Overlaps(second6.Prefix()), ok)
	})
}

// verifies that both class-closed operations allocate nothing in all
// three instantiations.
func Test_Contiguous_Intersection_AllocationFree(t *testing.T) {
	container4 := xnetip.MustParseContiguous4("10.0.0.0/8")
	nested4 := xnetip.MustParseContiguous4("10.1.0.0/16")
	requireNoAllocs(t, func() { contiguous4Sink, okSink = container4.Intersection(nested4) })
	requireNoAllocs(t, func() { contiguous4Sink, okSink = container4.MergeByLowestMaskBit(nested4) })
	container6 := xnetip.MustParseContiguous6("2001:db8::/32")
	nested6 := xnetip.MustParseContiguous6("2001:db8:1::/48")
	requireNoAllocs(t, func() { contiguous6Sink, okSink = container6.Intersection(nested6) })
	requireNoAllocs(t, func() { contiguous6Sink, okSink = container6.MergeByLowestMaskBit(nested6) })
	container := xnetip.MustParseContiguous("10.0.0.0/8")
	nested := xnetip.MustParseContiguous("10.1.0.0/16")
	requireNoAllocs(t, func() { contiguousSink, okSink = container.Intersection(nested) })
	requireNoAllocs(t, func() { contiguousSink, okSink = container.MergeByLowestMaskBit(nested) })
}

// verifies that subtracting a nested block peels exactly the prefix
// ladder between the two lengths, most significant bit first.
func Test_Contiguous_Difference_SupersetLadderExact(t *testing.T) {
	source := xnetip.MustParseContiguous4("192.168.0.0/16")
	other := xnetip.MustParseContiguous4("192.168.1.0/24")
	expected := []xnetip.Contiguous[xnetip.Network4]{
		xnetip.MustParseContiguous4("192.168.128.0/17"),
		xnetip.MustParseContiguous4("192.168.64.0/18"),
		xnetip.MustParseContiguous4("192.168.32.0/19"),
		xnetip.MustParseContiguous4("192.168.16.0/20"),
		xnetip.MustParseContiguous4("192.168.8.0/21"),
		xnetip.MustParseContiguous4("192.168.4.0/22"),
		xnetip.MustParseContiguous4("192.168.2.0/23"),
		xnetip.MustParseContiguous4("192.168.0.0/24"),
	}
	require.Equal(t, expected, slices.Collect(source.Difference(other)))
}

// verifies that a disjoint subtrahend leaves the source as the
// single part.
func Test_Contiguous_Difference_Disjoint(t *testing.T) {
	source := xnetip.MustParseContiguous4("10.0.0.0/8")
	other := xnetip.MustParseContiguous4("192.168.0.0/16")
	require.Equal(t, []xnetip.Contiguous[xnetip.Network4]{source}, slices.Collect(source.Difference(other)))
}

// verifies that a containing subtrahend and the block itself both
// leave nothing.
func Test_Contiguous_Difference_SubsetAndSelf(t *testing.T) {
	nested := xnetip.MustParseContiguous4("192.168.1.0/24")
	container := xnetip.MustParseContiguous4("192.168.0.0/16")
	require.Empty(t, slices.Collect(nested.Difference(container)))
	require.Empty(t, slices.Collect(nested.Difference(nested)))
}

// verifies the full-depth ladder: the universe minus one host peels
// the 32 blocks /1 through /32, each part the wrapped inner part.
func Test_Contiguous_Difference_UniverseMinusHost(t *testing.T) {
	source := xnetip.MustParseContiguous4("0.0.0.0/0")
	other := xnetip.MustParseContiguous4("8.8.8.8/32")
	parts := slices.Collect(source.Difference(other))
	require.Len(t, parts, 32)
	inner := slices.Collect(source.Network().Difference(other.Network()))
	for idx, part := range parts {
		require.Equal(t, idx+1, part.PrefixLen())
		require.Equal(t, inner[idx], part.Network())
	}
}

// verifies the IPv6 ladder whose peeled bits straddle the 64-bit
// half boundary: 17 parts, /49 through /65.
func Test_Contiguous_Difference_LadderAcrossBit64(t *testing.T) {
	source := xnetip.MustParseContiguous6("2001:db8::/48")
	other := xnetip.MustParseContiguous6("2001:db8:0:0:8000::/65")
	parts := slices.Collect(source.Difference(other))
	require.Len(t, parts, 17)
	inner := slices.Collect(source.Network().Difference(other.Network()))
	for idx, part := range parts {
		require.Equal(t, 49+idx, part.PrefixLen())
		require.Equal(t, inner[idx], part.Network())
	}
}

// verifies that a cross-family subtrahend of the dual instantiation
// leaves the source as the single part: the operands are disjoint.
func Test_Contiguous_Difference_DualCrossFamily(t *testing.T) {
	source := xnetip.MustParseContiguous("10.0.0.0/8")
	other := xnetip.MustParseContiguous("2001:db8::/32")
	require.Equal(t, []xnetip.Contiguous[xnetip.Network]{source}, slices.Collect(source.Difference(other)))
}

// verifies that breaking out of the range loop stops the peel, and
// that the sequence yields the full ladder again afterwards.
func Test_Contiguous_Difference_EarlyBreakStops(t *testing.T) {
	source := xnetip.MustParseContiguous4("192.168.0.0/16")
	other := xnetip.MustParseContiguous4("192.168.1.0/24")
	sequence := source.Difference(other)
	seen := 0
	for range sequence {
		seen++
		if seen == 2 {
			break
		}
	}
	require.Equal(t, 2, seen)
	require.Len(t, slices.Collect(sequence), 8)
}

// verifies that the typed parts equal the unwrapped difference item
// by item in the same order, in all three instantiations.
func Test_Contiguous_Difference_MatchesInnerProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		first4 := genContiguous4.Draw(t, "first4")
		second4 := genContiguous4.Draw(t, "second4")
		inner4 := slices.Collect(first4.Network().Difference(second4.Network()))
		parts4 := slices.Collect(first4.Difference(second4))
		require.Len(t, parts4, len(inner4))
		for idx, part := range parts4 {
			require.Equal(t, inner4[idx], part.Network())
		}
		first6 := genContiguous6.Draw(t, "first6")
		second6 := genContiguous6.Draw(t, "second6")
		inner6 := slices.Collect(first6.Network().Difference(second6.Network()))
		parts6 := slices.Collect(first6.Difference(second6))
		require.Len(t, parts6, len(inner6))
		for idx, part := range parts6 {
			require.Equal(t, inner6[idx], part.Network())
		}
		first := genContiguous.Draw(t, "first")
		second := genContiguous.Draw(t, "second")
		inner := slices.Collect(first.Network().Difference(second.Network()))
		parts := slices.Collect(first.Difference(second))
		require.Len(t, parts, len(inner))
		for idx, part := range parts {
			require.Equal(t, inner[idx], part.Network())
		}
	})
}

// verifies the ladder contract on strictly nested pairs in both
// families.
//
// The count is the prefix gap between the two lengths and part k
// carries the source length plus k plus one.
func Test_Contiguous_Difference_LadderProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		source4 := genContiguous4.Filter(func(block xnetip.Contiguous[xnetip.Network4]) bool {
			return block.PrefixLen() < 32
		}).Draw(t, "source4")
		addrBits, maskBits := ipv4NetworkBits(source4.Network())
		hostBits := rapid.Uint32().Draw(t, "host bits") &^ maskBits
		bits4 := rapid.IntRange(source4.PrefixLen()+1, 32).Draw(t, "nested prefix 4")
		nestedNetwork4, err := xnetip.Network4FromCIDR(netipAddrFrom4Bits(addrBits|hostBits), bits4)
		require.NoError(t, err)
		nested4, ok := xnetip.ContiguousFrom(nestedNetwork4)
		require.True(t, ok)
		parts4 := slices.Collect(source4.Difference(nested4))
		require.Len(t, parts4, nested4.PrefixLen()-source4.PrefixLen())
		for idx, part := range parts4 {
			require.Equal(t, source4.PrefixLen()+idx+1, part.PrefixLen())
		}
		source6 := genContiguous6.Filter(func(block xnetip.Contiguous[xnetip.Network6]) bool {
			return block.PrefixLen() < 128
		}).Draw(t, "source6")
		addrHi, addrLo, maskHi, maskLo := ipv6NetworkBits(source6.Network())
		hostHi := rapid.Uint64().Draw(t, "host hi") &^ maskHi
		hostLo := rapid.Uint64().Draw(t, "host lo") &^ maskLo
		bits6 := rapid.IntRange(source6.PrefixLen()+1, 128).Draw(t, "nested prefix 6")
		nestedNetwork6, err := xnetip.Network6FromCIDR(netipAddrFrom6Bits(addrHi|hostHi, addrLo|hostLo), bits6)
		require.NoError(t, err)
		nested6, ok := xnetip.ContiguousFrom(nestedNetwork6)
		require.True(t, ok)
		parts6 := slices.Collect(source6.Difference(nested6))
		require.Len(t, parts6, nested6.PrefixLen()-source6.PrefixLen())
		for idx, part := range parts6 {
			require.Equal(t, source6.PrefixLen()+idx+1, part.PrefixLen())
		}
	})
}

// verifies that every part revalidates as contiguous, is contained
// in the source and is disjoint from the subtrahend.
func Test_Contiguous_Difference_PartsInvariantsProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		source := genContiguous.Draw(t, "source")
		other := genContiguous.Draw(t, "other")
		for part := range source.Difference(other) {
			_, ok := xnetip.ContiguousFrom(part.Network())
			require.True(t, ok)
			require.True(t, source.Contains(part))
			_, overlaps := part.Intersection(other)
			require.False(t, overlaps)
		}
	})
}

// verifies that consuming the ladder with a range loop allocates
// nothing in any of the three instantiations.
func Test_Contiguous_Difference_AllocationFree(t *testing.T) {
	source4 := xnetip.MustParseContiguous4("0.0.0.0/0")
	other4 := xnetip.MustParseContiguous4("8.8.8.8/32")
	requireNoAllocs(t, func() {
		for part := range source4.Difference(other4) {
			contiguous4Sink = part
		}
	})
	source6 := xnetip.MustParseContiguous6("::/0")
	other6 := xnetip.MustParseContiguous6("2001:db8::1/128")
	requireNoAllocs(t, func() {
		for part := range source6.Difference(other6) {
			contiguous6Sink = part
		}
	})
	source := xnetip.MustParseContiguous("::/0")
	other := xnetip.MustParseContiguous("2001:db8::1/128")
	requireNoAllocs(t, func() {
		for part := range source.Difference(other) {
			contiguousSink = part
		}
	})
}

// verifies that typed containment allocates nothing in all three
// instantiations.
func Test_Contiguous_Contains_AllocationFree(t *testing.T) {
	container4 := xnetip.MustParseContiguous4("10.0.0.0/8")
	nested4 := xnetip.MustParseContiguous4("10.1.0.0/16")
	requireNoAllocs(t, func() { okSink = container4.Contains(nested4) })
	container6 := xnetip.MustParseContiguous6("2001:db8::/32")
	nested6 := xnetip.MustParseContiguous6("2001:db8:1::/48")
	requireNoAllocs(t, func() { okSink = container6.Contains(nested6) })
	container := xnetip.MustParseContiguous("10.0.0.0/8")
	nested := xnetip.MustParseContiguous("10.1.0.0/16")
	requireNoAllocs(t, func() { okSink = container.Contains(nested) })
}

// verifies that both total prefix accessors allocate nothing in all
// three instantiations.
func Test_Contiguous_PrefixLen_AllocationFree(t *testing.T) {
	block4 := xnetip.MustParseContiguous4("10.0.0.0/8")
	block6 := xnetip.MustParseContiguous6("2001:db8::/32")
	block := xnetip.MustParseContiguous("10.0.0.0/8")
	requireNoAllocs(t, func() { intSink = block4.PrefixLen() })
	requireNoAllocs(t, func() { prefixSink = block4.Prefix() })
	requireNoAllocs(t, func() { intSink = block6.PrefixLen() })
	requireNoAllocs(t, func() { prefixSink = block6.Prefix() })
	requireNoAllocs(t, func() { intSink = block.PrefixLen() })
	requireNoAllocs(t, func() { prefixSink = block.Prefix() })
}

// verifies that every contiguous IPv4 form parses to the exactly
// wrapped network: prefix, dotted mask and bare address notation.
func Test_ParseContiguous4_AcceptsContiguousForms(t *testing.T) {
	cases := []struct {
		name  string
		input string
		want  string
	}{
		{name: "prefix form", input: "192.168.0.0/16", want: "192.168.0.0/16"},
		{name: "another prefix form", input: "192.168.1.0/24", want: "192.168.1.0/24"},
		{name: "contiguous dotted mask equals the prefix form", input: "192.168.0.0/255.255.0.0", want: "192.168.0.0/16"},
		{name: "bare address is a host route", input: "10.0.0.1", want: "10.0.0.1/32"},
		{name: "/0 is the universe", input: "0.0.0.0/0", want: "0.0.0.0/0"},
		{name: "/32 keeps the address", input: "1.2.3.4/32", want: "1.2.3.4/32"},
		{name: "host bits normalize under the mask", input: "10.1.2.3/8", want: "10.0.0.0/8"},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			block, err := xnetip.ParseContiguous4(testCase.input)
			require.NoError(t, err)
			require.Equal(t, mustContiguous4(t, testCase.want), block)
		})
	}
}

// verifies that a valid IPv4 network with a one bit after a zero
// mask bit is rejected, yielding the sentinel and the zero wrapper.
func Test_ParseContiguous4_RejectsNonContiguousMask(t *testing.T) {
	cases := []struct {
		name  string
		input string
	}{
		{name: "two-run mask", input: "10.0.0.0/255.0.255.0"},
		{name: "two-run mask around the last octet", input: "192.168.0.1/255.255.0.255"},
		{name: "alternating mask", input: "170.85.170.85/170.85.170.85"},
		{name: "hole at the half boundary", input: "10.1.2.3/255.254.255.255"},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			block, err := xnetip.ParseContiguous4(testCase.input)
			require.ErrorIs(t, err, xnetip.ErrNonContiguousMask)
			require.Equal(t, xnetip.Contiguous[xnetip.Network4]{}, block)
		})
	}
}

// verifies that every contiguous IPv6 form parses to the exactly
// wrapped network: prefix, colon mask and bare address notation.
func Test_ParseContiguous6_AcceptsContiguousForms(t *testing.T) {
	cases := []struct {
		name  string
		input string
		want  string
	}{
		{name: "prefix form", input: "2001:db8::/32", want: "2001:db8::/32"},
		{name: "geo prefix form", input: "2a02:6b8:c00::/40", want: "2a02:6b8:c00::/40"},
		{name: "contiguous colon mask equals the prefix form", input: "2001:db8::/ffff:ffff::", want: "2001:db8::/32"},
		{name: "bare address is a host route", input: "2001:db8::1", want: "2001:db8::1/128"},
		{name: "/0 is the universe", input: "::/0", want: "::/0"},
		{name: "/128 keeps the address", input: "2001:db8::1/128", want: "2001:db8::1/128"},
		{name: "host bits normalize under the mask", input: "2001:db8::1/32", want: "2001:db8::/32"},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			block, err := xnetip.ParseContiguous6(testCase.input)
			require.NoError(t, err)
			require.Equal(t, mustContiguous6(t, testCase.want), block)
		})
	}
}

// verifies that a valid IPv6 network with a one bit after a zero
// mask bit is rejected, yielding the sentinel and the zero wrapper.
func Test_ParseContiguous6_RejectsNonContiguousMask(t *testing.T) {
	cases := []struct {
		name  string
		input string
	}{
		{name: "two-run mask", input: "2001::/ffff:0:ffff::"},
		{name: "geo-style two-run mask", input: "2a02:6b8:c00::1234:0:0/ffff:ffff:ff00::ffff:ffff:0:0"},
		{name: "alternating mask", input: "2001:db8::/aaaa:aaaa:aaaa:aaaa:aaaa:aaaa:aaaa:aaaa"},
		{name: "hole at bit 64", input: "2001:db8::/ffff:ffff:ffff:fffe:ffff::"},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			block, err := xnetip.ParseContiguous6(testCase.input)
			require.ErrorIs(t, err, xnetip.ErrNonContiguousMask)
			require.Equal(t, xnetip.Contiguous[xnetip.Network6]{}, block)
		})
	}
}

// verifies that the family-agnostic parser follows the address part:
// dotted text is IPv4 and IPv4-mapped text stays IPv6.
func Test_ParseContiguous_SelectsFamilyByAddress(t *testing.T) {
	ipv4, err := xnetip.ParseContiguous("10.0.0.0/8")
	require.NoError(t, err)
	require.True(t, ipv4.Network().Is4())
	require.Equal(t, mustContiguous(t, "10.0.0.0/8"), ipv4)
	mapped, err := xnetip.ParseContiguous("::ffff:10.0.0.0/104")
	require.NoError(t, err)
	require.True(t, mapped.Network().Is6())
	require.Equal(t, mustContiguous(t, "::ffff:10.0.0.0/104"), mapped)
}

// verifies that the family-agnostic parser rejects a non-contiguous
// mask of either family, yielding the sentinel and the zero wrapper.
func Test_ParseContiguous_RejectsNonContiguousMask(t *testing.T) {
	cases := []struct {
		name  string
		input string
	}{
		{name: "IPv4 two-run mask", input: "192.168.0.1/255.255.0.255"},
		{name: "IPv4 alternating mask", input: "170.85.170.85/170.85.170.85"},
		{name: "IPv6 two-run mask", input: "2001::/ffff:0:ffff::"},
		{name: "IPv6 hole at bit 64", input: "2001:db8::/ffff:ffff:ffff:fffe:ffff::"},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			block, err := xnetip.ParseContiguous(testCase.input)
			require.ErrorIs(t, err, xnetip.ErrNonContiguousMask)
			require.Equal(t, xnetip.Contiguous[xnetip.Network]{}, block)
		})
	}
}

// verifies that text that is no network at all keeps the parse
// sentinel of the network grammar in every family.
func Test_ParseContiguous_GarbageKeepsParseSentinel(t *testing.T) {
	_, err := xnetip.ParseContiguous4("not-a-net")
	require.ErrorIs(t, err, xnetip.ErrParse)
	_, err = xnetip.ParseContiguous6("not-a-net")
	require.ErrorIs(t, err, xnetip.ErrParse)
	_, err = xnetip.ParseContiguous("not-a-net")
	require.ErrorIs(t, err, xnetip.ErrParse)
}

// verifies that a zone suffix is rejected with the zone sentinel by
// the IPv6 and the family-agnostic parser alike.
func Test_ParseContiguous_RejectsZone(t *testing.T) {
	_, err := xnetip.ParseContiguous6("fe80::1%eth0/64")
	require.ErrorIs(t, err, xnetip.ErrZone)
	_, err = xnetip.ParseContiguous("fe80::1%eth0/64")
	require.ErrorIs(t, err, xnetip.ErrZone)
}

// verifies that every rejection names the contiguous parser and
// echoes the input, never leaking the network parser it delegates to.
func Test_ParseContiguous_ErrorNamesThisParser(t *testing.T) {
	inputs4 := []string{"not-a-net", "10.0.0.0/255.0.255.0", "10.0.0.0/33"}
	for _, input := range inputs4 {
		_, err := xnetip.ParseContiguous4(input)
		require.Error(t, err)
		require.True(t, strings.HasPrefix(err.Error(), "xnetip.ParseContiguous4("), err.Error())
		require.Contains(t, err.Error(), strconv.Quote(input))
	}
	inputs6 := []string{"not-a-net", "2001::/ffff:0:ffff::", "2001:db8::/129"}
	for _, input := range inputs6 {
		_, err := xnetip.ParseContiguous6(input)
		require.Error(t, err)
		require.True(t, strings.HasPrefix(err.Error(), "xnetip.ParseContiguous6("), err.Error())
		require.Contains(t, err.Error(), strconv.Quote(input))
	}
	inputsDual := []string{"not-a-net", "10.0.0.0/255.0.255.0", "2001::/ffff:0:ffff::"}
	for _, input := range inputsDual {
		_, err := xnetip.ParseContiguous(input)
		require.Error(t, err)
		require.True(t, strings.HasPrefix(err.Error(), "xnetip.ParseContiguous("), err.Error())
		require.Contains(t, err.Error(), strconv.Quote(input))
	}
}

// verifies that each must variant panics on invalid input and passes
// a valid block through.
func Test_MustParseContiguous_PanicsOnInvalidInput(t *testing.T) {
	require.Panics(t, func() { xnetip.MustParseContiguous4("10.0.0.0/255.0.255.0") })
	require.Panics(t, func() { xnetip.MustParseContiguous6("2001::/ffff:0:ffff::") })
	require.Panics(t, func() { xnetip.MustParseContiguous("not-a-net") })
	require.Equal(t, mustContiguous4(t, "10.0.0.0/8"), xnetip.MustParseContiguous4("10.0.0.0/8"))
	require.Equal(t, mustContiguous6(t, "2001:db8::/32"), xnetip.MustParseContiguous6("2001:db8::/32"))
	require.Equal(t, mustContiguous(t, "10.0.0.0/8"), xnetip.MustParseContiguous("10.0.0.0/8"))
}

// verifies that parsing an IPv4 network's text succeeds exactly when
// its mask is contiguous, wrapping that network and nothing else.
func Test_ParseContiguous4_AcceptOracleProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		network := genNetwork4.Draw(t, "network")
		block, err := xnetip.ParseContiguous4(network.String())
		if network.IsContiguous() {
			require.NoError(t, err)
			require.Equal(t, network, block.Network())
		} else {
			require.ErrorIs(t, err, xnetip.ErrNonContiguousMask)
			require.Equal(t, xnetip.Contiguous[xnetip.Network4]{}, block)
		}
	})
}

// verifies that parsing an IPv6 network's text succeeds exactly when
// its mask is contiguous, wrapping that network and nothing else.
func Test_ParseContiguous6_AcceptOracleProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		network := genNetwork6.Draw(t, "network")
		block, err := xnetip.ParseContiguous6(network.String())
		if network.IsContiguous() {
			require.NoError(t, err)
			require.Equal(t, network, block.Network())
		} else {
			require.ErrorIs(t, err, xnetip.ErrNonContiguousMask)
			require.Equal(t, xnetip.Contiguous[xnetip.Network6]{}, block)
		}
	})
}

// verifies that parsing a family-agnostic network's text succeeds
// exactly when its mask is contiguous, keeping family and network.
func Test_ParseContiguous_AcceptOracleProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		network := genNetwork.Draw(t, "network")
		block, err := xnetip.ParseContiguous(network.String())
		if network.IsContiguous() {
			require.NoError(t, err)
			require.Equal(t, network, block.Network())
		} else {
			require.ErrorIs(t, err, xnetip.ErrNonContiguousMask)
			require.Equal(t, xnetip.Contiguous[xnetip.Network]{}, block)
		}
	})
}

// verifies that a block's text parses back to the same block in all
// three instantiations.
func Test_ParseContiguous_RoundTripProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		block4 := genContiguous4.Draw(t, "block4")
		parsed4, err := xnetip.ParseContiguous4(block4.Network().String())
		require.NoError(t, err)
		require.Equal(t, block4, parsed4)
		block6 := genContiguous6.Draw(t, "block6")
		parsed6, err := xnetip.ParseContiguous6(block6.Network().String())
		require.NoError(t, err)
		require.Equal(t, block6, parsed6)
		block := genContiguous.Draw(t, "block")
		parsed, err := xnetip.ParseContiguous(block.Network().String())
		require.NoError(t, err)
		require.Equal(t, block, parsed)
	})
}

// verifies that on text the network parser rejects, the same-family
// contiguous parser rejects with exactly the same sentinel set.
func Test_ParseContiguous_ErrorSetMatchesNetworkParserProperty(t *testing.T) {
	corpus := []string{
		"", "/", "/24", "hello", "zz/24", " 10.0.0.1/24", "01.2.3.4/8",
		"10.0.0.0/33", "10.0.0.0/08", "10.0.0.0/+8", "10.0.0.1//24",
		"10.0.0.1/2001:db8::1", "2001:db8::1/129", "2001:db8::/xx",
		"fe80::1%eth0/64", "2001:db8::%eth0/32", "1.2.3/8", "10.0.0.0/256",
		"2001:db8::1", "10.0.0.1", "::ffff:10.0.0.1/120",
	}
	sentinels := []error{
		xnetip.ErrParse, xnetip.ErrAddrFamilyMismatch, xnetip.ErrZone,
		xnetip.ErrCIDROverflow, xnetip.ErrInvalidMask,
	}
	rapid.Check(t, func(t *rapid.T) {
		input := rapid.SampledFrom(corpus).Draw(t, "input")
		_, networkErr4 := xnetip.ParseNetwork4(input)
		_, blockErr4 := xnetip.ParseContiguous4(input)
		if networkErr4 != nil {
			require.Error(t, blockErr4)
			for _, sentinel := range sentinels {
				require.Equal(t, errors.Is(networkErr4, sentinel), errors.Is(blockErr4, sentinel))
			}
		}
		_, networkErr6 := xnetip.ParseNetwork6(input)
		_, blockErr6 := xnetip.ParseContiguous6(input)
		if networkErr6 != nil {
			require.Error(t, blockErr6)
			for _, sentinel := range sentinels {
				require.Equal(t, errors.Is(networkErr6, sentinel), errors.Is(blockErr6, sentinel))
			}
		}
		_, networkErr := xnetip.ParseNetwork(input)
		_, blockErr := xnetip.ParseContiguous(input)
		if networkErr != nil {
			require.Error(t, blockErr)
			for _, sentinel := range sentinels {
				require.Equal(t, errors.Is(networkErr, sentinel), errors.Is(blockErr, sentinel))
			}
		}
	})
}

// verifies that IPv4 prefix-form text agrees with the std masked
// prefix on acceptance and on the parsed address and length.
func Test_ParseContiguous4_MatchesNetipParsePrefixProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		addr := genNetipAddr4.Draw(t, "addr")
		bits := rapid.IntRange(0, 32).Draw(t, "bits")
		input := addr.String() + "/" + strconv.Itoa(bits)
		block, err := xnetip.ParseContiguous4(input)
		require.NoError(t, err)
		stdPrefix, err := netip.ParsePrefix(input)
		require.NoError(t, err)
		masked := stdPrefix.Masked()
		require.Equal(t, masked.Addr(), block.Network().Addr())
		prefixLen, ok := block.Network().PrefixLen()
		require.True(t, ok)
		require.Equal(t, masked.Bits(), prefixLen)
	})
}

// verifies that IPv6 prefix-form text agrees with the std masked
// prefix on acceptance and on the parsed address and length.
func Test_ParseContiguous6_MatchesNetipParsePrefixProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		addr := genNetipAddr6.Draw(t, "addr")
		bits := rapid.IntRange(0, 128).Draw(t, "bits")
		input := addr.String() + "/" + strconv.Itoa(bits)
		block, err := xnetip.ParseContiguous6(input)
		require.NoError(t, err)
		stdPrefix, err := netip.ParsePrefix(input)
		require.NoError(t, err)
		masked := stdPrefix.Masked()
		require.Equal(t, masked.Addr(), block.Network().Addr())
		prefixLen, ok := block.Network().PrefixLen()
		require.True(t, ok)
		require.Equal(t, masked.Bits(), prefixLen)
	})
}

func FuzzParseContiguous4(f *testing.F) {
	seeds := []string{
		"192.168.0.0/16", "192.168.1.0/24", "192.168.0.0/255.255.0.0", "10.0.0.1",
		"0.0.0.0/0", "1.2.3.4/32", "10.1.2.3/8", "10.0.0.0/255.0.255.0",
		"192.168.0.1/255.255.0.255", "170.85.170.85/170.85.170.85",
		"10.1.2.3/255.254.255.255", "not-a-net", "10.0.0.0/33", "10.0.0.0/08",
		"", "fe80::1%eth0/64", "2001:db8::/32", "::ffff:10.0.0.0/104",
	}
	for _, seed := range seeds {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, input string) {
		block, err := xnetip.ParseContiguous4(input)
		network, networkErr := xnetip.ParseNetwork4(input)
		switch {
		case networkErr != nil:
			if err == nil {
				t.Fatalf("accepted %q, which the network parser rejects: %v", input, networkErr)
			}
		case network.IsContiguous():
			if err != nil {
				t.Fatalf("rejected contiguous %q: %v", input, err)
			}
			if block.Network() != network {
				t.Fatalf("parsed %q as %v, the network parser says %v", input, block.Network(), network)
			}
		default:
			if !errors.Is(err, xnetip.ErrNonContiguousMask) {
				t.Fatalf("non-contiguous %q must wrap the sentinel, got %v", input, err)
			}
		}
	})
}

func FuzzParseContiguous6(f *testing.F) {
	seeds := []string{
		"2001:db8::/32", "2a02:6b8:c00::/40", "2001:db8::/ffff:ffff::",
		"2001:db8::1", "::/0", "2001:db8::1/128", "2001::/ffff:0:ffff::",
		"2a02:6b8:c00::1234:0:0/ffff:ffff:ff00::ffff:ffff:0:0",
		"2001:db8::/aaaa:aaaa:aaaa:aaaa:aaaa:aaaa:aaaa:aaaa",
		"2001:db8::/ffff:ffff:ffff:fffe:ffff::", "not-a-net", "2001:db8::/129",
		"", "fe80::1%eth0/64", "10.0.0.0/8", "::ffff:10.0.0.0/104",
	}
	for _, seed := range seeds {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, input string) {
		block, err := xnetip.ParseContiguous6(input)
		network, networkErr := xnetip.ParseNetwork6(input)
		switch {
		case networkErr != nil:
			if err == nil {
				t.Fatalf("accepted %q, which the network parser rejects: %v", input, networkErr)
			}
		case network.IsContiguous():
			if err != nil {
				t.Fatalf("rejected contiguous %q: %v", input, err)
			}
			if block.Network() != network {
				t.Fatalf("parsed %q as %v, the network parser says %v", input, block.Network(), network)
			}
		default:
			if !errors.Is(err, xnetip.ErrNonContiguousMask) {
				t.Fatalf("non-contiguous %q must wrap the sentinel, got %v", input, err)
			}
		}
	})
}

func BenchmarkParseContiguous4_Prefix(b *testing.B) {
	b.ReportAllocs()
	for b.Loop() {
		contiguous4Sink, errSink = xnetip.ParseContiguous4("192.168.0.0/16")
	}
}

func BenchmarkParseContiguous4_Mask(b *testing.B) {
	b.ReportAllocs()
	for b.Loop() {
		contiguous4Sink, errSink = xnetip.ParseContiguous4("192.168.0.0/255.255.0.0")
	}
}

func BenchmarkParseContiguous4_Reject(b *testing.B) {
	b.ReportAllocs()
	for b.Loop() {
		contiguous4Sink, errSink = xnetip.ParseContiguous4("10.0.0.0/255.0.255.0")
	}
}

func BenchmarkParseContiguous6_Prefix(b *testing.B) {
	b.ReportAllocs()
	for b.Loop() {
		contiguous6Sink, errSink = xnetip.ParseContiguous6("2001:db8::/32")
	}
}

func BenchmarkParseContiguous6_Mask(b *testing.B) {
	b.ReportAllocs()
	for b.Loop() {
		contiguous6Sink, errSink = xnetip.ParseContiguous6("2001:db8::/ffff:ffff::")
	}
}

func BenchmarkParseContiguous6_Reject(b *testing.B) {
	b.ReportAllocs()
	for b.Loop() {
		contiguous6Sink, errSink = xnetip.ParseContiguous6("2001::/ffff:0:ffff::")
	}
}

func BenchmarkContiguous_Contains_IPv4True(b *testing.B) {
	container := xnetip.MustParseContiguous4("10.0.0.0/8")
	nested := xnetip.MustParseContiguous4("10.1.0.0/16")
	b.ReportAllocs()
	for b.Loop() {
		okSink = container.Contains(nested)
	}
}

func BenchmarkContiguous_Contains_IPv4False(b *testing.B) {
	container := xnetip.MustParseContiguous4("10.0.0.0/8")
	foreign := xnetip.MustParseContiguous4("192.168.0.0/16")
	b.ReportAllocs()
	for b.Loop() {
		okSink = container.Contains(foreign)
	}
}

func BenchmarkContiguous_Contains_IPv6True(b *testing.B) {
	container := xnetip.MustParseContiguous6("2001:db8::/32")
	nested := xnetip.MustParseContiguous6("2001:db8:1::/48")
	b.ReportAllocs()
	for b.Loop() {
		okSink = container.Contains(nested)
	}
}

func BenchmarkContiguous_Contains_IPv6False(b *testing.B) {
	container := xnetip.MustParseContiguous6("2001:db8::/32")
	foreign := xnetip.MustParseContiguous6("fe80::/10")
	b.ReportAllocs()
	for b.Loop() {
		okSink = container.Contains(foreign)
	}
}

func BenchmarkContiguous_Contains_IPv4General(b *testing.B) {
	container := xnetip.MustParseContiguous4("10.0.0.0/8")
	nested := xnetip.MustParseContiguous4("10.1.0.0/16")
	b.ReportAllocs()
	for b.Loop() {
		okSink = container.Network().Contains(nested.Network())
	}
}

func BenchmarkContiguous_Contains_IPv6General(b *testing.B) {
	container := xnetip.MustParseContiguous6("2001:db8::/32")
	nested := xnetip.MustParseContiguous6("2001:db8:1::/48")
	b.ReportAllocs()
	for b.Loop() {
		okSink = container.Network().Contains(nested.Network())
	}
}

// verifies that a block prints as address and prefix length even
// when it was built from explicit-mask text.
func Test_Contiguous_String_AlwaysPrefixForm(t *testing.T) {
	require.Equal(t, "10.0.0.0/8", xnetip.MustParseContiguous4("10.0.0.0/255.0.0.0").String())
	require.Equal(t, "2001:db8::/32", xnetip.MustParseContiguous6("2001:db8::/ffff:ffff::").String())
	require.Equal(t, "2001:db8::/32", xnetip.MustParseContiguous6("2001:db8::/32").String())
	require.Equal(t, "10.0.0.0/8", xnetip.MustParseContiguous("10.0.0.0/255.0.0.0").String())
}

// verifies that a family-agnostic block prints in its own family,
// the IPv4-mapped IPv6 form staying IPv6.
func Test_Contiguous_String_DualPrintsFamily(t *testing.T) {
	require.Equal(t, "10.0.0.0/8", xnetip.MustParseContiguous("10.0.0.0/8").String())
	require.Equal(t, "::ffff:10.0.0.0/104", xnetip.MustParseContiguous("::ffff:10.0.0.0/104").String())
}

// verifies that the zero wrapper of every instantiation prints its
// universe block.
func Test_Contiguous_String_ZeroValues(t *testing.T) {
	require.Equal(t, "0.0.0.0/0", xnetip.Contiguous[xnetip.Network4]{}.String())
	require.Equal(t, "::/0", xnetip.Contiguous[xnetip.Network6]{}.String())
	require.Equal(t, "::/0", xnetip.Contiguous[xnetip.Network]{}.String())
}

// verifies that a host route keeps its full-length suffix.
func Test_Contiguous_String_HostRoutesKeepSuffix(t *testing.T) {
	require.Equal(t, "10.0.0.1/32", xnetip.MustParseContiguous4("10.0.0.1").String())
	require.Equal(t, "2001:db8::1/128", xnetip.MustParseContiguous6("2001:db8::1").String())
}

// verifies that the marshalled text equals the String form on all
// three instantiations.
func Test_Contiguous_MarshalText_EqualsString(t *testing.T) {
	block4 := xnetip.MustParseContiguous4("192.168.0.0/16")
	text4, err := block4.MarshalText()
	require.NoError(t, err)
	require.Equal(t, block4.String(), string(text4))
	block6 := xnetip.MustParseContiguous6("2001:db8::/32")
	text6, err := block6.MarshalText()
	require.NoError(t, err)
	require.Equal(t, block6.String(), string(text6))
	block := xnetip.MustParseContiguous("::ffff:10.0.0.0/104")
	text, err := block.MarshalText()
	require.NoError(t, err)
	require.Equal(t, block.String(), string(text))
}

// verifies that unmarshalling the marshalled text recovers the block
// on all three instantiations.
func Test_Contiguous_UnmarshalText_RoundTrip(t *testing.T) {
	block4 := xnetip.MustParseContiguous4("192.168.0.0/16")
	text4, err := block4.MarshalText()
	require.NoError(t, err)
	var decoded4 xnetip.Contiguous[xnetip.Network4]
	require.NoError(t, decoded4.UnmarshalText(text4))
	require.Equal(t, block4, decoded4)
	block6 := xnetip.MustParseContiguous6("2001:db8::/32")
	text6, err := block6.MarshalText()
	require.NoError(t, err)
	var decoded6 xnetip.Contiguous[xnetip.Network6]
	require.NoError(t, decoded6.UnmarshalText(text6))
	require.Equal(t, block6, decoded6)
	block := xnetip.MustParseContiguous("::ffff:10.0.0.0/104")
	text, err := block.MarshalText()
	require.NoError(t, err)
	var decoded xnetip.Contiguous[xnetip.Network]
	require.NoError(t, decoded.UnmarshalText(text))
	require.Equal(t, block, decoded)
}

// verifies that empty text is rejected with the empty-input sentinel
// and the receiver keeps its value.
func Test_Contiguous_UnmarshalText_EmptyKeepsReceiver(t *testing.T) {
	block4 := xnetip.MustParseContiguous4("10.0.0.0/8")
	require.ErrorIs(t, block4.UnmarshalText(nil), xnetip.ErrEmptyInput)
	require.Equal(t, xnetip.MustParseContiguous4("10.0.0.0/8"), block4)
	block6 := xnetip.MustParseContiguous6("2001:db8::/32")
	require.ErrorIs(t, block6.UnmarshalText([]byte{}), xnetip.ErrEmptyInput)
	require.Equal(t, xnetip.MustParseContiguous6("2001:db8::/32"), block6)
	block := xnetip.MustParseContiguous("10.0.0.0/8")
	require.ErrorIs(t, block.UnmarshalText(nil), xnetip.ErrEmptyInput)
	require.Equal(t, xnetip.MustParseContiguous("10.0.0.0/8"), block)
}

// verifies that a valid network with a non-contiguous mask is
// rejected with the dedicated sentinel, the receiver untouched.
func Test_Contiguous_UnmarshalText_NonContiguousKeepsReceiver(t *testing.T) {
	block4 := xnetip.MustParseContiguous4("10.0.0.0/8")
	require.ErrorIs(t, block4.UnmarshalText([]byte("10.0.0.0/255.0.255.0")), xnetip.ErrNonContiguousMask)
	require.Equal(t, xnetip.MustParseContiguous4("10.0.0.0/8"), block4)
	block6 := xnetip.MustParseContiguous6("2001:db8::/32")
	require.ErrorIs(t, block6.UnmarshalText([]byte("2001::/ffff:0:ffff::")), xnetip.ErrNonContiguousMask)
	require.Equal(t, xnetip.MustParseContiguous6("2001:db8::/32"), block6)
	block := xnetip.MustParseContiguous("10.0.0.0/8")
	require.ErrorIs(t, block.UnmarshalText([]byte("2001::/ffff:0:ffff::")), xnetip.ErrNonContiguousMask)
	require.Equal(t, xnetip.MustParseContiguous("10.0.0.0/8"), block)
}

// verifies that the suffix after "/" is always a decimal prefix
// length within the family's bit width, never a second address.
func Test_Contiguous_String_NoExplicitMaskProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		requireSuffixIsPrefixLen := func(text string, limit int) {
			_, suffix, found := strings.Cut(text, "/")
			require.True(t, found, text)
			bits, err := strconv.Atoi(suffix)
			require.NoError(t, err, text)
			require.GreaterOrEqual(t, bits, 0, text)
			require.LessOrEqual(t, bits, limit, text)
		}
		requireSuffixIsPrefixLen(genContiguous4.Draw(t, "block4").String(), 32)
		requireSuffixIsPrefixLen(genContiguous6.Draw(t, "block6").String(), 128)
		block := genContiguous.Draw(t, "block")
		limit := 128
		if block.Network().Is4() {
			limit = 32
		}
		requireSuffixIsPrefixLen(block.String(), limit)
	})
}

// verifies that the wrapper's text is exactly the wrapped network's
// on all three instantiations.
func Test_Contiguous_String_EqualsInnerProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		block4 := genContiguous4.Draw(t, "block4")
		require.Equal(t, block4.Network().String(), block4.String())
		block6 := genContiguous6.Draw(t, "block6")
		require.Equal(t, block6.Network().String(), block6.String())
		block := genContiguous.Draw(t, "block")
		require.Equal(t, block.Network().String(), block.String())
	})
}

// verifies that parsing and unmarshalling the printed block recovers
// it exactly on all three instantiations.
func Test_Contiguous_String_RoundTripProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		block4 := genContiguous4.Draw(t, "block4")
		parsed4, err := xnetip.ParseContiguous4(block4.String())
		require.NoError(t, err)
		require.Equal(t, block4, parsed4)
		var decoded4 xnetip.Contiguous[xnetip.Network4]
		require.NoError(t, decoded4.UnmarshalText([]byte(block4.String())))
		require.Equal(t, block4, decoded4)
		block6 := genContiguous6.Draw(t, "block6")
		parsed6, err := xnetip.ParseContiguous6(block6.String())
		require.NoError(t, err)
		require.Equal(t, block6, parsed6)
		var decoded6 xnetip.Contiguous[xnetip.Network6]
		require.NoError(t, decoded6.UnmarshalText([]byte(block6.String())))
		require.Equal(t, block6, decoded6)
		block := genContiguous.Draw(t, "block")
		parsed, err := xnetip.ParseContiguous(block.String())
		require.NoError(t, err)
		require.Equal(t, block, parsed)
		var decoded xnetip.Contiguous[xnetip.Network]
		require.NoError(t, decoded.UnmarshalText([]byte(block.String())))
		require.Equal(t, block, decoded)
	})
}

// verifies that a slice of blocks survives a JSON round trip in all
// three instantiations.
func Test_Contiguous_MarshalText_JSONRoundTripProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		value4 := rapid.SliceOfN(genContiguous4, 0, 8).Draw(t, "blocks4")
		encoded4, err := json.Marshal(value4)
		require.NoError(t, err)
		var decoded4 []xnetip.Contiguous[xnetip.Network4]
		require.NoError(t, json.Unmarshal(encoded4, &decoded4))
		if len(value4) == 0 {
			require.Empty(t, decoded4)
		} else {
			require.Equal(t, value4, decoded4)
		}
		value6 := rapid.SliceOfN(genContiguous6, 0, 8).Draw(t, "blocks6")
		encoded6, err := json.Marshal(value6)
		require.NoError(t, err)
		var decoded6 []xnetip.Contiguous[xnetip.Network6]
		require.NoError(t, json.Unmarshal(encoded6, &decoded6))
		if len(value6) == 0 {
			require.Empty(t, decoded6)
		} else {
			require.Equal(t, value6, decoded6)
		}
		value := rapid.SliceOfN(genContiguous, 0, 8).Draw(t, "blocks")
		encoded, err := json.Marshal(value)
		require.NoError(t, err)
		var decoded []xnetip.Contiguous[xnetip.Network]
		require.NoError(t, json.Unmarshal(encoded, &decoded))
		if len(value) == 0 {
			require.Empty(t, decoded)
		} else {
			require.Equal(t, value, decoded)
		}
	})
}

// verifies that the printed block equals the std masked prefix text
// of the same address and length, for both concrete families.
func Test_Contiguous_String_MatchesNetipPrefixProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		block4 := genContiguous4.Draw(t, "block4")
		bits4, ok := block4.Network().PrefixLen()
		require.True(t, ok)
		require.Equal(t, netip.PrefixFrom(block4.Network().Addr(), bits4).Masked().String(), block4.String())
		block6 := genContiguous6.Draw(t, "block6")
		bits6, ok := block6.Network().PrefixLen()
		require.True(t, ok)
		require.Equal(t, netip.PrefixFrom(block6.Network().Addr(), bits6).Masked().String(), block6.String())
	})
}

// verifies that appending into a preallocated buffer allocates
// nothing in all three instantiations.
func Test_Contiguous_AppendTo_AllocationFree(t *testing.T) {
	block4 := xnetip.MustParseContiguous4("192.168.0.0/16")
	block6 := xnetip.MustParseContiguous6("2001:db8::/32")
	block := xnetip.MustParseContiguous("::ffff:10.0.0.0/104")
	buffer := make([]byte, 0, 64)
	requireNoAllocs(t, func() { bytesSink = block4.AppendTo(buffer[:0]) })
	requireNoAllocs(t, func() { bytesSink = block6.AppendTo(buffer[:0]) })
	requireNoAllocs(t, func() { bytesSink = block.AppendTo(buffer[:0]) })
}

// verifies that host bits below the prefix length are cleared,
// wrapping the same block the equivalent prefix text parses to.
func Test_ContiguousFromCIDR4_ClearsHostBits(t *testing.T) {
	block, err := xnetip.ContiguousFromCIDR4(netip.MustParseAddr("192.168.1.5"), 24)
	require.NoError(t, err)
	require.Equal(t, mustContiguous4(t, "192.168.1.0/24"), block)
}

// verifies that both IPv4 length boundaries construct: zero masks
// every address bit away and thirty-two keeps the full host route.
func Test_ContiguousFromCIDR4_Boundaries(t *testing.T) {
	universe, err := xnetip.ContiguousFromCIDR4(netip.MustParseAddr("192.168.1.5"), 0)
	require.NoError(t, err)
	require.Equal(t, mustContiguous4(t, "0.0.0.0/0"), universe)
	host, err := xnetip.ContiguousFromCIDR4(netip.MustParseAddr("192.168.1.5"), 32)
	require.NoError(t, err)
	require.Equal(t, mustContiguous4(t, "192.168.1.5/32"), host)
}

// verifies that a length outside the IPv4 range is refused with the
// overflow sentinel under this constructor's name.
func Test_ContiguousFromCIDR4_Overflow(t *testing.T) {
	for _, bits := range []int{33, -1} {
		_, err := xnetip.ContiguousFromCIDR4(netip.MustParseAddr("192.168.1.5"), bits)
		require.ErrorIs(t, err, xnetip.ErrCIDROverflow, "bits %d", bits)
		require.True(t, strings.HasPrefix(err.Error(), "xnetip.ContiguousFromCIDR4("), err.Error())
	}
}

// verifies that the IPv4 form rejects every non-Is4 address: plain
// IPv6, IPv4-mapped IPv6 and the invalid zero address.
func Test_ContiguousFromCIDR4_FamilyMismatch(t *testing.T) {
	for _, addr := range []netip.Addr{
		netip.MustParseAddr("2001:db8::1"),
		netip.MustParseAddr("::ffff:192.168.1.5"),
		{},
	} {
		_, err := xnetip.ContiguousFromCIDR4(addr, 24)
		require.ErrorIs(t, err, xnetip.ErrAddrFamilyMismatch, addr.String())
	}
}

// verifies that host bits below the prefix length are cleared,
// wrapping the same block the equivalent prefix text parses to.
func Test_ContiguousFromCIDR6_ClearsHostBits(t *testing.T) {
	block, err := xnetip.ContiguousFromCIDR6(netip.MustParseAddr("2001:db8::1"), 64)
	require.NoError(t, err)
	require.Equal(t, mustContiguous6(t, "2001:db8::/64"), block)
}

// verifies that both IPv6 length boundaries construct: zero masks
// every address bit away and the full width keeps the host route.
func Test_ContiguousFromCIDR6_Boundaries(t *testing.T) {
	universe, err := xnetip.ContiguousFromCIDR6(netip.MustParseAddr("2001:db8::1"), 0)
	require.NoError(t, err)
	require.Equal(t, mustContiguous6(t, "::/0"), universe)
	host, err := xnetip.ContiguousFromCIDR6(netip.MustParseAddr("2001:db8::1"), 128)
	require.NoError(t, err)
	require.Equal(t, mustContiguous6(t, "2001:db8::1/128"), host)
}

// verifies that a length outside the IPv6 range is refused with the
// overflow sentinel under this constructor's name.
func Test_ContiguousFromCIDR6_Overflow(t *testing.T) {
	for _, bits := range []int{129, -1} {
		_, err := xnetip.ContiguousFromCIDR6(netip.MustParseAddr("2001:db8::1"), bits)
		require.ErrorIs(t, err, xnetip.ErrCIDROverflow, "bits %d", bits)
		require.True(t, strings.HasPrefix(err.Error(), "xnetip.ContiguousFromCIDR6("), err.Error())
	}
}

// verifies that the IPv6 form rejects an Is4 address and the invalid
// zero address while accepting an IPv4-mapped IPv6 one.
func Test_ContiguousFromCIDR6_FamilyMismatch(t *testing.T) {
	for _, addr := range []netip.Addr{netip.MustParseAddr("192.168.1.5"), {}} {
		_, err := xnetip.ContiguousFromCIDR6(addr, 64)
		require.ErrorIs(t, err, xnetip.ErrAddrFamilyMismatch, addr.String())
	}
	mapped, err := xnetip.ContiguousFromCIDR6(netip.MustParseAddr("::ffff:192.168.1.5"), 104)
	require.NoError(t, err)
	require.Equal(t, mustContiguous6(t, "::ffff:192.0.0.0/104"), mapped)
}

// verifies that the family follows the address: an Is4 address makes
// an IPv4 block and an IPv4-mapped IPv6 one stays IPv6.
func Test_ContiguousFromCIDR_SelectsFamilyByAddress(t *testing.T) {
	blockV4, err := xnetip.ContiguousFromCIDR(netip.MustParseAddr("192.168.1.5"), 24)
	require.NoError(t, err)
	require.Equal(t, mustContiguous(t, "192.168.1.0/24"), blockV4)
	_, ok := blockV4.Network().IPv4()
	require.True(t, ok)
	blockMapped, err := xnetip.ContiguousFromCIDR(netip.MustParseAddr("::ffff:192.168.1.5"), 104)
	require.NoError(t, err)
	require.Equal(t, mustContiguous(t, "::ffff:192.0.0.0/104"), blockMapped)
	_, ok = blockMapped.Network().IPv6()
	require.True(t, ok)
}

// verifies that both families' length boundaries construct through
// the family-agnostic form.
func Test_ContiguousFromCIDR_Boundaries(t *testing.T) {
	universe4, err := xnetip.ContiguousFromCIDR(netip.MustParseAddr("192.168.1.5"), 0)
	require.NoError(t, err)
	require.Equal(t, mustContiguous(t, "0.0.0.0/0"), universe4)
	host4, err := xnetip.ContiguousFromCIDR(netip.MustParseAddr("192.168.1.5"), 32)
	require.NoError(t, err)
	require.Equal(t, mustContiguous(t, "192.168.1.5/32"), host4)
	universe6, err := xnetip.ContiguousFromCIDR(netip.MustParseAddr("2001:db8::1"), 0)
	require.NoError(t, err)
	require.Equal(t, mustContiguous(t, "::/0"), universe6)
	host6, err := xnetip.ContiguousFromCIDR(netip.MustParseAddr("2001:db8::1"), 128)
	require.NoError(t, err)
	require.Equal(t, mustContiguous(t, "2001:db8::1/128"), host6)
}

// verifies that a length outside the address's own family range and
// the invalid zero address are refused with their sentinels.
func Test_ContiguousFromCIDR_OverflowAndZeroAddr(t *testing.T) {
	_, err := xnetip.ContiguousFromCIDR(netip.MustParseAddr("192.168.1.5"), 33)
	require.ErrorIs(t, err, xnetip.ErrCIDROverflow)
	require.True(t, strings.HasPrefix(err.Error(), "xnetip.ContiguousFromCIDR("), err.Error())
	_, err = xnetip.ContiguousFromCIDR(netip.MustParseAddr("2001:db8::1"), 129)
	require.ErrorIs(t, err, xnetip.ErrCIDROverflow)
	_, err = xnetip.ContiguousFromCIDR(netip.Addr{}, 0)
	require.ErrorIs(t, err, xnetip.ErrAddrFamilyMismatch)
}

// verifies that the typed IPv4 constructor accepts exactly the
// lengths the plain one does, wrapping the identical network.
func Test_ContiguousFromCIDR4_MatchesTypedProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		addr := genNetipAddr4.Draw(t, "addr")
		bits := rapid.IntRange(-1, 33).Draw(t, "bits")
		block, err := xnetip.ContiguousFromCIDR4(addr, bits)
		network, plainErr := xnetip.Network4FromCIDR(addr, bits)
		if plainErr != nil {
			require.ErrorIs(t, err, xnetip.ErrCIDROverflow)
			return
		}
		require.NoError(t, err)
		require.Equal(t, network, block.Network())
		require.Equal(t, bits, block.PrefixLen())
		require.Equal(t, netip.PrefixFrom(addr, bits).Masked(), block.Prefix())
	})
}

// verifies that the typed IPv6 constructor accepts exactly the
// lengths the plain one does, wrapping the identical network.
func Test_ContiguousFromCIDR6_MatchesTypedProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		addr := genNetipAddr6.Draw(t, "addr")
		bits := rapid.IntRange(-1, 129).Draw(t, "bits")
		block, err := xnetip.ContiguousFromCIDR6(addr, bits)
		network, plainErr := xnetip.Network6FromCIDR(addr, bits)
		if plainErr != nil {
			require.ErrorIs(t, err, xnetip.ErrCIDROverflow)
			return
		}
		require.NoError(t, err)
		require.Equal(t, network, block.Network())
		require.Equal(t, bits, block.PrefixLen())
		require.Equal(t, netip.PrefixFrom(addr, bits).Masked(), block.Prefix())
	})
}

// verifies that the typed family-agnostic constructor accepts the
// exact lengths the plain one does, wrapping the identical network.
func Test_ContiguousFromCIDR_MatchesTypedProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		addr := genNetipAddr4.Draw(t, "addr4")
		limit := 32
		if rapid.Bool().Draw(t, "ipv6") {
			addr = genNetipAddr6.Draw(t, "addr6")
			limit = 128
		}
		bits := rapid.IntRange(-1, limit+1).Draw(t, "bits")
		block, err := xnetip.ContiguousFromCIDR(addr, bits)
		network, plainErr := xnetip.NetworkFromCIDR(addr, bits)
		if plainErr != nil {
			require.ErrorIs(t, err, xnetip.ErrCIDROverflow)
			return
		}
		require.NoError(t, err)
		require.Equal(t, network, block.Network())
		require.Equal(t, bits, block.PrefixLen())
	})
}

// verifies that the address-and-length constructors agree with the
// parsers on the equivalent prefix text in every family.
func Test_ContiguousFromCIDR_AgreesWithParserProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		addr4 := genNetipAddr4.Draw(t, "addr4")
		bits4 := rapid.IntRange(0, 32).Draw(t, "bits4")
		block4, err := xnetip.ContiguousFromCIDR4(addr4, bits4)
		require.NoError(t, err)
		parsed4, err := xnetip.ParseContiguous4(addr4.String() + "/" + strconv.Itoa(bits4))
		require.NoError(t, err)
		require.Equal(t, parsed4, block4)
		addr6 := genNetipAddr6.Draw(t, "addr6")
		bits6 := rapid.IntRange(0, 128).Draw(t, "bits6")
		block6, err := xnetip.ContiguousFromCIDR6(addr6, bits6)
		require.NoError(t, err)
		parsed6, err := xnetip.ParseContiguous6(addr6.String() + "/" + strconv.Itoa(bits6))
		require.NoError(t, err)
		require.Equal(t, parsed6, block6)
		block, err := xnetip.ContiguousFromCIDR(addr6, bits6)
		require.NoError(t, err)
		parsed, err := xnetip.ParseContiguous(addr6.String() + "/" + strconv.Itoa(bits6))
		require.NoError(t, err)
		require.Equal(t, parsed, block)
	})
}

// verifies that the accept path of each address-and-length
// constructor is allocation-free.
func Test_ContiguousFromCIDR_AllocationFree(t *testing.T) {
	addr4 := netip.MustParseAddr("192.168.1.5")
	addr6 := netip.MustParseAddr("2001:db8::1")
	requireNoAllocs(t, func() { contiguous4Sink, errSink = xnetip.ContiguousFromCIDR4(addr4, 24) })
	requireNoAllocs(t, func() { contiguous6Sink, errSink = xnetip.ContiguousFromCIDR6(addr6, 64) })
	requireNoAllocs(t, func() { contiguousSink, errSink = xnetip.ContiguousFromCIDR(addr4, 24) })
	requireNoAllocs(t, func() { contiguousSink, errSink = xnetip.ContiguousFromCIDR(addr6, 64) })
}

// verifies that a prefix with host bits set converts to its masked
// block, the same network the equivalent text parses to.
func Test_ContiguousFromPrefix4_ClearsHostBits(t *testing.T) {
	block, ok := xnetip.ContiguousFromPrefix4(netip.MustParsePrefix("192.168.1.5/24"))
	require.True(t, ok)
	require.Equal(t, mustContiguous4(t, "192.168.1.0/24"), block)
}

// verifies that both IPv4 boundary lengths convert: the universe
// prefix and a host route.
func Test_ContiguousFromPrefix4_Boundaries(t *testing.T) {
	universe, ok := xnetip.ContiguousFromPrefix4(netip.MustParsePrefix("0.0.0.0/0"))
	require.True(t, ok)
	require.Equal(t, mustContiguous4(t, "0.0.0.0/0"), universe)
	host, ok := xnetip.ContiguousFromPrefix4(netip.MustParsePrefix("192.168.1.5/32"))
	require.True(t, ok)
	require.Equal(t, mustContiguous4(t, "192.168.1.5/32"), host)
}

// verifies that the invalid zero prefix and every non-Is4 prefix are
// refused with the zero block.
func Test_ContiguousFromPrefix4_Rejections(t *testing.T) {
	for _, prefix := range []netip.Prefix{
		{},
		netip.MustParsePrefix("2001:db8::/32"),
		netip.MustParsePrefix("::ffff:10.0.0.0/104"),
	} {
		block, ok := xnetip.ContiguousFromPrefix4(prefix)
		require.False(t, ok, prefix.String())
		require.Equal(t, xnetip.Contiguous[xnetip.Network4]{}, block)
	}
}

// verifies that a prefix with host bits set converts to its masked
// block, the same network the equivalent text parses to.
func Test_ContiguousFromPrefix6_ClearsHostBits(t *testing.T) {
	block, ok := xnetip.ContiguousFromPrefix6(netip.MustParsePrefix("2001:db8::1/64"))
	require.True(t, ok)
	require.Equal(t, mustContiguous6(t, "2001:db8::/64"), block)
}

// verifies that both IPv6 boundary lengths convert: the universe
// prefix and a host route.
func Test_ContiguousFromPrefix6_Boundaries(t *testing.T) {
	universe, ok := xnetip.ContiguousFromPrefix6(netip.MustParsePrefix("::/0"))
	require.True(t, ok)
	require.Equal(t, mustContiguous6(t, "::/0"), universe)
	host, ok := xnetip.ContiguousFromPrefix6(netip.MustParsePrefix("2001:db8::1/128"))
	require.True(t, ok)
	require.Equal(t, mustContiguous6(t, "2001:db8::1/128"), host)
}

// verifies that the invalid zero prefix and an Is4 prefix are
// refused while an IPv4-mapped IPv6 prefix converts.
func Test_ContiguousFromPrefix6_Rejections(t *testing.T) {
	for _, prefix := range []netip.Prefix{{}, netip.MustParsePrefix("10.0.0.0/8")} {
		block, ok := xnetip.ContiguousFromPrefix6(prefix)
		require.False(t, ok, prefix.String())
		require.Equal(t, xnetip.Contiguous[xnetip.Network6]{}, block)
	}
	mapped, ok := xnetip.ContiguousFromPrefix6(netip.MustParsePrefix("::ffff:10.0.0.0/104"))
	require.True(t, ok)
	require.Equal(t, mustContiguous6(t, "::ffff:10.0.0.0/104"), mapped)
}

// verifies that the family follows the prefix address: an Is4 prefix
// makes an IPv4 block and an IPv4-mapped IPv6 one stays IPv6.
func Test_ContiguousFromPrefix_SelectsFamilyByAddress(t *testing.T) {
	blockV4, ok := xnetip.ContiguousFromPrefix(netip.MustParsePrefix("192.168.1.5/24"))
	require.True(t, ok)
	require.Equal(t, mustContiguous(t, "192.168.1.0/24"), blockV4)
	_, ok = blockV4.Network().IPv4()
	require.True(t, ok)
	blockMapped, ok := xnetip.ContiguousFromPrefix(netip.MustParsePrefix("::ffff:10.0.0.0/104"))
	require.True(t, ok)
	require.Equal(t, mustContiguous(t, "::ffff:10.0.0.0/104"), blockMapped)
	_, ok = blockMapped.Network().IPv6()
	require.True(t, ok)
}

// verifies that only the invalid zero prefix is refused by the
// family-agnostic conversion.
func Test_ContiguousFromPrefix_RejectsZeroPrefix(t *testing.T) {
	block, ok := xnetip.ContiguousFromPrefix(netip.Prefix{})
	require.False(t, ok)
	require.Equal(t, xnetip.Contiguous[xnetip.Network]{}, block)
}

// verifies that every valid IPv4 prefix converts, with the block's
// prefix view and the conversion inverse to each other.
func Test_ContiguousFromPrefix4_BijectionProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		prefix := genIPv4Prefix.Draw(t, "prefix")
		block, ok := xnetip.ContiguousFromPrefix4(prefix)
		require.True(t, ok)
		require.Equal(t, prefix.Masked(), block.Prefix())
		draw := genContiguous4.Draw(t, "block")
		back, ok := xnetip.ContiguousFromPrefix4(draw.Prefix())
		require.True(t, ok)
		require.Equal(t, draw, back)
	})
}

// verifies that every valid IPv6 prefix converts, with the block's
// prefix view and the conversion inverse to each other.
func Test_ContiguousFromPrefix6_BijectionProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		prefix := genIPv6Prefix.Draw(t, "prefix")
		block, ok := xnetip.ContiguousFromPrefix6(prefix)
		require.True(t, ok)
		require.Equal(t, prefix.Masked(), block.Prefix())
		draw := genContiguous6.Draw(t, "block")
		back, ok := xnetip.ContiguousFromPrefix6(draw.Prefix())
		require.True(t, ok)
		require.Equal(t, draw, back)
	})
}

// verifies that every valid prefix of either family converts, with
// the block's prefix view and the conversion inverse to each other.
func Test_ContiguousFromPrefix_BijectionProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		prefix := genIPv4Prefix.Draw(t, "prefix4")
		if rapid.Bool().Draw(t, "ipv6") {
			prefix = genIPv6Prefix.Draw(t, "prefix6")
		}
		block, ok := xnetip.ContiguousFromPrefix(prefix)
		require.True(t, ok)
		require.Equal(t, prefix.Masked(), block.Prefix())
		draw := genContiguous.Draw(t, "block")
		back, ok := xnetip.ContiguousFromPrefix(draw.Prefix())
		require.True(t, ok)
		require.Equal(t, draw, back)
	})
}

// verifies that the conversion equals the network conversion
// followed by the exact wrap in every family.
func Test_ContiguousFromPrefix_MatchesTypedProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		prefix4 := genIPv4Prefix.Draw(t, "prefix4")
		network4, ok := xnetip.Network4FromPrefix(prefix4)
		require.True(t, ok)
		twoStep4, ok := xnetip.ContiguousFrom(network4)
		require.True(t, ok)
		block4, ok := xnetip.ContiguousFromPrefix4(prefix4)
		require.True(t, ok)
		require.Equal(t, twoStep4, block4)
		prefix6 := genIPv6Prefix.Draw(t, "prefix6")
		network6, ok := xnetip.Network6FromPrefix(prefix6)
		require.True(t, ok)
		twoStep6, ok := xnetip.ContiguousFrom(network6)
		require.True(t, ok)
		block6, ok := xnetip.ContiguousFromPrefix6(prefix6)
		require.True(t, ok)
		require.Equal(t, twoStep6, block6)
		network, ok := xnetip.NetworkFromPrefix(prefix6)
		require.True(t, ok)
		twoStep, ok := xnetip.ContiguousFrom(network)
		require.True(t, ok)
		block, ok := xnetip.ContiguousFromPrefix(prefix6)
		require.True(t, ok)
		require.Equal(t, twoStep, block)
	})
}

// verifies that the accept path of each prefix conversion is
// allocation-free.
func Test_ContiguousFromPrefix_AllocationFree(t *testing.T) {
	prefix4 := netip.MustParsePrefix("192.168.1.0/24")
	prefix6 := netip.MustParsePrefix("2001:db8::/64")
	requireNoAllocs(t, func() { contiguous4Sink, okSink = xnetip.ContiguousFromPrefix4(prefix4) })
	requireNoAllocs(t, func() { contiguous6Sink, okSink = xnetip.ContiguousFromPrefix6(prefix6) })
	requireNoAllocs(t, func() { contiguousSink, okSink = xnetip.ContiguousFromPrefix(prefix4) })
	requireNoAllocs(t, func() { contiguousSink, okSink = xnetip.ContiguousFromPrefix(prefix6) })
}

// verifies that a lifted IPv4 block lands in the IPv4 family of the
// family-agnostic instantiation with the same addresses.
func Test_ContiguousFrom4_LiftsIntoIPv4Family(t *testing.T) {
	lifted := xnetip.ContiguousFrom4(mustContiguous4(t, "10.0.0.0/24"))
	require.Equal(t, mustContiguous(t, "10.0.0.0/24"), lifted)
	require.True(t, lifted.Network().Is4())
	require.Equal(t, "10.0.0.0/24", lifted.String())
}

// verifies that a lifted IPv6 block lands in the IPv6 family of the
// family-agnostic instantiation with the same addresses.
func Test_ContiguousFrom6_LiftsIntoIPv6Family(t *testing.T) {
	lifted := xnetip.ContiguousFrom6(mustContiguous6(t, "2001:db8::/32"))
	require.Equal(t, mustContiguous(t, "2001:db8::/32"), lifted)
	require.True(t, lifted.Network().Is6())
	require.Equal(t, "2001:db8::/32", lifted.String())
}

// verifies that the universe and host route boundaries of both
// families lift with their family preserved.
func Test_ContiguousFrom_LiftBoundaries(t *testing.T) {
	require.Equal(t, mustContiguous(t, "0.0.0.0/0"), xnetip.ContiguousFrom4(mustContiguous4(t, "0.0.0.0/0")))
	require.Equal(t, mustContiguous(t, "10.0.0.1/32"), xnetip.ContiguousFrom4(mustContiguous4(t, "10.0.0.1/32")))
	require.Equal(t, mustContiguous(t, "::/0"), xnetip.ContiguousFrom6(mustContiguous6(t, "::/0")))
	require.Equal(t, mustContiguous(t, "2001:db8::1/128"), xnetip.ContiguousFrom6(mustContiguous6(t, "2001:db8::1/128")))
}

// verifies that splitting a lifted IPv4 block hands the original
// block back.
func Test_ContiguousIPv4_SplitsLiftedBlock(t *testing.T) {
	original := mustContiguous4(t, "10.0.0.0/24")
	back, ok := xnetip.ContiguousIPv4(xnetip.ContiguousFrom4(original))
	require.True(t, ok)
	require.Equal(t, original, back)
}

// verifies that splitting a lifted IPv6 block hands the original
// block back.
func Test_ContiguousIPv6_SplitsLiftedBlock(t *testing.T) {
	original := mustContiguous6(t, "2001:db8::/32")
	back, ok := xnetip.ContiguousIPv6(xnetip.ContiguousFrom6(original))
	require.True(t, ok)
	require.Equal(t, original, back)
}

// verifies that a split against the other family refuses with the
// zero block.
func Test_ContiguousIPv4_WrongFamilyIsFalse(t *testing.T) {
	block, ok := xnetip.ContiguousIPv4(mustContiguous(t, "2001:db8::/32"))
	require.False(t, ok)
	require.Equal(t, xnetip.Contiguous[xnetip.Network4]{}, block)
	block6, ok := xnetip.ContiguousIPv6(mustContiguous(t, "10.0.0.0/24"))
	require.False(t, ok)
	require.Equal(t, xnetip.Contiguous[xnetip.Network6]{}, block6)
}

// verifies that a lifted IPv4-mapped IPv6 block stays IPv6: the IPv4
// split refuses it and the IPv6 split hands it back.
func Test_ContiguousFrom6_MappedStaysIPv6(t *testing.T) {
	mapped := mustContiguous6(t, "::ffff:10.0.0.0/104")
	lifted := xnetip.ContiguousFrom6(mapped)
	_, ok := xnetip.ContiguousIPv4(lifted)
	require.False(t, ok)
	back, ok := xnetip.ContiguousIPv6(lifted)
	require.True(t, ok)
	require.Equal(t, mapped, back)
}

// verifies that lift then split is the identity on every IPv4 block
// and that the lift equals the two-step through the exact wrap.
func Test_ContiguousFrom4_RoundTripProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		block := genContiguous4.Draw(t, "block")
		lifted := xnetip.ContiguousFrom4(block)
		twoStep, ok := xnetip.ContiguousFrom(xnetip.NetworkFrom4(block.Network()))
		require.True(t, ok)
		require.Equal(t, twoStep, lifted)
		back, ok := xnetip.ContiguousIPv4(lifted)
		require.True(t, ok)
		require.Equal(t, block, back)
	})
}

// verifies that lift then split is the identity on every IPv6 block
// and that the lift equals the two-step through the exact wrap.
func Test_ContiguousFrom6_RoundTripProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		block := genContiguous6.Draw(t, "block")
		lifted := xnetip.ContiguousFrom6(block)
		twoStep, ok := xnetip.ContiguousFrom(xnetip.NetworkFrom6(block.Network()))
		require.True(t, ok)
		require.Equal(t, twoStep, lifted)
		back, ok := xnetip.ContiguousIPv6(lifted)
		require.True(t, ok)
		require.Equal(t, block, back)
	})
}

// verifies that exactly one split accepts every family-agnostic
// block and that lifting the accepted half restores the original.
func Test_ContiguousSplit_RoundTripProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		block := genContiguous.Draw(t, "block")
		block4, ok4 := xnetip.ContiguousIPv4(block)
		block6, ok6 := xnetip.ContiguousIPv6(block)
		require.NotEqual(t, ok4, ok6)
		if ok4 {
			require.Equal(t, block, xnetip.ContiguousFrom4(block4))
			return
		}
		require.Equal(t, block, xnetip.ContiguousFrom6(block6))
	})
}

// verifies that every blind rewrap of the lifts and splits holds a
// contiguous mask, revalidating through the exact wrap.
func Test_ContiguousFamily_RewrapsRevalidateProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		lifted4 := xnetip.ContiguousFrom4(genContiguous4.Draw(t, "block4"))
		rewrapped, ok := xnetip.ContiguousFrom(lifted4.Network())
		require.True(t, ok)
		require.Equal(t, lifted4, rewrapped)
		lifted6 := xnetip.ContiguousFrom6(genContiguous6.Draw(t, "block6"))
		rewrapped, ok = xnetip.ContiguousFrom(lifted6.Network())
		require.True(t, ok)
		require.Equal(t, lifted6, rewrapped)
		block := genContiguous.Draw(t, "block")
		if split4, ok := xnetip.ContiguousIPv4(block); ok {
			rewrapped4, ok := xnetip.ContiguousFrom(split4.Network())
			require.True(t, ok)
			require.Equal(t, split4, rewrapped4)
		}
		if split6, ok := xnetip.ContiguousIPv6(block); ok {
			rewrapped6, ok := xnetip.ContiguousFrom(split6.Network())
			require.True(t, ok)
			require.Equal(t, split6, rewrapped6)
		}
	})
}

// verifies that the lifts and the splits are allocation-free in both
// directions.
func Test_ContiguousFamily_AllocationFree(t *testing.T) {
	block4 := mustContiguous4(t, "10.0.0.0/24")
	block6 := mustContiguous6(t, "2001:db8::/32")
	lifted4 := xnetip.ContiguousFrom4(block4)
	lifted6 := xnetip.ContiguousFrom6(block6)
	requireNoAllocs(t, func() { contiguousSink = xnetip.ContiguousFrom4(block4) })
	requireNoAllocs(t, func() { contiguousSink = xnetip.ContiguousFrom6(block6) })
	requireNoAllocs(t, func() { contiguous4Sink, okSink = xnetip.ContiguousIPv4(lifted4) })
	requireNoAllocs(t, func() { contiguous6Sink, okSink = xnetip.ContiguousIPv6(lifted6) })
}
