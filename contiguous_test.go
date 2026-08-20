package xnetip_test

import (
	"net/netip"
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
