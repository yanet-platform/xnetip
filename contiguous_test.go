package xnetip_test

import (
	"errors"
	"net/netip"
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
