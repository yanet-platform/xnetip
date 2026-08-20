package xnetip_test

import (
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/yanet-platform/xnetip"
	"pgregory.net/rapid"
)

// verifies that an IPv4 host route prints as its bare address, without
// the /32 suffix the base string form always carries.
func Test_Compact_IPv4_HostRouteIsBare(t *testing.T) {
	network := xnetip.MustParseIPv4Network("127.0.0.1/32")
	require.Equal(t, "127.0.0.1", xnetip.Compact[xnetip.IPv4Network]{Network: network}.String())
}

// verifies that a contiguous non-host IPv4 network keeps the
// address/prefix form of the base string, the universe included.
func Test_Compact_IPv4_ContiguousKeepsPrefixForm(t *testing.T) {
	cases := []struct {
		name    string
		network xnetip.IPv4Network
		want    string
	}{
		{name: "CIDR", network: xnetip.MustParseIPv4Network("10.0.0.0/24"), want: "10.0.0.0/24"},
		{name: "zero prefix", network: xnetip.MustParseIPv4Network("0.0.0.0/0"), want: "0.0.0.0/0"},
		{name: "all-zero mask normalizes the address away", network: mustIPv4Network(t, "10.1.2.3", "0.0.0.0"), want: "0.0.0.0/0"},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			require.Equal(t, testCase.want, xnetip.Compact[xnetip.IPv4Network]{Network: testCase.network}.String())
		})
	}
}

// verifies that a non-contiguous IPv4 network keeps the explicit
// dotted mask, because no prefix length can describe it.
func Test_Compact_IPv4_NonContiguousKeepsMaskForm(t *testing.T) {
	cases := []struct {
		name    string
		network xnetip.IPv4Network
		want    string
	}{
		{name: "two-run mask", network: xnetip.MustParseIPv4Network("192.168.0.1/255.255.0.255"), want: "192.168.0.1/255.255.0.255"},
		{name: "alternating mask", network: xnetip.MustParseIPv4Network("170.85.170.85/170.85.170.85"), want: "170.85.170.85/170.85.170.85"},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			require.Equal(t, testCase.want, xnetip.Compact[xnetip.IPv4Network]{Network: testCase.network}.String())
		})
	}
}

// verifies that an IPv6 host route prints as its bare address, without
// the /128 suffix the base string form always carries.
func Test_Compact_IPv6_HostRouteIsBare(t *testing.T) {
	network := xnetip.MustParseIPv6Network("::1/128")
	require.Equal(t, "::1", xnetip.Compact[xnetip.IPv6Network]{Network: network}.String())
}

// verifies that a contiguous non-host IPv6 network keeps the
// address/prefix form of the base string, the universe included.
func Test_Compact_IPv6_ContiguousKeepsPrefixForm(t *testing.T) {
	cases := []struct {
		name    string
		network xnetip.IPv6Network
		want    string
	}{
		{name: "CIDR", network: xnetip.MustParseIPv6Network("2001:db8::/32"), want: "2001:db8::/32"},
		{name: "zero prefix", network: xnetip.MustParseIPv6Network("::/0"), want: "::/0"},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			require.Equal(t, testCase.want, xnetip.Compact[xnetip.IPv6Network]{Network: testCase.network}.String())
		})
	}
}

// verifies that a non-contiguous IPv6 network has no prefix length and
// keeps the explicit colon-form mask of the base string.
func Test_Compact_IPv6_NonContiguousKeepsMaskForm(t *testing.T) {
	network := xnetip.MustParseIPv6Network("2001:db8::1/ffff:ffff:ff00::ffff:ffff:0:0")
	_, ok := network.PrefixLen()
	require.False(t, ok)
	require.Equal(t, network.String(), xnetip.Compact[xnetip.IPv6Network]{Network: network}.String())
}

// verifies that the family-agnostic adapter renders exactly as the
// family it holds would, the IPv4 host-route rule included.
func Test_Compact_IPNetwork_DelegatesToFamily(t *testing.T) {
	cases := []struct {
		name    string
		network xnetip.IPNetwork
		want    string
	}{
		{name: "IPv4 host route is bare", network: xnetip.MustParseIPNetwork("127.0.0.1/32"), want: "127.0.0.1"},
		{name: "IPv6 CIDR", network: xnetip.MustParseIPNetwork("2001:db8::/32"), want: "2001:db8::/32"},
		{name: "IPv4 zero prefix", network: xnetip.MustParseIPNetwork("0.0.0.0/0"), want: "0.0.0.0/0"},
		{name: "IPv4 non-contiguous mask", network: xnetip.MustParseIPNetwork("192.168.0.1/255.255.0.255"), want: "192.168.0.1/255.255.0.255"},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			require.Equal(t, testCase.want, xnetip.Compact[xnetip.IPNetwork]{Network: testCase.network}.String())
		})
	}
}

// verifies that an IPv4-mapped IPv6 host route prints bare and in the
// mapped form, because 4in6 is IPv6 and never rewrites as IPv4.
func Test_Compact_IPNetwork_MappedHostRouteStaysIPv6(t *testing.T) {
	network := xnetip.MustParseIPNetwork("::ffff:1.2.3.4/128")
	require.True(t, network.Is6())
	require.Equal(t, "::ffff:1.2.3.4", xnetip.Compact[xnetip.IPNetwork]{Network: network}.String())
}

// verifies that appending writes after the caller's bytes and leaves
// them intact, in every instantiation.
func Test_Compact_AppendTo_KeepsExistingBytes(t *testing.T) {
	compact4 := xnetip.Compact[xnetip.IPv4Network]{Network: xnetip.MustParseIPv4Network("127.0.0.1/32")}
	require.Equal(t, "net=127.0.0.1", string(compact4.AppendTo([]byte("net="))))
	compact6 := xnetip.Compact[xnetip.IPv6Network]{Network: xnetip.MustParseIPv6Network("2001:db8::/32")}
	require.Equal(t, "net=2001:db8::/32", string(compact6.AppendTo([]byte("net="))))
	compact := xnetip.Compact[xnetip.IPNetwork]{Network: xnetip.MustParseIPNetwork("192.168.0.1/255.255.0.255")}
	require.Equal(t, "net=192.168.0.1/255.255.0.255", string(compact.AppendTo([]byte("net="))))
}

// verifies that the compact form differs from the base string only for
// IPv4 host routes, where it is the bare address rendering.
func Test_Compact_IPv4_MatchesStringExceptHostRouteProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		network := genIPv4Network.Draw(t, "network")
		compact := xnetip.Compact[xnetip.IPv4Network]{Network: network}.String()
		if prefix, ok := network.PrefixLen(); ok && prefix == 32 {
			require.Equal(t, network.Addr().String(), compact)
		} else {
			require.Equal(t, network.String(), compact)
		}
	})
}

// verifies that the compact form differs from the base string only for
// IPv6 host routes, where it is the bare address rendering.
func Test_Compact_IPv6_MatchesStringExceptHostRouteProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		network := genIPv6Network.Draw(t, "network")
		compact := xnetip.Compact[xnetip.IPv6Network]{Network: network}.String()
		if prefix, ok := network.PrefixLen(); ok && prefix == 128 {
			require.Equal(t, network.Addr().String(), compact)
		} else {
			require.Equal(t, network.String(), compact)
		}
	})
}

// verifies that the family-agnostic adapter is exactly the inner
// family's adapter, in both directions of the family.
func Test_Compact_IPNetwork_DelegatesProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		network4 := genIPv4Network.Draw(t, "network4")
		require.Equal(
			t,
			xnetip.Compact[xnetip.IPv4Network]{Network: network4}.String(),
			xnetip.Compact[xnetip.IPNetwork]{Network: network4.IPNetwork()}.String(),
		)
		network6 := genIPv6Network.Draw(t, "network6")
		require.Equal(
			t,
			xnetip.Compact[xnetip.IPv6Network]{Network: network6}.String(),
			xnetip.Compact[xnetip.IPNetwork]{Network: network6.IPNetwork()}.String(),
		)
	})
}

// verifies that appending to an empty buffer yields the same bytes the
// compact string form has, in every instantiation.
func Test_Compact_AppendTo_MatchesStringProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		compact4 := xnetip.Compact[xnetip.IPv4Network]{Network: genIPv4Network.Draw(t, "network4")}
		require.Equal(t, []byte(compact4.String()), compact4.AppendTo(nil))
		compact6 := xnetip.Compact[xnetip.IPv6Network]{Network: genIPv6Network.Draw(t, "network6")}
		require.Equal(t, []byte(compact6.String()), compact6.AppendTo(nil))
		compact := xnetip.Compact[xnetip.IPNetwork]{Network: genIPNetwork.Draw(t, "network")}
		require.Equal(t, []byte(compact.String()), compact.AppendTo(nil))
	})
}

// verifies that the compact form reparses to the original IPv4
// network.
//
// A bare address comes back as the host route it stood for, so
// dropping the host-route suffix loses nothing.
func Test_Compact_IPv4_ReparsesToSameNetworkProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		network := genIPv4Network.Draw(t, "network")
		parsed, err := xnetip.ParseIPv4Network(xnetip.Compact[xnetip.IPv4Network]{Network: network}.String())
		require.NoError(t, err)
		require.Equal(t, network, parsed)
	})
}

// verifies that the compact form reparses to the original IPv6
// network.
//
// A bare address comes back as the host route it stood for, so
// dropping the host-route suffix loses nothing.
func Test_Compact_IPv6_ReparsesToSameNetworkProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		network := genIPv6Network.Draw(t, "network")
		parsed, err := xnetip.ParseIPv6Network(xnetip.Compact[xnetip.IPv6Network]{Network: network}.String())
		require.NoError(t, err)
		require.Equal(t, network, parsed)
	})
}

// verifies that the compact form reparses to the original IPNetwork,
// with the family preserved.
//
// An IPv4-mapped IPv6 network prints in the mapped form and comes
// back IPv6, so the family survives the round trip.
func Test_Compact_IPNetwork_ReparsesToSameNetworkProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		network := genIPNetwork.Draw(t, "network")
		parsed, err := xnetip.ParseIPNetwork(xnetip.Compact[xnetip.IPNetwork]{Network: network}.String())
		require.NoError(t, err)
		require.Equal(t, network, parsed)
	})
}

// verifies that on contiguous IPv4 networks the compact form is
// byte-identical to the net/netip rendering of the same value.
func Test_Compact_IPv4_MatchesNetipRenderingProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		network := genIPv4Network.Draw(t, "network")
		prefix, ok := network.Prefix()
		if !ok {
			return
		}
		compact := xnetip.Compact[xnetip.IPv4Network]{Network: network}.String()
		if prefix.Bits() == 32 {
			require.Equal(t, network.Addr().String(), compact)
		} else {
			require.Equal(t, prefix.String(), compact)
		}
	})
}

// verifies that on contiguous IPv6 networks the compact form is
// byte-identical to the net/netip rendering of the same value.
func Test_Compact_IPv6_MatchesNetipRenderingProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		network := genIPv6Network.Draw(t, "network")
		prefix, ok := network.Prefix()
		if !ok {
			return
		}
		compact := xnetip.Compact[xnetip.IPv6Network]{Network: network}.String()
		if prefix.Bits() == 128 {
			require.Equal(t, network.Addr().String(), compact)
		} else {
			require.Equal(t, prefix.String(), compact)
		}
	})
}

// verifies that appending into a buffer with enough capacity allocates
// nothing, whatever the shape and the instantiation.
func Test_Compact_AppendTo_AllocationFree(t *testing.T) {
	buffer := make([]byte, 0, 128)
	compacts4 := []xnetip.Compact[xnetip.IPv4Network]{
		{Network: xnetip.MustParseIPv4Network("127.0.0.1/32")},
		{Network: xnetip.MustParseIPv4Network("10.0.0.0/24")},
		{Network: xnetip.MustParseIPv4Network("192.168.0.1/255.255.0.255")},
	}
	for _, compact := range compacts4 {
		requireNoAllocs(t, func() { bytesSink = compact.AppendTo(buffer[:0]) })
	}
	compacts6 := []xnetip.Compact[xnetip.IPv6Network]{
		{Network: xnetip.MustParseIPv6Network("::1/128")},
		{Network: xnetip.MustParseIPv6Network("2001:db8::/32")},
		{Network: xnetip.MustParseIPv6Network("2001:db8::1/ffff:ffff:ff00::ffff:ffff:0:0")},
	}
	for _, compact := range compacts6 {
		requireNoAllocs(t, func() { bytesSink = compact.AppendTo(buffer[:0]) })
	}
	compacts := []xnetip.Compact[xnetip.IPNetwork]{
		{Network: xnetip.MustParseIPNetwork("127.0.0.1/32")},
		{Network: xnetip.MustParseIPNetwork("2001:db8::/32")},
	}
	for _, compact := range compacts {
		requireNoAllocs(t, func() { bytesSink = compact.AppendTo(buffer[:0]) })
	}
}

// verifies that rendering to a string costs exactly the one string
// conversion in every instantiation, pinning any extra copy.
func Test_Compact_String_SingleAllocation(t *testing.T) {
	hostRoute := xnetip.Compact[xnetip.IPv4Network]{Network: xnetip.MustParseIPv4Network("127.0.0.1/32")}
	require.Equal(t, 1, int(testing.AllocsPerRun(100, func() { stringSink = hostRoute.String() })))
	nonContiguous := xnetip.Compact[xnetip.IPv4Network]{Network: xnetip.MustParseIPv4Network("192.168.0.1/255.255.0.255")}
	require.Equal(t, 1, int(testing.AllocsPerRun(100, func() { stringSink = nonContiguous.String() })))
	cidr6 := xnetip.Compact[xnetip.IPv6Network]{Network: xnetip.MustParseIPv6Network("2001:db8::/32")}
	require.Equal(t, 1, int(testing.AllocsPerRun(100, func() { stringSink = cidr6.String() })))
	ipNetwork := xnetip.Compact[xnetip.IPNetwork]{Network: xnetip.MustParseIPNetwork("::1/128")}
	require.Equal(t, 1, int(testing.AllocsPerRun(100, func() { stringSink = ipNetwork.String() })))
}

func BenchmarkCompact_IPv4_HostRoute(b *testing.B) {
	compact := xnetip.Compact[xnetip.IPv4Network]{Network: xnetip.MustParseIPv4Network("127.0.0.1/32")}
	b.ReportAllocs()
	for b.Loop() {
		stringSink = compact.String()
	}
}

func BenchmarkCompact_IPv4_CIDR(b *testing.B) {
	compact := xnetip.Compact[xnetip.IPv4Network]{Network: xnetip.MustParseIPv4Network("10.0.0.0/24")}
	b.ReportAllocs()
	for b.Loop() {
		stringSink = compact.String()
	}
}

func BenchmarkCompact_IPv4_NonContiguous(b *testing.B) {
	compact := xnetip.Compact[xnetip.IPv4Network]{Network: xnetip.MustParseIPv4Network("192.168.0.1/255.255.0.255")}
	b.ReportAllocs()
	for b.Loop() {
		stringSink = compact.String()
	}
}

func BenchmarkCompact_IPv6_HostRoute(b *testing.B) {
	compact := xnetip.Compact[xnetip.IPv6Network]{Network: xnetip.MustParseIPv6Network("::1/128")}
	b.ReportAllocs()
	for b.Loop() {
		stringSink = compact.String()
	}
}

func BenchmarkCompact_IPv6_CIDR(b *testing.B) {
	compact := xnetip.Compact[xnetip.IPv6Network]{Network: xnetip.MustParseIPv6Network("2001:db8::/32")}
	b.ReportAllocs()
	for b.Loop() {
		stringSink = compact.String()
	}
}

func BenchmarkCompact_IPv6_NonContiguous(b *testing.B) {
	compact := xnetip.Compact[xnetip.IPv6Network]{Network: xnetip.MustParseIPv6Network("2001:db8::1/ffff:ffff:ff00::ffff:ffff:0:0")}
	b.ReportAllocs()
	for b.Loop() {
		stringSink = compact.String()
	}
}

func BenchmarkCompact_IPNetwork_V4(b *testing.B) {
	compact := xnetip.Compact[xnetip.IPNetwork]{Network: xnetip.MustParseIPNetwork("10.0.0.0/24")}
	b.ReportAllocs()
	for b.Loop() {
		stringSink = compact.String()
	}
}

func BenchmarkCompact_IPNetwork_V6(b *testing.B) {
	compact := xnetip.Compact[xnetip.IPNetwork]{Network: xnetip.MustParseIPNetwork("2001:db8::/32")}
	b.ReportAllocs()
	for b.Loop() {
		stringSink = compact.String()
	}
}

func BenchmarkCompactAppendTo_IPv4_HostRoute(b *testing.B) {
	compact := xnetip.Compact[xnetip.IPv4Network]{Network: xnetip.MustParseIPv4Network("127.0.0.1/32")}
	buffer := make([]byte, 0, 128)
	b.ReportAllocs()
	for b.Loop() {
		bytesSink = compact.AppendTo(buffer[:0])
	}
}

func BenchmarkCompactAppendTo_IPv4_CIDR(b *testing.B) {
	compact := xnetip.Compact[xnetip.IPv4Network]{Network: xnetip.MustParseIPv4Network("10.0.0.0/24")}
	buffer := make([]byte, 0, 128)
	b.ReportAllocs()
	for b.Loop() {
		bytesSink = compact.AppendTo(buffer[:0])
	}
}

func BenchmarkCompactAppendTo_IPv4_NonContiguous(b *testing.B) {
	compact := xnetip.Compact[xnetip.IPv4Network]{Network: xnetip.MustParseIPv4Network("192.168.0.1/255.255.0.255")}
	buffer := make([]byte, 0, 128)
	b.ReportAllocs()
	for b.Loop() {
		bytesSink = compact.AppendTo(buffer[:0])
	}
}

func BenchmarkCompactAppendTo_IPv6_HostRoute(b *testing.B) {
	compact := xnetip.Compact[xnetip.IPv6Network]{Network: xnetip.MustParseIPv6Network("::1/128")}
	buffer := make([]byte, 0, 128)
	b.ReportAllocs()
	for b.Loop() {
		bytesSink = compact.AppendTo(buffer[:0])
	}
}

func BenchmarkCompactAppendTo_IPv6_CIDR(b *testing.B) {
	compact := xnetip.Compact[xnetip.IPv6Network]{Network: xnetip.MustParseIPv6Network("2001:db8::/32")}
	buffer := make([]byte, 0, 128)
	b.ReportAllocs()
	for b.Loop() {
		bytesSink = compact.AppendTo(buffer[:0])
	}
}

func BenchmarkCompactAppendTo_IPv6_NonContiguous(b *testing.B) {
	compact := xnetip.Compact[xnetip.IPv6Network]{Network: xnetip.MustParseIPv6Network("2001:db8::1/ffff:ffff:ff00::ffff:ffff:0:0")}
	buffer := make([]byte, 0, 128)
	b.ReportAllocs()
	for b.Loop() {
		bytesSink = compact.AppendTo(buffer[:0])
	}
}

func BenchmarkCompactAppendTo_IPNetwork_V4(b *testing.B) {
	compact := xnetip.Compact[xnetip.IPNetwork]{Network: xnetip.MustParseIPNetwork("10.0.0.0/24")}
	buffer := make([]byte, 0, 128)
	b.ReportAllocs()
	for b.Loop() {
		bytesSink = compact.AppendTo(buffer[:0])
	}
}

func BenchmarkCompactAppendTo_IPNetwork_V6(b *testing.B) {
	compact := xnetip.Compact[xnetip.IPNetwork]{Network: xnetip.MustParseIPNetwork("2001:db8::/32")}
	buffer := make([]byte, 0, 128)
	b.ReportAllocs()
	for b.Loop() {
		bytesSink = compact.AppendTo(buffer[:0])
	}
}
