package xnetip_test

import (
	"net/netip"
	"slices"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/yanet-platform/xnetip"
	"pgregory.net/rapid"
)

// verifies that mask refinement enumerates every IPv4 subnet in address order.
func Test_Network4_Subnets_MaskRefinement(t *testing.T) {
	cases := []struct {
		name, network, mask string
		want                []string
	}{
		{name: "CIDR quartering", network: "192.168.0.0/22", mask: "255.255.255.0", want: []string{"192.168.0.0/24", "192.168.1.0/24", "192.168.2.0/24", "192.168.3.0/24"}},
		{name: "equal alternating mask", network: "170.85.170.85/170.85.170.85", mask: "170.85.170.85", want: []string{"170.85.170.85/170.85.170.85"}},
		{name: "even and odd universe", network: "0.0.0.0/0", mask: "0.0.0.1", want: []string{"0.0.0.0/0.0.0.1", "0.0.0.1/0.0.0.1"}},
		{name: "host identity", network: "255.255.255.255", mask: "255.255.255.255", want: []string{"255.255.255.255/32"}},
		{name: "hole between fixed runs", network: "10.0.0.0/255.0.255.0", mask: "255.128.255.0", want: []string{"10.0.0.0/255.128.255.0", "10.128.0.0/255.128.255.0"}},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			network := xnetip.MustParseNetwork4(testCase.network)
			sequence := network.Subnets(netip.MustParseAddr(testCase.mask))
			var want []xnetip.Network4
			for _, text := range testCase.want {
				want = append(want, xnetip.MustParseNetwork4(text))
			}
			require.Equal(t, want, slices.Collect(sequence))
			require.Equal(t, want, slices.Collect(sequence))
		})
	}
}

// verifies that IPv6 refinement crosses the half boundary and drops zones.
func Test_Network6_Subnets_MaskRefinement(t *testing.T) {
	cases := []struct {
		name, network, mask string
		want                []string
	}{
		{name: "CIDR quartering", network: "2001:db8::/46", mask: "ffff:ffff:ffff::", want: []string{"2001:db8::/48", "2001:db8:1::/48", "2001:db8:2::/48", "2001:db8:3::/48"}},
		{name: "equal alternating mask", network: "aaaa::/aaaa:5555:aaaa:5555:aaaa:5555:aaaa:5555", mask: "aaaa:5555:aaaa:5555:aaaa:5555:aaaa:5555", want: []string{"aaaa::/aaaa:5555:aaaa:5555:aaaa:5555:aaaa:5555"}},
		{name: "even and odd universe", network: "::/0", mask: "::1", want: []string{"::/::1", "::1/::1"}},
		{name: "half boundary gap", network: "::/ffff:ffff:ffff:fffe:7fff:ffff:ffff:ffff", mask: "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", want: []string{"::/128", "::8000:0:0:0/128", "0:0:0:1::/128", "::1:8000:0:0:0/128"}},
		{name: "zone is dropped", network: "::/0", mask: "::1%eth0", want: []string{"::/::1", "::1/::1"}},
		{name: "maximum host identity", network: "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", mask: "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", want: []string{"ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/128"}},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			sequence := xnetip.MustParseNetwork6(testCase.network).Subnets(netip.MustParseAddr(testCase.mask))
			var want []xnetip.Network6
			for _, text := range testCase.want {
				want = append(want, xnetip.MustParseNetwork6(text))
			}
			require.Equal(t, want, slices.Collect(sequence))
			require.Equal(t, want, slices.Collect(sequence))
		})
	}
}

// verifies that invalid families and masks dropping fixed bits are rejected.
func Test_Subnets_RejectsInvalidMasks(t *testing.T) {
	for _, mask := range []netip.Addr{{}, netip.MustParseAddr("::"), netip.MustParseAddr("::ffff:255.255.255.255"), netip.MustParseAddr("254.255.0.0")} {
		sequence := xnetip.MustParseNetwork4("10.0.0.0/8").Subnets(mask)
		require.Empty(t, slices.Collect(sequence))
	}
	for _, mask := range []netip.Addr{{}, netip.MustParseAddr("255.255.255.255"), netip.MustParseAddr("fffe:ffff::")} {
		sequence := xnetip.MustParseNetwork6("2001:db8::/32").Subnets(mask)
		require.Empty(t, slices.Collect(sequence))
	}
}

// verifies that prefix refinement accepts holes only when all fixed bits fit.
func Test_SubnetsWithPrefix_CIDRAndNonContiguous(t *testing.T) {
	require.Equal(t, []xnetip.Contiguous[xnetip.Network4]{{}}, slices.Collect((xnetip.Network4{}).SubnetsWithPrefix(0)))
	require.Equal(t, []xnetip.Contiguous[xnetip.Network6]{{}}, slices.Collect((xnetip.Network6{}).SubnetsWithPrefix(0)))
	network4 := xnetip.MustParseNetwork4("10.0.0.0/255.0.255.0")
	sequence4 := network4.SubnetsWithPrefix(24)
	blocks4 := slices.Collect(sequence4)
	require.Len(t, blocks4, 256)
	require.Equal(t, xnetip.MustParseContiguous4("10.0.0.0/24"), blocks4[0])
	require.Equal(t, xnetip.MustParseContiguous4("10.255.0.0/24"), blocks4[255])
	for _, prefix := range []int{-1, 0, 16, 33, 256} {
		sequence := network4.SubnetsWithPrefix(prefix)
		require.Empty(t, slices.Collect(sequence))
	}
	network6 := xnetip.MustParseNetwork6("2001:db8::/ffff:ffff:fffc:ffff::")
	sequence6 := network6.SubnetsWithPrefix(64)
	require.Equal(t, []xnetip.Contiguous[xnetip.Network6]{
		xnetip.MustParseContiguous6("2001:db8::/64"),
		xnetip.MustParseContiguous6("2001:db8:1::/64"),
		xnetip.MustParseContiguous6("2001:db8:2::/64"),
		xnetip.MustParseContiguous6("2001:db8:3::/64"),
	}, slices.Collect(sequence6))
	for _, prefix := range []int{-1, 0, 48, 129, 256} {
		sequence := network6.SubnetsWithPrefix(prefix)
		require.Empty(t, slices.Collect(sequence))
	}
}

// verifies that full-width refinements terminate early without count overflow.
func Test_Subnets_StopsEarlyAndRestarts(t *testing.T) {
	sequence4 := (xnetip.Network4{}).SubnetsWithPrefix(32)
	sequence6 := (xnetip.Network6{}).SubnetsWithPrefix(128)
	for range 2 {
		count := 0
		for network := range sequence4 {
			require.Equal(t, netip.AddrFrom4([4]byte{0, 0, 0, byte(count)}), network.Network().Addr())
			count++
			if count == 3 {
				break
			}
		}
		require.Equal(t, 3, count)
		count = 0
		for network := range sequence6 {
			require.Equal(t, netip.AddrFrom16([16]byte{15: byte(count)}), network.Network().Addr())
			count++
			if count == 3 {
				break
			}
		}
		require.Equal(t, 3, count)
	}
}

// verifies that every parent address belongs to exactly one refined subnet.
func Test_Subnets_PartitionsParentProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		parent4 := drawBoundedNetwork4(t, 8)
		mask4 := parent4.Mask().As4()
		for idx := range mask4 {
			mask4[idx] |= rapid.Byte().Draw(t, "added IPv4 bits")
		}
		sequence4 := parent4.Subnets(netip.AddrFrom4(mask4))
		parts4 := slices.Collect(sequence4)
		for idx, part := range parts4 {
			require.True(t, parent4.Contains(part))
			require.Equal(t, netip.AddrFrom4(mask4), part.Mask())
			if idx > 0 {
				require.Negative(t, parts4[idx-1].Compare(part))
			}
		}
		for addr := range parent4.Addrs() {
			count := 0
			for _, part := range parts4 {
				if part.ContainsAddr(addr) {
					count++
				}
			}
			require.Equal(t, 1, count)
		}
		parent6 := drawBoundedNetwork6(t, 8)
		mask6 := parent6.Mask().As16()
		for idx := range mask6 {
			mask6[idx] |= rapid.Byte().Draw(t, "added IPv6 bits")
		}
		sequence6 := parent6.Subnets(netip.AddrFrom16(mask6))
		parts6 := slices.Collect(sequence6)
		for idx, part := range parts6 {
			require.True(t, parent6.Contains(part))
			require.Equal(t, netip.AddrFrom16(mask6), part.Mask())
			if idx > 0 {
				require.Negative(t, parts6[idx-1].Compare(part))
			}
		}
		for addr := range parent6.Addrs() {
			count := 0
			for _, part := range parts6 {
				if part.ContainsAddr(addr) {
					count++
				}
			}
			require.Equal(t, 1, count)
		}
	})
}

// verifies that subnet iteration and prefix refinement allocate no storage.
func Test_Subnets_AllocationFree(t *testing.T) {
	network4 := xnetip.MustParseNetwork4("10.0.0.0/8")
	network6 := xnetip.MustParseNetwork6("2001:db8::/32")
	mask4 := netip.MustParseAddr("255.0.0.255")
	mask6 := netip.MustParseAddr("ffff:ffff::ff")
	requireNoAllocs(t, func() {
		sequence := network4.Subnets(mask4)
		for network := range sequence {
			networkSink = network
		}
	})
	requireNoAllocs(t, func() {
		sequence := network6.Subnets(mask6)
		for network := range sequence {
			network6Sink = network
		}
	})
	requireNoAllocs(t, func() {
		sequence := network4.SubnetsWithPrefix(16)
		for network := range sequence {
			contiguous4Sink = network
		}
	})
	requireNoAllocs(t, func() {
		sequence := network6.SubnetsWithPrefix(40)
		for network := range sequence {
			contiguous6Sink = network
		}
	})
}

func BenchmarkNetwork4_Subnets_NonContiguous(b *testing.B) {
	network := xnetip.MustParseNetwork4("10.0.0.0/8")
	mask := netip.MustParseAddr("255.0.0.255")
	b.ReportAllocs()
	for b.Loop() {
		consumeSubnets4(network, mask)
	}
}

// consumeSubnets4 drains the subdivision through an ordinary range loop.
func consumeSubnets4(network xnetip.Network4, mask netip.Addr) {
	for part := range network.Subnets(mask) {
		networkSink = part
	}
}

func BenchmarkNetwork6_Subnets_NonContiguous(b *testing.B) {
	network := xnetip.MustParseNetwork6("2001:db8::/32")
	mask := netip.MustParseAddr("ffff:ffff::ff")
	b.ReportAllocs()
	for b.Loop() {
		consumeSubnets6(network, mask)
	}
}

// consumeSubnets6 drains the subdivision through an ordinary range loop.
func consumeSubnets6(network xnetip.Network6, mask netip.Addr) {
	for part := range network.Subnets(mask) {
		network6Sink = part
	}
}

func BenchmarkNetwork4_SubnetsWithPrefix_Contiguous(b *testing.B) {
	network := xnetip.MustParseNetwork4("10.0.0.0/8")
	b.ReportAllocs()
	for b.Loop() {
		consumePrefixSubnets4(network, 16)
	}
}

// consumePrefixSubnets4 drains the CIDR subdivision through a range loop.
func consumePrefixSubnets4(network xnetip.Network4, prefix int) {
	for part := range network.SubnetsWithPrefix(prefix) {
		contiguous4Sink = part
	}
}

func BenchmarkNetwork6_SubnetsWithPrefix_Contiguous(b *testing.B) {
	network := xnetip.MustParseNetwork6("2001:db8::/32")
	b.ReportAllocs()
	for b.Loop() {
		consumePrefixSubnets6(network, 40)
	}
}

// consumePrefixSubnets6 drains the CIDR subdivision through a range loop.
func consumePrefixSubnets6(network xnetip.Network6, prefix int) {
	for part := range network.SubnetsWithPrefix(prefix) {
		contiguous6Sink = part
	}
}
