package xnetip_test

import (
	"net/netip"
	"slices"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/yanet-platform/xnetip"
	"pgregory.net/rapid"
)

// verifies that IPv4 refinement yields descending addresses while
// retaining parent constraints across gaps and alternating mask bits.
func Test_Network4_SubnetsBackward_MaskShapes(t *testing.T) {
	cases := []struct {
		name, network, mask string
		want                []string
	}{
		{name: "CIDR quartering", network: "192.168.0.0/22", mask: "255.255.255.0", want: []string{"192.168.3.0/24", "192.168.2.0/24", "192.168.1.0/24", "192.168.0.0/24"}},
		{name: "alternating mask with a lower fixed address bit", network: "170.85.170.85/170.85.170.85", mask: "170.85.170.87", want: []string{"170.85.170.87/170.85.170.87", "170.85.170.85/170.85.170.87"}},
		{name: "even and odd universe", network: "0.0.0.0/0", mask: "0.0.0.1", want: []string{"0.0.0.1/0.0.0.1", "0.0.0.0/0.0.0.1"}},
		{name: "highest-bit refinement", network: "0.0.0.0/0", mask: "128.0.0.0", want: []string{"128.0.0.0/1", "0.0.0.0/1"}},
		{name: "maximum host identity", network: "255.255.255.255", mask: "255.255.255.255", want: []string{"255.255.255.255/32"}},
		{name: "universe identity", network: "0.0.0.0/0", mask: "0.0.0.0", want: []string{"0.0.0.0/0"}},
		{name: "hole between fixed runs", network: "10.0.0.0/255.0.255.0", mask: "255.128.255.0", want: []string{"10.128.0.0/255.128.255.0", "10.0.0.0/255.128.255.0"}},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			sequence := xnetip.MustParseNetwork4(testCase.network).SubnetsBackward(netip.MustParseAddr(testCase.mask))
			var want []xnetip.Network4
			for _, text := range testCase.want {
				want = append(want, xnetip.MustParseNetwork4(text))
			}
			require.Equal(t, want, slices.Collect(sequence))
			require.Equal(t, want, slices.Collect(sequence))
		})
	}
}

// verifies that descending IPv6 refinement borrows across the half
// boundary, preserves mapped families and drops mask zones.
func Test_Network6_SubnetsBackward_MaskShapes(t *testing.T) {
	cases := []struct {
		name, network, mask string
		want                []string
	}{
		{name: "CIDR quartering", network: "2001:db8::/46", mask: "ffff:ffff:ffff::", want: []string{"2001:db8:3::/48", "2001:db8:2::/48", "2001:db8:1::/48", "2001:db8::/48"}},
		{name: "half-boundary gap", network: "::/ffff:ffff:ffff:fffe:7fff:ffff:ffff:ffff", mask: "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", want: []string{"::1:8000:0:0:0/128", "0:0:0:1::/128", "::8000:0:0:0/128", "::/128"}},
		{name: "alternating mask preserves lower fixed bits", network: "aaaa:5555:aaaa:5555:aaaa:5555:aaaa:5555/aaaa:5555:aaaa:5555:aaaa:5555:aaaa:5555", mask: "aaaa:5555:aaaa:5555:aaaa:5555:aaaa:5557", want: []string{"aaaa:5555:aaaa:5555:aaaa:5555:aaaa:5557/aaaa:5555:aaaa:5555:aaaa:5555:aaaa:5557", "aaaa:5555:aaaa:5555:aaaa:5555:aaaa:5555/aaaa:5555:aaaa:5555:aaaa:5555:aaaa:5557"}},
		{name: "highest-bit refinement", network: "::/0", mask: "8000::", want: []string{"8000::/1", "::/1"}},
		{name: "mask zone is dropped", network: "::/0", mask: "::1%eth0", want: []string{"::1/::1", "::/::1"}},
		{name: "mapped IPv6 remains IPv6", network: "::ffff:192.0.2.0/127", mask: "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", want: []string{"::ffff:192.0.2.1/128", "::ffff:192.0.2.0/128"}},
		{name: "maximum host identity", network: "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", mask: "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", want: []string{"ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/128"}},
		{name: "universe identity", network: "::/0", mask: "::", want: []string{"::/0"}},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			sequence := xnetip.MustParseNetwork6(testCase.network).SubnetsBackward(netip.MustParseAddr(testCase.mask))
			var want []xnetip.Network6
			for _, text := range testCase.want {
				want = append(want, xnetip.MustParseNetwork6(text))
			}
			require.Equal(t, want, slices.Collect(sequence))
			require.Equal(t, want, slices.Collect(sequence))
		})
	}
}

// verifies that backward refinement rejects invalid families and
// masks or prefix lengths that cannot preserve the parent's fixed bits.
func Test_SubnetsBackward_RejectsInvalidRefinements(t *testing.T) {
	for _, mask := range []netip.Addr{{}, netip.MustParseAddr("::"), netip.MustParseAddr("::ffff:255.255.255.255"), netip.MustParseAddr("254.255.0.0")} {
		require.Empty(t, slices.Collect(xnetip.MustParseNetwork4("10.0.0.0/8").SubnetsBackward(mask)))
	}
	for _, mask := range []netip.Addr{{}, netip.MustParseAddr("255.255.255.255"), netip.MustParseAddr("fffe:ffff::")} {
		require.Empty(t, slices.Collect(xnetip.MustParseNetwork6("2001:db8::/32").SubnetsBackward(mask)))
	}
	for _, prefix := range []int{-1, 0, 16, 33, 256} {
		require.Empty(t, slices.Collect(xnetip.MustParseNetwork4("10.0.0.0/255.0.255.0").SubnetsWithPrefixBackward(prefix)))
	}
	for _, prefix := range []int{-1, 0, 48, 129, 256} {
		require.Empty(t, slices.Collect(xnetip.MustParseNetwork6("2001:db8::/ffff:ffff:fffc:ffff::").SubnetsWithPrefixBackward(prefix)))
	}
}

// verifies that descending prefix refinement stays typed and
// partitions non-contiguous parents in reverse address order.
func Test_SubnetsWithPrefixBackward_NonContiguousParents(t *testing.T) {
	require.Equal(t, []xnetip.Contiguous[xnetip.Network4]{{}}, slices.Collect((xnetip.Network4{}).SubnetsWithPrefixBackward(0)))
	require.Equal(t, []xnetip.Contiguous[xnetip.Network6]{{}}, slices.Collect((xnetip.Network6{}).SubnetsWithPrefixBackward(0)))
	sequence4 := xnetip.MustParseNetwork4("10.0.0.0/255.0.255.0").SubnetsWithPrefixBackward(24)
	blocks4 := slices.Collect(sequence4)
	require.Len(t, blocks4, 256)
	require.Equal(t, xnetip.MustParseContiguous4("10.255.0.0/24"), blocks4[0])
	require.Equal(t, xnetip.MustParseContiguous4("10.0.0.0/24"), blocks4[255])
	require.Equal(t, blocks4, slices.Collect(sequence4))
	sequence6 := xnetip.MustParseNetwork6("2001:db8::/ffff:ffff:fffc:ffff::").SubnetsWithPrefixBackward(64)
	blocks6 := slices.Collect(sequence6)
	require.Equal(t, []xnetip.Contiguous[xnetip.Network6]{
		xnetip.MustParseContiguous6("2001:db8:3::/64"),
		xnetip.MustParseContiguous6("2001:db8:2::/64"),
		xnetip.MustParseContiguous6("2001:db8:1::/64"),
		xnetip.MustParseContiguous6("2001:db8::/64"),
	}, blocks6)
	require.Equal(t, blocks6, slices.Collect(sequence6))
}

// verifies that unbounded reverse refinements start at the largest
// address, honor early termination and restart from the same state.
func Test_SubnetsBackward_FullWidthStopsEarlyAndRestarts(t *testing.T) {
	want4 := []netip.Addr{netip.MustParseAddr("255.255.255.255"), netip.MustParseAddr("255.255.255.254"), netip.MustParseAddr("255.255.255.253")}
	want6 := []netip.Addr{netip.MustParseAddr("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"), netip.MustParseAddr("ffff:ffff:ffff:ffff:ffff:ffff:ffff:fffe"), netip.MustParseAddr("ffff:ffff:ffff:ffff:ffff:ffff:ffff:fffd")}
	sequence4 := (xnetip.Network4{}).SubnetsBackward(netip.MustParseAddr("255.255.255.255"))
	sequence6 := (xnetip.Network6{}).SubnetsBackward(netip.MustParseAddr("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"))
	prefix4 := (xnetip.Network4{}).SubnetsWithPrefixBackward(32)
	prefix6 := (xnetip.Network6{}).SubnetsWithPrefixBackward(128)
	for range 2 {
		count := 0
		for block := range sequence4 {
			require.Equal(t, want4[count], block.Addr())
			count++
			if count == len(want4) {
				break
			}
		}
		require.Equal(t, len(want4), count)
		count = 0
		for block := range sequence6 {
			require.Equal(t, want6[count], block.Addr())
			count++
			if count == len(want6) {
				break
			}
		}
		require.Equal(t, len(want6), count)
		count = 0
		for block := range prefix4 {
			require.Equal(t, want4[count], block.Network().Addr())
			count++
			if count == len(want4) {
				break
			}
		}
		require.Equal(t, len(want4), count)
		count = 0
		for block := range prefix6 {
			require.Equal(t, want6[count], block.Network().Addr())
			count++
			if count == len(want6) {
				break
			}
		}
		require.Equal(t, len(want6), count)
	}
}

// verifies that bounded arbitrary-mask subdivision is exactly the
// reverse of its forward sequence for both address families.
func Test_SubnetsBackward_ReversesForwardProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		parent4 := drawBoundedNetwork4(t, 8)
		mask4 := parent4.Mask().As4()
		for idx := range mask4 {
			mask4[idx] |= rapid.Byte().Draw(t, "added IPv4 bits")
		}
		target4 := netip.AddrFrom4(mask4)
		want4 := slices.Collect(parent4.Subnets(target4))
		slices.Reverse(want4)
		require.Equal(t, want4, slices.Collect(parent4.SubnetsBackward(target4)))
		parent6 := drawBoundedNetwork6(t, 8)
		mask6 := parent6.Mask().As16()
		for idx := range mask6 {
			mask6[idx] |= rapid.Byte().Draw(t, "added IPv6 bits")
		}
		target6 := netip.AddrFrom16(mask6)
		want6 := slices.Collect(parent6.Subnets(target6))
		slices.Reverse(want6)
		require.Equal(t, want6, slices.Collect(parent6.SubnetsBackward(target6)))
		wantPrefix4 := slices.Collect(parent4.SubnetsWithPrefix(32))
		slices.Reverse(wantPrefix4)
		require.Equal(t, wantPrefix4, slices.Collect(parent4.SubnetsWithPrefixBackward(32)))
		wantPrefix6 := slices.Collect(parent6.SubnetsWithPrefix(128))
		slices.Reverse(wantPrefix6)
		require.Equal(t, wantPrefix6, slices.Collect(parent6.SubnetsWithPrefixBackward(128)))
	})
}

// verifies that CIDR prefix refinement is reversed for every prefix
// boundary without enumerating more than eight newly fixed bits.
func Test_SubnetsWithPrefixBackward_ReversesForwardProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		parent4 := genContiguous4.Draw(t, "parent4")
		prefix4 := rapid.IntRange(parent4.PrefixLen(), min(32, parent4.PrefixLen()+8)).Draw(t, "prefix4")
		want4 := slices.Collect(parent4.Network().SubnetsWithPrefix(prefix4))
		slices.Reverse(want4)
		require.Equal(t, want4, slices.Collect(parent4.Network().SubnetsWithPrefixBackward(prefix4)))
		parent6 := genContiguous6.Draw(t, "parent6")
		prefix6 := rapid.IntRange(parent6.PrefixLen(), min(128, parent6.PrefixLen()+8)).Draw(t, "prefix6")
		want6 := slices.Collect(parent6.Network().SubnetsWithPrefix(prefix6))
		slices.Reverse(want6)
		require.Equal(t, want6, slices.Collect(parent6.Network().SubnetsWithPrefixBackward(prefix6)))
	})
}

// verifies that descending mask and prefix subdivision allocate no
// storage for either family, including early-stopped full universes.
func Test_SubnetsBackward_AllocationFree(t *testing.T) {
	network4 := xnetip.MustParseNetwork4("10.0.0.0/8")
	network6 := xnetip.MustParseNetwork6("2001:db8::/32")
	mask4 := netip.MustParseAddr("255.0.0.255")
	mask6 := netip.MustParseAddr("ffff:ffff::ff")
	requireNoAllocs(t, func() {
		for block := range network4.SubnetsBackward(mask4) {
			networkSink = block
		}
		for block := range network6.SubnetsBackward(mask6) {
			network6Sink = block
		}
		for block := range network4.SubnetsWithPrefixBackward(16) {
			contiguous4Sink = block
		}
		for block := range network6.SubnetsWithPrefixBackward(40) {
			contiguous6Sink = block
		}
	})
	requireNoAllocs(t, func() {
		for block := range (xnetip.Network4{}).SubnetsWithPrefixBackward(32) {
			contiguous4Sink = block
			break
		}
		for block := range (xnetip.Network6{}).SubnetsWithPrefixBackward(128) {
			contiguous6Sink = block
			break
		}
	})
}

func BenchmarkNetwork4_SubnetsBackward_NonContiguous(b *testing.B) {
	network := xnetip.MustParseNetwork4("10.0.0.0/8")
	mask := netip.MustParseAddr("255.0.0.255")
	b.ReportAllocs()
	for b.Loop() {
		consumeSubnetsBackward4(network, mask)
	}
}

// consumeSubnetsBackward4 drains a descending IPv4 mask refinement.
func consumeSubnetsBackward4(network xnetip.Network4, mask netip.Addr) {
	for block := range network.SubnetsBackward(mask) {
		networkSink = block
	}
}

func BenchmarkNetwork6_SubnetsBackward_NonContiguous(b *testing.B) {
	network := xnetip.MustParseNetwork6("2001:db8::/32")
	mask := netip.MustParseAddr("ffff:ffff::ff")
	b.ReportAllocs()
	for b.Loop() {
		consumeSubnetsBackward6(network, mask)
	}
}

// consumeSubnetsBackward6 drains a descending IPv6 mask refinement.
func consumeSubnetsBackward6(network xnetip.Network6, mask netip.Addr) {
	for block := range network.SubnetsBackward(mask) {
		network6Sink = block
	}
}

func BenchmarkNetwork4_SubnetsWithPrefixBackward_Contiguous(b *testing.B) {
	network := xnetip.MustParseNetwork4("10.0.0.0/8")
	b.ReportAllocs()
	for b.Loop() {
		consumePrefixSubnetsBackward4(network, 16)
	}
}

// consumePrefixSubnetsBackward4 drains a descending IPv4 CIDR refinement.
func consumePrefixSubnetsBackward4(network xnetip.Network4, prefix int) {
	for block := range network.SubnetsWithPrefixBackward(prefix) {
		contiguous4Sink = block
	}
}

func BenchmarkNetwork6_SubnetsWithPrefixBackward_Contiguous(b *testing.B) {
	network := xnetip.MustParseNetwork6("2001:db8::/32")
	b.ReportAllocs()
	for b.Loop() {
		consumePrefixSubnetsBackward6(network, 40)
	}
}

// consumePrefixSubnetsBackward6 drains a descending IPv6 CIDR refinement.
func consumePrefixSubnetsBackward6(network xnetip.Network6, prefix int) {
	for block := range network.SubnetsWithPrefixBackward(prefix) {
		contiguous6Sink = block
	}
}
