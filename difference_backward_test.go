package xnetip_test

import (
	"iter"
	"net/netip"
	"slices"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/yanet-platform/xnetip"
	"pgregory.net/rapid"
)

// verifies that backward peeling reverses arbitrary IPv4 set differences exactly.
func Test_Network4_DifferenceBackward_ReferenceCases(t *testing.T) {
	cases := []struct {
		name, source, excluded string
	}{
		{name: "disjoint networks", source: "10.0.0.0/8", excluded: "192.168.0.0/16"},
		{name: "equal networks", source: "10.0.0.0/8", excluded: "10.0.0.0/8"},
		{name: "excluded contains source", source: "10.0.0.0/8", excluded: "0.0.0.0/0"},
		{name: "universe minus maximum host", source: "0.0.0.0/0", excluded: "255.255.255.255"},
		{name: "two-run masks partially overlap", source: "10.0.0.5/255.0.0.255", excluded: "10.2.0.0/255.255.0.0"},
		{name: "alternating pending bits", source: "0.0.0.0/0", excluded: "170.85.170.85/170.85.170.85"},
		{name: "source has alternating bits", source: "170.85.170.85/170.85.170.85", excluded: "255.255.255.255"},
		{name: "single low bit", source: "0.0.0.0/0", excluded: "0.0.0.1/0.0.0.1"},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			source := xnetip.MustParseNetwork4(testCase.source)
			excluded := xnetip.MustParseNetwork4(testCase.excluded)
			requireReverseDifference(t, source.Difference(excluded), source.DifferenceBackward(excluded))
		})
	}
	source := xnetip.MustParseNetwork4("0.0.0.0/0")
	excluded := xnetip.MustParseNetwork4("0.0.0.5/0.0.0.7")
	require.Equal(t, []xnetip.Network4{
		xnetip.MustParseNetwork4("0.0.0.4/0.0.0.7"),
		xnetip.MustParseNetwork4("0.0.0.6/0.0.0.6"),
		xnetip.MustParseNetwork4("0.0.0.0/0.0.0.4"),
	}, slices.Collect(source.DifferenceBackward(excluded)))
}

// verifies that backward IPv6 peeling crosses the word boundary without drift.
func Test_Network6_DifferenceBackward_ReferenceCases(t *testing.T) {
	cases := []struct {
		name, source, excluded string
	}{
		{name: "disjoint networks", source: "2001:db8::/32", excluded: "2002::/16"},
		{name: "equal networks", source: "2001:db8::/32", excluded: "2001:db8::/32"},
		{name: "excluded contains source", source: "2001:db8::/32", excluded: "::/0"},
		{name: "universe minus maximum host", source: "::/0", excluded: "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"},
		{name: "cross-half gap", source: "::/ffff:ffff:ffff:fffe:7fff:ffff:ffff:ffff", excluded: "::1:8000:0:0:0/128"},
		{name: "two-run masks partially overlap", source: "2001:db8::1/ffff:ffff::ffff", excluded: "2001:db8:1::/ffff:ffff:ffff::"},
		{name: "alternating pending bits", source: "::/0", excluded: "aaaa:5555:aaaa:5555:aaaa:5555:aaaa:5555/aaaa:5555:aaaa:5555:aaaa:5555:aaaa:5555"},
		{name: "single low bit", source: "::/0", excluded: "::1/::1"},
		{name: "mapped IPv6 stays IPv6", source: "::ffff:0.0.0.0/96", excluded: "::ffff:192.0.2.1/128"},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			source := xnetip.MustParseNetwork6(testCase.source)
			excluded := xnetip.MustParseNetwork6(testCase.excluded)
			requireReverseDifference(t, source.Difference(excluded), source.DifferenceBackward(excluded))
		})
	}
}

// verifies that mixed families remain disjoint and preserve the source family.
func Test_Network_DifferenceBackward_FamilyDispatch(t *testing.T) {
	for _, pair := range [][2]string{
		{"0.0.0.0/0", "10.0.0.1/32"},
		{"::/0", "2001:db8::1/128"},
		{"0.0.0.0/0", "::ffff:10.0.0.1/128"},
		{"::ffff:0.0.0.0/96", "10.0.0.1/32"},
		{"2001:db8::/32", "10.0.0.0/8"},
	} {
		source, excluded := xnetip.MustParseNetwork(pair[0]), xnetip.MustParseNetwork(pair[1])
		requireReverseDifference(t, source.Difference(excluded), source.DifferenceBackward(excluded))
		for part := range source.DifferenceBackward(excluded) {
			require.Equal(t, source.Is4(), part.Is4())
		}
	}
}

// verifies that typed wrappers retain their guarantees in reversed peel order.
func Test_Wrappers_DifferenceBackward_Guarantees(t *testing.T) {
	source4, excluded4 := xnetip.MustParseContiguous4("0.0.0.0/0"), xnetip.MustParseContiguous4("10.0.0.1/32")
	requireReverseDifference(t, source4.Difference(excluded4), source4.DifferenceBackward(excluded4))
	requireReverseDifference(t, source4.Difference(source4), source4.DifferenceBackward(source4))
	requireReverseDifference(t, excluded4.Difference(source4), excluded4.DifferenceBackward(source4))
	source6, excluded6 := xnetip.MustParseContiguous6("::/0"), xnetip.MustParseContiguous6("2001:db8::1/128")
	requireReverseDifference(t, source6.Difference(excluded6), source6.DifferenceBackward(excluded6))
	requireReverseDifference(t, source6.Difference(source6), source6.DifferenceBackward(source6))
	requireReverseDifference(t, excluded6.Difference(source6), excluded6.DifferenceBackward(source6))
	source, excluded := xnetip.ContiguousFrom4(source4), xnetip.ContiguousFrom6(excluded6)
	requireReverseDifference(t, source.Difference(excluded), source.DifferenceBackward(excluded))
	sourceBi := xnetip.MustParseBiContiguous("2001:db8::/ffff:ffff::ffff:0:0:0")
	excludedBi := xnetip.MustParseBiContiguous("2001:db8:1::1/ffff:ffff:ffff::ffff:ffff:ffff:ffff")
	requireReverseDifference(t, sourceBi.Difference(excludedBi), sourceBi.DifferenceBackward(excludedBi))
	requireReverseDifference(t, sourceBi.Difference(sourceBi), sourceBi.DifferenceBackward(sourceBi))
	for part := range sourceBi.DifferenceBackward(excludedBi) {
		require.True(t, part.Network().IsBicontiguous())
	}
}

// requireReverseDifference checks exact order, reiteration and early termination.
func requireReverseDifference[T comparable](t require.TestingT, forward, backward iter.Seq[T]) {
	want := slices.Collect(forward)
	slices.Reverse(want)
	require.Equal(t, want, slices.Collect(backward))
	require.Equal(t, want, slices.Collect(backward))
	count := 0
	for part := range backward {
		require.Equal(t, want[count], part)
		count++
		break
	}
	require.Equal(t, min(1, len(want)), count)
	require.Equal(t, want, slices.Collect(backward))
}

// verifies that arbitrary masks reverse both disjoint and forced-overlap peels.
func Test_DifferenceBackward_ArbitraryMasksProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		source4, excluded4 := genNetwork4.Draw(t, "IPv4 source"), genNetwork4.Draw(t, "IPv4 excluded")
		if rapid.Bool().Draw(t, "IPv4 force overlap") {
			address, mask := source4.Addr().As4(), source4.Mask().As4()
			otherAddress, otherMask := excluded4.Addr().As4(), excluded4.Mask().As4()
			for idx := range address {
				address[idx] |= otherAddress[idx] &^ mask[idx]
				mask[idx] |= otherMask[idx]
			}
			var err error
			excluded4, err = xnetip.Network4From(netip.AddrFrom4(address), netip.AddrFrom4(mask))
			require.NoError(t, err)
		}
		requireReverseDifference(t, source4.Difference(excluded4), source4.DifferenceBackward(excluded4))
		source6, excluded6 := genNetwork6.Draw(t, "IPv6 source"), genNetwork6.Draw(t, "IPv6 excluded")
		if rapid.Bool().Draw(t, "IPv6 force overlap") {
			address, mask := source6.Addr().As16(), source6.Mask().As16()
			otherAddress, otherMask := excluded6.Addr().As16(), excluded6.Mask().As16()
			for idx := range address {
				address[idx] |= otherAddress[idx] &^ mask[idx]
				mask[idx] |= otherMask[idx]
			}
			var err error
			excluded6, err = xnetip.Network6From(netip.AddrFrom16(address), netip.AddrFrom16(mask))
			require.NoError(t, err)
		}
		requireReverseDifference(t, source6.Difference(excluded6), source6.DifferenceBackward(excluded6))
		source, excluded := genNetwork.Draw(t, "dual source"), genNetwork.Draw(t, "dual excluded")
		requireReverseDifference(t, source.Difference(excluded), source.DifferenceBackward(excluded))
	})
}

// verifies that CIDR and bi-contiguous guarantees survive random reverse peels.
func Test_DifferenceBackward_TypedWrappersProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		source4, excluded4 := genContiguous4.Draw(t, "IPv4 source"), genContiguous4.Draw(t, "IPv4 excluded")
		requireReverseDifference(t, source4.Difference(excluded4), source4.DifferenceBackward(excluded4))
		nested4, err := xnetip.ContiguousFromCIDR4(source4.Network().LastAddr(), rapid.IntRange(source4.PrefixLen(), 32).Draw(t, "nested IPv4 prefix"))
		require.NoError(t, err)
		requireReverseDifference(t, source4.Difference(nested4), source4.DifferenceBackward(nested4))
		source6, excluded6 := genContiguous6.Draw(t, "IPv6 source"), genContiguous6.Draw(t, "IPv6 excluded")
		requireReverseDifference(t, source6.Difference(excluded6), source6.DifferenceBackward(excluded6))
		nested6, err := xnetip.ContiguousFromCIDR6(source6.Network().LastAddr(), rapid.IntRange(source6.PrefixLen(), 128).Draw(t, "nested IPv6 prefix"))
		require.NoError(t, err)
		requireReverseDifference(t, source6.Difference(nested6), source6.DifferenceBackward(nested6))
		source, excluded := genContiguous.Draw(t, "dual source"), genContiguous.Draw(t, "dual excluded")
		requireReverseDifference(t, source.Difference(excluded), source.DifferenceBackward(excluded))
		sourceBi, excludedBi := genBiContiguous.Draw(t, "bi source"), genBiContiguous.Draw(t, "bi excluded")
		requireReverseDifference(t, sourceBi.Difference(excludedBi), sourceBi.DifferenceBackward(excludedBi))
		host6, err := xnetip.ContiguousFromCIDR6(sourceBi.Network().LastAddr(), 128)
		require.NoError(t, err)
		nestedBi := xnetip.BiContiguousFromContiguous(host6)
		requireReverseDifference(t, sourceBi.Difference(nestedBi), sourceBi.DifferenceBackward(nestedBi))
	})
}

// verifies that idiomatic reverse iteration allocates no iterator storage.
func Test_DifferenceBackward_AllocationFree(t *testing.T) {
	excluded4 := xnetip.MustParseNetwork4("170.85.170.85/170.85.170.85")
	excluded6 := xnetip.MustParseNetwork6("aaaa:5555:aaaa:5555:aaaa:5555:aaaa:5555/aaaa:5555:aaaa:5555:aaaa:5555:aaaa:5555")
	requireNoAllocs(t, func() {
		for part := range (xnetip.Network4{}).DifferenceBackward(excluded4) {
			networkSink = part
		}
	})
	requireNoAllocs(t, func() {
		for part := range (xnetip.Network6{}).DifferenceBackward(excluded6) {
			network6Sink = part
		}
	})
	dual4, dual6 := xnetip.NetworkFrom4(excluded4), xnetip.NetworkFrom6(excluded6)
	requireNoAllocs(t, func() {
		for part := range xnetip.NetworkFrom4(xnetip.Network4{}).DifferenceBackward(dual4) {
			ipNetworkSink = part
		}
	})
	requireNoAllocs(t, func() {
		for part := range (xnetip.Network{}).DifferenceBackward(dual6) {
			ipNetworkSink = part
		}
	})
	cidr4 := xnetip.MustParseContiguous4("10.0.0.1/32")
	cidr6 := xnetip.MustParseContiguous6("2001:db8::1/128")
	requireNoAllocs(t, func() {
		for part := range (xnetip.Contiguous[xnetip.Network4]{}).DifferenceBackward(cidr4) {
			contiguous4Sink = part
		}
	})
	requireNoAllocs(t, func() {
		for part := range (xnetip.Contiguous[xnetip.Network6]{}).DifferenceBackward(cidr6) {
			contiguous6Sink = part
		}
	})
	dualCIDR4, dualCIDR6 := xnetip.ContiguousFrom4(cidr4), xnetip.ContiguousFrom6(cidr6)
	requireNoAllocs(t, func() {
		for part := range xnetip.ContiguousFrom4(xnetip.Contiguous[xnetip.Network4]{}).DifferenceBackward(dualCIDR4) {
			contiguousSink = part
		}
	})
	requireNoAllocs(t, func() {
		for part := range (xnetip.Contiguous[xnetip.Network]{}).DifferenceBackward(dualCIDR6) {
			contiguousSink = part
		}
	})
	bi := xnetip.BiContiguousFromContiguous(cidr6)
	requireNoAllocs(t, func() {
		for part := range (xnetip.BiContiguous{}).DifferenceBackward(bi) {
			biContiguousSink = part
		}
	})
}

func BenchmarkNetwork4_DifferenceBackward(b *testing.B) {
	for _, text := range []string{"10.0.0.1/32", "170.85.170.85/170.85.170.85"} {
		b.Run(text, func(b *testing.B) {
			excluded := xnetip.MustParseNetwork4(text)
			var source xnetip.Network4
			b.ReportAllocs()
			for b.Loop() {
				consumeReverseDifferenceNetwork4(source, excluded)
			}
		})
	}
}

// consumeReverseDifferenceNetwork4 drains the reverse peel through a range loop.
func consumeReverseDifferenceNetwork4(source, excluded xnetip.Network4) {
	for part := range source.DifferenceBackward(excluded) {
		networkSink = part
	}
}

func BenchmarkNetwork6_DifferenceBackward(b *testing.B) {
	for _, text := range []string{"2001:db8::1/128", "aaaa:5555:aaaa:5555:aaaa:5555:aaaa:5555/aaaa:5555:aaaa:5555:aaaa:5555:aaaa:5555"} {
		b.Run(text, func(b *testing.B) {
			excluded := xnetip.MustParseNetwork6(text)
			var source xnetip.Network6
			b.ReportAllocs()
			for b.Loop() {
				consumeReverseDifferenceNetwork6(source, excluded)
			}
		})
	}
}

// consumeReverseDifferenceNetwork6 drains the reverse peel through a range loop.
func consumeReverseDifferenceNetwork6(source, excluded xnetip.Network6) {
	for part := range source.DifferenceBackward(excluded) {
		network6Sink = part
	}
}

func BenchmarkNetwork_DifferenceBackward(b *testing.B) {
	for _, text := range []string{"10.0.0.1/32", "2001:db8::1/128"} {
		b.Run(text, func(b *testing.B) {
			excluded := xnetip.MustParseNetwork(text)
			var source xnetip.Network
			if excluded.Is4() {
				source = xnetip.NetworkFrom4(xnetip.Network4{})
			}
			b.ReportAllocs()
			for b.Loop() {
				consumeReverseDifferenceNetwork(source, excluded)
			}
		})
	}
}

// consumeReverseDifferenceNetwork drains the reverse peel through a range loop.
func consumeReverseDifferenceNetwork(source, excluded xnetip.Network) {
	for part := range source.DifferenceBackward(excluded) {
		ipNetworkSink = part
	}
}

func BenchmarkContiguous4_DifferenceBackward(b *testing.B) {
	for _, text := range []string{"10.0.0.1/32"} {
		b.Run(text, func(b *testing.B) {
			excluded := xnetip.MustParseContiguous4(text)
			var source xnetip.Contiguous[xnetip.Network4]
			b.ReportAllocs()
			for b.Loop() {
				consumeReverseDifferenceContiguous4(source, excluded)
			}
		})
	}
}

// consumeReverseDifferenceContiguous4 drains the reverse peel through a range loop.
func consumeReverseDifferenceContiguous4(source, excluded xnetip.Contiguous[xnetip.Network4]) {
	for part := range source.DifferenceBackward(excluded) {
		contiguous4Sink = part
	}
}

func BenchmarkContiguous6_DifferenceBackward(b *testing.B) {
	for _, text := range []string{"2001:db8::1/128"} {
		b.Run(text, func(b *testing.B) {
			excluded := xnetip.MustParseContiguous6(text)
			var source xnetip.Contiguous[xnetip.Network6]
			b.ReportAllocs()
			for b.Loop() {
				consumeReverseDifferenceContiguous6(source, excluded)
			}
		})
	}
}

// consumeReverseDifferenceContiguous6 drains the reverse peel through a range loop.
func consumeReverseDifferenceContiguous6(source, excluded xnetip.Contiguous[xnetip.Network6]) {
	for part := range source.DifferenceBackward(excluded) {
		contiguous6Sink = part
	}
}

func BenchmarkContiguous_DifferenceBackward(b *testing.B) {
	for _, text := range []string{"10.0.0.1/32", "2001:db8::1/128"} {
		b.Run(text, func(b *testing.B) {
			excluded := xnetip.MustParseContiguous(text)
			var source xnetip.Contiguous[xnetip.Network]
			if excluded.Network().Is4() {
				source = xnetip.ContiguousFrom4(xnetip.Contiguous[xnetip.Network4]{})
			}
			b.ReportAllocs()
			for b.Loop() {
				consumeReverseDifferenceContiguous(source, excluded)
			}
		})
	}
}

// consumeReverseDifferenceContiguous drains the reverse peel through a range loop.
func consumeReverseDifferenceContiguous(source, excluded xnetip.Contiguous[xnetip.Network]) {
	for part := range source.DifferenceBackward(excluded) {
		contiguousSink = part
	}
}

func BenchmarkBiContiguous_DifferenceBackward(b *testing.B) {
	for _, text := range []string{"2001:db8::1/128"} {
		b.Run(text, func(b *testing.B) {
			excluded := xnetip.MustParseBiContiguous(text)
			var source xnetip.BiContiguous
			b.ReportAllocs()
			for b.Loop() {
				consumeReverseDifferenceBiContiguous(source, excluded)
			}
		})
	}
}

// consumeReverseDifferenceBiContiguous drains the reverse peel through a range loop.
func consumeReverseDifferenceBiContiguous(source, excluded xnetip.BiContiguous) {
	for part := range source.DifferenceBackward(excluded) {
		biContiguousSink = part
	}
}
