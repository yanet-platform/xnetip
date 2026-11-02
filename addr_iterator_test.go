package xnetip_test

import (
	"math"
	"net/netip"
	"slices"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/yanet-platform/xnetip"
	"pgregory.net/rapid"
)

// verifies that an uninitialized cursor is empty and remains exhausted.
func Test_AddrIterator_Zero(t *testing.T) {
	var cursor xnetip.AddrIterator
	address, ok := cursor.Next()
	require.False(t, ok)
	require.Equal(t, netip.Addr{}, address)
	_, ok = cursor.NextBack()
	require.False(t, ok)
	size, exact := cursor.SizeHint()
	require.True(t, exact)
	require.Zero(t, size)
}

// verifies that both ends and indexed skips agree with the address sequence.
func Test_AddrIterator_ScatteredMasks(t *testing.T) {
	for _, text := range []string{
		"10.0.0.0/255.255.255.250", "0.0.0.0/127.255.255.238",
		"2001:db8::/ffff:ffff:ffff:fffe:7fff:ffff:ffff:fffa",
		"::/7fff:ffff:ffff:fffe:ffff:ffff:ffff:fffe", "::ffff:192.0.2.0/126",
	} {
		t.Run(text, func(t *testing.T) {
			network := xnetip.MustParseNetwork(text)
			expected := slices.Collect(network.Addrs())
			for idx, address := range expected {
				cursor := network.AddrIterator()
				actual, ok := cursor.Nth(uint64(idx))
				require.True(t, ok)
				require.Equal(t, address, actual)
				size, exact := cursor.SizeHint()
				require.True(t, exact)
				require.Equal(t, uint64(len(expected)-idx-1), size)
				cursor = network.AddrIterator()
				actual, ok = cursor.NthBack(uint64(len(expected) - idx - 1))
				require.True(t, ok)
				require.Equal(t, address, actual)
			}
			cursor := network.AddrIterator()
			for first, last := 0, len(expected)-1; first <= last; {
				actual, ok := cursor.Next()
				require.True(t, ok)
				require.Equal(t, expected[first], actual)
				first++
				if first <= last {
					actual, ok = cursor.NextBack()
					require.True(t, ok)
					require.Equal(t, expected[last], actual)
					last--
				}
			}
			_, ok := cursor.Next()
			require.False(t, ok)
			_, ok = cursor.NthBack(0)
			require.False(t, ok)
		})
	}
}

// verifies that full-width counts and maximum skips do not wrap into reuse.
func Test_AddrIterator_FullWidth(t *testing.T) {
	cursor := xnetip.MustParseNetwork4("0.0.0.0/0").AddrIterator()
	size, exact := cursor.SizeHint()
	require.True(t, exact)
	require.Equal(t, uint64(1)<<32, size)
	address, ok := cursor.Nth((uint64(1) << 32) - 1)
	require.True(t, ok)
	require.Equal(t, netip.MustParseAddr("255.255.255.255"), address)
	_, ok = cursor.NextBack()
	require.False(t, ok)
	cursor = xnetip.MustParseNetwork6("::/64").AddrIterator()
	size, exact = cursor.SizeHint()
	require.False(t, exact)
	require.Equal(t, uint64(math.MaxUint64), size)
	address, ok = cursor.Next()
	require.True(t, ok)
	require.Equal(t, netip.MustParseAddr("::"), address)
	size, exact = cursor.SizeHint()
	require.True(t, exact)
	require.Equal(t, uint64(math.MaxUint64), size)
	address, ok = cursor.NthBack(math.MaxUint64 - 1)
	require.True(t, ok)
	require.Equal(t, netip.MustParseAddr("::1"), address)
	_, ok = cursor.Next()
	require.False(t, ok)
	cursor = xnetip.MustParseNetwork6("::/0").AddrIterator()
	address, ok = cursor.Nth(math.MaxUint64)
	require.True(t, ok)
	require.Equal(t, netip.MustParseAddr("::ffff:ffff:ffff:ffff"), address)
	address, ok = cursor.Next()
	require.True(t, ok)
	require.Equal(t, netip.MustParseAddr("0:0:0:1::"), address)
	_, exact = cursor.SizeHint()
	require.False(t, exact)
	cursor = xnetip.MustParseNetwork6("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/128").AddrIterator()
	_, ok = cursor.Nth(1)
	require.False(t, ok)
	_, ok = cursor.NextBack()
	require.False(t, ok)
}

// verifies that a maximum skip crosses a scattered gap without wrapping.
func Test_AddrIterator_MaximumScatteredSkip(t *testing.T) {
	network := xnetip.MustParseNetwork6("::/ffff:ffff:ffff:fffd::")
	cursor := network.AddrIterator()
	address, ok := cursor.Nth(math.MaxUint64)
	require.True(t, ok)
	require.Equal(t, netip.MustParseAddr("::ffff:ffff:ffff:ffff"), address)
	address, ok = cursor.Next()
	require.True(t, ok)
	require.Equal(t, netip.MustParseAddr("0:0:0:2::"), address)
	cursor = network.AddrIterator()
	address, ok = cursor.NthBack(math.MaxUint64)
	require.True(t, ok)
	require.Equal(t, netip.MustParseAddr("0:0:0:2::"), address)
	address, ok = cursor.NextBack()
	require.True(t, ok)
	require.Equal(t, netip.MustParseAddr("::ffff:ffff:ffff:ffff"), address)
}

// verifies that arbitrary masks support skipping from an already advanced end.
func Test_AddrIterator_NthMatchesSteppingProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		network := genNetwork.Draw(t, "network")
		skip := rapid.IntRange(0, 64).Draw(t, "skip")
		backward := rapid.Bool().Draw(t, "backward")
		cursor := network.AddrIterator()
		stepped := network.AddrIterator()
		for range 3 {
			if backward {
				cursor.NextBack()
				stepped.NextBack()
			} else {
				cursor.Next()
				stepped.Next()
			}
		}
		for range skip {
			if backward {
				stepped.NextBack()
			} else {
				stepped.Next()
			}
		}
		var expected, actual netip.Addr
		var expectedOK, actualOK bool
		if backward {
			expected, expectedOK = stepped.NextBack()
			actual, actualOK = cursor.NthBack(uint64(skip))
		} else {
			expected, expectedOK = stepped.Next()
			actual, actualOK = cursor.Nth(uint64(skip))
		}
		require.Equal(t, expectedOK, actualOK)
		require.Equal(t, expected, actual)
		expectedSize, expectedExact := stepped.SizeHint()
		actualSize, actualExact := cursor.SizeHint()
		require.Equal(t, expectedSize, actualSize)
		require.Equal(t, expectedExact, actualExact)
	})
}

// verifies that copying a cursor snapshots its independent remaining range.
func Test_AddrIterator_Copy(t *testing.T) {
	cursor := xnetip.MustParseNetwork4("192.0.2.0/24").AddrIterator()
	cursor.Next()
	snapshot := cursor
	first, ok := cursor.Next()
	require.True(t, ok)
	copied, ok := snapshot.Next()
	require.True(t, ok)
	require.Equal(t, first, copied)
	cursor.NextBack()
	size, exact := snapshot.SizeHint()
	require.True(t, exact)
	require.Equal(t, uint64(254), size)
}

// verifies that guarantee wrappers expose the same traversal and cursors.
func Test_AddrIterator_Wrappers(t *testing.T) {
	block := xnetip.MustParseContiguous4("192.0.2.0/29")
	require.Equal(t, slices.Collect(block.Network().Addrs()), slices.Collect(block.Addrs()))
	require.Equal(t, slices.Collect(block.Network().AddrsBackward()), slices.Collect(block.AddrsBackward()))
	cursor := block.AddrIterator()
	address, ok := cursor.Nth(7)
	require.True(t, ok)
	require.Equal(t, netip.MustParseAddr("192.0.2.7"), address)
	rectangle := xnetip.MustParseBiContiguous("::/ffff:ffff:ffff:fffe:ffff:ffff:ffff:fffe")
	cursor = rectangle.AddrIterator()
	address, ok = cursor.NthBack(0)
	require.True(t, ok)
	require.Equal(t, rectangle.Network().LastAddr(), address)
}

// verifies that mutable traversal, indexed skipping and CIDR streams allocate nothing.
func Test_AddrIterator_AllocationFree(t *testing.T) {
	network := xnetip.MustParseNetwork("::/ffff:ffff:ffff:fffe:ffff:ffff:ffff:fffa")
	block := xnetip.MustParseContiguous6("2001:db8::/120")
	requireNoAllocs(t, func() {
		cursor := network.AddrIterator()
		addrSink, okSink = cursor.Next()
		addrSink, okSink = cursor.NextBack()
		addrSink, okSink = cursor.Nth(1)
		addrSink, okSink = cursor.NthBack(1)
		for address := range block.Addrs() {
			addrSink = address
		}
		for address := range block.AddrsBackward() {
			addrSink = address
		}
	})
}

// verifies that mixed end and skip operations consume exactly the bounded interval.
func Test_AddrIterator_InterleavedProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		network := xnetip.MustParseNetwork("2001:db8::/ffff:ffff:ffff:fffe:ffff:ffff:ffff:fffa")
		expected := slices.Collect(network.Addrs())
		cursor := network.AddrIterator()
		first, last := 0, len(expected)-1
		for step := range 20 {
			backward := rapid.Bool().Draw(t, "backward")
			skip := rapid.IntRange(0, 3).Draw(t, "skip")
			var actual netip.Addr
			var ok bool
			if backward {
				actual, ok = cursor.NthBack(uint64(skip))
			} else {
				actual, ok = cursor.Nth(uint64(skip))
			}
			if skip > last-first {
				require.False(t, ok)
				first = last + 1
			} else {
				require.True(t, ok)
				if backward {
					last -= skip
					require.Equal(t, expected[last], actual)
					last--
				} else {
					first += skip
					require.Equal(t, expected[first], actual)
					first++
				}
			}
			size, exact := cursor.SizeHint()
			require.True(t, exact)
			require.Equal(t, uint64(max(last-first+1, 0)), size, "step %d", step)
		}
	})
}

func BenchmarkAddrIterator_NthCIDR(b *testing.B) {
	network := xnetip.MustParseNetwork6("2001:db8::/32")
	b.ReportAllocs()
	for b.Loop() {
		cursor := network.AddrIterator()
		addrSink, okSink = cursor.Nth(math.MaxUint64)
	}
}

func BenchmarkAddrIterator_NthScattered(b *testing.B) {
	network := xnetip.MustParseNetwork6("2001:db8::/aaaa:aaaa:aaaa:aaaa:aaaa:aaaa:aaaa:aaaa")
	b.ReportAllocs()
	for b.Loop() {
		cursor := network.AddrIterator()
		addrSink, okSink = cursor.Nth(math.MaxUint64)
	}
}

func BenchmarkAddrIterator_NextBothEnds(b *testing.B) {
	network := xnetip.MustParseNetwork6("2001:db8::/64")
	b.ReportAllocs()
	for b.Loop() {
		cursor := network.AddrIterator()
		addrSink, okSink = cursor.Next()
		addrSink, okSink = cursor.NextBack()
	}
}

// consumeContiguousAddresses measures a stream from a normal inlinable call site.
func consumeContiguousAddresses(block xnetip.Contiguous[xnetip.Network6]) {
	for address := range block.Addrs() {
		addrSink = address
	}
}

func BenchmarkContiguous_Addrs(b *testing.B) {
	block := xnetip.MustParseContiguous6("2001:db8::/120")
	b.ReportAllocs()
	for b.Loop() {
		consumeContiguousAddresses(block)
	}
}
