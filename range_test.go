package xnetip_test

import (
	"math/bits"
	"net/netip"
	"slices"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/yanet-platform/xnetip"
	"pgregory.net/rapid"
)

// verifies that an aligned block collapses to its single CIDR.
func Test_RangeToNetworks4_SingleAlignedBlock(t *testing.T) {
	blocks := collectIPv4Range("10.0.0.0", "10.0.0.255")
	require.Equal(t, []xnetip.Network4{xnetip.MustParseNetwork4("10.0.0.0/24")}, blocks)
}

// collectIPv4Range collects the cover of a range given as addresses
// in string form.
func collectIPv4Range(first, last string) []xnetip.Network4 {
	return slices.Collect(xnetip.RangeToNetworks4(netip.MustParseAddr(first), netip.MustParseAddr(last)))
}

// verifies the textbook decomposition of the interior of a /24: 14
// blocks growing to the middle and shrinking after it.
func Test_RangeToNetworks4_ClassicMisaligned(t *testing.T) {
	expectedTexts := []string{
		"0.0.0.1/32", "0.0.0.2/31", "0.0.0.4/30", "0.0.0.8/29",
		"0.0.0.16/28", "0.0.0.32/27", "0.0.0.64/26", "0.0.0.128/26",
		"0.0.0.192/27", "0.0.0.224/28", "0.0.0.240/29", "0.0.0.248/30",
		"0.0.0.252/31", "0.0.0.254/32",
	}
	expected := []xnetip.Network4{}
	for _, text := range expectedTexts {
		expected = append(expected, xnetip.MustParseNetwork4(text))
	}
	require.Equal(t, expected, collectIPv4Range("0.0.0.1", "0.0.0.254"))
}

// verifies that the full address space is covered by the default
// route alone.
func Test_RangeToNetworks4_FullRange(t *testing.T) {
	blocks := collectIPv4Range("0.0.0.0", "255.255.255.255")
	require.Equal(t, []xnetip.Network4{xnetip.MustParseNetwork4("0.0.0.0/0")}, blocks)
}

// verifies the single host at the top of the address space.
func Test_RangeToNetworks4_SingleHostAtMax(t *testing.T) {
	blocks := collectIPv4Range("255.255.255.255", "255.255.255.255")
	require.Equal(t, []xnetip.Network4{xnetip.MustParseNetwork4("255.255.255.255/32")}, blocks)
}

// verifies that a one-address interval is its host route.
func Test_RangeToNetworks4_SingleHost(t *testing.T) {
	blocks := collectIPv4Range("10.0.0.5", "10.0.0.5")
	require.Equal(t, []xnetip.Network4{xnetip.MustParseNetwork4("10.0.0.5/32")}, blocks)
}

// verifies that a reversed interval yields an empty sequence and no
// error.
func Test_RangeToNetworks4_ReversedIsEmpty(t *testing.T) {
	require.Empty(t, collectIPv4Range("10.0.0.10", "10.0.0.5"))
}

// verifies the totality rule on foreign or invalid ends.
//
// An IPv6 end, an IPv4-mapped end (Is6 in netip) and the invalid
// zero address all bound an interval holding no IPv4 addresses, so
// the sequence is empty like a reversed one.
func Test_RangeToNetworks4_ForeignEndsYieldEmpty(t *testing.T) {
	cases := []struct {
		name  string
		first netip.Addr
		last  netip.Addr
	}{
		{name: "IPv6 first end", first: netip.MustParseAddr("2001:db8::1"), last: netip.MustParseAddr("10.0.0.5")},
		{name: "IPv6 last end", first: netip.MustParseAddr("10.0.0.5"), last: netip.MustParseAddr("2001:db8::1")},
		{name: "mapped first end", first: netip.MustParseAddr("::ffff:10.0.0.1"), last: netip.MustParseAddr("10.0.0.5")},
		{name: "invalid first end", first: netip.Addr{}, last: netip.MustParseAddr("10.0.0.5")},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			require.Empty(t, slices.Collect(xnetip.RangeToNetworks4(testCase.first, testCase.last)))
		})
	}
}

// verifies that an interval ending at the address-space maximum does
// not overflow the walk.
func Test_RangeToNetworks4_EndsAtMax(t *testing.T) {
	blocks := collectIPv4Range("255.255.255.254", "255.255.255.255")
	require.Equal(t, []xnetip.Network4{xnetip.MustParseNetwork4("255.255.255.254/31")}, blocks)
}

// verifies a small misaligned interval block by block.
func Test_RangeToNetworks4_SmallMisaligned(t *testing.T) {
	expected := []xnetip.Network4{
		xnetip.MustParseNetwork4("10.0.0.1/32"),
		xnetip.MustParseNetwork4("10.0.0.2/31"),
		xnetip.MustParseNetwork4("10.0.0.4/31"),
		xnetip.MustParseNetwork4("10.0.0.6/32"),
	}
	require.Equal(t, expected, collectIPv4Range("10.0.0.1", "10.0.0.6"))
}

// verifies an interval crossing a /24 boundary block by block: the
// phases meet at the highest differing bit.
func Test_RangeToNetworks4_CrossesBlockBoundary(t *testing.T) {
	expectedTexts := []string{
		"192.168.0.5/32", "192.168.0.6/31", "192.168.0.8/29",
		"192.168.0.16/28", "192.168.0.32/27", "192.168.0.64/26",
		"192.168.0.128/25", "192.168.1.0/29", "192.168.1.8/31",
		"192.168.1.10/32",
	}
	expected := []xnetip.Network4{}
	for _, text := range expectedTexts {
		expected = append(expected, xnetip.MustParseNetwork4(text))
	}
	require.Equal(t, expected, collectIPv4Range("192.168.0.5", "192.168.1.10"))
}

// verifies the documented worst case: both ends misaligned in every
// bit yield the 2 times 32 minus 2 block maximum.
func Test_RangeToNetworks4_WorstCaseCount(t *testing.T) {
	require.Len(t, collectIPv4Range("0.0.0.1", "255.255.255.254"), 62)
}

// verifies on edge intervals that every block satisfies the network
// invariant of a zero address outside the mask.
//
// The walk constructs blocks directly instead of going through a
// normalizing constructor, relying on the cursor being aligned to
// each block, so the invariant is pinned here.
func Test_RangeToNetworks4_NormalizedEdgeCases(t *testing.T) {
	cases := [][2]uint32{
		{0, ^uint32(0)},
		{0, 0},
		{^uint32(0), ^uint32(0)},
		{1, ^uint32(0) - 1},
		{0x12345678, 0x12345678},
	}
	for _, interval := range cases {
		sequence := xnetip.RangeToNetworks4(
			netipAddrFrom4Bits(interval[0]),
			netipAddrFrom4Bits(interval[1]),
		)
		for block := range sequence {
			addr, mask := ipv4NetworkBits(block)
			require.Equal(t, addr&mask, addr, "block %v not normalized", block)
		}
	}
}

// verifies that breaking out of the loop stops the sequence after
// exactly the consumed items.
func Test_RangeToNetworks4_EarlyBreakStops(t *testing.T) {
	sequence := xnetip.RangeToNetworks4(
		netipAddrFrom4Bits(1),
		netipAddrFrom4Bits(^uint32(0)-1),
	)
	consumed := 0
	for range sequence {
		consumed++
		if consumed == 3 {
			break
		}
	}
	require.Equal(t, 3, consumed)
}

// verifies that the cover abuts the interval exactly.
//
// The blocks are contiguous CIDRs, each starting where the previous
// one ended, the first at the start and the last at the end of the
// interval.
func Test_RangeToNetworks4_CoversExactlyProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		a := rapid.Uint32().Draw(t, "a")
		b := rapid.Uint32().Draw(t, "b")
		first, last := min(a, b), max(a, b)
		blocks := slices.Collect(xnetip.RangeToNetworks4(netipAddrFrom4Bits(first), netipAddrFrom4Bits(last)))
		require.NotEmpty(t, blocks)
		require.LessOrEqual(t, len(blocks), 62)
		cursor := first
		for idx, block := range blocks {
			addr, mask := ipv4NetworkBits(block)
			require.Equal(t, addr&mask, addr, "block %v not normalized", block)
			require.True(t, block.IsContiguous(), "block %v not contiguous", block)
			require.Equal(t, cursor, addr, "block %v does not abut the cursor", block)
			end := addr | ^mask
			if idx+1 < len(blocks) {
				require.Less(t, end, ^uint32(0))
				cursor = end + 1
			} else {
				require.Equal(t, last, end, "last block does not end the interval")
			}
		}
	})
}

// verifies that reversed random intervals yield an empty sequence.
func Test_RangeToNetworks4_EmptyWhenReversedProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		a := rapid.Uint32().Draw(t, "a")
		b := rapid.Uint32().Draw(t, "b")
		if a <= b {
			return
		}
		require.Empty(t, slices.Collect(xnetip.RangeToNetworks4(netipAddrFrom4Bits(a), netipAddrFrom4Bits(b))))
	})
}

// rangeToNetworks4Reference is the greedy reference oracle: the
// largest block aligned at the cursor and not exceeding the end.
//
// Blocks come back as address and mask word pairs.
func rangeToNetworks4Reference(first, last uint32) [][2]uint32 {
	out := [][2]uint32{}
	if first > last {
		return out
	}
	for {
		size := uint64(last) - uint64(first) + 1
		sizeLog := 63 - bits.LeadingZeros64(size)
		align := 32
		if first != 0 {
			align = bits.TrailingZeros32(first)
		}
		exponent := min(sizeLog, align)
		blockMax := ^uint32(0)
		if exponent < 32 {
			blockMax = 1<<exponent - 1
		}
		end := first + blockMax
		out = append(out, [2]uint32{first, ^blockMax})
		if end == last {
			return out
		}
		first = end + 1
	}
}

// requireIPv4RangeMatchesReference collects the cover of a word
// interval and compares it block by block against the greedy oracle.
func requireIPv4RangeMatchesReference(t require.TestingT, first, last uint32) {
	if helper, ok := t.(interface{ Helper() }); ok {
		helper.Helper()
	}
	got := [][2]uint32{}
	for block := range xnetip.RangeToNetworks4(netipAddrFrom4Bits(first), netipAddrFrom4Bits(last)) {
		addr, mask := ipv4NetworkBits(block)
		got = append(got, [2]uint32{addr, mask})
	}
	require.Equal(t, rangeToNetworks4Reference(first, last), got, "first=%#x last=%#x", first, last)
}

// verifies the walk against the greedy oracle on random raw pairs in
// both orders, reversed (empty) intervals included.
func Test_RangeToNetworks4_MatchesReferenceProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		requireIPv4RangeMatchesReference(
			t,
			rapid.Uint32().Draw(t, "first"),
			rapid.Uint32().Draw(t, "last"),
		)
	})
}

// verifies the oracle agreement on exact CIDR blocks of every size,
// the single-step ranges the greedy cover collapses.
func Test_RangeToNetworks4_MatchesReferenceSingleBlockProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		addr := rapid.Uint32().Draw(t, "addr")
		prefix := rapid.IntRange(0, 32).Draw(t, "prefix")
		mask := uint32(0)
		if prefix > 0 {
			mask = ^uint32(0) << (32 - prefix)
		}
		requireIPv4RangeMatchesReference(t, addr&mask, addr&mask|^mask)
	})
}

// verifies the oracle agreement with one aligned endpoint and one
// arbitrary endpoint, the covers where a single phase dominates.
func Test_RangeToNetworks4_MatchesReferenceAlignedEdgeProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		a := rapid.Uint32().Draw(t, "a")
		b := rapid.Uint32().Draw(t, "b")
		prefix := rapid.IntRange(0, 32).Draw(t, "prefix")
		mask := uint32(0)
		if prefix > 0 {
			mask = ^uint32(0) << (32 - prefix)
		}
		requireIPv4RangeMatchesReference(t, a&mask, b)
		requireIPv4RangeMatchesReference(t, a, b|^mask)
	})
}

// verifies the walk against the greedy oracle exhaustively over
// windows hitting every phase shape.
//
// The windows cover intervals touching zero, crossing the top-bit
// boundary and touching the address-space maximum, reversed pairs
// included.
func Test_RangeToNetworks4_MatchesReferenceExhaustiveWindows(t *testing.T) {
	windows := [][2]uint32{
		{0, 300},
		{0x7fffff80, 0x8000007f},
		{^uint32(0) - 300, ^uint32(0)},
	}
	for _, window := range windows {
		for first := window[0]; first <= window[1] && first >= window[0]; first++ {
			for last := window[0]; last <= window[1] && last >= window[0]; last++ {
				requireIPv4RangeMatchesReference(t, first, last)
			}
		}
	}
}

// verifies the union by brute force on small intervals: every
// address is covered by exactly one block, none outside.
func Test_RangeToNetworks4_UnionBruteForceProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		first := rapid.Uint32Range(0, ^uint32(0)-4096).Draw(t, "first")
		last := first + rapid.Uint32Range(0, 4096).Draw(t, "span")
		blocks := slices.Collect(xnetip.RangeToNetworks4(netipAddrFrom4Bits(first), netipAddrFrom4Bits(last)))
		for address := first; ; address++ {
			covering := 0
			for _, block := range blocks {
				addr, mask := ipv4NetworkBits(block)
				if address&mask == addr {
					covering++
				}
			}
			require.Equal(t, 1, covering, "address %#x covered %d times", address, covering)
			if address == last {
				break
			}
		}
		for _, block := range blocks {
			addr, mask := ipv4NetworkBits(block)
			require.GreaterOrEqual(t, addr, first)
			require.LessOrEqual(t, addr|^mask, last)
		}
	})
}

// verifies against net/netip that every block is a valid masked
// prefix.
//
// The prefix built from the block's address and length comes back
// unchanged from Masked, pinning the alignment against std.
func Test_RangeToNetworks4_BlocksRoundTripNetipPrefixProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		a := rapid.Uint32().Draw(t, "a")
		b := rapid.Uint32().Draw(t, "b")
		sequence := xnetip.RangeToNetworks4(
			netipAddrFrom4Bits(min(a, b)),
			netipAddrFrom4Bits(max(a, b)),
		)
		for block := range sequence {
			length, ok := block.PrefixLen()
			require.True(t, ok, "block %v has no prefix length", block)
			prefix := netip.PrefixFrom(block.Addr(), length)
			require.Equal(t, prefix, prefix.Masked(), "block %v not aligned", block)
		}
	})
}

// verifies that consuming the sequence with a range loop allocates
// nothing.
func Test_RangeToNetworks4_AllocationFree(t *testing.T) {
	first := netipAddrFrom4Bits(1)
	last := netipAddrFrom4Bits(^uint32(0) - 1)
	requireNoAllocs(t, func() {
		for block := range xnetip.RangeToNetworks4(first, last) {
			networkSink = block
		}
	})
}

func BenchmarkRangeToNetworks4_MisalignedWorstCase(b *testing.B) {
	first := netipAddrFrom4Bits(1)
	last := netipAddrFrom4Bits(^uint32(0) - 1)
	b.ReportAllocs()
	for b.Loop() {
		for block := range xnetip.RangeToNetworks4(first, last) {
			networkSink = block
		}
	}
}

func BenchmarkRangeToNetworks4_ClassicMisaligned(b *testing.B) {
	first := netip.MustParseAddr("0.0.0.1")
	last := netip.MustParseAddr("0.0.0.254")
	b.ReportAllocs()
	for b.Loop() {
		for block := range xnetip.RangeToNetworks4(first, last) {
			networkSink = block
		}
	}
}

func BenchmarkRangeToNetworks4_AlignedSingleBlock(b *testing.B) {
	first := netip.MustParseAddr("10.0.0.0")
	last := netip.MustParseAddr("10.255.255.255")
	b.ReportAllocs()
	for b.Loop() {
		for block := range xnetip.RangeToNetworks4(first, last) {
			networkSink = block
		}
	}
}
