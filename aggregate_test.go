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

// verifies that aggregation collapses duplicates, containment and
// sibling chains of the reference table in place, element by element.
func Test_Aggregate4_UnitAndBoundary(t *testing.T) {
	cases := []struct {
		name     string
		input    []string
		expected []string
	}{
		{name: "empty slice", input: []string{}, expected: []string{}},
		{name: "single network", input: []string{"10.0.0.0/8"}, expected: []string{"10.0.0.0/8"}},
		{name: "duplicates", input: []string{"10.0.0.0/8", "10.0.0.0/8", "10.0.0.0/8"}, expected: []string{"10.0.0.0/8"}},
		{name: "nested containment", input: []string{"10.0.0.0/8", "10.1.0.0/16", "10.1.1.0/24"}, expected: []string{"10.0.0.0/8"}},
		{name: "sibling merge", input: []string{"192.168.0.0/24", "192.168.1.0/24"}, expected: []string{"192.168.0.0/23"}},
		{name: "cascading merge", input: []string{"192.168.0.0/24", "192.168.1.0/24", "192.168.2.0/24", "192.168.3.0/24"}, expected: []string{"192.168.0.0/22"}},
		{name: "non-adjacent pair kept", input: []string{"192.168.0.0/24", "192.168.3.0/24"}, expected: []string{"192.168.0.0/24", "192.168.3.0/24"}},
		{name: "containment and merge mixed", input: []string{"10.0.0.0/8", "10.1.0.0/16", "192.168.0.0/24", "192.168.1.0/24"}, expected: []string{"10.0.0.0/8", "192.168.0.0/23"}},
		{name: "already minimal keeps the sorted order", input: []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"}, expected: []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"}},
		{name: "reverse-sorted input collapses the same", input: []string{"192.168.3.0/24", "192.168.2.0/24", "192.168.1.0/24", "192.168.0.0/24"}, expected: []string{"192.168.0.0/22"}},
		{name: "doc example", input: []string{"192.168.0.0/24", "192.168.1.0/24", "10.0.0.0/8", "10.1.0.0/16"}, expected: []string{"10.0.0.0/8", "192.168.0.0/23"}},
		{name: "readme example", input: []string{"10.0.0.0/24", "10.0.1.0/24", "10.0.0.128/25"}, expected: []string{"10.0.0.0/23"}},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			nets := networks4FromStrings(testCase.input)
			result := xnetip.Aggregate4(nets)
			require.Equal(t, networks4FromStrings(testCase.expected), result)
			if len(result) > 0 {
				require.Same(t, &nets[0], &result[0])
			}
		})
	}
}

// verifies that non-contiguous masks aggregate through the full-stack
// scan and leave a deterministic but unsorted output.
//
// A merge partner may sit below the stack top, and a merge result may
// absorb an earlier survivor that sorted ahead of both inputs.
func Test_Aggregate4_NonContiguousMasks(t *testing.T) {
	cases := []struct {
		name     string
		input    []string
		expected []string
	}{
		{name: "container between siblings in sort order", input: []string{"10.0.0.1/255.0.0.255", "10.1.0.0/255.255.0.0", "10.2.0.1/255.255.0.255"}, expected: []string{"10.0.0.1/255.0.0.255", "10.1.0.0/255.255.0.0"}},
		{name: "merge result sorts before an earlier survivor and absorbs it", input: []string{"0.0.0.0/128.0.0.1", "0.0.0.0/128.0.0.2", "0.0.0.2/128.0.0.2"}, expected: []string{"0.0.0.0/128.0.0.0"}},
		{name: "same non-contiguous mask differing in one bit", input: []string{"10.0.0.1/255.0.0.255", "10.0.0.0/255.0.0.255"}, expected: []string{"10.0.0.0/255.0.0.254"}},
		{name: "merge at a non-boundary bit leaves the class", input: []string{"10.0.0.0/24", "10.0.2.0/24"}, expected: []string{"10.0.0.0/255.255.253.0"}},
		{name: "unsorted output pin", input: []string{"10.0.0.0/24", "10.0.1.0/25", "10.0.4.0/25", "10.0.4.128/25"}, expected: []string{"10.0.1.0/25", "10.0.0.0/255.255.251.0"}},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			nets := networks4FromStrings(testCase.input)
			require.Equal(t, networks4FromStrings(testCase.expected), xnetip.Aggregate4(nets))
		})
	}
}

// verifies that the 256 consecutive third-octet blocks collapse into
// the single enclosing network through cascading sibling merges.
func Test_Aggregate4_FullOctet(t *testing.T) {
	result := xnetip.Aggregate4(aggregate4FullOctet(t))
	require.Equal(t, []xnetip.Network4{xnetip.MustParseNetwork4("10.0.0.0/16")}, result)
}

// verifies that the address union of the result equals the address
// union of the input on a bounded contiguous window.
func Test_Aggregate4_PreservesAddressesProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		nets := genAggregateWindow4.Draw(t, "nets")
		before := ipv4Union(nets)
		require.Equal(t, before, ipv4Union(xnetip.Aggregate4(nets)))
	})
}

// verifies that the address union survives aggregation when the drawn
// masks have holes in the low byte.
func Test_Aggregate4_NonContiguousPreservesAddressesProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		nets := genAggregateNonContiguousWindow4.Draw(t, "nets")
		before := ipv4Union(nets)
		require.Equal(t, before, ipv4Union(xnetip.Aggregate4(nets)))
	})
}

// verifies that the result is a fixpoint: no duplicates, no survivor
// contains another and no pair merges.
func Test_Aggregate4_FixpointProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		result := xnetip.Aggregate4(genAggregateWindow4.Draw(t, "nets"))
		for left := range result {
			for right := range result {
				if left == right {
					continue
				}
				require.False(t, result[left].Contains(result[right]))
			}
		}
		for left := range result {
			for right := left + 1; right < len(result); right++ {
				require.NotEqual(t, result[left], result[right])
				_, ok := result[left].Merge(result[right])
				require.False(t, ok)
			}
		}
	})
}

// verifies that aggregating the result again only re-sorts it: a
// fixpoint has nothing left to merge.
func Test_Aggregate4_IdempotentProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		result := xnetip.Aggregate4(genAggregateWindow4.Draw(t, "nets"))
		expected := slices.Clone(result)
		slices.SortFunc(expected, xnetip.Network4.Compare)
		require.Equal(t, expected, xnetip.Aggregate4(slices.Clone(result)))
	})
}

// verifies that the result never outgrows the input and every
// survivor stays inside the input's address union.
//
// Each survivor is probed at its first, its last and one sampled
// interior address.
func Test_Aggregate4_SurvivorsWithinInputProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		nets := genAggregateWindow4.Draw(t, "nets")
		input := slices.Clone(nets)
		result := xnetip.Aggregate4(nets)
		require.LessOrEqual(t, len(result), len(input))
		for _, survivor := range result {
			addr, mask := ipv4NetworkBits(survivor)
			sampled := addr | rapid.Uint32().Draw(t, "interior")&^mask
			for _, probe := range []netip.Addr{survivor.Addr(), survivor.LastAddr(), netipAddrFrom4Bits(sampled)} {
				require.True(t, ipv4AnyContains(t, input, probe), "survivor address outside the input union")
			}
		}
	})
}

// verifies that the address union of the result does not depend on
// the input order, even though the survivor sequence may.
func Test_Aggregate4_UnionOrderIndependenceProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		nets := genAggregateWindow4.Draw(t, "nets")
		shuffled := slices.Clone(nets)
		for idx := len(shuffled) - 1; idx > 0; idx-- {
			other := rapid.IntRange(0, idx).Draw(t, "shuffle")
			shuffled[idx], shuffled[other] = shuffled[other], shuffled[idx]
		}
		require.Equal(t, ipv4Union(xnetip.Aggregate4(nets)), ipv4Union(xnetip.Aggregate4(shuffled)))
	})
}

// verifies that aggregation allocates nothing, on the merge-heavy
// full-octet fixture and on the never-merging host-route fixture.
func Test_Aggregate4_AllocationFree(t *testing.T) {
	merging := aggregate4FullOctet(t)
	inert := aggregate4NeverMerges(t, 256)
	workingMerging := make([]xnetip.Network4, len(merging))
	workingInert := make([]xnetip.Network4, len(inert))
	requireNoAllocs(t, func() {
		copy(workingMerging, merging)
		intSink = len(xnetip.Aggregate4(workingMerging))
	})
	requireNoAllocs(t, func() {
		copy(workingInert, inert)
		intSink = len(xnetip.Aggregate4(workingInert))
	})
}

// networks4FromStrings parses each element with the panicking parser,
// returning a non-nil slice so empty fixtures compare equal.
func networks4FromStrings(texts []string) []xnetip.Network4 {
	nets := make([]xnetip.Network4, len(texts))
	for idx, text := range texts {
		nets[idx] = xnetip.MustParseNetwork4(text)
	}
	return nets
}

// aggregate4FullOctet returns the 256 third-octet /24 blocks covering
// 10.0.0.0/16, the merge-heavy reference fixture.
func aggregate4FullOctet(t require.TestingT) []xnetip.Network4 {
	nets := make([]xnetip.Network4, 256)
	for idx := range nets {
		network, err := xnetip.Network4FromCIDR(netipAddrFrom4Bits(0x0A000000|uint32(idx)<<8), 24)
		require.NoError(t, err)
		nets[idx] = network
	}
	return nets
}

// aggregate4NeverMerges returns count host routes on even-popcount
// addresses, on which aggregation finds nothing to collapse.
//
// No two such addresses differ in a single bit and none contains
// another, so every candidate pays the full stack scan for nothing.
func aggregate4NeverMerges(t require.TestingT, count int) []xnetip.Network4 {
	nets := make([]xnetip.Network4, count)
	for idx := range nets {
		host := uint32(2 * idx)
		if bits.OnesCount32(host)%2 != 0 {
			host++
		}
		network, err := xnetip.Network4FromAddr(netipAddrFrom4Bits(0x0A000000 | host))
		require.NoError(t, err)
		nets[idx] = network
	}
	return nets
}

// ipv4NetworkAddresses lists every address of the network by spreading
// each host index over the mask's zero bits, low to high.
//
// It is a brute-force oracle: the caller keeps the drawn masks dense
// enough that the full enumeration stays cheap.
func ipv4NetworkAddresses(network xnetip.Network4) []uint32 {
	addr, mask := ipv4NetworkBits(network)
	free := ^mask
	count := uint32(1) << bits.OnesCount32(free)
	addresses := make([]uint32, 0, count)
	for host := range count {
		spread := uint32(0)
		remaining := host
		for bit := range 32 {
			if free&(1<<bit) != 0 {
				spread |= (remaining & 1) << bit
				remaining >>= 1
			}
		}
		addresses = append(addresses, addr|spread)
	}
	return addresses
}

// ipv4Union collects the distinct addresses of the networks, sorted
// ascending, so two unions compare with a single slice equality.
func ipv4Union(nets []xnetip.Network4) []uint32 {
	union := []uint32{}
	for _, network := range nets {
		union = append(union, ipv4NetworkAddresses(network)...)
	}
	slices.Sort(union)
	return slices.Compact(union)
}

// ipv4AnyContains reports whether any of the networks contains the
// address, probed through its host route.
func ipv4AnyContains(t require.TestingT, nets []xnetip.Network4, addr netip.Addr) bool {
	hostRoute, err := xnetip.Network4FromAddr(addr)
	require.NoError(t, err)
	for _, network := range nets {
		if network.Contains(hostRoute) {
			return true
		}
	}
	return false
}

// genAggregateWindow4 draws up to 32 contiguous blocks with prefixes
// 24 through 28 under 192.168.0.0/16, the reference window.
//
// The tight window makes containment and sibling merges frequent while
// keeping every block small enough for the brute-force union oracle.
var genAggregateWindow4 = rapid.SliceOfN(rapid.Custom(func(t *rapid.T) xnetip.Network4 {
	thirdOctet := rapid.Uint32Range(0, 255).Draw(t, "third octet")
	prefix := rapid.IntRange(24, 28).Draw(t, "prefix")
	network, err := xnetip.Network4FromCIDR(netipAddrFrom4Bits(0xC0A80000|thirdOctet<<8), prefix)
	require.NoError(t, err)
	return network
}), 1, 32)

// genAggregateNonContiguousWindow4 draws up to 8 networks whose masks
// keep the top three octets and hole the low byte arbitrarily.
var genAggregateNonContiguousWindow4 = rapid.SliceOfN(rapid.Custom(func(t *rapid.T) xnetip.Network4 {
	addrLow := rapid.Uint32Range(0, 255).Draw(t, "addr low byte")
	maskLow := rapid.Uint32Range(0, 255).Draw(t, "mask low byte")
	network, err := xnetip.Network4From(
		netipAddrFrom4Bits(0x0A000000|addrLow),
		netipAddrFrom4Bits(0xFFFFFF00|maskLow),
	)
	require.NoError(t, err)
	return network
}), 1, 8)

func BenchmarkAggregate4_256x24To16(b *testing.B) {
	template := aggregate4FullOctet(b)
	networks := make([]xnetip.Network4, len(template))
	b.ReportAllocs()
	for b.Loop() {
		copy(networks, template)
		intSink = len(xnetip.Aggregate4(networks))
	}
}

func BenchmarkAggregate4_1024Random20To28(b *testing.B) {
	// The fixture mirrors the Rust bench recipe: pseudo-random blocks
	// spread by a multiplicative walk, prefixes cycling over /20../28.
	template := make([]xnetip.Network4, 1024)
	for idx := range template {
		prefix := 20 + idx%9
		addr := 0x0A000000 | uint32(idx)*97%(1<<24)
		network, err := xnetip.Network4FromCIDR(netipAddrFrom4Bits(addr), prefix)
		if err != nil {
			b.Fatal(err)
		}
		template[idx] = network
	}
	networks := make([]xnetip.Network4, len(template))
	b.ReportAllocs()
	for b.Loop() {
		copy(networks, template)
		intSink = len(xnetip.Aggregate4(networks))
	}
}

func BenchmarkAggregate4_256xHostNeverMerges(b *testing.B) {
	template := aggregate4NeverMerges(b, 256)
	networks := make([]xnetip.Network4, len(template))
	b.ReportAllocs()
	for b.Loop() {
		copy(networks, template)
		intSink = len(xnetip.Aggregate4(networks))
	}
}

func BenchmarkAggregate4_1024xHostNeverMerges(b *testing.B) {
	template := aggregate4NeverMerges(b, 1024)
	networks := make([]xnetip.Network4, len(template))
	b.ReportAllocs()
	for b.Loop() {
		copy(networks, template)
		intSink = len(xnetip.Aggregate4(networks))
	}
}

func BenchmarkAggregate4_256NonContiguous(b *testing.B) {
	template := make([]xnetip.Network4, 256)
	for idx := range template {
		network, err := xnetip.Network4From(
			netipAddrFrom4Bits(0x0A000000|uint32(idx)),
			netipAddrFrom4Bits(0xFFFF00FF),
		)
		if err != nil {
			b.Fatal(err)
		}
		template[idx] = network
	}
	networks := make([]xnetip.Network4, len(template))
	b.ReportAllocs()
	for b.Loop() {
		copy(networks, template)
		intSink = len(xnetip.Aggregate4(networks))
	}
}

func BenchmarkAggregate4_CopyOnly256(b *testing.B) {
	template := aggregate4NeverMerges(b, 256)
	networks := make([]xnetip.Network4, len(template))
	b.ReportAllocs()
	for b.Loop() {
		copy(networks, template)
		intSink = len(networks)
	}
}

func BenchmarkAggregate4_CopyOnly1024(b *testing.B) {
	template := aggregate4NeverMerges(b, 1024)
	networks := make([]xnetip.Network4, len(template))
	b.ReportAllocs()
	for b.Loop() {
		copy(networks, template)
		intSink = len(networks)
	}
}

// verifies that aggregation collapses duplicates, containment and
// sibling chains of the reference table in place, element by element.
func Test_Aggregate6_UnitAndBoundary(t *testing.T) {
	cases := []struct {
		name     string
		input    []string
		expected []string
	}{
		{name: "empty slice", input: []string{}, expected: []string{}},
		{name: "single network", input: []string{"2001:db8::/32"}, expected: []string{"2001:db8::/32"}},
		{name: "duplicates", input: []string{"fe80::/10", "fe80::/10", "fe80::/10"}, expected: []string{"fe80::/10"}},
		{name: "nested containment", input: []string{"fe80::/10", "fe80::/64", "fe80::/96"}, expected: []string{"fe80::/10"}},
		{name: "sibling merge", input: []string{"2001:db8::/48", "2001:db8:1::/48"}, expected: []string{"2001:db8::/47"}},
		{name: "cascading merge", input: []string{"2001:db8::/50", "2001:db8:0:4000::/50", "2001:db8:0:8000::/50", "2001:db8:0:c000::/50"}, expected: []string{"2001:db8::/48"}},
		{name: "non-adjacent pair kept", input: []string{"2001:db8::/48", "2001:db8:3::/48"}, expected: []string{"2001:db8::/48", "2001:db8:3::/48"}},
		{name: "containment and merge mixed", input: []string{"fe80::/10", "fe80::/64", "2001:db8::/48", "2001:db8:1::/48"}, expected: []string{"2001:db8::/47", "fe80::/10"}},
		{name: "already minimal keeps the sorted order", input: []string{"2001:db8::/32", "fc00::/7", "fe80::/10"}, expected: []string{"2001:db8::/32", "fc00::/7", "fe80::/10"}},
		{name: "reverse-sorted input collapses the same", input: []string{"2001:db8:0:c000::/50", "2001:db8:0:8000::/50", "2001:db8:0:4000::/50", "2001:db8::/50"}, expected: []string{"2001:db8::/48"}},
		{name: "doc example", input: []string{"2001:db8::/48", "2001:db8:1::/48", "fe80::/10", "fe80::/64"}, expected: []string{"2001:db8::/47", "fe80::/10"}},
		{name: "host routes merging", input: []string{"::1/128", "::/128"}, expected: []string{"::/127"}},
		{name: "merge ending at the half boundary", input: []string{"2001:db8::/64", "2001:db8:0:1::/64"}, expected: []string{"2001:db8::/63"}},
		{name: "merge crossing the half boundary", input: []string{"2001:db8::/65", "2001:db8:0:0:8000::/65"}, expected: []string{"2001:db8::/64"}},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			nets := networks6FromStrings(testCase.input)
			result := xnetip.Aggregate6(nets)
			require.Equal(t, networks6FromStrings(testCase.expected), result)
			if len(result) > 0 {
				require.Same(t, &nets[0], &result[0])
			}
		})
	}
}

// verifies that non-contiguous masks aggregate through the full-stack
// scan and leave a deterministic but unsorted output.
//
// A merge partner may sit below the stack top, and a merge result may
// absorb an earlier survivor that sorted ahead of both inputs.
func Test_Aggregate6_NonContiguousMasks(t *testing.T) {
	cases := []struct {
		name     string
		input    []string
		expected []string
	}{
		{name: "container between siblings in sort order", input: []string{"2001:db8:a:0:0:1::/ffff:ffff:ffff:0:0:ffff::", "2001:db8:a:1::/ffff:ffff:ffff:ffff::", "2001:db8:a:2:0:1::/ffff:ffff:ffff:ffff:0:ffff::"}, expected: []string{"2001:db8:a:0:0:1::/ffff:ffff:ffff:0:0:ffff::", "2001:db8:a:1::/ffff:ffff:ffff:ffff::"}},
		{name: "merge result sorts before an earlier survivor and absorbs it", input: []string{"::/8000::1", "::/8000::2", "::2/8000::2"}, expected: []string{"::/8000::"}},
		{name: "same non-contiguous mask differing in one bit", input: []string{"2001:db8::1/ffff:ffff:ff00:0:ffff:ffff:0:ff", "2001:db8::/ffff:ffff:ff00:0:ffff:ffff:0:ff"}, expected: []string{"2001:db8::/ffff:ffff:ff00:0:ffff:ffff:0:fe"}},
		{name: "hole straddling bit 64 keeps the halves apart", input: []string{"2001:db8::/ffff:ffff:ffff:ffff:0:ffff:ffff:ffff", "2001:db8:0:1::/ffff:ffff:ffff:ffff:0:ffff:ffff:ffff"}, expected: []string{"2001:db8::/ffff:ffff:ffff:fffe:0:ffff:ffff:ffff"}},
		{name: "unsorted output pin", input: []string{"2001:db8::/120", "2001:db8::100/121", "2001:db8::400/121", "2001:db8::480/121"}, expected: []string{"2001:db8::100/121", "2001:db8::/ffff:ffff:ffff:ffff:ffff:ffff:ffff:fb00"}},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			nets := networks6FromStrings(testCase.input)
			require.Equal(t, networks6FromStrings(testCase.expected), xnetip.Aggregate6(nets))
		})
	}
}

// verifies that the 256 consecutive third-group blocks collapse into
// the single enclosing network through cascading sibling merges.
func Test_Aggregate6_FullBlock(t *testing.T) {
	result := xnetip.Aggregate6(aggregate6FullBlock(t))
	require.Equal(t, []xnetip.Network6{xnetip.MustParseNetwork6("2001:db8::/40")}, result)
}

// verifies that the address union of the result equals the address
// union of the input on a bounded contiguous window.
func Test_Aggregate6_PreservesAddressesProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		nets := genAggregateWindow6.Draw(t, "nets")
		before := ipv6Union(nets)
		require.Equal(t, before, ipv6Union(xnetip.Aggregate6(nets)))
	})
}

// verifies that the address union survives aggregation when the drawn
// masks have holes in the low byte.
func Test_Aggregate6_NonContiguousPreservesAddressesProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		nets := genAggregateNonContiguousWindow6.Draw(t, "nets")
		before := ipv6Union(nets)
		require.Equal(t, before, ipv6Union(xnetip.Aggregate6(nets)))
	})
}

// verifies that the result is a fixpoint: no duplicates, no survivor
// contains another and no pair merges.
func Test_Aggregate6_FixpointProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		result := xnetip.Aggregate6(genAggregateWindow6.Draw(t, "nets"))
		for left := range result {
			for right := range result {
				if left == right {
					continue
				}
				require.False(t, result[left].Contains(result[right]))
			}
		}
		for left := range result {
			for right := left + 1; right < len(result); right++ {
				require.NotEqual(t, result[left], result[right])
				_, ok := result[left].Merge(result[right])
				require.False(t, ok)
			}
		}
	})
}

// verifies that aggregating the result again only re-sorts it: a
// fixpoint has nothing left to merge.
func Test_Aggregate6_IdempotentProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		result := xnetip.Aggregate6(genAggregateWindow6.Draw(t, "nets"))
		expected := slices.Clone(result)
		slices.SortFunc(expected, xnetip.Network6.Compare)
		require.Equal(t, expected, xnetip.Aggregate6(slices.Clone(result)))
	})
}

// verifies that the result never outgrows the input and every
// survivor stays inside the input's address union.
//
// Each survivor is probed at its first, its last and one sampled
// interior address.
func Test_Aggregate6_SurvivorsWithinInputProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		nets := genAggregateWindow6.Draw(t, "nets")
		input := slices.Clone(nets)
		result := xnetip.Aggregate6(nets)
		require.LessOrEqual(t, len(result), len(input))
		for _, survivor := range result {
			addrHi, addrLo, maskHi, maskLo := ipv6NetworkBits(survivor)
			sampledHi := addrHi | rapid.Uint64().Draw(t, "interior hi")&^maskHi
			sampledLo := addrLo | rapid.Uint64().Draw(t, "interior lo")&^maskLo
			for _, probe := range []netip.Addr{survivor.Addr(), survivor.LastAddr(), netipAddrFrom6Bits(sampledHi, sampledLo)} {
				require.True(t, ipv6AnyContains(t, input, probe), "survivor address outside the input union")
			}
		}
	})
}

// verifies that the address union of the result does not depend on
// the input order, even though the survivor sequence may.
func Test_Aggregate6_UnionOrderIndependenceProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		nets := genAggregateWindow6.Draw(t, "nets")
		shuffled := slices.Clone(nets)
		for idx := len(shuffled) - 1; idx > 0; idx-- {
			other := rapid.IntRange(0, idx).Draw(t, "shuffle")
			shuffled[idx], shuffled[other] = shuffled[other], shuffled[idx]
		}
		require.Equal(t, ipv6Union(xnetip.Aggregate6(nets)), ipv6Union(xnetip.Aggregate6(shuffled)))
	})
}

// verifies that both kernels behave identically at both word widths:
// aggregating IPv4-mapped images gives the mapped IPv4 result.
//
// The mapped mask pins the 96 leading bits, so every comparison and
// merge decision reduces to the low 32 bits, mirroring the IPv4 run
// element by element.
func Test_Aggregate6_MappedParityWithAggregate4Property(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		nets := rapid.SliceOfN(genNetwork4, 1, 16).Draw(t, "nets")
		images := make([]xnetip.Network6, len(nets))
		for idx, network := range nets {
			images[idx] = network.ToIPv6Mapped()
		}
		expected := xnetip.Aggregate4(nets)
		result := xnetip.Aggregate6(images)
		require.Len(t, result, len(expected))
		for idx, survivor := range result {
			back, ok := survivor.ToIPv4Mapped()
			require.True(t, ok, "mapped survivor left the IPv4-mapped form")
			require.Equal(t, expected[idx], back)
		}
	})
}

// verifies that aggregation allocates nothing, on the merge-heavy
// full-block fixture and on the never-merging host-route fixture.
func Test_Aggregate6_AllocationFree(t *testing.T) {
	merging := aggregate6FullBlock(t)
	inert := aggregate6NeverMerges(t, 256)
	workingMerging := make([]xnetip.Network6, len(merging))
	workingInert := make([]xnetip.Network6, len(inert))
	requireNoAllocs(t, func() {
		copy(workingMerging, merging)
		intSink = len(xnetip.Aggregate6(workingMerging))
	})
	requireNoAllocs(t, func() {
		copy(workingInert, inert)
		intSink = len(xnetip.Aggregate6(workingInert))
	})
}

// networks6FromStrings parses each element with the panicking parser,
// returning a non-nil slice so empty fixtures compare equal.
func networks6FromStrings(texts []string) []xnetip.Network6 {
	nets := make([]xnetip.Network6, len(texts))
	for idx, text := range texts {
		nets[idx] = xnetip.MustParseNetwork6(text)
	}
	return nets
}

// aggregate6FullBlock returns the 256 third-group /48 blocks covering
// 2001:db8::/40, the merge-heavy reference fixture.
func aggregate6FullBlock(t require.TestingT) []xnetip.Network6 {
	nets := make([]xnetip.Network6, 256)
	for idx := range nets {
		network, err := xnetip.Network6FromCIDR(netipAddrFrom6Bits(0x20010DB800000000|uint64(idx)<<16, 0), 48)
		require.NoError(t, err)
		nets[idx] = network
	}
	return nets
}

// aggregate6NeverMerges returns count host routes on even-popcount
// addresses, on which aggregation finds nothing to collapse.
//
// No two such addresses differ in a single bit and none contains
// another, so every candidate pays the full stack scan for nothing.
func aggregate6NeverMerges(t require.TestingT, count int) []xnetip.Network6 {
	nets := make([]xnetip.Network6, count)
	for idx := range nets {
		host := uint64(2 * idx)
		if bits.OnesCount64(host)%2 != 0 {
			host++
		}
		network, err := xnetip.Network6FromAddr(netipAddrFrom6Bits(0x20010DB800000000, host))
		require.NoError(t, err)
		nets[idx] = network
	}
	return nets
}

// ipv6NetworkAddresses lists every address of the network by spreading
// each host index over the mask's zero bits, low to high.
//
// It is a brute-force oracle: the caller keeps the drawn masks dense
// enough that the full enumeration stays cheap.
func ipv6NetworkAddresses(network xnetip.Network6) []netip.Addr {
	addrHi, addrLo, maskHi, maskLo := ipv6NetworkBits(network)
	freeHi, freeLo := ^maskHi, ^maskLo
	count := 1 << (bits.OnesCount64(freeHi) + bits.OnesCount64(freeLo))
	addresses := make([]netip.Addr, 0, count)
	for host := range count {
		spreadHi, spreadLo := uint64(0), uint64(0)
		remaining := uint64(host)
		for bit := range 64 {
			if freeLo&(1<<bit) != 0 {
				spreadLo |= (remaining & 1) << bit
				remaining >>= 1
			}
		}
		for bit := range 64 {
			if freeHi&(1<<bit) != 0 {
				spreadHi |= (remaining & 1) << bit
				remaining >>= 1
			}
		}
		addresses = append(addresses, netipAddrFrom6Bits(addrHi|spreadHi, addrLo|spreadLo))
	}
	return addresses
}

// ipv6Union collects the distinct addresses of the networks, sorted
// ascending, so two unions compare with a single slice equality.
func ipv6Union(nets []xnetip.Network6) []netip.Addr {
	union := []netip.Addr{}
	for _, network := range nets {
		union = append(union, ipv6NetworkAddresses(network)...)
	}
	slices.SortFunc(union, netip.Addr.Compare)
	return slices.Compact(union)
}

// ipv6AnyContains reports whether any of the networks contains the
// address, probed through its host route.
func ipv6AnyContains(t require.TestingT, nets []xnetip.Network6, addr netip.Addr) bool {
	hostRoute, err := xnetip.Network6FromAddr(addr)
	require.NoError(t, err)
	for _, network := range nets {
		if network.Contains(hostRoute) {
			return true
		}
	}
	return false
}

// genAggregateWindow6 draws up to 32 contiguous blocks with prefixes
// 120 through 124 under 2001:db8::/112, the reference window.
//
// The tight window makes containment and sibling merges frequent while
// keeping every block small enough for the brute-force union oracle.
var genAggregateWindow6 = rapid.SliceOfN(rapid.Custom(func(t *rapid.T) xnetip.Network6 {
	blockByte := rapid.Uint64Range(0, 255).Draw(t, "block byte")
	prefix := rapid.IntRange(120, 124).Draw(t, "prefix")
	network, err := xnetip.Network6FromCIDR(netipAddrFrom6Bits(0x20010DB800000000, blockByte<<8), prefix)
	require.NoError(t, err)
	return network
}), 1, 32)

// genAggregateNonContiguousWindow6 draws up to 8 networks whose masks
// keep everything above the low byte and hole the low byte arbitrarily.
var genAggregateNonContiguousWindow6 = rapid.SliceOfN(rapid.Custom(func(t *rapid.T) xnetip.Network6 {
	addrLow := rapid.Uint64Range(0, 255).Draw(t, "addr low byte")
	maskLow := rapid.Uint64Range(0, 255).Draw(t, "mask low byte")
	network, err := xnetip.Network6From(
		netipAddrFrom6Bits(0x20010DB800000000, addrLow),
		netipAddrFrom6Bits(^uint64(0), 0xFFFFFFFFFFFFFF00|maskLow),
	)
	require.NoError(t, err)
	return network
}), 1, 8)

func BenchmarkAggregate6_256x48To40(b *testing.B) {
	template := aggregate6FullBlock(b)
	networks := make([]xnetip.Network6, len(template))
	b.ReportAllocs()
	for b.Loop() {
		copy(networks, template)
		intSink = len(xnetip.Aggregate6(networks))
	}
}

func BenchmarkAggregate6_1024Random116To124(b *testing.B) {
	// The fixture mirrors the IPv4 recipe: a multiplicative walk of
	// pseudo-random blocks, prefixes cycling over /116../124.
	template := make([]xnetip.Network6, 1024)
	for idx := range template {
		prefix := 116 + idx%9
		low := uint64(idx) * 97 % (1 << 24)
		network, err := xnetip.Network6FromCIDR(netipAddrFrom6Bits(0x20010DB800000000, low), prefix)
		if err != nil {
			b.Fatal(err)
		}
		template[idx] = network
	}
	networks := make([]xnetip.Network6, len(template))
	b.ReportAllocs()
	for b.Loop() {
		copy(networks, template)
		intSink = len(xnetip.Aggregate6(networks))
	}
}

func BenchmarkAggregate6_256xHostNeverMerges(b *testing.B) {
	template := aggregate6NeverMerges(b, 256)
	networks := make([]xnetip.Network6, len(template))
	b.ReportAllocs()
	for b.Loop() {
		copy(networks, template)
		intSink = len(xnetip.Aggregate6(networks))
	}
}

func BenchmarkAggregate6_1024xHostNeverMerges(b *testing.B) {
	template := aggregate6NeverMerges(b, 1024)
	networks := make([]xnetip.Network6, len(template))
	b.ReportAllocs()
	for b.Loop() {
		copy(networks, template)
		intSink = len(xnetip.Aggregate6(networks))
	}
}

func BenchmarkAggregate6_256NonContiguous(b *testing.B) {
	template := make([]xnetip.Network6, 256)
	for idx := range template {
		network, err := xnetip.Network6From(
			netipAddrFrom6Bits(0x20010DB800000000, uint64(idx)),
			netipAddrFrom6Bits(0xFFFFFFFFFF00FFFF, ^uint64(0)),
		)
		if err != nil {
			b.Fatal(err)
		}
		template[idx] = network
	}
	networks := make([]xnetip.Network6, len(template))
	b.ReportAllocs()
	for b.Loop() {
		copy(networks, template)
		intSink = len(xnetip.Aggregate6(networks))
	}
}

func BenchmarkAggregate6_CopyOnly256(b *testing.B) {
	template := aggregate6NeverMerges(b, 256)
	networks := make([]xnetip.Network6, len(template))
	b.ReportAllocs()
	for b.Loop() {
		copy(networks, template)
		intSink = len(networks)
	}
}

func BenchmarkAggregate6_CopyOnly1024(b *testing.B) {
	template := aggregate6NeverMerges(b, 1024)
	networks := make([]xnetip.Network6, len(template))
	b.ReportAllocs()
	for b.Loop() {
		copy(networks, template)
		intSink = len(networks)
	}
}
