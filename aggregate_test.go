package xnetip_test

import (
	"encoding/binary"
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

// verifies that the typed aggregation collapses the reference table
// into the minimal sorted CIDR cover, element by element and in place.
func Test_AggregateContiguous_IPv4UnitAndBoundary(t *testing.T) {
	cases := []struct {
		name     string
		input    []string
		expected []string
	}{
		{name: "empty slice", input: []string{}, expected: []string{}},
		{name: "single block", input: []string{"10.0.0.0/8"}, expected: []string{"10.0.0.0/8"}},
		{name: "duplicates", input: []string{"10.0.0.0/8", "10.0.0.0/8", "10.0.0.0/8"}, expected: []string{"10.0.0.0/8"}},
		{name: "containment", input: []string{"10.0.0.0/8", "10.1.0.0/16", "10.1.1.0/24"}, expected: []string{"10.0.0.0/8"}},
		{name: "single buddy merge", input: []string{"192.168.0.0/24", "192.168.1.0/24"}, expected: []string{"192.168.0.0/23"}},
		{name: "multi-level cascade", input: []string{"192.168.0.0/24", "192.168.1.0/24", "192.168.2.0/24", "192.168.3.0/24"}, expected: []string{"192.168.0.0/22"}},
		{name: "non-adjacent blocks survive", input: []string{"192.168.0.0/24", "192.168.3.0/24"}, expected: []string{"192.168.0.0/24", "192.168.3.0/24"}},
		{name: "non-buddy neighbours the general merge would fuse", input: []string{"10.0.0.0/24", "10.0.2.0/24"}, expected: []string{"10.0.0.0/24", "10.0.2.0/24"}},
		{name: "already minimal keeps the sorted order", input: []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"}, expected: []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"}},
		{name: "doc example", input: []string{"192.168.0.0/24", "192.168.1.0/24", "10.0.0.0/8", "10.1.0.0/16"}, expected: []string{"10.0.0.0/8", "192.168.0.0/23"}},
		{name: "mixed containment and merge", input: []string{"10.0.0.0/8", "10.1.0.0/16", "192.168.0.0/24", "192.168.1.0/24"}, expected: []string{"10.0.0.0/8", "192.168.0.0/23"}},
		{name: "default route absorbs everything", input: []string{"10.0.0.0/8", "0.0.0.0/0", "192.168.1.0/24"}, expected: []string{"0.0.0.0/0"}},
		{name: "host route buddies merge", input: []string{"10.0.0.0/32", "10.0.0.1/32"}, expected: []string{"10.0.0.0/31"}},
		{name: "non-adjacent host routes survive", input: []string{"10.0.0.0/32", "10.0.0.2/32"}, expected: []string{"10.0.0.0/32", "10.0.0.2/32"}},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			nets := contiguous4FromStrings(testCase.input)
			result := xnetip.AggregateContiguous(nets)
			require.Equal(t, contiguous4FromStrings(testCase.expected), result)
			if len(result) > 0 {
				require.Same(t, &nets[0], &result[0])
			}
		})
	}
}

// verifies that the typed aggregation collapses the reference table
// into the minimal sorted CIDR cover, element by element and in place.
func Test_AggregateContiguous_IPv6UnitAndBoundary(t *testing.T) {
	cases := []struct {
		name     string
		input    []string
		expected []string
	}{
		{name: "empty slice", input: []string{}, expected: []string{}},
		{name: "single block", input: []string{"2001:db8::/32"}, expected: []string{"2001:db8::/32"}},
		{name: "duplicates", input: []string{"2001:db8::/32", "2001:db8::/32", "2001:db8::/32"}, expected: []string{"2001:db8::/32"}},
		{name: "containment", input: []string{"2001:db8::/32", "2001:db8::/48", "2001:db8:0:1::/64"}, expected: []string{"2001:db8::/32"}},
		{name: "single buddy merge", input: []string{"2001:db8::/48", "2001:db8:1::/48"}, expected: []string{"2001:db8::/47"}},
		{name: "multi-level cascade", input: []string{"2001:db8:0:0::/64", "2001:db8:0:1::/64", "2001:db8:0:2::/64", "2001:db8:0:3::/64"}, expected: []string{"2001:db8::/62"}},
		{name: "cascade across bit 64", input: []string{"2001:db8::/66", "2001:db8:0:0:4000::/66", "2001:db8:0:0:8000::/66", "2001:db8:0:0:c000::/66"}, expected: []string{"2001:db8::/64"}},
		{name: "non-adjacent blocks survive", input: []string{"2001:db8:0:0::/64", "2001:db8:0:3::/64"}, expected: []string{"2001:db8:0:0::/64", "2001:db8:0:3::/64"}},
		{name: "non-buddy neighbours the general merge would fuse", input: []string{"2001:db8:0:0::/64", "2001:db8:0:2::/64"}, expected: []string{"2001:db8:0:0::/64", "2001:db8:0:2::/64"}},
		{name: "already minimal keeps the sorted order", input: []string{"2001:db8::/32", "2001:dba::/32", "fe80::/10"}, expected: []string{"2001:db8::/32", "2001:dba::/32", "fe80::/10"}},
		{name: "mixed containment and merge", input: []string{"fe80::/10", "fe80::/64", "2001:db8::/48", "2001:db8:1::/48"}, expected: []string{"2001:db8::/47", "fe80::/10"}},
		{name: "default route absorbs everything", input: []string{"2001:db8::/32", "::/0", "fe80::/10"}, expected: []string{"::/0"}},
		{name: "host route buddies merge", input: []string{"2001:db8::/128", "2001:db8::1/128"}, expected: []string{"2001:db8::/127"}},
		{name: "non-adjacent host routes survive", input: []string{"2001:db8::/128", "2001:db8::2/128"}, expected: []string{"2001:db8::/128", "2001:db8::2/128"}},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			nets := contiguous6FromStrings(testCase.input)
			result := xnetip.AggregateContiguous(nets)
			require.Equal(t, contiguous6FromStrings(testCase.expected), result)
			if len(result) > 0 {
				require.Same(t, &nets[0], &result[0])
			}
		})
	}
}

// verifies the family-agnostic instantiation: IPv4 sorts first and
// blocks merge or absorb only within their own family.
//
// The IPv6 universe must leave IPv4 blocks alone even though the
// mapped storage form sits inside it as a 128-bit set.
func Test_AggregateContiguous_DualFamilySpotChecks(t *testing.T) {
	cases := []struct {
		name     string
		input    []string
		expected []string
	}{
		{name: "buddies merge within each family", input: []string{"2001:db8::/48", "10.0.0.0/24", "10.0.1.0/24", "2001:db8:1::/48"}, expected: []string{"10.0.0.0/23", "2001:db8::/47"}},
		{name: "IPv4 default route absorbs only IPv4", input: []string{"2001:db8::/48", "0.0.0.0/0", "10.0.0.0/24"}, expected: []string{"0.0.0.0/0", "2001:db8::/48"}},
		{name: "IPv6 universe does not absorb IPv4", input: []string{"::/0", "10.0.0.0/24"}, expected: []string{"10.0.0.0/24", "::/0"}},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			nets := make([]xnetip.Contiguous[xnetip.Network], len(testCase.input))
			for idx, text := range testCase.input {
				nets[idx] = xnetip.MustParseContiguous(text)
			}
			expected := make([]xnetip.Contiguous[xnetip.Network], len(testCase.expected))
			for idx, text := range testCase.expected {
				expected[idx] = xnetip.MustParseContiguous(text)
			}
			require.Equal(t, expected, xnetip.AggregateContiguous(nets))
		})
	}
}

// verifies that the address union of the minimal cover equals the
// address union of the clustered input.
func Test_AggregateContiguous_IPv4PreservesAddressesProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		nets := genClusteredContiguous4.Draw(t, "nets")
		before := ipv4Union(contiguous4Unwrapped(nets))
		result := xnetip.AggregateContiguous(nets)
		require.Equal(t, before, ipv4Union(contiguous4Unwrapped(result)))
	})
}

// verifies minimality: no two blocks of the cover are equal, none
// contains another and no pair merges at the prefix boundary bit.
func Test_AggregateContiguous_IPv4MinimalProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		result := xnetip.AggregateContiguous(genClusteredContiguous4.Draw(t, "nets"))
		for left := range result {
			for right := left + 1; right < len(result); right++ {
				require.NotEqual(t, result[left], result[right])
				_, ok := result[left].MergeByLowestMaskBit(result[right])
				require.False(t, ok)
				require.False(t, result[left].Contains(result[right]))
				require.False(t, result[right].Contains(result[left]))
			}
		}
	})
}

// verifies the cover's shape after the blind rewrap.
//
// Every block must stay contiguous under the general mask check, the
// sequence ascend strictly by Compare and the blocks be pairwise
// disjoint.
func Test_AggregateContiguous_IPv4StaysContiguousSortedDisjointProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		result := xnetip.AggregateContiguous(genClusteredContiguous4.Draw(t, "nets"))
		for idx, block := range result {
			require.True(t, block.Network().IsContiguous())
			if idx > 0 {
				require.Negative(t, result[idx-1].Compare(block))
			}
		}
		for left := range result {
			for right := left + 1; right < len(result); right++ {
				_, ok := result[left].Intersection(result[right])
				require.False(t, ok)
			}
		}
	})
}

// verifies that the fast top-only cascade matches the naive fixpoint
// oracle that retries every pair until nothing merges.
func Test_AggregateContiguous_IPv4MatchesReferenceProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		nets := genClusteredContiguous4.Draw(t, "nets")
		expected := aggregateContiguous4Reference(nets)
		result := xnetip.AggregateContiguous(nets)
		require.Equal(t, expected, contiguous4Unwrapped(result))
	})
}

// verifies that aggregating the minimal cover again returns it
// unchanged, order included.
func Test_AggregateContiguous_IPv4IdempotentProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		first := xnetip.AggregateContiguous(genClusteredContiguous4.Draw(t, "nets"))
		require.Equal(t, first, xnetip.AggregateContiguous(slices.Clone(first)))
	})
}

// verifies that the address union of the minimal cover equals the
// address union of the clustered input.
func Test_AggregateContiguous_IPv6PreservesAddressesProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		nets := genClusteredContiguous6.Draw(t, "nets")
		before := ipv6Union(contiguous6Unwrapped(nets))
		result := xnetip.AggregateContiguous(nets)
		require.Equal(t, before, ipv6Union(contiguous6Unwrapped(result)))
	})
}

// verifies minimality: no two blocks of the cover are equal, none
// contains another and no pair merges at the prefix boundary bit.
func Test_AggregateContiguous_IPv6MinimalProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		result := xnetip.AggregateContiguous(genClusteredContiguous6.Draw(t, "nets"))
		for left := range result {
			for right := left + 1; right < len(result); right++ {
				require.NotEqual(t, result[left], result[right])
				_, ok := result[left].MergeByLowestMaskBit(result[right])
				require.False(t, ok)
				require.False(t, result[left].Contains(result[right]))
				require.False(t, result[right].Contains(result[left]))
			}
		}
	})
}

// verifies the cover's shape after the blind rewrap.
//
// Every block must stay contiguous under the general mask check, the
// sequence ascend strictly by Compare and the blocks be pairwise
// disjoint.
func Test_AggregateContiguous_IPv6StaysContiguousSortedDisjointProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		result := xnetip.AggregateContiguous(genClusteredContiguous6.Draw(t, "nets"))
		for idx, block := range result {
			require.True(t, block.Network().IsContiguous())
			if idx > 0 {
				require.Negative(t, result[idx-1].Compare(block))
			}
		}
		for left := range result {
			for right := left + 1; right < len(result); right++ {
				_, ok := result[left].Intersection(result[right])
				require.False(t, ok)
			}
		}
	})
}

// verifies that the fast top-only cascade matches the naive fixpoint
// oracle that retries every pair until nothing merges.
func Test_AggregateContiguous_IPv6MatchesReferenceProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		nets := genClusteredContiguous6.Draw(t, "nets")
		expected := aggregateContiguous6Reference(nets)
		result := xnetip.AggregateContiguous(nets)
		require.Equal(t, expected, contiguous6Unwrapped(result))
	})
}

// verifies that aggregating the minimal cover again returns it
// unchanged, order included.
func Test_AggregateContiguous_IPv6IdempotentProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		first := xnetip.AggregateContiguous(genClusteredContiguous6.Draw(t, "nets"))
		require.Equal(t, first, xnetip.AggregateContiguous(slices.Clone(first)))
	})
}

// verifies that a range decomposition is already a minimal cover:
// aggregating it returns it unchanged, order included.
func Test_AggregateContiguous_RangeCoverIsFixedPointProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		first := genNetipAddr4.Draw(t, "first")
		last := genNetipAddr4.Draw(t, "last")
		if first.Compare(last) > 0 {
			first, last = last, first
		}
		cover := []xnetip.Contiguous[xnetip.Network4]{}
		for block := range xnetip.RangeToNetworks4(first, last) {
			cover = append(cover, block)
		}
		require.Equal(t, cover, xnetip.AggregateContiguous(slices.Clone(cover)))

		first6 := genNetipAddr6.Draw(t, "first6")
		last6 := genNetipAddr6.Draw(t, "last6")
		if first6.Compare(last6) > 0 {
			first6, last6 = last6, first6
		}
		cover6 := []xnetip.Contiguous[xnetip.Network6]{}
		for block := range xnetip.RangeToNetworks6(first6, last6) {
			cover6 = append(cover6, block)
		}
		require.Equal(t, cover6, xnetip.AggregateContiguous(slices.Clone(cover6)))
	})
}

// verifies that the typed aggregation allocates nothing on pre-built
// slices of either family.
func Test_AggregateContiguous_AllocationFree(t *testing.T) {
	template4 := aggregateContiguous4Clustered(t)
	template6 := aggregateContiguous6Clustered(t)
	working4 := make([]xnetip.Contiguous[xnetip.Network4], len(template4))
	working6 := make([]xnetip.Contiguous[xnetip.Network6], len(template6))
	requireNoAllocs(t, func() {
		copy(working4, template4)
		intSink = len(xnetip.AggregateContiguous(working4))
	})
	requireNoAllocs(t, func() {
		copy(working6, template6)
		intSink = len(xnetip.AggregateContiguous(working6))
	})
}

// contiguous4FromStrings parses each element with the panicking
// parser, returning a non-nil slice so empty fixtures compare equal.
func contiguous4FromStrings(texts []string) []xnetip.Contiguous[xnetip.Network4] {
	nets := make([]xnetip.Contiguous[xnetip.Network4], len(texts))
	for idx, text := range texts {
		nets[idx] = xnetip.MustParseContiguous4(text)
	}
	return nets
}

// contiguous6FromStrings parses each element with the panicking
// parser, returning a non-nil slice so empty fixtures compare equal.
func contiguous6FromStrings(texts []string) []xnetip.Contiguous[xnetip.Network6] {
	nets := make([]xnetip.Contiguous[xnetip.Network6], len(texts))
	for idx, text := range texts {
		nets[idx] = xnetip.MustParseContiguous6(text)
	}
	return nets
}

// contiguous4Unwrapped returns the wrapped networks of the blocks.
func contiguous4Unwrapped(nets []xnetip.Contiguous[xnetip.Network4]) []xnetip.Network4 {
	unwrapped := make([]xnetip.Network4, len(nets))
	for idx, block := range nets {
		unwrapped[idx] = block.Network()
	}
	return unwrapped
}

// contiguous6Unwrapped returns the wrapped networks of the blocks.
func contiguous6Unwrapped(nets []xnetip.Contiguous[xnetip.Network6]) []xnetip.Network6 {
	unwrapped := make([]xnetip.Network6, len(nets))
	for idx, block := range nets {
		unwrapped[idx] = block.Network()
	}
	return unwrapped
}

// aggregateContiguous4Reference is the naive fixpoint oracle.
//
// It absorbs containment and merges buddies pair by pair until
// nothing changes, then sorts the survivors.
func aggregateContiguous4Reference(input []xnetip.Contiguous[xnetip.Network4]) []xnetip.Network4 {
	nets := contiguous4Unwrapped(input)
	for changed := true; changed; {
		changed = false
	scan:
		for left := range nets {
			for right := left + 1; right < len(nets); right++ {
				if parent, ok := nets[left].MergeByLowestMaskBit(nets[right]); ok {
					nets[left] = parent
					nets = slices.Delete(nets, right, right+1)
					changed = true
					break scan
				}
			}
		}
	}
	slices.SortFunc(nets, xnetip.Network4.Compare)
	return nets
}

// aggregateContiguous6Reference is the naive fixpoint oracle.
//
// It absorbs containment and merges buddies pair by pair until
// nothing changes, then sorts the survivors.
func aggregateContiguous6Reference(input []xnetip.Contiguous[xnetip.Network6]) []xnetip.Network6 {
	nets := contiguous6Unwrapped(input)
	for changed := true; changed; {
		changed = false
	scan:
		for left := range nets {
			for right := left + 1; right < len(nets); right++ {
				if parent, ok := nets[left].MergeByLowestMaskBit(nets[right]); ok {
					nets[left] = parent
					nets = slices.Delete(nets, right, right+1)
					changed = true
					break scan
				}
			}
		}
	}
	slices.SortFunc(nets, xnetip.Network6.Compare)
	return nets
}

// aggregateContiguous4Clustered returns 1024 /30 blocks packed as 64
// children under each of 16 parent /24 windows, cascading fully.
func aggregateContiguous4Clustered(t require.TestingT) []xnetip.Contiguous[xnetip.Network4] {
	nets := make([]xnetip.Contiguous[xnetip.Network4], 1024)
	for idx := range nets {
		addr := 0xC0A80000 | uint32(idx>>6)<<8 | uint32(idx&63)<<2
		block, err := xnetip.ContiguousFromCIDR4(netipAddrFrom4Bits(addr), 30)
		require.NoError(t, err)
		nets[idx] = block
	}
	return nets
}

// aggregateContiguous6Clustered returns 1024 /126 blocks packed as 64
// children under each of 16 parent /120 windows, cascading fully.
func aggregateContiguous6Clustered(t require.TestingT) []xnetip.Contiguous[xnetip.Network6] {
	nets := make([]xnetip.Contiguous[xnetip.Network6], 1024)
	for idx := range nets {
		low := uint64(idx>>6)<<8 | uint64(idx&63)<<2
		block, err := xnetip.ContiguousFromCIDR6(netipAddrFrom6Bits(0x20010DB800000000, low), 126)
		require.NoError(t, err)
		nets[idx] = block
	}
	return nets
}

// genClusteredContiguous4 draws up to 24 CIDR blocks with prefixes 24
// through 32 confined to a 4096-address window.
//
// The tight window makes containment and buddy cascades frequent
// while capping each block at 256 addresses, so a whole collection's
// union stays brute-forceable.
var genClusteredContiguous4 = rapid.SliceOfN(rapid.Custom(func(t *rapid.T) xnetip.Contiguous[xnetip.Network4] {
	addr := 0xC0A80000 | rapid.Uint32().Draw(t, "addr")&0x0FFF
	prefix := rapid.IntRange(24, 32).Draw(t, "prefix")
	block, err := xnetip.ContiguousFromCIDR4(netipAddrFrom4Bits(addr), prefix)
	require.NoError(t, err)
	return block
}), 0, 24)

// genClusteredContiguous6 draws up to 24 CIDR blocks with prefixes
// 120 through 128 confined to a 4096-address window.
//
// The tight window makes containment and buddy cascades frequent
// while capping each block at 256 addresses, so a whole collection's
// union stays brute-forceable.
var genClusteredContiguous6 = rapid.SliceOfN(rapid.Custom(func(t *rapid.T) xnetip.Contiguous[xnetip.Network6] {
	low := rapid.Uint64().Draw(t, "addr") & 0x0FFF
	prefix := rapid.IntRange(120, 128).Draw(t, "prefix")
	block, err := xnetip.ContiguousFromCIDR6(netipAddrFrom6Bits(0x20010DB800000000, low), prefix)
	require.NoError(t, err)
	return block
}), 0, 24)

func BenchmarkAggregateContiguous_IPv41024Clustered(b *testing.B) {
	template := aggregateContiguous4Clustered(b)
	networks := make([]xnetip.Contiguous[xnetip.Network4], len(template))
	b.ReportAllocs()
	for b.Loop() {
		copy(networks, template)
		intSink = len(xnetip.AggregateContiguous(networks))
	}
}

func BenchmarkAggregateContiguous_IPv41024Disjoint(b *testing.B) {
	template := make([]xnetip.Contiguous[xnetip.Network4], 1024)
	for idx, network := range aggregate4NeverMerges(b, 1024) {
		template[idx] = network.ToContiguous()
	}
	networks := make([]xnetip.Contiguous[xnetip.Network4], len(template))
	b.ReportAllocs()
	for b.Loop() {
		copy(networks, template)
		intSink = len(xnetip.AggregateContiguous(networks))
	}
}

func BenchmarkAggregateContiguous_IPv61024Clustered(b *testing.B) {
	template := aggregateContiguous6Clustered(b)
	networks := make([]xnetip.Contiguous[xnetip.Network6], len(template))
	b.ReportAllocs()
	for b.Loop() {
		copy(networks, template)
		intSink = len(xnetip.AggregateContiguous(networks))
	}
}

func BenchmarkAggregateContiguous_IPv61024Disjoint(b *testing.B) {
	template := make([]xnetip.Contiguous[xnetip.Network6], 1024)
	for idx, network := range aggregate6NeverMerges(b, 1024) {
		template[idx] = network.ToContiguous()
	}
	networks := make([]xnetip.Contiguous[xnetip.Network6], len(template))
	b.ReportAllocs()
	for b.Loop() {
		copy(networks, template)
		intSink = len(xnetip.AggregateContiguous(networks))
	}
}

func BenchmarkAggregate4_1024Clustered(b *testing.B) {
	template := contiguous4Unwrapped(aggregateContiguous4Clustered(b))
	networks := make([]xnetip.Network4, len(template))
	b.ReportAllocs()
	for b.Loop() {
		copy(networks, template)
		intSink = len(xnetip.Aggregate4(networks))
	}
}

func BenchmarkAggregate6_1024Clustered(b *testing.B) {
	template := contiguous6Unwrapped(aggregateContiguous6Clustered(b))
	networks := make([]xnetip.Network6, len(template))
	b.ReportAllocs()
	for b.Loop() {
		copy(networks, template)
		intSink = len(xnetip.Aggregate6(networks))
	}
}

// mustBiContiguousFromHalves builds a normalized rectangle from two address
// halves and their independent leading-one prefix lengths.
func mustBiContiguousFromHalves(
	highAddr uint64,
	highPrefix int,
	lowAddr uint64,
	lowPrefix int,
) xnetip.BiContiguous {
	block, err := xnetip.BiContiguousFrom(
		netipAddrFrom6Bits(highAddr, lowAddr),
		netipAddrFrom6Bits(
			prefixMask64(highPrefix),
			prefixMask64(lowPrefix),
		),
	)
	if err != nil {
		panic(err)
	}
	return block
}

// parseBiContiguousBlocks parses an exact table fixture into wrappers.
func parseBiContiguousBlocks(texts []string) []xnetip.BiContiguous {
	blocks := make([]xnetip.BiContiguous, len(texts))
	for idx, text := range texts {
		blocks[idx] = xnetip.MustParseBiContiguous(text)
	}
	return blocks
}

// compareBiContiguousMaskAddress orders rectangles by numeric mask and then
// normalized address, the aggregate output's public sort key.
func compareBiContiguousMaskAddress(first, second xnetip.BiContiguous) int {
	if order := first.Network().Mask().Compare(second.Network().Mask()); order != 0 {
		return order
	}
	return first.Network().Addr().Compare(second.Network().Addr())
}

type biContiguousHighGroupKey struct {
	prefix int
	addr   uint64
}

type biContiguousLowShape struct {
	addr   uint64
	prefix int
}

// biContiguousAddressHalves returns the host-order high and low address halves.
func biContiguousAddressHalves(block xnetip.BiContiguous) (uint64, uint64) {
	addr := block.Network().Addr().As16()
	return binary.BigEndian.Uint64(addr[:8]), binary.BigEndian.Uint64(addr[8:])
}

// findBiContiguousHighRowMerge finds the first high-half buddy pair carrying
// equal canonical low-half sets in level-major order.
func findBiContiguousHighRowMerge(
	blocks []xnetip.BiContiguous,
) ([]int, []int, int, bool) {
	groups := map[biContiguousHighGroupKey][]int{}
	for idx, block := range blocks {
		highAddr, _ := biContiguousAddressHalves(block)
		key := biContiguousHighGroupKey{
			prefix: block.HighPrefixLen(),
			addr:   highAddr,
		}
		groups[key] = append(groups[key], idx)
	}
	keys := make([]biContiguousHighGroupKey, 0, len(groups))
	for key := range groups {
		keys = append(keys, key)
	}
	slices.SortFunc(keys, func(first, second biContiguousHighGroupKey) int {
		switch {
		case first.prefix < second.prefix:
			return -1
		case first.prefix > second.prefix:
			return 1
		case first.addr < second.addr:
			return -1
		case first.addr > second.addr:
			return 1
		default:
			return 0
		}
	})
	for _, lowerKey := range keys {
		if lowerKey.prefix == 0 {
			continue
		}
		buddyBit := uint64(1) << (64 - lowerKey.prefix)
		if lowerKey.addr&buddyBit != 0 {
			continue
		}
		upperKey := biContiguousHighGroupKey{
			prefix: lowerKey.prefix,
			addr:   lowerKey.addr | buddyBit,
		}
		upper, ok := groups[upperKey]
		if !ok {
			continue
		}
		lower := groups[lowerKey]
		if len(lower) != len(upper) {
			continue
		}
		lowerShapes := make([]biContiguousLowShape, len(lower))
		upperShapes := make([]biContiguousLowShape, len(upper))
		for idx := range lower {
			_, lowerAddr := biContiguousAddressHalves(blocks[lower[idx]])
			_, upperAddr := biContiguousAddressHalves(blocks[upper[idx]])
			lowerShapes[idx] = biContiguousLowShape{
				addr: lowerAddr, prefix: blocks[lower[idx]].LowPrefixLen(),
			}
			upperShapes[idx] = biContiguousLowShape{
				addr: upperAddr, prefix: blocks[upper[idx]].LowPrefixLen(),
			}
		}
		compareLowShape := func(first, second biContiguousLowShape) int {
			switch {
			case first.addr < second.addr:
				return -1
			case first.addr > second.addr:
				return 1
			case first.prefix < second.prefix:
				return -1
			case first.prefix > second.prefix:
				return 1
			default:
				return 0
			}
		}
		slices.SortFunc(lowerShapes, compareLowShape)
		slices.SortFunc(upperShapes, compareLowShape)
		if slices.Equal(lowerShapes, upperShapes) {
			return lower, upper, lowerKey.prefix - 1, true
		}
	}
	return nil, nil, 0, false
}

// applyBiContiguousHighRowMerge applies one independent high-half group
// rewrite and reports whether a matching buddy pair existed.
func applyBiContiguousHighRowMerge(blocks []xnetip.BiContiguous) ([]xnetip.BiContiguous, bool) {
	lower, upper, newHighPrefix, ok := findBiContiguousHighRowMerge(blocks)
	if !ok {
		return blocks, false
	}
	lowerSet := map[int]struct{}{}
	upperSet := map[int]struct{}{}
	for _, idx := range lower {
		lowerSet[idx] = struct{}{}
	}
	for _, idx := range upper {
		upperSet[idx] = struct{}{}
	}
	result := make([]xnetip.BiContiguous, 0, len(blocks)-len(upper))
	for idx, block := range blocks {
		if _, drop := upperSet[idx]; drop {
			continue
		}
		if _, reparent := lowerSet[idx]; reparent {
			highAddr, lowAddr := biContiguousAddressHalves(block)
			block = mustBiContiguousFromHalves(
				highAddr,
				newHighPrefix,
				lowAddr,
				block.LowPrefixLen(),
			)
		}
		result = append(result, block)
	}
	return result, true
}

// referenceAggregateBiContiguous6 applies the three class-preserving rewrites
// with a simple allocating quadratic fixpoint.
func referenceAggregateBiContiguous6(
	input []xnetip.BiContiguous,
) []xnetip.BiContiguous {
	blocks := slices.Clone(input)
	for {
		applied := false
		for firstIdx := 0; firstIdx < len(blocks) && !applied; firstIdx++ {
			for secondIdx := firstIdx + 1; secondIdx < len(blocks); secondIdx++ {
				merged, ok := blocks[firstIdx].MergeByLowestMaskBit(blocks[secondIdx])
				if !ok {
					continue
				}
				blocks[firstIdx] = merged
				blocks = append(blocks[:secondIdx], blocks[secondIdx+1:]...)
				applied = true
				break
			}
		}
		if applied {
			continue
		}
		var merged bool
		blocks, merged = applyBiContiguousHighRowMerge(blocks)
		if merged {
			continue
		}
		break
	}
	slices.SortFunc(blocks, compareBiContiguousMaskAddress)
	return blocks
}

// boundedBiContiguousUnion enumerates the exact address union of fixtures
// whose total host space is intentionally small.
func boundedBiContiguousUnion(
	blocks []xnetip.BiContiguous,
) map[netip.Addr]struct{} {
	union := map[netip.Addr]struct{}{}
	for _, block := range blocks {
		for addr := range block.Addrs() {
			union[addr] = struct{}{}
		}
	}
	return union
}

// requireBiContiguousAggregateFixpoint checks the public sorted, class and
// pairwise-closed result contract.
func requireBiContiguousAggregateFixpoint(
	t require.TestingT,
	blocks []xnetip.BiContiguous,
) {
	for idx := 1; idx < len(blocks); idx++ {
		require.LessOrEqual(
			t,
			compareBiContiguousMaskAddress(blocks[idx-1], blocks[idx]),
			0,
		)
	}
	for idx, block := range blocks {
		revalidated, ok := xnetip.BiContiguousFrom6(block.Network())
		require.True(t, ok)
		require.Equal(t, block, revalidated)
		for otherIdx := idx + 1; otherIdx < len(blocks); otherIdx++ {
			require.False(t, block.Contains(blocks[otherIdx]))
			require.False(t, blocks[otherIdx].Contains(block))
			_, ok = block.MergeByLowestMaskBit(blocks[otherIdx])
			require.False(t, ok)
		}
	}
	_, _, _, ok := findBiContiguousHighRowMerge(blocks)
	require.False(t, ok)
}

// verifies exact positional output for containment, both buddy axes,
// cascades, cross-shape interference and the documented non-minimal gadget.
func Test_AggregateBiContiguous6_ExactFixtures(t *testing.T) {
	cases := []struct {
		name     string
		input    []string
		expected []string
	}{
		{name: "empty slice", input: []string{}, expected: []string{}},
		{
			name: "singleton unchanged",
			input: []string{
				"2001:db8::1234:abcd:0:0/ffff:ffff:ff00::ffff:ffff:0:0",
			},
			expected: []string{
				"2001:db8::1234:abcd:0:0/ffff:ffff:ff00::ffff:ffff:0:0",
			},
		},
		{
			name: "duplicates collapse",
			input: []string{
				"2a02:6b8:c00::1234:abcd:0:0/ffff:ffff:ff00::ffff:ffff:0:0",
				"2a02:6b8:c00::1234:abcd:0:0/ffff:ffff:ff00::ffff:ffff:0:0",
				"2a02:6b8:c00::1234:abcd:0:0/ffff:ffff:ff00::ffff:ffff:0:0",
			},
			expected: []string{
				"2a02:6b8:c00::1234:abcd:0:0/ffff:ffff:ff00::ffff:ffff:0:0",
			},
		},
		{
			name: "low buddies merge",
			input: []string{
				"2001:db8:1:0:aaaa:bbbb:0:0/ffff:ffff:ffff:0:ffff:ffff:ffff:0",
				"2001:db8:1:0:aaaa:bbbb:1:0/ffff:ffff:ffff:0:ffff:ffff:ffff:0",
			},
			expected: []string{
				"2001:db8:1:0:aaaa:bbbb:0:0/ffff:ffff:ffff:0:ffff:ffff:fffe:0",
			},
		},
		{
			name: "high buddies with equal low rows merge",
			input: []string{
				"2001:db8:0:0:aaaa:bbbb:cccc:0/ffff:ffff:ffff:0:ffff:ffff:ffff:0",
				"2001:db8:1:0:aaaa:bbbb:cccc:0/ffff:ffff:ffff:0:ffff:ffff:ffff:0",
			},
			expected: []string{
				"2001:db8:0:0:aaaa:bbbb:cccc:0/ffff:ffff:fffe:0:ffff:ffff:ffff:0",
			},
		},
		{
			name: "high buddies with different low rows stay separate",
			input: []string{
				"2001:db8:0:0:aaaa:bbbb:cccc:0/ffff:ffff:ffff:0:ffff:ffff:ffff:0",
				"2001:db8:1:0:aaaa:bbbb:dddd:0/ffff:ffff:ffff:0:ffff:ffff:ffff:0",
			},
			expected: []string{
				"2001:db8:0:0:aaaa:bbbb:cccc:0/ffff:ffff:ffff:0:ffff:ffff:ffff:0",
				"2001:db8:1:0:aaaa:bbbb:dddd:0/ffff:ffff:ffff:0:ffff:ffff:ffff:0",
			},
		},
		{
			name: "full two by two grid collapses",
			input: []string{
				"2001:db8:0:0:aaaa:bbbb:0:0/ffff:ffff:ffff:0:ffff:ffff:ffff:0",
				"2001:db8:0:0:aaaa:bbbb:1:0/ffff:ffff:ffff:0:ffff:ffff:ffff:0",
				"2001:db8:1:0:aaaa:bbbb:0:0/ffff:ffff:ffff:0:ffff:ffff:ffff:0",
				"2001:db8:1:0:aaaa:bbbb:1:0/ffff:ffff:ffff:0:ffff:ffff:ffff:0",
			},
			expected: []string{
				"2001:db8:0:0:aaaa:bbbb:0:0/ffff:ffff:fffe:0:ffff:ffff:fffe:0",
			},
		},
		{
			name:     "contiguous slash forty-eight buddies merge",
			input:    []string{"2001:db8::/48", "2001:db8:1::/48"},
			expected: []string{"2001:db8::/47"},
		},
		{
			name: "multi-level high cascade keeps disjoint survivor",
			input: []string{
				"2001:db8::/48",
				"2001:db8:1::/48",
				"2001:db8:2::/48",
				"2001:db8:3::/48",
				"2001:dead::/32",
			},
			expected: []string{"2001:dead::/32", "2001:db8::/46"},
		},
		{
			name: "non-adjacent containment crosses sort interference",
			input: []string{
				"2001:db8::/32",
				"2001:dead::/32",
				"2001:db8:1::/48",
			},
			expected: []string{"2001:db8::/32", "2001:dead::/32"},
		},
		{
			name: "implied coverage remains three",
			input: []string{
				"::/c000:0:0:0:8000:0:0:0",
				"4000::/c000:0:0:0:c000:0:0:0",
				"::4000:0:0:0/8000:0:0:0:c000:0:0:0",
			},
			expected: []string{
				"::4000:0:0:0/8000:0:0:0:c000:0:0:0",
				"::/c000:0:0:0:8000:0:0:0",
				"4000::/c000:0:0:0:c000:0:0:0",
			},
		},
		{
			name: "broader motivating low rectangle absorbs narrower",
			input: []string{
				"2a02:6b8:c00::1234:abcd:0:0/ffff:ffff:ff00::ffff:ffff:0:0",
				"2a02:6b8:c00::1234:0:0:0/ffff:ffff:ff00::ffff:0:0:0",
			},
			expected: []string{
				"2a02:6b8:c00::1234:0:0:0/ffff:ffff:ff00::ffff:0:0:0",
			},
		},
		{
			name: "reparented survivor meets native next level",
			input: []string{
				"2001:db8::/48",
				"2001:db8:1::/48",
				"2001:db8:2::/47",
			},
			expected: []string{"2001:db8::/46"},
		},
		{
			name: "reparented survivor low-aggregates with native row",
			input: []string{
				"2001:db8:0:0:aaaa:bbbb:cccc:0/ffff:ffff:ffff:0:ffff:ffff:ffff:0",
				"2001:db8:1:0:aaaa:bbbb:cccc:0/ffff:ffff:ffff:0:ffff:ffff:ffff:0",
				"2001:db8:0:0:aaaa:bbbb:cccd:0/ffff:ffff:fffe:0:ffff:ffff:ffff:0",
			},
			expected: []string{
				"2001:db8:0:0:aaaa:bbbb:cccc:0/ffff:ffff:fffe:0:ffff:ffff:fffe:0",
			},
		},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			work := parseBiContiguousBlocks(testCase.input)
			var first *xnetip.BiContiguous
			if len(work) > 0 {
				first = &work[0]
			}
			result := xnetip.AggregateBiContiguous6(work)
			require.LessOrEqual(t, len(result), len(work))
			if first != nil {
				require.Same(t, first, &result[0])
			}
			require.Equal(t, parseBiContiguousBlocks(testCase.expected), result)
			requireBiContiguousAggregateFixpoint(t, result)
		})
	}
}

// verifies all 63 independent high-level buddy pairs reparent exactly once
// while eight inert host routes remain in numeric mask-address order.
func Test_AggregateBiContiguous6_DisjointCascadeExactOutput(t *testing.T) {
	input := make([]xnetip.BiContiguous, 0, 134)
	for prefix := 2; prefix <= 64; prefix++ {
		buddyBit := uint64(1) << (64 - prefix)
		marker := uint64(1) << (65 - prefix)
		input = append(
			input,
			mustBiContiguousFromHalves(marker, prefix, 0, 0),
			mustBiContiguousFromHalves(marker|buddyBit, prefix, 0, 0),
		)
	}
	for idx := range 8 {
		input = append(input, mustBiContiguousFromHalves(0, 64, uint64(0x100*(idx+1)), 64))
	}
	expected := make([]xnetip.BiContiguous, 0, 71)
	for prefix := 2; prefix <= 64; prefix++ {
		expected = append(expected, mustBiContiguousFromHalves(
			uint64(1)<<(65-prefix),
			prefix-1,
			0,
			0,
		))
	}
	for idx := range 8 {
		expected = append(expected, mustBiContiguousFromHalves(
			0,
			64,
			uint64(0x100*(idx+1)),
			64,
		))
	}
	slices.SortFunc(expected, compareBiContiguousMaskAddress)
	require.Equal(t, expected, xnetip.AggregateBiContiguous6(input))
}

// verifies a same-shape run spanning three 64-element chunks is removed by
// a strict ancestor without losing or retaining a boundary element.
func Test_AggregateBiContiguous6_ContainmentAcrossChunkBoundaries(t *testing.T) {
	container := mustBiContiguousFromHalves(0, 8, 0, 0)
	input := make([]xnetip.BiContiguous, 1, 131)
	input[0] = container
	for idx := range 130 {
		input = append(input, mustBiContiguousFromHalves(uint64(2*(idx+1)), 64, 0, 64))
	}
	require.Equal(t, []xnetip.BiContiguous{container}, xnetip.AggregateBiContiguous6(input))
}

// verifies shape bitmap endpoints zero and 64 and containment crossing the
// address-half boundary preserve the two incomparable axis-wide rectangles.
func Test_AggregateBiContiguous6_ShapeBitmapBoundaries(t *testing.T) {
	highWildcard := xnetip.MustParseBiContiguous(
		"::1234/0:0:0:0:ffff:ffff:ffff:ffff",
	)
	lowWildcard := xnetip.MustParseBiContiguous(
		"2001:db8::/ffff:ffff:ffff:ffff::",
	)
	host := xnetip.MustParseBiContiguous("2001:db8::1234/128")
	input := []xnetip.BiContiguous{host, lowWildcard, highWildcard}
	require.Equal(
		t,
		[]xnetip.BiContiguous{highWildcard, lowWildcard},
		xnetip.AggregateBiContiguous6(input),
	)
}

var genBiContiguousAggregateWindow = rapid.SliceOfN(rapid.Custom(
	func(t *rapid.T) xnetip.BiContiguous {
		highPrefix := rapid.IntRange(60, 64).Draw(t, "high prefix")
		lowPrefix := rapid.IntRange(60, 64).Draw(t, "low prefix")
		return mustBiContiguousFromHalves(
			rapid.Uint64().Draw(t, "high address"),
			highPrefix,
			rapid.Uint64().Draw(t, "low address"),
			lowPrefix,
		)
	},
), 0, 15)

// verifies on brute-forceable rectangles that the exact address union is
// preserved and both production and independent greedy covers reach closure.
func Test_AggregateBiContiguous6_PreservesBoundedUnionAndOracleContractProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		input := genBiContiguousAggregateWindow.Draw(t, "rectangles")
		expectedUnion := boundedBiContiguousUnion(input)
		work := slices.Clone(input)
		result := xnetip.AggregateBiContiguous6(work)
		reference := referenceAggregateBiContiguous6(input)
		require.Equal(t, expectedUnion, boundedBiContiguousUnion(result))
		require.Equal(t, expectedUnion, boundedBiContiguousUnion(reference))
		requireBiContiguousAggregateFixpoint(t, result)
		requireBiContiguousAggregateFixpoint(t, reference)
	})
}

// verifies arbitrary wrapper slices produce a revalidated numeric-order
// fixpoint with no containment, lowest-bit merge or equal-row buddy remaining.
func Test_AggregateBiContiguous6_GeneralFixpointProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		input := rapid.SliceOfN(genBiContiguous, 0, 23).Draw(t, "rectangles")
		work := slices.Clone(input)
		result := xnetip.AggregateBiContiguous6(work)
		require.LessOrEqual(t, len(result), len(input))
		requireBiContiguousAggregateFixpoint(t, result)
	})
}

// verifies aggregating a closed result again preserves its exact value set.
func Test_AggregateBiContiguous6_IdempotentAsSetProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		input := rapid.SliceOfN(genBiContiguous, 0, 23).Draw(t, "rectangles")
		firstWork := slices.Clone(input)
		first := slices.Clone(xnetip.AggregateBiContiguous6(firstWork))
		secondWork := slices.Clone(first)
		second := slices.Clone(xnetip.AggregateBiContiguous6(secondWork))
		slices.SortFunc(first, xnetip.BiContiguous.Compare)
		slices.SortFunc(second, xnetip.BiContiguous.Compare)
		require.Equal(t, first, second)
	})
}

// verifies repeated input shuffles may choose different valid covers but
// always preserve the exact bounded union and the full fixpoint contract.
func Test_AggregateBiContiguous6_ShuffleInvariantContractProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		input := genBiContiguousAggregateWindow.Draw(t, "rectangles")
		expectedUnion := boundedBiContiguousUnion(input)
		for shuffle := range 3 {
			work := rapid.Permutation(input).Draw(t, "shuffle "+string(rune('a'+shuffle)))
			result := xnetip.AggregateBiContiguous6(work)
			require.Equal(t, expectedUnion, boundedBiContiguousUnion(result))
			requireBiContiguousAggregateFixpoint(t, result)
		}
	})
}

// sweepCleanContainmentFixture builds exact host routes with neither low nor
// high buddies, plus one ancestor containing only the unmarked branch.
func sweepCleanContainmentFixture(count int) []xnetip.BiContiguous {
	const (
		highBase = uint64(0x2001_0db8_abcd_1200)
		lowBase  = uint64(0x5678_9abc_def0_1200)
	)
	blocks := make([]xnetip.BiContiguous, 1, count)
	blocks[0] = mustBiContiguousFromHalves(highBase, 59, lowBase, 59)
	for idx := 0; idx < count-1; idx++ {
		withinBranch := idx / 2
		highOffset := uint64(2 * ((withinBranch / 16) % 16))
		lowOffset := uint64(2 * (withinBranch % 16))
		highAddr := highBase | highOffset
		if idx%2 != 0 {
			highAddr |= 1 << 5
		}
		blocks = append(blocks, mustBiContiguousFromHalves(
			highAddr,
			64,
			lowBase|lowOffset,
			64,
		))
	}
	return blocks
}

// referenceBiContiguousContainment drops every uniquely represented block
// contained by another block and sorts the survivors by the public key.
func referenceBiContiguousContainment(
	input []xnetip.BiContiguous,
) []xnetip.BiContiguous {
	result := make([]xnetip.BiContiguous, 0, len(input))
	for idx, candidate := range input {
		contained := false
		for otherIdx, other := range input {
			if idx != otherIdx && other.Contains(candidate) {
				contained = true
				break
			}
		}
		if !contained {
			result = append(result, candidate)
		}
	}
	slices.SortFunc(result, compareBiContiguousMaskAddress)
	return result
}

// verifies the chunked containment probe matches a quadratic oracle exactly
// on large sweep-clean slices ranging across the three chunk sizes.
func Test_AggregateBiContiguous6_MultiChunkContainmentMatchesQuadraticProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		count := rapid.IntRange(64, 191).Draw(t, "rectangle count")
		input := sweepCleanContainmentFixture(count)
		work := rapid.Permutation(input).Draw(t, "input order")
		result := xnetip.AggregateBiContiguous6(work)
		require.Equal(t, referenceBiContiguousContainment(input), result)
	})
}

// aggregateBiContiguousNeverMerges spreads distinct normalized values across
// many deep shapes without an intended sibling or containment relation.
func aggregateBiContiguousNeverMerges(count, shapeCount int) []xnetip.BiContiguous {
	blocks := make([]xnetip.BiContiguous, count)
	for idx := range count {
		shape := uint64(idx % shapeCount)
		highPrefix := 20 + int((shape*7)%44)
		lowPrefix := 20 + int((shape*11)%44)
		highAddr := uint64(idx) * 0x9E37_79B9_7F4A_7C15
		lowAddr := uint64(idx)*0xBF58_476D_1CE4_E5B9 ^ 0xABCD_EF01_2345_6789
		blocks[idx] = mustBiContiguousFromHalves(
			highAddr,
			highPrefix,
			lowAddr,
			lowPrefix,
		)
	}
	return blocks
}

// aggregateBiContiguousGeo builds site-wide high blocks whose low /32 rows
// nest inside low /16 rows at the same small pool of sites.
func aggregateBiContiguousGeo(count int) []xnetip.BiContiguous {
	siteCount := min(max(count/50, 4), 2000)
	blocks := make([]xnetip.BiContiguous, count)
	for idx := range count {
		site := uint64(idx % siteCount)
		lowPrefix := 16
		if idx%2 == 0 {
			lowPrefix = 32
		}
		blocks[idx] = mustBiContiguousFromHalves(
			site*0x9E37_79B9_7F4A_7C15,
			40,
			uint64(idx)*0xBF58_476D_1CE4_E5B9,
			lowPrefix,
		)
	}
	return blocks
}

// aggregateBiContiguousMergeableGrid builds low buddy rows under consecutive
// high buddy blocks so both aggregation phases cascade densely.
func aggregateBiContiguousMergeableGrid(count int) []xnetip.BiContiguous {
	blocks := make([]xnetip.BiContiguous, count)
	for idx := range count {
		highIndex := uint64(idx / 64)
		lowIndex := uint64(idx % 64)
		blocks[idx] = mustBiContiguousFromHalves(
			0x2001_0db8_0000_0000|(highIndex<<16),
			48,
			lowIndex<<16,
			48,
		)
	}
	return blocks
}

// aggregateBiContiguousReparentCascade builds a high-buddy chain beside an
// inert coarse-prefix block that makes localized re-sorting observable.
func aggregateBiContiguousReparentCascade(count int) []xnetip.BiContiguous {
	const (
		cascadeFloor = 8
		marker       = uint64(1) << 63
	)
	blocks := make([]xnetip.BiContiguous, 0, count)
	blocks = append(
		blocks,
		mustBiContiguousFromHalves(marker, 64, 0, 0),
		mustBiContiguousFromHalves(marker|1, 64, 0, 0),
	)
	for prefix := cascadeFloor + 1; prefix < 64; prefix++ {
		buddyBit := uint64(1) << (64 - prefix)
		blocks = append(blocks, mustBiContiguousFromHalves(
			marker|buddyBit,
			prefix,
			0,
			0,
		))
	}
	inertCount := max(count-len(blocks), 0)
	shapeCount := min(16, max(inertCount, 1))
	for idx := range inertCount {
		shape := uint64(idx % shapeCount)
		lowPrefix := 20 + int((shape*11)%44)
		lowAddr := uint64(idx)*0xBF58_476D_1CE4_E5B9 ^ 0xABCD_EF01_2345_6789
		blocks = append(blocks, mustBiContiguousFromHalves(0, 4, lowAddr, lowPrefix))
	}
	return blocks
}

// aggregateBiContiguousContainmentSmall builds one wildcard ancestor and a
// many-shape fan with alternating contained and disjoint descendants.
func aggregateBiContiguousContainmentSmall(count int) []xnetip.BiContiguous {
	blocks := make([]xnetip.BiContiguous, 0, count)
	blocks = append(blocks, mustBiContiguousFromHalves(0, 8, 0, 0))
	for idx := 1; idx < count; idx++ {
		tag := uint64(idx & 0xFF)
		if idx%2 == 0 {
			tag = 0
		}
		highPrefix := 9 + idx%56
		lowPrefix := idx % 65
		highAddr := tag<<56 |
			(uint64(idx) * 0x9E37_79B9_7F4A_7C15 & 0x00FF_FFFF_FFFF_FFFF)
		lowAddr := uint64(idx)*0xBF58_476D_1CE4_E5B9 ^ 0xABCD_EF01_2345_6789
		blocks = append(blocks, mustBiContiguousFromHalves(
			highAddr,
			highPrefix,
			lowAddr,
			lowPrefix,
		))
	}
	return blocks
}

// verifies empty, singleton, inert, merge-heavy, containment and reparenting
// fixtures allocate no heap memory, including their in-place refresh copies.
func Test_AggregateBiContiguous6_AllocationFree(t *testing.T) {
	empty := []xnetip.BiContiguous{}
	requireNoAllocs(t, func() {
		intSink = len(xnetip.AggregateBiContiguous6(empty))
	})
	singleTemplate := []xnetip.BiContiguous{xnetip.MustParseBiContiguous("2001:db8::/32")}
	singleWork := make([]xnetip.BiContiguous, len(singleTemplate))
	requireNoAllocs(t, func() {
		copy(singleWork, singleTemplate)
		intSink = len(xnetip.AggregateBiContiguous6(singleWork))
	})
	fixtures := [][]xnetip.BiContiguous{
		aggregateBiContiguousNeverMerges(256, 16),
		aggregateBiContiguousMergeableGrid(256),
		aggregateBiContiguousGeo(256),
		aggregateBiContiguousReparentCascade(256),
	}
	for _, template := range fixtures {
		work := make([]xnetip.BiContiguous, len(template))
		requireNoAllocs(t, func() {
			copy(work, template)
			intSink = len(xnetip.AggregateBiContiguous6(work))
		})
	}
}

func benchmarkAggregateBiContiguous6(
	b *testing.B,
	template []xnetip.BiContiguous,
) {
	work := make([]xnetip.BiContiguous, len(template))
	b.ReportAllocs()
	for b.Loop() {
		// The O(N) fixture refresh is part of the timed aggregate cost.
		copy(work, template)
		intSink = len(xnetip.AggregateBiContiguous6(work))
	}
}

func benchmarkAggregateBiContiguous6NeverMerges(
	b *testing.B,
	count int,
) {
	template := aggregateBiContiguousNeverMerges(count, 16)
	b.Run("BiContiguous", func(b *testing.B) {
		benchmarkAggregateBiContiguous6(b, template)
	})
	plainTemplate := make([]xnetip.Network6, len(template))
	for idx, block := range template {
		plainTemplate[idx] = block.Network()
	}
	b.Run("Aggregate6", func(b *testing.B) {
		work := make([]xnetip.Network6, len(plainTemplate))
		b.ReportAllocs()
		for b.Loop() {
			copy(work, plainTemplate)
			intSink = len(xnetip.Aggregate6(work))
		}
	})
}

func BenchmarkAggregateBiContiguous6_ContainmentSmall_16(b *testing.B) {
	benchmarkAggregateBiContiguous6(b, aggregateBiContiguousContainmentSmall(16))
}

func BenchmarkAggregateBiContiguous6_ContainmentSmall_64(b *testing.B) {
	benchmarkAggregateBiContiguous6(b, aggregateBiContiguousContainmentSmall(64))
}

func BenchmarkAggregateBiContiguous6_ContainmentSmall_256(b *testing.B) {
	benchmarkAggregateBiContiguous6(b, aggregateBiContiguousContainmentSmall(256))
}

func BenchmarkAggregateBiContiguous6_NeverMerges_1024(b *testing.B) {
	benchmarkAggregateBiContiguous6NeverMerges(b, 1024)
}

func BenchmarkAggregateBiContiguous6_NeverMerges_4096(b *testing.B) {
	benchmarkAggregateBiContiguous6NeverMerges(b, 4096)
}

func BenchmarkAggregateBiContiguous6_Geo_1024(b *testing.B) {
	benchmarkAggregateBiContiguous6(b, aggregateBiContiguousGeo(1024))
}

func BenchmarkAggregateBiContiguous6_Geo_4096(b *testing.B) {
	benchmarkAggregateBiContiguous6(b, aggregateBiContiguousGeo(4096))
}

func BenchmarkAggregateBiContiguous6_MergeableGrid_1024(b *testing.B) {
	benchmarkAggregateBiContiguous6(b, aggregateBiContiguousMergeableGrid(1024))
}

func BenchmarkAggregateBiContiguous6_MergeableGrid_4096(b *testing.B) {
	benchmarkAggregateBiContiguous6(b, aggregateBiContiguousMergeableGrid(4096))
}

func BenchmarkAggregateBiContiguous6_ReparentCascade_1024(b *testing.B) {
	benchmarkAggregateBiContiguous6(b, aggregateBiContiguousReparentCascade(1024))
}

func BenchmarkAggregateBiContiguous6_ReparentCascade_4096(b *testing.B) {
	benchmarkAggregateBiContiguous6(b, aggregateBiContiguousReparentCascade(4096))
}
