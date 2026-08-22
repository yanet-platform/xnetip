// Package xnetip_test holds the black-box tests of xnetip, and this file
// its shared infrastructure: assertion helpers and rapid generators.
//
// Generators are package-level values named after the type they draw
// (genNetwork4, …), added by the session that introduces the type.
// Each draws its boundary shapes — all-zero, all-ones, host route,
// alternating and other non-contiguous masks, masks straddling bit 64 —
// with fixed weights rather than relying on shrinking, because a shrunk
// random value is rarely the interesting one. Shared helpers take the
// testify TestingT interface so they also run inside rapid.Check.
package xnetip_test

import (
	"encoding/binary"
	"iter"
	"math"
	"net/netip"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/yanet-platform/xnetip"
	"pgregory.net/rapid"
)

// requireNoAllocs stops the test when running the closure allocates.
//
// The closure is measured with testing.AllocsPerRun over 100 runs, so
// the reported number is the integer average per call. It accepts the
// testify TestingT interface, so it works under *testing.T and, inside
// rapid.Check, under *rapid.T alike.
func requireNoAllocs(t require.TestingT, run func()) {
	if helper, ok := t.(interface{ Helper() }); ok {
		helper.Helper()
	}
	allocs := int(testing.AllocsPerRun(100, run))
	require.Zero(t, allocs, "allocations per call")
}

// verifies that an allocation-free closure passes the helper.
func Test_RequireNoAllocs_PassesOnAllocationFreeCode(t *testing.T) {
	requireNoAllocs(t, func() { wordSink = wordSink&0xff00ff00 | 1 })
}

// verifies that a closure allocating on every call fails the helper
// through the fail-now path, the way a require assertion does.
func Test_RequireNoAllocs_FailsOnAllocatingCode(t *testing.T) {
	recorder := &failRecorder{}
	requireNoAllocs(recorder, func() { bytesSink = make([]byte, 64) })
	require.Equal(t, 1, recorder.errors)
	require.True(t, recorder.failedNow)
}

// verifies that the helper accepts rapid's T, so a property test can
// assert allocation freedom on every drawn input.
func Test_RequireNoAllocs_ComposesWithRapid(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		word := rapid.Uint32().Draw(t, "word")
		requireNoAllocs(t, func() { wordSink = word &^ 0x0f0f0f0f })
	})
}

// failRecorder is a require.TestingT that records failures instead of
// stopping the test, so a helper's negative path can be asserted.
type failRecorder struct {
	errors    int
	failedNow bool
}

func (m *failRecorder) Errorf(string, ...any) { m.errors++ }

func (m *failRecorder) FailNow() { m.failedNow = true }

// collectHead collects at most limit leading elements of an address
// sequence.
//
// It exists so the head of an unbounded network can be asserted
// without draining the whole sequence.
func collectHead(sequence iter.Seq[netip.Addr], limit int) []netip.Addr {
	head := []netip.Addr{}
	for addr := range sequence {
		head = append(head, addr)
		if len(head) == limit {
			break
		}
	}
	return head
}

// mustNetwork4 builds a Network4 from an address and mask pair
// given in string form, stopping the test on any constructor error.
func mustNetwork4(t require.TestingT, addr, mask string) xnetip.Network4 {
	if helper, ok := t.(interface{ Helper() }); ok {
		helper.Helper()
	}
	network, err := xnetip.Network4From(netip.MustParseAddr(addr), netip.MustParseAddr(mask))
	require.NoError(t, err)
	return network
}

// mustNetwork6 builds a Network6 from an address and mask pair
// given in string form, stopping the test on any constructor error.
func mustNetwork6(t require.TestingT, addr, mask string) xnetip.Network6 {
	if helper, ok := t.(interface{ Helper() }); ok {
		helper.Helper()
	}
	network, err := xnetip.Network6From(netip.MustParseAddr(addr), netip.MustParseAddr(mask))
	require.NoError(t, err)
	return network
}

// mustNetworkIs4 builds the Network of an Is4 address and mask pair
// given in string form, stopping the test on any constructor error.
func mustNetworkIs4(t require.TestingT, addr, mask string) xnetip.Network {
	if helper, ok := t.(interface{ Helper() }); ok {
		helper.Helper()
	}
	network, err := xnetip.NetworkFrom(netip.MustParseAddr(addr), netip.MustParseAddr(mask))
	require.NoError(t, err)
	require.True(t, network.Is4())
	return network
}

// mustNetworkIs6 builds the Network of an Is6 address and mask pair
// given in string form, stopping the test on any constructor error.
func mustNetworkIs6(t require.TestingT, addr, mask string) xnetip.Network {
	if helper, ok := t.(interface{ Helper() }); ok {
		helper.Helper()
	}
	network, err := xnetip.NetworkFrom(netip.MustParseAddr(addr), netip.MustParseAddr(mask))
	require.NoError(t, err)
	require.True(t, network.Is6())
	return network
}

// netipAddrFrom4Bits returns the Is4 netip.Addr whose host-order bit
// pattern is bits, the integer entry point for tests and generators.
func netipAddrFrom4Bits(bits uint32) netip.Addr {
	var bytes [4]byte
	binary.BigEndian.PutUint32(bytes[:], bits)
	return netip.AddrFrom4(bytes)
}

// netipAddrFrom6Bits returns the Is6 netip.Addr for host-order 64-bit
// halves, high half first.
func netipAddrFrom6Bits(hi, lo uint64) netip.Addr {
	var bytes [16]byte
	binary.BigEndian.PutUint64(bytes[:8], hi)
	binary.BigEndian.PutUint64(bytes[8:], lo)
	return netip.AddrFrom16(bytes)
}

// genNetipAddr4 draws an Is4 netip.Addr: uniform 32-bit values, with one
// draw in ten on a boundary or half-word pattern.
//
// The fixed shapes are the two extremes, the sign-bit split and the two
// half-word masks, the patterns the network generators build masks from.
// They are drawn explicitly because shrinking walks towards zero and
// rarely stops at the other boundaries.
var genNetipAddr4 = rapid.Custom(func(t *rapid.T) netip.Addr {
	var bits uint32
	if rapid.IntRange(0, 9).Draw(t, "shape") > 0 {
		bits = rapid.Uint32().Draw(t, "bits")
	} else {
		boundaries := []uint32{0, math.MaxUint32, 0x7FFFFFFF, 0x80000000, 0x0000FFFF, 0xFFFF0000}
		bits = rapid.SampledFrom(boundaries).Draw(t, "boundary")
	}
	return netipAddrFrom4Bits(bits)
})

// genNetipAddr6 draws an Is6 netip.Addr: uniform 128-bit values with
// fixed shares of IPv4-mapped and boundary patterns.
//
// One draw in five is IPv4-mapped and one in ten a boundary pattern.
// IPv4-mapped addresses are drawn explicitly because they are the Is6
// values closest to the IPv4 family and the ones most likely to slip
// through a family check that unmaps too eagerly: per the
// netip.Prefix.Contains rule, 4in6 is IPv6.
var genNetipAddr6 = rapid.Custom(func(t *rapid.T) netip.Addr {
	var hi, lo uint64
	switch rapid.IntRange(0, 9).Draw(t, "shape") {
	case 0:
		boundaries := [][2]uint64{
			{0, 0},
			{math.MaxUint64, math.MaxUint64},
			{0, math.MaxUint64},
			{math.MaxUint64, 0},
		}
		halves := rapid.SampledFrom(boundaries).Draw(t, "boundary")
		hi, lo = halves[0], halves[1]
	case 1, 2:
		hi, lo = 0, 0x0000FFFF00000000|uint64(rapid.Uint32().Draw(t, "mapped"))
	default:
		hi = rapid.Uint64().Draw(t, "hi")
		lo = rapid.Uint64().Draw(t, "lo")
	}
	return netipAddrFrom6Bits(hi, lo)
})

// genNetwork4 draws an IPv4 network through the checked
// constructor, asserting every draw normalized.
//
// The address is uniform and the mask comes from fixed-weight shapes:
// contiguous prefixes of every length, random
// patterns, the two alternating patterns, the all-zero universe mask
// and the all-ones host route, weighted 3:3:2:1:1 so the boundary
// shapes appear in every run instead of relying on shrinking. The
// normalization assertion makes every property test that draws a
// network inherit the invariant check of the type's birth session.
var genNetwork4 = rapid.Custom(func(t *rapid.T) xnetip.Network4 {
	addressBits := rapid.Uint32().Draw(t, "addr")
	var maskBits uint32
	switch rapid.IntRange(0, 9).Draw(t, "mask shape") {
	case 0, 1, 2:
		maskBits = ^uint32(0) << (32 - rapid.IntRange(0, 32).Draw(t, "prefix"))
	case 3, 4, 5:
		maskBits = rapid.Uint32().Draw(t, "mask")
	case 6, 7:
		maskBits = rapid.SampledFrom([]uint32{0xAAAAAAAA, 0x55555555}).Draw(t, "alternating")
	case 8:
		maskBits = 0
	default:
		maskBits = math.MaxUint32
	}
	network, err := xnetip.Network4From(
		netipAddrFrom4Bits(addressBits),
		netipAddrFrom4Bits(maskBits),
	)
	require.NoError(t, err)
	require.Equal(t, netipAddrFrom4Bits(addressBits&maskBits), network.Addr(), "network not normalized")
	require.Equal(t, netipAddrFrom4Bits(maskBits), network.Mask(), "mask not preserved")
	return network
})

// genIPv4Prefix draws a valid Is4 netip.Prefix with the address left
// unmasked and the length uniform over 0 through 32.
//
// It exists for differential tests against net/netip on contiguous
// networks: the prefix carries the same information as a contiguous
// network, with std as the oracle for normalization, containment and
// formatting.
var genIPv4Prefix = rapid.Custom(func(t *rapid.T) netip.Prefix {
	address := genNetipAddr4.Draw(t, "addr")
	bits := rapid.IntRange(0, 32).Draw(t, "bits")
	return netip.PrefixFrom(address, bits)
})

// genIPv4LowestBitSiblingPair draws a network with a non-empty mask
// and its buddy at the mask's lowest set bit.
//
// Such a pair is adjacent by the lowest mask bit by construction, so
// it exercises the merging case that random pairs almost never hit,
// over every mask shape the network generator draws.
var genIPv4LowestBitSiblingPair = rapid.Custom(func(t *rapid.T) [2]xnetip.Network4 {
	network := genNetwork4.Filter(func(network xnetip.Network4) bool {
		return network.Mask() != netipAddrFrom4Bits(0)
	}).Draw(t, "network")
	addrBits, maskBits := ipv4NetworkBits(network)
	buddy, err := xnetip.Network4From(
		netipAddrFrom4Bits(addrBits^(maskBits&-maskBits)),
		netipAddrFrom4Bits(maskBits),
	)
	require.NoError(t, err)
	return [2]xnetip.Network4{network, buddy}
})

// genIPv4ContiguousSiblingPair draws a CIDR network of prefix length
// one or more and its buddy at the prefix boundary bit.
//
// Both halves are contiguous, so the pair pins the class closure of
// the lowest-mask-bit merge: the parent must be contiguous too.
var genIPv4ContiguousSiblingPair = rapid.Custom(func(t *rapid.T) [2]xnetip.Network4 {
	bits := rapid.IntRange(1, 32).Draw(t, "bits")
	network, err := xnetip.Network4FromCIDR(genNetipAddr4.Draw(t, "addr"), bits)
	require.NoError(t, err)
	addrBits, maskBits := ipv4NetworkBits(network)
	buddy, err := xnetip.Network4From(
		netipAddrFrom4Bits(addrBits^(maskBits&-maskBits)),
		netipAddrFrom4Bits(maskBits),
	)
	require.NoError(t, err)
	return [2]xnetip.Network4{network, buddy}
})

// genNetwork6 draws an IPv6 network through the checked
// constructor, asserting every draw normalized.
//
// The address is uniform and the mask comes from fixed-weight shapes:
// contiguous prefixes of every length, random patterns, the alternating
// patterns, the all-zero universe mask, the all-ones host route, the
// two half-word masks and two-run masks whose set runs straddle bit 64
// — the IPv6-specific shape that catches a half-word mixup, drawn
// explicitly because shrinking rarely lands on it. The normalization
// assertion makes every property test that draws a network inherit the
// invariant check of the type's birth session.
var genNetwork6 = rapid.Custom(func(t *rapid.T) xnetip.Network6 {
	addrHi := rapid.Uint64().Draw(t, "addr hi")
	addrLo := rapid.Uint64().Draw(t, "addr lo")
	var maskHi, maskLo uint64
	switch rapid.IntRange(0, 9).Draw(t, "mask shape") {
	case 0, 1, 2:
		prefix := rapid.IntRange(0, 128).Draw(t, "prefix")
		if prefix <= 64 {
			maskHi = ^uint64(0) << (64 - prefix)
		} else {
			maskHi = ^uint64(0)
			maskLo = ^uint64(0) << (128 - prefix)
		}
	case 3, 4:
		maskHi = rapid.Uint64().Draw(t, "mask hi")
		maskLo = rapid.Uint64().Draw(t, "mask lo")
	case 5:
		alternating := rapid.SampledFrom([]uint64{0xAAAAAAAAAAAAAAAA, 0x5555555555555555}).Draw(t, "alternating")
		maskHi, maskLo = alternating, alternating
	case 6:
		maskHi, maskLo = 0, 0
	case 7:
		maskHi, maskLo = ^uint64(0), ^uint64(0)
	case 8:
		if rapid.Bool().Draw(t, "high half") {
			maskHi = ^uint64(0)
		} else {
			maskLo = ^uint64(0)
		}
	default:
		straddleHigh := rapid.IntRange(1, 32).Draw(t, "straddle bits above 64")
		straddleLow := rapid.IntRange(1, 32).Draw(t, "straddle bits below 64")
		maskHi = 0xFF00000000000000 | ^uint64(0)>>(64-straddleHigh)
		maskLo = ^uint64(0) << (64 - straddleLow)
	}
	network, err := xnetip.Network6From(
		netipAddrFrom6Bits(addrHi, addrLo),
		netipAddrFrom6Bits(maskHi, maskLo),
	)
	require.NoError(t, err)
	require.Equal(t, netipAddrFrom6Bits(addrHi&maskHi, addrLo&maskLo), network.Addr(), "network not normalized")
	require.Equal(t, netipAddrFrom6Bits(maskHi, maskLo), network.Mask(), "mask not preserved")
	return network
})

// genIPv6Prefix draws a valid Is6 netip.Prefix with the address left
// unmasked and the length uniform over 0 through 128.
//
// It exists for differential tests against net/netip on contiguous
// networks: the prefix carries the same information as a contiguous
// network, with std as the oracle for normalization, containment and
// formatting.
var genIPv6Prefix = rapid.Custom(func(t *rapid.T) netip.Prefix {
	address := genNetipAddr6.Draw(t, "addr")
	bits := rapid.IntRange(0, 128).Draw(t, "bits")
	return netip.PrefixFrom(address, bits)
})

// genIPv6BicontiguousNetwork draws a network whose mask is a product
// of a high-half prefix and a low-half prefix.
//
// Both per-half lengths are uniform over 0 through 64 and the address
// is uniform, so the draws cover the degenerate shapes — a contiguous
// mask, an empty half, a host route — alongside the two-run ones.
var genIPv6BicontiguousNetwork = rapid.Custom(func(t *rapid.T) xnetip.Network6 {
	hiPrefix := rapid.IntRange(0, 64).Draw(t, "hi prefix")
	loPrefix := rapid.IntRange(0, 64).Draw(t, "lo prefix")
	network, err := xnetip.Network6From(
		netipAddrFrom6Bits(rapid.Uint64().Draw(t, "addr hi"), rapid.Uint64().Draw(t, "addr lo")),
		netipAddrFrom6Bits(^uint64(0)<<(64-hiPrefix), ^uint64(0)<<(64-loPrefix)),
	)
	require.NoError(t, err)
	return network
})

// genIPv6LowestBitSiblingPair draws a network with a non-empty mask
// and its buddy at the mask's lowest set bit.
//
// Such a pair is adjacent by the lowest mask bit by construction, so
// it exercises the merging case that random pairs almost never hit,
// over every mask shape the network generator draws, the half-word
// and straddle masks included.
var genIPv6LowestBitSiblingPair = rapid.Custom(func(t *rapid.T) [2]xnetip.Network6 {
	network := genNetwork6.Filter(func(network xnetip.Network6) bool {
		return network.Mask() != netipAddrFrom6Bits(0, 0)
	}).Draw(t, "network")
	return ipv6SiblingPairAtLowestMaskBit(t, network)
})

// genIPv6ContiguousSiblingPair draws a CIDR network of prefix length
// one or more and its buddy at the prefix boundary bit.
//
// Both halves are contiguous, so the pair pins the class closure of
// the lowest-mask-bit merge: the parent must be contiguous too.
var genIPv6ContiguousSiblingPair = rapid.Custom(func(t *rapid.T) [2]xnetip.Network6 {
	bits := rapid.IntRange(1, 128).Draw(t, "bits")
	network, err := xnetip.Network6FromCIDR(genNetipAddr6.Draw(t, "addr"), bits)
	require.NoError(t, err)
	return ipv6SiblingPairAtLowestMaskBit(t, network)
})

// genIPv6BicontiguousSiblingPair draws a network whose mask is a
// product of per-half prefixes, the low run non-empty, and its buddy.
//
// The low half carries at least one leading one, so the lowest set
// mask bit sits in the low half and the pair pins the bi-contiguous
// class closure of the merge, the degenerate one-bit low run
// included.
var genIPv6BicontiguousSiblingPair = rapid.Custom(func(t *rapid.T) [2]xnetip.Network6 {
	hiPrefix := rapid.IntRange(0, 64).Draw(t, "hi prefix")
	loPrefix := rapid.IntRange(1, 64).Draw(t, "lo prefix")
	network, err := xnetip.Network6From(
		netipAddrFrom6Bits(rapid.Uint64().Draw(t, "addr hi"), rapid.Uint64().Draw(t, "addr lo")),
		netipAddrFrom6Bits(^uint64(0)<<(64-hiPrefix), ^uint64(0)<<(64-loPrefix)),
	)
	require.NoError(t, err)
	return ipv6SiblingPairAtLowestMaskBit(t, network)
})

// ipv6SiblingPairAtLowestMaskBit pairs a network, whose mask must be
// non-empty, with its buddy at the mask's lowest set bit.
func ipv6SiblingPairAtLowestMaskBit(t require.TestingT, network xnetip.Network6) [2]xnetip.Network6 {
	addrHi, addrLo, maskHi, maskLo := ipv6NetworkBits(network)
	var lowestHi, lowestLo uint64
	if maskLo != 0 {
		lowestLo = maskLo & -maskLo
	} else {
		lowestHi = maskHi & -maskHi
	}
	buddy, err := xnetip.Network6From(
		netipAddrFrom6Bits(addrHi^lowestHi, addrLo^lowestLo),
		netipAddrFrom6Bits(maskHi, maskLo),
	)
	require.NoError(t, err)
	return [2]xnetip.Network6{network, buddy}
}

// genNetwork draws a family-agnostic network, wrapping an IPv4 or an
// IPv6 draw with equal probability.
//
// Both branches reuse the concrete network generators, so every mask
// shape and boundary pattern they draw flows through, and each drawn
// value has already passed their normalization assertions.
var genNetwork = rapid.Custom(func(t *rapid.T) xnetip.Network {
	if rapid.Bool().Draw(t, "is4") {
		return xnetip.NetworkFrom4(genNetwork4.Draw(t, "network4"))
	}
	return xnetip.NetworkFrom6(genNetwork6.Draw(t, "network6"))
})

// genContiguous4 draws an IPv4 CIDR block: uniform prefix lengths
// with fixed weights for the universe and the host route.
//
// Every draw is asserted to wrap through the exact constructor, so
// each property test drawing a block inherits the invariant check of
// the wrapper's birth session.
var genContiguous4 = rapid.Custom(func(t *rapid.T) xnetip.Contiguous[xnetip.Network4] {
	var bits int
	switch rapid.IntRange(0, 9).Draw(t, "prefix shape") {
	case 0:
		bits = 0
	case 1:
		bits = 32
	default:
		bits = rapid.IntRange(0, 32).Draw(t, "prefix")
	}
	network, err := xnetip.Network4FromCIDR(genNetipAddr4.Draw(t, "addr"), bits)
	require.NoError(t, err)
	wrapped, ok := xnetip.ContiguousFrom(network)
	require.True(t, ok, "CIDR draw did not wrap")
	return wrapped
})

// genContiguous6 draws an IPv6 CIDR block: uniform prefix lengths
// with fixed weights for the universe and the host route.
//
// Every draw is asserted to wrap through the exact constructor, so
// each property test drawing a block inherits the invariant check of
// the wrapper's birth session.
var genContiguous6 = rapid.Custom(func(t *rapid.T) xnetip.Contiguous[xnetip.Network6] {
	var bits int
	switch rapid.IntRange(0, 9).Draw(t, "prefix shape") {
	case 0:
		bits = 0
	case 1:
		bits = 128
	default:
		bits = rapid.IntRange(0, 128).Draw(t, "prefix")
	}
	network, err := xnetip.Network6FromCIDR(genNetipAddr6.Draw(t, "addr"), bits)
	require.NoError(t, err)
	wrapped, ok := xnetip.ContiguousFrom(network)
	require.True(t, ok, "CIDR draw did not wrap")
	return wrapped
})

// prefixMask64 returns a 64-bit leading run of prefix one bits.
func prefixMask64(prefix int) uint64 {
	if prefix == 0 {
		return 0
	}
	return math.MaxUint64 << (64 - prefix)
}

// drawBiContiguousPrefix draws a per-half prefix length with fixed
// weight for the empty, one-bit, near-full and full boundary runs.
func drawBiContiguousPrefix(t *rapid.T, label string) int {
	switch rapid.IntRange(0, 9).Draw(t, label+" shape") {
	case 0:
		return 0
	case 1:
		return 1
	case 2:
		return 63
	case 3:
		return 64
	default:
		return rapid.IntRange(0, 64).Draw(t, label+" random")
	}
}

// genBiContiguous draws an IPv6 network whose mask halves are
// independent leading runs of ones.
//
// Every draw enters through the checked address-pair constructor and
// is asserted normalized, so later property tests inherit the wrapper
// invariant and the boundary-shape coverage.
var genBiContiguous = rapid.Custom(func(t *rapid.T) xnetip.BiContiguous {
	addrHi := rapid.Uint64().Draw(t, "addr hi")
	addrLo := rapid.Uint64().Draw(t, "addr lo")
	maskHi := prefixMask64(drawBiContiguousPrefix(t, "high prefix"))
	maskLo := prefixMask64(drawBiContiguousPrefix(t, "low prefix"))
	wrapper, err := xnetip.BiContiguousFrom(
		netipAddrFrom6Bits(addrHi, addrLo),
		netipAddrFrom6Bits(maskHi, maskLo),
	)
	require.NoError(t, err)
	require.Equal(t, netipAddrFrom6Bits(addrHi&maskHi, addrLo&maskLo), wrapper.Network().Addr())
	require.Equal(t, netipAddrFrom6Bits(maskHi, maskLo), wrapper.Network().Mask())
	return wrapper
})

// genContiguous draws a family-agnostic CIDR block, reusing the
// concrete block generators with a fixed share of IPv4-mapped IPv6.
//
// Two draws in five are IPv4, one is an IPv4-mapped IPv6 network —
// the Is6 shape closest to the IPv4 family — and the rest are plain
// IPv6, so both families and the mapped edge flow through every
// property test. Every draw is asserted to wrap through the exact
// constructor.
var genContiguous = rapid.Custom(func(t *rapid.T) xnetip.Contiguous[xnetip.Network] {
	var network xnetip.Network
	switch rapid.IntRange(0, 4).Draw(t, "family shape") {
	case 0, 1:
		network = xnetip.NetworkFrom4(genContiguous4.Draw(t, "network4").Network())
	case 2:
		mapped := netipAddrFrom6Bits(0, 0x0000FFFF00000000|uint64(rapid.Uint32().Draw(t, "mapped")))
		fromCIDR, err := xnetip.NetworkFromCIDR(mapped, rapid.IntRange(0, 128).Draw(t, "mapped prefix"))
		require.NoError(t, err)
		network = fromCIDR
	default:
		network = xnetip.NetworkFrom6(genContiguous6.Draw(t, "network6").Network())
	}
	wrapped, ok := xnetip.ContiguousFrom(network)
	require.True(t, ok, "CIDR draw did not wrap")
	return wrapped
})

// digitsOnly reports whether text is non-empty and all ASCII digits.
//
// This is the shape a CIDR suffix must have for the std-parity checks
// of the parser fuzz suites.
func digitsOnly(text string) bool {
	if text == "" {
		return false
	}
	for idx := range len(text) {
		if text[idx] < '0' || text[idx] > '9' {
			return false
		}
	}
	return true
}

// Sinks keep the measured closures' results alive, so the compiler cannot
// optimise the work under test away.
var (
	wordSink         uint32
	stringSink       string
	intSink          int
	bytesSink        []byte
	networkSink      xnetip.Network4
	network6Sink     xnetip.Network6
	ipNetworkSink    xnetip.Network
	addrSink         netip.Addr
	prefixSink       netip.Prefix
	okSink           bool
	contiguous4Sink  xnetip.Contiguous[xnetip.Network4]
	contiguous6Sink  xnetip.Contiguous[xnetip.Network6]
	contiguousSink   xnetip.Contiguous[xnetip.Network]
	biContiguousSink xnetip.BiContiguous
	errSink          error
)
