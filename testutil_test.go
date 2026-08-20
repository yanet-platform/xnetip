// Package xnetip_test holds the black-box tests of xnetip, and this file
// its shared infrastructure: assertion helpers and rapid generators.
//
// Generators are package-level values named after the type they draw
// (genIPv4Network, …), added by the session that introduces the type.
// Each draws its boundary shapes — all-zero, all-ones, host route,
// alternating and other non-contiguous masks, masks straddling bit 64 —
// with fixed weights rather than relying on shrinking, because a shrunk
// random value is rarely the interesting one. Shared helpers take the
// testify TestingT interface so they also run inside rapid.Check.
package xnetip_test

import (
	"encoding/binary"
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
	var bytes [4]byte
	binary.BigEndian.PutUint32(bytes[:], bits)
	return netip.AddrFrom4(bytes)
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
	var bytes [16]byte
	binary.BigEndian.PutUint64(bytes[:8], hi)
	binary.BigEndian.PutUint64(bytes[8:], lo)
	return netip.AddrFrom16(bytes)
})

// genIPv4Network draws an IPv4 network through the total integer
// constructor, asserting every draw normalized.
//
// The address is uniform and the mask comes from fixed-weight shapes:
// contiguous prefixes of every length, random
// patterns, the two alternating patterns, the all-zero universe mask
// and the all-ones host route, weighted 3:3:2:1:1 so the boundary
// shapes appear in every run instead of relying on shrinking. The
// normalization assertion makes every property test that draws a
// network inherit the invariant check of the type's birth session.
var genIPv4Network = rapid.Custom(func(t *rapid.T) xnetip.IPv4Network {
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
	network := xnetip.IPv4NetworkFromBits(addressBits, maskBits)
	networkAddr, networkMask := network.Bits()
	require.Equal(t, networkAddr&networkMask, networkAddr, "network not normalized")
	require.Equal(t, maskBits, networkMask, "mask not preserved")
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

// genIPv6Network draws an IPv6 network through the total integer
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
var genIPv6Network = rapid.Custom(func(t *rapid.T) xnetip.IPv6Network {
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
	network := xnetip.IPv6NetworkFromBits(addrHi, addrLo, maskHi, maskLo)
	networkAddrHi, networkAddrLo, networkMaskHi, networkMaskLo := network.Bits()
	require.Equal(t, networkAddrHi&networkMaskHi, networkAddrHi, "network high half not normalized")
	require.Equal(t, networkAddrLo&networkMaskLo, networkAddrLo, "network low half not normalized")
	require.Equal(t, maskHi, networkMaskHi, "mask high half not preserved")
	require.Equal(t, maskLo, networkMaskLo, "mask low half not preserved")
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

// Sinks keep the measured closures' results alive, so the compiler cannot
// optimise the work under test away.
var (
	wordSink     uint32
	word64Sink   uint64
	bytesSink    []byte
	networkSink  xnetip.IPv4Network
	network6Sink xnetip.IPv6Network
	addrSink     netip.Addr
	okSink       bool
)
