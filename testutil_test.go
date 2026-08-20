// Package xnetip_test holds the black-box tests of xnetip, and this file
// its shared infrastructure: assertion helpers and rapid generators.
//
// Generators are package-level values named after the type they draw
// (genIPv4Addr, genIPv4Network, …), added by the session that introduces
// the type. Each draws its boundary shapes — all-zero, all-ones, host
// route, alternating and other non-contiguous masks, masks straddling
// bit 64 — with fixed weights rather than relying on shrinking, because
// a shrunk random value is rarely the interesting one. Shared helpers
// take the testify TestingT interface so they also run inside rapid.Check.
package xnetip_test

import (
	"math"
	"net/netip"
	"testing"

	"github.com/stretchr/testify/require"
	"pgregory.net/rapid"

	"github.com/yanet-platform/xnetip"
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

// genIPv4Addr draws an IPv4 address: uniform over the 32-bit space, with
// one draw in ten landing on a boundary or half-word pattern.
//
// The fixed shapes are the two extremes, the sign-bit split, and the two
// half-word masks, the patterns the network generators later build
// masks from. They are drawn explicitly because shrinking walks towards
// zero and rarely stops at the other boundaries.
var genIPv4Addr = rapid.Custom(func(t *rapid.T) xnetip.IPv4Addr {
	if rapid.IntRange(0, 9).Draw(t, "shape") > 0 {
		return xnetip.IPv4AddrFromBits(rapid.Uint32().Draw(t, "bits"))
	}
	boundaries := []uint32{0, math.MaxUint32, 0x7FFFFFFF, 0x80000000, 0x0000FFFF, 0xFFFF0000}
	return xnetip.IPv4AddrFromBits(rapid.SampledFrom(boundaries).Draw(t, "boundary"))
})

// genIPv6Addr draws an IPv6 address: uniform over the 128-bit space,
// with three draws in ten on a boundary, mapped or edge-group shape.
//
// The fixed shapes are the two extremes, each half alone at its extreme,
// the top bit alone, the bottom bit alone, a mapped address with a random
// IPv4 part, and addresses whose first group sits on either side of a
// classification range edge (fe80::/10, ff00::/8, fc00::/7 and the
// multicast scopes) — the patterns the IPv6 mask generators later build
// from and the predicate suites classify. They are drawn explicitly
// because shrinking walks towards zero and rarely stops at the other
// boundaries.
var genIPv6Addr = rapid.Custom(func(t *rapid.T) xnetip.IPv6Addr {
	switch rapid.IntRange(0, 9).Draw(t, "shape") {
	case 0:
		boundaries := [][2]uint64{
			{0, 0},
			{math.MaxUint64, math.MaxUint64},
			{0, math.MaxUint64},
			{math.MaxUint64, 0},
			{1 << 63, 0},
			{0, 1},
		}
		halves := rapid.SampledFrom(boundaries).Draw(t, "boundary")
		return xnetip.IPv6AddrFromBits(halves[0], halves[1])
	case 1:
		mapped := 0x0000ffff00000000 | uint64(rapid.Uint32().Draw(t, "mapped"))
		return xnetip.IPv6AddrFromBits(0, mapped)
	case 2:
		groups := []uint64{
			0xfbff, 0xfc00, 0xfdff, 0xfe00, 0xfe7f, 0xfe80, 0xfebf, 0xfec0,
			0xfeff, 0xff00, 0xff01, 0xff02, 0xff0f, 0xff11, 0xff12, 0xffff,
		}
		group := rapid.SampledFrom(groups).Draw(t, "group")
		tail := rapid.Uint64Range(0, 1<<48-1).Draw(t, "tail")
		return xnetip.IPv6AddrFromBits(group<<48|tail, rapid.Uint64().Draw(t, "lo"))
	default:
		return xnetip.IPv6AddrFromBits(rapid.Uint64().Draw(t, "hi"), rapid.Uint64().Draw(t, "lo"))
	}
})

// failRecorder is a require.TestingT that records failures instead of
// stopping the test, so a helper's negative path can be asserted.
type failRecorder struct {
	errors    int
	failedNow bool
}

func (m *failRecorder) Errorf(string, ...any) { m.errors++ }

func (m *failRecorder) FailNow() { m.failedNow = true }

// Sinks keep the measured closures' results alive, so the compiler cannot
// optimise the work under test away.
var (
	wordSink      uint32
	intSink       int
	boolSink      bool
	bytesSink     []byte
	stringSink    string
	errSink       error
	ipv4AddrSink  xnetip.IPv4Addr
	ipv6AddrSink  xnetip.IPv6Addr
	netipAddrSink netip.Addr
)
