package xnetip_test

import (
	"encoding"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/netip"
	"strconv"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/yanet-platform/xnetip"
	"pgregory.net/rapid"
)

var (
	_ fmt.Stringer             = xnetip.BiContiguous{}
	_ encoding.TextMarshaler   = xnetip.BiContiguous{}
	_ encoding.TextUnmarshaler = (*xnetip.BiContiguous)(nil)
)

// mustBiContiguous wraps a parsed IPv6 network fixture, stopping the
// test when either its text or its per-half mask shape is invalid.
func mustBiContiguous(t require.TestingT, text string) xnetip.BiContiguous {
	if helper, ok := t.(interface{ Helper() }); ok {
		helper.Helper()
	}
	wrapper, ok := xnetip.BiContiguousFrom6(xnetip.MustParseNetwork6(text))
	require.True(t, ok, "fixture mask is not bi-contiguous")
	return wrapper
}

// maskHalfPrefixLenOracle counts leading one bits in one eight-byte mask half.
func maskHalfPrefixLenOracle(mask [16]byte, offset int) int {
	prefix := 0
	for byteOffset := range 8 {
		word := mask[offset+byteOffset]
		for bitOffset := range 8 {
			if word&(1<<uint(7-bitOffset)) == 0 {
				return prefix
			}
			prefix++
		}
	}
	return prefix
}

// verifies that the bi-contiguous shape rejection has its own stable
// sentinel text, distinct from the stricter CIDR shape rejection.
func Test_ErrNonBiContiguousMask_HasDedicatedText(t *testing.T) {
	require.Equal(t, "mask not bi-contiguous", xnetip.ErrNonBiContiguousMask.Error())
	require.NotEqual(t, xnetip.ErrNonContiguousMask, xnetip.ErrNonBiContiguousMask)
}

// verifies that the representative two-run, degenerate and half-boundary
// mask shapes enter through the exact conversion unchanged.
func Test_BiContiguousFrom6_AcceptsUnitAndBoundaryShapes(t *testing.T) {
	cases := []struct {
		name string
		text string
	}{
		{
			name: "motivating two-run mask",
			text: "2a02:6b8:c00::1234:abcd:0:0/ffff:ffff:ff00::ffff:ffff:0:0",
		},
		{name: "empty mask", text: "::/::"},
		{name: "host route", text: "::1/128"},
		{name: "low-half-only run", text: "::/::8000:0:0:0"},
		{name: "globally contiguous below half", text: "2001:db8::/40"},
		{name: "globally contiguous above half", text: "2001:db8::/96"},
		{name: "one-bit gap at half boundary", text: "::/ffff:ffff:ffff:fffe:8000::"},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			network := xnetip.MustParseNetwork6(testCase.text)
			wrapper, ok := xnetip.BiContiguousFrom6(network)
			require.True(t, ok)
			require.Equal(t, network, wrapper.Network())
		})
	}
}

// verifies that an interior hole in either half and an isolated tail bit
// are rejected by the exact conversion with the zero wrapper returned.
func Test_BiContiguousFrom6_RejectsInvalidShapes(t *testing.T) {
	cases := []struct {
		name string
		text string
	}{
		{name: "hole in high half", text: "::/ffff:0:ffff::"},
		{name: "hole in low half", text: "::/ffff:ffff::f0f0:f0f0:f0f0:f0f0"},
		{name: "isolated low tail bit", text: "::/::1"},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			wrapper, ok := xnetip.BiContiguousFrom6(xnetip.MustParseNetwork6(testCase.text))
			require.False(t, ok)
			require.Equal(t, xnetip.BiContiguous{}, wrapper)
		})
	}
}

// verifies that the zero wrapper is the valid IPv6 universe network.
func Test_BiContiguous_ZeroValueIsUniverse(t *testing.T) {
	require.Equal(t, xnetip.MustParseNetwork6("::/0"), xnetip.BiContiguous{}.Network())

	wrapper, ok := xnetip.BiContiguousFrom6(xnetip.Network6{})
	require.True(t, ok)
	require.Equal(t, xnetip.BiContiguous{}, wrapper)
}

// verifies that checked address-pair construction normalizes host bits,
// accepts mapped IPv6, and drops zones from either input.
func Test_BiContiguousFrom_NormalizesAndAcceptsIPv6Forms(t *testing.T) {
	cases := []struct {
		name string
		addr netip.Addr
		mask netip.Addr
		want xnetip.Network6
	}{
		{
			name: "host bits under two runs",
			addr: netip.MustParseAddr("2a02:6b8:cff:1234:ffff:ffff:abcd:ef01"),
			mask: netip.MustParseAddr("ffff:ffff:ff00::ffff:ffff:0:0"),
			want: mustNetwork6(t, "2a02:6b8:c00::ffff:ffff:0:0", "ffff:ffff:ff00::ffff:ffff:0:0"),
		},
		{
			name: "IPv4-mapped IPv6",
			addr: netip.MustParseAddr("::ffff:192.0.2.129"),
			mask: netip.MustParseAddr("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ff00"),
			want: xnetip.MustParseNetwork6("::ffff:192.0.2.0/120"),
		},
		{
			name: "zone on address",
			addr: netip.MustParseAddr("fe80::1234%eth0"),
			mask: netip.MustParseAddr("ffff:ffff:ffff:ffff::"),
			want: xnetip.MustParseNetwork6("fe80::/64"),
		},
		{
			name: "zone on mask",
			addr: netip.MustParseAddr("2001:db8::1234"),
			mask: netip.MustParseAddr("ffff:ffff:ffff:ffff::%mask"),
			want: xnetip.MustParseNetwork6("2001:db8::/64"),
		},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			wrapper, err := xnetip.BiContiguousFrom(testCase.addr, testCase.mask)
			require.NoError(t, err)
			require.Equal(t, testCase.want, wrapper.Network())
			require.Empty(t, wrapper.Network().Addr().Zone())
			require.Empty(t, wrapper.Network().Mask().Zone())
		})
	}
}

// verifies that either non-IPv6 input is rejected under the constructor's
// own name with the family sentinel, exact input and zero result.
func Test_BiContiguousFrom_RejectsFamilyMismatch(t *testing.T) {
	cases := []struct {
		name        string
		addr        netip.Addr
		mask        netip.Addr
		wantMessage string
	}{
		{
			name:        "IPv4 address",
			addr:        netip.MustParseAddr("192.0.2.1"),
			mask:        netip.MustParseAddr("ffff::"),
			wantMessage: `xnetip.BiContiguousFrom("192.0.2.1/ffff::"): address family mismatch`,
		},
		{
			name:        "IPv4 mask",
			addr:        netip.MustParseAddr("2001:db8::1"),
			mask:        netip.MustParseAddr("192.0.2.1"),
			wantMessage: `xnetip.BiContiguousFrom("2001:db8::1/192.0.2.1"): address family mismatch`,
		},
		{
			name:        "invalid zero address",
			addr:        netip.Addr{},
			mask:        netip.MustParseAddr("ffff::"),
			wantMessage: `xnetip.BiContiguousFrom("invalid IP/ffff::"): address family mismatch`,
		},
		{
			name:        "invalid zero mask",
			addr:        netip.MustParseAddr("2001:db8::1"),
			mask:        netip.Addr{},
			wantMessage: `xnetip.BiContiguousFrom("2001:db8::1/invalid IP"): address family mismatch`,
		},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			wrapper, err := xnetip.BiContiguousFrom(testCase.addr, testCase.mask)
			require.ErrorIs(t, err, xnetip.ErrAddrFamilyMismatch)
			require.Equal(t, testCase.wantMessage, err.Error())
			require.Equal(t, xnetip.BiContiguous{}, wrapper)
		})
	}
}

// verifies that valid IPv6 masks with an interior hole wrap the dedicated
// shape sentinel under the checked constructor's own name.
func Test_BiContiguousFrom_RejectsInvalidShapes(t *testing.T) {
	cases := []struct {
		name        string
		mask        netip.Addr
		wantMessage string
	}{
		{
			name:        "hole in high half",
			mask:        netip.MustParseAddr("ffff:0:ffff::"),
			wantMessage: `xnetip.BiContiguousFrom("2001:db8::1/ffff:0:ffff::"): mask not bi-contiguous`,
		},
		{
			name:        "hole in low half",
			mask:        netip.MustParseAddr("ffff:ffff::f0f0:f0f0:f0f0:f0f0"),
			wantMessage: `xnetip.BiContiguousFrom("2001:db8::1/ffff:ffff::f0f0:f0f0:f0f0:f0f0"): mask not bi-contiguous`,
		},
		{
			name:        "isolated low tail bit",
			mask:        netip.MustParseAddr("::1"),
			wantMessage: `xnetip.BiContiguousFrom("2001:db8::1/::1"): mask not bi-contiguous`,
		},
	}
	addr := netip.MustParseAddr("2001:db8::1")
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			wrapper, err := xnetip.BiContiguousFrom(addr, testCase.mask)
			require.ErrorIs(t, err, xnetip.ErrNonBiContiguousMask)
			require.Equal(t, testCase.wantMessage, err.Error())
			require.Equal(t, xnetip.BiContiguous{}, wrapper)
		})
	}
}

// verifies that all 4,225 products of per-half prefix masks construct,
// normalize, unwrap and rewrap without changing the network.
func Test_BiContiguousFrom_AcceptsEveryShape(t *testing.T) {
	addr := netipAddrFrom6Bits(math.MaxUint64, math.MaxUint64)
	for highPrefix := 0; highPrefix <= 64; highPrefix++ {
		for lowPrefix := 0; lowPrefix <= 64; lowPrefix++ {
			mask := netipAddrFrom6Bits(prefixMask64(highPrefix), prefixMask64(lowPrefix))
			wrapper, err := xnetip.BiContiguousFrom(addr, mask)
			require.NoError(t, err, "high prefix %d, low prefix %d", highPrefix, lowPrefix)

			expected, err := xnetip.Network6From(addr, mask)
			require.NoError(t, err)
			require.Equal(t, expected, wrapper.Network(), "high prefix %d, low prefix %d", highPrefix, lowPrefix)

			rewrapped, ok := xnetip.BiContiguousFrom6(expected)
			require.True(t, ok, "high prefix %d, low prefix %d", highPrefix, lowPrefix)
			require.Equal(t, wrapper, rewrapped, "high prefix %d, low prefix %d", highPrefix, lowPrefix)
		}
	}
}

// verifies that punching any non-tail bit out of either full half leaves
// a later set bit and is rejected as an interior hole.
func Test_BiContiguousFrom_RejectsEveryInteriorHole(t *testing.T) {
	addr := netipAddrFrom6Bits(math.MaxUint64, math.MaxUint64)
	for bit := 1; bit < 64; bit++ {
		highMask := math.MaxUint64 &^ (uint64(1) << bit)
		wrapper, err := xnetip.BiContiguousFrom(
			addr,
			netipAddrFrom6Bits(highMask, math.MaxUint64),
		)
		require.ErrorIs(t, err, xnetip.ErrNonBiContiguousMask, "high-half bit %d", bit)
		require.Equal(t, xnetip.BiContiguous{}, wrapper)

		lowMask := math.MaxUint64 &^ (uint64(1) << bit)
		wrapper, err = xnetip.BiContiguousFrom(
			addr,
			netipAddrFrom6Bits(math.MaxUint64, lowMask),
		)
		require.ErrorIs(t, err, xnetip.ErrNonBiContiguousMask, "low-half bit %d", bit)
		require.Equal(t, xnetip.BiContiguous{}, wrapper)
	}
}

// verifies that every boundary CIDR length lifts without validation and
// keeps the wrapped IPv6 network byte-for-byte equal.
func Test_BiContiguousFromContiguous_LiftsBoundaryPrefixes(t *testing.T) {
	addr := netip.MustParseAddr("2001:db8:ffff:ffff:ffff:ffff:ffff:ffff")
	for _, bits := range []int{0, 40, 64, 96, 128} {
		block, err := xnetip.ContiguousFromCIDR6(addr, bits)
		require.NoError(t, err)

		wrapper := xnetip.BiContiguousFromContiguous(block)
		require.Equal(t, block.Network(), wrapper.Network(), "prefix length %d", bits)
		rewrapped, ok := xnetip.BiContiguousFrom6(wrapper.Network())
		require.True(t, ok)
		require.Equal(t, wrapper, rewrapped)
	}
}

// verifies that prefix, explicit-mask and bare-address forms enter the
// bi-contiguous wrapper with normalization and IPv6 family semantics.
func Test_ParseBiContiguous_AcceptsFormsAndBoundaries(t *testing.T) {
	cases := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "motivating high 40 low 32 mask",
			input: "2a02:6b8:c00::1234:abcd:0:0/ffff:ffff:ff00::ffff:ffff:0:0",
			want:  "2a02:6b8:c00::1234:abcd:0:0/ffff:ffff:ff00::ffff:ffff:0:0",
		},
		{
			name:  "motivating high 40 low 16 mask",
			input: "2a02:6b8:c00::1234:0:0:0/ffff:ffff:ff00::ffff:0:0:0",
			want:  "2a02:6b8:c00::1234:0:0:0/ffff:ffff:ff00::ffff:0:0:0",
		},
		{name: "explicit empty mask", input: "::/::", want: "::/0"},
		{name: "bare address is host route", input: "::1", want: "::1/128"},
		{
			name:  "low-half-only run",
			input: "::/::8000:0:0:0",
			want:  "::/::8000:0:0:0",
		},
		{name: "CIDR below half boundary", input: "2001:db8::/40", want: "2001:db8::/40"},
		{name: "CIDR at half boundary", input: "2001:db8::/64", want: "2001:db8::/64"},
		{name: "CIDR above half boundary", input: "2001:db8::/96", want: "2001:db8::/96"},
		{
			name:  "independent runs meet across half boundary",
			input: "::/ffff:ffff:ffff:fffe:8000::",
			want:  "::/ffff:ffff:ffff:fffe:8000::",
		},
		{
			name:  "mapped IPv6 host route",
			input: "::ffff:192.0.2.1/128",
			want:  "::ffff:192.0.2.1/128",
		},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			wrapper, err := xnetip.ParseBiContiguous(testCase.input)
			require.NoError(t, err)
			require.Equal(t, xnetip.MustParseNetwork6(testCase.want), wrapper.Network())
		})
	}
}

// verifies that an interior hole in either mask half is rejected with
// only the shape sentinel, the parser's own name and the zero wrapper.
func Test_ParseBiContiguous_RejectsInvalidShapes(t *testing.T) {
	cases := []struct {
		name  string
		input string
	}{
		{name: "isolated low bit", input: "::/::1"},
		{name: "high-half interior hole", input: "::/ffff:0:ffff::"},
		{
			name:  "low-half interior hole",
			input: "2a02:6b8:0:0:1234:5678::/ffff:ffff:0:0:f0f0:f0f0:f0f0:f0f0",
		},
	}
	otherSentinels := []error{
		xnetip.ErrParse,
		xnetip.ErrAddrFamilyMismatch,
		xnetip.ErrZone,
		xnetip.ErrCIDROverflow,
		xnetip.ErrInvalidMask,
		xnetip.ErrNonContiguousMask,
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			wrapper, err := xnetip.ParseBiContiguous(testCase.input)
			require.ErrorIs(t, err, xnetip.ErrNonBiContiguousMask)
			require.Equal(
				t,
				"xnetip.ParseBiContiguous("+strconv.Quote(testCase.input)+"): mask not bi-contiguous",
				err.Error(),
			)
			for _, sentinel := range otherSentinels {
				require.NotErrorIs(t, err, sentinel, "unexpected sentinel %v", sentinel)
			}
			require.Equal(t, xnetip.BiContiguous{}, wrapper)
		})
	}
}

// verifies that every network-grammar rejection is returned unchanged
// from the plain IPv6 parser while the wrapper result stays zero.
func Test_ParseBiContiguous_PreservesNetworkParserErrors(t *testing.T) {
	cases := []struct {
		name      string
		input     string
		sentinels []error
	}{
		{name: "IPv4 address", input: "192.0.2.1/24", sentinels: []error{xnetip.ErrAddrFamilyMismatch}},
		{
			name:  "IPv4 mask",
			input: "2001:db8::/255.255.255.0",
			sentinels: []error{
				xnetip.ErrInvalidMask,
				xnetip.ErrAddrFamilyMismatch,
			},
		},
		{name: "zone in address", input: "fe80::1%eth0/64", sentinels: []error{xnetip.ErrZone}},
		{
			name:  "zone in mask",
			input: "fe80::/ffff::%eth0",
			sentinels: []error{
				xnetip.ErrInvalidMask,
				xnetip.ErrZone,
			},
		},
		{name: "empty input", input: "", sentinels: []error{xnetip.ErrParse}},
		{name: "bad address hex", input: "gggg::/64", sentinels: []error{xnetip.ErrParse}},
		{
			name:      "duplicate slash",
			input:     "2001:db8:://64",
			sentinels: []error{xnetip.ErrInvalidMask},
		},
		{
			name:      "bad mask hex",
			input:     "2001:db8::/gggg::",
			sentinels: []error{xnetip.ErrInvalidMask},
		},
		{
			name:      "plus-prefixed length",
			input:     "2001:db8::/+64",
			sentinels: []error{xnetip.ErrInvalidMask},
		},
		{
			name:      "leading-zero length",
			input:     "2001:db8::/064",
			sentinels: []error{xnetip.ErrInvalidMask},
		},
		{
			name:      "prefix overflow",
			input:     "2001:db8::/129",
			sentinels: []error{xnetip.ErrCIDROverflow},
		},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			_, networkErr := xnetip.ParseNetwork6(testCase.input)
			require.Error(t, networkErr)

			wrapper, err := xnetip.ParseBiContiguous(testCase.input)
			require.Error(t, err)
			for _, sentinel := range testCase.sentinels {
				require.ErrorIs(t, err, sentinel)
			}
			require.NotErrorIs(t, err, xnetip.ErrNonBiContiguousMask)
			require.EqualError(t, err, networkErr.Error())
			require.Equal(t, xnetip.BiContiguous{}, wrapper)
		})
	}
}

// verifies that every pair of per-half prefix lengths survives text
// formatting and parsing with its normalized network unchanged.
func Test_ParseBiContiguous_AcceptsEveryShape(t *testing.T) {
	addr := netipAddrFrom6Bits(math.MaxUint64, math.MaxUint64)
	for highPrefix := 0; highPrefix <= 64; highPrefix++ {
		for lowPrefix := 0; lowPrefix <= 64; lowPrefix++ {
			mask := netipAddrFrom6Bits(prefixMask64(highPrefix), prefixMask64(lowPrefix))
			network, err := xnetip.Network6From(addr, mask)
			require.NoError(t, err)

			wrapper, err := xnetip.ParseBiContiguous(network.String())
			require.NoError(t, err, "high prefix %d, low prefix %d", highPrefix, lowPrefix)
			require.Equal(
				t,
				network,
				wrapper.Network(),
				"high prefix %d, low prefix %d",
				highPrefix,
				lowPrefix,
			)
		}
	}
}

// verifies that every generated wrapper's inner network text parses back
// to the same guarantee-bearing value.
func Test_ParseBiContiguous_RoundTripsGeneratedWrapperProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		wrapper := genBiContiguous.Draw(t, "wrapper")
		parsed, err := xnetip.ParseBiContiguous(wrapper.Network().String())
		require.NoError(t, err)
		require.Equal(t, wrapper, parsed)
	})
}

// verifies that parsing arbitrary IPv6 network text succeeds exactly when
// the plain parsed network has two individually contiguous mask halves.
func Test_ParseBiContiguous_MatchesNetworkShapeProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		network := genNetwork6.Draw(t, "network")
		input := network.String()
		plain, plainErr := xnetip.ParseNetwork6(input)
		require.NoError(t, plainErr)
		require.Equal(t, network, plain)

		wrapper, err := xnetip.ParseBiContiguous(input)
		if network.IsBicontiguous() {
			require.NoError(t, err)
			require.Equal(t, network, wrapper.Network())
			return
		}
		require.ErrorIs(t, err, xnetip.ErrNonBiContiguousMask)
		require.Equal(t, xnetip.BiContiguous{}, wrapper)
	})
}

// verifies that text rejected by the plain IPv6 parser keeps exactly its
// stable sentinel classes when routed through the wrapper parser.
func Test_ParseBiContiguous_MatchesNetworkErrorSetProperty(t *testing.T) {
	corpus := []string{
		"", "/", "/64", "hello", "zz::/64", " 2001:db8::/32",
		"2001:db8::/129", "2001:db8::/064", "2001:db8::/+64",
		"2001:db8:://64", "2001:db8::/not-a-mask", "fe80::1%eth0/64",
		"fe80::/ffff::%eth0", "192.0.2.1/24", "2001:db8::/255.255.255.0",
	}
	sentinels := []error{
		xnetip.ErrParse,
		xnetip.ErrAddrFamilyMismatch,
		xnetip.ErrZone,
		xnetip.ErrCIDROverflow,
		xnetip.ErrInvalidMask,
	}
	rapid.Check(t, func(t *rapid.T) {
		input := rapid.SampledFrom(corpus).Draw(t, "input")
		_, networkErr := xnetip.ParseNetwork6(input)
		require.Error(t, networkErr)

		wrapper, err := xnetip.ParseBiContiguous(input)
		require.Error(t, err)
		for _, sentinel := range sentinels {
			require.Equal(t, errors.Is(networkErr, sentinel), errors.Is(err, sentinel))
		}
		require.NotErrorIs(t, err, xnetip.ErrNonBiContiguousMask)
		require.EqualError(t, err, networkErr.Error())
		require.Equal(t, xnetip.BiContiguous{}, wrapper)
	})
}

// verifies that the must parser returns valid input and panics with either
// a shape failure or a malformed-network failure.
func Test_MustParseBiContiguous_ReturnsOrPanics(t *testing.T) {
	input := "2a02:6b8:c00::1234:abcd:0:0/ffff:ffff:ff00::ffff:ffff:0:0"
	require.Equal(t, mustBiContiguous(t, input), xnetip.MustParseBiContiguous(input))
	require.Panics(t, func() { xnetip.MustParseBiContiguous("::/::1") })
	require.Panics(t, func() { xnetip.MustParseBiContiguous("not-a-network") })
}

// verifies that successful prefix and genuine two-run parses allocate no
// heap memory beyond their allocation-free inner parser.
func Test_ParseBiContiguous_AllocationFree(t *testing.T) {
	requireNoAllocs(t, func() {
		biContiguousSink, errSink = xnetip.ParseBiContiguous("2001:db8::/48")
	})
	requireNoAllocs(t, func() {
		biContiguousSink, errSink = xnetip.ParseBiContiguous(
			"2a02:6b8:c00::1234:abcd:0:0/ffff:ffff:ff00::ffff:ffff:0:0",
		)
	})
}

// verifies that arbitrary input follows the plain parser and shape
// predicate oracle without panicking or changing successful networks.
func FuzzParseBiContiguous(f *testing.F) {
	seeds := []string{
		"2001:db8::/48",
		"2a02:6b8:c00::1234:abcd:0:0/ffff:ffff:ff00::ffff:ffff:0:0",
		"2a02:6b8:c00::1234:0:0:0/ffff:ffff:ff00::ffff:0:0:0",
		"::/::",
		"::ffff:192.0.2.1/128",
		"::/ffff:0:ffff::",
		"::/ffff:ffff::f0f0:f0f0:f0f0:f0f0",
		"fe80::1%eth0/64",
		"2001:db8::/+64",
		"2001:db8::/064",
		"2001:db8::/129",
		"not-a-network",
		"",
	}
	for _, seed := range seeds {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, input string) {
		wrapper, err := xnetip.ParseBiContiguous(input)
		network, networkErr := xnetip.ParseNetwork6(input)
		switch {
		case networkErr != nil:
			if err == nil {
				t.Fatalf("accepted %q, which the network parser rejects: %v", input, networkErr)
			}
			if err.Error() != networkErr.Error() {
				t.Fatalf("parser error changed for %q: wrapper %v, network %v", input, err, networkErr)
			}
			for _, sentinel := range []error{
				xnetip.ErrParse,
				xnetip.ErrAddrFamilyMismatch,
				xnetip.ErrZone,
				xnetip.ErrCIDROverflow,
				xnetip.ErrInvalidMask,
			} {
				if errors.Is(err, sentinel) != errors.Is(networkErr, sentinel) {
					t.Fatalf(
						"sentinel %v differs for %q: wrapper %v, network %v",
						sentinel,
						input,
						err,
						networkErr,
					)
				}
			}
			if errors.Is(err, xnetip.ErrNonBiContiguousMask) {
				t.Fatalf("plain parser failure %q gained the shape sentinel: %v", input, err)
			}
		case network.IsBicontiguous():
			if err != nil {
				t.Fatalf("rejected bi-contiguous %q: %v", input, err)
			}
			if wrapper.Network() != network {
				t.Fatalf("parsed %q as %v, the network parser says %v", input, wrapper.Network(), network)
			}
			back, backErr := xnetip.ParseBiContiguous(wrapper.Network().String())
			if backErr != nil || back != wrapper {
				t.Fatalf("round trip of %q changed the wrapper: %v, %v", input, back, backErr)
			}
		default:
			if !errors.Is(err, xnetip.ErrNonBiContiguousMask) {
				t.Fatalf("non-bi-contiguous %q must wrap the shape sentinel, got %v", input, err)
			}
			if wrapper != (xnetip.BiContiguous{}) {
				t.Fatalf("non-bi-contiguous %q returned a non-zero wrapper: %v", input, wrapper)
			}
		}
	})
}

func BenchmarkParseBiContiguous_CIDR(b *testing.B) {
	b.ReportAllocs()
	for b.Loop() {
		biContiguousSink, errSink = xnetip.ParseBiContiguous("2001:db8::/48")
	}
}

func BenchmarkParseNetwork6_BiContiguousCIDR(b *testing.B) {
	b.ReportAllocs()
	for b.Loop() {
		network6Sink, errSink = xnetip.ParseNetwork6("2001:db8::/48")
	}
}

func BenchmarkParseBiContiguous_TwoRun(b *testing.B) {
	const input = "2a02:6b8:c00::1234:abcd:0:0/ffff:ffff:ff00::ffff:ffff:0:0"
	b.ReportAllocs()
	for b.Loop() {
		biContiguousSink, errSink = xnetip.ParseBiContiguous(input)
	}
}

func BenchmarkParseNetwork6_BiContiguousTwoRun(b *testing.B) {
	const input = "2a02:6b8:c00::1234:abcd:0:0/ffff:ffff:ff00::ffff:ffff:0:0"
	b.ReportAllocs()
	for b.Loop() {
		network6Sink, errSink = xnetip.ParseNetwork6(input)
	}
}

func BenchmarkParseBiContiguous_NonBiContiguous(b *testing.B) {
	b.ReportAllocs()
	for b.Loop() {
		biContiguousSink, errSink = xnetip.ParseBiContiguous("::/ffff:0:ffff::")
	}
}

// verifies that normalization defines wrapper equality and therefore map-key
// identity even when the source addresses differ only in host bits.
func Test_BiContiguous_EqualityAndMapKeyFollowNetwork(t *testing.T) {
	mask := netip.MustParseAddr("ffff:ffff:ff00::ffff:ffff:0:0")
	first, err := xnetip.BiContiguousFrom(
		netip.MustParseAddr("2a02:6b8:c01:1111:1234:5678:aaaa:bbbb"),
		mask,
	)
	require.NoError(t, err)
	second, err := xnetip.BiContiguousFrom(
		netip.MustParseAddr("2a02:6b8:cfe:2222:1234:5678:cccc:dddd"),
		mask,
	)
	require.NoError(t, err)
	require.Equal(t, first, second)

	values := map[xnetip.BiContiguous]string{first: "normalized"}
	require.Equal(t, "normalized", values[second])
}

// verifies that both reported mask coordinates are exact at the empty,
// full, half-boundary and genuine two-run shapes.
func Test_BiContiguous_HighPrefixLenAndLowPrefixLen_UnitAndBoundaries(t *testing.T) {
	cases := []struct {
		name     string
		block    xnetip.BiContiguous
		wantHigh int
		wantLow  int
	}{
		{name: "zero wrapper", block: xnetip.BiContiguous{}, wantHigh: 0, wantLow: 0},
		{
			name:     "host route",
			block:    xnetip.MustParseBiContiguous("::1/128"),
			wantHigh: 64,
			wantLow:  64,
		},
		{
			name:     "global prefix below half boundary",
			block:    xnetip.MustParseBiContiguous("2001:db8::/40"),
			wantHigh: 40,
			wantLow:  0,
		},
		{
			name:     "global prefix at half boundary",
			block:    xnetip.MustParseBiContiguous("2001:db8::/64"),
			wantHigh: 64,
			wantLow:  0,
		},
		{
			name:     "global prefix one bit above half boundary",
			block:    xnetip.MustParseBiContiguous("2001:db8::/65"),
			wantHigh: 64,
			wantLow:  1,
		},
		{
			name:     "global prefix in low half",
			block:    xnetip.MustParseBiContiguous("2001:db8::/96"),
			wantHigh: 64,
			wantLow:  32,
		},
		{
			name: "motivating independent runs",
			block: xnetip.MustParseBiContiguous(
				"2a02:6b8:c00::1234:abcd:0:0/ffff:ffff:ff00::ffff:ffff:0:0",
			),
			wantHigh: 40,
			wantLow:  32,
		},
		{
			name:     "low half only first bit",
			block:    xnetip.MustParseBiContiguous("::/::8000:0:0:0"),
			wantHigh: 0,
			wantLow:  1,
		},
		{
			name: "nearly full high half and full low half",
			block: xnetip.MustParseBiContiguous(
				"::/ffff:ffff:ffff:fffe:ffff:ffff:ffff:ffff",
			),
			wantHigh: 63,
			wantLow:  64,
		},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			require.Equal(
				t,
				[2]int{testCase.wantHigh, testCase.wantLow},
				[2]int{testCase.block.HighPrefixLen(), testCase.block.LowPrefixLen()},
			)
		})
	}
}

// verifies that every pair of mask-half prefix lengths is recovered exactly,
// reconstructs the mask and identifies the globally contiguous subset.
func Test_BiContiguous_HighPrefixLenAndLowPrefixLen_ExhaustEveryShape(t *testing.T) {
	addr := netip.MustParseAddr("::")
	for highPrefix := 0; highPrefix <= 64; highPrefix++ {
		for lowPrefix := 0; lowPrefix <= 64; lowPrefix++ {
			mask := netipAddrFrom6Bits(prefixMask64(highPrefix), prefixMask64(lowPrefix))
			block, err := xnetip.BiContiguousFrom(addr, mask)
			require.NoError(t, err)
			require.Equal(
				t,
				[2]int{highPrefix, lowPrefix},
				[2]int{block.HighPrefixLen(), block.LowPrefixLen()},
				"high prefix %d, low prefix %d",
				highPrefix,
				lowPrefix,
			)
			require.Equal(
				t,
				lowPrefix == 0 || highPrefix == 64,
				block.Network().IsContiguous(),
				"high prefix %d, low prefix %d",
				highPrefix,
				lowPrefix,
			)

			rebuiltMask := netipAddrFrom6Bits(
				prefixMask64(block.HighPrefixLen()),
				prefixMask64(block.LowPrefixLen()),
			)
			require.Equal(
				t,
				block.Network().Mask(),
				rebuiltMask,
				"high prefix %d, low prefix %d",
				highPrefix,
				lowPrefix,
			)
		}
	}
}

// verifies that generated mask coordinates match an independent byte-and-bit
// oracle, reconstruct the mask and characterize global contiguity.
func Test_BiContiguous_HighPrefixLenAndLowPrefixLen_MatchBitLoopProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		block := genBiContiguous.Draw(t, "block")
		mask := block.Network().Mask().As16()
		highPrefix := block.HighPrefixLen()
		lowPrefix := block.LowPrefixLen()
		require.Equal(
			t,
			[2]int{
				maskHalfPrefixLenOracle(mask, 0),
				maskHalfPrefixLenOracle(mask, 8),
			},
			[2]int{highPrefix, lowPrefix},
		)
		require.Equal(
			t,
			lowPrefix == 0 || highPrefix == 64,
			block.Network().IsContiguous(),
		)
		require.Equal(
			t,
			block.Network().Mask(),
			netipAddrFrom6Bits(prefixMask64(highPrefix), prefixMask64(lowPrefix)),
		)
	})
}

// verifies that reading either mask coordinate allocates nothing for the
// zero wrapper and a genuine two-run value.
func Test_BiContiguous_HighPrefixLenAndLowPrefixLen_AllocationFree(t *testing.T) {
	cases := []struct {
		name  string
		block xnetip.BiContiguous
	}{
		{name: "zero wrapper", block: xnetip.BiContiguous{}},
		{
			name: "independent high and low runs",
			block: xnetip.MustParseBiContiguous(
				"2a02:6b8:c00::1234:abcd:0:0/ffff:ffff:ff00::ffff:ffff:0:0",
			),
		},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			requireNoAllocs(t, func() { intSink = testCase.block.HighPrefixLen() })
			requireNoAllocs(t, func() { intSink = testCase.block.LowPrefixLen() })
		})
	}
}

// verifies that representative wrapper comparisons use address first and
// mask second exactly as the wrapped network order does.
func Test_BiContiguous_CompareMatchesNetworkOrder(t *testing.T) {
	cases := []struct {
		name   string
		first  xnetip.BiContiguous
		second xnetip.BiContiguous
		want   int
	}{
		{
			name:   "shorter mask sorts first",
			first:  mustBiContiguous(t, "::/0"),
			second: mustBiContiguous(t, "::/ffff::"),
			want:   -1,
		},
		{
			name:   "equal networks",
			first:  mustBiContiguous(t, "2001:db8::/32"),
			second: mustBiContiguous(t, "2001:db8::/32"),
			want:   0,
		},
		{
			name:   "higher address sorts after",
			first:  mustBiContiguous(t, "2001:db9::/32"),
			second: mustBiContiguous(t, "2001:db8::/32"),
			want:   1,
		},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			require.Equal(t, testCase.want, testCase.first.Compare(testCase.second))
			require.Equal(
				t,
				testCase.first.Network().Compare(testCase.second.Network()),
				testCase.first.Compare(testCase.second),
			)
		})
	}
}

// verifies that exact conversion succeeds precisely for networks whose
// two mask halves are individually contiguous.
func Test_BiContiguousFrom6_MatchesPredicateProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		network := genNetwork6.Draw(t, "network")
		wrapper, ok := xnetip.BiContiguousFrom6(network)
		require.Equal(t, network.IsBicontiguous(), ok)
		if ok {
			require.Equal(t, network, wrapper.Network())
		} else {
			require.Equal(t, xnetip.BiContiguous{}, wrapper)
		}
	})
}

// verifies that every generated IPv6 CIDR block lifts unchanged and still
// passes the exact bi-contiguous conversion.
func Test_BiContiguousFromContiguous_PreservesNetworkProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		block := genContiguous6.Draw(t, "block")
		wrapper := xnetip.BiContiguousFromContiguous(block)
		require.Equal(t, block.Network(), wrapper.Network())

		exact, ok := xnetip.BiContiguousFrom6(wrapper.Network())
		require.True(t, ok)
		require.Equal(t, wrapper, exact)
	})
}

// verifies that checked address-pair construction equals plain normalized
// construction followed by exact conversion for every valid IPv6 pair.
func Test_BiContiguousFrom_MatchesTwoStepProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		addr := genNetipAddr6.Draw(t, "addr")
		mask := genNetipAddr6.Draw(t, "mask")
		network, err := xnetip.Network6From(addr, mask)
		require.NoError(t, err)
		expected, ok := xnetip.BiContiguousFrom6(network)

		actual, err := xnetip.BiContiguousFrom(addr, mask)
		if ok {
			require.NoError(t, err)
			require.Equal(t, expected, actual)
		} else {
			require.ErrorIs(t, err, xnetip.ErrNonBiContiguousMask)
			require.Equal(t, xnetip.BiContiguous{}, actual)
		}
	})
}

// verifies that random wrapper comparisons equal the wrapped result and
// report equality exactly for equal wrapper values.
func Test_BiContiguous_CompareMatchesNetworkProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		first := genBiContiguous.Draw(t, "first")
		second := genBiContiguous.Draw(t, "second")
		comparison := first.Compare(second)
		require.Equal(t, first.Network().Compare(second.Network()), comparison)
		require.Equal(t, first == second, comparison == 0)
	})
}

// verifies that every successful construction, view and comparison hot path
// allocates no heap memory.
func Test_BiContiguous_OperationsAllocationFree(t *testing.T) {
	network := mustNetwork6(t, "2a02:6b8:c00::1234:abcd:0:0", "ffff:ffff:ff00::ffff:ffff:0:0")
	block := mustContiguous6(t, "2001:db8::/32")
	first := mustBiContiguous(t, "2a02:6b8:c00::1234:abcd:0:0/ffff:ffff:ff00::ffff:ffff:0:0")
	second := mustBiContiguous(t, "2001:db8::/32")
	addr := netip.MustParseAddr("2a02:6b8:c00::1234:abcd:0:0")
	mask := netip.MustParseAddr("ffff:ffff:ff00::ffff:ffff:0:0")

	requireNoAllocs(t, func() { biContiguousSink, okSink = xnetip.BiContiguousFrom6(network) })
	requireNoAllocs(t, func() { biContiguousSink, errSink = xnetip.BiContiguousFrom(addr, mask) })
	requireNoAllocs(t, func() { biContiguousSink = xnetip.BiContiguousFromContiguous(block) })
	requireNoAllocs(t, func() { network6Sink = first.Network() })
	requireNoAllocs(t, func() { intSink = first.Compare(second) })
}

// verifies that every representative mask shape uses exactly the
// canonical text of its wrapped IPv6 network.
func Test_BiContiguous_String_ExactForms(t *testing.T) {
	cases := []struct {
		name    string
		wrapper xnetip.BiContiguous
		want    string
	}{
		{name: "zero wrapper", wrapper: xnetip.BiContiguous{}, want: "::/0"},
		{
			name:    "host route",
			wrapper: xnetip.MustParseBiContiguous("::1/128"),
			want:    "::1/128",
		},
		{
			name:    "global prefix below half boundary",
			wrapper: xnetip.MustParseBiContiguous("2001:db8::/40"),
			want:    "2001:db8::/40",
		},
		{
			name:    "global prefix above half boundary",
			wrapper: xnetip.MustParseBiContiguous("2001:db8::/96"),
			want:    "2001:db8::/96",
		},
		{
			name: "independent high 40 and low 32 runs",
			wrapper: xnetip.MustParseBiContiguous(
				"2a02:6b8:c00::1234:abcd:0:0/ffff:ffff:ff00::ffff:ffff:0:0",
			),
			want: "2a02:6b8:c00:0:1234:abcd::/ffff:ffff:ff00:0:ffff:ffff::",
		},
		{
			name:    "low half only one-bit run",
			wrapper: xnetip.MustParseBiContiguous("::/::8000:0:0:0"),
			want:    "::/::8000:0:0:0",
		},
		{
			name:    "mapped IPv6 host route",
			wrapper: xnetip.MustParseBiContiguous("::ffff:192.0.2.1/128"),
			want:    "::ffff:192.0.2.1/128",
		},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			require.Equal(t, testCase.want, testCase.wrapper.String())
		})
	}
}

// verifies that every text adapter emits the same bytes as the wrapped
// network and preserves bytes already present in an append buffer.
func Test_BiContiguous_TextAdapters_MatchNetworkProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		wrapper := genBiContiguous.Draw(t, "wrapper")
		want := wrapper.Network().String()
		require.Equal(t, want, wrapper.String())
		require.Equal(t, want, string(wrapper.AppendTo(nil)))
		require.Equal(t, "network="+want, string(wrapper.AppendTo([]byte("network="))))
		text, err := wrapper.MarshalText()
		require.NoError(t, err)
		require.Equal(t, want, string(text))
	})
}

// verifies that an append buffer with enough spare capacity is reused
// instead of replacing its backing storage.
func Test_BiContiguous_AppendTo_ReusesCapacity(t *testing.T) {
	wrapper := xnetip.MustParseBiContiguous(
		"2a02:6b8:c00::1234:abcd:0:0/ffff:ffff:ff00::ffff:ffff:0:0",
	)
	buffer := make([]byte, len("network="), 128)
	copy(buffer, "network=")
	firstByte := &buffer[0]

	appended := wrapper.AppendTo(buffer)

	require.Equal(t, firstByte, &appended[0])
}

// verifies that every pair of per-half prefix lengths survives both
// parser and text-unmarshaler round trips without changing the block.
func Test_BiContiguous_Text_RoundTripsEveryShape(t *testing.T) {
	addr := netipAddrFrom6Bits(math.MaxUint64, math.MaxUint64)
	for highPrefix := range 65 {
		for lowPrefix := range 65 {
			mask := netipAddrFrom6Bits(
				prefixMask64(highPrefix),
				prefixMask64(lowPrefix),
			)
			wrapper, err := xnetip.BiContiguousFrom(addr, mask)
			require.NoError(t, err)

			parsed, err := xnetip.ParseBiContiguous(wrapper.String())
			require.NoError(
				t,
				err,
				"high prefix %d, low prefix %d",
				highPrefix,
				lowPrefix,
			)
			require.Equal(
				t,
				wrapper,
				parsed,
				"high prefix %d, low prefix %d",
				highPrefix,
				lowPrefix,
			)

			text, err := wrapper.MarshalText()
			require.NoError(t, err)
			var decoded xnetip.BiContiguous
			require.NoError(
				t,
				decoded.UnmarshalText(text),
				"high prefix %d, low prefix %d",
				highPrefix,
				lowPrefix,
			)
			require.Equal(
				t,
				wrapper,
				decoded,
				"high prefix %d, low prefix %d",
				highPrefix,
				lowPrefix,
			)
		}
	}
}

// verifies that generated wrappers survive direct text parsing and
// marshaling in both directions.
func Test_BiContiguous_Text_RoundTripsProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		wrapper := genBiContiguous.Draw(t, "wrapper")
		parsed, err := xnetip.ParseBiContiguous(wrapper.String())
		require.NoError(t, err)
		require.Equal(t, wrapper, parsed)

		text, err := wrapper.MarshalText()
		require.NoError(t, err)
		var decoded xnetip.BiContiguous
		require.NoError(t, decoded.UnmarshalText(text))
		require.Equal(t, wrapper, decoded)
	})
}

// verifies that generated wrappers survive JSON round trips both as
// standalone values and as struct fields.
func Test_BiContiguous_MarshalText_JSONRoundTripsProperty(t *testing.T) {
	type document struct {
		Network xnetip.BiContiguous `json:"network"`
	}

	rapid.Check(t, func(t *rapid.T) {
		wrapper := genBiContiguous.Draw(t, "wrapper")
		encoded, err := json.Marshal(wrapper)
		require.NoError(t, err)
		var decoded xnetip.BiContiguous
		require.NoError(t, json.Unmarshal(encoded, &decoded))
		require.Equal(t, wrapper, decoded)

		encoded, err = json.Marshal(document{Network: wrapper})
		require.NoError(t, err)
		var decodedDocument document
		require.NoError(t, json.Unmarshal(encoded, &decodedDocument))
		require.Equal(t, document{Network: wrapper}, decodedDocument)
	})
}

// verifies that nil and non-nil empty text both report the dedicated
// sentinel and leave a nonzero receiver unchanged.
func Test_BiContiguous_UnmarshalText_EmptyKeepsReceiver(t *testing.T) {
	initial := xnetip.MustParseBiContiguous("2001:db8::/32")
	cases := []struct {
		name string
		text []byte
	}{
		{name: "nil slice", text: nil},
		{name: "non-nil empty slice", text: []byte{}},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			wrapper := initial
			err := wrapper.UnmarshalText(testCase.text)
			require.ErrorIs(t, err, xnetip.ErrEmptyInput)
			require.EqualError(
				t,
				err,
				`xnetip.BiContiguous.UnmarshalText(""): empty input`,
			)
			require.Equal(t, initial, wrapper)
		})
	}
}

// verifies that every nonempty rejection keeps the parser's error class
// and text while leaving a nonzero receiver unchanged.
func Test_BiContiguous_UnmarshalText_ErrorsKeepReceiver(t *testing.T) {
	initial := xnetip.MustParseBiContiguous("2001:db8::/32")
	cases := []struct {
		name     string
		input    string
		sentinel error
	}{
		{
			name:     "high-half interior hole",
			input:    "::/ffff:0:ffff::",
			sentinel: xnetip.ErrNonBiContiguousMask,
		},
		{
			name:     "low-half interior hole",
			input:    "::/ffff:ffff::f0f0:f0f0:f0f0:f0f0",
			sentinel: xnetip.ErrNonBiContiguousMask,
		},
		{name: "malformed text", input: "not-a-network", sentinel: xnetip.ErrParse},
		{
			name:     "IPv4 text",
			input:    "192.0.2.1/24",
			sentinel: xnetip.ErrAddrFamilyMismatch,
		},
		{name: "zone", input: "fe80::1%eth0/64", sentinel: xnetip.ErrZone},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			_, parseErr := xnetip.ParseBiContiguous(testCase.input)
			require.Error(t, parseErr)

			wrapper := initial
			err := wrapper.UnmarshalText([]byte(testCase.input))
			require.ErrorIs(t, err, testCase.sentinel)
			require.EqualError(t, err, parseErr.Error())
			require.Equal(t, initial, wrapper)
		})
	}
}

// verifies that JSON reports the same shape sentinel as direct text
// decoding and preserves the destination after the rejected string.
func Test_BiContiguous_UnmarshalText_JSONErrorKeepsReceiver(t *testing.T) {
	initial := xnetip.MustParseBiContiguous("2001:db8::/32")
	wrapper := initial

	err := json.Unmarshal([]byte(`"::/ffff:0:ffff::"`), &wrapper)

	require.ErrorIs(t, err, xnetip.ErrNonBiContiguousMask)
	require.Equal(t, initial, wrapper)
}

// verifies that formatting pays only for its returned value and that
// a preallocated append path adds no allocation over the inner network.
func Test_BiContiguous_Text_AllocationContract(t *testing.T) {
	wrapper := xnetip.MustParseBiContiguous(
		"2a02:6b8:c00::1234:abcd:0:0/ffff:ffff:ff00::ffff:ffff:0:0",
	)
	inner := wrapper.Network()
	buffer := make([]byte, 0, 128)

	requireNoAllocs(t, func() { bytesSink = wrapper.AppendTo(buffer[:0]) })
	require.Equal(
		t,
		int(testing.AllocsPerRun(100, func() { stringSink = inner.String() })),
		int(testing.AllocsPerRun(100, func() { stringSink = wrapper.String() })),
	)
	require.Equal(t, 1, int(testing.AllocsPerRun(100, func() { stringSink = wrapper.String() })))
	require.Equal(
		t,
		1,
		int(testing.AllocsPerRun(100, func() { bytesSink, errSink = wrapper.MarshalText() })),
	)
}

// verifies that successful text decoding adds no allocation beyond the
// wrapped network's parser path for the same stable bytes.
func Test_BiContiguous_UnmarshalText_MatchesNetwork6Allocations(t *testing.T) {
	text := []byte(
		"2a02:6b8:c00::1234:abcd:0:0/ffff:ffff:ff00::ffff:ffff:0:0",
	)
	var network xnetip.Network6
	var wrapper xnetip.BiContiguous

	networkAllocs := int(testing.AllocsPerRun(100, func() {
		errSink = network.UnmarshalText(text)
	}))
	unmarshalAllocs := int(testing.AllocsPerRun(100, func() {
		errSink = wrapper.UnmarshalText(text)
	}))

	require.Equal(t, networkAllocs, unmarshalAllocs)
}

// verifies that the compact adapter accepts the guarantee-bearing value
// and drops only a host route's redundant suffix.
func Test_Compact_BiContiguous_ExactForms(t *testing.T) {
	cases := []struct {
		name    string
		wrapper xnetip.BiContiguous
		want    string
	}{
		{name: "zero wrapper", wrapper: xnetip.BiContiguous{}, want: "::/0"},
		{
			name:    "host route",
			wrapper: xnetip.MustParseBiContiguous("::1/128"),
			want:    "::1",
		},
		{
			name:    "global prefix",
			wrapper: xnetip.MustParseBiContiguous("2001:db8::/32"),
			want:    "2001:db8::/32",
		},
		{
			name: "genuine two-run mask",
			wrapper: xnetip.MustParseBiContiguous(
				"2a02:6b8:c00::1234:abcd:0:0/ffff:ffff:ff00::ffff:ffff:0:0",
			),
			want: "2a02:6b8:c00:0:1234:abcd::/ffff:ffff:ff00:0:ffff:ffff::",
		},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			require.Equal(t, testCase.want, xnetip.Compact(testCase.wrapper).String())
		})
	}
}

// verifies that compact rendering of every generated wrapper matches the
// inner IPv6 adapter, reparses exactly and appends without allocation.
func Test_Compact_BiContiguous_DelegatesProperty(t *testing.T) {
	buffer := make([]byte, 0, 128)
	rapid.Check(t, func(t *rapid.T) {
		wrapper := genBiContiguous.Draw(t, "wrapper")
		compact := xnetip.Compact(wrapper)
		want := xnetip.Compact(wrapper.Network()).String()
		require.Equal(t, want, compact.String())
		require.Equal(t, want, string(compact.AppendTo(nil)))

		parsed, err := xnetip.ParseBiContiguous(compact.String())
		require.NoError(t, err)
		require.Equal(t, wrapper, parsed)
		requireNoAllocs(t, func() { bytesSink = compact.AppendTo(buffer[:0]) })
	})
}
