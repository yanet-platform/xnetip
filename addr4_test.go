package xnetip

import (
	"math"
	"math/bits"
	"net/netip"
	"testing"

	"github.com/stretchr/testify/require"
	"pgregory.net/rapid"
)

// genIPv4Addr draws an IPv4 kernel address: uniform 32-bit values,
// with one draw in ten on a boundary or half-word pattern.
//
// The fixed shapes are the two extremes, the sign-bit split, and the two
// half-word masks, the patterns the network generators later build masks
// from. They are drawn explicitly because shrinking walks towards zero
// and rarely stops at the other boundaries.
var genIPv4Addr = rapid.Custom(func(t *rapid.T) ipv4Addr {
	if rapid.IntRange(0, 9).Draw(t, "shape") > 0 {
		return ipv4AddrFromBits(rapid.Uint32().Draw(t, "bits"))
	}
	boundaries := []uint32{0, math.MaxUint32, 0x7FFFFFFF, 0x80000000, 0x0000FFFF, 0xFFFF0000}
	return ipv4AddrFromBits(rapid.SampledFrom(boundaries).Draw(t, "boundary"))
})

// verifies that the 4-byte constructor reads the bytes in network order,
// first octet into the most significant byte.
func Test_IPv4Addr_From4_PlacesBytesBigEndian(t *testing.T) {
	address := ipv4AddrFrom4([4]byte{192, 168, 0, 1})
	require.Equal(t, uint32(0xC0A80001), address.Bits())
	require.Equal(t, [4]byte{192, 168, 0, 1}, address.As4())
}

// verifies that the integer constructor and the byte view invert each
// other over the whole value space.
func Test_IPv4Addr_FromBits_RoundTripsAs4(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		address := genIPv4Addr.Draw(t, "address")
		require.Equal(t, address, ipv4AddrFrom4(address.As4()))
		require.Equal(t, address.Bits(), ipv4AddrFromBits(address.Bits()).Bits())
	})
}

// verifies that the netip constructor accepts exactly the IPv4 family:
// IPv6, IPv4-mapped and invalid inputs are rejected.
func Test_IPv4Addr_FromNetip_AcceptsOnlyIs4(t *testing.T) {
	address, ok := ipv4AddrFromNetip(netip.MustParseAddr("1.2.3.4"))
	require.True(t, ok)
	require.Equal(t, ipv4AddrFrom4([4]byte{1, 2, 3, 4}), address)
	_, ok = ipv4AddrFromNetip(netip.MustParseAddr("2001:db8::1"))
	require.False(t, ok)
	_, ok = ipv4AddrFromNetip(netip.MustParseAddr("::ffff:1.2.3.4"))
	require.False(t, ok)
	_, ok = ipv4AddrFromNetip(netip.Addr{})
	require.False(t, ok)
}

// verifies that the prefix mask has exactly the given number of leading
// ones at the edges and the octet boundaries.
func Test_IPv4MaskFromPrefix_LeadingOnesTable(t *testing.T) {
	cases := []struct {
		name string
		bits int
		want uint32
	}{
		{name: "0 is the empty mask", bits: 0, want: 0},
		{name: "1 is the top bit", bits: 1, want: 0x80000000},
		{name: "8 fills the first octet", bits: 8, want: 0xFF000000},
		{name: "16 fills the top half", bits: 16, want: 0xFFFF0000},
		{name: "24 fills three octets", bits: 24, want: 0xFFFFFF00},
		{name: "31 leaves the lowest bit clear", bits: 31, want: 0xFFFFFFFE},
		{name: "32 is all ones", bits: 32, want: ^uint32(0)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, ipv4AddrFromBits(tc.want), ipv4MaskFromPrefix(tc.bits))
		})
	}
}

// verifies that the prefix mask of any length has that many leading ones
// and no other set bit, exhaustively over all 33 lengths.
//
// A value whose leading-one run and population count both equal the
// length is uniquely determined, so together the two counts pin every
// mask.
func Test_IPv4MaskFromPrefix_LeadingOnesAndCountAreLength(t *testing.T) {
	for length := range 33 {
		mask := ipv4MaskFromPrefix(length).Bits()
		require.Equal(t, length, bits.LeadingZeros32(^mask), "prefix length %d", length)
		require.Equal(t, length, bits.OnesCount32(mask), "prefix length %d", length)
	}
}

// verifies that every prefix mask grows strictly with the length, so
// longer prefixes are supersets as bit sets.
func Test_IPv4MaskFromPrefix_MonotoneInLength(t *testing.T) {
	for length := range 32 {
		shorter := ipv4MaskFromPrefix(length).Bits()
		longer := ipv4MaskFromPrefix(length + 1).Bits()
		require.Less(t, shorter, longer, "prefix length %d", length)
		require.Equal(t, shorter, shorter&longer, "prefix length %d", length)
	}
}

// verifies that masking with the prefix mask yields the same address the
// standard library keeps when it applies a prefix length.
func Test_IPv4MaskFromPrefix_AgreesWithNetipPrefix(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		address := genIPv4Addr.Draw(t, "address")
		length := rapid.IntRange(0, 32).Draw(t, "length")
		prefix, err := address.Netip().Prefix(length)
		require.NoError(t, err)
		masked := address.Bits() & ipv4MaskFromPrefix(length).Bits()
		require.Equal(t, prefix.Addr().As4(), ipv4AddrFromBits(masked).As4())
	})
}

// verifies that the netip view is a valid zone-free IPv4 address and
// that converting it back restores the value.
func Test_IPv4Addr_Netip_RoundTrips(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		address := genIPv4Addr.Draw(t, "address")
		view := address.Netip()
		require.True(t, view.Is4())
		require.Empty(t, view.Zone())
		restored, ok := ipv4AddrFromNetip(view)
		require.True(t, ok)
		require.Equal(t, address, restored)
	})
}

// verifies that the mapping embeds the 32 address bits below the
// ::ffff:0:0/96 prefix.
func Test_IPv4Addr_ToIPv6Mapped_EmbedsOctets(t *testing.T) {
	mapped := ipv4AddrFromBits(0xC0A80001).ToIPv6Mapped()
	require.Equal(t, ipv6AddrFromBits(0, 0x0000FFFFC0A80001), mapped)
	require.True(t, mapped.Is4In6())
}

// verifies that the mapping agrees with the 16-byte form net/netip gives
// an IPv4 address, which is the mapped form by definition.
func Test_IPv4Addr_ToIPv6Mapped_MatchesNetipAs16(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		address := genIPv4Addr.Draw(t, "address")
		require.Equal(t, address.Netip().As16(), address.ToIPv6Mapped().As16())
	})
}

// verifies that the mapped extractor inverts the mapping for every
// address.
func Test_IPv4Addr_ToIPv6Mapped_RoundTripsThroughExtractor(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		address := genIPv4Addr.Draw(t, "address")
		extracted, ok := address.ToIPv6Mapped().ToIPv4Mapped()
		require.True(t, ok)
		require.Equal(t, address, extracted)
	})
}

// verifies that the order is the numeric order net/netip gives two IPv4
// addresses.
func Test_IPv4Addr_Compare_MatchesNetip(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		left := genIPv4Addr.Draw(t, "left")
		right := genIPv4Addr.Draw(t, "right")
		require.Equal(t, left.Netip().Compare(right.Netip()), left.Compare(right))
	})
}

// verifies that the text kernel prints exactly the dotted-decimal form
// net/netip prints.
func Test_IPv4Addr_AppendTo_MatchesNetipString(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		address := genIPv4Addr.Draw(t, "address")
		require.Equal(t, address.Netip().String(), string(address.AppendTo(nil)))
	})
}

// verifies that the text kernel appends after existing content instead
// of overwriting it.
func Test_IPv4Addr_AppendTo_AppendsAfterExistingContent(t *testing.T) {
	buffer := ipv4AddrFromBits(0xFF00FF00).AppendTo([]byte("mask="))
	require.Equal(t, "mask=255.0.255.0", string(buffer))
}

// verifies that the kernel operations the networks build on do not
// allocate, the text kernel measured with a preallocated buffer.
func Test_IPv4Addr_Kernel_AllocationFree(t *testing.T) {
	address := ipv4AddrFromBits(0xC0A80001)
	view := address.Netip()
	buffer := make([]byte, 0, 64)
	allocs := testing.AllocsPerRun(100, func() {
		address4Sink = address.As4()
		wordKernelSink = address.Bits()
		compareSink = address.Compare(address)
		address6Sink = address.ToIPv6Mapped()
		bytesKernelSink = address.AppendTo(buffer[:0])
		_, okSink = ipv4AddrFromNetip(view)
		netipKernelSink = address.Netip()
		maskKernelSink = ipv4MaskFromPrefix(24)
	})
	require.Zero(t, int(allocs), "allocations per call")
}

// Sinks keep the measured results alive, so the compiler cannot optimise
// the work under test away.
var (
	address4Sink    [4]byte
	address6Sink    ipv6Addr
	maskKernelSink  ipv4Addr
	wordKernelSink  uint32
	bytesKernelSink []byte
	okSink          bool
	netipKernelSink netip.Addr
)
