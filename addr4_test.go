package xnetip_test

import (
	"cmp"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"math"
	"net/netip"
	"slices"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"pgregory.net/rapid"

	"github.com/yanet-platform/xnetip"
)

// verifies that the byte constructor reads the octets most significant
// first, so the first octet lands in the top byte of the integer.
func Test_IPv4Addr_From4_PinsByteOrder(t *testing.T) {
	require.Equal(t, uint32(0xC0A80001), xnetip.IPv4AddrFrom4([4]byte{192, 168, 0, 1}).Bits())
}

// verifies that the bits constructor writes the top byte of the integer
// into the first octet.
func Test_IPv4Addr_FromBits_PinsByteOrder(t *testing.T) {
	require.Equal(t, [4]byte{10, 0, 0, 1}, xnetip.IPv4AddrFromBits(0x0A000001).As4())
}

// verifies that the zero value is the unspecified address under both
// views and equals the address built from zero inputs.
func Test_IPv4Addr_ZeroValue_IsUnspecified(t *testing.T) {
	var zero xnetip.IPv4Addr
	require.Equal(t, [4]byte{}, zero.As4())
	require.Equal(t, uint32(0), zero.Bits())
	require.Equal(t, xnetip.IPv4AddrFrom4([4]byte{}), zero)
	require.Equal(t, xnetip.IPv4AddrFromBits(0), zero)
}

// verifies that the all-ones address maps to the largest 32-bit integer.
func Test_IPv4Addr_AllOnes_IsMaxUint32(t *testing.T) {
	require.Equal(t, uint32(math.MaxUint32), xnetip.IPv4AddrFrom4([4]byte{255, 255, 255, 255}).Bits())
}

// verifies that the == operator itself compares addresses by bit pattern,
// whichever constructor built them.
func Test_IPv4Addr_Equality_IsStructural(t *testing.T) {
	address := xnetip.IPv4AddrFromBits(1)
	sameBits := address == xnetip.IPv4AddrFrom4([4]byte{0, 0, 0, 1})
	otherBits := address == xnetip.IPv4AddrFromBits(2)
	require.True(t, sameBits)
	require.False(t, otherBits)
}

// verifies that the type is usable as a map key, with distinct addresses
// occupying distinct entries and equal ones sharing an entry.
func Test_IPv4Addr_MapKey_DistinguishesAddresses(t *testing.T) {
	seen := map[xnetip.IPv4Addr]int{}
	seen[xnetip.IPv4AddrFrom4([4]byte{10, 0, 0, 1})]++
	seen[xnetip.IPv4AddrFrom4([4]byte{10, 0, 0, 2})]++
	seen[xnetip.IPv4AddrFromBits(0x0A000001)]++
	require.Len(t, seen, 2)
	require.Equal(t, 2, seen[xnetip.IPv4AddrFrom4([4]byte{10, 0, 0, 1})])
}

// verifies that the byte view round-trips every 4-byte input.
func Test_IPv4Addr_From4_RoundTrips(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		octets := [4]byte(rapid.SliceOfN(rapid.Byte(), 4, 4).Draw(t, "octets"))
		require.Equal(t, octets, xnetip.IPv4AddrFrom4(octets).As4())
	})
}

// verifies that the integer view round-trips every 32-bit input.
func Test_IPv4Addr_FromBits_RoundTrips(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		bits := rapid.Uint32().Draw(t, "bits")
		require.Equal(t, bits, xnetip.IPv4AddrFromBits(bits).Bits())
	})
}

// verifies that the two views agree through big-endian encoding in both
// directions: octets to integer and integer to octets.
func Test_IPv4Addr_Views_AgreeWithBigEndian(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		octets := [4]byte(rapid.SliceOfN(rapid.Byte(), 4, 4).Draw(t, "octets"))
		require.Equal(t, binary.BigEndian.Uint32(octets[:]), xnetip.IPv4AddrFrom4(octets).Bits())
		address := genIPv4Addr.Draw(t, "address")
		require.Equal(t, [4]byte(binary.BigEndian.AppendUint32(nil, address.Bits())), address.As4())
	})
}

// verifies that the byte view agrees with net/netip for every 4-byte
// input, pinning the byte-order convention against the standard library.
func Test_IPv4Addr_From4_MatchesNetip(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		octets := [4]byte(rapid.SliceOfN(rapid.Byte(), 4, 4).Draw(t, "octets"))
		require.Equal(t, netip.AddrFrom4(octets).As4(), xnetip.IPv4AddrFrom4(octets).As4())
	})
}

// verifies that construction and the accessors do not allocate.
func Test_IPv4Addr_Construction_DoesNotAllocate(t *testing.T) {
	octets := [4]byte{192, 168, 0, 1}
	requireNoAllocs(t, func() {
		address := xnetip.IPv4AddrFrom4(octets)
		wordSink = xnetip.IPv4AddrFromBits(address.Bits()).Bits()
		octets = address.As4()
	})
}

// verifies that compare is the numeric order of the 32-bit pattern.
//
// The first octet dominates, lower octets break ties, the top bit is not
// a sign bit, and swapping the operands mirrors the sign.
func Test_IPv4Addr_Compare_OrdersNumerically(t *testing.T) {
	cases := []struct {
		name        string
		left, right [4]byte
		want        int
	}{
		{name: "equal addresses compare 0", left: [4]byte{10, 0, 0, 1}, right: [4]byte{10, 0, 0, 1}, want: 0},
		{name: "lower octet chain sorts first", left: [4]byte{192, 168, 0, 1}, right: [4]byte{192, 168, 1, 0}, want: -1},
		{name: "first octet dominates", left: [4]byte{9, 255, 255, 255}, right: [4]byte{10, 0, 0, 0}, want: -1},
		{name: "minimum sorts before maximum", left: [4]byte{0, 0, 0, 0}, right: [4]byte{255, 255, 255, 255}, want: -1},
		{name: "high-bit addresses are not negative", left: [4]byte{127, 255, 255, 255}, right: [4]byte{128, 0, 0, 0}, want: -1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			left, right := xnetip.IPv4AddrFrom4(tc.left), xnetip.IPv4AddrFrom4(tc.right)
			require.Equal(t, tc.want, left.Compare(right))
			require.Equal(t, -tc.want, right.Compare(left))
		})
	}
}

// verifies that the method expression is a comparator the standard sort
// accepts and that it yields ascending numeric order.
func Test_IPv4Addr_Compare_SortsWithSliceSortFunc(t *testing.T) {
	addrs := []xnetip.IPv4Addr{
		xnetip.IPv4AddrFrom4([4]byte{255, 0, 0, 0}),
		xnetip.IPv4AddrFrom4([4]byte{0, 0, 0, 1}),
		xnetip.IPv4AddrFrom4([4]byte{10, 0, 0, 0}),
	}
	slices.SortFunc(addrs, xnetip.IPv4Addr.Compare)
	require.Equal(t, []xnetip.IPv4Addr{
		xnetip.IPv4AddrFrom4([4]byte{0, 0, 0, 1}),
		xnetip.IPv4AddrFrom4([4]byte{10, 0, 0, 0}),
		xnetip.IPv4AddrFrom4([4]byte{255, 0, 0, 0}),
	}, addrs)
}

// verifies that compare is antisymmetric and that every address compares
// equal to itself.
func Test_IPv4Addr_Compare_AntisymmetricAndReflexive(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		left := genIPv4Addr.Draw(t, "left")
		right := genIPv4Addr.Draw(t, "right")
		require.Equal(t, -right.Compare(left), left.Compare(right))
		require.Equal(t, 0, left.Compare(left))
	})
}

// verifies that compare is transitive: once three addresses are sorted by
// it, the first also sorts no later than the last.
func Test_IPv4Addr_Compare_Transitive(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		addrs := []xnetip.IPv4Addr{
			genIPv4Addr.Draw(t, "first"),
			genIPv4Addr.Draw(t, "second"),
			genIPv4Addr.Draw(t, "third"),
		}
		slices.SortFunc(addrs, xnetip.IPv4Addr.Compare)
		require.LessOrEqual(t, addrs[0].Compare(addrs[1]), 0)
		require.LessOrEqual(t, addrs[1].Compare(addrs[2]), 0)
		require.LessOrEqual(t, addrs[0].Compare(addrs[2]), 0)
	})
}

// verifies that compare reports 0 exactly when the two addresses are equal
// under ==, so order and structural equality never disagree.
func Test_IPv4Addr_Compare_ZeroIffEqual(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		left := genIPv4Addr.Draw(t, "left")
		right := genIPv4Addr.Draw(t, "right")
		if rapid.Bool().Draw(t, "same") {
			right = left
		}
		require.Equal(t, left == right, left.Compare(right) == 0)
	})
}

// verifies that compare is the numeric order of the integer view, the
// contract the network order and the slice algorithms build on.
func Test_IPv4Addr_Compare_IsNumericOrderOfBits(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		left := genIPv4Addr.Draw(t, "left")
		right := genIPv4Addr.Draw(t, "right")
		require.Equal(t, cmp.Compare(left.Bits(), right.Bits()), left.Compare(right))
	})
}

// verifies that compare agrees with net/netip on every pair of IPv4
// addresses, pinning the order against the standard library.
func Test_IPv4Addr_Compare_MatchesNetip(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		left := genIPv4Addr.Draw(t, "left")
		right := genIPv4Addr.Draw(t, "right")
		want := netip.AddrFrom4(left.As4()).Compare(netip.AddrFrom4(right.As4()))
		require.Equal(t, want, left.Compare(right))
	})
}

// verifies that compare does not allocate.
func Test_IPv4Addr_Compare_DoesNotAllocate(t *testing.T) {
	left := xnetip.IPv4AddrFrom4([4]byte{192, 168, 0, 1})
	right := xnetip.IPv4AddrFrom4([4]byte{192, 168, 1, 0})
	requireNoAllocs(t, func() { intSink = left.Compare(right) })
}

func BenchmarkIPv4Addr_Compare(b *testing.B) {
	fixture := benchIPv4Addrs(2)
	left, right := fixture[0], fixture[1]
	b.ReportAllocs()
	for b.Loop() {
		intSink = left.Compare(right)
	}
}

// Sorts a fresh copy of the fixture on every iteration, the refresh
// included in the timed region.
//
// A 4 KiB copy is well under one percent of the sort, and pausing the
// timer inside a b.Loop body keeps the loop from ever reaching its
// benchtime on Go 1.24.
func BenchmarkIPv4Addr_SortFunc_1024(b *testing.B) {
	fixture := benchIPv4Addrs(1024)
	scratch := make([]xnetip.IPv4Addr, len(fixture))
	b.ReportAllocs()
	for b.Loop() {
		copy(scratch, fixture)
		slices.SortFunc(scratch, xnetip.IPv4Addr.Compare)
	}
}

// benchIPv4Addrs returns count addresses in a fixed, unsorted "random-ish"
// order, the same fixture on every run.
//
// Each address is its index multiplied by Knuth's multiplicative hash
// constant, the recipe of the Rust crate's sort benchmark
// (../netip/benches/net.rs:2293), so the two sort benchmarks see the same
// input shape.
func benchIPv4Addrs(count int) []xnetip.IPv4Addr {
	addrs := make([]xnetip.IPv4Addr, count)
	for idx := range addrs {
		addrs[idx] = xnetip.IPv4AddrFromBits(uint32(idx) * 2_654_435_761)
	}
	return addrs
}

// verifies that the text form is dotted decimal without padding.
//
// Each octet prints with as many digits as it needs, from the unspecified
// address to the fifteen-byte broadcast address.
func Test_IPv4Addr_String_FormatsDottedDecimal(t *testing.T) {
	cases := []struct {
		name   string
		octets [4]byte
		want   string
	}{
		{name: "typical address", octets: [4]byte{192, 168, 0, 1}, want: "192.168.0.1"},
		{name: "unspecified address", octets: [4]byte{0, 0, 0, 0}, want: "0.0.0.0"},
		{name: "broadcast address is the longest form", octets: [4]byte{255, 255, 255, 255}, want: "255.255.255.255"},
		{name: "single-, double- and triple-digit octets mix without padding", octets: [4]byte{1, 10, 100, 200}, want: "1.10.100.200"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.want, xnetip.IPv4AddrFrom4(tc.octets).String())
		})
	}
}

// verifies that the text form is appended after the buffer's existing
// content rather than overwriting it.
func Test_IPv4Addr_AppendTo_AppendsAfterExistingContent(t *testing.T) {
	address := xnetip.IPv4AddrFrom4([4]byte{10, 0, 0, 1})
	got := address.AppendTo([]byte("addr="))
	require.Equal(t, "addr=10.0.0.1", string(got))
}

// verifies that a buffer with spare capacity is extended in place: the
// returned slice shares the caller's backing array.
func Test_IPv4Addr_AppendTo_KeepsBackingArray(t *testing.T) {
	address := xnetip.IPv4AddrFrom4([4]byte{255, 255, 255, 255})
	buffer := make([]byte, 0, 32)
	got := address.AppendTo(buffer)
	require.Equal(t, "255.255.255.255", string(got))
	require.Same(t, &buffer[:1][0], &got[0])
}

// verifies that the appending form and the string form agree on every
// address.
func Test_IPv4Addr_AppendTo_AgreesWithString(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		address := genIPv4Addr.Draw(t, "address")
		require.Equal(t, address.String(), string(address.AppendTo(nil)))
	})
}

// verifies that the text form equals the four octets printed in decimal
// and joined by dots, the simplest possible oracle.
func Test_IPv4Addr_String_MatchesOctetOracle(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		address := genIPv4Addr.Draw(t, "address")
		octets := address.As4()
		want := fmt.Sprintf("%d.%d.%d.%d", octets[0], octets[1], octets[2], octets[3])
		require.Equal(t, want, address.String())
	})
}

// verifies that the text form is between seven and fifteen bytes long
// and contains exactly three dots on every address.
func Test_IPv4Addr_String_HasBoundedLengthAndThreeDots(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		address := genIPv4Addr.Draw(t, "address")
		text := address.String()
		require.GreaterOrEqual(t, len(text), len("0.0.0.0"))
		require.LessOrEqual(t, len(text), len("255.255.255.255"))
		require.Equal(t, 3, strings.Count(text, "."))
	})
}

// verifies that the text form is byte for byte what net/netip prints for
// the same four octets.
func Test_IPv4Addr_String_MatchesNetip(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		address := genIPv4Addr.Draw(t, "address")
		require.Equal(t, netip.AddrFrom4(address.As4()).String(), address.String())
	})
}

// verifies that appending into a buffer with enough capacity does not
// allocate, which is the contract every network formatter builds on.
func Test_IPv4Addr_AppendTo_DoesNotAllocate(t *testing.T) {
	address := xnetip.IPv4AddrFrom4([4]byte{255, 255, 255, 255})
	buffer := make([]byte, 0, 32)
	requireNoAllocs(t, func() { bytesSink = address.AppendTo(buffer[:0]) })
}

// verifies that the string form allocates at most once, for the result
// itself.
func Test_IPv4Addr_String_AllocatesAtMostOnce(t *testing.T) {
	address := xnetip.IPv4AddrFrom4([4]byte{255, 255, 255, 255})
	allocs := testing.AllocsPerRun(100, func() { stringSink = address.String() })
	require.LessOrEqual(t, allocs, 1.0)
}

func BenchmarkIPv4Addr_String_Short(b *testing.B) {
	address := xnetip.IPv4AddrFrom4([4]byte{1, 1, 1, 1})
	b.ReportAllocs()
	for b.Loop() {
		stringSink = address.String()
	}
}

func BenchmarkIPv4Addr_String_Longest(b *testing.B) {
	address := xnetip.IPv4AddrFrom4([4]byte{255, 255, 255, 255})
	b.ReportAllocs()
	for b.Loop() {
		stringSink = address.String()
	}
}

func BenchmarkIPv4Addr_AppendTo_Short(b *testing.B) {
	address := xnetip.IPv4AddrFrom4([4]byte{1, 1, 1, 1})
	buffer := make([]byte, 0, 32)
	b.ReportAllocs()
	for b.Loop() {
		bytesSink = address.AppendTo(buffer[:0])
	}
}

func BenchmarkIPv4Addr_AppendTo_Longest(b *testing.B) {
	address := xnetip.IPv4AddrFrom4([4]byte{255, 255, 255, 255})
	buffer := make([]byte, 0, 32)
	b.ReportAllocs()
	for b.Loop() {
		bytesSink = address.AppendTo(buffer[:0])
	}
}

// verifies that the marshalled text is exactly the dotted-decimal string
// form of the address, with a nil error.
func Test_IPv4Addr_MarshalText_EmitsStringForm(t *testing.T) {
	address := xnetip.MustParseIPv4Addr("10.0.0.1")
	got, err := address.MarshalText()
	require.NoError(t, err)
	require.Equal(t, []byte("10.0.0.1"), got)
}

// verifies that the zero value marshals as the unspecified address rather
// than as empty text, because the zero value is a real address.
func Test_IPv4Addr_MarshalText_ZeroValueIsUnspecified(t *testing.T) {
	var zero xnetip.IPv4Addr
	got, err := zero.MarshalText()
	require.NoError(t, err)
	require.Equal(t, "0.0.0.0", string(got))
}

// verifies that the appending marshal form writes the text after the
// buffer's existing content rather than overwriting it.
func Test_IPv4Addr_AppendText_AppendsAfterExistingContent(t *testing.T) {
	address := xnetip.MustParseIPv4Addr("10.0.0.1")
	got, err := address.AppendText([]byte("x="))
	require.NoError(t, err)
	require.Equal(t, "x=10.0.0.1", string(got))
}

// verifies that unmarshalling accepts what the parser accepts and stores
// the parsed address into the receiver.
func Test_IPv4Addr_UnmarshalText_AcceptsValidText(t *testing.T) {
	var address xnetip.IPv4Addr
	require.NoError(t, address.UnmarshalText([]byte("192.168.0.1")))
	require.Equal(t, xnetip.MustParseIPv4Addr("192.168.0.1"), address)
}

// verifies that empty text is a parse error and leaves the receiver
// untouched.
//
// This diverges from net/netip on purpose: there the zero value marks an
// invalid address, here it is the valid unspecified address, so empty
// text must not silently decode into it.
func Test_IPv4Addr_UnmarshalText_RejectsEmptyText(t *testing.T) {
	address := xnetip.MustParseIPv4Addr("10.0.0.1")
	err := address.UnmarshalText([]byte(""))
	require.ErrorIs(t, err, xnetip.ErrParse)
	require.Equal(t, xnetip.MustParseIPv4Addr("10.0.0.1"), address)
}

// verifies that text the parser rejects fails unmarshalling and leaves
// the receiver untouched, whatever the reason for the rejection.
func Test_IPv4Addr_UnmarshalText_RejectsInvalidText(t *testing.T) {
	cases := []struct {
		name  string
		input string
	}{
		{name: "leading zero octet", input: "01.2.3.4"},
		{name: "IPv6 literal", input: "2001:db8::1"},
		{name: "leading space", input: " 1.2.3.4"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			address := xnetip.MustParseIPv4Addr("10.0.0.1")
			require.Error(t, address.UnmarshalText([]byte(tc.input)))
			require.Equal(t, xnetip.MustParseIPv4Addr("10.0.0.1"), address)
		})
	}
}

// verifies that a failed unmarshal does not clobber a previously stored
// address.
func Test_IPv4Addr_UnmarshalText_KeepsReceiverOnError(t *testing.T) {
	address := xnetip.MustParseIPv4Addr("10.0.0.1")
	require.Error(t, address.UnmarshalText([]byte("x")))
	require.Equal(t, xnetip.MustParseIPv4Addr("10.0.0.1"), address)
}

// verifies that a struct field of the address type round-trips through
// JSON as a quoted dotted-decimal string.
func Test_IPv4Addr_MarshalText_JSONRoundTripsStructField(t *testing.T) {
	type record struct{ A xnetip.IPv4Addr }
	original := record{A: xnetip.MustParseIPv4Addr("10.0.0.1")}
	encoded, err := json.Marshal(original)
	require.NoError(t, err)
	require.JSONEq(t, `{"A":"10.0.0.1"}`, string(encoded))
	var decoded record
	require.NoError(t, json.Unmarshal(encoded, &decoded))
	require.Equal(t, original, decoded)
}

// verifies that a JSON number does not decode into the address type,
// which accepts text only.
func Test_IPv4Addr_UnmarshalText_JSONRejectsNumber(t *testing.T) {
	var decoded struct{ A xnetip.IPv4Addr }
	require.Error(t, json.Unmarshal([]byte(`{"A":1}`), &decoded))
}

// verifies that unmarshalling the marshalled text yields the address
// back, for every address.
func Test_IPv4Addr_MarshalText_RoundTripsThroughUnmarshal(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		address := genIPv4Addr.Draw(t, "address")
		text, err := address.MarshalText()
		require.NoError(t, err)
		var decoded xnetip.IPv4Addr
		require.NoError(t, decoded.UnmarshalText(text))
		require.Equal(t, address, decoded)
	})
}

// verifies that the marshalled text and the string form agree on every
// address.
func Test_IPv4Addr_MarshalText_AgreesWithString(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		address := genIPv4Addr.Draw(t, "address")
		text, err := address.MarshalText()
		require.NoError(t, err)
		require.Equal(t, address.String(), string(text))
	})
}

// verifies that the marshalled text is byte for byte what net/netip
// marshals for the same four octets.
func Test_IPv4Addr_MarshalText_MatchesNetip(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		address := genIPv4Addr.Draw(t, "address")
		want, wantErr := netip.AddrFrom4(address.As4()).MarshalText()
		require.NoError(t, wantErr)
		got, err := address.MarshalText()
		require.NoError(t, err)
		require.Equal(t, want, got)
	})
}

// verifies that marshalling allocates exactly once, for the returned
// text itself, even in the longest form.
func Test_IPv4Addr_MarshalText_AllocatesOnce(t *testing.T) {
	address := xnetip.MustParseIPv4Addr("255.255.255.255")
	allocs := int(testing.AllocsPerRun(100, func() { bytesSink, errSink = address.MarshalText() }))
	require.Equal(t, 1, allocs)
}

// verifies that the appending marshal form into a buffer with enough
// capacity does not allocate.
func Test_IPv4Addr_AppendText_DoesNotAllocate(t *testing.T) {
	address := xnetip.MustParseIPv4Addr("255.255.255.255")
	buffer := make([]byte, 0, 32)
	requireNoAllocs(t, func() { bytesSink, errSink = address.AppendText(buffer[:0]) })
}

// verifies that dotted-decimal text of four octets in range parses to the
// address it spells.
//
// The cases span the unspecified address, the broadcast address, and a
// zero octet and a 255 octet on their own.
func Test_ParseIPv4Addr_AcceptsBasicForms(t *testing.T) {
	cases := []struct {
		name  string
		input string
		want  [4]byte
	}{
		{name: "unspecified address", input: "0.0.0.0", want: [4]byte{0, 0, 0, 0}},
		{name: "broadcast address is the longest form", input: "255.255.255.255", want: [4]byte{255, 255, 255, 255}},
		{name: "private address", input: "192.168.1.1", want: [4]byte{192, 168, 1, 1}},
		{name: "single-digit octets", input: "1.2.3.4", want: [4]byte{1, 2, 3, 4}},
		{name: "zero octet itself is not a leading zero", input: "0.1.2.3", want: [4]byte{0, 1, 2, 3}},
		{name: "255 is the largest octet", input: "255.0.0.0", want: [4]byte{255, 0, 0, 0}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := xnetip.ParseIPv4Addr(tc.input)
			require.NoError(t, err)
			require.Equal(t, xnetip.IPv4AddrFrom4(tc.want), got)
		})
	}
}

// verifies that an octet with a leading zero is rejected as unparseable
// text, the octal-injection guard the standard grammars share.
func Test_ParseIPv4Addr_RejectsLeadingZeroOctets(t *testing.T) {
	cases := []struct {
		name  string
		input string
	}{
		{name: "leading zero in the first octet", input: "01.2.3.4"},
		{name: "leading zero in the second octet", input: "1.02.3.4"},
		{name: "leading zero in the third octet", input: "1.2.03.4"},
		{name: "leading zero in the fourth octet", input: "1.2.3.04"},
		{name: "double zero", input: "00.0.0.0"},
		{name: "triple zero", input: "000.0.0.0"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := xnetip.ParseIPv4Addr(tc.input)
			require.ErrorIs(t, err, xnetip.ErrParse)
		})
	}
}

// verifies that an octet above 255 is rejected as unparseable text,
// whether by one or by many digits.
func Test_ParseIPv4Addr_RejectsOctetOverflow(t *testing.T) {
	cases := []struct {
		name  string
		input string
	}{
		{name: "256 in the first octet", input: "256.0.0.0"},
		{name: "999 in the first octet", input: "999.0.0.0"},
		{name: "999 in the last octet", input: "0.0.0.999"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := xnetip.ParseIPv4Addr(tc.input)
			require.ErrorIs(t, err, xnetip.ErrParse)
		})
	}
}

// verifies that anything but exactly four dot-separated groups is rejected
// as unparseable text: too many, too few, empty input and empty groups.
func Test_ParseIPv4Addr_RejectsWrongGroupCount(t *testing.T) {
	cases := []struct {
		name  string
		input string
	}{
		{name: "five groups", input: "1.2.3.4.5"},
		{name: "three groups", input: "1.2.3"},
		{name: "two groups", input: "1.2"},
		{name: "one group", input: "1"},
		{name: "empty input", input: ""},
		{name: "single dot", input: "."},
		{name: "three dots with empty groups", input: "..."},
		{name: "empty group in the middle", input: "1..2.3"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := xnetip.ParseIPv4Addr(tc.input)
			require.ErrorIs(t, err, xnetip.ErrParse)
		})
	}
}

// verifies that the whole input must be the address, so any surrounding
// or trailing byte is rejected as unparseable text.
//
// The cases cover whitespace, a trailing letter, letters instead of
// digits, CIDR, port and zone suffixes, an oversized octet and a
// multibyte character.
func Test_ParseIPv4Addr_RejectsGarbageAndWhitespace(t *testing.T) {
	cases := []struct {
		name  string
		input string
	}{
		{name: "leading space", input: " 1.2.3.4"},
		{name: "trailing space", input: "1.2.3.4 "},
		{name: "trailing newline", input: "1.2.3.4\n"},
		{name: "trailing letter", input: "1.2.3.4x"},
		{name: "letters instead of digits", input: "a.b.c.d"},
		{name: "CIDR suffix", input: "1.2.3.4/24"},
		{name: "port suffix", input: "1.2.3.4:80"},
		{name: "zone suffix on an IPv4 address", input: "1.2.3.4%eth0"},
		{name: "huge first octet", input: "999999999999999999.0.0.0"},
		{name: "multibyte character in the last octet", input: "1.2.3.é"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := xnetip.ParseIPv4Addr(tc.input)
			require.ErrorIs(t, err, xnetip.ErrParse)
		})
	}
}

// verifies that well-formed IPv6 text is rejected as a family mismatch,
// not as unparseable text.
//
// The cases cover a plain IPv6 address, an IPv4-mapped one, the
// unspecified one and a zoned one.
func Test_ParseIPv4Addr_RejectsIPv6AsFamilyMismatch(t *testing.T) {
	cases := []struct {
		name  string
		input string
	}{
		{name: "IPv6 literal", input: "2001:db8::1"},
		{name: "IPv4-mapped IPv6 literal", input: "::ffff:1.2.3.4"},
		{name: "unspecified IPv6 address", input: "::"},
		{name: "zoned IPv6 literal", input: "fe80::1%eth0"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := xnetip.ParseIPv4Addr(tc.input)
			require.ErrorIs(t, err, xnetip.ErrAddrFamilyMismatch)
			require.NotErrorIs(t, err, xnetip.ErrParse)
		})
	}
}

// verifies that the error message names the parser, echoes the input in
// quotes and carries the cause, so a log line identifies the failed text.
func Test_ParseIPv4Addr_ErrorEchoesInput(t *testing.T) {
	_, err := xnetip.ParseIPv4Addr("1.2.3")
	require.Error(t, err)
	require.True(t, strings.HasPrefix(err.Error(), `xnetip.ParseIPv4Addr("1.2.3"): `), err.Error())
	require.Contains(t, err.Error(), xnetip.ErrParse.Error())
	_, err = xnetip.ParseIPv4Addr("2001:db8::1")
	require.Error(t, err)
	require.Equal(t, `xnetip.ParseIPv4Addr("2001:db8::1"): `+xnetip.ErrAddrFamilyMismatch.Error(), err.Error())
}

// verifies that the panicking variant panics on unparseable text with the
// parse error itself.
func Test_MustParseIPv4Addr_PanicsOnError(t *testing.T) {
	require.PanicsWithError(t, `xnetip.ParseIPv4Addr("x"): `+xnetip.ErrParse.Error()+`: ParseAddr("x"): unable to parse IP`, func() {
		xnetip.MustParseIPv4Addr("x")
	})
}

// verifies that the panicking variant returns the parsed address on valid
// text.
func Test_MustParseIPv4Addr_ReturnsOnSuccess(t *testing.T) {
	require.Equal(t, xnetip.IPv4AddrFrom4([4]byte{10, 0, 0, 1}), xnetip.MustParseIPv4Addr("10.0.0.1"))
}

// verifies that parsing the text form of an address yields the address
// back, for every address.
func Test_ParseIPv4Addr_RoundTripsThroughString(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		address := genIPv4Addr.Draw(t, "address")
		got, err := xnetip.ParseIPv4Addr(address.String())
		require.NoError(t, err)
		require.Equal(t, address, got)
	})
}

// verifies accept/reject parity with net/netip on strings drawn from the
// characters of the address grammar plus a few easy-to-confuse extras.
//
// Drawing from that alphabet rather than from arbitrary bytes exercises
// the parity close to the accept boundary.
func Test_ParseIPv4Addr_NearMissParityWithNetip(t *testing.T) {
	alphabet := []byte(".:/+ x0123456789abcdef")
	rapid.Check(t, func(t *rapid.T) {
		text := string(rapid.SliceOfN(rapid.SampledFrom(alphabet), 0, 24).Draw(t, "text"))
		requireParseIPv4AddrMatchesNetip(t, text)
	})
}

// verifies accept/reject parity with net/netip on the text of a valid
// address with one byte deleted or replaced by an arbitrary byte.
func Test_ParseIPv4Addr_MutationParityWithNetip(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		text := []byte(genIPv4Addr.Draw(t, "address").String())
		position := rapid.IntRange(0, len(text)-1).Draw(t, "position")
		if rapid.Bool().Draw(t, "delete") {
			text = slices.Delete(text, position, position+1)
		} else {
			text[position] = rapid.Byte().Draw(t, "replacement")
		}
		requireParseIPv4AddrMatchesNetip(t, string(text))
	})
}

// verifies accept/reject parity and value agreement with net/netip on
// arbitrary text, seeded with every input of the unit tables.
func FuzzParseIPv4Addr(f *testing.F) {
	seeds := []string{
		"0.0.0.0", "255.255.255.255", "192.168.1.1", "1.2.3.4", "0.1.2.3", "255.0.0.0",
		"01.2.3.4", "1.02.3.4", "1.2.03.4", "1.2.3.04", "00.0.0.0", "000.0.0.0",
		"256.0.0.0", "999.0.0.0", "0.0.0.999",
		"1.2.3.4.5", "1.2.3", "1.2", "1", "", ".", "...", "1..2.3",
		" 1.2.3.4", "1.2.3.4 ", "1.2.3.4\n", "1.2.3.4x", "a.b.c.d", "1.2.3.4/24", "1.2.3.4:80",
		"1.2.3.4%eth0", "999999999999999999.0.0.0", "1.2.3.é",
		"2001:db8::1", "::ffff:1.2.3.4", "::", "fe80::1%eth0", "x", "10.0.0.1",
	}
	for _, seed := range seeds {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, text string) {
		requireParseIPv4AddrMatchesNetip(t, text)
	})
}

// requireParseIPv4AddrMatchesNetip asserts that the parser accepts text
// exactly when net/netip parses it as IPv4, with the same octets.
func requireParseIPv4AddrMatchesNetip(t require.TestingT, text string) {
	if helper, ok := t.(interface{ Helper() }); ok {
		helper.Helper()
	}
	got, err := xnetip.ParseIPv4Addr(text)
	want, wantErr := netip.ParseAddr(text)
	if wantErr != nil || !want.Is4() {
		require.Error(t, err, "input %q", text)
		return
	}
	require.NoError(t, err, "input %q", text)
	require.Equal(t, want.As4(), got.As4(), "input %q", text)
}

// verifies that parsing valid text does not allocate: the error wrapping
// is the only allocating path.
func Test_ParseIPv4Addr_DoesNotAllocate(t *testing.T) {
	text := "192.168.0.1"
	requireNoAllocs(t, func() { ipv4AddrSink, errSink = xnetip.ParseIPv4Addr(text) })
}

func BenchmarkParseIPv4Addr_Bare(b *testing.B) {
	text := "10.0.0.1"
	b.ReportAllocs()
	for b.Loop() {
		ipv4AddrSink, errSink = xnetip.ParseIPv4Addr(text)
	}
}

func BenchmarkParseIPv4Addr_Typical(b *testing.B) {
	text := "192.168.0.1"
	b.ReportAllocs()
	for b.Loop() {
		ipv4AddrSink, errSink = xnetip.ParseIPv4Addr(text)
	}
}

func BenchmarkParseIPv4Addr_Longest(b *testing.B) {
	text := "255.255.255.255"
	b.ReportAllocs()
	for b.Loop() {
		ipv4AddrSink, errSink = xnetip.ParseIPv4Addr(text)
	}
}

func BenchmarkParseIPv4Addr_Reject(b *testing.B) {
	text := "1.2.3"
	b.ReportAllocs()
	for b.Loop() {
		ipv4AddrSink, errSink = xnetip.ParseIPv4Addr(text)
	}
}
