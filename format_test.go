package xnetip_test

import (
	"fmt"
	"net/netip"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"pgregory.net/rapid"

	"github.com/yanet-platform/xnetip"
)

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
