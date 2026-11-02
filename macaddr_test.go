package xnetip_test

import (
	"encoding"
	"encoding/json"
	"fmt"
	"net"
	"slices"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/yanet-platform/xnetip"
	"pgregory.net/rapid"
)

var macAddrSink xnetip.MacAddr

var (
	_ encoding.TextMarshaler   = xnetip.MacAddr{}
	_ encoding.TextUnmarshaler = (*xnetip.MacAddr)(nil)
	_ fmt.Formatter            = xnetip.MacAddr{}
)

// verifies octet and integer construction preserve transmission order and
// reject every bit above the 48-bit address without truncating it.
func Test_MacAddr_ConstructorsAndZero(t *testing.T) {
	var zero xnetip.MacAddr
	require.True(t, zero.IsZero())
	require.Equal(t, "00:00:00:00:00:00", zero.String())
	address := xnetip.MacAddrFrom6([6]byte{0x3a, 0xac, 0x26, 0x9b, 0x5b, 0xf9})
	require.Equal(t, uint64(0x3aac269b5bf9), address.Uint64())
	require.Equal(t, [6]byte{0x3a, 0xac, 0x26, 0x9b, 0x5b, 0xf9}, address.As6())
	for _, value := range []uint64{0, 1, 0x3aac269b5bf9, 0xffffffffffff} {
		converted, ok := xnetip.MacAddrFromUint64(value)
		require.True(t, ok)
		require.Equal(t, value, converted.Uint64())
	}
	for position := 48; position < 64; position++ {
		converted, ok := xnetip.MacAddrFromUint64(uint64(1)<<position | 0x3aac269b5bf9)
		require.False(t, ok)
		require.Equal(t, zero, converted)
	}
	require.Equal(t, "ff:ff:ff:ff:ff:ff", xnetip.MacAddrFrom6([6]byte{255, 255, 255, 255, 255, 255}).String())
}

// verifies all first-octet combinations classify the group and administration
// bits independently, including the multicast broadcast and unicast zero.
func Test_MacAddr_Predicates(t *testing.T) {
	for first := range 256 {
		address := xnetip.MacAddrFrom6([6]byte{byte(first), 0, 0, 0, 0, 0})
		require.Equal(t, first&1 != 0, address.IsMulticast())
		require.Equal(t, first&1 == 0, address.IsUnicast())
		require.Equal(t, first&2 != 0, address.IsLocallyAdministered())
		require.Equal(t, first&2 == 0, address.IsUniversallyAdministered())
		require.Equal(t, first == 0, address.IsZero())
		require.False(t, address.IsBroadcast())
	}
	broadcast := xnetip.MustParseMacAddr("ff:ff:ff:ff:ff:ff")
	require.True(t, broadcast.IsBroadcast())
	require.True(t, broadcast.IsMulticast())
	require.False(t, broadcast.IsUnicast())
	require.True(t, broadcast.IsLocallyAdministered())
}

// verifies the three case-insensitive address forms parse identically through
// string and byte entry points and agree with the standard library.
func Test_ParseMacAddr_AcceptedForms(t *testing.T) {
	cases := []string{
		"3a:ac:26:9b:5b:f9", "3A:AC:26:9B:5B:F9", "3a:Ac:26:9B:5b:F9",
		"3a-ac-26-9b-5b-f9", "3A-AC-26-9B-5B-F9", "3aac.269b.5bf9", "3AAC.269B.5BF9",
		"00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff",
	}
	for _, text := range cases {
		t.Run(text, func(t *testing.T) {
			expected, err := net.ParseMAC(text)
			require.NoError(t, err)
			address, err := xnetip.ParseMacAddr(text)
			require.NoError(t, err)
			require.Equal(t, expected.String(), address.String())
			fromBytes, err := xnetip.ParseMacAddrASCII([]byte(text))
			require.NoError(t, err)
			require.Equal(t, address, fromBytes)
			require.Equal(t, address, xnetip.MustParseMacAddr(text))
		})
	}
}

// verifies malformed lengths, mixed separators, invalid digits and trailing
// data are rejected without accepting bare or wider hardware addresses.
func Test_ParseMacAddr_RejectsMalformedForms(t *testing.T) {
	cases := []string{
		"", "3aac269b5bf9", "3a:ac:26:9b:5b", "3a:ac:26:9b:5b:f9:00", "3a:ac:26:9b:5b:f9:00:00",
		"3:ac:26:9b:5b:f9", "3aa:ac:26:9b:5b:f9", "3g:ac:26:9b:5b:f9",
		"3a:ac-26:9b:5b:f9", "3a-ac:26-9b-5b-f9", "3a ac 26 9b 5b f9",
		"3a.ac.26.9b.5b.f9", "3aac-269b.5bf9", "3aac.269b-5bf9", "3aa.269b.5bf9",
		"3aac.269b.5bf9.", "3aac.269b.5bfz", " 3a:ac:26:9b:5b:f9", "3a:ac:26:9b:5b:f9\n",
		"3a:ac:26:9b:5b:\x00f", "3a:ac:26:9b:5b:\xfff", "３a:ac:26:9b:5b:f9",
	}
	for _, text := range cases {
		t.Run(text, func(t *testing.T) {
			address, err := xnetip.ParseMacAddr(text)
			require.ErrorIs(t, err, xnetip.ErrParse)
			require.ErrorIs(t, err, xnetip.ErrInvalidMacAddr)
			require.Equal(t, xnetip.MacAddr{}, address)
			require.Contains(t, err.Error(), "xnetip.ParseMacAddr(")
			address, err = xnetip.ParseMacAddrASCII([]byte(text))
			require.ErrorIs(t, err, xnetip.ErrInvalidMacAddr)
			require.Equal(t, xnetip.MacAddr{}, address)
		})
	}
	require.Panics(t, func() { xnetip.MustParseMacAddr("invalid") })
}

// verifies every separator position is validated independently and every
// non-ASCII byte is rejected when inserted into a hexadecimal position.
func Test_ParseMacAddr_ByteBoundaries(t *testing.T) {
	for _, text := range []string{"aa:bb:cc:dd:ee:ff", "aa-bb-cc-dd-ee-ff", "aabb.ccdd.eeff"} {
		for position := range len(text) {
			for _, replacement := range []byte{0, 'g', '/', ':', '-', '.', 0x80, 0xff} {
				mutated := []byte(text)
				mutated[position] = replacement
				address, err := xnetip.ParseMacAddrASCII(mutated)
				expected, expectedError := net.ParseMAC(string(mutated))
				if expectedError != nil {
					require.ErrorIs(t, err, xnetip.ErrInvalidMacAddr)
				} else {
					require.NoError(t, err)
					require.Equal(t, expected.String(), address.String())
				}
			}
		}
	}
}

// verifies numeric and lexicographic octet orders agree and immutable values
// remain directly usable as map keys.
func Test_MacAddr_CompareAndValueSemanticsProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		first := genMacAddr.Draw(t, "first address")
		second := genMacAddr.Draw(t, "second address")
		firstOctets, secondOctets := first.As6(), second.As6()
		require.Equal(t, slices.Compare(firstOctets[:], secondOctets[:]), first.Compare(second))
		require.Equal(t, -first.Compare(second), second.Compare(first))
		require.Zero(t, first.Compare(first))
		lookup := map[xnetip.MacAddr]int{first: 1}
		fromOctets := xnetip.MacAddrFrom6(first.As6())
		require.Equal(t, 1, lookup[fromOctets])
		fromInteger, ok := xnetip.MacAddrFromUint64(first.Uint64())
		require.True(t, ok)
		require.Equal(t, first, fromInteger)
	})
}

// verifies canonical and alternative formats round-trip through both parsers,
// preserve append prefixes and match the standard library's canonical text.
func Test_MacAddr_FormatRoundTripProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		address := genMacAddr.Draw(t, "address")
		octets := address.As6()
		require.Equal(t, net.HardwareAddr(octets[:]).String(), address.String())
		for _, text := range []string{
			address.String(), fmt.Sprintf("%X", address),
			xnetip.MacHyphens(address).String(), fmt.Sprintf("%X", xnetip.MacHyphens(address)),
			xnetip.MacDots(address).String(), fmt.Sprintf("%X", xnetip.MacDots(address)),
		} {
			parsed, err := xnetip.ParseMacAddr(text)
			require.NoError(t, err)
			require.Equal(t, address, parsed)
			parsed, err = xnetip.ParseMacAddrASCII([]byte(text))
			require.NoError(t, err)
			require.Equal(t, address, parsed)
		}
		require.Equal(t, "mac="+address.String(), string(address.AppendTo([]byte("mac="))))
	})
}

// verifies hexadecimal case, whole-text width and precision, quoting, and
// conventional diagnostics for unsupported formatting verbs.
func Test_MacAddr_FormatFlagsAndAdapters(t *testing.T) {
	address := xnetip.MustParseMacAddr("3a:ac:26:9b:5b:f9")
	cases := []struct {
		format   string
		value    any
		expected string
	}{
		{"%v", address, "3a:ac:26:9b:5b:f9"},
		{"%s", address, "3a:ac:26:9b:5b:f9"},
		{"%x", address, "3a:ac:26:9b:5b:f9"},
		{"%X", address, "3A:AC:26:9B:5B:F9"},
		{"[%20s]", address, "[   3a:ac:26:9b:5b:f9]"},
		{"[%-20X]", address, "[3A:AC:26:9B:5B:F9   ]"},
		{"%.5s", address, "3a:ac"},
		{"%.0s", address, ""},
		{"%020s", address, "0003a:ac:26:9b:5b:f9"},
		{"%-020s", address, "3a:ac:26:9b:5b:f9   "},
		{"%.5q", address, `"3a:ac"`},
		{"%#q", address, "`3a:ac:26:9b:5b:f9`"},
		{"%q", address, `"3a:ac:26:9b:5b:f9"`},
		{"%s", xnetip.MacHyphens(address), "3a-ac-26-9b-5b-f9"},
		{"%X", xnetip.MacHyphens(address), "3A-AC-26-9B-5B-F9"},
		{"%s", xnetip.MacDots(address), "3aac.269b.5bf9"},
		{"%X", xnetip.MacDots(address), "3AAC.269B.5BF9"},
		{"[%17.6X]", xnetip.MacDots(address), "[           3AAC.2]"},
		{"%d", address, "%!d(xnetip.MacAddr=3a:ac:26:9b:5b:f9)"},
	}
	for _, testCase := range cases {
		require.Equal(t, testCase.expected, fmt.Sprintf(testCase.format, testCase.value))
	}
	require.Equal(t, "mac=3a-ac-26-9b-5b-f9", string(xnetip.MacHyphens(address).AppendTo([]byte("mac="))))
	require.Equal(t, "mac=3aac.269b.5bf9", string(xnetip.MacDots(address).AppendTo([]byte("mac="))))
}

// verifies successful text decoding replaces the receiver and errors leave
// it intact, including empty text and malformed byte input.
func Test_MacAddr_TextMarshaling(t *testing.T) {
	original := xnetip.MustParseMacAddr("3a:ac:26:9b:5b:f9")
	text, err := original.MarshalText()
	require.NoError(t, err)
	require.Equal(t, "3a:ac:26:9b:5b:f9", string(text))
	for _, input := range []string{"", "bad", "3a:ac:26:9b:5b:\xfff", "3aac269b5bf9"} {
		receiver := original
		err := receiver.UnmarshalText([]byte(input))
		if input == "" {
			require.ErrorIs(t, err, xnetip.ErrEmptyInput)
		} else {
			require.ErrorIs(t, err, xnetip.ErrInvalidMacAddr)
		}
		require.Equal(t, original, receiver)
	}
	for _, input := range []string{"00:00:00:00:00:00", "AA-BB-CC-DD-EE-FF", "aabb.ccdd.eeff"} {
		receiver := original
		require.NoError(t, receiver.UnmarshalText([]byte(input)))
		require.Equal(t, xnetip.MustParseMacAddr(input), receiver)
	}
	lookup := map[xnetip.MacAddr]int{original: 1}
	encoded, err := json.Marshal(lookup)
	require.NoError(t, err)
	var decoded map[xnetip.MacAddr]int
	require.NoError(t, json.Unmarshal(encoded, &decoded))
	require.Equal(t, lookup, decoded)
}

// verifies successful parsing, unmarshaling, appending and value operations
// need no heap allocations when their output storage is already available.
func Test_MacAddr_AllocationFree(t *testing.T) {
	address := xnetip.MustParseMacAddr("3a:ac:26:9b:5b:f9")
	for _, text := range []string{"3a:ac:26:9b:5b:f9", "3A-AC-26-9B-5B-F9", "3aac.269b.5bf9"} {
		input := []byte(text)
		requireNoAllocs(t, func() {
			var err error
			macAddrSink, err = xnetip.ParseMacAddr(text)
			if err != nil {
				panic(err)
			}
		})
		requireNoAllocs(t, func() {
			var err error
			macAddrSink, err = xnetip.ParseMacAddrASCII(input)
			if err != nil {
				panic(err)
			}
		})
		requireNoAllocs(t, func() {
			if err := macAddrSink.UnmarshalText(input); err != nil {
				panic(err)
			}
		})
	}
	buffer := make([]byte, 0, 17)
	requireNoAllocs(t, func() { bytesSink = address.AppendTo(buffer[:0]) })
	requireNoAllocs(t, func() { bytesSink = xnetip.MacHyphens(address).AppendTo(buffer[:0]) })
	requireNoAllocs(t, func() { bytesSink = xnetip.MacDots(address).AppendTo(buffer[:0]) })
	requireNoAllocs(t, func() {
		macAddrSink = xnetip.MacAddrFrom6(address.As6())
		macAddrSink, _ = xnetip.MacAddrFromUint64(address.Uint64())
		intSink = address.Compare(macAddrSink)
		okSink = address.IsZero() || address.IsBroadcast() || address.IsMulticast() ||
			address.IsUnicast() || address.IsLocallyAdministered() || address.IsUniversallyAdministered()
	})
}

// macFormatState captures formatter output without allocating writer storage.
type macFormatState struct {
	buffer       [128]byte
	length       int
	width        int
	precision    int
	hasPrecision bool
	flags        string
}

func (m *macFormatState) Write(text []byte) (int, error) {
	copied := copy(m.buffer[m.length:], text)
	m.length += copied
	return copied, nil
}

func (m *macFormatState) Width() (int, bool) {
	return m.width, m.width != 0
}

func (m *macFormatState) Precision() (int, bool) {
	return m.precision, m.hasPrecision
}

func (m *macFormatState) Flag(flag int) bool {
	return strings.ContainsRune(m.flags, rune(flag))
}

// verifies formatter output needs no heap allocation through a preallocated
// writer for all text shapes, case modes, quoting and whole-text padding.
func Test_MacAddr_FormatAllocationFree(t *testing.T) {
	address := xnetip.MustParseMacAddr("3a:ac:26:9b:5b:f9")
	state := &macFormatState{width: 23, precision: 12, hasPrecision: true}
	for _, verb := range []rune{'v', 's', 'x', 'X', 'q'} {
		for _, flags := range []string{"", "-", "0", "#"} {
			state.flags = flags
			requireNoAllocs(t, func() { state.length = 0; address.Format(state, verb) })
			requireNoAllocs(t, func() { state.length = 0; xnetip.MacHyphens(address).Format(state, verb) })
			requireNoAllocs(t, func() { state.length = 0; xnetip.MacDots(address).Format(state, verb) })
		}
	}
}

// verifies arbitrary text agrees with the standard library on the shared
// three EUI-48 forms and accepted text always round-trips canonically.
func FuzzParseMacAddr(f *testing.F) {
	for _, text := range []string{"3a:ac:26:9b:5b:f9", "3A-AC-26-9B-5B-F9", "3aac.269b.5bf9", "", "aabbccddeeff"} {
		f.Add(text)
	}
	f.Fuzz(func(t *testing.T, text string) {
		address, err := xnetip.ParseMacAddr(text)
		expected, expectedError := net.ParseMAC(text)
		accepted := expectedError == nil && len(expected) == 6 && (len(text) == 14 || len(text) == 17)
		require.Equal(t, accepted, err == nil)
		if err == nil {
			require.Equal(t, expected.String(), address.String())
			require.Equal(t, address, xnetip.MustParseMacAddr(address.String()))
		}
		fromBytes, byteError := xnetip.ParseMacAddrASCII([]byte(text))
		require.Equal(t, err == nil, byteError == nil)
		require.Equal(t, address, fromBytes)
	})
}

func BenchmarkMacAddr_Parse(b *testing.B) {
	for _, text := range []string{"3a:ac:26:9b:5b:f9", "3a-ac-26-9b-5b-f9", "3aac.269b.5bf9"} {
		b.Run(text, func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				macAddrSink, _ = xnetip.ParseMacAddr(text)
			}
		})
	}
}

func BenchmarkMacAddr_ParseASCII(b *testing.B) {
	input := []byte("3a:ac:26:9b:5b:f9")
	b.ReportAllocs()
	for b.Loop() {
		macAddrSink, _ = xnetip.ParseMacAddrASCII(input)
	}
}

func BenchmarkMacAddr_AppendTo(b *testing.B) {
	address := xnetip.MustParseMacAddr("3a:ac:26:9b:5b:f9")
	buffer := make([]byte, 0, 17)
	b.ReportAllocs()
	for b.Loop() {
		bytesSink = address.AppendTo(buffer[:0])
	}
}

func BenchmarkMacAddr_String(b *testing.B) {
	address := xnetip.MustParseMacAddr("3a:ac:26:9b:5b:f9")
	b.ReportAllocs()
	for b.Loop() {
		stringSink = address.String()
	}
}

func BenchmarkMacAddr_Compare(b *testing.B) {
	first := xnetip.MustParseMacAddr("3a:ac:26:9b:5b:f9")
	second := xnetip.MustParseMacAddr("3a:ac:26:9b:5b:fa")
	b.ReportAllocs()
	for b.Loop() {
		intSink = first.Compare(second)
	}
}

func BenchmarkMacAddr_Format(b *testing.B) {
	address := xnetip.MustParseMacAddr("3a:ac:26:9b:5b:f9")
	state := &macFormatState{}
	b.ReportAllocs()
	for b.Loop() {
		state.length = 0
		address.Format(state, 'X')
	}
}

// verifies the canonical address can be uppercased without changing its value.
func ExampleMacAddr() {
	address := xnetip.MustParseMacAddr("3aac.269b.5bf9")
	fmt.Println(address)
	fmt.Println(strings.ToUpper(address.String()))
	// Output:
	// 3a:ac:26:9b:5b:f9
	// 3A:AC:26:9B:5B:F9
}
