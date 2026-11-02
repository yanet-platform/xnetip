package xnetip_test

import (
	"encoding"
	"fmt"
	"net/netip"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/yanet-platform/xnetip"
	"pgregory.net/rapid"
)

var asciiNetworkFixtures = []string{
	"", "0.0.0.0/0", "255.255.255.255/32", "10.1.2.3", "192.168.1.5/24",
	"10.1.2.3/255.0.255.0", "170.85.170.85/170.85.170.85",
	"::/0", "::1", "2001:db8::1/64", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/128",
	"2001:db8:1:2:3:4:5:6/ffff:ffff:ffff:0:0:ffff:ffff:ffff",
	"::/ffff:0:ffff:0:ffff:0:ffff:0", "::ffff:192.0.2.1/120",
	"1:2:3:4:5:6:192.0.2.1", "1:2:3::192.0.2.1",
	"1.2.3.4/+24", "1.2.3.4/024", "::/+64", "::/064", "1.2.3.4/33", "::/129",
	"1.2.3.4/999999999999999999999999999999", "::/999999999999999999999999999999",
	"1.2.3.4/::", "::/255.255.255.0", "01.2.3.4", "1.2.3.256", "1.2.3.4/",
	"1:2:3:4:5:6:7:8", "1:2:3:4:5:6:7", "1:2:3:4:5:6:7:8:9",
	"1:2:3:4:5:6:7:8::", "1:2:3:4:5:6::7:8", "1:2:3:4:5:6:7::",
	":::", "1::2::3", ":1", "1:", "12345::", "::ffff:192.168.001.1",
	"fe80::1%eth0", "::/ffff::%eth0", " 1.2.3.4", "::1 ", "::1\x00", "\xff", "::/\xff",
}

// verifies that full byte parsers retain every string-parser grammar
// decision and error category across both address families.
func Test_ParseNetworkASCII_StringParity(t *testing.T) {
	for _, input := range asciiNetworkFixtures {
		t.Run(input, func(t *testing.T) {
			requireASCIIParseParity(t, []byte(input), xnetip.ParseNetwork4ASCII, xnetip.ParseNetwork4)
			requireASCIIParseParity(t, []byte(input), xnetip.ParseNetwork6ASCII, xnetip.ParseNetwork6)
			requireASCIIParseParity(t, []byte(input), xnetip.ParseNetworkASCII, xnetip.ParseNetwork)
		})
	}
}

// verifies that leading-token parsing uses the exact family alphabet
// and rejects a malformed maximal token instead of shortening it.
func Test_ParseNextNetworkASCII_TokenBoundaries(t *testing.T) {
	cases := []struct {
		name   string
		input  string
		family int
		want   string
		rest   string
	}{
		{name: "declared IPv4 stops before a port", input: "1.2.3.4:8080", family: 4, want: "1.2.3.4/32", rest: ":8080"},
		{name: "declared IPv4 stops before hex letters", input: "1.2.3.4abcd", family: 4, want: "1.2.3.4/32", rest: "abcd"},
		{name: "declared IPv4 leaves a following action", input: "10.0.0.1/24 allow", family: 4, want: "10.0.0.0/24", rest: " allow"},
		{name: "declared IPv4 accepts an adjacent action", input: "10.0.0.1/24allow", family: 4, want: "10.0.0.0/24", rest: "allow"},
		{name: "shared alphabet keeps the port in the token", input: "1.2.3.4:8080", family: 0},
		{name: "shared alphabet keeps hex letters in the token", input: "1.2.3.4abcd", family: 0},
		{name: "shared alphabet needs an action delimiter", input: "10.0.0.1/24allow", family: 0},
		{name: "IPv6 colon remains address material", input: "::1:8080 allow", family: 6, want: "::1:8080/128", rest: " allow"},
		{name: "mixed parser detects IPv4", input: "10.1.2.3/255.0.255.0 allow", family: 0, want: "10.0.2.0/255.0.255.0", rest: " allow"},
		{name: "mixed parser detects mapped IPv6", input: "::ffff:192.0.2.1/120 allow", family: 0, want: "::ffff:192.0.2.0/120", rest: " allow"},
		{name: "zone delimiter is unconsumed", input: "fe80::1%eth0", family: 6, want: "fe80::1/128", rest: "%eth0"},
		{name: "non-ASCII delimiter is unconsumed", input: "::1\xfftail", family: 0, want: "::1/128", rest: "\xfftail"},
		{name: "leading whitespace is not skipped", input: " 1.2.3.4", family: 4},
		{name: "empty token is rejected", input: "!::1", family: 6},
		{name: "malformed dotted suffix is not shortened", input: "1.2.3.4/24.1 allow", family: 4},
		{name: "second slash is token material", input: "1.2.3.4/24/8 allow", family: 4},
		{name: "strict unsigned prefix grammar is retained", input: "1.2.3.4/+24 allow", family: 4},
		{name: "strict no-leading-zero grammar is retained", input: "::/064 allow", family: 6},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			input := []byte(testCase.input)
			var network xnetip.Network
			var rest []byte
			var err error
			switch testCase.family {
			case 4:
				var concrete xnetip.Network4
				concrete, rest, err = xnetip.ParseNextNetwork4ASCII(input)
				network = xnetip.NetworkFrom4(concrete)
			case 6:
				var concrete xnetip.Network6
				concrete, rest, err = xnetip.ParseNextNetwork6ASCII(input)
				network = xnetip.NetworkFrom6(concrete)
			default:
				network, rest, err = xnetip.ParseNextNetworkASCII(input)
			}
			if testCase.want == "" {
				require.Error(t, err)
				require.Nil(t, rest)
				return
			}
			require.NoError(t, err)
			require.Equal(t, xnetip.MustParseNetwork(testCase.want), network)
			require.Equal(t, testCase.rest, string(rest))
			if len(rest) > 0 {
				require.Same(t, &input[len(input)-len(rest)], &rest[0])
			}
		})
	}
}

// verifies that errors own their original byte text after the caller
// reuses or overwrites the input buffer.
func Test_ParseNetworkASCII_ErrorOwnsInput(t *testing.T) {
	input := []byte("2001:db8::/ffff::%eth0")
	_, err := xnetip.ParseNetworkASCII(input)
	require.Error(t, err)
	want := err.Error()
	for idx := range input {
		input[idx] = 'x'
	}
	require.Equal(t, want, err.Error())
}

// verifies that token errors retain the original rejected token
// after the rule-text buffer is overwritten.
func Test_ParseNextNetworkASCII_ErrorOwnsInput(t *testing.T) {
	input := []byte("1.2.3.4:8080 allow")
	_, _, err := xnetip.ParseNextNetworkASCII(input)
	require.Error(t, err)
	want := err.Error()
	for idx := range input {
		input[idx] = 'x'
	}
	require.Equal(t, want, err.Error())
}

// verifies that arbitrary normalized networks round-trip through
// the byte kernels without allocations for every mask shape.
func Test_ParseNetworkASCII_RoundTripProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		network4 := genNetwork4.Draw(t, "network4")
		input4 := []byte(network4.String())
		actual4, err := xnetip.ParseNetwork4ASCII(input4)
		require.NoError(t, err)
		require.Equal(t, network4, actual4)
		network6 := genNetwork6.Draw(t, "network6")
		input6 := []byte(network6.String())
		actual6, err := xnetip.ParseNetwork6ASCII(input6)
		require.NoError(t, err)
		require.Equal(t, network6, actual6)
		network := genNetwork.Draw(t, "network")
		input := []byte(network.String())
		actual, err := xnetip.ParseNetworkASCII(input)
		require.NoError(t, err)
		require.Equal(t, network, actual)
		requireNoAllocs(t, func() {
			networkSink, errSink = xnetip.ParseNetwork4ASCII(input4)
			network6Sink, errSink = xnetip.ParseNetwork6ASCII(input6)
			ipNetworkSink, errSink = xnetip.ParseNetworkASCII(input)
		})
	})
}

// verifies that byte parsing and leading-token extraction allocate
// nothing for both families, explicit masks and embedded IPv4.
func Test_ParseNetworkASCII_NoAllocations(t *testing.T) {
	input4 := []byte("170.85.170.85/170.85.170.85")
	input6 := []byte("2001:db8:1:2:3:4:5:6/ffff:ffff:ffff:0:0:ffff:ffff:ffff")
	mapped := []byte("::ffff:192.0.2.1/120")
	requireNoAllocs(t, func() {
		networkSink, errSink = xnetip.ParseNetwork4ASCII(input4)
		network6Sink, errSink = xnetip.ParseNetwork6ASCII(input6)
		ipNetworkSink, errSink = xnetip.ParseNetworkASCII(mapped)
		networkSink, bytesSink, errSink = xnetip.ParseNextNetwork4ASCII(input4)
		network6Sink, bytesSink, errSink = xnetip.ParseNextNetwork6ASCII(input6)
		ipNetworkSink, bytesSink, errSink = xnetip.ParseNextNetworkASCII(mapped)
	})
	require.NoError(t, errSink)
}

// verifies that text decoding stays allocation-free for all network
// and guarantee-wrapper instantiations, including long IPv6 text.
func Test_UnmarshalText_AllTypesNoAllocations(t *testing.T) {
	cases := []struct {
		name  string
		value encoding.TextUnmarshaler
		input []byte
	}{
		{name: "IPv4", value: &xnetip.Network4{}, input: []byte("170.85.170.85/170.85.170.85")},
		{name: "IPv6", value: &xnetip.Network6{}, input: []byte("2001:db8:1:2:3:4:5:6/ffff:ffff:ffff:0:0:ffff:ffff:ffff")},
		{name: "mixed IPv4", value: &xnetip.Network{}, input: []byte("10.0.0.0/255.0.255.0")},
		{name: "mixed IPv6", value: &xnetip.Network{}, input: []byte("::ffff:192.0.2.1/120")},
		{name: "contiguous IPv4", value: &xnetip.Contiguous[xnetip.Network4]{}, input: []byte("192.168.1.5/24")},
		{name: "contiguous IPv6", value: &xnetip.Contiguous[xnetip.Network6]{}, input: []byte("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/128")},
		{name: "contiguous mixed", value: &xnetip.Contiguous[xnetip.Network]{}, input: []byte("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/128")},
		{name: "bi-contiguous", value: &xnetip.BiContiguous{}, input: []byte("2001:db8:1:2:3:4:5:6/ffff:ffff:ff00::ffff:ffff:0:0")},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			requireNoAllocs(t, func() { errSink = testCase.value.UnmarshalText(testCase.input) })
			require.NoError(t, errSink)
		})
	}
}

// verifies that arbitrary bytes retain exact full-parse semantics
// when compared with the existing standard-library-backed parsers.
func FuzzParseNetworkASCII(f *testing.F) {
	for _, input := range asciiNetworkFixtures {
		f.Add([]byte(input))
	}
	f.Fuzz(func(t *testing.T, input []byte) {
		requireASCIIParseParity(t, input, xnetip.ParseNetwork4ASCII, xnetip.ParseNetwork4)
		requireASCIIParseParity(t, input, xnetip.ParseNetwork6ASCII, xnetip.ParseNetwork6)
		requireASCIIParseParity(t, input, xnetip.ParseNetworkASCII, xnetip.ParseNetwork)
		if len(input) == 0 {
			return
		}
		requireASCIIParseParity(t, input, func(text []byte) (xnetip.Contiguous[xnetip.Network4], error) {
			var actual xnetip.Contiguous[xnetip.Network4]
			err := actual.UnmarshalText(text)
			return actual, err
		}, xnetip.ParseContiguous4)
		requireASCIIParseParity(t, input, func(text []byte) (xnetip.Contiguous[xnetip.Network6], error) {
			var actual xnetip.Contiguous[xnetip.Network6]
			err := actual.UnmarshalText(text)
			return actual, err
		}, xnetip.ParseContiguous6)
		requireASCIIParseParity(t, input, func(text []byte) (xnetip.Contiguous[xnetip.Network], error) {
			var actual xnetip.Contiguous[xnetip.Network]
			err := actual.UnmarshalText(text)
			return actual, err
		}, xnetip.ParseContiguous)
		requireASCIIParseParity(t, input, func(text []byte) (xnetip.BiContiguous, error) {
			var actual xnetip.BiContiguous
			err := actual.UnmarshalText(text)
			return actual, err
		}, xnetip.ParseBiContiguous)
	})
}

// verifies that arbitrary rule text agrees with maximal-alphabet
// tokenization followed by complete string parsing.
func FuzzParseNextNetworkASCII(f *testing.F) {
	for _, input := range asciiNetworkFixtures {
		f.Add([]byte(input + " allow"))
	}
	for _, input := range []string{"1.2.3.4:8080", "::1%eth0", "1.2.3.4abcd", "::1\xfftail"} {
		f.Add([]byte(input))
	}
	f.Fuzz(func(t *testing.T, input []byte) {
		requireNextASCIIParseParity(t, input, "0123456789./+", xnetip.ParseNextNetwork4ASCII, xnetip.ParseNetwork4)
		requireNextASCIIParseParity(t, input, "0123456789abcdefABCDEF:./+", xnetip.ParseNextNetwork6ASCII, xnetip.ParseNetwork6)
		requireNextASCIIParseParity(t, input, "0123456789abcdefABCDEF:./+", xnetip.ParseNextNetworkASCII, xnetip.ParseNetwork)
	})
}

// BenchmarkParseNetwork4ASCII measures strict CIDR decoding from bytes.
func BenchmarkParseNetwork4ASCII(b *testing.B) {
	input := []byte("192.168.1.5/24")
	b.ReportAllocs()
	for b.Loop() {
		networkSink, errSink = xnetip.ParseNetwork4ASCII(input)
	}
}

// BenchmarkParseNetwork6ASCII measures arbitrary-mask decoding from bytes.
func BenchmarkParseNetwork6ASCII(b *testing.B) {
	input := []byte("2001:db8:1:2:3:4:5:6/ffff:ffff:ffff:0:0:ffff:ffff:ffff")
	b.ReportAllocs()
	for b.Loop() {
		network6Sink, errSink = xnetip.ParseNetwork6ASCII(input)
	}
}

// BenchmarkParseNetworkASCII measures family detection for embedded IPv4.
func BenchmarkParseNetworkASCII(b *testing.B) {
	input := []byte("::ffff:192.0.2.1/120")
	b.ReportAllocs()
	for b.Loop() {
		ipNetworkSink, errSink = xnetip.ParseNetworkASCII(input)
	}
}

// BenchmarkParseNextNetwork4ASCII measures declared-family rule extraction.
func BenchmarkParseNextNetwork4ASCII(b *testing.B) {
	input := []byte("10.1.2.3/255.0.255.0 allow")
	b.ReportAllocs()
	for b.Loop() {
		networkSink, bytesSink, errSink = xnetip.ParseNextNetwork4ASCII(input)
	}
}

// BenchmarkParseNextNetwork6ASCII measures IPv6 rule extraction.
func BenchmarkParseNextNetwork6ASCII(b *testing.B) {
	input := []byte("2001:db8:1:2:3:4:5:6/ffff:ffff:ff00::ffff:ffff:0:0 allow")
	b.ReportAllocs()
	for b.Loop() {
		network6Sink, bytesSink, errSink = xnetip.ParseNextNetwork6ASCII(input)
	}
}

// BenchmarkParseNextNetworkASCII measures shared-alphabet rule extraction.
func BenchmarkParseNextNetworkASCII(b *testing.B) {
	input := []byte("::ffff:192.0.2.1/120 allow")
	b.ReportAllocs()
	for b.Loop() {
		ipNetworkSink, bytesSink, errSink = xnetip.ParseNextNetworkASCII(input)
	}
}

// verifies that the byte parser's CIDR path preserves normalization.
func ExampleParseNetwork4ASCII() {
	network, _ := xnetip.ParseNetwork4ASCII([]byte("192.168.1.5/24"))
	fmt.Println(network.ContainsAddr(netip.MustParseAddr("192.168.1.100")))
	// Output: true
}
