package xnetip

import (
	"testing"

	"github.com/stretchr/testify/require"
	"pgregory.net/rapid"
)

// verifies that unwrapping the mapped storage form returns exactly the
// IPv4 network the family-agnostic value was built from.
func Test_Network_Unwrap4_RoundTrip(t *testing.T) {
	tests := []struct {
		name    string
		network Network4
	}{
		{name: "universe", network: MustParseNetwork4("0.0.0.0/0")},
		{name: "cidr block", network: MustParseNetwork4("10.0.0.0/8")},
		{name: "host route", network: MustParseNetwork4("192.168.1.5/32")},
		{name: "all ones host route", network: MustParseNetwork4("255.255.255.255/32")},
		{name: "alternating non-contiguous mask", network: MustParseNetwork4("170.85.170.85/170.85.170.85")},
		{name: "two-run mask 255.0.255.0", network: MustParseNetwork4("10.0.3.0/255.0.255.0")},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			require.Equal(t, test.network, NetworkFrom4(test.network).unwrap4())
		})
	}
}

// verifies that the round trip through the mapped storage form is the
// identity on every address and mask shape the kernel generator draws.
func Test_Network_Unwrap4_RoundTripProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		addr := genAddr4.Draw(t, "addr")
		mask := genAddr4.Draw(t, "mask")
		network := fromBits4(addr, mask)
		require.Equal(t, network, NetworkFrom4(network).unwrap4())
	})
}
