package xnetip_test

import (
	"bytes"
	"net/netip"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/yanet-platform/xnetip"
	"pgregory.net/rapid"
)

// verifies that the constructor clears every address bit outside the
// mask and keeps the mask unchanged, whatever the mask's shape.
func Test_IPv4NetworkFrom_NormalizesAddressByMask(t *testing.T) {
	cases := []struct {
		name     string
		addr     string
		mask     string
		wantAddr string
	}{
		{name: "contiguous mask clears host bits", addr: "192.168.1.1", mask: "255.255.255.0", wantAddr: "192.168.1.0"},
		{name: "host route keeps the address", addr: "192.168.0.1", mask: "255.255.255.255", wantAddr: "192.168.0.1"},
		{name: "all-zero mask clears everything", addr: "10.1.2.3", mask: "0.0.0.0", wantAddr: "0.0.0.0"},
		{name: "mask 255.255.0.255 clears the hole in the third octet", addr: "192.168.7.1", mask: "255.255.0.255", wantAddr: "192.168.0.1"},
		{name: "already normalized address stays", addr: "192.168.0.1", mask: "255.255.0.255", wantAddr: "192.168.0.1"},
		{name: "alternating mask keeps every second bit", addr: "255.255.255.255", mask: "170.85.170.85", wantAddr: "170.85.170.85"},
		{name: "single-bit mask keeps the lowest bit", addr: "255.255.255.255", mask: "0.0.0.1", wantAddr: "0.0.0.1"},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			network, err := xnetip.IPv4NetworkFrom(
				netip.MustParseAddr(testCase.addr),
				netip.MustParseAddr(testCase.mask),
			)
			require.NoError(t, err)
			require.Equal(t, netip.MustParseAddr(testCase.wantAddr), network.Addr())
			require.Equal(t, netip.MustParseAddr(testCase.mask), network.Mask())
		})
	}
}

// verifies that a non-Is4 argument in either position, IPv4-mapped
// included, yields the family-mismatch sentinel and the zero network.
func Test_IPv4NetworkFrom_RejectsForeignFamily(t *testing.T) {
	cases := []struct {
		name string
		addr netip.Addr
		mask netip.Addr
	}{
		{name: "IPv6 address", addr: netip.MustParseAddr("2001:db8::1"), mask: netip.MustParseAddr("255.0.0.0")},
		{name: "IPv4-mapped IPv6 address", addr: netip.MustParseAddr("::ffff:1.2.3.4"), mask: netip.MustParseAddr("255.0.0.0")},
		{name: "IPv6 mask", addr: netip.MustParseAddr("10.0.0.0"), mask: netip.MustParseAddr("ffff::")},
		{name: "invalid zero address", addr: netip.Addr{}, mask: netip.MustParseAddr("255.0.0.0")},
		{name: "invalid zero mask", addr: netip.MustParseAddr("10.0.0.0"), mask: netip.Addr{}},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			network, err := xnetip.IPv4NetworkFrom(testCase.addr, testCase.mask)
			require.ErrorIs(t, err, xnetip.ErrAddrFamilyMismatch)
			require.Equal(t, xnetip.IPv4Network{}, network)
		})
	}
}

// verifies that the accessors return Is4, zone-free netip values.
func Test_IPv4Network_Accessors_ReturnIs4Views(t *testing.T) {
	network, err := xnetip.IPv4NetworkFrom(
		netip.MustParseAddr("192.168.1.1"),
		netip.MustParseAddr("255.255.0.255"),
	)
	require.NoError(t, err)
	require.True(t, network.Addr().Is4())
	require.True(t, network.Mask().Is4())
	require.Empty(t, network.Addr().Zone())
	require.Empty(t, network.Mask().Zone())
}

// verifies that the all-zero mask produces the unspecified network,
// which is the zero value of the type.
func Test_IPv4NetworkFrom_UniverseEqualsZeroValue(t *testing.T) {
	network, err := xnetip.IPv4NetworkFrom(
		netip.MustParseAddr("10.1.2.3"),
		netip.MustParseAddr("0.0.0.0"),
	)
	require.NoError(t, err)
	require.Equal(t, xnetip.IPv4Network{}, network)
}

// verifies that the zero value is the unspecified network 0.0.0.0/0.
func Test_IPv4Network_ZeroValue_IsUnspecifiedNetwork(t *testing.T) {
	var network xnetip.IPv4Network
	require.Equal(t, netip.MustParseAddr("0.0.0.0"), network.Addr())
	require.Equal(t, netip.MustParseAddr("0.0.0.0"), network.Mask())
}

// verifies that two constructions from different hosts of one subnet
// compare equal with ==, which only normalization makes sound.
func Test_IPv4Network_Equality_AfterNormalization(t *testing.T) {
	left, err := xnetip.IPv4NetworkFrom(
		netip.MustParseAddr("192.168.1.1"),
		netip.MustParseAddr("255.255.255.0"),
	)
	require.NoError(t, err)
	right, err := xnetip.IPv4NetworkFrom(
		netip.MustParseAddr("192.168.1.200"),
		netip.MustParseAddr("255.255.255.0"),
	)
	require.NoError(t, err)
	operatorEqual := left == right
	require.True(t, operatorEqual)
}

// verifies that the checked constructor accepts every Is4 pair and
// always produces a normalized result with the mask preserved.
func Test_IPv4NetworkFrom_NormalizationProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		addr := genNetipAddr4.Draw(t, "addr")
		mask := genNetipAddr4.Draw(t, "mask")
		network, err := xnetip.IPv4NetworkFrom(addr, mask)
		require.NoError(t, err)
		addrBytes := addr.As4()
		maskBytes := mask.As4()
		var wantBytes [4]byte
		for idx := range wantBytes {
			wantBytes[idx] = addrBytes[idx] & maskBytes[idx]
		}
		require.Equal(t, netip.AddrFrom4(wantBytes), network.Addr())
		require.Equal(t, mask, network.Mask())
	})
}

// verifies that reconstructing a network from its own accessors
// reproduces it exactly and without error.
func Test_IPv4NetworkFrom_Idempotent(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		network := genIPv4Network.Draw(t, "network")
		rebuilt, err := xnetip.IPv4NetworkFrom(network.Addr(), network.Mask())
		require.NoError(t, err)
		require.Equal(t, network, rebuilt)
	})
}

// verifies that an Is6 value in either argument position always yields
// the family-mismatch sentinel, whatever the other argument is.
func Test_IPv4NetworkFrom_RejectsIs6EitherPosition(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		foreign := genNetipAddr6.Draw(t, "foreign")
		valid := genNetipAddr4.Draw(t, "valid")
		_, err := xnetip.IPv4NetworkFrom(foreign, valid)
		require.ErrorIs(t, err, xnetip.ErrAddrFamilyMismatch)
		_, err = xnetip.IPv4NetworkFrom(valid, foreign)
		require.ErrorIs(t, err, xnetip.ErrAddrFamilyMismatch)
	})
}

// verifies that normalization by a contiguous mask agrees with the
// net/netip oracle for masking a prefix.
func Test_IPv4NetworkFrom_MatchesNetipMasked(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		prefix := genIPv4Prefix.Draw(t, "prefix")
		maskBits := ^uint32(0) << (32 - prefix.Bits())
		network, err := xnetip.IPv4NetworkFrom(prefix.Addr(), netipAddrFrom4Bits(maskBits))
		require.NoError(t, err)
		require.Equal(t, prefix.Masked().Addr(), network.Addr())
	})
}

// verifies that construction and the accessors allocate nothing on the
// success path, per the allocation-free runtime contract.
func Test_IPv4Network_Constructors_AllocationFree(t *testing.T) {
	addr := netip.MustParseAddr("192.168.1.1")
	mask := netip.MustParseAddr("255.255.0.255")
	var err error
	requireNoAllocs(t, func() { networkSink, err = xnetip.IPv4NetworkFrom(addr, mask) })
	require.NoError(t, err)
	network, err := xnetip.IPv4NetworkFrom(addr, mask)
	require.NoError(t, err)
	requireNoAllocs(t, func() { addrSink = network.Addr() })
	requireNoAllocs(t, func() { addrSink = network.Mask() })
}

// verifies that lifting a network into IPv6 space maps the address to
// ::ffff:a.b.c.d and pins the upper 96 mask bits.
//
// The IPv4 mask travels verbatim in the low 32 bits of the result,
// contiguous or not, so the mapped form encodes the same address set.
func Test_IPv4Network_ToIPv6Mapped_MapsAddressAndMask(t *testing.T) {
	cases := []struct {
		name     string
		addr     string
		mask     string
		wantAddr string
		wantMask string
	}{
		{name: "contiguous /24", addr: "192.168.1.0", mask: "255.255.255.0", wantAddr: "::ffff:c0a8:100", wantMask: "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ff00"},
		{name: "address normalized before mapping", addr: "192.168.1.42", mask: "255.255.252.0", wantAddr: "::ffff:c0a8:0", wantMask: "ffff:ffff:ffff:ffff:ffff:ffff:ffff:fc00"},
		{name: "universe maps to the mapped /96", addr: "0.0.0.0", mask: "0.0.0.0", wantAddr: "::ffff:0:0", wantMask: "ffff:ffff:ffff:ffff:ffff:ffff::"},
		{name: "host route maps to a /128", addr: "10.1.2.3", mask: "255.255.255.255", wantAddr: "::ffff:a01:203", wantMask: "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"},
		{name: "mask 255.255.0.255 keeps its hole", addr: "192.168.0.1", mask: "255.255.0.255", wantAddr: "::ffff:c0a8:1", wantMask: "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ff"},
		{name: "alternating mask carries verbatim", addr: "170.85.170.85", mask: "170.85.170.85", wantAddr: "::ffff:aa55:aa55", wantMask: "ffff:ffff:ffff:ffff:ffff:ffff:aa55:aa55"},
		{name: "single-bit mask carries verbatim", addr: "0.0.0.1", mask: "0.0.0.1", wantAddr: "::ffff:0:1", wantMask: "ffff:ffff:ffff:ffff:ffff:ffff:0:1"},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			network, err := xnetip.IPv4NetworkFrom(
				netip.MustParseAddr(testCase.addr),
				netip.MustParseAddr(testCase.mask),
			)
			require.NoError(t, err)
			expected, err := xnetip.IPv6NetworkFrom(
				netip.MustParseAddr(testCase.wantAddr),
				netip.MustParseAddr(testCase.wantMask),
			)
			require.NoError(t, err)
			require.Equal(t, expected, network.ToIPv6Mapped())
		})
	}
}

// verifies that every mapped network pins the upper 96 mask bits and
// puts the address in ::ffff:0:0/96.
//
// The mapped address unmaps back to the original and the low four mask
// bytes carry the IPv4 mask verbatim, which is what makes the mapping
// invertible.
func Test_IPv4Network_ToIPv6Mapped_UpperBitsProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		network := genIPv4Network.Draw(t, "network")
		mapped := network.ToIPv6Mapped()
		require.True(t, mapped.Addr().Is4In6())
		require.Equal(t, network.Addr(), mapped.Addr().Unmap())
		maskBytes := mapped.Mask().As16()
		require.Equal(t, bytes.Repeat([]byte{0xff}, 12), maskBytes[:12])
		require.Equal(t, network.Mask().As4(), [4]byte(maskBytes[12:]))
	})
}

// verifies that the mapping allocates nothing, per the allocation-free
// runtime contract.
func Test_IPv4Network_ToIPv6Mapped_AllocationFree(t *testing.T) {
	network, err := xnetip.IPv4NetworkFrom(
		netip.MustParseAddr("192.168.0.1"),
		netip.MustParseAddr("255.255.0.255"),
	)
	require.NoError(t, err)
	requireNoAllocs(t, func() { network6Sink = network.ToIPv6Mapped() })
}
