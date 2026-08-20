package xnetip_test

import (
	"bytes"
	"encoding/binary"
	"math/bits"
	"net/netip"
	"slices"
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

// verifies that the CIDR constructor clears the host bits of the
// address and produces the contiguous mask of the given length.
func Test_IPv4NetworkFromCIDR_MasksHostBits(t *testing.T) {
	cases := []struct {
		name     string
		addr     string
		bits     int
		wantAddr string
		wantMask string
	}{
		{name: "host bits cleared", addr: "192.168.1.5", bits: 24, wantAddr: "192.168.1.0", wantMask: "255.255.255.0"},
		{name: "host route keeps the address", addr: "192.168.1.5", bits: 32, wantAddr: "192.168.1.5", wantMask: "255.255.255.255"},
		{name: "zero length is the universe", addr: "192.168.1.5", bits: 0, wantAddr: "0.0.0.0", wantMask: "0.0.0.0"},
		{name: "single leading bit", addr: "255.255.255.255", bits: 1, wantAddr: "128.0.0.0", wantMask: "128.0.0.0"},
		{name: "point-to-point pair keeps bit 31", addr: "10.0.0.3", bits: 31, wantAddr: "10.0.0.2", wantMask: "255.255.255.254"},
		{name: "already aligned address stays", addr: "10.0.0.0", bits: 8, wantAddr: "10.0.0.0", wantMask: "255.0.0.0"},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			network, err := xnetip.IPv4NetworkFromCIDR(netip.MustParseAddr(testCase.addr), testCase.bits)
			require.NoError(t, err)
			require.Equal(t, netip.MustParseAddr(testCase.wantAddr), network.Addr())
			require.Equal(t, netip.MustParseAddr(testCase.wantMask), network.Mask())
		})
	}
}

// verifies that the universe network built from a zero length equals
// the type's zero value.
func Test_IPv4NetworkFromCIDR_UniverseEqualsZeroValue(t *testing.T) {
	network, err := xnetip.IPv4NetworkFromCIDR(netip.MustParseAddr("192.168.1.5"), 0)
	require.NoError(t, err)
	require.Equal(t, xnetip.IPv4Network{}, network)
}

// verifies that a prefix length outside 0 through 32 yields the
// overflow sentinel and the zero network.
func Test_IPv4NetworkFromCIDR_RejectsOutOfRangeBits(t *testing.T) {
	cases := []struct {
		name string
		bits int
	}{
		{name: "one past the family width", bits: 33},
		{name: "negative length", bits: -1},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			network, err := xnetip.IPv4NetworkFromCIDR(netip.MustParseAddr("192.168.1.5"), testCase.bits)
			require.ErrorIs(t, err, xnetip.ErrCIDROverflow)
			require.Equal(t, xnetip.IPv4Network{}, network)
		})
	}
}

// verifies that a non-Is4 address, IPv4-mapped included, yields the
// family-mismatch sentinel and the zero network for a valid length.
func Test_IPv4NetworkFromCIDR_RejectsForeignFamily(t *testing.T) {
	cases := []struct {
		name string
		addr netip.Addr
	}{
		{name: "IPv6 address", addr: netip.MustParseAddr("2001:db8::1")},
		{name: "IPv4-mapped IPv6 address", addr: netip.MustParseAddr("::ffff:192.168.1.5")},
		{name: "invalid zero address", addr: netip.Addr{}},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			network, err := xnetip.IPv4NetworkFromCIDR(testCase.addr, 24)
			require.ErrorIs(t, err, xnetip.ErrAddrFamilyMismatch)
			require.Equal(t, xnetip.IPv4Network{}, network)
		})
	}
}

// verifies that the CIDR constructor agrees with the net/netip oracle
// for masking a prefix and always yields a normalized result.
//
// Non-contiguous masks cannot arise from this constructor — the mask
// is a leading run of ones by construction — so the contiguity of
// every drawn result is asserted in place of a non-contiguous case
// table.
func Test_IPv4NetworkFromCIDR_MatchesNetipMasked(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		addr := genNetipAddr4.Draw(t, "addr")
		bits := rapid.IntRange(0, 32).Draw(t, "bits")
		network, err := xnetip.IPv4NetworkFromCIDR(addr, bits)
		require.NoError(t, err)
		require.Equal(t, netip.PrefixFrom(addr, bits).Masked().Addr(), network.Addr())
		require.Equal(t, netipAddrFrom4Bits(^uint32(0)<<(32-bits)), network.Mask())
		maskBytes := network.Mask().As4()
		maskBits := binary.BigEndian.Uint32(maskBytes[:])
		require.Equal(t, ^uint32(0), maskBits|(maskBits-1))
		addrBytes := network.Addr().As4()
		addrBits := binary.BigEndian.Uint32(addrBytes[:])
		require.Equal(t, addrBits, addrBits&maskBits)
	})
}

// verifies that every length outside 0 through 32, far past the width
// or negative, yields the overflow sentinel.
func Test_IPv4NetworkFromCIDR_OverflowProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		addr := genNetipAddr4.Draw(t, "addr")
		bits := rapid.OneOf(rapid.IntRange(33, 300), rapid.IntRange(-300, -1)).Draw(t, "bits")
		network, err := xnetip.IPv4NetworkFromCIDR(addr, bits)
		require.ErrorIs(t, err, xnetip.ErrCIDROverflow)
		require.Equal(t, xnetip.IPv4Network{}, network)
	})
}

// verifies that the CIDR constructor allocates nothing on the success
// path, per the allocation-free runtime contract.
func Test_IPv4NetworkFromCIDR_AllocationFree(t *testing.T) {
	addr := netip.MustParseAddr("192.168.1.5")
	var err error
	requireNoAllocs(t, func() { networkSink, err = xnetip.IPv4NetworkFromCIDR(addr, 24) })
	require.NoError(t, err)
}

// verifies that the host-route constructor pairs the address with the
// all-ones mask without clearing a single address bit.
//
// A non-contiguous mask table is not applicable to this constructor:
// the mask is fixed to all ones, the universe of bits, so the
// alternating-pattern address below pins bit preservation instead.
func Test_IPv4NetworkFromAddr_BuildsHostRoute(t *testing.T) {
	cases := []struct {
		name string
		addr string
	}{
		{name: "loopback host route", addr: "127.0.0.1"},
		{name: "private address host route", addr: "192.168.1.1"},
		{name: "unspecified address", addr: "0.0.0.0"},
		{name: "broadcast address", addr: "255.255.255.255"},
		{name: "alternating bit pattern", addr: "170.85.170.85"},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			network, err := xnetip.IPv4NetworkFromAddr(netip.MustParseAddr(testCase.addr))
			require.NoError(t, err)
			require.Equal(t, netip.MustParseAddr(testCase.addr), network.Addr())
			require.Equal(t, netip.MustParseAddr("255.255.255.255"), network.Mask())
		})
	}
}

// verifies that the host route carries the exact bit pattern of its
// address and the all-ones mask pattern.
func Test_IPv4NetworkFromAddr_PreservesBitPattern(t *testing.T) {
	network, err := xnetip.IPv4NetworkFromAddr(netipAddrFrom4Bits(0x0A000001))
	require.NoError(t, err)
	require.Equal(t, netipAddrFrom4Bits(0x0A000001), network.Addr())
	require.Equal(t, netipAddrFrom4Bits(0xFFFFFFFF), network.Mask())
}

// verifies that the host route equals the same network built through
// the checked normalizing constructor.
func Test_IPv4NetworkFromAddr_EqualsCheckedConstructor(t *testing.T) {
	fromAddr, err := xnetip.IPv4NetworkFromAddr(netip.MustParseAddr("10.0.0.1"))
	require.NoError(t, err)
	fromPair, err := xnetip.IPv4NetworkFrom(
		netip.MustParseAddr("10.0.0.1"),
		netip.MustParseAddr("255.255.255.255"),
	)
	require.NoError(t, err)
	require.Equal(t, fromPair, fromAddr)
}

// verifies that a non-Is4 address, IPv4-mapped included, yields the
// family-mismatch sentinel and the zero network.
func Test_IPv4NetworkFromAddr_RejectsForeignFamily(t *testing.T) {
	cases := []struct {
		name string
		addr netip.Addr
	}{
		{name: "IPv6 address", addr: netip.MustParseAddr("2001:db8::1")},
		{name: "IPv4-mapped IPv6 address", addr: netip.MustParseAddr("::ffff:10.0.0.1")},
		{name: "invalid zero address", addr: netip.Addr{}},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			network, err := xnetip.IPv4NetworkFromAddr(testCase.addr)
			require.ErrorIs(t, err, xnetip.ErrAddrFamilyMismatch)
			require.Equal(t, xnetip.IPv4Network{}, network)
		})
	}
}

// verifies that every Is4 address lifts into its host route with the
// address preserved and the mask all ones.
//
// The result must also equal the same network built through the
// checked normalizing constructor, so the two entry points agree.
func Test_IPv4NetworkFromAddr_HostRouteProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		addr := genNetipAddr4.Draw(t, "addr")
		network, err := xnetip.IPv4NetworkFromAddr(addr)
		require.NoError(t, err)
		require.Equal(t, addr, network.Addr())
		require.Equal(t, netipAddrFrom4Bits(^uint32(0)), network.Mask())
		fromPair, err := xnetip.IPv4NetworkFrom(addr, netipAddrFrom4Bits(^uint32(0)))
		require.NoError(t, err)
		require.Equal(t, fromPair, network)
	})
}

// verifies that every Is6 address, whatever its shape, is rejected
// with the family-mismatch sentinel.
func Test_IPv4NetworkFromAddr_RejectsIs6Property(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		addr := genNetipAddr6.Draw(t, "addr")
		network, err := xnetip.IPv4NetworkFromAddr(addr)
		require.ErrorIs(t, err, xnetip.ErrAddrFamilyMismatch)
		require.Equal(t, xnetip.IPv4Network{}, network)
	})
}

// verifies that the host route agrees with the net/netip oracle for a
// full-length masked prefix.
func Test_IPv4NetworkFromAddr_MatchesNetipHostPrefix(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		addr := genNetipAddr4.Draw(t, "addr")
		network, err := xnetip.IPv4NetworkFromAddr(addr)
		require.NoError(t, err)
		require.Equal(t, netip.PrefixFrom(addr, 32).Masked().Addr(), network.Addr())
	})
}

// verifies that the host-route constructor allocates nothing on the
// success path, per the allocation-free runtime contract.
func Test_IPv4NetworkFromAddr_AllocationFree(t *testing.T) {
	addr := netip.MustParseAddr("192.168.1.5")
	var err error
	requireNoAllocs(t, func() { networkSink, err = xnetip.IPv4NetworkFromAddr(addr) })
	require.NoError(t, err)
}

// verifies that the order is lexicographic on the address first and
// the mask second, both as unsigned 32-bit integers.
func Test_IPv4Network_Compare_AddressFirstMaskSecond(t *testing.T) {
	cases := []struct {
		name  string
		left  xnetip.IPv4Network
		right xnetip.IPv4Network
		want  int
	}{
		{name: "address dominates mask", left: mustIPv4Network(t, "10.0.0.0", "255.255.255.255"), right: mustIPv4Network(t, "11.0.0.0", "255.0.0.0"), want: -1},
		{name: "equal address, mask decides", left: mustIPv4Network(t, "10.0.0.0", "255.255.0.0"), right: mustIPv4Network(t, "10.0.0.0", "255.255.255.0"), want: -1},
		{name: "equal address, larger mask after", left: mustIPv4Network(t, "10.0.0.0", "255.255.255.0"), right: mustIPv4Network(t, "10.0.0.0", "255.255.0.0"), want: 1},
		{name: "zero before middle", left: mustIPv4Network(t, "0.0.0.0", "0.0.0.0"), right: mustIPv4Network(t, "10.0.0.0", "255.0.0.0"), want: -1},
		{name: "middle before max", left: mustIPv4Network(t, "10.0.0.0", "255.0.0.0"), right: mustIPv4Network(t, "255.255.255.255", "255.255.255.255"), want: -1},
		{name: "zero before max", left: mustIPv4Network(t, "0.0.0.0", "0.0.0.0"), right: mustIPv4Network(t, "255.255.255.255", "255.255.255.255"), want: -1},
		{name: "antisymmetry on the dominance pair", left: mustIPv4Network(t, "11.0.0.0", "255.0.0.0"), right: mustIPv4Network(t, "10.0.0.0", "255.255.255.255"), want: 1},
		{name: "top address bit compares unsigned", left: mustIPv4Network(t, "128.0.0.0", "128.0.0.0"), right: mustIPv4Network(t, "127.255.255.255", "255.255.255.255"), want: 1},
		{name: "same address, non-contiguous mask decides", left: mustIPv4Network(t, "10.0.0.5", "255.0.0.255"), right: mustIPv4Network(t, "10.0.0.5", "255.255.0.255"), want: -1},
		{name: "alternating masks under one address", left: mustIPv4Network(t, "0.0.0.0", "170.85.170.85"), right: mustIPv4Network(t, "0.0.0.0", "85.170.85.170"), want: 1},
		{name: "address bit beats any mask", left: mustIPv4Network(t, "10.0.0.4", "255.0.0.255"), right: mustIPv4Network(t, "10.0.0.5", "255.255.255.255"), want: -1},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			require.Equal(t, testCase.want, testCase.left.Compare(testCase.right))
		})
	}
}

// verifies that equal networks compare as zero and only they do.
func Test_IPv4Network_Compare_EqualityIsZero(t *testing.T) {
	left := mustIPv4Network(t, "192.168.1.0", "255.255.255.0")
	right := mustIPv4Network(t, "192.168.1.0", "255.255.255.0")
	require.Equal(t, 0, left.Compare(right))
	require.Equal(t, left, right)
}

// verifies that sorting a shuffled fixture yields the exact documented
// order, the contract the aggregation and split inputs rely on.
func Test_IPv4Network_Compare_SortPinsDocumentedOrder(t *testing.T) {
	shuffled := []xnetip.IPv4Network{
		mustIPv4Network(t, "192.168.1.1", "255.255.255.255"),
		mustIPv4Network(t, "10.1.0.0", "255.255.0.0"),
		mustIPv4Network(t, "255.255.255.255", "255.255.255.255"),
		mustIPv4Network(t, "10.0.0.5", "255.255.0.255"),
		mustIPv4Network(t, "0.0.0.0", "0.0.0.0"),
		mustIPv4Network(t, "10.0.0.0", "255.255.255.0"),
		mustIPv4Network(t, "10.0.0.5", "255.0.0.255"),
		mustIPv4Network(t, "10.0.0.0", "255.0.0.0"),
	}
	want := []xnetip.IPv4Network{
		mustIPv4Network(t, "0.0.0.0", "0.0.0.0"),
		mustIPv4Network(t, "10.0.0.0", "255.0.0.0"),
		mustIPv4Network(t, "10.0.0.0", "255.255.255.0"),
		mustIPv4Network(t, "10.0.0.5", "255.0.0.255"),
		mustIPv4Network(t, "10.0.0.5", "255.255.0.255"),
		mustIPv4Network(t, "10.1.0.0", "255.255.0.0"),
		mustIPv4Network(t, "192.168.1.1", "255.255.255.255"),
		mustIPv4Network(t, "255.255.255.255", "255.255.255.255"),
	}
	slices.SortFunc(shuffled, xnetip.IPv4Network.Compare)
	require.Equal(t, want, shuffled)
}

// verifies that the order equals the tuple order of the netip address
// views, is antisymmetric and is zero exactly on equal values.
func Test_IPv4Network_Compare_MatchesTupleOrderProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		left := genIPv4Network.Draw(t, "left")
		right := genIPv4Network.Draw(t, "right")
		want := left.Addr().Compare(right.Addr())
		if want == 0 {
			want = left.Mask().Compare(right.Mask())
		}
		require.Equal(t, want, left.Compare(right))
		require.Equal(t, -want, right.Compare(left))
		require.Equal(t, left == right, left.Compare(right) == 0)
	})
}

// verifies that the order is transitive on random triples.
func Test_IPv4Network_Compare_TransitivityProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		first := genIPv4Network.Draw(t, "first")
		second := genIPv4Network.Draw(t, "second")
		third := genIPv4Network.Draw(t, "third")
		if first.Compare(second) <= 0 && second.Compare(third) <= 0 {
			require.LessOrEqual(t, first.Compare(third), 0)
		}
	})
}

// verifies that sorting a random slice by the order yields a sorted
// permutation of the input.
func Test_IPv4Network_Compare_SortFuncProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		networks := rapid.SliceOfN(genIPv4Network, 0, 32).Draw(t, "networks")
		sorted := slices.Clone(networks)
		slices.SortFunc(sorted, xnetip.IPv4Network.Compare)
		require.True(t, slices.IsSortedFunc(sorted, xnetip.IPv4Network.Compare))
		require.ElementsMatch(t, networks, sorted)
	})
}

// verifies that the address-first component agrees with the
// netip.Addr order whenever the addresses differ.
func Test_IPv4Network_Compare_MatchesNetipAddrOrder(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		left := genIPv4Network.Draw(t, "left")
		right := genIPv4Network.Draw(t, "right")
		if left.Addr() != right.Addr() {
			require.Equal(t, left.Addr().Compare(right.Addr()), left.Compare(right))
		}
	})
}

// verifies that comparing allocates nothing.
func Test_IPv4Network_Compare_AllocationFree(t *testing.T) {
	left := mustIPv4Network(t, "10.0.0.0", "255.0.0.0")
	right := mustIPv4Network(t, "10.0.0.0", "255.255.255.0")
	requireNoAllocs(t, func() { intSink = left.Compare(right) })
}

func BenchmarkIPv4Network_Compare_MaskDecides(b *testing.B) {
	left := mustIPv4Network(b, "10.0.0.0", "255.0.0.0")
	right := mustIPv4Network(b, "10.0.0.0", "255.255.255.0")
	b.ReportAllocs()
	for b.Loop() {
		intSink = left.Compare(right)
	}
}

func BenchmarkIPv4Network_Compare_AddressDecides(b *testing.B) {
	left := mustIPv4Network(b, "10.0.0.0", "255.0.0.0")
	right := mustIPv4Network(b, "11.0.0.0", "255.255.255.0")
	b.ReportAllocs()
	for b.Loop() {
		intSink = left.Compare(right)
	}
}

func BenchmarkIPv4Network_SortFunc_1024(b *testing.B) {
	// The fixture mirrors the Rust bench recipe: index times Knuth's
	// multiplicative constant, prefixes spread over /8../32.
	template := make([]xnetip.IPv4Network, 1024)
	for idx := range template {
		bits := uint32(idx) * 2_654_435_761
		network, err := xnetip.IPv4NetworkFromCIDR(netipAddrFrom4Bits(bits), 8+int(bits%25))
		if err != nil {
			b.Fatal(err)
		}
		template[idx] = network
	}
	networks := make([]xnetip.IPv4Network, len(template))
	b.ReportAllocs()
	for b.Loop() {
		// The 4 KiB fixture refresh stays inside the timed region: a
		// paused timer would keep the loop from ever finishing.
		copy(networks, template)
		slices.SortFunc(networks, xnetip.IPv4Network.Compare)
	}
}

// verifies that exactly the masks made of leading ones followed by
// zeros are contiguous, the all-zero and all-ones masks included.
func Test_IPv4Network_IsContiguous_LeadingOnesRunOnly(t *testing.T) {
	cases := []struct {
		name    string
		network xnetip.IPv4Network
		want    bool
	}{
		{name: "universe /0", network: mustIPv4Network(t, "0.0.0.0", "0.0.0.0"), want: true},
		{name: "/19", network: mustIPv4Network(t, "213.180.192.0", "255.255.224.0"), want: true},
		{name: "/24", network: mustIPv4Network(t, "192.168.0.0", "255.255.255.0"), want: true},
		{name: "single leading bit /1", network: mustIPv4Network(t, "128.0.0.0", "128.0.0.0"), want: true},
		{name: "/31", network: mustIPv4Network(t, "10.0.0.2", "255.255.255.254"), want: true},
		{name: "host route /32", network: mustIPv4Network(t, "10.0.0.1", "255.255.255.255"), want: true},
		{name: "zero value is the universe", network: xnetip.IPv4Network{}, want: true},
		{name: "top bit clear, rest set", network: mustIPv4Network(t, "0.0.0.0", "127.255.255.255"), want: false},
		{name: "trailing-only bits", network: mustIPv4Network(t, "0.0.0.1", "0.0.0.255"), want: false},
		{name: "hole in the third octet", network: mustIPv4Network(t, "213.180.0.192", "255.255.0.255"), want: false},
		{name: "two runs", network: mustIPv4Network(t, "192.168.0.1", "255.0.255.0"), want: false},
		{name: "leading zero octet", network: mustIPv4Network(t, "0.0.0.0", "0.255.255.255"), want: false},
		{name: "alternating", network: mustIPv4Network(t, "170.85.170.85", "170.85.170.85"), want: false},
		{name: "single isolated bit in the middle", network: mustIPv4Network(t, "0.0.0.0", "0.0.1.0"), want: false},
		{name: "bench non-contiguous shape", network: mustIPv4Network(t, "192.168.0.1", "255.255.0.255"), want: false},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			require.Equal(t, testCase.want, testCase.network.IsContiguous())
		})
	}
}

// verifies that the predicate agrees with the brute-force bit scan:
// contiguous means no one bit after a zero bit, top to bottom.
func Test_IPv4Network_IsContiguous_MatchesBitScanProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		network := genIPv4Network.Draw(t, "network")
		maskBytes := network.Mask().As4()
		maskBits := binary.BigEndian.Uint32(maskBytes[:])
		want := true
		seenZero := false
		for idx := range 32 {
			bit := maskBits>>(31-idx)&1 == 1
			if bit && seenZero {
				want = false
			}
			if !bit {
				seenZero = true
			}
		}
		require.Equal(t, want, network.IsContiguous())
	})
}

// verifies that every network built from a prefix length is
// contiguous and round-trips its length through the netip oracle.
func Test_IPv4Network_IsContiguous_PrefixMasksAreContiguousProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		addr := genNetipAddr4.Draw(t, "addr")
		bits := rapid.IntRange(0, 32).Draw(t, "bits")
		network, err := xnetip.IPv4NetworkFromCIDR(addr, bits)
		require.NoError(t, err)
		require.True(t, network.IsContiguous())
		require.Equal(t, bits, netip.PrefixFrom(network.Addr(), bits).Bits())
	})
}

// verifies that clearing a non-final bit of a leading run of two or
// more ones breaks contiguity: some run bit stays below the hole.
func Test_IPv4Network_IsContiguous_HolePunchedMaskProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		prefix := rapid.IntRange(2, 32).Draw(t, "prefix")
		hole := rapid.IntRange(0, prefix-2).Draw(t, "hole")
		maskBits := ^uint32(0) << (32 - prefix) &^ (uint32(1) << (31 - hole))
		network, err := xnetip.IPv4NetworkFrom(
			genNetipAddr4.Draw(t, "addr"),
			netipAddrFrom4Bits(maskBits),
		)
		require.NoError(t, err)
		require.False(t, network.IsContiguous())
	})
}

// verifies that the predicate allocates nothing.
func Test_IPv4Network_IsContiguous_AllocationFree(t *testing.T) {
	network := mustIPv4Network(t, "192.168.0.0", "255.255.0.0")
	requireNoAllocs(t, func() { okSink = network.IsContiguous() })
}

func BenchmarkIPv4Network_IsContiguous_Contiguous(b *testing.B) {
	network := mustIPv4Network(b, "192.168.0.0", "255.255.0.0")
	b.ReportAllocs()
	for b.Loop() {
		okSink = network.IsContiguous()
	}
}

func BenchmarkIPv4Network_IsContiguous_NonContiguous(b *testing.B) {
	network := mustIPv4Network(b, "192.168.0.1", "255.255.0.255")
	b.ReportAllocs()
	for b.Loop() {
		okSink = network.IsContiguous()
	}
}

// verifies that a contiguous mask reports its leading-ones run length,
// from the universe through the host route.
func Test_IPv4Network_PrefixLen_LeadingOnesRunLength(t *testing.T) {
	cases := []struct {
		name    string
		network xnetip.IPv4Network
		want    int
	}{
		{name: "/24", network: mustIPv4Network(t, "192.168.1.0", "255.255.255.0"), want: 24},
		{name: "host route /32", network: mustIPv4Network(t, "192.168.1.1", "255.255.255.255"), want: 32},
		{name: "universe /0", network: mustIPv4Network(t, "0.0.0.0", "0.0.0.0"), want: 0},
		{name: "single leading bit /1", network: mustIPv4Network(t, "128.0.0.0", "128.0.0.0"), want: 1},
		{name: "/31", network: mustIPv4Network(t, "10.0.0.2", "255.255.255.254"), want: 31},
		{name: "zero value is the universe", network: xnetip.IPv4Network{}, want: 0},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			prefix, ok := testCase.network.PrefixLen()
			require.True(t, ok)
			require.Equal(t, testCase.want, prefix)
		})
	}
}

// verifies that a non-contiguous mask has no prefix length and reports
// zero, whether the leading run is broken, empty or trailing-only.
func Test_IPv4Network_PrefixLen_NonContiguousHasNone(t *testing.T) {
	cases := []struct {
		name    string
		network xnetip.IPv4Network
	}{
		{name: "hole in the middle", network: mustIPv4Network(t, "10.0.0.1", "255.0.0.255")},
		{name: "no leading run", network: mustIPv4Network(t, "0.0.0.1", "0.0.0.255")},
		{name: "leading zero then ones", network: mustIPv4Network(t, "0.0.0.0", "127.255.255.255")},
		{name: "mask 255.0.255.0 ignores the second octet", network: mustIPv4Network(t, "192.0.1.0", "255.0.255.0")},
		{name: "alternating", network: mustIPv4Network(t, "170.85.170.85", "170.85.170.85")},
		{name: "two runs", network: mustIPv4Network(t, "10.0.0.0", "255.255.0.255")},
		{name: "trailing ones only", network: mustIPv4Network(t, "0.0.0.1", "0.0.0.1")},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			prefix, ok := testCase.network.PrefixLen()
			require.False(t, ok)
			require.Zero(t, prefix)
		})
	}
}

// verifies that a prefix length exists exactly for contiguous masks
// and that the length rebuilds the mask through the netip oracle.
func Test_IPv4Network_PrefixLen_SomeIffContiguousProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		network := genIPv4Network.Draw(t, "network")
		prefix, ok := network.PrefixLen()
		require.Equal(t, network.IsContiguous(), ok)
		if !ok {
			require.Zero(t, prefix)
			return
		}
		maskOracle, err := netip.MustParseAddr("255.255.255.255").Prefix(prefix)
		require.NoError(t, err)
		require.Equal(t, maskOracle.Addr(), network.Mask())
	})
}

// verifies that a network built from any address and prefix length
// reports that same length back.
func Test_IPv4Network_PrefixLen_RoundTripsCIDRProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		addr := genNetipAddr4.Draw(t, "addr")
		cidr := rapid.IntRange(0, 32).Draw(t, "cidr")
		network, err := xnetip.IPv4NetworkFromCIDR(addr, cidr)
		require.NoError(t, err)
		prefix, ok := network.PrefixLen()
		require.True(t, ok)
		require.Equal(t, cidr, prefix)
	})
}

// verifies that for a contiguous mask the reported length is the one
// net/netip accepts and reports back for the same address.
func Test_IPv4Network_PrefixLen_MatchesNetipBitsProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		network := genIPv4Network.Draw(t, "network")
		if !network.IsContiguous() {
			return
		}
		maskBytes := network.Mask().As4()
		leading := bits.LeadingZeros32(^binary.BigEndian.Uint32(maskBytes[:]))
		prefix, ok := network.PrefixLen()
		require.True(t, ok)
		require.Equal(t, netip.PrefixFrom(network.Addr(), leading).Bits(), prefix)
	})
}

// verifies that computing the prefix allocates nothing on either
// outcome.
func Test_IPv4Network_PrefixLen_AllocationFree(t *testing.T) {
	contiguous := mustIPv4Network(t, "192.168.0.0", "255.255.0.0")
	nonContiguous := mustIPv4Network(t, "192.168.0.1", "255.255.0.255")
	requireNoAllocs(t, func() { intSink, okSink = contiguous.PrefixLen() })
	requireNoAllocs(t, func() { intSink, okSink = nonContiguous.PrefixLen() })
}

func BenchmarkIPv4Network_PrefixLen_Contiguous(b *testing.B) {
	network := mustIPv4Network(b, "192.168.0.0", "255.255.0.0")
	b.ReportAllocs()
	for b.Loop() {
		intSink, okSink = network.PrefixLen()
	}
}

func BenchmarkIPv4Network_PrefixLen_NonContiguous(b *testing.B) {
	network := mustIPv4Network(b, "192.168.0.1", "255.255.0.255")
	b.ReportAllocs()
	for b.Loop() {
		intSink, okSink = network.PrefixLen()
	}
}

func BenchmarkIPv4Network_PrefixLen_Mixed(b *testing.B) {
	// A 50/50 contiguous/non-contiguous rotation exercises both
	// outcomes of the contiguity check within one measurement.
	networks := []xnetip.IPv4Network{
		mustIPv4Network(b, "192.168.0.0", "255.255.0.0"),
		mustIPv4Network(b, "192.168.0.1", "255.255.0.255"),
		mustIPv4Network(b, "10.0.0.0", "255.0.0.0"),
		mustIPv4Network(b, "10.0.0.1", "255.0.0.255"),
	}
	b.ReportAllocs()
	for b.Loop() {
		for _, network := range networks {
			intSink, okSink = network.PrefixLen()
		}
	}
}
