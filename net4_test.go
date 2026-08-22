package xnetip_test

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"math/bits"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/yanet-platform/xnetip"
	"pgregory.net/rapid"
)

// verifies that the constructor clears every address bit outside the
// mask and keeps the mask unchanged, whatever the mask's shape.
func Test_Network4From_NormalizesAddressByMask(t *testing.T) {
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
			network, err := xnetip.Network4From(
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
func Test_Network4From_RejectsForeignFamily(t *testing.T) {
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
			network, err := xnetip.Network4From(testCase.addr, testCase.mask)
			require.ErrorIs(t, err, xnetip.ErrAddrFamilyMismatch)
			require.Equal(t, xnetip.Network4{}, network)
		})
	}
}

// verifies that the accessors return Is4, zone-free netip values.
func Test_Network4_Accessors_ReturnIs4Views(t *testing.T) {
	network, err := xnetip.Network4From(
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
func Test_Network4From_UniverseEqualsZeroValue(t *testing.T) {
	network, err := xnetip.Network4From(
		netip.MustParseAddr("10.1.2.3"),
		netip.MustParseAddr("0.0.0.0"),
	)
	require.NoError(t, err)
	require.Equal(t, xnetip.Network4{}, network)
}

// verifies that the zero value is the unspecified network 0.0.0.0/0.
func Test_Network4_ZeroValue_IsUnspecifiedNetwork(t *testing.T) {
	var network xnetip.Network4
	require.Equal(t, netip.MustParseAddr("0.0.0.0"), network.Addr())
	require.Equal(t, netip.MustParseAddr("0.0.0.0"), network.Mask())
}

// verifies that two constructions from different hosts of one subnet
// compare equal with ==, which only normalization makes sound.
func Test_Network4_Equality_AfterNormalization(t *testing.T) {
	left, err := xnetip.Network4From(
		netip.MustParseAddr("192.168.1.1"),
		netip.MustParseAddr("255.255.255.0"),
	)
	require.NoError(t, err)
	right, err := xnetip.Network4From(
		netip.MustParseAddr("192.168.1.200"),
		netip.MustParseAddr("255.255.255.0"),
	)
	require.NoError(t, err)
	operatorEqual := left == right
	require.True(t, operatorEqual)
}

// verifies that the checked constructor accepts every Is4 pair and
// always produces a normalized result with the mask preserved.
func Test_Network4From_NormalizationProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		addr := genNetipAddr4.Draw(t, "addr")
		mask := genNetipAddr4.Draw(t, "mask")
		network, err := xnetip.Network4From(addr, mask)
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
func Test_Network4From_Idempotent(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		network := genNetwork4.Draw(t, "network")
		rebuilt, err := xnetip.Network4From(network.Addr(), network.Mask())
		require.NoError(t, err)
		require.Equal(t, network, rebuilt)
	})
}

// verifies that an Is6 value in either argument position always yields
// the family-mismatch sentinel, whatever the other argument is.
func Test_Network4From_RejectsIs6EitherPosition(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		foreign := genNetipAddr6.Draw(t, "foreign")
		valid := genNetipAddr4.Draw(t, "valid")
		_, err := xnetip.Network4From(foreign, valid)
		require.ErrorIs(t, err, xnetip.ErrAddrFamilyMismatch)
		_, err = xnetip.Network4From(valid, foreign)
		require.ErrorIs(t, err, xnetip.ErrAddrFamilyMismatch)
	})
}

// verifies that normalization by a contiguous mask agrees with the
// net/netip oracle for masking a prefix.
func Test_Network4From_MatchesNetipMasked(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		prefix := genIPv4Prefix.Draw(t, "prefix")
		maskBits := ^uint32(0) << (32 - prefix.Bits())
		network, err := xnetip.Network4From(prefix.Addr(), netipAddrFrom4Bits(maskBits))
		require.NoError(t, err)
		require.Equal(t, prefix.Masked().Addr(), network.Addr())
	})
}

// verifies that construction and the accessors allocate nothing on the
// success path, per the allocation-free runtime contract.
func Test_Network4_Constructors_AllocationFree(t *testing.T) {
	addr := netip.MustParseAddr("192.168.1.1")
	mask := netip.MustParseAddr("255.255.0.255")
	var err error
	requireNoAllocs(t, func() { networkSink, err = xnetip.Network4From(addr, mask) })
	require.NoError(t, err)
	network, err := xnetip.Network4From(addr, mask)
	require.NoError(t, err)
	requireNoAllocs(t, func() { addrSink = network.Addr() })
	requireNoAllocs(t, func() { addrSink = network.Mask() })
}

// verifies that lifting a network into IPv6 space maps the address to
// ::ffff:a.b.c.d and pins the upper 96 mask bits.
//
// The IPv4 mask travels verbatim in the low 32 bits of the result,
// contiguous or not, so the mapped form encodes the same address set.
func Test_Network4_ToIPv6Mapped_MapsAddressAndMask(t *testing.T) {
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
			network, err := xnetip.Network4From(
				netip.MustParseAddr(testCase.addr),
				netip.MustParseAddr(testCase.mask),
			)
			require.NoError(t, err)
			expected, err := xnetip.Network6From(
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
func Test_Network4_ToIPv6Mapped_UpperBitsProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		network := genNetwork4.Draw(t, "network")
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
func Test_Network4_ToIPv6Mapped_AllocationFree(t *testing.T) {
	network, err := xnetip.Network4From(
		netip.MustParseAddr("192.168.0.1"),
		netip.MustParseAddr("255.255.0.255"),
	)
	require.NoError(t, err)
	requireNoAllocs(t, func() { network6Sink = network.ToIPv6Mapped() })
}

// verifies that the CIDR constructor clears the host bits of the
// address and produces the contiguous mask of the given length.
func Test_Network4FromCIDR_MasksHostBits(t *testing.T) {
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
			network, err := xnetip.Network4FromCIDR(netip.MustParseAddr(testCase.addr), testCase.bits)
			require.NoError(t, err)
			require.Equal(t, netip.MustParseAddr(testCase.wantAddr), network.Addr())
			require.Equal(t, netip.MustParseAddr(testCase.wantMask), network.Mask())
		})
	}
}

// verifies that the universe network built from a zero length equals
// the type's zero value.
func Test_Network4FromCIDR_UniverseEqualsZeroValue(t *testing.T) {
	network, err := xnetip.Network4FromCIDR(netip.MustParseAddr("192.168.1.5"), 0)
	require.NoError(t, err)
	require.Equal(t, xnetip.Network4{}, network)
}

// verifies that a prefix length outside 0 through 32 yields the
// overflow sentinel and the zero network.
func Test_Network4FromCIDR_RejectsOutOfRangeBits(t *testing.T) {
	cases := []struct {
		name      string
		bits      int
		wantError string
	}{
		{
			name:      "one past the family width",
			bits:      33,
			wantError: `xnetip.Network4FromCIDR("192.168.1.5/33"): prefix length out of range`,
		},
		{
			name:      "negative length",
			bits:      -1,
			wantError: `xnetip.Network4FromCIDR("192.168.1.5/-1"): prefix length out of range`,
		},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			network, err := xnetip.Network4FromCIDR(netip.MustParseAddr("192.168.1.5"), testCase.bits)
			require.ErrorIs(t, err, xnetip.ErrCIDROverflow)
			require.Equal(t, testCase.wantError, err.Error())
			require.Equal(t, xnetip.Network4{}, network)
		})
	}
}

// verifies that a non-Is4 address, IPv4-mapped included, yields the
// family-mismatch sentinel and the zero network for a valid length.
func Test_Network4FromCIDR_RejectsForeignFamily(t *testing.T) {
	cases := []struct {
		name      string
		addr      netip.Addr
		wantError string
	}{
		{
			name:      "IPv6 address",
			addr:      netip.MustParseAddr("2001:db8::1"),
			wantError: `xnetip.Network4FromCIDR("2001:db8::1/24"): address family mismatch`,
		},
		{
			name:      "IPv4-mapped IPv6 address",
			addr:      netip.MustParseAddr("::ffff:192.168.1.5"),
			wantError: `xnetip.Network4FromCIDR("::ffff:192.168.1.5/24"): address family mismatch`,
		},
		{
			name:      "invalid zero address",
			addr:      netip.Addr{},
			wantError: `xnetip.Network4FromCIDR("invalid IP/24"): address family mismatch`,
		},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			network, err := xnetip.Network4FromCIDR(testCase.addr, 24)
			require.ErrorIs(t, err, xnetip.ErrAddrFamilyMismatch)
			require.Equal(t, testCase.wantError, err.Error())
			require.Equal(t, xnetip.Network4{}, network)
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
func Test_Network4FromCIDR_MatchesNetipMasked(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		addr := genNetipAddr4.Draw(t, "addr")
		bits := rapid.IntRange(0, 32).Draw(t, "bits")
		network, err := xnetip.Network4FromCIDR(addr, bits)
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
func Test_Network4FromCIDR_OverflowProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		addr := genNetipAddr4.Draw(t, "addr")
		bits := rapid.OneOf(rapid.IntRange(33, 300), rapid.IntRange(-300, -1)).Draw(t, "bits")
		network, err := xnetip.Network4FromCIDR(addr, bits)
		require.ErrorIs(t, err, xnetip.ErrCIDROverflow)
		require.Equal(t, xnetip.Network4{}, network)
	})
}

// verifies that the CIDR constructor allocates nothing on the success
// path, per the allocation-free runtime contract.
func Test_Network4FromCIDR_AllocationFree(t *testing.T) {
	addr := netip.MustParseAddr("192.168.1.5")
	var err error
	requireNoAllocs(t, func() { networkSink, err = xnetip.Network4FromCIDR(addr, 24) })
	require.NoError(t, err)
}

// verifies that the host-route constructor pairs the address with the
// all-ones mask without clearing a single address bit.
//
// A non-contiguous mask table is not applicable to this constructor:
// the mask is fixed to all ones, the universe of bits, so the
// alternating-pattern address below pins bit preservation instead.
func Test_Network4FromAddr_BuildsHostRoute(t *testing.T) {
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
			network, err := xnetip.Network4FromAddr(netip.MustParseAddr(testCase.addr))
			require.NoError(t, err)
			require.Equal(t, netip.MustParseAddr(testCase.addr), network.Addr())
			require.Equal(t, netip.MustParseAddr("255.255.255.255"), network.Mask())
		})
	}
}

// verifies that the host route carries the exact bit pattern of its
// address and the all-ones mask pattern.
func Test_Network4FromAddr_PreservesBitPattern(t *testing.T) {
	network, err := xnetip.Network4FromAddr(netipAddrFrom4Bits(0x0A000001))
	require.NoError(t, err)
	require.Equal(t, netipAddrFrom4Bits(0x0A000001), network.Addr())
	require.Equal(t, netipAddrFrom4Bits(0xFFFFFFFF), network.Mask())
}

// verifies that the host route equals the same network built through
// the checked normalizing constructor.
func Test_Network4FromAddr_EqualsCheckedConstructor(t *testing.T) {
	fromAddr, err := xnetip.Network4FromAddr(netip.MustParseAddr("10.0.0.1"))
	require.NoError(t, err)
	fromPair, err := xnetip.Network4From(
		netip.MustParseAddr("10.0.0.1"),
		netip.MustParseAddr("255.255.255.255"),
	)
	require.NoError(t, err)
	require.Equal(t, fromPair, fromAddr)
}

// verifies that a non-Is4 address, IPv4-mapped included, yields the
// family-mismatch sentinel and the zero network.
func Test_Network4FromAddr_RejectsForeignFamily(t *testing.T) {
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
			network, err := xnetip.Network4FromAddr(testCase.addr)
			require.ErrorIs(t, err, xnetip.ErrAddrFamilyMismatch)
			require.Equal(t, xnetip.Network4{}, network)
		})
	}
}

// verifies that every Is4 address lifts into its host route with the
// address preserved and the mask all ones.
//
// The result must also equal the same network built through the
// checked normalizing constructor, so the two entry points agree.
func Test_Network4FromAddr_HostRouteProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		addr := genNetipAddr4.Draw(t, "addr")
		network, err := xnetip.Network4FromAddr(addr)
		require.NoError(t, err)
		require.Equal(t, addr, network.Addr())
		require.Equal(t, netipAddrFrom4Bits(^uint32(0)), network.Mask())
		fromPair, err := xnetip.Network4From(addr, netipAddrFrom4Bits(^uint32(0)))
		require.NoError(t, err)
		require.Equal(t, fromPair, network)
	})
}

// verifies that every Is6 address, whatever its shape, is rejected
// with the family-mismatch sentinel.
func Test_Network4FromAddr_RejectsIs6Property(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		addr := genNetipAddr6.Draw(t, "addr")
		network, err := xnetip.Network4FromAddr(addr)
		require.ErrorIs(t, err, xnetip.ErrAddrFamilyMismatch)
		require.Equal(t, xnetip.Network4{}, network)
	})
}

// verifies that the host route agrees with the net/netip oracle for a
// full-length masked prefix.
func Test_Network4FromAddr_MatchesNetipHostPrefix(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		addr := genNetipAddr4.Draw(t, "addr")
		network, err := xnetip.Network4FromAddr(addr)
		require.NoError(t, err)
		require.Equal(t, netip.PrefixFrom(addr, 32).Masked().Addr(), network.Addr())
	})
}

// verifies that the host-route constructor allocates nothing on the
// success path, per the allocation-free runtime contract.
func Test_Network4FromAddr_AllocationFree(t *testing.T) {
	addr := netip.MustParseAddr("192.168.1.5")
	var err error
	requireNoAllocs(t, func() { networkSink, err = xnetip.Network4FromAddr(addr) })
	require.NoError(t, err)
}

// verifies that the order is lexicographic on the address first and
// the mask second, both as unsigned 32-bit integers.
func Test_Network4_Compare_AddressFirstMaskSecond(t *testing.T) {
	cases := []struct {
		name  string
		left  xnetip.Network4
		right xnetip.Network4
		want  int
	}{
		{name: "address dominates mask", left: mustNetwork4(t, "10.0.0.0", "255.255.255.255"), right: mustNetwork4(t, "11.0.0.0", "255.0.0.0"), want: -1},
		{name: "equal address, mask decides", left: mustNetwork4(t, "10.0.0.0", "255.255.0.0"), right: mustNetwork4(t, "10.0.0.0", "255.255.255.0"), want: -1},
		{name: "equal address, larger mask after", left: mustNetwork4(t, "10.0.0.0", "255.255.255.0"), right: mustNetwork4(t, "10.0.0.0", "255.255.0.0"), want: 1},
		{name: "zero before middle", left: mustNetwork4(t, "0.0.0.0", "0.0.0.0"), right: mustNetwork4(t, "10.0.0.0", "255.0.0.0"), want: -1},
		{name: "middle before max", left: mustNetwork4(t, "10.0.0.0", "255.0.0.0"), right: mustNetwork4(t, "255.255.255.255", "255.255.255.255"), want: -1},
		{name: "zero before max", left: mustNetwork4(t, "0.0.0.0", "0.0.0.0"), right: mustNetwork4(t, "255.255.255.255", "255.255.255.255"), want: -1},
		{name: "antisymmetry on the dominance pair", left: mustNetwork4(t, "11.0.0.0", "255.0.0.0"), right: mustNetwork4(t, "10.0.0.0", "255.255.255.255"), want: 1},
		{name: "top address bit compares unsigned", left: mustNetwork4(t, "128.0.0.0", "128.0.0.0"), right: mustNetwork4(t, "127.255.255.255", "255.255.255.255"), want: 1},
		{name: "same address, non-contiguous mask decides", left: mustNetwork4(t, "10.0.0.5", "255.0.0.255"), right: mustNetwork4(t, "10.0.0.5", "255.255.0.255"), want: -1},
		{name: "alternating masks under one address", left: mustNetwork4(t, "0.0.0.0", "170.85.170.85"), right: mustNetwork4(t, "0.0.0.0", "85.170.85.170"), want: 1},
		{name: "address bit beats any mask", left: mustNetwork4(t, "10.0.0.4", "255.0.0.255"), right: mustNetwork4(t, "10.0.0.5", "255.255.255.255"), want: -1},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			require.Equal(t, testCase.want, testCase.left.Compare(testCase.right))
		})
	}
}

// verifies that equal networks compare as zero and only they do.
func Test_Network4_Compare_EqualityIsZero(t *testing.T) {
	left := mustNetwork4(t, "192.168.1.0", "255.255.255.0")
	right := mustNetwork4(t, "192.168.1.0", "255.255.255.0")
	require.Equal(t, 0, left.Compare(right))
	require.Equal(t, left, right)
}

// verifies that sorting a shuffled fixture yields the exact documented
// order, the contract the aggregation and split inputs rely on.
func Test_Network4_Compare_SortPinsDocumentedOrder(t *testing.T) {
	shuffled := []xnetip.Network4{
		mustNetwork4(t, "192.168.1.1", "255.255.255.255"),
		mustNetwork4(t, "10.1.0.0", "255.255.0.0"),
		mustNetwork4(t, "255.255.255.255", "255.255.255.255"),
		mustNetwork4(t, "10.0.0.5", "255.255.0.255"),
		mustNetwork4(t, "0.0.0.0", "0.0.0.0"),
		mustNetwork4(t, "10.0.0.0", "255.255.255.0"),
		mustNetwork4(t, "10.0.0.5", "255.0.0.255"),
		mustNetwork4(t, "10.0.0.0", "255.0.0.0"),
	}
	want := []xnetip.Network4{
		mustNetwork4(t, "0.0.0.0", "0.0.0.0"),
		mustNetwork4(t, "10.0.0.0", "255.0.0.0"),
		mustNetwork4(t, "10.0.0.0", "255.255.255.0"),
		mustNetwork4(t, "10.0.0.5", "255.0.0.255"),
		mustNetwork4(t, "10.0.0.5", "255.255.0.255"),
		mustNetwork4(t, "10.1.0.0", "255.255.0.0"),
		mustNetwork4(t, "192.168.1.1", "255.255.255.255"),
		mustNetwork4(t, "255.255.255.255", "255.255.255.255"),
	}
	slices.SortFunc(shuffled, xnetip.Network4.Compare)
	require.Equal(t, want, shuffled)
}

// verifies that the order equals the tuple order of the netip address
// views, is antisymmetric and is zero exactly on equal values.
func Test_Network4_Compare_MatchesTupleOrderProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		left := genNetwork4.Draw(t, "left")
		right := genNetwork4.Draw(t, "right")
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
func Test_Network4_Compare_TransitivityProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		first := genNetwork4.Draw(t, "first")
		second := genNetwork4.Draw(t, "second")
		third := genNetwork4.Draw(t, "third")
		if first.Compare(second) <= 0 && second.Compare(third) <= 0 {
			require.LessOrEqual(t, first.Compare(third), 0)
		}
	})
}

// verifies that sorting a random slice by the order yields a sorted
// permutation of the input.
func Test_Network4_Compare_SortFuncProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		networks := rapid.SliceOfN(genNetwork4, 0, 32).Draw(t, "networks")
		sorted := slices.Clone(networks)
		slices.SortFunc(sorted, xnetip.Network4.Compare)
		require.True(t, slices.IsSortedFunc(sorted, xnetip.Network4.Compare))
		require.ElementsMatch(t, networks, sorted)
	})
}

// verifies that the address-first component agrees with the
// netip.Addr order whenever the addresses differ.
func Test_Network4_Compare_MatchesNetipAddrOrder(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		left := genNetwork4.Draw(t, "left")
		right := genNetwork4.Draw(t, "right")
		if left.Addr() != right.Addr() {
			require.Equal(t, left.Addr().Compare(right.Addr()), left.Compare(right))
		}
	})
}

// verifies that comparing allocates nothing.
func Test_Network4_Compare_AllocationFree(t *testing.T) {
	left := mustNetwork4(t, "10.0.0.0", "255.0.0.0")
	right := mustNetwork4(t, "10.0.0.0", "255.255.255.0")
	requireNoAllocs(t, func() { intSink = left.Compare(right) })
}

func BenchmarkNetwork4_Compare_MaskDecides(b *testing.B) {
	left := mustNetwork4(b, "10.0.0.0", "255.0.0.0")
	right := mustNetwork4(b, "10.0.0.0", "255.255.255.0")
	b.ReportAllocs()
	for b.Loop() {
		intSink = left.Compare(right)
	}
}

func BenchmarkNetwork4_Compare_AddressDecides(b *testing.B) {
	left := mustNetwork4(b, "10.0.0.0", "255.0.0.0")
	right := mustNetwork4(b, "11.0.0.0", "255.255.255.0")
	b.ReportAllocs()
	for b.Loop() {
		intSink = left.Compare(right)
	}
}

func BenchmarkNetwork4_SortFunc_1024(b *testing.B) {
	// The fixture mirrors the Rust bench recipe: index times Knuth's
	// multiplicative constant, prefixes spread over /8../32.
	template := make([]xnetip.Network4, 1024)
	for idx := range template {
		bits := uint32(idx) * 2_654_435_761
		network, err := xnetip.Network4FromCIDR(netipAddrFrom4Bits(bits), 8+int(bits%25))
		if err != nil {
			b.Fatal(err)
		}
		template[idx] = network
	}
	networks := make([]xnetip.Network4, len(template))
	b.ReportAllocs()
	for b.Loop() {
		// The 4 KiB fixture refresh stays inside the timed region: a
		// paused timer would keep the loop from ever finishing.
		copy(networks, template)
		slices.SortFunc(networks, xnetip.Network4.Compare)
	}
}

// verifies that containment over contiguous masks follows the prefix
// rules.
//
// The universe contains everything, a shorter prefix contains its
// refinements and not the reverse, and a host route contains only
// itself.
func Test_Network4_Contains_ContiguousAndBoundary(t *testing.T) {
	cases := []struct {
		name  string
		outer xnetip.Network4
		inner xnetip.Network4
		want  bool
	}{
		{name: "universe contains host route", outer: xnetip.MustParseNetwork4("0.0.0.0/0"), inner: xnetip.MustParseNetwork4("127.0.0.1"), want: true},
		{name: "shorter prefix contains longer", outer: xnetip.MustParseNetwork4("0.0.0.0/8"), inner: xnetip.MustParseNetwork4("0.0.0.0/9"), want: true},
		{name: "longer prefix does not contain shorter", outer: xnetip.MustParseNetwork4("0.0.0.0/9"), inner: xnetip.MustParseNetwork4("0.0.0.0/8"), want: false},
		{name: "host route contains itself", outer: xnetip.MustParseNetwork4("127.0.0.1"), inner: xnetip.MustParseNetwork4("127.0.0.1"), want: true},
		{name: "host route does not contain neighbour", outer: xnetip.MustParseNetwork4("10.0.0.1/32"), inner: xnetip.MustParseNetwork4("10.0.0.2/32"), want: false},
		{name: "nested contiguous", outer: xnetip.MustParseNetwork4("192.168.0.0/16"), inner: xnetip.MustParseNetwork4("192.168.1.0/24"), want: true},
		{name: "nested contiguous reversed", outer: xnetip.MustParseNetwork4("192.168.1.0/24"), inner: xnetip.MustParseNetwork4("192.168.0.0/16"), want: false},
		{name: "disjoint contiguous", outer: xnetip.MustParseNetwork4("10.0.0.0/8"), inner: xnetip.MustParseNetwork4("192.168.0.0/16"), want: false},
		{name: "disjoint contiguous reversed", outer: xnetip.MustParseNetwork4("192.168.0.0/16"), inner: xnetip.MustParseNetwork4("10.0.0.0/8"), want: false},
		{name: "universe contains universe", outer: xnetip.MustParseNetwork4("0.0.0.0/0"), inner: xnetip.MustParseNetwork4("0.0.0.0/0"), want: true},
		{name: "all-ones host contains itself", outer: xnetip.MustParseNetwork4("255.255.255.255/32"), inner: xnetip.MustParseNetwork4("255.255.255.255/32"), want: true},
		{name: "top /31 contains the all-ones host", outer: xnetip.MustParseNetwork4("255.255.255.254/31"), inner: xnetip.MustParseNetwork4("255.255.255.255/32"), want: true},
		{name: "all-ones host does not contain its /31", outer: xnetip.MustParseNetwork4("255.255.255.255/32"), inner: xnetip.MustParseNetwork4("255.255.255.254/31"), want: false},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			require.Equal(t, testCase.want, testCase.outer.Contains(testCase.inner))
		})
	}
}

// verifies that containment over non-contiguous masks needs both the
// pattern match and the mask-subset relation.
//
// The subset relation is bitwise, so a numerically smaller mask is
// not thereby a subset and the shortcut valid for contiguous masks
// must not leak in.
func Test_Network4_Contains_NonContiguousMasks(t *testing.T) {
	cases := []struct {
		name  string
		outer xnetip.Network4
		inner xnetip.Network4
		want  bool
	}{
		{name: "pattern 10.*.0.* contains matching host", outer: xnetip.MustParseNetwork4("10.0.0.0/255.0.255.0"), inner: xnetip.MustParseNetwork4("10.42.0.99/32"), want: true},
		{name: "pattern mismatch on a constrained octet", outer: xnetip.MustParseNetwork4("10.0.0.0/255.0.255.0"), inner: xnetip.MustParseNetwork4("10.42.1.99/32"), want: false},
		{name: "pattern contains narrower pattern", outer: xnetip.MustParseNetwork4("10.0.0.0/255.0.0.0"), inner: xnetip.MustParseNetwork4("10.0.0.1/255.0.0.255"), want: true},
		{name: "narrower pattern does not contain wider", outer: xnetip.MustParseNetwork4("10.0.0.1/255.0.0.255"), inner: xnetip.MustParseNetwork4("10.0.0.0/255.0.0.0"), want: false},
		{name: "mask subset fails on disjoint mask bits", outer: xnetip.MustParseNetwork4("10.0.0.0/255.0.255.0"), inner: xnetip.MustParseNetwork4("10.0.0.0/255.0.0.255"), want: false},
		{name: "mask subset fails on disjoint mask bits reversed", outer: xnetip.MustParseNetwork4("10.0.0.0/255.0.0.255"), inner: xnetip.MustParseNetwork4("10.0.0.0/255.0.255.0"), want: false},
		{name: "hole in the middle octets contains refinement", outer: xnetip.MustParseNetwork4("10.0.0.0/255.0.0.255"), inner: xnetip.MustParseNetwork4("10.5.9.0/255.255.0.255"), want: true},
		{name: "alternating mask contains its host refinement", outer: xnetip.MustParseNetwork4("170.85.170.85/170.85.170.85"), inner: xnetip.MustParseNetwork4("170.85.170.85/32"), want: true},
		{name: "host does not contain the alternating pattern", outer: xnetip.MustParseNetwork4("170.85.170.85/32"), inner: xnetip.MustParseNetwork4("170.85.170.85/170.85.170.85"), want: false},
		{name: "complementary alternating patterns", outer: xnetip.MustParseNetwork4("170.0.170.0/170.85.170.85"), inner: xnetip.MustParseNetwork4("0.170.0.170/85.170.85.170"), want: false},
		{name: "complementary alternating patterns reversed", outer: xnetip.MustParseNetwork4("0.170.0.170/85.170.85.170"), inner: xnetip.MustParseNetwork4("170.0.170.0/170.85.170.85"), want: false},
		{name: "numerically smaller mask is not a subset", outer: xnetip.MustParseNetwork4("0.0.0.0/0.0.255.255"), inner: xnetip.MustParseNetwork4("0.0.0.0/0.255.0.0"), want: false},
		{name: "numerically larger mask is not a subset either", outer: xnetip.MustParseNetwork4("0.0.0.0/0.255.0.0"), inner: xnetip.MustParseNetwork4("0.0.0.0/0.0.255.255"), want: false},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			require.Equal(t, testCase.want, testCase.outer.Contains(testCase.inner))
		})
	}
}

// verifies that every network contains itself, whatever the mask shape.
func Test_Network4_Contains_ReflexiveProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		network := genNetwork4.Draw(t, "network")
		require.True(t, network.Contains(network))
	})
}

// verifies that mutual containment holds exactly for equal networks.
func Test_Network4_Contains_AntisymmetryProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		left := genNetwork4.Draw(t, "left")
		right := genNetwork4.Draw(t, "right")
		mutual := left.Contains(right) && right.Contains(left)
		require.Equal(t, left == right, mutual)
	})
}

// verifies that containment is transitive on random triples.
func Test_Network4_Contains_TransitivityProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		first := genNetwork4.Draw(t, "first")
		second := genNetwork4.Draw(t, "second")
		third := genNetwork4.Draw(t, "third")
		if first.Contains(second) && second.Contains(third) {
			require.True(t, first.Contains(third))
		}
	})
}

// verifies that the universe contains every network and is contained
// only in itself.
func Test_Network4_Contains_UniverseProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		network := genNetwork4.Draw(t, "network")
		require.True(t, xnetip.Network4{}.Contains(network))
		require.Equal(t, network == xnetip.Network4{}, network.Contains(xnetip.Network4{}))
	})
}

// verifies that containment equals set inclusion on networks confined
// to the top octet.
//
// Both masks live in the top eight bits, so enumerating the 256
// patterns there is exhaustive: the outer network contains the inner
// one exactly when every member of the inner is a member of the outer.
func Test_Network4_Contains_BruteForceMembershipProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		outerAddr := uint32(rapid.IntRange(0, 255).Draw(t, "outer addr"))
		outerMask := uint32(rapid.IntRange(0, 255).Draw(t, "outer mask"))
		innerAddr := uint32(rapid.IntRange(0, 255).Draw(t, "inner addr"))
		innerMask := uint32(rapid.IntRange(0, 255).Draw(t, "inner mask"))
		outer, err := xnetip.Network4From(
			netipAddrFrom4Bits(outerAddr<<24),
			netipAddrFrom4Bits(outerMask<<24),
		)
		require.NoError(t, err)
		inner, err := xnetip.Network4From(
			netipAddrFrom4Bits(innerAddr<<24),
			netipAddrFrom4Bits(innerMask<<24),
		)
		require.NoError(t, err)
		want := true
		for x := uint32(0); x <= 255; x++ {
			memberOfInner := x&innerMask == innerAddr&innerMask
			memberOfOuter := x&outerMask == outerAddr&outerMask
			if memberOfInner && !memberOfOuter {
				want = false
				break
			}
		}
		require.Equal(t, want, outer.Contains(inner))
	})
}

// verifies that on contiguous networks containment agrees with the
// net/netip rule.
//
// The oracle is the prefix pair: the outer prefix covers the inner
// address and its length does not exceed the inner one.
func Test_Network4_Contains_MatchesNetipPrefixProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		outerPrefix := genIPv4Prefix.Draw(t, "outer").Masked()
		innerPrefix := genIPv4Prefix.Draw(t, "inner").Masked()
		outer, ok := xnetip.Network4FromPrefix(outerPrefix)
		require.True(t, ok)
		inner, ok := xnetip.Network4FromPrefix(innerPrefix)
		require.True(t, ok)
		want := outerPrefix.Contains(innerPrefix.Addr()) && outerPrefix.Bits() <= innerPrefix.Bits()
		require.Equal(t, want, outer.Contains(inner))
	})
}

// verifies that containing a host route agrees with the net/netip
// address containment of the same prefix.
func Test_Network4_Contains_HostRouteMatchesNetipProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		outerPrefix := genIPv4Prefix.Draw(t, "outer").Masked()
		outer, ok := xnetip.Network4FromPrefix(outerPrefix)
		require.True(t, ok)
		address := genNetipAddr4.Draw(t, "address")
		host, err := xnetip.Network4FromAddr(address)
		require.NoError(t, err)
		require.Equal(t, outerPrefix.Contains(address), outer.Contains(host))
	})
}

// verifies that the containment check allocates nothing.
func Test_Network4_Contains_AllocationFree(t *testing.T) {
	outer := xnetip.MustParseNetwork4("10.0.0.0/255.0.0.255")
	inner := xnetip.MustParseNetwork4("10.5.9.0/255.255.0.255")
	requireNoAllocs(t, func() { okSink = outer.Contains(inner) })
}

func BenchmarkNetwork4_Contains_ContiguousTrue(b *testing.B) {
	outer := xnetip.MustParseNetwork4("10.0.0.0/8")
	inner := xnetip.MustParseNetwork4("10.1.0.0/16")
	b.ReportAllocs()
	for b.Loop() {
		okSink = outer.Contains(inner)
	}
}

func BenchmarkNetwork4_Contains_ContiguousFalse(b *testing.B) {
	outer := xnetip.MustParseNetwork4("10.0.0.0/8")
	inner := xnetip.MustParseNetwork4("192.168.0.0/16")
	b.ReportAllocs()
	for b.Loop() {
		okSink = outer.Contains(inner)
	}
}

func BenchmarkNetwork4_Contains_NonContiguous(b *testing.B) {
	outer := xnetip.MustParseNetwork4("10.0.0.0/255.0.0.255")
	inner := xnetip.MustParseNetwork4("10.5.9.0/255.255.0.255")
	b.ReportAllocs()
	for b.Loop() {
		okSink = outer.Contains(inner)
	}
}

// verifies that address membership is total and follows the
// netip.Prefix.Contains rule over contiguous networks.
//
// A member is any address agreeing on the prefix, the universe holds
// every Is4 address, a host route holds only itself, and an address
// that is not Is4 — plain IPv6, IPv4-mapped or the invalid zero value
// — is not contained rather than an error.
func Test_Network4_ContainsAddr_UnitAndBoundary(t *testing.T) {
	cases := []struct {
		name    string
		network xnetip.Network4
		addr    netip.Addr
		want    bool
	}{
		{name: "member", network: xnetip.MustParseNetwork4("10.0.0.0/8"), addr: netip.MustParseAddr("10.1.2.3"), want: true},
		{name: "non-member", network: xnetip.MustParseNetwork4("10.0.0.0/8"), addr: netip.MustParseAddr("11.0.0.0"), want: false},
		{name: "network address itself", network: xnetip.MustParseNetwork4("10.0.0.0/8"), addr: netip.MustParseAddr("10.0.0.0"), want: true},
		{name: "last address", network: xnetip.MustParseNetwork4("10.0.0.0/8"), addr: netip.MustParseAddr("10.255.255.255"), want: true},
		{name: "host route contains itself", network: xnetip.MustParseNetwork4("10.0.0.1/32"), addr: netip.MustParseAddr("10.0.0.1"), want: true},
		{name: "host route excludes neighbour", network: xnetip.MustParseNetwork4("10.0.0.1/32"), addr: netip.MustParseAddr("10.0.0.2"), want: false},
		{name: "universe contains zero address", network: xnetip.MustParseNetwork4("0.0.0.0/0"), addr: netip.MustParseAddr("0.0.0.0"), want: true},
		{name: "universe contains all-ones address", network: xnetip.MustParseNetwork4("0.0.0.0/0"), addr: netip.MustParseAddr("255.255.255.255"), want: true},
		{name: "IPv6 argument", network: xnetip.MustParseNetwork4("10.0.0.0/8"), addr: netip.MustParseAddr("2001:db8::1"), want: false},
		{name: "IPv4-mapped argument", network: xnetip.MustParseNetwork4("10.0.0.0/8"), addr: netip.MustParseAddr("::ffff:10.1.2.3"), want: false},
		{name: "IPv4-mapped argument against the universe", network: xnetip.MustParseNetwork4("0.0.0.0/0"), addr: netip.MustParseAddr("::ffff:1.2.3.4"), want: false},
		{name: "invalid zero Addr", network: xnetip.MustParseNetwork4("10.0.0.0/8"), addr: netip.Addr{}, want: false},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			require.Equal(t, testCase.want, testCase.network.ContainsAddr(testCase.addr))
		})
	}
}

// verifies that membership under a non-contiguous mask is agreement
// on every mask bit, with the unmasked bits free to vary.
func Test_Network4_ContainsAddr_NonContiguousMasks(t *testing.T) {
	cases := []struct {
		name    string
		network xnetip.Network4
		addr    netip.Addr
		want    bool
	}{
		{name: "free middle octet varies", network: xnetip.MustParseNetwork4("10.0.0.0/255.0.255.0"), addr: netip.MustParseAddr("10.77.0.5"), want: true},
		{name: "free octets at their extremes", network: xnetip.MustParseNetwork4("10.0.0.0/255.0.255.0"), addr: netip.MustParseAddr("10.255.0.255"), want: true},
		{name: "constrained third octet differs", network: xnetip.MustParseNetwork4("10.0.0.0/255.0.255.0"), addr: netip.MustParseAddr("10.0.1.0"), want: false},
		{name: "constrained first octet differs", network: xnetip.MustParseNetwork4("10.0.0.0/255.0.255.0"), addr: netip.MustParseAddr("11.5.0.5"), want: false},
		{name: "alternating mask keeps its pattern", network: xnetip.MustParseNetwork4("170.85.170.85/170.85.170.85"), addr: netip.MustParseAddr("170.85.170.85"), want: true},
		{name: "alternating mask with every free bit set", network: xnetip.MustParseNetwork4("170.85.170.85/170.85.170.85"), addr: netip.MustParseAddr("255.255.255.255"), want: true},
		{name: "alternating mask near miss in the last octet", network: xnetip.MustParseNetwork4("170.85.170.85/170.85.170.85"), addr: netip.MustParseAddr("170.85.170.84"), want: false},
		{name: "two-run mask holds both runs", network: xnetip.MustParseNetwork4("192.168.0.0/255.255.0.255"), addr: netip.MustParseAddr("192.168.44.0"), want: true},
		{name: "two-run mask broken in the low run", network: xnetip.MustParseNetwork4("192.168.0.0/255.255.0.255"), addr: netip.MustParseAddr("192.168.44.1"), want: false},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			require.Equal(t, testCase.want, testCase.network.ContainsAddr(testCase.addr))
		})
	}
}

// verifies that address membership equals containing the address's
// host route, over every mask shape.
func Test_Network4_ContainsAddr_HostRouteEquivalenceProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		network := genNetwork4.Draw(t, "network")
		address := genNetipAddr4.Draw(t, "address")
		host, err := xnetip.Network4FromAddr(address)
		require.NoError(t, err)
		require.Equal(t, network.Contains(host), network.ContainsAddr(address))
	})
}

// verifies that membership agrees with the address iterator: exactly
// the yielded addresses are contained.
//
// The mask is widened to leave at most eight host bits, so the
// iterator's address set is small enough to collect and exhaustive
// for the membership comparison, over contiguous and ragged low-byte
// mask shapes alike.
func Test_Network4_ContainsAddr_MatchesAddrsProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		seed := genNetwork4.Draw(t, "seed")
		seedAddr, seedMask := ipv4NetworkBits(seed)
		network, err := xnetip.Network4From(
			netipAddrFrom4Bits(seedAddr),
			netipAddrFrom4Bits(seedMask|^uint32(0xFF)),
		)
		require.NoError(t, err)
		members := map[netip.Addr]bool{}
		for address := range network.Addrs() {
			require.True(t, network.ContainsAddr(address))
			members[address] = true
		}
		probe := genNetipAddr4.Draw(t, "probe")
		require.Equal(t, members[probe], network.ContainsAddr(probe))
	})
}

// verifies that membership is total over arguments of every shape.
//
// An IPv6, zoned or invalid argument answers false, never a panic.
func Test_Network4_ContainsAddr_TotalityProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		network := genNetwork4.Draw(t, "network")
		var address netip.Addr
		switch rapid.IntRange(0, 3).Draw(t, "argument shape") {
		case 0:
			address = genNetipAddr4.Draw(t, "member candidate")
		case 1:
			address = genNetipAddr6.Draw(t, "foreign family")
		case 2:
			address = genNetipAddr6.Draw(t, "zoned").WithZone("eth0")
		default:
			address = netip.Addr{}
		}
		contained := network.ContainsAddr(address)
		if !address.Is4() {
			require.False(t, contained)
		}
	})
}

// verifies that on contiguous networks address membership agrees with
// the net/netip prefix rule for arguments of both families.
func Test_Network4_ContainsAddr_MatchesNetipPrefixProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		prefix := genIPv4Prefix.Draw(t, "prefix").Masked()
		network, ok := xnetip.Network4FromPrefix(prefix)
		require.True(t, ok)
		var address netip.Addr
		if rapid.Bool().Draw(t, "foreign family") {
			address = genNetipAddr6.Draw(t, "address6")
		} else {
			address = genNetipAddr4.Draw(t, "address4")
		}
		require.Equal(t, prefix.Contains(address), network.ContainsAddr(address))
	})
}

// verifies that the membership check allocates nothing.
func Test_Network4_ContainsAddr_AllocationFree(t *testing.T) {
	network := xnetip.MustParseNetwork4("10.0.0.0/255.0.255.0")
	address := netip.MustParseAddr("10.77.0.5")
	requireNoAllocs(t, func() { okSink = network.ContainsAddr(address) })
}

func BenchmarkNetwork4_ContainsAddr_Member(b *testing.B) {
	network := xnetip.MustParseNetwork4("10.0.0.0/8")
	address := netip.MustParseAddr("10.1.2.3")
	b.ReportAllocs()
	for b.Loop() {
		okSink = network.ContainsAddr(address)
	}
}

func BenchmarkNetwork4_ContainsAddr_NonMember(b *testing.B) {
	network := xnetip.MustParseNetwork4("10.0.0.0/8")
	address := netip.MustParseAddr("192.168.1.1")
	b.ReportAllocs()
	for b.Loop() {
		okSink = network.ContainsAddr(address)
	}
}

func BenchmarkNetwork4_ContainsAddr_ForeignFamily(b *testing.B) {
	network := xnetip.MustParseNetwork4("10.0.0.0/8")
	address := netip.MustParseAddr("2001:db8::1")
	b.ReportAllocs()
	for b.Loop() {
		okSink = network.ContainsAddr(address)
	}
}

// verifies that intersecting contiguous networks yields the more
// specific one and fails exactly on disjoint prefixes.
//
// Containment yields the inner network in both orders, identical
// networks and host routes intersect as themselves, the universe is
// neutral, and a disjoint pair answers the zero network so a caller
// ignoring the flag cannot pick up plausible garbage.
func Test_Network4_Intersection_ContiguousAndBoundary(t *testing.T) {
	cases := []struct {
		name   string
		left   xnetip.Network4
		right  xnetip.Network4
		want   xnetip.Network4
		wantOK bool
	}{
		{name: "containment yields the inner network", left: xnetip.MustParseNetwork4("192.168.0.0/16"), right: xnetip.MustParseNetwork4("192.168.1.0/24"), want: xnetip.MustParseNetwork4("192.168.1.0/24"), wantOK: true},
		{name: "containment reversed yields the inner network", left: xnetip.MustParseNetwork4("192.168.1.0/24"), right: xnetip.MustParseNetwork4("192.168.0.0/16"), want: xnetip.MustParseNetwork4("192.168.1.0/24"), wantOK: true},
		{name: "identical networks intersect as themselves", left: xnetip.MustParseNetwork4("10.0.0.0/8"), right: xnetip.MustParseNetwork4("10.0.0.0/8"), want: xnetip.MustParseNetwork4("10.0.0.0/8"), wantOK: true},
		{name: "disjoint contiguous networks answer the zero network", left: xnetip.MustParseNetwork4("192.168.0.0/16"), right: xnetip.MustParseNetwork4("10.0.0.0/8"), want: xnetip.Network4{}, wantOK: false},
		{name: "universe is neutral", left: xnetip.MustParseNetwork4("0.0.0.0/0"), right: xnetip.MustParseNetwork4("192.168.1.0/24"), want: xnetip.MustParseNetwork4("192.168.1.0/24"), wantOK: true},
		{name: "universe is neutral reversed", left: xnetip.MustParseNetwork4("192.168.1.0/24"), right: xnetip.MustParseNetwork4("0.0.0.0/0"), want: xnetip.MustParseNetwork4("192.168.1.0/24"), wantOK: true},
		{name: "same host route intersects as itself", left: xnetip.MustParseNetwork4("10.0.0.1/32"), right: xnetip.MustParseNetwork4("10.0.0.1/32"), want: xnetip.MustParseNetwork4("10.0.0.1/32"), wantOK: true},
		{name: "different host routes are disjoint", left: xnetip.MustParseNetwork4("10.0.0.1/32"), right: xnetip.MustParseNetwork4("10.0.0.2/32"), want: xnetip.Network4{}, wantOK: false},
		{name: "universe with universe", left: xnetip.MustParseNetwork4("0.0.0.0/0"), right: xnetip.MustParseNetwork4("0.0.0.0/0"), want: xnetip.MustParseNetwork4("0.0.0.0/0"), wantOK: true},
		{name: "adjacent /24 siblings are disjoint", left: xnetip.MustParseNetwork4("10.0.0.0/24"), right: xnetip.MustParseNetwork4("10.0.1.0/24"), want: xnetip.Network4{}, wantOK: false},
		{name: "host route inside /31", left: xnetip.MustParseNetwork4("10.0.0.0/31"), right: xnetip.MustParseNetwork4("10.0.0.1/32"), want: xnetip.MustParseNetwork4("10.0.0.1/32"), wantOK: true},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			got, ok := testCase.left.Intersection(testCase.right)
			require.Equal(t, testCase.wantOK, ok)
			require.Equal(t, testCase.want, got)
		})
	}
}

// verifies that intersection unions the masks and the addresses of
// non-contiguous networks.
//
// Failure needs a doubly constrained disagreement: masks sharing no
// set bit always intersect whatever the addresses,
// two complementary alternating patterns collapsing to a single host
// route, while one shared constrained bit that differs makes the
// pair disjoint.
func Test_Network4_Intersection_NonContiguousMasks(t *testing.T) {
	cases := []struct {
		name   string
		left   xnetip.Network4
		right  xnetip.Network4
		want   xnetip.Network4
		wantOK bool
	}{
		{name: "one non-contiguous", left: xnetip.MustParseNetwork4("10.0.0.1/255.0.0.255"), right: xnetip.MustParseNetwork4("10.1.0.0/255.255.0.0"), want: xnetip.MustParseNetwork4("10.1.0.1/255.255.0.255"), wantOK: true},
		{name: "one non-contiguous reversed", left: xnetip.MustParseNetwork4("10.1.0.0/255.255.0.0"), right: xnetip.MustParseNetwork4("10.0.0.1/255.0.0.255"), want: xnetip.MustParseNetwork4("10.1.0.1/255.255.0.255"), wantOK: true},
		{name: "both non-contiguous", left: xnetip.MustParseNetwork4("10.0.10.0/255.0.255.0"), right: xnetip.MustParseNetwork4("10.0.0.5/255.0.0.255"), want: xnetip.MustParseNetwork4("10.0.10.5/255.0.255.255"), wantOK: true},
		{name: "both non-contiguous reversed", left: xnetip.MustParseNetwork4("10.0.0.5/255.0.0.255"), right: xnetip.MustParseNetwork4("10.0.10.0/255.0.255.0"), want: xnetip.MustParseNetwork4("10.0.10.5/255.0.255.255"), wantOK: true},
		{name: "single common address", left: xnetip.MustParseNetwork4("10.0.0.0/255.0.255.0"), right: xnetip.MustParseNetwork4("10.5.0.0/255.255.0.255"), want: xnetip.MustParseNetwork4("10.5.0.0/32"), wantOK: true},
		{name: "alternating masks always intersect", left: xnetip.MustParseNetwork4("170.0.170.0/170.85.170.85"), right: xnetip.MustParseNetwork4("0.170.0.170/85.170.85.170"), want: xnetip.MustParseNetwork4("170.170.170.170/32"), wantOK: true},
		{name: "disjoint on a shared top octet", left: xnetip.MustParseNetwork4("10.0.0.0/255.0.255.0"), right: xnetip.MustParseNetwork4("11.0.0.0/255.0.255.0"), want: xnetip.Network4{}, wantOK: false},
		{name: "disjoint on a shared low bit", left: xnetip.MustParseNetwork4("10.0.0.0/255.0.255.0"), right: xnetip.MustParseNetwork4("10.5.1.0/255.255.255.0"), want: xnetip.Network4{}, wantOK: false},
		{name: "pattern with host route inside", left: xnetip.MustParseNetwork4("10.0.0.0/255.0.255.0"), right: xnetip.MustParseNetwork4("10.42.0.99/32"), want: xnetip.MustParseNetwork4("10.42.0.99/32"), wantOK: true},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			got, ok := testCase.left.Intersection(testCase.right)
			require.Equal(t, testCase.wantOK, ok)
			require.Equal(t, testCase.want, got)
		})
	}
}

// verifies that intersection is commutative in both the value and the
// flag.
func Test_Network4_Intersection_CommutativityProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		left := genNetwork4.Draw(t, "left")
		right := genNetwork4.Draw(t, "right")
		leftValue, leftOK := left.Intersection(right)
		rightValue, rightOK := right.Intersection(left)
		require.Equal(t, leftOK, rightOK)
		require.Equal(t, leftValue, rightValue)
	})
}

// verifies that every network intersected with itself is itself.
func Test_Network4_Intersection_SelfIntersectionProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		network := genNetwork4.Draw(t, "network")
		got, ok := network.Intersection(network)
		require.True(t, ok)
		require.Equal(t, network, got)
	})
}

// verifies that when one network contains the other the intersection
// is the contained one.
func Test_Network4_Intersection_ContainmentYieldsInnerProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		outer := genNetwork4.Draw(t, "outer")
		inner := genNetwork4.Draw(t, "inner")
		if outer.Contains(inner) {
			got, ok := outer.Intersection(inner)
			require.True(t, ok)
			require.Equal(t, inner, got)
		}
	})
}

// verifies that an existing intersection is contained in both inputs.
func Test_Network4_Intersection_SubsetOfBothProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		left := genNetwork4.Draw(t, "left")
		right := genNetwork4.Draw(t, "right")
		if got, ok := left.Intersection(right); ok {
			require.True(t, left.Contains(got))
			require.True(t, right.Contains(got))
		}
	})
}

// verifies that an existing intersection carries the union of the
// masks and of the addresses, already normalized.
//
// The mask union constrains every bit either input constrains and the
// address union stays inside it, so the shape check subsumes the
// normalization one.
func Test_Network4_Intersection_ShapeAndNormalizedProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		left := genNetwork4.Draw(t, "left")
		right := genNetwork4.Draw(t, "right")
		got, ok := left.Intersection(right)
		if !ok {
			return
		}
		leftAddr := left.Addr().As4()
		leftMask := left.Mask().As4()
		rightAddr := right.Addr().As4()
		rightMask := right.Mask().As4()
		wantAddr := binary.BigEndian.Uint32(leftAddr[:]) | binary.BigEndian.Uint32(rightAddr[:])
		wantMask := binary.BigEndian.Uint32(leftMask[:]) | binary.BigEndian.Uint32(rightMask[:])
		require.Equal(t, netipAddrFrom4Bits(wantAddr), got.Addr())
		require.Equal(t, netipAddrFrom4Bits(wantMask), got.Mask())
		require.Equal(t, netipAddrFrom4Bits(wantAddr&wantMask), got.Addr())
	})
}

// verifies that intersection equals set intersection on networks
// confined to the top octet.
//
// Both masks live in the top eight bits, so enumerating the 256
// patterns there is exhaustive: an address belongs to both inputs
// exactly when the intersection exists and the address belongs to it.
func Test_Network4_Intersection_BruteForceMembershipProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		leftAddr := uint32(rapid.IntRange(0, 255).Draw(t, "left addr"))
		leftMask := uint32(rapid.IntRange(0, 255).Draw(t, "left mask"))
		rightAddr := uint32(rapid.IntRange(0, 255).Draw(t, "right addr"))
		rightMask := uint32(rapid.IntRange(0, 255).Draw(t, "right mask"))
		left, err := xnetip.Network4From(
			netipAddrFrom4Bits(leftAddr<<24),
			netipAddrFrom4Bits(leftMask<<24),
		)
		require.NoError(t, err)
		right, err := xnetip.Network4From(
			netipAddrFrom4Bits(rightAddr<<24),
			netipAddrFrom4Bits(rightMask<<24),
		)
		require.NoError(t, err)
		got, ok := left.Intersection(right)
		gotAddr := got.Addr().As4()
		gotMask := got.Mask().As4()
		gotAddrBits := binary.BigEndian.Uint32(gotAddr[:]) >> 24
		gotMaskBits := binary.BigEndian.Uint32(gotMask[:]) >> 24
		for x := uint32(0); x <= 255; x++ {
			memberOfLeft := x&leftMask == leftAddr&leftMask
			memberOfRight := x&rightMask == rightAddr&rightMask
			memberOfResult := ok && x&gotMaskBits == gotAddrBits
			require.Equal(t, memberOfLeft && memberOfRight, memberOfResult, "address %d", x)
		}
	})
}

// verifies that on contiguous networks the intersection agrees with
// the net/netip overlap rule.
//
// Two prefixes overlap exactly when the networks intersect, and the
// intersection of two overlapping prefixes is the more specific one.
func Test_Network4_Intersection_MatchesNetipOverlapsProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		leftPrefix := genIPv4Prefix.Draw(t, "left").Masked()
		rightPrefix := genIPv4Prefix.Draw(t, "right").Masked()
		left, ok := xnetip.Network4FromPrefix(leftPrefix)
		require.True(t, ok)
		right, ok := xnetip.Network4FromPrefix(rightPrefix)
		require.True(t, ok)
		got, ok := left.Intersection(right)
		require.Equal(t, leftPrefix.Overlaps(rightPrefix), ok)
		if !ok {
			return
		}
		want := left
		if rightPrefix.Bits() > leftPrefix.Bits() {
			want = right
		}
		require.Equal(t, want, got)
	})
}

// verifies that the intersection allocates nothing.
func Test_Network4_Intersection_AllocationFree(t *testing.T) {
	left := xnetip.MustParseNetwork4("10.0.0.1/255.0.0.255")
	right := xnetip.MustParseNetwork4("10.1.0.0/255.255.0.0")
	requireNoAllocs(t, func() { networkSink, okSink = left.Intersection(right) })
}

func BenchmarkNetwork4_Intersection_ContiguousOverlapping(b *testing.B) {
	left := xnetip.MustParseNetwork4("192.168.0.0/16")
	right := xnetip.MustParseNetwork4("192.168.1.0/24")
	b.ReportAllocs()
	for b.Loop() {
		networkSink, okSink = left.Intersection(right)
	}
}

func BenchmarkNetwork4_Intersection_ContiguousDisjoint(b *testing.B) {
	left := xnetip.MustParseNetwork4("192.168.0.0/16")
	right := xnetip.MustParseNetwork4("10.0.0.0/8")
	b.ReportAllocs()
	for b.Loop() {
		networkSink, okSink = left.Intersection(right)
	}
}

func BenchmarkNetwork4_Intersection_NonContiguous(b *testing.B) {
	left := xnetip.MustParseNetwork4("10.0.0.1/255.0.0.255")
	right := xnetip.MustParseNetwork4("10.1.0.0/255.255.0.0")
	b.ReportAllocs()
	for b.Loop() {
		networkSink, okSink = left.Intersection(right)
	}
}

// verifies that contiguous networks intersect exactly when one
// contains the other or they are equal prefixes of a common address.
//
// A network always intersects itself, the universe intersects
// everything, and two host routes intersect only when equal.
func Test_Network4_Intersects_ContiguousAndBoundary(t *testing.T) {
	cases := []struct {
		name  string
		left  xnetip.Network4
		right xnetip.Network4
		want  bool
	}{
		{name: "overlapping contiguous", left: xnetip.MustParseNetwork4("192.168.0.0/16"), right: xnetip.MustParseNetwork4("192.168.1.0/24"), want: true},
		{name: "overlapping contiguous reversed", left: xnetip.MustParseNetwork4("192.168.1.0/24"), right: xnetip.MustParseNetwork4("192.168.0.0/16"), want: true},
		{name: "disjoint contiguous", left: xnetip.MustParseNetwork4("192.168.0.0/16"), right: xnetip.MustParseNetwork4("10.0.0.0/8"), want: false},
		{name: "disjoint contiguous reversed", left: xnetip.MustParseNetwork4("10.0.0.0/8"), right: xnetip.MustParseNetwork4("192.168.0.0/16"), want: false},
		{name: "self", left: xnetip.MustParseNetwork4("10.0.0.0/8"), right: xnetip.MustParseNetwork4("10.0.0.0/8"), want: true},
		{name: "unspecified with anything", left: xnetip.MustParseNetwork4("0.0.0.0/0"), right: xnetip.MustParseNetwork4("192.168.1.0/24"), want: true},
		{name: "anything with unspecified", left: xnetip.MustParseNetwork4("192.168.1.0/24"), right: xnetip.MustParseNetwork4("0.0.0.0/0"), want: true},
		{name: "unspecified with itself", left: xnetip.MustParseNetwork4("0.0.0.0/0"), right: xnetip.MustParseNetwork4("0.0.0.0/0"), want: true},
		{name: "equal host routes", left: xnetip.MustParseNetwork4("10.0.0.1/32"), right: xnetip.MustParseNetwork4("10.0.0.1/32"), want: true},
		{name: "different host routes", left: xnetip.MustParseNetwork4("10.0.0.1/32"), right: xnetip.MustParseNetwork4("10.0.0.2/32"), want: false},
		{name: "host route inside a block", left: xnetip.MustParseNetwork4("10.0.0.1/32"), right: xnetip.MustParseNetwork4("10.0.0.0/8"), want: true},
		{name: "block around a host route", left: xnetip.MustParseNetwork4("10.0.0.0/8"), right: xnetip.MustParseNetwork4("10.0.0.1/32"), want: true},
		{name: "all-ones host route vs the universe", left: xnetip.MustParseNetwork4("255.255.255.255/32"), right: xnetip.MustParseNetwork4("0.0.0.0/0"), want: true},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			require.Equal(t, testCase.want, testCase.left.Intersects(testCase.right))
		})
	}
}

// verifies that non-contiguous networks intersect exactly when their
// addresses agree on every doubly constrained bit.
//
// Masks sharing no set bit always intersect whatever the addresses,
// while a single shared constrained bit that differs keeps the
// networks apart.
func Test_Network4_Intersects_NonContiguousMasks(t *testing.T) {
	cases := []struct {
		name  string
		left  xnetip.Network4
		right xnetip.Network4
		want  bool
	}{
		{name: "pattern overlaps block", left: xnetip.MustParseNetwork4("10.0.0.1/255.0.0.255"), right: xnetip.MustParseNetwork4("10.1.0.0/255.255.0.0"), want: true},
		{name: "pattern overlaps block reversed", left: xnetip.MustParseNetwork4("10.1.0.0/255.255.0.0"), right: xnetip.MustParseNetwork4("10.0.0.1/255.0.0.255"), want: true},
		{name: "pattern disjoint from block", left: xnetip.MustParseNetwork4("10.0.0.1/255.0.0.255"), right: xnetip.MustParseNetwork4("11.0.0.0/255.0.0.0"), want: false},
		{name: "two patterns meeting in one address", left: xnetip.MustParseNetwork4("10.0.10.0/255.0.255.0"), right: xnetip.MustParseNetwork4("10.0.0.5/255.0.0.255"), want: true},
		{name: "alternating masks always intersect", left: xnetip.MustParseNetwork4("170.0.170.0/170.85.170.85"), right: xnetip.MustParseNetwork4("0.170.0.170/85.170.85.170"), want: true},
		{name: "same pattern mask, different fixed octet", left: xnetip.MustParseNetwork4("10.0.0.1/255.0.0.255"), right: xnetip.MustParseNetwork4("10.0.0.2/255.0.0.255"), want: false},
		{name: "pattern vs host route matching it", left: xnetip.MustParseNetwork4("10.0.0.0/255.0.255.0"), right: xnetip.MustParseNetwork4("10.42.0.99/32"), want: true},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			require.Equal(t, testCase.want, testCase.left.Intersects(testCase.right))
		})
	}
}

// verifies that the predicate is symmetric.
func Test_Network4_Intersects_SymmetryProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		left := genNetwork4.Draw(t, "left")
		right := genNetwork4.Draw(t, "right")
		require.Equal(t, left.Intersects(right), right.Intersects(left))
	})
}

// verifies that the predicate answers exactly whether the
// intersection exists.
func Test_Network4_Intersects_EquivalentToIntersectionProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		left := genNetwork4.Draw(t, "left")
		right := genNetwork4.Draw(t, "right")
		_, ok := left.Intersection(right)
		require.Equal(t, ok, left.Intersects(right))
	})
}

// verifies that every network intersects itself and the universe
// intersects every network.
func Test_Network4_Intersects_ReflexiveAndUniverseProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		network := genNetwork4.Draw(t, "network")
		require.True(t, network.Intersects(network))
		require.True(t, xnetip.Network4{}.Intersects(network))
	})
}

// verifies that containment implies intersection.
func Test_Network4_Intersects_ContainmentImpliesIntersectionProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		outer := genNetwork4.Draw(t, "outer")
		inner := genNetwork4.Draw(t, "inner")
		if outer.Contains(inner) {
			require.True(t, outer.Intersects(inner))
		}
	})
}

// verifies that the predicate equals shared membership on networks
// confined to the top octet.
//
// Both masks live in the top eight bits, so enumerating the 256
// patterns there is exhaustive: the networks intersect exactly when
// some address belongs to both.
func Test_Network4_Intersects_BruteForceMembershipProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		leftAddr := uint32(rapid.IntRange(0, 255).Draw(t, "left addr"))
		leftMask := uint32(rapid.IntRange(0, 255).Draw(t, "left mask"))
		rightAddr := uint32(rapid.IntRange(0, 255).Draw(t, "right addr"))
		rightMask := uint32(rapid.IntRange(0, 255).Draw(t, "right mask"))
		left, err := xnetip.Network4From(
			netipAddrFrom4Bits(leftAddr<<24),
			netipAddrFrom4Bits(leftMask<<24),
		)
		require.NoError(t, err)
		right, err := xnetip.Network4From(
			netipAddrFrom4Bits(rightAddr<<24),
			netipAddrFrom4Bits(rightMask<<24),
		)
		require.NoError(t, err)
		want := false
		for x := uint32(0); x <= 255; x++ {
			if x&leftMask == leftAddr&leftMask && x&rightMask == rightAddr&rightMask {
				want = true
				break
			}
		}
		require.Equal(t, want, left.Intersects(right))
	})
}

// verifies that on contiguous networks the predicate agrees with the
// net/netip overlap rule.
func Test_Network4_Intersects_MatchesNetipOverlapsProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		leftPrefix := genIPv4Prefix.Draw(t, "left").Masked()
		rightPrefix := genIPv4Prefix.Draw(t, "right").Masked()
		left, ok := xnetip.Network4FromPrefix(leftPrefix)
		require.True(t, ok)
		right, ok := xnetip.Network4FromPrefix(rightPrefix)
		require.True(t, ok)
		require.Equal(t, leftPrefix.Overlaps(rightPrefix), left.Intersects(right))
	})
}

// verifies that the predicate allocates nothing.
func Test_Network4_Intersects_AllocationFree(t *testing.T) {
	left := xnetip.MustParseNetwork4("10.0.0.1/255.0.0.255")
	right := xnetip.MustParseNetwork4("10.1.0.0/255.255.0.0")
	requireNoAllocs(t, func() { okSink = left.Intersects(right) })
}

func BenchmarkNetwork4_Intersects_Contiguous(b *testing.B) {
	left := xnetip.MustParseNetwork4("192.168.0.0/16")
	right := xnetip.MustParseNetwork4("192.168.1.0/24")
	b.ReportAllocs()
	for b.Loop() {
		okSink = left.Intersects(right)
	}
}

func BenchmarkNetwork4_Intersects_Disjoint(b *testing.B) {
	left := xnetip.MustParseNetwork4("192.168.0.0/16")
	right := xnetip.MustParseNetwork4("10.0.0.0/8")
	b.ReportAllocs()
	for b.Loop() {
		okSink = left.Intersects(right)
	}
}

func BenchmarkNetwork4_Intersects_NonContiguous(b *testing.B) {
	left := xnetip.MustParseNetwork4("10.0.0.1/255.0.0.255")
	right := xnetip.MustParseNetwork4("10.1.0.0/255.255.0.0")
	b.ReportAllocs()
	for b.Loop() {
		okSink = left.Intersects(right)
	}
}

// verifies that disjointness holds exactly for networks sharing no
// address.
//
// No network is disjoint from itself or from the universe, and two
// host routes are disjoint exactly when they differ.
func Test_Network4_IsDisjoint_ContiguousAndBoundary(t *testing.T) {
	cases := []struct {
		name  string
		left  xnetip.Network4
		right xnetip.Network4
		want  bool
	}{
		{name: "overlapping contiguous", left: xnetip.MustParseNetwork4("192.168.0.0/16"), right: xnetip.MustParseNetwork4("192.168.1.0/24"), want: false},
		{name: "overlapping contiguous reversed", left: xnetip.MustParseNetwork4("192.168.1.0/24"), right: xnetip.MustParseNetwork4("192.168.0.0/16"), want: false},
		{name: "disjoint contiguous", left: xnetip.MustParseNetwork4("192.168.0.0/16"), right: xnetip.MustParseNetwork4("10.0.0.0/8"), want: true},
		{name: "self", left: xnetip.MustParseNetwork4("10.0.0.0/8"), right: xnetip.MustParseNetwork4("10.0.0.0/8"), want: false},
		{name: "unspecified with anything", left: xnetip.MustParseNetwork4("0.0.0.0/0"), right: xnetip.MustParseNetwork4("203.0.113.0/24"), want: false},
		{name: "different host routes", left: xnetip.MustParseNetwork4("10.0.0.1/32"), right: xnetip.MustParseNetwork4("10.0.0.2/32"), want: true},
		{name: "equal host routes", left: xnetip.MustParseNetwork4("10.0.0.1/32"), right: xnetip.MustParseNetwork4("10.0.0.1/32"), want: false},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			require.Equal(t, testCase.want, testCase.left.IsDisjoint(testCase.right))
		})
	}
}

// verifies that disjointness of non-contiguous networks needs a
// doubly constrained bit that differs.
//
// Masks sharing no set bit are never disjoint, whatever the
// addresses.
func Test_Network4_IsDisjoint_NonContiguousMasks(t *testing.T) {
	cases := []struct {
		name  string
		left  xnetip.Network4
		right xnetip.Network4
		want  bool
	}{
		{name: "pattern disjoint from block", left: xnetip.MustParseNetwork4("10.0.0.1/255.0.0.255"), right: xnetip.MustParseNetwork4("11.0.0.0/255.0.0.0"), want: true},
		{name: "pattern overlapping block", left: xnetip.MustParseNetwork4("10.0.0.1/255.0.0.255"), right: xnetip.MustParseNetwork4("10.1.0.0/255.255.0.0"), want: false},
		{name: "alternating masks", left: xnetip.MustParseNetwork4("170.0.170.0/170.85.170.85"), right: xnetip.MustParseNetwork4("0.170.0.170/85.170.85.170"), want: false},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			require.Equal(t, testCase.want, testCase.left.IsDisjoint(testCase.right))
		})
	}
}

// verifies that disjointness is the exact complement of intersection,
// symmetric, and never holds for a network against itself.
func Test_Network4_IsDisjoint_ComplementOfIntersectsProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		left := genNetwork4.Draw(t, "left")
		right := genNetwork4.Draw(t, "right")
		require.Equal(t, !left.Intersects(right), left.IsDisjoint(right))
		require.Equal(t, left.IsDisjoint(right), right.IsDisjoint(left))
		require.False(t, left.IsDisjoint(left))
	})
}

// verifies that the predicate allocates nothing.
func Test_Network4_IsDisjoint_AllocationFree(t *testing.T) {
	left := xnetip.MustParseNetwork4("10.0.0.1/255.0.0.255")
	right := xnetip.MustParseNetwork4("11.0.0.0/255.0.0.0")
	requireNoAllocs(t, func() { okSink = left.IsDisjoint(right) })
}

// verifies that disjoint operands yield the source network once.
//
// With nothing shared, the difference is the whole minuend. The
// suites for this sequence are forward-only: the back-end pins of a
// double-ended cursor have no iter.Seq analogue, so none appear
// here.
func Test_Network4_Difference_DisjointYieldsSource(t *testing.T) {
	source := xnetip.MustParseNetwork4("10.0.0.0/8")
	other := xnetip.MustParseNetwork4("192.168.0.0/16")
	require.Equal(t, []xnetip.Network4{source}, slices.Collect(source.Difference(other)))
}

// verifies that subtracting a superset leaves nothing.
func Test_Network4_Difference_SubsetIsEmpty(t *testing.T) {
	source := xnetip.MustParseNetwork4("192.168.1.0/24")
	other := xnetip.MustParseNetwork4("192.168.0.0/16")
	require.Empty(t, slices.Collect(source.Difference(other)))
}

// verifies that a network minus itself is empty.
func Test_Network4_Difference_SelfIsEmpty(t *testing.T) {
	source := xnetip.MustParseNetwork4("10.0.0.0/8")
	require.Empty(t, slices.Collect(source.Difference(source)))
}

// verifies that subtracting a /24 from its /16 superset yields eight
// networks satisfying every part invariant.
func Test_Network4_Difference_SupersetInvariants(t *testing.T) {
	source := xnetip.MustParseNetwork4("192.168.0.0/16")
	other := xnetip.MustParseNetwork4("192.168.1.0/24")
	parts := slices.Collect(source.Difference(other))
	require.Len(t, parts, 8)
	requireIPv4DifferenceParts(t, source, other, parts)
}

// requireIPv4DifferenceParts asserts the invariants every difference
// part must satisfy.
//
// Each part must lie inside the source and be disjoint from the
// subtracted network, and the parts must be pairwise disjoint.
func requireIPv4DifferenceParts(t require.TestingT, source, other xnetip.Network4, parts []xnetip.Network4) {
	if helper, ok := t.(interface{ Helper() }); ok {
		helper.Helper()
	}
	for _, part := range parts {
		require.True(t, source.Contains(part), "part %v not in source", part)
		require.True(t, part.IsDisjoint(other), "part %v intersects the other network", part)
	}
	for first := range parts {
		for second := first + 1; second < len(parts); second++ {
			require.True(t, parts[first].IsDisjoint(parts[second]),
				"parts %v and %v overlap", parts[first], parts[second])
		}
	}
}

// verifies that the universe minus one host peels one network per
// address bit.
func Test_Network4_Difference_UniverseMinusHost(t *testing.T) {
	source := xnetip.MustParseNetwork4("0.0.0.0/0")
	other := xnetip.MustParseNetwork4("1.2.3.4/32")
	require.Len(t, slices.Collect(source.Difference(other)), 32)
}

// verifies that a host route minus the universe is empty.
func Test_Network4_Difference_HostMinusUniverse(t *testing.T) {
	source := xnetip.MustParseNetwork4("1.2.3.4/32")
	other := xnetip.MustParseNetwork4("0.0.0.0/0")
	require.Empty(t, slices.Collect(source.Difference(other)))
}

// verifies that two equal host routes leave nothing.
func Test_Network4_Difference_HostsSame(t *testing.T) {
	source := xnetip.MustParseNetwork4("1.2.3.4/32")
	other := xnetip.MustParseNetwork4("1.2.3.4/32")
	require.Empty(t, slices.Collect(source.Difference(other)))
}

// verifies that two different host routes yield the source alone.
func Test_Network4_Difference_HostsDifferent(t *testing.T) {
	source := xnetip.MustParseNetwork4("1.2.3.4/32")
	other := xnetip.MustParseNetwork4("5.6.7.8/32")
	require.Equal(t, []xnetip.Network4{source}, slices.Collect(source.Difference(other)))
}

// verifies the documented peel order on a hand-checked case.
//
// The universe minus one host yields the 32 contiguous networks /1
// through /32, most significant differing bit first.
func Test_Network4_Difference_VerifiedByHandExactOrder(t *testing.T) {
	source := xnetip.MustParseNetwork4("0.0.0.0/0")
	other := xnetip.MustParseNetwork4("8.8.8.8/32")
	expected := []xnetip.Network4{
		xnetip.MustParseNetwork4("128.0.0.0/1"),
		xnetip.MustParseNetwork4("64.0.0.0/2"),
		xnetip.MustParseNetwork4("32.0.0.0/3"),
		xnetip.MustParseNetwork4("16.0.0.0/4"),
		xnetip.MustParseNetwork4("0.0.0.0/5"),
		xnetip.MustParseNetwork4("12.0.0.0/6"),
		xnetip.MustParseNetwork4("10.0.0.0/7"),
		xnetip.MustParseNetwork4("9.0.0.0/8"),
		xnetip.MustParseNetwork4("8.128.0.0/9"),
		xnetip.MustParseNetwork4("8.64.0.0/10"),
		xnetip.MustParseNetwork4("8.32.0.0/11"),
		xnetip.MustParseNetwork4("8.16.0.0/12"),
		xnetip.MustParseNetwork4("8.0.0.0/13"),
		xnetip.MustParseNetwork4("8.12.0.0/14"),
		xnetip.MustParseNetwork4("8.10.0.0/15"),
		xnetip.MustParseNetwork4("8.9.0.0/16"),
		xnetip.MustParseNetwork4("8.8.128.0/17"),
		xnetip.MustParseNetwork4("8.8.64.0/18"),
		xnetip.MustParseNetwork4("8.8.32.0/19"),
		xnetip.MustParseNetwork4("8.8.16.0/20"),
		xnetip.MustParseNetwork4("8.8.0.0/21"),
		xnetip.MustParseNetwork4("8.8.12.0/22"),
		xnetip.MustParseNetwork4("8.8.10.0/23"),
		xnetip.MustParseNetwork4("8.8.9.0/24"),
		xnetip.MustParseNetwork4("8.8.8.128/25"),
		xnetip.MustParseNetwork4("8.8.8.64/26"),
		xnetip.MustParseNetwork4("8.8.8.32/27"),
		xnetip.MustParseNetwork4("8.8.8.16/28"),
		xnetip.MustParseNetwork4("8.8.8.0/29"),
		xnetip.MustParseNetwork4("8.8.8.12/30"),
		xnetip.MustParseNetwork4("8.8.8.10/31"),
		xnetip.MustParseNetwork4("8.8.8.9/32"),
	}
	collected := slices.Collect(source.Difference(other))
	require.Equal(t, expected, collected)
	for _, part := range collected {
		require.True(t, part.IsContiguous(), "part %v not contiguous", part)
	}
}

// verifies the exact-count contract across all three branches.
//
// The count is the popcount of the extra intersection bits when the
// operands overlap, one when they are disjoint and zero for a subset
// — non-contiguous masks included.
func Test_Network4_Difference_CountFixedCases(t *testing.T) {
	cases := []struct {
		name   string
		source string
		other  string
		want   int
	}{
		{name: "overlapping /16 minus /24", source: "192.168.0.0/16", other: "192.168.1.0/24", want: 8},
		{name: "disjoint", source: "10.0.0.0/8", other: "192.168.0.0/16", want: 1},
		{name: "subset", source: "192.168.1.0/24", other: "192.168.0.0/16", want: 0},
		{name: "non-contiguous low-byte hole", source: "10.0.0.0/255.0.0.0", other: "10.0.0.1/255.0.0.255", want: 8},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			source := xnetip.MustParseNetwork4(testCase.source)
			other := xnetip.MustParseNetwork4(testCase.other)
			require.Len(t, slices.Collect(source.Difference(other)), testCase.want)
		})
	}
}

// verifies that breaking out of the loop stops the sequence after
// exactly the consumed items.
func Test_Network4_Difference_EarlyBreakStops(t *testing.T) {
	source := xnetip.MustParseNetwork4("192.168.0.0/16")
	other := xnetip.MustParseNetwork4("192.168.1.0/24")
	consumed := 0
	for range source.Difference(other) {
		consumed++
		if consumed == 2 {
			break
		}
	}
	require.Equal(t, 2, consumed)
}

// verifies that the same sequence value can be ranged twice and
// yields identical items both times.
func Test_Network4_Difference_ReIterable(t *testing.T) {
	source := xnetip.MustParseNetwork4("192.168.0.0/16")
	other := xnetip.MustParseNetwork4("192.168.1.0/24")
	sequence := source.Difference(other)
	firstPass := slices.Collect(sequence)
	secondPass := slices.Collect(sequence)
	require.Equal(t, firstPass, secondPass)
}

// verifies the exact peel of a non-contiguous pair.
//
// The low-byte hole in the subtrahend mask is peeled bit by bit,
// highest first, every part keeping the source's non-contiguous
// shape.
func Test_Network4_Difference_NonContiguousExactPeel(t *testing.T) {
	source := xnetip.MustParseNetwork4("10.0.0.0/255.0.0.0")
	other := xnetip.MustParseNetwork4("10.0.0.1/255.0.0.255")
	expected := []xnetip.Network4{
		xnetip.MustParseNetwork4("10.0.0.128/255.0.0.128"),
		xnetip.MustParseNetwork4("10.0.0.64/255.0.0.192"),
		xnetip.MustParseNetwork4("10.0.0.32/255.0.0.224"),
		xnetip.MustParseNetwork4("10.0.0.16/255.0.0.240"),
		xnetip.MustParseNetwork4("10.0.0.8/255.0.0.248"),
		xnetip.MustParseNetwork4("10.0.0.4/255.0.0.252"),
		xnetip.MustParseNetwork4("10.0.0.2/255.0.0.254"),
		xnetip.MustParseNetwork4("10.0.0.0/255.0.0.255"),
	}
	collected := slices.Collect(source.Difference(other))
	require.Equal(t, expected, collected)
	requireIPv4DifferenceParts(t, source, other, collected)
}

// verifies the peel on an alternating subtrahend mask.
//
// The 16 parts accumulate the bits of 85.85.85.85 into their masks
// from the top; the first three and the last are pinned by hand.
func Test_Network4_Difference_UniverseMinusAlternatingHost(t *testing.T) {
	source := xnetip.MustParseNetwork4("0.0.0.0/0")
	other := xnetip.MustParseNetwork4("1.2.3.4/85.85.85.85")
	parts := slices.Collect(source.Difference(other))
	require.Len(t, parts, 16)
	require.Equal(t, xnetip.MustParseNetwork4("64.0.0.0/64.0.0.0"), parts[0])
	require.Equal(t, xnetip.MustParseNetwork4("16.0.0.0/80.0.0.0"), parts[1])
	require.Equal(t, xnetip.MustParseNetwork4("4.0.0.0/84.0.0.0"), parts[2])
	require.Equal(t, xnetip.MustParseNetwork4("1.0.1.5/85.85.85.85"), parts[15])
	requireIPv4DifferenceParts(t, source, other, parts)
}

// verifies a non-contiguous source against a contiguous subtrahend.
//
// The peel walks the middle-byte hole, so every part but the final
// one stays non-contiguous and the final one closes the run.
func Test_Network4_Difference_NonContiguousSourceContiguousOther(t *testing.T) {
	source := xnetip.MustParseNetwork4("10.0.0.0/255.0.255.0")
	other := xnetip.MustParseNetwork4("10.0.0.0/24")
	parts := slices.Collect(source.Difference(other))
	require.Len(t, parts, 8)
	for _, part := range parts[:7] {
		require.False(t, part.IsContiguous(), "part %v unexpectedly contiguous", part)
	}
	require.True(t, parts[7].IsContiguous())
	requireIPv4DifferenceParts(t, source, other, parts)
}

// verifies a two-run source mask against a host route: the peel is
// confined to the bits the source leaves free below its upper run.
func Test_Network4_Difference_TwoRunMasksOnBoth(t *testing.T) {
	source := xnetip.MustParseNetwork4("192.168.0.0/255.255.0.255")
	other := xnetip.MustParseNetwork4("192.168.0.0/255.255.255.255")
	parts := slices.Collect(source.Difference(other))
	require.Len(t, parts, 8)
	requireIPv4DifferenceParts(t, source, other, parts)
}

// verifies that every difference part lies inside the source network.
func Test_Network4_Difference_PartsInSourceProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		source := genNetwork4.Draw(t, "source")
		other := genNetwork4.Draw(t, "other")
		for part := range source.Difference(other) {
			require.True(t, source.Contains(part), "part %v not in source %v", part, source)
		}
	})
}

// verifies that every difference part is disjoint from the subtracted
// network.
func Test_Network4_Difference_PartsDisjointFromOtherProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		source := genNetwork4.Draw(t, "source")
		other := genNetwork4.Draw(t, "other")
		for part := range source.Difference(other) {
			require.True(t, part.IsDisjoint(other), "part %v intersects %v", part, other)
		}
	})
}

// verifies that the difference parts are pairwise disjoint.
func Test_Network4_Difference_PairwiseDisjointProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		source := genNetwork4.Draw(t, "source")
		other := genNetwork4.Draw(t, "other")
		parts := slices.Collect(source.Difference(other))
		for first := range parts {
			for second := first + 1; second < len(parts); second++ {
				require.True(t, parts[first].IsDisjoint(parts[second]),
					"parts %v and %v overlap", parts[first], parts[second])
			}
		}
	})
}

// verifies that any network minus itself is empty.
func Test_Network4_Difference_SelfIsEmptyProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		source := genNetwork4.Draw(t, "source")
		require.Empty(t, slices.Collect(source.Difference(source)))
	})
}

// verifies completeness by counting.
//
// The parts' sizes plus the intersection's size add up to the
// source's size, which together with the pairwise-disjoint and
// inside-the-source invariants proves the union of the parts is
// exactly the set difference.
func Test_Network4_Difference_CompletenessProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		source := genNetwork4.Draw(t, "source")
		other := genNetwork4.Draw(t, "other")
		sourceSize := uint64(1) << source.NumHostBits()
		intersectionSize := uint64(0)
		if intersected, ok := source.Intersection(other); ok {
			intersectionSize = uint64(1) << intersected.NumHostBits()
		}
		differenceSize := uint64(0)
		for part := range source.Difference(other) {
			differenceSize += uint64(1) << part.NumHostBits()
		}
		require.Equal(t, sourceSize, differenceSize+intersectionSize)
	})
}

// verifies the three-branch count rule.
//
// The sequence holds exactly one part per extra intersection bit
// when the operands overlap, a lone part when they are disjoint and
// no parts for a subset.
func Test_Network4_Difference_CountMatchesPopcountProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		source := genNetwork4.Draw(t, "source")
		other := genNetwork4.Draw(t, "other")
		want := 1
		if intersected, ok := source.Intersection(other); ok {
			_, sourceMask := ipv4NetworkBits(source)
			_, intersectionMask := ipv4NetworkBits(intersected)
			want = bits.OnesCount32(intersectionMask &^ sourceMask)
		}
		require.Len(t, slices.Collect(source.Difference(other)), want)
	})
}

// verifies that every yielded part satisfies the network invariant
// of a zero address outside the mask.
//
// The peel step constructs parts directly instead of going through a
// normalizing constructor, so the invariant is pinned here.
func Test_Network4_Difference_ItemsAreNormalizedProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		source := genNetwork4.Draw(t, "source")
		other := genNetwork4.Draw(t, "other")
		for part := range source.Difference(other) {
			addr, mask := ipv4NetworkBits(part)
			require.Equal(t, addr&mask, addr, "part %v not normalized", part)
		}
	})
}

// verifies the documented peel order over the bits `d` fixed by the
// intersection but free in the source.
//
// Each part's mask grows the already-peeled set by exactly one bit
// of `d`, always the highest pending one, until all of `d` is
// covered.
func Test_Network4_Difference_PeelOrderProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		source := genNetwork4.Draw(t, "source")
		other := genNetwork4.Draw(t, "other")
		_, sourceMask := ipv4NetworkBits(source)
		intersected, ok := source.Intersection(other)
		if !ok {
			require.Equal(t, []xnetip.Network4{source}, slices.Collect(source.Difference(other)))
			return
		}
		_, intersectionMask := ipv4NetworkBits(intersected)
		d := intersectionMask &^ sourceMask
		peeled := uint32(0)
		for part := range source.Difference(other) {
			_, mask := ipv4NetworkBits(part)
			extra := mask &^ sourceMask
			newBit := extra &^ peeled
			pending := d &^ peeled
			require.Zero(t, extra&^d, "part %v adds bits outside d", part)
			require.Equal(t, peeled, extra&peeled, "part %v drops peeled bits", part)
			require.Equal(t, 1, bits.OnesCount32(newBit), "part %v adds more than one bit", part)
			require.Equal(t, uint32(1)<<(31-bits.LeadingZeros32(pending)), newBit,
				"part %v peels a non-highest pending bit", part)
			peeled = extra
		}
		require.Equal(t, d, peeled)
	})
}

// ipv4NetworkMembers lists every address of a small network by
// scattering each host index over the mask's zero bits.
//
// It is the simple oracle the brute-force membership checks loop
// over, independent of the address iterators.
func ipv4NetworkMembers(addr, mask uint32) []uint32 {
	hostBits := []uint32{}
	for bit := uint32(1); bit != 0; bit <<= 1 {
		if mask&bit == 0 {
			hostBits = append(hostBits, bit)
		}
	}
	members := []uint32{}
	for index := range 1 << len(hostBits) {
		value := addr
		for position, bit := range hostBits {
			if index&(1<<position) != 0 {
				value |= bit
			}
		}
		members = append(members, value)
	}
	return members
}

// verifies membership by brute force on small sources: the parts
// cover exactly the source members outside the other network.
func Test_Network4_Difference_BruteForceMembershipProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		source := genNetwork4.Filter(func(network xnetip.Network4) bool {
			return network.NumHostBits() <= 12
		}).Draw(t, "source")
		other := genNetwork4.Draw(t, "other")
		parts := slices.Collect(source.Difference(other))
		sourceAddr, sourceMask := ipv4NetworkBits(source)
		otherAddr, otherMask := ipv4NetworkBits(other)
		for _, member := range ipv4NetworkMembers(sourceAddr, sourceMask) {
			inOther := member&otherMask == otherAddr
			inParts := false
			for _, part := range parts {
				partAddr, partMask := ipv4NetworkBits(part)
				if member&partMask == partAddr {
					inParts = true
					break
				}
			}
			require.Equal(t, !inOther, inParts, "member %#x miscovered", member)
		}
	})
}

// verifies that consuming the sequence with a range loop allocates
// nothing.
func Test_Network4_Difference_AllocationFree(t *testing.T) {
	source := xnetip.MustParseNetwork4("0.0.0.0/0")
	other := xnetip.MustParseNetwork4("8.8.8.8/32")
	requireNoAllocs(t, func() {
		for part := range source.Difference(other) {
			networkSink = part
		}
	})
}

func BenchmarkNetwork4_Difference_UniverseMinusHost(b *testing.B) {
	source := xnetip.MustParseNetwork4("0.0.0.0/0")
	other := xnetip.MustParseNetwork4("1.2.3.4/32")
	b.ReportAllocs()
	for b.Loop() {
		for part := range source.Difference(other) {
			networkSink = part
		}
	}
}

func BenchmarkNetwork4_Difference_UniverseMinusAlternatingHost(b *testing.B) {
	source := xnetip.MustParseNetwork4("0.0.0.0/0")
	other := xnetip.MustParseNetwork4("1.2.3.4/85.85.85.85")
	b.ReportAllocs()
	for b.Loop() {
		for part := range source.Difference(other) {
			networkSink = part
		}
	}
}

// verifies that adjacency needs the same mask and exactly one
// differing masked bit, anywhere in the mask.
//
// Identical networks are not adjacent, different masks never are, and
// the differing bit may sit above the contiguous boundary — those
// siblings merge into a non-contiguous mask.
func Test_Network4_IsAdjacent_ContiguousAndBoundary(t *testing.T) {
	cases := []struct {
		name  string
		left  xnetip.Network4
		right xnetip.Network4
		want  bool
	}{
		{name: "contiguous siblings", left: xnetip.MustParseNetwork4("192.168.0.0/24"), right: xnetip.MustParseNetwork4("192.168.1.0/24"), want: true},
		{name: "contiguous siblings reversed", left: xnetip.MustParseNetwork4("192.168.1.0/24"), right: xnetip.MustParseNetwork4("192.168.0.0/24"), want: true},
		{name: "identical", left: xnetip.MustParseNetwork4("192.168.0.0/24"), right: xnetip.MustParseNetwork4("192.168.0.0/24"), want: false},
		{name: "different masks", left: xnetip.MustParseNetwork4("192.168.0.0/24"), right: xnetip.MustParseNetwork4("192.168.0.0/16"), want: false},
		{name: "same mask, two differing bits", left: xnetip.MustParseNetwork4("192.168.0.0/24"), right: xnetip.MustParseNetwork4("192.168.3.0/24"), want: false},
		{name: "one differing bit above the boundary", left: xnetip.MustParseNetwork4("10.0.0.0/24"), right: xnetip.MustParseNetwork4("10.0.2.0/24"), want: true},
		{name: "adjacent at the top mask bit", left: xnetip.MustParseNetwork4("0.0.0.0/2"), right: xnetip.MustParseNetwork4("128.0.0.0/2"), want: true},
		{name: "host routes differing in bit 0", left: xnetip.MustParseNetwork4("192.168.0.0/32"), right: xnetip.MustParseNetwork4("192.168.0.1/32"), want: true},
		{name: "host routes differing in bit 31", left: xnetip.MustParseNetwork4("0.0.0.1/32"), right: xnetip.MustParseNetwork4("128.0.0.1/32"), want: true},
		{name: "host routes differing in two bits", left: xnetip.MustParseNetwork4("10.0.0.0/32"), right: xnetip.MustParseNetwork4("10.0.0.3/32"), want: false},
		{name: "default route with itself", left: xnetip.MustParseNetwork4("0.0.0.0/0"), right: xnetip.MustParseNetwork4("0.0.0.0/0"), want: false},
		{name: "all-ones host and its bit-31 neighbour", left: xnetip.MustParseNetwork4("255.255.255.255/32"), right: xnetip.MustParseNetwork4("127.255.255.255/32"), want: true},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			require.Equal(t, testCase.want, testCase.left.IsAdjacent(testCase.right))
		})
	}
}

// verifies that adjacency of non-contiguous networks counts only
// masked bits, wherever the differing bit sits in the pattern.
func Test_Network4_IsAdjacent_NonContiguousMasks(t *testing.T) {
	cases := []struct {
		name  string
		left  xnetip.Network4
		right xnetip.Network4
		want  bool
	}{
		{name: "differing in a masked middle bit", left: xnetip.MustParseNetwork4("10.0.0.1/255.255.0.255"), right: xnetip.MustParseNetwork4("10.1.0.1/255.255.0.255"), want: true},
		{name: "differing in a masked middle bit reversed", left: xnetip.MustParseNetwork4("10.1.0.1/255.255.0.255"), right: xnetip.MustParseNetwork4("10.0.0.1/255.255.0.255"), want: true},
		{name: "differing in the lowest masked bit", left: xnetip.MustParseNetwork4("10.0.0.0/255.255.0.255"), right: xnetip.MustParseNetwork4("10.0.0.1/255.255.0.255"), want: true},
		{name: "same pattern mask, two differing bits", left: xnetip.MustParseNetwork4("10.0.0.1/255.255.0.255"), right: xnetip.MustParseNetwork4("10.3.0.1/255.255.0.255"), want: false},
		{name: "pattern vs contiguous of equal popcount", left: xnetip.MustParseNetwork4("10.0.0.1/255.255.0.255"), right: xnetip.MustParseNetwork4("10.0.0.0/255.255.255.0"), want: false},
		{name: "alternating mask, one differing bit", left: xnetip.MustParseNetwork4("170.0.170.0/170.85.170.85"), right: xnetip.MustParseNetwork4("170.0.170.1/170.85.170.85"), want: true},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			require.Equal(t, testCase.want, testCase.left.IsAdjacent(testCase.right))
		})
	}
}

// verifies that adjacency is symmetric, irreflexive and impossible
// across different masks.
func Test_Network4_IsAdjacent_SymmetryAndMaskProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		left := genNetwork4.Draw(t, "left")
		right := genNetwork4.Draw(t, "right")
		require.Equal(t, left.IsAdjacent(right), right.IsAdjacent(left))
		require.False(t, left.IsAdjacent(left))
		if left.Mask() != right.Mask() {
			require.False(t, left.IsAdjacent(right))
		}
	})
}

// verifies that flipping one masked address bit always produces an
// adjacent sibling.
//
// Random pairs are almost never adjacent, so the positive case is
// constructed: any network with a non-empty mask is adjacent to its
// image under a single masked-bit flip.
func Test_Network4_IsAdjacent_ConstructedSiblingProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		network := genNetwork4.Draw(t, "network")
		maskBytes := network.Mask().As4()
		maskBits := binary.BigEndian.Uint32(maskBytes[:])
		if maskBits == 0 {
			return
		}
		setBits := []int{}
		for bit := range 32 {
			if maskBits&(1<<bit) != 0 {
				setBits = append(setBits, bit)
			}
		}
		bit := rapid.SampledFrom(setBits).Draw(t, "bit")
		addrBytes := network.Addr().As4()
		addrBits := binary.BigEndian.Uint32(addrBytes[:])
		sibling, err := xnetip.Network4From(
			netipAddrFrom4Bits(addrBits^uint32(1)<<bit),
			netipAddrFrom4Bits(maskBits),
		)
		require.NoError(t, err)
		require.True(t, network.IsAdjacent(sibling))
		require.True(t, sibling.IsAdjacent(network))
	})
}

// verifies that the predicate allocates nothing.
func Test_Network4_IsAdjacent_AllocationFree(t *testing.T) {
	left := xnetip.MustParseNetwork4("10.0.0.1/255.255.0.255")
	right := xnetip.MustParseNetwork4("10.1.0.1/255.255.0.255")
	requireNoAllocs(t, func() { okSink = left.IsAdjacent(right) })
}

func BenchmarkNetwork4_IsAdjacent_Contiguous(b *testing.B) {
	left := xnetip.MustParseNetwork4("192.168.0.0/24")
	right := xnetip.MustParseNetwork4("192.168.1.0/24")
	b.ReportAllocs()
	for b.Loop() {
		okSink = left.IsAdjacent(right)
	}
}

func BenchmarkNetwork4_IsAdjacent_NonAdjacent(b *testing.B) {
	left := xnetip.MustParseNetwork4("192.168.0.0/24")
	right := xnetip.MustParseNetwork4("192.168.3.0/24")
	b.ReportAllocs()
	for b.Loop() {
		okSink = left.IsAdjacent(right)
	}
}

func BenchmarkNetwork4_IsAdjacent_NonContiguous(b *testing.B) {
	left := xnetip.MustParseNetwork4("10.0.0.1/255.255.0.255")
	right := xnetip.MustParseNetwork4("10.1.0.1/255.255.0.255")
	b.ReportAllocs()
	for b.Loop() {
		okSink = left.IsAdjacent(right)
	}
}

// verifies that exactly the masks made of leading ones followed by
// zeros are contiguous, the all-zero and all-ones masks included.
func Test_Network4_IsContiguous_LeadingOnesRunOnly(t *testing.T) {
	cases := []struct {
		name    string
		network xnetip.Network4
		want    bool
	}{
		{name: "universe /0", network: mustNetwork4(t, "0.0.0.0", "0.0.0.0"), want: true},
		{name: "/19", network: mustNetwork4(t, "213.180.192.0", "255.255.224.0"), want: true},
		{name: "/24", network: mustNetwork4(t, "192.168.0.0", "255.255.255.0"), want: true},
		{name: "single leading bit /1", network: mustNetwork4(t, "128.0.0.0", "128.0.0.0"), want: true},
		{name: "/31", network: mustNetwork4(t, "10.0.0.2", "255.255.255.254"), want: true},
		{name: "host route /32", network: mustNetwork4(t, "10.0.0.1", "255.255.255.255"), want: true},
		{name: "zero value is the universe", network: xnetip.Network4{}, want: true},
		{name: "top bit clear, rest set", network: mustNetwork4(t, "0.0.0.0", "127.255.255.255"), want: false},
		{name: "trailing-only bits", network: mustNetwork4(t, "0.0.0.1", "0.0.0.255"), want: false},
		{name: "hole in the third octet", network: mustNetwork4(t, "213.180.0.192", "255.255.0.255"), want: false},
		{name: "two runs", network: mustNetwork4(t, "192.168.0.1", "255.0.255.0"), want: false},
		{name: "leading zero octet", network: mustNetwork4(t, "0.0.0.0", "0.255.255.255"), want: false},
		{name: "alternating", network: mustNetwork4(t, "170.85.170.85", "170.85.170.85"), want: false},
		{name: "single isolated bit in the middle", network: mustNetwork4(t, "0.0.0.0", "0.0.1.0"), want: false},
		{name: "bench non-contiguous shape", network: mustNetwork4(t, "192.168.0.1", "255.255.0.255"), want: false},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			require.Equal(t, testCase.want, testCase.network.IsContiguous())
		})
	}
}

// verifies that the predicate agrees with the brute-force bit scan:
// contiguous means no one bit after a zero bit, top to bottom.
func Test_Network4_IsContiguous_MatchesBitScanProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		network := genNetwork4.Draw(t, "network")
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
func Test_Network4_IsContiguous_PrefixMasksAreContiguousProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		addr := genNetipAddr4.Draw(t, "addr")
		bits := rapid.IntRange(0, 32).Draw(t, "bits")
		network, err := xnetip.Network4FromCIDR(addr, bits)
		require.NoError(t, err)
		require.True(t, network.IsContiguous())
		require.Equal(t, bits, netip.PrefixFrom(network.Addr(), bits).Bits())
	})
}

// verifies that clearing a non-final bit of a leading run of two or
// more ones breaks contiguity: some run bit stays below the hole.
func Test_Network4_IsContiguous_HolePunchedMaskProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		prefix := rapid.IntRange(2, 32).Draw(t, "prefix")
		hole := rapid.IntRange(0, prefix-2).Draw(t, "hole")
		maskBits := ^uint32(0) << (32 - prefix) &^ (uint32(1) << (31 - hole))
		network, err := xnetip.Network4From(
			genNetipAddr4.Draw(t, "addr"),
			netipAddrFrom4Bits(maskBits),
		)
		require.NoError(t, err)
		require.False(t, network.IsContiguous())
	})
}

// verifies that the predicate allocates nothing.
func Test_Network4_IsContiguous_AllocationFree(t *testing.T) {
	network := mustNetwork4(t, "192.168.0.0", "255.255.0.0")
	requireNoAllocs(t, func() { okSink = network.IsContiguous() })
}

func BenchmarkNetwork4_IsContiguous_Contiguous(b *testing.B) {
	network := mustNetwork4(b, "192.168.0.0", "255.255.0.0")
	b.ReportAllocs()
	for b.Loop() {
		okSink = network.IsContiguous()
	}
}

func BenchmarkNetwork4_IsContiguous_NonContiguous(b *testing.B) {
	network := mustNetwork4(b, "192.168.0.1", "255.255.0.255")
	b.ReportAllocs()
	for b.Loop() {
		okSink = network.IsContiguous()
	}
}

// verifies that a contiguous mask reports its leading-ones run length,
// from the universe through the host route.
func Test_Network4_PrefixLen_LeadingOnesRunLength(t *testing.T) {
	cases := []struct {
		name    string
		network xnetip.Network4
		want    int
	}{
		{name: "/24", network: mustNetwork4(t, "192.168.1.0", "255.255.255.0"), want: 24},
		{name: "host route /32", network: mustNetwork4(t, "192.168.1.1", "255.255.255.255"), want: 32},
		{name: "universe /0", network: mustNetwork4(t, "0.0.0.0", "0.0.0.0"), want: 0},
		{name: "single leading bit /1", network: mustNetwork4(t, "128.0.0.0", "128.0.0.0"), want: 1},
		{name: "/31", network: mustNetwork4(t, "10.0.0.2", "255.255.255.254"), want: 31},
		{name: "zero value is the universe", network: xnetip.Network4{}, want: 0},
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
func Test_Network4_PrefixLen_NonContiguousHasNone(t *testing.T) {
	cases := []struct {
		name    string
		network xnetip.Network4
	}{
		{name: "hole in the middle", network: mustNetwork4(t, "10.0.0.1", "255.0.0.255")},
		{name: "no leading run", network: mustNetwork4(t, "0.0.0.1", "0.0.0.255")},
		{name: "leading zero then ones", network: mustNetwork4(t, "0.0.0.0", "127.255.255.255")},
		{name: "mask 255.0.255.0 ignores the second octet", network: mustNetwork4(t, "192.0.1.0", "255.0.255.0")},
		{name: "alternating", network: mustNetwork4(t, "170.85.170.85", "170.85.170.85")},
		{name: "two runs", network: mustNetwork4(t, "10.0.0.0", "255.255.0.255")},
		{name: "trailing ones only", network: mustNetwork4(t, "0.0.0.1", "0.0.0.1")},
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
func Test_Network4_PrefixLen_SomeIffContiguousProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		network := genNetwork4.Draw(t, "network")
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
func Test_Network4_PrefixLen_RoundTripsCIDRProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		addr := genNetipAddr4.Draw(t, "addr")
		cidr := rapid.IntRange(0, 32).Draw(t, "cidr")
		network, err := xnetip.Network4FromCIDR(addr, cidr)
		require.NoError(t, err)
		prefix, ok := network.PrefixLen()
		require.True(t, ok)
		require.Equal(t, cidr, prefix)
	})
}

// verifies that for a contiguous mask the reported length is the one
// net/netip accepts and reports back for the same address.
func Test_Network4_PrefixLen_MatchesNetipBitsProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		network := genNetwork4.Draw(t, "network")
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
func Test_Network4_PrefixLen_AllocationFree(t *testing.T) {
	contiguous := mustNetwork4(t, "192.168.0.0", "255.255.0.0")
	nonContiguous := mustNetwork4(t, "192.168.0.1", "255.255.0.255")
	requireNoAllocs(t, func() { intSink, okSink = contiguous.PrefixLen() })
	requireNoAllocs(t, func() { intSink, okSink = nonContiguous.PrefixLen() })
}

func BenchmarkNetwork4_PrefixLen_Contiguous(b *testing.B) {
	network := mustNetwork4(b, "192.168.0.0", "255.255.0.0")
	b.ReportAllocs()
	for b.Loop() {
		intSink, okSink = network.PrefixLen()
	}
}

func BenchmarkNetwork4_PrefixLen_NonContiguous(b *testing.B) {
	network := mustNetwork4(b, "192.168.0.1", "255.255.0.255")
	b.ReportAllocs()
	for b.Loop() {
		intSink, okSink = network.PrefixLen()
	}
}

func BenchmarkNetwork4_PrefixLen_Mixed(b *testing.B) {
	// A 50/50 contiguous/non-contiguous rotation exercises both
	// outcomes of the contiguity check within one measurement.
	networks := []xnetip.Network4{
		mustNetwork4(b, "192.168.0.0", "255.255.0.0"),
		mustNetwork4(b, "192.168.0.1", "255.255.0.255"),
		mustNetwork4(b, "10.0.0.0", "255.0.0.0"),
		mustNetwork4(b, "10.0.0.1", "255.0.0.255"),
	}
	b.ReportAllocs()
	for b.Loop() {
		for _, network := range networks {
			intSink, okSink = network.PrefixLen()
		}
	}
}

// verifies that a contiguous network prints as address/prefix with the
// suffix always present: a host route keeps /32 and the universe /0.
func Test_Network4_String_ContiguousUsesPrefixForm(t *testing.T) {
	cases := []struct {
		name    string
		network xnetip.Network4
		want    string
	}{
		{name: "host route keeps /32", network: mustNetwork4(t, "127.0.0.1", "255.255.255.255"), want: "127.0.0.1/32"},
		{name: "CIDR", network: mustNetwork4(t, "10.0.0.0", "255.255.255.0"), want: "10.0.0.0/24"},
		{name: "universe", network: mustNetwork4(t, "0.0.0.0", "0.0.0.0"), want: "0.0.0.0/0"},
		{name: "zero value", network: xnetip.Network4{}, want: "0.0.0.0/0"},
		{name: "all ones", network: mustNetwork4(t, "255.255.255.255", "255.255.255.255"), want: "255.255.255.255/32"},
		{name: "normalized before print", network: mustNetwork4(t, "10.0.0.1", "255.0.0.0"), want: "10.0.0.0/8"},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			require.Equal(t, testCase.want, testCase.network.String())
		})
	}
}

// verifies that a non-contiguous network prints its mask in dotted
// decimal, because no prefix length can describe it.
func Test_Network4_String_NonContiguousUsesDottedMask(t *testing.T) {
	cases := []struct {
		name    string
		network xnetip.Network4
		want    string
	}{
		{name: "geo-style", network: mustNetwork4(t, "10.0.1.0", "255.0.255.0"), want: "10.0.1.0/255.0.255.0"},
		{name: "two-run", network: mustNetwork4(t, "192.168.0.1", "255.255.0.255"), want: "192.168.0.1/255.255.0.255"},
		{name: "alternating", network: mustNetwork4(t, "170.85.170.85", "170.85.170.85"), want: "170.85.170.85/170.85.170.85"},
		{name: "trailing ones only", network: mustNetwork4(t, "0.0.0.1", "0.0.0.255"), want: "0.0.0.1/0.0.0.255"},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			require.Equal(t, testCase.want, testCase.network.String())
		})
	}
}

// verifies that appending writes after the caller's bytes and leaves
// them intact.
func Test_Network4_AppendTo_KeepsExistingBytes(t *testing.T) {
	network := mustNetwork4(t, "10.0.0.0", "255.255.255.0")
	require.Equal(t, "net=10.0.0.0/24", string(network.AppendTo([]byte("net="))))
}

// verifies that a buffer with enough capacity is extended in place,
// without growing to a new backing array.
func Test_Network4_AppendTo_ReusesSizedBuffer(t *testing.T) {
	network := mustNetwork4(t, "10.0.0.0", "255.255.255.0")
	buffer := make([]byte, 0, 32)
	extended := network.AppendTo(buffer)
	require.Equal(t, "10.0.0.0/24", string(extended))
	require.Equal(t, cap(buffer), cap(extended))
}

// verifies that the text splits at a single slash into the network
// address and the decimal prefix length or the dotted mask.
func Test_Network4_String_ShapeProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		network := genNetwork4.Draw(t, "network")
		text := network.String()
		require.Equal(t, 1, strings.Count(text, "/"))
		slash := strings.IndexByte(text, '/')
		addr, err := netip.ParseAddr(text[:slash])
		require.NoError(t, err)
		require.True(t, addr.Is4())
		require.Equal(t, network.Addr(), addr)
		if prefix, ok := network.PrefixLen(); ok {
			require.Equal(t, strconv.Itoa(prefix), text[slash+1:])
		} else {
			require.Equal(t, network.Mask().String(), text[slash+1:])
		}
	})
}

// verifies that appending to an empty buffer yields the same bytes the
// string form has, and that drawn buffer content survives untouched.
func Test_Network4_AppendTo_MatchesStringProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		network := genNetwork4.Draw(t, "network")
		prefix := rapid.SliceOf(rapid.Byte()).Draw(t, "buffer")
		require.Equal(t, network.String(), string(network.AppendTo(nil)))
		extended := network.AppendTo(slices.Clone(prefix))
		require.True(t, bytes.Equal(prefix, extended[:len(prefix)]))
		require.Equal(t, network.String(), string(extended[len(prefix):]))
	})
}

// verifies that the contiguous form is byte-identical to the netip
// prefix rendering of the same network.
func Test_Network4_String_MatchesNetipPrefixProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		network := genNetwork4.Draw(t, "network")
		prefix, ok := network.PrefixLen()
		if !ok {
			return
		}
		require.Equal(t, netip.PrefixFrom(network.Addr(), prefix).String(), network.String())
	})
}

// verifies that appending into a buffer with enough capacity allocates
// nothing, whatever the mask's shape.
func Test_Network4_AppendTo_AllocationFree(t *testing.T) {
	contiguous := mustNetwork4(t, "10.0.0.0", "255.255.255.0")
	nonContiguous := mustNetwork4(t, "192.168.0.1", "255.255.0.255")
	buffer := make([]byte, 0, 64)
	requireNoAllocs(t, func() { bytesSink = contiguous.AppendTo(buffer[:0]) })
	requireNoAllocs(t, func() { bytesSink = nonContiguous.AppendTo(buffer[:0]) })
}

// verifies that rendering to a string costs exactly the one string
// conversion, pinning any formatting regression that adds more.
func Test_Network4_String_SingleAllocation(t *testing.T) {
	contiguous := mustNetwork4(t, "10.0.0.0", "255.255.255.0")
	nonContiguous := mustNetwork4(t, "192.168.0.1", "255.255.0.255")
	require.Equal(t, 1, int(testing.AllocsPerRun(100, func() { stringSink = contiguous.String() })))
	require.Equal(t, 1, int(testing.AllocsPerRun(100, func() { stringSink = nonContiguous.String() })))
}

func BenchmarkNetwork4_String_CIDR(b *testing.B) {
	network := mustNetwork4(b, "10.0.0.0", "255.0.0.0")
	b.ReportAllocs()
	for b.Loop() {
		stringSink = network.String()
	}
}

func BenchmarkNetwork4_String_NonContiguous(b *testing.B) {
	network := mustNetwork4(b, "192.168.0.1", "255.255.0.255")
	b.ReportAllocs()
	for b.Loop() {
		stringSink = network.String()
	}
}

func BenchmarkNetwork4_AppendTo_CIDR(b *testing.B) {
	network := mustNetwork4(b, "10.0.0.0", "255.0.0.0")
	buffer := make([]byte, 0, 32)
	b.ReportAllocs()
	for b.Loop() {
		bytesSink = network.AppendTo(buffer[:0])
	}
}

// verifies that the parser accepts the bare, CIDR and dotted-mask forms
// and normalizes the address under the mask in every one of them.
func Test_ParseNetwork4_AcceptsAllForms(t *testing.T) {
	cases := []struct {
		name     string
		input    string
		wantAddr string
		wantMask string
	}{
		{name: "bare address is a host route", input: "127.0.0.1", wantAddr: "127.0.0.1", wantMask: "255.255.255.255"},
		{name: "CIDR normalizes host bits", input: "192.168.0.1/24", wantAddr: "192.168.0.0", wantMask: "255.255.255.0"},
		{name: "explicit /32 keeps the address", input: "192.168.0.1/32", wantAddr: "192.168.0.1", wantMask: "255.255.255.255"},
		{name: "dotted contiguous mask normalizes", input: "192.168.0.1/255.255.255.0", wantAddr: "192.168.0.0", wantMask: "255.255.255.0"},
		{name: "/0 is the universe", input: "0.0.0.0/0", wantAddr: "0.0.0.0", wantMask: "0.0.0.0"},
		{name: "/0 normalizes everything away", input: "10.1.2.3/0", wantAddr: "0.0.0.0", wantMask: "0.0.0.0"},
		{name: "/1 keeps the top bit", input: "128.0.0.0/1", wantAddr: "128.0.0.0", wantMask: "128.0.0.0"},
		{name: "/31 keeps all but the last bit", input: "10.0.0.2/31", wantAddr: "10.0.0.2", wantMask: "255.255.255.254"},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			network, err := xnetip.ParseNetwork4(testCase.input)
			require.NoError(t, err)
			require.Equal(t, mustNetwork4(t, testCase.wantAddr, testCase.wantMask), network)
		})
	}
}

// verifies that the universe text parses to the zero value, so the two
// spellings of "every IPv4 address" are one value.
func Test_ParseNetwork4_UniverseIsZeroValue(t *testing.T) {
	network, err := xnetip.ParseNetwork4("0.0.0.0/0")
	require.NoError(t, err)
	require.Equal(t, xnetip.Network4{}, network)
}

// verifies that the bare, CIDR and all-ones dotted-mask spellings of a
// host route parse to the same network.
func Test_ParseNetwork4_AllFormsAgreeOnHostRoute(t *testing.T) {
	bare, err := xnetip.ParseNetwork4("192.168.1.1")
	require.NoError(t, err)
	cidr, err := xnetip.ParseNetwork4("192.168.1.1/32")
	require.NoError(t, err)
	dotted, err := xnetip.ParseNetwork4("192.168.1.1/255.255.255.255")
	require.NoError(t, err)
	require.Equal(t, bare, cidr)
	require.Equal(t, bare, dotted)
}

// verifies that a digits-only suffix beyond the family limit is a
// prefix-length overflow, never a dotted-mask attempt.
func Test_ParseNetwork4_RejectsPrefixOverflow(t *testing.T) {
	cases := []struct {
		name  string
		input string
	}{
		{name: "one past the limit", input: "10.0.0.0/33"},
		{name: "far past the limit", input: "10.0.0.0/256"},
		{name: "longer than any int", input: "10.0.0.0/99999999999999999999"},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			network, err := xnetip.ParseNetwork4(testCase.input)
			require.ErrorIs(t, err, xnetip.ErrCIDROverflow)
			require.Equal(t, xnetip.Network4{}, network)
		})
	}
}

// verifies that a suffix that is neither a strict prefix length nor a
// dotted mask is rejected with the mask sentinel.
//
// The strict prefix grammar takes no sign, no leading zero and no
// trailing bytes, so each of those falls through to the mask parse
// and fails there.
func Test_ParseNetwork4_RejectsBadSuffix(t *testing.T) {
	cases := []struct {
		name  string
		input string
	}{
		{name: "leading zero in prefix", input: "10.0.0.0/08"},
		{name: "plus sign in prefix", input: "10.0.0.0/+8"},
		{name: "minus sign in prefix", input: "10.0.0.0/-8"},
		{name: "empty suffix", input: "10.0.0.1/"},
		{name: "double slash", input: "10.0.0.1//24"},
		{name: "trailing space in suffix", input: "10.0.0.1/24 "},
		{name: "trailing garbage in suffix", input: "10.0.0.1/24x"},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			network, err := xnetip.ParseNetwork4(testCase.input)
			require.ErrorIs(t, err, xnetip.ErrInvalidMask)
			require.Equal(t, xnetip.Network4{}, network)
		})
	}
}

// verifies that an IPv6 mask under an IPv4 address carries both the
// mask sentinel and the family sentinel in its chain.
func Test_ParseNetwork4_ForeignFamilyMaskKeepsBothSentinels(t *testing.T) {
	_, err := xnetip.ParseNetwork4("10.0.0.1/2001:db8::1")
	require.ErrorIs(t, err, xnetip.ErrInvalidMask)
	require.ErrorIs(t, err, xnetip.ErrAddrFamilyMismatch)
}

// verifies that text whose address part is not an IPv4 address is
// rejected with the parse sentinel and the net/netip cause in the chain.
func Test_ParseNetwork4_RejectsBadAddress(t *testing.T) {
	cases := []struct {
		name  string
		input string
	}{
		{name: "empty input", input: ""},
		{name: "lone slash", input: "/"},
		{name: "missing address", input: "/24"},
		{name: "garbage", input: "hello"},
		{name: "garbage with suffix", input: "zz/24"},
		{name: "leading whitespace", input: " 10.0.0.1/24"},
		{name: "leading-zero octet", input: "01.2.3.4/8"},
		{name: "octet overflow", input: "256.0.0.0/8"},
		{name: "three groups", input: "1.2.3/8"},
		{name: "five groups", input: "1.2.3.4.5/8"},
		{name: "port-like suffix", input: "1.2.3.4:80"},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			network, err := xnetip.ParseNetwork4(testCase.input)
			require.ErrorIs(t, err, xnetip.ErrParse)
			require.Equal(t, xnetip.Network4{}, network)
		})
	}
}

// verifies that an IPv6 address, the IPv4-mapped form included, is
// rejected with the family sentinel, not treated as an IPv4 network.
func Test_ParseNetwork4_RejectsIPv6Literal(t *testing.T) {
	cases := []struct {
		name  string
		input string
	}{
		{name: "plain IPv6", input: "2001:db8::1"},
		{name: "IPv4-mapped with prefix", input: "::ffff:10.0.0.1/120"},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			network, err := xnetip.ParseNetwork4(testCase.input)
			require.ErrorIs(t, err, xnetip.ErrAddrFamilyMismatch)
			require.Equal(t, xnetip.Network4{}, network)
		})
	}
}

// verifies that a dotted mask of any shape is accepted verbatim and the
// address bits outside it are cleared.
func Test_ParseNetwork4_NonContiguousMasks(t *testing.T) {
	cases := []struct {
		name     string
		input    string
		wantAddr string
		wantMask string
	}{
		{name: "two-run mask kept verbatim", input: "192.168.0.1/255.255.0.255", wantAddr: "192.168.0.1", wantMask: "255.255.0.255"},
		{name: "bits outside the mask cleared", input: "192.168.7.1/255.255.0.255", wantAddr: "192.168.0.1", wantMask: "255.255.0.255"},
		{name: "geo-style mask", input: "10.0.1.0/255.0.255.0", wantAddr: "10.0.1.0", wantMask: "255.0.255.0"},
		{name: "alternating mask", input: "170.85.170.85/170.85.170.85", wantAddr: "170.85.170.85", wantMask: "170.85.170.85"},
		{name: "alternating clears the complement", input: "255.255.255.255/170.85.170.85", wantAddr: "170.85.170.85", wantMask: "170.85.170.85"},
		{name: "mask with empty leading run", input: "0.0.0.1/0.0.0.255", wantAddr: "0.0.0.1", wantMask: "0.0.0.255"},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			network, err := xnetip.ParseNetwork4(testCase.input)
			require.NoError(t, err)
			require.Equal(t, mustNetwork4(t, testCase.wantAddr, testCase.wantMask), network)
		})
	}
}

// verifies that the must variant panics on invalid input instead of
// returning an error.
func Test_MustParseNetwork4_PanicsOnInvalidInput(t *testing.T) {
	require.Panics(t, func() { xnetip.MustParseNetwork4("10.0.0.0/33") })
}

// verifies that the must variant passes a valid parse through.
func Test_MustParseNetwork4_ReturnsParsedNetwork(t *testing.T) {
	network := xnetip.MustParseNetwork4("10.0.0.0/8")
	require.Equal(t, mustNetwork4(t, "10.0.0.0", "255.0.0.0"), network)
}

// verifies that every parse error names this parser and echoes the
// rejected input in quotes.
func Test_ParseNetwork4_ErrorEchoesInput(t *testing.T) {
	_, err := xnetip.ParseNetwork4("10.0.0.0/33")
	require.Error(t, err)
	require.True(t, strings.HasPrefix(err.Error(), "xnetip.ParseNetwork4("))
	require.Contains(t, err.Error(), `"10.0.0.0/33"`)
}

// verifies that parsing the string form recovers the network exactly,
// whatever the mask's shape.
func Test_ParseNetwork4_StringRoundTripProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		network := genNetwork4.Draw(t, "network")
		parsed, err := xnetip.ParseNetwork4(network.String())
		require.NoError(t, err)
		require.Equal(t, network, parsed)
	})
}

// verifies that the CIDR text form parses to the same network the CIDR
// constructor builds from the same address and length.
func Test_ParseNetwork4_CIDRFormAgreesWithConstructorProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		addr := genNetipAddr4.Draw(t, "addr")
		bits := rapid.IntRange(0, 32).Draw(t, "bits")
		constructed, err := xnetip.Network4FromCIDR(addr, bits)
		require.NoError(t, err)
		parsed, err := xnetip.ParseNetwork4(addr.String() + "/" + strconv.Itoa(bits))
		require.NoError(t, err)
		require.Equal(t, constructed, parsed)
	})
}

// verifies that the dotted-mask text form, non-contiguous masks
// included, parses like the checked constructor on the same pair.
func Test_ParseNetwork4_DottedMaskAgreesWithConstructorProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		addr := genNetipAddr4.Draw(t, "addr")
		mask := genNetipAddr4.Draw(t, "mask")
		constructed, err := xnetip.Network4From(addr, mask)
		require.NoError(t, err)
		parsed, err := xnetip.ParseNetwork4(addr.String() + "/" + mask.String())
		require.NoError(t, err)
		require.Equal(t, constructed, parsed)
	})
}

// verifies that every accepted input yields a normalized network: no
// address bit survives outside the mask, in any of the three forms.
func Test_ParseNetwork4_ResultNormalizedProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		addr := genNetipAddr4.Draw(t, "addr")
		var input string
		switch rapid.IntRange(0, 2).Draw(t, "form") {
		case 0:
			input = addr.String()
		case 1:
			input = addr.String() + "/" + strconv.Itoa(rapid.IntRange(0, 32).Draw(t, "bits"))
		default:
			input = addr.String() + "/" + genNetipAddr4.Draw(t, "mask").String()
		}
		network, err := xnetip.ParseNetwork4(input)
		require.NoError(t, err)
		addrBytes := network.Addr().As4()
		maskBytes := network.Mask().As4()
		for idx := range addrBytes {
			require.Equal(t, addrBytes[idx]&maskBytes[idx], addrBytes[idx], "address bit outside the mask")
		}
	})
}

// verifies that no byte string makes the parser panic, whatever it
// holds.
func Test_ParseNetwork4_NeverPanicsProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		input := string(rapid.SliceOfN(rapid.Byte(), 0, 40).Draw(t, "input"))
		networkSink, errSink = xnetip.ParseNetwork4(input)
	})
}

// verifies that on CIDR-shaped text the accept set and the parsed
// value are exactly those of the std prefix parser.
func Test_ParseNetwork4_MatchesNetipParsePrefixProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		addr := genNetipAddr4.Draw(t, "addr")
		var suffix string
		if rapid.Bool().Draw(t, "digit suffix") {
			suffix = strconv.Itoa(rapid.IntRange(0, 40).Draw(t, "bits"))
		} else {
			suffix = rapid.SampledFrom([]string{"08", "+8", "-8", "", "33", "032"}).Draw(t, "malformed suffix")
		}
		input := addr.String() + "/" + suffix
		parsed, err := xnetip.ParseNetwork4(input)
		stdPrefix, stdErr := netip.ParsePrefix(input)
		if stdErr != nil {
			require.Error(t, err)
			return
		}
		require.NoError(t, err)
		require.Equal(t, stdPrefix.Masked().Addr(), parsed.Addr())
		bits, ok := parsed.PrefixLen()
		require.True(t, ok)
		require.Equal(t, stdPrefix.Bits(), bits)
	})
}

// verifies that accepting a network allocates nothing in any of the
// three forms: the input is only ever sliced, never copied.
func Test_ParseNetwork4_AllocationFree(t *testing.T) {
	requireNoAllocs(t, func() { networkSink, errSink = xnetip.ParseNetwork4("10.0.0.0/8") })
	requireNoAllocs(t, func() { networkSink, errSink = xnetip.ParseNetwork4("10.0.0.0/255.0.255.0") })
	requireNoAllocs(t, func() { networkSink, errSink = xnetip.ParseNetwork4("10.0.0.1") })
}

func FuzzParseNetwork4(f *testing.F) {
	seeds := []string{
		"127.0.0.1", "192.168.0.1/24", "192.168.0.1/32", "192.168.0.1/255.255.255.0",
		"0.0.0.0/0", "10.1.2.3/0", "128.0.0.0/1", "10.0.0.2/31",
		"10.0.0.0/33", "10.0.0.0/256", "10.0.0.0/99999999999999999999",
		"10.0.0.0/08", "10.0.0.0/+8", "10.0.0.0/-8", "10.0.0.1/", "10.0.0.1//24",
		"10.0.0.1/24 ", "10.0.0.1/24x", "", "/", "/24", "hello", "zz/24",
		" 10.0.0.1/24", "01.2.3.4/8", "256.0.0.0/8", "1.2.3/8", "1.2.3.4.5/8",
		"1.2.3.4:80", "2001:db8::1", "::ffff:10.0.0.1/120", "10.0.0.1/2001:db8::1",
		"192.168.0.1/255.255.0.255", "192.168.7.1/255.255.0.255", "10.0.1.0/255.0.255.0",
		"170.85.170.85/170.85.170.85", "255.255.255.255/170.85.170.85", "0.0.0.1/0.0.0.255",
	}
	for _, seed := range seeds {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, input string) {
		network, err := xnetip.ParseNetwork4(input)
		if err == nil {
			back, err := xnetip.ParseNetwork4(network.String())
			if err != nil {
				t.Fatalf("round trip of %q rejected %q: %v", input, network.String(), err)
			}
			if back != network {
				t.Fatalf("round trip of %q changed the network: %v != %v", input, back, network)
			}
		}
		slash := strings.IndexByte(input, '/')
		if slash < 0 || strings.IndexByte(input[slash+1:], '/') >= 0 || !digitsOnly(input[slash+1:]) {
			return
		}
		stdPrefix, stdErr := netip.ParsePrefix(input)
		if stdErr != nil || !stdPrefix.Addr().Is4() {
			if err == nil {
				t.Fatalf("accepted %q, which std rejects or reads as IPv6", input)
			}
			return
		}
		if err != nil {
			t.Fatalf("rejected %q, which std accepts: %v", input, err)
		}
		if bits, ok := network.PrefixLen(); !ok || bits != stdPrefix.Bits() || network.Addr() != stdPrefix.Masked().Addr() {
			t.Fatalf("parsed %q as %v, std says %v", input, network, stdPrefix.Masked())
		}
	})
}

func BenchmarkParseNetwork4_CIDR(b *testing.B) {
	b.ReportAllocs()
	for b.Loop() {
		networkSink, errSink = xnetip.ParseNetwork4("10.0.0.0/8")
	}
}

func BenchmarkParseNetwork4_DottedMask(b *testing.B) {
	b.ReportAllocs()
	for b.Loop() {
		networkSink, errSink = xnetip.ParseNetwork4("10.0.0.0/255.0.0.0")
	}
}

func BenchmarkParseNetwork4_NonContiguous(b *testing.B) {
	b.ReportAllocs()
	for b.Loop() {
		networkSink, errSink = xnetip.ParseNetwork4("192.168.0.1/255.255.0.255")
	}
}

func BenchmarkParseNetwork4_Bare(b *testing.B) {
	b.ReportAllocs()
	for b.Loop() {
		networkSink, errSink = xnetip.ParseNetwork4("10.0.0.1")
	}
}

func BenchmarkParseNetwork4_Reject(b *testing.B) {
	b.ReportAllocs()
	for b.Loop() {
		networkSink, errSink = xnetip.ParseNetwork4("10.0.0.0/33")
	}
}

func BenchmarkParseNetwork4_Reject_Rendered(b *testing.B) {
	b.ReportAllocs()
	for b.Loop() {
		networkSink, errSink = xnetip.ParseNetwork4("10.0.0.0/33")
		stringSink = errSink.Error()
	}
}

// verifies that the marshaled text is the string form: prefix length
// for a contiguous mask, dotted mask otherwise, suffix always present.
func Test_Network4_MarshalText_MatchesStringForm(t *testing.T) {
	cases := []struct {
		name  string
		input string
		want  string
	}{
		{name: "contiguous prefix form", input: "192.168.0.0/24", want: "192.168.0.0/24"},
		{name: "host route keeps the suffix", input: "10.0.0.1/32", want: "10.0.0.1/32"},
		{name: "universe", input: "0.0.0.0/0", want: "0.0.0.0/0"},
		{name: "all-ones mask and address", input: "255.255.255.255/32", want: "255.255.255.255/32"},
		{name: "non-contiguous dotted form", input: "10.0.0.0/255.0.255.0", want: "10.0.0.0/255.0.255.0"},
		{name: "alternating mask", input: "170.85.170.85/170.85.170.85", want: "170.85.170.85/170.85.170.85"},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			text, err := xnetip.MustParseNetwork4(testCase.input).MarshalText()
			require.NoError(t, err)
			require.Equal(t, testCase.want, string(text))
		})
	}
}

// verifies that unmarshaling accepts every parser form, normalizes the
// address under the mask and lands the value in the receiver.
func Test_Network4_UnmarshalText_AcceptsParserForms(t *testing.T) {
	cases := []struct {
		name  string
		input string
		want  string
	}{
		{name: "prefix form", input: "10.0.0.0/8", want: "10.0.0.0/8"},
		{name: "host bits normalized", input: "10.0.0.1/8", want: "10.0.0.0/8"},
		{name: "bare address", input: "10.0.0.1", want: "10.0.0.1/32"},
		{name: "dotted non-contiguous mask", input: "192.168.0.1/255.255.0.255", want: "192.168.0.1/255.255.0.255"},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			var network xnetip.Network4
			require.NoError(t, network.UnmarshalText([]byte(testCase.input)))
			require.Equal(t, xnetip.MustParseNetwork4(testCase.want), network)
		})
	}
}

// verifies that empty text is an error, because the zero value is the
// valid universe network and must not appear out of a missing field.
func Test_Network4_UnmarshalText_EmptyTextIsError(t *testing.T) {
	network := xnetip.MustParseNetwork4("10.0.0.0/8")
	err := network.UnmarshalText(nil)
	require.ErrorIs(t, err, xnetip.ErrEmptyInput)
	require.Equal(t, xnetip.MustParseNetwork4("10.0.0.0/8"), network)
}

// verifies that a failed unmarshal reports the parser's sentinel and
// leaves the receiver untouched.
func Test_Network4_UnmarshalText_KeepsReceiverOnError(t *testing.T) {
	cases := []struct {
		name     string
		input    string
		sentinel error
	}{
		{name: "empty suffix", input: "10.0.0.0/", sentinel: xnetip.ErrInvalidMask},
		{name: "IPv6 text", input: "2001:db8::/32", sentinel: xnetip.ErrAddrFamilyMismatch},
		{name: "prefix overflow", input: "10.0.0.0/33", sentinel: xnetip.ErrCIDROverflow},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			network := xnetip.MustParseNetwork4("192.168.0.0/24")
			err := network.UnmarshalText([]byte(testCase.input))
			require.ErrorIs(t, err, testCase.sentinel)
			require.Equal(t, xnetip.MustParseNetwork4("192.168.0.0/24"), network)
		})
	}
}

// verifies that a struct field round-trips through JSON as its text
// form, non-contiguous masks included.
func Test_Network4_MarshalText_JSONStructRoundTrip(t *testing.T) {
	type wrapper struct {
		N xnetip.Network4
	}
	cases := []struct {
		name     string
		network  string
		wantJSON string
	}{
		{name: "contiguous", network: "10.0.0.0/8", wantJSON: `{"N":"10.0.0.0/8"}`},
		{name: "non-contiguous", network: "10.0.0.0/255.0.255.0", wantJSON: `{"N":"10.0.0.0/255.0.255.0"}`},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			value := wrapper{N: xnetip.MustParseNetwork4(testCase.network)}
			encoded, err := json.Marshal(value)
			require.NoError(t, err)
			require.Equal(t, testCase.wantJSON, string(encoded))
			var decoded wrapper
			require.NoError(t, json.Unmarshal(encoded, &decoded))
			require.Equal(t, value, decoded)
		})
	}
}

// verifies that the type works as a JSON map key, which encoding/json
// routes through the text marshaler pair.
func Test_Network4_MarshalText_JSONMapKeyRoundTrip(t *testing.T) {
	value := map[xnetip.Network4]int{xnetip.MustParseNetwork4("10.0.0.0/8"): 1}
	encoded, err := json.Marshal(value)
	require.NoError(t, err)
	require.Equal(t, `{"10.0.0.0/8":1}`, string(encoded))
	var decoded map[xnetip.Network4]int
	require.NoError(t, json.Unmarshal(encoded, &decoded))
	require.Equal(t, value, decoded)
}

// verifies that unmarshaling the marshaled text recovers the network
// exactly, and that the text is byte-identical to the string form.
func Test_Network4_MarshalText_RoundTripProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		network := genNetwork4.Draw(t, "network")
		text, err := network.MarshalText()
		require.NoError(t, err)
		require.Equal(t, []byte(network.String()), text)
		var back xnetip.Network4
		require.NoError(t, back.UnmarshalText(text))
		require.Equal(t, network, back)
	})
}

// verifies that a JSON struct round trip preserves the network for
// every mask shape.
func Test_Network4_MarshalText_JSONRoundTripProperty(t *testing.T) {
	type wrapper struct {
		N xnetip.Network4
	}
	rapid.Check(t, func(t *rapid.T) {
		value := wrapper{N: genNetwork4.Draw(t, "network")}
		encoded, err := json.Marshal(value)
		require.NoError(t, err)
		var decoded wrapper
		require.NoError(t, json.Unmarshal(encoded, &decoded))
		require.Equal(t, value, decoded)
	})
}

// verifies that on contiguous networks the marshaled text is
// byte-identical to the netip prefix marshaling of the same network.
func Test_Network4_MarshalText_MatchesNetipPrefixProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		network := genNetwork4.Draw(t, "network")
		bits, ok := network.PrefixLen()
		if !ok {
			return
		}
		stdText, err := netip.PrefixFrom(network.Addr(), bits).MarshalText()
		require.NoError(t, err)
		text, err := network.MarshalText()
		require.NoError(t, err)
		require.Equal(t, stdText, text)
	})
}

// verifies the deliberate divergence from std: empty text unmarshals
// into a zero netip prefix but is an error here.
//
// The zero netip prefix is invalid and safe to produce, while the zero
// network here is the whole IPv4 universe.
func Test_Network4_UnmarshalText_EmptyTextDivergesFromNetip(t *testing.T) {
	var stdPrefix netip.Prefix
	require.NoError(t, stdPrefix.UnmarshalText(nil))
	var network xnetip.Network4
	require.Error(t, network.UnmarshalText(nil))
}

// verifies that marshaling allocates exactly the returned slice,
// whatever the mask's shape.
func Test_Network4_MarshalText_SingleAllocation(t *testing.T) {
	contiguous := xnetip.MustParseNetwork4("10.0.0.0/8")
	nonContiguous := xnetip.MustParseNetwork4("10.0.0.0/255.0.255.0")
	require.Equal(t, 1, int(testing.AllocsPerRun(100, func() { bytesSink, errSink = contiguous.MarshalText() })))
	require.Equal(t, 1, int(testing.AllocsPerRun(100, func() { bytesSink, errSink = nonContiguous.MarshalText() })))
}

// verifies that a valid IPv4 netip.Prefix converts into the network
// with the same address set, host bits cleared.
func Test_Network4FromPrefix_ConvertsValidPrefixes(t *testing.T) {
	cases := []struct {
		name   string
		prefix netip.Prefix
		want   xnetip.Network4
	}{
		{
			name:   "already masked /8",
			prefix: netip.MustParsePrefix("10.0.0.0/8"),
			want:   xnetip.MustParseNetwork4("10.0.0.0/8"),
		},
		{
			name:   "host bits cleared",
			prefix: netip.MustParsePrefix("10.1.2.3/8"),
			want:   xnetip.MustParseNetwork4("10.0.0.0/8"),
		},
		{
			name:   "/0 is the zero value",
			prefix: netip.MustParsePrefix("0.0.0.0/0"),
			want:   xnetip.Network4{},
		},
		{
			name:   "host route /32",
			prefix: netip.MustParsePrefix("10.0.0.1/32"),
			want:   xnetip.MustParseNetwork4("10.0.0.1/32"),
		},
		{
			name:   "unmasked PrefixFrom input",
			prefix: netip.PrefixFrom(netip.MustParseAddr("192.168.1.7"), 24),
			want:   xnetip.MustParseNetwork4("192.168.1.0/24"),
		},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			network, ok := xnetip.Network4FromPrefix(testCase.prefix)
			require.True(t, ok)
			require.Equal(t, testCase.want, network)
		})
	}
}

// verifies that the invalid zero prefix and any prefix whose address
// is not Is4, the IPv4-mapped form included, are rejected.
func Test_Network4FromPrefix_RejectsInvalidAndForeignFamily(t *testing.T) {
	cases := []struct {
		name   string
		prefix netip.Prefix
	}{
		{name: "invalid zero prefix", prefix: netip.Prefix{}},
		{name: "IPv6 prefix", prefix: netip.MustParsePrefix("2001:db8::/32")},
		{name: "IPv4-mapped prefix is IPv6", prefix: netip.MustParsePrefix("::ffff:10.0.0.0/104")},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			network, ok := xnetip.Network4FromPrefix(testCase.prefix)
			require.False(t, ok)
			require.Equal(t, xnetip.Network4{}, network)
		})
	}
}

// verifies that a contiguous network converts to the already-masked
// netip.Prefix carrying the same address set.
func Test_Network4_Prefix_ContiguousForms(t *testing.T) {
	cases := []struct {
		name    string
		network xnetip.Network4
		want    netip.Prefix
	}{
		{
			name:    "/24",
			network: xnetip.MustParseNetwork4("192.168.0.0/24"),
			want:    netip.MustParsePrefix("192.168.0.0/24"),
		},
		{
			name:    "universe /0",
			network: xnetip.MustParseNetwork4("0.0.0.0/0"),
			want:    netip.MustParsePrefix("0.0.0.0/0"),
		},
		{
			name:    "host route /32 is a single IP",
			network: xnetip.MustParseNetwork4("10.0.0.1/32"),
			want:    netip.MustParsePrefix("10.0.0.1/32"),
		},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			prefix, ok := testCase.network.Prefix()
			require.True(t, ok)
			require.Equal(t, testCase.want, prefix)
			require.Equal(t, prefix.Masked(), prefix)
		})
	}
	singleIP, ok := xnetip.MustParseNetwork4("10.0.0.1/32").Prefix()
	require.True(t, ok)
	require.True(t, singleIP.IsSingleIP())
}

// verifies that a non-contiguous mask has no prefix form and answers
// the invalid zero netip.Prefix.
func Test_Network4_Prefix_NonContiguousHasNone(t *testing.T) {
	cases := []struct {
		name    string
		network xnetip.Network4
	}{
		{name: "two runs", network: xnetip.MustParseNetwork4("10.0.0.0/255.0.255.0")},
		{name: "alternating", network: xnetip.MustParseNetwork4("170.85.170.85/170.85.170.85")},
		{name: "single low bit", network: xnetip.MustParseNetwork4("0.0.0.0/0.0.0.1")},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			prefix, ok := testCase.network.Prefix()
			require.False(t, ok)
			require.Equal(t, netip.Prefix{}, prefix)
		})
	}
}

// verifies that any valid IPv4 prefix converts and converts back to
// its masked self, with the result normalized and contiguous.
func Test_Network4FromPrefix_RoundTripProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		stdPrefix := genIPv4Prefix.Draw(t, "prefix")
		network, ok := xnetip.Network4FromPrefix(stdPrefix)
		require.True(t, ok)
		require.True(t, network.IsContiguous())
		require.Equal(t, stdPrefix.Masked().Addr(), network.Addr())
		back, ok := network.Prefix()
		require.True(t, ok)
		require.Equal(t, stdPrefix.Masked(), back)
	})
}

// verifies that a prefix form exists exactly for contiguous masks,
// whatever the drawn mask shape.
func Test_Network4_Prefix_SomeIffContiguousProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		network := genNetwork4.Draw(t, "network")
		prefix, ok := network.Prefix()
		require.Equal(t, network.IsContiguous(), ok)
		if !ok {
			require.Equal(t, netip.Prefix{}, prefix)
		}
	})
}

// verifies that a contiguous network survives the round trip through
// netip.Prefix unchanged.
func Test_Network4_Prefix_RoundTripProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		network := genNetwork4.Draw(t, "network")
		stdPrefix, ok := network.Prefix()
		if !ok {
			return
		}
		back, ok := xnetip.Network4FromPrefix(stdPrefix)
		require.True(t, ok)
		require.Equal(t, network, back)
	})
}

// verifies that the converted prefix length agrees with the network's
// own prefix length, the net/netip view of the same mask.
func Test_Network4_Prefix_BitsMatchPrefixLenProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		network := genNetwork4.Draw(t, "network")
		stdPrefix, ok := network.Prefix()
		if !ok {
			return
		}
		bits, bitsOk := network.PrefixLen()
		require.True(t, bitsOk)
		require.Equal(t, bits, stdPrefix.Bits())
	})
}

// verifies that both conversion directions allocate nothing on any
// outcome.
func Test_Network4FromPrefix_AllocationFree(t *testing.T) {
	valid := netip.MustParsePrefix("10.0.0.0/8")
	foreign := netip.MustParsePrefix("2001:db8::/32")
	requireNoAllocs(t, func() { networkSink, okSink = xnetip.Network4FromPrefix(valid) })
	requireNoAllocs(t, func() { networkSink, okSink = xnetip.Network4FromPrefix(foreign) })
}

// verifies that converting out to a netip.Prefix allocates nothing,
// whatever the mask's shape.
func Test_Network4_Prefix_AllocationFree(t *testing.T) {
	contiguous := xnetip.MustParseNetwork4("192.168.0.0/24")
	nonContiguous := xnetip.MustParseNetwork4("10.0.0.0/255.0.255.0")
	requireNoAllocs(t, func() { prefixSink, okSink = contiguous.Prefix() })
	requireNoAllocs(t, func() { prefixSink, okSink = nonContiguous.Prefix() })
}

// verifies that the greatest member of a contiguous network is its
// broadcast address, through the default-route and host-route extremes.
func Test_Network4_LastAddr_ContiguousBroadcast(t *testing.T) {
	cases := []struct {
		name    string
		network xnetip.Network4
		want    netip.Addr
	}{
		{name: "/24 broadcast", network: xnetip.MustParseNetwork4("192.168.1.0/24"), want: netip.MustParseAddr("192.168.1.255")},
		{name: "/24 broadcast in 10/8 space", network: xnetip.MustParseNetwork4("10.0.0.0/24"), want: netip.MustParseAddr("10.0.0.255")},
		{name: "/16 broadcast", network: xnetip.MustParseNetwork4("172.16.0.0/16"), want: netip.MustParseAddr("172.16.255.255")},
		{name: "/8 broadcast", network: xnetip.MustParseNetwork4("127.0.0.0/8"), want: netip.MustParseAddr("127.255.255.255")},
		{name: "host route is its own last address", network: xnetip.MustParseNetwork4("10.0.0.1/32"), want: netip.MustParseAddr("10.0.0.1")},
		{name: "all-ones host route", network: xnetip.MustParseNetwork4("255.255.255.255/32"), want: netip.MustParseAddr("255.255.255.255")},
		{name: "default route ends at all ones", network: xnetip.MustParseNetwork4("0.0.0.0/0"), want: netip.MustParseAddr("255.255.255.255")},
		{name: "zero value is the default route", network: xnetip.Network4{}, want: netip.MustParseAddr("255.255.255.255")},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			require.Equal(t, testCase.want, testCase.network.LastAddr())
		})
	}
}

// verifies that a non-contiguous mask sets every host bit wherever the
// mask leaves a hole, not only in a trailing run.
func Test_Network4_LastAddr_NonContiguousMasks(t *testing.T) {
	cases := []struct {
		name    string
		network xnetip.Network4
		want    netip.Addr
	}{
		{name: "hole in the third octet", network: xnetip.MustParseNetwork4("192.168.0.1/255.255.0.255"), want: netip.MustParseAddr("192.168.255.1")},
		{name: "hole in the second octet", network: xnetip.MustParseNetwork4("10.0.0.42/255.0.255.255"), want: netip.MustParseAddr("10.255.0.42")},
		{name: "alternating mask fills the odd bits", network: xnetip.MustParseNetwork4("0.0.0.0/170.170.170.170"), want: netip.MustParseAddr("85.85.85.85")},
		{name: "single host bit in the middle", network: xnetip.MustParseNetwork4("10.0.0.0/255.255.255.254"), want: netip.MustParseAddr("10.0.0.1")},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			require.Equal(t, testCase.want, testCase.network.LastAddr())
		})
	}
}

// verifies that the result is a member of the network: masking it
// yields the network address again.
func Test_Network4_LastAddr_MemberProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		network := genNetwork4.Draw(t, "network")
		lastBytes := network.LastAddr().As4()
		maskBytes := network.Mask().As4()
		last := binary.BigEndian.Uint32(lastBytes[:])
		mask := binary.BigEndian.Uint32(maskBytes[:])
		require.Equal(t, network.Addr(), netipAddrFrom4Bits(last&mask))
	})
}

// verifies by brute force on small networks that no member exceeds
// the last address and that the last address itself is enumerated.
//
// The mask is built by clearing at most 12 chosen positions, so every
// host pattern can be deposited into those positions and the whole
// membership enumerated.
func Test_Network4_LastAddr_MaximalByBruteForceProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		hostBits := rapid.IntRange(0, 12).Draw(t, "host bits")
		positions := rapid.SliceOfNDistinct(rapid.IntRange(0, 31), hostBits, hostBits, rapid.ID).Draw(t, "host positions")
		mask := ^uint32(0)
		for _, position := range positions {
			mask &^= uint32(1) << position
		}
		network, err := xnetip.Network4From(
			genNetipAddr4.Draw(t, "addr"),
			netipAddrFrom4Bits(mask),
		)
		require.NoError(t, err)
		addrBytes := network.Addr().As4()
		base := binary.BigEndian.Uint32(addrBytes[:])
		last := network.LastAddr()
		reached := false
		for pattern := range 1 << hostBits {
			member := base
			for idx, position := range positions {
				if pattern>>idx&1 == 1 {
					member |= uint32(1) << position
				}
			}
			require.LessOrEqual(t, netipAddrFrom4Bits(member).Compare(last), 0)
			if netipAddrFrom4Bits(member) == last {
				reached = true
			}
		}
		require.True(t, reached, "last address never enumerated")
	})
}

// verifies that the last address never sorts below the network address
// and coincides with it exactly on a host route.
func Test_Network4_LastAddr_AtLeastAddrProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		network := genNetwork4.Draw(t, "network")
		require.GreaterOrEqual(t, network.LastAddr().Compare(network.Addr()), 0)
		fullMask := network.Mask() == netipAddrFrom4Bits(^uint32(0))
		require.Equal(t, fullMask, network.LastAddr() == network.Addr())
	})
}

// verifies against prefix arithmetic that a contiguous network's last
// address is the network address with the trailing host run filled.
func Test_Network4_LastAddr_MatchesPrefixArithmeticProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		addr := genNetipAddr4.Draw(t, "addr")
		bits := rapid.IntRange(0, 32).Draw(t, "bits")
		network, err := xnetip.Network4FromCIDR(addr, bits)
		require.NoError(t, err)
		baseBytes := network.Addr().As4()
		base := binary.BigEndian.Uint32(baseBytes[:])
		want := base | ^uint32(0)>>uint(bits)
		require.Equal(t, netipAddrFrom4Bits(want), network.LastAddr())
	})
}

// verifies that the last address is computed without allocating,
// whatever the mask's shape.
func Test_Network4_LastAddr_AllocationFree(t *testing.T) {
	contiguous := xnetip.MustParseNetwork4("192.168.1.0/24")
	nonContiguous := xnetip.MustParseNetwork4("192.168.0.1/255.255.0.255")
	requireNoAllocs(t, func() { addrSink = contiguous.LastAddr() })
	requireNoAllocs(t, func() { addrSink = nonContiguous.LastAddr() })
}

// verifies that a contiguous network reports its mask's zero bits,
// the complement of the prefix length.
func Test_Network4_NumHostBits_ContiguousComplementsPrefix(t *testing.T) {
	cases := []struct {
		name    string
		network xnetip.Network4
		want    int
	}{
		{name: "default route frees the whole word", network: xnetip.MustParseNetwork4("0.0.0.0/0"), want: 32},
		{name: "/8", network: xnetip.MustParseNetwork4("10.0.0.0/8"), want: 24},
		{name: "/24", network: xnetip.MustParseNetwork4("192.168.1.0/24"), want: 8},
		{name: "/31", network: xnetip.MustParseNetwork4("10.0.0.0/31"), want: 1},
		{name: "host route holds one address", network: xnetip.MustParseNetwork4("10.0.0.1/32"), want: 0},
		{name: "zero value is the default route", network: xnetip.Network4{}, want: 32},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			require.Equal(t, testCase.want, testCase.network.NumHostBits())
		})
	}
}

// verifies that host bits are counted wherever the mask leaves them,
// not only in a trailing run.
func Test_Network4_NumHostBits_NonContiguousMasks(t *testing.T) {
	cases := []struct {
		name    string
		network xnetip.Network4
		want    int
	}{
		{name: "hole in the second octet", network: xnetip.MustParseNetwork4("10.0.0.0/255.0.255.0"), want: 16},
		{name: "hole in the third octet", network: xnetip.MustParseNetwork4("192.168.0.1/255.255.0.255"), want: 8},
		{name: "alternating mask frees every other bit", network: xnetip.MustParseNetwork4("0.0.0.0/170.170.170.170"), want: 16},
		{name: "single host bit in the middle", network: xnetip.MustParseNetwork4("10.0.0.0/255.255.255.254"), want: 1},
		{name: "mask with one set bit", network: xnetip.MustParseNetwork4("0.0.0.0/128.0.0.0"), want: 31},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			require.Equal(t, testCase.want, testCase.network.NumHostBits())
		})
	}
}

// verifies that the count agrees with a brute bit loop over the mask.
func Test_Network4_NumHostBits_MatchesBitLoopProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		network := genNetwork4.Draw(t, "network")
		maskBytes := network.Mask().As4()
		mask := binary.BigEndian.Uint32(maskBytes[:])
		want := 0
		for idx := range 32 {
			if mask>>idx&1 == 0 {
				want++
			}
		}
		require.Equal(t, want, network.NumHostBits())
	})
}

// verifies that a contiguous network's host-bit count complements its
// prefix length to the word width.
func Test_Network4_NumHostBits_ComplementsPrefixLenProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		network := genNetwork4.Draw(t, "network")
		prefix, ok := network.PrefixLen()
		if !ok {
			return
		}
		require.Equal(t, 32-prefix, network.NumHostBits())
	})
}

// verifies that the count is zero exactly on the all-ones mask and
// the full width exactly on the zero mask.
func Test_Network4_NumHostBits_ExtremesMatchMaskProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		network := genNetwork4.Draw(t, "network")
		require.Equal(t, network.Mask() == netipAddrFrom4Bits(^uint32(0)), network.NumHostBits() == 0)
		require.Equal(t, network.Mask() == netipAddrFrom4Bits(0), network.NumHostBits() == 32)
	})
}

// verifies that the count is computed without allocating, whatever
// the mask's shape.
func Test_Network4_NumHostBits_AllocationFree(t *testing.T) {
	contiguous := xnetip.MustParseNetwork4("192.168.1.0/24")
	nonContiguous := xnetip.MustParseNetwork4("10.0.0.0/255.0.255.0")
	requireNoAllocs(t, func() { intSink = contiguous.NumHostBits() })
	requireNoAllocs(t, func() { intSink = nonContiguous.NumHostBits() })
}

// ipv4NetworkBits returns the network's address and mask as host-order
// integers, the form the bit-level oracles compute in.
func ipv4NetworkBits(network xnetip.Network4) (addr, mask uint32) {
	addrBytes := network.Addr().As4()
	maskBytes := network.Mask().As4()
	return binary.BigEndian.Uint32(addrBytes[:]), binary.BigEndian.Uint32(maskBytes[:])
}

// verifies that a /24 yields its 256 addresses in ascending numeric
// order, each greater than the previous by exactly one.
//
// The suites for this sequence are forward-only: the interleaved
// front-and-back cases a double-ended cursor would pin have no
// iter.Seq analogue, so none appear here — the backward walk is a
// sequence of its own.
func Test_Network4_Addrs_Slash24AscendsByOne(t *testing.T) {
	network := xnetip.MustParseNetwork4("192.168.1.0/24")
	expected := netip.MustParseAddr("192.168.1.0")
	count := 0
	for addr := range network.Addrs() {
		require.Equal(t, expected, addr)
		expected = expected.Next()
		count++
	}
	require.Equal(t, 256, count)
}

// verifies that a host route yields exactly its single address.
func Test_Network4_Addrs_HostRouteSingle(t *testing.T) {
	network := xnetip.MustParseNetwork4("10.0.0.1/32")
	collected := slices.Collect(network.Addrs())
	require.Equal(t, []netip.Addr{netip.MustParseAddr("10.0.0.1")}, collected)
}

// verifies that the default route starts at the unspecified address
// and steps to its successor: the head of the 2^32-item sequence.
func Test_Network4_Addrs_UniverseHead(t *testing.T) {
	network := xnetip.MustParseNetwork4("0.0.0.0/0")
	head := collectHead(network.Addrs(), 2)
	require.Equal(t, []netip.Addr{
		netip.MustParseAddr("0.0.0.0"),
		netip.MustParseAddr("0.0.0.1"),
	}, head)
}

// verifies that a non-contiguous sequence starts at the network
// address, ends at the last address and never repeats an item.
func Test_Network4_Addrs_NonContiguousFirstAndLast(t *testing.T) {
	network := xnetip.MustParseNetwork4("192.168.0.1/255.255.0.255")
	collected := slices.Collect(network.Addrs())
	require.Len(t, collected, 256)
	require.Equal(t, network.Addr(), collected[0])
	require.Equal(t, network.LastAddr(), collected[255])
	require.Equal(t, netip.MustParseAddr("192.168.255.1"), collected[255])
	seen := map[netip.Addr]bool{}
	for _, addr := range collected {
		require.False(t, seen[addr], "address repeated: %v", addr)
		seen[addr] = true
	}
}

// verifies that breaking out of the loop stops the sequence after
// exactly the consumed items.
func Test_Network4_Addrs_EarlyBreakStops(t *testing.T) {
	network := xnetip.MustParseNetwork4("192.168.1.0/24")
	consumed := 0
	for range network.Addrs() {
		consumed++
		if consumed == 3 {
			break
		}
	}
	require.Equal(t, 3, consumed)
}

// verifies that one sequence value can be ranged twice and yields the
// same addresses on both passes.
func Test_Network4_Addrs_ReIterable(t *testing.T) {
	network := xnetip.MustParseNetwork4("192.168.0.1/255.255.0.255")
	sequence := network.Addrs()
	first := slices.Collect(sequence)
	second := slices.Collect(sequence)
	require.Equal(t, first, second)
}

// verifies that a mask freeing the third octet yields, as a set, the
// grid of addresses ranging over exactly that octet.
func Test_Network4_Addrs_NonContiguousGrid(t *testing.T) {
	network := xnetip.MustParseNetwork4("192.168.0.1/255.255.0.255")
	expected := make([]netip.Addr, 0, 256)
	for value := range 256 {
		expected = append(expected, netip.AddrFrom4([4]byte{192, 168, byte(value), 1}))
	}
	actual := slices.Collect(network.Addrs())
	slices.SortFunc(expected, netip.Addr.Compare)
	slices.SortFunc(actual, netip.Addr.Compare)
	require.Equal(t, expected, actual)
}

// verifies the exact forward order of a mask with a four-bit hole.
//
// Successive host indices fill the hole, so the third octet steps by
// sixteen while every other octet stays pinned.
func Test_Network4_Addrs_NonContiguousPinnedForwardOrder(t *testing.T) {
	network := xnetip.MustParseNetwork4("10.0.0.1/255.255.15.255")
	expected := make([]netip.Addr, 0, 16)
	for value := range 16 {
		expected = append(expected, netip.AddrFrom4([4]byte{10, 0, byte(16 * value), 1}))
	}
	require.Equal(t, expected, slices.Collect(network.Addrs()))
}

// verifies on the alternating mask that the two lowest host bits fill
// first: indices 0 through 3 map to host patterns 0, 1, 4, 5.
func Test_Network4_Addrs_AlternatingMask(t *testing.T) {
	network := xnetip.MustParseNetwork4("0.0.0.0/170.170.170.170")
	head := collectHead(network.Addrs(), 4)
	require.Equal(t, []netip.Addr{
		netip.MustParseAddr("0.0.0.0"),
		netip.MustParseAddr("0.0.0.1"),
		netip.MustParseAddr("0.0.0.4"),
		netip.MustParseAddr("0.0.0.5"),
	}, head)
}

// verifies the head of the widest non-contiguous network against the
// host-index oracle.
//
// Its 30 host bits make a full drain infeasible, so only the first
// three items are probed.
func Test_Network4_Addrs_WidestNonContiguousHead(t *testing.T) {
	network := xnetip.MustParseNetwork4("128.0.0.1/128.0.0.1")
	head := collectHead(network.Addrs(), 3)
	require.Equal(t, []netip.Addr{
		addr4AtHostIndexReference(network, 0),
		addr4AtHostIndexReference(network, 1),
		addr4AtHostIndexReference(network, 2),
	}, head)
	require.Equal(t, []netip.Addr{
		netip.MustParseAddr("128.0.0.1"),
		netip.MustParseAddr("128.0.0.3"),
		netip.MustParseAddr("128.0.0.5"),
	}, head)
}

// verifies that the head of the sequence matches the host-index
// oracle.
//
// The address at index k is the network address with k deposited
// into the mask's zero bits, least significant first.
func Test_Network4_Addrs_HeadMatchesHostIndexOracleProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		network := genNetwork4.Draw(t, "network")
		take := min(uint64(1)<<network.NumHostBits(), 32)
		index := uint64(0)
		for addr := range network.Addrs() {
			require.Equal(t, addr4AtHostIndexReference(network, uint32(index)), addr)
			index++
			if index == take {
				break
			}
		}
		require.Equal(t, take, index)
	})
}

// pdepUint32Reference deposits the low bits of source into the set
// bits of mask, least significant first.
//
// It is the software expansion the host-index oracle is defined by,
// kept as an obviously correct bit loop.
func pdepUint32Reference(source, mask uint32) uint32 {
	deposited := uint32(0)
	for mask != 0 {
		lowest := mask & -mask
		if source&1 != 0 {
			deposited |= lowest
		}
		source >>= 1
		mask ^= lowest
	}
	return deposited
}

// addr4AtHostIndexReference returns the address the sequence must
// yield at the given host index.
//
// That address is the network address with the index deposited into
// the mask's zero bits.
func addr4AtHostIndexReference(network xnetip.Network4, index uint32) netip.Addr {
	base, mask := ipv4NetworkBits(network)
	return netipAddrFrom4Bits(base | pdepUint32Reference(index, ^mask))
}

// verifies on bounded spaces that the yielded count is exactly two to
// the number of host bits.
func Test_Network4_Addrs_CountMatchesHostBitsProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		network := drawBoundedNetwork4(t, 16)
		count := 0
		for range network.Addrs() {
			count++
		}
		require.Equal(t, 1<<network.NumHostBits(), count)
	})
}

// drawBoundedNetwork4 draws a network whose mask clears at most
// maxHostBits chosen positions.
//
// The bounded host space keeps a full drain of the membership cheap
// enough for a property test.
func drawBoundedNetwork4(t *rapid.T, maxHostBits int) xnetip.Network4 {
	hostBits := rapid.IntRange(0, maxHostBits).Draw(t, "host bits")
	positions := rapid.SliceOfNDistinct(rapid.IntRange(0, 31), hostBits, hostBits, rapid.ID).Draw(t, "host positions")
	mask := ^uint32(0)
	for _, position := range positions {
		mask &^= uint32(1) << position
	}
	network, err := xnetip.Network4From(genNetipAddr4.Draw(t, "addr"), netipAddrFrom4Bits(mask))
	require.NoError(t, err)
	return network
}

// verifies on bounded spaces that every yielded address is a member
// of the network by the bit test and that no address repeats.
func Test_Network4_Addrs_MembershipAndUniquenessProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		network := drawBoundedNetwork4(t, 12)
		base, mask := ipv4NetworkBits(network)
		seen := map[netip.Addr]bool{}
		for addr := range network.Addrs() {
			addrBytes := addr.As4()
			require.Equal(t, base, binary.BigEndian.Uint32(addrBytes[:])&mask)
			require.False(t, seen[addr], "address repeated")
			seen[addr] = true
		}
		require.Len(t, seen, 1<<network.NumHostBits())
	})
}

// verifies that a contiguous network's sequence ascends strictly from
// the network address to the last address.
func Test_Network4_Addrs_ContiguousAscendsProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		prefixBits := rapid.IntRange(16, 32).Draw(t, "bits")
		network, err := xnetip.Network4FromCIDR(genNetipAddr4.Draw(t, "addr"), prefixBits)
		require.NoError(t, err)
		previous, started := netip.Addr{}, false
		for addr := range network.Addrs() {
			if started {
				require.Equal(t, 1, addr.Compare(previous), "sequence not strictly ascending")
			} else {
				require.Equal(t, network.Addr(), addr)
				started = true
			}
			previous = addr
		}
		require.True(t, started)
		require.Equal(t, network.LastAddr(), previous)
	})
}

// verifies against net/netip that a contiguous sequence equals
// repeated successor steps from the network address onward.
func Test_Network4_Addrs_MatchesNetipNextDifferential(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		prefixBits := rapid.IntRange(20, 32).Draw(t, "bits")
		network, err := xnetip.Network4FromCIDR(genNetipAddr4.Draw(t, "addr"), prefixBits)
		require.NoError(t, err)
		expected := network.Addr()
		for addr := range network.Addrs() {
			require.Equal(t, expected, addr)
			expected = expected.Next()
		}
	})
}

// verifies that a full drain of the sequence performs no allocation,
// whatever the mask's shape.
func Test_Network4_Addrs_AllocationFree(t *testing.T) {
	contiguous := xnetip.MustParseNetwork4("192.168.1.0/24")
	nonContiguous := xnetip.MustParseNetwork4("192.168.0.1/255.255.0.255")
	requireNoAllocs(t, func() {
		for addr := range contiguous.Addrs() {
			addrSink = addr
		}
	})
	requireNoAllocs(t, func() {
		for addr := range nonContiguous.Addrs() {
			addrSink = addr
		}
	})
}

func BenchmarkNetwork4_Addrs_Slash24(b *testing.B) {
	network := xnetip.MustParseNetwork4("77.88.55.0/24")
	b.ReportAllocs()
	for b.Loop() {
		for addr := range network.Addrs() {
			addrSink = addr
		}
	}
}

func BenchmarkNetwork4_Addrs_Slash16(b *testing.B) {
	network := xnetip.MustParseNetwork4("77.88.0.0/16")
	b.ReportAllocs()
	for b.Loop() {
		for addr := range network.Addrs() {
			addrSink = addr
		}
	}
}

func BenchmarkNetwork4_Addrs_NonContiguous8HostBits(b *testing.B) {
	network := xnetip.MustParseNetwork4("192.168.0.1/255.255.0.255")
	b.ReportAllocs()
	for b.Loop() {
		for addr := range network.Addrs() {
			addrSink = addr
		}
	}
}

// verifies that a /24 yields its 256 addresses in descending numeric
// order, each smaller than the previous by exactly one.
func Test_Network4_AddrsBackward_Slash24DescendsByOne(t *testing.T) {
	network := xnetip.MustParseNetwork4("192.168.1.0/24")
	expected := netip.MustParseAddr("192.168.1.255")
	count := 0
	for addr := range network.AddrsBackward() {
		require.Equal(t, expected, addr)
		expected = expected.Prev()
		count++
	}
	require.Equal(t, 256, count)
	require.Equal(t, netip.MustParseAddr("192.168.1.0"), expected.Next())
}

// verifies that a host route yields exactly its single address.
func Test_Network4_AddrsBackward_HostRouteSingle(t *testing.T) {
	network := xnetip.MustParseNetwork4("10.0.0.1/32")
	collected := slices.Collect(network.AddrsBackward())
	require.Equal(t, []netip.Addr{netip.MustParseAddr("10.0.0.1")}, collected)
}

// verifies that the default route starts at the all-ones address and
// steps to its predecessor: the head of the 2^32-item sequence.
func Test_Network4_AddrsBackward_UniverseHead(t *testing.T) {
	network := xnetip.MustParseNetwork4("0.0.0.0/0")
	head := collectHead(network.AddrsBackward(), 2)
	require.Equal(t, []netip.Addr{
		netip.MustParseAddr("255.255.255.255"),
		netip.MustParseAddr("255.255.255.254"),
	}, head)
}

// verifies that a non-contiguous sequence starts at the last address,
// ends at the network address and never repeats an item.
func Test_Network4_AddrsBackward_StartsAtLastAddr(t *testing.T) {
	network := xnetip.MustParseNetwork4("192.168.0.1/255.255.0.255")
	collected := slices.Collect(network.AddrsBackward())
	require.Len(t, collected, 256)
	require.Equal(t, network.LastAddr(), collected[0])
	require.Equal(t, netip.MustParseAddr("192.168.255.1"), collected[0])
	require.Equal(t, network.Addr(), collected[255])
	seen := map[netip.Addr]bool{}
	for _, addr := range collected {
		require.False(t, seen[addr], "address repeated: %v", addr)
		seen[addr] = true
	}
}

// verifies that breaking out of the loop stops the sequence after
// exactly the consumed items.
func Test_Network4_AddrsBackward_EarlyBreakStops(t *testing.T) {
	network := xnetip.MustParseNetwork4("192.168.1.0/24")
	consumed := 0
	for range network.AddrsBackward() {
		consumed++
		if consumed == 3 {
			break
		}
	}
	require.Equal(t, 3, consumed)
}

// verifies that one sequence value can be ranged twice and yields the
// same addresses on both passes.
func Test_Network4_AddrsBackward_ReIterable(t *testing.T) {
	network := xnetip.MustParseNetwork4("192.168.0.1/255.255.0.255")
	sequence := network.AddrsBackward()
	first := slices.Collect(sequence)
	second := slices.Collect(sequence)
	require.Equal(t, first, second)
}

// verifies the exact reverse order of a mask with a four-bit hole.
//
// Descending host indices drain the hole, so the third octet steps
// down by sixteen while every other octet stays pinned.
func Test_Network4_AddrsBackward_NonContiguousPinnedReverseOrder(t *testing.T) {
	network := xnetip.MustParseNetwork4("10.0.0.1/255.255.15.255")
	expected := make([]netip.Addr, 0, 16)
	for value := range 16 {
		expected = append(expected, netip.AddrFrom4([4]byte{10, 0, byte(16 * (15 - value)), 1}))
	}
	require.Equal(t, expected, slices.Collect(network.AddrsBackward()))
}

// verifies on the alternating mask that the two lowest host bits
// drain first: the borrow clears bit 0, then moves to bit 2.
func Test_Network4_AddrsBackward_AlternatingMaskHead(t *testing.T) {
	network := xnetip.MustParseNetwork4("0.0.0.0/170.170.170.170")
	head := collectHead(network.AddrsBackward(), 3)
	require.Equal(t, []netip.Addr{
		netip.MustParseAddr("85.85.85.85"),
		netip.MustParseAddr("85.85.85.84"),
		netip.MustParseAddr("85.85.85.81"),
	}, head)
}

// verifies the head of the widest non-contiguous network against the
// host-index oracle.
//
// Its 30 host bits make a full drain infeasible, so only the first
// two items are probed: the all-ones address, then the borrow
// clearing bit 1, the lowest host bit above the masked bit 0.
func Test_Network4_AddrsBackward_WidestNonContiguousHead(t *testing.T) {
	network := xnetip.MustParseNetwork4("128.0.0.1/128.0.0.1")
	head := collectHead(network.AddrsBackward(), 2)
	require.Equal(t, []netip.Addr{
		addr4AtHostIndexReference(network, 1<<30-1),
		addr4AtHostIndexReference(network, 1<<30-2),
	}, head)
	require.Equal(t, []netip.Addr{
		netip.MustParseAddr("255.255.255.255"),
		netip.MustParseAddr("255.255.255.253"),
	}, head)
}

// verifies on bounded spaces that the backward sequence is exactly
// the reverse of the forward one, whatever the mask's shape.
func Test_Network4_AddrsBackward_ExactReverseOfAddrsProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		network := drawBoundedNetwork4(t, 16)
		expected := slices.Collect(network.Addrs())
		slices.Reverse(expected)
		require.Equal(t, expected, slices.Collect(network.AddrsBackward()))
	})
}

// verifies that the head of the sequence matches the host-index
// oracle walked from the last index downward.
//
// The address at backward step s is the address at host index
// count-1-s, so the sequence drains the indices in descending order.
func Test_Network4_AddrsBackward_HeadMatchesHostIndexOracleProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		network := genNetwork4.Draw(t, "network")
		count := uint64(1) << network.NumHostBits()
		take := min(count, 32)
		step := uint64(0)
		for addr := range network.AddrsBackward() {
			require.Equal(t, addr4AtHostIndexReference(network, uint32(count-1-step)), addr)
			step++
			if step == take {
				break
			}
		}
		require.Equal(t, take, step)
	})
}

// verifies that the first yielded address is the last address for
// every generated network.
func Test_Network4_AddrsBackward_FirstIsLastAddrProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		network := genNetwork4.Draw(t, "network")
		head := collectHead(network.AddrsBackward(), 1)
		require.Equal(t, []netip.Addr{network.LastAddr()}, head)
	})
}

// verifies against net/netip that a contiguous backward sequence
// equals repeated predecessor steps from the last address onward.
func Test_Network4_AddrsBackward_MatchesNetipPrevDifferential(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		prefixBits := rapid.IntRange(20, 32).Draw(t, "bits")
		network, err := xnetip.Network4FromCIDR(genNetipAddr4.Draw(t, "addr"), prefixBits)
		require.NoError(t, err)
		expected := network.LastAddr()
		for addr := range network.AddrsBackward() {
			require.Equal(t, expected, addr)
			expected = expected.Prev()
		}
	})
}

// verifies that a full drain of the backward sequence performs no
// allocation, whatever the mask's shape.
func Test_Network4_AddrsBackward_AllocationFree(t *testing.T) {
	contiguous := xnetip.MustParseNetwork4("192.168.1.0/24")
	nonContiguous := xnetip.MustParseNetwork4("192.168.0.1/255.255.0.255")
	requireNoAllocs(t, func() {
		for addr := range contiguous.AddrsBackward() {
			addrSink = addr
		}
	})
	requireNoAllocs(t, func() {
		for addr := range nonContiguous.AddrsBackward() {
			addrSink = addr
		}
	})
}

func BenchmarkNetwork4_AddrsBackward_Slash24(b *testing.B) {
	network := xnetip.MustParseNetwork4("77.88.55.0/24")
	b.ReportAllocs()
	for b.Loop() {
		for addr := range network.AddrsBackward() {
			addrSink = addr
		}
	}
}

func BenchmarkNetwork4_AddrsBackward_Slash16(b *testing.B) {
	network := xnetip.MustParseNetwork4("77.88.0.0/16")
	b.ReportAllocs()
	for b.Loop() {
		for addr := range network.AddrsBackward() {
			addrSink = addr
		}
	}
}

func BenchmarkNetwork4_AddrsBackward_NonContiguous8HostBits(b *testing.B) {
	network := xnetip.MustParseNetwork4("192.168.0.1/255.255.0.255")
	b.ReportAllocs()
	for b.Loop() {
		for addr := range network.AddrsBackward() {
			addrSink = addr
		}
	}
}

// mergeReferenceIPv4 is the simple merge oracle.
//
// Equal networks merge to themselves, equal-mask single-bit siblings
// drop the differing bit through the adjacency predicate, and
// containment either way returns the container.
func mergeReferenceIPv4(t require.TestingT, left, right xnetip.Network4) (xnetip.Network4, bool) {
	if left == right {
		return left, true
	}
	if left.Mask() == right.Mask() {
		if !left.IsAdjacent(right) {
			return xnetip.Network4{}, false
		}
		leftAddr, leftMask := ipv4NetworkBits(left)
		rightAddr, _ := ipv4NetworkBits(right)
		mask := leftMask ^ (leftAddr ^ rightAddr)
		merged, err := xnetip.Network4From(
			netipAddrFrom4Bits(leftAddr&mask),
			netipAddrFrom4Bits(mask),
		)
		require.NoError(t, err)
		return merged, true
	}
	if left.Contains(right) {
		return left, true
	}
	if right.Contains(left) {
		return right, true
	}
	return xnetip.Network4{}, false
}

// verifies that merging succeeds exactly for duplicates, single-bit
// siblings and containment, and returns the union network.
func Test_Network4_Merge_UnitAndBoundary(t *testing.T) {
	cases := []struct {
		name  string
		left  xnetip.Network4
		right xnetip.Network4
		want  xnetip.Network4
		ok    bool
	}{
		{name: "identical", left: xnetip.MustParseNetwork4("192.168.1.0/24"), right: xnetip.MustParseNetwork4("192.168.1.0/24"), want: xnetip.MustParseNetwork4("192.168.1.0/24"), ok: true},
		{name: "contiguous siblings", left: xnetip.MustParseNetwork4("192.168.0.0/24"), right: xnetip.MustParseNetwork4("192.168.1.0/24"), want: xnetip.MustParseNetwork4("192.168.0.0/23"), ok: true},
		{name: "contiguous siblings reversed", left: xnetip.MustParseNetwork4("192.168.1.0/24"), right: xnetip.MustParseNetwork4("192.168.0.0/24"), want: xnetip.MustParseNetwork4("192.168.0.0/23"), ok: true},
		{name: "siblings at a higher bit give a non-contiguous mask", left: xnetip.MustParseNetwork4("192.168.0.0/24"), right: xnetip.MustParseNetwork4("192.168.2.0/24"), want: xnetip.MustParseNetwork4("192.168.0.0/255.255.253.0"), ok: true},
		{name: "siblings at bit 16 give a non-contiguous mask", left: xnetip.MustParseNetwork4("10.0.0.0/24"), right: xnetip.MustParseNetwork4("10.1.0.0/24"), want: xnetip.MustParseNetwork4("10.0.0.0/255.254.255.0"), ok: true},
		{name: "same mask, two differing bits", left: xnetip.MustParseNetwork4("192.168.0.0/24"), right: xnetip.MustParseNetwork4("192.168.3.0/24"), ok: false},
		{name: "same mask, two differing bits reversed", left: xnetip.MustParseNetwork4("192.168.3.0/24"), right: xnetip.MustParseNetwork4("192.168.0.0/24"), ok: false},
		{name: "containment returns the container", left: xnetip.MustParseNetwork4("10.0.0.0/8"), right: xnetip.MustParseNetwork4("10.1.0.0/16"), want: xnetip.MustParseNetwork4("10.0.0.0/8"), ok: true},
		{name: "containment reversed", left: xnetip.MustParseNetwork4("10.1.0.0/16"), right: xnetip.MustParseNetwork4("10.0.0.0/8"), want: xnetip.MustParseNetwork4("10.0.0.0/8"), ok: true},
		{name: "comparable masks, address mismatch", left: xnetip.MustParseNetwork4("10.0.0.0/8"), right: xnetip.MustParseNetwork4("172.16.0.0/16"), ok: false},
		{name: "comparable masks, address mismatch reversed", left: xnetip.MustParseNetwork4("172.16.0.0/16"), right: xnetip.MustParseNetwork4("10.0.0.0/8"), ok: false},
		{name: "host routes differing in one bit", left: xnetip.MustParseNetwork4("10.0.0.0/32"), right: xnetip.MustParseNetwork4("10.0.0.1/32"), want: xnetip.MustParseNetwork4("10.0.0.0/31"), ok: true},
		{name: "host routes differing in two bits", left: xnetip.MustParseNetwork4("10.0.0.0/32"), right: xnetip.MustParseNetwork4("10.0.0.3/32"), ok: false},
		{name: "default route absorbs any network", left: xnetip.MustParseNetwork4("0.0.0.0/0"), right: xnetip.MustParseNetwork4("203.0.113.0/24"), want: xnetip.MustParseNetwork4("0.0.0.0/0"), ok: true},
		{name: "default route with itself", left: xnetip.MustParseNetwork4("0.0.0.0/0"), right: xnetip.MustParseNetwork4("0.0.0.0/0"), want: xnetip.MustParseNetwork4("0.0.0.0/0"), ok: true},
		{name: "top-bit siblings give the default route", left: xnetip.MustParseNetwork4("0.0.0.0/1"), right: xnetip.MustParseNetwork4("128.0.0.0/1"), want: xnetip.MustParseNetwork4("0.0.0.0/0"), ok: true},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			merged, ok := testCase.left.Merge(testCase.right)
			require.Equal(t, testCase.ok, ok)
			require.Equal(t, testCase.want, merged)
		})
	}
}

// verifies that merging follows the mask bit pattern: only comparable
// masks or single-bit siblings combine, wherever the bits sit.
func Test_Network4_Merge_NonContiguousMasks(t *testing.T) {
	cases := []struct {
		name  string
		left  xnetip.Network4
		right xnetip.Network4
		want  xnetip.Network4
		ok    bool
	}{
		{name: "pattern siblings at a middle bit", left: xnetip.MustParseNetwork4("10.0.0.1/255.255.0.255"), right: xnetip.MustParseNetwork4("10.1.0.1/255.255.0.255"), want: xnetip.MustParseNetwork4("10.0.0.1/255.254.0.255"), ok: true},
		{name: "pattern siblings at a middle bit reversed", left: xnetip.MustParseNetwork4("10.1.0.1/255.255.0.255"), right: xnetip.MustParseNetwork4("10.0.0.1/255.255.0.255"), want: xnetip.MustParseNetwork4("10.0.0.1/255.254.0.255"), ok: true},
		{name: "pattern siblings at the lowest bit", left: xnetip.MustParseNetwork4("10.0.0.0/255.255.0.255"), right: xnetip.MustParseNetwork4("10.0.0.1/255.255.0.255"), want: xnetip.MustParseNetwork4("10.0.0.0/255.255.0.254"), ok: true},
		{name: "incomparable non-contiguous masks", left: xnetip.MustParseNetwork4("10.0.0.1/255.255.0.255"), right: xnetip.MustParseNetwork4("10.0.0.1/255.0.255.255"), ok: false},
		{name: "pattern contains a host route", left: xnetip.MustParseNetwork4("10.0.0.0/255.0.255.0"), right: xnetip.MustParseNetwork4("10.42.0.99/32"), want: xnetip.MustParseNetwork4("10.0.0.0/255.0.255.0"), ok: true},
		{name: "pattern contains a narrower pattern", left: xnetip.MustParseNetwork4("10.0.0.0/255.0.255.0"), right: xnetip.MustParseNetwork4("10.5.0.0/255.255.255.0"), want: xnetip.MustParseNetwork4("10.0.0.0/255.0.255.0"), ok: true},
		{name: "alternating mask siblings", left: xnetip.MustParseNetwork4("170.0.170.0/170.85.170.85"), right: xnetip.MustParseNetwork4("170.0.170.1/170.85.170.85"), want: xnetip.MustParseNetwork4("170.0.170.0/170.85.170.84"), ok: true},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			merged, ok := testCase.left.Merge(testCase.right)
			require.Equal(t, testCase.ok, ok)
			require.Equal(t, testCase.want, merged)
		})
	}
}

// verifies that the nine reference pairs, one per branch of the case
// analysis, agree with the simple oracle.
func Test_Network4_Merge_ReferenceFixedCases(t *testing.T) {
	cases := [][2]string{
		{"192.168.1.0/24", "192.168.1.0/24"},
		{"192.168.0.0/24", "192.168.1.0/24"},
		{"192.168.0.0/255.255.255.0", "192.168.2.0/255.255.255.0"},
		{"192.168.0.0/24", "192.168.3.0/24"},
		{"10.0.0.0/8", "10.1.0.0/16"},
		{"10.1.0.0/16", "10.0.0.0/8"},
		{"10.0.0.0/8", "172.16.0.0/16"},
		{"172.16.0.0/16", "10.0.0.0/8"},
		{"10.0.0.1/255.255.0.255", "10.0.0.1/255.0.255.255"},
	}
	for _, pair := range cases {
		left := xnetip.MustParseNetwork4(pair[0])
		right := xnetip.MustParseNetwork4(pair[1])
		wantNetwork, wantOK := mergeReferenceIPv4(t, left, right)
		merged, ok := left.Merge(right)
		require.Equal(t, wantOK, ok, "pair %v", pair)
		require.Equal(t, wantNetwork, merged, "pair %v", pair)
	}
}

// verifies that merging agrees with the simple oracle on random pairs.
func Test_Network4_Merge_MatchesReferenceProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		left := genNetwork4.Draw(t, "left")
		right := genNetwork4.Draw(t, "right")
		wantNetwork, wantOK := mergeReferenceIPv4(t, left, right)
		merged, ok := left.Merge(right)
		require.Equal(t, wantOK, ok)
		require.Equal(t, wantNetwork, merged)
	})
}

// verifies that merging is commutative in both the value and the flag.
func Test_Network4_Merge_CommutativityProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		left := genNetwork4.Draw(t, "left")
		right := genNetwork4.Draw(t, "right")
		leftMerged, leftOK := left.Merge(right)
		rightMerged, rightOK := right.Merge(left)
		require.Equal(t, leftOK, rightOK)
		require.Equal(t, leftMerged, rightMerged)
	})
}

// verifies that a network merged with itself is itself: aggregation
// leans on this path to absorb duplicates.
func Test_Network4_Merge_SelfIsSelfProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		network := genNetwork4.Draw(t, "network")
		merged, ok := network.Merge(network)
		require.True(t, ok)
		require.Equal(t, network, merged)
	})
}

// verifies that a successful merge contains both inputs and returns a
// normalized network.
func Test_Network4_Merge_ResultContainsBothAndNormalizedProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		left := genNetwork4.Draw(t, "left")
		right := genNetwork4.Draw(t, "right")
		merged, ok := left.Merge(right)
		if !ok {
			return
		}
		require.True(t, merged.Contains(left))
		require.True(t, merged.Contains(right))
		mergedAddr, mergedMask := ipv4NetworkBits(merged)
		require.Equal(t, mergedAddr, mergedAddr&mergedMask)
	})
}

// verifies on an 8-bit model, networks confined to the top octet, that
// a successful merge holds exactly the union of the two address sets.
func Test_Network4_Merge_MembershipBruteForceProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		leftAddr := uint32(rapid.IntRange(0, 255).Draw(t, "left addr")) << 24
		leftMask := uint32(rapid.IntRange(0, 255).Draw(t, "left mask")) << 24
		rightAddr := uint32(rapid.IntRange(0, 255).Draw(t, "right addr")) << 24
		rightMask := uint32(rapid.IntRange(0, 255).Draw(t, "right mask")) << 24
		left, err := xnetip.Network4From(netipAddrFrom4Bits(leftAddr), netipAddrFrom4Bits(leftMask))
		require.NoError(t, err)
		right, err := xnetip.Network4From(netipAddrFrom4Bits(rightAddr), netipAddrFrom4Bits(rightMask))
		require.NoError(t, err)
		merged, ok := left.Merge(right)
		mergedAddr, mergedMask := ipv4NetworkBits(merged)
		for x := range uint32(256) {
			candidate := x << 24
			inLeft := candidate&leftMask == leftAddr&leftMask
			inRight := candidate&rightMask == rightAddr&rightMask
			inMerged := ok && candidate&mergedMask == mergedAddr
			require.Equal(t, ok && (inLeft || inRight), inMerged, "member 0x%08x", candidate)
		}
	})
}

// verifies that flipping any single masked bit builds a sibling whose
// merge drops exactly that bit from the mask.
func Test_Network4_Merge_ConstructedSiblingProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		network := genNetwork4.Draw(t, "network")
		addrBits, maskBits := ipv4NetworkBits(network)
		if maskBits == 0 {
			return
		}
		setBits := []int{}
		for bit := range 32 {
			if maskBits&(1<<bit) != 0 {
				setBits = append(setBits, bit)
			}
		}
		bit := uint32(1) << rapid.SampledFrom(setBits).Draw(t, "bit")
		sibling, err := xnetip.Network4From(
			netipAddrFrom4Bits(addrBits^bit),
			netipAddrFrom4Bits(maskBits),
		)
		require.NoError(t, err)
		merged, ok := network.Merge(sibling)
		require.True(t, ok)
		require.Equal(t, netipAddrFrom4Bits(maskBits&^bit), merged.Mask())
		require.Equal(t, netipAddrFrom4Bits(addrBits&^bit), merged.Addr())
	})
}

// verifies that equal masks with neither adjacency nor equality never
// merge: the differing bits are two or more.
func Test_Network4_Merge_SameMaskNotAdjacentNotIdenticalProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		left := genNetwork4.Draw(t, "left")
		right := genNetwork4.Draw(t, "right")
		if left.Mask() != right.Mask() || left == right || left.IsAdjacent(right) {
			return
		}
		_, ok := left.Merge(right)
		require.False(t, ok)
	})
}

// verifies that merging allocates nothing on any branch.
func Test_Network4_Merge_AllocationFree(t *testing.T) {
	sibling := xnetip.MustParseNetwork4("192.168.0.0/24")
	buddy := xnetip.MustParseNetwork4("192.168.1.0/24")
	container := xnetip.MustParseNetwork4("10.0.0.0/8")
	contained := xnetip.MustParseNetwork4("10.1.0.0/16")
	requireNoAllocs(t, func() { networkSink, okSink = sibling.Merge(buddy) })
	requireNoAllocs(t, func() { networkSink, okSink = container.Merge(contained) })
}

func BenchmarkNetwork4_Merge_EqualMaskAdjacent(b *testing.B) {
	left := xnetip.MustParseNetwork4("192.168.0.0/24")
	right := xnetip.MustParseNetwork4("192.168.1.0/24")
	b.ReportAllocs()
	for b.Loop() {
		networkSink, okSink = left.Merge(right)
	}
}

func BenchmarkNetwork4_Merge_EqualMaskNonMergeable(b *testing.B) {
	left := xnetip.MustParseNetwork4("192.168.0.0/24")
	right := xnetip.MustParseNetwork4("192.168.3.0/24")
	b.ReportAllocs()
	for b.Loop() {
		networkSink, okSink = left.Merge(right)
	}
}

func BenchmarkNetwork4_Merge_Containment(b *testing.B) {
	left := xnetip.MustParseNetwork4("10.0.0.0/8")
	right := xnetip.MustParseNetwork4("10.1.0.0/16")
	b.ReportAllocs()
	for b.Loop() {
		networkSink, okSink = left.Merge(right)
	}
}

func BenchmarkNetwork4_Merge_ComparableMasksAddressMismatch(b *testing.B) {
	left := xnetip.MustParseNetwork4("10.0.0.0/8")
	right := xnetip.MustParseNetwork4("172.16.0.0/16")
	b.ReportAllocs()
	for b.Loop() {
		networkSink, okSink = left.Merge(right)
	}
}

func BenchmarkNetwork4_Merge_IncomparableMasks(b *testing.B) {
	left := xnetip.MustParseNetwork4("10.0.0.1/255.255.0.255")
	right := xnetip.MustParseNetwork4("10.0.0.1/255.0.255.255")
	b.ReportAllocs()
	for b.Loop() {
		networkSink, okSink = left.Merge(right)
	}
}

func BenchmarkNetwork4_Merge_NonContiguous(b *testing.B) {
	left := xnetip.MustParseNetwork4("10.0.0.1/255.255.0.255")
	right := xnetip.MustParseNetwork4("10.1.0.1/255.255.0.255")
	b.ReportAllocs()
	for b.Loop() {
		networkSink, okSink = left.Merge(right)
	}
}

// isAdjacentByLowestMaskBitReferenceIPv4 is the simple oracle for the
// lowest-mask-bit adjacency.
//
// It isolates the boundary bit with a trailing-zero count and a
// shift, independent from the arithmetic isolation the
// implementation uses. A zero mask has no boundary bit and never
// qualifies.
func isAdjacentByLowestMaskBitReferenceIPv4(left, right xnetip.Network4) bool {
	leftAddr, leftMask := ipv4NetworkBits(left)
	rightAddr, rightMask := ipv4NetworkBits(right)
	return leftMask == rightMask && leftMask != 0 &&
		leftAddr^rightAddr == uint32(1)<<bits.TrailingZeros32(leftMask)
}

// verifies that only same-mask pairs differing in exactly the mask's
// lowest set bit qualify, and adjacency at any higher bit is refused.
func Test_Network4_IsAdjacentByLowestMaskBit_ContiguousAndBoundary(t *testing.T) {
	cases := []struct {
		name  string
		left  xnetip.Network4
		right xnetip.Network4
		want  bool
	}{
		{name: "CIDR siblings", left: xnetip.MustParseNetwork4("192.168.0.0/24"), right: xnetip.MustParseNetwork4("192.168.1.0/24"), want: true},
		{name: "CIDR siblings reversed", left: xnetip.MustParseNetwork4("192.168.1.0/24"), right: xnetip.MustParseNetwork4("192.168.0.0/24"), want: true},
		{name: "host routes differing in bit 0", left: xnetip.MustParseNetwork4("192.168.0.0/32"), right: xnetip.MustParseNetwork4("192.168.0.1/32"), want: true},
		{name: "host routes differing in bit 0 reversed", left: xnetip.MustParseNetwork4("192.168.0.1/32"), right: xnetip.MustParseNetwork4("192.168.0.0/32"), want: true},
		{name: "identical", left: xnetip.MustParseNetwork4("192.168.0.0/24"), right: xnetip.MustParseNetwork4("192.168.0.0/24"), want: false},
		{name: "different masks", left: xnetip.MustParseNetwork4("192.168.0.0/24"), right: xnetip.MustParseNetwork4("192.168.0.0/16"), want: false},
		{name: "adjacent at the top mask bit, not the lowest", left: xnetip.MustParseNetwork4("0.0.0.0/2"), right: xnetip.MustParseNetwork4("128.0.0.0/2"), want: false},
		{name: "adjacent one bit above the boundary", left: xnetip.MustParseNetwork4("10.0.0.0/24"), right: xnetip.MustParseNetwork4("10.0.2.0/24"), want: false},
		{name: "default route with itself", left: xnetip.MustParseNetwork4("0.0.0.0/0"), right: xnetip.MustParseNetwork4("0.0.0.0/0"), want: false},
		{name: "/1 siblings at bit 31", left: xnetip.MustParseNetwork4("0.0.0.0/1"), right: xnetip.MustParseNetwork4("128.0.0.0/1"), want: true},
		{name: "host routes differing in bit 1", left: xnetip.MustParseNetwork4("10.0.0.0/32"), right: xnetip.MustParseNetwork4("10.0.0.2/32"), want: false},
		{name: "/31 siblings", left: xnetip.MustParseNetwork4("10.0.0.0/31"), right: xnetip.MustParseNetwork4("10.0.0.2/31"), want: true},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			require.Equal(t, testCase.want, testCase.left.IsAdjacentByLowestMaskBit(testCase.right))
		})
	}
}

// verifies that for a non-contiguous mask only the lowest run's
// boundary bit counts.
//
// A sibling differing at a higher run's boundary stays adjacent in
// the plain sense but does not qualify here.
func Test_Network4_IsAdjacentByLowestMaskBit_NonContiguousMasks(t *testing.T) {
	cases := []struct {
		name  string
		left  xnetip.Network4
		right xnetip.Network4
		want  bool
	}{
		{name: "two-run mask at its lowest bit", left: xnetip.MustParseNetwork4("10.0.0.0/255.255.0.255"), right: xnetip.MustParseNetwork4("10.0.0.1/255.255.0.255"), want: true},
		{name: "two-run mask at its lowest bit reversed", left: xnetip.MustParseNetwork4("10.0.0.1/255.255.0.255"), right: xnetip.MustParseNetwork4("10.0.0.0/255.255.0.255"), want: true},
		{name: "two-run mask at the high run's boundary", left: xnetip.MustParseNetwork4("10.0.0.0/255.255.0.255"), right: xnetip.MustParseNetwork4("10.1.0.0/255.255.0.255"), want: false},
		{name: "mask with lowest set bit 8, differing there", left: xnetip.MustParseNetwork4("10.0.0.0/255.0.255.0"), right: xnetip.MustParseNetwork4("10.0.1.0/255.0.255.0"), want: true},
		{name: "mask with lowest set bit 8, differing at bit 24", left: xnetip.MustParseNetwork4("10.0.0.0/255.0.255.0"), right: xnetip.MustParseNetwork4("11.0.0.0/255.0.255.0"), want: false},
		{name: "alternating mask, differing at bit 0", left: xnetip.MustParseNetwork4("170.0.170.0/170.85.170.85"), right: xnetip.MustParseNetwork4("170.0.170.1/170.85.170.85"), want: true},
		{name: "alternating mask, differing at bit 2", left: xnetip.MustParseNetwork4("170.0.170.0/170.85.170.85"), right: xnetip.MustParseNetwork4("170.0.170.4/170.85.170.85"), want: false},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			require.Equal(t, testCase.want, testCase.left.IsAdjacentByLowestMaskBit(testCase.right))
		})
	}
}

// verifies that the rejected higher-bit pairs of the unit tables are
// still plainly adjacent: the predicate is a strict restriction.
func Test_Network4_IsAdjacentByLowestMaskBit_RejectedPairsStayAdjacent(t *testing.T) {
	cases := [][2]string{
		{"0.0.0.0/2", "128.0.0.0/2"},
		{"10.0.0.0/24", "10.0.2.0/24"},
		{"10.0.0.0/255.255.0.255", "10.1.0.0/255.255.0.255"},
		{"10.0.0.0/255.0.255.0", "11.0.0.0/255.0.255.0"},
	}
	for _, pair := range cases {
		left := xnetip.MustParseNetwork4(pair[0])
		right := xnetip.MustParseNetwork4(pair[1])
		require.True(t, left.IsAdjacent(right), "pair %v", pair)
		require.False(t, left.IsAdjacentByLowestMaskBit(right), "pair %v", pair)
	}
}

// verifies that the predicate agrees with the trailing-zeros oracle
// on random pairs.
func Test_Network4_IsAdjacentByLowestMaskBit_MatchesReferenceProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		left := genNetwork4.Draw(t, "left")
		right := genNetwork4.Draw(t, "right")
		require.Equal(t, isAdjacentByLowestMaskBitReferenceIPv4(left, right), left.IsAdjacentByLowestMaskBit(right))
	})
}

// verifies that the predicate implies plain adjacency, is symmetric
// and is irreflexive.
func Test_Network4_IsAdjacentByLowestMaskBit_ImpliesAdjacentAndSymmetryProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		left := genNetwork4.Draw(t, "left")
		right := genNetwork4.Draw(t, "right")
		if left.IsAdjacentByLowestMaskBit(right) {
			require.True(t, left.IsAdjacent(right))
		}
		require.Equal(t, left.IsAdjacentByLowestMaskBit(right), right.IsAdjacentByLowestMaskBit(left))
		require.False(t, left.IsAdjacentByLowestMaskBit(left))
	})
}

// verifies that the buddy at the mask's lowest set bit qualifies and
// a sibling at any higher set bit is adjacent but does not.
func Test_Network4_IsAdjacentByLowestMaskBit_BuddyConstructionProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		network := genNetwork4.Draw(t, "network")
		addrBits, maskBits := ipv4NetworkBits(network)
		if maskBits == 0 {
			return
		}
		lowest := maskBits & -maskBits
		buddy, err := xnetip.Network4From(
			netipAddrFrom4Bits(addrBits^lowest),
			netipAddrFrom4Bits(maskBits),
		)
		require.NoError(t, err)
		require.True(t, network.IsAdjacentByLowestMaskBit(buddy))
		require.True(t, buddy.IsAdjacentByLowestMaskBit(network))
		higherBits := []int{}
		for bit := range 32 {
			if maskBits&(1<<bit) != 0 && uint32(1)<<bit != lowest {
				higherBits = append(higherBits, bit)
			}
		}
		if len(higherBits) == 0 {
			return
		}
		bit := uint32(1) << rapid.SampledFrom(higherBits).Draw(t, "higher bit")
		sibling, err := xnetip.Network4From(
			netipAddrFrom4Bits(addrBits^bit),
			netipAddrFrom4Bits(maskBits),
		)
		require.NoError(t, err)
		require.True(t, network.IsAdjacent(sibling))
		require.False(t, network.IsAdjacentByLowestMaskBit(sibling))
	})
}

// verifies that the predicate allocates nothing.
func Test_Network4_IsAdjacentByLowestMaskBit_AllocationFree(t *testing.T) {
	left := xnetip.MustParseNetwork4("10.0.0.0/255.255.0.255")
	right := xnetip.MustParseNetwork4("10.0.0.1/255.255.0.255")
	requireNoAllocs(t, func() { okSink = left.IsAdjacentByLowestMaskBit(right) })
}

func BenchmarkNetwork4_IsAdjacentByLowestMaskBit_CIDRSiblings(b *testing.B) {
	left := xnetip.MustParseNetwork4("192.168.0.0/24")
	right := xnetip.MustParseNetwork4("192.168.1.0/24")
	b.ReportAllocs()
	for b.Loop() {
		okSink = left.IsAdjacentByLowestMaskBit(right)
	}
}

func BenchmarkNetwork4_IsAdjacentByLowestMaskBit_AdjacentNonLowestBit(b *testing.B) {
	left := xnetip.MustParseNetwork4("0.0.0.0/2")
	right := xnetip.MustParseNetwork4("128.0.0.0/2")
	b.ReportAllocs()
	for b.Loop() {
		okSink = left.IsAdjacentByLowestMaskBit(right)
	}
}

func BenchmarkNetwork4_IsAdjacentByLowestMaskBit_NonContiguous(b *testing.B) {
	left := xnetip.MustParseNetwork4("10.0.0.0/255.255.0.255")
	right := xnetip.MustParseNetwork4("10.0.0.1/255.255.0.255")
	b.ReportAllocs()
	for b.Loop() {
		okSink = left.IsAdjacentByLowestMaskBit(right)
	}
}

// mergeByLowestMaskBitReferenceIPv4 is the simple oracle for the
// class-closed merge.
//
// Containment either way returns the container, otherwise the
// trailing-zeros adjacency oracle gates a sibling merge whose mask
// clears the counted bit and whose address is re-normalized through
// the checked constructor.
func mergeByLowestMaskBitReferenceIPv4(t require.TestingT, left, right xnetip.Network4) (xnetip.Network4, bool) {
	if left.Contains(right) {
		return left, true
	}
	if right.Contains(left) {
		return right, true
	}
	if !isAdjacentByLowestMaskBitReferenceIPv4(left, right) {
		return xnetip.Network4{}, false
	}
	leftAddr, leftMask := ipv4NetworkBits(left)
	rightAddr, _ := ipv4NetworkBits(right)
	lowest := uint32(1) << bits.TrailingZeros32(leftMask)
	merged, err := xnetip.Network4From(
		netipAddrFrom4Bits(leftAddr&rightAddr),
		netipAddrFrom4Bits(leftMask&^lowest),
	)
	require.NoError(t, err)
	return merged, true
}

// verifies that merging succeeds exactly for containment and for
// lowest-mask-bit siblings, and returns the combined network.
func Test_Network4_MergeByLowestMaskBit_UnitAndBoundary(t *testing.T) {
	cases := []struct {
		name  string
		left  xnetip.Network4
		right xnetip.Network4
		want  xnetip.Network4
		ok    bool
	}{
		{name: "CIDR siblings merge to the parent", left: xnetip.MustParseNetwork4("192.168.0.0/24"), right: xnetip.MustParseNetwork4("192.168.1.0/24"), want: xnetip.MustParseNetwork4("192.168.0.0/23"), ok: true},
		{name: "CIDR siblings reversed", left: xnetip.MustParseNetwork4("192.168.1.0/24"), right: xnetip.MustParseNetwork4("192.168.0.0/24"), want: xnetip.MustParseNetwork4("192.168.0.0/23"), ok: true},
		{name: "host routes differing in bit 0 merge to /31", left: xnetip.MustParseNetwork4("10.0.0.0/32"), right: xnetip.MustParseNetwork4("10.0.0.1/32"), want: xnetip.MustParseNetwork4("10.0.0.0/255.255.255.254"), ok: true},
		{name: "adjacent at the top bit is refused", left: xnetip.MustParseNetwork4("0.0.0.0/2"), right: xnetip.MustParseNetwork4("128.0.0.0/2"), ok: false},
		{name: "identical returns itself", left: xnetip.MustParseNetwork4("192.168.1.0/24"), right: xnetip.MustParseNetwork4("192.168.1.0/24"), want: xnetip.MustParseNetwork4("192.168.1.0/24"), ok: true},
		{name: "containment returns the larger", left: xnetip.MustParseNetwork4("10.0.0.0/8"), right: xnetip.MustParseNetwork4("10.1.0.0/16"), want: xnetip.MustParseNetwork4("10.0.0.0/8"), ok: true},
		{name: "containment reversed", left: xnetip.MustParseNetwork4("10.1.0.0/16"), right: xnetip.MustParseNetwork4("10.0.0.0/8"), want: xnetip.MustParseNetwork4("10.0.0.0/8"), ok: true},
		{name: "default route with itself", left: xnetip.MustParseNetwork4("0.0.0.0/0"), right: xnetip.MustParseNetwork4("0.0.0.0/0"), want: xnetip.MustParseNetwork4("0.0.0.0/0"), ok: true},
		{name: "default route absorbs any network", left: xnetip.MustParseNetwork4("0.0.0.0/0"), right: xnetip.MustParseNetwork4("192.168.1.0/24"), want: xnetip.MustParseNetwork4("0.0.0.0/0"), ok: true},
		{name: "default route absorbs any network reversed", left: xnetip.MustParseNetwork4("192.168.1.0/24"), right: xnetip.MustParseNetwork4("0.0.0.0/0"), want: xnetip.MustParseNetwork4("0.0.0.0/0"), ok: true},
		{name: "different masks, no containment", left: xnetip.MustParseNetwork4("192.168.0.0/24"), right: xnetip.MustParseNetwork4("10.0.0.0/16"), ok: false},
		{name: "different masks, no containment reversed", left: xnetip.MustParseNetwork4("10.0.0.0/16"), right: xnetip.MustParseNetwork4("192.168.0.0/24"), ok: false},
		{name: "same mask, unrelated addresses", left: xnetip.MustParseNetwork4("192.168.0.0/24"), right: xnetip.MustParseNetwork4("192.168.3.0/24"), ok: false},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			merged, ok := testCase.left.MergeByLowestMaskBit(testCase.right)
			require.Equal(t, testCase.ok, ok)
			require.Equal(t, testCase.want, merged)
		})
	}
}

// verifies that non-contiguous masks merge only at the lowest run's
// boundary bit or by containment.
func Test_Network4_MergeByLowestMaskBit_NonContiguousMasks(t *testing.T) {
	cases := []struct {
		name  string
		left  xnetip.Network4
		right xnetip.Network4
		want  xnetip.Network4
		ok    bool
	}{
		{name: "siblings at the lowest run's bit 0", left: xnetip.MustParseNetwork4("10.0.0.0/255.255.0.255"), right: xnetip.MustParseNetwork4("10.0.0.1/255.255.0.255"), want: xnetip.MustParseNetwork4("10.0.0.0/255.255.0.254"), ok: true},
		{name: "siblings at the lowest run's bit 0 reversed", left: xnetip.MustParseNetwork4("10.0.0.1/255.255.0.255"), right: xnetip.MustParseNetwork4("10.0.0.0/255.255.0.255"), want: xnetip.MustParseNetwork4("10.0.0.0/255.255.0.254"), ok: true},
		{name: "siblings at the higher run's bit 16 refused", left: xnetip.MustParseNetwork4("10.0.0.1/255.255.0.255"), right: xnetip.MustParseNetwork4("10.1.0.1/255.255.0.255"), ok: false},
		{name: "containment with non-contiguous masks", left: xnetip.MustParseNetwork4("10.0.0.0/255.0.0.255"), right: xnetip.MustParseNetwork4("10.0.0.0/255.128.0.255"), want: xnetip.MustParseNetwork4("10.0.0.0/255.0.0.255"), ok: true},
		{name: "containment with non-contiguous masks reversed", left: xnetip.MustParseNetwork4("10.0.0.0/255.128.0.255"), right: xnetip.MustParseNetwork4("10.0.0.0/255.0.0.255"), want: xnetip.MustParseNetwork4("10.0.0.0/255.0.0.255"), ok: true},
		{name: "alternating mask, siblings at bit 0", left: xnetip.MustParseNetwork4("0.0.0.0/85.85.85.85"), right: xnetip.MustParseNetwork4("0.0.0.1/85.85.85.85"), want: xnetip.MustParseNetwork4("0.0.0.0/85.85.85.84"), ok: true},
		{name: "alternating mask, siblings at bit 2 refused", left: xnetip.MustParseNetwork4("0.0.0.0/85.85.85.85"), right: xnetip.MustParseNetwork4("0.0.0.4/85.85.85.85"), ok: false},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			merged, ok := testCase.left.MergeByLowestMaskBit(testCase.right)
			require.Equal(t, testCase.ok, ok)
			require.Equal(t, testCase.want, merged)
		})
	}
}

// verifies that the refused higher-bit pairs of the unit tables are
// still combined by the unrestricted merge.
//
// The refusal is what keeps the result inside the inputs' class.
func Test_Network4_MergeByLowestMaskBit_RefusedPairsStillMerge(t *testing.T) {
	cases := []struct {
		name string
		pair [2]string
		want string
	}{
		{name: "top-bit pair merges non-contiguously", pair: [2]string{"0.0.0.0/2", "128.0.0.0/2"}, want: "0.0.0.0/64.0.0.0"},
		{name: "higher-run pair widens the two-run mask", pair: [2]string{"10.0.0.1/255.255.0.255", "10.1.0.1/255.255.0.255"}, want: "10.0.0.1/255.254.0.255"},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			left := xnetip.MustParseNetwork4(testCase.pair[0])
			right := xnetip.MustParseNetwork4(testCase.pair[1])
			_, ok := left.MergeByLowestMaskBit(right)
			require.False(t, ok)
			merged, ok := left.Merge(right)
			require.True(t, ok)
			require.Equal(t, xnetip.MustParseNetwork4(testCase.want), merged)
		})
	}
}

// verifies that the seven reference pairs, one per branch of the case
// analysis, agree with the simple oracle.
func Test_Network4_MergeByLowestMaskBit_ReferenceFixedCases(t *testing.T) {
	cases := [][2]string{
		{"192.168.0.0/24", "192.168.1.0/24"},
		{"10.0.0.0/255.255.0.255", "10.0.0.1/255.255.0.255"},
		{"0.0.0.0/2", "128.0.0.0/2"},
		{"192.168.1.0/24", "192.168.1.0/24"},
		{"10.0.0.0/8", "10.1.0.0/16"},
		{"10.0.0.0/8", "172.16.0.0/16"},
		{"0.0.0.0/0", "0.0.0.0/0"},
	}
	for _, pair := range cases {
		left := xnetip.MustParseNetwork4(pair[0])
		right := xnetip.MustParseNetwork4(pair[1])
		wantNetwork, wantOK := mergeByLowestMaskBitReferenceIPv4(t, left, right)
		merged, ok := left.MergeByLowestMaskBit(right)
		require.Equal(t, wantOK, ok, "pair %v", pair)
		require.Equal(t, wantNetwork, merged, "pair %v", pair)
	}
}

// verifies that the merge agrees with the simple oracle on random
// pairs.
func Test_Network4_MergeByLowestMaskBit_MatchesReferenceProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		left := genNetwork4.Draw(t, "left")
		right := genNetwork4.Draw(t, "right")
		wantNetwork, wantOK := mergeByLowestMaskBitReferenceIPv4(t, left, right)
		merged, ok := left.MergeByLowestMaskBit(right)
		require.Equal(t, wantOK, ok)
		require.Equal(t, wantNetwork, merged)
	})
}

// verifies that the merge fires exactly on containment in either
// direction or on a lowest-mask-bit sibling pair.
func Test_Network4_MergeByLowestMaskBit_OKIffPredicateProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		left := genNetwork4.Draw(t, "left")
		right := genNetwork4.Draw(t, "right")
		_, ok := left.MergeByLowestMaskBit(right)
		want := left.Contains(right) || right.Contains(left) || left.IsAdjacentByLowestMaskBit(right)
		require.Equal(t, want, ok)
	})
}

// verifies that the merge is commutative in both the value and the
// flag.
func Test_Network4_MergeByLowestMaskBit_CommutativityProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		left := genNetwork4.Draw(t, "left")
		right := genNetwork4.Draw(t, "right")
		leftMerged, leftOK := left.MergeByLowestMaskBit(right)
		rightMerged, rightOK := right.MergeByLowestMaskBit(left)
		require.Equal(t, leftOK, rightOK)
		require.Equal(t, leftMerged, rightMerged)
	})
}

// verifies that the merge is a restriction of Merge: whenever it
// fires it returns exactly the same network.
func Test_Network4_MergeByLowestMaskBit_AgreesWithMergeProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		left := genNetwork4.Draw(t, "left")
		right := genNetwork4.Draw(t, "right")
		merged, ok := left.MergeByLowestMaskBit(right)
		if !ok {
			return
		}
		unrestricted, unrestrictedOK := left.Merge(right)
		require.True(t, unrestrictedOK)
		require.Equal(t, unrestricted, merged)
	})
}

// verifies that constructed buddy pairs always merge, agree with
// Merge, commute, contain both inputs and yield a normalized result.
func Test_Network4_MergeByLowestMaskBit_SiblingsMergeAndAgreeProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		pair := genIPv4LowestBitSiblingPair.Draw(t, "pair")
		merged, ok := pair[0].MergeByLowestMaskBit(pair[1])
		require.True(t, ok)
		unrestricted, unrestrictedOK := pair[0].Merge(pair[1])
		require.True(t, unrestrictedOK)
		require.Equal(t, unrestricted, merged)
		reversed, reversedOK := pair[1].MergeByLowestMaskBit(pair[0])
		require.True(t, reversedOK)
		require.Equal(t, merged, reversed)
		require.True(t, merged.Contains(pair[0]))
		require.True(t, merged.Contains(pair[1]))
		mergedAddr, mergedMask := ipv4NetworkBits(merged)
		require.Equal(t, mergedAddr, mergedAddr&mergedMask)
	})
}

// verifies the class closure: two contiguous buddies always merge
// into a contiguous parent.
func Test_Network4_MergeByLowestMaskBit_ClosureContiguousProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		pair := genIPv4ContiguousSiblingPair.Draw(t, "pair")
		require.True(t, pair[0].IsContiguous())
		require.True(t, pair[1].IsContiguous())
		merged, ok := pair[0].MergeByLowestMaskBit(pair[1])
		require.True(t, ok)
		require.True(t, merged.IsContiguous())
	})
}

// verifies on an 8-bit model, networks confined to the top octet,
// that a successful merge holds exactly the union of the two sets.
func Test_Network4_MergeByLowestMaskBit_MembershipBruteForceProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		leftAddr := uint32(rapid.IntRange(0, 255).Draw(t, "left addr")) << 24
		leftMask := uint32(rapid.IntRange(0, 255).Draw(t, "left mask")) << 24
		rightAddr := uint32(rapid.IntRange(0, 255).Draw(t, "right addr")) << 24
		rightMask := uint32(rapid.IntRange(0, 255).Draw(t, "right mask")) << 24
		left, err := xnetip.Network4From(netipAddrFrom4Bits(leftAddr), netipAddrFrom4Bits(leftMask))
		require.NoError(t, err)
		right, err := xnetip.Network4From(netipAddrFrom4Bits(rightAddr), netipAddrFrom4Bits(rightMask))
		require.NoError(t, err)
		merged, ok := left.MergeByLowestMaskBit(right)
		if !ok {
			return
		}
		mergedAddr, mergedMask := ipv4NetworkBits(merged)
		for x := range uint32(256) {
			candidate := x << 24
			inLeft := candidate&leftMask == leftAddr&leftMask
			inRight := candidate&rightMask == rightAddr&rightMask
			inMerged := candidate&mergedMask == mergedAddr
			require.Equal(t, inLeft || inRight, inMerged, "member 0x%08x", candidate)
		}
	})
}

// verifies that the merge allocates nothing on the sibling and the
// containment paths.
func Test_Network4_MergeByLowestMaskBit_AllocationFree(t *testing.T) {
	sibling := xnetip.MustParseNetwork4("192.168.0.0/24")
	buddy := xnetip.MustParseNetwork4("192.168.1.0/24")
	container := xnetip.MustParseNetwork4("10.0.0.0/8")
	contained := xnetip.MustParseNetwork4("10.1.0.0/16")
	requireNoAllocs(t, func() { networkSink, okSink = sibling.MergeByLowestMaskBit(buddy) })
	requireNoAllocs(t, func() { networkSink, okSink = container.MergeByLowestMaskBit(contained) })
}

func BenchmarkNetwork4_MergeByLowestMaskBit_CIDRSiblings(b *testing.B) {
	left := xnetip.MustParseNetwork4("192.168.0.0/24")
	right := xnetip.MustParseNetwork4("192.168.1.0/24")
	b.ReportAllocs()
	for b.Loop() {
		networkSink, okSink = left.MergeByLowestMaskBit(right)
	}
}

func BenchmarkNetwork4_MergeByLowestMaskBit_AdjacentNonLowestBit(b *testing.B) {
	left := xnetip.MustParseNetwork4("0.0.0.0/2")
	right := xnetip.MustParseNetwork4("128.0.0.0/2")
	b.ReportAllocs()
	for b.Loop() {
		networkSink, okSink = left.MergeByLowestMaskBit(right)
	}
}

func BenchmarkNetwork4_MergeByLowestMaskBit_NonContiguous(b *testing.B) {
	left := xnetip.MustParseNetwork4("10.0.0.0/255.255.0.255")
	right := xnetip.MustParseNetwork4("10.0.0.1/255.255.0.255")
	b.ReportAllocs()
	for b.Loop() {
		networkSink, okSink = left.MergeByLowestMaskBit(right)
	}
}

func BenchmarkNetwork4_MergeByLowestMaskBit_Containment(b *testing.B) {
	left := xnetip.MustParseNetwork4("10.0.0.0/8")
	right := xnetip.MustParseNetwork4("10.1.0.0/16")
	b.ReportAllocs()
	for b.Loop() {
		networkSink, okSink = left.MergeByLowestMaskBit(right)
	}
}

// supernetForReferenceIPv4 is the plain fold oracle for the supernet
// computation.
//
// It keeps a mask bit only when every input masks it and agrees with
// the receiver's address on it, and re-normalizes the address through
// the checked constructor.
func supernetForReferenceIPv4(t require.TestingT, receiver xnetip.Network4, nets []xnetip.Network4) xnetip.Network4 {
	addr, mask := ipv4NetworkBits(receiver)
	for _, network := range nets {
		otherAddr, otherMask := ipv4NetworkBits(network)
		mask &= otherMask &^ (addr ^ otherAddr)
	}
	oracle, err := xnetip.Network4From(
		netipAddrFrom4Bits(addr&mask),
		netipAddrFrom4Bits(mask),
	)
	require.NoError(t, err)
	return oracle
}

// ipv4RelatedNetworks returns count consecutive /28 blocks under
// 10.0.0.0/16, so a fold over them never collapses the mask to zero.
func ipv4RelatedNetworks(t require.TestingT, count int) []xnetip.Network4 {
	networks := make([]xnetip.Network4, count)
	for idx := range networks {
		network, err := xnetip.Network4FromCIDR(netipAddrFrom4Bits(0x0A000000|uint32(idx)*16), 28)
		require.NoError(t, err)
		networks[idx] = network
	}
	return networks
}

// ipv4RelatedNonContiguousNetworks returns count networks under the
// two-run mask 255.255.0.255.
//
// The addresses spread over the second and fourth octets, so a fold
// over them exercises the two-run shape without collapsing the mask
// to zero.
func ipv4RelatedNonContiguousNetworks(t require.TestingT, count int) []xnetip.Network4 {
	networks := make([]xnetip.Network4, count)
	for idx := range networks {
		addr := 0x0A000000 | (uint32(idx)>>8&0xFF)<<16 | uint32(idx)&0xFF
		network, err := xnetip.Network4From(
			netipAddrFrom4Bits(addr),
			netipAddrFrom4Bits(0xFFFF00FF),
		)
		require.NoError(t, err)
		networks[idx] = network
	}
	return networks
}

// verifies that the fold keeps exactly the mask bits every input
// masks and agrees on, over the ported reference cases.
func Test_Network4_SupernetFor_UnitAndBoundary(t *testing.T) {
	cases := []struct {
		name     string
		receiver xnetip.Network4
		nets     []xnetip.Network4
		want     xnetip.Network4
	}{
		{name: "two /25 halves fold to the /24", receiver: xnetip.MustParseNetwork4("192.0.2.0/25"), nets: []xnetip.Network4{xnetip.MustParseNetwork4("192.0.2.128/25")}, want: xnetip.MustParseNetwork4("192.0.2.0/24")},
		{name: "two /25 halves reversed", receiver: xnetip.MustParseNetwork4("192.0.2.128/25"), nets: []xnetip.Network4{xnetip.MustParseNetwork4("192.0.2.0/25")}, want: xnetip.MustParseNetwork4("192.0.2.0/24")},
		{name: "equal networks yield themselves", receiver: xnetip.MustParseNetwork4("192.0.2.128/25"), nets: []xnetip.Network4{xnetip.MustParseNetwork4("192.0.2.128/25")}, want: xnetip.MustParseNetwork4("192.0.2.128/25")},
		{name: "wider CIDR absorbs the receiver", receiver: xnetip.MustParseNetwork4("10.0.0.0/24"), nets: []xnetip.Network4{xnetip.MustParseNetwork4("10.0.0.0/16")}, want: xnetip.MustParseNetwork4("10.0.0.0/16")},
		{name: "wider CIDR absorbs the element", receiver: xnetip.MustParseNetwork4("10.0.0.0/16"), nets: []xnetip.Network4{xnetip.MustParseNetwork4("10.0.0.0/24")}, want: xnetip.MustParseNetwork4("10.0.0.0/16")},
		{name: "empty slice returns the receiver", receiver: xnetip.MustParseNetwork4("10.0.0.0/8"), nets: nil, want: xnetip.MustParseNetwork4("10.0.0.0/8")},
		{name: "default route receiver stays the default route", receiver: xnetip.MustParseNetwork4("0.0.0.0/0"), nets: []xnetip.Network4{xnetip.MustParseNetwork4("10.0.0.0/8")}, want: xnetip.MustParseNetwork4("0.0.0.0/0")},
		{name: "contiguous inputs leave a hole off the mask boundary", receiver: xnetip.MustParseNetwork4("10.0.0.0/24"), nets: []xnetip.Network4{xnetip.MustParseNetwork4("10.1.0.0/24")}, want: xnetip.MustParseNetwork4("10.0.0.0/255.254.255.0")},
		{name: "three hosts differing in the third octet", receiver: xnetip.MustParseNetwork4("10.40.101.1/32"), nets: []xnetip.Network4{xnetip.MustParseNetwork4("10.40.102.1/32"), xnetip.MustParseNetwork4("10.40.103.1/32")}, want: xnetip.MustParseNetwork4("10.40.100.1/255.255.252.255")},
		{name: "three hosts crossing the first octet", receiver: xnetip.MustParseNetwork4("10.40.101.1/32"), nets: []xnetip.Network4{xnetip.MustParseNetwork4("10.40.102.1/32"), xnetip.MustParseNetwork4("11.40.103.1/32")}, want: xnetip.MustParseNetwork4("10.40.100.1/254.255.252.255")},
		{name: "five /24 blocks far apart", receiver: xnetip.MustParseNetwork4("192.168.0.0/24"), nets: []xnetip.Network4{xnetip.MustParseNetwork4("192.168.1.0/24"), xnetip.MustParseNetwork4("192.168.2.0/24"), xnetip.MustParseNetwork4("192.168.100.0/24"), xnetip.MustParseNetwork4("192.168.200.0/24")}, want: xnetip.MustParseNetwork4("192.168.0.0/255.255.16.0")},
		{name: "top-bit disagreement clears the top mask bits", receiver: xnetip.MustParseNetwork4("128.0.0.0/24"), nets: []xnetip.Network4{xnetip.MustParseNetwork4("192.0.0.0/24"), xnetip.MustParseNetwork4("65.0.0.0/24")}, want: xnetip.MustParseNetwork4("0.0.0.0/62.255.255.0")},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			require.Equal(t, testCase.want, testCase.receiver.SupernetFor(testCase.nets))
		})
	}
}

// verifies that a complete set of sibling blocks folds to their
// common parent, from every choice of receiver.
func Test_Network4_SupernetFor_SiblingBlocksFoldToParent(t *testing.T) {
	parent := xnetip.MustParseNetwork4("192.0.2.0/24")
	blocks := make([]xnetip.Network4, 8)
	for idx := range blocks {
		network, err := xnetip.Network4FromCIDR(netipAddrFrom4Bits(0xC0000200|uint32(idx)*32), 27)
		require.NoError(t, err)
		blocks[idx] = network
	}
	for receiverIdx, receiver := range blocks {
		others := slices.Concat(blocks[:receiverIdx], blocks[receiverIdx+1:])
		require.Equal(t, parent, receiver.SupernetFor(others), "receiver %v", receiver)
	}
	halves := make([]xnetip.Network4, 16)
	for idx := range halves {
		network, err := xnetip.Network4FromCIDR(netipAddrFrom4Bits(0xC0000200|uint32(idx)*16), 28)
		require.NoError(t, err)
		halves[idx] = network
	}
	require.Equal(t, parent, halves[0].SupernetFor(halves[1:]))
}

// verifies that non-contiguous inputs fold bit by bit: holes of the
// input masks and address disagreements both clear result bits.
func Test_Network4_SupernetFor_NonContiguousMasks(t *testing.T) {
	cases := []struct {
		name     string
		receiver xnetip.Network4
		nets     []xnetip.Network4
		want     xnetip.Network4
	}{
		{name: "three two-run networks crossing the first octet", receiver: xnetip.MustParseNetwork4("10.40.0.1/255.255.0.255"), nets: []xnetip.Network4{xnetip.MustParseNetwork4("10.40.0.2/255.255.0.255"), xnetip.MustParseNetwork4("11.40.0.3/255.255.0.255")}, want: xnetip.MustParseNetwork4("10.40.0.0/254.255.0.252")},
		{name: "alternating addresses disagree on every bit", receiver: xnetip.MustParseNetwork4("170.170.170.170/255.255.255.255"), nets: []xnetip.Network4{xnetip.MustParseNetwork4("85.85.85.85/255.255.255.255")}, want: xnetip.MustParseNetwork4("0.0.0.0/0")},
		{name: "mask of the input narrows the result", receiver: xnetip.MustParseNetwork4("10.0.0.0/255.255.255.0"), nets: []xnetip.Network4{xnetip.MustParseNetwork4("10.0.0.0/255.0.255.0")}, want: xnetip.MustParseNetwork4("10.0.0.0/255.0.255.0")},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			require.Equal(t, testCase.want, testCase.receiver.SupernetFor(testCase.nets))
		})
	}
}

// verifies that the fold agrees with the simple oracle on random
// receivers and slices.
func Test_Network4_SupernetFor_MatchesReferenceProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		receiver := genNetwork4.Draw(t, "receiver")
		nets := rapid.SliceOfN(genNetwork4, 0, 32).Draw(t, "nets")
		require.Equal(t, supernetForReferenceIPv4(t, receiver, nets), receiver.SupernetFor(nets))
	})
}

// verifies that the result is normalized and contains the receiver
// and every element.
func Test_Network4_SupernetFor_ContainsAllProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		receiver := genNetwork4.Draw(t, "receiver")
		nets := rapid.SliceOfN(genNetwork4, 0, 32).Draw(t, "nets")
		result := receiver.SupernetFor(nets)
		resultAddr, resultMask := ipv4NetworkBits(result)
		require.Equal(t, resultAddr, resultAddr&resultMask)
		require.True(t, result.Contains(receiver))
		for _, network := range nets {
			require.True(t, result.Contains(network), "element %v", network)
		}
	})
}

// verifies bit-level maximality: every kept mask bit is masked and
// agreed on by every input.
//
// Conversely, every dropped bit of the receiver's mask has an input
// that either leaves the bit unmasked or disagrees with the receiver
// on it, so no further bit could have been kept.
func Test_Network4_SupernetFor_MaximalityProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		receiver := genNetwork4.Draw(t, "receiver")
		nets := rapid.SliceOfN(genNetwork4, 0, 32).Draw(t, "nets")
		result := receiver.SupernetFor(nets)
		receiverAddr, receiverMask := ipv4NetworkBits(receiver)
		_, resultMask := ipv4NetworkBits(result)
		for bit := range 32 {
			probe := uint32(1) << bit
			switch {
			case resultMask&probe != 0:
				require.NotZero(t, receiverMask&probe, "kept bit %d outside the receiver mask", bit)
				for _, network := range nets {
					addr, mask := ipv4NetworkBits(network)
					require.NotZero(t, mask&probe, "kept bit %d unmasked by %v", bit, network)
					require.Equal(t, receiverAddr&probe, addr&probe, "kept bit %d disagreed on by %v", bit, network)
				}
			case receiverMask&probe != 0:
				dropped := false
				for _, network := range nets {
					addr, mask := ipv4NetworkBits(network)
					if mask&probe == 0 || addr&probe != receiverAddr&probe {
						dropped = true
					}
				}
				require.True(t, dropped, "bit %d dropped with no input forcing it", bit)
			}
		}
	})
}

// verifies that the fold does not depend on the order of the slice.
func Test_Network4_SupernetFor_OrderIndependenceProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		receiver := genNetwork4.Draw(t, "receiver")
		nets := rapid.SliceOfN(genNetwork4, 0, 32).Draw(t, "nets")
		shuffled := rapid.Permutation(nets).Draw(t, "shuffled")
		require.Equal(t, receiver.SupernetFor(nets), receiver.SupernetFor(shuffled))
	})
}

// verifies that whenever two networks merge, the merged network is
// exactly the supernet of one for the other.
func Test_Network4_SupernetFor_AgreesWithMergeProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		left := genNetwork4.Draw(t, "left")
		right := genNetwork4.Draw(t, "right")
		if merged, ok := left.Merge(right); ok {
			require.Equal(t, merged, left.SupernetFor([]xnetip.Network4{right}))
		}
		pair := genIPv4LowestBitSiblingPair.Draw(t, "pair")
		merged, ok := pair[0].Merge(pair[1])
		require.True(t, ok)
		require.Equal(t, merged, pair[0].SupernetFor(pair[1:]))
	})
}

// verifies that the fold allocates nothing over a 64-element slice,
// whatever the mask's shape.
func Test_Network4_SupernetFor_AllocationFree(t *testing.T) {
	related := ipv4RelatedNetworks(t, 64)
	nonContiguous := ipv4RelatedNonContiguousNetworks(t, 64)
	requireNoAllocs(t, func() { networkSink = related[0].SupernetFor(related[1:]) })
	requireNoAllocs(t, func() { networkSink = nonContiguous[0].SupernetFor(nonContiguous[1:]) })
}

func BenchmarkNetwork4_SupernetFor_64x28(b *testing.B) {
	nets := ipv4RelatedNetworks(b, 64)
	b.ReportAllocs()
	for b.Loop() {
		networkSink = nets[0].SupernetFor(nets[1:])
	}
}

func BenchmarkNetwork4_SupernetFor_1024x28(b *testing.B) {
	nets := ipv4RelatedNetworks(b, 1024)
	b.ReportAllocs()
	for b.Loop() {
		networkSink = nets[0].SupernetFor(nets[1:])
	}
}

func BenchmarkNetwork4_SupernetFor_1024xNonContiguous(b *testing.B) {
	nets := ipv4RelatedNonContiguousNetworks(b, 1024)
	b.ReportAllocs()
	for b.Loop() {
		networkSink = nets[0].SupernetFor(nets[1:])
	}
}

// verifies that the mask is truncated at its first zero bit and the
// address re-normalized under the leading run.
func Test_Network4_ToContiguous_TruncatesAtFirstZeroBit(t *testing.T) {
	cases := []struct {
		name  string
		input string
		want  string
	}{
		{name: "two-run mask", input: "192.168.0.1/255.255.0.255", want: "192.168.0.0/16"},
		{name: "already contiguous", input: "10.0.0.0/8", want: "10.0.0.0/8"},
		{name: "universe", input: "0.0.0.0/0", want: "0.0.0.0/0"},
		{name: "host route", input: "10.0.0.1/32", want: "10.0.0.1/32"},
		{name: "mask with empty leading run", input: "0.0.0.1/0.0.0.255", want: "0.0.0.0/0"},
		{name: "trailing zero is not a hole", input: "10.0.0.0/255.255.255.254", want: "10.0.0.0/31"},
		{name: "hole at the half boundary", input: "10.1.2.3/255.254.255.255", want: "10.0.0.0/15"},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			network := xnetip.MustParseNetwork4(testCase.input)
			require.Equal(t, xnetip.MustParseContiguous4(testCase.want), network.ToContiguous())
		})
	}
}

// verifies that the zero network truncates to the zero wrapper.
func Test_Network4_ToContiguous_ZeroValue(t *testing.T) {
	require.Equal(t, xnetip.Contiguous[xnetip.Network4]{}, xnetip.Network4{}.ToContiguous())
}

// verifies that widening the supernet fixtures keeps the leading run
// and drops every one bit after the first hole.
func Test_Network4_ToContiguous_SupernetFixtures(t *testing.T) {
	cases := []struct {
		name  string
		input string
		want  string
	}{
		{name: "hole in the third octet", input: "10.40.100.1/255.255.252.255", want: "10.40.100.0/22"},
		{name: "hole in the first octet", input: "10.40.100.1/254.255.252.255", want: "10.0.0.0/7"},
		{name: "zero third octet ends the run", input: "192.168.0.0/255.255.16.0", want: "192.168.0.0/16"},
		{name: "empty leading run widens to the universe", input: "0.0.0.0/62.255.255.0", want: "0.0.0.0/0"},
		{name: "sparse low mask bits", input: "10.40.0.0/254.255.0.252", want: "10.0.0.0/7"},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			network := xnetip.MustParseNetwork4(testCase.input)
			require.Equal(t, xnetip.MustParseContiguous4(testCase.want), network.ToContiguous())
		})
	}
}

// verifies that a non-contiguous mask keeps only its leading run of
// ones.
func Test_Network4_ToContiguous_NonContiguousMasks(t *testing.T) {
	cases := []struct {
		name  string
		input string
		want  string
	}{
		{name: "alternating mask keeps one bit", input: "170.85.170.85/170.85.170.85", want: "128.0.0.0/1"},
		{name: "inverse alternating mask keeps nothing", input: "85.170.85.170/85.170.85.170", want: "0.0.0.0/0"},
		{name: "geo-style mask keeps the first octet", input: "10.0.1.0/255.0.255.0", want: "10.0.0.0/8"},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			network := xnetip.MustParseNetwork4(testCase.input)
			require.Equal(t, xnetip.MustParseContiguous4(testCase.want), network.ToContiguous())
		})
	}
}

// verifies that the wrapped result of every truncation satisfies the
// contiguity its type claims, pinning the blind wrap.
func Test_Network4_ToContiguous_ResultContiguousProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		network := genNetwork4.Draw(t, "network")
		require.True(t, network.ToContiguous().Network().IsContiguous())
	})
}

// verifies that truncating an already truncated network changes
// nothing.
func Test_Network4_ToContiguous_IdempotentProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		network := genNetwork4.Draw(t, "network")
		block := network.ToContiguous()
		require.Equal(t, block, block.Network().ToContiguous())
	})
}

// verifies that the result's prefix length equals the number of
// leading one bits of the input mask.
func Test_Network4_ToContiguous_PrefixIsLeadingOnesProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		network := genNetwork4.Draw(t, "network")
		prefixLen, ok := network.ToContiguous().Network().PrefixLen()
		require.True(t, ok)
		count := 0
	counting:
		for _, octet := range network.Mask().As4() {
			for bit := 7; bit >= 0; bit-- {
				if octet&(1<<bit) == 0 {
					break counting
				}
				count++
			}
		}
		require.Equal(t, count, prefixLen)
	})
}

// verifies that the block always contains the network it widened.
func Test_Network4_ToContiguous_ContainsOriginalProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		network := genNetwork4.Draw(t, "network")
		require.True(t, network.ToContiguous().Network().Contains(network))
	})
}

// verifies that on contiguous input the widening conversion equals
// the exact one and changes nothing.
func Test_Network4_ToContiguous_AgreesWithContiguousFromProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		block := genContiguous4.Draw(t, "block")
		require.Equal(t, block, block.Network().ToContiguous())
		exact, ok := xnetip.ContiguousFrom(block.Network())
		require.True(t, ok)
		require.Equal(t, exact, block.Network().ToContiguous())
	})
}

// verifies that the truncated network holds no address bit outside
// its mask.
func Test_Network4_ToContiguous_ResultNormalizedProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		network := genNetwork4.Draw(t, "network")
		addr, mask := ipv4NetworkBits(network.ToContiguous().Network())
		require.Equal(t, addr&mask, addr)
	})
}

// verifies that the result agrees with the std masked prefix of the
// input address under the truncated length.
func Test_Network4_ToContiguous_MatchesNetipMaskedProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		network := genNetwork4.Draw(t, "network")
		block := network.ToContiguous()
		prefixLen, ok := block.Network().PrefixLen()
		require.True(t, ok)
		prefix, ok := block.Network().Prefix()
		require.True(t, ok)
		require.Equal(t, netip.PrefixFrom(network.Addr(), prefixLen).Masked(), prefix)
	})
}

// verifies that truncation allocates nothing for either mask shape.
func Test_Network4_ToContiguous_AllocationFree(t *testing.T) {
	contiguous := xnetip.MustParseNetwork4("192.168.0.0/16")
	nonContiguous := xnetip.MustParseNetwork4("192.168.0.1/255.255.0.255")
	requireNoAllocs(t, func() { contiguous4Sink = contiguous.ToContiguous() })
	requireNoAllocs(t, func() { contiguous4Sink = nonContiguous.ToContiguous() })
}

func BenchmarkNetwork4_ToContiguous_Contiguous(b *testing.B) {
	network := xnetip.MustParseNetwork4("192.168.0.0/16")
	b.ReportAllocs()
	for b.Loop() {
		contiguous4Sink = network.ToContiguous()
	}
}

func BenchmarkNetwork4_ToContiguous_NonContiguous(b *testing.B) {
	network := xnetip.MustParseNetwork4("192.168.0.1/255.255.0.255")
	b.ReportAllocs()
	for b.Loop() {
		contiguous4Sink = network.ToContiguous()
	}
}
