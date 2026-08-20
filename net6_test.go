package xnetip_test

import (
	"encoding/binary"
	"math"
	"net/netip"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/yanet-platform/xnetip"
	"pgregory.net/rapid"
)

// verifies that the constructor clears every address bit outside the
// mask and keeps the mask unchanged, whatever the mask's shape.
//
// The cases include masks touching only one 64-bit half and masks with
// holes straddling the half boundary, where each half must be
// normalized independently.
func Test_IPv6NetworkFrom_NormalizesAddressByMask(t *testing.T) {
	cases := []struct {
		name     string
		addr     string
		mask     string
		wantAddr string
	}{
		{name: "contiguous mask clears host bits", addr: "2a02:6b8:c00:1:2:3:4:5", mask: "ffff:ffff:ff00::", wantAddr: "2a02:6b8:c00::"},
		{name: "host route keeps the address", addr: "2a02:6b8::1", mask: "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", wantAddr: "2a02:6b8::1"},
		{name: "all-zero mask clears everything", addr: "2001:db8::1", mask: "::", wantAddr: "::"},
		{name: "high-word-only mask clears the low half", addr: "2001:db8:1:2:3:4:5:6", mask: "ffff:ffff:ffff:ffff::", wantAddr: "2001:db8:1:2::"},
		{name: "low-word-only mask clears the high half", addr: "2001:db8:1:2:3:4:5:6", mask: "::ffff:ffff:ffff:ffff", wantAddr: "::3:4:5:6"},
		{name: "IPv4-mapped address is IPv6 and accepted", addr: "::ffff:1.2.3.4", mask: "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ff00", wantAddr: "::ffff:1.2.3.0"},
		{name: "two-run mask clears the host tail", addr: "2a02:6b8:c00::1234:9:9", mask: "ffff:ffff:ff00::ffff:ffff:0:0", wantAddr: "2a02:6b8:c00::1234:0:0"},
		{name: "already normalized address stays", addr: "2a02:6b8:c00::1234:0:0", mask: "ffff:ffff:ff00::ffff:ffff:0:0", wantAddr: "2a02:6b8:c00::1234:0:0"},
		{name: "alternating groups keep every second group", addr: "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", mask: "ffff:0:ffff:0:ffff:0:ffff:0", wantAddr: "ffff:0:ffff:0:ffff:0:ffff:0"},
		{name: "mask hole across bit 64 clears groups 4 and 5", addr: "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", mask: "ffff:ffff:ffff:0:0:ffff:ffff:ffff", wantAddr: "ffff:ffff:ffff:0:0:ffff:ffff:ffff"},
		{name: "single lowest bit survives", addr: "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", mask: "::1", wantAddr: "::1"},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			network, err := xnetip.IPv6NetworkFrom(
				netip.MustParseAddr(testCase.addr),
				netip.MustParseAddr(testCase.mask),
			)
			require.NoError(t, err)
			require.Equal(t, netip.MustParseAddr(testCase.wantAddr), network.Addr())
			require.Equal(t, netip.MustParseAddr(testCase.mask), network.Mask())
		})
	}
}

// verifies that a non-Is6 argument in either position yields the
// family-mismatch sentinel and the zero network.
func Test_IPv6NetworkFrom_RejectsForeignFamily(t *testing.T) {
	cases := []struct {
		name string
		addr netip.Addr
		mask netip.Addr
	}{
		{name: "IPv4 address", addr: netip.MustParseAddr("1.2.3.4"), mask: netip.MustParseAddr("ffff::")},
		{name: "IPv4 mask", addr: netip.MustParseAddr("2001:db8::"), mask: netip.MustParseAddr("255.0.0.0")},
		{name: "invalid zero address", addr: netip.Addr{}, mask: netip.MustParseAddr("ffff::")},
		{name: "invalid zero mask", addr: netip.MustParseAddr("2001:db8::"), mask: netip.Addr{}},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			network, err := xnetip.IPv6NetworkFrom(testCase.addr, testCase.mask)
			require.ErrorIs(t, err, xnetip.ErrAddrFamilyMismatch)
			require.Equal(t, xnetip.IPv6Network{}, network)
		})
	}
}

// verifies that a zone on either argument is dropped silently, the
// network being zone-free by construction.
func Test_IPv6NetworkFrom_DropsZoneSilently(t *testing.T) {
	network, err := xnetip.IPv6NetworkFrom(
		netip.MustParseAddr("fe80::1%eth0"),
		netip.MustParseAddr("ffff::%eth0"),
	)
	require.NoError(t, err)
	require.Equal(t, netip.MustParseAddr("fe80::"), network.Addr())
	require.Equal(t, netip.MustParseAddr("ffff::"), network.Mask())
}

// verifies that the accessors return Is6, zone-free netip values.
func Test_IPv6Network_Accessors_ReturnIs6Views(t *testing.T) {
	network, err := xnetip.IPv6NetworkFrom(
		netip.MustParseAddr("2a02:6b8::1"),
		netip.MustParseAddr("ffff:0:ffff::"),
	)
	require.NoError(t, err)
	require.True(t, network.Addr().Is6())
	require.True(t, network.Mask().Is6())
	require.Empty(t, network.Addr().Zone())
	require.Empty(t, network.Mask().Zone())
}

// verifies that the all-zero mask produces the unspecified network,
// which is the zero value of the type.
func Test_IPv6NetworkFrom_UniverseEqualsZeroValue(t *testing.T) {
	network, err := xnetip.IPv6NetworkFrom(
		netip.MustParseAddr("2001:db8::1"),
		netip.MustParseAddr("::"),
	)
	require.NoError(t, err)
	require.Equal(t, xnetip.IPv6Network{}, network)
}

// verifies that the zero value is the unspecified network ::/0.
func Test_IPv6Network_ZeroValue_IsUnspecifiedNetwork(t *testing.T) {
	var network xnetip.IPv6Network
	addrHi, addrLo, maskHi, maskLo := network.Bits()
	require.Equal(t, uint64(0), addrHi)
	require.Equal(t, uint64(0), addrLo)
	require.Equal(t, uint64(0), maskHi)
	require.Equal(t, uint64(0), maskLo)
	require.Equal(t, netip.MustParseAddr("::"), network.Addr())
	require.Equal(t, netip.MustParseAddr("::"), network.Mask())
}

// verifies that the integer constructor matches the checked one and
// the bits view returns the host-order halves it was built from.
func Test_IPv6NetworkFromBits_RoundTrip(t *testing.T) {
	expected, err := xnetip.IPv6NetworkFrom(
		netip.MustParseAddr("2a02:6b8:b081:7228::1:b"),
		netip.MustParseAddr("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"),
	)
	require.NoError(t, err)
	network := xnetip.IPv6NetworkFromBits(0x2a0206b8b0817228, 0x000000000001000b, math.MaxUint64, math.MaxUint64)
	require.Equal(t, expected, network)
	addrHi, addrLo, maskHi, maskLo := network.Bits()
	require.Equal(t, uint64(0x2a0206b8b0817228), addrHi)
	require.Equal(t, uint64(0x000000000001000b), addrLo)
	require.Equal(t, uint64(math.MaxUint64), maskHi)
	require.Equal(t, uint64(math.MaxUint64), maskLo)
}

// verifies that the integer constructor normalizes the address by the
// mask like the checked constructor, each half independently.
func Test_IPv6NetworkFromBits_Normalizes(t *testing.T) {
	network := xnetip.IPv6NetworkFromBits(0x20010db800000000, 1, 0xffffffff00000000, 0)
	addrHi, addrLo, maskHi, maskLo := network.Bits()
	require.Equal(t, uint64(0x20010db800000000), addrHi)
	require.Equal(t, uint64(0), addrLo)
	require.Equal(t, uint64(0xffffffff00000000), maskHi)
	require.Equal(t, uint64(0), maskLo)
}

// verifies that the single-lowest-bit mask keeps exactly bit zero of
// the low half, pinning the half layout of the bits view.
func Test_IPv6NetworkFrom_SingleLowestBit_Bits(t *testing.T) {
	network, err := xnetip.IPv6NetworkFrom(
		netip.MustParseAddr("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"),
		netip.MustParseAddr("::1"),
	)
	require.NoError(t, err)
	addrHi, addrLo, maskHi, maskLo := network.Bits()
	require.Equal(t, uint64(0), addrHi)
	require.Equal(t, uint64(1), addrLo)
	require.Equal(t, uint64(0), maskHi)
	require.Equal(t, uint64(1), maskLo)
}

// verifies that two constructions from different hosts of one subnet
// compare equal with ==, which only normalization makes sound.
func Test_IPv6Network_Equality_AfterNormalization(t *testing.T) {
	left, err := xnetip.IPv6NetworkFrom(
		netip.MustParseAddr("2a02:6b8::1"),
		netip.MustParseAddr("ffff:ffff::"),
	)
	require.NoError(t, err)
	right, err := xnetip.IPv6NetworkFrom(
		netip.MustParseAddr("2a02:6b8::ffff:1:2:3"),
		netip.MustParseAddr("ffff:ffff::"),
	)
	require.NoError(t, err)
	operatorEqual := left == right
	require.True(t, operatorEqual)
}

// verifies that the checked constructor accepts every Is6 pair and
// always produces a normalized result with the mask preserved.
func Test_IPv6NetworkFrom_NormalizationProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		addr := genNetipAddr6.Draw(t, "addr")
		mask := genNetipAddr6.Draw(t, "mask")
		network, err := xnetip.IPv6NetworkFrom(addr, mask)
		require.NoError(t, err)
		addrHi, addrLo, maskHi, maskLo := network.Bits()
		require.Equal(t, addrHi&maskHi, addrHi)
		require.Equal(t, addrLo&maskLo, addrLo)
		require.Equal(t, mask, network.Mask())
	})
}

// verifies that reconstructing a network from its own accessors
// reproduces it exactly and without error.
func Test_IPv6NetworkFrom_Idempotent(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		network := genIPv6Network.Draw(t, "network")
		rebuilt, err := xnetip.IPv6NetworkFrom(network.Addr(), network.Mask())
		require.NoError(t, err)
		require.Equal(t, network, rebuilt)
	})
}

// verifies that the bits view and the integer constructor invert each
// other.
func Test_IPv6NetworkFromBits_RoundTripsBits(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		network := genIPv6Network.Draw(t, "network")
		require.Equal(t, network, xnetip.IPv6NetworkFromBits(network.Bits()))
	})
}

// verifies that an Is4 value in either argument position always yields
// the family-mismatch sentinel, whatever the other argument is.
func Test_IPv6NetworkFrom_RejectsIs4EitherPosition(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		foreign := genNetipAddr4.Draw(t, "foreign")
		valid := genNetipAddr6.Draw(t, "valid")
		_, err := xnetip.IPv6NetworkFrom(foreign, valid)
		require.ErrorIs(t, err, xnetip.ErrAddrFamilyMismatch)
		_, err = xnetip.IPv6NetworkFrom(valid, foreign)
		require.ErrorIs(t, err, xnetip.ErrAddrFamilyMismatch)
	})
}

// verifies that normalization by a contiguous mask agrees with the
// net/netip oracle for masking a prefix.
func Test_IPv6NetworkFrom_MatchesNetipMasked(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		prefix := genIPv6Prefix.Draw(t, "prefix")
		var maskHi, maskLo uint64
		if prefix.Bits() <= 64 {
			maskHi = ^uint64(0) << (64 - prefix.Bits())
		} else {
			maskHi = ^uint64(0)
			maskLo = ^uint64(0) << (128 - prefix.Bits())
		}
		var maskBytes [16]byte
		binary.BigEndian.PutUint64(maskBytes[:8], maskHi)
		binary.BigEndian.PutUint64(maskBytes[8:], maskLo)
		network, err := xnetip.IPv6NetworkFrom(prefix.Addr(), netip.AddrFrom16(maskBytes))
		require.NoError(t, err)
		require.Equal(t, prefix.Masked().Addr(), network.Addr())
	})
}

// verifies that construction and the accessors allocate nothing on the
// success path, per the allocation-free runtime contract.
func Test_IPv6Network_Constructors_AllocationFree(t *testing.T) {
	addr := netip.MustParseAddr("2a02:6b8:c00::1234:9:9")
	mask := netip.MustParseAddr("ffff:ffff:ff00::ffff:ffff:0:0")
	var err error
	requireNoAllocs(t, func() { network6Sink, err = xnetip.IPv6NetworkFrom(addr, mask) })
	require.NoError(t, err)
	requireNoAllocs(t, func() {
		network6Sink = xnetip.IPv6NetworkFromBits(0x2a0206b8b0817228, 0x1000b, ^uint64(0), ^uint64(0))
	})
	network := xnetip.IPv6NetworkFromBits(0x2a0206b8b0817228, 0, ^uint64(0), 0)
	requireNoAllocs(t, func() {
		addrHi, addrLo, maskHi, maskLo := network.Bits()
		word64Sink = addrHi ^ addrLo ^ maskHi ^ maskLo
	})
	requireNoAllocs(t, func() { addrSink = network.Addr() })
	requireNoAllocs(t, func() { addrSink = network.Mask() })
}

// verifies that a network is IPv4-mapped exactly when its address lies
// in ::ffff:0:0/96 and its mask pins all of those upper 96 bits.
//
// The low 32 mask bits are unconstrained, so non-contiguous IPv4 masks
// still qualify, while a mapped-looking address under a mask that does
// not pin the upper bits does not: collapsing it to IPv4 would lose
// addresses.
func Test_IPv6Network_IsIPv4MappedIPv6(t *testing.T) {
	cases := []struct {
		name string
		addr string
		mask string
		want bool
	}{
		{name: "mapped /96 universe", addr: "::ffff:0:0", mask: "ffff:ffff:ffff:ffff:ffff:ffff::", want: true},
		{name: "mapped host route", addr: "::ffff:c0a8:101", mask: "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", want: true},
		{name: "mapped /120", addr: "::ffff:c0a8:100", mask: "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ff00", want: true},
		{name: "plain IPv6 /40", addr: "2a02:6b8::", mask: "ffff:ffff:ff00::", want: false},
		{name: "IPv4-compatible address is not mapped", addr: "::c00a:2ff", mask: "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", want: false},
		{name: "ffff pattern under a /95 mask", addr: "::ffff:c0a8:1", mask: "ffff:ffff:ffff:ffff:ffff:fffe::", want: false},
		{name: "ffff pattern under a mask not pinning the top bits", addr: "::ffff:c0a8:1", mask: "0:ffff:ffff:ffff:ffff:ffff:ffff:ffff", want: false},
		{name: "universe", addr: "::", mask: "::", want: false},
		{name: "mapped with a non-contiguous low mask", addr: "::ffff:c0a8:1", mask: "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ff", want: true},
		{name: "mapped with an alternating low mask", addr: "::ffff:aa55:aa55", mask: "ffff:ffff:ffff:ffff:ffff:ffff:aa55:aa55", want: true},
		{name: "hole inside the upper 96 mask bits", addr: "::ffff:c0a8:1", mask: "ffff:ffff:ffff:0:ffff:ffff:ffff:ffff", want: false},
		{name: "hole in the ffff group of the address", addr: "::fff0:c0a8:1", mask: "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", want: false},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			network, err := xnetip.IPv6NetworkFrom(
				netip.MustParseAddr(testCase.addr),
				netip.MustParseAddr(testCase.mask),
			)
			require.NoError(t, err)
			require.Equal(t, testCase.want, network.IsIPv4MappedIPv6())
		})
	}
}

// verifies that the zero value, the universe ::/0, is not mapped.
func Test_IPv6Network_IsIPv4MappedIPv6_ZeroValue(t *testing.T) {
	var network xnetip.IPv6Network
	require.False(t, network.IsIPv4MappedIPv6())
}

// verifies that every image of an IPv4 network under the mapping is
// recognized as mapped, whatever the IPv4 mask's shape.
func Test_IPv6Network_IsIPv4MappedIPv6_TrueOnMappedIPv4(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		network := genIPv4Network.Draw(t, "network")
		require.True(t, network.ToIPv6Mapped().IsIPv4MappedIPv6())
	})
}

// verifies the cheap necessary condition: a network whose mask does not
// keep the whole high half is never mapped.
func Test_IPv6Network_IsIPv4MappedIPv6_FalseWhenMaskHighHalfNotFull(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		network := genIPv6Network.Draw(t, "network")
		_, _, maskHi, _ := network.Bits()
		if maskHi != ^uint64(0) {
			require.False(t, network.IsIPv4MappedIPv6())
		}
	})
}

// verifies that the predicate agrees with the byte-level oracle.
//
// The oracle spells the definition out over the 16-byte forms: the
// first ten address bytes zero, then two 0xff bytes, and the first
// twelve mask bytes 0xff.
func Test_IPv6Network_IsIPv4MappedIPv6_MatchesByteOracle(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		network := genIPv6Network.Draw(t, "network")
		addrBytes := network.Addr().As16()
		maskBytes := network.Mask().As16()
		want := true
		for idx := range 12 {
			if idx < 10 {
				want = want && addrBytes[idx] == 0
			} else {
				want = want && addrBytes[idx] == 0xff
			}
			want = want && maskBytes[idx] == 0xff
		}
		require.Equal(t, want, network.IsIPv4MappedIPv6())
	})
}

// verifies that the predicate allocates nothing, per the
// allocation-free runtime contract.
func Test_IPv6Network_IsIPv4MappedIPv6_AllocationFree(t *testing.T) {
	network := xnetip.IPv4NetworkFromBits(0xC0A80001, 0xFFFF00FF).ToIPv6Mapped()
	requireNoAllocs(t, func() { okSink = network.IsIPv4MappedIPv6() })
}

// verifies that a mapped network collapses to the IPv4 network in its
// low 32 address and mask bits, and everything else reports not ok.
//
// The guard is the strict mapped predicate: an IPv4-compatible address,
// a plain IPv6 network and a mapped-looking address under a mask that
// does not pin the upper 96 bits all refuse to collapse.
func Test_IPv6Network_ToIPv4Mapped(t *testing.T) {
	cases := []struct {
		name     string
		addr     string
		mask     string
		wantAddr string
		wantMask string
		wantOk   bool
	}{
		{name: "mapped /120 doctest", addr: "::ffff:c00a:2ff", mask: "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ff00", wantAddr: "192.10.2.0", wantMask: "255.255.255.0", wantOk: true},
		{name: "mapped /120", addr: "::ffff:c0a8:100", mask: "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ff00", wantAddr: "192.168.1.0", wantMask: "255.255.255.0", wantOk: true},
		{name: "mapped universe", addr: "::ffff:0:0", mask: "ffff:ffff:ffff:ffff:ffff:ffff::", wantAddr: "0.0.0.0", wantMask: "0.0.0.0", wantOk: true},
		{name: "mapped host route", addr: "::ffff:a01:203", mask: "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", wantAddr: "10.1.2.3", wantMask: "255.255.255.255", wantOk: true},
		{name: "mapped with a hole in the third octet", addr: "::ffff:c0a8:1", mask: "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ff", wantAddr: "192.168.0.1", wantMask: "255.255.0.255", wantOk: true},
		{name: "mapped with an alternating low mask", addr: "::ffff:aa55:aa55", mask: "ffff:ffff:ffff:ffff:ffff:ffff:aa55:aa55", wantAddr: "170.85.170.85", wantMask: "170.85.170.85", wantOk: true},
		{name: "IPv4-compatible address is not mapped", addr: "::c00a:2ff", mask: "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ff00", wantOk: false},
		{name: "plain IPv6 /32", addr: "2001:db8::", mask: "ffff:ffff::", wantOk: false},
		{name: "ffff pattern under a mask not pinning the top bits", addr: "::ffff:c0a8:1", mask: "0:ffff:ffff:ffff:ffff:ffff:ffff:ffff", wantOk: false},
		{name: "universe", addr: "::", mask: "::", wantOk: false},
		{name: "hole inside the upper 96 mask bits", addr: "::ffff:c0a8:1", mask: "ffff:ffff:ffff:0:ffff:ffff:ffff:ffff", wantOk: false},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			network, err := xnetip.IPv6NetworkFrom(
				netip.MustParseAddr(testCase.addr),
				netip.MustParseAddr(testCase.mask),
			)
			require.NoError(t, err)
			recovered, ok := network.ToIPv4Mapped()
			if !testCase.wantOk {
				require.False(t, ok)
				require.Equal(t, xnetip.IPv4Network{}, recovered)
				return
			}
			require.True(t, ok)
			expected, err := xnetip.IPv4NetworkFrom(
				netip.MustParseAddr(testCase.wantAddr),
				netip.MustParseAddr(testCase.wantMask),
			)
			require.NoError(t, err)
			require.Equal(t, expected, recovered)
		})
	}
}

// verifies that collapsing the mapped image of any IPv4 network
// recovers it exactly and normalized, whatever the mask's shape.
func Test_IPv6Network_ToIPv4Mapped_RoundTripsMappedIPv4(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		network := genIPv4Network.Draw(t, "network")
		recovered, ok := network.ToIPv6Mapped().ToIPv4Mapped()
		require.True(t, ok)
		require.Equal(t, network, recovered)
		recoveredAddr, recoveredMask := recovered.Bits()
		require.Equal(t, recoveredAddr&recoveredMask, recoveredAddr)
	})
}

// verifies that the collapse succeeds exactly when the strict mapped
// predicate holds, on every mask shape the generator draws.
func Test_IPv6Network_ToIPv4Mapped_ConsistentWithGuard(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		network := genIPv6Network.Draw(t, "network")
		_, ok := network.ToIPv4Mapped()
		require.Equal(t, network.IsIPv4MappedIPv6(), ok)
	})
}

// verifies that a successful collapse returns exactly the low 32 bits
// of the address and the mask, pinning the truncation.
func Test_IPv6Network_ToIPv4Mapped_TakesLowBits(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		network := genIPv6Network.Draw(t, "network")
		recovered, ok := network.ToIPv4Mapped()
		if !ok {
			return
		}
		_, addrLo, _, maskLo := network.Bits()
		recoveredAddr, recoveredMask := recovered.Bits()
		require.Equal(t, uint32(addrLo), recoveredAddr)
		require.Equal(t, uint32(maskLo), recoveredMask)
	})
}

// verifies that the collapse allocates nothing on either path, per the
// allocation-free runtime contract.
func Test_IPv6Network_ToIPv4Mapped_AllocationFree(t *testing.T) {
	mapped := xnetip.IPv4NetworkFromBits(0xC0A80001, 0xFFFF00FF).ToIPv6Mapped()
	notMapped := xnetip.IPv6NetworkFromBits(0x20010db800000000, 0, 0xffffffff00000000, 0)
	requireNoAllocs(t, func() { networkSink, okSink = mapped.ToIPv4Mapped() })
	requireNoAllocs(t, func() { networkSink, okSink = notMapped.ToIPv4Mapped() })
}

func BenchmarkIPv6Network_ToIPv4Mapped_Contiguous(b *testing.B) {
	network, err := xnetip.IPv6NetworkFrom(
		netip.MustParseAddr("::ffff:192.168.1.0"),
		netip.MustParseAddr("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ff00"),
	)
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	for b.Loop() {
		networkSink, okSink = network.ToIPv4Mapped()
	}
}

func BenchmarkIPv6Network_ToIPv4Mapped_NonContiguous(b *testing.B) {
	network, err := xnetip.IPv6NetworkFrom(
		netip.MustParseAddr("::ffff:c0a8:1"),
		netip.MustParseAddr("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ff00"),
	)
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	for b.Loop() {
		networkSink, okSink = network.ToIPv4Mapped()
	}
}

func BenchmarkIPv6Network_ToIPv4Mapped_NotMapped(b *testing.B) {
	network, err := xnetip.IPv6NetworkFrom(
		netip.MustParseAddr("2001:db8::"),
		netip.MustParseAddr("ffff:ffff::"),
	)
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	for b.Loop() {
		networkSink, okSink = network.ToIPv4Mapped()
	}
}
