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
	require.Equal(t, netip.MustParseAddr("::"), network.Addr())
	require.Equal(t, netip.MustParseAddr("::"), network.Mask())
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
		addrBytes := addr.As16()
		maskBytes := mask.As16()
		var wantBytes [16]byte
		for idx := range wantBytes {
			wantBytes[idx] = addrBytes[idx] & maskBytes[idx]
		}
		require.Equal(t, netip.AddrFrom16(wantBytes), network.Addr())
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
		network, err := xnetip.IPv6NetworkFrom(prefix.Addr(), netipAddrFrom6Bits(maskHi, maskLo))
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
	network, err := xnetip.IPv6NetworkFrom(addr, mask)
	require.NoError(t, err)
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
		maskBytes := network.Mask().As16()
		if binary.BigEndian.Uint64(maskBytes[:8]) != ^uint64(0) {
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
	network4, err := xnetip.IPv4NetworkFrom(
		netip.MustParseAddr("192.168.0.1"),
		netip.MustParseAddr("255.255.0.255"),
	)
	require.NoError(t, err)
	network := network4.ToIPv6Mapped()
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
// recovers it exactly, whatever the mask's shape.
func Test_IPv6Network_ToIPv4Mapped_RoundTripsMappedIPv4(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		network := genIPv4Network.Draw(t, "network")
		recovered, ok := network.ToIPv6Mapped().ToIPv4Mapped()
		require.True(t, ok)
		require.Equal(t, network, recovered)
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

// verifies that a successful collapse returns exactly the low four
// address and mask bytes, pinning the truncation.
func Test_IPv6Network_ToIPv4Mapped_TakesLowBits(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		network := genIPv6Network.Draw(t, "network")
		recovered, ok := network.ToIPv4Mapped()
		if !ok {
			return
		}
		addrBytes := network.Addr().As16()
		maskBytes := network.Mask().As16()
		require.Equal(t, [4]byte(addrBytes[12:]), recovered.Addr().As4())
		require.Equal(t, [4]byte(maskBytes[12:]), recovered.Mask().As4())
	})
}

// verifies that the collapse allocates nothing on either path, per the
// allocation-free runtime contract.
func Test_IPv6Network_ToIPv4Mapped_AllocationFree(t *testing.T) {
	network4, err := xnetip.IPv4NetworkFrom(
		netip.MustParseAddr("192.168.0.1"),
		netip.MustParseAddr("255.255.0.255"),
	)
	require.NoError(t, err)
	mapped := network4.ToIPv6Mapped()
	notMapped, err := xnetip.IPv6NetworkFrom(
		netip.MustParseAddr("2001:db8::"),
		netip.MustParseAddr("ffff:ffff::"),
	)
	require.NoError(t, err)
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

// verifies that the CIDR constructor clears the host bits of the
// address and produces the contiguous mask of the given length.
//
// The half-boundary lengths 63, 64 and 65 are pinned explicitly,
// because they are where a two-word implementation can misplace the
// run of ones.
func Test_IPv6NetworkFromCIDR_MasksHostBits(t *testing.T) {
	cases := []struct {
		name     string
		addr     string
		bits     int
		wantAddr string
		wantMask string
	}{
		{name: "host bits cleared at 64", addr: "2001:db8::1", bits: 64, wantAddr: "2001:db8::", wantMask: "ffff:ffff:ffff:ffff::"},
		{name: "host route keeps the address", addr: "2001:db8::1", bits: 128, wantAddr: "2001:db8::1", wantMask: "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"},
		{name: "zero length is the universe", addr: "2001:db8::1", bits: 0, wantAddr: "::", wantMask: "::"},
		{name: "single leading bit", addr: "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", bits: 1, wantAddr: "8000::", wantMask: "8000::"},
		{name: "length 63 stops short of the half boundary", addr: "2001:db8:1:3::1", bits: 63, wantAddr: "2001:db8:1:2::", wantMask: "ffff:ffff:ffff:fffe::"},
		{name: "length 65 crosses the half boundary", addr: "2001:db8::ffff:0:0:1", bits: 65, wantAddr: "2001:db8::8000:0:0:0", wantMask: "ffff:ffff:ffff:ffff:8000::"},
		{name: "point-to-point pair keeps bit 127", addr: "2001:db8::3", bits: 127, wantAddr: "2001:db8::2", wantMask: "ffff:ffff:ffff:ffff:ffff:ffff:ffff:fffe"},
		{name: "length 40 clears mid-group bits", addr: "2a02:6b8:c00:1:2:3:4:5", bits: 40, wantAddr: "2a02:6b8:c00::", wantMask: "ffff:ffff:ff00::"},
		{name: "IPv4-mapped address is IPv6 and accepted", addr: "::ffff:192.168.1.5", bits: 120, wantAddr: "::ffff:192.168.1.0", wantMask: "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ff00"},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			network, err := xnetip.IPv6NetworkFromCIDR(netip.MustParseAddr(testCase.addr), testCase.bits)
			require.NoError(t, err)
			require.Equal(t, netip.MustParseAddr(testCase.wantAddr), network.Addr())
			require.Equal(t, netip.MustParseAddr(testCase.wantMask), network.Mask())
		})
	}
}

// verifies that the universe network built from a zero length equals
// the type's zero value.
func Test_IPv6NetworkFromCIDR_UniverseEqualsZeroValue(t *testing.T) {
	network, err := xnetip.IPv6NetworkFromCIDR(netip.MustParseAddr("2001:db8::1"), 0)
	require.NoError(t, err)
	require.Equal(t, xnetip.IPv6Network{}, network)
}

// verifies that a zone suffix on the address is dropped silently, the
// network being zone-free by construction.
func Test_IPv6NetworkFromCIDR_DropsZoneSilently(t *testing.T) {
	network, err := xnetip.IPv6NetworkFromCIDR(netip.MustParseAddr("fe80::1%eth0"), 64)
	require.NoError(t, err)
	require.Equal(t, netip.MustParseAddr("fe80::"), network.Addr())
	require.Empty(t, network.Addr().Zone())
}

// verifies that a prefix length outside 0 through 128 yields the
// overflow sentinel and the zero network.
func Test_IPv6NetworkFromCIDR_RejectsOutOfRangeBits(t *testing.T) {
	cases := []struct {
		name string
		bits int
	}{
		{name: "one past the family width", bits: 129},
		{name: "negative length", bits: -1},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			network, err := xnetip.IPv6NetworkFromCIDR(netip.MustParseAddr("2001:db8::1"), testCase.bits)
			require.ErrorIs(t, err, xnetip.ErrCIDROverflow)
			require.Equal(t, xnetip.IPv6Network{}, network)
		})
	}
}

// verifies that an Is4 address or the invalid zero address yields the
// family-mismatch sentinel and the zero network for a valid length.
func Test_IPv6NetworkFromCIDR_RejectsForeignFamily(t *testing.T) {
	cases := []struct {
		name string
		addr netip.Addr
	}{
		{name: "IPv4 address", addr: netip.MustParseAddr("1.2.3.4")},
		{name: "invalid zero address", addr: netip.Addr{}},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			network, err := xnetip.IPv6NetworkFromCIDR(testCase.addr, 64)
			require.ErrorIs(t, err, xnetip.ErrAddrFamilyMismatch)
			require.Equal(t, xnetip.IPv6Network{}, network)
		})
	}
}

// verifies that the CIDR constructor agrees with the net/netip oracle
// for masking a prefix and always yields a normalized result.
//
// Non-contiguous masks cannot arise from this constructor — the mask
// is a leading run of ones by construction — so the contiguity of
// every drawn result is asserted in place of a non-contiguous case
// table, with the predecessor trick applied across the 64-bit halves.
func Test_IPv6NetworkFromCIDR_MatchesNetipMasked(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		addr := genNetipAddr6.Draw(t, "addr")
		bits := rapid.IntRange(0, 128).Draw(t, "bits")
		network, err := xnetip.IPv6NetworkFromCIDR(addr, bits)
		require.NoError(t, err)
		require.Equal(t, netip.PrefixFrom(addr, bits).Masked().Addr(), network.Addr())
		var wantHi, wantLo uint64
		if bits <= 64 {
			wantHi = ^uint64(0) << (64 - bits)
		} else {
			wantHi = ^uint64(0)
			wantLo = ^uint64(0) << (128 - bits)
		}
		require.Equal(t, netipAddrFrom6Bits(wantHi, wantLo), network.Mask())
		maskBytes := network.Mask().As16()
		maskHi := binary.BigEndian.Uint64(maskBytes[:8])
		maskLo := binary.BigEndian.Uint64(maskBytes[8:])
		predecessorHi, predecessorLo := maskHi, maskLo-1
		if maskLo == 0 {
			predecessorHi, predecessorLo = maskHi-1, ^uint64(0)
		}
		require.Equal(t, ^uint64(0), maskHi|predecessorHi)
		require.Equal(t, ^uint64(0), maskLo|predecessorLo)
		addrBytes := network.Addr().As16()
		addrHi := binary.BigEndian.Uint64(addrBytes[:8])
		addrLo := binary.BigEndian.Uint64(addrBytes[8:])
		require.Equal(t, addrHi, addrHi&maskHi)
		require.Equal(t, addrLo, addrLo&maskLo)
	})
}

// verifies that every length outside 0 through 128, far past the width
// or negative, yields the overflow sentinel.
func Test_IPv6NetworkFromCIDR_OverflowProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		addr := genNetipAddr6.Draw(t, "addr")
		bits := rapid.OneOf(rapid.IntRange(129, 400), rapid.IntRange(-400, -1)).Draw(t, "bits")
		network, err := xnetip.IPv6NetworkFromCIDR(addr, bits)
		require.ErrorIs(t, err, xnetip.ErrCIDROverflow)
		require.Equal(t, xnetip.IPv6Network{}, network)
	})
}

// verifies that the CIDR constructor allocates nothing on the success
// path, per the allocation-free runtime contract.
func Test_IPv6NetworkFromCIDR_AllocationFree(t *testing.T) {
	addr := netip.MustParseAddr("2001:db8::1")
	var err error
	requireNoAllocs(t, func() { network6Sink, err = xnetip.IPv6NetworkFromCIDR(addr, 64) })
	require.NoError(t, err)
}

// verifies that the host-route constructor pairs the address with the
// all-ones mask without clearing a single address bit.
//
// A non-contiguous mask table is not applicable to this constructor:
// the mask is fixed to all ones, the universe of bits, so the case
// with set bits on both halves pins that neither half is dropped.
func Test_IPv6NetworkFromAddr_BuildsHostRoute(t *testing.T) {
	cases := []struct {
		name string
		addr string
	}{
		{name: "documentation host route", addr: "2001:db8::1"},
		{name: "loopback", addr: "::1"},
		{name: "unspecified address", addr: "::"},
		{name: "all ones address", addr: "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"},
		{name: "bits on both halves", addr: "2a02:6b8:c00:1:2:3:4:1"},
		{name: "IPv4-mapped address stays IPv6", addr: "::ffff:192.168.0.1"},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			network, err := xnetip.IPv6NetworkFromAddr(netip.MustParseAddr(testCase.addr))
			require.NoError(t, err)
			require.Equal(t, netip.MustParseAddr(testCase.addr), network.Addr())
			require.Equal(t, netip.MustParseAddr("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"), network.Mask())
		})
	}
}

// verifies that the host route carries the exact bit pattern of its
// address on both halves and the all-ones mask pattern.
func Test_IPv6NetworkFromAddr_PreservesBitPattern(t *testing.T) {
	network, err := xnetip.IPv6NetworkFromAddr(netipAddrFrom6Bits(0x20010DB800000000, 0x1))
	require.NoError(t, err)
	require.Equal(t, netipAddrFrom6Bits(0x20010DB800000000, 0x1), network.Addr())
	require.Equal(t, netipAddrFrom6Bits(math.MaxUint64, math.MaxUint64), network.Mask())
}

// verifies that the host route equals the same network built through
// the checked normalizing constructor.
func Test_IPv6NetworkFromAddr_EqualsCheckedConstructor(t *testing.T) {
	fromAddr, err := xnetip.IPv6NetworkFromAddr(netip.MustParseAddr("2001:db8::1"))
	require.NoError(t, err)
	fromPair, err := xnetip.IPv6NetworkFrom(
		netip.MustParseAddr("2001:db8::1"),
		netip.MustParseAddr("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"),
	)
	require.NoError(t, err)
	require.Equal(t, fromPair, fromAddr)
}

// verifies that an Is4 address or the invalid zero address yields the
// family-mismatch sentinel and the zero network.
func Test_IPv6NetworkFromAddr_RejectsForeignFamily(t *testing.T) {
	cases := []struct {
		name string
		addr netip.Addr
	}{
		{name: "IPv4 address", addr: netip.MustParseAddr("1.2.3.4")},
		{name: "invalid zero address", addr: netip.Addr{}},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			network, err := xnetip.IPv6NetworkFromAddr(testCase.addr)
			require.ErrorIs(t, err, xnetip.ErrAddrFamilyMismatch)
			require.Equal(t, xnetip.IPv6Network{}, network)
		})
	}
}

// verifies that every Is6 address lifts into its host route with the
// address preserved and the mask all ones.
//
// The result must also equal the same network built through the
// checked normalizing constructor, so the two entry points agree.
func Test_IPv6NetworkFromAddr_HostRouteProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		addr := genNetipAddr6.Draw(t, "addr")
		network, err := xnetip.IPv6NetworkFromAddr(addr)
		require.NoError(t, err)
		require.Equal(t, addr, network.Addr())
		require.Equal(t, netipAddrFrom6Bits(math.MaxUint64, math.MaxUint64), network.Mask())
		fromPair, err := xnetip.IPv6NetworkFrom(addr, netipAddrFrom6Bits(math.MaxUint64, math.MaxUint64))
		require.NoError(t, err)
		require.Equal(t, fromPair, network)
	})
}

// verifies that every Is4 address is rejected with the family-mismatch
// sentinel.
func Test_IPv6NetworkFromAddr_RejectsIs4Property(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		addr := genNetipAddr4.Draw(t, "addr")
		network, err := xnetip.IPv6NetworkFromAddr(addr)
		require.ErrorIs(t, err, xnetip.ErrAddrFamilyMismatch)
		require.Equal(t, xnetip.IPv6Network{}, network)
	})
}

// verifies that the host route agrees with the net/netip oracle for a
// full-length masked prefix.
func Test_IPv6NetworkFromAddr_MatchesNetipHostPrefix(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		addr := genNetipAddr6.Draw(t, "addr")
		network, err := xnetip.IPv6NetworkFromAddr(addr)
		require.NoError(t, err)
		require.Equal(t, netip.PrefixFrom(addr, 128).Masked().Addr(), network.Addr())
	})
}

// verifies that the host-route constructor allocates nothing on the
// success path, per the allocation-free runtime contract.
func Test_IPv6NetworkFromAddr_AllocationFree(t *testing.T) {
	addr := netip.MustParseAddr("2001:db8::1")
	var err error
	requireNoAllocs(t, func() { network6Sink, err = xnetip.IPv6NetworkFromAddr(addr) })
	require.NoError(t, err)
}
