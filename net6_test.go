package xnetip_test

import (
	"bytes"
	"encoding/binary"
	"math"
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

// verifies that the order is lexicographic on the address first and
// the mask second, both as unsigned 128-bit integers.
func Test_IPv6Network_Compare_AddressFirstMaskSecond(t *testing.T) {
	cases := []struct {
		name  string
		left  xnetip.IPv6Network
		right xnetip.IPv6Network
		want  int
	}{
		{name: "address dominates mask", left: mustIPv6Network(t, "2001::", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"), right: mustIPv6Network(t, "2001:db9::", "ffff:ffff::"), want: -1},
		{name: "equal address, mask decides", left: mustIPv6Network(t, "2001:db8::", "ffff:ffff::"), right: mustIPv6Network(t, "2001:db8::", "ffff:ffff:ffff:ffff::"), want: -1},
		{name: "equal address, larger mask after", left: mustIPv6Network(t, "2001:db8::", "ffff:ffff:ffff:ffff::"), right: mustIPv6Network(t, "2001:db8::", "ffff:ffff::"), want: 1},
		{name: "zero before middle", left: mustIPv6Network(t, "::", "::"), right: mustIPv6Network(t, "2001:db8::", "ffff:ffff::"), want: -1},
		{name: "middle before max", left: mustIPv6Network(t, "2001:db8::", "ffff:ffff::"), right: mustIPv6Network(t, "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"), want: -1},
		{name: "zero before max", left: mustIPv6Network(t, "::", "::"), right: mustIPv6Network(t, "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"), want: -1},
		{name: "low half decides when high halves agree", left: mustIPv6Network(t, "2001:db8::1", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"), right: mustIPv6Network(t, "2001:db8::2", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"), want: -1},
		{name: "high half decides regardless of low half", left: mustIPv6Network(t, "2001:db8::ffff:ffff:ffff:ffff", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"), right: mustIPv6Network(t, "2001:db9::", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"), want: -1},
		{name: "top address bit compares unsigned", left: mustIPv6Network(t, "8000::", "8000::"), right: mustIPv6Network(t, "7fff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"), want: 1},
		{name: "same address, non-contiguous mask decides", left: mustIPv6Network(t, "2001:db8::5", "ffff:ffff:ff00:ff00:ffff:ffff:ffff:ffff"), right: mustIPv6Network(t, "2001:db8::5", "ffff:ffff:ff00:ffff:ffff:ffff:ffff:ffff"), want: -1},
		{name: "masks differing only in the low half", left: mustIPv6Network(t, "::", "ffff::ffff:0:0"), right: mustIPv6Network(t, "::", "ffff::ffff:ffff:0"), want: -1},
		{name: "alternating masks under one address", left: mustIPv6Network(t, "::", "ffff:0:ffff:0:ffff:0:ffff:0"), right: mustIPv6Network(t, "::", "0:ffff:0:ffff:0:ffff:0:ffff"), want: 1},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			require.Equal(t, testCase.want, testCase.left.Compare(testCase.right))
		})
	}
}

// verifies that equal networks compare as zero and only they do.
func Test_IPv6Network_Compare_EqualityIsZero(t *testing.T) {
	left := mustIPv6Network(t, "2001:db8::", "ffff:ffff::")
	right := mustIPv6Network(t, "2001:db8::", "ffff:ffff::")
	require.Equal(t, 0, left.Compare(right))
	require.Equal(t, left, right)
}

// verifies that sorting a shuffled fixture yields the exact documented
// order, the contract the aggregation and split inputs rely on.
func Test_IPv6Network_Compare_SortPinsDocumentedOrder(t *testing.T) {
	shuffled := []xnetip.IPv6Network{
		mustIPv6Network(t, "2a02:6b8::1", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"),
		mustIPv6Network(t, "2001:db9::", "ffff:ffff::"),
		mustIPv6Network(t, "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"),
		mustIPv6Network(t, "2001:db8::5", "ffff:ffff:ff00:ffff:ffff:ffff:ffff:ffff"),
		mustIPv6Network(t, "::", "::"),
		mustIPv6Network(t, "2001:db8::", "ffff:ffff:ffff::"),
		mustIPv6Network(t, "2001:db8::5", "ffff:ffff:ff00:ff00:ffff:ffff:ffff:ffff"),
		mustIPv6Network(t, "2001:db8::", "ffff:ffff::"),
	}
	want := []xnetip.IPv6Network{
		mustIPv6Network(t, "::", "::"),
		mustIPv6Network(t, "2001:db8::", "ffff:ffff::"),
		mustIPv6Network(t, "2001:db8::", "ffff:ffff:ffff::"),
		mustIPv6Network(t, "2001:db8::5", "ffff:ffff:ff00:ff00:ffff:ffff:ffff:ffff"),
		mustIPv6Network(t, "2001:db8::5", "ffff:ffff:ff00:ffff:ffff:ffff:ffff:ffff"),
		mustIPv6Network(t, "2001:db9::", "ffff:ffff::"),
		mustIPv6Network(t, "2a02:6b8::1", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"),
		mustIPv6Network(t, "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"),
	}
	slices.SortFunc(shuffled, xnetip.IPv6Network.Compare)
	require.Equal(t, want, shuffled)
}

// verifies that the order equals the tuple order of the netip address
// views, is antisymmetric and is zero exactly on equal values.
func Test_IPv6Network_Compare_MatchesTupleOrderProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		left := genIPv6Network.Draw(t, "left")
		right := genIPv6Network.Draw(t, "right")
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
func Test_IPv6Network_Compare_TransitivityProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		first := genIPv6Network.Draw(t, "first")
		second := genIPv6Network.Draw(t, "second")
		third := genIPv6Network.Draw(t, "third")
		if first.Compare(second) <= 0 && second.Compare(third) <= 0 {
			require.LessOrEqual(t, first.Compare(third), 0)
		}
	})
}

// verifies that sorting a random slice by the order yields a sorted
// permutation of the input.
func Test_IPv6Network_Compare_SortFuncProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		networks := rapid.SliceOfN(genIPv6Network, 0, 32).Draw(t, "networks")
		sorted := slices.Clone(networks)
		slices.SortFunc(sorted, xnetip.IPv6Network.Compare)
		require.True(t, slices.IsSortedFunc(sorted, xnetip.IPv6Network.Compare))
		require.ElementsMatch(t, networks, sorted)
	})
}

// verifies that the address-first component agrees with the
// netip.Addr order whenever the addresses differ.
func Test_IPv6Network_Compare_MatchesNetipAddrOrder(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		left := genIPv6Network.Draw(t, "left")
		right := genIPv6Network.Draw(t, "right")
		if left.Addr() != right.Addr() {
			require.Equal(t, left.Addr().Compare(right.Addr()), left.Compare(right))
		}
	})
}

// verifies that comparing allocates nothing.
func Test_IPv6Network_Compare_AllocationFree(t *testing.T) {
	left := mustIPv6Network(t, "2001:db8::", "ffff:ffff::")
	right := mustIPv6Network(t, "2001:db8::", "ffff:ffff:ffff::")
	requireNoAllocs(t, func() { intSink = left.Compare(right) })
}

func BenchmarkIPv6Network_Compare_MaskDecides(b *testing.B) {
	left := mustIPv6Network(b, "2001:db8::", "ffff:ffff::")
	right := mustIPv6Network(b, "2001:db8::", "ffff:ffff:ffff::")
	b.ReportAllocs()
	for b.Loop() {
		intSink = left.Compare(right)
	}
}

func BenchmarkIPv6Network_Compare_AddressDecides(b *testing.B) {
	left := mustIPv6Network(b, "2001:db8::", "ffff:ffff::")
	right := mustIPv6Network(b, "2001:db9::", "ffff:ffff:ffff::")
	b.ReportAllocs()
	for b.Loop() {
		intSink = left.Compare(right)
	}
}

func BenchmarkIPv6Network_SortFunc_1024(b *testing.B) {
	// The fixture is random-ish, not nearly sorted.
	//
	// The 64-bit wrapping product of the index and the golden-ratio
	// constant fills the high address half, the low half stays zero
	// and the prefixes spread over /16../128.
	template := make([]xnetip.IPv6Network, 1024)
	for idx := range template {
		bits := uint64(idx) * 0x9E3779B97F4A7C15
		network, err := xnetip.IPv6NetworkFromCIDR(netipAddrFrom6Bits(bits, 0), 16+int(bits%113))
		if err != nil {
			b.Fatal(err)
		}
		template[idx] = network
	}
	networks := make([]xnetip.IPv6Network, len(template))
	b.ReportAllocs()
	for b.Loop() {
		// The 32 KiB fixture refresh stays inside the timed region: a
		// paused timer would keep the loop from ever finishing.
		copy(networks, template)
		slices.SortFunc(networks, xnetip.IPv6Network.Compare)
	}
}

// verifies that exactly the masks made of leading ones followed by
// zeros are contiguous, the all-zero and all-ones masks included.
//
// The 64-bit half boundary is the IPv6-specific trap: runs ending at,
// crossing and holes straddling bit 64 must all classify correctly.
func Test_IPv6Network_IsContiguous_LeadingOnesRunOnly(t *testing.T) {
	cases := []struct {
		name    string
		network xnetip.IPv6Network
		want    bool
	}{
		{name: "universe /0", network: mustIPv6Network(t, "::", "::"), want: true},
		{name: "host route /128", network: mustIPv6Network(t, "::1", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"), want: true},
		{name: "/40", network: mustIPv6Network(t, "2a02:6b8:c00::", "ffff:ffff:ff00::"), want: true},
		{name: "/127", network: mustIPv6Network(t, "2a02:6b8:c00:1:2:3:4:1", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:fffe"), want: true},
		{name: "/128 with bits in both halves", network: mustIPv6Network(t, "2a02:6b8:c00:1:2:3:4:1", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"), want: true},
		{name: "run ends exactly at the half boundary /64", network: mustIPv6Network(t, "2001:db8::", "ffff:ffff:ffff:ffff::"), want: true},
		{name: "run crosses the half boundary /65", network: mustIPv6Network(t, "2001:db8::", "ffff:ffff:ffff:ffff:8000::"), want: true},
		{name: "single leading bit /1", network: mustIPv6Network(t, "8000::", "8000::"), want: true},
		{name: "zero value is the universe", network: xnetip.IPv6Network{}, want: true},
		{name: "top bit clear, rest set", network: mustIPv6Network(t, "::", "7fff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"), want: false},
		{name: "low half only", network: mustIPv6Network(t, "::", "::ffff:ffff:ffff:ffff"), want: false},
		{name: "two runs", network: mustIPv6Network(t, "2a02:6b8:c00::f800:0:0", "ffff:ffff:ff00::ffff:ffff:0:0"), want: false},
		{name: "second run crosses the half boundary", network: mustIPv6Network(t, "2a02:6b8:c00::f800:0:0", "ffff:ffff:ff00:0:ffff:f800::"), want: false},
		{name: "hole exactly at bits 64..95", network: mustIPv6Network(t, "2a02:6b8:0:0:1234:5678::", "ffff:ffff:0:0:ffff:ffff:0:0"), want: false},
		{name: "nibble-alternating low half", network: mustIPv6Network(t, "2a02:6b8:0:0:1234:5678::", "ffff:ffff:0:0:f0f0:f0f0:f0f0:f0f0"), want: false},
		{name: "hole straddling bit 64", network: mustIPv6Network(t, "::", "ffff:ffff:ffff:fffe:8000::"), want: false},
		{name: "bench non-contiguous shape", network: mustIPv6Network(t, "2001::1", "ffff::ffff"), want: false},
		{name: "alternating groups", network: mustIPv6Network(t, "::", "ffff:0:ffff:0:ffff:0:ffff:0"), want: false},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			require.Equal(t, testCase.want, testCase.network.IsContiguous())
		})
	}
}

// verifies that the predicate agrees with the brute-force bit scan:
// contiguous means no one bit after a zero bit, top to bottom.
func Test_IPv6Network_IsContiguous_MatchesBitScanProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		network := genIPv6Network.Draw(t, "network")
		maskBytes := network.Mask().As16()
		want := true
		seenZero := false
		for _, maskByte := range maskBytes {
			for idx := range 8 {
				bit := maskByte>>(7-idx)&1 == 1
				if bit && seenZero {
					want = false
				}
				if !bit {
					seenZero = true
				}
			}
		}
		require.Equal(t, want, network.IsContiguous())
	})
}

// verifies that every network built from a prefix length is
// contiguous, the half boundary neighbourhood included.
func Test_IPv6Network_IsContiguous_PrefixMasksAreContiguousProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		addr := genNetipAddr6.Draw(t, "addr")
		bits := rapid.OneOf(
			rapid.IntRange(0, 128),
			rapid.SampledFrom([]int{63, 64, 65}),
		).Draw(t, "bits")
		network, err := xnetip.IPv6NetworkFromCIDR(addr, bits)
		require.NoError(t, err)
		require.True(t, network.IsContiguous())
		require.Equal(t, bits, netip.PrefixFrom(network.Addr(), bits).Bits())
	})
}

// verifies that clearing a non-final bit of a leading run of two or
// more ones breaks contiguity: some run bit stays below the hole.
func Test_IPv6Network_IsContiguous_HolePunchedMaskProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		prefix := rapid.IntRange(2, 128).Draw(t, "prefix")
		hole := rapid.IntRange(0, prefix-2).Draw(t, "hole")
		var maskHi, maskLo uint64
		if prefix <= 64 {
			maskHi = ^uint64(0) << (64 - prefix)
		} else {
			maskHi = ^uint64(0)
			maskLo = ^uint64(0) << (128 - prefix)
		}
		if hole < 64 {
			maskHi &^= uint64(1) << (63 - hole)
		} else {
			maskLo &^= uint64(1) << (127 - hole)
		}
		network, err := xnetip.IPv6NetworkFrom(
			genNetipAddr6.Draw(t, "addr"),
			netipAddrFrom6Bits(maskHi, maskLo),
		)
		require.NoError(t, err)
		require.False(t, network.IsContiguous())
	})
}

// verifies that the predicate allocates nothing.
func Test_IPv6Network_IsContiguous_AllocationFree(t *testing.T) {
	network := mustIPv6Network(t, "2001:db8::", "ffff:ffff::")
	requireNoAllocs(t, func() { okSink = network.IsContiguous() })
}

func BenchmarkIPv6Network_IsContiguous_Contiguous(b *testing.B) {
	network := mustIPv6Network(b, "2001:db8::", "ffff:ffff::")
	b.ReportAllocs()
	for b.Loop() {
		okSink = network.IsContiguous()
	}
}

func BenchmarkIPv6Network_IsContiguous_NonContiguous(b *testing.B) {
	network := mustIPv6Network(b, "2001::1", "ffff::ffff")
	b.ReportAllocs()
	for b.Loop() {
		okSink = network.IsContiguous()
	}
}

// verifies that a contiguous mask reports its leading-ones run length,
// from the universe through the host route.
//
// The run lengths at and just past the 64-bit half boundary are pinned
// explicitly, and an IPv4-mapped network reports its 128-bit length:
// the image of an IPv4 /24 is a /120.
func Test_IPv6Network_PrefixLen_LeadingOnesRunLength(t *testing.T) {
	cases := []struct {
		name    string
		network xnetip.IPv6Network
		want    int
	}{
		{name: "/40", network: mustIPv6Network(t, "2a02:6b8::", "ffff:ffff:ff00::"), want: 40},
		{name: "host route /128", network: mustIPv6Network(t, "2a02:6b8::1", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"), want: 128},
		{name: "mapped /24 is /120", network: mustIPv4Network(t, "8.8.8.0", "255.255.255.0").ToIPv6Mapped(), want: 120},
		{name: "universe /0", network: mustIPv6Network(t, "::", "::"), want: 0},
		{name: "single leading bit /1", network: mustIPv6Network(t, "8000::", "8000::"), want: 1},
		{name: "/127", network: mustIPv6Network(t, "2001:db8::2", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:fffe"), want: 127},
		{name: "/128 explicit", network: mustIPv6Network(t, "2001:db8::1", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"), want: 128},
		{name: "run ends exactly at the half boundary /64", network: mustIPv6Network(t, "2001:db8::", "ffff:ffff:ffff:ffff::"), want: 64},
		{name: "run crosses the half boundary /65", network: mustIPv6Network(t, "2001:db8::", "ffff:ffff:ffff:ffff:8000::"), want: 65},
		{name: "zero value is the universe", network: xnetip.IPv6Network{}, want: 0},
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
//
// The half boundary is the IPv6-specific trap: a hole straddling bit
// 64 and a full high half over a broken low half must both report no
// prefix.
func Test_IPv6Network_PrefixLen_NonContiguousHasNone(t *testing.T) {
	cases := []struct {
		name    string
		network xnetip.IPv6Network
	}{
		{name: "hole in the middle", network: mustIPv6Network(t, "2001:db8::1", "ffff:ffff::ffff")},
		{name: "no leading run", network: mustIPv6Network(t, "::1", "::ffff")},
		{name: "leading zero then ones", network: mustIPv6Network(t, "::", "7fff:ffff:ffff:ffff:ffff:ffff:ffff:ffff")},
		{name: "geo mask with two runs", network: mustIPv6Network(t, "2001:db8::", "ffff:ffff:ff00::ffff:ffff:0:0")},
		{name: "hole straddling bit 64", network: mustIPv6Network(t, "2001:db8::", "ffff:ffff:ffff:fff0:0fff:ffff::")},
		{name: "alternating groups", network: mustIPv6Network(t, "2001:0:db8::", "ffff:0:ffff:0:ffff:0:ffff:0")},
		{name: "high half full, low half broken", network: mustIPv6Network(t, "::", "ffff:ffff:ffff:ffff:0:ffff:0:ffff")},
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
func Test_IPv6Network_PrefixLen_SomeIffContiguousProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		network := genIPv6Network.Draw(t, "network")
		prefix, ok := network.PrefixLen()
		require.Equal(t, network.IsContiguous(), ok)
		if !ok {
			require.Zero(t, prefix)
			return
		}
		allOnes := netip.MustParseAddr("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff")
		maskOracle, err := allOnes.Prefix(prefix)
		require.NoError(t, err)
		require.Equal(t, maskOracle.Addr(), network.Mask())
	})
}

// verifies that a network built from any address and prefix length
// reports that same length back.
func Test_IPv6Network_PrefixLen_RoundTripsCIDRProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		addr := genNetipAddr6.Draw(t, "addr")
		cidr := rapid.IntRange(0, 128).Draw(t, "cidr")
		network, err := xnetip.IPv6NetworkFromCIDR(addr, cidr)
		require.NoError(t, err)
		prefix, ok := network.PrefixLen()
		require.True(t, ok)
		require.Equal(t, cidr, prefix)
	})
}

// verifies that for a contiguous mask the reported length is the one
// net/netip accepts and reports back for the same address.
func Test_IPv6Network_PrefixLen_MatchesNetipBitsProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		network := genIPv6Network.Draw(t, "network")
		if !network.IsContiguous() {
			return
		}
		maskBytes := network.Mask().As16()
		leading := bits.LeadingZeros64(^binary.BigEndian.Uint64(maskBytes[:8]))
		if leading == 64 {
			leading += bits.LeadingZeros64(^binary.BigEndian.Uint64(maskBytes[8:]))
		}
		prefix, ok := network.PrefixLen()
		require.True(t, ok)
		require.Equal(t, netip.PrefixFrom(network.Addr(), leading).Bits(), prefix)
	})
}

// verifies that computing the prefix allocates nothing on either
// outcome.
func Test_IPv6Network_PrefixLen_AllocationFree(t *testing.T) {
	contiguous := mustIPv6Network(t, "2001:db8::", "ffff:ffff::")
	nonContiguous := mustIPv6Network(t, "2001:db8::1", "ffff:ffff::ffff")
	requireNoAllocs(t, func() { intSink, okSink = contiguous.PrefixLen() })
	requireNoAllocs(t, func() { intSink, okSink = nonContiguous.PrefixLen() })
}

func BenchmarkIPv6Network_PrefixLen_Contiguous(b *testing.B) {
	network := mustIPv6Network(b, "2001:db8::", "ffff:ffff::")
	b.ReportAllocs()
	for b.Loop() {
		intSink, okSink = network.PrefixLen()
	}
}

func BenchmarkIPv6Network_PrefixLen_NonContiguous(b *testing.B) {
	network := mustIPv6Network(b, "2001:db8::1", "ffff:ffff::ffff")
	b.ReportAllocs()
	for b.Loop() {
		intSink, okSink = network.PrefixLen()
	}
}

func BenchmarkIPv6Network_PrefixLen_Mixed(b *testing.B) {
	// A 50/50 contiguous/non-contiguous rotation exercises both
	// outcomes of the contiguity check within one measurement.
	networks := []xnetip.IPv6Network{
		mustIPv6Network(b, "2001:db8::", "ffff:ffff::"),
		mustIPv6Network(b, "2001:db8::1", "ffff:ffff::ffff"),
		mustIPv6Network(b, "2a02:6b8::", "ffff:ffff:ffff::"),
		mustIPv6Network(b, "2a02:6b8::1", "ffff:0:0:0:ffff::"),
	}
	b.ReportAllocs()
	for b.Loop() {
		for _, network := range networks {
			intSink, okSink = network.PrefixLen()
		}
	}
}

// verifies that a contiguous network prints as address/prefix with the
// suffix always present, in the compressed form net/netip renders.
func Test_IPv6Network_String_ContiguousUsesPrefixForm(t *testing.T) {
	cases := []struct {
		name    string
		network xnetip.IPv6Network
		want    string
	}{
		{name: "host route keeps /128", network: mustIPv6Network(t, "2a02:6b8::1", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"), want: "2a02:6b8::1/128"},
		{name: "CIDR with inner zero groups", network: mustIPv6Network(t, "2a02:6b8:c00:0:1:2::", "ffff:ffff:ffff:ffff:ffff:ffff::"), want: "2a02:6b8:c00:0:1:2::/96"},
		{name: "universe", network: mustIPv6Network(t, "::", "::"), want: "::/0"},
		{name: "zero value", network: xnetip.IPv6Network{}, want: "::/0"},
		{name: "loopback host keeps /128", network: mustIPv6Network(t, "::1", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"), want: "::1/128"},
		{name: "all ones", network: mustIPv6Network(t, "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"), want: "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/128"},
		{name: "full form gets compressed", network: mustIPv6Network(t, "2001:db8:0:0:0:0:0:1", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"), want: "2001:db8::1/128"},
		{name: "mapped network", network: mustIPv6Network(t, "::ffff:192.0.2.0", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ff00"), want: "::ffff:192.0.2.0/120"},
		{name: "normalized before print", network: mustIPv6Network(t, "2a02:6b8:c00:1:2:3:4:5", "ffff:ffff:ff00::"), want: "2a02:6b8:c00::/40"},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			require.Equal(t, testCase.want, testCase.network.String())
		})
	}
}

// verifies that a non-contiguous network prints its mask compressed
// like an address, the IPv4-mapped-looking form included.
func Test_IPv6Network_String_NonContiguousUsesMaskForm(t *testing.T) {
	cases := []struct {
		name    string
		network xnetip.IPv6Network
		want    string
	}{
		{name: "two runs, mask compressed", network: mustIPv6Network(t, "2a02:6b8:0:0:0:1234::", "ffff:ffff:0:0:ffff:ffff:0:0"), want: "2a02:6b8::1234:0:0/ffff:ffff::ffff:ffff:0:0"},
		{name: "two runs, longer address", network: mustIPv6Network(t, "2a02:6b8:0:0:1234:5678::", "ffff:ffff:0:0:ffff:ffff:0:0"), want: "2a02:6b8::1234:5678:0:0/ffff:ffff::ffff:ffff:0:0"},
		{name: "geo mask, address normalized", network: mustIPv6Network(t, "2001:db8::1", "ffff:ffff:ff00::ffff:ffff:0:0"), want: "2001:db8::/ffff:ffff:ff00:0:ffff:ffff::"},
		{name: "alternating groups, nothing to compress", network: mustIPv6Network(t, "2001:0:db8::", "ffff:0:ffff:0:ffff:0:ffff:0"), want: "2001:0:db8::/ffff:0:ffff:0:ffff:0:ffff:0"},
		{name: "mask that looks IPv4-mapped", network: mustIPv6Network(t, "::ffff:1.0.1.0", "::ffff:255.0.255.0"), want: "::ffff:1.0.1.0/::ffff:255.0.255.0"},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			require.Equal(t, testCase.want, testCase.network.String())
		})
	}
}

// verifies that appending writes after the caller's bytes and leaves
// them intact.
func Test_IPv6Network_AppendTo_KeepsExistingBytes(t *testing.T) {
	network := mustIPv6Network(t, "2001:db8::", "ffff:ffff::")
	require.Equal(t, "net=2001:db8::/32", string(network.AppendTo([]byte("net="))))
}

// verifies that a buffer with enough capacity is extended in place,
// without growing to a new backing array.
func Test_IPv6Network_AppendTo_ReusesSizedBuffer(t *testing.T) {
	network := mustIPv6Network(t, "2001:db8::", "ffff:ffff::")
	buffer := make([]byte, 0, 96)
	extended := network.AppendTo(buffer)
	require.Equal(t, "2001:db8::/32", string(extended))
	require.Equal(t, cap(buffer), cap(extended))
}

// verifies that the text splits at a single slash into the network
// address and the decimal prefix length or the rendered mask.
func Test_IPv6Network_String_ShapeProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		network := genIPv6Network.Draw(t, "network")
		text := network.String()
		require.Equal(t, 1, strings.Count(text, "/"))
		slash := strings.IndexByte(text, '/')
		addr, err := netip.ParseAddr(text[:slash])
		require.NoError(t, err)
		require.True(t, addr.Is6())
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
func Test_IPv6Network_AppendTo_MatchesStringProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		network := genIPv6Network.Draw(t, "network")
		prefix := rapid.SliceOf(rapid.Byte()).Draw(t, "buffer")
		require.Equal(t, network.String(), string(network.AppendTo(nil)))
		extended := network.AppendTo(slices.Clone(prefix))
		require.True(t, bytes.Equal(prefix, extended[:len(prefix)]))
		require.Equal(t, network.String(), string(extended[len(prefix):]))
	})
}

// verifies that the contiguous form is byte-identical to the netip
// prefix rendering of the same network.
func Test_IPv6Network_String_MatchesNetipPrefixProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		network := genIPv6Network.Draw(t, "network")
		prefix, ok := network.PrefixLen()
		if !ok {
			return
		}
		require.Equal(t, netip.PrefixFrom(network.Addr(), prefix).String(), network.String())
	})
}

// verifies that appending into a buffer with enough capacity allocates
// nothing, whatever the mask's shape.
func Test_IPv6Network_AppendTo_AllocationFree(t *testing.T) {
	contiguous := mustIPv6Network(t, "2001:db8::", "ffff:ffff::")
	nonContiguous := mustIPv6Network(t, "2001:db8::", "ffff:ffff:ff00::ffff:ffff:0:0")
	buffer := make([]byte, 0, 128)
	requireNoAllocs(t, func() { bytesSink = contiguous.AppendTo(buffer[:0]) })
	requireNoAllocs(t, func() { bytesSink = nonContiguous.AppendTo(buffer[:0]) })
}

// verifies that rendering to a string costs exactly the one string
// conversion, pinning any formatting regression that adds more.
func Test_IPv6Network_String_SingleAllocation(t *testing.T) {
	contiguous := mustIPv6Network(t, "2001:db8::", "ffff:ffff::")
	nonContiguous := mustIPv6Network(t, "2001:db8::", "ffff:ffff:ff00::ffff:ffff:0:0")
	require.Equal(t, 1, int(testing.AllocsPerRun(100, func() { stringSink = contiguous.String() })))
	require.Equal(t, 1, int(testing.AllocsPerRun(100, func() { stringSink = nonContiguous.String() })))
}

func BenchmarkIPv6Network_String_CIDR(b *testing.B) {
	network := mustIPv6Network(b, "2001:db8::", "ffff:ffff::")
	b.ReportAllocs()
	for b.Loop() {
		stringSink = network.String()
	}
}

func BenchmarkIPv6Network_String_NonContiguous(b *testing.B) {
	network := mustIPv6Network(b, "2001:db8::", "ffff:ffff:ff00::ffff:ffff:0:0")
	b.ReportAllocs()
	for b.Loop() {
		stringSink = network.String()
	}
}

func BenchmarkIPv6Network_AppendTo_CIDR(b *testing.B) {
	network := mustIPv6Network(b, "2001:db8::", "ffff:ffff::")
	buffer := make([]byte, 0, 96)
	b.ReportAllocs()
	for b.Loop() {
		bytesSink = network.AppendTo(buffer[:0])
	}
}

// verifies that the parser accepts the bare, CIDR and colon-mask forms
// and normalizes the address under the mask in every one of them.
func Test_ParseIPv6Network_AcceptsAllForms(t *testing.T) {
	cases := []struct {
		name     string
		input    string
		wantAddr string
		wantMask string
	}{
		{name: "bare address is a host route", input: "2a02:6b8::2:242", wantAddr: "2a02:6b8::2:242", wantMask: "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"},
		{name: "CIDR", input: "2a02:6b8:c00::/40", wantAddr: "2a02:6b8:c00::", wantMask: "ffff:ffff:ff00::"},
		{name: "CIDR normalizes host bits", input: "2a02:6b8:c00::1/40", wantAddr: "2a02:6b8:c00::", wantMask: "ffff:ffff:ff00::"},
		{name: "explicit contiguous mask", input: "2a02:6b8:c00::/ffff:ffff:ff00::", wantAddr: "2a02:6b8:c00::", wantMask: "ffff:ffff:ff00::"},
		{name: "explicit mask normalizes", input: "2a02:6b8:c00:1:2:3:4:5/ffff:ffff:ff00::", wantAddr: "2a02:6b8:c00::", wantMask: "ffff:ffff:ff00::"},
		{name: "/0 is the universe", input: "::/0", wantAddr: "::", wantMask: "::"},
		{name: "/0 normalizes everything away", input: "2001:db8::1/0", wantAddr: "::", wantMask: "::"},
		{name: "/1 keeps the top bit", input: "8000::/1", wantAddr: "8000::", wantMask: "8000::"},
		{name: "/64 is the half boundary", input: "2001:db8::/64", wantAddr: "2001:db8::", wantMask: "ffff:ffff:ffff:ffff::"},
		{name: "/65 crosses the half boundary", input: "2001:db8::/65", wantAddr: "2001:db8::", wantMask: "ffff:ffff:ffff:ffff:8000::"},
		{name: "/127 keeps all but the last bit", input: "2001:db8::2/127", wantAddr: "2001:db8::2", wantMask: "ffff:ffff:ffff:ffff:ffff:ffff:ffff:fffe"},
		{name: "/128 is a host route", input: "2001:db8::1/128", wantAddr: "2001:db8::1", wantMask: "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"},
		{name: "full form without compression", input: "2001:db8:1:2:3:4:5:6/64", wantAddr: "2001:db8:1:2::", wantMask: "ffff:ffff:ffff:ffff::"},
		{name: "uppercase hex", input: "2001:DB8::/32", wantAddr: "2001:db8::", wantMask: "ffff:ffff::"},
		{name: "embedded IPv4 address", input: "::ffff:192.0.2.1/120", wantAddr: "::ffff:192.0.2.0", wantMask: "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ff00"},
		{name: "embedded IPv4 in the mask", input: "2001:db8::/ffff:ffff::255.255.0.0", wantAddr: "2001:db8::", wantMask: "ffff:ffff::ffff:0"},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			network, err := xnetip.ParseIPv6Network(testCase.input)
			require.NoError(t, err)
			require.Equal(t, mustIPv6Network(t, testCase.wantAddr, testCase.wantMask), network)
		})
	}
}

// verifies that the universe text parses to the zero value, so the two
// spellings of "every IPv6 address" are one value.
func Test_ParseIPv6Network_UniverseIsZeroValue(t *testing.T) {
	network, err := xnetip.ParseIPv6Network("::/0")
	require.NoError(t, err)
	require.Equal(t, xnetip.IPv6Network{}, network)
}

// verifies that a digits-only suffix beyond the family limit is a
// prefix-length overflow, never a colon-mask attempt.
func Test_ParseIPv6Network_RejectsPrefixOverflow(t *testing.T) {
	cases := []struct {
		name  string
		input string
	}{
		{name: "one past the limit", input: "::/129"},
		{name: "far past the limit", input: "2001:db8::/999"},
		{name: "longer than any int", input: "::/99999999999999999999"},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			network, err := xnetip.ParseIPv6Network(testCase.input)
			require.ErrorIs(t, err, xnetip.ErrCIDROverflow)
			require.Equal(t, xnetip.IPv6Network{}, network)
		})
	}
}

// verifies that a suffix that is neither a strict prefix length nor a
// colon-form mask is rejected with the mask sentinel.
//
// The strict prefix grammar takes no sign, no leading zero and no
// trailing bytes, so each of those falls through to the mask parse
// and fails there.
func Test_ParseIPv6Network_RejectsBadSuffix(t *testing.T) {
	cases := []struct {
		name  string
		input string
	}{
		{name: "leading zero in prefix", input: "2001:db8::/032"},
		{name: "plus sign in prefix", input: "2001:db8::/+32"},
		{name: "minus sign in prefix", input: "2001:db8::/-32"},
		{name: "empty suffix", input: "2001:db8::/"},
		{name: "double slash", input: "2001:db8::1//64"},
		{name: "trailing space in suffix", input: "::1/64 "},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			network, err := xnetip.ParseIPv6Network(testCase.input)
			require.ErrorIs(t, err, xnetip.ErrInvalidMask)
			require.Equal(t, xnetip.IPv6Network{}, network)
		})
	}
}

// verifies that an IPv4 mask under an IPv6 address carries both the
// mask sentinel and the family sentinel in its chain.
func Test_ParseIPv6Network_ForeignFamilyMaskKeepsBothSentinels(t *testing.T) {
	_, err := xnetip.ParseIPv6Network("2001:db8::1/255.255.255.0")
	require.ErrorIs(t, err, xnetip.ErrInvalidMask)
	require.ErrorIs(t, err, xnetip.ErrAddrFamilyMismatch)
}

// verifies that a zone suffix on the address is rejected with the zone
// sentinel: the zone-free network types cannot represent it.
func Test_ParseIPv6Network_RejectsZoneInAddress(t *testing.T) {
	network, err := xnetip.ParseIPv6Network("fe80::1%eth0/64")
	require.ErrorIs(t, err, xnetip.ErrZone)
	require.Equal(t, xnetip.IPv6Network{}, network)
}

// verifies that a zone suffix on the mask keeps the zone sentinel in
// the chain behind the mask sentinel.
func Test_ParseIPv6Network_RejectsZoneInMask(t *testing.T) {
	_, err := xnetip.ParseIPv6Network("fe80::/ffff::%eth0")
	require.ErrorIs(t, err, xnetip.ErrInvalidMask)
	require.ErrorIs(t, err, xnetip.ErrZone)
}

// verifies that zoned prefix text is rejected here exactly as the std
// prefix parser rejects it.
func Test_ParseIPv6Network_ZoneParityWithNetip(t *testing.T) {
	_, err := xnetip.ParseIPv6Network("fe80::1%eth0/64")
	require.Error(t, err)
	_, stdErr := netip.ParsePrefix("fe80::1%eth0/64")
	require.Error(t, stdErr)
}

// verifies that text whose address part is not an IPv6 address is
// rejected with the parse sentinel and the net/netip cause in the chain.
func Test_ParseIPv6Network_RejectsBadAddress(t *testing.T) {
	cases := []struct {
		name  string
		input string
	}{
		{name: "empty input", input: ""},
		{name: "lone slash", input: "/"},
		{name: "missing address", input: "/64"},
		{name: "garbage", input: "hello"},
		{name: "garbage with suffix", input: "zz/64"},
		{name: "leading whitespace", input: " ::1/64"},
		{name: "double compression", input: "1::2::3/64"},
		{name: "too many groups", input: "1:2:3:4:5:6:7:8:9/64"},
		{name: "five hex digits", input: "12345::/64"},
		{name: "embedded IPv4 not last", input: "1.2.3.4::/64"},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			network, err := xnetip.ParseIPv6Network(testCase.input)
			require.ErrorIs(t, err, xnetip.ErrParse)
			require.Equal(t, xnetip.IPv6Network{}, network)
		})
	}
}

// verifies that an IPv4 address is rejected with the family sentinel,
// not read as an IPv6 network.
func Test_ParseIPv6Network_RejectsIPv4Literal(t *testing.T) {
	network, err := xnetip.ParseIPv6Network("192.168.1.1")
	require.ErrorIs(t, err, xnetip.ErrAddrFamilyMismatch)
	require.Equal(t, xnetip.IPv6Network{}, network)
}

// verifies that a colon-form mask of any shape is accepted verbatim and
// the address bits outside it are cleared, both halves included.
func Test_ParseIPv6Network_NonContiguousMasks(t *testing.T) {
	cases := []struct {
		name     string
		input    string
		wantAddr string
		wantMask string
	}{
		{name: "geo mask kept verbatim", input: "2a02:6b8:c00::1234:0:0/ffff:ffff:ff00::ffff:ffff:0:0", wantAddr: "2a02:6b8:c00::1234:0:0", wantMask: "ffff:ffff:ff00:0:ffff:ffff::"},
		{name: "bits outside the mask cleared", input: "2a02:6b8:c00::1234:9:9/ffff:ffff:ff00::ffff:ffff:0:0", wantAddr: "2a02:6b8:c00::1234:0:0", wantMask: "ffff:ffff:ff00:0:ffff:ffff::"},
		{name: "two runs", input: "2001:db8::1/ffff:ffff::ffff", wantAddr: "2001:db8::1", wantMask: "ffff:ffff::ffff"},
		{name: "alternating groups", input: "2001:0:db8:0:1:0:2:0/ffff:0:ffff:0:ffff:0:ffff:0", wantAddr: "2001:0:db8:0:1:0:2:0", wantMask: "ffff:0:ffff:0:ffff:0:ffff:0"},
		{name: "hole straddling bit 64", input: "2001:db8:1:2:3:4:5:6/ffff:ffff:ffff:fff0:0fff:ffff::", wantAddr: "2001:db8:1:0:3:4::", wantMask: "ffff:ffff:ffff:fff0:fff:ffff::"},
		{name: "mapped-looking mask", input: "::ffff:1.0.1.0/::ffff:255.0.255.0", wantAddr: "::ffff:1.0.1.0", wantMask: "::ffff:255.0.255.0"},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			network, err := xnetip.ParseIPv6Network(testCase.input)
			require.NoError(t, err)
			require.Equal(t, mustIPv6Network(t, testCase.wantAddr, testCase.wantMask), network)
		})
	}
}

// verifies that the must variant panics on invalid input instead of
// returning an error.
func Test_MustParseIPv6Network_PanicsOnInvalidInput(t *testing.T) {
	require.Panics(t, func() { xnetip.MustParseIPv6Network("::/129") })
}

// verifies that the must variant passes a valid parse through.
func Test_MustParseIPv6Network_ReturnsParsedNetwork(t *testing.T) {
	network := xnetip.MustParseIPv6Network("2001:db8::/32")
	require.Equal(t, mustIPv6Network(t, "2001:db8::", "ffff:ffff::"), network)
}

// verifies that every parse error names this parser and echoes the
// rejected input in quotes.
func Test_ParseIPv6Network_ErrorEchoesInput(t *testing.T) {
	_, err := xnetip.ParseIPv6Network("::/129")
	require.Error(t, err)
	require.True(t, strings.HasPrefix(err.Error(), "xnetip.ParseIPv6Network("))
	require.Contains(t, err.Error(), `"::/129"`)
}

// verifies that parsing the string form recovers the network exactly,
// whatever the mask's shape.
func Test_ParseIPv6Network_StringRoundTripProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		network := genIPv6Network.Draw(t, "network")
		parsed, err := xnetip.ParseIPv6Network(network.String())
		require.NoError(t, err)
		require.Equal(t, network, parsed)
	})
}

// verifies that the CIDR text form parses to the same network the CIDR
// constructor builds from the same address and length.
func Test_ParseIPv6Network_CIDRFormAgreesWithConstructorProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		addr := genNetipAddr6.Draw(t, "addr")
		bits := rapid.IntRange(0, 128).Draw(t, "bits")
		constructed, err := xnetip.IPv6NetworkFromCIDR(addr, bits)
		require.NoError(t, err)
		parsed, err := xnetip.ParseIPv6Network(addr.String() + "/" + strconv.Itoa(bits))
		require.NoError(t, err)
		require.Equal(t, constructed, parsed)
	})
}

// verifies that the colon-mask text form, non-contiguous masks
// included, parses like the checked constructor on the same pair.
func Test_ParseIPv6Network_ColonMaskAgreesWithConstructorProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		addr := genNetipAddr6.Draw(t, "addr")
		mask := genNetipAddr6.Draw(t, "mask")
		constructed, err := xnetip.IPv6NetworkFrom(addr, mask)
		require.NoError(t, err)
		parsed, err := xnetip.ParseIPv6Network(addr.String() + "/" + mask.String())
		require.NoError(t, err)
		require.Equal(t, constructed, parsed)
	})
}

// verifies that every accepted input yields a normalized network: no
// address bit survives outside the mask, in any of the three forms.
func Test_ParseIPv6Network_ResultNormalizedProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		addr := genNetipAddr6.Draw(t, "addr")
		var input string
		switch rapid.IntRange(0, 2).Draw(t, "form") {
		case 0:
			input = addr.String()
		case 1:
			input = addr.String() + "/" + strconv.Itoa(rapid.IntRange(0, 128).Draw(t, "bits"))
		default:
			input = addr.String() + "/" + genNetipAddr6.Draw(t, "mask").String()
		}
		network, err := xnetip.ParseIPv6Network(input)
		require.NoError(t, err)
		addrBytes := network.Addr().As16()
		maskBytes := network.Mask().As16()
		for idx := range addrBytes {
			require.Equal(t, addrBytes[idx]&maskBytes[idx], addrBytes[idx], "address bit outside the mask")
		}
	})
}

// verifies that no byte string makes the parser panic, whatever it
// holds.
func Test_ParseIPv6Network_NeverPanicsProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		input := string(rapid.SliceOfN(rapid.Byte(), 0, 60).Draw(t, "input"))
		network6Sink, errSink = xnetip.ParseIPv6Network(input)
	})
}

// verifies that on CIDR-shaped text the accept set and the parsed
// value are exactly those of the std prefix parser.
func Test_ParseIPv6Network_MatchesNetipParsePrefixProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		addr := genNetipAddr6.Draw(t, "addr")
		var suffix string
		if rapid.Bool().Draw(t, "digit suffix") {
			suffix = strconv.Itoa(rapid.IntRange(0, 140).Draw(t, "bits"))
		} else {
			suffix = rapid.SampledFrom([]string{"032", "+32", "-1", ""}).Draw(t, "malformed suffix")
		}
		input := addr.String() + "/" + suffix
		parsed, err := xnetip.ParseIPv6Network(input)
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
func Test_ParseIPv6Network_AllocationFree(t *testing.T) {
	requireNoAllocs(t, func() { network6Sink, errSink = xnetip.ParseIPv6Network("2001:db8::/32") })
	requireNoAllocs(t, func() { network6Sink, errSink = xnetip.ParseIPv6Network("2001:db8::1/ffff:ffff::ffff") })
	requireNoAllocs(t, func() { network6Sink, errSink = xnetip.ParseIPv6Network("2001:db8::1") })
}

func FuzzParseIPv6Network(f *testing.F) {
	seeds := []string{
		"2a02:6b8::2:242", "2a02:6b8:c00::/40", "2a02:6b8:c00::1/40",
		"2a02:6b8:c00::/ffff:ffff:ff00::", "2a02:6b8:c00:1:2:3:4:5/ffff:ffff:ff00::",
		"::/0", "2001:db8::1/0", "8000::/1", "2001:db8::/64", "2001:db8::/65",
		"2001:db8::2/127", "2001:db8::1/128", "2001:db8:1:2:3:4:5:6/64",
		"2001:DB8::/32", "::ffff:192.0.2.1/120", "2001:db8::/ffff:ffff::255.255.0.0",
		"::/129", "2001:db8::/999", "::/99999999999999999999",
		"2001:db8::/032", "2001:db8::/+32", "2001:db8::/-32", "2001:db8::/",
		"2001:db8::1//64", "::1/64 ", " ::1/64", "fe80::1%eth0/64", "fe80::/ffff::%eth0",
		"192.168.1.1", "2001:db8::1/255.255.255.0", "", "/", "/64", "hello", "zz/64",
		"1::2::3/64", "1:2:3:4:5:6:7:8:9/64", "12345::/64", "1.2.3.4::/64",
		"2a02:6b8:c00::1234:0:0/ffff:ffff:ff00::ffff:ffff:0:0",
		"2001:db8::1/ffff:ffff::ffff", "2001:0:db8:0:1:0:2:0/ffff:0:ffff:0:ffff:0:ffff:0",
		"2001:db8:1:2:3:4:5:6/ffff:ffff:ffff:fff0:0fff:ffff::", "::ffff:1.0.1.0/::ffff:255.0.255.0",
	}
	for _, seed := range seeds {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, input string) {
		network, err := xnetip.ParseIPv6Network(input)
		if err == nil {
			back, backErr := xnetip.ParseIPv6Network(network.String())
			if backErr != nil {
				t.Fatalf("round trip of %q rejected %q: %v", input, network.String(), backErr)
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
		if stdErr != nil || !stdPrefix.Addr().Is6() {
			if err == nil {
				t.Fatalf("accepted %q, which std rejects or reads as IPv4", input)
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

func BenchmarkParseIPv6Network_CIDR(b *testing.B) {
	b.ReportAllocs()
	for b.Loop() {
		network6Sink, errSink = xnetip.ParseIPv6Network("2001:db8::/32")
	}
}

func BenchmarkParseIPv6Network_FullMask(b *testing.B) {
	b.ReportAllocs()
	for b.Loop() {
		network6Sink, errSink = xnetip.ParseIPv6Network("2001:db8::1/ffff:ffff::ffff")
	}
}

func BenchmarkParseIPv6Network_Bare(b *testing.B) {
	b.ReportAllocs()
	for b.Loop() {
		network6Sink, errSink = xnetip.ParseIPv6Network("2001:db8::1")
	}
}

func BenchmarkParseIPv6Network_FullForm(b *testing.B) {
	b.ReportAllocs()
	for b.Loop() {
		network6Sink, errSink = xnetip.ParseIPv6Network("2001:db8:1:2:3:4:5:6/64")
	}
}

func BenchmarkParseIPv6Network_Compressed(b *testing.B) {
	b.ReportAllocs()
	for b.Loop() {
		network6Sink, errSink = xnetip.ParseIPv6Network("2a02:6b8::c00:1")
	}
}

func BenchmarkParseIPv6Network_EmbeddedIPv4(b *testing.B) {
	b.ReportAllocs()
	for b.Loop() {
		network6Sink, errSink = xnetip.ParseIPv6Network("::ffff:192.0.2.1")
	}
}

func BenchmarkParseIPv6Network_NonContiguousColonMask(b *testing.B) {
	b.ReportAllocs()
	for b.Loop() {
		network6Sink, errSink = xnetip.ParseIPv6Network("2a02:6b8:c00::1234:0:0/ffff:ffff:ff00::ffff:ffff:0:0")
	}
}

func BenchmarkParseIPv6Network_Reject(b *testing.B) {
	b.ReportAllocs()
	for b.Loop() {
		network6Sink, errSink = xnetip.ParseIPv6Network("::/129")
	}
}
