package xnetip_test

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
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

// verifies that containment over contiguous masks follows the prefix
// rules.
//
// The universe contains everything, a shorter prefix contains its
// refinements and not the reverse, and a host route contains only
// itself. Prefixes ending at, crossing and starting past bit 64 pin
// the half boundary.
func Test_IPv6Network_Contains_ContiguousAndBoundary(t *testing.T) {
	cases := []struct {
		name  string
		outer xnetip.IPv6Network
		inner xnetip.IPv6Network
		want  bool
	}{
		{name: "universe contains host route", outer: xnetip.MustParseIPv6Network("::/0"), inner: xnetip.MustParseIPv6Network("::1"), want: true},
		{name: "shorter prefix contains longer", outer: xnetip.MustParseIPv6Network("::/32"), inner: xnetip.MustParseIPv6Network("::/33"), want: true},
		{name: "longer prefix does not contain shorter", outer: xnetip.MustParseIPv6Network("::/33"), inner: xnetip.MustParseIPv6Network("::/32"), want: false},
		{name: "host route contains itself", outer: xnetip.MustParseIPv6Network("::1"), inner: xnetip.MustParseIPv6Network("::1"), want: true},
		{name: "host route does not contain neighbour", outer: xnetip.MustParseIPv6Network("::1/128"), inner: xnetip.MustParseIPv6Network("::2/128"), want: false},
		{name: "nested contiguous", outer: xnetip.MustParseIPv6Network("2001:db8::/32"), inner: xnetip.MustParseIPv6Network("2001:db8:1::/48"), want: true},
		{name: "nested contiguous reversed", outer: xnetip.MustParseIPv6Network("2001:db8:1::/48"), inner: xnetip.MustParseIPv6Network("2001:db8::/32"), want: false},
		{name: "disjoint contiguous", outer: xnetip.MustParseIPv6Network("2001:db8::/32"), inner: xnetip.MustParseIPv6Network("fe80::/10"), want: false},
		{name: "disjoint contiguous reversed", outer: xnetip.MustParseIPv6Network("fe80::/10"), inner: xnetip.MustParseIPv6Network("2001:db8::/32"), want: false},
		{name: "run ending at the half boundary contains longer", outer: xnetip.MustParseIPv6Network("2001:db8:1:2::/64"), inner: xnetip.MustParseIPv6Network("2001:db8:1:2:3::/80"), want: true},
		{name: "longer run does not contain the half-boundary run", outer: xnetip.MustParseIPv6Network("2001:db8:1:2:3::/80"), inner: xnetip.MustParseIPv6Network("2001:db8:1:2::/64"), want: false},
		{name: "/63 contains the /64 across the boundary", outer: xnetip.MustParseIPv6Network("2001:db8:1:2::/63"), inner: xnetip.MustParseIPv6Network("2001:db8:1:3::/64"), want: true},
		{name: "/64 does not contain its /63", outer: xnetip.MustParseIPv6Network("2001:db8:1:3::/64"), inner: xnetip.MustParseIPv6Network("2001:db8:1:2::/63"), want: false},
		{name: "/65 does not contain the /64 above it", outer: xnetip.MustParseIPv6Network("2001:db8:1:2:8000::/65"), inner: xnetip.MustParseIPv6Network("2001:db8:1:2::/64"), want: false},
		{name: "/64 contains its lower /65 half", outer: xnetip.MustParseIPv6Network("2001:db8:1:2::/64"), inner: xnetip.MustParseIPv6Network("2001:db8:1:2:8000::/65"), want: true},
		{name: "all-ones host contains itself", outer: xnetip.MustParseIPv6Network("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/128"), inner: xnetip.MustParseIPv6Network("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/128"), want: true},
		{name: "universe contains universe", outer: xnetip.MustParseIPv6Network("::/0"), inner: xnetip.MustParseIPv6Network("::/0"), want: true},
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
// must not leak in. Two-run masks and holes straddling bit 64 pin the
// half boundary.
func Test_IPv6Network_Contains_NonContiguousMasks(t *testing.T) {
	cases := []struct {
		name  string
		outer xnetip.IPv6Network
		inner xnetip.IPv6Network
		want  bool
	}{
		{name: "two-run mask contains matching host", outer: xnetip.MustParseIPv6Network("2a02:6b8:c00::4d71:0:0/ffff:ffff:ff00::ffff:ffff:0:0"), inner: xnetip.MustParseIPv6Network("2a02:6b8:c00:1234:0:4d71::1"), want: true},
		{name: "two-run mask rejects mismatch on a constrained group", outer: xnetip.MustParseIPv6Network("2a02:6b8:c00::4d71:0:0/ffff:ffff:ff00::ffff:ffff:0:0"), inner: xnetip.MustParseIPv6Network("2a02:6b8:c00:1234:0:4d72::1"), want: false},
		{name: "pattern contains narrower pattern", outer: xnetip.MustParseIPv6Network("2001:db8::/ffff:ffff::"), inner: xnetip.MustParseIPv6Network("2001:db8::1/ffff:ffff::ffff"), want: true},
		{name: "narrower pattern does not contain wider", outer: xnetip.MustParseIPv6Network("2001:db8::1/ffff:ffff::ffff"), inner: xnetip.MustParseIPv6Network("2001:db8::/ffff:ffff::"), want: false},
		{name: "hole in the third group contains its host", outer: xnetip.MustParseIPv6Network("2001:db8:c00::1/ffff:ffff:ff00:ffff:ffff:ffff:ffff:ffff"), inner: xnetip.MustParseIPv6Network("2001:db8:c05::1/128"), want: true},
		{name: "mask subset fails on disjoint mask bits", outer: xnetip.MustParseIPv6Network("2001::/ffff::ffff:0"), inner: xnetip.MustParseIPv6Network("2001::/ffff::ffff"), want: false},
		{name: "mask subset fails on disjoint mask bits reversed", outer: xnetip.MustParseIPv6Network("2001::/ffff::ffff"), inner: xnetip.MustParseIPv6Network("2001::/ffff::ffff:0"), want: false},
		{name: "host varying only inside the straddling hole", outer: xnetip.MustParseIPv6Network("2001:db8::/ffff:ffff:ffff:ff00:ff:ffff::"), inner: xnetip.MustParseIPv6Network("2001:db8:0:12:3400::/128"), want: true},
		{name: "constrained bits around the straddling hole differ", outer: xnetip.MustParseIPv6Network("2001:db8::/ffff:ffff:ffff:ff00:ff:ffff::"), inner: xnetip.MustParseIPv6Network("2001:db8:0:1200:34::/ffff:ffff:ffff:ff00:ff:ffff::"), want: false},
		{name: "constrained bits around the straddling hole differ reversed", outer: xnetip.MustParseIPv6Network("2001:db8:0:1200:34::/ffff:ffff:ffff:ff00:ff:ffff::"), inner: xnetip.MustParseIPv6Network("2001:db8::/ffff:ffff:ffff:ff00:ff:ffff::"), want: false},
		{name: "alternating groups contain the zero host", outer: xnetip.MustParseIPv6Network("::/ffff:0:ffff:0:ffff:0:ffff:0"), inner: xnetip.MustParseIPv6Network("::/128"), want: true},
		{name: "zero host does not contain the alternating groups", outer: xnetip.MustParseIPv6Network("::/128"), inner: xnetip.MustParseIPv6Network("::/ffff:0:ffff:0:ffff:0:ffff:0"), want: false},
		{name: "complementary alternating patterns", outer: xnetip.MustParseIPv6Network("aa00:0:aa00:0:aa00:0:aa00:0/ff00:ff:ff00:ff:ff00:ff:ff00:ff"), inner: xnetip.MustParseIPv6Network("bb:0:bb:0:bb:0:bb:0/ff:ff00:ff:ff00:ff:ff00:ff:ff00"), want: false},
		{name: "complementary alternating patterns reversed", outer: xnetip.MustParseIPv6Network("bb:0:bb:0:bb:0:bb:0/ff:ff00:ff:ff00:ff:ff00:ff:ff00"), inner: xnetip.MustParseIPv6Network("aa00:0:aa00:0:aa00:0:aa00:0/ff00:ff:ff00:ff:ff00:ff:ff00:ff"), want: false},
		{name: "numerically smaller mask is not a subset", outer: xnetip.MustParseIPv6Network("::/::ffff:ffff"), inner: xnetip.MustParseIPv6Network("::/0:0:0:0:ffff:ffff::"), want: false},
		{name: "numerically larger mask is not a subset either", outer: xnetip.MustParseIPv6Network("::/0:0:0:0:ffff:ffff::"), inner: xnetip.MustParseIPv6Network("::/::ffff:ffff"), want: false},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			require.Equal(t, testCase.want, testCase.outer.Contains(testCase.inner))
		})
	}
}

// verifies that every network contains itself, whatever the mask shape.
func Test_IPv6Network_Contains_ReflexiveProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		network := genIPv6Network.Draw(t, "network")
		require.True(t, network.Contains(network))
	})
}

// verifies that mutual containment holds exactly for equal networks.
func Test_IPv6Network_Contains_AntisymmetryProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		left := genIPv6Network.Draw(t, "left")
		right := genIPv6Network.Draw(t, "right")
		mutual := left.Contains(right) && right.Contains(left)
		require.Equal(t, left == right, mutual)
	})
}

// verifies that containment is transitive on random triples.
func Test_IPv6Network_Contains_TransitivityProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		first := genIPv6Network.Draw(t, "first")
		second := genIPv6Network.Draw(t, "second")
		third := genIPv6Network.Draw(t, "third")
		if first.Contains(second) && second.Contains(third) {
			require.True(t, first.Contains(third))
		}
	})
}

// verifies that the universe contains every network and is contained
// only in itself.
func Test_IPv6Network_Contains_UniverseProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		network := genIPv6Network.Draw(t, "network")
		require.True(t, xnetip.IPv6Network{}.Contains(network))
		require.Equal(t, network == xnetip.IPv6Network{}, network.Contains(xnetip.IPv6Network{}))
	})
}

// verifies that containment equals set inclusion on networks confined
// to the top group.
//
// Both masks live in the top eight bits, so enumerating the 256
// patterns there is exhaustive: the outer network contains the inner
// one exactly when every member of the inner is a member of the outer.
func Test_IPv6Network_Contains_BruteForceMembershipTopProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		outerAddr := uint64(rapid.IntRange(0, 255).Draw(t, "outer addr"))
		outerMask := uint64(rapid.IntRange(0, 255).Draw(t, "outer mask"))
		innerAddr := uint64(rapid.IntRange(0, 255).Draw(t, "inner addr"))
		innerMask := uint64(rapid.IntRange(0, 255).Draw(t, "inner mask"))
		outer, err := xnetip.IPv6NetworkFrom(
			netipAddrFrom6Bits(outerAddr<<56, 0),
			netipAddrFrom6Bits(outerMask<<56, 0),
		)
		require.NoError(t, err)
		inner, err := xnetip.IPv6NetworkFrom(
			netipAddrFrom6Bits(innerAddr<<56, 0),
			netipAddrFrom6Bits(innerMask<<56, 0),
		)
		require.NoError(t, err)
		want := true
		for x := uint64(0); x <= 255; x++ {
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

// verifies that containment equals set inclusion on networks confined
// to an eight-bit window straddling the half boundary.
//
// The window spans bits 60 through 67, four bits in each 64-bit half,
// so the exhaustive check exercises exactly the seam a half-word
// mixup would break: the outer network contains the inner one exactly
// when every member of the inner is a member of the outer.
func Test_IPv6Network_Contains_BruteForceMembershipStraddlingProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		outerAddr := uint64(rapid.IntRange(0, 255).Draw(t, "outer addr"))
		outerMask := uint64(rapid.IntRange(0, 255).Draw(t, "outer mask"))
		innerAddr := uint64(rapid.IntRange(0, 255).Draw(t, "inner addr"))
		innerMask := uint64(rapid.IntRange(0, 255).Draw(t, "inner mask"))
		outer, err := xnetip.IPv6NetworkFrom(
			netipAddrFrom6Bits(outerAddr>>4, outerAddr<<60),
			netipAddrFrom6Bits(outerMask>>4, outerMask<<60),
		)
		require.NoError(t, err)
		inner, err := xnetip.IPv6NetworkFrom(
			netipAddrFrom6Bits(innerAddr>>4, innerAddr<<60),
			netipAddrFrom6Bits(innerMask>>4, innerMask<<60),
		)
		require.NoError(t, err)
		want := true
		for x := uint64(0); x <= 255; x++ {
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

// verifies that lifting two IPv4 networks into IPv6 space preserves
// containment, the property dual-stack comparisons rely on.
func Test_IPv6Network_Contains_IPv4MappedEquivalenceProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		outer := genIPv4Network.Draw(t, "outer")
		inner := genIPv4Network.Draw(t, "inner")
		require.Equal(
			t,
			outer.Contains(inner),
			outer.ToIPv6Mapped().Contains(inner.ToIPv6Mapped()),
		)
	})
}

// verifies that on contiguous networks containment agrees with the
// net/netip rule.
//
// The oracle is the prefix pair: the outer prefix covers the inner
// address and its length does not exceed the inner one.
func Test_IPv6Network_Contains_MatchesNetipPrefixProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		outerPrefix := genIPv6Prefix.Draw(t, "outer").Masked()
		innerPrefix := genIPv6Prefix.Draw(t, "inner").Masked()
		outer, ok := xnetip.IPv6NetworkFromPrefix(outerPrefix)
		require.True(t, ok)
		inner, ok := xnetip.IPv6NetworkFromPrefix(innerPrefix)
		require.True(t, ok)
		want := outerPrefix.Contains(innerPrefix.Addr()) && outerPrefix.Bits() <= innerPrefix.Bits()
		require.Equal(t, want, outer.Contains(inner))
	})
}

// verifies that containing a host route agrees with the net/netip
// address containment of the same prefix.
func Test_IPv6Network_Contains_HostRouteMatchesNetipProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		outerPrefix := genIPv6Prefix.Draw(t, "outer").Masked()
		outer, ok := xnetip.IPv6NetworkFromPrefix(outerPrefix)
		require.True(t, ok)
		address := genNetipAddr6.Draw(t, "address")
		host, err := xnetip.IPv6NetworkFromAddr(address)
		require.NoError(t, err)
		require.Equal(t, outerPrefix.Contains(address), outer.Contains(host))
	})
}

// verifies that the containment check allocates nothing.
func Test_IPv6Network_Contains_AllocationFree(t *testing.T) {
	outer := xnetip.MustParseIPv6Network("2001:db8:c00::1/ffff:ffff:ff00:ffff:ffff:ffff:ffff:ffff")
	inner := xnetip.MustParseIPv6Network("2001:db8:c05::1/128")
	requireNoAllocs(t, func() { okSink = outer.Contains(inner) })
}

func BenchmarkIPv6Network_Contains_ContiguousTrue(b *testing.B) {
	outer := xnetip.MustParseIPv6Network("2001:db8::/32")
	inner := xnetip.MustParseIPv6Network("2001:db8:1::/48")
	b.ReportAllocs()
	for b.Loop() {
		okSink = outer.Contains(inner)
	}
}

func BenchmarkIPv6Network_Contains_ContiguousFalse(b *testing.B) {
	outer := xnetip.MustParseIPv6Network("2001:db8::/32")
	inner := xnetip.MustParseIPv6Network("fe80::/10")
	b.ReportAllocs()
	for b.Loop() {
		okSink = outer.Contains(inner)
	}
}

func BenchmarkIPv6Network_Contains_NonContiguous(b *testing.B) {
	outer := xnetip.MustParseIPv6Network("2001:db8:c00::1/ffff:ffff:ff00:ffff:ffff:ffff:ffff:ffff")
	inner := xnetip.MustParseIPv6Network("2001:db8:c05::1/128")
	b.ReportAllocs()
	for b.Loop() {
		okSink = outer.Contains(inner)
	}
}

// verifies that intersecting contiguous networks yields the more
// specific one and fails exactly on disjoint prefixes.
//
// Containment yields the inner network in both orders, the half
// boundary included, identical networks and host routes intersect as
// themselves, the universe is neutral, and a disjoint pair answers
// the zero network so a caller ignoring the flag cannot pick up
// plausible garbage.
func Test_IPv6Network_Intersection_ContiguousAndBoundary(t *testing.T) {
	cases := []struct {
		name   string
		left   xnetip.IPv6Network
		right  xnetip.IPv6Network
		want   xnetip.IPv6Network
		wantOK bool
	}{
		{name: "containment yields the inner network", left: xnetip.MustParseIPv6Network("2001:db8::/32"), right: xnetip.MustParseIPv6Network("2001:db8:1::/48"), want: xnetip.MustParseIPv6Network("2001:db8:1::/48"), wantOK: true},
		{name: "containment reversed yields the inner network", left: xnetip.MustParseIPv6Network("2001:db8:1::/48"), right: xnetip.MustParseIPv6Network("2001:db8::/32"), want: xnetip.MustParseIPv6Network("2001:db8:1::/48"), wantOK: true},
		{name: "identical networks intersect as themselves", left: xnetip.MustParseIPv6Network("2001:db8::/32"), right: xnetip.MustParseIPv6Network("2001:db8::/32"), want: xnetip.MustParseIPv6Network("2001:db8::/32"), wantOK: true},
		{name: "disjoint contiguous networks answer the zero network", left: xnetip.MustParseIPv6Network("2001:db8::/32"), right: xnetip.MustParseIPv6Network("fe80::/10"), want: xnetip.IPv6Network{}, wantOK: false},
		{name: "universe is neutral", left: xnetip.MustParseIPv6Network("::/0"), right: xnetip.MustParseIPv6Network("2001:db8:1::/48"), want: xnetip.MustParseIPv6Network("2001:db8:1::/48"), wantOK: true},
		{name: "universe is neutral reversed", left: xnetip.MustParseIPv6Network("2001:db8:1::/48"), right: xnetip.MustParseIPv6Network("::/0"), want: xnetip.MustParseIPv6Network("2001:db8:1::/48"), wantOK: true},
		{name: "same host route intersects as itself", left: xnetip.MustParseIPv6Network("::1/128"), right: xnetip.MustParseIPv6Network("::1/128"), want: xnetip.MustParseIPv6Network("::1/128"), wantOK: true},
		{name: "different host routes are disjoint", left: xnetip.MustParseIPv6Network("::1/128"), right: xnetip.MustParseIPv6Network("::2/128"), want: xnetip.IPv6Network{}, wantOK: false},
		{name: "/64 siblings are disjoint", left: xnetip.MustParseIPv6Network("2001:db8:1:2::/64"), right: xnetip.MustParseIPv6Network("2001:db8:1:3::/64"), want: xnetip.IPv6Network{}, wantOK: false},
		{name: "/63 with the /64 inside across the boundary", left: xnetip.MustParseIPv6Network("2001:db8:1:2::/63"), right: xnetip.MustParseIPv6Network("2001:db8:1:3::/64"), want: xnetip.MustParseIPv6Network("2001:db8:1:3::/64"), wantOK: true},
		{name: "/64 with the /65 inside just past the boundary", left: xnetip.MustParseIPv6Network("2001:db8:1:2::/64"), right: xnetip.MustParseIPv6Network("2001:db8:1:2:8000::/65"), want: xnetip.MustParseIPv6Network("2001:db8:1:2:8000::/65"), wantOK: true},
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
// set bit always intersect whatever the addresses, two complementary
// alternating patterns collapsing to a single host route. Two-run
// masks and holes straddling bit 64 pin the half boundary.
func Test_IPv6Network_Intersection_NonContiguousMasks(t *testing.T) {
	cases := []struct {
		name   string
		left   xnetip.IPv6Network
		right  xnetip.IPv6Network
		want   xnetip.IPv6Network
		wantOK bool
	}{
		{name: "one non-contiguous", left: xnetip.MustParseIPv6Network("2001::1/ffff::ffff"), right: xnetip.MustParseIPv6Network("2001:1::/ffff:ffff::"), want: xnetip.MustParseIPv6Network("2001:1::1/ffff:ffff::ffff"), wantOK: true},
		{name: "one non-contiguous reversed", left: xnetip.MustParseIPv6Network("2001:1::/ffff:ffff::"), right: xnetip.MustParseIPv6Network("2001::1/ffff::ffff"), want: xnetip.MustParseIPv6Network("2001:1::1/ffff:ffff::ffff"), wantOK: true},
		{name: "both non-contiguous", left: xnetip.MustParseIPv6Network("2001:0:a::/ffff:0:ffff::"), right: xnetip.MustParseIPv6Network("2001::5/ffff::ffff"), want: xnetip.MustParseIPv6Network("2001:0:a::5/ffff:0:ffff::ffff"), wantOK: true},
		{name: "both non-contiguous reversed", left: xnetip.MustParseIPv6Network("2001::5/ffff::ffff"), right: xnetip.MustParseIPv6Network("2001:0:a::/ffff:0:ffff::"), want: xnetip.MustParseIPv6Network("2001:0:a::5/ffff:0:ffff::ffff"), wantOK: true},
		{name: "alternating masks always intersect", left: xnetip.MustParseIPv6Network("aa00:0:aa00:0:aa00:0:aa00:0/ff00:ff:ff00:ff:ff00:ff:ff00:ff"), right: xnetip.MustParseIPv6Network("bb:0:bb:0:bb:0:bb:0/ff:ff00:ff:ff00:ff:ff00:ff:ff00"), want: xnetip.MustParseIPv6Network("aabb:0:aabb:0:aabb:0:aabb:0/128"), wantOK: true},
		{name: "high half with low half", left: xnetip.MustParseIPv6Network("2001:db8:1:2::/64"), right: xnetip.MustParseIPv6Network("::3:4:5:6/::ffff:ffff:ffff:ffff"), want: xnetip.MustParseIPv6Network("2001:db8:1:2:3:4:5:6/128"), wantOK: true},
		{name: "two-run masks disagreeing on a constrained group", left: xnetip.MustParseIPv6Network("2a02:6b8:c00::4d71:0:0/ffff:ffff:ff00::ffff:ffff:0:0"), right: xnetip.MustParseIPv6Network("2a02:6b8:c00::4d72:0:0/ffff:ffff:ff00::ffff:ffff:0:0"), want: xnetip.IPv6Network{}, wantOK: false},
		{name: "two-run mask agreeing with a prefix", left: xnetip.MustParseIPv6Network("2a02:6b8:c00::4d71:0:0/ffff:ffff:ff00::ffff:ffff:0:0"), right: xnetip.MustParseIPv6Network("2a02:6b8:c00:1234::/ffff:ffff:ffff:ffff::"), want: xnetip.MustParseIPv6Network("2a02:6b8:c00:1234:0:4d71:0:0/ffff:ffff:ffff:ffff:ffff:ffff:0:0"), wantOK: true},
		{name: "hole straddling bit 64 with a host inside", left: xnetip.MustParseIPv6Network("2001:db8::/ffff:ffff:ffff:ff00:ff:ffff::"), right: xnetip.MustParseIPv6Network("2001:db8:0:12:3400::/128"), want: xnetip.MustParseIPv6Network("2001:db8:0:12:3400::/128"), wantOK: true},
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
func Test_IPv6Network_Intersection_CommutativityProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		left := genIPv6Network.Draw(t, "left")
		right := genIPv6Network.Draw(t, "right")
		leftValue, leftOK := left.Intersection(right)
		rightValue, rightOK := right.Intersection(left)
		require.Equal(t, leftOK, rightOK)
		require.Equal(t, leftValue, rightValue)
	})
}

// verifies that every network intersected with itself is itself.
func Test_IPv6Network_Intersection_SelfIntersectionProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		network := genIPv6Network.Draw(t, "network")
		got, ok := network.Intersection(network)
		require.True(t, ok)
		require.Equal(t, network, got)
	})
}

// verifies that when one network contains the other the intersection
// is the contained one.
func Test_IPv6Network_Intersection_ContainmentYieldsInnerProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		outer := genIPv6Network.Draw(t, "outer")
		inner := genIPv6Network.Draw(t, "inner")
		if outer.Contains(inner) {
			got, ok := outer.Intersection(inner)
			require.True(t, ok)
			require.Equal(t, inner, got)
		}
	})
}

// verifies that an existing intersection is contained in both inputs.
func Test_IPv6Network_Intersection_SubsetOfBothProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		left := genIPv6Network.Draw(t, "left")
		right := genIPv6Network.Draw(t, "right")
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
func Test_IPv6Network_Intersection_ShapeAndNormalizedProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		left := genIPv6Network.Draw(t, "left")
		right := genIPv6Network.Draw(t, "right")
		got, ok := left.Intersection(right)
		if !ok {
			return
		}
		leftAddr := left.Addr().As16()
		leftMask := left.Mask().As16()
		rightAddr := right.Addr().As16()
		rightMask := right.Mask().As16()
		wantAddrHi := binary.BigEndian.Uint64(leftAddr[:8]) | binary.BigEndian.Uint64(rightAddr[:8])
		wantAddrLo := binary.BigEndian.Uint64(leftAddr[8:]) | binary.BigEndian.Uint64(rightAddr[8:])
		wantMaskHi := binary.BigEndian.Uint64(leftMask[:8]) | binary.BigEndian.Uint64(rightMask[:8])
		wantMaskLo := binary.BigEndian.Uint64(leftMask[8:]) | binary.BigEndian.Uint64(rightMask[8:])
		require.Equal(t, netipAddrFrom6Bits(wantAddrHi, wantAddrLo), got.Addr())
		require.Equal(t, netipAddrFrom6Bits(wantMaskHi, wantMaskLo), got.Mask())
		require.Equal(t, netipAddrFrom6Bits(wantAddrHi&wantMaskHi, wantAddrLo&wantMaskLo), got.Addr())
	})
}

// verifies that intersection equals set intersection on networks
// confined to the top group.
//
// Both masks live in the top eight bits, so enumerating the 256
// patterns there is exhaustive: an address belongs to both inputs
// exactly when the intersection exists and the address belongs to it.
func Test_IPv6Network_Intersection_BruteForceMembershipTopProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		leftAddr := uint64(rapid.IntRange(0, 255).Draw(t, "left addr"))
		leftMask := uint64(rapid.IntRange(0, 255).Draw(t, "left mask"))
		rightAddr := uint64(rapid.IntRange(0, 255).Draw(t, "right addr"))
		rightMask := uint64(rapid.IntRange(0, 255).Draw(t, "right mask"))
		left, err := xnetip.IPv6NetworkFrom(
			netipAddrFrom6Bits(leftAddr<<56, 0),
			netipAddrFrom6Bits(leftMask<<56, 0),
		)
		require.NoError(t, err)
		right, err := xnetip.IPv6NetworkFrom(
			netipAddrFrom6Bits(rightAddr<<56, 0),
			netipAddrFrom6Bits(rightMask<<56, 0),
		)
		require.NoError(t, err)
		got, ok := left.Intersection(right)
		gotAddr := got.Addr().As16()
		gotMask := got.Mask().As16()
		gotAddrBits := binary.BigEndian.Uint64(gotAddr[:8]) >> 56
		gotMaskBits := binary.BigEndian.Uint64(gotMask[:8]) >> 56
		for x := uint64(0); x <= 255; x++ {
			memberOfLeft := x&leftMask == leftAddr&leftMask
			memberOfRight := x&rightMask == rightAddr&rightMask
			memberOfResult := ok && x&gotMaskBits == gotAddrBits
			require.Equal(t, memberOfLeft && memberOfRight, memberOfResult, "address %d", x)
		}
	})
}

// verifies that intersection equals set intersection on networks
// confined to an eight-bit window straddling the half boundary.
//
// The window spans bits 60 through 67, four bits in each 64-bit half,
// so the exhaustive check exercises exactly the seam a half-word
// mixup would break: an address belongs to both inputs exactly when
// the intersection exists and the address belongs to it.
func Test_IPv6Network_Intersection_BruteForceMembershipStraddlingProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		leftAddr := uint64(rapid.IntRange(0, 255).Draw(t, "left addr"))
		leftMask := uint64(rapid.IntRange(0, 255).Draw(t, "left mask"))
		rightAddr := uint64(rapid.IntRange(0, 255).Draw(t, "right addr"))
		rightMask := uint64(rapid.IntRange(0, 255).Draw(t, "right mask"))
		left, err := xnetip.IPv6NetworkFrom(
			netipAddrFrom6Bits(leftAddr>>4, leftAddr<<60),
			netipAddrFrom6Bits(leftMask>>4, leftMask<<60),
		)
		require.NoError(t, err)
		right, err := xnetip.IPv6NetworkFrom(
			netipAddrFrom6Bits(rightAddr>>4, rightAddr<<60),
			netipAddrFrom6Bits(rightMask>>4, rightMask<<60),
		)
		require.NoError(t, err)
		got, ok := left.Intersection(right)
		gotAddr := got.Addr().As16()
		gotMask := got.Mask().As16()
		gotAddrBits := binary.BigEndian.Uint64(gotAddr[:8])<<4 | binary.BigEndian.Uint64(gotAddr[8:])>>60
		gotMaskBits := binary.BigEndian.Uint64(gotMask[:8])<<4 | binary.BigEndian.Uint64(gotMask[8:])>>60
		for x := uint64(0); x <= 255; x++ {
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
func Test_IPv6Network_Intersection_MatchesNetipOverlapsProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		leftPrefix := genIPv6Prefix.Draw(t, "left").Masked()
		rightPrefix := genIPv6Prefix.Draw(t, "right").Masked()
		left, ok := xnetip.IPv6NetworkFromPrefix(leftPrefix)
		require.True(t, ok)
		right, ok := xnetip.IPv6NetworkFromPrefix(rightPrefix)
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
func Test_IPv6Network_Intersection_AllocationFree(t *testing.T) {
	left := xnetip.MustParseIPv6Network("2001::1/ffff::ffff")
	right := xnetip.MustParseIPv6Network("2001:1::/ffff:ffff::")
	requireNoAllocs(t, func() { network6Sink, okSink = left.Intersection(right) })
}

func BenchmarkIPv6Network_Intersection_ContiguousOverlapping(b *testing.B) {
	left := xnetip.MustParseIPv6Network("2001:db8::/32")
	right := xnetip.MustParseIPv6Network("2001:db8:1::/48")
	b.ReportAllocs()
	for b.Loop() {
		network6Sink, okSink = left.Intersection(right)
	}
}

func BenchmarkIPv6Network_Intersection_ContiguousDisjoint(b *testing.B) {
	left := xnetip.MustParseIPv6Network("2001:db8::/32")
	right := xnetip.MustParseIPv6Network("fe80::/10")
	b.ReportAllocs()
	for b.Loop() {
		network6Sink, okSink = left.Intersection(right)
	}
}

func BenchmarkIPv6Network_Intersection_NonContiguous(b *testing.B) {
	left := xnetip.MustParseIPv6Network("2001::1/ffff::ffff")
	right := xnetip.MustParseIPv6Network("2001:1::/ffff:ffff::")
	b.ReportAllocs()
	for b.Loop() {
		network6Sink, okSink = left.Intersection(right)
	}
}

// verifies that contiguous networks intersect exactly when one
// contains the other or they are equal prefixes of a common address.
//
// A network always intersects itself, the universe intersects
// everything, two host routes intersect only when equal, and sibling
// blocks split at bit 64 pin the half boundary.
func Test_IPv6Network_Intersects_ContiguousAndBoundary(t *testing.T) {
	cases := []struct {
		name  string
		left  xnetip.IPv6Network
		right xnetip.IPv6Network
		want  bool
	}{
		{name: "overlapping contiguous", left: xnetip.MustParseIPv6Network("2001:db8::/32"), right: xnetip.MustParseIPv6Network("2001:db8:1::/48"), want: true},
		{name: "overlapping contiguous reversed", left: xnetip.MustParseIPv6Network("2001:db8:1::/48"), right: xnetip.MustParseIPv6Network("2001:db8::/32"), want: true},
		{name: "disjoint contiguous", left: xnetip.MustParseIPv6Network("2001:db8::/32"), right: xnetip.MustParseIPv6Network("fe80::/10"), want: false},
		{name: "disjoint contiguous reversed", left: xnetip.MustParseIPv6Network("fe80::/10"), right: xnetip.MustParseIPv6Network("2001:db8::/32"), want: false},
		{name: "self", left: xnetip.MustParseIPv6Network("2001:db8::/32"), right: xnetip.MustParseIPv6Network("2001:db8::/32"), want: true},
		{name: "unspecified with anything", left: xnetip.MustParseIPv6Network("::/0"), right: xnetip.MustParseIPv6Network("2001:db8:1::/48"), want: true},
		{name: "anything with unspecified", left: xnetip.MustParseIPv6Network("2001:db8:1::/48"), right: xnetip.MustParseIPv6Network("::/0"), want: true},
		{name: "equal host routes", left: xnetip.MustParseIPv6Network("2001:db8::1/128"), right: xnetip.MustParseIPv6Network("2001:db8::1/128"), want: true},
		{name: "different host routes", left: xnetip.MustParseIPv6Network("2001:db8::1/128"), right: xnetip.MustParseIPv6Network("2001:db8::2/128"), want: false},
		{name: "blocks differing only in the low half", left: xnetip.MustParseIPv6Network("2001:db8::/64"), right: xnetip.MustParseIPv6Network("2001:db8:0:0:8000::/65"), want: true},
		{name: "blocks differing at bit 64", left: xnetip.MustParseIPv6Network("2001:db8:0:0::/64"), right: xnetip.MustParseIPv6Network("2001:db8:0:1::/64"), want: false},
		{name: "all-ones host route vs the universe", left: xnetip.MustParseIPv6Network("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/128"), right: xnetip.MustParseIPv6Network("::/0"), want: true},
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
// a bit constrained by only one side never separates, and a single
// doubly constrained group that differs keeps the networks apart —
// including when the free hole straddles bit 64.
func Test_IPv6Network_Intersects_NonContiguousMasks(t *testing.T) {
	cases := []struct {
		name  string
		left  xnetip.IPv6Network
		right xnetip.IPv6Network
		want  bool
	}{
		{name: "pattern overlaps block", left: xnetip.MustParseIPv6Network("2001::1/ffff::ffff"), right: xnetip.MustParseIPv6Network("2001:1::/32"), want: true},
		{name: "pattern overlaps block reversed", left: xnetip.MustParseIPv6Network("2001:1::/32"), right: xnetip.MustParseIPv6Network("2001::1/ffff::ffff"), want: true},
		{name: "pattern disjoint from block", left: xnetip.MustParseIPv6Network("2001::1/ffff::ffff"), right: xnetip.MustParseIPv6Network("2002::/16"), want: false},
		{name: "alternating masks always intersect", left: xnetip.MustParseIPv6Network("aa00:0:aa00:0:aa00:0:aa00:0/ff00:ff:ff00:ff:ff00:ff:ff00:ff"), right: xnetip.MustParseIPv6Network("bb:0:bb:0:bb:0:bb:0/ff:ff00:ff:ff00:ff:ff00:ff:ff00"), want: true},
		{name: "same pattern mask, different fixed low group", left: xnetip.MustParseIPv6Network("2001::1/ffff::ffff"), right: xnetip.MustParseIPv6Network("2001::2/ffff::ffff"), want: false},
		{name: "hole straddling the boundary, disagreeing constrained group", left: xnetip.MustParseIPv6Network("2001:db8::1:0:0/ffff:ffff:ffff:0:0:ffff::"), right: xnetip.MustParseIPv6Network("2001:db8:0:1:1:2::/ffff:ffff:ffff:ffff:ffff:ffff::"), want: false},
		{name: "hole straddling the boundary, agreeing constrained groups", left: xnetip.MustParseIPv6Network("2001:db8::1:0:0/ffff:ffff:ffff:0:0:ffff::"), right: xnetip.MustParseIPv6Network("2001:db8:0:1:1:1::/ffff:ffff:ffff:ffff:ffff:ffff::"), want: true},
		{name: "two-run mask vs contiguous containing it", left: xnetip.MustParseIPv6Network("2a02:6b8:c00::1234:0:0/ffff:ffff:ff00::ffff:ffff:0:0"), right: xnetip.MustParseIPv6Network("2a02:6b8::/32"), want: true},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			require.Equal(t, testCase.want, testCase.left.Intersects(testCase.right))
		})
	}
}

// verifies that the predicate is symmetric.
func Test_IPv6Network_Intersects_SymmetryProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		left := genIPv6Network.Draw(t, "left")
		right := genIPv6Network.Draw(t, "right")
		require.Equal(t, left.Intersects(right), right.Intersects(left))
	})
}

// verifies that the predicate answers exactly whether the
// intersection exists.
func Test_IPv6Network_Intersects_EquivalentToIntersectionProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		left := genIPv6Network.Draw(t, "left")
		right := genIPv6Network.Draw(t, "right")
		_, ok := left.Intersection(right)
		require.Equal(t, ok, left.Intersects(right))
	})
}

// verifies that every network intersects itself and the universe
// intersects every network.
func Test_IPv6Network_Intersects_ReflexiveAndUniverseProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		network := genIPv6Network.Draw(t, "network")
		require.True(t, network.Intersects(network))
		require.True(t, xnetip.IPv6Network{}.Intersects(network))
	})
}

// verifies that containment implies intersection.
func Test_IPv6Network_Intersects_ContainmentImpliesIntersectionProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		outer := genIPv6Network.Draw(t, "outer")
		inner := genIPv6Network.Draw(t, "inner")
		if outer.Contains(inner) {
			require.True(t, outer.Intersects(inner))
		}
	})
}

// verifies that the predicate equals shared membership on networks
// confined to the top group.
//
// Both masks live in the top eight bits, so enumerating the 256
// patterns there is exhaustive: the networks intersect exactly when
// some address belongs to both.
func Test_IPv6Network_Intersects_BruteForceMembershipProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		leftAddr := uint64(rapid.IntRange(0, 255).Draw(t, "left addr"))
		leftMask := uint64(rapid.IntRange(0, 255).Draw(t, "left mask"))
		rightAddr := uint64(rapid.IntRange(0, 255).Draw(t, "right addr"))
		rightMask := uint64(rapid.IntRange(0, 255).Draw(t, "right mask"))
		left, err := xnetip.IPv6NetworkFrom(
			netipAddrFrom6Bits(leftAddr<<56, 0),
			netipAddrFrom6Bits(leftMask<<56, 0),
		)
		require.NoError(t, err)
		right, err := xnetip.IPv6NetworkFrom(
			netipAddrFrom6Bits(rightAddr<<56, 0),
			netipAddrFrom6Bits(rightMask<<56, 0),
		)
		require.NoError(t, err)
		want := false
		for x := uint64(0); x <= 255; x++ {
			if x&leftMask == leftAddr&leftMask && x&rightMask == rightAddr&rightMask {
				want = true
				break
			}
		}
		require.Equal(t, want, left.Intersects(right))
	})
}

// verifies that lifting two IPv4 networks into IPv6 space preserves
// intersection, the property dual-stack comparisons rely on.
func Test_IPv6Network_Intersects_IPv4MappedEquivalenceProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		left := genIPv4Network.Draw(t, "left")
		right := genIPv4Network.Draw(t, "right")
		require.Equal(
			t,
			left.Intersects(right),
			left.ToIPv6Mapped().Intersects(right.ToIPv6Mapped()),
		)
	})
}

// verifies that on contiguous networks the predicate agrees with the
// net/netip overlap rule.
func Test_IPv6Network_Intersects_MatchesNetipOverlapsProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		leftPrefix := genIPv6Prefix.Draw(t, "left").Masked()
		rightPrefix := genIPv6Prefix.Draw(t, "right").Masked()
		left, ok := xnetip.IPv6NetworkFromPrefix(leftPrefix)
		require.True(t, ok)
		right, ok := xnetip.IPv6NetworkFromPrefix(rightPrefix)
		require.True(t, ok)
		require.Equal(t, leftPrefix.Overlaps(rightPrefix), left.Intersects(right))
	})
}

// verifies that the predicate allocates nothing.
func Test_IPv6Network_Intersects_AllocationFree(t *testing.T) {
	left := xnetip.MustParseIPv6Network("2001::1/ffff::ffff")
	right := xnetip.MustParseIPv6Network("2001:1::/32")
	requireNoAllocs(t, func() { okSink = left.Intersects(right) })
}

func BenchmarkIPv6Network_Intersects_Contiguous(b *testing.B) {
	left := xnetip.MustParseIPv6Network("2001:db8::/32")
	right := xnetip.MustParseIPv6Network("2001:db8:1::/48")
	b.ReportAllocs()
	for b.Loop() {
		okSink = left.Intersects(right)
	}
}

func BenchmarkIPv6Network_Intersects_Disjoint(b *testing.B) {
	left := xnetip.MustParseIPv6Network("2001:db8::/32")
	right := xnetip.MustParseIPv6Network("fe80::/10")
	b.ReportAllocs()
	for b.Loop() {
		okSink = left.Intersects(right)
	}
}

func BenchmarkIPv6Network_Intersects_NonContiguous(b *testing.B) {
	left := xnetip.MustParseIPv6Network("2001::1/ffff::ffff")
	right := xnetip.MustParseIPv6Network("2001:1::/32")
	b.ReportAllocs()
	for b.Loop() {
		okSink = left.Intersects(right)
	}
}

// verifies that disjointness holds exactly for networks sharing no
// address.
//
// No network is disjoint from itself or from the universe, two host
// routes are disjoint exactly when they differ, and sibling blocks
// split at bit 64 pin the half boundary.
func Test_IPv6Network_IsDisjoint_ContiguousAndBoundary(t *testing.T) {
	cases := []struct {
		name  string
		left  xnetip.IPv6Network
		right xnetip.IPv6Network
		want  bool
	}{
		{name: "overlapping contiguous", left: xnetip.MustParseIPv6Network("2001:db8::/32"), right: xnetip.MustParseIPv6Network("2001:db8:1::/48"), want: false},
		{name: "overlapping contiguous reversed", left: xnetip.MustParseIPv6Network("2001:db8:1::/48"), right: xnetip.MustParseIPv6Network("2001:db8::/32"), want: false},
		{name: "disjoint contiguous", left: xnetip.MustParseIPv6Network("2001:db8::/32"), right: xnetip.MustParseIPv6Network("fe80::/10"), want: true},
		{name: "self", left: xnetip.MustParseIPv6Network("2001:db8::/32"), right: xnetip.MustParseIPv6Network("2001:db8::/32"), want: false},
		{name: "unspecified with anything", left: xnetip.MustParseIPv6Network("::/0"), right: xnetip.MustParseIPv6Network("2001:db8::/32"), want: false},
		{name: "different host routes", left: xnetip.MustParseIPv6Network("2001:db8::1/128"), right: xnetip.MustParseIPv6Network("2001:db8::2/128"), want: true},
		{name: "blocks differing at bit 64", left: xnetip.MustParseIPv6Network("2001:db8:0:0::/64"), right: xnetip.MustParseIPv6Network("2001:db8:0:1::/64"), want: true},
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
// addresses, and a disagreement next to a free hole straddling bit 64
// pins the half boundary.
func Test_IPv6Network_IsDisjoint_NonContiguousMasks(t *testing.T) {
	cases := []struct {
		name  string
		left  xnetip.IPv6Network
		right xnetip.IPv6Network
		want  bool
	}{
		{name: "pattern disjoint from block", left: xnetip.MustParseIPv6Network("2001::1/ffff::ffff"), right: xnetip.MustParseIPv6Network("2002::/16"), want: true},
		{name: "pattern overlapping block", left: xnetip.MustParseIPv6Network("2001::1/ffff::ffff"), right: xnetip.MustParseIPv6Network("2001:1::/32"), want: false},
		{name: "hole straddling the boundary, disagreeing constrained group", left: xnetip.MustParseIPv6Network("2001:db8::1:0:0/ffff:ffff:ffff:0:0:ffff::"), right: xnetip.MustParseIPv6Network("2001:db8:0:1:1:2::/ffff:ffff:ffff:ffff:ffff:ffff::"), want: true},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			require.Equal(t, testCase.want, testCase.left.IsDisjoint(testCase.right))
		})
	}
}

// verifies that disjointness is the exact complement of intersection,
// symmetric, and never holds for a network against itself.
func Test_IPv6Network_IsDisjoint_ComplementOfIntersectsProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		left := genIPv6Network.Draw(t, "left")
		right := genIPv6Network.Draw(t, "right")
		require.Equal(t, !left.Intersects(right), left.IsDisjoint(right))
		require.Equal(t, left.IsDisjoint(right), right.IsDisjoint(left))
		require.False(t, left.IsDisjoint(left))
	})
}

// verifies that the predicate allocates nothing.
func Test_IPv6Network_IsDisjoint_AllocationFree(t *testing.T) {
	left := xnetip.MustParseIPv6Network("2001::1/ffff::ffff")
	right := xnetip.MustParseIPv6Network("2002::/16")
	requireNoAllocs(t, func() { okSink = left.IsDisjoint(right) })
}

// verifies that adjacency needs the same mask and exactly one
// differing masked bit, anywhere in the mask.
//
// Identical networks are not adjacent, different masks never are, and
// differing bits at positions 63 and 64 pin the borrow across the
// half boundary in the single-bit test.
func Test_IPv6Network_IsAdjacent_ContiguousAndBoundary(t *testing.T) {
	cases := []struct {
		name  string
		left  xnetip.IPv6Network
		right xnetip.IPv6Network
		want  bool
	}{
		{name: "contiguous siblings", left: xnetip.MustParseIPv6Network("2001:db8::/48"), right: xnetip.MustParseIPv6Network("2001:db8:1::/48"), want: true},
		{name: "contiguous siblings reversed", left: xnetip.MustParseIPv6Network("2001:db8:1::/48"), right: xnetip.MustParseIPv6Network("2001:db8::/48"), want: true},
		{name: "identical", left: xnetip.MustParseIPv6Network("2001:db8::/48"), right: xnetip.MustParseIPv6Network("2001:db8::/48"), want: false},
		{name: "different masks", left: xnetip.MustParseIPv6Network("2001:db8::/48"), right: xnetip.MustParseIPv6Network("2001:db8::/32"), want: false},
		{name: "same mask, two differing bits", left: xnetip.MustParseIPv6Network("2001:db8::/48"), right: xnetip.MustParseIPv6Network("2001:db8:5::/48"), want: false},
		{name: "adjacent at the top mask bit", left: xnetip.MustParseIPv6Network("::/2"), right: xnetip.MustParseIPv6Network("8000::/2"), want: true},
		{name: "differing at bit 64, mask /64", left: xnetip.MustParseIPv6Network("2001:db8:0:0::/64"), right: xnetip.MustParseIPv6Network("2001:db8:0:1::/64"), want: true},
		{name: "differing at bit 63, mask /65", left: xnetip.MustParseIPv6Network("2001:db8::/65"), right: xnetip.MustParseIPv6Network("2001:db8:0:0:8000::/65"), want: true},
		{name: "differing at bit 64, mask /65", left: xnetip.MustParseIPv6Network("2001:db8::/65"), right: xnetip.MustParseIPv6Network("2001:db8:0:1::/65"), want: true},
		{name: "differing at bits 63 and 64 together, mask /65", left: xnetip.MustParseIPv6Network("2001:db8::/65"), right: xnetip.MustParseIPv6Network("2001:db8:0:1:8000::/65"), want: false},
		{name: "host routes differing in bit 0", left: xnetip.MustParseIPv6Network("2001:db8::/128"), right: xnetip.MustParseIPv6Network("2001:db8::1/128"), want: true},
		{name: "host routes differing in bit 127", left: xnetip.MustParseIPv6Network("::1/128"), right: xnetip.MustParseIPv6Network("8000::1/128"), want: true},
		{name: "default route with itself", left: xnetip.MustParseIPv6Network("::/0"), right: xnetip.MustParseIPv6Network("::/0"), want: false},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			require.Equal(t, testCase.want, testCase.left.IsAdjacent(testCase.right))
		})
	}
}

// verifies that adjacency of non-contiguous networks counts only
// masked bits, wherever the differing bit sits in the pattern.
func Test_IPv6Network_IsAdjacent_NonContiguousMasks(t *testing.T) {
	cases := []struct {
		name  string
		left  xnetip.IPv6Network
		right xnetip.IPv6Network
		want  bool
	}{
		{name: "two-run mask, differing in the low run", left: xnetip.MustParseIPv6Network("2a02:6b8:c00::1234:0:0/ffff:ffff:ff00::ffff:ffff:0:0"), right: xnetip.MustParseIPv6Network("2a02:6b8:c00::1235:0:0/ffff:ffff:ff00::ffff:ffff:0:0"), want: true},
		{name: "two-run mask, differing in the low run reversed", left: xnetip.MustParseIPv6Network("2a02:6b8:c00::1235:0:0/ffff:ffff:ff00::ffff:ffff:0:0"), right: xnetip.MustParseIPv6Network("2a02:6b8:c00::1234:0:0/ffff:ffff:ff00::ffff:ffff:0:0"), want: true},
		{name: "two-run mask, differing at the bottom of the high run", left: xnetip.MustParseIPv6Network("::/ffff:ffff::ffff"), right: xnetip.MustParseIPv6Network("0:1::/ffff:ffff::ffff"), want: true},
		{name: "two-run mask, differing in the lowest masked bit", left: xnetip.MustParseIPv6Network("::/ffff:ffff::ffff"), right: xnetip.MustParseIPv6Network("::1/ffff:ffff::ffff"), want: true},
		{name: "pattern mask, two differing bits", left: xnetip.MustParseIPv6Network("2001::1/ffff:ff00::ffff"), right: xnetip.MustParseIPv6Network("2001:300::1/ffff:ff00::ffff"), want: false},
		{name: "pattern mask, one differing bit", left: xnetip.MustParseIPv6Network("2001::1/ffff:ff00::ffff"), right: xnetip.MustParseIPv6Network("2001:100::1/ffff:ff00::ffff"), want: true},
		{name: "straddling hole, differing bit inside the low run", left: xnetip.MustParseIPv6Network("2001:db8::/ffff:ffff:ffff:0:0:ffff::"), right: xnetip.MustParseIPv6Network("2001:db8::1:0:0/ffff:ffff:ffff:0:0:ffff::"), want: true},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			require.Equal(t, testCase.want, testCase.left.IsAdjacent(testCase.right))
		})
	}
}

// verifies that adjacency is symmetric, irreflexive and impossible
// across different masks.
func Test_IPv6Network_IsAdjacent_SymmetryAndMaskProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		left := genIPv6Network.Draw(t, "left")
		right := genIPv6Network.Draw(t, "right")
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
// image under a single masked-bit flip, the flips at bits 63 and 64
// included whenever the mask offers them.
func Test_IPv6Network_IsAdjacent_ConstructedSiblingProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		network := genIPv6Network.Draw(t, "network")
		maskBytes := network.Mask().As16()
		maskHi := binary.BigEndian.Uint64(maskBytes[:8])
		maskLo := binary.BigEndian.Uint64(maskBytes[8:])
		if maskHi|maskLo == 0 {
			return
		}
		setBits := []int{}
		for bit := range 64 {
			if maskLo&(1<<bit) != 0 {
				setBits = append(setBits, bit)
			}
			if maskHi&(1<<bit) != 0 {
				setBits = append(setBits, bit+64)
			}
		}
		bit := rapid.SampledFrom(setBits).Draw(t, "bit")
		addrBytes := network.Addr().As16()
		addrHi := binary.BigEndian.Uint64(addrBytes[:8])
		addrLo := binary.BigEndian.Uint64(addrBytes[8:])
		if bit < 64 {
			addrLo ^= uint64(1) << bit
		} else {
			addrHi ^= uint64(1) << (bit - 64)
		}
		sibling, err := xnetip.IPv6NetworkFrom(
			netipAddrFrom6Bits(addrHi, addrLo),
			netipAddrFrom6Bits(maskHi, maskLo),
		)
		require.NoError(t, err)
		require.True(t, network.IsAdjacent(sibling))
		require.True(t, sibling.IsAdjacent(network))
	})
}

// verifies that the predicate allocates nothing.
func Test_IPv6Network_IsAdjacent_AllocationFree(t *testing.T) {
	left := xnetip.MustParseIPv6Network("2001::1/ffff:ff00::ffff")
	right := xnetip.MustParseIPv6Network("2001:100::1/ffff:ff00::ffff")
	requireNoAllocs(t, func() { okSink = left.IsAdjacent(right) })
}

func BenchmarkIPv6Network_IsAdjacent_Contiguous(b *testing.B) {
	left := xnetip.MustParseIPv6Network("2001:db8::/48")
	right := xnetip.MustParseIPv6Network("2001:db8:1::/48")
	b.ReportAllocs()
	for b.Loop() {
		okSink = left.IsAdjacent(right)
	}
}

func BenchmarkIPv6Network_IsAdjacent_NonContiguous(b *testing.B) {
	left := xnetip.MustParseIPv6Network("2001::1/ffff:ff00::ffff")
	right := xnetip.MustParseIPv6Network("2001:100::1/ffff:ff00::ffff")
	b.ReportAllocs()
	for b.Loop() {
		okSink = left.IsAdjacent(right)
	}
}

func BenchmarkIPv6Network_IsAdjacent_NonAdjacent(b *testing.B) {
	left := xnetip.MustParseIPv6Network("2001:db8::/48")
	right := xnetip.MustParseIPv6Network("2001:db8:5::/48")
	b.ReportAllocs()
	for b.Loop() {
		okSink = left.IsAdjacent(right)
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
	_, err = netip.ParsePrefix("fe80::1%eth0/64")
	require.Error(t, err)
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
			back, err := xnetip.ParseIPv6Network(network.String())
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

// verifies that the marshaled text is the string form: prefix length
// or colon-form mask by contiguity, suffix always present.
func Test_IPv6Network_MarshalText_MatchesStringForm(t *testing.T) {
	cases := []struct {
		name  string
		input string
		want  string
	}{
		{name: "contiguous prefix form", input: "2001:db8::/32", want: "2001:db8::/32"},
		{name: "host route keeps the suffix", input: "::1/128", want: "::1/128"},
		{name: "universe", input: "::/0", want: "::/0"},
		{name: "all ones", input: "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/128", want: "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/128"},
		{name: "mapped address stays IPv6", input: "::ffff:1.2.3.4/120", want: "::ffff:1.2.3.0/120"},
		{name: "non-contiguous colon form", input: "2a02:6b8:c00::1234:0:0/ffff:ffff:ff00::ffff:ffff:0:0", want: "2a02:6b8:c00::1234:0:0/ffff:ffff:ff00:0:ffff:ffff::"},
		{name: "hole straddling bit 64", input: "2001:db8::/ffff:ffff:ffff:ff00:ff:ffff::", want: "2001:db8::/ffff:ffff:ffff:ff00:ff:ffff::"},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			text, err := xnetip.MustParseIPv6Network(testCase.input).MarshalText()
			require.NoError(t, err)
			require.Equal(t, testCase.want, string(text))
		})
	}
}

// verifies that unmarshaling accepts every parser form, normalizes the
// address under the mask and lands the value in the receiver.
func Test_IPv6Network_UnmarshalText_AcceptsParserForms(t *testing.T) {
	cases := []struct {
		name  string
		input string
		want  string
	}{
		{name: "prefix form", input: "2a02:6b8:c00::/40", want: "2a02:6b8:c00::/40"},
		{name: "host bits normalized", input: "2001:db8::1/32", want: "2001:db8::/32"},
		{name: "bare address", input: "2a02:6b8::2:242", want: "2a02:6b8::2:242/128"},
		{name: "colon non-contiguous mask", input: "2001:db8::1/ffff:ffff::ffff", want: "2001:db8::1/ffff:ffff::ffff"},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			var network xnetip.IPv6Network
			require.NoError(t, network.UnmarshalText([]byte(testCase.input)))
			require.Equal(t, xnetip.MustParseIPv6Network(testCase.want), network)
		})
	}
}

// verifies that empty text is an error, because the zero value is the
// valid universe network and must not appear out of a missing field.
func Test_IPv6Network_UnmarshalText_EmptyTextIsError(t *testing.T) {
	network := xnetip.MustParseIPv6Network("2001:db8::/32")
	err := network.UnmarshalText(nil)
	require.ErrorIs(t, err, xnetip.ErrEmptyInput)
	require.Equal(t, xnetip.MustParseIPv6Network("2001:db8::/32"), network)
}

// verifies that a failed unmarshal reports the parser's sentinel and
// leaves the receiver untouched.
func Test_IPv6Network_UnmarshalText_KeepsReceiverOnError(t *testing.T) {
	cases := []struct {
		name     string
		input    string
		sentinel error
	}{
		{name: "zone", input: "fe80::1%eth0/64", sentinel: xnetip.ErrZone},
		{name: "IPv4 text", input: "10.0.0.0/8", sentinel: xnetip.ErrAddrFamilyMismatch},
		{name: "prefix overflow", input: "2001:db8::/129", sentinel: xnetip.ErrCIDROverflow},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			network := xnetip.MustParseIPv6Network("2a02:6b8:c00::/40")
			err := network.UnmarshalText([]byte(testCase.input))
			require.ErrorIs(t, err, testCase.sentinel)
			require.Equal(t, xnetip.MustParseIPv6Network("2a02:6b8:c00::/40"), network)
		})
	}
}

// verifies that a struct field round-trips through JSON as its text
// form, non-contiguous masks included.
func Test_IPv6Network_MarshalText_JSONStructRoundTrip(t *testing.T) {
	type wrapper struct {
		N xnetip.IPv6Network
	}
	cases := []struct {
		name     string
		network  string
		wantJSON string
	}{
		{name: "contiguous", network: "2001:db8::/32", wantJSON: `{"N":"2001:db8::/32"}`},
		{name: "non-contiguous", network: "2001:db8::/ffff:ffff::ffff:ffff:0:0", wantJSON: `{"N":"2001:db8::/ffff:ffff::ffff:ffff:0:0"}`},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			value := wrapper{N: xnetip.MustParseIPv6Network(testCase.network)}
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
func Test_IPv6Network_MarshalText_JSONMapKeyRoundTrip(t *testing.T) {
	value := map[xnetip.IPv6Network]int{xnetip.MustParseIPv6Network("2001:db8::/32"): 1}
	encoded, err := json.Marshal(value)
	require.NoError(t, err)
	require.Equal(t, `{"2001:db8::/32":1}`, string(encoded))
	var decoded map[xnetip.IPv6Network]int
	require.NoError(t, json.Unmarshal(encoded, &decoded))
	require.Equal(t, value, decoded)
}

// verifies that unmarshaling the marshaled text recovers the network
// exactly and that the text is byte-identical to the string form.
func Test_IPv6Network_MarshalText_RoundTripProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		network := genIPv6Network.Draw(t, "network")
		text, err := network.MarshalText()
		require.NoError(t, err)
		require.Equal(t, []byte(network.String()), text)
		var back xnetip.IPv6Network
		require.NoError(t, back.UnmarshalText(text))
		require.Equal(t, network, back)
	})
}

// verifies that a JSON struct round trip preserves the network for
// every mask shape.
func Test_IPv6Network_MarshalText_JSONRoundTripProperty(t *testing.T) {
	type wrapper struct {
		N xnetip.IPv6Network
	}
	rapid.Check(t, func(t *rapid.T) {
		value := wrapper{N: genIPv6Network.Draw(t, "network")}
		encoded, err := json.Marshal(value)
		require.NoError(t, err)
		var decoded wrapper
		require.NoError(t, json.Unmarshal(encoded, &decoded))
		require.Equal(t, value, decoded)
	})
}

// verifies that on contiguous networks the marshaled text is
// byte-identical to the netip prefix marshaling of the same network.
func Test_IPv6Network_MarshalText_MatchesNetipPrefixProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		network := genIPv6Network.Draw(t, "network")
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
// network here is the whole IPv6 universe.
func Test_IPv6Network_UnmarshalText_EmptyTextDivergesFromNetip(t *testing.T) {
	var stdPrefix netip.Prefix
	require.NoError(t, stdPrefix.UnmarshalText(nil))
	var network xnetip.IPv6Network
	require.Error(t, network.UnmarshalText(nil))
}

// verifies that marshaling allocates exactly the returned slice,
// whatever the mask's shape.
func Test_IPv6Network_MarshalText_SingleAllocation(t *testing.T) {
	contiguous := xnetip.MustParseIPv6Network("2001:db8::/32")
	nonContiguous := xnetip.MustParseIPv6Network("2001:db8::/ffff:ffff::ffff:ffff:0:0")
	require.Equal(t, 1, int(testing.AllocsPerRun(100, func() { bytesSink, errSink = contiguous.MarshalText() })))
	require.Equal(t, 1, int(testing.AllocsPerRun(100, func() { bytesSink, errSink = nonContiguous.MarshalText() })))
}

// verifies that a valid IPv6 netip.Prefix converts into the network
// with the same address set, host bits cleared.
func Test_IPv6NetworkFromPrefix_ConvertsValidPrefixes(t *testing.T) {
	cases := []struct {
		name   string
		prefix netip.Prefix
		want   xnetip.IPv6Network
	}{
		{
			name:   "already masked /32",
			prefix: netip.MustParsePrefix("2001:db8::/32"),
			want:   xnetip.MustParseIPv6Network("2001:db8::/32"),
		},
		{
			name:   "host bits cleared",
			prefix: netip.MustParsePrefix("2001:db8::1/32"),
			want:   xnetip.MustParseIPv6Network("2001:db8::/32"),
		},
		{
			name:   "/0 is the zero value",
			prefix: netip.MustParsePrefix("::/0"),
			want:   xnetip.IPv6Network{},
		},
		{
			name:   "host route /128",
			prefix: netip.MustParsePrefix("::1/128"),
			want:   xnetip.MustParseIPv6Network("::1/128"),
		},
		{
			name:   "/64 run ends at the half boundary",
			prefix: netip.MustParsePrefix("2001:db8:1:2::/64"),
			want:   mustIPv6Network(t, "2001:db8:1:2::", "ffff:ffff:ffff:ffff::"),
		},
		{
			name:   "unmasked PrefixFrom input",
			prefix: netip.PrefixFrom(netip.MustParseAddr("2001:db8::ff"), 120),
			want:   xnetip.MustParseIPv6Network("2001:db8::/120"),
		},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			network, ok := xnetip.IPv6NetworkFromPrefix(testCase.prefix)
			require.True(t, ok)
			require.Equal(t, testCase.want, network)
		})
	}
}

// verifies that an IPv4-mapped prefix is IPv6 here and converts into
// the mapped network, the netip family rule.
func Test_IPv6NetworkFromPrefix_AcceptsIPv4MappedPrefix(t *testing.T) {
	network, ok := xnetip.IPv6NetworkFromPrefix(netip.MustParsePrefix("::ffff:10.0.0.0/104"))
	require.True(t, ok)
	require.Equal(t, xnetip.MustParseIPv6Network("::ffff:10.0.0.0/104"), network)
	require.True(t, network.IsIPv4MappedIPv6())
}

// verifies that the invalid zero prefix and a prefix whose address is
// Is4 are rejected.
func Test_IPv6NetworkFromPrefix_RejectsInvalidAndForeignFamily(t *testing.T) {
	cases := []struct {
		name   string
		prefix netip.Prefix
	}{
		{name: "invalid zero prefix", prefix: netip.Prefix{}},
		{name: "IPv4 prefix", prefix: netip.MustParsePrefix("10.0.0.0/8")},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			network, ok := xnetip.IPv6NetworkFromPrefix(testCase.prefix)
			require.False(t, ok)
			require.Equal(t, xnetip.IPv6Network{}, network)
		})
	}
}

// verifies that a contiguous network converts to the already-masked
// netip.Prefix carrying the same address set.
func Test_IPv6Network_Prefix_ContiguousForms(t *testing.T) {
	cases := []struct {
		name    string
		network xnetip.IPv6Network
		want    netip.Prefix
	}{
		{
			name:    "/40",
			network: xnetip.MustParseIPv6Network("2a02:6b8:c00::/40"),
			want:    netip.MustParsePrefix("2a02:6b8:c00::/40"),
		},
		{
			name:    "universe /0",
			network: xnetip.MustParseIPv6Network("::/0"),
			want:    netip.MustParsePrefix("::/0"),
		},
		{
			name:    "host route /128 is a single IP",
			network: xnetip.MustParseIPv6Network("::1/128"),
			want:    netip.MustParsePrefix("::1/128"),
		},
		{
			name:    "IPv4-mapped network stays IPv6",
			network: xnetip.MustParseIPv6Network("::ffff:10.0.0.0/104"),
			want:    netip.MustParsePrefix("::ffff:10.0.0.0/104"),
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
	singleIP, ok := xnetip.MustParseIPv6Network("::1/128").Prefix()
	require.True(t, ok)
	require.True(t, singleIP.IsSingleIP())
}

// verifies that a non-contiguous mask has no prefix form and answers
// the invalid zero netip.Prefix, the hole straddling bit 64 included.
func Test_IPv6Network_Prefix_NonContiguousHasNone(t *testing.T) {
	cases := []struct {
		name    string
		network xnetip.IPv6Network
	}{
		{name: "two runs", network: xnetip.MustParseIPv6Network("2001:db8::/ffff:ffff:ff00::ffff:ffff:0:0")},
		{name: "hole straddling bit 64", network: xnetip.MustParseIPv6Network("2001:db8::/ffff:ffff:ffff:ff00:ff:ffff::")},
		{name: "alternating", network: xnetip.MustParseIPv6Network("::/ffff:0:ffff:0:ffff:0:ffff:0")},
		{name: "single low bit", network: xnetip.MustParseIPv6Network("::/::1")},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			prefix, ok := testCase.network.Prefix()
			require.False(t, ok)
			require.Equal(t, netip.Prefix{}, prefix)
		})
	}
}

// verifies that any valid IPv6 prefix converts and converts back to
// its masked self, with the result normalized and contiguous.
func Test_IPv6NetworkFromPrefix_RoundTripProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		stdPrefix := genIPv6Prefix.Draw(t, "prefix")
		network, ok := xnetip.IPv6NetworkFromPrefix(stdPrefix)
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
func Test_IPv6Network_Prefix_SomeIffContiguousProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		network := genIPv6Network.Draw(t, "network")
		prefix, ok := network.Prefix()
		require.Equal(t, network.IsContiguous(), ok)
		if !ok {
			require.Equal(t, netip.Prefix{}, prefix)
		}
	})
}

// verifies that a contiguous network survives the round trip through
// netip.Prefix unchanged.
func Test_IPv6Network_Prefix_RoundTripProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		network := genIPv6Network.Draw(t, "network")
		stdPrefix, ok := network.Prefix()
		if !ok {
			return
		}
		back, ok := xnetip.IPv6NetworkFromPrefix(stdPrefix)
		require.True(t, ok)
		require.Equal(t, network, back)
	})
}

// verifies that the converted prefix length agrees with the network's
// own prefix length, the net/netip view of the same mask.
func Test_IPv6Network_Prefix_BitsMatchPrefixLenProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		network := genIPv6Network.Draw(t, "network")
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
func Test_IPv6NetworkFromPrefix_AllocationFree(t *testing.T) {
	valid := netip.MustParsePrefix("2001:db8::/32")
	foreign := netip.MustParsePrefix("10.0.0.0/8")
	requireNoAllocs(t, func() { network6Sink, okSink = xnetip.IPv6NetworkFromPrefix(valid) })
	requireNoAllocs(t, func() { network6Sink, okSink = xnetip.IPv6NetworkFromPrefix(foreign) })
}

// verifies that converting out to a netip.Prefix allocates nothing,
// whatever the mask's shape.
func Test_IPv6Network_Prefix_AllocationFree(t *testing.T) {
	contiguous := xnetip.MustParseIPv6Network("2a02:6b8:c00::/40")
	nonContiguous := xnetip.MustParseIPv6Network("2001:db8::/ffff:ffff:ff00::ffff:ffff:0:0")
	requireNoAllocs(t, func() { prefixSink, okSink = contiguous.Prefix() })
	requireNoAllocs(t, func() { prefixSink, okSink = nonContiguous.Prefix() })
}

// verifies that the greatest member of a contiguous network is the
// last address of its CIDR block, half-boundary lengths included.
func Test_IPv6Network_LastAddr_ContiguousBlockEnd(t *testing.T) {
	cases := []struct {
		name    string
		network xnetip.IPv6Network
		want    netip.Addr
	}{
		{name: "/96 fills the low 32 bits", network: xnetip.MustParseIPv6Network("2001:db8:1::/96"), want: netip.MustParseAddr("2001:db8:1::ffff:ffff")},
		{name: "/40 fills across a group", network: xnetip.MustParseIPv6Network("2a02:6b8:c00::/40"), want: netip.MustParseAddr("2a02:6b8:cff:ffff:ffff:ffff:ffff:ffff")},
		{name: "/32 fills six groups", network: xnetip.MustParseIPv6Network("2a02:6b8::/32"), want: netip.MustParseAddr("2a02:6b8:ffff:ffff:ffff:ffff:ffff:ffff")},
		{name: "host route is its own last address", network: xnetip.MustParseIPv6Network("2001:db8::1/128"), want: netip.MustParseAddr("2001:db8::1")},
		{name: "default route ends at all ones", network: xnetip.MustParseIPv6Network("::/0"), want: netip.MustParseAddr("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff")},
		{name: "/64 fills exactly the low half", network: xnetip.MustParseIPv6Network("2a02:6b8::/64"), want: netip.MustParseAddr("2a02:6b8::ffff:ffff:ffff:ffff")},
		{name: "/63 crosses the half boundary", network: xnetip.MustParseIPv6Network("2001:db8::/63"), want: netip.MustParseAddr("2001:db8:0:1:ffff:ffff:ffff:ffff")},
		{name: "/65 starts below the half boundary", network: xnetip.MustParseIPv6Network("2001:db8::/65"), want: netip.MustParseAddr("2001:db8:0:0:7fff:ffff:ffff:ffff")},
		{name: "zero value is the default route", network: xnetip.IPv6Network{}, want: netip.MustParseAddr("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff")},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			require.Equal(t, testCase.want, testCase.network.LastAddr())
		})
	}
}

// verifies that a non-contiguous mask sets every host bit wherever the
// mask leaves a hole, in either half and at the half boundary.
func Test_IPv6Network_LastAddr_NonContiguousMasks(t *testing.T) {
	cases := []struct {
		name    string
		network xnetip.IPv6Network
		want    netip.Addr
	}{
		{name: "two-run mask fills both holes", network: mustIPv6Network(t, "2a02:6b8:c00::1234:0:0", "ffff:ffff:ff00::ffff:ffff:0:0"), want: netip.MustParseAddr("2a02:6b8:cff:ffff:0:1234:ffff:ffff")},
		{name: "alternating mask fills the odd bits", network: mustIPv6Network(t, "::", "aaaa:aaaa:aaaa:aaaa:aaaa:aaaa:aaaa:aaaa"), want: netip.MustParseAddr("5555:5555:5555:5555:5555:5555:5555:5555")},
		{name: "single host bit at the half boundary", network: mustIPv6Network(t, "2001:db8::", "ffff:ffff:ffff:fffe:ffff:ffff:ffff:ffff"), want: netip.MustParseAddr("2001:db8:0:1::")},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			require.Equal(t, testCase.want, testCase.network.LastAddr())
		})
	}
}

// verifies that the result is a member of the network: masking it
// yields the network address again.
func Test_IPv6Network_LastAddr_MemberProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		network := genIPv6Network.Draw(t, "network")
		lastBytes := network.LastAddr().As16()
		maskBytes := network.Mask().As16()
		lastHi := binary.BigEndian.Uint64(lastBytes[:8])
		lastLo := binary.BigEndian.Uint64(lastBytes[8:])
		maskHi := binary.BigEndian.Uint64(maskBytes[:8])
		maskLo := binary.BigEndian.Uint64(maskBytes[8:])
		require.Equal(t, network.Addr(), netipAddrFrom6Bits(lastHi&maskHi, lastLo&maskLo))
	})
}

// verifies by brute force on small networks that no member exceeds
// the last address and that the last address itself is enumerated.
//
// The mask is built by clearing at most 12 chosen positions, drawn
// with extra weight around bit 64 so the patterns straddle the half
// boundary, and every host pattern is deposited into those positions
// to enumerate the whole membership.
func Test_IPv6Network_LastAddr_MaximalByBruteForceProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		hostBits := rapid.IntRange(0, 12).Draw(t, "host bits")
		positionGen := rapid.OneOf(rapid.IntRange(0, 127), rapid.IntRange(58, 70))
		positions := rapid.SliceOfNDistinct(positionGen, hostBits, hostBits, rapid.ID).Draw(t, "host positions")
		maskHi, maskLo := ^uint64(0), ^uint64(0)
		for _, position := range positions {
			if position < 64 {
				maskLo &^= uint64(1) << position
			} else {
				maskHi &^= uint64(1) << (position - 64)
			}
		}
		network, err := xnetip.IPv6NetworkFrom(
			genNetipAddr6.Draw(t, "addr"),
			netipAddrFrom6Bits(maskHi, maskLo),
		)
		require.NoError(t, err)
		addrBytes := network.Addr().As16()
		baseHi := binary.BigEndian.Uint64(addrBytes[:8])
		baseLo := binary.BigEndian.Uint64(addrBytes[8:])
		last := network.LastAddr()
		reached := false
		for pattern := range 1 << hostBits {
			memberHi, memberLo := baseHi, baseLo
			for idx, position := range positions {
				if pattern>>idx&1 == 0 {
					continue
				}
				if position < 64 {
					memberLo |= uint64(1) << position
				} else {
					memberHi |= uint64(1) << (position - 64)
				}
			}
			member := netipAddrFrom6Bits(memberHi, memberLo)
			require.LessOrEqual(t, member.Compare(last), 0)
			if member == last {
				reached = true
			}
		}
		require.True(t, reached, "last address never enumerated")
	})
}

// verifies that the last address never sorts below the network address
// and coincides with it exactly on a host route.
func Test_IPv6Network_LastAddr_AtLeastAddrProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		network := genIPv6Network.Draw(t, "network")
		require.GreaterOrEqual(t, network.LastAddr().Compare(network.Addr()), 0)
		fullMask := network.Mask() == netipAddrFrom6Bits(^uint64(0), ^uint64(0))
		require.Equal(t, fullMask, network.LastAddr() == network.Addr())
	})
}

// verifies that the last address is computed without allocating,
// whatever the mask's shape.
func Test_IPv6Network_LastAddr_AllocationFree(t *testing.T) {
	contiguous := xnetip.MustParseIPv6Network("2001:db8:1::/64")
	nonContiguous := xnetip.MustParseIPv6Network("2a02:6b8:c00::1234:0:0/ffff:ffff:ff00::ffff:ffff:0:0")
	requireNoAllocs(t, func() { addrSink = contiguous.LastAddr() })
	requireNoAllocs(t, func() { addrSink = nonContiguous.LastAddr() })
}

// verifies that masks made of one leading run per 64-bit half are
// bi-contiguous, the fully contiguous and boundary shapes included.
func Test_IPv6Network_IsBicontiguous_PerHalfLeadingRuns(t *testing.T) {
	cases := []struct {
		name    string
		network xnetip.IPv6Network
		want    bool
	}{
		{name: "/40 by /32 classifier mask", network: xnetip.MustParseIPv6Network("2a02:6b8:c00::1234:abcd:0:0/ffff:ffff:ff00::ffff:ffff:0:0"), want: true},
		{name: "/40 by /16 classifier mask", network: xnetip.MustParseIPv6Network("2a02:6b8:c00::1234:0:0:0/ffff:ffff:ff00::ffff:0:0:0"), want: true},
		{name: "zero mask", network: xnetip.MustParseIPv6Network("::/::"), want: true},
		{name: "all-ones mask of a host route", network: xnetip.MustParseIPv6Network("::1"), want: true},
		{name: "lone bit at the top of the low half", network: mustIPv6Network(t, "::", "::8000:0:0:0"), want: true},
		{name: "contiguous /40", network: xnetip.MustParseIPv6Network("2a02:6b8:c00::/40"), want: true},
		{name: "contiguous /64", network: xnetip.MustParseIPv6Network("2001:db8::/64"), want: true},
		{name: "contiguous /65", network: xnetip.MustParseIPv6Network("2001:db8::/65"), want: true},
		{name: "lone bit at the very bottom", network: mustIPv6Network(t, "::", "::1"), want: false},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			require.Equal(t, testCase.want, testCase.network.IsBicontiguous())
		})
	}
}

// verifies that a run ending inside a half breaks bi-contiguity while
// a mask living entirely in the low half keeps it.
func Test_IPv6Network_IsBicontiguous_NonContiguousMasks(t *testing.T) {
	cases := []struct {
		name    string
		network xnetip.IPv6Network
		want    bool
	}{
		{name: "hole inside the low half", network: xnetip.MustParseIPv6Network("2a02:6b8:0:0:1234:5678::/ffff:ffff:0:0:f0f0:f0f0:f0f0:f0f0"), want: false},
		{name: "hole inside the high half", network: mustIPv6Network(t, "::", "f0f0:f0f0:f0f0:f0f0::"), want: false},
		{name: "low run below the top of the low half", network: mustIPv6Network(t, "::", "ffff:ffff:ffff:ffff:0:ffff::"), want: false},
		{name: "alternating mask", network: mustIPv6Network(t, "::", "aaaa:aaaa:aaaa:aaaa:aaaa:aaaa:aaaa:aaaa"), want: false},
		{name: "low run in the middle under a full high half", network: mustIPv6Network(t, "::", "ffff:ffff:ffff:ffff:00ff:ff00::"), want: false},
		{name: "empty high half with a full low half", network: mustIPv6Network(t, "::", "::ffff:ffff:ffff:ffff"), want: true},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			require.Equal(t, testCase.want, testCase.network.IsBicontiguous())
		})
	}
}

// referenceIsBicontiguous is the independent per-half oracle for the
// run-top formula.
//
// Each 64-bit half must be a run of leading ones on its own, checked
// with the contiguity trick applied separately per half.
func referenceIsBicontiguous(maskHi, maskLo uint64) bool {
	isContiguous64 := func(mask uint64) bool { return mask|(mask-1) == ^uint64(0) }
	return isContiguous64(maskHi) && isContiguous64(maskLo)
}

// verifies that the predicate agrees with the per-half oracle on
// every mask shape the network generator draws.
func Test_IPv6Network_IsBicontiguous_MatchesReferenceProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		network := genIPv6Network.Draw(t, "network")
		maskBytes := network.Mask().As16()
		maskHi := binary.BigEndian.Uint64(maskBytes[:8])
		maskLo := binary.BigEndian.Uint64(maskBytes[8:])
		require.Equal(t, referenceIsBicontiguous(maskHi, maskLo), network.IsBicontiguous())
	})
}

// verifies constructively that every product of a high-half prefix
// and a low-half prefix is bi-contiguous, by exhausting all pairs.
func Test_IPv6Network_IsBicontiguous_AcceptsEveryPrefixPair(t *testing.T) {
	for hiPrefix := range 65 {
		for loPrefix := range 65 {
			network, err := xnetip.IPv6NetworkFrom(
				netipAddrFrom6Bits(0x2a0206b80c000000, 0x123400000000abcd),
				netipAddrFrom6Bits(^uint64(0)<<(64-hiPrefix), ^uint64(0)<<(64-loPrefix)),
			)
			require.NoError(t, err)
			require.True(t, network.IsBicontiguous(), "hi %d lo %d", hiPrefix, loPrefix)
		}
	}
}

// verifies that every contiguous mask is bi-contiguous: its low half
// is all ones or all zeros, both single leading runs.
func Test_IPv6Network_IsBicontiguous_ImpliedByContiguousProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		network := genIPv6Network.Draw(t, "network")
		if network.IsContiguous() {
			require.True(t, network.IsBicontiguous())
		}
	})
}

// verifies that every draw of the bi-contiguous generator satisfies
// the predicate, whatever the address.
func Test_IPv6Network_IsBicontiguous_GeneratorDrawsSatisfyProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		network := genIPv6BicontiguousNetwork.Draw(t, "network")
		require.True(t, network.IsBicontiguous())
	})
}

// verifies that the predicate allocates nothing on either outcome.
func Test_IPv6Network_IsBicontiguous_AllocationFree(t *testing.T) {
	bicontiguous := xnetip.MustParseIPv6Network("2a02:6b8:c00::1234:abcd:0:0/ffff:ffff:ff00::ffff:ffff:0:0")
	nonBicontiguous := mustIPv6Network(t, "::", "f0f0:f0f0:f0f0:f0f0::")
	requireNoAllocs(t, func() { okSink = bicontiguous.IsBicontiguous() })
	requireNoAllocs(t, func() { okSink = nonBicontiguous.IsBicontiguous() })
}

func BenchmarkIPv6Network_IsBicontiguous_Bicontiguous(b *testing.B) {
	network := xnetip.MustParseIPv6Network("2a02:1a1:c00::1234:abcd:0:0/ffff:ffff:ff00::ffff:ffff:0:0")
	b.ReportAllocs()
	for b.Loop() {
		okSink = network.IsBicontiguous()
	}
}

func BenchmarkIPv6Network_IsBicontiguous_NonBicontiguous(b *testing.B) {
	network := mustIPv6Network(b, "f0f0:f0f0:f0f0:f0f0::", "f0f0:f0f0:f0f0:f0f0::")
	b.ReportAllocs()
	for b.Loop() {
		okSink = network.IsBicontiguous()
	}
}

// verifies that a contiguous network reports its mask's zero bits,
// the complement of the prefix length, half-boundary lengths included.
func Test_IPv6Network_NumHostBits_ContiguousComplementsPrefix(t *testing.T) {
	cases := []struct {
		name    string
		network xnetip.IPv6Network
		want    int
	}{
		{name: "default route frees the whole word", network: xnetip.MustParseIPv6Network("::/0"), want: 128},
		{name: "/32", network: xnetip.MustParseIPv6Network("2001:db8::/32"), want: 96},
		{name: "/64 frees exactly the low half", network: xnetip.MustParseIPv6Network("2001:db8::/64"), want: 64},
		{name: "/63 crosses the half boundary", network: xnetip.MustParseIPv6Network("2001:db8::/63"), want: 65},
		{name: "/65 starts below the half boundary", network: xnetip.MustParseIPv6Network("2001:db8::/65"), want: 63},
		{name: "/127", network: xnetip.MustParseIPv6Network("2001:db8::/127"), want: 1},
		{name: "host route holds one address", network: xnetip.MustParseIPv6Network("2001:db8::1/128"), want: 0},
		{name: "zero value is the default route", network: xnetip.IPv6Network{}, want: 128},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			require.Equal(t, testCase.want, testCase.network.NumHostBits())
		})
	}
}

// verifies that host bits are counted wherever the mask leaves them,
// in either half and across the half boundary.
func Test_IPv6Network_NumHostBits_NonContiguousMasks(t *testing.T) {
	cases := []struct {
		name    string
		network xnetip.IPv6Network
		want    int
	}{
		{name: "two-run classifier mask", network: xnetip.MustParseIPv6Network("2a02:6b8:c00::1234:0:0/ffff:ffff:ff00::ffff:ffff:0:0"), want: 56},
		{name: "hole across the half boundary", network: mustIPv6Network(t, "::", "ffff:ffff:ffff:0:0:ffff:ffff:ffff"), want: 32},
		{name: "alternating mask frees every other bit", network: mustIPv6Network(t, "::", "aaaa:aaaa:aaaa:aaaa:aaaa:aaaa:aaaa:aaaa"), want: 64},
		{name: "single host bit at the half boundary", network: mustIPv6Network(t, "::", "ffff:ffff:ffff:fffe:ffff:ffff:ffff:ffff"), want: 1},
		{name: "mask with one set bit", network: mustIPv6Network(t, "::", "8000::"), want: 127},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			require.Equal(t, testCase.want, testCase.network.NumHostBits())
		})
	}
}

// verifies that the count agrees with a brute bit loop over the mask
// bytes.
func Test_IPv6Network_NumHostBits_MatchesBitLoopProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		network := genIPv6Network.Draw(t, "network")
		maskBytes := network.Mask().As16()
		want := 0
		for _, maskByte := range maskBytes {
			for idx := range 8 {
				if maskByte>>idx&1 == 0 {
					want++
				}
			}
		}
		require.Equal(t, want, network.NumHostBits())
	})
}

// verifies that a contiguous network's host-bit count complements its
// prefix length to the word width.
func Test_IPv6Network_NumHostBits_ComplementsPrefixLenProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		network := genIPv6Network.Draw(t, "network")
		prefix, ok := network.PrefixLen()
		if !ok {
			return
		}
		require.Equal(t, 128-prefix, network.NumHostBits())
	})
}

// verifies that the count is zero exactly on the all-ones mask and
// the full width exactly on the zero mask.
func Test_IPv6Network_NumHostBits_ExtremesMatchMaskProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		network := genIPv6Network.Draw(t, "network")
		require.Equal(t, network.Mask() == netipAddrFrom6Bits(^uint64(0), ^uint64(0)), network.NumHostBits() == 0)
		require.Equal(t, network.Mask() == netipAddrFrom6Bits(0, 0), network.NumHostBits() == 128)
	})
}

// verifies that the count is computed without allocating, whatever
// the mask's shape.
func Test_IPv6Network_NumHostBits_AllocationFree(t *testing.T) {
	contiguous := xnetip.MustParseIPv6Network("2001:db8::/64")
	nonContiguous := xnetip.MustParseIPv6Network("2a02:6b8:c00::1234:0:0/ffff:ffff:ff00::ffff:ffff:0:0")
	requireNoAllocs(t, func() { intSink = contiguous.NumHostBits() })
	requireNoAllocs(t, func() { intSink = nonContiguous.NumHostBits() })
}

// ipv6NetworkBits returns the network's address and mask as host-order
// 64-bit halves, the form the bit-level oracles compute in.
func ipv6NetworkBits(network xnetip.IPv6Network) (addrHi, addrLo, maskHi, maskLo uint64) {
	addrBytes := network.Addr().As16()
	maskBytes := network.Mask().As16()
	addrHi = binary.BigEndian.Uint64(addrBytes[:8])
	addrLo = binary.BigEndian.Uint64(addrBytes[8:])
	maskHi = binary.BigEndian.Uint64(maskBytes[:8])
	maskLo = binary.BigEndian.Uint64(maskBytes[8:])
	return addrHi, addrLo, maskHi, maskLo
}

// mergeReferenceIPv6 is the simple merge oracle.
//
// Equal networks merge to themselves, equal-mask single-bit siblings
// drop the differing bit through the adjacency predicate, and
// containment either way returns the container.
func mergeReferenceIPv6(t require.TestingT, left, right xnetip.IPv6Network) (xnetip.IPv6Network, bool) {
	if left == right {
		return left, true
	}
	if left.Mask() == right.Mask() {
		if !left.IsAdjacent(right) {
			return xnetip.IPv6Network{}, false
		}
		leftAddrHi, leftAddrLo, leftMaskHi, leftMaskLo := ipv6NetworkBits(left)
		rightAddrHi, rightAddrLo, _, _ := ipv6NetworkBits(right)
		maskHi := leftMaskHi ^ (leftAddrHi ^ rightAddrHi)
		maskLo := leftMaskLo ^ (leftAddrLo ^ rightAddrLo)
		merged, err := xnetip.IPv6NetworkFrom(
			netipAddrFrom6Bits(leftAddrHi&maskHi, leftAddrLo&maskLo),
			netipAddrFrom6Bits(maskHi, maskLo),
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
	return xnetip.IPv6Network{}, false
}

// verifies that merging succeeds exactly for duplicates, single-bit
// siblings and containment, and returns the union network.
//
// The half-boundary rows pin the single-bit test and the xor across
// bit 64, where the difference or the reduced mask crosses the
// 64-bit halves of the word.
func Test_IPv6Network_Merge_UnitAndBoundary(t *testing.T) {
	cases := []struct {
		name  string
		left  xnetip.IPv6Network
		right xnetip.IPv6Network
		want  xnetip.IPv6Network
		ok    bool
	}{
		{name: "identical", left: xnetip.MustParseIPv6Network("2001:db8::/48"), right: xnetip.MustParseIPv6Network("2001:db8::/48"), want: xnetip.MustParseIPv6Network("2001:db8::/48"), ok: true},
		{name: "contiguous siblings", left: xnetip.MustParseIPv6Network("2001:db8::/48"), right: xnetip.MustParseIPv6Network("2001:db8:1::/48"), want: xnetip.MustParseIPv6Network("2001:db8::/47"), ok: true},
		{name: "contiguous siblings reversed", left: xnetip.MustParseIPv6Network("2001:db8:1::/48"), right: xnetip.MustParseIPv6Network("2001:db8::/48"), want: xnetip.MustParseIPv6Network("2001:db8::/47"), ok: true},
		{name: "containment returns the container", left: xnetip.MustParseIPv6Network("2001:db8::/32"), right: xnetip.MustParseIPv6Network("2001:db8:1::/48"), want: xnetip.MustParseIPv6Network("2001:db8::/32"), ok: true},
		{name: "containment reversed", left: xnetip.MustParseIPv6Network("2001:db8:1::/48"), right: xnetip.MustParseIPv6Network("2001:db8::/32"), want: xnetip.MustParseIPv6Network("2001:db8::/32"), ok: true},
		{name: "same mask, two differing bits", left: xnetip.MustParseIPv6Network("2001:db8::/48"), right: xnetip.MustParseIPv6Network("2001:db8:5::/48"), ok: false},
		{name: "comparable masks, address mismatch", left: xnetip.MustParseIPv6Network("2001:db8::/32"), right: xnetip.MustParseIPv6Network("2001:beef:1::/48"), ok: false},
		{name: "comparable masks, address mismatch reversed", left: xnetip.MustParseIPv6Network("2001:beef:1::/48"), right: xnetip.MustParseIPv6Network("2001:db8::/32"), ok: false},
		{name: "/64 siblings at bit 64", left: xnetip.MustParseIPv6Network("2001:db8:0:0::/64"), right: xnetip.MustParseIPv6Network("2001:db8:0:1::/64"), want: xnetip.MustParseIPv6Network("2001:db8::/63"), ok: true},
		{name: "/65 siblings at bit 63", left: xnetip.MustParseIPv6Network("2001:db8::/65"), right: xnetip.MustParseIPv6Network("2001:db8:0:0:8000::/65"), want: xnetip.MustParseIPv6Network("2001:db8::/64"), ok: true},
		{name: "/65 siblings at bit 64 give a non-contiguous mask", left: xnetip.MustParseIPv6Network("2001:db8::/65"), right: xnetip.MustParseIPv6Network("2001:db8:0:1::/65"), want: xnetip.MustParseIPv6Network("2001:db8::/ffff:ffff:ffff:fffe:8000::"), ok: true},
		{name: "host routes differing in bit 0", left: xnetip.MustParseIPv6Network("2001:db8::/128"), right: xnetip.MustParseIPv6Network("2001:db8::1/128"), want: xnetip.MustParseIPv6Network("2001:db8::/127"), ok: true},
		{name: "default route absorbs any network", left: xnetip.MustParseIPv6Network("::/0"), right: xnetip.MustParseIPv6Network("2001:db8::/32"), want: xnetip.MustParseIPv6Network("::/0"), ok: true},
		{name: "top-bit siblings give the default route", left: xnetip.MustParseIPv6Network("::/1"), right: xnetip.MustParseIPv6Network("8000::/1"), want: xnetip.MustParseIPv6Network("::/0"), ok: true},
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
func Test_IPv6Network_Merge_NonContiguousMasks(t *testing.T) {
	cases := []struct {
		name  string
		left  xnetip.IPv6Network
		right xnetip.IPv6Network
		want  xnetip.IPv6Network
		ok    bool
	}{
		{name: "pattern siblings at bit 104", left: xnetip.MustParseIPv6Network("2001::1/ffff:ff00::ffff"), right: xnetip.MustParseIPv6Network("2001:100::1/ffff:ff00::ffff"), want: xnetip.MustParseIPv6Network("2001::1/ffff:fe00::ffff"), ok: true},
		{name: "pattern siblings at bit 104 reversed", left: xnetip.MustParseIPv6Network("2001:100::1/ffff:ff00::ffff"), right: xnetip.MustParseIPv6Network("2001::1/ffff:ff00::ffff"), want: xnetip.MustParseIPv6Network("2001::1/ffff:fe00::ffff"), ok: true},
		{name: "pattern with two differing bits", left: xnetip.MustParseIPv6Network("2001::1/ffff:ff00::ffff"), right: xnetip.MustParseIPv6Network("2001:300::1/ffff:ff00::ffff"), ok: false},
		{name: "two-run siblings in the low run", left: xnetip.MustParseIPv6Network("2a02:6b8:c00::1234:0:0/ffff:ffff:ff00::ffff:ffff:0:0"), right: xnetip.MustParseIPv6Network("2a02:6b8:c00::1235:0:0/ffff:ffff:ff00::ffff:ffff:0:0"), want: xnetip.MustParseIPv6Network("2a02:6b8:c00::1234:0:0/ffff:ffff:ff00::ffff:fffe:0:0"), ok: true},
		{name: "incomparable non-contiguous masks", left: xnetip.MustParseIPv6Network("2001:db8::1/ffff:0:ffff::"), right: xnetip.MustParseIPv6Network("2001:db8::1/0:ffff:ffff::"), ok: false},
		{name: "two-run mask contains a contiguous block", left: xnetip.MustParseIPv6Network("2a02:6b8::5:6:0:0/ffff:ffff::ffff:ffff:0:0"), right: xnetip.MustParseIPv6Network("2a02:6b8:1:2:5:6::/96"), want: xnetip.MustParseIPv6Network("2a02:6b8::5:6:0:0/ffff:ffff::ffff:ffff:0:0"), ok: true},
		{name: "two-run mask contains a contiguous block reversed", left: xnetip.MustParseIPv6Network("2a02:6b8:1:2:5:6::/96"), right: xnetip.MustParseIPv6Network("2a02:6b8::5:6:0:0/ffff:ffff::ffff:ffff:0:0"), want: xnetip.MustParseIPv6Network("2a02:6b8::5:6:0:0/ffff:ffff::ffff:ffff:0:0"), ok: true},
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
func Test_IPv6Network_Merge_ReferenceFixedCases(t *testing.T) {
	cases := [][2]string{
		{"2001:db8::/48", "2001:db8::/48"},
		{"2001:db8::/48", "2001:db8:1::/48"},
		{"2a02:6b8:c00::1234:0:0/ffff:ffff:ff00::ffff:ffff:0:0", "2a02:6b8:c00::1235:0:0/ffff:ffff:ff00::ffff:ffff:0:0"},
		{"2001:db8::/48", "2001:db8:5::/48"},
		{"2001:db8::/32", "2001:db8:1::/48"},
		{"2001:db8:1::/48", "2001:db8::/32"},
		{"2001:db8::/32", "2001:beef:1::/48"},
		{"2001:beef:1::/48", "2001:db8::/32"},
		{"2001:db8::1/ffff:0:ffff::", "2001:db8::1/0:ffff:ffff::"},
	}
	for _, pair := range cases {
		left := xnetip.MustParseIPv6Network(pair[0])
		right := xnetip.MustParseIPv6Network(pair[1])
		wantNetwork, wantOK := mergeReferenceIPv6(t, left, right)
		merged, ok := left.Merge(right)
		require.Equal(t, wantOK, ok, "pair %v", pair)
		require.Equal(t, wantNetwork, merged, "pair %v", pair)
	}
}

// verifies that merging agrees with the simple oracle on random pairs.
func Test_IPv6Network_Merge_MatchesReferenceProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		left := genIPv6Network.Draw(t, "left")
		right := genIPv6Network.Draw(t, "right")
		wantNetwork, wantOK := mergeReferenceIPv6(t, left, right)
		merged, ok := left.Merge(right)
		require.Equal(t, wantOK, ok)
		require.Equal(t, wantNetwork, merged)
	})
}

// verifies that merging is commutative in both the value and the flag.
func Test_IPv6Network_Merge_CommutativityProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		left := genIPv6Network.Draw(t, "left")
		right := genIPv6Network.Draw(t, "right")
		leftMerged, leftOK := left.Merge(right)
		rightMerged, rightOK := right.Merge(left)
		require.Equal(t, leftOK, rightOK)
		require.Equal(t, leftMerged, rightMerged)
	})
}

// verifies that a network merged with itself is itself: aggregation
// leans on this path to absorb duplicates.
func Test_IPv6Network_Merge_SelfIsSelfProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		network := genIPv6Network.Draw(t, "network")
		merged, ok := network.Merge(network)
		require.True(t, ok)
		require.Equal(t, network, merged)
	})
}

// verifies that a successful merge contains both inputs and returns a
// normalized network.
func Test_IPv6Network_Merge_ResultContainsBothAndNormalizedProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		left := genIPv6Network.Draw(t, "left")
		right := genIPv6Network.Draw(t, "right")
		merged, ok := left.Merge(right)
		if !ok {
			return
		}
		require.True(t, merged.Contains(left))
		require.True(t, merged.Contains(right))
		addrHi, addrLo, maskHi, maskLo := ipv6NetworkBits(merged)
		require.Equal(t, addrHi, addrHi&maskHi)
		require.Equal(t, addrLo, addrLo&maskLo)
	})
}

// verifies on an 8-bit model, networks confined to the top octet, that
// a successful merge holds exactly the union of the two address sets.
func Test_IPv6Network_Merge_MembershipBruteForceProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		leftAddr := uint64(rapid.IntRange(0, 255).Draw(t, "left addr")) << 56
		leftMask := uint64(rapid.IntRange(0, 255).Draw(t, "left mask")) << 56
		rightAddr := uint64(rapid.IntRange(0, 255).Draw(t, "right addr")) << 56
		rightMask := uint64(rapid.IntRange(0, 255).Draw(t, "right mask")) << 56
		left, err := xnetip.IPv6NetworkFrom(netipAddrFrom6Bits(leftAddr, 0), netipAddrFrom6Bits(leftMask, 0))
		require.NoError(t, err)
		right, err := xnetip.IPv6NetworkFrom(netipAddrFrom6Bits(rightAddr, 0), netipAddrFrom6Bits(rightMask, 0))
		require.NoError(t, err)
		merged, ok := left.Merge(right)
		mergedAddrHi, _, mergedMaskHi, _ := ipv6NetworkBits(merged)
		for x := range uint64(256) {
			candidate := x << 56
			inLeft := candidate&leftMask == leftAddr&leftMask
			inRight := candidate&rightMask == rightAddr&rightMask
			inMerged := ok && candidate&mergedMaskHi == mergedAddrHi
			require.Equal(t, ok && (inLeft || inRight), inMerged, "member 0x%016x", candidate)
		}
	})
}

// verifies that flipping any single masked bit builds a sibling whose
// merge drops exactly that bit from the mask.
//
// The drawn bit ranges over every set mask bit, so masks straddling
// the halves exercise flips at bits 63 and 64 alongside the ends.
func Test_IPv6Network_Merge_ConstructedSiblingProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		network := genIPv6Network.Draw(t, "network")
		addrHi, addrLo, maskHi, maskLo := ipv6NetworkBits(network)
		if maskHi|maskLo == 0 {
			return
		}
		setBits := []int{}
		for bit := range 128 {
			if bit < 64 && maskLo&(1<<bit) != 0 || bit >= 64 && maskHi&(1<<(bit-64)) != 0 {
				setBits = append(setBits, bit)
			}
		}
		bit := rapid.SampledFrom(setBits).Draw(t, "bit")
		var bitHi, bitLo uint64
		if bit < 64 {
			bitLo = 1 << bit
		} else {
			bitHi = 1 << (bit - 64)
		}
		sibling, err := xnetip.IPv6NetworkFrom(
			netipAddrFrom6Bits(addrHi^bitHi, addrLo^bitLo),
			netipAddrFrom6Bits(maskHi, maskLo),
		)
		require.NoError(t, err)
		merged, ok := network.Merge(sibling)
		require.True(t, ok)
		require.Equal(t, netipAddrFrom6Bits(maskHi&^bitHi, maskLo&^bitLo), merged.Mask())
		require.Equal(t, netipAddrFrom6Bits(addrHi&^bitHi, addrLo&^bitLo), merged.Addr())
	})
}

// verifies that equal masks with neither adjacency nor equality never
// merge: the differing bits are two or more.
func Test_IPv6Network_Merge_SameMaskNotAdjacentNotIdenticalProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		left := genIPv6Network.Draw(t, "left")
		right := genIPv6Network.Draw(t, "right")
		if left.Mask() != right.Mask() || left == right || left.IsAdjacent(right) {
			return
		}
		_, ok := left.Merge(right)
		require.False(t, ok)
	})
}

// verifies that merging allocates nothing on any branch.
func Test_IPv6Network_Merge_AllocationFree(t *testing.T) {
	sibling := xnetip.MustParseIPv6Network("2001:db8::/48")
	buddy := xnetip.MustParseIPv6Network("2001:db8:1::/48")
	container := xnetip.MustParseIPv6Network("2001:db8::/32")
	contained := xnetip.MustParseIPv6Network("2001:db8:1::/48")
	requireNoAllocs(t, func() { network6Sink, okSink = sibling.Merge(buddy) })
	requireNoAllocs(t, func() { network6Sink, okSink = container.Merge(contained) })
}

func BenchmarkIPv6Network_Merge_EqualMaskAdjacent(b *testing.B) {
	left := xnetip.MustParseIPv6Network("2001:db8::/48")
	right := xnetip.MustParseIPv6Network("2001:db8:1::/48")
	b.ReportAllocs()
	for b.Loop() {
		network6Sink, okSink = left.Merge(right)
	}
}

func BenchmarkIPv6Network_Merge_EqualMaskNonMergeable(b *testing.B) {
	left := xnetip.MustParseIPv6Network("2001:db8::/48")
	right := xnetip.MustParseIPv6Network("2001:db8:5::/48")
	b.ReportAllocs()
	for b.Loop() {
		network6Sink, okSink = left.Merge(right)
	}
}

func BenchmarkIPv6Network_Merge_Containment(b *testing.B) {
	left := xnetip.MustParseIPv6Network("2001:db8::/32")
	right := xnetip.MustParseIPv6Network("2001:db8:1::/48")
	b.ReportAllocs()
	for b.Loop() {
		network6Sink, okSink = left.Merge(right)
	}
}

func BenchmarkIPv6Network_Merge_ComparableMasksAddressMismatch(b *testing.B) {
	left := xnetip.MustParseIPv6Network("2001:db8::/32")
	right := xnetip.MustParseIPv6Network("2001:beef:1::/48")
	b.ReportAllocs()
	for b.Loop() {
		network6Sink, okSink = left.Merge(right)
	}
}

func BenchmarkIPv6Network_Merge_IncomparableMasks(b *testing.B) {
	left := xnetip.MustParseIPv6Network("2001:db8::1/ffff:0:ffff::")
	right := xnetip.MustParseIPv6Network("2001:db8::1/0:ffff:ffff::")
	b.ReportAllocs()
	for b.Loop() {
		network6Sink, okSink = left.Merge(right)
	}
}

func BenchmarkIPv6Network_Merge_NonContiguous(b *testing.B) {
	left := xnetip.MustParseIPv6Network("2001::1/ffff:ff00::ffff")
	right := xnetip.MustParseIPv6Network("2001:100::1/ffff:ff00::ffff")
	b.ReportAllocs()
	for b.Loop() {
		network6Sink, okSink = left.Merge(right)
	}
}

// isAdjacentByLowestMaskBitReferenceIPv6 is the simple oracle for the
// lowest-mask-bit adjacency.
//
// It isolates the boundary bit with a trailing-zero count over the
// halves and a shift, independent from the arithmetic isolation the
// implementation uses. A zero mask has no boundary bit and never
// qualifies.
func isAdjacentByLowestMaskBitReferenceIPv6(left, right xnetip.IPv6Network) bool {
	leftAddrHi, leftAddrLo, leftMaskHi, leftMaskLo := ipv6NetworkBits(left)
	rightAddrHi, rightAddrLo, rightMaskHi, rightMaskLo := ipv6NetworkBits(right)
	if leftMaskHi != rightMaskHi || leftMaskLo != rightMaskLo || leftMaskHi|leftMaskLo == 0 {
		return false
	}
	var lowestHi, lowestLo uint64
	if leftMaskLo != 0 {
		lowestLo = 1 << bits.TrailingZeros64(leftMaskLo)
	} else {
		lowestHi = 1 << bits.TrailingZeros64(leftMaskHi)
	}
	return leftAddrHi^rightAddrHi == lowestHi && leftAddrLo^rightAddrLo == lowestLo
}

// verifies that only same-mask pairs differing in exactly the mask's
// lowest set bit qualify, and adjacency at any higher bit is refused.
//
// The half-boundary rows pin the lowest-bit isolation across bit 64,
// which must scan the low half first and fall back to the high half
// only when the low half is empty.
func Test_IPv6Network_IsAdjacentByLowestMaskBit_ContiguousAndBoundary(t *testing.T) {
	cases := []struct {
		name  string
		left  xnetip.IPv6Network
		right xnetip.IPv6Network
		want  bool
	}{
		{name: "CIDR siblings", left: xnetip.MustParseIPv6Network("2001:db8::/48"), right: xnetip.MustParseIPv6Network("2001:db8:1::/48"), want: true},
		{name: "CIDR siblings reversed", left: xnetip.MustParseIPv6Network("2001:db8:1::/48"), right: xnetip.MustParseIPv6Network("2001:db8::/48"), want: true},
		{name: "host routes differing in bit 0", left: xnetip.MustParseIPv6Network("2001:db8::/128"), right: xnetip.MustParseIPv6Network("2001:db8::1/128"), want: true},
		{name: "host routes differing in bit 0 reversed", left: xnetip.MustParseIPv6Network("2001:db8::1/128"), right: xnetip.MustParseIPv6Network("2001:db8::/128"), want: true},
		{name: "identical", left: xnetip.MustParseIPv6Network("2001:db8::/48"), right: xnetip.MustParseIPv6Network("2001:db8::/48"), want: false},
		{name: "different masks", left: xnetip.MustParseIPv6Network("2001:db8::/48"), right: xnetip.MustParseIPv6Network("2001:db8::/32"), want: false},
		{name: "adjacent at the top mask bit, not the lowest", left: xnetip.MustParseIPv6Network("::/2"), right: xnetip.MustParseIPv6Network("8000::/2"), want: false},
		{name: "default route with itself", left: xnetip.MustParseIPv6Network("::/0"), right: xnetip.MustParseIPv6Network("::/0"), want: false},
		{name: "/64 siblings at bit 64", left: xnetip.MustParseIPv6Network("2001:db8:0:0::/64"), right: xnetip.MustParseIPv6Network("2001:db8:0:1::/64"), want: true},
		{name: "/65 siblings at bit 63", left: xnetip.MustParseIPv6Network("2001:db8::/65"), right: xnetip.MustParseIPv6Network("2001:db8:0:0:8000::/65"), want: true},
		{name: "/65 pair differing at bit 64", left: xnetip.MustParseIPv6Network("2001:db8::/65"), right: xnetip.MustParseIPv6Network("2001:db8:0:1::/65"), want: false},
		{name: "/63 pair differing at a host bit is identical", left: xnetip.MustParseIPv6Network("2001:db8:0:0::/63"), right: xnetip.MustParseIPv6Network("2001:db8:0:1::/63"), want: false},
		{name: "/1 siblings at bit 127", left: xnetip.MustParseIPv6Network("::/1"), right: xnetip.MustParseIPv6Network("8000::/1"), want: true},
		{name: "/127 siblings", left: xnetip.MustParseIPv6Network("2001:db8::/127"), right: xnetip.MustParseIPv6Network("2001:db8::2/127"), want: true},
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
func Test_IPv6Network_IsAdjacentByLowestMaskBit_NonContiguousMasks(t *testing.T) {
	cases := []struct {
		name  string
		left  xnetip.IPv6Network
		right xnetip.IPv6Network
		want  bool
	}{
		{name: "two-run mask at its lowest bit", left: xnetip.MustParseIPv6Network("::/ffff:ffff::ffff"), right: xnetip.MustParseIPv6Network("::1/ffff:ffff::ffff"), want: true},
		{name: "two-run mask at its lowest bit reversed", left: xnetip.MustParseIPv6Network("::1/ffff:ffff::ffff"), right: xnetip.MustParseIPv6Network("::/ffff:ffff::ffff"), want: true},
		{name: "two-run mask at the high run's boundary bit 96", left: xnetip.MustParseIPv6Network("::/ffff:ffff::ffff"), right: xnetip.MustParseIPv6Network("0:1::/ffff:ffff::ffff"), want: false},
		{name: "low run ending at bit 32, differing there", left: xnetip.MustParseIPv6Network("2a02:6b8::/ffff:ffff::ffff:ffff:0:0"), right: xnetip.MustParseIPv6Network("2a02:6b8::1:0:0/ffff:ffff::ffff:ffff:0:0"), want: true},
		{name: "lowest set bit 64 under a hole, differing there", left: xnetip.MustParseIPv6Network("2001:db8::/ffff:ffff:0:ffff::"), right: xnetip.MustParseIPv6Network("2001:db8:0:1::/ffff:ffff:0:ffff::"), want: true},
		{name: "lowest set bit 64 under a hole, differing at bit 96", left: xnetip.MustParseIPv6Network("2001:db8::/ffff:ffff:0:ffff::"), right: xnetip.MustParseIPv6Network("2001:db9::/ffff:ffff:0:ffff::"), want: false},
		{name: "geo two-run siblings in the low run", left: xnetip.MustParseIPv6Network("2a02:6b8:c00::1234:0:0/ffff:ffff:ff00::ffff:ffff:0:0"), right: xnetip.MustParseIPv6Network("2a02:6b8:c00::1235:0:0/ffff:ffff:ff00::ffff:ffff:0:0"), want: true},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			require.Equal(t, testCase.want, testCase.left.IsAdjacentByLowestMaskBit(testCase.right))
		})
	}
}

// verifies that the rejected higher-bit pairs of the unit tables are
// still plainly adjacent: the predicate is a strict restriction.
func Test_IPv6Network_IsAdjacentByLowestMaskBit_RejectedPairsStayAdjacent(t *testing.T) {
	cases := [][2]string{
		{"::/2", "8000::/2"},
		{"2001:db8::/65", "2001:db8:0:1::/65"},
		{"::/ffff:ffff::ffff", "0:1::/ffff:ffff::ffff"},
		{"2001:db8::/ffff:ffff:0:ffff::", "2001:db9::/ffff:ffff:0:ffff::"},
	}
	for _, pair := range cases {
		left := xnetip.MustParseIPv6Network(pair[0])
		right := xnetip.MustParseIPv6Network(pair[1])
		require.True(t, left.IsAdjacent(right), "pair %v", pair)
		require.False(t, left.IsAdjacentByLowestMaskBit(right), "pair %v", pair)
	}
}

// verifies that the predicate agrees with the trailing-zeros oracle
// on random pairs.
func Test_IPv6Network_IsAdjacentByLowestMaskBit_MatchesReferenceProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		left := genIPv6Network.Draw(t, "left")
		right := genIPv6Network.Draw(t, "right")
		require.Equal(t, isAdjacentByLowestMaskBitReferenceIPv6(left, right), left.IsAdjacentByLowestMaskBit(right))
	})
}

// verifies that the predicate implies plain adjacency, is symmetric
// and is irreflexive.
func Test_IPv6Network_IsAdjacentByLowestMaskBit_ImpliesAdjacentAndSymmetryProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		left := genIPv6Network.Draw(t, "left")
		right := genIPv6Network.Draw(t, "right")
		if left.IsAdjacentByLowestMaskBit(right) {
			require.True(t, left.IsAdjacent(right))
		}
		require.Equal(t, left.IsAdjacentByLowestMaskBit(right), right.IsAdjacentByLowestMaskBit(left))
		require.False(t, left.IsAdjacentByLowestMaskBit(left))
	})
}

// verifies that the buddy at the mask's lowest set bit qualifies and
// a sibling at any higher set bit is adjacent but does not.
func Test_IPv6Network_IsAdjacentByLowestMaskBit_BuddyConstructionProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		network := genIPv6Network.Draw(t, "network")
		addrHi, addrLo, maskHi, maskLo := ipv6NetworkBits(network)
		if maskHi|maskLo == 0 {
			return
		}
		var lowestHi, lowestLo uint64
		if maskLo != 0 {
			lowestLo = maskLo & -maskLo
		} else {
			lowestHi = maskHi & -maskHi
		}
		buddy, err := xnetip.IPv6NetworkFrom(
			netipAddrFrom6Bits(addrHi^lowestHi, addrLo^lowestLo),
			netipAddrFrom6Bits(maskHi, maskLo),
		)
		require.NoError(t, err)
		require.True(t, network.IsAdjacentByLowestMaskBit(buddy))
		require.True(t, buddy.IsAdjacentByLowestMaskBit(network))
		higherBits := []int{}
		for bit := range 128 {
			set := bit < 64 && maskLo&(1<<bit) != 0 || bit >= 64 && maskHi&(1<<(bit-64)) != 0
			isLowest := bit < 64 && lowestLo == 1<<bit || bit >= 64 && lowestHi == 1<<(bit-64)
			if set && !isLowest {
				higherBits = append(higherBits, bit)
			}
		}
		if len(higherBits) == 0 {
			return
		}
		bit := rapid.SampledFrom(higherBits).Draw(t, "higher bit")
		var bitHi, bitLo uint64
		if bit < 64 {
			bitLo = 1 << bit
		} else {
			bitHi = 1 << (bit - 64)
		}
		sibling, err := xnetip.IPv6NetworkFrom(
			netipAddrFrom6Bits(addrHi^bitHi, addrLo^bitLo),
			netipAddrFrom6Bits(maskHi, maskLo),
		)
		require.NoError(t, err)
		require.True(t, network.IsAdjacent(sibling))
		require.False(t, network.IsAdjacentByLowestMaskBit(sibling))
	})
}

// verifies the buddy construction on masks whose lowest set bit sits
// at the interesting positions 0, 63, 64 and 127.
//
// A contiguous mask ending at the drawn position makes that position
// the lowest set bit, so the flip crosses the 64-bit half boundary in
// both directions.
func Test_IPv6Network_IsAdjacentByLowestMaskBit_HalfBoundaryBuddyProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		position := rapid.SampledFrom([]int{0, 63, 64, 127}).Draw(t, "position")
		var maskHi, maskLo uint64
		if position < 64 {
			maskHi = ^uint64(0)
			maskLo = ^uint64(0) << position
		} else {
			maskHi = ^uint64(0) << (position - 64)
		}
		network, err := xnetip.IPv6NetworkFrom(
			netipAddrFrom6Bits(rapid.Uint64().Draw(t, "addr hi"), rapid.Uint64().Draw(t, "addr lo")),
			netipAddrFrom6Bits(maskHi, maskLo),
		)
		require.NoError(t, err)
		addrHi, addrLo, _, _ := ipv6NetworkBits(network)
		var bitHi, bitLo uint64
		if position < 64 {
			bitLo = 1 << position
		} else {
			bitHi = 1 << (position - 64)
		}
		buddy, err := xnetip.IPv6NetworkFrom(
			netipAddrFrom6Bits(addrHi^bitHi, addrLo^bitLo),
			netipAddrFrom6Bits(maskHi, maskLo),
		)
		require.NoError(t, err)
		require.True(t, network.IsAdjacentByLowestMaskBit(buddy))
		require.True(t, buddy.IsAdjacentByLowestMaskBit(network))
	})
}

// verifies that the predicate allocates nothing.
func Test_IPv6Network_IsAdjacentByLowestMaskBit_AllocationFree(t *testing.T) {
	left := xnetip.MustParseIPv6Network("::/ffff:ffff::ffff")
	right := xnetip.MustParseIPv6Network("::1/ffff:ffff::ffff")
	requireNoAllocs(t, func() { okSink = left.IsAdjacentByLowestMaskBit(right) })
}

func BenchmarkIPv6Network_IsAdjacentByLowestMaskBit_CIDRSiblings(b *testing.B) {
	left := xnetip.MustParseIPv6Network("2001:db8::/48")
	right := xnetip.MustParseIPv6Network("2001:db8:1::/48")
	b.ReportAllocs()
	for b.Loop() {
		okSink = left.IsAdjacentByLowestMaskBit(right)
	}
}

func BenchmarkIPv6Network_IsAdjacentByLowestMaskBit_AdjacentNonLowestBit(b *testing.B) {
	left := xnetip.MustParseIPv6Network("::/2")
	right := xnetip.MustParseIPv6Network("8000::/2")
	b.ReportAllocs()
	for b.Loop() {
		okSink = left.IsAdjacentByLowestMaskBit(right)
	}
}

func BenchmarkIPv6Network_IsAdjacentByLowestMaskBit_NonContiguous(b *testing.B) {
	left := xnetip.MustParseIPv6Network("::/ffff:ffff::ffff")
	right := xnetip.MustParseIPv6Network("::1/ffff:ffff::ffff")
	b.ReportAllocs()
	for b.Loop() {
		okSink = left.IsAdjacentByLowestMaskBit(right)
	}
}
