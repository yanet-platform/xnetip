package xnetip_test

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"math"
	"math/big"
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
func Test_Network6From_NormalizesAddressByMask(t *testing.T) {
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
			network, err := xnetip.Network6From(
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
func Test_Network6From_RejectsForeignFamily(t *testing.T) {
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
			network, err := xnetip.Network6From(testCase.addr, testCase.mask)
			require.ErrorIs(t, err, xnetip.ErrAddrFamilyMismatch)
			require.Equal(t, xnetip.Network6{}, network)
		})
	}
}

// verifies that a zone on either argument is dropped silently, the
// network being zone-free by construction.
func Test_Network6From_DropsZoneSilently(t *testing.T) {
	network, err := xnetip.Network6From(
		netip.MustParseAddr("fe80::1%eth0"),
		netip.MustParseAddr("ffff::%eth0"),
	)
	require.NoError(t, err)
	require.Equal(t, netip.MustParseAddr("fe80::"), network.Addr())
	require.Equal(t, netip.MustParseAddr("ffff::"), network.Mask())
}

// verifies that the accessors return Is6, zone-free netip values.
func Test_Network6_Accessors_ReturnIs6Views(t *testing.T) {
	network, err := xnetip.Network6From(
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
func Test_Network6From_UniverseEqualsZeroValue(t *testing.T) {
	network, err := xnetip.Network6From(
		netip.MustParseAddr("2001:db8::1"),
		netip.MustParseAddr("::"),
	)
	require.NoError(t, err)
	require.Equal(t, xnetip.Network6{}, network)
}

// verifies that the zero value is the unspecified network ::/0.
func Test_Network6_ZeroValue_IsUnspecifiedNetwork(t *testing.T) {
	var network xnetip.Network6
	require.Equal(t, netip.MustParseAddr("::"), network.Addr())
	require.Equal(t, netip.MustParseAddr("::"), network.Mask())
}

// verifies that two constructions from different hosts of one subnet
// compare equal with ==, which only normalization makes sound.
func Test_Network6_Equality_AfterNormalization(t *testing.T) {
	left, err := xnetip.Network6From(
		netip.MustParseAddr("2a02:6b8::1"),
		netip.MustParseAddr("ffff:ffff::"),
	)
	require.NoError(t, err)
	right, err := xnetip.Network6From(
		netip.MustParseAddr("2a02:6b8::ffff:1:2:3"),
		netip.MustParseAddr("ffff:ffff::"),
	)
	require.NoError(t, err)
	operatorEqual := left == right
	require.True(t, operatorEqual)
}

// verifies that the checked constructor accepts every Is6 pair and
// always produces a normalized result with the mask preserved.
func Test_Network6From_NormalizationProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		addr := genNetipAddr6.Draw(t, "addr")
		mask := genNetipAddr6.Draw(t, "mask")
		network, err := xnetip.Network6From(addr, mask)
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
func Test_Network6From_Idempotent(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		network := genNetwork6.Draw(t, "network")
		rebuilt, err := xnetip.Network6From(network.Addr(), network.Mask())
		require.NoError(t, err)
		require.Equal(t, network, rebuilt)
	})
}

// verifies that an Is4 value in either argument position always yields
// the family-mismatch sentinel, whatever the other argument is.
func Test_Network6From_RejectsIs4EitherPosition(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		foreign := genNetipAddr4.Draw(t, "foreign")
		valid := genNetipAddr6.Draw(t, "valid")
		_, err := xnetip.Network6From(foreign, valid)
		require.ErrorIs(t, err, xnetip.ErrAddrFamilyMismatch)
		_, err = xnetip.Network6From(valid, foreign)
		require.ErrorIs(t, err, xnetip.ErrAddrFamilyMismatch)
	})
}

// verifies that normalization by a contiguous mask agrees with the
// net/netip oracle for masking a prefix.
func Test_Network6From_MatchesNetipMasked(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		prefix := genIPv6Prefix.Draw(t, "prefix")
		var maskHi, maskLo uint64
		if prefix.Bits() <= 64 {
			maskHi = ^uint64(0) << (64 - prefix.Bits())
		} else {
			maskHi = ^uint64(0)
			maskLo = ^uint64(0) << (128 - prefix.Bits())
		}
		network, err := xnetip.Network6From(prefix.Addr(), netipAddrFrom6Bits(maskHi, maskLo))
		require.NoError(t, err)
		require.Equal(t, prefix.Masked().Addr(), network.Addr())
	})
}

// verifies that construction and the accessors allocate nothing on the
// success path, per the allocation-free runtime contract.
func Test_Network6_Constructors_AllocationFree(t *testing.T) {
	addr := netip.MustParseAddr("2a02:6b8:c00::1234:9:9")
	mask := netip.MustParseAddr("ffff:ffff:ff00::ffff:ffff:0:0")
	var err error
	requireNoAllocs(t, func() { network6Sink, err = xnetip.Network6From(addr, mask) })
	require.NoError(t, err)
	network, err := xnetip.Network6From(addr, mask)
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
func Test_Network6_IsIPv4MappedIPv6(t *testing.T) {
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
			network, err := xnetip.Network6From(
				netip.MustParseAddr(testCase.addr),
				netip.MustParseAddr(testCase.mask),
			)
			require.NoError(t, err)
			require.Equal(t, testCase.want, network.IsIPv4MappedIPv6())
		})
	}
}

// verifies that the zero value, the universe ::/0, is not mapped.
func Test_Network6_IsIPv4MappedIPv6_ZeroValue(t *testing.T) {
	var network xnetip.Network6
	require.False(t, network.IsIPv4MappedIPv6())
}

// verifies that every image of an IPv4 network under the mapping is
// recognized as mapped, whatever the IPv4 mask's shape.
func Test_Network6_IsIPv4MappedIPv6_TrueOnMappedIPv4(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		network := genNetwork4.Draw(t, "network")
		require.True(t, network.ToIPv6Mapped().IsIPv4MappedIPv6())
	})
}

// verifies the cheap necessary condition: a network whose mask does not
// keep the whole high half is never mapped.
func Test_Network6_IsIPv4MappedIPv6_FalseWhenMaskHighHalfNotFull(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		network := genNetwork6.Draw(t, "network")
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
func Test_Network6_IsIPv4MappedIPv6_MatchesByteOracle(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		network := genNetwork6.Draw(t, "network")
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
func Test_Network6_IsIPv4MappedIPv6_AllocationFree(t *testing.T) {
	network4, err := xnetip.Network4From(
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
func Test_Network6_ToIPv4Mapped(t *testing.T) {
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
			network, err := xnetip.Network6From(
				netip.MustParseAddr(testCase.addr),
				netip.MustParseAddr(testCase.mask),
			)
			require.NoError(t, err)
			recovered, ok := network.ToIPv4Mapped()
			if !testCase.wantOk {
				require.False(t, ok)
				require.Equal(t, xnetip.Network4{}, recovered)
				return
			}
			require.True(t, ok)
			expected, err := xnetip.Network4From(
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
func Test_Network6_ToIPv4Mapped_RoundTripsMappedIPv4(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		network := genNetwork4.Draw(t, "network")
		recovered, ok := network.ToIPv6Mapped().ToIPv4Mapped()
		require.True(t, ok)
		require.Equal(t, network, recovered)
	})
}

// verifies that the collapse succeeds exactly when the strict mapped
// predicate holds, on every mask shape the generator draws.
func Test_Network6_ToIPv4Mapped_ConsistentWithGuard(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		network := genNetwork6.Draw(t, "network")
		_, ok := network.ToIPv4Mapped()
		require.Equal(t, network.IsIPv4MappedIPv6(), ok)
	})
}

// verifies that a successful collapse returns exactly the low four
// address and mask bytes, pinning the truncation.
func Test_Network6_ToIPv4Mapped_TakesLowBits(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		network := genNetwork6.Draw(t, "network")
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
func Test_Network6_ToIPv4Mapped_AllocationFree(t *testing.T) {
	network4, err := xnetip.Network4From(
		netip.MustParseAddr("192.168.0.1"),
		netip.MustParseAddr("255.255.0.255"),
	)
	require.NoError(t, err)
	mapped := network4.ToIPv6Mapped()
	notMapped, err := xnetip.Network6From(
		netip.MustParseAddr("2001:db8::"),
		netip.MustParseAddr("ffff:ffff::"),
	)
	require.NoError(t, err)
	requireNoAllocs(t, func() { networkSink, okSink = mapped.ToIPv4Mapped() })
	requireNoAllocs(t, func() { networkSink, okSink = notMapped.ToIPv4Mapped() })
}

func BenchmarkNetwork6_ToIPv4Mapped_Contiguous(b *testing.B) {
	network, err := xnetip.Network6From(
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

func BenchmarkNetwork6_ToIPv4Mapped_NonContiguous(b *testing.B) {
	network, err := xnetip.Network6From(
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

func BenchmarkNetwork6_ToIPv4Mapped_NotMapped(b *testing.B) {
	network, err := xnetip.Network6From(
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
func Test_Network6FromCIDR_MasksHostBits(t *testing.T) {
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
			network, err := xnetip.Network6FromCIDR(netip.MustParseAddr(testCase.addr), testCase.bits)
			require.NoError(t, err)
			require.Equal(t, netip.MustParseAddr(testCase.wantAddr), network.Addr())
			require.Equal(t, netip.MustParseAddr(testCase.wantMask), network.Mask())
		})
	}
}

// verifies that the universe network built from a zero length equals
// the type's zero value.
func Test_Network6FromCIDR_UniverseEqualsZeroValue(t *testing.T) {
	network, err := xnetip.Network6FromCIDR(netip.MustParseAddr("2001:db8::1"), 0)
	require.NoError(t, err)
	require.Equal(t, xnetip.Network6{}, network)
}

// verifies that a zone suffix on the address is dropped silently, the
// network being zone-free by construction.
func Test_Network6FromCIDR_DropsZoneSilently(t *testing.T) {
	network, err := xnetip.Network6FromCIDR(netip.MustParseAddr("fe80::1%eth0"), 64)
	require.NoError(t, err)
	require.Equal(t, netip.MustParseAddr("fe80::"), network.Addr())
	require.Empty(t, network.Addr().Zone())
}

// verifies that a prefix length outside 0 through 128 yields the
// overflow sentinel and the zero network.
func Test_Network6FromCIDR_RejectsOutOfRangeBits(t *testing.T) {
	cases := []struct {
		name      string
		bits      int
		wantError string
	}{
		{
			name:      "one past the family width",
			bits:      129,
			wantError: `xnetip.Network6FromCIDR("2001:db8::1/129"): prefix length out of range`,
		},
		{
			name:      "negative length",
			bits:      -1,
			wantError: `xnetip.Network6FromCIDR("2001:db8::1/-1"): prefix length out of range`,
		},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			network, err := xnetip.Network6FromCIDR(netip.MustParseAddr("2001:db8::1"), testCase.bits)
			require.ErrorIs(t, err, xnetip.ErrCIDROverflow)
			require.Equal(t, testCase.wantError, err.Error())
			require.Equal(t, xnetip.Network6{}, network)
		})
	}
}

// verifies that an Is4 address or the invalid zero address yields the
// family-mismatch sentinel and the zero network for a valid length.
func Test_Network6FromCIDR_RejectsForeignFamily(t *testing.T) {
	cases := []struct {
		name      string
		addr      netip.Addr
		wantError string
	}{
		{
			name:      "IPv4 address",
			addr:      netip.MustParseAddr("1.2.3.4"),
			wantError: `xnetip.Network6FromCIDR("1.2.3.4/64"): address family mismatch`,
		},
		{
			name:      "invalid zero address",
			addr:      netip.Addr{},
			wantError: `xnetip.Network6FromCIDR("invalid IP/64"): address family mismatch`,
		},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			network, err := xnetip.Network6FromCIDR(testCase.addr, 64)
			require.ErrorIs(t, err, xnetip.ErrAddrFamilyMismatch)
			require.Equal(t, testCase.wantError, err.Error())
			require.Equal(t, xnetip.Network6{}, network)
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
func Test_Network6FromCIDR_MatchesNetipMasked(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		addr := genNetipAddr6.Draw(t, "addr")
		bits := rapid.IntRange(0, 128).Draw(t, "bits")
		network, err := xnetip.Network6FromCIDR(addr, bits)
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
func Test_Network6FromCIDR_OverflowProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		addr := genNetipAddr6.Draw(t, "addr")
		bits := rapid.OneOf(rapid.IntRange(129, 400), rapid.IntRange(-400, -1)).Draw(t, "bits")
		network, err := xnetip.Network6FromCIDR(addr, bits)
		require.ErrorIs(t, err, xnetip.ErrCIDROverflow)
		require.Equal(t, xnetip.Network6{}, network)
	})
}

// verifies that the CIDR constructor allocates nothing on the success
// path, per the allocation-free runtime contract.
func Test_Network6FromCIDR_AllocationFree(t *testing.T) {
	addr := netip.MustParseAddr("2001:db8::1")
	var err error
	requireNoAllocs(t, func() { network6Sink, err = xnetip.Network6FromCIDR(addr, 64) })
	require.NoError(t, err)
}

// verifies that the host-route constructor pairs the address with the
// all-ones mask without clearing a single address bit.
//
// A non-contiguous mask table is not applicable to this constructor:
// the mask is fixed to all ones, the universe of bits, so the case
// with set bits on both halves pins that neither half is dropped.
func Test_Network6FromAddr_BuildsHostRoute(t *testing.T) {
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
			network, err := xnetip.Network6FromAddr(netip.MustParseAddr(testCase.addr))
			require.NoError(t, err)
			require.Equal(t, netip.MustParseAddr(testCase.addr), network.Addr())
			require.Equal(t, netip.MustParseAddr("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"), network.Mask())
		})
	}
}

// verifies that the host route carries the exact bit pattern of its
// address on both halves and the all-ones mask pattern.
func Test_Network6FromAddr_PreservesBitPattern(t *testing.T) {
	network, err := xnetip.Network6FromAddr(netipAddrFrom6Bits(0x20010DB800000000, 0x1))
	require.NoError(t, err)
	require.Equal(t, netipAddrFrom6Bits(0x20010DB800000000, 0x1), network.Addr())
	require.Equal(t, netipAddrFrom6Bits(math.MaxUint64, math.MaxUint64), network.Mask())
}

// verifies that the host route equals the same network built through
// the checked normalizing constructor.
func Test_Network6FromAddr_EqualsCheckedConstructor(t *testing.T) {
	fromAddr, err := xnetip.Network6FromAddr(netip.MustParseAddr("2001:db8::1"))
	require.NoError(t, err)
	fromPair, err := xnetip.Network6From(
		netip.MustParseAddr("2001:db8::1"),
		netip.MustParseAddr("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"),
	)
	require.NoError(t, err)
	require.Equal(t, fromPair, fromAddr)
}

// verifies that an Is4 address or the invalid zero address yields the
// family-mismatch sentinel and the zero network.
func Test_Network6FromAddr_RejectsForeignFamily(t *testing.T) {
	cases := []struct {
		name string
		addr netip.Addr
	}{
		{name: "IPv4 address", addr: netip.MustParseAddr("1.2.3.4")},
		{name: "invalid zero address", addr: netip.Addr{}},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			network, err := xnetip.Network6FromAddr(testCase.addr)
			require.ErrorIs(t, err, xnetip.ErrAddrFamilyMismatch)
			require.Equal(t, xnetip.Network6{}, network)
		})
	}
}

// verifies that every Is6 address lifts into its host route with the
// address preserved and the mask all ones.
//
// The result must also equal the same network built through the
// checked normalizing constructor, so the two entry points agree.
func Test_Network6FromAddr_HostRouteProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		addr := genNetipAddr6.Draw(t, "addr")
		network, err := xnetip.Network6FromAddr(addr)
		require.NoError(t, err)
		require.Equal(t, addr, network.Addr())
		require.Equal(t, netipAddrFrom6Bits(math.MaxUint64, math.MaxUint64), network.Mask())
		fromPair, err := xnetip.Network6From(addr, netipAddrFrom6Bits(math.MaxUint64, math.MaxUint64))
		require.NoError(t, err)
		require.Equal(t, fromPair, network)
	})
}

// verifies that every Is4 address is rejected with the family-mismatch
// sentinel.
func Test_Network6FromAddr_RejectsIs4Property(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		addr := genNetipAddr4.Draw(t, "addr")
		network, err := xnetip.Network6FromAddr(addr)
		require.ErrorIs(t, err, xnetip.ErrAddrFamilyMismatch)
		require.Equal(t, xnetip.Network6{}, network)
	})
}

// verifies that the host route agrees with the net/netip oracle for a
// full-length masked prefix.
func Test_Network6FromAddr_MatchesNetipHostPrefix(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		addr := genNetipAddr6.Draw(t, "addr")
		network, err := xnetip.Network6FromAddr(addr)
		require.NoError(t, err)
		require.Equal(t, netip.PrefixFrom(addr, 128).Masked().Addr(), network.Addr())
	})
}

// verifies that the host-route constructor allocates nothing on the
// success path, per the allocation-free runtime contract.
func Test_Network6FromAddr_AllocationFree(t *testing.T) {
	addr := netip.MustParseAddr("2001:db8::1")
	var err error
	requireNoAllocs(t, func() { network6Sink, err = xnetip.Network6FromAddr(addr) })
	require.NoError(t, err)
}

// verifies that the order is lexicographic on the address first and
// the mask second, both as unsigned 128-bit integers.
func Test_Network6_Compare_AddressFirstMaskSecond(t *testing.T) {
	cases := []struct {
		name  string
		left  xnetip.Network6
		right xnetip.Network6
		want  int
	}{
		{name: "address dominates mask", left: mustNetwork6(t, "2001::", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"), right: mustNetwork6(t, "2001:db9::", "ffff:ffff::"), want: -1},
		{name: "equal address, mask decides", left: mustNetwork6(t, "2001:db8::", "ffff:ffff::"), right: mustNetwork6(t, "2001:db8::", "ffff:ffff:ffff:ffff::"), want: -1},
		{name: "equal address, larger mask after", left: mustNetwork6(t, "2001:db8::", "ffff:ffff:ffff:ffff::"), right: mustNetwork6(t, "2001:db8::", "ffff:ffff::"), want: 1},
		{name: "zero before middle", left: mustNetwork6(t, "::", "::"), right: mustNetwork6(t, "2001:db8::", "ffff:ffff::"), want: -1},
		{name: "middle before max", left: mustNetwork6(t, "2001:db8::", "ffff:ffff::"), right: mustNetwork6(t, "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"), want: -1},
		{name: "zero before max", left: mustNetwork6(t, "::", "::"), right: mustNetwork6(t, "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"), want: -1},
		{name: "low half decides when high halves agree", left: mustNetwork6(t, "2001:db8::1", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"), right: mustNetwork6(t, "2001:db8::2", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"), want: -1},
		{name: "high half decides regardless of low half", left: mustNetwork6(t, "2001:db8::ffff:ffff:ffff:ffff", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"), right: mustNetwork6(t, "2001:db9::", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"), want: -1},
		{name: "top address bit compares unsigned", left: mustNetwork6(t, "8000::", "8000::"), right: mustNetwork6(t, "7fff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"), want: 1},
		{name: "same address, non-contiguous mask decides", left: mustNetwork6(t, "2001:db8::5", "ffff:ffff:ff00:ff00:ffff:ffff:ffff:ffff"), right: mustNetwork6(t, "2001:db8::5", "ffff:ffff:ff00:ffff:ffff:ffff:ffff:ffff"), want: -1},
		{name: "masks differing only in the low half", left: mustNetwork6(t, "::", "ffff::ffff:0:0"), right: mustNetwork6(t, "::", "ffff::ffff:ffff:0"), want: -1},
		{name: "alternating masks under one address", left: mustNetwork6(t, "::", "ffff:0:ffff:0:ffff:0:ffff:0"), right: mustNetwork6(t, "::", "0:ffff:0:ffff:0:ffff:0:ffff"), want: 1},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			require.Equal(t, testCase.want, testCase.left.Compare(testCase.right))
		})
	}
}

// verifies that equal networks compare as zero and only they do.
func Test_Network6_Compare_EqualityIsZero(t *testing.T) {
	left := mustNetwork6(t, "2001:db8::", "ffff:ffff::")
	right := mustNetwork6(t, "2001:db8::", "ffff:ffff::")
	require.Equal(t, 0, left.Compare(right))
	require.Equal(t, left, right)
}

// verifies that sorting a shuffled fixture yields the exact documented
// order, the contract the aggregation and split inputs rely on.
func Test_Network6_Compare_SortPinsDocumentedOrder(t *testing.T) {
	shuffled := []xnetip.Network6{
		mustNetwork6(t, "2a02:6b8::1", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"),
		mustNetwork6(t, "2001:db9::", "ffff:ffff::"),
		mustNetwork6(t, "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"),
		mustNetwork6(t, "2001:db8::5", "ffff:ffff:ff00:ffff:ffff:ffff:ffff:ffff"),
		mustNetwork6(t, "::", "::"),
		mustNetwork6(t, "2001:db8::", "ffff:ffff:ffff::"),
		mustNetwork6(t, "2001:db8::5", "ffff:ffff:ff00:ff00:ffff:ffff:ffff:ffff"),
		mustNetwork6(t, "2001:db8::", "ffff:ffff::"),
	}
	want := []xnetip.Network6{
		mustNetwork6(t, "::", "::"),
		mustNetwork6(t, "2001:db8::", "ffff:ffff::"),
		mustNetwork6(t, "2001:db8::", "ffff:ffff:ffff::"),
		mustNetwork6(t, "2001:db8::5", "ffff:ffff:ff00:ff00:ffff:ffff:ffff:ffff"),
		mustNetwork6(t, "2001:db8::5", "ffff:ffff:ff00:ffff:ffff:ffff:ffff:ffff"),
		mustNetwork6(t, "2001:db9::", "ffff:ffff::"),
		mustNetwork6(t, "2a02:6b8::1", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"),
		mustNetwork6(t, "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"),
	}
	slices.SortFunc(shuffled, xnetip.Network6.Compare)
	require.Equal(t, want, shuffled)
}

// verifies that the order equals the tuple order of the netip address
// views, is antisymmetric and is zero exactly on equal values.
func Test_Network6_Compare_MatchesTupleOrderProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		left := genNetwork6.Draw(t, "left")
		right := genNetwork6.Draw(t, "right")
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
func Test_Network6_Compare_TransitivityProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		first := genNetwork6.Draw(t, "first")
		second := genNetwork6.Draw(t, "second")
		third := genNetwork6.Draw(t, "third")
		if first.Compare(second) <= 0 && second.Compare(third) <= 0 {
			require.LessOrEqual(t, first.Compare(third), 0)
		}
	})
}

// verifies that sorting a random slice by the order yields a sorted
// permutation of the input.
func Test_Network6_Compare_SortFuncProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		networks := rapid.SliceOfN(genNetwork6, 0, 32).Draw(t, "networks")
		sorted := slices.Clone(networks)
		slices.SortFunc(sorted, xnetip.Network6.Compare)
		require.True(t, slices.IsSortedFunc(sorted, xnetip.Network6.Compare))
		require.ElementsMatch(t, networks, sorted)
	})
}

// verifies that the address-first component agrees with the
// netip.Addr order whenever the addresses differ.
func Test_Network6_Compare_MatchesNetipAddrOrder(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		left := genNetwork6.Draw(t, "left")
		right := genNetwork6.Draw(t, "right")
		if left.Addr() != right.Addr() {
			require.Equal(t, left.Addr().Compare(right.Addr()), left.Compare(right))
		}
	})
}

// verifies that comparing allocates nothing.
func Test_Network6_Compare_AllocationFree(t *testing.T) {
	left := mustNetwork6(t, "2001:db8::", "ffff:ffff::")
	right := mustNetwork6(t, "2001:db8::", "ffff:ffff:ffff::")
	requireNoAllocs(t, func() { intSink = left.Compare(right) })
}

func BenchmarkNetwork6_Compare_MaskDecides(b *testing.B) {
	left := mustNetwork6(b, "2001:db8::", "ffff:ffff::")
	right := mustNetwork6(b, "2001:db8::", "ffff:ffff:ffff::")
	b.ReportAllocs()
	for b.Loop() {
		intSink = left.Compare(right)
	}
}

func BenchmarkNetwork6_Compare_AddressDecides(b *testing.B) {
	left := mustNetwork6(b, "2001:db8::", "ffff:ffff::")
	right := mustNetwork6(b, "2001:db9::", "ffff:ffff:ffff::")
	b.ReportAllocs()
	for b.Loop() {
		intSink = left.Compare(right)
	}
}

func BenchmarkNetwork6_SortFunc_1024(b *testing.B) {
	// The fixture is random-ish, not nearly sorted.
	//
	// The 64-bit wrapping product of the index and the golden-ratio
	// constant fills the high address half, the low half stays zero
	// and the prefixes spread over /16../128.
	template := make([]xnetip.Network6, 1024)
	for idx := range template {
		bits := uint64(idx) * 0x9E3779B97F4A7C15
		network, err := xnetip.Network6FromCIDR(netipAddrFrom6Bits(bits, 0), 16+int(bits%113))
		if err != nil {
			b.Fatal(err)
		}
		template[idx] = network
	}
	networks := make([]xnetip.Network6, len(template))
	b.ReportAllocs()
	for b.Loop() {
		// The 32 KiB fixture refresh stays inside the timed region: a
		// paused timer would keep the loop from ever finishing.
		copy(networks, template)
		slices.SortFunc(networks, xnetip.Network6.Compare)
	}
}

// verifies that containment over contiguous masks follows the prefix
// rules.
//
// The universe contains everything, a shorter prefix contains its
// refinements and not the reverse, and a host route contains only
// itself. Prefixes ending at, crossing and starting past bit 64 pin
// the half boundary.
func Test_Network6_Contains_ContiguousAndBoundary(t *testing.T) {
	cases := []struct {
		name  string
		outer xnetip.Network6
		inner xnetip.Network6
		want  bool
	}{
		{name: "universe contains host route", outer: xnetip.MustParseNetwork6("::/0"), inner: xnetip.MustParseNetwork6("::1"), want: true},
		{name: "shorter prefix contains longer", outer: xnetip.MustParseNetwork6("::/32"), inner: xnetip.MustParseNetwork6("::/33"), want: true},
		{name: "longer prefix does not contain shorter", outer: xnetip.MustParseNetwork6("::/33"), inner: xnetip.MustParseNetwork6("::/32"), want: false},
		{name: "host route contains itself", outer: xnetip.MustParseNetwork6("::1"), inner: xnetip.MustParseNetwork6("::1"), want: true},
		{name: "host route does not contain neighbour", outer: xnetip.MustParseNetwork6("::1/128"), inner: xnetip.MustParseNetwork6("::2/128"), want: false},
		{name: "nested contiguous", outer: xnetip.MustParseNetwork6("2001:db8::/32"), inner: xnetip.MustParseNetwork6("2001:db8:1::/48"), want: true},
		{name: "nested contiguous reversed", outer: xnetip.MustParseNetwork6("2001:db8:1::/48"), inner: xnetip.MustParseNetwork6("2001:db8::/32"), want: false},
		{name: "disjoint contiguous", outer: xnetip.MustParseNetwork6("2001:db8::/32"), inner: xnetip.MustParseNetwork6("fe80::/10"), want: false},
		{name: "disjoint contiguous reversed", outer: xnetip.MustParseNetwork6("fe80::/10"), inner: xnetip.MustParseNetwork6("2001:db8::/32"), want: false},
		{name: "run ending at the half boundary contains longer", outer: xnetip.MustParseNetwork6("2001:db8:1:2::/64"), inner: xnetip.MustParseNetwork6("2001:db8:1:2:3::/80"), want: true},
		{name: "longer run does not contain the half-boundary run", outer: xnetip.MustParseNetwork6("2001:db8:1:2:3::/80"), inner: xnetip.MustParseNetwork6("2001:db8:1:2::/64"), want: false},
		{name: "/63 contains the /64 across the boundary", outer: xnetip.MustParseNetwork6("2001:db8:1:2::/63"), inner: xnetip.MustParseNetwork6("2001:db8:1:3::/64"), want: true},
		{name: "/64 does not contain its /63", outer: xnetip.MustParseNetwork6("2001:db8:1:3::/64"), inner: xnetip.MustParseNetwork6("2001:db8:1:2::/63"), want: false},
		{name: "/65 does not contain the /64 above it", outer: xnetip.MustParseNetwork6("2001:db8:1:2:8000::/65"), inner: xnetip.MustParseNetwork6("2001:db8:1:2::/64"), want: false},
		{name: "/64 contains its lower /65 half", outer: xnetip.MustParseNetwork6("2001:db8:1:2::/64"), inner: xnetip.MustParseNetwork6("2001:db8:1:2:8000::/65"), want: true},
		{name: "all-ones host contains itself", outer: xnetip.MustParseNetwork6("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/128"), inner: xnetip.MustParseNetwork6("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/128"), want: true},
		{name: "universe contains universe", outer: xnetip.MustParseNetwork6("::/0"), inner: xnetip.MustParseNetwork6("::/0"), want: true},
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
func Test_Network6_Contains_NonContiguousMasks(t *testing.T) {
	cases := []struct {
		name  string
		outer xnetip.Network6
		inner xnetip.Network6
		want  bool
	}{
		{name: "two-run mask contains matching host", outer: xnetip.MustParseNetwork6("2a02:6b8:c00::4d71:0:0/ffff:ffff:ff00::ffff:ffff:0:0"), inner: xnetip.MustParseNetwork6("2a02:6b8:c00:1234:0:4d71::1"), want: true},
		{name: "two-run mask rejects mismatch on a constrained group", outer: xnetip.MustParseNetwork6("2a02:6b8:c00::4d71:0:0/ffff:ffff:ff00::ffff:ffff:0:0"), inner: xnetip.MustParseNetwork6("2a02:6b8:c00:1234:0:4d72::1"), want: false},
		{name: "pattern contains narrower pattern", outer: xnetip.MustParseNetwork6("2001:db8::/ffff:ffff::"), inner: xnetip.MustParseNetwork6("2001:db8::1/ffff:ffff::ffff"), want: true},
		{name: "narrower pattern does not contain wider", outer: xnetip.MustParseNetwork6("2001:db8::1/ffff:ffff::ffff"), inner: xnetip.MustParseNetwork6("2001:db8::/ffff:ffff::"), want: false},
		{name: "hole in the third group contains its host", outer: xnetip.MustParseNetwork6("2001:db8:c00::1/ffff:ffff:ff00:ffff:ffff:ffff:ffff:ffff"), inner: xnetip.MustParseNetwork6("2001:db8:c05::1/128"), want: true},
		{name: "mask subset fails on disjoint mask bits", outer: xnetip.MustParseNetwork6("2001::/ffff::ffff:0"), inner: xnetip.MustParseNetwork6("2001::/ffff::ffff"), want: false},
		{name: "mask subset fails on disjoint mask bits reversed", outer: xnetip.MustParseNetwork6("2001::/ffff::ffff"), inner: xnetip.MustParseNetwork6("2001::/ffff::ffff:0"), want: false},
		{name: "host varying only inside the straddling hole", outer: xnetip.MustParseNetwork6("2001:db8::/ffff:ffff:ffff:ff00:ff:ffff::"), inner: xnetip.MustParseNetwork6("2001:db8:0:12:3400::/128"), want: true},
		{name: "constrained bits around the straddling hole differ", outer: xnetip.MustParseNetwork6("2001:db8::/ffff:ffff:ffff:ff00:ff:ffff::"), inner: xnetip.MustParseNetwork6("2001:db8:0:1200:34::/ffff:ffff:ffff:ff00:ff:ffff::"), want: false},
		{name: "constrained bits around the straddling hole differ reversed", outer: xnetip.MustParseNetwork6("2001:db8:0:1200:34::/ffff:ffff:ffff:ff00:ff:ffff::"), inner: xnetip.MustParseNetwork6("2001:db8::/ffff:ffff:ffff:ff00:ff:ffff::"), want: false},
		{name: "alternating groups contain the zero host", outer: xnetip.MustParseNetwork6("::/ffff:0:ffff:0:ffff:0:ffff:0"), inner: xnetip.MustParseNetwork6("::/128"), want: true},
		{name: "zero host does not contain the alternating groups", outer: xnetip.MustParseNetwork6("::/128"), inner: xnetip.MustParseNetwork6("::/ffff:0:ffff:0:ffff:0:ffff:0"), want: false},
		{name: "complementary alternating patterns", outer: xnetip.MustParseNetwork6("aa00:0:aa00:0:aa00:0:aa00:0/ff00:ff:ff00:ff:ff00:ff:ff00:ff"), inner: xnetip.MustParseNetwork6("bb:0:bb:0:bb:0:bb:0/ff:ff00:ff:ff00:ff:ff00:ff:ff00"), want: false},
		{name: "complementary alternating patterns reversed", outer: xnetip.MustParseNetwork6("bb:0:bb:0:bb:0:bb:0/ff:ff00:ff:ff00:ff:ff00:ff:ff00"), inner: xnetip.MustParseNetwork6("aa00:0:aa00:0:aa00:0:aa00:0/ff00:ff:ff00:ff:ff00:ff:ff00:ff"), want: false},
		{name: "numerically smaller mask is not a subset", outer: xnetip.MustParseNetwork6("::/::ffff:ffff"), inner: xnetip.MustParseNetwork6("::/0:0:0:0:ffff:ffff::"), want: false},
		{name: "numerically larger mask is not a subset either", outer: xnetip.MustParseNetwork6("::/0:0:0:0:ffff:ffff::"), inner: xnetip.MustParseNetwork6("::/::ffff:ffff"), want: false},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			require.Equal(t, testCase.want, testCase.outer.Contains(testCase.inner))
		})
	}
}

// verifies that every network contains itself, whatever the mask shape.
func Test_Network6_Contains_ReflexiveProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		network := genNetwork6.Draw(t, "network")
		require.True(t, network.Contains(network))
	})
}

// verifies that mutual containment holds exactly for equal networks.
func Test_Network6_Contains_AntisymmetryProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		left := genNetwork6.Draw(t, "left")
		right := genNetwork6.Draw(t, "right")
		mutual := left.Contains(right) && right.Contains(left)
		require.Equal(t, left == right, mutual)
	})
}

// verifies that containment is transitive on random triples.
func Test_Network6_Contains_TransitivityProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		first := genNetwork6.Draw(t, "first")
		second := genNetwork6.Draw(t, "second")
		third := genNetwork6.Draw(t, "third")
		if first.Contains(second) && second.Contains(third) {
			require.True(t, first.Contains(third))
		}
	})
}

// verifies that the universe contains every network and is contained
// only in itself.
func Test_Network6_Contains_UniverseProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		network := genNetwork6.Draw(t, "network")
		require.True(t, xnetip.Network6{}.Contains(network))
		require.Equal(t, network == xnetip.Network6{}, network.Contains(xnetip.Network6{}))
	})
}

// verifies that containment equals set inclusion on networks confined
// to the top group.
//
// Both masks live in the top eight bits, so enumerating the 256
// patterns there is exhaustive: the outer network contains the inner
// one exactly when every member of the inner is a member of the outer.
func Test_Network6_Contains_BruteForceMembershipTopProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		outerAddr := uint64(rapid.IntRange(0, 255).Draw(t, "outer addr"))
		outerMask := uint64(rapid.IntRange(0, 255).Draw(t, "outer mask"))
		innerAddr := uint64(rapid.IntRange(0, 255).Draw(t, "inner addr"))
		innerMask := uint64(rapid.IntRange(0, 255).Draw(t, "inner mask"))
		outer, err := xnetip.Network6From(
			netipAddrFrom6Bits(outerAddr<<56, 0),
			netipAddrFrom6Bits(outerMask<<56, 0),
		)
		require.NoError(t, err)
		inner, err := xnetip.Network6From(
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
func Test_Network6_Contains_BruteForceMembershipStraddlingProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		outerAddr := uint64(rapid.IntRange(0, 255).Draw(t, "outer addr"))
		outerMask := uint64(rapid.IntRange(0, 255).Draw(t, "outer mask"))
		innerAddr := uint64(rapid.IntRange(0, 255).Draw(t, "inner addr"))
		innerMask := uint64(rapid.IntRange(0, 255).Draw(t, "inner mask"))
		outer, err := xnetip.Network6From(
			netipAddrFrom6Bits(outerAddr>>4, outerAddr<<60),
			netipAddrFrom6Bits(outerMask>>4, outerMask<<60),
		)
		require.NoError(t, err)
		inner, err := xnetip.Network6From(
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
func Test_Network6_Contains_IPv4MappedEquivalenceProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		outer := genNetwork4.Draw(t, "outer")
		inner := genNetwork4.Draw(t, "inner")
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
func Test_Network6_Contains_MatchesNetipPrefixProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		outerPrefix := genIPv6Prefix.Draw(t, "outer").Masked()
		innerPrefix := genIPv6Prefix.Draw(t, "inner").Masked()
		outer, ok := xnetip.Network6FromPrefix(outerPrefix)
		require.True(t, ok)
		inner, ok := xnetip.Network6FromPrefix(innerPrefix)
		require.True(t, ok)
		want := outerPrefix.Contains(innerPrefix.Addr()) && outerPrefix.Bits() <= innerPrefix.Bits()
		require.Equal(t, want, outer.Contains(inner))
	})
}

// verifies that containing a host route agrees with the net/netip
// address containment of the same prefix.
func Test_Network6_Contains_HostRouteMatchesNetipProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		outerPrefix := genIPv6Prefix.Draw(t, "outer").Masked()
		outer, ok := xnetip.Network6FromPrefix(outerPrefix)
		require.True(t, ok)
		address := genNetipAddr6.Draw(t, "address")
		host, err := xnetip.Network6FromAddr(address)
		require.NoError(t, err)
		require.Equal(t, outerPrefix.Contains(address), outer.Contains(host))
	})
}

// verifies that the containment check allocates nothing.
func Test_Network6_Contains_AllocationFree(t *testing.T) {
	outer := xnetip.MustParseNetwork6("2001:db8:c00::1/ffff:ffff:ff00:ffff:ffff:ffff:ffff:ffff")
	inner := xnetip.MustParseNetwork6("2001:db8:c05::1/128")
	requireNoAllocs(t, func() { okSink = outer.Contains(inner) })
}

func BenchmarkNetwork6_Contains_ContiguousTrue(b *testing.B) {
	outer := xnetip.MustParseNetwork6("2001:db8::/32")
	inner := xnetip.MustParseNetwork6("2001:db8:1::/48")
	b.ReportAllocs()
	for b.Loop() {
		okSink = outer.Contains(inner)
	}
}

func BenchmarkNetwork6_Contains_ContiguousFalse(b *testing.B) {
	outer := xnetip.MustParseNetwork6("2001:db8::/32")
	inner := xnetip.MustParseNetwork6("fe80::/10")
	b.ReportAllocs()
	for b.Loop() {
		okSink = outer.Contains(inner)
	}
}

func BenchmarkNetwork6_Contains_NonContiguous(b *testing.B) {
	outer := xnetip.MustParseNetwork6("2001:db8:c00::1/ffff:ffff:ff00:ffff:ffff:ffff:ffff:ffff")
	inner := xnetip.MustParseNetwork6("2001:db8:c05::1/128")
	b.ReportAllocs()
	for b.Loop() {
		okSink = outer.Contains(inner)
	}
}

// verifies that address membership is total and follows the
// netip.Prefix.Contains rule over contiguous networks.
//
// A member is any address agreeing on the prefix, the universe holds
// every Is6 address with IPv4-mapped ones tested by their 16-byte
// form, a host route holds only itself, and an Is4 argument, a zoned
// address or the invalid zero value is not contained rather than an
// error.
func Test_Network6_ContainsAddr_UnitAndBoundary(t *testing.T) {
	cases := []struct {
		name    string
		network xnetip.Network6
		addr    netip.Addr
		want    bool
	}{
		{name: "member", network: xnetip.MustParseNetwork6("2001:db8::/32"), addr: netip.MustParseAddr("2001:db8::1"), want: true},
		{name: "non-member", network: xnetip.MustParseNetwork6("2001:db8::/32"), addr: netip.MustParseAddr("2001:db9::"), want: false},
		{name: "network address itself", network: xnetip.MustParseNetwork6("2001:db8::/32"), addr: netip.MustParseAddr("2001:db8::"), want: true},
		{name: "last address", network: xnetip.MustParseNetwork6("2001:db8::/32"), addr: netip.MustParseAddr("2001:db8:ffff:ffff:ffff:ffff:ffff:ffff"), want: true},
		{name: "host route contains itself", network: xnetip.MustParseNetwork6("2001:db8::1/128"), addr: netip.MustParseAddr("2001:db8::1"), want: true},
		{name: "host route excludes neighbour", network: xnetip.MustParseNetwork6("2001:db8::1/128"), addr: netip.MustParseAddr("2001:db8::2"), want: false},
		{name: "universe contains zero address", network: xnetip.MustParseNetwork6("::/0"), addr: netip.MustParseAddr("::"), want: true},
		{name: "universe contains all-ones address", network: xnetip.MustParseNetwork6("::/0"), addr: netip.MustParseAddr("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"), want: true},
		{name: "IPv4 argument", network: xnetip.MustParseNetwork6("2001:db8::/32"), addr: netip.MustParseAddr("1.2.3.4"), want: false},
		{name: "IPv4 argument against the universe", network: xnetip.MustParseNetwork6("::/0"), addr: netip.MustParseAddr("1.2.3.4"), want: false},
		{name: "invalid zero Addr", network: xnetip.MustParseNetwork6("2001:db8::/32"), addr: netip.Addr{}, want: false},
		{name: "zoned member address", network: xnetip.MustParseNetwork6("fe80::/10"), addr: netip.MustParseAddr("fe80::1%eth0"), want: false},
		{name: "zoned non-member", network: xnetip.MustParseNetwork6("2001:db8::/32"), addr: netip.MustParseAddr("fe80::1%eth0"), want: false},
		{name: "IPv4-mapped in mapped network", network: xnetip.MustParseNetwork6("::ffff:10.0.0.0/104"), addr: netip.MustParseAddr("::ffff:10.1.2.3"), want: true},
		{name: "IPv4-mapped in plain network", network: xnetip.MustParseNetwork6("::/0"), addr: netip.MustParseAddr("::ffff:1.2.3.4"), want: true},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			require.Equal(t, testCase.want, testCase.network.ContainsAddr(testCase.addr))
		})
	}
}

// verifies that membership under a non-contiguous mask is agreement
// on every mask bit, with the unmasked bits free to vary.
//
// The cases include an alternating-group mask spanning both 64-bit
// halves and a mask whose hole straddles the half boundary, so a
// mismatch in either half and in the straddling hole is exercised.
func Test_Network6_ContainsAddr_NonContiguousMasks(t *testing.T) {
	cases := []struct {
		name    string
		network xnetip.Network6
		addr    netip.Addr
		want    bool
	}{
		{name: "free second group varies", network: xnetip.MustParseNetwork6("2001:0:db8::/ffff:0:ffff::"), addr: netip.MustParseAddr("2001:abcd:db8:1:2:3:4:5"), want: true},
		{name: "constrained third group differs", network: xnetip.MustParseNetwork6("2001:0:db8::/ffff:0:ffff::"), addr: netip.MustParseAddr("2001:abcd:db9::1"), want: false},
		{name: "alternating groups keep both halves", network: xnetip.MustParseNetwork6("aaaa:0:bbbb:0:cccc:0:dddd:0/ffff:0:ffff:0:ffff:0:ffff:0"), addr: netip.MustParseAddr("aaaa:1111:bbbb:2222:cccc:3333:dddd:4444"), want: true},
		{name: "alternating groups broken in the high half", network: xnetip.MustParseNetwork6("aaaa:0:bbbb:0:cccc:0:dddd:0/ffff:0:ffff:0:ffff:0:ffff:0"), addr: netip.MustParseAddr("aaab:1111:bbbb:2222:cccc:3333:dddd:4444"), want: false},
		{name: "alternating groups broken in the low half", network: xnetip.MustParseNetwork6("aaaa:0:bbbb:0:cccc:0:dddd:0/ffff:0:ffff:0:ffff:0:ffff:0"), addr: netip.MustParseAddr("aaaa:1111:bbbb:2222:cccd:3333:dddd:4444"), want: false},
		{name: "hole straddling the half boundary varies", network: xnetip.MustParseNetwork6("2001:db8:1::2:3:4/ffff:ffff:ffff:0:0:ffff:ffff:ffff"), addr: netip.MustParseAddr("2001:db8:1:dead:beef:2:3:4"), want: true},
		{name: "hole straddling the half boundary near miss", network: xnetip.MustParseNetwork6("2001:db8:1::2:3:4/ffff:ffff:ffff:0:0:ffff:ffff:ffff"), addr: netip.MustParseAddr("2001:db8:1:dead:beef:2:3:5"), want: false},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			require.Equal(t, testCase.want, testCase.network.ContainsAddr(testCase.addr))
		})
	}
}

// verifies that address membership equals containing the address's
// host route, over every mask shape.
func Test_Network6_ContainsAddr_HostRouteEquivalenceProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		network := genNetwork6.Draw(t, "network")
		address := genNetipAddr6.Draw(t, "address")
		host, err := xnetip.Network6FromAddr(address)
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
func Test_Network6_ContainsAddr_MatchesAddrsProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		seed := genNetwork6.Draw(t, "seed")
		addrHi, addrLo, _, maskLo := ipv6NetworkBits(seed)
		network, err := xnetip.Network6From(
			netipAddrFrom6Bits(addrHi, addrLo),
			netipAddrFrom6Bits(^uint64(0), maskLo|^uint64(0xFF)),
		)
		require.NoError(t, err)
		members := map[netip.Addr]bool{}
		for address := range network.Addrs() {
			require.True(t, network.ContainsAddr(address))
			members[address] = true
		}
		probe := genNetipAddr6.Draw(t, "probe")
		require.Equal(t, members[probe], network.ContainsAddr(probe))
	})
}

// verifies that membership is total over arguments of every shape.
//
// An IPv4, zoned or invalid argument answers false, never a panic.
func Test_Network6_ContainsAddr_TotalityProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		network := genNetwork6.Draw(t, "network")
		var address netip.Addr
		switch rapid.IntRange(0, 3).Draw(t, "argument shape") {
		case 0:
			address = genNetipAddr6.Draw(t, "member candidate")
		case 1:
			address = genNetipAddr4.Draw(t, "foreign family")
		case 2:
			address = genNetipAddr6.Draw(t, "zoned").WithZone("eth0")
		default:
			address = netip.Addr{}
		}
		contained := network.ContainsAddr(address)
		if !address.Is6() || address.Zone() != "" {
			require.False(t, contained)
		}
	})
}

// verifies that on contiguous networks address membership agrees with
// the net/netip prefix rule for arguments of every shape.
//
// Zoned addresses are included without a carve-out: both sides
// reject them, the rule this package mirrors verbatim.
func Test_Network6_ContainsAddr_MatchesNetipPrefixProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		prefix := genIPv6Prefix.Draw(t, "prefix").Masked()
		network, ok := xnetip.Network6FromPrefix(prefix)
		require.True(t, ok)
		var address netip.Addr
		switch rapid.IntRange(0, 2).Draw(t, "argument shape") {
		case 0:
			address = genNetipAddr4.Draw(t, "foreign family")
		case 1:
			address = genNetipAddr6.Draw(t, "zoned").WithZone("eth0")
		default:
			address = genNetipAddr6.Draw(t, "address6")
		}
		require.Equal(t, prefix.Contains(address), network.ContainsAddr(address))
	})
}

// verifies that the membership check allocates nothing.
func Test_Network6_ContainsAddr_AllocationFree(t *testing.T) {
	network := xnetip.MustParseNetwork6("2001:db8:1::2:3:4/ffff:ffff:ffff:0:0:ffff:ffff:ffff")
	address := netip.MustParseAddr("2001:db8:1:dead:beef:2:3:4")
	requireNoAllocs(t, func() { okSink = network.ContainsAddr(address) })
}

func BenchmarkNetwork6_ContainsAddr_Member(b *testing.B) {
	network := xnetip.MustParseNetwork6("2001:db8::/32")
	address := netip.MustParseAddr("2001:db8::1")
	b.ReportAllocs()
	for b.Loop() {
		okSink = network.ContainsAddr(address)
	}
}

func BenchmarkNetwork6_ContainsAddr_NonMember(b *testing.B) {
	network := xnetip.MustParseNetwork6("2001:db8::/32")
	address := netip.MustParseAddr("2001:db9::1")
	b.ReportAllocs()
	for b.Loop() {
		okSink = network.ContainsAddr(address)
	}
}

func BenchmarkNetwork6_ContainsAddr_ForeignFamily(b *testing.B) {
	network := xnetip.MustParseNetwork6("2001:db8::/32")
	address := netip.MustParseAddr("10.1.2.3")
	b.ReportAllocs()
	for b.Loop() {
		okSink = network.ContainsAddr(address)
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
func Test_Network6_Intersection_ContiguousAndBoundary(t *testing.T) {
	cases := []struct {
		name   string
		left   xnetip.Network6
		right  xnetip.Network6
		want   xnetip.Network6
		wantOK bool
	}{
		{name: "containment yields the inner network", left: xnetip.MustParseNetwork6("2001:db8::/32"), right: xnetip.MustParseNetwork6("2001:db8:1::/48"), want: xnetip.MustParseNetwork6("2001:db8:1::/48"), wantOK: true},
		{name: "containment reversed yields the inner network", left: xnetip.MustParseNetwork6("2001:db8:1::/48"), right: xnetip.MustParseNetwork6("2001:db8::/32"), want: xnetip.MustParseNetwork6("2001:db8:1::/48"), wantOK: true},
		{name: "identical networks intersect as themselves", left: xnetip.MustParseNetwork6("2001:db8::/32"), right: xnetip.MustParseNetwork6("2001:db8::/32"), want: xnetip.MustParseNetwork6("2001:db8::/32"), wantOK: true},
		{name: "disjoint contiguous networks answer the zero network", left: xnetip.MustParseNetwork6("2001:db8::/32"), right: xnetip.MustParseNetwork6("fe80::/10"), want: xnetip.Network6{}, wantOK: false},
		{name: "universe is neutral", left: xnetip.MustParseNetwork6("::/0"), right: xnetip.MustParseNetwork6("2001:db8:1::/48"), want: xnetip.MustParseNetwork6("2001:db8:1::/48"), wantOK: true},
		{name: "universe is neutral reversed", left: xnetip.MustParseNetwork6("2001:db8:1::/48"), right: xnetip.MustParseNetwork6("::/0"), want: xnetip.MustParseNetwork6("2001:db8:1::/48"), wantOK: true},
		{name: "same host route intersects as itself", left: xnetip.MustParseNetwork6("::1/128"), right: xnetip.MustParseNetwork6("::1/128"), want: xnetip.MustParseNetwork6("::1/128"), wantOK: true},
		{name: "different host routes are disjoint", left: xnetip.MustParseNetwork6("::1/128"), right: xnetip.MustParseNetwork6("::2/128"), want: xnetip.Network6{}, wantOK: false},
		{name: "/64 siblings are disjoint", left: xnetip.MustParseNetwork6("2001:db8:1:2::/64"), right: xnetip.MustParseNetwork6("2001:db8:1:3::/64"), want: xnetip.Network6{}, wantOK: false},
		{name: "/63 with the /64 inside across the boundary", left: xnetip.MustParseNetwork6("2001:db8:1:2::/63"), right: xnetip.MustParseNetwork6("2001:db8:1:3::/64"), want: xnetip.MustParseNetwork6("2001:db8:1:3::/64"), wantOK: true},
		{name: "/64 with the /65 inside just past the boundary", left: xnetip.MustParseNetwork6("2001:db8:1:2::/64"), right: xnetip.MustParseNetwork6("2001:db8:1:2:8000::/65"), want: xnetip.MustParseNetwork6("2001:db8:1:2:8000::/65"), wantOK: true},
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
func Test_Network6_Intersection_NonContiguousMasks(t *testing.T) {
	cases := []struct {
		name   string
		left   xnetip.Network6
		right  xnetip.Network6
		want   xnetip.Network6
		wantOK bool
	}{
		{name: "one non-contiguous", left: xnetip.MustParseNetwork6("2001::1/ffff::ffff"), right: xnetip.MustParseNetwork6("2001:1::/ffff:ffff::"), want: xnetip.MustParseNetwork6("2001:1::1/ffff:ffff::ffff"), wantOK: true},
		{name: "one non-contiguous reversed", left: xnetip.MustParseNetwork6("2001:1::/ffff:ffff::"), right: xnetip.MustParseNetwork6("2001::1/ffff::ffff"), want: xnetip.MustParseNetwork6("2001:1::1/ffff:ffff::ffff"), wantOK: true},
		{name: "both non-contiguous", left: xnetip.MustParseNetwork6("2001:0:a::/ffff:0:ffff::"), right: xnetip.MustParseNetwork6("2001::5/ffff::ffff"), want: xnetip.MustParseNetwork6("2001:0:a::5/ffff:0:ffff::ffff"), wantOK: true},
		{name: "both non-contiguous reversed", left: xnetip.MustParseNetwork6("2001::5/ffff::ffff"), right: xnetip.MustParseNetwork6("2001:0:a::/ffff:0:ffff::"), want: xnetip.MustParseNetwork6("2001:0:a::5/ffff:0:ffff::ffff"), wantOK: true},
		{name: "alternating masks always intersect", left: xnetip.MustParseNetwork6("aa00:0:aa00:0:aa00:0:aa00:0/ff00:ff:ff00:ff:ff00:ff:ff00:ff"), right: xnetip.MustParseNetwork6("bb:0:bb:0:bb:0:bb:0/ff:ff00:ff:ff00:ff:ff00:ff:ff00"), want: xnetip.MustParseNetwork6("aabb:0:aabb:0:aabb:0:aabb:0/128"), wantOK: true},
		{name: "high half with low half", left: xnetip.MustParseNetwork6("2001:db8:1:2::/64"), right: xnetip.MustParseNetwork6("::3:4:5:6/::ffff:ffff:ffff:ffff"), want: xnetip.MustParseNetwork6("2001:db8:1:2:3:4:5:6/128"), wantOK: true},
		{name: "two-run masks disagreeing on a constrained group", left: xnetip.MustParseNetwork6("2a02:6b8:c00::4d71:0:0/ffff:ffff:ff00::ffff:ffff:0:0"), right: xnetip.MustParseNetwork6("2a02:6b8:c00::4d72:0:0/ffff:ffff:ff00::ffff:ffff:0:0"), want: xnetip.Network6{}, wantOK: false},
		{name: "two-run mask agreeing with a prefix", left: xnetip.MustParseNetwork6("2a02:6b8:c00::4d71:0:0/ffff:ffff:ff00::ffff:ffff:0:0"), right: xnetip.MustParseNetwork6("2a02:6b8:c00:1234::/ffff:ffff:ffff:ffff::"), want: xnetip.MustParseNetwork6("2a02:6b8:c00:1234:0:4d71:0:0/ffff:ffff:ffff:ffff:ffff:ffff:0:0"), wantOK: true},
		{name: "hole straddling bit 64 with a host inside", left: xnetip.MustParseNetwork6("2001:db8::/ffff:ffff:ffff:ff00:ff:ffff::"), right: xnetip.MustParseNetwork6("2001:db8:0:12:3400::/128"), want: xnetip.MustParseNetwork6("2001:db8:0:12:3400::/128"), wantOK: true},
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
func Test_Network6_Intersection_CommutativityProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		left := genNetwork6.Draw(t, "left")
		right := genNetwork6.Draw(t, "right")
		leftValue, leftOK := left.Intersection(right)
		rightValue, rightOK := right.Intersection(left)
		require.Equal(t, leftOK, rightOK)
		require.Equal(t, leftValue, rightValue)
	})
}

// verifies that every network intersected with itself is itself.
func Test_Network6_Intersection_SelfIntersectionProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		network := genNetwork6.Draw(t, "network")
		got, ok := network.Intersection(network)
		require.True(t, ok)
		require.Equal(t, network, got)
	})
}

// verifies that when one network contains the other the intersection
// is the contained one.
func Test_Network6_Intersection_ContainmentYieldsInnerProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		outer := genNetwork6.Draw(t, "outer")
		inner := genNetwork6.Draw(t, "inner")
		if outer.Contains(inner) {
			got, ok := outer.Intersection(inner)
			require.True(t, ok)
			require.Equal(t, inner, got)
		}
	})
}

// verifies that an existing intersection is contained in both inputs.
func Test_Network6_Intersection_SubsetOfBothProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		left := genNetwork6.Draw(t, "left")
		right := genNetwork6.Draw(t, "right")
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
func Test_Network6_Intersection_ShapeAndNormalizedProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		left := genNetwork6.Draw(t, "left")
		right := genNetwork6.Draw(t, "right")
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
func Test_Network6_Intersection_BruteForceMembershipTopProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		leftAddr := uint64(rapid.IntRange(0, 255).Draw(t, "left addr"))
		leftMask := uint64(rapid.IntRange(0, 255).Draw(t, "left mask"))
		rightAddr := uint64(rapid.IntRange(0, 255).Draw(t, "right addr"))
		rightMask := uint64(rapid.IntRange(0, 255).Draw(t, "right mask"))
		left, err := xnetip.Network6From(
			netipAddrFrom6Bits(leftAddr<<56, 0),
			netipAddrFrom6Bits(leftMask<<56, 0),
		)
		require.NoError(t, err)
		right, err := xnetip.Network6From(
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
func Test_Network6_Intersection_BruteForceMembershipStraddlingProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		leftAddr := uint64(rapid.IntRange(0, 255).Draw(t, "left addr"))
		leftMask := uint64(rapid.IntRange(0, 255).Draw(t, "left mask"))
		rightAddr := uint64(rapid.IntRange(0, 255).Draw(t, "right addr"))
		rightMask := uint64(rapid.IntRange(0, 255).Draw(t, "right mask"))
		left, err := xnetip.Network6From(
			netipAddrFrom6Bits(leftAddr>>4, leftAddr<<60),
			netipAddrFrom6Bits(leftMask>>4, leftMask<<60),
		)
		require.NoError(t, err)
		right, err := xnetip.Network6From(
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
func Test_Network6_Intersection_MatchesNetipOverlapsProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		leftPrefix := genIPv6Prefix.Draw(t, "left").Masked()
		rightPrefix := genIPv6Prefix.Draw(t, "right").Masked()
		left, ok := xnetip.Network6FromPrefix(leftPrefix)
		require.True(t, ok)
		right, ok := xnetip.Network6FromPrefix(rightPrefix)
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
func Test_Network6_Intersection_AllocationFree(t *testing.T) {
	left := xnetip.MustParseNetwork6("2001::1/ffff::ffff")
	right := xnetip.MustParseNetwork6("2001:1::/ffff:ffff::")
	requireNoAllocs(t, func() { network6Sink, okSink = left.Intersection(right) })
}

func BenchmarkNetwork6_Intersection_ContiguousOverlapping(b *testing.B) {
	left := xnetip.MustParseNetwork6("2001:db8::/32")
	right := xnetip.MustParseNetwork6("2001:db8:1::/48")
	b.ReportAllocs()
	for b.Loop() {
		network6Sink, okSink = left.Intersection(right)
	}
}

func BenchmarkNetwork6_Intersection_ContiguousDisjoint(b *testing.B) {
	left := xnetip.MustParseNetwork6("2001:db8::/32")
	right := xnetip.MustParseNetwork6("fe80::/10")
	b.ReportAllocs()
	for b.Loop() {
		network6Sink, okSink = left.Intersection(right)
	}
}

func BenchmarkNetwork6_Intersection_NonContiguous(b *testing.B) {
	left := xnetip.MustParseNetwork6("2001::1/ffff::ffff")
	right := xnetip.MustParseNetwork6("2001:1::/ffff:ffff::")
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
func Test_Network6_Intersects_ContiguousAndBoundary(t *testing.T) {
	cases := []struct {
		name  string
		left  xnetip.Network6
		right xnetip.Network6
		want  bool
	}{
		{name: "overlapping contiguous", left: xnetip.MustParseNetwork6("2001:db8::/32"), right: xnetip.MustParseNetwork6("2001:db8:1::/48"), want: true},
		{name: "overlapping contiguous reversed", left: xnetip.MustParseNetwork6("2001:db8:1::/48"), right: xnetip.MustParseNetwork6("2001:db8::/32"), want: true},
		{name: "disjoint contiguous", left: xnetip.MustParseNetwork6("2001:db8::/32"), right: xnetip.MustParseNetwork6("fe80::/10"), want: false},
		{name: "disjoint contiguous reversed", left: xnetip.MustParseNetwork6("fe80::/10"), right: xnetip.MustParseNetwork6("2001:db8::/32"), want: false},
		{name: "self", left: xnetip.MustParseNetwork6("2001:db8::/32"), right: xnetip.MustParseNetwork6("2001:db8::/32"), want: true},
		{name: "unspecified with anything", left: xnetip.MustParseNetwork6("::/0"), right: xnetip.MustParseNetwork6("2001:db8:1::/48"), want: true},
		{name: "anything with unspecified", left: xnetip.MustParseNetwork6("2001:db8:1::/48"), right: xnetip.MustParseNetwork6("::/0"), want: true},
		{name: "equal host routes", left: xnetip.MustParseNetwork6("2001:db8::1/128"), right: xnetip.MustParseNetwork6("2001:db8::1/128"), want: true},
		{name: "different host routes", left: xnetip.MustParseNetwork6("2001:db8::1/128"), right: xnetip.MustParseNetwork6("2001:db8::2/128"), want: false},
		{name: "blocks differing only in the low half", left: xnetip.MustParseNetwork6("2001:db8::/64"), right: xnetip.MustParseNetwork6("2001:db8:0:0:8000::/65"), want: true},
		{name: "blocks differing at bit 64", left: xnetip.MustParseNetwork6("2001:db8:0:0::/64"), right: xnetip.MustParseNetwork6("2001:db8:0:1::/64"), want: false},
		{name: "all-ones host route vs the universe", left: xnetip.MustParseNetwork6("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/128"), right: xnetip.MustParseNetwork6("::/0"), want: true},
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
func Test_Network6_Intersects_NonContiguousMasks(t *testing.T) {
	cases := []struct {
		name  string
		left  xnetip.Network6
		right xnetip.Network6
		want  bool
	}{
		{name: "pattern overlaps block", left: xnetip.MustParseNetwork6("2001::1/ffff::ffff"), right: xnetip.MustParseNetwork6("2001:1::/32"), want: true},
		{name: "pattern overlaps block reversed", left: xnetip.MustParseNetwork6("2001:1::/32"), right: xnetip.MustParseNetwork6("2001::1/ffff::ffff"), want: true},
		{name: "pattern disjoint from block", left: xnetip.MustParseNetwork6("2001::1/ffff::ffff"), right: xnetip.MustParseNetwork6("2002::/16"), want: false},
		{name: "alternating masks always intersect", left: xnetip.MustParseNetwork6("aa00:0:aa00:0:aa00:0:aa00:0/ff00:ff:ff00:ff:ff00:ff:ff00:ff"), right: xnetip.MustParseNetwork6("bb:0:bb:0:bb:0:bb:0/ff:ff00:ff:ff00:ff:ff00:ff:ff00"), want: true},
		{name: "same pattern mask, different fixed low group", left: xnetip.MustParseNetwork6("2001::1/ffff::ffff"), right: xnetip.MustParseNetwork6("2001::2/ffff::ffff"), want: false},
		{name: "hole straddling the boundary, disagreeing constrained group", left: xnetip.MustParseNetwork6("2001:db8::1:0:0/ffff:ffff:ffff:0:0:ffff::"), right: xnetip.MustParseNetwork6("2001:db8:0:1:1:2::/ffff:ffff:ffff:ffff:ffff:ffff::"), want: false},
		{name: "hole straddling the boundary, agreeing constrained groups", left: xnetip.MustParseNetwork6("2001:db8::1:0:0/ffff:ffff:ffff:0:0:ffff::"), right: xnetip.MustParseNetwork6("2001:db8:0:1:1:1::/ffff:ffff:ffff:ffff:ffff:ffff::"), want: true},
		{name: "two-run mask vs contiguous containing it", left: xnetip.MustParseNetwork6("2a02:6b8:c00::1234:0:0/ffff:ffff:ff00::ffff:ffff:0:0"), right: xnetip.MustParseNetwork6("2a02:6b8::/32"), want: true},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			require.Equal(t, testCase.want, testCase.left.Intersects(testCase.right))
		})
	}
}

// verifies that the predicate is symmetric.
func Test_Network6_Intersects_SymmetryProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		left := genNetwork6.Draw(t, "left")
		right := genNetwork6.Draw(t, "right")
		require.Equal(t, left.Intersects(right), right.Intersects(left))
	})
}

// verifies that the predicate answers exactly whether the
// intersection exists.
func Test_Network6_Intersects_EquivalentToIntersectionProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		left := genNetwork6.Draw(t, "left")
		right := genNetwork6.Draw(t, "right")
		_, ok := left.Intersection(right)
		require.Equal(t, ok, left.Intersects(right))
	})
}

// verifies that every network intersects itself and the universe
// intersects every network.
func Test_Network6_Intersects_ReflexiveAndUniverseProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		network := genNetwork6.Draw(t, "network")
		require.True(t, network.Intersects(network))
		require.True(t, xnetip.Network6{}.Intersects(network))
	})
}

// verifies that containment implies intersection.
func Test_Network6_Intersects_ContainmentImpliesIntersectionProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		outer := genNetwork6.Draw(t, "outer")
		inner := genNetwork6.Draw(t, "inner")
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
func Test_Network6_Intersects_BruteForceMembershipProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		leftAddr := uint64(rapid.IntRange(0, 255).Draw(t, "left addr"))
		leftMask := uint64(rapid.IntRange(0, 255).Draw(t, "left mask"))
		rightAddr := uint64(rapid.IntRange(0, 255).Draw(t, "right addr"))
		rightMask := uint64(rapid.IntRange(0, 255).Draw(t, "right mask"))
		left, err := xnetip.Network6From(
			netipAddrFrom6Bits(leftAddr<<56, 0),
			netipAddrFrom6Bits(leftMask<<56, 0),
		)
		require.NoError(t, err)
		right, err := xnetip.Network6From(
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
func Test_Network6_Intersects_IPv4MappedEquivalenceProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		left := genNetwork4.Draw(t, "left")
		right := genNetwork4.Draw(t, "right")
		require.Equal(
			t,
			left.Intersects(right),
			left.ToIPv6Mapped().Intersects(right.ToIPv6Mapped()),
		)
	})
}

// verifies that on contiguous networks the predicate agrees with the
// net/netip overlap rule.
func Test_Network6_Intersects_MatchesNetipOverlapsProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		leftPrefix := genIPv6Prefix.Draw(t, "left").Masked()
		rightPrefix := genIPv6Prefix.Draw(t, "right").Masked()
		left, ok := xnetip.Network6FromPrefix(leftPrefix)
		require.True(t, ok)
		right, ok := xnetip.Network6FromPrefix(rightPrefix)
		require.True(t, ok)
		require.Equal(t, leftPrefix.Overlaps(rightPrefix), left.Intersects(right))
	})
}

// verifies that the predicate allocates nothing.
func Test_Network6_Intersects_AllocationFree(t *testing.T) {
	left := xnetip.MustParseNetwork6("2001::1/ffff::ffff")
	right := xnetip.MustParseNetwork6("2001:1::/32")
	requireNoAllocs(t, func() { okSink = left.Intersects(right) })
}

func BenchmarkNetwork6_Intersects_Contiguous(b *testing.B) {
	left := xnetip.MustParseNetwork6("2001:db8::/32")
	right := xnetip.MustParseNetwork6("2001:db8:1::/48")
	b.ReportAllocs()
	for b.Loop() {
		okSink = left.Intersects(right)
	}
}

func BenchmarkNetwork6_Intersects_Disjoint(b *testing.B) {
	left := xnetip.MustParseNetwork6("2001:db8::/32")
	right := xnetip.MustParseNetwork6("fe80::/10")
	b.ReportAllocs()
	for b.Loop() {
		okSink = left.Intersects(right)
	}
}

func BenchmarkNetwork6_Intersects_NonContiguous(b *testing.B) {
	left := xnetip.MustParseNetwork6("2001::1/ffff::ffff")
	right := xnetip.MustParseNetwork6("2001:1::/32")
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
func Test_Network6_IsDisjoint_ContiguousAndBoundary(t *testing.T) {
	cases := []struct {
		name  string
		left  xnetip.Network6
		right xnetip.Network6
		want  bool
	}{
		{name: "overlapping contiguous", left: xnetip.MustParseNetwork6("2001:db8::/32"), right: xnetip.MustParseNetwork6("2001:db8:1::/48"), want: false},
		{name: "overlapping contiguous reversed", left: xnetip.MustParseNetwork6("2001:db8:1::/48"), right: xnetip.MustParseNetwork6("2001:db8::/32"), want: false},
		{name: "disjoint contiguous", left: xnetip.MustParseNetwork6("2001:db8::/32"), right: xnetip.MustParseNetwork6("fe80::/10"), want: true},
		{name: "self", left: xnetip.MustParseNetwork6("2001:db8::/32"), right: xnetip.MustParseNetwork6("2001:db8::/32"), want: false},
		{name: "unspecified with anything", left: xnetip.MustParseNetwork6("::/0"), right: xnetip.MustParseNetwork6("2001:db8::/32"), want: false},
		{name: "different host routes", left: xnetip.MustParseNetwork6("2001:db8::1/128"), right: xnetip.MustParseNetwork6("2001:db8::2/128"), want: true},
		{name: "blocks differing at bit 64", left: xnetip.MustParseNetwork6("2001:db8:0:0::/64"), right: xnetip.MustParseNetwork6("2001:db8:0:1::/64"), want: true},
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
func Test_Network6_IsDisjoint_NonContiguousMasks(t *testing.T) {
	cases := []struct {
		name  string
		left  xnetip.Network6
		right xnetip.Network6
		want  bool
	}{
		{name: "pattern disjoint from block", left: xnetip.MustParseNetwork6("2001::1/ffff::ffff"), right: xnetip.MustParseNetwork6("2002::/16"), want: true},
		{name: "pattern overlapping block", left: xnetip.MustParseNetwork6("2001::1/ffff::ffff"), right: xnetip.MustParseNetwork6("2001:1::/32"), want: false},
		{name: "hole straddling the boundary, disagreeing constrained group", left: xnetip.MustParseNetwork6("2001:db8::1:0:0/ffff:ffff:ffff:0:0:ffff::"), right: xnetip.MustParseNetwork6("2001:db8:0:1:1:2::/ffff:ffff:ffff:ffff:ffff:ffff::"), want: true},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			require.Equal(t, testCase.want, testCase.left.IsDisjoint(testCase.right))
		})
	}
}

// verifies that disjointness is the exact complement of intersection,
// symmetric, and never holds for a network against itself.
func Test_Network6_IsDisjoint_ComplementOfIntersectsProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		left := genNetwork6.Draw(t, "left")
		right := genNetwork6.Draw(t, "right")
		require.Equal(t, !left.Intersects(right), left.IsDisjoint(right))
		require.Equal(t, left.IsDisjoint(right), right.IsDisjoint(left))
		require.False(t, left.IsDisjoint(left))
	})
}

// verifies that the predicate allocates nothing.
func Test_Network6_IsDisjoint_AllocationFree(t *testing.T) {
	left := xnetip.MustParseNetwork6("2001::1/ffff::ffff")
	right := xnetip.MustParseNetwork6("2002::/16")
	requireNoAllocs(t, func() { okSink = left.IsDisjoint(right) })
}

// verifies that disjoint operands yield the source network once.
//
// With nothing shared, the difference is the whole minuend. The
// suites for this sequence are forward-only: the back-end pins of a
// double-ended cursor have no iter.Seq analogue, so none appear
// here.
func Test_Network6_Difference_DisjointYieldsSource(t *testing.T) {
	source := xnetip.MustParseNetwork6("2001:db8::/32")
	other := xnetip.MustParseNetwork6("fe80::/10")
	require.Equal(t, []xnetip.Network6{source}, slices.Collect(source.Difference(other)))
}

// verifies that subtracting a superset leaves nothing.
func Test_Network6_Difference_SubsetIsEmpty(t *testing.T) {
	source := xnetip.MustParseNetwork6("2001:db8::/64")
	other := xnetip.MustParseNetwork6("2001:db8::/48")
	require.Empty(t, slices.Collect(source.Difference(other)))
}

// verifies that a network minus itself is empty.
func Test_Network6_Difference_SelfIsEmpty(t *testing.T) {
	source := xnetip.MustParseNetwork6("2001:db8::/32")
	require.Empty(t, slices.Collect(source.Difference(source)))
}

// verifies that subtracting a /64 from its /48 superset yields 16
// networks satisfying every part invariant.
func Test_Network6_Difference_SupersetInvariants(t *testing.T) {
	source := xnetip.MustParseNetwork6("2001:db8::/48")
	other := xnetip.MustParseNetwork6("2001:db8::/64")
	parts := slices.Collect(source.Difference(other))
	require.Len(t, parts, 16)
	requireIPv6DifferenceParts(t, source, other, parts)
}

// requireIPv6DifferenceParts asserts the invariants every difference
// part must satisfy.
//
// Each part must lie inside the source and be disjoint from the
// subtracted network, and the parts must be pairwise disjoint.
func requireIPv6DifferenceParts(t require.TestingT, source, other xnetip.Network6, parts []xnetip.Network6) {
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

// verifies that the universe minus one host peels one contiguous
// network per address bit, 64 on each side of the half boundary.
func Test_Network6_Difference_UniverseMinusHost(t *testing.T) {
	source := xnetip.MustParseNetwork6("::/0")
	other := xnetip.MustParseNetwork6("2001:db8::1/128")
	parts := slices.Collect(source.Difference(other))
	require.Len(t, parts, 128)
	for _, part := range parts {
		require.True(t, part.IsContiguous(), "part %v not contiguous", part)
		require.True(t, source.Contains(part), "part %v not in source", part)
		require.True(t, part.IsDisjoint(other), "part %v intersects the host", part)
	}
}

// verifies that a host route minus the universe is empty.
func Test_Network6_Difference_HostMinusUniverse(t *testing.T) {
	source := xnetip.MustParseNetwork6("2001:db8::1/128")
	other := xnetip.MustParseNetwork6("::/0")
	require.Empty(t, slices.Collect(source.Difference(other)))
}

// verifies that two equal host routes leave nothing.
func Test_Network6_Difference_HostsSame(t *testing.T) {
	source := xnetip.MustParseNetwork6("2001:db8::1/128")
	other := xnetip.MustParseNetwork6("2001:db8::1/128")
	require.Empty(t, slices.Collect(source.Difference(other)))
}

// verifies that two different host routes yield the source alone.
func Test_Network6_Difference_HostsDifferent(t *testing.T) {
	source := xnetip.MustParseNetwork6("2001:db8::1/128")
	other := xnetip.MustParseNetwork6("2001:db8::2/128")
	require.Equal(t, []xnetip.Network6{source}, slices.Collect(source.Difference(other)))
}

// verifies the documented peel order on a hand-checked head and tail.
//
// The universe minus one host starts at /1 with the host's top bit
// flipped, walks one prefix length per step and ends at the /128
// flipping the host's last bit.
func Test_Network6_Difference_UniverseMinusHostExactHeadAndTail(t *testing.T) {
	source := xnetip.MustParseNetwork6("::/0")
	other := xnetip.MustParseNetwork6("2001:db8::1/128")
	parts := slices.Collect(source.Difference(other))
	require.Len(t, parts, 128)
	require.Equal(t, xnetip.MustParseNetwork6("8000::/1"), parts[0])
	require.Equal(t, xnetip.MustParseNetwork6("4000::/2"), parts[1])
	require.Equal(t, xnetip.MustParseNetwork6("::/3"), parts[2])
	require.Equal(t, xnetip.MustParseNetwork6("3000::/4"), parts[3])
	require.Equal(t, xnetip.MustParseNetwork6("2001:db8::/128"), parts[127])
}

// verifies the exact-count contract across all three branches.
//
// The count is the popcount of the extra intersection bits when the
// operands overlap, one when they are disjoint and zero for a subset
// — non-contiguous masks included.
func Test_Network6_Difference_CountFixedCases(t *testing.T) {
	cases := []struct {
		name   string
		source string
		other  string
		want   int
	}{
		{name: "overlapping /48 minus /64", source: "2001:db8::/48", other: "2001:db8::/64", want: 16},
		{name: "disjoint", source: "2001:db8::/32", other: "fe80::/10", want: 1},
		{name: "subset", source: "2001:db8::/64", other: "2001:db8::/48", want: 0},
		{name: "non-contiguous low-byte hole", source: "2001::/ffff::", other: "2001::1/ffff::ff", want: 8},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			source := xnetip.MustParseNetwork6(testCase.source)
			other := xnetip.MustParseNetwork6(testCase.other)
			require.Len(t, slices.Collect(source.Difference(other)), testCase.want)
		})
	}
}

// verifies that breaking out of the loop stops the sequence after
// exactly the consumed items.
func Test_Network6_Difference_EarlyBreakStops(t *testing.T) {
	source := xnetip.MustParseNetwork6("2001:db8::/48")
	other := xnetip.MustParseNetwork6("2001:db8::/64")
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
func Test_Network6_Difference_ReIterable(t *testing.T) {
	source := xnetip.MustParseNetwork6("2001:db8::/48")
	other := xnetip.MustParseNetwork6("2001:db8::/64")
	sequence := source.Difference(other)
	firstPass := slices.Collect(sequence)
	secondPass := slices.Collect(sequence)
	require.Equal(t, firstPass, secondPass)
}

// verifies the exact peel of a non-contiguous pair.
//
// The low-byte hole in the subtrahend mask is peeled bit by bit,
// highest first, every part keeping the source's non-contiguous
// shape; the first part and the final two are pinned by hand.
func Test_Network6_Difference_NonContiguousLowBytePeel(t *testing.T) {
	source := xnetip.MustParseNetwork6("2001::/ffff::")
	other := xnetip.MustParseNetwork6("2001::1/ffff::ff")
	parts := slices.Collect(source.Difference(other))
	require.Len(t, parts, 8)
	require.Equal(t, xnetip.MustParseNetwork6("2001::80/ffff::80"), parts[0])
	require.Equal(t, xnetip.MustParseNetwork6("2001::2/ffff::fe"), parts[6])
	require.Equal(t, xnetip.MustParseNetwork6("2001::/ffff::ff"), parts[7])
	requireIPv6DifferenceParts(t, source, other, parts)
}

// verifies a peel whose pending bits straddle the 64-bit half
// boundary.
//
// The subtrahend fixes bits 64 through 79 and bit 63 beyond the
// source mask, so the walk crosses from the high half into the low
// half with no seam: 17 parts, the first peeling bit 79 and the last
// peeling bit 63.
func Test_Network6_Difference_StraddlesHalfBoundary(t *testing.T) {
	source := xnetip.MustParseNetwork6("2001:db8::/ffff:ffff::")
	other := xnetip.MustParseNetwork6("2001:db8:0:1:8000::/ffff:ffff:0:ffff:8000::")
	parts := slices.Collect(source.Difference(other))
	require.Len(t, parts, 17)
	require.Equal(t, xnetip.MustParseNetwork6("2001:db8:0:8000::/ffff:ffff:0:8000::"), parts[0])
	require.Equal(t, xnetip.MustParseNetwork6("2001:db8:0:1::/ffff:ffff:0:ffff:8000::"), parts[16])
	requireIPv6DifferenceParts(t, source, other, parts)
}

// verifies the peel on an alternating subtrahend mask spanning both
// halves: one part per set mask bit, the first pinned by hand.
func Test_Network6_Difference_UniverseMinusAlternatingHost(t *testing.T) {
	source := xnetip.MustParseNetwork6("::/0")
	other := xnetip.MustParseNetwork6("1::/aaaa:aaaa:aaaa:aaaa:aaaa:aaaa:aaaa:aaaa")
	parts := slices.Collect(source.Difference(other))
	require.Len(t, parts, 64)
	require.Equal(t, xnetip.MustParseNetwork6("8000::/8000::"), parts[0])
	requireIPv6DifferenceParts(t, source, other, parts)
}

// verifies a two-run source mask against a subtrahend extending its
// lower run: the peel is confined to the extension bits.
func Test_Network6_Difference_TwoRunMasksOnBoth(t *testing.T) {
	source := xnetip.MustParseNetwork6("2a02:6b8::/ffff:ffff::ffff:ffff:0:0")
	other := xnetip.MustParseNetwork6("2a02:6b8::1:0/ffff:ffff::ffff:ffff:ffff:0")
	parts := slices.Collect(source.Difference(other))
	require.Len(t, parts, 16)
	requireIPv6DifferenceParts(t, source, other, parts)
}

// verifies that every difference part lies inside the source network.
func Test_Network6_Difference_PartsInSourceProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		source := genNetwork6.Draw(t, "source")
		other := genNetwork6.Draw(t, "other")
		for part := range source.Difference(other) {
			require.True(t, source.Contains(part), "part %v not in source %v", part, source)
		}
	})
}

// verifies that every difference part is disjoint from the subtracted
// network.
func Test_Network6_Difference_PartsDisjointFromOtherProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		source := genNetwork6.Draw(t, "source")
		other := genNetwork6.Draw(t, "other")
		for part := range source.Difference(other) {
			require.True(t, part.IsDisjoint(other), "part %v intersects %v", part, other)
		}
	})
}

// verifies that the difference parts are pairwise disjoint.
func Test_Network6_Difference_PairwiseDisjointProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		source := genNetwork6.Draw(t, "source")
		other := genNetwork6.Draw(t, "other")
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
func Test_Network6_Difference_SelfIsEmptyProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		source := genNetwork6.Draw(t, "source")
		require.Empty(t, slices.Collect(source.Difference(source)))
	})
}

// verifies completeness by counting.
//
// The parts' sizes plus the intersection's size add up to the
// source's size, which together with the pairwise-disjoint and
// inside-the-source invariants proves the union of the parts is
// exactly the set difference. The source is bounded to 62 host bits
// so every size fits an unsigned 64-bit count.
func Test_Network6_Difference_CompletenessProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		source := genNetwork6.Filter(func(network xnetip.Network6) bool {
			return network.NumHostBits() <= 62
		}).Draw(t, "source")
		other := genNetwork6.Draw(t, "other")
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
func Test_Network6_Difference_CountMatchesPopcountProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		source := genNetwork6.Draw(t, "source")
		other := genNetwork6.Draw(t, "other")
		want := 1
		if intersected, ok := source.Intersection(other); ok {
			_, _, sourceMaskHi, sourceMaskLo := ipv6NetworkBits(source)
			_, _, intersectionMaskHi, intersectionMaskLo := ipv6NetworkBits(intersected)
			want = bits.OnesCount64(intersectionMaskHi&^sourceMaskHi) +
				bits.OnesCount64(intersectionMaskLo&^sourceMaskLo)
		}
		require.Len(t, slices.Collect(source.Difference(other)), want)
	})
}

// verifies that every yielded part satisfies the network invariant
// of a zero address outside the mask.
//
// The peel step constructs parts directly instead of going through a
// normalizing constructor, so the invariant is pinned here.
func Test_Network6_Difference_ItemsAreNormalizedProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		source := genNetwork6.Draw(t, "source")
		other := genNetwork6.Draw(t, "other")
		for part := range source.Difference(other) {
			addrHi, addrLo, maskHi, maskLo := ipv6NetworkBits(part)
			require.Equal(t, addrHi&maskHi, addrHi, "part %v not normalized", part)
			require.Equal(t, addrLo&maskLo, addrLo, "part %v not normalized", part)
		}
	})
}

// verifies the documented peel order over the bits `d` fixed by the
// intersection but free in the source.
//
// Each part's mask grows the already-peeled set by exactly one bit
// of `d`, always the highest pending one across the half boundary,
// until all of `d` is covered.
func Test_Network6_Difference_PeelOrderProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		source := genNetwork6.Draw(t, "source")
		other := genNetwork6.Draw(t, "other")
		_, _, sourceMaskHi, sourceMaskLo := ipv6NetworkBits(source)
		intersected, ok := source.Intersection(other)
		if !ok {
			require.Equal(t, []xnetip.Network6{source}, slices.Collect(source.Difference(other)))
			return
		}
		_, _, intersectionMaskHi, intersectionMaskLo := ipv6NetworkBits(intersected)
		dHi := intersectionMaskHi &^ sourceMaskHi
		dLo := intersectionMaskLo &^ sourceMaskLo
		peeledHi, peeledLo := uint64(0), uint64(0)
		for part := range source.Difference(other) {
			_, _, maskHi, maskLo := ipv6NetworkBits(part)
			extraHi, extraLo := maskHi&^sourceMaskHi, maskLo&^sourceMaskLo
			newHi, newLo := extraHi&^peeledHi, extraLo&^peeledLo
			pendingHi, pendingLo := dHi&^peeledHi, dLo&^peeledLo
			wantHi, wantLo := uint64(0), uint64(0)
			if pendingHi != 0 {
				wantHi = uint64(1) << (63 - bits.LeadingZeros64(pendingHi))
			} else {
				wantLo = uint64(1) << (63 - bits.LeadingZeros64(pendingLo))
			}
			require.Zero(t, extraHi&^dHi, "part %v adds bits outside d", part)
			require.Zero(t, extraLo&^dLo, "part %v adds bits outside d", part)
			require.Equal(t, peeledHi, extraHi&peeledHi, "part %v drops peeled bits", part)
			require.Equal(t, peeledLo, extraLo&peeledLo, "part %v drops peeled bits", part)
			require.Equal(t, 1, bits.OnesCount64(newHi)+bits.OnesCount64(newLo),
				"part %v adds more than one bit", part)
			require.Equal(t, wantHi, newHi, "part %v peels a non-highest pending bit", part)
			require.Equal(t, wantLo, newLo, "part %v peels a non-highest pending bit", part)
			peeledHi, peeledLo = extraHi, extraLo
		}
		require.Equal(t, dHi, peeledHi)
		require.Equal(t, dLo, peeledLo)
	})
}

// ipv6NetworkMembers lists every address of a small network by
// scattering each host index over the mask's zero bits.
//
// It is the simple oracle the brute-force membership checks loop
// over, independent of the address iterators. Addresses are pairs of
// host-order 64-bit halves, high half first.
func ipv6NetworkMembers(addrHi, addrLo, maskHi, maskLo uint64) [][2]uint64 {
	hostBits := [][2]uint64{}
	for bit := uint64(1); bit != 0; bit <<= 1 {
		if maskLo&bit == 0 {
			hostBits = append(hostBits, [2]uint64{0, bit})
		}
	}
	for bit := uint64(1); bit != 0; bit <<= 1 {
		if maskHi&bit == 0 {
			hostBits = append(hostBits, [2]uint64{bit, 0})
		}
	}
	members := [][2]uint64{}
	for index := range 1 << len(hostBits) {
		hi, lo := addrHi, addrLo
		for position, halves := range hostBits {
			if index&(1<<position) != 0 {
				hi |= halves[0]
				lo |= halves[1]
			}
		}
		members = append(members, [2]uint64{hi, lo})
	}
	return members
}

// verifies membership by brute force on small sources: the parts
// cover exactly the source members outside the other network.
func Test_Network6_Difference_BruteForceMembershipProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		source := genNetwork6.Filter(func(network xnetip.Network6) bool {
			return network.NumHostBits() <= 12
		}).Draw(t, "source")
		other := genNetwork6.Draw(t, "other")
		parts := slices.Collect(source.Difference(other))
		sourceAddrHi, sourceAddrLo, sourceMaskHi, sourceMaskLo := ipv6NetworkBits(source)
		otherAddrHi, otherAddrLo, otherMaskHi, otherMaskLo := ipv6NetworkBits(other)
		for _, member := range ipv6NetworkMembers(sourceAddrHi, sourceAddrLo, sourceMaskHi, sourceMaskLo) {
			inOther := member[0]&otherMaskHi == otherAddrHi && member[1]&otherMaskLo == otherAddrLo
			inParts := false
			for _, part := range parts {
				partAddrHi, partAddrLo, partMaskHi, partMaskLo := ipv6NetworkBits(part)
				if member[0]&partMaskHi == partAddrHi && member[1]&partMaskLo == partAddrLo {
					inParts = true
					break
				}
			}
			require.Equal(t, !inOther, inParts, "member %#x %#x miscovered", member[0], member[1])
		}
	})
}

// verifies mapped parity with the IPv4 peel.
//
// Mapping both operands into the IPv4-mapped range yields the IPv4
// parts mapped, in the same order, pinning identical control flow
// across the families.
func Test_Network6_Difference_MappedParityProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		source := genNetwork4.Draw(t, "source")
		other := genNetwork4.Draw(t, "other")
		mappedParts := slices.Collect(source.ToIPv6Mapped().Difference(other.ToIPv6Mapped()))
		parts := slices.Collect(source.Difference(other))
		require.Len(t, mappedParts, len(parts))
		for idx, part := range parts {
			require.Equal(t, part.ToIPv6Mapped(), mappedParts[idx])
		}
	})
}

// verifies that consuming the sequence with a range loop allocates
// nothing.
func Test_Network6_Difference_AllocationFree(t *testing.T) {
	source := xnetip.MustParseNetwork6("::/0")
	other := xnetip.MustParseNetwork6("2001:db8::1/128")
	requireNoAllocs(t, func() {
		for part := range source.Difference(other) {
			network6Sink = part
		}
	})
}

func BenchmarkNetwork6_Difference_UniverseMinusHost(b *testing.B) {
	source := xnetip.MustParseNetwork6("::/0")
	other := xnetip.MustParseNetwork6("2001:db8::1/128")
	b.ReportAllocs()
	for b.Loop() {
		for part := range source.Difference(other) {
			network6Sink = part
		}
	}
}

func BenchmarkNetwork6_Difference_UniverseMinusAlternatingHost(b *testing.B) {
	source := xnetip.MustParseNetwork6("::/0")
	other := xnetip.MustParseNetwork6("1::/aaaa:aaaa:aaaa:aaaa:aaaa:aaaa:aaaa:aaaa")
	b.ReportAllocs()
	for b.Loop() {
		for part := range source.Difference(other) {
			network6Sink = part
		}
	}
}

// verifies that adjacency needs the same mask and exactly one
// differing masked bit, anywhere in the mask.
//
// Identical networks are not adjacent, different masks never are, and
// differing bits at positions 63 and 64 pin the borrow across the
// half boundary in the single-bit test.
func Test_Network6_IsAdjacent_ContiguousAndBoundary(t *testing.T) {
	cases := []struct {
		name  string
		left  xnetip.Network6
		right xnetip.Network6
		want  bool
	}{
		{name: "contiguous siblings", left: xnetip.MustParseNetwork6("2001:db8::/48"), right: xnetip.MustParseNetwork6("2001:db8:1::/48"), want: true},
		{name: "contiguous siblings reversed", left: xnetip.MustParseNetwork6("2001:db8:1::/48"), right: xnetip.MustParseNetwork6("2001:db8::/48"), want: true},
		{name: "identical", left: xnetip.MustParseNetwork6("2001:db8::/48"), right: xnetip.MustParseNetwork6("2001:db8::/48"), want: false},
		{name: "different masks", left: xnetip.MustParseNetwork6("2001:db8::/48"), right: xnetip.MustParseNetwork6("2001:db8::/32"), want: false},
		{name: "same mask, two differing bits", left: xnetip.MustParseNetwork6("2001:db8::/48"), right: xnetip.MustParseNetwork6("2001:db8:5::/48"), want: false},
		{name: "adjacent at the top mask bit", left: xnetip.MustParseNetwork6("::/2"), right: xnetip.MustParseNetwork6("8000::/2"), want: true},
		{name: "differing at bit 64, mask /64", left: xnetip.MustParseNetwork6("2001:db8:0:0::/64"), right: xnetip.MustParseNetwork6("2001:db8:0:1::/64"), want: true},
		{name: "differing at bit 63, mask /65", left: xnetip.MustParseNetwork6("2001:db8::/65"), right: xnetip.MustParseNetwork6("2001:db8:0:0:8000::/65"), want: true},
		{name: "differing at bit 64, mask /65", left: xnetip.MustParseNetwork6("2001:db8::/65"), right: xnetip.MustParseNetwork6("2001:db8:0:1::/65"), want: true},
		{name: "differing at bits 63 and 64 together, mask /65", left: xnetip.MustParseNetwork6("2001:db8::/65"), right: xnetip.MustParseNetwork6("2001:db8:0:1:8000::/65"), want: false},
		{name: "host routes differing in bit 0", left: xnetip.MustParseNetwork6("2001:db8::/128"), right: xnetip.MustParseNetwork6("2001:db8::1/128"), want: true},
		{name: "host routes differing in bit 127", left: xnetip.MustParseNetwork6("::1/128"), right: xnetip.MustParseNetwork6("8000::1/128"), want: true},
		{name: "default route with itself", left: xnetip.MustParseNetwork6("::/0"), right: xnetip.MustParseNetwork6("::/0"), want: false},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			require.Equal(t, testCase.want, testCase.left.IsAdjacent(testCase.right))
		})
	}
}

// verifies that adjacency of non-contiguous networks counts only
// masked bits, wherever the differing bit sits in the pattern.
func Test_Network6_IsAdjacent_NonContiguousMasks(t *testing.T) {
	cases := []struct {
		name  string
		left  xnetip.Network6
		right xnetip.Network6
		want  bool
	}{
		{name: "two-run mask, differing in the low run", left: xnetip.MustParseNetwork6("2a02:6b8:c00::1234:0:0/ffff:ffff:ff00::ffff:ffff:0:0"), right: xnetip.MustParseNetwork6("2a02:6b8:c00::1235:0:0/ffff:ffff:ff00::ffff:ffff:0:0"), want: true},
		{name: "two-run mask, differing in the low run reversed", left: xnetip.MustParseNetwork6("2a02:6b8:c00::1235:0:0/ffff:ffff:ff00::ffff:ffff:0:0"), right: xnetip.MustParseNetwork6("2a02:6b8:c00::1234:0:0/ffff:ffff:ff00::ffff:ffff:0:0"), want: true},
		{name: "two-run mask, differing at the bottom of the high run", left: xnetip.MustParseNetwork6("::/ffff:ffff::ffff"), right: xnetip.MustParseNetwork6("0:1::/ffff:ffff::ffff"), want: true},
		{name: "two-run mask, differing in the lowest masked bit", left: xnetip.MustParseNetwork6("::/ffff:ffff::ffff"), right: xnetip.MustParseNetwork6("::1/ffff:ffff::ffff"), want: true},
		{name: "pattern mask, two differing bits", left: xnetip.MustParseNetwork6("2001::1/ffff:ff00::ffff"), right: xnetip.MustParseNetwork6("2001:300::1/ffff:ff00::ffff"), want: false},
		{name: "pattern mask, one differing bit", left: xnetip.MustParseNetwork6("2001::1/ffff:ff00::ffff"), right: xnetip.MustParseNetwork6("2001:100::1/ffff:ff00::ffff"), want: true},
		{name: "straddling hole, differing bit inside the low run", left: xnetip.MustParseNetwork6("2001:db8::/ffff:ffff:ffff:0:0:ffff::"), right: xnetip.MustParseNetwork6("2001:db8::1:0:0/ffff:ffff:ffff:0:0:ffff::"), want: true},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			require.Equal(t, testCase.want, testCase.left.IsAdjacent(testCase.right))
		})
	}
}

// verifies that adjacency is symmetric, irreflexive and impossible
// across different masks.
func Test_Network6_IsAdjacent_SymmetryAndMaskProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		left := genNetwork6.Draw(t, "left")
		right := genNetwork6.Draw(t, "right")
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
func Test_Network6_IsAdjacent_ConstructedSiblingProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		network := genNetwork6.Draw(t, "network")
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
		sibling, err := xnetip.Network6From(
			netipAddrFrom6Bits(addrHi, addrLo),
			netipAddrFrom6Bits(maskHi, maskLo),
		)
		require.NoError(t, err)
		require.True(t, network.IsAdjacent(sibling))
		require.True(t, sibling.IsAdjacent(network))
	})
}

// verifies that the predicate allocates nothing.
func Test_Network6_IsAdjacent_AllocationFree(t *testing.T) {
	left := xnetip.MustParseNetwork6("2001::1/ffff:ff00::ffff")
	right := xnetip.MustParseNetwork6("2001:100::1/ffff:ff00::ffff")
	requireNoAllocs(t, func() { okSink = left.IsAdjacent(right) })
}

func BenchmarkNetwork6_IsAdjacent_Contiguous(b *testing.B) {
	left := xnetip.MustParseNetwork6("2001:db8::/48")
	right := xnetip.MustParseNetwork6("2001:db8:1::/48")
	b.ReportAllocs()
	for b.Loop() {
		okSink = left.IsAdjacent(right)
	}
}

func BenchmarkNetwork6_IsAdjacent_NonContiguous(b *testing.B) {
	left := xnetip.MustParseNetwork6("2001::1/ffff:ff00::ffff")
	right := xnetip.MustParseNetwork6("2001:100::1/ffff:ff00::ffff")
	b.ReportAllocs()
	for b.Loop() {
		okSink = left.IsAdjacent(right)
	}
}

func BenchmarkNetwork6_IsAdjacent_NonAdjacent(b *testing.B) {
	left := xnetip.MustParseNetwork6("2001:db8::/48")
	right := xnetip.MustParseNetwork6("2001:db8:5::/48")
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
func Test_Network6_IsContiguous_LeadingOnesRunOnly(t *testing.T) {
	cases := []struct {
		name    string
		network xnetip.Network6
		want    bool
	}{
		{name: "universe /0", network: mustNetwork6(t, "::", "::"), want: true},
		{name: "host route /128", network: mustNetwork6(t, "::1", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"), want: true},
		{name: "/40", network: mustNetwork6(t, "2a02:6b8:c00::", "ffff:ffff:ff00::"), want: true},
		{name: "/127", network: mustNetwork6(t, "2a02:6b8:c00:1:2:3:4:1", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:fffe"), want: true},
		{name: "/128 with bits in both halves", network: mustNetwork6(t, "2a02:6b8:c00:1:2:3:4:1", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"), want: true},
		{name: "run ends exactly at the half boundary /64", network: mustNetwork6(t, "2001:db8::", "ffff:ffff:ffff:ffff::"), want: true},
		{name: "run crosses the half boundary /65", network: mustNetwork6(t, "2001:db8::", "ffff:ffff:ffff:ffff:8000::"), want: true},
		{name: "single leading bit /1", network: mustNetwork6(t, "8000::", "8000::"), want: true},
		{name: "zero value is the universe", network: xnetip.Network6{}, want: true},
		{name: "top bit clear, rest set", network: mustNetwork6(t, "::", "7fff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"), want: false},
		{name: "low half only", network: mustNetwork6(t, "::", "::ffff:ffff:ffff:ffff"), want: false},
		{name: "two runs", network: mustNetwork6(t, "2a02:6b8:c00::f800:0:0", "ffff:ffff:ff00::ffff:ffff:0:0"), want: false},
		{name: "second run crosses the half boundary", network: mustNetwork6(t, "2a02:6b8:c00::f800:0:0", "ffff:ffff:ff00:0:ffff:f800::"), want: false},
		{name: "hole exactly at bits 64..95", network: mustNetwork6(t, "2a02:6b8:0:0:1234:5678::", "ffff:ffff:0:0:ffff:ffff:0:0"), want: false},
		{name: "nibble-alternating low half", network: mustNetwork6(t, "2a02:6b8:0:0:1234:5678::", "ffff:ffff:0:0:f0f0:f0f0:f0f0:f0f0"), want: false},
		{name: "hole straddling bit 64", network: mustNetwork6(t, "::", "ffff:ffff:ffff:fffe:8000::"), want: false},
		{name: "bench non-contiguous shape", network: mustNetwork6(t, "2001::1", "ffff::ffff"), want: false},
		{name: "alternating groups", network: mustNetwork6(t, "::", "ffff:0:ffff:0:ffff:0:ffff:0"), want: false},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			require.Equal(t, testCase.want, testCase.network.IsContiguous())
		})
	}
}

// verifies that the predicate agrees with the brute-force bit scan:
// contiguous means no one bit after a zero bit, top to bottom.
func Test_Network6_IsContiguous_MatchesBitScanProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		network := genNetwork6.Draw(t, "network")
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
func Test_Network6_IsContiguous_PrefixMasksAreContiguousProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		addr := genNetipAddr6.Draw(t, "addr")
		bits := rapid.OneOf(
			rapid.IntRange(0, 128),
			rapid.SampledFrom([]int{63, 64, 65}),
		).Draw(t, "bits")
		network, err := xnetip.Network6FromCIDR(addr, bits)
		require.NoError(t, err)
		require.True(t, network.IsContiguous())
		require.Equal(t, bits, netip.PrefixFrom(network.Addr(), bits).Bits())
	})
}

// verifies that clearing a non-final bit of a leading run of two or
// more ones breaks contiguity: some run bit stays below the hole.
func Test_Network6_IsContiguous_HolePunchedMaskProperty(t *testing.T) {
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
		network, err := xnetip.Network6From(
			genNetipAddr6.Draw(t, "addr"),
			netipAddrFrom6Bits(maskHi, maskLo),
		)
		require.NoError(t, err)
		require.False(t, network.IsContiguous())
	})
}

// verifies that the predicate allocates nothing.
func Test_Network6_IsContiguous_AllocationFree(t *testing.T) {
	network := mustNetwork6(t, "2001:db8::", "ffff:ffff::")
	requireNoAllocs(t, func() { okSink = network.IsContiguous() })
}

func BenchmarkNetwork6_IsContiguous_Contiguous(b *testing.B) {
	network := mustNetwork6(b, "2001:db8::", "ffff:ffff::")
	b.ReportAllocs()
	for b.Loop() {
		okSink = network.IsContiguous()
	}
}

func BenchmarkNetwork6_IsContiguous_NonContiguous(b *testing.B) {
	network := mustNetwork6(b, "2001::1", "ffff::ffff")
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
func Test_Network6_PrefixLen_LeadingOnesRunLength(t *testing.T) {
	cases := []struct {
		name    string
		network xnetip.Network6
		want    int
	}{
		{name: "/40", network: mustNetwork6(t, "2a02:6b8::", "ffff:ffff:ff00::"), want: 40},
		{name: "host route /128", network: mustNetwork6(t, "2a02:6b8::1", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"), want: 128},
		{name: "mapped /24 is /120", network: mustNetwork4(t, "8.8.8.0", "255.255.255.0").ToIPv6Mapped(), want: 120},
		{name: "universe /0", network: mustNetwork6(t, "::", "::"), want: 0},
		{name: "single leading bit /1", network: mustNetwork6(t, "8000::", "8000::"), want: 1},
		{name: "/127", network: mustNetwork6(t, "2001:db8::2", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:fffe"), want: 127},
		{name: "/128 explicit", network: mustNetwork6(t, "2001:db8::1", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"), want: 128},
		{name: "run ends exactly at the half boundary /64", network: mustNetwork6(t, "2001:db8::", "ffff:ffff:ffff:ffff::"), want: 64},
		{name: "run crosses the half boundary /65", network: mustNetwork6(t, "2001:db8::", "ffff:ffff:ffff:ffff:8000::"), want: 65},
		{name: "zero value is the universe", network: xnetip.Network6{}, want: 0},
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
func Test_Network6_PrefixLen_NonContiguousHasNone(t *testing.T) {
	cases := []struct {
		name    string
		network xnetip.Network6
	}{
		{name: "hole in the middle", network: mustNetwork6(t, "2001:db8::1", "ffff:ffff::ffff")},
		{name: "no leading run", network: mustNetwork6(t, "::1", "::ffff")},
		{name: "leading zero then ones", network: mustNetwork6(t, "::", "7fff:ffff:ffff:ffff:ffff:ffff:ffff:ffff")},
		{name: "geo mask with two runs", network: mustNetwork6(t, "2001:db8::", "ffff:ffff:ff00::ffff:ffff:0:0")},
		{name: "hole straddling bit 64", network: mustNetwork6(t, "2001:db8::", "ffff:ffff:ffff:fff0:0fff:ffff::")},
		{name: "alternating groups", network: mustNetwork6(t, "2001:0:db8::", "ffff:0:ffff:0:ffff:0:ffff:0")},
		{name: "high half full, low half broken", network: mustNetwork6(t, "::", "ffff:ffff:ffff:ffff:0:ffff:0:ffff")},
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
func Test_Network6_PrefixLen_SomeIffContiguousProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		network := genNetwork6.Draw(t, "network")
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
func Test_Network6_PrefixLen_RoundTripsCIDRProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		addr := genNetipAddr6.Draw(t, "addr")
		cidr := rapid.IntRange(0, 128).Draw(t, "cidr")
		network, err := xnetip.Network6FromCIDR(addr, cidr)
		require.NoError(t, err)
		prefix, ok := network.PrefixLen()
		require.True(t, ok)
		require.Equal(t, cidr, prefix)
	})
}

// verifies that for a contiguous mask the reported length is the one
// net/netip accepts and reports back for the same address.
func Test_Network6_PrefixLen_MatchesNetipBitsProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		network := genNetwork6.Draw(t, "network")
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
func Test_Network6_PrefixLen_AllocationFree(t *testing.T) {
	contiguous := mustNetwork6(t, "2001:db8::", "ffff:ffff::")
	nonContiguous := mustNetwork6(t, "2001:db8::1", "ffff:ffff::ffff")
	requireNoAllocs(t, func() { intSink, okSink = contiguous.PrefixLen() })
	requireNoAllocs(t, func() { intSink, okSink = nonContiguous.PrefixLen() })
}

func BenchmarkNetwork6_PrefixLen_Contiguous(b *testing.B) {
	network := mustNetwork6(b, "2001:db8::", "ffff:ffff::")
	b.ReportAllocs()
	for b.Loop() {
		intSink, okSink = network.PrefixLen()
	}
}

func BenchmarkNetwork6_PrefixLen_NonContiguous(b *testing.B) {
	network := mustNetwork6(b, "2001:db8::1", "ffff:ffff::ffff")
	b.ReportAllocs()
	for b.Loop() {
		intSink, okSink = network.PrefixLen()
	}
}

func BenchmarkNetwork6_PrefixLen_Mixed(b *testing.B) {
	// A 50/50 contiguous/non-contiguous rotation exercises both
	// outcomes of the contiguity check within one measurement.
	networks := []xnetip.Network6{
		mustNetwork6(b, "2001:db8::", "ffff:ffff::"),
		mustNetwork6(b, "2001:db8::1", "ffff:ffff::ffff"),
		mustNetwork6(b, "2a02:6b8::", "ffff:ffff:ffff::"),
		mustNetwork6(b, "2a02:6b8::1", "ffff:0:0:0:ffff::"),
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
func Test_Network6_String_ContiguousUsesPrefixForm(t *testing.T) {
	cases := []struct {
		name    string
		network xnetip.Network6
		want    string
	}{
		{name: "host route keeps /128", network: mustNetwork6(t, "2a02:6b8::1", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"), want: "2a02:6b8::1/128"},
		{name: "CIDR with inner zero groups", network: mustNetwork6(t, "2a02:6b8:c00:0:1:2::", "ffff:ffff:ffff:ffff:ffff:ffff::"), want: "2a02:6b8:c00:0:1:2::/96"},
		{name: "universe", network: mustNetwork6(t, "::", "::"), want: "::/0"},
		{name: "zero value", network: xnetip.Network6{}, want: "::/0"},
		{name: "loopback host keeps /128", network: mustNetwork6(t, "::1", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"), want: "::1/128"},
		{name: "all ones", network: mustNetwork6(t, "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"), want: "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/128"},
		{name: "full form gets compressed", network: mustNetwork6(t, "2001:db8:0:0:0:0:0:1", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"), want: "2001:db8::1/128"},
		{name: "mapped network", network: mustNetwork6(t, "::ffff:192.0.2.0", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ff00"), want: "::ffff:192.0.2.0/120"},
		{name: "normalized before print", network: mustNetwork6(t, "2a02:6b8:c00:1:2:3:4:5", "ffff:ffff:ff00::"), want: "2a02:6b8:c00::/40"},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			require.Equal(t, testCase.want, testCase.network.String())
		})
	}
}

// verifies that a non-contiguous network prints its mask compressed
// like an address, the IPv4-mapped-looking form included.
func Test_Network6_String_NonContiguousUsesMaskForm(t *testing.T) {
	cases := []struct {
		name    string
		network xnetip.Network6
		want    string
	}{
		{name: "two runs, mask compressed", network: mustNetwork6(t, "2a02:6b8:0:0:0:1234::", "ffff:ffff:0:0:ffff:ffff:0:0"), want: "2a02:6b8::1234:0:0/ffff:ffff::ffff:ffff:0:0"},
		{name: "two runs, longer address", network: mustNetwork6(t, "2a02:6b8:0:0:1234:5678::", "ffff:ffff:0:0:ffff:ffff:0:0"), want: "2a02:6b8::1234:5678:0:0/ffff:ffff::ffff:ffff:0:0"},
		{name: "geo mask, address normalized", network: mustNetwork6(t, "2001:db8::1", "ffff:ffff:ff00::ffff:ffff:0:0"), want: "2001:db8::/ffff:ffff:ff00:0:ffff:ffff::"},
		{name: "alternating groups, nothing to compress", network: mustNetwork6(t, "2001:0:db8::", "ffff:0:ffff:0:ffff:0:ffff:0"), want: "2001:0:db8::/ffff:0:ffff:0:ffff:0:ffff:0"},
		{name: "mask that looks IPv4-mapped", network: mustNetwork6(t, "::ffff:1.0.1.0", "::ffff:255.0.255.0"), want: "::ffff:1.0.1.0/::ffff:255.0.255.0"},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			require.Equal(t, testCase.want, testCase.network.String())
		})
	}
}

// verifies that appending writes after the caller's bytes and leaves
// them intact.
func Test_Network6_AppendTo_KeepsExistingBytes(t *testing.T) {
	network := mustNetwork6(t, "2001:db8::", "ffff:ffff::")
	require.Equal(t, "net=2001:db8::/32", string(network.AppendTo([]byte("net="))))
}

// verifies that a buffer with enough capacity is extended in place,
// without growing to a new backing array.
func Test_Network6_AppendTo_ReusesSizedBuffer(t *testing.T) {
	network := mustNetwork6(t, "2001:db8::", "ffff:ffff::")
	buffer := make([]byte, 0, 96)
	extended := network.AppendTo(buffer)
	require.Equal(t, "2001:db8::/32", string(extended))
	require.Equal(t, cap(buffer), cap(extended))
}

// verifies that the text splits at a single slash into the network
// address and the decimal prefix length or the rendered mask.
func Test_Network6_String_ShapeProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		network := genNetwork6.Draw(t, "network")
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
func Test_Network6_AppendTo_MatchesStringProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		network := genNetwork6.Draw(t, "network")
		prefix := rapid.SliceOf(rapid.Byte()).Draw(t, "buffer")
		require.Equal(t, network.String(), string(network.AppendTo(nil)))
		extended := network.AppendTo(slices.Clone(prefix))
		require.True(t, bytes.Equal(prefix, extended[:len(prefix)]))
		require.Equal(t, network.String(), string(extended[len(prefix):]))
	})
}

// verifies that the contiguous form is byte-identical to the netip
// prefix rendering of the same network.
func Test_Network6_String_MatchesNetipPrefixProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		network := genNetwork6.Draw(t, "network")
		prefix, ok := network.PrefixLen()
		if !ok {
			return
		}
		require.Equal(t, netip.PrefixFrom(network.Addr(), prefix).String(), network.String())
	})
}

// verifies that the longest zone-free canonical address-plus-mask form is
// 79 bytes and still needs only the returned string allocation.
func Test_Network6_String_MaximumCanonicalLength(t *testing.T) {
	const text = "ffff:ffff:ffff:fffe:ffff:ffff:ffff:ffff/ffff:ffff:ffff:fffe:ffff:ffff:ffff:ffff"
	network := xnetip.MustParseNetwork6(text)

	require.Len(t, network.String(), 79)
	require.Equal(t, text, network.String())
	require.Equal(t, 1, int(testing.AllocsPerRun(100, func() { stringSink = network.String() })))
}

// verifies that appending into a buffer with enough capacity allocates
// nothing, whatever the mask's shape.
func Test_Network6_AppendTo_AllocationFree(t *testing.T) {
	contiguous := mustNetwork6(t, "2001:db8::", "ffff:ffff::")
	nonContiguous := mustNetwork6(t, "2001:db8::", "ffff:ffff:ff00::ffff:ffff:0:0")
	buffer := make([]byte, 0, 128)
	requireNoAllocs(t, func() { bytesSink = contiguous.AppendTo(buffer[:0]) })
	requireNoAllocs(t, func() { bytesSink = nonContiguous.AppendTo(buffer[:0]) })
}

// verifies that rendering to a string costs exactly the one string
// conversion, pinning any formatting regression that adds more.
func Test_Network6_String_SingleAllocation(t *testing.T) {
	contiguous := mustNetwork6(t, "2001:db8::", "ffff:ffff::")
	nonContiguous := mustNetwork6(t, "2001:db8::", "ffff:ffff:ff00::ffff:ffff:0:0")
	require.Equal(t, 1, int(testing.AllocsPerRun(100, func() { stringSink = contiguous.String() })))
	require.Equal(t, 1, int(testing.AllocsPerRun(100, func() { stringSink = nonContiguous.String() })))
}

func BenchmarkNetwork6_String_CIDR(b *testing.B) {
	network := mustNetwork6(b, "2001:db8::", "ffff:ffff::")
	b.ReportAllocs()
	for b.Loop() {
		stringSink = network.String()
	}
}

func BenchmarkNetwork6_String_NonContiguous(b *testing.B) {
	network := mustNetwork6(b, "2001:db8::", "ffff:ffff:ff00::ffff:ffff:0:0")
	b.ReportAllocs()
	for b.Loop() {
		stringSink = network.String()
	}
}

func BenchmarkNetwork6_AppendTo_CIDR(b *testing.B) {
	network := mustNetwork6(b, "2001:db8::", "ffff:ffff::")
	buffer := make([]byte, 0, 96)
	b.ReportAllocs()
	for b.Loop() {
		bytesSink = network.AppendTo(buffer[:0])
	}
}

// verifies that the parser accepts the bare, CIDR and colon-mask forms
// and normalizes the address under the mask in every one of them.
func Test_ParseNetwork6_AcceptsAllForms(t *testing.T) {
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
			network, err := xnetip.ParseNetwork6(testCase.input)
			require.NoError(t, err)
			require.Equal(t, mustNetwork6(t, testCase.wantAddr, testCase.wantMask), network)
		})
	}
}

// verifies that the universe text parses to the zero value, so the two
// spellings of "every IPv6 address" are one value.
func Test_ParseNetwork6_UniverseIsZeroValue(t *testing.T) {
	network, err := xnetip.ParseNetwork6("::/0")
	require.NoError(t, err)
	require.Equal(t, xnetip.Network6{}, network)
}

// verifies that a digits-only suffix beyond the family limit is a
// prefix-length overflow, never a colon-mask attempt.
func Test_ParseNetwork6_RejectsPrefixOverflow(t *testing.T) {
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
			network, err := xnetip.ParseNetwork6(testCase.input)
			require.ErrorIs(t, err, xnetip.ErrCIDROverflow)
			require.Equal(t, xnetip.Network6{}, network)
		})
	}
}

// verifies that a suffix that is neither a strict prefix length nor a
// colon-form mask is rejected with the mask sentinel.
//
// The strict prefix grammar takes no sign, no leading zero and no
// trailing bytes, so each of those falls through to the mask parse
// and fails there.
func Test_ParseNetwork6_RejectsBadSuffix(t *testing.T) {
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
			network, err := xnetip.ParseNetwork6(testCase.input)
			require.ErrorIs(t, err, xnetip.ErrInvalidMask)
			require.Equal(t, xnetip.Network6{}, network)
		})
	}
}

// verifies that an IPv4 mask under an IPv6 address carries both the
// mask sentinel and the family sentinel in its chain.
func Test_ParseNetwork6_ForeignFamilyMaskKeepsBothSentinels(t *testing.T) {
	_, err := xnetip.ParseNetwork6("2001:db8::1/255.255.255.0")
	require.ErrorIs(t, err, xnetip.ErrInvalidMask)
	require.ErrorIs(t, err, xnetip.ErrAddrFamilyMismatch)
}

// verifies that a zone suffix on the address is rejected with the zone
// sentinel: the zone-free network types cannot represent it.
func Test_ParseNetwork6_RejectsZoneInAddress(t *testing.T) {
	network, err := xnetip.ParseNetwork6("fe80::1%eth0/64")
	require.ErrorIs(t, err, xnetip.ErrZone)
	require.Equal(t, xnetip.Network6{}, network)
}

// verifies that a zone suffix on the mask keeps the zone sentinel in
// the chain behind the mask sentinel.
func Test_ParseNetwork6_RejectsZoneInMask(t *testing.T) {
	_, err := xnetip.ParseNetwork6("fe80::/ffff::%eth0")
	require.ErrorIs(t, err, xnetip.ErrInvalidMask)
	require.ErrorIs(t, err, xnetip.ErrZone)
}

// verifies that zoned prefix text is rejected here exactly as the std
// prefix parser rejects it.
func Test_ParseNetwork6_ZoneParityWithNetip(t *testing.T) {
	_, err := xnetip.ParseNetwork6("fe80::1%eth0/64")
	require.Error(t, err)
	_, err = netip.ParsePrefix("fe80::1%eth0/64")
	require.Error(t, err)
}

// verifies that text whose address part is not an IPv6 address is
// rejected with the parse sentinel and the net/netip cause in the chain.
func Test_ParseNetwork6_RejectsBadAddress(t *testing.T) {
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
			network, err := xnetip.ParseNetwork6(testCase.input)
			require.ErrorIs(t, err, xnetip.ErrParse)
			require.Equal(t, xnetip.Network6{}, network)
		})
	}
}

// verifies that an IPv4 address is rejected with the family sentinel,
// not read as an IPv6 network.
func Test_ParseNetwork6_RejectsIPv4Literal(t *testing.T) {
	network, err := xnetip.ParseNetwork6("192.168.1.1")
	require.ErrorIs(t, err, xnetip.ErrAddrFamilyMismatch)
	require.Equal(t, xnetip.Network6{}, network)
}

// verifies that a colon-form mask of any shape is accepted verbatim and
// the address bits outside it are cleared, both halves included.
func Test_ParseNetwork6_NonContiguousMasks(t *testing.T) {
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
			network, err := xnetip.ParseNetwork6(testCase.input)
			require.NoError(t, err)
			require.Equal(t, mustNetwork6(t, testCase.wantAddr, testCase.wantMask), network)
		})
	}
}

// verifies that the must variant panics on invalid input instead of
// returning an error.
func Test_MustParseNetwork6_PanicsOnInvalidInput(t *testing.T) {
	require.Panics(t, func() { xnetip.MustParseNetwork6("::/129") })
}

// verifies that the must variant passes a valid parse through.
func Test_MustParseNetwork6_ReturnsParsedNetwork(t *testing.T) {
	network := xnetip.MustParseNetwork6("2001:db8::/32")
	require.Equal(t, mustNetwork6(t, "2001:db8::", "ffff:ffff::"), network)
}

// verifies that every parse error names this parser and echoes the
// rejected input in quotes.
func Test_ParseNetwork6_ErrorEchoesInput(t *testing.T) {
	_, err := xnetip.ParseNetwork6("::/129")
	require.Error(t, err)
	require.True(t, strings.HasPrefix(err.Error(), "xnetip.ParseNetwork6("))
	require.Contains(t, err.Error(), `"::/129"`)
}

// verifies that parsing the string form recovers the network exactly,
// whatever the mask's shape.
func Test_ParseNetwork6_StringRoundTripProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		network := genNetwork6.Draw(t, "network")
		parsed, err := xnetip.ParseNetwork6(network.String())
		require.NoError(t, err)
		require.Equal(t, network, parsed)
	})
}

// verifies that the CIDR text form parses to the same network the CIDR
// constructor builds from the same address and length.
func Test_ParseNetwork6_CIDRFormAgreesWithConstructorProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		addr := genNetipAddr6.Draw(t, "addr")
		bits := rapid.IntRange(0, 128).Draw(t, "bits")
		constructed, err := xnetip.Network6FromCIDR(addr, bits)
		require.NoError(t, err)
		parsed, err := xnetip.ParseNetwork6(addr.String() + "/" + strconv.Itoa(bits))
		require.NoError(t, err)
		require.Equal(t, constructed, parsed)
	})
}

// verifies that the colon-mask text form, non-contiguous masks
// included, parses like the checked constructor on the same pair.
func Test_ParseNetwork6_ColonMaskAgreesWithConstructorProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		addr := genNetipAddr6.Draw(t, "addr")
		mask := genNetipAddr6.Draw(t, "mask")
		constructed, err := xnetip.Network6From(addr, mask)
		require.NoError(t, err)
		parsed, err := xnetip.ParseNetwork6(addr.String() + "/" + mask.String())
		require.NoError(t, err)
		require.Equal(t, constructed, parsed)
	})
}

// verifies that every accepted input yields a normalized network: no
// address bit survives outside the mask, in any of the three forms.
func Test_ParseNetwork6_ResultNormalizedProperty(t *testing.T) {
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
		network, err := xnetip.ParseNetwork6(input)
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
func Test_ParseNetwork6_NeverPanicsProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		input := string(rapid.SliceOfN(rapid.Byte(), 0, 60).Draw(t, "input"))
		network6Sink, errSink = xnetip.ParseNetwork6(input)
	})
}

// verifies that on CIDR-shaped text the accept set and the parsed
// value are exactly those of the std prefix parser.
func Test_ParseNetwork6_MatchesNetipParsePrefixProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		addr := genNetipAddr6.Draw(t, "addr")
		var suffix string
		if rapid.Bool().Draw(t, "digit suffix") {
			suffix = strconv.Itoa(rapid.IntRange(0, 140).Draw(t, "bits"))
		} else {
			suffix = rapid.SampledFrom([]string{"032", "+32", "-1", ""}).Draw(t, "malformed suffix")
		}
		input := addr.String() + "/" + suffix
		parsed, err := xnetip.ParseNetwork6(input)
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
func Test_ParseNetwork6_AllocationFree(t *testing.T) {
	requireNoAllocs(t, func() { network6Sink, errSink = xnetip.ParseNetwork6("2001:db8::/32") })
	requireNoAllocs(t, func() { network6Sink, errSink = xnetip.ParseNetwork6("2001:db8::1/ffff:ffff::ffff") })
	requireNoAllocs(t, func() { network6Sink, errSink = xnetip.ParseNetwork6("2001:db8::1") })
}

func FuzzParseNetwork6(f *testing.F) {
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
		network, err := xnetip.ParseNetwork6(input)
		if err == nil {
			back, err := xnetip.ParseNetwork6(network.String())
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

func BenchmarkParseNetwork6_CIDR(b *testing.B) {
	b.ReportAllocs()
	for b.Loop() {
		network6Sink, errSink = xnetip.ParseNetwork6("2001:db8::/32")
	}
}

func BenchmarkParseNetwork6_FullMask(b *testing.B) {
	b.ReportAllocs()
	for b.Loop() {
		network6Sink, errSink = xnetip.ParseNetwork6("2001:db8::1/ffff:ffff::ffff")
	}
}

func BenchmarkParseNetwork6_Bare(b *testing.B) {
	b.ReportAllocs()
	for b.Loop() {
		network6Sink, errSink = xnetip.ParseNetwork6("2001:db8::1")
	}
}

func BenchmarkParseNetwork6_FullForm(b *testing.B) {
	b.ReportAllocs()
	for b.Loop() {
		network6Sink, errSink = xnetip.ParseNetwork6("2001:db8:1:2:3:4:5:6/64")
	}
}

func BenchmarkParseNetwork6_Compressed(b *testing.B) {
	b.ReportAllocs()
	for b.Loop() {
		network6Sink, errSink = xnetip.ParseNetwork6("2a02:6b8::c00:1")
	}
}

func BenchmarkParseNetwork6_EmbeddedIPv4(b *testing.B) {
	b.ReportAllocs()
	for b.Loop() {
		network6Sink, errSink = xnetip.ParseNetwork6("::ffff:192.0.2.1")
	}
}

func BenchmarkParseNetwork6_NonContiguousColonMask(b *testing.B) {
	b.ReportAllocs()
	for b.Loop() {
		network6Sink, errSink = xnetip.ParseNetwork6("2a02:6b8:c00::1234:0:0/ffff:ffff:ff00::ffff:ffff:0:0")
	}
}

func BenchmarkParseNetwork6_Reject(b *testing.B) {
	b.ReportAllocs()
	for b.Loop() {
		network6Sink, errSink = xnetip.ParseNetwork6("::/129")
	}
}

func BenchmarkParseNetwork6_Reject_Rendered(b *testing.B) {
	b.ReportAllocs()
	for b.Loop() {
		network6Sink, errSink = xnetip.ParseNetwork6("::/129")
		stringSink = errSink.Error()
	}
}

// verifies that the marshaled text is the string form: prefix length
// or colon-form mask by contiguity, suffix always present.
func Test_Network6_MarshalText_MatchesStringForm(t *testing.T) {
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
			text, err := xnetip.MustParseNetwork6(testCase.input).MarshalText()
			require.NoError(t, err)
			require.Equal(t, testCase.want, string(text))
		})
	}
}

// verifies that unmarshaling accepts every parser form, normalizes the
// address under the mask and lands the value in the receiver.
func Test_Network6_UnmarshalText_AcceptsParserForms(t *testing.T) {
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
			var network xnetip.Network6
			require.NoError(t, network.UnmarshalText([]byte(testCase.input)))
			require.Equal(t, xnetip.MustParseNetwork6(testCase.want), network)
		})
	}
}

// verifies that empty text is an error, because the zero value is the
// valid universe network and must not appear out of a missing field.
func Test_Network6_UnmarshalText_EmptyTextIsError(t *testing.T) {
	network := xnetip.MustParseNetwork6("2001:db8::/32")
	err := network.UnmarshalText(nil)
	require.ErrorIs(t, err, xnetip.ErrEmptyInput)
	require.Equal(t, xnetip.MustParseNetwork6("2001:db8::/32"), network)
}

// verifies that a failed unmarshal reports the parser's sentinel and
// leaves the receiver untouched.
func Test_Network6_UnmarshalText_KeepsReceiverOnError(t *testing.T) {
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
			network := xnetip.MustParseNetwork6("2a02:6b8:c00::/40")
			err := network.UnmarshalText([]byte(testCase.input))
			require.ErrorIs(t, err, testCase.sentinel)
			require.Equal(t, xnetip.MustParseNetwork6("2a02:6b8:c00::/40"), network)
		})
	}
}

// verifies that a struct field round-trips through JSON as its text
// form, non-contiguous masks included.
func Test_Network6_MarshalText_JSONStructRoundTrip(t *testing.T) {
	type wrapper struct {
		N xnetip.Network6
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
			value := wrapper{N: xnetip.MustParseNetwork6(testCase.network)}
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
func Test_Network6_MarshalText_JSONMapKeyRoundTrip(t *testing.T) {
	value := map[xnetip.Network6]int{xnetip.MustParseNetwork6("2001:db8::/32"): 1}
	encoded, err := json.Marshal(value)
	require.NoError(t, err)
	require.Equal(t, `{"2001:db8::/32":1}`, string(encoded))
	var decoded map[xnetip.Network6]int
	require.NoError(t, json.Unmarshal(encoded, &decoded))
	require.Equal(t, value, decoded)
}

// verifies that unmarshaling the marshaled text recovers the network
// exactly and that the text is byte-identical to the string form.
func Test_Network6_MarshalText_RoundTripProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		network := genNetwork6.Draw(t, "network")
		text, err := network.MarshalText()
		require.NoError(t, err)
		require.Equal(t, []byte(network.String()), text)
		var back xnetip.Network6
		require.NoError(t, back.UnmarshalText(text))
		require.Equal(t, network, back)
	})
}

// verifies that a JSON struct round trip preserves the network for
// every mask shape.
func Test_Network6_MarshalText_JSONRoundTripProperty(t *testing.T) {
	type wrapper struct {
		N xnetip.Network6
	}
	rapid.Check(t, func(t *rapid.T) {
		value := wrapper{N: genNetwork6.Draw(t, "network")}
		encoded, err := json.Marshal(value)
		require.NoError(t, err)
		var decoded wrapper
		require.NoError(t, json.Unmarshal(encoded, &decoded))
		require.Equal(t, value, decoded)
	})
}

// verifies that on contiguous networks the marshaled text is
// byte-identical to the netip prefix marshaling of the same network.
func Test_Network6_MarshalText_MatchesNetipPrefixProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		network := genNetwork6.Draw(t, "network")
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
func Test_Network6_UnmarshalText_EmptyTextDivergesFromNetip(t *testing.T) {
	var stdPrefix netip.Prefix
	require.NoError(t, stdPrefix.UnmarshalText(nil))
	var network xnetip.Network6
	require.Error(t, network.UnmarshalText(nil))
}

// verifies that marshaling allocates exactly the returned slice,
// whatever the mask's shape.
func Test_Network6_MarshalText_SingleAllocation(t *testing.T) {
	contiguous := xnetip.MustParseNetwork6("2001:db8::/32")
	nonContiguous := xnetip.MustParseNetwork6("2001:db8::/ffff:ffff::ffff:ffff:0:0")
	require.Equal(t, 1, int(testing.AllocsPerRun(100, func() { bytesSink, errSink = contiguous.MarshalText() })))
	require.Equal(t, 1, int(testing.AllocsPerRun(100, func() { bytesSink, errSink = nonContiguous.MarshalText() })))
}

// verifies that a valid IPv6 netip.Prefix converts into the network
// with the same address set, host bits cleared.
func Test_Network6FromPrefix_ConvertsValidPrefixes(t *testing.T) {
	cases := []struct {
		name   string
		prefix netip.Prefix
		want   xnetip.Network6
	}{
		{
			name:   "already masked /32",
			prefix: netip.MustParsePrefix("2001:db8::/32"),
			want:   xnetip.MustParseNetwork6("2001:db8::/32"),
		},
		{
			name:   "host bits cleared",
			prefix: netip.MustParsePrefix("2001:db8::1/32"),
			want:   xnetip.MustParseNetwork6("2001:db8::/32"),
		},
		{
			name:   "/0 is the zero value",
			prefix: netip.MustParsePrefix("::/0"),
			want:   xnetip.Network6{},
		},
		{
			name:   "host route /128",
			prefix: netip.MustParsePrefix("::1/128"),
			want:   xnetip.MustParseNetwork6("::1/128"),
		},
		{
			name:   "/64 run ends at the half boundary",
			prefix: netip.MustParsePrefix("2001:db8:1:2::/64"),
			want:   mustNetwork6(t, "2001:db8:1:2::", "ffff:ffff:ffff:ffff::"),
		},
		{
			name:   "unmasked PrefixFrom input",
			prefix: netip.PrefixFrom(netip.MustParseAddr("2001:db8::ff"), 120),
			want:   xnetip.MustParseNetwork6("2001:db8::/120"),
		},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			network, ok := xnetip.Network6FromPrefix(testCase.prefix)
			require.True(t, ok)
			require.Equal(t, testCase.want, network)
		})
	}
}

// verifies that an IPv4-mapped prefix is IPv6 here and converts into
// the mapped network, the netip family rule.
func Test_Network6FromPrefix_AcceptsIPv4MappedPrefix(t *testing.T) {
	network, ok := xnetip.Network6FromPrefix(netip.MustParsePrefix("::ffff:10.0.0.0/104"))
	require.True(t, ok)
	require.Equal(t, xnetip.MustParseNetwork6("::ffff:10.0.0.0/104"), network)
	require.True(t, network.IsIPv4MappedIPv6())
}

// verifies that the invalid zero prefix and a prefix whose address is
// Is4 are rejected.
func Test_Network6FromPrefix_RejectsInvalidAndForeignFamily(t *testing.T) {
	cases := []struct {
		name   string
		prefix netip.Prefix
	}{
		{name: "invalid zero prefix", prefix: netip.Prefix{}},
		{name: "IPv4 prefix", prefix: netip.MustParsePrefix("10.0.0.0/8")},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			network, ok := xnetip.Network6FromPrefix(testCase.prefix)
			require.False(t, ok)
			require.Equal(t, xnetip.Network6{}, network)
		})
	}
}

// verifies that a contiguous network converts to the already-masked
// netip.Prefix carrying the same address set.
func Test_Network6_Prefix_ContiguousForms(t *testing.T) {
	cases := []struct {
		name    string
		network xnetip.Network6
		want    netip.Prefix
	}{
		{
			name:    "/40",
			network: xnetip.MustParseNetwork6("2a02:6b8:c00::/40"),
			want:    netip.MustParsePrefix("2a02:6b8:c00::/40"),
		},
		{
			name:    "universe /0",
			network: xnetip.MustParseNetwork6("::/0"),
			want:    netip.MustParsePrefix("::/0"),
		},
		{
			name:    "host route /128 is a single IP",
			network: xnetip.MustParseNetwork6("::1/128"),
			want:    netip.MustParsePrefix("::1/128"),
		},
		{
			name:    "IPv4-mapped network stays IPv6",
			network: xnetip.MustParseNetwork6("::ffff:10.0.0.0/104"),
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
	singleIP, ok := xnetip.MustParseNetwork6("::1/128").Prefix()
	require.True(t, ok)
	require.True(t, singleIP.IsSingleIP())
}

// verifies that a non-contiguous mask has no prefix form and answers
// the invalid zero netip.Prefix, the hole straddling bit 64 included.
func Test_Network6_Prefix_NonContiguousHasNone(t *testing.T) {
	cases := []struct {
		name    string
		network xnetip.Network6
	}{
		{name: "two runs", network: xnetip.MustParseNetwork6("2001:db8::/ffff:ffff:ff00::ffff:ffff:0:0")},
		{name: "hole straddling bit 64", network: xnetip.MustParseNetwork6("2001:db8::/ffff:ffff:ffff:ff00:ff:ffff::")},
		{name: "alternating", network: xnetip.MustParseNetwork6("::/ffff:0:ffff:0:ffff:0:ffff:0")},
		{name: "single low bit", network: xnetip.MustParseNetwork6("::/::1")},
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
func Test_Network6FromPrefix_RoundTripProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		stdPrefix := genIPv6Prefix.Draw(t, "prefix")
		network, ok := xnetip.Network6FromPrefix(stdPrefix)
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
func Test_Network6_Prefix_SomeIffContiguousProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		network := genNetwork6.Draw(t, "network")
		prefix, ok := network.Prefix()
		require.Equal(t, network.IsContiguous(), ok)
		if !ok {
			require.Equal(t, netip.Prefix{}, prefix)
		}
	})
}

// verifies that a contiguous network survives the round trip through
// netip.Prefix unchanged.
func Test_Network6_Prefix_RoundTripProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		network := genNetwork6.Draw(t, "network")
		stdPrefix, ok := network.Prefix()
		if !ok {
			return
		}
		back, ok := xnetip.Network6FromPrefix(stdPrefix)
		require.True(t, ok)
		require.Equal(t, network, back)
	})
}

// verifies that the converted prefix length agrees with the network's
// own prefix length, the net/netip view of the same mask.
func Test_Network6_Prefix_BitsMatchPrefixLenProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		network := genNetwork6.Draw(t, "network")
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
func Test_Network6FromPrefix_AllocationFree(t *testing.T) {
	valid := netip.MustParsePrefix("2001:db8::/32")
	foreign := netip.MustParsePrefix("10.0.0.0/8")
	requireNoAllocs(t, func() { network6Sink, okSink = xnetip.Network6FromPrefix(valid) })
	requireNoAllocs(t, func() { network6Sink, okSink = xnetip.Network6FromPrefix(foreign) })
}

// verifies that converting out to a netip.Prefix allocates nothing,
// whatever the mask's shape.
func Test_Network6_Prefix_AllocationFree(t *testing.T) {
	contiguous := xnetip.MustParseNetwork6("2a02:6b8:c00::/40")
	nonContiguous := xnetip.MustParseNetwork6("2001:db8::/ffff:ffff:ff00::ffff:ffff:0:0")
	requireNoAllocs(t, func() { prefixSink, okSink = contiguous.Prefix() })
	requireNoAllocs(t, func() { prefixSink, okSink = nonContiguous.Prefix() })
}

// verifies that the greatest member of a contiguous network is the
// last address of its CIDR block, half-boundary lengths included.
func Test_Network6_LastAddr_ContiguousBlockEnd(t *testing.T) {
	cases := []struct {
		name    string
		network xnetip.Network6
		want    netip.Addr
	}{
		{name: "/96 fills the low 32 bits", network: xnetip.MustParseNetwork6("2001:db8:1::/96"), want: netip.MustParseAddr("2001:db8:1::ffff:ffff")},
		{name: "/40 fills across a group", network: xnetip.MustParseNetwork6("2a02:6b8:c00::/40"), want: netip.MustParseAddr("2a02:6b8:cff:ffff:ffff:ffff:ffff:ffff")},
		{name: "/32 fills six groups", network: xnetip.MustParseNetwork6("2a02:6b8::/32"), want: netip.MustParseAddr("2a02:6b8:ffff:ffff:ffff:ffff:ffff:ffff")},
		{name: "host route is its own last address", network: xnetip.MustParseNetwork6("2001:db8::1/128"), want: netip.MustParseAddr("2001:db8::1")},
		{name: "default route ends at all ones", network: xnetip.MustParseNetwork6("::/0"), want: netip.MustParseAddr("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff")},
		{name: "/64 fills exactly the low half", network: xnetip.MustParseNetwork6("2a02:6b8::/64"), want: netip.MustParseAddr("2a02:6b8::ffff:ffff:ffff:ffff")},
		{name: "/63 crosses the half boundary", network: xnetip.MustParseNetwork6("2001:db8::/63"), want: netip.MustParseAddr("2001:db8:0:1:ffff:ffff:ffff:ffff")},
		{name: "/65 starts below the half boundary", network: xnetip.MustParseNetwork6("2001:db8::/65"), want: netip.MustParseAddr("2001:db8:0:0:7fff:ffff:ffff:ffff")},
		{name: "zero value is the default route", network: xnetip.Network6{}, want: netip.MustParseAddr("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff")},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			require.Equal(t, testCase.want, testCase.network.LastAddr())
		})
	}
}

// verifies that a non-contiguous mask sets every host bit wherever the
// mask leaves a hole, in either half and at the half boundary.
func Test_Network6_LastAddr_NonContiguousMasks(t *testing.T) {
	cases := []struct {
		name    string
		network xnetip.Network6
		want    netip.Addr
	}{
		{name: "two-run mask fills both holes", network: mustNetwork6(t, "2a02:6b8:c00::1234:0:0", "ffff:ffff:ff00::ffff:ffff:0:0"), want: netip.MustParseAddr("2a02:6b8:cff:ffff:0:1234:ffff:ffff")},
		{name: "alternating mask fills the odd bits", network: mustNetwork6(t, "::", "aaaa:aaaa:aaaa:aaaa:aaaa:aaaa:aaaa:aaaa"), want: netip.MustParseAddr("5555:5555:5555:5555:5555:5555:5555:5555")},
		{name: "single host bit at the half boundary", network: mustNetwork6(t, "2001:db8::", "ffff:ffff:ffff:fffe:ffff:ffff:ffff:ffff"), want: netip.MustParseAddr("2001:db8:0:1::")},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			require.Equal(t, testCase.want, testCase.network.LastAddr())
		})
	}
}

// verifies that the result is a member of the network: masking it
// yields the network address again.
func Test_Network6_LastAddr_MemberProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		network := genNetwork6.Draw(t, "network")
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
func Test_Network6_LastAddr_MaximalByBruteForceProperty(t *testing.T) {
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
		network, err := xnetip.Network6From(
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
func Test_Network6_LastAddr_AtLeastAddrProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		network := genNetwork6.Draw(t, "network")
		require.GreaterOrEqual(t, network.LastAddr().Compare(network.Addr()), 0)
		fullMask := network.Mask() == netipAddrFrom6Bits(^uint64(0), ^uint64(0))
		require.Equal(t, fullMask, network.LastAddr() == network.Addr())
	})
}

// verifies that the last address is computed without allocating,
// whatever the mask's shape.
func Test_Network6_LastAddr_AllocationFree(t *testing.T) {
	contiguous := xnetip.MustParseNetwork6("2001:db8:1::/64")
	nonContiguous := xnetip.MustParseNetwork6("2a02:6b8:c00::1234:0:0/ffff:ffff:ff00::ffff:ffff:0:0")
	requireNoAllocs(t, func() { addrSink = contiguous.LastAddr() })
	requireNoAllocs(t, func() { addrSink = nonContiguous.LastAddr() })
}

// verifies that masks made of one leading run per 64-bit half are
// bi-contiguous, the fully contiguous and boundary shapes included.
func Test_Network6_IsBicontiguous_PerHalfLeadingRuns(t *testing.T) {
	cases := []struct {
		name    string
		network xnetip.Network6
		want    bool
	}{
		{name: "/40 by /32 classifier mask", network: xnetip.MustParseNetwork6("2a02:6b8:c00::1234:abcd:0:0/ffff:ffff:ff00::ffff:ffff:0:0"), want: true},
		{name: "/40 by /16 classifier mask", network: xnetip.MustParseNetwork6("2a02:6b8:c00::1234:0:0:0/ffff:ffff:ff00::ffff:0:0:0"), want: true},
		{name: "zero mask", network: xnetip.MustParseNetwork6("::/::"), want: true},
		{name: "all-ones mask of a host route", network: xnetip.MustParseNetwork6("::1"), want: true},
		{name: "lone bit at the top of the low half", network: mustNetwork6(t, "::", "::8000:0:0:0"), want: true},
		{name: "contiguous /40", network: xnetip.MustParseNetwork6("2a02:6b8:c00::/40"), want: true},
		{name: "contiguous /64", network: xnetip.MustParseNetwork6("2001:db8::/64"), want: true},
		{name: "contiguous /65", network: xnetip.MustParseNetwork6("2001:db8::/65"), want: true},
		{name: "lone bit at the very bottom", network: mustNetwork6(t, "::", "::1"), want: false},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			require.Equal(t, testCase.want, testCase.network.IsBicontiguous())
		})
	}
}

// verifies that a run ending inside a half breaks bi-contiguity while
// a mask living entirely in the low half keeps it.
func Test_Network6_IsBicontiguous_NonContiguousMasks(t *testing.T) {
	cases := []struct {
		name    string
		network xnetip.Network6
		want    bool
	}{
		{name: "hole inside the low half", network: xnetip.MustParseNetwork6("2a02:6b8:0:0:1234:5678::/ffff:ffff:0:0:f0f0:f0f0:f0f0:f0f0"), want: false},
		{name: "hole inside the high half", network: mustNetwork6(t, "::", "f0f0:f0f0:f0f0:f0f0::"), want: false},
		{name: "low run below the top of the low half", network: mustNetwork6(t, "::", "ffff:ffff:ffff:ffff:0:ffff::"), want: false},
		{name: "alternating mask", network: mustNetwork6(t, "::", "aaaa:aaaa:aaaa:aaaa:aaaa:aaaa:aaaa:aaaa"), want: false},
		{name: "low run in the middle under a full high half", network: mustNetwork6(t, "::", "ffff:ffff:ffff:ffff:00ff:ff00::"), want: false},
		{name: "empty high half with a full low half", network: mustNetwork6(t, "::", "::ffff:ffff:ffff:ffff"), want: true},
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
func Test_Network6_IsBicontiguous_MatchesReferenceProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		network := genNetwork6.Draw(t, "network")
		maskBytes := network.Mask().As16()
		maskHi := binary.BigEndian.Uint64(maskBytes[:8])
		maskLo := binary.BigEndian.Uint64(maskBytes[8:])
		require.Equal(t, referenceIsBicontiguous(maskHi, maskLo), network.IsBicontiguous())
	})
}

// verifies constructively that every product of a high-half prefix
// and a low-half prefix is bi-contiguous, by exhausting all pairs.
func Test_Network6_IsBicontiguous_AcceptsEveryPrefixPair(t *testing.T) {
	for hiPrefix := range 65 {
		for loPrefix := range 65 {
			network, err := xnetip.Network6From(
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
func Test_Network6_IsBicontiguous_ImpliedByContiguousProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		network := genNetwork6.Draw(t, "network")
		if network.IsContiguous() {
			require.True(t, network.IsBicontiguous())
		}
	})
}

// verifies that every draw of the bi-contiguous generator satisfies
// the predicate, whatever the address.
func Test_Network6_IsBicontiguous_GeneratorDrawsSatisfyProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		network := genIPv6BicontiguousNetwork.Draw(t, "network")
		require.True(t, network.IsBicontiguous())
	})
}

// verifies that the predicate allocates nothing on either outcome.
func Test_Network6_IsBicontiguous_AllocationFree(t *testing.T) {
	bicontiguous := xnetip.MustParseNetwork6("2a02:6b8:c00::1234:abcd:0:0/ffff:ffff:ff00::ffff:ffff:0:0")
	nonBicontiguous := mustNetwork6(t, "::", "f0f0:f0f0:f0f0:f0f0::")
	requireNoAllocs(t, func() { okSink = bicontiguous.IsBicontiguous() })
	requireNoAllocs(t, func() { okSink = nonBicontiguous.IsBicontiguous() })
}

func BenchmarkNetwork6_IsBicontiguous_Bicontiguous(b *testing.B) {
	network := xnetip.MustParseNetwork6("2a02:1a1:c00::1234:abcd:0:0/ffff:ffff:ff00::ffff:ffff:0:0")
	b.ReportAllocs()
	for b.Loop() {
		okSink = network.IsBicontiguous()
	}
}

func BenchmarkNetwork6_IsBicontiguous_NonBicontiguous(b *testing.B) {
	network := mustNetwork6(b, "f0f0:f0f0:f0f0:f0f0::", "f0f0:f0f0:f0f0:f0f0::")
	b.ReportAllocs()
	for b.Loop() {
		okSink = network.IsBicontiguous()
	}
}

// verifies that a contiguous network reports its mask's zero bits,
// the complement of the prefix length, half-boundary lengths included.
func Test_Network6_NumHostBits_ContiguousComplementsPrefix(t *testing.T) {
	cases := []struct {
		name    string
		network xnetip.Network6
		want    int
	}{
		{name: "default route frees the whole word", network: xnetip.MustParseNetwork6("::/0"), want: 128},
		{name: "/32", network: xnetip.MustParseNetwork6("2001:db8::/32"), want: 96},
		{name: "/64 frees exactly the low half", network: xnetip.MustParseNetwork6("2001:db8::/64"), want: 64},
		{name: "/63 crosses the half boundary", network: xnetip.MustParseNetwork6("2001:db8::/63"), want: 65},
		{name: "/65 starts below the half boundary", network: xnetip.MustParseNetwork6("2001:db8::/65"), want: 63},
		{name: "/127", network: xnetip.MustParseNetwork6("2001:db8::/127"), want: 1},
		{name: "host route holds one address", network: xnetip.MustParseNetwork6("2001:db8::1/128"), want: 0},
		{name: "zero value is the default route", network: xnetip.Network6{}, want: 128},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			require.Equal(t, testCase.want, testCase.network.NumHostBits())
		})
	}
}

// verifies that host bits are counted wherever the mask leaves them,
// in either half and across the half boundary.
func Test_Network6_NumHostBits_NonContiguousMasks(t *testing.T) {
	cases := []struct {
		name    string
		network xnetip.Network6
		want    int
	}{
		{name: "two-run classifier mask", network: xnetip.MustParseNetwork6("2a02:6b8:c00::1234:0:0/ffff:ffff:ff00::ffff:ffff:0:0"), want: 56},
		{name: "hole across the half boundary", network: mustNetwork6(t, "::", "ffff:ffff:ffff:0:0:ffff:ffff:ffff"), want: 32},
		{name: "alternating mask frees every other bit", network: mustNetwork6(t, "::", "aaaa:aaaa:aaaa:aaaa:aaaa:aaaa:aaaa:aaaa"), want: 64},
		{name: "single host bit at the half boundary", network: mustNetwork6(t, "::", "ffff:ffff:ffff:fffe:ffff:ffff:ffff:ffff"), want: 1},
		{name: "mask with one set bit", network: mustNetwork6(t, "::", "8000::"), want: 127},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			require.Equal(t, testCase.want, testCase.network.NumHostBits())
		})
	}
}

// verifies that the count agrees with a brute bit loop over the mask
// bytes.
func Test_Network6_NumHostBits_MatchesBitLoopProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		network := genNetwork6.Draw(t, "network")
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
func Test_Network6_NumHostBits_ComplementsPrefixLenProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		network := genNetwork6.Draw(t, "network")
		prefix, ok := network.PrefixLen()
		if !ok {
			return
		}
		require.Equal(t, 128-prefix, network.NumHostBits())
	})
}

// verifies that the count is zero exactly on the all-ones mask and
// the full width exactly on the zero mask.
func Test_Network6_NumHostBits_ExtremesMatchMaskProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		network := genNetwork6.Draw(t, "network")
		require.Equal(t, network.Mask() == netipAddrFrom6Bits(^uint64(0), ^uint64(0)), network.NumHostBits() == 0)
		require.Equal(t, network.Mask() == netipAddrFrom6Bits(0, 0), network.NumHostBits() == 128)
	})
}

// verifies that the count is computed without allocating, whatever
// the mask's shape.
func Test_Network6_NumHostBits_AllocationFree(t *testing.T) {
	contiguous := xnetip.MustParseNetwork6("2001:db8::/64")
	nonContiguous := xnetip.MustParseNetwork6("2a02:6b8:c00::1234:0:0/ffff:ffff:ff00::ffff:ffff:0:0")
	requireNoAllocs(t, func() { intSink = contiguous.NumHostBits() })
	requireNoAllocs(t, func() { intSink = nonContiguous.NumHostBits() })
}

// ipv6NetworkBits returns the network's address and mask as host-order
// 64-bit halves, the form the bit-level oracles compute in.
func ipv6NetworkBits(network xnetip.Network6) (addrHi, addrLo, maskHi, maskLo uint64) {
	addrBytes := network.Addr().As16()
	maskBytes := network.Mask().As16()
	addrHi = binary.BigEndian.Uint64(addrBytes[:8])
	addrLo = binary.BigEndian.Uint64(addrBytes[8:])
	maskHi = binary.BigEndian.Uint64(maskBytes[:8])
	maskLo = binary.BigEndian.Uint64(maskBytes[8:])
	return addrHi, addrLo, maskHi, maskLo
}

// verifies that a /120 yields its 256 addresses in ascending numeric
// order, each greater than the previous by exactly one.
//
// The suites for this sequence are forward-only: the interleaved
// front-and-back cases a double-ended cursor would pin have no
// iter.Seq analogue, so none appear here — the backward walk is a
// sequence of its own.
func Test_Network6_Addrs_Slash120AscendsByOne(t *testing.T) {
	network := xnetip.MustParseNetwork6("2a02:6b8:c00::1234:0:0/120")
	expected := netip.MustParseAddr("2a02:6b8:c00::1234:0:0")
	count := 0
	for addr := range network.Addrs() {
		require.Equal(t, expected, addr)
		expected = expected.Next()
		count++
	}
	require.Equal(t, 256, count)
}

// verifies that a host route yields exactly its single address.
func Test_Network6_Addrs_HostRouteSingle(t *testing.T) {
	network := xnetip.MustParseNetwork6("::1/128")
	collected := slices.Collect(network.Addrs())
	require.Equal(t, []netip.Addr{netip.MustParseAddr("::1")}, collected)
}

// verifies that the default route starts at the unspecified address
// and steps to its successor: the head of the 2^128-item sequence.
func Test_Network6_Addrs_UniverseHead(t *testing.T) {
	network := xnetip.MustParseNetwork6("::/0")
	head := collectHead(network.Addrs(), 2)
	require.Equal(t, []netip.Addr{
		netip.MustParseAddr("::"),
		netip.MustParseAddr("::1"),
	}, head)
}

// verifies that a non-contiguous sequence starts at the network
// address, ends at the last address and never repeats an item.
func Test_Network6_Addrs_NonContiguousFirstAndLast(t *testing.T) {
	network := xnetip.MustParseNetwork6("2a02:6b8:c00::1234:0:0/ffff:ffff:ff00:ffff:ffff:ffff:ffff:ffff")
	collected := slices.Collect(network.Addrs())
	require.Len(t, collected, 256)
	require.Equal(t, network.Addr(), collected[0])
	require.Equal(t, network.LastAddr(), collected[255])
	seen := map[netip.Addr]bool{}
	for _, addr := range collected {
		require.False(t, seen[addr], "address repeated: %v", addr)
		seen[addr] = true
	}
}

// verifies the head of a 96-host-bit network against the host-index
// oracle.
//
// The host run spans positions 16 through 111, far beyond what a
// drain can cover, so only the first three items are probed.
func Test_Network6_Addrs_WideHeadOnly(t *testing.T) {
	network := xnetip.MustParseNetwork6("2001::1/ffff::ffff")
	head := collectHead(network.Addrs(), 3)
	require.Equal(t, []netip.Addr{
		addr6AtHostIndexReference(network, 0),
		addr6AtHostIndexReference(network, 1),
		addr6AtHostIndexReference(network, 2),
	}, head)
	require.Equal(t, network.Addr(), head[0])
}

// verifies that stepping out of a fully drained low host run carries
// across bit 64 into the high half.
//
// The mask frees positions 0 through 15 and position 64, so item
// 65536 must flip the high half's lowest bit and clear the low run
// in one step.
func Test_Network6_Addrs_CarryAcrossBit64(t *testing.T) {
	network := xnetip.MustParseNetwork6("2001:db8::/ffff:ffff:ffff:fffe:ffff:ffff:ffff:0000")
	head := collectHead(network.Addrs(), 65538)
	require.Len(t, head, 65538)
	require.Equal(t, netip.MustParseAddr("2001:db8::"), head[0])
	require.Equal(t, netip.MustParseAddr("2001:db8::ffff"), head[65535])
	require.Equal(t, netip.MustParseAddr("2001:db8:0:1::"), head[65536])
	require.Equal(t, netip.MustParseAddr("2001:db8:0:1::1"), head[65537])
}

// verifies that breaking out of the loop stops the sequence after
// exactly the consumed items.
func Test_Network6_Addrs_EarlyBreakStops(t *testing.T) {
	network := xnetip.MustParseNetwork6("2a02:6b8:c00::1234:0:0/120")
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
func Test_Network6_Addrs_ReIterable(t *testing.T) {
	network := xnetip.MustParseNetwork6("2a02:6b8:c00::1234:0:0/ffff:ffff:ff00:ffff:ffff:ffff:ffff:ffff")
	sequence := network.Addrs()
	first := slices.Collect(sequence)
	second := slices.Collect(sequence)
	require.Equal(t, first, second)
}

// verifies that a mask freeing the third group's low byte yields, as
// a set, the grid of addresses ranging over exactly that byte.
func Test_Network6_Addrs_NonContiguousGrid(t *testing.T) {
	network := xnetip.MustParseNetwork6("2a02:6b8:c00::1/ffff:ffff:ff00:ffff:ffff:ffff:ffff:ffff")
	expected := make([]netip.Addr, 0, 256)
	for value := range 256 {
		expected = append(expected, netipAddrFrom6Bits(
			0x2a02_06b8_0000_0000|uint64(0x0c00|value)<<16,
			1,
		))
	}
	actual := slices.Collect(network.Addrs())
	slices.SortFunc(expected, netip.Addr.Compare)
	slices.SortFunc(actual, netip.Addr.Compare)
	require.Equal(t, expected, actual)
}

// verifies the exact forward order of a two-run host mask.
//
// The host bits sit at positions 12 through 15 and 80 through 83, so
// index bits 0 through 3 fill the lower run and index bits 4 through
// 7 the upper one.
func Test_Network6_Addrs_NonContiguousPinnedTwoRunOrder(t *testing.T) {
	network := xnetip.MustParseNetwork6("2001:db8::1/ffff:ffff:fff0:ffff:ffff:ffff:ffff:0fff")
	expected := make([]netip.Addr, 0, 256)
	for value := range 256 {
		expected = append(expected, netipAddrFrom6Bits(
			0x2001_0db8_0000_0000|uint64(value>>4)<<16,
			uint64(1|(value&0xf)<<12),
		))
	}
	require.Equal(t, expected, slices.Collect(network.Addrs()))
}

// verifies the order of four host bits in a non-contiguous position:
// the sequence steps through the second-lowest nibble alone.
func Test_Network6_Addrs_FourHostBitsAboveLowestNibble(t *testing.T) {
	network := xnetip.MustParseNetwork6("2001:db8::/ffff:ffff:ffff:ffff:ffff:ffff:ffff:ff0f")
	expected := make([]netip.Addr, 0, 16)
	for value := range 16 {
		expected = append(expected, netipAddrFrom6Bits(0x2001_0db8_0000_0000, uint64(value)<<4))
	}
	require.Equal(t, expected, slices.Collect(network.Addrs()))
}

// verifies on the alternating mask that the two lowest host bits fill
// first: indices 0 through 3 map to host patterns 0, 1, 4, 5.
func Test_Network6_Addrs_AlternatingMask(t *testing.T) {
	network := xnetip.MustParseNetwork6("::/aaaa:aaaa:aaaa:aaaa:aaaa:aaaa:aaaa:aaaa")
	head := collectHead(network.Addrs(), 4)
	require.Equal(t, []netip.Addr{
		netip.MustParseAddr("::"),
		netip.MustParseAddr("::1"),
		netip.MustParseAddr("::4"),
		netip.MustParseAddr("::5"),
	}, head)
}

// verifies that the head of the sequence matches the host-index
// oracle.
//
// The address at index k is the network address with k deposited
// into the mask's zero bits, least significant first.
func Test_Network6_Addrs_HeadMatchesHostIndexOracleProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		network := genNetwork6.Draw(t, "network")
		take := uint64(32)
		if hostBits := network.NumHostBits(); hostBits < 6 {
			take = uint64(1) << hostBits
		}
		index := uint64(0)
		for addr := range network.Addrs() {
			require.Equal(t, addr6AtHostIndexReference(network, index), addr)
			index++
			if index == take {
				break
			}
		}
		require.Equal(t, take, index)
	})
}

// addr6AtHostIndexReference returns the address the sequence must
// yield at the given host index.
//
// That address is the network address with the index deposited into
// the mask's zero bits, least significant first, computed by an
// obviously correct walk over all 128 bit positions.
func addr6AtHostIndexReference(network xnetip.Network6, index uint64) netip.Addr {
	addrHi, addrLo, maskHi, maskLo := ipv6NetworkBits(network)
	var depositedHi, depositedLo uint64
	for position := range 128 {
		var hostBit bool
		if position < 64 {
			hostBit = maskLo>>position&1 == 0
		} else {
			hostBit = maskHi>>(position-64)&1 == 0
		}
		if !hostBit {
			continue
		}
		if index&1 == 1 {
			if position < 64 {
				depositedLo |= uint64(1) << position
			} else {
				depositedHi |= uint64(1) << (position - 64)
			}
		}
		index >>= 1
	}
	return netipAddrFrom6Bits(addrHi|depositedHi, addrLo|depositedLo)
}

// verifies on bounded spaces that the yielded count is exactly two to
// the number of host bits.
func Test_Network6_Addrs_CountMatchesHostBitsProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		network := drawBoundedNetwork6(t, 16)
		count := 0
		for range network.Addrs() {
			count++
		}
		require.Equal(t, 1<<network.NumHostBits(), count)
	})
}

// drawBoundedNetwork6 draws a network whose mask clears at most
// maxHostBits chosen positions.
//
// The bounded host space keeps a full drain of the membership cheap
// enough for a property test, while the cleared positions still range
// over the whole word, the half boundary included.
func drawBoundedNetwork6(t *rapid.T, maxHostBits int) xnetip.Network6 {
	hostBits := rapid.IntRange(0, maxHostBits).Draw(t, "host bits")
	positions := rapid.SliceOfNDistinct(rapid.IntRange(0, 127), hostBits, hostBits, rapid.ID).Draw(t, "host positions")
	maskHi, maskLo := ^uint64(0), ^uint64(0)
	for _, position := range positions {
		if position < 64 {
			maskLo &^= uint64(1) << position
		} else {
			maskHi &^= uint64(1) << (position - 64)
		}
	}
	network, err := xnetip.Network6From(genNetipAddr6.Draw(t, "addr"), netipAddrFrom6Bits(maskHi, maskLo))
	require.NoError(t, err)
	return network
}

// verifies on bounded spaces that every yielded address is a member
// of the network by the bit test and that no address repeats.
func Test_Network6_Addrs_MembershipAndUniquenessProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		network := drawBoundedNetwork6(t, 12)
		addrHi, addrLo, maskHi, maskLo := ipv6NetworkBits(network)
		seen := map[netip.Addr]bool{}
		for addr := range network.Addrs() {
			addrBytes := addr.As16()
			memberHi := binary.BigEndian.Uint64(addrBytes[:8])
			memberLo := binary.BigEndian.Uint64(addrBytes[8:])
			require.Equal(t, addrHi, memberHi&maskHi)
			require.Equal(t, addrLo, memberLo&maskLo)
			require.False(t, seen[addr], "address repeated")
			seen[addr] = true
		}
		require.Len(t, seen, 1<<network.NumHostBits())
	})
}

// verifies that a contiguous network's sequence ascends strictly from
// the network address to the last address.
func Test_Network6_Addrs_ContiguousAscendsProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		prefixBits := rapid.IntRange(112, 128).Draw(t, "bits")
		network, err := xnetip.Network6FromCIDR(genNetipAddr6.Draw(t, "addr"), prefixBits)
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

// verifies that mapping an IPv4 network preserves its sequence.
//
// The mapped network must yield the IPv4-mapped form of every IPv4
// address in the same order, which pins the same control flow in
// both families.
func Test_Network6_Addrs_MatchesMappedIPv4SequenceProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		network := drawBoundedNetwork4(t, 12)
		expected := []netip.Addr{}
		for addr := range network.Addrs() {
			expected = append(expected, netip.AddrFrom16(addr.As16()))
		}
		require.Equal(t, expected, slices.Collect(network.ToIPv6Mapped().Addrs()))
	})
}

// verifies against net/netip that a contiguous sequence equals
// repeated successor steps from the network address onward.
func Test_Network6_Addrs_MatchesNetipNextDifferential(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		prefixBits := rapid.IntRange(116, 128).Draw(t, "bits")
		network, err := xnetip.Network6FromCIDR(genNetipAddr6.Draw(t, "addr"), prefixBits)
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
func Test_Network6_Addrs_AllocationFree(t *testing.T) {
	contiguous := xnetip.MustParseNetwork6("2a02:6b8:c00::1234:0:0/120")
	nonContiguous := xnetip.MustParseNetwork6("2a02:6b8:c00::1234:0:0/ffff:ffff:ff00:ffff:ffff:ffff:ffff:ffff")
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

func BenchmarkNetwork6_Addrs_Slash120(b *testing.B) {
	network := xnetip.MustParseNetwork6("2a02:6b8:c00::1234:0:0/120")
	b.ReportAllocs()
	for b.Loop() {
		for addr := range network.Addrs() {
			addrSink = addr
		}
	}
}

func BenchmarkNetwork6_Addrs_Slash112(b *testing.B) {
	network := xnetip.MustParseNetwork6("2a02:6b8:c00::1234:0:0/112")
	b.ReportAllocs()
	for b.Loop() {
		for addr := range network.Addrs() {
			addrSink = addr
		}
	}
}

func BenchmarkNetwork6_Addrs_NonContiguous8HostBits(b *testing.B) {
	network := xnetip.MustParseNetwork6("2a02:6b8:c00::1234:0:0/ffff:ffff:ff00:ffff:ffff:ffff:ffff:ffff")
	b.ReportAllocs()
	for b.Loop() {
		for addr := range network.Addrs() {
			addrSink = addr
		}
	}
}

// verifies that a /120 yields its 256 addresses in descending numeric
// order, each smaller than the previous by exactly one.
func Test_Network6_AddrsBackward_Slash120DescendsByOne(t *testing.T) {
	network := xnetip.MustParseNetwork6("2a02:6b8:c00::1234:0:0/120")
	expected := netip.MustParseAddr("2a02:6b8:c00::1234:0:ff")
	count := 0
	for addr := range network.AddrsBackward() {
		require.Equal(t, expected, addr)
		expected = expected.Prev()
		count++
	}
	require.Equal(t, 256, count)
	require.Equal(t, netip.MustParseAddr("2a02:6b8:c00::1234:0:0"), expected.Next())
}

// verifies that a host route yields exactly its single address.
func Test_Network6_AddrsBackward_HostRouteSingle(t *testing.T) {
	network := xnetip.MustParseNetwork6("::1/128")
	collected := slices.Collect(network.AddrsBackward())
	require.Equal(t, []netip.Addr{netip.MustParseAddr("::1")}, collected)
}

// verifies that the default route starts at the all-ones address and
// steps to its predecessor: the head of the 2^128-item sequence.
func Test_Network6_AddrsBackward_UniverseHead(t *testing.T) {
	network := xnetip.MustParseNetwork6("::/0")
	head := collectHead(network.AddrsBackward(), 2)
	require.Equal(t, []netip.Addr{
		netip.MustParseAddr("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"),
		netip.MustParseAddr("ffff:ffff:ffff:ffff:ffff:ffff:ffff:fffe"),
	}, head)
}

// verifies that a non-contiguous sequence starts at the last address,
// ends at the network address and never repeats an item.
func Test_Network6_AddrsBackward_StartsAtLastAddr(t *testing.T) {
	network := xnetip.MustParseNetwork6("2a02:6b8:c00::1234:0:0/ffff:ffff:ff00:ffff:ffff:ffff:ffff:ffff")
	collected := slices.Collect(network.AddrsBackward())
	require.Len(t, collected, 256)
	require.Equal(t, network.LastAddr(), collected[0])
	require.Equal(t, network.Addr(), collected[255])
	seen := map[netip.Addr]bool{}
	for _, addr := range collected {
		require.False(t, seen[addr], "address repeated: %v", addr)
		seen[addr] = true
	}
}

// verifies the head of a 96-host-bit network against the backward
// step oracle.
//
// The host run spans positions 16 through 111, far beyond what a
// drain can cover, so only the first three items are probed: the
// all-ones host pattern, then the borrow clearing one and two of
// the run's lowest bits.
func Test_Network6_AddrsBackward_WideHeadOnly(t *testing.T) {
	network := xnetip.MustParseNetwork6("2001::1/ffff::ffff")
	head := collectHead(network.AddrsBackward(), 3)
	require.Equal(t, []netip.Addr{
		addr6AtBackwardStepReference(network, 0),
		addr6AtBackwardStepReference(network, 1),
		addr6AtBackwardStepReference(network, 2),
	}, head)
	require.Equal(t, []netip.Addr{
		netip.MustParseAddr("2001:ffff:ffff:ffff:ffff:ffff:ffff:1"),
		netip.MustParseAddr("2001:ffff:ffff:ffff:ffff:ffff:fffe:1"),
		netip.MustParseAddr("2001:ffff:ffff:ffff:ffff:ffff:fffd:1"),
	}, head)
	require.Equal(t, network.LastAddr(), head[0])
}

// verifies that draining the freed bit above the half boundary
// borrows across bit 64 into the low host run.
//
// The mask frees positions 0 through 15 and position 64, so the
// step after the item carrying only the freed high bit must clear
// it and set the whole low run in one borrow.
func Test_Network6_AddrsBackward_BorrowAcrossBit64(t *testing.T) {
	network := xnetip.MustParseNetwork6("2001:db8::/ffff:ffff:ffff:fffe:ffff:ffff:ffff:0000")
	head := collectHead(network.AddrsBackward(), 65537)
	require.Len(t, head, 65537)
	require.Equal(t, netip.MustParseAddr("2001:db8:0:1::ffff"), head[0])
	require.Equal(t, netip.MustParseAddr("2001:db8:0:1::"), head[65535])
	require.Equal(t, netip.MustParseAddr("2001:db8::ffff"), head[65536])
}

// verifies that breaking out of the loop stops the sequence after
// exactly the consumed items.
func Test_Network6_AddrsBackward_EarlyBreakStops(t *testing.T) {
	network := xnetip.MustParseNetwork6("2a02:6b8:c00::1234:0:0/120")
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
func Test_Network6_AddrsBackward_ReIterable(t *testing.T) {
	network := xnetip.MustParseNetwork6("2a02:6b8:c00::1234:0:0/ffff:ffff:ff00:ffff:ffff:ffff:ffff:ffff")
	sequence := network.AddrsBackward()
	first := slices.Collect(sequence)
	second := slices.Collect(sequence)
	require.Equal(t, first, second)
}

// verifies the exact reverse order of a two-run host mask.
//
// The host bits sit at positions 12 through 15 and 80 through 83, so
// descending host indices drain the upper run's value first and step
// the lower run down within each of its values.
func Test_Network6_AddrsBackward_NonContiguousPinnedTwoRunReverseOrder(t *testing.T) {
	network := xnetip.MustParseNetwork6("2001:db8::1/ffff:ffff:fff0:ffff:ffff:ffff:ffff:0fff")
	expected := make([]netip.Addr, 0, 256)
	for value := range 256 {
		index := 255 - value
		expected = append(expected, netipAddrFrom6Bits(
			0x2001_0db8_0000_0000|uint64(index>>4)<<16,
			uint64(1|(index&0xf)<<12),
		))
	}
	require.Equal(t, expected, slices.Collect(network.AddrsBackward()))
}

// verifies that four non-contiguous host bits drain by stepping
// down through the second-lowest nibble alone.
func Test_Network6_AddrsBackward_FourHostBitsAboveLowestNibble(t *testing.T) {
	network := xnetip.MustParseNetwork6("2001:db8::/ffff:ffff:ffff:ffff:ffff:ffff:ffff:ff0f")
	expected := make([]netip.Addr, 0, 16)
	for value := range 16 {
		expected = append(expected, netipAddrFrom6Bits(0x2001_0db8_0000_0000, uint64(15-value)<<4))
	}
	require.Equal(t, expected, slices.Collect(network.AddrsBackward()))
}

// verifies on the alternating mask that the two lowest host bits
// drain first: the borrow clears bit 0, then moves to bit 2.
func Test_Network6_AddrsBackward_AlternatingMaskHead(t *testing.T) {
	network := xnetip.MustParseNetwork6("::/aaaa:aaaa:aaaa:aaaa:aaaa:aaaa:aaaa:aaaa")
	head := collectHead(network.AddrsBackward(), 3)
	require.Equal(t, []netip.Addr{
		netip.MustParseAddr("5555:5555:5555:5555:5555:5555:5555:5555"),
		netip.MustParseAddr("5555:5555:5555:5555:5555:5555:5555:5554"),
		netip.MustParseAddr("5555:5555:5555:5555:5555:5555:5555:5551"),
	}, head)
}

// verifies on bounded spaces that the backward sequence is exactly
// the reverse of the forward one, whatever the mask's shape.
func Test_Network6_AddrsBackward_ExactReverseOfAddrsProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		network := drawBoundedNetwork6(t, 16)
		expected := slices.Collect(network.Addrs())
		slices.Reverse(expected)
		require.Equal(t, expected, slices.Collect(network.AddrsBackward()))
	})
}

// verifies that the head of the sequence matches the backward step
// oracle for every generated network.
func Test_Network6_AddrsBackward_HeadMatchesHostIndexOracleProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		network := genNetwork6.Draw(t, "network")
		take := uint64(32)
		if hostBits := network.NumHostBits(); hostBits < 6 {
			take = uint64(1) << hostBits
		}
		step := uint64(0)
		for addr := range network.AddrsBackward() {
			require.Equal(t, addr6AtBackwardStepReference(network, step), addr)
			step++
			if step == take {
				break
			}
		}
		require.Equal(t, take, step)
	})
}

// addr6AtBackwardStepReference returns the address the backward
// sequence must yield at the given step.
//
// The item at a backward step sits at the host index that many
// places before the last one, and subtracting from the all-ones
// index is bitwise complement, so the address is the network address
// with the complement of the step deposited into the mask's zero
// bits, least significant first. Valid while the step stays below
// the network's address count.
func addr6AtBackwardStepReference(network xnetip.Network6, step uint64) netip.Addr {
	addrHi, addrLo, maskHi, maskLo := ipv6NetworkBits(network)
	var depositedHi, depositedLo uint64
	for position := range 128 {
		var hostBit bool
		if position < 64 {
			hostBit = maskLo>>position&1 == 0
		} else {
			hostBit = maskHi>>(position-64)&1 == 0
		}
		if !hostBit {
			continue
		}
		if step&1 == 0 {
			if position < 64 {
				depositedLo |= uint64(1) << position
			} else {
				depositedHi |= uint64(1) << (position - 64)
			}
		}
		step >>= 1
	}
	return netipAddrFrom6Bits(addrHi|depositedHi, addrLo|depositedLo)
}

// verifies that the first yielded address is the last address for
// every generated network.
func Test_Network6_AddrsBackward_FirstIsLastAddrProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		network := genNetwork6.Draw(t, "network")
		head := collectHead(network.AddrsBackward(), 1)
		require.Equal(t, []netip.Addr{network.LastAddr()}, head)
	})
}

// verifies that mapping an IPv4 network preserves its backward
// sequence.
//
// The mapped network must yield the IPv4-mapped form of every IPv4
// address in the same order, which pins the same control flow in
// both families.
func Test_Network6_AddrsBackward_MatchesMappedIPv4SequenceProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		network := drawBoundedNetwork4(t, 12)
		expected := []netip.Addr{}
		for addr := range network.AddrsBackward() {
			expected = append(expected, netip.AddrFrom16(addr.As16()))
		}
		require.Equal(t, expected, slices.Collect(network.ToIPv6Mapped().AddrsBackward()))
	})
}

// verifies against net/netip that a contiguous backward sequence
// equals repeated predecessor steps from the last address onward.
func Test_Network6_AddrsBackward_MatchesNetipPrevDifferential(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		prefixBits := rapid.IntRange(116, 128).Draw(t, "bits")
		network, err := xnetip.Network6FromCIDR(genNetipAddr6.Draw(t, "addr"), prefixBits)
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
func Test_Network6_AddrsBackward_AllocationFree(t *testing.T) {
	contiguous := xnetip.MustParseNetwork6("2a02:6b8:c00::1234:0:0/120")
	nonContiguous := xnetip.MustParseNetwork6("2a02:6b8:c00::1234:0:0/ffff:ffff:ff00:ffff:ffff:ffff:ffff:ffff")
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

func BenchmarkNetwork6_AddrsBackward_Slash120(b *testing.B) {
	network := xnetip.MustParseNetwork6("2a02:6b8:c00::1234:0:0/120")
	b.ReportAllocs()
	for b.Loop() {
		for addr := range network.AddrsBackward() {
			addrSink = addr
		}
	}
}

func BenchmarkNetwork6_AddrsBackward_Slash112(b *testing.B) {
	network := xnetip.MustParseNetwork6("2a02:6b8:c00::1234:0:0/112")
	b.ReportAllocs()
	for b.Loop() {
		for addr := range network.AddrsBackward() {
			addrSink = addr
		}
	}
}

func BenchmarkNetwork6_AddrsBackward_NonContiguous8HostBits(b *testing.B) {
	network := xnetip.MustParseNetwork6("2a02:6b8:c00::1234:0:0/ffff:ffff:ff00:ffff:ffff:ffff:ffff:ffff")
	b.ReportAllocs()
	for b.Loop() {
		for addr := range network.AddrsBackward() {
			addrSink = addr
		}
	}
}

// mergeReferenceIPv6 is the simple merge oracle.
//
// Equal networks merge to themselves, equal-mask single-bit siblings
// drop the differing bit through the adjacency predicate, and
// containment either way returns the container.
func mergeReferenceIPv6(t require.TestingT, left, right xnetip.Network6) (xnetip.Network6, bool) {
	if left == right {
		return left, true
	}
	if left.Mask() == right.Mask() {
		if !left.IsAdjacent(right) {
			return xnetip.Network6{}, false
		}
		leftAddrHi, leftAddrLo, leftMaskHi, leftMaskLo := ipv6NetworkBits(left)
		rightAddrHi, rightAddrLo, _, _ := ipv6NetworkBits(right)
		maskHi := leftMaskHi ^ (leftAddrHi ^ rightAddrHi)
		maskLo := leftMaskLo ^ (leftAddrLo ^ rightAddrLo)
		merged, err := xnetip.Network6From(
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
	return xnetip.Network6{}, false
}

// verifies that merging succeeds exactly for duplicates, single-bit
// siblings and containment, and returns the union network.
//
// The half-boundary rows pin the single-bit test and the xor across
// bit 64, where the difference or the reduced mask crosses the
// 64-bit halves of the word.
func Test_Network6_Merge_UnitAndBoundary(t *testing.T) {
	cases := []struct {
		name  string
		left  xnetip.Network6
		right xnetip.Network6
		want  xnetip.Network6
		ok    bool
	}{
		{name: "identical", left: xnetip.MustParseNetwork6("2001:db8::/48"), right: xnetip.MustParseNetwork6("2001:db8::/48"), want: xnetip.MustParseNetwork6("2001:db8::/48"), ok: true},
		{name: "contiguous siblings", left: xnetip.MustParseNetwork6("2001:db8::/48"), right: xnetip.MustParseNetwork6("2001:db8:1::/48"), want: xnetip.MustParseNetwork6("2001:db8::/47"), ok: true},
		{name: "contiguous siblings reversed", left: xnetip.MustParseNetwork6("2001:db8:1::/48"), right: xnetip.MustParseNetwork6("2001:db8::/48"), want: xnetip.MustParseNetwork6("2001:db8::/47"), ok: true},
		{name: "containment returns the container", left: xnetip.MustParseNetwork6("2001:db8::/32"), right: xnetip.MustParseNetwork6("2001:db8:1::/48"), want: xnetip.MustParseNetwork6("2001:db8::/32"), ok: true},
		{name: "containment reversed", left: xnetip.MustParseNetwork6("2001:db8:1::/48"), right: xnetip.MustParseNetwork6("2001:db8::/32"), want: xnetip.MustParseNetwork6("2001:db8::/32"), ok: true},
		{name: "same mask, two differing bits", left: xnetip.MustParseNetwork6("2001:db8::/48"), right: xnetip.MustParseNetwork6("2001:db8:5::/48"), ok: false},
		{name: "comparable masks, address mismatch", left: xnetip.MustParseNetwork6("2001:db8::/32"), right: xnetip.MustParseNetwork6("2001:beef:1::/48"), ok: false},
		{name: "comparable masks, address mismatch reversed", left: xnetip.MustParseNetwork6("2001:beef:1::/48"), right: xnetip.MustParseNetwork6("2001:db8::/32"), ok: false},
		{name: "/64 siblings at bit 64", left: xnetip.MustParseNetwork6("2001:db8:0:0::/64"), right: xnetip.MustParseNetwork6("2001:db8:0:1::/64"), want: xnetip.MustParseNetwork6("2001:db8::/63"), ok: true},
		{name: "/65 siblings at bit 63", left: xnetip.MustParseNetwork6("2001:db8::/65"), right: xnetip.MustParseNetwork6("2001:db8:0:0:8000::/65"), want: xnetip.MustParseNetwork6("2001:db8::/64"), ok: true},
		{name: "/65 siblings at bit 64 give a non-contiguous mask", left: xnetip.MustParseNetwork6("2001:db8::/65"), right: xnetip.MustParseNetwork6("2001:db8:0:1::/65"), want: xnetip.MustParseNetwork6("2001:db8::/ffff:ffff:ffff:fffe:8000::"), ok: true},
		{name: "host routes differing in bit 0", left: xnetip.MustParseNetwork6("2001:db8::/128"), right: xnetip.MustParseNetwork6("2001:db8::1/128"), want: xnetip.MustParseNetwork6("2001:db8::/127"), ok: true},
		{name: "default route absorbs any network", left: xnetip.MustParseNetwork6("::/0"), right: xnetip.MustParseNetwork6("2001:db8::/32"), want: xnetip.MustParseNetwork6("::/0"), ok: true},
		{name: "top-bit siblings give the default route", left: xnetip.MustParseNetwork6("::/1"), right: xnetip.MustParseNetwork6("8000::/1"), want: xnetip.MustParseNetwork6("::/0"), ok: true},
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
func Test_Network6_Merge_NonContiguousMasks(t *testing.T) {
	cases := []struct {
		name  string
		left  xnetip.Network6
		right xnetip.Network6
		want  xnetip.Network6
		ok    bool
	}{
		{name: "pattern siblings at bit 104", left: xnetip.MustParseNetwork6("2001::1/ffff:ff00::ffff"), right: xnetip.MustParseNetwork6("2001:100::1/ffff:ff00::ffff"), want: xnetip.MustParseNetwork6("2001::1/ffff:fe00::ffff"), ok: true},
		{name: "pattern siblings at bit 104 reversed", left: xnetip.MustParseNetwork6("2001:100::1/ffff:ff00::ffff"), right: xnetip.MustParseNetwork6("2001::1/ffff:ff00::ffff"), want: xnetip.MustParseNetwork6("2001::1/ffff:fe00::ffff"), ok: true},
		{name: "pattern with two differing bits", left: xnetip.MustParseNetwork6("2001::1/ffff:ff00::ffff"), right: xnetip.MustParseNetwork6("2001:300::1/ffff:ff00::ffff"), ok: false},
		{name: "two-run siblings in the low run", left: xnetip.MustParseNetwork6("2a02:6b8:c00::1234:0:0/ffff:ffff:ff00::ffff:ffff:0:0"), right: xnetip.MustParseNetwork6("2a02:6b8:c00::1235:0:0/ffff:ffff:ff00::ffff:ffff:0:0"), want: xnetip.MustParseNetwork6("2a02:6b8:c00::1234:0:0/ffff:ffff:ff00::ffff:fffe:0:0"), ok: true},
		{name: "incomparable non-contiguous masks", left: xnetip.MustParseNetwork6("2001:db8::1/ffff:0:ffff::"), right: xnetip.MustParseNetwork6("2001:db8::1/0:ffff:ffff::"), ok: false},
		{name: "two-run mask contains a contiguous block", left: xnetip.MustParseNetwork6("2a02:6b8::5:6:0:0/ffff:ffff::ffff:ffff:0:0"), right: xnetip.MustParseNetwork6("2a02:6b8:1:2:5:6::/96"), want: xnetip.MustParseNetwork6("2a02:6b8::5:6:0:0/ffff:ffff::ffff:ffff:0:0"), ok: true},
		{name: "two-run mask contains a contiguous block reversed", left: xnetip.MustParseNetwork6("2a02:6b8:1:2:5:6::/96"), right: xnetip.MustParseNetwork6("2a02:6b8::5:6:0:0/ffff:ffff::ffff:ffff:0:0"), want: xnetip.MustParseNetwork6("2a02:6b8::5:6:0:0/ffff:ffff::ffff:ffff:0:0"), ok: true},
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
func Test_Network6_Merge_ReferenceFixedCases(t *testing.T) {
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
		left := xnetip.MustParseNetwork6(pair[0])
		right := xnetip.MustParseNetwork6(pair[1])
		wantNetwork, wantOK := mergeReferenceIPv6(t, left, right)
		merged, ok := left.Merge(right)
		require.Equal(t, wantOK, ok, "pair %v", pair)
		require.Equal(t, wantNetwork, merged, "pair %v", pair)
	}
}

// verifies that merging agrees with the simple oracle on random pairs.
func Test_Network6_Merge_MatchesReferenceProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		left := genNetwork6.Draw(t, "left")
		right := genNetwork6.Draw(t, "right")
		wantNetwork, wantOK := mergeReferenceIPv6(t, left, right)
		merged, ok := left.Merge(right)
		require.Equal(t, wantOK, ok)
		require.Equal(t, wantNetwork, merged)
	})
}

// verifies that merging is commutative in both the value and the flag.
func Test_Network6_Merge_CommutativityProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		left := genNetwork6.Draw(t, "left")
		right := genNetwork6.Draw(t, "right")
		leftMerged, leftOK := left.Merge(right)
		rightMerged, rightOK := right.Merge(left)
		require.Equal(t, leftOK, rightOK)
		require.Equal(t, leftMerged, rightMerged)
	})
}

// verifies that a network merged with itself is itself: aggregation
// leans on this path to absorb duplicates.
func Test_Network6_Merge_SelfIsSelfProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		network := genNetwork6.Draw(t, "network")
		merged, ok := network.Merge(network)
		require.True(t, ok)
		require.Equal(t, network, merged)
	})
}

// verifies that a successful merge contains both inputs and returns a
// normalized network.
func Test_Network6_Merge_ResultContainsBothAndNormalizedProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		left := genNetwork6.Draw(t, "left")
		right := genNetwork6.Draw(t, "right")
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
func Test_Network6_Merge_MembershipBruteForceProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		leftAddr := uint64(rapid.IntRange(0, 255).Draw(t, "left addr")) << 56
		leftMask := uint64(rapid.IntRange(0, 255).Draw(t, "left mask")) << 56
		rightAddr := uint64(rapid.IntRange(0, 255).Draw(t, "right addr")) << 56
		rightMask := uint64(rapid.IntRange(0, 255).Draw(t, "right mask")) << 56
		left, err := xnetip.Network6From(netipAddrFrom6Bits(leftAddr, 0), netipAddrFrom6Bits(leftMask, 0))
		require.NoError(t, err)
		right, err := xnetip.Network6From(netipAddrFrom6Bits(rightAddr, 0), netipAddrFrom6Bits(rightMask, 0))
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
func Test_Network6_Merge_ConstructedSiblingProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		network := genNetwork6.Draw(t, "network")
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
		sibling, err := xnetip.Network6From(
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
func Test_Network6_Merge_SameMaskNotAdjacentNotIdenticalProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		left := genNetwork6.Draw(t, "left")
		right := genNetwork6.Draw(t, "right")
		if left.Mask() != right.Mask() || left == right || left.IsAdjacent(right) {
			return
		}
		_, ok := left.Merge(right)
		require.False(t, ok)
	})
}

// verifies that merging allocates nothing on any branch.
func Test_Network6_Merge_AllocationFree(t *testing.T) {
	sibling := xnetip.MustParseNetwork6("2001:db8::/48")
	buddy := xnetip.MustParseNetwork6("2001:db8:1::/48")
	container := xnetip.MustParseNetwork6("2001:db8::/32")
	contained := xnetip.MustParseNetwork6("2001:db8:1::/48")
	requireNoAllocs(t, func() { network6Sink, okSink = sibling.Merge(buddy) })
	requireNoAllocs(t, func() { network6Sink, okSink = container.Merge(contained) })
}

func BenchmarkNetwork6_Merge_EqualMaskAdjacent(b *testing.B) {
	left := xnetip.MustParseNetwork6("2001:db8::/48")
	right := xnetip.MustParseNetwork6("2001:db8:1::/48")
	b.ReportAllocs()
	for b.Loop() {
		network6Sink, okSink = left.Merge(right)
	}
}

func BenchmarkNetwork6_Merge_EqualMaskNonMergeable(b *testing.B) {
	left := xnetip.MustParseNetwork6("2001:db8::/48")
	right := xnetip.MustParseNetwork6("2001:db8:5::/48")
	b.ReportAllocs()
	for b.Loop() {
		network6Sink, okSink = left.Merge(right)
	}
}

func BenchmarkNetwork6_Merge_Containment(b *testing.B) {
	left := xnetip.MustParseNetwork6("2001:db8::/32")
	right := xnetip.MustParseNetwork6("2001:db8:1::/48")
	b.ReportAllocs()
	for b.Loop() {
		network6Sink, okSink = left.Merge(right)
	}
}

func BenchmarkNetwork6_Merge_ComparableMasksAddressMismatch(b *testing.B) {
	left := xnetip.MustParseNetwork6("2001:db8::/32")
	right := xnetip.MustParseNetwork6("2001:beef:1::/48")
	b.ReportAllocs()
	for b.Loop() {
		network6Sink, okSink = left.Merge(right)
	}
}

func BenchmarkNetwork6_Merge_IncomparableMasks(b *testing.B) {
	left := xnetip.MustParseNetwork6("2001:db8::1/ffff:0:ffff::")
	right := xnetip.MustParseNetwork6("2001:db8::1/0:ffff:ffff::")
	b.ReportAllocs()
	for b.Loop() {
		network6Sink, okSink = left.Merge(right)
	}
}

func BenchmarkNetwork6_Merge_NonContiguous(b *testing.B) {
	left := xnetip.MustParseNetwork6("2001::1/ffff:ff00::ffff")
	right := xnetip.MustParseNetwork6("2001:100::1/ffff:ff00::ffff")
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
func isAdjacentByLowestMaskBitReferenceIPv6(left, right xnetip.Network6) bool {
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
func Test_Network6_IsAdjacentByLowestMaskBit_ContiguousAndBoundary(t *testing.T) {
	cases := []struct {
		name  string
		left  xnetip.Network6
		right xnetip.Network6
		want  bool
	}{
		{name: "CIDR siblings", left: xnetip.MustParseNetwork6("2001:db8::/48"), right: xnetip.MustParseNetwork6("2001:db8:1::/48"), want: true},
		{name: "CIDR siblings reversed", left: xnetip.MustParseNetwork6("2001:db8:1::/48"), right: xnetip.MustParseNetwork6("2001:db8::/48"), want: true},
		{name: "host routes differing in bit 0", left: xnetip.MustParseNetwork6("2001:db8::/128"), right: xnetip.MustParseNetwork6("2001:db8::1/128"), want: true},
		{name: "host routes differing in bit 0 reversed", left: xnetip.MustParseNetwork6("2001:db8::1/128"), right: xnetip.MustParseNetwork6("2001:db8::/128"), want: true},
		{name: "identical", left: xnetip.MustParseNetwork6("2001:db8::/48"), right: xnetip.MustParseNetwork6("2001:db8::/48"), want: false},
		{name: "different masks", left: xnetip.MustParseNetwork6("2001:db8::/48"), right: xnetip.MustParseNetwork6("2001:db8::/32"), want: false},
		{name: "adjacent at the top mask bit, not the lowest", left: xnetip.MustParseNetwork6("::/2"), right: xnetip.MustParseNetwork6("8000::/2"), want: false},
		{name: "default route with itself", left: xnetip.MustParseNetwork6("::/0"), right: xnetip.MustParseNetwork6("::/0"), want: false},
		{name: "/64 siblings at bit 64", left: xnetip.MustParseNetwork6("2001:db8:0:0::/64"), right: xnetip.MustParseNetwork6("2001:db8:0:1::/64"), want: true},
		{name: "/65 siblings at bit 63", left: xnetip.MustParseNetwork6("2001:db8::/65"), right: xnetip.MustParseNetwork6("2001:db8:0:0:8000::/65"), want: true},
		{name: "/65 pair differing at bit 64", left: xnetip.MustParseNetwork6("2001:db8::/65"), right: xnetip.MustParseNetwork6("2001:db8:0:1::/65"), want: false},
		{name: "/63 pair differing at a host bit is identical", left: xnetip.MustParseNetwork6("2001:db8:0:0::/63"), right: xnetip.MustParseNetwork6("2001:db8:0:1::/63"), want: false},
		{name: "/1 siblings at bit 127", left: xnetip.MustParseNetwork6("::/1"), right: xnetip.MustParseNetwork6("8000::/1"), want: true},
		{name: "/127 siblings", left: xnetip.MustParseNetwork6("2001:db8::/127"), right: xnetip.MustParseNetwork6("2001:db8::2/127"), want: true},
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
func Test_Network6_IsAdjacentByLowestMaskBit_NonContiguousMasks(t *testing.T) {
	cases := []struct {
		name  string
		left  xnetip.Network6
		right xnetip.Network6
		want  bool
	}{
		{name: "two-run mask at its lowest bit", left: xnetip.MustParseNetwork6("::/ffff:ffff::ffff"), right: xnetip.MustParseNetwork6("::1/ffff:ffff::ffff"), want: true},
		{name: "two-run mask at its lowest bit reversed", left: xnetip.MustParseNetwork6("::1/ffff:ffff::ffff"), right: xnetip.MustParseNetwork6("::/ffff:ffff::ffff"), want: true},
		{name: "two-run mask at the high run's boundary bit 96", left: xnetip.MustParseNetwork6("::/ffff:ffff::ffff"), right: xnetip.MustParseNetwork6("0:1::/ffff:ffff::ffff"), want: false},
		{name: "low run ending at bit 32, differing there", left: xnetip.MustParseNetwork6("2a02:6b8::/ffff:ffff::ffff:ffff:0:0"), right: xnetip.MustParseNetwork6("2a02:6b8::1:0:0/ffff:ffff::ffff:ffff:0:0"), want: true},
		{name: "lowest set bit 64 under a hole, differing there", left: xnetip.MustParseNetwork6("2001:db8::/ffff:ffff:0:ffff::"), right: xnetip.MustParseNetwork6("2001:db8:0:1::/ffff:ffff:0:ffff::"), want: true},
		{name: "lowest set bit 64 under a hole, differing at bit 96", left: xnetip.MustParseNetwork6("2001:db8::/ffff:ffff:0:ffff::"), right: xnetip.MustParseNetwork6("2001:db9::/ffff:ffff:0:ffff::"), want: false},
		{name: "geo two-run siblings in the low run", left: xnetip.MustParseNetwork6("2a02:6b8:c00::1234:0:0/ffff:ffff:ff00::ffff:ffff:0:0"), right: xnetip.MustParseNetwork6("2a02:6b8:c00::1235:0:0/ffff:ffff:ff00::ffff:ffff:0:0"), want: true},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			require.Equal(t, testCase.want, testCase.left.IsAdjacentByLowestMaskBit(testCase.right))
		})
	}
}

// verifies that the rejected higher-bit pairs of the unit tables are
// still plainly adjacent: the predicate is a strict restriction.
func Test_Network6_IsAdjacentByLowestMaskBit_RejectedPairsStayAdjacent(t *testing.T) {
	cases := [][2]string{
		{"::/2", "8000::/2"},
		{"2001:db8::/65", "2001:db8:0:1::/65"},
		{"::/ffff:ffff::ffff", "0:1::/ffff:ffff::ffff"},
		{"2001:db8::/ffff:ffff:0:ffff::", "2001:db9::/ffff:ffff:0:ffff::"},
	}
	for _, pair := range cases {
		left := xnetip.MustParseNetwork6(pair[0])
		right := xnetip.MustParseNetwork6(pair[1])
		require.True(t, left.IsAdjacent(right), "pair %v", pair)
		require.False(t, left.IsAdjacentByLowestMaskBit(right), "pair %v", pair)
	}
}

// verifies that the predicate agrees with the trailing-zeros oracle
// on random pairs.
func Test_Network6_IsAdjacentByLowestMaskBit_MatchesReferenceProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		left := genNetwork6.Draw(t, "left")
		right := genNetwork6.Draw(t, "right")
		require.Equal(t, isAdjacentByLowestMaskBitReferenceIPv6(left, right), left.IsAdjacentByLowestMaskBit(right))
	})
}

// verifies that the predicate implies plain adjacency, is symmetric
// and is irreflexive.
func Test_Network6_IsAdjacentByLowestMaskBit_ImpliesAdjacentAndSymmetryProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		left := genNetwork6.Draw(t, "left")
		right := genNetwork6.Draw(t, "right")
		if left.IsAdjacentByLowestMaskBit(right) {
			require.True(t, left.IsAdjacent(right))
		}
		require.Equal(t, left.IsAdjacentByLowestMaskBit(right), right.IsAdjacentByLowestMaskBit(left))
		require.False(t, left.IsAdjacentByLowestMaskBit(left))
	})
}

// verifies that the buddy at the mask's lowest set bit qualifies and
// a sibling at any higher set bit is adjacent but does not.
func Test_Network6_IsAdjacentByLowestMaskBit_BuddyConstructionProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		network := genNetwork6.Draw(t, "network")
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
		buddy, err := xnetip.Network6From(
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
		sibling, err := xnetip.Network6From(
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
func Test_Network6_IsAdjacentByLowestMaskBit_HalfBoundaryBuddyProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		position := rapid.SampledFrom([]int{0, 63, 64, 127}).Draw(t, "position")
		var maskHi, maskLo uint64
		if position < 64 {
			maskHi = ^uint64(0)
			maskLo = ^uint64(0) << position
		} else {
			maskHi = ^uint64(0) << (position - 64)
		}
		network, err := xnetip.Network6From(
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
		buddy, err := xnetip.Network6From(
			netipAddrFrom6Bits(addrHi^bitHi, addrLo^bitLo),
			netipAddrFrom6Bits(maskHi, maskLo),
		)
		require.NoError(t, err)
		require.True(t, network.IsAdjacentByLowestMaskBit(buddy))
		require.True(t, buddy.IsAdjacentByLowestMaskBit(network))
	})
}

// verifies that the predicate allocates nothing.
func Test_Network6_IsAdjacentByLowestMaskBit_AllocationFree(t *testing.T) {
	left := xnetip.MustParseNetwork6("::/ffff:ffff::ffff")
	right := xnetip.MustParseNetwork6("::1/ffff:ffff::ffff")
	requireNoAllocs(t, func() { okSink = left.IsAdjacentByLowestMaskBit(right) })
}

func BenchmarkNetwork6_IsAdjacentByLowestMaskBit_CIDRSiblings(b *testing.B) {
	left := xnetip.MustParseNetwork6("2001:db8::/48")
	right := xnetip.MustParseNetwork6("2001:db8:1::/48")
	b.ReportAllocs()
	for b.Loop() {
		okSink = left.IsAdjacentByLowestMaskBit(right)
	}
}

func BenchmarkNetwork6_IsAdjacentByLowestMaskBit_AdjacentNonLowestBit(b *testing.B) {
	left := xnetip.MustParseNetwork6("::/2")
	right := xnetip.MustParseNetwork6("8000::/2")
	b.ReportAllocs()
	for b.Loop() {
		okSink = left.IsAdjacentByLowestMaskBit(right)
	}
}

func BenchmarkNetwork6_IsAdjacentByLowestMaskBit_NonContiguous(b *testing.B) {
	left := xnetip.MustParseNetwork6("::/ffff:ffff::ffff")
	right := xnetip.MustParseNetwork6("::1/ffff:ffff::ffff")
	b.ReportAllocs()
	for b.Loop() {
		okSink = left.IsAdjacentByLowestMaskBit(right)
	}
}

// mergeByLowestMaskBitReferenceIPv6 is the simple oracle for the
// class-closed merge.
//
// Containment either way returns the container, otherwise the
// trailing-zeros adjacency oracle gates a sibling merge whose mask
// clears the counted bit and whose address is re-normalized through
// the checked constructor.
func mergeByLowestMaskBitReferenceIPv6(t require.TestingT, left, right xnetip.Network6) (xnetip.Network6, bool) {
	if left.Contains(right) {
		return left, true
	}
	if right.Contains(left) {
		return right, true
	}
	if !isAdjacentByLowestMaskBitReferenceIPv6(left, right) {
		return xnetip.Network6{}, false
	}
	leftAddrHi, leftAddrLo, leftMaskHi, leftMaskLo := ipv6NetworkBits(left)
	rightAddrHi, rightAddrLo, _, _ := ipv6NetworkBits(right)
	var lowestHi, lowestLo uint64
	if leftMaskLo != 0 {
		lowestLo = 1 << bits.TrailingZeros64(leftMaskLo)
	} else {
		lowestHi = 1 << bits.TrailingZeros64(leftMaskHi)
	}
	merged, err := xnetip.Network6From(
		netipAddrFrom6Bits(leftAddrHi&rightAddrHi, leftAddrLo&rightAddrLo),
		netipAddrFrom6Bits(leftMaskHi&^lowestHi, leftMaskLo&^lowestLo),
	)
	require.NoError(t, err)
	return merged, true
}

// verifies that merging succeeds exactly for containment and for
// lowest-mask-bit siblings, and returns the combined network.
//
// The half-boundary rows pin the sibling path where the lowest mask
// bit sits at bit 64 or bit 63, so the cleared bit and the reduced
// mask cross the 64-bit halves of the word.
func Test_Network6_MergeByLowestMaskBit_UnitAndBoundary(t *testing.T) {
	cases := []struct {
		name  string
		left  xnetip.Network6
		right xnetip.Network6
		want  xnetip.Network6
		ok    bool
	}{
		{name: "CIDR siblings merge to the parent", left: xnetip.MustParseNetwork6("2001:db8::/48"), right: xnetip.MustParseNetwork6("2001:db8:1::/48"), want: xnetip.MustParseNetwork6("2001:db8::/47"), ok: true},
		{name: "CIDR siblings reversed", left: xnetip.MustParseNetwork6("2001:db8:1::/48"), right: xnetip.MustParseNetwork6("2001:db8::/48"), want: xnetip.MustParseNetwork6("2001:db8::/47"), ok: true},
		{name: "host routes differing in bit 0 merge to /127", left: xnetip.MustParseNetwork6("2001:db8::/128"), right: xnetip.MustParseNetwork6("2001:db8::1/128"), want: xnetip.MustParseNetwork6("2001:db8::/ffff:ffff:ffff:ffff:ffff:ffff:ffff:fffe"), ok: true},
		{name: "adjacent at the top bit is refused", left: xnetip.MustParseNetwork6("::/2"), right: xnetip.MustParseNetwork6("8000::/2"), ok: false},
		{name: "identical returns itself", left: xnetip.MustParseNetwork6("2001:db8::/48"), right: xnetip.MustParseNetwork6("2001:db8::/48"), want: xnetip.MustParseNetwork6("2001:db8::/48"), ok: true},
		{name: "containment returns the larger", left: xnetip.MustParseNetwork6("2001:db8::/32"), right: xnetip.MustParseNetwork6("2001:db8:1::/48"), want: xnetip.MustParseNetwork6("2001:db8::/32"), ok: true},
		{name: "containment reversed", left: xnetip.MustParseNetwork6("2001:db8:1::/48"), right: xnetip.MustParseNetwork6("2001:db8::/32"), want: xnetip.MustParseNetwork6("2001:db8::/32"), ok: true},
		{name: "default route with itself", left: xnetip.MustParseNetwork6("::/0"), right: xnetip.MustParseNetwork6("::/0"), want: xnetip.MustParseNetwork6("::/0"), ok: true},
		{name: "default route absorbs any network", left: xnetip.MustParseNetwork6("::/0"), right: xnetip.MustParseNetwork6("2001:db8::/48"), want: xnetip.MustParseNetwork6("::/0"), ok: true},
		{name: "default route absorbs any network reversed", left: xnetip.MustParseNetwork6("2001:db8::/48"), right: xnetip.MustParseNetwork6("::/0"), want: xnetip.MustParseNetwork6("::/0"), ok: true},
		{name: "different masks, no containment", left: xnetip.MustParseNetwork6("2001:db8::/48"), right: xnetip.MustParseNetwork6("2001:beef::/32"), ok: false},
		{name: "different masks, no containment reversed", left: xnetip.MustParseNetwork6("2001:beef::/32"), right: xnetip.MustParseNetwork6("2001:db8::/48"), ok: false},
		{name: "/64 siblings at bit 64 merge to /63", left: xnetip.MustParseNetwork6("2001:db8:0:0::/64"), right: xnetip.MustParseNetwork6("2001:db8:0:1::/64"), want: xnetip.MustParseNetwork6("2001:db8::/63"), ok: true},
		{name: "/65 siblings at bit 63 merge to /64", left: xnetip.MustParseNetwork6("2001:db8::/65"), right: xnetip.MustParseNetwork6("2001:db8:0:0:8000::/65"), want: xnetip.MustParseNetwork6("2001:db8::/64"), ok: true},
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
func Test_Network6_MergeByLowestMaskBit_NonContiguousMasks(t *testing.T) {
	cases := []struct {
		name  string
		left  xnetip.Network6
		right xnetip.Network6
		want  xnetip.Network6
		ok    bool
	}{
		{name: "containment with two-run masks", left: xnetip.MustParseNetwork6("2001::/ffff:ff00::ffff"), right: xnetip.MustParseNetwork6("2001::/ffff:ff80::ffff"), want: xnetip.MustParseNetwork6("2001::/ffff:ff00::ffff"), ok: true},
		{name: "containment with two-run masks reversed", left: xnetip.MustParseNetwork6("2001::/ffff:ff80::ffff"), right: xnetip.MustParseNetwork6("2001::/ffff:ff00::ffff"), want: xnetip.MustParseNetwork6("2001::/ffff:ff00::ffff"), ok: true},
		{name: "siblings at the low run's bit 0", left: xnetip.MustParseNetwork6("2001::/ffff:ff00::ffff"), right: xnetip.MustParseNetwork6("2001::1/ffff:ff00::ffff"), want: xnetip.MustParseNetwork6("2001::/ffff:ff00::fffe"), ok: true},
		{name: "siblings at the low run's bit 0 reversed", left: xnetip.MustParseNetwork6("2001::1/ffff:ff00::ffff"), right: xnetip.MustParseNetwork6("2001::/ffff:ff00::ffff"), want: xnetip.MustParseNetwork6("2001::/ffff:ff00::fffe"), ok: true},
		{name: "siblings at the high run's bit 104 refused", left: xnetip.MustParseNetwork6("2001::1/ffff:ff00::ffff"), right: xnetip.MustParseNetwork6("2001:100::1/ffff:ff00::ffff"), ok: false},
		{name: "one-bit low run collapses to the contiguous /32", left: xnetip.MustParseNetwork6("::/ffff:ffff:0:0:8000::"), right: xnetip.MustParseNetwork6("::8000:0:0:0/ffff:ffff:0:0:8000::"), want: xnetip.MustParseNetwork6("::/ffff:ffff::"), ok: true},
		{name: "alternating mask, siblings at bit 0", left: xnetip.MustParseNetwork6("::/5555:5555:5555:5555:5555:5555:5555:5555"), right: xnetip.MustParseNetwork6("::1/5555:5555:5555:5555:5555:5555:5555:5555"), want: xnetip.MustParseNetwork6("::/5555:5555:5555:5555:5555:5555:5555:5554"), ok: true},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			merged, ok := testCase.left.MergeByLowestMaskBit(testCase.right)
			require.Equal(t, testCase.ok, ok)
			require.Equal(t, testCase.want, merged)
		})
	}
}

// verifies that the one-bit low run pair and its merge stay in the
// bi-contiguous class while the result degenerates to contiguous.
func Test_Network6_MergeByLowestMaskBit_BicontiguousDegeneration(t *testing.T) {
	left := xnetip.MustParseNetwork6("::/ffff:ffff:0:0:8000::")
	right := xnetip.MustParseNetwork6("::8000:0:0:0/ffff:ffff:0:0:8000::")
	require.True(t, left.IsBicontiguous())
	require.True(t, right.IsBicontiguous())
	require.True(t, left.IsAdjacentByLowestMaskBit(right))
	merged, ok := left.MergeByLowestMaskBit(right)
	require.True(t, ok)
	require.Equal(t, xnetip.MustParseNetwork6("::/ffff:ffff::"), merged)
	require.True(t, merged.IsContiguous())
	require.True(t, merged.IsBicontiguous())
}

// verifies that the refused higher-bit pairs of the unit tables are
// still combined by the unrestricted merge.
//
// The refusal is what keeps the result inside the inputs' class.
func Test_Network6_MergeByLowestMaskBit_RefusedPairsStillMerge(t *testing.T) {
	cases := []struct {
		name string
		pair [2]string
		want string
	}{
		{name: "top-bit pair merges non-contiguously", pair: [2]string{"::/2", "8000::/2"}, want: "::/4000::"},
		{name: "higher-run pair widens the two-run mask", pair: [2]string{"2001::1/ffff:ff00::ffff", "2001:100::1/ffff:ff00::ffff"}, want: "2001::1/ffff:fe00::ffff"},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			left := xnetip.MustParseNetwork6(testCase.pair[0])
			right := xnetip.MustParseNetwork6(testCase.pair[1])
			_, ok := left.MergeByLowestMaskBit(right)
			require.False(t, ok)
			merged, ok := left.Merge(right)
			require.True(t, ok)
			require.Equal(t, xnetip.MustParseNetwork6(testCase.want), merged)
		})
	}
}

// verifies that the seven reference pairs, one per branch of the case
// analysis, agree with the simple oracle.
func Test_Network6_MergeByLowestMaskBit_ReferenceFixedCases(t *testing.T) {
	cases := [][2]string{
		{"2001:db8::/48", "2001:db8:1::/48"},
		{"2001::/ffff:ff00::ffff", "2001::1/ffff:ff00::ffff"},
		{"::/2", "8000::/2"},
		{"2001:db8::/48", "2001:db8::/48"},
		{"2001:db8::/32", "2001:db8:1::/48"},
		{"2001:db8::/32", "2001:beef:1::/48"},
		{"::/0", "::/0"},
	}
	for _, pair := range cases {
		left := xnetip.MustParseNetwork6(pair[0])
		right := xnetip.MustParseNetwork6(pair[1])
		wantNetwork, wantOK := mergeByLowestMaskBitReferenceIPv6(t, left, right)
		merged, ok := left.MergeByLowestMaskBit(right)
		require.Equal(t, wantOK, ok, "pair %v", pair)
		require.Equal(t, wantNetwork, merged, "pair %v", pair)
	}
}

// verifies that the merge agrees with the simple oracle on random
// pairs.
func Test_Network6_MergeByLowestMaskBit_MatchesReferenceProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		left := genNetwork6.Draw(t, "left")
		right := genNetwork6.Draw(t, "right")
		wantNetwork, wantOK := mergeByLowestMaskBitReferenceIPv6(t, left, right)
		merged, ok := left.MergeByLowestMaskBit(right)
		require.Equal(t, wantOK, ok)
		require.Equal(t, wantNetwork, merged)
	})
}

// verifies that the merge fires exactly on containment in either
// direction or on a lowest-mask-bit sibling pair.
func Test_Network6_MergeByLowestMaskBit_OKIffPredicateProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		left := genNetwork6.Draw(t, "left")
		right := genNetwork6.Draw(t, "right")
		_, ok := left.MergeByLowestMaskBit(right)
		want := left.Contains(right) || right.Contains(left) || left.IsAdjacentByLowestMaskBit(right)
		require.Equal(t, want, ok)
	})
}

// verifies that the merge is commutative in both the value and the
// flag.
func Test_Network6_MergeByLowestMaskBit_CommutativityProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		left := genNetwork6.Draw(t, "left")
		right := genNetwork6.Draw(t, "right")
		leftMerged, leftOK := left.MergeByLowestMaskBit(right)
		rightMerged, rightOK := right.MergeByLowestMaskBit(left)
		require.Equal(t, leftOK, rightOK)
		require.Equal(t, leftMerged, rightMerged)
	})
}

// verifies that the merge is a restriction of Merge: whenever it
// fires it returns exactly the same network.
func Test_Network6_MergeByLowestMaskBit_AgreesWithMergeProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		left := genNetwork6.Draw(t, "left")
		right := genNetwork6.Draw(t, "right")
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
func Test_Network6_MergeByLowestMaskBit_SiblingsMergeAndAgreeProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		pair := genIPv6LowestBitSiblingPair.Draw(t, "pair")
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
		addrHi, addrLo, maskHi, maskLo := ipv6NetworkBits(merged)
		require.Equal(t, addrHi, addrHi&maskHi)
		require.Equal(t, addrLo, addrLo&maskLo)
	})
}

// verifies the class closure: two contiguous buddies always merge
// into a contiguous parent.
func Test_Network6_MergeByLowestMaskBit_ClosureContiguousProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		pair := genIPv6ContiguousSiblingPair.Draw(t, "pair")
		require.True(t, pair[0].IsContiguous())
		require.True(t, pair[1].IsContiguous())
		merged, ok := pair[0].MergeByLowestMaskBit(pair[1])
		require.True(t, ok)
		require.True(t, merged.IsContiguous())
	})
}

// verifies the class closure: two bi-contiguous buddies always merge
// into a bi-contiguous parent.
//
// The degenerate one-bit low run collapses to a contiguous mask,
// which is still bi-contiguous.
func Test_Network6_MergeByLowestMaskBit_ClosureBicontiguousProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		pair := genIPv6BicontiguousSiblingPair.Draw(t, "pair")
		require.True(t, pair[0].IsBicontiguous())
		require.True(t, pair[1].IsBicontiguous())
		merged, ok := pair[0].MergeByLowestMaskBit(pair[1])
		require.True(t, ok)
		require.True(t, merged.IsBicontiguous())
	})
}

// verifies on an 8-bit model, networks confined to the top octet,
// that a successful merge holds exactly the union of the two sets.
func Test_Network6_MergeByLowestMaskBit_MembershipBruteForceProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		leftAddr := uint64(rapid.IntRange(0, 255).Draw(t, "left addr")) << 56
		leftMask := uint64(rapid.IntRange(0, 255).Draw(t, "left mask")) << 56
		rightAddr := uint64(rapid.IntRange(0, 255).Draw(t, "right addr")) << 56
		rightMask := uint64(rapid.IntRange(0, 255).Draw(t, "right mask")) << 56
		left, err := xnetip.Network6From(netipAddrFrom6Bits(leftAddr, 0), netipAddrFrom6Bits(leftMask, 0))
		require.NoError(t, err)
		right, err := xnetip.Network6From(netipAddrFrom6Bits(rightAddr, 0), netipAddrFrom6Bits(rightMask, 0))
		require.NoError(t, err)
		merged, ok := left.MergeByLowestMaskBit(right)
		if !ok {
			return
		}
		mergedAddrHi, _, mergedMaskHi, _ := ipv6NetworkBits(merged)
		for x := range uint64(256) {
			candidate := x << 56
			inLeft := candidate&leftMask == leftAddr&leftMask
			inRight := candidate&rightMask == rightAddr&rightMask
			inMerged := candidate&mergedMaskHi == mergedAddrHi
			require.Equal(t, inLeft || inRight, inMerged, "member 0x%016x", candidate)
		}
	})
}

// verifies that the merge allocates nothing on the sibling and the
// containment paths.
func Test_Network6_MergeByLowestMaskBit_AllocationFree(t *testing.T) {
	sibling := xnetip.MustParseNetwork6("2001:db8::/48")
	buddy := xnetip.MustParseNetwork6("2001:db8:1::/48")
	container := xnetip.MustParseNetwork6("2001:db8::/32")
	contained := xnetip.MustParseNetwork6("2001:db8:1::/48")
	requireNoAllocs(t, func() { network6Sink, okSink = sibling.MergeByLowestMaskBit(buddy) })
	requireNoAllocs(t, func() { network6Sink, okSink = container.MergeByLowestMaskBit(contained) })
}

func BenchmarkNetwork6_MergeByLowestMaskBit_CIDRSiblings(b *testing.B) {
	left := xnetip.MustParseNetwork6("2001:db8::/48")
	right := xnetip.MustParseNetwork6("2001:db8:1::/48")
	b.ReportAllocs()
	for b.Loop() {
		network6Sink, okSink = left.MergeByLowestMaskBit(right)
	}
}

func BenchmarkNetwork6_MergeByLowestMaskBit_AdjacentNonLowestBit(b *testing.B) {
	left := xnetip.MustParseNetwork6("::/2")
	right := xnetip.MustParseNetwork6("8000::/2")
	b.ReportAllocs()
	for b.Loop() {
		network6Sink, okSink = left.MergeByLowestMaskBit(right)
	}
}

func BenchmarkNetwork6_MergeByLowestMaskBit_NonContiguous(b *testing.B) {
	left := xnetip.MustParseNetwork6("::/ffff:ffff::ffff")
	right := xnetip.MustParseNetwork6("::1/ffff:ffff::ffff")
	b.ReportAllocs()
	for b.Loop() {
		network6Sink, okSink = left.MergeByLowestMaskBit(right)
	}
}

func BenchmarkNetwork6_MergeByLowestMaskBit_Containment(b *testing.B) {
	left := xnetip.MustParseNetwork6("2001:db8::/32")
	right := xnetip.MustParseNetwork6("2001:db8:1::/48")
	b.ReportAllocs()
	for b.Loop() {
		network6Sink, okSink = left.MergeByLowestMaskBit(right)
	}
}

// ipv6BigFromAddr returns the address's 128-bit pattern as a big
// integer, the currency of the arbitrary-precision oracles.
func ipv6BigFromAddr(addr netip.Addr) *big.Int {
	bytes := addr.As16()
	return new(big.Int).SetBytes(bytes[:])
}

// netipAddrFromBig returns the Is6 netip.Addr of a big integer's low
// 128 bits, inverting ipv6BigFromAddr.
func netipAddrFromBig(value *big.Int) netip.Addr {
	var bytes [16]byte
	value.FillBytes(bytes[:])
	return netip.AddrFrom16(bytes)
}

// supernetForReferenceIPv6 is the fold oracle on big integers, an
// implementation independent of the 128-bit word type.
//
// It keeps a mask bit only when every input masks it and agrees with
// the receiver's address on it, and re-normalizes the address through
// the checked constructor.
func supernetForReferenceIPv6(t require.TestingT, receiver xnetip.Network6, nets []xnetip.Network6) xnetip.Network6 {
	addr := ipv6BigFromAddr(receiver.Addr())
	mask := ipv6BigFromAddr(receiver.Mask())
	for _, network := range nets {
		disagreement := new(big.Int).Xor(addr, ipv6BigFromAddr(network.Addr()))
		mask.And(mask, new(big.Int).AndNot(ipv6BigFromAddr(network.Mask()), disagreement))
	}
	oracle, err := xnetip.Network6From(
		netipAddrFromBig(new(big.Int).And(addr, mask)),
		netipAddrFromBig(mask),
	)
	require.NoError(t, err)
	return oracle
}

// ipv6RelatedNetworks returns count consecutive /124 blocks under
// 2001:db8:1::/48, a fold fixture that never collapses to zero.
func ipv6RelatedNetworks(t require.TestingT, count int) []xnetip.Network6 {
	networks := make([]xnetip.Network6, count)
	for idx := range networks {
		network, err := xnetip.Network6FromCIDR(netipAddrFrom6Bits(0x20010DB800010000, uint64(idx)*16), 124)
		require.NoError(t, err)
		networks[idx] = network
	}
	return networks
}

// ipv6RelatedNonContiguousNetworks returns count networks under the
// mask with an 8-bit hole in the third group.
//
// The addresses spread over the last group, so a fold over them
// exercises the holed shape without collapsing the mask to zero.
func ipv6RelatedNonContiguousNetworks(t require.TestingT, count int) []xnetip.Network6 {
	networks := make([]xnetip.Network6, count)
	for idx := range networks {
		network, err := xnetip.Network6From(
			netipAddrFrom6Bits(0x20010DB80C000000, uint64(idx)),
			netipAddrFrom6Bits(0xFFFFFFFFFF00FFFF, ^uint64(0)),
		)
		require.NoError(t, err)
		networks[idx] = network
	}
	return networks
}

// verifies that the fold keeps exactly the mask bits every input
// masks and agrees on, over the ported reference cases.
func Test_Network6_SupernetFor_UnitAndBoundary(t *testing.T) {
	cases := []struct {
		name     string
		receiver xnetip.Network6
		nets     []xnetip.Network6
		want     xnetip.Network6
	}{
		{name: "a /39 folds into the shared /32", receiver: xnetip.MustParseNetwork6("2001:db8:1::/32"), nets: []xnetip.Network6{xnetip.MustParseNetwork6("2001:db8:2::/39")}, want: xnetip.MustParseNetwork6("2001:db8::/32")},
		{name: "two /64 leave a hole in the third group", receiver: xnetip.MustParseNetwork6("2013:db8:1::1/64"), nets: []xnetip.Network6{xnetip.MustParseNetwork6("2013:db8:2::1/64")}, want: xnetip.MustParseNetwork6("2013:db8::/ffff:ffff:fffc:ffff::")},
		{name: "alternating addresses disagree on every bit", receiver: xnetip.MustParseNetwork6("aaaa:aaaa:aaaa:aaaa:aaaa:aaaa:aaaa:aaaa/128"), nets: []xnetip.Network6{xnetip.MustParseNetwork6("5555:5555:5555:5555:5555:5555:5555:5555/128")}, want: xnetip.MustParseNetwork6("::/0")},
		{name: "partial agreement in the top group", receiver: xnetip.MustParseNetwork6("8001:db8:1::/34"), nets: []xnetip.Network6{xnetip.MustParseNetwork6("2013:db8:2::/32")}, want: xnetip.MustParseNetwork6("1:db8::/5fed:ffff::")},
		{name: "wider CIDR absorbs the receiver", receiver: xnetip.MustParseNetwork6("2001:db8::/48"), nets: []xnetip.Network6{xnetip.MustParseNetwork6("2001:db8::/32")}, want: xnetip.MustParseNetwork6("2001:db8::/32")},
		{name: "wider CIDR absorbs the element", receiver: xnetip.MustParseNetwork6("2001:db8::/32"), nets: []xnetip.Network6{xnetip.MustParseNetwork6("2001:db8::/48")}, want: xnetip.MustParseNetwork6("2001:db8::/32")},
		{name: "empty slice returns the receiver", receiver: xnetip.MustParseNetwork6("2001:db8::/32"), nets: nil, want: xnetip.MustParseNetwork6("2001:db8::/32")},
		{name: "default route receiver stays the default route", receiver: xnetip.MustParseNetwork6("::/0"), nets: []xnetip.Network6{xnetip.MustParseNetwork6("2001:db8::/32")}, want: xnetip.MustParseNetwork6("::/0")},
		{name: "disagreement in the last bit of the high half", receiver: xnetip.MustParseNetwork6("2001:db8::/64"), nets: []xnetip.Network6{xnetip.MustParseNetwork6("2001:db8:0:1::/64")}, want: xnetip.MustParseNetwork6("2001:db8::/63")},
		{name: "disagreement in the first bit of the low half", receiver: xnetip.MustParseNetwork6("2001:db8::/65"), nets: []xnetip.Network6{xnetip.MustParseNetwork6("2001:db8:0:0:8000::/65")}, want: xnetip.MustParseNetwork6("2001:db8::/64")},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			require.Equal(t, testCase.want, testCase.receiver.SupernetFor(testCase.nets))
		})
	}
}

// verifies that non-contiguous inputs fold bit by bit: holes of the
// input masks and address disagreements both clear result bits.
func Test_Network6_SupernetFor_NonContiguousMasks(t *testing.T) {
	cases := []struct {
		name     string
		receiver xnetip.Network6
		nets     []xnetip.Network6
		want     xnetip.Network6
	}{
		{name: "two-run inputs sharing the high runs", receiver: xnetip.MustParseNetwork6("2a02:6b8:c00::48aa:0:0/ffff:ffff:ff00::ffff:ffff:0:0"), nets: []xnetip.Network6{xnetip.MustParseNetwork6("2a02:6b8:c00::4707:0:0/ffff:ffff:ff00::ffff:ffff:0:0")}, want: xnetip.MustParseNetwork6("2a02:6b8:c00::4002:0:0/ffff:ffff:ff00:0:ffff:f052::")},
		{name: "two-run inputs disagreeing in the third group", receiver: xnetip.MustParseNetwork6("2a02:6b8:c00::48aa:0:0/ffff:ffff:ff00::ffff:ffff:0:0"), nets: []xnetip.Network6{xnetip.MustParseNetwork6("2a02:6b8:fc00::4707:0:0/ffff:ffff:ff00::ffff:ffff:0:0")}, want: xnetip.MustParseNetwork6("2a02:6b8:c00::4002:0:0/ffff:ffff:f00:0:ffff:f052::")},
		{name: "alternating mask of the input narrows the result", receiver: xnetip.MustParseNetwork6("::/ffff:ffff::"), nets: []xnetip.Network6{xnetip.MustParseNetwork6("::/5555:5555::")}, want: xnetip.MustParseNetwork6("::/5555:5555::")},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			require.Equal(t, testCase.want, testCase.receiver.SupernetFor(testCase.nets))
		})
	}
}

// verifies that the fold agrees with the big-integer oracle on random
// receivers and slices.
func Test_Network6_SupernetFor_MatchesReferenceProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		receiver := genNetwork6.Draw(t, "receiver")
		nets := rapid.SliceOfN(genNetwork6, 0, 32).Draw(t, "nets")
		require.Equal(t, supernetForReferenceIPv6(t, receiver, nets), receiver.SupernetFor(nets))
	})
}

// verifies that the result is normalized and contains the receiver
// and every element.
func Test_Network6_SupernetFor_ContainsAllProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		receiver := genNetwork6.Draw(t, "receiver")
		nets := rapid.SliceOfN(genNetwork6, 0, 32).Draw(t, "nets")
		result := receiver.SupernetFor(nets)
		addrHi, addrLo, maskHi, maskLo := ipv6NetworkBits(result)
		require.Equal(t, addrHi, addrHi&maskHi)
		require.Equal(t, addrLo, addrLo&maskLo)
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
func Test_Network6_SupernetFor_MaximalityProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		receiver := genNetwork6.Draw(t, "receiver")
		nets := rapid.SliceOfN(genNetwork6, 0, 32).Draw(t, "nets")
		result := receiver.SupernetFor(nets)
		receiverAddr := ipv6BigFromAddr(receiver.Addr())
		receiverMask := ipv6BigFromAddr(receiver.Mask())
		resultMask := ipv6BigFromAddr(result.Mask())
		addrs := make([]*big.Int, len(nets))
		masks := make([]*big.Int, len(nets))
		for idx, network := range nets {
			addrs[idx] = ipv6BigFromAddr(network.Addr())
			masks[idx] = ipv6BigFromAddr(network.Mask())
		}
		for bit := range 128 {
			switch {
			case resultMask.Bit(bit) == 1:
				require.Equal(t, uint(1), receiverMask.Bit(bit), "kept bit %d outside the receiver mask", bit)
				for idx := range nets {
					require.Equal(t, uint(1), masks[idx].Bit(bit), "kept bit %d unmasked by %v", bit, nets[idx])
					require.Equal(t, receiverAddr.Bit(bit), addrs[idx].Bit(bit), "kept bit %d disagreed on by %v", bit, nets[idx])
				}
			case receiverMask.Bit(bit) == 1:
				dropped := false
				for idx := range nets {
					if masks[idx].Bit(bit) == 0 || addrs[idx].Bit(bit) != receiverAddr.Bit(bit) {
						dropped = true
					}
				}
				require.True(t, dropped, "bit %d dropped with no input forcing it", bit)
			}
		}
	})
}

// verifies that the fold does not depend on the order of the slice.
func Test_Network6_SupernetFor_OrderIndependenceProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		receiver := genNetwork6.Draw(t, "receiver")
		nets := rapid.SliceOfN(genNetwork6, 0, 32).Draw(t, "nets")
		shuffled := rapid.Permutation(nets).Draw(t, "shuffled")
		require.Equal(t, receiver.SupernetFor(nets), receiver.SupernetFor(shuffled))
	})
}

// verifies that whenever two networks merge, the merged network is
// exactly the supernet of one for the other.
func Test_Network6_SupernetFor_AgreesWithMergeProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		left := genNetwork6.Draw(t, "left")
		right := genNetwork6.Draw(t, "right")
		if merged, ok := left.Merge(right); ok {
			require.Equal(t, merged, left.SupernetFor([]xnetip.Network6{right}))
		}
		pair := genIPv6LowestBitSiblingPair.Draw(t, "pair")
		merged, ok := pair[0].Merge(pair[1])
		require.True(t, ok)
		require.Equal(t, merged, pair[0].SupernetFor(pair[1:]))
	})
}

// verifies that the fold allocates nothing over a 64-element slice,
// whatever the mask's shape.
func Test_Network6_SupernetFor_AllocationFree(t *testing.T) {
	related := ipv6RelatedNetworks(t, 64)
	nonContiguous := ipv6RelatedNonContiguousNetworks(t, 64)
	requireNoAllocs(t, func() { network6Sink = related[0].SupernetFor(related[1:]) })
	requireNoAllocs(t, func() { network6Sink = nonContiguous[0].SupernetFor(nonContiguous[1:]) })
}

func BenchmarkNetwork6_SupernetFor_64x124(b *testing.B) {
	nets := ipv6RelatedNetworks(b, 64)
	b.ReportAllocs()
	for b.Loop() {
		network6Sink = nets[0].SupernetFor(nets[1:])
	}
}

func BenchmarkNetwork6_SupernetFor_1024x124(b *testing.B) {
	nets := ipv6RelatedNetworks(b, 1024)
	b.ReportAllocs()
	for b.Loop() {
		network6Sink = nets[0].SupernetFor(nets[1:])
	}
}

func BenchmarkNetwork6_SupernetFor_1024xNonContiguous(b *testing.B) {
	nets := ipv6RelatedNonContiguousNetworks(b, 1024)
	b.ReportAllocs()
	for b.Loop() {
		network6Sink = nets[0].SupernetFor(nets[1:])
	}
}

// verifies that the mask is truncated at its first zero bit and the
// address re-normalized under the leading run.
func Test_Network6_ToContiguous_TruncatesAtFirstZeroBit(t *testing.T) {
	cases := []struct {
		name  string
		input string
		want  string
	}{
		{name: "geo mask", input: "2001:db8::1/ffff:ffff:ff00::ffff:ffff:0:0", want: "2001:db8::/40"},
		{name: "already contiguous", input: "2001:db8::/32", want: "2001:db8::/32"},
		{name: "universe", input: "::/0", want: "::/0"},
		{name: "host route", input: "2001:db8::1/128", want: "2001:db8::1/128"},
		{name: "run ends at bit 64", input: "2001:db8:1:2:3:4:5:6/ffff:ffff:ffff:ffff:0:ffff::", want: "2001:db8:1:2::/64"},
		{name: "run crosses bit 64", input: "2001:db8:1:2:3:4:5:6/ffff:ffff:ffff:ffff:ff00:0:ffff:0", want: "2001:db8:1:2::/72"},
		{name: "hole right below bit 64", input: "2001:db8:1:2:3:4:5:6/ffff:ffff:ffff:fffe:ffff::", want: "2001:db8:1:2::/63"},
		{name: "mask with empty leading run", input: "::1/::ffff", want: "::/0"},
		{name: "mapped network keeps its run", input: "::ffff:192.168.0.1/ffff:ffff:ffff:ffff:ffff:ffff:ffff:ff0f", want: "::ffff:192.168.0.0/120"},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			network := xnetip.MustParseNetwork6(testCase.input)
			require.Equal(t, xnetip.MustParseContiguous6(testCase.want), network.ToContiguous())
		})
	}
}

// verifies that the zero network truncates to the zero wrapper.
func Test_Network6_ToContiguous_ZeroValue(t *testing.T) {
	require.Equal(t, xnetip.Contiguous[xnetip.Network6]{}, xnetip.Network6{}.ToContiguous())
}

// verifies that a non-contiguous mask keeps only its leading run of
// ones.
func Test_Network6_ToContiguous_NonContiguousMasks(t *testing.T) {
	cases := []struct {
		name  string
		input string
		want  string
	}{
		{name: "alternating groups keep the first", input: "2001:0:db8:0:1:0:2:0/ffff:0:ffff:0:ffff:0:ffff:0", want: "2001::/16"},
		{name: "high run then low run keeps the high one", input: "2a02:6b8::1234:0:0/ffff:ffff::ffff:ffff:0:0", want: "2a02:6b8::/32"},
		{name: "single leading bit then noise keeps one bit", input: "8000::1/8000::1", want: "8000::/1"},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			network := xnetip.MustParseNetwork6(testCase.input)
			require.Equal(t, xnetip.MustParseContiguous6(testCase.want), network.ToContiguous())
		})
	}
}

// verifies that the wrapped result of every truncation satisfies the
// contiguity its type claims, pinning the blind wrap.
func Test_Network6_ToContiguous_ResultContiguousProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		network := genNetwork6.Draw(t, "network")
		require.True(t, network.ToContiguous().Network().IsContiguous())
	})
}

// verifies that truncating an already truncated network changes
// nothing.
func Test_Network6_ToContiguous_IdempotentProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		network := genNetwork6.Draw(t, "network")
		block := network.ToContiguous()
		require.Equal(t, block, block.Network().ToContiguous())
	})
}

// verifies that the result's prefix length equals the number of
// leading one bits of the input mask.
func Test_Network6_ToContiguous_PrefixIsLeadingOnesProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		network := genNetwork6.Draw(t, "network")
		prefixLen, ok := network.ToContiguous().Network().PrefixLen()
		require.True(t, ok)
		count := 0
	counting:
		for _, octet := range network.Mask().As16() {
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
func Test_Network6_ToContiguous_ContainsOriginalProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		network := genNetwork6.Draw(t, "network")
		require.True(t, network.ToContiguous().Network().Contains(network))
	})
}

// verifies that on contiguous input the widening conversion equals
// the exact one and changes nothing.
func Test_Network6_ToContiguous_AgreesWithContiguousFromProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		block := genContiguous6.Draw(t, "block")
		require.Equal(t, block, block.Network().ToContiguous())
		exact, ok := xnetip.ContiguousFrom(block.Network())
		require.True(t, ok)
		require.Equal(t, exact, block.Network().ToContiguous())
	})
}

// verifies that the truncated network holds no address bit outside
// its mask.
func Test_Network6_ToContiguous_ResultNormalizedProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		network := genNetwork6.Draw(t, "network")
		addrHi, addrLo, maskHi, maskLo := ipv6NetworkBits(network.ToContiguous().Network())
		require.Equal(t, addrHi&maskHi, addrHi)
		require.Equal(t, addrLo&maskLo, addrLo)
	})
}

// verifies that the result agrees with the std masked prefix of the
// input address under the truncated length.
func Test_Network6_ToContiguous_MatchesNetipMaskedProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		network := genNetwork6.Draw(t, "network")
		block := network.ToContiguous()
		prefixLen, ok := block.Network().PrefixLen()
		require.True(t, ok)
		prefix, ok := block.Network().Prefix()
		require.True(t, ok)
		require.Equal(t, netip.PrefixFrom(network.Addr(), prefixLen).Masked(), prefix)
	})
}

// verifies that truncation allocates nothing for either mask shape.
func Test_Network6_ToContiguous_AllocationFree(t *testing.T) {
	contiguous := xnetip.MustParseNetwork6("2001:db8::/32")
	nonContiguous := xnetip.MustParseNetwork6("2001:db8::1/ffff:ffff:ff00::ffff:ffff:0:0")
	requireNoAllocs(t, func() { contiguous6Sink = contiguous.ToContiguous() })
	requireNoAllocs(t, func() { contiguous6Sink = nonContiguous.ToContiguous() })
}

func BenchmarkNetwork6_ToContiguous_Contiguous(b *testing.B) {
	network := xnetip.MustParseNetwork6("2001:db8::/32")
	b.ReportAllocs()
	for b.Loop() {
		contiguous6Sink = network.ToContiguous()
	}
}

func BenchmarkNetwork6_ToContiguous_NonContiguous(b *testing.B) {
	network := xnetip.MustParseNetwork6("2001:db8::1/ffff:ffff:ff00::ffff:ffff:0:0")
	b.ReportAllocs()
	for b.Loop() {
		contiguous6Sink = network.ToContiguous()
	}
}

// verifies that widening keeps the longest leading run in each mask
// half and normalizes the address under those independent runs.
func Test_Network6_ToBiContiguous_PerHalfTruncation(t *testing.T) {
	cases := []struct {
		name  string
		input string
		want  string
	}{
		{name: "zero network", input: "::/0", want: "::/0"},
		{name: "host route", input: "2001:db8::1/128", want: "2001:db8::1/128"},
		{name: "motivating two-run mask", input: "2a02:6b8:c00::1234:abcd:0:0/ffff:ffff:ff00::ffff:ffff:0:0", want: "2a02:6b8:c00::1234:abcd:0:0/ffff:ffff:ff00::ffff:ffff:0:0"},
		{name: "global /40", input: "2a02:6b8:c00::/40", want: "2a02:6b8:c00::/40"},
		{name: "global /64", input: "2001:db8:1:2::/64", want: "2001:db8:1:2::/64"},
		{name: "global /96", input: "2001:db8:1:2:3:4::/96", want: "2001:db8:1:2:3:4::/96"},
		{name: "hole in high half", input: "ffff:0:ffff:ffff:abcd:ef01::/ffff:0:ffff:ffff:ffff:ffff::", want: "ffff::abcd:ef01:0:0/ffff::ffff:ffff:0:0"},
		{name: "hole in low half", input: "ffff:ffff:ff00:0:f0f0:ffff:ffff:ffff/ffff:ffff:ff00:0:f0f0:ffff:ffff:ffff", want: "ffff:ffff:ff00:0:f000::/ffff:ffff:ff00:0:f000::"},
		{name: "holes in both halves", input: "aaaa:aaaa:aaaa:aaaa:aaaa:aaaa:aaaa:aaaa/aaaa:aaaa:aaaa:aaaa:aaaa:aaaa:aaaa:aaaa", want: "8000::8000:0:0:0/8000::8000:0:0:0"},
		{name: "hole at half boundary", input: "ffff:ffff:ffff:fffe:ffff:ffff::/ffff:ffff:ffff:fffe:ffff:ffff::", want: "ffff:ffff:ffff:fffe:ffff:ffff::/ffff:ffff:ffff:fffe:ffff:ffff::"},
		{name: "set host bits are cleared", input: "ffff:0:ffff:ffff:f0f0:ffff:ffff:ffff/ffff:0:ffff:ffff:f0f0:ffff:ffff:ffff", want: "ffff::f000:0:0:0/ffff::f000:0:0:0"},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			network := xnetip.MustParseNetwork6(testCase.input)
			require.Equal(t, xnetip.MustParseBiContiguous(testCase.want), network.ToBiContiguous())
		})
	}
}

// verifies that the zero network widens to the exact zero wrapper.
func Test_Network6_ToBiContiguous_ZeroValue(t *testing.T) {
	require.Equal(t, xnetip.BiContiguous{}, xnetip.Network6{}.ToBiContiguous())
}

// verifies that every widened result carries a valid guarantee and
// succeeds through the exact conversion without changing.
func Test_Network6_ToBiContiguous_ResultGuaranteedProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		network := genNetwork6.Draw(t, "network")
		result := network.ToBiContiguous()
		require.True(t, result.Network().IsBicontiguous())
		exact, ok := xnetip.BiContiguousFrom6(result.Network())
		require.True(t, ok)
		require.Equal(t, result, exact)
	})
}

// verifies that widening always produces a supernet of the source.
func Test_Network6_ToBiContiguous_ContainsSourceProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		network := genNetwork6.Draw(t, "network")
		require.True(t, network.ToBiContiguous().Network().Contains(network))
	})
}

// verifies that widening is an identity exactly for masks already
// made of one leading run in each half.
func Test_Network6_ToBiContiguous_IdentityIffBicontiguousProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		network := genNetwork6.Draw(t, "network")
		result := network.ToBiContiguous().Network()
		require.Equal(t, network.IsBicontiguous(), result == network)
	})
}

// The oracle builds the uninterrupted leading-one run one bit at a
// time, independently of the runtime bit-counting implementation.
func leadingPrefixMask64Oracle(mask uint64) uint64 {
	var prefix uint64
	for position := 63; position >= 0; position-- {
		bit := uint64(1) << position
		if mask&bit == 0 {
			break
		}
		prefix |= bit
	}
	return prefix
}

// verifies that each result half equals the simple bit-loop oracle
// for the corresponding source half.
func Test_Network6_ToBiContiguous_MatchesPerHalfOracleProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		network := genNetwork6.Draw(t, "network")
		_, _, sourceMaskHi, sourceMaskLo := ipv6NetworkBits(network)
		_, _, resultMaskHi, resultMaskLo := ipv6NetworkBits(network.ToBiContiguous().Network())
		require.Equal(t, leadingPrefixMask64Oracle(sourceMaskHi), resultMaskHi)
		require.Equal(t, leadingPrefixMask64Oracle(sourceMaskLo), resultMaskLo)
	})
}

// The bounded oracle constructs an eight-bit prefix one bit at a time.
func prefixMask8Oracle(prefix int) uint8 {
	var mask uint8
	for offset := range prefix {
		mask |= uint8(1) << (7 - offset)
	}
	return mask
}

// verifies on bounded halves that the chosen admissible prefixes
// contain every other prefix-mask subset of the source mask.
//
// More mask bits describe a smaller address set, so this dominance
// makes the chosen product the unique smallest admissible supernet.
func Test_Network6_ToBiContiguous_MinimalOnBoundedHalvesProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		sourceHi := rapid.Uint8().Draw(t, "source high half")
		sourceLo := rapid.Uint8().Draw(t, "source low half")
		network, err := xnetip.Network6From(
			netipAddrFrom6Bits(math.MaxUint64, math.MaxUint64),
			netipAddrFrom6Bits(uint64(sourceHi)<<56, uint64(sourceLo)<<56),
		)
		require.NoError(t, err)
		_, _, resultMaskHi, resultMaskLo := ipv6NetworkBits(network.ToBiContiguous().Network())
		chosenHi := uint8(resultMaskHi >> 56)
		chosenLo := uint8(resultMaskLo >> 56)
		require.Zero(t, resultMaskHi<<8)
		require.Zero(t, resultMaskLo<<8)
		require.Equal(t, chosenHi, chosenHi&sourceHi)
		require.Equal(t, chosenLo, chosenLo&sourceLo)

		for highPrefix := range 9 {
			candidateHi := prefixMask8Oracle(highPrefix)
			if candidateHi&sourceHi != candidateHi {
				continue
			}
			for lowPrefix := range 9 {
				candidateLo := prefixMask8Oracle(lowPrefix)
				if candidateLo&sourceLo != candidateLo {
					continue
				}
				require.Equal(t, candidateHi, candidateHi&chosenHi)
				require.Equal(t, candidateLo, candidateLo&chosenLo)
			}
		}
	})
}

// verifies exhaustively that all 4,225 admissible mask shapes are
// exact identities under the widening conversion.
func Test_Network6_ToBiContiguous_IdentityForEveryShape(t *testing.T) {
	for highPrefix := range 65 {
		for lowPrefix := range 65 {
			network, err := xnetip.Network6From(
				netipAddrFrom6Bits(math.MaxUint64, math.MaxUint64),
				netipAddrFrom6Bits(prefixMask64(highPrefix), prefixMask64(lowPrefix)),
			)
			require.NoError(t, err)
			require.Equal(
				t,
				network,
				network.ToBiContiguous().Network(),
				"high prefix %d, low prefix %d",
				highPrefix,
				lowPrefix,
			)
		}
	}
}

// verifies that exact and widening conversions allocate nothing.
func Test_Network6_ToBiContiguous_AllocationFree(t *testing.T) {
	exact := xnetip.MustParseNetwork6("2a02:6b8:c00::1234:abcd:0:0/ffff:ffff:ff00::ffff:ffff:0:0")
	widening := xnetip.MustParseNetwork6("aaaa:aaaa:aaaa:aaaa:aaaa:aaaa:aaaa:aaaa/aaaa:aaaa:aaaa:aaaa:aaaa:aaaa:aaaa:aaaa")
	requireNoAllocs(t, func() { biContiguousSink = exact.ToBiContiguous() })
	requireNoAllocs(t, func() { biContiguousSink = widening.ToBiContiguous() })
}

func BenchmarkNetwork6_ToBiContiguous_Exact(b *testing.B) {
	network := xnetip.MustParseNetwork6("2a02:6b8:c00::1234:abcd:0:0/ffff:ffff:ff00::ffff:ffff:0:0")
	b.ReportAllocs()
	for b.Loop() {
		biContiguousSink = network.ToBiContiguous()
	}
}

func BenchmarkNetwork6_ToBiContiguous_WidenBothHalves(b *testing.B) {
	network := xnetip.MustParseNetwork6("aaaa:aaaa:aaaa:aaaa:aaaa:aaaa:aaaa:aaaa/aaaa:aaaa:aaaa:aaaa:aaaa:aaaa:aaaa:aaaa")
	b.ReportAllocs()
	for b.Loop() {
		biContiguousSink = network.ToBiContiguous()
	}
}

func BenchmarkNetwork6_ToBiContiguous_Zero(b *testing.B) {
	network := xnetip.Network6{}
	b.ReportAllocs()
	for b.Loop() {
		biContiguousSink = network.ToBiContiguous()
	}
}
