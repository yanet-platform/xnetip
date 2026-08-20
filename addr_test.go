package xnetip_test

import (
	"encoding/json"
	"net/netip"
	"slices"
	"testing"

	"github.com/stretchr/testify/require"
	"pgregory.net/rapid"

	"github.com/yanet-platform/xnetip"
)

// verifies that an address built from an IPv4 value reports the IPv4
// family under every accessor.
func Test_IPAddr_From4_ReportsIPv4(t *testing.T) {
	address := xnetip.IPAddrFrom4(xnetip.MustParseIPv4Addr("192.168.1.0"))
	require.True(t, address.Is4())
	require.False(t, address.Is6())
	v4, ok := address.IPv4()
	require.True(t, ok)
	require.Equal(t, xnetip.MustParseIPv4Addr("192.168.1.0"), v4)
	_, ok = address.IPv6()
	require.False(t, ok)
	require.Equal(t, 32, address.BitLen())
}

// verifies that an address built from an IPv6 value reports the IPv6
// family under every accessor.
func Test_IPAddr_From6_ReportsIPv6(t *testing.T) {
	address := xnetip.IPAddrFrom6(xnetip.MustParseIPv6Addr("2001:db8::"))
	require.True(t, address.Is6())
	require.False(t, address.Is4())
	v6, ok := address.IPv6()
	require.True(t, ok)
	require.Equal(t, xnetip.MustParseIPv6Addr("2001:db8::"), v6)
	_, ok = address.IPv4()
	require.False(t, ok)
	require.Equal(t, 128, address.BitLen())
}

// verifies that an IPv4-mapped IPv6 value stays IPv6: the constructor
// never reinterprets the mapped range as the IPv4 family.
func Test_IPAddr_From6_MappedStaysIPv6(t *testing.T) {
	address := xnetip.IPAddrFrom6(xnetip.MustParseIPv6Addr("::ffff:1.2.3.4"))
	require.False(t, address.Is4())
	require.True(t, address.Is6())
	_, ok := address.IPv4()
	require.False(t, ok)
}

// verifies that an IPv4 address and its mapped IPv6 twin are distinct
// values: they share the 16-byte form but differ in family.
func Test_IPAddr_From4AndFrom6Mapped_Differ(t *testing.T) {
	four := xnetip.IPAddrFrom4(xnetip.MustParseIPv4Addr("1.2.3.4"))
	six := xnetip.IPAddrFrom6(xnetip.MustParseIPv6Addr("::ffff:1.2.3.4"))
	require.NotEqual(t, four, six)
	require.Equal(t, four.As16(), six.As16())
}

// verifies that the 16-byte form of an IPv4 address is the IPv4-mapped
// layout, as netip.Addr.As16 returns it.
func Test_IPAddr_As16_OfIPv4IsMapped(t *testing.T) {
	address := xnetip.IPAddrFrom4(xnetip.MustParseIPv4Addr("1.2.3.4"))
	require.Equal(t, [16]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 1, 2, 3, 4}, address.As16())
}

// verifies the 16-byte form of an IPv6 address.
func Test_IPAddr_As16_OfIPv6(t *testing.T) {
	address := xnetip.IPAddrFrom6(xnetip.MustParseIPv6Addr("2001:db8::1"))
	require.Equal(t, [16]byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}, address.As16())
}

// verifies that the zero value is the IPv6 unspecified address ::, a
// real address with no invalid state.
func Test_IPAddr_ZeroValue_IsIPv6Unspecified(t *testing.T) {
	var address xnetip.IPAddr
	require.True(t, address.Is6())
	require.False(t, address.Is4())
	require.Equal(t, [16]byte{}, address.As16())
	require.Equal(t, 128, address.BitLen())
	v6, ok := address.IPv6()
	require.True(t, ok)
	require.Equal(t, xnetip.IPv6Addr{}, v6)
}

// verifies that the IPv4 unspecified address is not the zero value: it
// is an IPv4 address stored in the mapped form.
func Test_IPAddr_From4Zero_IsNotZeroValue(t *testing.T) {
	address := xnetip.IPAddrFrom4(xnetip.MustParseIPv4Addr("0.0.0.0"))
	require.NotEqual(t, xnetip.IPAddr{}, address)
	require.True(t, address.Is4())
	require.Equal(t, [16]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 0, 0, 0, 0}, address.As16())
}

// verifies that a non-contiguous mask value survives the round trip
// through the family-agnostic type, the way network mask accessors use it.
func Test_IPAddr_From4_KeepsNonContiguousMaskValue(t *testing.T) {
	mask := xnetip.MustParseIPv4Addr("255.255.0.255")
	v4, ok := xnetip.IPAddrFrom4(mask).IPv4()
	require.True(t, ok)
	require.Equal(t, mask, v4)
}

// verifies that the type is usable as a map key and that an IPv4 address
// and its mapped IPv6 twin are distinct keys.
func Test_IPAddr_MapKey_DistinguishesFamilies(t *testing.T) {
	seen := map[xnetip.IPAddr]string{}
	seen[xnetip.IPAddrFrom4(xnetip.MustParseIPv4Addr("1.2.3.4"))] = "four"
	seen[xnetip.IPAddrFrom6(xnetip.MustParseIPv6Addr("::ffff:1.2.3.4"))] = "six"
	require.Len(t, seen, 2)
	require.Equal(t, "four", seen[xnetip.IPAddrFrom4(xnetip.MustParseIPv4Addr("1.2.3.4"))])
}

// verifies that the IPv4 accessor inverts the IPv4 constructor for every
// address.
func Test_IPAddr_IPv4_RoundTripsFrom4(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		address := genIPv4Addr.Draw(t, "address")
		v4, ok := xnetip.IPAddrFrom4(address).IPv4()
		require.True(t, ok)
		require.Equal(t, address, v4)
	})
}

// verifies that the IPv6 accessor inverts the IPv6 constructor for every
// address.
func Test_IPAddr_IPv6_RoundTripsFrom6(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		address := genIPv6Addr.Draw(t, "address")
		v6, ok := xnetip.IPAddrFrom6(address).IPv6()
		require.True(t, ok)
		require.Equal(t, address, v6)
	})
}

// verifies that exactly one family holds for every value and that the
// bit length reports the family.
func Test_IPAddr_Family_IsExclusive(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		address := genIPAddr.Draw(t, "address")
		require.NotEqual(t, address.Is6(), address.Is4())
		require.Equal(t, address.Is4(), address.BitLen() == 32)
		require.Equal(t, address.Is6(), address.BitLen() == 128)
	})
}

// verifies that the 16-byte form agrees with net/netip for both
// families: mapped for IPv4, verbatim for IPv6.
func Test_IPAddr_As16_MatchesNetip(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		if rapid.Bool().Draw(t, "four") {
			address := genIPv4Addr.Draw(t, "address")
			require.Equal(t, netip.AddrFrom4(address.As4()).As16(), xnetip.IPAddrFrom4(address).As16())
			return
		}
		address := genIPv6Addr.Draw(t, "address")
		require.Equal(t, address.As16(), xnetip.IPAddrFrom6(address).As16())
	})
}

// verifies that an IPv4 netip address converts to an IPv4 value.
func Test_IPAddrFromNetip_ConvertsIPv4(t *testing.T) {
	address := xnetip.IPAddrFromNetip(netip.MustParseAddr("10.0.0.1"))
	require.Equal(t, mustParseIPAddr4(t, "10.0.0.1"), address)
	require.True(t, address.Is4())
}

// verifies that an IPv6 netip address converts to an IPv6 value.
func Test_IPAddrFromNetip_ConvertsIPv6(t *testing.T) {
	address := xnetip.IPAddrFromNetip(netip.MustParseAddr("2001:db8::1"))
	require.Equal(t, mustParseIPAddr6(t, "2001:db8::1"), address)
	require.True(t, address.Is6())
}

// verifies that an IPv4-mapped netip address stays IPv6: the conversion
// follows the netip family, never the value range.
func Test_IPAddrFromNetip_Keeps4In6IPv6(t *testing.T) {
	address := xnetip.IPAddrFromNetip(netip.MustParseAddr("::ffff:10.0.0.1"))
	require.True(t, address.Is6())
	_, ok := address.IPv4()
	require.False(t, ok)
	require.Equal(t, mustParseIPAddr6(t, "::ffff:10.0.0.1"), address)
}

// verifies that a zone is dropped silently: the address converts to its
// bytes and the zone is gone, because addresses here are zone-free.
func Test_IPAddrFromNetip_DropsZone(t *testing.T) {
	address := xnetip.IPAddrFromNetip(netip.MustParseAddr("fe80::1%eth0"))
	require.Equal(t, mustParseIPAddr6(t, "fe80::1"), address)
}

// verifies that the invalid zero netip address maps onto the zero value
// ::, the documented lossy corner of the total conversion.
func Test_IPAddrFromNetip_MapsInvalidToZeroValue(t *testing.T) {
	require.Equal(t, xnetip.IPAddr{}, xnetip.IPAddrFromNetip(netip.Addr{}))
}

// verifies that the netip view of an IPv4 value is the 4-byte netip
// form, not the mapped 16-byte one.
func Test_IPAddr_Netip_IsIPv4ForIPv4(t *testing.T) {
	view := mustParseIPAddr4(t, "10.0.0.1").Netip()
	require.Equal(t, netip.MustParseAddr("10.0.0.1"), view)
	require.True(t, view.Is4())
}

// verifies that the netip view of an IPv6 value is valid and zone-free.
func Test_IPAddr_Netip_IsIPv6WithoutZone(t *testing.T) {
	view := mustParseIPAddr6(t, "2001:db8::1").Netip()
	require.Equal(t, netip.MustParseAddr("2001:db8::1"), view)
	require.True(t, view.IsValid())
	require.Empty(t, view.Zone())
}

// verifies that the netip view of a mapped value kept IPv6 stays in the
// mapped form: the 4in6 range, not the IPv4 family.
func Test_IPAddr_Netip_KeepsMappedForm(t *testing.T) {
	view := mustParseIPAddr6(t, "::ffff:1.2.3.4").Netip()
	require.True(t, view.Is4In6())
	require.False(t, view.Is4())
}

// verifies that the zero value converts to the valid IPv6 unspecified
// netip address.
func Test_IPAddr_Netip_ZeroValueIsIPv6Unspecified(t *testing.T) {
	view := xnetip.IPAddr{}.Netip()
	require.Equal(t, netip.IPv6Unspecified(), view)
	require.True(t, view.IsValid())
}

// verifies that a zoned netip address round-trips to its zone-free
// twin.
func Test_IPAddrFromNetip_RoundTripsZonedToZoneFree(t *testing.T) {
	zoned := netip.MustParseAddr("fe80::1%eth0")
	require.Equal(t, zoned.WithZone(""), xnetip.IPAddrFromNetip(zoned).Netip())
}

// verifies that converting the netip view back yields the address, for
// every address, family flag included.
func Test_IPAddrFromNetip_RoundTripsThroughNetip(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		address := genIPAddr.Draw(t, "address")
		require.Equal(t, address, xnetip.IPAddrFromNetip(address.Netip()))
	})
}

// verifies that every valid netip address round-trips to its zone-free
// twin with the family preserved.
func Test_IPAddrFromNetip_RoundTripsEveryValidNetipAddr(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		var oracle netip.Addr
		if rapid.Bool().Draw(t, "four") {
			oracle = netip.AddrFrom4(genIPv4Addr.Draw(t, "addr4").As4())
		} else {
			oracle = netip.AddrFrom16(genIPv6Addr.Draw(t, "addr6").As16())
			if rapid.Bool().Draw(t, "zoned") {
				oracle = oracle.WithZone("eth0")
			}
		}
		address := xnetip.IPAddrFromNetip(oracle)
		require.Equal(t, oracle.Is4(), address.Is4())
		require.Equal(t, oracle.WithZone(""), address.Netip())
	})
}

// verifies that the netip view prints exactly what the address prints,
// tying the family switch of the formatter to the std one.
func Test_IPAddr_Netip_AgreesWithStringForm(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		address := genIPAddr.Draw(t, "address")
		require.Equal(t, address.String(), address.Netip().String())
	})
}

// verifies that the conversions do not allocate in either direction.
func Test_IPAddrFromNetip_DoesNotAllocate(t *testing.T) {
	peer := netip.MustParseAddr("2001:db8::1")
	address := mustParseIPAddr4(t, "10.0.0.1")
	requireNoAllocs(t, func() {
		ipAddrSink = xnetip.IPAddrFromNetip(peer)
		netipAddrSink = address.Netip()
	})
}

// verifies that every IPv4 address sorts before every IPv6 address,
// even where the numeric values would order the other way.
func Test_IPAddr_Compare_IPv4BeforeIPv6(t *testing.T) {
	require.Equal(t, -1, mustParseIPAddr4(t, "1.2.3.4").Compare(mustParseIPAddr6(t, "::")))
	require.Equal(t, -1, mustParseIPAddr4(t, "255.255.255.255").Compare(mustParseIPAddr6(t, "::")))
}

// verifies that an IPv4 address sorts before its own mapped IPv6 twin:
// the same 16 bytes, but the families differ and never compare equal.
func Test_IPAddr_Compare_IPv4BeforeItsMappedTwin(t *testing.T) {
	four := mustParseIPAddr4(t, "1.2.3.4")
	six := mustParseIPAddr6(t, "::ffff:1.2.3.4")
	require.Equal(t, -1, four.Compare(six))
	require.Equal(t, 1, six.Compare(four))
}

// verifies that within one family the order is numeric, including
// across the IPv6 64-bit half boundary, and that equality compares 0.
func Test_IPAddr_Compare_OrdersNumericallyWithinFamily(t *testing.T) {
	cases := []struct {
		name        string
		left, right xnetip.IPAddr
		want        int
	}{
		{name: "reflexive", left: mustParseIPAddr4(t, "10.0.0.1"), right: mustParseIPAddr4(t, "10.0.0.1"), want: 0},
		{name: "adjacent IPv4", left: mustParseIPAddr4(t, "10.0.0.1"), right: mustParseIPAddr4(t, "10.0.0.2"), want: -1},
		{name: "IPv4 first octet dominates", left: mustParseIPAddr4(t, "9.255.255.255"), right: mustParseIPAddr4(t, "10.0.0.0"), want: -1},
		{name: "IPv6 across the half boundary", left: mustParseIPAddr6(t, "::ffff:ffff:ffff:ffff"), right: mustParseIPAddr6(t, "0:0:0:1::"), want: -1},
		{name: "IPv6 high word dominates", left: mustParseIPAddr6(t, "2001:db8::1"), right: mustParseIPAddr6(t, "2001:db9::"), want: -1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.want, tc.left.Compare(tc.right))
			require.Equal(t, -tc.want, tc.right.Compare(tc.left))
		})
	}
}

// verifies that the zero value is the smallest IPv6 address: below every
// other IPv6 address and above every IPv4 address.
func Test_IPAddr_Compare_ZeroValueIsSmallestIPv6(t *testing.T) {
	require.Equal(t, -1, xnetip.IPAddr{}.Compare(mustParseIPAddr6(t, "::1")))
	require.Equal(t, 1, xnetip.IPAddr{}.Compare(mustParseIPAddr4(t, "255.255.255.255")))
}

// verifies that sorting a mixed slice groups IPv4 first, each family
// numerically ascending.
func Test_IPAddr_Compare_SortsMixedSlice(t *testing.T) {
	addrs := []xnetip.IPAddr{
		mustParseIPAddr6(t, "2001:db8::1"),
		mustParseIPAddr4(t, "10.0.0.1"),
		mustParseIPAddr6(t, "::"),
		mustParseIPAddr4(t, "9.0.0.0"),
	}
	slices.SortFunc(addrs, xnetip.IPAddr.Compare)
	require.Equal(t, []xnetip.IPAddr{
		mustParseIPAddr4(t, "9.0.0.0"),
		mustParseIPAddr4(t, "10.0.0.1"),
		mustParseIPAddr6(t, "::"),
		mustParseIPAddr6(t, "2001:db8::1"),
	}, addrs)
}

// verifies that compare agrees with netip.Addr.Compare on every pair of
// zone-free addresses, which orders by bit length first and value next.
func Test_IPAddr_Compare_MatchesNetip(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		left := genIPAddr.Draw(t, "left")
		right := genIPAddr.Draw(t, "right")
		require.Equal(t, toNetipAddr(left).Compare(toNetipAddr(right)), left.Compare(right))
	})
}

// verifies that compare is antisymmetric and that every address compares
// equal to itself.
func Test_IPAddr_Compare_AntisymmetricAndReflexive(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		left := genIPAddr.Draw(t, "left")
		right := genIPAddr.Draw(t, "right")
		require.Equal(t, -right.Compare(left), left.Compare(right))
		require.Equal(t, 0, left.Compare(left))
	})
}

// verifies that compare is transitive: once three addresses are sorted
// by it, the first also sorts no later than the last.
func Test_IPAddr_Compare_Transitive(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		addrs := []xnetip.IPAddr{
			genIPAddr.Draw(t, "first"),
			genIPAddr.Draw(t, "second"),
			genIPAddr.Draw(t, "third"),
		}
		slices.SortFunc(addrs, xnetip.IPAddr.Compare)
		require.LessOrEqual(t, addrs[0].Compare(addrs[1]), 0)
		require.LessOrEqual(t, addrs[1].Compare(addrs[2]), 0)
		require.LessOrEqual(t, addrs[0].Compare(addrs[2]), 0)
	})
}

// verifies that compare reports 0 exactly when the two addresses are
// equal under ==, so the family flag splits the mapped twins in both.
func Test_IPAddr_Compare_ZeroIffEqual(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		left := genIPAddr.Draw(t, "left")
		right := genIPAddr.Draw(t, "right")
		if rapid.Bool().Draw(t, "same") {
			right = left
		}
		require.Equal(t, left == right, left.Compare(right) == 0)
	})
}

// verifies the family split on every cross-family pair.
func Test_IPAddr_Compare_SplitsFamilies(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		four := xnetip.IPAddrFrom4(genIPv4Addr.Draw(t, "four"))
		six := xnetip.IPAddrFrom6(genIPv6Addr.Draw(t, "six"))
		require.Equal(t, -1, four.Compare(six))
		require.Equal(t, 1, six.Compare(four))
	})
}

// verifies that a sorted random slice puts every IPv4 value before every
// IPv6 value, each run numerically non-decreasing.
func Test_IPAddr_Compare_SortGroupsFamilies(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		addrs := rapid.SliceOfN(genIPAddr, 0, 16).Draw(t, "addrs")
		slices.SortFunc(addrs, xnetip.IPAddr.Compare)
		sawSix := false
		for idx := range addrs {
			if addrs[idx].Is6() {
				sawSix = true
			} else {
				require.False(t, sawSix, "IPv4 after IPv6 at %d", idx)
			}
			if idx > 0 {
				require.LessOrEqual(t, addrs[idx-1].Compare(addrs[idx]), 0)
			}
		}
	})
}

// verifies that compare does not allocate.
func Test_IPAddr_Compare_DoesNotAllocate(t *testing.T) {
	left := mustParseIPAddr4(t, "10.0.0.1")
	right := mustParseIPAddr6(t, "2001:db8::1")
	requireNoAllocs(t, func() { intSink = left.Compare(right) })
}

// verifies the text of both families and the mapped special case, the
// contract of netip.Addr.String minus the invalid and zone cases.
func Test_IPAddr_String_FormatsBothFamilies(t *testing.T) {
	cases := []struct {
		name string
		addr xnetip.IPAddr
		want string
	}{
		{name: "IPv4 network address", addr: mustParseIPAddr4(t, "192.168.1.0"), want: "192.168.1.0"},
		{name: "IPv4 non-contiguous mask value", addr: mustParseIPAddr4(t, "255.255.0.255"), want: "255.255.0.255"},
		{name: "IPv4 prints without mapping prefix", addr: mustParseIPAddr4(t, "1.2.3.4"), want: "1.2.3.4"},
		{name: "IPv6 compressed", addr: mustParseIPAddr6(t, "2001:db8::"), want: "2001:db8::"},
		{name: "IPv6 mask value", addr: mustParseIPAddr6(t, "ffff:ffff::"), want: "ffff:ffff::"},
		{name: "zero value", addr: xnetip.IPAddr{}, want: "::"},
		{name: "loopback", addr: mustParseIPAddr6(t, "::1"), want: "::1"},
		{name: "mapped stored as IPv6", addr: mustParseIPAddr6(t, "::ffff:1.2.3.4"), want: "::ffff:1.2.3.4"},
		{name: "all ones IPv6 has no compression", addr: mustParseIPAddr6(t, "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"), want: "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.want, tc.addr.String())
		})
	}
}

// verifies that the text form is appended after the buffer's existing
// content.
func Test_IPAddr_AppendTo_AppendsAfterExistingContent(t *testing.T) {
	buffer := mustParseIPAddr4(t, "10.0.0.1").AppendTo([]byte("x="))
	require.Equal(t, "x=10.0.0.1", string(buffer))
}

// verifies that the appending form and the string form agree on every
// address.
func Test_IPAddr_AppendTo_AgreesWithString(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		address := genIPAddr.Draw(t, "address")
		require.Equal(t, address.String(), string(address.AppendTo(nil)))
	})
}

// verifies that the text agrees with net/netip for every address, the
// oracle that fixes the mapped form and the compression rules.
func Test_IPAddr_String_MatchesNetip(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		address := genIPAddr.Draw(t, "address")
		require.Equal(t, toNetipAddr(address).String(), address.String())
	})
}

// verifies that appending into a buffer with enough capacity does not
// allocate.
func Test_IPAddr_AppendTo_DoesNotAllocate(t *testing.T) {
	address := mustParseIPAddr6(t, "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff")
	buffer := make([]byte, 0, 64)
	requireNoAllocs(t, func() { bytesSink = address.AppendTo(buffer[:0]) })
}

// verifies that the string form allocates exactly once, for the result
// itself, so a regression to a second allocation is visible.
func Test_IPAddr_String_AllocatesOnce(t *testing.T) {
	address := mustParseIPAddr6(t, "2001:db8::1")
	allocs := int(testing.AllocsPerRun(100, func() { stringSink = address.String() }))
	require.Equal(t, 1, allocs)
}

// verifies that both families parse from their text with the family
// taken from the text: dots mean IPv4, colons mean IPv6.
func Test_ParseIPAddr_AcceptsBothFamilies(t *testing.T) {
	cases := []struct {
		name string
		text string
		want xnetip.IPAddr
	}{
		{name: "bare IPv4", text: "192.168.1.1", want: mustParseIPAddr4(t, "192.168.1.1")},
		{name: "IPv4 zero", text: "0.0.0.0", want: mustParseIPAddr4(t, "0.0.0.0")},
		{name: "IPv4 broadcast", text: "255.255.255.255", want: mustParseIPAddr4(t, "255.255.255.255")},
		{name: "bare IPv6", text: "2001:db8::1", want: mustParseIPAddr6(t, "2001:db8::1")},
		{name: "IPv6 full form", text: "2001:db8:0:0:0:0:0:1", want: mustParseIPAddr6(t, "2001:db8::1")},
		{name: "IPv6 unspecified", text: "::", want: xnetip.IPAddr{}},
		{name: "IPv6 loopback", text: "::1", want: mustParseIPAddr6(t, "::1")},
		{name: "compression at the end", text: "1:2:3:4:5:6:7::", want: mustParseIPAddr6(t, "1:2:3:4:5:6:7:0")},
		{name: "compression at the start", text: "::1:2:3:4:5:6:7", want: mustParseIPAddr6(t, "0:1:2:3:4:5:6:7")},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			address, err := xnetip.ParseIPAddr(tc.text)
			require.NoError(t, err)
			require.Equal(t, tc.want, address)
		})
	}
}

// verifies that the IPv4-mapped text form stays IPv6: the family flag
// follows the text, not the value range.
func Test_ParseIPAddr_KeepsMappedTextIPv6(t *testing.T) {
	address, err := xnetip.ParseIPAddr("::ffff:1.2.3.4")
	require.NoError(t, err)
	require.True(t, address.Is6())
	require.Equal(t, [16]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 1, 2, 3, 4}, address.As16())
	_, ok := address.IPv4()
	require.False(t, ok)
}

// verifies that an embedded IPv4 quad in the last two groups parses as
// the equivalent hex groups.
func Test_ParseIPAddr_AcceptsEmbeddedIPv4InLastPosition(t *testing.T) {
	address, err := xnetip.ParseIPAddr("1:2:3:4:5:6:1.2.3.4")
	require.NoError(t, err)
	require.Equal(t, mustParseIPAddr6(t, "1:2:3:4:5:6:102:304"), address)
}

// verifies that malformed text of either family is rejected with an
// error wrapping the parse sentinel.
//
// The shapes cover the pinned malformed set of the Rust reference:
// leading-zero octets, octet overflow, wrong group counts, double
// compression, oversized hex groups, a misplaced embedded quad, network
// suffixes, whitespace and port-like garbage.
func Test_ParseIPAddr_RejectsMalformedText(t *testing.T) {
	malformed := []string{
		"01.2.3.4", "1.2.3.04", "00.0.0.0",
		"256.0.0.0", "0.0.0.999",
		"1.2.3", "1.2.3.4.5", "1..2.3", ".",
		"1::2::3", ":::", "::1::",
		"12345::", "1:22222:3::",
		"1.2.3.4::", "::1.2.3.4:5",
		"", "hello", "zz", "/", "/24", "10.0.0.1/",
		"10.0.0.1/24", "2001:db8::1/32",
		" 10.0.0.1", "10.0.0.1 ", "::1\n",
		"1.2.3.4:80",
	}
	for _, text := range malformed {
		_, err := xnetip.ParseIPAddr(text)
		require.ErrorIs(t, err, xnetip.ErrParse, "input %q", text)
	}
}

// verifies that a zone suffix is rejected with the zone sentinel alone,
// even though net/netip accepts it.
func Test_ParseIPAddr_RejectsZone(t *testing.T) {
	for _, text := range []string{"fe80::1%eth0", "fe80::1%0"} {
		_, err := xnetip.ParseIPAddr(text)
		require.ErrorIs(t, err, xnetip.ErrZone, "input %q", text)
		require.NotErrorIs(t, err, xnetip.ErrParse, "input %q", text)
	}
}

// verifies that a percent sign without an address is a plain parse
// error, not a zone rejection: net/netip fails before the zone check.
func Test_ParseIPAddr_PercentWithoutAddressIsParseError(t *testing.T) {
	_, err := xnetip.ParseIPAddr("%eth0")
	require.ErrorIs(t, err, xnetip.ErrParse)
	require.NotErrorIs(t, err, xnetip.ErrZone)
}

// verifies that the error names the parser and echoes the input.
func Test_ParseIPAddr_ErrorEchoesInput(t *testing.T) {
	_, err := xnetip.ParseIPAddr("zz")
	require.ErrorContains(t, err, "xnetip.ParseIPAddr")
	require.ErrorContains(t, err, `"zz"`)
}

// verifies that the must variant panics on invalid text and parses the
// same values otherwise.
func Test_MustParseIPAddr_PanicsOnInvalidText(t *testing.T) {
	require.Panics(t, func() { xnetip.MustParseIPAddr("zz") })
	require.Equal(t, mustParseIPAddr4(t, "10.0.0.1"), xnetip.MustParseIPAddr("10.0.0.1"))
}

// verifies that the parser inverts the formatter on every address,
// family flag included: mapped-as-IPv6 values come back IPv6.
func Test_ParseIPAddr_RoundTripsString(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		address := genIPAddr.Draw(t, "address")
		back, err := xnetip.ParseIPAddr(address.String())
		require.NoError(t, err)
		require.Equal(t, address, back)
	})
}

// verifies that every string net/netip prints for a random zone-free
// address parses back with the same family and bytes.
func Test_ParseIPAddr_ParsesEveryNetipString(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		var oracle netip.Addr
		if rapid.Bool().Draw(t, "four") {
			oracle = netip.AddrFrom4(genIPv4Addr.Draw(t, "addr4").As4())
		} else {
			oracle = netip.AddrFrom16(genIPv6Addr.Draw(t, "addr6").As16())
		}
		address, err := xnetip.ParseIPAddr(oracle.String())
		require.NoError(t, err)
		require.Equal(t, oracle.Is4(), address.Is4())
		require.Equal(t, oracle.As16(), address.As16())
	})
}

// verifies accept/reject parity with net/netip on short strings over the
// characters of the address grammar plus a few easy-to-confuse extras.
//
// Drawing from that alphabet rather than from arbitrary bytes exercises
// the parity close to the accept boundary.
func Test_ParseIPAddr_NearMissParityWithNetip(t *testing.T) {
	alphabet := []byte(".:/%+ x0123456789abcdef")
	rapid.Check(t, func(t *rapid.T) {
		text := string(rapid.SliceOfN(rapid.SampledFrom(alphabet), 0, 24).Draw(t, "text"))
		requireParseIPAddrMatchesNetip(t, text)
	})
}

// verifies accept/reject parity with net/netip on the text of a valid
// address with one byte deleted or replaced by an arbitrary byte.
func Test_ParseIPAddr_MutationParityWithNetip(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		text := []byte(genIPAddr.Draw(t, "address").String())
		position := rapid.IntRange(0, len(text)-1).Draw(t, "position")
		if rapid.Bool().Draw(t, "delete") {
			text = slices.Delete(text, position, position+1)
		} else {
			text[position] = rapid.Byte().Draw(t, "replacement")
		}
		requireParseIPAddrMatchesNetip(t, string(text))
	})
}

// verifies accept/reject parity and value agreement with net/netip on
// arbitrary text, seeded with every input of the unit tables.
func FuzzParseIPAddr(f *testing.F) {
	seeds := []string{
		"192.168.1.1", "0.0.0.0", "255.255.255.255", "10.0.0.1", "1.2.3.4",
		"2001:db8::1", "2001:db8:0:0:0:0:0:1", "::", "::1",
		"1:2:3:4:5:6:7::", "::1:2:3:4:5:6:7", "1:2:3:4:5:6:1.2.3.4",
		"::ffff:1.2.3.4", "::ffff:192.0.2.1",
		"01.2.3.4", "1.2.3.04", "00.0.0.0", "256.0.0.0", "0.0.0.999",
		"1.2.3", "1.2.3.4.5", "1..2.3", ".",
		"1::2::3", ":::", "::1::", "12345::", "1:22222:3::",
		"1.2.3.4::", "::1.2.3.4:5",
		"", "hello", "zz", "/", "/24", "10.0.0.1/", "10.0.0.1/24", "2001:db8::1/32",
		" 10.0.0.1", "10.0.0.1 ", "::1\n", "1.2.3.4:80",
		"fe80::1%eth0", "fe80::1%0", "%eth0",
	}
	for _, seed := range seeds {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, text string) {
		requireParseIPAddrMatchesNetip(t, text)
	})
}

// requireParseIPAddrMatchesNetip asserts that the parser accepts text
// exactly when net/netip parses it without a zone, value included.
//
// On netip success the family and the bytes must agree, and zoned text
// must be rejected with the zone sentinel.
func requireParseIPAddrMatchesNetip(t require.TestingT, text string) {
	if helper, ok := t.(interface{ Helper() }); ok {
		helper.Helper()
	}
	got, err := xnetip.ParseIPAddr(text)
	want, wantErr := netip.ParseAddr(text)
	if wantErr != nil {
		require.Error(t, err, "input %q", text)
		return
	}
	if want.Zone() != "" {
		require.ErrorIs(t, err, xnetip.ErrZone, "input %q", text)
		return
	}
	require.NoError(t, err, "input %q", text)
	require.Equal(t, want.Is4(), got.Is4(), "input %q", text)
	require.Equal(t, want.As16(), got.As16(), "input %q", text)
}

// verifies that parsing valid text of either family does not allocate:
// the error wrapping is the only allocating path.
func Test_ParseIPAddr_DoesNotAllocate(t *testing.T) {
	four, six := "192.168.0.1", "2001:db8::1"
	requireNoAllocs(t, func() {
		ipAddrSink, errSink = xnetip.ParseIPAddr(four)
		ipAddrSink, errSink = xnetip.ParseIPAddr(six)
	})
}

func BenchmarkParseIPAddr_IPv4Short(b *testing.B) {
	text := "1.2.3.4"
	b.ReportAllocs()
	for b.Loop() {
		ipAddrSink, errSink = xnetip.ParseIPAddr(text)
	}
}

func BenchmarkParseIPAddr_IPv4Long(b *testing.B) {
	text := "255.255.255.255"
	b.ReportAllocs()
	for b.Loop() {
		ipAddrSink, errSink = xnetip.ParseIPAddr(text)
	}
}

func BenchmarkParseIPAddr_IPv6Compressed(b *testing.B) {
	text := "2001:db8::1"
	b.ReportAllocs()
	for b.Loop() {
		ipAddrSink, errSink = xnetip.ParseIPAddr(text)
	}
}

func BenchmarkParseIPAddr_IPv6Full(b *testing.B) {
	text := "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"
	b.ReportAllocs()
	for b.Loop() {
		ipAddrSink, errSink = xnetip.ParseIPAddr(text)
	}
}

func BenchmarkParseIPAddr_IPv6Mapped(b *testing.B) {
	text := "::ffff:192.0.2.1"
	b.ReportAllocs()
	for b.Loop() {
		ipAddrSink, errSink = xnetip.ParseIPAddr(text)
	}
}

func BenchmarkParseIPAddr_Reject(b *testing.B) {
	text := "1.2.3.4:80"
	b.ReportAllocs()
	for b.Loop() {
		ipAddrSink, errSink = xnetip.ParseIPAddr(text)
	}
}

// verifies that marshalling emits exactly the string form for both
// families and the mapped special case.
func Test_IPAddr_MarshalText_EmitsStringForm(t *testing.T) {
	cases := []struct {
		name string
		addr xnetip.IPAddr
		want string
	}{
		{name: "IPv4", addr: mustParseIPAddr4(t, "192.168.1.0"), want: "192.168.1.0"},
		{name: "IPv6", addr: mustParseIPAddr6(t, "2001:db8::"), want: "2001:db8::"},
		{name: "mapped stored as IPv6", addr: mustParseIPAddr6(t, "::ffff:1.2.3.4"), want: "::ffff:1.2.3.4"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := tc.addr.MarshalText()
			require.NoError(t, err)
			require.Equal(t, tc.want, string(got))
		})
	}
}

// verifies that the zero value marshals as its address text, not as
// empty text, because it is the real address ::.
func Test_IPAddr_MarshalText_ZeroValueIsUnspecified(t *testing.T) {
	got, err := xnetip.IPAddr{}.MarshalText()
	require.NoError(t, err)
	require.Equal(t, "::", string(got))
}

// verifies that unmarshalling accepts what the parser accepts, family
// flag included.
func Test_IPAddr_UnmarshalText_AcceptsValidText(t *testing.T) {
	var address xnetip.IPAddr
	require.NoError(t, address.UnmarshalText([]byte("10.0.0.1")))
	require.Equal(t, mustParseIPAddr4(t, "10.0.0.1"), address)
	require.NoError(t, address.UnmarshalText([]byte("::1")))
	require.Equal(t, mustParseIPAddr6(t, "::1"), address)
	require.NoError(t, address.UnmarshalText([]byte("::ffff:1.2.3.4")))
	require.True(t, address.Is6())
}

// verifies that empty text is an error and leaves the receiver
// untouched: an absent value must not silently decode into ::.
func Test_IPAddr_UnmarshalText_RejectsEmptyText(t *testing.T) {
	address := mustParseIPAddr4(t, "10.0.0.1")
	require.Error(t, address.UnmarshalText([]byte("")))
	require.Equal(t, mustParseIPAddr4(t, "10.0.0.1"), address)
}

// verifies that garbage is rejected and the receiver is left untouched.
func Test_IPAddr_UnmarshalText_KeepsReceiverOnError(t *testing.T) {
	address := mustParseIPAddr6(t, "2001:db8::1")
	require.Error(t, address.UnmarshalText([]byte("zz")))
	require.Equal(t, mustParseIPAddr6(t, "2001:db8::1"), address)
}

// verifies that a zone suffix is rejected with the zone sentinel.
func Test_IPAddr_UnmarshalText_RejectsZone(t *testing.T) {
	var address xnetip.IPAddr
	require.ErrorIs(t, address.UnmarshalText([]byte("fe80::1%eth0")), xnetip.ErrZone)
}

// verifies that a struct field of the type round-trips through JSON as
// its address text.
func Test_IPAddr_MarshalText_JSONRoundTripsStructField(t *testing.T) {
	type payload struct{ A xnetip.IPAddr }
	original := payload{A: mustParseIPAddr4(t, "1.2.3.4")}
	encoded, err := json.Marshal(original)
	require.NoError(t, err)
	require.JSONEq(t, `{"A":"1.2.3.4"}`, string(encoded))
	var decoded payload
	require.NoError(t, json.Unmarshal(encoded, &decoded))
	require.Equal(t, original, decoded)
}

// verifies that the type works as a JSON map key through the text
// interfaces.
func Test_IPAddr_MarshalText_JSONRoundTripsMapKey(t *testing.T) {
	original := map[xnetip.IPAddr]int{mustParseIPAddr6(t, "::1"): 1}
	encoded, err := json.Marshal(original)
	require.NoError(t, err)
	require.JSONEq(t, `{"::1":1}`, string(encoded))
	var decoded map[xnetip.IPAddr]int
	require.NoError(t, json.Unmarshal(encoded, &decoded))
	require.Equal(t, original, decoded)
}

// verifies that a JSON null leaves the field untouched without an
// error, the encoding/json contract for text unmarshalers.
func Test_IPAddr_UnmarshalText_JSONNullKeepsField(t *testing.T) {
	type payload struct{ A xnetip.IPAddr }
	decoded := payload{A: mustParseIPAddr4(t, "1.2.3.4")}
	require.NoError(t, json.Unmarshal([]byte(`{"A":null}`), &decoded))
	require.Equal(t, mustParseIPAddr4(t, "1.2.3.4"), decoded.A)
}

// verifies that the marshalled text equals the string form on every
// address.
func Test_IPAddr_MarshalText_AgreesWithString(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		address := genIPAddr.Draw(t, "address")
		text, err := address.MarshalText()
		require.NoError(t, err)
		require.Equal(t, address.String(), string(text))
	})
}

// verifies that unmarshalling the marshalled text restores every
// address, family flag included.
func Test_IPAddr_MarshalText_RoundTripsThroughUnmarshal(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		address := genIPAddr.Draw(t, "address")
		text, err := address.MarshalText()
		require.NoError(t, err)
		var decoded xnetip.IPAddr
		require.NoError(t, decoded.UnmarshalText(text))
		require.Equal(t, address, decoded)
	})
}

// verifies that a JSON slice of addresses round-trips as the identity.
func Test_IPAddr_MarshalText_JSONRoundTripsSlice(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		addrs := rapid.SliceOfN(genIPAddr, 0, 8).Draw(t, "addrs")
		encoded, err := json.Marshal(addrs)
		require.NoError(t, err)
		var decoded []xnetip.IPAddr
		require.NoError(t, json.Unmarshal(encoded, &decoded))
		if len(addrs) == 0 {
			require.Empty(t, decoded)
			return
		}
		require.Equal(t, addrs, decoded)
	})
}

// verifies that the marshalled text agrees with net/netip for every
// address.
//
// The netip oracle is built from the family and the bytes, so it is
// always a valid address and never hits netip's empty-text zero case.
func Test_IPAddr_MarshalText_MatchesNetip(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		address := genIPAddr.Draw(t, "address")
		want, wantErr := toNetipAddr(address).MarshalText()
		require.NoError(t, wantErr)
		got, err := address.MarshalText()
		require.NoError(t, err)
		require.Equal(t, want, got)
	})
}

// verifies that marshalling allocates exactly once, for the returned
// text itself, even in the longest form.
func Test_IPAddr_MarshalText_AllocatesOnce(t *testing.T) {
	address := mustParseIPAddr6(t, "ffff:ffff:ffff:ffff:ffff:ffff:255.255.255.255")
	allocs := int(testing.AllocsPerRun(100, func() { bytesSink, errSink = address.MarshalText() }))
	require.Equal(t, 1, allocs)
}

// verifies that the unmarshal success path allocates at most once, for
// the string conversion of the input bytes.
func Test_IPAddr_UnmarshalText_AllocatesAtMostOnce(t *testing.T) {
	text := []byte("2001:db8::1")
	var address xnetip.IPAddr
	allocs := int(testing.AllocsPerRun(100, func() { errSink = address.UnmarshalText(text) }))
	require.LessOrEqual(t, allocs, 1)
}

// mustParseIPAddr4 builds an IPv4 IPAddr from dotted-decimal text.
func mustParseIPAddr4(t require.TestingT, s string) xnetip.IPAddr {
	if helper, ok := t.(interface{ Helper() }); ok {
		helper.Helper()
	}
	return xnetip.IPAddrFrom4(xnetip.MustParseIPv4Addr(s))
}

// mustParseIPAddr6 builds an IPv6 IPAddr from RFC 5952 text.
func mustParseIPAddr6(t require.TestingT, s string) xnetip.IPAddr {
	if helper, ok := t.(interface{ Helper() }); ok {
		helper.Helper()
	}
	return xnetip.IPAddrFrom6(xnetip.MustParseIPv6Addr(s))
}

// toNetipAddr converts an IPAddr to the netip.Addr with the same family
// and bytes, bypassing the public conversions under test.
func toNetipAddr(address xnetip.IPAddr) netip.Addr {
	if v4, ok := address.IPv4(); ok {
		return netip.AddrFrom4(v4.As4())
	}
	return netip.AddrFrom16(address.As16())
}

// verifies that the constructors and the accessors do not allocate.
func Test_IPAddr_Construction_DoesNotAllocate(t *testing.T) {
	four := xnetip.MustParseIPv4Addr("192.168.1.0")
	six := xnetip.MustParseIPv6Addr("2001:db8::1")
	var octets [16]byte
	requireNoAllocs(t, func() {
		ipAddrSink = xnetip.IPAddrFrom4(four)
		boolSink = ipAddrSink.Is4()
		boolSink = ipAddrSink.Is6()
		ipv4AddrSink, boolSink = ipAddrSink.IPv4()
		ipv6AddrSink, boolSink = xnetip.IPAddrFrom6(six).IPv6()
		octets = ipAddrSink.As16()
		intSink = ipAddrSink.BitLen()
	})
	_ = octets
}

// verifies that the IPv4 loopback address is loopback and, like every
// loopback address, not global unicast.
func Test_IPAddr_IsLoopback_IPv4Loopback(t *testing.T) {
	address := mustParseIPAddr4(t, "127.0.0.1")
	require.True(t, address.IsLoopback())
	require.False(t, address.IsGlobalUnicast())
}

// verifies that the IPv6 loopback address is loopback.
func Test_IPAddr_IsLoopback_IPv6Loopback(t *testing.T) {
	require.True(t, mustParseIPAddr6(t, "::1").IsLoopback())
}

// verifies that a mapped loopback kept in the IPv6 family is classified
// by its embedded IPv4 part while staying IPv6, the net/netip rule.
func Test_IPAddr_IsLoopback_MappedLoopbackStaysIPv6(t *testing.T) {
	address := mustParseIPAddr6(t, "::ffff:127.0.0.1")
	require.True(t, address.IsLoopback())
	require.True(t, address.Is4In6())
	require.False(t, address.Is4())
}

// verifies that an IPv4 value is not 4in6 even though its storage is
// mapped.
func Test_IPAddr_Is4In6_FalseForIPv4Value(t *testing.T) {
	require.False(t, mustParseIPAddr4(t, "1.2.3.4").Is4In6())
}

// verifies that private addresses of both families and a mapped private
// address all report private.
func Test_IPAddr_IsPrivate_BothFamiliesAndMapped(t *testing.T) {
	require.True(t, mustParseIPAddr4(t, "10.0.0.1").IsPrivate())
	require.True(t, mustParseIPAddr6(t, "fc00::1").IsPrivate())
	require.True(t, mustParseIPAddr6(t, "::ffff:192.168.0.1").IsPrivate())
}

// verifies that multicast addresses of both families report multicast.
func Test_IPAddr_IsMulticast_BothFamilies(t *testing.T) {
	require.True(t, mustParseIPAddr4(t, "224.0.0.1").IsMulticast())
	require.True(t, mustParseIPAddr6(t, "ff02::1").IsMulticast())
}

// verifies that interface-local multicast is IPv6-only: true for scope
// 1, false for an IPv4 value and for a mapped IPv4 multicast address.
func Test_IPAddr_IsInterfaceLocalMulticast_IPv6Only(t *testing.T) {
	require.True(t, mustParseIPAddr6(t, "ff01::1").IsInterfaceLocalMulticast())
	require.False(t, mustParseIPAddr4(t, "224.0.0.1").IsInterfaceLocalMulticast())
	require.False(t, mustParseIPAddr6(t, "::ffff:224.0.0.1").IsInterfaceLocalMulticast())
}

// verifies that link-local unicast addresses of both families report
// link-local unicast.
func Test_IPAddr_IsLinkLocalUnicast_BothFamilies(t *testing.T) {
	require.True(t, mustParseIPAddr4(t, "169.254.1.1").IsLinkLocalUnicast())
	require.True(t, mustParseIPAddr6(t, "fe80::1").IsLinkLocalUnicast())
}

// verifies that the unspecified address of each family reports
// unspecified, the zero value being the IPv6 one.
func Test_IPAddr_IsUnspecified_BothFamilies(t *testing.T) {
	require.True(t, mustParseIPAddr4(t, "0.0.0.0").IsUnspecified())
	require.True(t, xnetip.IPAddr{}.IsUnspecified())
}

// verifies that the mapped zero address kept in the IPv6 family is not
// unspecified: it is a different 128-bit value than ::.
func Test_IPAddr_IsUnspecified_MappedZeroIsNot(t *testing.T) {
	require.False(t, mustParseIPAddr6(t, "::ffff:0.0.0.0").IsUnspecified())
}

// verifies that ordinary public addresses of both families report
// global unicast.
func Test_IPAddr_IsGlobalUnicast_BothFamilies(t *testing.T) {
	require.True(t, mustParseIPAddr4(t, "8.8.8.8").IsGlobalUnicast())
	require.True(t, mustParseIPAddr6(t, "2001:db8::1").IsGlobalUnicast())
}

// verifies that unmapping an IPv4-mapped address collapses it into the
// IPv4 family with the embedded octets.
func Test_IPAddr_Unmap_CollapsesMappedToIPv4(t *testing.T) {
	unmapped := mustParseIPAddr6(t, "::ffff:192.0.2.1").Unmap()
	require.Equal(t, mustParseIPAddr4(t, "192.0.2.1"), unmapped)
	require.True(t, unmapped.Is4())
}

// verifies that unmapping an IPv4 value returns it unchanged.
func Test_IPAddr_Unmap_IPv4Unchanged(t *testing.T) {
	address := mustParseIPAddr4(t, "192.168.0.0")
	require.Equal(t, address, address.Unmap())
}

// verifies that unmapping a plain IPv6 address returns it unchanged.
func Test_IPAddr_Unmap_PlainIPv6Unchanged(t *testing.T) {
	address := mustParseIPAddr6(t, "2001:db8::")
	require.Equal(t, address, address.Unmap())
}

// verifies that the deprecated IPv4-compatible form is not mapped and
// passes through unmapping unchanged.
func Test_IPAddr_Unmap_IPv4CompatibleUnchanged(t *testing.T) {
	address := mustParseIPAddr6(t, "::c00a:2ff")
	require.Equal(t, address, address.Unmap())
}

// verifies that unmapping is idempotent on a mapped address.
func Test_IPAddr_Unmap_Idempotent(t *testing.T) {
	once := mustParseIPAddr6(t, "::ffff:1.2.3.4").Unmap()
	require.Equal(t, once, once.Unmap())
}

// verifies that the IPv4 increment carries across an octet boundary and
// fails at the top of the IPv4 family instead of crossing into IPv6.
func Test_IPAddr_Next_IPv4CarriesAndStopsAtTop(t *testing.T) {
	next, ok := mustParseIPAddr4(t, "10.0.0.255").Next()
	require.True(t, ok)
	require.Equal(t, mustParseIPAddr4(t, "10.0.1.0"), next)
	_, ok = mustParseIPAddr4(t, "255.255.255.255").Next()
	require.False(t, ok)
}

// verifies that the IPv6 increment carries across the 64-bit half
// boundary and fails at the all-ones address.
func Test_IPAddr_Next_IPv6CarriesAndStopsAtTop(t *testing.T) {
	next, ok := mustParseIPAddr6(t, "::ffff:ffff:ffff:ffff").Next()
	require.True(t, ok)
	require.Equal(t, mustParseIPAddr6(t, "0:0:0:1::"), next)
	_, ok = mustParseIPAddr6(t, "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff").Next()
	require.False(t, ok)
}

// verifies that the decrement fails at the bottom of each family.
func Test_IPAddr_Prev_FailsAtFamilyBottoms(t *testing.T) {
	_, ok := mustParseIPAddr4(t, "0.0.0.0").Prev()
	require.False(t, ok)
	_, ok = xnetip.IPAddr{}.Prev()
	require.False(t, ok)
}

// verifies that the increment of an IPv4 value stays IPv4.
func Test_IPAddr_Next_KeepsFamily(t *testing.T) {
	next, ok := mustParseIPAddr4(t, "1.2.3.4").Next()
	require.True(t, ok)
	require.True(t, next.Is4())
}

// verifies that every predicate agrees with net/netip on every address.
//
// The generator mixes both families with mapped-as-IPv6 values, so the
// differential suite exercises the family switch and the mapped branch,
// not only uniform luck.
func Test_IPAddr_Predicates_MatchNetip(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		address := genIPAddr.Draw(t, "address")
		oracle := toNetipAddr(address)
		require.Equal(t, oracle.IsUnspecified(), address.IsUnspecified())
		require.Equal(t, oracle.Is4In6(), address.Is4In6())
		require.Equal(t, oracle.IsLoopback(), address.IsLoopback())
		require.Equal(t, oracle.IsPrivate(), address.IsPrivate())
		require.Equal(t, oracle.IsMulticast(), address.IsMulticast())
		require.Equal(t, oracle.IsLinkLocalUnicast(), address.IsLinkLocalUnicast())
		require.Equal(t, oracle.IsLinkLocalMulticast(), address.IsLinkLocalMulticast())
		require.Equal(t, oracle.IsInterfaceLocalMulticast(), address.IsInterfaceLocalMulticast())
		require.Equal(t, oracle.IsGlobalUnicast(), address.IsGlobalUnicast())
	})
}

// verifies that unmapping agrees with net/netip in family and bytes on
// every address, is idempotent, and never leaves a mapped result.
func Test_IPAddr_Unmap_MatchesNetip(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		address := genIPAddr.Draw(t, "address")
		unmapped := address.Unmap()
		oracle := toNetipAddr(address).Unmap()
		require.Equal(t, oracle.Is4(), unmapped.Is4())
		require.Equal(t, oracle.As16(), unmapped.As16())
		require.Equal(t, unmapped, unmapped.Unmap())
		require.False(t, unmapped.Is4In6())
		if address.Is4() {
			require.Equal(t, address, unmapped)
		}
	})
}

// verifies that the increment agrees with net/netip: it exists exactly
// when netip's next address is valid, with the same family and bytes.
func Test_IPAddr_Next_MatchesNetip(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		address := genIPAddr.Draw(t, "address")
		next, ok := address.Next()
		oracle := toNetipAddr(address).Next()
		require.Equal(t, oracle.IsValid(), ok)
		if ok {
			require.Equal(t, oracle.Is4(), next.Is4())
			require.Equal(t, oracle.As16(), next.As16())
		}
	})
}

// verifies that the decrement agrees with net/netip: it exists exactly
// when netip's previous address is valid, with the same family and bytes.
func Test_IPAddr_Prev_MatchesNetip(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		address := genIPAddr.Draw(t, "address")
		prev, ok := address.Prev()
		oracle := toNetipAddr(address).Prev()
		require.Equal(t, oracle.IsValid(), ok)
		if ok {
			require.Equal(t, oracle.Is4(), prev.Is4())
			require.Equal(t, oracle.As16(), prev.As16())
		}
	})
}

// verifies that the decrement undoes the increment whenever the
// increment exists.
func Test_IPAddr_Next_ThenPrev_RoundTrips(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		address := genIPAddr.Draw(t, "address")
		next, ok := address.Next()
		if !ok {
			t.Skip("no next address")
		}
		prev, ok := next.Prev()
		require.True(t, ok)
		require.Equal(t, address, prev)
	})
}

// verifies that the predicates, the unmapping, the increment and the
// decrement do not allocate.
func Test_IPAddr_Predicates_DoNotAllocate(t *testing.T) {
	address := mustParseIPAddr6(t, "::ffff:192.0.2.1")
	requireNoAllocs(t, func() {
		boolSink = address.IsUnspecified()
		boolSink = address.IsLoopback()
		boolSink = address.IsPrivate()
		boolSink = address.IsMulticast()
		boolSink = address.IsLinkLocalUnicast()
		boolSink = address.IsLinkLocalMulticast()
		boolSink = address.IsInterfaceLocalMulticast()
		boolSink = address.IsGlobalUnicast()
		boolSink = address.Is4In6()
		ipAddrSink = address.Unmap()
		ipAddrSink, boolSink = address.Next()
		ipAddrSink, boolSink = address.Prev()
	})
}

// verifies that an IPv4 address maps into ::ffff:a.b.c.d.
func Test_IPAddr_ToIPv6Mapped_MapsIPv4(t *testing.T) {
	mapped := mustParseIPAddr4(t, "192.168.1.0").ToIPv6Mapped()
	require.Equal(t, xnetip.MustParseIPv6Addr("::ffff:c0a8:100"), mapped)
}

// verifies that the mapping keeps every octet, not only the aligned
// ones.
func Test_IPAddr_ToIPv6Mapped_MapsNonTrivialOctets(t *testing.T) {
	mapped := mustParseIPAddr4(t, "192.168.0.1").ToIPv6Mapped()
	require.Equal(t, xnetip.MustParseIPv6Addr("::ffff:c0a8:1"), mapped)
}

// verifies that the IPv4 zero address maps into the mapped zero, not
// into ::.
func Test_IPAddr_ToIPv6Mapped_MapsIPv4Zero(t *testing.T) {
	mapped := mustParseIPAddr4(t, "0.0.0.0").ToIPv6Mapped()
	require.Equal(t, xnetip.MustParseIPv6Addr("::ffff:0.0.0.0"), mapped)
}

// verifies that an IPv6 address passes through unchanged.
func Test_IPAddr_ToIPv6Mapped_IPv6Identity(t *testing.T) {
	six := xnetip.MustParseIPv6Addr("2001:db8::")
	require.Equal(t, six, xnetip.IPAddrFrom6(six).ToIPv6Mapped())
}

// verifies that an IPv6 address with bits in both halves passes through
// unchanged.
func Test_IPAddr_ToIPv6Mapped_IPv6IdentityNonTrivial(t *testing.T) {
	six := xnetip.MustParseIPv6Addr("2a02:6b8:c00::1234:abcd:0:0")
	require.Equal(t, six, xnetip.IPAddrFrom6(six).ToIPv6Mapped())
}

// verifies that a mapped address kept in the IPv6 family passes through
// unchanged.
func Test_IPAddr_ToIPv6Mapped_MappedAsIPv6Identity(t *testing.T) {
	six := xnetip.MustParseIPv6Addr("::ffff:1.2.3.4")
	require.Equal(t, six, xnetip.IPAddrFrom6(six).ToIPv6Mapped())
}

// verifies that the zero value maps to the IPv6 unspecified address.
func Test_IPAddr_ToIPv6Mapped_ZeroValue(t *testing.T) {
	require.Equal(t, xnetip.IPv6Addr{}, xnetip.IPAddr{}.ToIPv6Mapped())
}

// verifies that the mapped view holds exactly the 16-byte form of the
// address, for an IPv4 value in particular.
func Test_IPAddr_ToIPv6Mapped_AgreesWithAs16(t *testing.T) {
	address := mustParseIPAddr4(t, "1.2.3.4")
	require.Equal(t, address.As16(), address.ToIPv6Mapped().As16())
}

// verifies that the mapped view keeps the 16-byte form of every
// address and agrees with the netip 16-byte form, which is also mapped.
func Test_IPAddr_ToIPv6Mapped_MatchesAs16AndNetip(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		address := genIPAddr.Draw(t, "address")
		mapped := address.ToIPv6Mapped()
		require.Equal(t, address.As16(), mapped.As16())
		require.Equal(t, toNetipAddr(address).As16(), mapped.As16())
	})
}

// verifies that the mapped view of an IPv4 value is 4in6 and extracts
// back to the same IPv4 address.
func Test_IPAddr_ToIPv6Mapped_RoundTripsIPv4(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		address := genIPAddr.Draw(t, "address")
		if !address.Is4() {
			t.Skip("IPv6 value")
		}
		mapped := address.ToIPv6Mapped()
		require.True(t, mapped.Is4In6())
		extracted, ok := mapped.ToIPv4Mapped()
		require.True(t, ok)
		expected, ok := address.IPv4()
		require.True(t, ok)
		require.Equal(t, expected, extracted)
	})
}

// verifies that the mapped view of an IPv6 value is the value itself.
func Test_IPAddr_ToIPv6Mapped_IdentityOnIPv6(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		address := genIPAddr.Draw(t, "address")
		if !address.Is6() {
			t.Skip("IPv4 value")
		}
		six, ok := address.IPv6()
		require.True(t, ok)
		require.Equal(t, six, address.ToIPv6Mapped())
	})
}

// verifies that re-entering the family-agnostic type through the mapped
// view lands on the same canonical form as the original address.
func Test_IPAddr_ToIPv6Mapped_ThenUnmap_AgreesWithUnmap(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		address := genIPAddr.Draw(t, "address")
		reentered := xnetip.IPAddrFrom6(address.ToIPv6Mapped())
		require.Equal(t, address.Unmap(), reentered.Unmap())
	})
}

// verifies that the mapped view does not allocate.
func Test_IPAddr_ToIPv6Mapped_DoesNotAllocate(t *testing.T) {
	address := mustParseIPAddr4(t, "192.0.2.1")
	requireNoAllocs(t, func() { ipv6AddrSink = address.ToIPv6Mapped() })
}
