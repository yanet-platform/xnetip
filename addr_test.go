package xnetip_test

import (
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
