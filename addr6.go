package xnetip

import "net/netip"

// IPv6Addr is an IPv6 address stored as a 128-bit integer.
//
// The zero value is the unspecified address ::. Values are comparable
// with == and are never invalid: unlike netip.Addr there is no zone and
// no "invalid" state, so an address is exactly a 128-bit pattern.
// IPv4-mapped addresses (::ffff:a.b.c.d) are ordinary IPv6 addresses
// here, as in netip's 16-byte form.
type IPv6Addr struct {
	bits uint128
}

// IPv6AddrFrom16 returns the address of the given 16 bytes in network order.
func IPv6AddrFrom16(addr [16]byte) IPv6Addr {
	return IPv6Addr{uint128From16(addr)}
}

// IPv6AddrFromBits returns the address whose 128-bit pattern is hi<<64 | lo.
//
// hi holds the first eight bytes in network order and lo the last eight,
// so IPv6AddrFromBits(0x20010db800000000, 1) is 2001:db8::1.
func IPv6AddrFromBits(hi, lo uint64) IPv6Addr {
	return IPv6Addr{uint128FromHalves(hi, lo)}
}

// IPv6AddrFrom8 returns the address made of the eight 16-bit groups as
// they appear in the textual form, first group first.
//
// It is the constructor that spells an address group by group:
// IPv6AddrFrom8(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1) is 2001:db8::1. The
// first four groups form the high half and the last four the low half.
func IPv6AddrFrom8(a, b, c, d, e, f, g, h uint16) IPv6Addr {
	hi := uint64(a)<<48 | uint64(b)<<32 | uint64(c)<<16 | uint64(d)
	lo := uint64(e)<<48 | uint64(f)<<32 | uint64(g)<<16 | uint64(h)
	return IPv6Addr{uint128FromHalves(hi, lo)}
}

// As16 returns the address as 16 bytes in network order.
func (m IPv6Addr) As16() [16]byte {
	return m.bits.As16()
}

// Bits returns the address as two host-order 64-bit halves, hi first.
func (m IPv6Addr) Bits() (hi, lo uint64) {
	return m.bits.hi, m.bits.lo
}

// Compare returns -1, 0 or +1 as m sorts before, equal to or after other.
//
// The order is the numeric order of the 128-bit address, high half first
// and low half on a tie, the same order netip.Addr.Compare gives two IPv6
// addresses without zones. It is the order every sorting operation in
// this package uses for IPv6 addresses, and the key the network order
// packs together with the mask.
func (m IPv6Addr) Compare(other IPv6Addr) int {
	return m.bits.Compare(other.bits)
}

// String returns the canonical RFC 5952 text of the address, such as
// "2001:db8::1" or "::ffff:1.2.3.4" for the IPv4-mapped range.
//
// The form is the one net/netip prints for an IPv6 address without a
// zone: the longest run of two or more zero groups collapses to "::",
// the leftmost run wins a tie, a single zero group stays, hex is
// lowercase without leading zeros. It allocates once, for the result.
func (m IPv6Addr) String() string {
	return netip.AddrFrom16(m.As16()).String()
}

// AppendTo appends the canonical text of the address to b and returns
// the extended buffer.
//
// It is the allocation-free path behind String and MarshalText: with
// enough capacity in b (45 bytes suffice) it performs no allocation.
func (m IPv6Addr) AppendTo(b []byte) []byte {
	return netip.AddrFrom16(m.As16()).AppendTo(b)
}

// StringExpanded returns the address as eight zero-padded 4-digit hex
// groups, such as "2001:0db8:0000:0000:0000:0000:0000:0001".
//
// It is the form netip.Addr.StringExpanded prints: nothing is compressed
// and the IPv4-mapped range is written as hex groups too, so every
// address is exactly 39 bytes long. It allocates once, for the result.
func (m IPv6Addr) StringExpanded() string {
	return netip.AddrFrom16(m.As16()).StringExpanded()
}

// ParseIPv6Addr parses s as an IPv6 address ("2001:db8::1",
// "::ffff:1.2.3.4").
//
// The accepted grammar is the IPv6 grammar of net/netip without zones:
// hex groups of up to four digits in either case, one optional "::" for
// at least one zero group, an optional dotted IPv4 quad as the last two
// groups, nothing else. Other text wraps ErrParse with the net/netip
// error that explains the rejection. A zone suffix ("fe80::1%eth0")
// wraps ErrZone and dotted-decimal IPv4 text wraps ErrAddrFamilyMismatch,
// each alone. IPv4-mapped text stays its 16 bytes, never unmapped. Every
// error names the parser and echoes s, so errors.Is works on the sentinels.
func ParseIPv6Addr(s string) (IPv6Addr, error) {
	addr, err := netip.ParseAddr(s)
	if err != nil {
		return IPv6Addr{}, wrapParseError("ParseIPv6Addr", s, ErrParse, err)
	}
	if addr.Zone() != "" {
		return IPv6Addr{}, wrapParseError("ParseIPv6Addr", s, ErrZone, nil)
	}
	if !addr.Is6() {
		return IPv6Addr{}, wrapParseError("ParseIPv6Addr", s, ErrAddrFamilyMismatch, nil)
	}
	return IPv6AddrFrom16(addr.As16()), nil
}

// MustParseIPv6Addr calls ParseIPv6Addr and panics on error.
//
// It is intended for tests and package-level variables with hard-coded
// text, like netip.MustParseAddr.
func MustParseIPv6Addr(s string) IPv6Addr {
	addr, err := ParseIPv6Addr(s)
	if err != nil {
		panic(err)
	}
	return addr
}
