package xnetip

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
