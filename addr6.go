package xnetip

import "net/netip"

// addr6 is an IPv6 address stored as a 128-bit integer.
//
// It is the internal address kernel of the IPv6 network type: the public
// API speaks netip.Addr, while the mask algebra runs on this plain bit
// pattern, which has no zone and no invalid state by construction.
// IPv4-mapped addresses (::ffff:a.b.c.d) are ordinary IPv6 addresses
// here, as in netip's 16-byte form.
type addr6 struct {
	bits uint128
}

// addr6From16 returns the address of the given 16 bytes in network
// order.
func addr6From16(addr [16]byte) addr6 {
	return addr6{uint128From16(addr)}
}

// addr6FromBits returns the address whose 128-bit pattern is
// hi<<64 | lo.
//
// hi holds the first eight bytes in network order and lo the last eight,
// so addr6FromBits(0x20010db800000000, 1) is 2001:db8::1.
func addr6FromBits(hi, lo uint64) addr6 {
	return addr6{uint128FromHalves(hi, lo)}
}

// addr6FromNetip converts a netip.Addr to addr6, dropping any zone.
//
// ok is false unless a.Is6() reports true: an IPv4 address and the
// invalid zero netip.Addr are not converted, while an IPv4-mapped
// address such as ::ffff:1.2.3.4 is IPv6 and converts as its 16-byte
// form, never unmapped. A zone is discarded silently because the
// addresses of this package are zone-free by design — a zone only scopes
// link-local forwarding and has no bearing on mask algebra. On failure
// the returned address is the zero value.
func addr6FromNetip(a netip.Addr) (addr addr6, ok bool) {
	if !a.Is6() {
		return addr6{}, false
	}
	return addr6From16(a.As16()), true
}

// As16 returns the address as 16 bytes in network order.
func (m addr6) As16() [16]byte {
	return m.bits.As16()
}

// Bits returns the two host-order halves of the address, the first eight
// bytes in hi and the last eight in lo.
func (m addr6) Bits() (hi, lo uint64) {
	return m.bits.hi, m.bits.lo
}

// Netip returns the address as a netip.Addr (Is6 true, no zone).
//
// The view is always valid, so it can flow into every standard API that
// takes a netip.Addr, and converting it back always succeeds. An
// IPv4-mapped value keeps its 16-byte form (Is4In6, not Is4).
func (m addr6) Netip() netip.Addr {
	return netip.AddrFrom16(m.As16())
}

// ToIPv4Mapped returns the IPv4 address embedded in an IPv4-mapped IPv6
// address ::ffff:a.b.c.d, inverting the mapping of the IPv4 kernel.
//
// The second result is false for every address outside ::ffff:0:0/96,
// including the deprecated IPv4-compatible form ::a.b.c.d (RFC 4291
// section 2.5.5.1), which netip.Addr.Unmap does not unwrap either.
func (m addr6) ToIPv4Mapped() (addr4, bool) {
	if !m.Is4In6() {
		return addr4{}, false
	}
	return addr4FromBits(uint32(m.bits.lo)), true
}

// ipv4MappedPrefix is the low half of the IPv4-mapped range
// ::ffff:0:0/96: the embedded IPv4 address sits in the 32 bits below it.
const ipv4MappedPrefix = uint64(0xffff) << 32

// Is4In6 reports whether the address is IPv4-mapped, that is in
// ::ffff:0:0/96 (RFC 4291 section 2.5.5.2).
//
// The family-agnostic network type stores IPv4 networks in this range
// and relies on the test to keep its family flag consistent.
func (m addr6) Is4In6() bool {
	return m.bits.hi == 0 && m.bits.lo>>32 == ipv4MappedPrefix>>32
}

// Compare returns -1, 0 or +1 as m sorts before, equal to or after other.
//
// The order is the numeric order of the 128-bit address, high half first
// and low half on a tie, the same order netip.Addr.Compare gives two
// IPv6 addresses without zones. It is the order every sorting operation
// in this package uses for IPv6 addresses, and the key the network order
// packs together with the mask.
func (m addr6) Compare(other addr6) int {
	return m.bits.Compare(other.bits)
}

// AppendTo appends the canonical text of the address to b and returns
// the extended buffer.
//
// The form is the RFC 5952 one net/netip prints, mapped addresses as
// "::ffff:a.b.c.d", 45 bytes at most. It is the allocation-free kernel
// behind the network formatters: with enough capacity in b it performs
// no allocation.
func (m addr6) AppendTo(b []byte) []byte {
	return netip.AddrFrom16(m.As16()).AppendTo(b)
}
