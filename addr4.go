package xnetip

import (
	"cmp"
	"encoding/binary"
	"net/netip"
)

// addr4 is an IPv4 address stored as a host-order 32-bit integer.
//
// It is the internal address kernel of the IPv4 network type: the public
// API speaks [netip.Addr], while the mask algebra runs on this plain bit
// pattern, which has no zone and no invalid state by construction.
type addr4 struct {
	bits uint32
}

// addr4From4 returns the address of the given 4 bytes in network order.
func addr4From4(addr [4]byte) addr4 {
	return addr4{binary.BigEndian.Uint32(addr[:])}
}

// addr4FromBits returns the address whose host-order bit pattern is
// bits.
//
// The most significant byte of bits is the first octet, so
// addr4FromBits(0xC0A80001) is 192.168.0.1.
func addr4FromBits(bits uint32) addr4 {
	return addr4{bits}
}

// addr4FromNetip converts a [netip.Addr] to addr4.
//
// ok is false unless [netip.Addr.Is4] reports true: an IPv6 address, including an
// IPv4-mapped one such as ::ffff:1.2.3.4, is not converted (the caller
// unmaps on the netip side when that is intended), and the invalid zero
// [netip.Addr] is rejected. On failure the returned address is the zero
// value.
func addr4FromNetip(a netip.Addr) (addr addr4, ok bool) {
	if !a.Is4() {
		return addr4{}, false
	}
	return addr4From4(a.As4()), true
}

// ipv4MaskFromPrefix returns the mask whose top bits are ones and the
// rest zero, for bits in 0 through 32.
//
// Callers validate the range: the public constructors and the parser
// reject longer prefixes with an error, this helper is only ever called
// with a length a contiguous mask can have. The mask is the complement
// of all ones shifted right by the length, and a shift by the full word
// width is zero in Go, so 0 yields the empty mask and 32 all ones
// without a special case.
func ipv4MaskFromPrefix(bits int) addr4 {
	return addr4FromBits(^(^uint32(0) >> uint(bits)))
}

// As4 returns the address as 4 bytes in network order.
func (m addr4) As4() [4]byte {
	var addr [4]byte
	binary.BigEndian.PutUint32(addr[:], m.bits)
	return addr
}

// Bits returns the address as a host-order 32-bit integer.
func (m addr4) Bits() uint32 {
	return m.bits
}

// Netip returns the address as a [netip.Addr] ([netip.Addr.Is4] true, no zone).
//
// The view is always valid, so it can flow into every standard API that
// takes a [netip.Addr], and converting it back always succeeds.
func (m addr4) Netip() netip.Addr {
	return netip.AddrFrom4(m.As4())
}

// ToIPv6Mapped returns the IPv4-mapped IPv6 address ::ffff:a.b.c.d that
// embeds m, as defined by RFC 4291 section 2.5.5.2.
//
// The result is recognized as IPv4-mapped and converts back with the
// mapped extractor of the IPv6 kernel. The mapping preserves order, which lets
// the family-agnostic network type store IPv4 values in this form.
func (m addr4) ToIPv6Mapped() addr6 {
	return addr6{uint128FromHalves(0, ipv4MappedPrefix|uint64(m.bits))}
}

// Compare returns -1, 0 or +1 as m sorts before, equal to or after other.
//
// The order is the numeric order of the 32-bit address, the same order
// [netip.Addr.Compare] gives two IPv4 addresses. It is the order every
// sorting operation in this package uses for IPv4 addresses, and the
// key the network order packs together with the mask.
func (m addr4) Compare(other addr4) int {
	return cmp.Compare(m.bits, other.bits)
}

// AppendTo appends the dotted-decimal form of the address to b and
// returns the extended buffer.
//
// The form is the one net/netip prints for an IPv4 address: four decimal
// octets without leading zeros, 15 bytes at most. It is the
// allocation-free kernel behind the network formatters: with enough
// capacity in b it performs no allocation.
func (m addr4) AppendTo(b []byte) []byte {
	return netip.AddrFrom4(m.As4()).AppendTo(b)
}
