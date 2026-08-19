package xnetip

import (
	"cmp"
	"encoding/binary"
	"net/netip"
)

// IPv4Addr is an IPv4 address stored as a host-order 32-bit integer.
//
// The zero value is the unspecified address 0.0.0.0. Values are comparable
// with == and are never invalid: unlike netip.Addr there is no zone and no
// "invalid" state, which is what lets networks treat addresses as plain
// bit patterns.
type IPv4Addr struct {
	bits uint32
}

// IPv4AddrFrom4 returns the address of the given 4 bytes in network order.
func IPv4AddrFrom4(addr [4]byte) IPv4Addr {
	return IPv4Addr{binary.BigEndian.Uint32(addr[:])}
}

// IPv4AddrFromBits returns the address whose host-order bit pattern is bits.
//
// The most significant byte of bits is the first octet, so
// IPv4AddrFromBits(0xC0A80001) is 192.168.0.1.
func IPv4AddrFromBits(bits uint32) IPv4Addr {
	return IPv4Addr{bits}
}

// As4 returns the address as 4 bytes in network order.
func (m IPv4Addr) As4() [4]byte {
	var addr [4]byte
	binary.BigEndian.PutUint32(addr[:], m.bits)
	return addr
}

// Bits returns the address as a host-order 32-bit integer.
func (m IPv4Addr) Bits() uint32 {
	return m.bits
}

// Compare returns -1, 0 or +1 as m sorts before, equal to or after other.
//
// The order is the numeric order of the 32-bit address, the same order
// netip.Addr.Compare gives two IPv4 addresses. It is the order every
// sorting operation in this package uses for IPv4 addresses, and the
// key the network order packs together with the mask.
func (m IPv4Addr) Compare(other IPv4Addr) int {
	return cmp.Compare(m.bits, other.bits)
}

// String returns the dotted-decimal form of the address, such as
// "192.168.0.1".
//
// The form is the one net/netip prints for an IPv4 address: four decimal
// octets without leading zeros. It allocates once, for the result.
func (m IPv4Addr) String() string {
	return netip.AddrFrom4(m.As4()).String()
}

// AppendTo appends the dotted-decimal form of the address to b and returns
// the extended buffer.
//
// It is the allocation-free path behind String and MarshalText: with
// enough capacity in b (15 bytes suffice) it performs no allocation.
func (m IPv4Addr) AppendTo(b []byte) []byte {
	return netip.AddrFrom4(m.As4()).AppendTo(b)
}
