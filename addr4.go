package xnetip

import "encoding/binary"

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
