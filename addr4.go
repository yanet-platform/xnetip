package xnetip

import (
	"cmp"
	"encoding/binary"
	"fmt"
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

// ParseIPv4Addr parses s as a dotted-decimal IPv4 address ("192.168.0.1").
//
// The accepted grammar is the IPv4 grammar of net/netip: four decimal
// octets in 0..255 without leading zeros and nothing else, no whitespace,
// no suffix. Text that is not an address wraps ErrParse together with the
// net/netip error that explains the rejection. IPv6 text, including
// IPv4-mapped forms such as "::ffff:1.2.3.4", wraps ErrAddrFamilyMismatch.
// Every error names the parser and echoes s, so errors.Is works on the
// sentinels and the message identifies the input.
func ParseIPv4Addr(s string) (IPv4Addr, error) {
	addr, err := netip.ParseAddr(s)
	if err != nil {
		return IPv4Addr{}, wrapParseError("ParseIPv4Addr", s, ErrParse, err)
	}
	if !addr.Is4() {
		return IPv4Addr{}, wrapParseError("ParseIPv4Addr", s, ErrAddrFamilyMismatch, nil)
	}
	return IPv4AddrFrom4(addr.As4()), nil
}

// wrapParseError builds the error every parser of this package returns:
// the parser's name with the input echoed in quotes, then the cause.
//
// The sentinel is one of the exported errors of this package and the
// detail, if not nil, is the underlying net/netip error. Both are wrapped,
// so errors.Is matches the sentinel while the message keeps the exact
// reason net/netip gave.
func wrapParseError(parser, input string, sentinel, detail error) error {
	if detail == nil {
		return fmt.Errorf("xnetip.%s(%q): %w", parser, input, sentinel)
	}
	return fmt.Errorf("xnetip.%s(%q): %w: %w", parser, input, sentinel, detail)
}

// MustParseIPv4Addr calls ParseIPv4Addr and panics on error.
//
// It is intended for tests and package-level variables with hard-coded
// text, like netip.MustParseAddr.
func MustParseIPv4Addr(s string) IPv4Addr {
	addr, err := ParseIPv4Addr(s)
	if err != nil {
		panic(err)
	}
	return addr
}
