package xnetip

import (
	"cmp"
	"encoding/binary"
	"fmt"
	"math"
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

// IPv4AddrFromNetip converts a netip.Addr to IPv4Addr.
//
// ok is false unless a.Is4() reports true: an IPv6 address, including an
// IPv4-mapped one such as ::ffff:1.2.3.4, is not converted (use Unmap on
// the netip side first if that is intended), and the zero netip.Addr is
// rejected. On failure the returned address is the zero value.
func IPv4AddrFromNetip(a netip.Addr) (addr IPv4Addr, ok bool) {
	if !a.Is4() {
		return IPv4Addr{}, false
	}
	return IPv4AddrFrom4(a.As4()), true
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

// Netip returns the address as a netip.Addr (Is4 true, no zone).
//
// The view is always valid, so it can flow into every standard API that
// takes a netip.Addr, and converting it back always succeeds.
func (m IPv4Addr) Netip() netip.Addr {
	return netip.AddrFrom4(m.As4())
}

// IsUnspecified reports whether the address is 0.0.0.0.
func (m IPv4Addr) IsUnspecified() bool {
	return m.bits == 0
}

// IsLoopback reports whether the address is in 127.0.0.0/8.
func (m IPv4Addr) IsLoopback() bool {
	return m.bits>>24 == 127
}

// IsPrivate reports whether the address is in one of the RFC 1918 ranges
// 10.0.0.0/8, 172.16.0.0/12 or 192.168.0.0/16.
//
// A private address still counts as global unicast, exactly as in
// net/netip.
func (m IPv4Addr) IsPrivate() bool {
	octet0, octet1 := uint8(m.bits>>24), uint8(m.bits>>16)
	return octet0 == 10 ||
		(octet0 == 172 && octet1&0xf0 == 16) ||
		(octet0 == 192 && octet1 == 168)
}

// IsMulticast reports whether the address is in 224.0.0.0/4.
func (m IPv4Addr) IsMulticast() bool {
	return m.bits>>28 == 0xe
}

// IsLinkLocalUnicast reports whether the address is in 169.254.0.0/16.
func (m IPv4Addr) IsLinkLocalUnicast() bool {
	return m.bits>>16 == 169<<8|254
}

// IsLinkLocalMulticast reports whether the address is in 224.0.0.0/24.
func (m IPv4Addr) IsLinkLocalMulticast() bool {
	return m.bits>>8 == 224<<16
}

// IsGlobalUnicast reports whether the address is global unicast in the
// sense of net/netip and package net.
//
// It is false for 0.0.0.0 and 255.255.255.255, and otherwise true unless
// the address is loopback, multicast or link-local unicast. Private
// RFC 1918 addresses count as global unicast, exactly as in net/netip.
func (m IPv4Addr) IsGlobalUnicast() bool {
	if m.bits == 0 || m.bits == math.MaxUint32 {
		return false
	}
	return !m.IsLoopback() && !m.IsMulticast() && !m.IsLinkLocalUnicast()
}

// Next returns the address one above m, in the numeric order of Compare.
//
// The second result is false when m is 255.255.255.255, which has no next
// address. Unlike netip.Addr.Next, the end is reported with the comma-ok
// form rather than an invalid address, because every IPv4Addr value is a
// real address.
func (m IPv4Addr) Next() (IPv4Addr, bool) {
	if m.bits == math.MaxUint32 {
		return IPv4Addr{}, false
	}
	return IPv4Addr{m.bits + 1}, true
}

// Prev returns the address one below m, in the numeric order of Compare.
//
// The second result is false when m is 0.0.0.0, which has no previous
// address. Unlike netip.Addr.Prev, the end is reported with the comma-ok
// form rather than an invalid address, because every IPv4Addr value is a
// real address.
func (m IPv4Addr) Prev() (IPv4Addr, bool) {
	if m.bits == 0 {
		return IPv4Addr{}, false
	}
	return IPv4Addr{m.bits - 1}, true
}

// BitLen returns 32, the number of bits in an IPv4 address.
func (m IPv4Addr) BitLen() int {
	return 32
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

// MarshalText implements encoding.TextMarshaler.
//
// The text is exactly String(): dotted decimal without padding. The
// error is always nil, and the single allocation is the returned slice,
// sized upfront for the longest form. The zero value marshals as
// "0.0.0.0", not as empty text, because it is a real address.
func (m IPv4Addr) MarshalText() ([]byte, error) {
	return m.AppendText(make([]byte, 0, len("255.255.255.255")))
}

// AppendText implements encoding.TextAppender by appending the text of
// MarshalText to b.
//
// It is the allocation-free variant of MarshalText, and the error is
// always nil.
func (m IPv4Addr) AppendText(b []byte) ([]byte, error) {
	return m.AppendTo(b), nil
}

// UnmarshalText implements encoding.TextUnmarshaler.
//
// The text must be accepted by ParseIPv4Addr, and on error the receiver
// is left untouched. Unlike netip.Addr, empty text is an error rather
// than the zero value, because the zero IPv4Addr is the valid address
// 0.0.0.0 and an absent field must not silently decode into it.
func (m *IPv4Addr) UnmarshalText(text []byte) error {
	address, err := ParseIPv4Addr(string(text))
	if err != nil {
		return err
	}
	*m = address
	return nil
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
