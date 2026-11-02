package xnetip

import (
	"cmp"
	"errors"
	"fmt"
	"net/netip"
)

// ErrInvalidMacAddr reports malformed EUI-48 address text.
//
// The MAC parsers wrap it together with [ErrParse], preserving the input.
// Accepted forms have six hexadecimal octets with colons or hyphens, or
// three four-digit groups with dots. Bare digits and EUI-64 are rejected.
var ErrInvalidMacAddr = errors.New("invalid MAC address")

// MacAddr is an immutable, comparable 48-bit Ethernet address.
//
// The zero value is 00:00:00:00:00:00. The six octets occupy the lower
// 48 bits of an integer, with the first octet highest. Values can be map
// keys. Text is case-insensitive on input and lowercase with colons on
// output. Both colons and hyphens require exactly two digits per octet,
// while Cisco's dotted form requires three groups of four digits.
type MacAddr struct {
	bits uint64
}

// MacAddrFrom6 returns the address of six octets in transmission order.
func MacAddrFrom6(octets [6]byte) MacAddr {
	return MacAddr{bits: uint64(octets[0])<<40 | uint64(octets[1])<<32 |
		uint64(octets[2])<<24 | uint64(octets[3])<<16 |
		uint64(octets[4])<<8 | uint64(octets[5])}
}

// MacAddrFromUint64 returns an EUI-48 address when the upper 16 bits are zero.
//
// The first octet occupies bits 40 through 47. On overflow the result is
// the zero address and false. The inverse conversion is [MacAddr.Uint64].
func MacAddrFromUint64(value uint64) (MacAddr, bool) {
	if value>>48 != 0 {
		return MacAddr{}, false
	}
	return MacAddr{bits: value}, true
}

// ParseMacAddr parses a colon, hyphen or Cisco dotted EUI-48 address.
//
// Hexadecimal letters may have either case. Spaces, mixed separators,
// bare hexadecimal digits and wider hardware addresses are rejected.
// Failure wraps [ErrParse] and [ErrInvalidMacAddr] and echoes the input.
func ParseMacAddr(text string) (MacAddr, error) {
	if address, ok := parseMacAddr(text); ok {
		return address, nil
	}
	return MacAddr{}, wrapParseError("ParseMacAddr", text, ErrParse, ErrInvalidMacAddr)
}

// parseMacAddr recognizes the same exact ASCII grammar for strings and bytes.
func parseMacAddr[T ~string | ~[]byte](text T) (MacAddr, bool) {
	var separator byte
	switch len(text) {
	case 17:
		separator = text[2]
		if separator != ':' && separator != '-' {
			return MacAddr{}, false
		}
		for position := 5; position < 17; position += 3 {
			if text[position] != separator {
				return MacAddr{}, false
			}
		}
	case 14:
		if text[4] != '.' || text[9] != '.' {
			return MacAddr{}, false
		}
		separator = '.'
	default:
		return MacAddr{}, false
	}
	var value uint64
	for idx := range 6 {
		position := 3 * idx
		if separator == '.' {
			position = 2*idx + idx/2
		}
		high, highOK := decodeMacHex(text[position])
		low, lowOK := decodeMacHex(text[position+1])
		if !highOK || !lowOK {
			return MacAddr{}, false
		}
		value = value<<8 | uint64(high<<4|low)
	}
	return MacAddr{bits: value}, true
}

// decodeMacHex rejects non-ASCII digits before producing a hexadecimal nibble.
func decodeMacHex(digit byte) (byte, bool) {
	if digit >= '0' && digit <= '9' {
		return digit - '0', true
	}
	digit |= 0x20
	if digit >= 'a' && digit <= 'f' {
		return digit - 'a' + 10, true
	}
	return 0, false
}

// ParseMacAddrASCII parses ASCII bytes with the grammar of [ParseMacAddr].
//
// Successful parsing does not allocate and does not retain the input.
// Failure wraps [ErrParse] and [ErrInvalidMacAddr] and echoes the bytes.
func ParseMacAddrASCII(text []byte) (MacAddr, error) {
	if address, ok := parseMacAddr(text); ok {
		return address, nil
	}
	return MacAddr{}, wrapParseError("ParseMacAddrASCII", string(text), ErrParse, ErrInvalidMacAddr)
}

// MustParseMacAddr parses an address or panics if parsing fails.
func MustParseMacAddr(text string) MacAddr {
	address, err := ParseMacAddr(text)
	if err != nil {
		panic(err)
	}
	return address
}

// As6 returns the six octets in transmission order.
func (m MacAddr) As6() [6]byte {
	return [6]byte{
		byte(m.bits >> 40), byte(m.bits >> 32), byte(m.bits >> 24),
		byte(m.bits >> 16), byte(m.bits >> 8), byte(m.bits),
	}
}

// Uint64 returns the lower 48-bit numeric address, first octet highest.
func (m MacAddr) Uint64() uint64 {
	return m.bits
}

// IsZero reports whether all six octets are zero.
func (m MacAddr) IsZero() bool {
	return m.bits == 0
}

// IsBroadcast reports whether all six octets are ff.
func (m MacAddr) IsBroadcast() bool {
	return m.bits == 0xffffffffffff
}

// IsMulticast reports whether the group bit of the first octet is set.
//
// The broadcast address is also multicast.
func (m MacAddr) IsMulticast() bool {
	return m.bits&(uint64(1)<<40) != 0
}

// IsUnicast reports whether the group bit of the first octet is clear.
//
// It is the complement of [MacAddr.IsMulticast]. The zero address is unicast.
func (m MacAddr) IsUnicast() bool {
	return !m.IsMulticast()
}

// IsLocallyAdministered reports whether the first octet's U/L bit is set.
func (m MacAddr) IsLocallyAdministered() bool {
	return m.bits&(uint64(2)<<40) != 0
}

// IsUniversallyAdministered reports whether the first octet's U/L bit is clear.
//
// It is the complement of [MacAddr.IsLocallyAdministered].
func (m MacAddr) IsUniversallyAdministered() bool {
	return !m.IsLocallyAdministered()
}

// ToModifiedEUI64 returns the modified EUI-64 interface identifier.
//
// The middle ff:fe octets are inserted after the third address octet, and
// the first octet's U/L bit is inverted as defined in RFC 4291 appendix A.
// The first octet is highest in the integer. [MacAddrFromModifiedEUI64]
// converts the identifier back.
func (m MacAddr) ToModifiedEUI64() uint64 {
	prefix := m.bits >> 24
	suffix := m.bits & 0xffffff
	return (prefix<<40 | uint64(0xfffe)<<24 | suffix) ^ (uint64(2) << 56)
}

// MacAddrFromModifiedEUI64 reverses a MAC-derived modified interface identifier.
//
// Only identifiers with ff:fe in their middle octets qualify. The octets
// are removed and the U/L bit inverted, reversing [MacAddr.ToModifiedEUI64].
// An identifier without the marker returns the zero address and false.
func MacAddrFromModifiedEUI64(identifier uint64) (MacAddr, bool) {
	if identifier>>24&0xffff != 0xfffe {
		return MacAddr{}, false
	}
	prefix := identifier>>40 ^ uint64(2)<<16
	suffix := identifier & 0xffffff
	return MacAddr{bits: prefix<<24 | suffix}, true
}

// ToIPv6LinkLocal returns fe80::/64 with the modified EUI-64 identifier.
//
// The returned [netip.Addr] is IPv6 without a zone, using the interface
// identifier from [MacAddr.ToModifiedEUI64] as in RFC 4862 section 5.3.
func (m MacAddr) ToIPv6LinkLocal() netip.Addr {
	return addr6FromBits(0xfe80000000000000, m.ToModifiedEUI64()).Netip()
}

// MacAddrFromIPv4Multicast returns the Ethernet address of an IPv4 group.
//
// RFC 1112 section 6.4 places the low 23 group bits after 01:00:5e, so
// 32 groups share each MAC address. Only native IPv4 addresses in 224.0.0.0/4
// qualify. Invalid, IPv6 and IPv4-mapped inputs return the zero address and
// false, preserving the address-family boundary.
func MacAddrFromIPv4Multicast(group netip.Addr) (MacAddr, bool) {
	if !group.Is4() || !group.IsMulticast() {
		return MacAddr{}, false
	}
	bits := addr4From4(group.As4()).Bits()
	return MacAddr{bits: 0x01005e000000 | uint64(bits&0x7fffff)}, true
}

// MacAddrFromIPv6Multicast returns the Ethernet address of an IPv6 group.
//
// RFC 2464 section 7 places the group's last four octets after 33:33.
// Only IPv6 addresses in ff00::/8 qualify, and an input zone is ignored.
// Invalid, IPv4 and IPv4-mapped inputs return the zero address and false.
// In particular, a mapped IPv4 multicast group is not an IPv6 group.
func MacAddrFromIPv6Multicast(group netip.Addr) (MacAddr, bool) {
	if !group.Is6() || group.Is4In6() || !group.IsMulticast() {
		return MacAddr{}, false
	}
	bits := addr6From16(group.As16()).bits
	return MacAddr{bits: 0x333300000000 | uint64(uint32(bits.lo))}, true
}

// Compare returns -1, 0 or +1 as m sorts before, equal to or after other.
//
// Numeric order agrees with lexicographic transmission-order octet comparison.
func (m MacAddr) Compare(other MacAddr) int {
	return cmp.Compare(m.bits, other.bits)
}

// String returns the canonical lowercase colon-separated text.
func (m MacAddr) String() string {
	var buffer [17]byte
	return string(m.AppendTo(buffer[:0]))
}

// AppendTo appends the canonical lowercase colon-separated text to b.
//
// With room for 17 additional bytes the append does not allocate.
func (m MacAddr) AppendTo(b []byte) []byte {
	return appendMacAddr(b, m, ':')
}

// appendMacAddr encodes octets with consistent pair or four-digit separators.
func appendMacAddr(buffer []byte, address MacAddr, separator byte) []byte {
	const digits = "0123456789abcdef"
	for idx, octet := range address.As6() {
		if idx > 0 && (separator != '.' || idx%2 == 0) {
			buffer = append(buffer, separator)
		}
		buffer = append(buffer, digits[octet>>4], digits[octet&15])
	}
	return buffer
}

// MarshalText implements [encoding.TextMarshaler] with canonical MAC text.
//
// It never fails and allocates only the returned 17-byte slice.
func (m MacAddr) MarshalText() ([]byte, error) {
	return m.AppendTo(make([]byte, 0, 17)), nil
}

// UnmarshalText implements [encoding.TextUnmarshaler] using the MAC grammar.
//
// Successful decoding does not allocate. An error leaves the receiver intact.
// Empty input wraps [ErrEmptyInput] because the zero address is a valid value.
func (m *MacAddr) UnmarshalText(text []byte) error {
	if len(text) == 0 {
		return wrapParseError("MacAddr.UnmarshalText", "", ErrEmptyInput, nil)
	}
	address, ok := parseMacAddr(text)
	if !ok {
		return wrapParseError("MacAddr.UnmarshalText", string(text), ErrParse, ErrInvalidMacAddr)
	}
	*m = address
	return nil
}

// Format implements [fmt.Formatter] for canonical and hexadecimal MAC text.
//
// The verbs v, s and x use lowercase colons, X uses uppercase and q quotes
// the canonical text. Width, precision, left alignment and zero padding apply
// to the whole text as for strings. Bare hexadecimal digits can be obtained
// by formatting [MacAddr.Uint64] instead.
func (m MacAddr) Format(state fmt.State, verb rune) {
	formatMacAddr(state, verb, m, ':')
}

// formatMacAddr streams immutable characters to avoid allocating a local
// formatting buffer through an interface writer.
func formatMacAddr(state fmt.State, verb rune, address MacAddr, separator byte) {
	if verb != 'v' && verb != 's' && verb != 'x' && verb != 'X' && verb != 'q' {
		_, _ = fmt.Fprintf(state, "%%!%c(xnetip.MacAddr=%s)", verb, address.String())
		return
	}
	length := 17
	if separator == '.' {
		length = 14
	}
	if precision, ok := state.Precision(); ok && precision < length {
		length = precision
	}
	quote := -1
	if verb == 'q' {
		quote = 2
		if state.Flag('#') {
			quote = 3
		}
	}
	textLength := length
	if quote >= 0 {
		textLength += 2
	}
	width, _ := state.Width()
	padding := max(width-textLength, 0)
	paddingCharacter := 0
	if state.Flag('0') {
		paddingCharacter = 1
	}
	if !state.Flag('-') {
		writeMacPadding(state, paddingCharacter, padding)
	}
	if quote >= 0 {
		_, _ = state.Write(macFormatCharacters[quote : quote+1])
	}
	writeMacAddr(state, address, separator, verb == 'X', length)
	if quote >= 0 {
		_, _ = state.Write(macFormatCharacters[quote : quote+1])
	}
	if state.Flag('-') {
		writeMacPadding(state, 0, padding)
	}
}

// The alphabets and punctuation are immutable output storage shared by all
// formatters. Writers must not modify the bytes they receive.
var (
	macFormatLowerHex   = []byte("0123456789abcdef")
	macFormatUpperHex   = []byte("0123456789ABCDEF")
	macFormatCharacters = []byte(" 0\"`:-.")
)

// writeMacPadding emits padding from immutable storage without scratch space.
func writeMacPadding(state fmt.State, character, count int) {
	for range count {
		_, _ = state.Write(macFormatCharacters[character : character+1])
	}
}

// writeMacAddr stops after the requested number of ASCII text characters.
func writeMacAddr(state fmt.State, address MacAddr, separator byte, upper bool, limit int) {
	digits := macFormatLowerHex
	if upper {
		digits = macFormatUpperHex
	}
	separatorPosition := 4
	switch separator {
	case '-':
		separatorPosition = 5
	case '.':
		separatorPosition = 6
	}
	for idx, octet := range address.As6() {
		if idx > 0 && (separator != '.' || idx%2 == 0) {
			if limit == 0 {
				return
			}
			_, _ = state.Write(macFormatCharacters[separatorPosition : separatorPosition+1])
			limit--
		}
		for _, nibble := range [2]byte{octet >> 4, octet & 15} {
			if limit == 0 {
				return
			}
			_, _ = state.Write(digits[nibble : nibble+1])
			limit--
		}
	}
}
