package xnetip

import (
	"errors"
	"net/netip"
	"strconv"
)

// ErrParse reports text that is not an address or network in any accepted
// form.
//
// Every parser of this package wraps it, together with the net/netip error
// that carries the detail, so [errors.Is] recognizes a rejection whatever
// its cause.
var ErrParse = errors.New("invalid address or network text")

// ErrAddrFamilyMismatch reports an address of the other IP family where one
// family was required.
//
// Examples are IPv6 text given to [ParseNetwork4] or an IPv6 mask given to
// an IPv4 network.
var ErrAddrFamilyMismatch = errors.New("address family mismatch")

// ErrZone reports IPv6 text carrying a zone suffix ("fe80::1%eth0"),
// which the zone-free address types of this package cannot represent.
//
// Only the IPv6 parsers return it: net/netip accepts the zone, so the
// rejection is this package's own and wraps the sentinel alone.
var ErrZone = errors.New("zone not allowed")

// ErrCIDROverflow reports a prefix length outside its address family's
// range, 0 through 32 for IPv4 and 0 through 128 for IPv6.
//
// The CIDR constructors return it wrapped with the address and length
// echoed, so [errors.Is] recognizes the rejection whatever the entry
// point.
var ErrCIDROverflow = errors.New("prefix length out of range")

// ErrInvalidMask reports network text whose part after "/" is neither
// a prefix length nor a mask address of the network's family.
//
// The network parsers return it, together with the underlying cause
// when one exists: the net/netip error for a suffix that is no address
// at all, [ErrAddrFamilyMismatch] for a mask of the other family, [ErrZone]
// for a mask carrying a zone suffix.
var ErrInvalidMask = errors.New("invalid network mask")

// ErrNonContiguousMask reports network text whose mask is valid but
// not a leading run of one bits, where a CIDR block was required.
//
// Only the [Contiguous] parsers return it: the text is a well-formed
// network that the plain network parsers accept.
var ErrNonContiguousMask = errors.New("mask not contiguous")

// ErrNonBiContiguousMask reports a valid IPv6 mask with an interior
// hole in either 64-bit half, where a bi-contiguous mask was required.
//
// The checked address-pair constructor returns it when the plain IPv6
// network is valid but does not carry the stronger per-half shape.
var ErrNonBiContiguousMask = errors.New("mask not bi-contiguous")

// ErrEmptyInput reports empty text where a network was required.
//
// Only the text-unmarshaling methods return it: their zero values
// are valid networks, so empty text must not silently produce one the
// way it produces the invalid zero [netip.Prefix]. The parsers reject
// empty text through [ErrParse] and the net/netip cause instead.
var ErrEmptyInput = errors.New("empty input")

// Ordinary network diagnostics fit in the stack buffer. Longer arbitrary
// input grows through append without changing the rendered text.
const parseErrorBufferSize = 256

// parseError is the deferred error the parsers and checked constructors
// return: the function name with the input echoed, then the cause.
//
// Rendering is postponed until the message is requested. Both the
// sentinel and optional detail remain available to [errors.Is] and
// [errors.As].
type parseError struct {
	function string
	input    string
	sentinel error
	detail   error
}

func (m *parseError) Error() string {
	sentinel := m.sentinel.Error()
	detail := ""
	if m.detail != nil {
		detail = m.detail.Error()
	}

	var buffer [parseErrorBufferSize]byte
	message := buffer[:0]
	message = append(message, "xnetip."...)
	message = append(message, m.function...)
	message = append(message, '(')
	message = strconv.AppendQuote(message, m.input)
	message = append(message, ')', ':', ' ')
	message = append(message, sentinel...)
	if m.detail != nil {
		message = append(message, ':', ' ')
		message = append(message, detail...)
	}
	return string(message)
}

func (m *parseError) Unwrap() []error {
	if m.detail == nil {
		return []error{m.sentinel}
	}
	return []error{m.sentinel, m.detail}
}

// wrapParseError returns the shared deferred parser and constructor error.
//
// The sentinel is one of the exported package errors. The optional detail
// carries the underlying cause when a parser can provide one.
func wrapParseError(function, input string, sentinel, detail error) error {
	return &parseError{
		function: function,
		input:    input,
		sentinel: sentinel,
		detail:   detail,
	}
}

// cidrInput formats an address and prefix length pair the way the
// CIDR constructors echo it in their errors, as addr/bits text.
func cidrInput(addr netip.Addr, bits int) string {
	return addr.String() + "/" + strconv.Itoa(bits)
}
