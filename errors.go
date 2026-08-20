package xnetip

import (
	"errors"
	"fmt"
)

// ErrParse reports text that is not an address or network in any accepted
// form.
//
// Every parser of this package wraps it, together with the net/netip error
// that carries the detail, so errors.Is recognizes a rejection whatever
// its cause.
var ErrParse = errors.New("invalid address or network text")

// ErrAddrFamilyMismatch reports an address of the other IP family where one
// family was required.
//
// Examples are IPv6 text given to ParseIPv4Addr or an IPv6 mask given to
// an IPv4 network.
var ErrAddrFamilyMismatch = errors.New("address family mismatch")

// ErrZone reports IPv6 text carrying a zone suffix ("fe80::1%eth0"),
// which the zone-free address types of this package cannot represent.
//
// Only the IPv6 parsers return it: net/netip accepts the zone, so the
// rejection is this package's own and wraps the sentinel alone.
var ErrZone = errors.New("zone not allowed")

// wrapParseError builds the error the parsers and checked constructors
// return: the function name with the input echoed, then the cause.
//
// The sentinel is one of the exported errors of this package and the
// detail, if not nil, is the underlying net/netip error. Both are
// wrapped, so errors.Is matches the sentinel while the message keeps the
// exact reason net/netip gave.
func wrapParseError(function, input string, sentinel, detail error) error {
	if detail == nil {
		return fmt.Errorf("xnetip.%s(%q): %w", function, input, sentinel)
	}
	return fmt.Errorf("xnetip.%s(%q): %w: %w", function, input, sentinel, detail)
}
