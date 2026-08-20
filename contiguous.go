package xnetip

import (
	"net/netip"
	"strings"
)

// ContiguousFrom returns the network as a typed CIDR block.
//
// ok is false when the mask is not contiguous, and the zero block is
// returned. The type argument is inferred from the argument. The
// exact counterpart of the widening ToContiguous conversions.
func ContiguousFrom[T network[T]](network T) (Contiguous[T], bool) {
	if !network.IsContiguous() {
		return Contiguous[T]{}, false
	}
	return Contiguous[T]{network: network}, true
}

// ParseContiguous4 parses an IPv4 CIDR block in prefix,
// explicit-mask or bare address notation.
//
// The grammar is exactly ParseNetwork4's: "10.0.0.0/8",
// "10.0.0.0/255.0.0.0" (the mask must be contiguous) and "10.0.0.1"
// (a host route) are accepted. Text whose mask is valid but not a
// leading run of one bits wraps ErrNonContiguousMask; every other
// rejection is ParseNetwork4's, under this function's name.
func ParseContiguous4(s string) (Contiguous[Network4], error) {
	addrText, suffix, hasSuffix := strings.Cut(s, "/")
	addr, err := netip.ParseAddr(addrText)
	if err != nil {
		return Contiguous[Network4]{}, wrapParseError("ParseContiguous4", s, ErrParse, err)
	}
	network, err := parseNetwork4Parts("ParseContiguous4", s, addr, suffix, hasSuffix)
	if err != nil {
		return Contiguous[Network4]{}, err
	}
	if !network.IsContiguous() {
		return Contiguous[Network4]{}, wrapParseError("ParseContiguous4", s, ErrNonContiguousMask, nil)
	}
	return Contiguous[Network4]{network: network}, nil
}

// MustParseContiguous4 calls ParseContiguous4 and panics on error.
//
// It is intended for tests and package-level constants built from
// literals.
func MustParseContiguous4(s string) Contiguous[Network4] {
	block, err := ParseContiguous4(s)
	if err != nil {
		panic(err)
	}
	return block
}

// ParseContiguous6 parses an IPv6 CIDR block in prefix,
// explicit-mask or bare address notation.
//
// The grammar is exactly ParseNetwork6's: "2001:db8::/32",
// "2001:db8::/ffff:ffff::" (the mask must be contiguous) and
// "2001:db8::1" (a host route) are accepted, an IPv4-mapped address
// is IPv6 and a zone suffix is an error. Text whose mask is valid
// but not a leading run of one bits wraps ErrNonContiguousMask;
// every other rejection is ParseNetwork6's, under this function's
// name.
func ParseContiguous6(s string) (Contiguous[Network6], error) {
	addrText, suffix, hasSuffix := strings.Cut(s, "/")
	addr, err := netip.ParseAddr(addrText)
	if err != nil {
		return Contiguous[Network6]{}, wrapParseError("ParseContiguous6", s, ErrParse, err)
	}
	network, err := parseNetwork6Parts("ParseContiguous6", s, addr, suffix, hasSuffix)
	if err != nil {
		return Contiguous[Network6]{}, err
	}
	if !network.IsContiguous() {
		return Contiguous[Network6]{}, wrapParseError("ParseContiguous6", s, ErrNonContiguousMask, nil)
	}
	return Contiguous[Network6]{network: network}, nil
}

// MustParseContiguous6 calls ParseContiguous6 and panics on error.
//
// It is intended for tests and package-level constants built from
// literals.
func MustParseContiguous6(s string) Contiguous[Network6] {
	block, err := ParseContiguous6(s)
	if err != nil {
		panic(err)
	}
	return block
}

// ParseContiguous parses an IPv4 or IPv6 CIDR block, the address
// part selecting the family (an IPv4-mapped address is IPv6).
//
// The grammar is exactly ParseNetwork's, so both families' prefix,
// explicit-mask and bare address forms are accepted, with the mask
// required to be contiguous. Text whose mask is valid but not a
// leading run of one bits wraps ErrNonContiguousMask; every other
// rejection is ParseNetwork's, under this function's name.
func ParseContiguous(s string) (Contiguous[Network], error) {
	addrText, suffix, hasSuffix := strings.Cut(s, "/")
	addr, err := netip.ParseAddr(addrText)
	if err != nil {
		return Contiguous[Network]{}, wrapParseError("ParseContiguous", s, ErrParse, err)
	}
	if addr.Is4() {
		network, err := parseNetwork4Parts("ParseContiguous", s, addr, suffix, hasSuffix)
		if err != nil {
			return Contiguous[Network]{}, err
		}
		if !network.IsContiguous() {
			return Contiguous[Network]{}, wrapParseError("ParseContiguous", s, ErrNonContiguousMask, nil)
		}
		return Contiguous[Network]{network: NetworkFrom4(network)}, nil
	}
	network, err := parseNetwork6Parts("ParseContiguous", s, addr, suffix, hasSuffix)
	if err != nil {
		return Contiguous[Network]{}, err
	}
	if !network.IsContiguous() {
		return Contiguous[Network]{}, wrapParseError("ParseContiguous", s, ErrNonContiguousMask, nil)
	}
	return Contiguous[Network]{network: NetworkFrom6(network)}, nil
}

// MustParseContiguous calls ParseContiguous and panics on error.
//
// It is intended for tests and package-level constants built from
// literals.
func MustParseContiguous(s string) Contiguous[Network] {
	block, err := ParseContiguous(s)
	if err != nil {
		panic(err)
	}
	return block
}

// Contiguous is a CIDR block: a network whose mask is a leading run
// of one bits, carried as a type-level guarantee.
//
// The zero value wraps the zero network (0.0.0.0/0 for Network4,
// ::/0 otherwise), which is contiguous, so it is valid. Values are
// immutable, comparable with == exactly when the wrapped networks
// are, and safe to copy. The wrapper is generic over the family:
// Contiguous[Network4] is the IPv4 CIDR block, Contiguous[Network6]
// the IPv6 one, Contiguous[Network] the family-agnostic one.
type Contiguous[T network[T]] struct {
	// network is the wrapped network, contiguous by construction:
	// the field stays unexported so the guarantee cannot be forged.
	network T
}

// Network returns the wrapped network.
//
// It is total and free: the wrapper adds only the contiguity
// guarantee, every operation the wrapper does not carry is reached
// through this view.
func (m Contiguous[T]) Network() T {
	return m.network
}

// Compare returns -1, 0 or +1 as m sorts before, equal to or after
// other, in the wrapped type's own order.
func (m Contiguous[T]) Compare(other Contiguous[T]) int {
	return m.network.Compare(other.network)
}

// network is the constraint the generic adapters and wrappers range
// over: the three network types plus the self-typed operations they share.
//
// The F-bound (T appears in its own constraint) is what lets a
// generic method call binary operations such as Compare and Contains
// on the wrapped value: per-family signatures like Compare(Network4)
// never reach a plain union's method set. It is a constraint for
// type parameters, not an interface for values. Methods are added by
// the wrapper session that first needs them.
type network[T any] interface {
	Network4 | Network6 | Network

	// Compare is the concrete type's own three-way comparison.
	Compare(T) int

	// IsContiguous is the concrete type's own mask-shape predicate.
	IsContiguous() bool

	// AppendTo is the concrete type's own text-form appender.
	AppendTo([]byte) []byte
}
