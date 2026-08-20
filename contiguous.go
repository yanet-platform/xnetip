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

// Contains reports whether every address of other is also an address
// of m.
//
// Both blocks are CIDR by the type invariant, so the mask-subset
// check is a single unsigned compare of the masks — the typed
// argument is what makes that formula sound. The answer equals the
// wrapped networks' Contains; blocks of different families (Network
// instantiation) never contain each other.
func (m Contiguous[T]) Contains(other Contiguous[T]) bool {
	return m.network.containsContiguous(other.network)
}

// PrefixLen returns the prefix length of the block, total by the
// contiguity invariant.
//
// The length is 0 through 32 for an IPv4 block, 0 through 128 for
// an IPv6 one, family-native for a Network instantiation.
func (m Contiguous[T]) PrefixLen() int {
	// The wrapped mask is a leading run of ones by the type
	// invariant, so the inner comma-ok cannot answer false.
	prefix, _ := m.network.PrefixLen()
	return prefix
}

// Prefix returns the block as a netip.Prefix, total by the
// contiguity invariant.
//
// The prefix is always valid, already masked and in the block's own
// family: an IPv4 block of the Network instantiation yields an Is4
// prefix, never the mapped storage form.
func (m Contiguous[T]) Prefix() netip.Prefix {
	// The wrapped mask is a leading run of ones by the type
	// invariant, so the inner comma-ok cannot answer false.
	prefix, _ := m.network.Prefix()
	return prefix
}

// String returns the text form of the block, always an address and
// a prefix length ("10.0.0.0/8", "2001:db8::/32").
//
// An explicit mask never appears: a contiguous mask always has a
// prefix length, so the prefix branch of the network format is the
// only reachable one. A Network instantiation prints in its own
// family. The output parses back with the matching ParseContiguous
// function.
func (m Contiguous[T]) String() string {
	// The buffer covers the longest form of any instantiation, so
	// the string conversion is the only allocation.
	//
	// A generic method cannot size the buffer per family (see
	// Network6.String for the widest form), and the overshoot is
	// stack space.
	var buffer [91]byte
	return string(m.AppendTo(buffer[:0]))
}

// AppendTo appends the text form of the block to b and returns the
// extended buffer.
//
// The format is exactly the wrapped network's, and by the contiguity
// invariant the suffix is always a prefix length, never an explicit
// mask. The output parses back with the matching ParseContiguous
// function.
func (m Contiguous[T]) AppendTo(b []byte) []byte {
	return m.network.AppendTo(b)
}

// MarshalText implements encoding.TextMarshaler.
//
// The text is the String form of the block: an address, "/" and a
// prefix length. It never fails and allocates only the returned
// slice.
func (m Contiguous[T]) MarshalText() ([]byte, error) {
	return m.AppendTo(make([]byte, 0, len("ffff:ffff:ffff:ffff:ffff:ffff:255.255.255.255/128"))), nil
}

// UnmarshalText implements encoding.TextUnmarshaler.
//
// The text must be accepted by the family's ParseContiguous
// function, so a valid network with a non-contiguous mask wraps
// ErrNonContiguousMask. Empty text wraps ErrEmptyInput (the zero
// wrapper is a valid block). The receiver is untouched on any error.
func (m *Contiguous[T]) UnmarshalText(text []byte) error {
	if len(text) == 0 {
		return wrapParseError("Contiguous.UnmarshalText", "", ErrEmptyInput, nil)
	}
	network, err := m.network.parseText(string(text))
	if err != nil {
		return err
	}
	*m = Contiguous[T]{network: network}
	return nil
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

	// PrefixLen is the concrete type's own comma-ok prefix length.
	PrefixLen() (int, bool)

	// Prefix is the concrete type's own comma-ok netip.Prefix view.
	Prefix() (netip.Prefix, bool)

	// parseText is the concrete type's route to its ParseContiguous
	// function, called on a zero value as a dispatch token.
	parseText(string) (T, error)

	// containsContiguous is the concrete type's containment kernel
	// for two CIDR operands.
	containsContiguous(T) bool
}
