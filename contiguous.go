package xnetip

import (
	"iter"
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

// ContiguousFromCIDR4 returns the block of addr with the top bits
// bits masked, host bits cleared.
//
// The mask built from a length is a leading run of ones, so the
// result is a CIDR block by construction. The address must be Is4 —
// an IPv6 address, IPv4-mapped included, or the invalid zero
// netip.Addr is rejected with ErrAddrFamilyMismatch — and bits must
// be in the range 0 through 32, otherwise ErrCIDROverflow is
// returned: the Network4FromCIDR contract under this function's
// name.
func ContiguousFromCIDR4(addr netip.Addr, bits int) (Contiguous[Network4], error) {
	// The typed constructor can only reject the length after the
	// family check, so the error is rebuilt to name this entry point.
	if !addr.Is4() {
		input := cidrInput(addr, bits)
		return Contiguous[Network4]{}, wrapParseError("ContiguousFromCIDR4", input, ErrAddrFamilyMismatch, nil)
	}
	network, err := Network4FromCIDR(addr, bits)
	if err != nil {
		input := cidrInput(addr, bits)
		return Contiguous[Network4]{}, wrapParseError("ContiguousFromCIDR4", input, ErrCIDROverflow, nil)
	}
	// A mask built from a prefix length is contiguous by
	// construction, so the block wraps without revalidation.
	return Contiguous[Network4]{network: network}, nil
}

// ContiguousFromCIDR6 returns the block of addr with the top bits
// bits masked, host bits cleared.
//
// The mask built from a length is a leading run of ones, so the
// result is a CIDR block by construction. The address must be Is6
// (an IPv4-mapped address is IPv6, a zone is dropped silently) — an
// Is4 address or the invalid zero netip.Addr is rejected with
// ErrAddrFamilyMismatch — and bits must be in the range 0 through
// 128, otherwise ErrCIDROverflow is returned: the Network6FromCIDR
// contract under this function's name.
func ContiguousFromCIDR6(addr netip.Addr, bits int) (Contiguous[Network6], error) {
	if !addr.Is6() {
		input := cidrInput(addr, bits)
		return Contiguous[Network6]{}, wrapParseError("ContiguousFromCIDR6", input, ErrAddrFamilyMismatch, nil)
	}
	network, err := Network6FromCIDR(addr, bits)
	if err != nil {
		input := cidrInput(addr, bits)
		return Contiguous[Network6]{}, wrapParseError("ContiguousFromCIDR6", input, ErrCIDROverflow, nil)
	}
	// A mask built from a prefix length is contiguous by
	// construction, so the block wraps without revalidation.
	return Contiguous[Network6]{network: network}, nil
}

// ContiguousFromCIDR returns the block of addr with the top bits
// bits masked, in addr's own family, host bits cleared.
//
// The mask built from a length is a leading run of ones, so the
// result is a CIDR block by construction. The length is bounded by
// the family, 0 through 32 for IPv4 and 0 through 128 for IPv6,
// otherwise ErrCIDROverflow is returned. An IPv4-mapped address is
// IPv6 and stays IPv6, as in netip. The invalid zero netip.Addr is
// rejected with ErrAddrFamilyMismatch: the NetworkFromCIDR contract
// under this function's name.
func ContiguousFromCIDR(addr netip.Addr, bits int) (Contiguous[Network], error) {
	if !addr.IsValid() {
		input := cidrInput(addr, bits)
		return Contiguous[Network]{}, wrapParseError("ContiguousFromCIDR", input, ErrAddrFamilyMismatch, nil)
	}
	network, err := NetworkFromCIDR(addr, bits)
	if err != nil {
		input := cidrInput(addr, bits)
		return Contiguous[Network]{}, wrapParseError("ContiguousFromCIDR", input, ErrCIDROverflow, nil)
	}
	// A mask built from a prefix length is contiguous by
	// construction, so the block wraps without revalidation.
	return Contiguous[Network]{network: network}, nil
}

// ContiguousFromPrefix4 converts a netip.Prefix into an IPv4 CIDR
// block, host bits cleared.
//
// ok is false when the prefix is invalid or its address is not Is4 —
// an IPv4-mapped prefix is IPv6, convert it through
// ContiguousFromPrefix6 instead. A valid prefix always carries a
// contiguous mask, so the conversion accepts every valid Is4 prefix
// and is the exact inverse of Prefix: the round trip through either
// direction is the identity on masked prefixes.
func ContiguousFromPrefix4(p netip.Prefix) (Contiguous[Network4], bool) {
	network, ok := Network4FromPrefix(p)
	if !ok {
		return Contiguous[Network4]{}, false
	}
	// A mask built from a prefix length is contiguous by
	// construction, so the block wraps without revalidation.
	return Contiguous[Network4]{network: network}, true
}

// ContiguousFromPrefix6 converts a netip.Prefix into an IPv6 CIDR
// block, host bits cleared.
//
// ok is false when the prefix is invalid or its address is Is4 — an
// IPv4-mapped IPv6 prefix is IPv6 and is accepted. A valid prefix
// always carries a contiguous mask, so the conversion accepts every
// valid Is6 prefix and is the exact inverse of Prefix: the round
// trip through either direction is the identity on masked prefixes.
func ContiguousFromPrefix6(p netip.Prefix) (Contiguous[Network6], bool) {
	network, ok := Network6FromPrefix(p)
	if !ok {
		return Contiguous[Network6]{}, false
	}
	// A mask built from a prefix length is contiguous by
	// construction, so the block wraps without revalidation.
	return Contiguous[Network6]{network: network}, true
}

// ContiguousFromPrefix converts a netip.Prefix into a CIDR block in
// the prefix address's own family, host bits cleared.
//
// An Is4 prefix becomes an IPv4 block, anything else — an
// IPv4-mapped IPv6 prefix included — an IPv6 one, as in netip. ok is
// false only for the invalid zero prefix: a valid prefix always
// carries a contiguous mask, so the conversion is the exact inverse
// of Prefix and the round trip through either direction is the
// identity on masked prefixes.
func ContiguousFromPrefix(p netip.Prefix) (Contiguous[Network], bool) {
	network, ok := NetworkFromPrefix(p)
	if !ok {
		return Contiguous[Network]{}, false
	}
	// A mask built from a prefix length is contiguous by
	// construction, so the block wraps without revalidation.
	return Contiguous[Network]{network: network}, true
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

// Intersection returns the block of addresses common to m and other.
//
// Two CIDR blocks intersect exactly when one contains the other, so
// the result is the nested block, still contiguous — the class is
// closed under intersection and the result needs no revalidation.
// ok is false when the blocks are disjoint, and for blocks of
// different families in the Network instantiation; the first result
// is then the zero block.
func (m Contiguous[T]) Intersection(other Contiguous[T]) (Contiguous[T], bool) {
	intersected, ok := m.network.Intersection(other.network)
	if !ok {
		return Contiguous[T]{}, false
	}
	// The mask union of two leading runs is the longer run, so the
	// result is contiguous and wraps without revalidation.
	return Contiguous[T]{network: intersected}, true
}

// MergeByLowestMaskBit merges two blocks when one contains the other
// or when they are CIDR buddies at the prefix boundary bit.
//
// Containment returns the larger block; buddies merge into their
// parent, whose mask drops the run's lowest bit and therefore stays
// contiguous — the class is closed and the result needs no
// revalidation. Whenever ok is true the result equals the wrapped
// networks' MergeByLowestMaskBit; on ok=false the first result is
// the zero block.
func (m Contiguous[T]) MergeByLowestMaskBit(other Contiguous[T]) (Contiguous[T], bool) {
	merged, ok := m.network.MergeByLowestMaskBit(other.network)
	if !ok {
		return Contiguous[T]{}, false
	}
	// The result is contiguous and wraps without revalidation.
	//
	// Containment hands back an input unchanged, and a buddy merge
	// only clears the run's lowest bit, leaving a leading run.
	return Contiguous[T]{network: merged}, true
}

// Difference returns the blocks whose union is the set difference
// m \ other: every address of m that is not in other.
//
// For CIDR operands every part is itself a CIDR block, so the
// sequence carries the type: when other is nested inside m the parts
// are the prefix ladder from m's length plus one down to other's
// length, most significant peeled bit first; a disjoint other yields
// m once; a containing other yields nothing. Order, count and
// disjointness are those of the wrapped networks' Difference. The
// sequence is allocation-free and re-iterable.
func (m Contiguous[T]) Difference(other Contiguous[T]) iter.Seq[Contiguous[T]] {
	return func(yield func(Contiguous[T]) bool) {
		// CIDR blocks never partially overlap, so the case analysis
		// is containment alone.
		//
		// A containing subtrahend covers the source and leaves
		// nothing. With containment ruled out both ways the blocks
		// are disjoint — cross-family dual operands included — and
		// the difference is the source itself.
		if other.network.containsContiguous(m.network) {
			return
		}
		if !m.network.containsContiguous(other.network) {
			yield(m)
			return
		}
		// Each ladder part is contiguous and wraps without revalidation.
		//
		// With the subtrahend strictly nested, the peel extends the
		// source's leading run one bit per step, flipped on the
		// subtrahend's address, so every part's mask is a leading run
		// again and the parts match the general peel exactly.
		last, _ := other.network.PrefixLen()
		bits, _ := m.network.PrefixLen()
		for ; bits < last; bits++ {
			if !yield(Contiguous[T]{network: other.network.contiguousLadderPart(bits + 1)}) {
				return
			}
		}
	}
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

	// Intersection is the concrete type's own comma-ok intersection.
	Intersection(T) (T, bool)

	// MergeByLowestMaskBit is the concrete type's own comma-ok merge
	// at containment or the mask's lowest set bit.
	MergeByLowestMaskBit(T) (T, bool)

	// contiguousLadderPart is the concrete type's kernel for one part
	// of the CIDR difference ladder, built over the nested subtrahend.
	contiguousLadderPart(int) T
}
