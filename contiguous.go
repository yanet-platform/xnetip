package xnetip

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
