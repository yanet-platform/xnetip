package xnetip

// Compact renders a network-like value in its shortest unambiguous form.
//
// A host route is written as its bare address, everything else
// exactly as the network's canonical text: address and prefix
// length for a contiguous mask, address and explicit mask otherwise.
// A [Network] is written in its own family, so the host-route rule
// fires at 32 bits for IPv4 and at 128 for IPv6, an IPv4-mapped IPv6
// network counting as IPv6. Guarantee-bearing wrappers keep the same
// rule and reparse through their own parsers. The opaque result carries
// string and append operations and implements [fmt.Stringer].
func Compact[T compactable](n T) compact[T] {
	return compact[T]{network: n}
}

// compactable is the closed set of values accepted by the compact adapter.
//
// The guarantee-bearing values join the three base network types because
// they have the same text and host-route semantics as their wrapped networks.
type compactable interface {
	Network4 | Network6 | Network |
		Contiguous[Network4] | Contiguous[Network6] | Contiguous[Network] |
		BiContiguous

	// AppendTo appends the value's canonical text to a byte slice.
	AppendTo([]byte) []byte
}

// compact is the adapter [Compact] returns, a wrapper over a network
// value carrying string and append operations.
//
// The type stays unexported so the constructor is the whole API
// surface: callers hold the adapter through type inference and the
// [fmt.Stringer] contract, never by name. Future formatting adapters
// follow the same shape, a constructor function over an opaque
// wrapper.
type compact[T compactable] struct {
	// network is the network value to render.
	network T
}

// String returns the compact text form of the network, see [Compact]
// for the format.
func (m compact[T]) String() string {
	// The buffer covers the longest form of any instantiation, so
	// the string conversion is the only allocation.
	var buffer [maxNetworkTextLen]byte
	return string(m.AppendTo(buffer[:0]))
}

// AppendTo appends the compact text form of the network to b and
// returns the extended buffer, see [Compact] for the format.
func (m compact[T]) AppendTo(b []byte) []byte {
	switch network := any(m.network).(type) {
	case Network4:
		return appendCompact4(b, network)
	case Network6:
		return appendCompact6(b, network)
	case Contiguous[Network4]:
		return appendCompact4(b, network.network)
	case Contiguous[Network6]:
		return appendCompact6(b, network.network)
	case Contiguous[Network]:
		if inner, ok := network.network.IPv4(); ok {
			return appendCompact4(b, inner)
		}
		return appendCompact6(b, network.network.network)
	case BiContiguous:
		return appendCompact6(b, network.network6)
	}
	// The constraint leaves Network as the only remaining
	// instantiation, and it renders as the family it holds.
	network := any(m.network).(Network)
	if inner, ok := network.IPv4(); ok {
		return appendCompact4(b, inner)
	}
	return appendCompact6(b, network.network)
}

// appendCompact4 appends the compact form of an IPv4 network: the
// bare address of a host route, the network's own text otherwise.
func appendCompact4(b []byte, network Network4) []byte {
	if prefix, ok := network.PrefixLen(); ok && prefix == 32 {
		return network.Addr().AppendTo(b)
	}
	return network.AppendTo(b)
}

// appendCompact6 appends the compact form of an IPv6 network: the
// bare address of a host route, the network's own text otherwise.
func appendCompact6(b []byte, network Network6) []byte {
	if prefix, ok := network.PrefixLen(); ok && prefix == 128 {
		return network.Addr().AppendTo(b)
	}
	return network.AppendTo(b)
}
