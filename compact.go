package xnetip

// network is the set of network types the formatting adapters accept.
//
// It exists so an adapter is written once over a type parameter
// instead of three times per network type. It is a constraint for
// type parameters, not an interface for values.
type network interface {
	Network4 | Network6 | Network
}

// Compact renders a network in its shortest unambiguous form.
//
// A host route is written as its bare address, everything else
// exactly as the network's own String writes it: address and prefix
// length for a contiguous mask, address and explicit mask otherwise.
// A Network is written in its own family, so the host-route rule
// fires at 32 bits for IPv4 and at 128 for IPv6, an IPv4-mapped IPv6
// network counting as IPv6. The output reparses with the family's
// Parse function, which reads a bare address as a host route. The
// opaque result carries String, AppendTo and fmt.Stringer.
func Compact[T network](n T) compact[T] {
	return compact[T]{network: n}
}

// compact is the adapter Compact returns, a wrapper over a network
// value carrying String and AppendTo.
//
// The type stays unexported so the constructor is the whole API
// surface: callers hold the adapter through type inference and the
// fmt.Stringer contract, never by name. Future formatting adapters
// follow the same shape, a constructor function over an opaque
// wrapper.
type compact[T network] struct {
	// network is the network value to render.
	network T
}

// String returns the compact text form of the network, see Compact
// for the format.
func (m compact[T]) String() string {
	// Each branch sizes its buffer to the family's longest form, so
	// the string conversion is the only allocation.
	switch network := any(m.network).(type) {
	case Network4:
		var buffer [31]byte
		return string(appendCompact4(buffer[:0], network))
	case Network6:
		var buffer [91]byte
		return string(appendCompact6(buffer[:0], network))
	}
	// The constraint leaves Network as the only remaining
	// instantiation, and it renders as the family it holds.
	network := any(m.network).(Network)
	var buffer [91]byte
	if inner, ok := network.IPv4(); ok {
		return string(appendCompact4(buffer[:0], inner))
	}
	return string(appendCompact6(buffer[:0], network.network))
}

// AppendTo appends the compact text form of the network to b and
// returns the extended buffer, see Compact for the format.
func (m compact[T]) AppendTo(b []byte) []byte {
	switch network := any(m.network).(type) {
	case Network4:
		return appendCompact4(b, network)
	case Network6:
		return appendCompact6(b, network)
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
