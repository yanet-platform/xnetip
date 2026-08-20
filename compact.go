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
// A host route prints as a bare address, any other contiguous network
// as an address and a prefix length, and a non-contiguous network as
// an address and an explicit mask. This differs from the network's own
// String only for host routes, whose explicit suffix is part of that
// output contract, and the bare address still reparses as the same
// host route. Future formatting adapters follow this shape: a wrapper
// type over network with String and AppendTo.
type Compact[T network] struct {
	// Network is the network value to render.
	Network T
}

// String returns the compact text form of the network, see AppendTo.
func (m Compact[T]) String() string {
	// Each branch sizes its buffer to the family's longest form, so
	// the string conversion is the only allocation.
	switch network := any(m.Network).(type) {
	case Network4:
		var buffer [31]byte
		return string(appendCompact4(buffer[:0], network))
	case Network6:
		var buffer [91]byte
		return string(appendCompact6(buffer[:0], network))
	}
	// The constraint leaves Network as the only remaining
	// instantiation, and it renders as the family it holds.
	network := any(m.Network).(Network)
	var buffer [91]byte
	if inner, ok := network.IPv4(); ok {
		return string(appendCompact4(buffer[:0], inner))
	}
	return string(appendCompact6(buffer[:0], network.network))
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

// AppendTo appends the compact text form of the network to b and
// returns the extended buffer.
//
// A host route is written as its bare address, everything else
// exactly as the network's own AppendTo writes it: address and
// prefix length for a contiguous mask, address and explicit mask
// otherwise. A Network is written in its own family, so the
// host-route rule fires at 32 bits for IPv4 and at 128 for IPv6,
// an IPv4-mapped IPv6 network counting as IPv6. The output parses
// back with the family's Parse function, which reads a bare address
// as a host route.
func (m Compact[T]) AppendTo(b []byte) []byte {
	switch network := any(m.Network).(type) {
	case Network4:
		return appendCompact4(b, network)
	case Network6:
		return appendCompact6(b, network)
	}
	// The constraint leaves Network as the only remaining
	// instantiation, and it renders as the family it holds.
	network := any(m.Network).(Network)
	if inner, ok := network.IPv4(); ok {
		return appendCompact4(b, inner)
	}
	return appendCompact6(b, network.network)
}
