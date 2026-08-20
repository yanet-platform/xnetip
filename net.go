package xnetip

import "net/netip"

// IPNetwork is an IPv4 or IPv6 network with a mask of arbitrary shape.
//
// It is the family-agnostic counterpart of IPv4Network and IPv6Network:
// every operation of the concrete types exists here and delegates to
// them, operations across families are false, ok=false or empty as
// documented on each method, and Compare orders every IPv4 network
// before every IPv6 network. An IPv4 network is stored as its image
// under IPv4Network.ToIPv6Mapped, which preserves every set relation,
// while the accessors keep returning unmapped Is4 views. The zero
// value is ::/0. Values are immutable and safe to copy.
type IPNetwork struct {
	network IPv6Network // IPv4 networks are stored IPv4-mapped.
	is4     bool
}

// IPNetworkFrom4 returns the IPNetwork holding an IPv4 network.
func IPNetworkFrom4(network IPv4Network) IPNetwork {
	return IPNetwork{network: network.ToIPv6Mapped(), is4: true}
}

// IPNetworkFrom6 returns the IPNetwork holding an IPv6 network.
//
// An IPv6 network that happens to be IPv4-mapped stays IPv6, as in
// netip, where an IPv4-mapped address reports Is6 and not Is4.
func IPNetworkFrom6(network IPv6Network) IPNetwork {
	return IPNetwork{network: network}
}

// Is4 reports whether the network is IPv4.
func (m IPNetwork) Is4() bool {
	return m.is4
}

// Is6 reports whether the network is IPv6 (including IPv4-mapped ones).
func (m IPNetwork) Is6() bool {
	return !m.is4
}

// IPv4 returns the IPv4 network, ok is false for an IPv6 network.
func (m IPNetwork) IPv4() (IPv4Network, bool) {
	if !m.is4 {
		return IPv4Network{}, false
	}
	// The stored form of an IPv4 network is IPv4-mapped by
	// construction, so the truncation always succeeds.
	network, _ := m.network.ToIPv4Mapped()
	return network, true
}

// IPv6 returns the IPv6 network, ok is false for an IPv4 network.
func (m IPNetwork) IPv6() (IPv6Network, bool) {
	if m.is4 {
		return IPv6Network{}, false
	}
	return m.network, true
}

// Addr returns the network address as a netip.Addr of the network's
// own family: Is4 for an IPv4 network, Is6 otherwise.
//
// An IPv4 network answers with the unmapped view of the low 32 stored
// address bits, which the mapped-storage invariant makes exact.
func (m IPNetwork) Addr() netip.Addr {
	if m.is4 {
		_, lo := m.network.addr.Bits()
		return ipv4AddrFromBits(uint32(lo)).Netip()
	}
	return m.network.addr.Netip()
}

// Mask returns the network mask as a netip.Addr of the network's own
// family: Is4 for an IPv4 network, Is6 otherwise.
//
// An IPv4 network answers with the unmapped view of the low 32 stored
// mask bits, the upper 96 being all ones by the mapped-storage
// invariant. A non-contiguous mask comes back verbatim.
func (m IPNetwork) Mask() netip.Addr {
	if m.is4 {
		_, lo := m.network.mask.Bits()
		return ipv4AddrFromBits(uint32(lo)).Netip()
	}
	return m.network.mask.Netip()
}
