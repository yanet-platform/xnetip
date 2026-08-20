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

// IPNetworkFrom returns the network with the given address and mask,
// normalizing the address by the mask.
//
// Both arguments must belong to the same address family (Is4 with Is4,
// Is6 with Is6 — an IPv4-mapped address is Is6), otherwise
// ErrAddrFamilyMismatch is returned; the invalid zero netip.Addr is
// rejected the same way. Any mask bit pattern of the family is
// accepted, non-contiguous ones included. An IPv4 pair produces an
// IPv4 network, an IPv6 pair (IPv4-mapped addresses included) an IPv6
// network. A zone is dropped silently.
func IPNetworkFrom(addr, mask netip.Addr) (IPNetwork, error) {
	// The family dispatch makes the typed constructors total here, so
	// their errors are impossible.
	switch {
	case addr.Is4() && mask.Is4():
		network, _ := IPv4NetworkFrom(addr, mask)
		return IPNetworkFrom4(network), nil
	case addr.Is6() && mask.Is6():
		network, _ := IPv6NetworkFrom(addr, mask)
		return IPNetworkFrom6(network), nil
	default:
		input := addr.String() + "/" + mask.String()
		return IPNetwork{}, wrapParseError("IPNetworkFrom", input, ErrAddrFamilyMismatch, nil)
	}
}

// IPNetworkFromAddr returns the host route that contains exactly addr,
// in the address family of addr.
//
// An Is4 address yields an IPv4 network (/32) and an Is6 address an
// IPv6 network (/128). An IPv4-mapped IPv6 address is Is6 and yields
// an IPv6 network, a zone is dropped silently, and the invalid zero
// netip.Addr is rejected with ErrAddrFamilyMismatch.
func IPNetworkFromAddr(addr netip.Addr) (IPNetwork, error) {
	// The family dispatch makes the typed constructors total here, so
	// their errors are impossible.
	switch {
	case addr.Is4():
		network, _ := IPv4NetworkFromAddr(addr)
		return IPNetworkFrom4(network), nil
	case addr.Is6():
		network, _ := IPv6NetworkFromAddr(addr)
		return IPNetworkFrom6(network), nil
	default:
		return IPNetwork{}, wrapParseError("IPNetworkFromAddr", addr.String(), ErrAddrFamilyMismatch, nil)
	}
}

// IPNetworkFromCIDR returns the network of addr with the top bits
// bits masked, in addr's own family.
//
// The length is bounded by the family, 0 through 32 for IPv4 and 0
// through 128 for IPv6, otherwise ErrCIDROverflow is returned. An
// IPv4-mapped address is IPv6 and stays IPv6, as in netip. The invalid
// zero netip.Addr is rejected with ErrAddrFamilyMismatch. Host bits of
// addr are cleared.
func IPNetworkFromCIDR(addr netip.Addr, bits int) (IPNetwork, error) {
	// The typed constructors can only reject the length after the
	// family dispatch, so the error is rebuilt to name this entry point.
	switch {
	case addr.Is4():
		network, err := IPv4NetworkFromCIDR(addr, bits)
		if err != nil {
			input := cidrInput(addr, bits)
			return IPNetwork{}, wrapParseError("IPNetworkFromCIDR", input, ErrCIDROverflow, nil)
		}
		return IPNetworkFrom4(network), nil
	case addr.Is6():
		network, err := IPv6NetworkFromCIDR(addr, bits)
		if err != nil {
			input := cidrInput(addr, bits)
			return IPNetwork{}, wrapParseError("IPNetworkFromCIDR", input, ErrCIDROverflow, nil)
		}
		return IPNetworkFrom6(network), nil
	default:
		input := cidrInput(addr, bits)
		return IPNetwork{}, wrapParseError("IPNetworkFromCIDR", input, ErrAddrFamilyMismatch, nil)
	}
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

// Compare returns -1, 0 or +1 as m sorts before, equal to or after
// other.
//
// Every IPv4 network sorts before every IPv6 network, the order
// netip.Addr.Compare gives across families. Within a family the order
// is that of IPv4Network.Compare or IPv6Network.Compare: lexicographic
// on (address, mask). An IPv4-mapped IPv6 network is an IPv6 network
// and sorts among IPv6 networks, not next to its IPv4 counterpart.
func (m IPNetwork) Compare(other IPNetwork) int {
	if m.is4 != other.is4 {
		if m.is4 {
			return -1
		}
		return 1
	}
	// Two IPv4 networks agree on the top 96 stored address and mask
	// bits, so the 128-bit compare reduces to the 32-bit one.
	return m.network.Compare(other.network)
}

// IsContiguous reports whether the mask, in the network's own family,
// is a CIDR prefix mask: leading one bits followed only by zero bits.
//
// For an IPv4 network the answer is that of IPv4Network.IsContiguous,
// for an IPv6 network that of IPv6Network.IsContiguous. The stored
// mask of an IPv4 network carries 96 leading ones above the 32 IPv4
// mask bits, extending the leading run, so the 128-bit predicate of
// the stored form answers for both families without a branch. When
// the IPv4 mask is zero, the wrapped predecessor borrows one bit out
// of the pinned region and the or restores it, so the all-zero IPv4
// mask still counts as contiguous.
func (m IPNetwork) IsContiguous() bool {
	return m.network.IsContiguous()
}

// ipv4MappedPrefixBits is the width of the IPv4-mapped range
// ::ffff:0:0/96.
//
// The stored mask of an IPv4 network pins this many leading one bits
// above its 32 family bits.
const ipv4MappedPrefixBits = 96

// Prefix returns the family-native prefix length when the mask is
// contiguous.
//
// For an IPv4 network the prefix is 0 through 32, for an IPv6 network
// 0 through 128, in both cases the number of leading one bits of the
// mask in that family. The second result is false for a non-contiguous
// mask, in which case the first result is 0. The stored mask of an
// IPv4 network carries the 96 mapped-range bits as leading ones above
// its 32 family bits, so the family length is the 128-bit length of
// the stored form minus that width.
func (m IPNetwork) Prefix() (int, bool) {
	prefix, ok := m.network.Prefix()
	if ok && m.is4 {
		return prefix - ipv4MappedPrefixBits, true
	}
	return prefix, ok
}

// ToIPv6Mapped embeds the network into IPv6 address space.
//
// An IPv4 network is returned as its IPv4-mapped IPv6 network (address
// ::ffff:a.b.c.d, mask ffff:ffff:ffff:ffff:ffff:ffff:M). An IPv6
// network is returned unchanged, so the result is not necessarily
// IPv4-mapped: any IPv6 network passes through as is. Lifting both
// operands of a dual-stack comparison this way makes containment and
// intersection, which are false across families, meaningful. Both arms
// return the stored network, which for the IPv4 arm already is the
// mapped image by the storage invariant.
func (m IPNetwork) ToIPv6Mapped() IPv6Network {
	return m.network
}

// ToCanonical returns the network in its canonical address family.
//
// An IPv4 network is returned unchanged. An IPv6 network that is
// IPv4-mapped (address ::ffff:a.b.c.d and a mask whose top 96 bits are
// all ones, see IPv6Network.IsIPv4MappedIPv6) collapses to the
// equivalent IPv4 network, non-contiguous masks included. Any other
// IPv6 network, including IPv4-compatible ::a.b.c.d addresses and
// mapped addresses whose mask does not pin the top 96 bits, is
// returned unchanged. The inverse of ToIPv6Mapped on mapped values.
func (m IPNetwork) ToCanonical() IPNetwork {
	if m.is4 {
		return m
	}
	// The collapse is a flag flip: a mapped IPv6 network already
	// holds the exact bits an IPv4 network is stored in.
	if m.network.IsIPv4MappedIPv6() {
		return IPNetwork{network: m.network, is4: true}
	}
	return m
}
