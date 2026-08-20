package xnetip

import "net/netip"

// IPv4Network is an IPv4 network: an address and a mask of arbitrary
// shape.
//
// The mask need not be contiguous (255.0.255.0 is a valid mask). The
// address is always normalized, every bit outside the mask is zero, so
// two values describing the same address set compare equal with ==. The
// zero value is 0.0.0.0/0, the network of every IPv4 address. Values
// are immutable and safe to copy.
type IPv4Network struct {
	addr ipv4Addr
	mask ipv4Addr
}

// IPv4NetworkFrom returns the network with the given address and mask.
//
// The address is normalized by the mask: 192.168.1.1/255.255.255.0
// becomes 192.168.1.0/255.255.255.0 and 192.168.1.1/255.255.0.255
// becomes 192.168.0.1/255.255.0.255. Any mask bit pattern is accepted.
// Both arguments must be Is4 addresses: an IPv6 address (IPv4-mapped
// included) or the invalid zero netip.Addr is rejected with
// ErrAddrFamilyMismatch.
func IPv4NetworkFrom(addr, mask netip.Addr) (IPv4Network, error) {
	addrKernel, addrOk := ipv4AddrFromNetip(addr)
	maskKernel, maskOk := ipv4AddrFromNetip(mask)
	if !addrOk || !maskOk {
		input := addr.String() + "/" + mask.String()
		return IPv4Network{}, wrapParseError("IPv4NetworkFrom", input, ErrAddrFamilyMismatch, nil)
	}
	return IPv4NetworkFromBits(addrKernel.Bits(), maskKernel.Bits()), nil
}

// IPv4NetworkFromBits returns the network for a host-order address and
// mask.
//
// The address is normalized by the mask, as in IPv4NetworkFrom. It is
// the total integer fast path: every input is a valid network.
func IPv4NetworkFromBits(addr, mask uint32) IPv4Network {
	return IPv4Network{
		addr: ipv4AddrFromBits(addr & mask),
		mask: ipv4AddrFromBits(mask),
	}
}

// Addr returns the network address (already normalized by the mask) as
// an Is4 netip.Addr.
func (m IPv4Network) Addr() netip.Addr {
	return m.addr.Netip()
}

// Mask returns the network mask as an Is4 netip.Addr.
func (m IPv4Network) Mask() netip.Addr {
	return m.mask.Netip()
}

// Bits returns the address and the mask as host-order integers.
func (m IPv4Network) Bits() (addr, mask uint32) {
	return m.addr.Bits(), m.mask.Bits()
}

// ToIPv6Mapped returns this network as an IPv4-mapped IPv6 network.
//
// The address becomes ::ffff:a.b.c.d and the mask keeps the upper 96
// bits set, so the result pins the mapped prefix and carries the IPv4
// mask, contiguous or not, in its low 32 bits. Set relations are
// preserved: two IPv4 networks contain or intersect each other exactly
// when their mapped forms do. IPv6Network.ToIPv4Mapped inverts it.
func (m IPv4Network) ToIPv6Mapped() IPv6Network {
	addrHi, addrLo := m.addr.ToIPv6Mapped().Bits()
	return IPv6NetworkFromBits(addrHi, addrLo, ^uint64(0), 0xffffffff_00000000|uint64(m.mask.Bits()))
}

// IPNetwork returns this IPv4 network as an IPNetwork.
func (m IPv4Network) IPNetwork() IPNetwork {
	return IPNetworkFrom4(m)
}
