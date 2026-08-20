package xnetip

import "net/netip"

// IPv6Network is an IPv6 network: an address and a mask of arbitrary
// shape.
//
// The mask need not be contiguous (ffff:0:ffff:: is a valid mask). The
// address is always normalized, every bit outside the mask is zero, so
// two values describing the same address set compare equal with ==. The
// zero value is ::/0, the network of every IPv6 address. Values are
// immutable and safe to copy.
type IPv6Network struct {
	addr ipv6Addr
	mask ipv6Addr
}

// IPv6NetworkFrom returns the network with the given address and mask.
//
// The address is normalized by the mask:
// 2a02:6b8:c00:1:2:3:4:5/ffff:ffff:ff00:: becomes
// 2a02:6b8:c00::/ffff:ffff:ff00::. Any mask bit pattern is accepted.
// Both arguments must be Is6 addresses (an IPv4-mapped address is IPv6
// and converts as its 16-byte form, a zone is dropped silently): an Is4
// address or the invalid zero netip.Addr is rejected with
// ErrAddrFamilyMismatch.
func IPv6NetworkFrom(addr, mask netip.Addr) (IPv6Network, error) {
	addrKernel, addrOk := ipv6AddrFromNetip(addr)
	maskKernel, maskOk := ipv6AddrFromNetip(mask)
	if !addrOk || !maskOk {
		input := addr.String() + "/" + mask.String()
		return IPv6Network{}, wrapParseError("IPv6NetworkFrom", input, ErrAddrFamilyMismatch, nil)
	}
	addrHi, addrLo := addrKernel.Bits()
	maskHi, maskLo := maskKernel.Bits()
	return IPv6NetworkFromBits(addrHi, addrLo, maskHi, maskLo), nil
}

// IPv6NetworkFromBits returns the network for host-order address and
// mask halves, high 64 bits first.
//
// The address is normalized by the mask, as in IPv6NetworkFrom. It is
// the total integer fast path: every input is a valid network.
func IPv6NetworkFromBits(addrHi, addrLo, maskHi, maskLo uint64) IPv6Network {
	mask := uint128FromHalves(maskHi, maskLo)
	return IPv6Network{
		addr: ipv6Addr{uint128FromHalves(addrHi, addrLo).And(mask)},
		mask: ipv6Addr{mask},
	}
}

// Addr returns the network address (already normalized by the mask) as
// an Is6 netip.Addr.
func (m IPv6Network) Addr() netip.Addr {
	return m.addr.Netip()
}

// Mask returns the network mask as an Is6 netip.Addr.
func (m IPv6Network) Mask() netip.Addr {
	return m.mask.Netip()
}

// Bits returns the address and the mask as host-order 64-bit halves.
func (m IPv6Network) Bits() (addrHi, addrLo, maskHi, maskLo uint64) {
	addrHi, addrLo = m.addr.Bits()
	maskHi, maskLo = m.mask.Bits()
	return addrHi, addrLo, maskHi, maskLo
}

// IsIPv4MappedIPv6 reports whether this network is an IPv4-mapped IPv6
// network.
//
// True when the address lies in ::ffff:0:0/96 and the mask keeps all
// of those upper 96 bits, so the network is exactly the image of an
// IPv4 network under IPv4Network.ToIPv6Mapped. An address with the
// ::ffff pattern under a mask that does not pin the upper bits is not
// mapped: collapsing it to IPv4 would lose addresses.
func (m IPv6Network) IsIPv4MappedIPv6() bool {
	maskHi, maskLo := m.mask.Bits()
	return m.addr.Is4In6() && maskHi == ^uint64(0) && maskLo>>32 == 0xffffffff
}

// ToIPv4Mapped returns the IPv4 network this IPv4-mapped IPv6 network
// encodes.
//
// The result is the low 32 bits of the address and the mask, valid
// only when IsIPv4MappedIPv6 holds, otherwise ok is false. Truncation
// preserves normalization, because the upper 96 bits of a mapped
// network are fully masked. The inverse of IPv4Network.ToIPv6Mapped.
func (m IPv6Network) ToIPv4Mapped() (IPv4Network, bool) {
	if !m.IsIPv4MappedIPv6() {
		return IPv4Network{}, false
	}
	_, addrLo := m.addr.Bits()
	_, maskLo := m.mask.Bits()
	return IPv4NetworkFromBits(uint32(addrLo), uint32(maskLo)), true
}
