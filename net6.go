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
	return fromBits6(addrKernel, maskKernel), nil
}

// fromBits6 returns the normalized network of an address and mask
// kernel.
//
// It is the total internal fast path shared by every constructor: the
// address is normalized by the mask, so any kernel pair yields a valid
// network.
func fromBits6(addr, mask ipv6Addr) IPv6Network {
	return IPv6Network{
		addr: ipv6Addr{addr.bits.And(mask.bits)},
		mask: mask,
	}
}

// IPv6NetworkFromCIDR returns the network of addr with the top bits
// bits masked.
//
// Host bits of addr are cleared: 2001:db8::1 with 64 gives
// 2001:db8::/64, the same network netip.Prefix.Masked would report.
// The address must be Is6 (an IPv4-mapped address is IPv6 and converts
// as its 16-byte form, a zone is dropped silently) — an Is4 address or
// the invalid zero netip.Addr is rejected with ErrAddrFamilyMismatch —
// and bits must be in the range 0 through 128, otherwise
// ErrCIDROverflow is returned.
func IPv6NetworkFromCIDR(addr netip.Addr, bits int) (IPv6Network, error) {
	addrKernel, ok := ipv6AddrFromNetip(addr)
	if !ok {
		input := cidrInput(addr, bits)
		return IPv6Network{}, wrapParseError("IPv6NetworkFromCIDR", input, ErrAddrFamilyMismatch, nil)
	}
	if bits < 0 || bits > 128 {
		input := cidrInput(addr, bits)
		return IPv6Network{}, wrapParseError("IPv6NetworkFromCIDR", input, ErrCIDROverflow, nil)
	}
	return fromBits6(addrKernel, ipv6Addr{uint128MaskFromPrefix(bits)}), nil
}

// IPv6NetworkFromAddr returns the host route that contains exactly
// addr.
//
// The mask is all ones (/128), so the result is normalized by
// construction and no address bit is cleared. addr must be Is6 (an
// IPv4-mapped address is IPv6, a zone is dropped silently): an Is4
// address or the invalid zero netip.Addr is rejected with
// ErrAddrFamilyMismatch.
func IPv6NetworkFromAddr(addr netip.Addr) (IPv6Network, error) {
	addrKernel, ok := ipv6AddrFromNetip(addr)
	if !ok {
		return IPv6Network{}, wrapParseError("IPv6NetworkFromAddr", addr.String(), ErrAddrFamilyMismatch, nil)
	}
	return IPv6Network{addr: addrKernel, mask: ipv6AllBits}, nil
}

// ipv6AllBits is the all-ones mask, the mask of a host route.
//
// Pairing an address with it keeps every address bit, so a host route
// is normalized by construction.
var ipv6AllBits = ipv6AddrFromBits(^uint64(0), ^uint64(0))

// Addr returns the network address (already normalized by the mask) as
// an Is6 netip.Addr.
func (m IPv6Network) Addr() netip.Addr {
	return m.addr.Netip()
}

// Mask returns the network mask as an Is6 netip.Addr.
func (m IPv6Network) Mask() netip.Addr {
	return m.mask.Netip()
}

// Compare returns -1, 0 or +1 as m sorts before, equal to or after
// other.
//
// The order is lexicographic on (address, mask), both compared as
// unsigned 128-bit integers: the address decides first and the mask
// breaks ties, so a container sorts before the networks nested under
// the same address. This order is a documented contract: the output
// of AggregateIPv6 and the input of BinarySplitIPv6 are sorted by it.
func (m IPv6Network) Compare(other IPv6Network) int {
	if order := m.addr.Compare(other.addr); order != 0 {
		return order
	}
	return m.mask.Compare(other.mask)
}

// IsContiguous reports whether the mask is a CIDR prefix mask: a run
// of leading one bits followed only by zero bits.
//
// The all-zero mask (/0) and the all-ones mask (/128) are both
// contiguous. Any mask with a one bit after a zero bit, such as
// ffff:0:ffff::, is not. The formula is the 128-bit twin of the IPv4
// one: or with the wrapped predecessor against all ones, with the
// subtraction borrowing across the 64-bit halves.
func (m IPv6Network) IsContiguous() bool {
	return m.mask.bits.IsContiguousMask()
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
	return fromBits4(ipv4AddrFromBits(uint32(addrLo)), ipv4AddrFromBits(uint32(maskLo))), true
}

// IPNetwork returns this IPv6 network as an IPNetwork.
func (m IPv6Network) IPNetwork() IPNetwork {
	return IPNetworkFrom6(m)
}
