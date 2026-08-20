package xnetip

import (
	"net/netip"
	"strings"
)

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

// IPNetworkFromPrefix converts a netip.Prefix into an IPNetwork.
//
// The family follows the prefix address: an IPv4 prefix becomes an
// IPv4 network, anything else — an IPv4-mapped IPv6 prefix included —
// an IPv6 network, as in netip. The result is normalized: host bits
// of the prefix address are cleared, the same network
// netip.Prefix.Masked would report. ok is false only for the invalid
// zero prefix. The inverse of Prefix.
func IPNetworkFromPrefix(p netip.Prefix) (IPNetwork, bool) {
	if !p.IsValid() {
		return IPNetwork{}, false
	}
	// The family dispatch makes the typed conversions total here, so
	// their rejections are impossible.
	if p.Addr().Is4() {
		network, ok := IPv4NetworkFromPrefix(p)
		if !ok {
			return IPNetwork{}, false
		}
		return IPNetworkFrom4(network), true
	}
	network, ok := IPv6NetworkFromPrefix(p)
	if !ok {
		return IPNetwork{}, false
	}
	return IPNetworkFrom6(network), true
}

// ParseIPNetwork parses an IPv4 or IPv6 network in CIDR,
// explicit-mask or bare address notation.
//
// The address part selects the family and the mask must be of the same
// family: "10.0.0.0/8", "10.0.0.0/255.0.255.0", "2001:db8::/32",
// "2001:db8::/ffff:ffff::ffff:ffff:0:0", "10.0.0.1" and "2001:db8::1"
// are all accepted. An IPv4-mapped address such as "::ffff:192.0.2.0"
// is IPv6, so the network stays IPv6. Text whose address part is no
// address of either family wraps ErrParse with the net/netip cause;
// past that point the per-family grammar and errors are those of
// ParseIPv4Network and ParseIPv6Network.
func ParseIPNetwork(s string) (IPNetwork, error) {
	addrText, suffix, hasSuffix := strings.Cut(s, "/")
	addr, err := netip.ParseAddr(addrText)
	if err != nil {
		return IPNetwork{}, wrapParseError("ParseIPNetwork", s, ErrParse, err)
	}
	if addr.Is4() {
		network, err := parseIPv4NetworkParts("ParseIPNetwork", s, addr, suffix, hasSuffix)
		if err != nil {
			return IPNetwork{}, err
		}
		return IPNetworkFrom4(network), nil
	}
	network, err := parseIPv6NetworkParts("ParseIPNetwork", s, addr, suffix, hasSuffix)
	if err != nil {
		return IPNetwork{}, err
	}
	return IPNetworkFrom6(network), nil
}

// MustParseIPNetwork calls ParseIPNetwork and panics on error.
//
// It is intended for tests and package-level constants built from
// literals.
func MustParseIPNetwork(s string) IPNetwork {
	network, err := ParseIPNetwork(s)
	if err != nil {
		panic(err)
	}
	return network
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

// Contains reports whether every address of other is also an address
// of m.
//
// Networks of different address families never contain each other.
// Within a family the result is the family's Contains, so masks may
// be non-contiguous and the usual rules apply: identical networks
// contain each other, the family universe contains every network of
// its family, a host route contains only itself.
func (m IPNetwork) Contains(other IPNetwork) bool {
	// The family check must come first: without it the IPv6 universe
	// would contain the mapped storage form of every IPv4 network.
	//
	// For two IPv4 networks the 128-bit check of the stored forms is
	// exact: mapped storage pins the top 96 address and mask bits to
	// the same values on both sides, leaving exactly the IPv4 formula
	// on the low 32 bits.
	return m.is4 == other.is4 && m.network.Contains(other.network)
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

// PrefixLen returns the family-native prefix length when the mask is
// contiguous.
//
// For an IPv4 network the prefix is 0 through 32, for an IPv6 network
// 0 through 128, in both cases the number of leading one bits of the
// mask in that family. The second result is false for a non-contiguous
// mask, in which case the first result is 0. The stored mask of an
// IPv4 network carries the 96 mapped-range bits as leading ones above
// its 32 family bits, so the family length is the 128-bit length of
// the stored form minus that width.
func (m IPNetwork) PrefixLen() (int, bool) {
	prefix, ok := m.network.PrefixLen()
	if ok && m.is4 {
		return prefix - ipv4MappedPrefixBits, true
	}
	return prefix, ok
}

// Prefix returns the network as a netip.Prefix in its own family.
//
// An IPv4 network yields an Is4 prefix with its 0 through 32 length,
// never the IPv4-mapped storage form, while an IPv4-mapped IPv6
// network stays IPv6. ok is false when the mask is not contiguous,
// and the first result is then the invalid zero netip.Prefix. The
// returned prefix is already masked. The inverse of
// IPNetworkFromPrefix.
func (m IPNetwork) Prefix() (netip.Prefix, bool) {
	if network, ok := m.IPv4(); ok {
		return network.Prefix()
	}
	return m.network.Prefix()
}

// String returns the text form of the network, see AppendTo.
func (m IPNetwork) String() string {
	// The buffer covers the longest form of either family, so the
	// string conversion is the only allocation.
	var buffer [91]byte
	return string(m.AppendTo(buffer[:0]))
}

// AppendTo appends the text form of the network to b and returns the
// extended buffer.
//
// An IPv4 network is written in the IPv4 form ("10.0.0.0/8"), never in
// its IPv4-mapped storage form. See IPv4Network.AppendTo and
// IPv6Network.AppendTo for the per-family format. The output parses
// back with ParseIPNetwork.
func (m IPNetwork) AppendTo(b []byte) []byte {
	if network, ok := m.IPv4(); ok {
		return network.AppendTo(b)
	}
	return m.network.AppendTo(b)
}

// MarshalText implements encoding.TextMarshaler.
//
// The text is the String form of the network in its own address
// family: an IPv4 network prints in dotted form even though it is
// stored IPv4-mapped, an IPv6 network prints compressed. It never
// fails and allocates only the returned slice.
func (m IPNetwork) MarshalText() ([]byte, error) {
	return m.AppendTo(make([]byte, 0, len("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"))), nil
}

// UnmarshalText implements encoding.TextUnmarshaler.
//
// The text must be accepted by ParseIPNetwork, which detects the
// family from the address part, so a zone suffix is rejected and
// IPv4-mapped text stays IPv6. Empty text wraps ErrEmptyInput rather
// than yielding the zero value the way it yields the invalid zero
// netip.Prefix: the zero IPNetwork is the valid network ::/0, so empty
// text would silently hide a missing field. The receiver is untouched
// on any error.
func (m *IPNetwork) UnmarshalText(text []byte) error {
	if len(text) == 0 {
		return wrapParseError("IPNetwork.UnmarshalText", "", ErrEmptyInput, nil)
	}
	network, err := ParseIPNetwork(string(text))
	if err != nil {
		return err
	}
	*m = network
	return nil
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
