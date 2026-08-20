package xnetip

import (
	"net/netip"
	"strconv"
	"strings"
)

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

// IPv6NetworkFromPrefix converts a netip.Prefix into an IPv6Network.
//
// The result is normalized: host bits of the prefix address are
// cleared, the same network netip.Prefix.Masked would report. An
// IPv4-mapped IPv6 prefix (::ffff:a.b.c.d/n) is IPv6 and is accepted,
// and a zone never appears because netip.Prefix carries none. ok is
// false when the prefix is invalid or its address is Is4 — convert
// that one through IPv4NetworkFromPrefix instead. The inverse of
// Prefix.
func IPv6NetworkFromPrefix(p netip.Prefix) (IPv6Network, bool) {
	if !p.IsValid() || !p.Addr().Is6() {
		return IPv6Network{}, false
	}
	// A valid Is6 prefix carries a length within 0 through 128, so the
	// constructor cannot fail; its error answers false, not a panic.
	network, err := IPv6NetworkFromCIDR(p.Addr(), p.Bits())
	if err != nil {
		return IPv6Network{}, false
	}
	return network, true
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

// ParseIPv6Network parses an IPv6 network in CIDR, explicit-mask or
// bare address notation.
//
// Accepted forms are "2001:db8::/32", "2001:db8::/ffff:ffff::" (the
// mask may be non-contiguous) and "2001:db8::1" (a host route,
// "/128"). IPv4-mapped addresses such as "::ffff:192.0.2.1" are IPv6
// here. The address is normalized under the mask. The prefix length
// after "/" is decimal digits with no sign and no leading zero, at
// most 128. A zone suffix ("%eth0") anywhere is an error. Errors wrap
// ErrZone, ErrAddrFamilyMismatch (an IPv4 literal), ErrCIDROverflow,
// ErrInvalidMask or ErrParse together with the net/netip cause.
func ParseIPv6Network(s string) (IPv6Network, error) {
	addrText, suffix, hasSuffix := strings.Cut(s, "/")
	addr, err := netip.ParseAddr(addrText)
	if err != nil {
		return IPv6Network{}, wrapParseError("ParseIPv6Network", s, ErrParse, err)
	}
	return parseIPv6NetworkParts("ParseIPv6Network", s, addr, suffix, hasSuffix)
}

// parseIPv6NetworkParts finishes a network parse whose address part
// is already parsed.
//
// Errors carry the given parser name and echo the full input. The
// suffix is read as a strict prefix length first and as a colon-form
// mask second, so a digits-only suffix past the limit is an overflow,
// never a mask attempt. A missing suffix is a host route.
func parseIPv6NetworkParts(function, input string, addr netip.Addr, suffix string, hasSuffix bool) (IPv6Network, error) {
	addrKernel, err := ipv6ParsedKernel(addr)
	if err != nil {
		return IPv6Network{}, wrapParseError(function, input, err, nil)
	}
	if !hasSuffix {
		return IPv6Network{addr: addrKernel, mask: ipv6AllBits}, nil
	}
	bits, isPrefixForm, ok := parsePrefixLenText(suffix, 128)
	switch {
	case ok:
		return fromBits6(addrKernel, ipv6Addr{uint128MaskFromPrefix(bits)}), nil
	case isPrefixForm:
		return IPv6Network{}, wrapParseError(function, input, ErrCIDROverflow, nil)
	}
	mask, err := netip.ParseAddr(suffix)
	if err != nil {
		return IPv6Network{}, wrapParseError(function, input, ErrInvalidMask, err)
	}
	maskKernel, err := ipv6ParsedKernel(mask)
	if err != nil {
		return IPv6Network{}, wrapParseError(function, input, ErrInvalidMask, err)
	}
	return fromBits6(addrKernel, maskKernel), nil
}

// ipv6ParsedKernel converts parsed network text to the IPv6 kernel,
// rejecting what the parsers must not accept.
//
// Unlike the checked constructors, which drop a zone silently, parse
// input carrying a zone is an error: the result is the bare ErrZone or
// ErrAddrFamilyMismatch sentinel for the caller to wrap under its own
// position, address or mask.
func ipv6ParsedKernel(addr netip.Addr) (ipv6Addr, error) {
	if addr.Zone() != "" {
		return ipv6Addr{}, ErrZone
	}
	kernel, ok := ipv6AddrFromNetip(addr)
	if !ok {
		return ipv6Addr{}, ErrAddrFamilyMismatch
	}
	return kernel, nil
}

// MustParseIPv6Network calls ParseIPv6Network and panics on error.
//
// It is intended for tests and package-level constants built from
// literals.
func MustParseIPv6Network(s string) IPv6Network {
	network, err := ParseIPv6Network(s)
	if err != nil {
		panic(err)
	}
	return network
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

// LastAddr returns the greatest address in this network.
//
// For a contiguous network this is the last address of the CIDR
// block. For a non-contiguous mask it is the network address with
// every host bit set: masking that back yields the network address,
// so it is a member, and no member can set a bit the mask clears
// beyond all of them, so none is greater. Host bits need not form a
// trailing run for either fact to hold. The result is an Is6
// netip.Addr, zone-free.
func (m IPv6Network) LastAddr() netip.Addr {
	return ipv6Addr{m.addr.bits.Or(m.mask.bits.Not())}.Netip()
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

// Contains reports whether every address of other is also an address
// of m.
//
// Two networks are compared as address sets: m contains other when
// other agrees with m on every bit position m constrains, and other
// constrains at least those positions. Identical networks contain
// each other, ::/0 contains everything, a host route contains only
// itself. Masks may be non-contiguous.
func (m IPv6Network) Contains(other IPv6Network) bool {
	// With this network as `(a1, m1)` and the other as `(a2, m2)`,
	// inclusion is the match `a2&m1 == a1` plus the subset `m2&m1 == m1`.
	//
	// The first conjunct checks agreement on every constrained bit,
	// the second that the other mask fixes at least those bits. Both
	// lean on the addresses being normalized, and the subset test
	// must stay an AND: a numeric mask comparison is wrong for
	// non-contiguous masks.
	a1, m1 := m.addr.bits, m.mask.bits
	a2, m2 := other.addr.bits, other.mask.bits
	return a2.And(m1) == a1 && m2.And(m1) == m1
}

// Intersection returns the network of addresses common to m and other.
//
// The intersection of two networks is always a single network: its
// mask is the union of both masks and its address the union of both
// addresses. ok is false when the networks are disjoint, which happens
// exactly when they disagree on a bit position both masks constrain.
// Masks may be non-contiguous. When one network contains the other the
// result is the contained one, and a network intersected with itself
// is itself.
func (m IPv6Network) Intersection(other IPv6Network) (IPv6Network, bool) {
	// The disjointness test compares the addresses on the doubly
	// constrained bits alone.
	//
	// With this network as `(a1, m1)` and the other as `(a2, m2)`, the
	// sets are disjoint exactly when `a1&m2 != a2&m1`: a bit set in
	// only one mask is free on the other side and cannot conflict.
	a1, m1 := m.addr.bits, m.mask.bits
	a2, m2 := other.addr.bits, other.mask.bits
	if a1.And(m2) != a2.And(m1) {
		return IPv6Network{}, false
	}
	// The raw construction is exact, no masking AND is needed.
	//
	// Every set bit of either address lies inside its own mask and
	// thus inside the union mask, so the union address is already
	// normalized.
	return IPv6Network{
		addr: ipv6Addr{a1.Or(a2)},
		mask: ipv6Addr{m1.Or(m2)},
	}, true
}

// Intersects reports whether the two networks share at least one
// address.
//
// Two networks intersect when their addresses agree on every bit that
// both masks constrain. The check is equivalent to Intersection
// returning ok, and holds for non-contiguous masks. A network always
// intersects itself and the unspecified network ::/0 intersects
// everything.
func (m IPv6Network) Intersects(other IPv6Network) bool {
	_, ok := m.Intersection(other)
	return ok
}

// IsDisjoint reports whether the two networks share no address.
//
// It is the logical complement of Intersects and holds the same
// guarantees for non-contiguous masks.
func (m IPv6Network) IsDisjoint(other IPv6Network) bool {
	return !m.Intersects(other)
}

// IsAdjacent reports whether the two networks share a mask and differ
// in exactly one masked bit.
//
// Adjacent networks merge into a single network by dropping the
// differing bit from the mask. Identical networks are not adjacent,
// and networks with different masks are never adjacent. The differing
// bit may sit anywhere in the mask, so merging two contiguous
// networks that are adjacent at a non-boundary bit yields a
// non-contiguous mask. Works with non-contiguous masks.
func (m IPv6Network) IsAdjacent(other IPv6Network) bool {
	_, ok := m.adjacentBit(other)
	return ok
}

// adjacentBit returns the single bit in which the addresses of two
// same-mask networks differ.
//
// ok is false when the masks differ or the addresses differ in zero
// or more than one bit. Both addresses are normalized, so their
// difference can hold only masked bits and needs no extra masking.
func (m IPv6Network) adjacentBit(other IPv6Network) (uint128, bool) {
	if m.mask != other.mask {
		return uint128{}, false
	}
	// Exactly one differing bit means the difference is a power of
	// two: non-zero, and clearing its lowest set bit leaves zero.
	diff := m.addr.bits.Xor(other.addr.bits)
	if !diff.IsPowerOfTwo() {
		return uint128{}, false
	}
	return diff, true
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

// IsBicontiguous reports whether each 64-bit half of the mask is a
// run of leading ones on its own.
//
// Such a mask describes a product of a high-half prefix and a
// low-half prefix, the shape of site-by-subnet classifiers. Every
// contiguous mask is bi-contiguous — its low half is all ones or all
// zeros — but the converse is false. The check uses the run-top
// property: a set bit whose upper neighbour is clear ends a maximal
// run of ones, and the mask is bi-contiguous exactly when every run
// ends at bit 127 or at bit 63, so clearing those two positions from
// the run tops must leave nothing.
func (m IPv6Network) IsBicontiguous() bool {
	mask := m.mask.bits
	runTops := mask.AndNot(mask.Shr(1))
	return runTops.AndNot(uint128FromHalves(1<<63, 1<<63)).IsZero()
}

// PrefixLen returns the prefix length of the mask when the mask is
// contiguous.
//
// The prefix is the number of leading one bits, 0 through 128. The
// second result is false for a non-contiguous mask, in which case no
// prefix length describes the network and the first result is 0. An
// IPv4-mapped network reports its 128-bit length: the image of an
// IPv4 /24 is a /120 here.
func (m IPv6Network) PrefixLen() (int, bool) {
	if !m.IsContiguous() {
		return 0, false
	}
	return m.mask.bits.LeadingOnes(), true
}

// Prefix returns the network as a netip.Prefix.
//
// ok is false when the mask is not contiguous, because netip.Prefix
// can only express prefix lengths, and the first result is then the
// invalid zero netip.Prefix. The returned prefix is already masked
// and carries no zone. The inverse of IPv6NetworkFromPrefix.
func (m IPv6Network) Prefix() (netip.Prefix, bool) {
	bits, ok := m.PrefixLen()
	if !ok {
		return netip.Prefix{}, false
	}
	return netip.PrefixFrom(m.Addr(), bits), true
}

// String returns the text form of the network, see AppendTo.
func (m IPv6Network) String() string {
	// The buffer covers the longest form (address and mask of 45
	// bytes each), so the string conversion is the only allocation.
	var buffer [91]byte
	return string(m.AppendTo(buffer[:0]))
}

// AppendTo appends the text form of the network to b and returns the
// extended buffer.
//
// A contiguous network is written as "addr/prefix", a non-contiguous
// one as "addr/mask" with the mask in the same compressed form as an
// address. The suffix is always present, so a host route is written
// with "/128". The output parses back with ParseIPv6Network.
func (m IPv6Network) AppendTo(b []byte) []byte {
	b = m.addr.AppendTo(b)
	b = append(b, '/')
	if prefix, ok := m.PrefixLen(); ok {
		return strconv.AppendInt(b, int64(prefix), 10)
	}
	return m.mask.AppendTo(b)
}

// MarshalText implements encoding.TextMarshaler.
//
// The text is the String form of the network: a compressed address,
// "/" and either a prefix length (contiguous mask) or a colon-form
// mask (non-contiguous mask). It never fails and allocates only the
// returned slice.
func (m IPv6Network) MarshalText() ([]byte, error) {
	return m.AppendTo(make([]byte, 0, len("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"))), nil
}

// UnmarshalText implements encoding.TextUnmarshaler.
//
// The text must be accepted by ParseIPv6Network, so a zone suffix is
// rejected. Empty text wraps ErrEmptyInput rather than yielding the
// zero value the way it yields the invalid zero netip.Prefix: the zero
// IPv6Network is the valid network ::/0, so empty text would silently
// hide a missing field. The receiver is untouched on any error.
func (m *IPv6Network) UnmarshalText(text []byte) error {
	if len(text) == 0 {
		return wrapParseError("IPv6Network.UnmarshalText", "", ErrEmptyInput, nil)
	}
	network, err := ParseIPv6Network(string(text))
	if err != nil {
		return err
	}
	*m = network
	return nil
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
