package xnetip

import (
	"math/bits"
	"net/netip"
	"strconv"
	"strings"
)

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
	return fromBits4(addrKernel, maskKernel), nil
}

// fromBits4 returns the normalized network of an address and mask
// kernel.
//
// It is the total internal fast path shared by every constructor: the
// address is normalized by the mask, so any kernel pair yields a valid
// network.
func fromBits4(addr, mask ipv4Addr) IPv4Network {
	return IPv4Network{
		addr: ipv4AddrFromBits(addr.Bits() & mask.Bits()),
		mask: mask,
	}
}

// IPv4NetworkFromCIDR returns the network of addr with the top bits
// bits masked.
//
// Host bits of addr are cleared: 192.168.1.5 with 24 gives
// 192.168.1.0/24, the same network netip.Prefix.Masked would report.
// The address must be Is4 — an IPv6 address, IPv4-mapped included, or
// the invalid zero netip.Addr is rejected with ErrAddrFamilyMismatch —
// and bits must be in the range 0 through 32, otherwise
// ErrCIDROverflow is returned.
func IPv4NetworkFromCIDR(addr netip.Addr, bits int) (IPv4Network, error) {
	addrKernel, ok := ipv4AddrFromNetip(addr)
	if !ok {
		input := cidrInput(addr, bits)
		return IPv4Network{}, wrapParseError("IPv4NetworkFromCIDR", input, ErrAddrFamilyMismatch, nil)
	}
	if bits < 0 || bits > 32 {
		input := cidrInput(addr, bits)
		return IPv4Network{}, wrapParseError("IPv4NetworkFromCIDR", input, ErrCIDROverflow, nil)
	}
	return fromBits4(addrKernel, ipv4MaskFromPrefix(bits)), nil
}

// IPv4NetworkFromPrefix converts a netip.Prefix into an IPv4Network.
//
// The result is normalized: host bits of the prefix address are
// cleared, the same network netip.Prefix.Masked would report. ok is
// false when the prefix is invalid or its address is not Is4 — an
// IPv4-mapped IPv6 prefix is IPv6, convert it through
// IPv6NetworkFromPrefix instead. The inverse of Prefix.
func IPv4NetworkFromPrefix(p netip.Prefix) (IPv4Network, bool) {
	if !p.IsValid() || !p.Addr().Is4() {
		return IPv4Network{}, false
	}
	// A valid Is4 prefix carries a length within 0 through 32, so the
	// constructor cannot fail; its error answers false, not a panic.
	network, err := IPv4NetworkFromCIDR(p.Addr(), p.Bits())
	if err != nil {
		return IPv4Network{}, false
	}
	return network, true
}

// IPv4NetworkFromAddr returns the host route that contains exactly
// addr.
//
// The mask is all ones (/32), so the result is normalized by
// construction and no address bit is cleared. addr must be Is4: an
// IPv6 address (IPv4-mapped included) or the invalid zero netip.Addr
// is rejected with ErrAddrFamilyMismatch.
func IPv4NetworkFromAddr(addr netip.Addr) (IPv4Network, error) {
	addrKernel, ok := ipv4AddrFromNetip(addr)
	if !ok {
		return IPv4Network{}, wrapParseError("IPv4NetworkFromAddr", addr.String(), ErrAddrFamilyMismatch, nil)
	}
	return IPv4Network{addr: addrKernel, mask: ipv4AllBits}, nil
}

// ipv4AllBits is the all-ones mask, the mask of a host route.
//
// Pairing an address with it keeps every address bit, so a host route
// is normalized by construction.
var ipv4AllBits = ipv4AddrFromBits(^uint32(0))

// ParseIPv4Network parses an IPv4 network in CIDR, explicit-mask or
// bare address notation.
//
// Accepted forms are "10.0.0.0/8", "10.0.0.0/255.0.0.0" (the mask may
// be non-contiguous, "10.0.0.0/255.0.255.0") and "10.0.0.1" (a host
// route, "/32"). The address is normalized under the mask, so
// "10.0.0.1/8" is the network "10.0.0.0/8". The prefix length after
// "/" is one or more decimal digits with no sign and no leading zero,
// at most 32. Errors wrap ErrAddrFamilyMismatch (an IPv6 literal),
// ErrCIDROverflow, ErrInvalidMask or, for text that is not an address
// in any form, ErrParse together with the net/netip cause.
func ParseIPv4Network(s string) (IPv4Network, error) {
	addrText, suffix, hasSuffix := strings.Cut(s, "/")
	addr, err := netip.ParseAddr(addrText)
	if err != nil {
		return IPv4Network{}, wrapParseError("ParseIPv4Network", s, ErrParse, err)
	}
	return parseIPv4NetworkParts("ParseIPv4Network", s, addr, suffix, hasSuffix)
}

// parseIPv4NetworkParts finishes a network parse whose address part
// is already parsed.
//
// Errors carry the given parser name and echo the full input. The
// suffix is read as a strict prefix length first and as a dotted
// mask second, so a digits-only suffix past the limit is an overflow,
// never a mask attempt. A missing suffix is a host route.
func parseIPv4NetworkParts(function, input string, addr netip.Addr, suffix string, hasSuffix bool) (IPv4Network, error) {
	addrKernel, ok := ipv4AddrFromNetip(addr)
	if !ok {
		return IPv4Network{}, wrapParseError(function, input, ErrAddrFamilyMismatch, nil)
	}
	if !hasSuffix {
		return IPv4Network{addr: addrKernel, mask: ipv4AllBits}, nil
	}
	bits, isPrefixForm, ok := parsePrefixLenText(suffix, 32)
	switch {
	case ok:
		return fromBits4(addrKernel, ipv4MaskFromPrefix(bits)), nil
	case isPrefixForm:
		return IPv4Network{}, wrapParseError(function, input, ErrCIDROverflow, nil)
	}
	mask, err := netip.ParseAddr(suffix)
	if err != nil {
		return IPv4Network{}, wrapParseError(function, input, ErrInvalidMask, err)
	}
	maskKernel, ok := ipv4AddrFromNetip(mask)
	if !ok {
		return IPv4Network{}, wrapParseError(function, input, ErrInvalidMask, ErrAddrFamilyMismatch)
	}
	return fromBits4(addrKernel, maskKernel), nil
}

// parsePrefixLenText reads a network suffix as a prefix length under
// the strict grammar.
//
// The grammar is one or more ASCII digits, no sign, no leading zero
// unless the whole text is "0". A text of that shape is in prefix
// form and never falls back to a
// mask parse, so ok is false with isPrefixForm true when the value
// exceeds limit. Any other text is not in prefix form and both results
// are false. Accumulation stops at the first excess digit, which keeps
// the value small however long the text runs.
func parsePrefixLenText(text string, limit int) (bits int, isPrefixForm, ok bool) {
	if text == "" || (len(text) > 1 && text[0] == '0') {
		return 0, false, false
	}
	value := 0
	overflow := false
	for idx := range len(text) {
		digit := text[idx]
		if digit < '0' || digit > '9' {
			return 0, false, false
		}
		if !overflow {
			value = value*10 + int(digit-'0')
			overflow = value > limit
		}
	}
	if overflow {
		return 0, true, false
	}
	return value, true, true
}

// MustParseIPv4Network calls ParseIPv4Network and panics on error.
//
// It is intended for tests and package-level constants built from
// literals.
func MustParseIPv4Network(s string) IPv4Network {
	network, err := ParseIPv4Network(s)
	if err != nil {
		panic(err)
	}
	return network
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

// LastAddr returns the greatest address in this network.
//
// For a contiguous network this is the broadcast address. For a
// non-contiguous mask it is the network address with every host bit
// set: masking that back yields the network address, so it is a
// member, and no member can set a bit the mask clears beyond all of
// them, so none is greater. Host bits need not form a trailing run
// for either fact to hold. The result is an Is4 netip.Addr.
func (m IPv4Network) LastAddr() netip.Addr {
	return ipv4AddrFromBits(m.addr.Bits() | ^m.mask.Bits()).Netip()
}

// NumHostBits returns the number of host bits, the zero bits of the
// mask.
//
// The network holds exactly 2 to the power of this value addresses,
// in any position the mask leaves free, so the count is carried
// exactly for every network including the default route. There is no
// separate address count: 2 to the 32 does not fit a uint32 and 2 to
// the 128 fits no integer, the exponent is the lossless form.
func (m IPv4Network) NumHostBits() int {
	return bits.OnesCount32(^m.mask.Bits())
}

// Compare returns -1, 0 or +1 as m sorts before, equal to or after
// other.
//
// The order is lexicographic on (address, mask), both compared as
// unsigned 32-bit integers: the address decides first and the mask
// breaks ties, so a container sorts before the networks nested under
// the same address. This order is a documented contract: the output
// of AggregateIPv4 and the input of BinarySplitIPv4 are sorted by it.
func (m IPv4Network) Compare(other IPv4Network) int {
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
// each other, the universe 0.0.0.0/0 contains everything, a host
// route contains only itself. Masks may be non-contiguous.
func (m IPv4Network) Contains(other IPv4Network) bool {
	// With this network as `(a1, m1)` and the other as `(a2, m2)`,
	// inclusion is the match `a2&m1 == a1` plus the subset `m2&m1 == m1`.
	//
	// The first conjunct checks agreement on every constrained bit,
	// the second that the other mask fixes at least those bits. Both
	// lean on the addresses being normalized, and the subset test
	// must stay an AND: a numeric mask comparison is wrong for
	// non-contiguous masks.
	a1, m1 := m.addr.Bits(), m.mask.Bits()
	a2, m2 := other.addr.Bits(), other.mask.Bits()
	return a2&m1 == a1 && m2&m1 == m1
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
func (m IPv4Network) Intersection(other IPv4Network) (IPv4Network, bool) {
	// The disjointness test compares the addresses on the doubly
	// constrained bits alone.
	//
	// With this network as `(a1, m1)` and the other as `(a2, m2)`, the
	// sets are disjoint exactly when `a1&m2 != a2&m1`: a bit set in
	// only one mask is free on the other side and cannot conflict.
	a1, m1 := m.addr.Bits(), m.mask.Bits()
	a2, m2 := other.addr.Bits(), other.mask.Bits()
	if a1&m2 != a2&m1 {
		return IPv4Network{}, false
	}
	// The raw construction is exact, no masking AND is needed.
	//
	// Every set bit of either address lies inside its own mask and
	// thus inside the union mask, so the union address is already
	// normalized.
	return IPv4Network{
		addr: ipv4AddrFromBits(a1 | a2),
		mask: ipv4AddrFromBits(m1 | m2),
	}, true
}

// Intersects reports whether the two networks share at least one
// address.
//
// Two networks intersect when their addresses agree on every bit that
// both masks constrain. The check is equivalent to Intersection
// returning ok, and holds for non-contiguous masks. A network always
// intersects itself and the unspecified network 0.0.0.0/0 intersects
// everything.
func (m IPv4Network) Intersects(other IPv4Network) bool {
	_, ok := m.Intersection(other)
	return ok
}

// IsDisjoint reports whether the two networks share no address.
//
// It is the logical complement of Intersects and holds the same
// guarantees for non-contiguous masks.
func (m IPv4Network) IsDisjoint(other IPv4Network) bool {
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
func (m IPv4Network) IsAdjacent(other IPv4Network) bool {
	_, ok := m.adjacentBit(other)
	return ok
}

// adjacentBit returns the single bit in which the addresses of two
// same-mask networks differ.
//
// ok is false when the masks differ or the addresses differ in zero
// or more than one bit. Both addresses are normalized, so their
// difference can hold only masked bits and needs no extra masking.
func (m IPv4Network) adjacentBit(other IPv4Network) (uint32, bool) {
	if m.mask != other.mask {
		return 0, false
	}
	// Exactly one differing bit means the difference is a power of
	// two: non-zero, and clearing its lowest set bit leaves zero.
	diff := m.addr.Bits() ^ other.addr.Bits()
	if diff == 0 || diff&(diff-1) != 0 {
		return 0, false
	}
	return diff, true
}

// Merge returns the single network whose address set is the union of
// the two inputs, and false when no such network exists.
//
// The union is a single network in exactly two cases: the masks are
// equal and the addresses differ in at most one bit (the result drops
// that bit from the mask, a duplicate merges to itself), or one
// network contains the other (the result is the larger one). The
// differing bit may be any masked bit, so merging two contiguous
// networks adjacent at a non-boundary bit yields a non-contiguous
// mask. Works with non-contiguous masks.
func (m IPv4Network) Merge(other IPv4Network) (IPv4Network, bool) {
	a1, m1 := m.addr.Bits(), m.mask.Bits()
	a2, m2 := other.addr.Bits(), other.mask.Bits()
	if m1 == m2 {
		// A zero or single-bit difference merges through one formula.
		//
		// The difference is dropped from the mask and cleared from
		// the address, which yields the sibling union, or the input
		// itself unchanged when the difference is zero (a duplicate).
		diff := a1 ^ a2
		if diff&(diff-1) != 0 {
			return IPv4Network{}, false
		}
		mask := m1 ^ diff
		return IPv4Network{
			addr: ipv4AddrFromBits(a1 & mask),
			mask: ipv4AddrFromBits(mask),
		}, true
	}
	// With unequal masks only containment remains.
	//
	// The common mask decides which side can be the container: the
	// container's mask must be the subset, and the contained address
	// must then match it on every container bit. Incomparable masks
	// reject without an address probe.
	common := m1 & m2
	if common == m2 {
		if a1&m2 == a2 {
			return other, true
		}
		return IPv4Network{}, false
	}
	if common == m1 {
		if a2&m1 == a1 {
			return m, true
		}
		return IPv4Network{}, false
	}
	return IPv4Network{}, false
}

// IsContiguous reports whether the mask is a CIDR prefix mask: a run
// of leading one bits followed only by zero bits.
//
// The all-zero mask (/0) and the all-ones mask (/32) are both
// contiguous. Any mask with a one bit after a zero bit, such as
// 255.0.255.0, is not.
func (m IPv4Network) IsContiguous() bool {
	mask := m.mask.Bits()
	// The or with the predecessor fills exactly the trailing zeros:
	// all ones iff no zero sits above the lowest set bit, zero wraps.
	return mask|(mask-1) == ^uint32(0)
}

// PrefixLen returns the prefix length of the mask when the mask is
// contiguous.
//
// The prefix is the number of leading one bits, 0 through 32. The
// second result is false for a non-contiguous mask, in which case no
// prefix length describes the network and the first result is 0.
func (m IPv4Network) PrefixLen() (int, bool) {
	if !m.IsContiguous() {
		return 0, false
	}
	// The mask's leading ones are its complement's leading zeros, and
	// after the contiguity check that run is the whole mask.
	return bits.LeadingZeros32(^m.mask.Bits()), true
}

// Prefix returns the network as a netip.Prefix.
//
// ok is false when the mask is not contiguous, because netip.Prefix
// can only express prefix lengths, and the first result is then the
// invalid zero netip.Prefix. The returned prefix is already masked.
// The inverse of IPv4NetworkFromPrefix.
func (m IPv4Network) Prefix() (netip.Prefix, bool) {
	bits, ok := m.PrefixLen()
	if !ok {
		return netip.Prefix{}, false
	}
	return netip.PrefixFrom(m.Addr(), bits), true
}

// String returns the text form of the network, see AppendTo.
func (m IPv4Network) String() string {
	// The buffer covers the longest form (a dotted mask, 31 bytes),
	// so the string conversion is the only allocation.
	var buffer [31]byte
	return string(m.AppendTo(buffer[:0]))
}

// AppendTo appends the text form of the network to b and returns the
// extended buffer.
//
// A contiguous network is written as "addr/prefix", a non-contiguous
// one as "addr/mask" with the mask in dotted-decimal form. The suffix
// is always present, so a host route is written with "/32". The output
// parses back with ParseIPv4Network.
func (m IPv4Network) AppendTo(b []byte) []byte {
	b = m.addr.AppendTo(b)
	b = append(b, '/')
	if prefix, ok := m.PrefixLen(); ok {
		return strconv.AppendInt(b, int64(prefix), 10)
	}
	return m.mask.AppendTo(b)
}

// MarshalText implements encoding.TextMarshaler.
//
// The text is the String form of the network: an address, "/" and
// either a prefix length (contiguous mask) or a dotted mask
// (non-contiguous mask). It never fails and allocates only the
// returned slice.
func (m IPv4Network) MarshalText() ([]byte, error) {
	return m.AppendTo(make([]byte, 0, len("255.255.255.255/255.255.255.255"))), nil
}

// UnmarshalText implements encoding.TextUnmarshaler.
//
// The text must be accepted by ParseIPv4Network. Empty text wraps
// ErrEmptyInput rather than yielding the zero value the way it yields
// the invalid zero netip.Prefix: the zero IPv4Network is the valid
// network 0.0.0.0/0, so empty text would silently hide a missing
// field. The receiver is untouched on any error.
func (m *IPv4Network) UnmarshalText(text []byte) error {
	if len(text) == 0 {
		return wrapParseError("IPv4Network.UnmarshalText", "", ErrEmptyInput, nil)
	}
	network, err := ParseIPv4Network(string(text))
	if err != nil {
		return err
	}
	*m = network
	return nil
}

// ToIPv6Mapped returns this network as an IPv4-mapped IPv6 network.
//
// The address becomes ::ffff:a.b.c.d and the mask keeps the upper 96
// bits set, so the result pins the mapped prefix and carries the IPv4
// mask, contiguous or not, in its low 32 bits. Set relations are
// preserved: two IPv4 networks contain or intersect each other exactly
// when their mapped forms do. IPv6Network.ToIPv4Mapped inverts it.
func (m IPv4Network) ToIPv6Mapped() IPv6Network {
	mappedMask := ipv6AddrFromBits(^uint64(0), 0xffffffff_00000000|uint64(m.mask.Bits()))
	return fromBits6(m.addr.ToIPv6Mapped(), mappedMask)
}

// IPNetwork returns this IPv4 network as an IPNetwork.
func (m IPv4Network) IPNetwork() IPNetwork {
	return IPNetworkFrom4(m)
}
