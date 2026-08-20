package xnetip

import (
	"iter"
	"net/netip"
	"strings"
)

// Network is an IPv4 or IPv6 network with a mask of arbitrary shape.
//
// It is the family-agnostic counterpart of Network4 and Network6:
// every operation of the concrete types exists here and delegates to
// them, operations across families are false, ok=false or empty as
// documented on each method, and Compare orders every IPv4 network
// before every IPv6 network. An IPv4 network is stored as its image
// under Network4.ToIPv6Mapped, which preserves every set relation,
// while the accessors keep returning unmapped Is4 views. The zero
// value is ::/0. Values are immutable and safe to copy.
type Network struct {
	network Network6 // IPv4 networks are stored IPv4-mapped.
	is4     bool
}

// NetworkFrom4 returns the Network holding an IPv4 network.
func NetworkFrom4(network Network4) Network {
	return Network{network: network.ToIPv6Mapped(), is4: true}
}

// NetworkFrom6 returns the Network holding an IPv6 network.
//
// An IPv6 network that happens to be IPv4-mapped stays IPv6, as in
// netip, where an IPv4-mapped address reports Is6 and not Is4.
func NetworkFrom6(network Network6) Network {
	return Network{network: network}
}

// NetworkFrom returns the network with the given address and mask,
// normalizing the address by the mask.
//
// Both arguments must belong to the same address family (Is4 with Is4,
// Is6 with Is6 — an IPv4-mapped address is Is6), otherwise
// ErrAddrFamilyMismatch is returned; the invalid zero netip.Addr is
// rejected the same way. Any mask bit pattern of the family is
// accepted, non-contiguous ones included. An IPv4 pair produces an
// IPv4 network, an IPv6 pair (IPv4-mapped addresses included) an IPv6
// network. A zone is dropped silently.
func NetworkFrom(addr, mask netip.Addr) (Network, error) {
	// The family dispatch makes the typed constructors total here, so
	// their errors are impossible.
	switch {
	case addr.Is4() && mask.Is4():
		network, _ := Network4From(addr, mask)
		return NetworkFrom4(network), nil
	case addr.Is6() && mask.Is6():
		network, _ := Network6From(addr, mask)
		return NetworkFrom6(network), nil
	default:
		input := addr.String() + "/" + mask.String()
		return Network{}, wrapParseError("NetworkFrom", input, ErrAddrFamilyMismatch, nil)
	}
}

// NetworkFromAddr returns the host route that contains exactly addr,
// in the address family of addr.
//
// An Is4 address yields an IPv4 network (/32) and an Is6 address an
// IPv6 network (/128). An IPv4-mapped IPv6 address is Is6 and yields
// an IPv6 network, a zone is dropped silently, and the invalid zero
// netip.Addr is rejected with ErrAddrFamilyMismatch.
func NetworkFromAddr(addr netip.Addr) (Network, error) {
	// The family dispatch makes the typed constructors total here, so
	// their errors are impossible.
	switch {
	case addr.Is4():
		network, _ := Network4FromAddr(addr)
		return NetworkFrom4(network), nil
	case addr.Is6():
		network, _ := Network6FromAddr(addr)
		return NetworkFrom6(network), nil
	default:
		return Network{}, wrapParseError("NetworkFromAddr", addr.String(), ErrAddrFamilyMismatch, nil)
	}
}

// NetworkFromCIDR returns the network of addr with the top bits
// bits masked, in addr's own family.
//
// The length is bounded by the family, 0 through 32 for IPv4 and 0
// through 128 for IPv6, otherwise ErrCIDROverflow is returned. An
// IPv4-mapped address is IPv6 and stays IPv6, as in netip. The invalid
// zero netip.Addr is rejected with ErrAddrFamilyMismatch. Host bits of
// addr are cleared.
func NetworkFromCIDR(addr netip.Addr, bits int) (Network, error) {
	// The typed constructors can only reject the length after the
	// family dispatch, so the error is rebuilt to name this entry point.
	switch {
	case addr.Is4():
		network, err := Network4FromCIDR(addr, bits)
		if err != nil {
			input := cidrInput(addr, bits)
			return Network{}, wrapParseError("NetworkFromCIDR", input, ErrCIDROverflow, nil)
		}
		return NetworkFrom4(network), nil
	case addr.Is6():
		network, err := Network6FromCIDR(addr, bits)
		if err != nil {
			input := cidrInput(addr, bits)
			return Network{}, wrapParseError("NetworkFromCIDR", input, ErrCIDROverflow, nil)
		}
		return NetworkFrom6(network), nil
	default:
		input := cidrInput(addr, bits)
		return Network{}, wrapParseError("NetworkFromCIDR", input, ErrAddrFamilyMismatch, nil)
	}
}

// NetworkFromPrefix converts a netip.Prefix into a Network.
//
// The family follows the prefix address: an IPv4 prefix becomes an
// IPv4 network, anything else — an IPv4-mapped IPv6 prefix included —
// an IPv6 network, as in netip. The result is normalized: host bits
// of the prefix address are cleared, the same network
// netip.Prefix.Masked would report. ok is false only for the invalid
// zero prefix. The inverse of Prefix.
func NetworkFromPrefix(p netip.Prefix) (Network, bool) {
	if !p.IsValid() {
		return Network{}, false
	}
	// The family dispatch makes the typed conversions total here, so
	// their rejections are impossible.
	if p.Addr().Is4() {
		network, ok := Network4FromPrefix(p)
		if !ok {
			return Network{}, false
		}
		return NetworkFrom4(network), true
	}
	network, ok := Network6FromPrefix(p)
	if !ok {
		return Network{}, false
	}
	return NetworkFrom6(network), true
}

// ParseNetwork parses an IPv4 or IPv6 network in CIDR,
// explicit-mask or bare address notation.
//
// The address part selects the family and the mask must be of the same
// family: "10.0.0.0/8", "10.0.0.0/255.0.255.0", "2001:db8::/32",
// "2001:db8::/ffff:ffff::ffff:ffff:0:0", "10.0.0.1" and "2001:db8::1"
// are all accepted. An IPv4-mapped address such as "::ffff:192.0.2.0"
// is IPv6, so the network stays IPv6. Text whose address part is no
// address of either family wraps ErrParse with the net/netip cause;
// past that point the per-family grammar and errors are those of
// ParseNetwork4 and ParseNetwork6.
func ParseNetwork(s string) (Network, error) {
	addrText, suffix, hasSuffix := strings.Cut(s, "/")
	addr, err := netip.ParseAddr(addrText)
	if err != nil {
		return Network{}, wrapParseError("ParseNetwork", s, ErrParse, err)
	}
	if addr.Is4() {
		network, err := parseNetwork4Parts("ParseNetwork", s, addr, suffix, hasSuffix)
		if err != nil {
			return Network{}, err
		}
		return NetworkFrom4(network), nil
	}
	network, err := parseNetwork6Parts("ParseNetwork", s, addr, suffix, hasSuffix)
	if err != nil {
		return Network{}, err
	}
	return NetworkFrom6(network), nil
}

// parseText parses CIDR-block text for the generic contiguous
// wrapper, exactly as ParseContiguous does, its error labels included.
//
// The receiver is a zero-value dispatch token: a generic method
// cannot name a per-family function, so the constraint carries this
// route instead.
func (Network) parseText(s string) (Network, error) {
	block, err := ParseContiguous(s)
	return block.Network(), err
}

// MustParseNetwork calls ParseNetwork and panics on error.
//
// It is intended for tests and package-level constants built from
// literals.
func MustParseNetwork(s string) Network {
	network, err := ParseNetwork(s)
	if err != nil {
		panic(err)
	}
	return network
}

// Is4 reports whether the network is IPv4.
func (m Network) Is4() bool {
	return m.is4
}

// Is6 reports whether the network is IPv6 (including IPv4-mapped ones).
func (m Network) Is6() bool {
	return !m.is4
}

// IPv4 returns the IPv4 network, ok is false for an IPv6 network.
func (m Network) IPv4() (Network4, bool) {
	if !m.is4 {
		return Network4{}, false
	}
	// The stored form of an IPv4 network is IPv4-mapped by
	// construction, so the truncation always succeeds.
	network, _ := m.network.ToIPv4Mapped()
	return network, true
}

// IPv6 returns the IPv6 network, ok is false for an IPv4 network.
func (m Network) IPv6() (Network6, bool) {
	if m.is4 {
		return Network6{}, false
	}
	return m.network, true
}

// Addr returns the network address as a netip.Addr of the network's
// own family: Is4 for an IPv4 network, Is6 otherwise.
//
// An IPv4 network answers with the unmapped view of the low 32 stored
// address bits, which the mapped-storage invariant makes exact.
func (m Network) Addr() netip.Addr {
	if m.is4 {
		_, lo := m.network.addr.Bits()
		return addr4FromBits(uint32(lo)).Netip()
	}
	return m.network.addr.Netip()
}

// Mask returns the network mask as a netip.Addr of the network's own
// family: Is4 for an IPv4 network, Is6 otherwise.
//
// An IPv4 network answers with the unmapped view of the low 32 stored
// mask bits, the upper 96 being all ones by the mapped-storage
// invariant. A non-contiguous mask comes back verbatim.
func (m Network) Mask() netip.Addr {
	if m.is4 {
		_, lo := m.network.mask.Bits()
		return addr4FromBits(uint32(lo)).Netip()
	}
	return m.network.mask.Netip()
}

// LastAddr returns the greatest address in this network, in the
// network's address family.
//
// For an IPv4 network the result is an Is4 netip.Addr, for an IPv6
// network an Is6 one, zone-free either way. The value is the family's
// greatest member: the broadcast address of a CIDR block, or the
// network address with every host bit set for a non-contiguous mask.
// It is computed once on the stored 128-bit form — the mapped mask of
// an IPv4 network pins the top 96 bits, so setting its host bits only
// touches the low 32 — and an IPv4 network merely unmaps the view.
func (m Network) LastAddr() netip.Addr {
	last := m.network.addr.bits.Or(m.network.mask.bits.Not())
	if m.is4 {
		return addr4FromBits(uint32(last.lo)).Netip()
	}
	return addr6{last}.Netip()
}

// NumHostBits returns the number of host bits, the zero bits of the
// mask, in the network's address family.
//
// An IPv4 network reports a value in 0 through 32, an IPv6 network in
// 0 through 128. The network holds exactly 2 to the power of this
// value addresses. Both families are answered by the stored 128-bit
// mask without a branch: the mapped mask of an IPv4 network pins its
// top 96 bits as ones, so they contribute no host bits and the
// whole-word count is the family count.
func (m Network) NumHostBits() int {
	return m.network.NumHostBits()
}

// Addrs returns every address of the network in host-index order,
// each carrying the network's address family.
//
// An IPv4 network yields Is4 addresses, an IPv6 network Is6 ones,
// zone-free, in exactly the order of Network4.Addrs and
// Network6.Addrs. The number of addresses is 1 << NumHostBits().
func (m Network) Addrs() iter.Seq[netip.Addr] {
	// The dispatch lives inside a single returned closure so a range
	// over it stays a direct call in both families.
	return func(yield func(netip.Addr) bool) {
		// An IPv4 network must unwrap before iterating.
		//
		// The stored IPv4-mapped form would yield addresses of the
		// wrong family. The mapped-storage invariant makes the low
		// 32 stored bits the IPv4 network, already normalized.
		if m.is4 {
			network := Network4{
				addr: addr4FromBits(uint32(m.network.addr.bits.lo)),
				mask: addr4FromBits(uint32(m.network.mask.bits.lo)),
			}
			network.Addrs()(yield)
			return
		}
		m.network.Addrs()(yield)
	}
}

// AddrsBackward returns every address of the network in reverse
// host-index order, each carrying the network's address family.
//
// It yields exactly the addresses of Addrs in the opposite order:
// Is4 netip.Addr values for an IPv4 network, Is6 for an IPv6 one,
// zone-free either way. The walk starts at LastAddr(), and for a
// contiguous mask it is descending numeric order down to Addr().
// The sequence is re-iterable, allocation-free and stops early when
// the consumer breaks. The number of addresses is exactly
// 1 << NumHostBits().
func (m Network) AddrsBackward() iter.Seq[netip.Addr] {
	// The dispatch lives inside a single returned closure so a range
	// over it stays a direct call in both families.
	return func(yield func(netip.Addr) bool) {
		// An IPv4 network must unwrap before iterating.
		//
		// The stored IPv4-mapped form would yield addresses of the
		// wrong family. The mapped-storage invariant makes the low
		// 32 stored bits the IPv4 network, already normalized.
		if m.is4 {
			network := Network4{
				addr: addr4FromBits(uint32(m.network.addr.bits.lo)),
				mask: addr4FromBits(uint32(m.network.mask.bits.lo)),
			}
			network.AddrsBackward()(yield)
			return
		}
		m.network.AddrsBackward()(yield)
	}
}

// Compare returns -1, 0 or +1 as m sorts before, equal to or after
// other.
//
// Every IPv4 network sorts before every IPv6 network, the order
// netip.Addr.Compare gives across families. Within a family the order
// is that of Network4.Compare or Network6.Compare: lexicographic
// on (address, mask). An IPv4-mapped IPv6 network is an IPv6 network
// and sorts among IPv6 networks, not next to its IPv4 counterpart.
func (m Network) Compare(other Network) int {
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
func (m Network) Contains(other Network) bool {
	// The family check must come first: without it the IPv6 universe
	// would contain the mapped storage form of every IPv4 network.
	//
	// For two IPv4 networks the 128-bit check of the stored forms is
	// exact: mapped storage pins the top 96 address and mask bits to
	// the same values on both sides, leaving exactly the IPv4 formula
	// on the low 32 bits.
	return m.is4 == other.is4 && m.network.Contains(other.network)
}

// Intersection returns the network of addresses common to m and other.
//
// Networks of different address families are disjoint and yield
// ok=false. Within a family the result is the family's Intersection:
// always a single network, ok=false only when the two disagree on a
// bit position both masks constrain. Masks may be non-contiguous. The
// result keeps the family of the inputs, and on ok=false the returned
// value is the zero Network.
func (m Network) Intersection(other Network) (Network, bool) {
	// The family check must come first: without it the IPv6 universe
	// would intersect the mapped storage form of every IPv4 network.
	//
	// For two IPv4 networks the 128-bit intersection of the stored
	// forms is exact: mapped storage pins the top 96 address and mask
	// bits to the same values on both sides, so the disjointness test
	// reduces to the IPv4 formula on the low 32 bits and the unions
	// keep the top bits pinned — the result is a valid mapped network.
	if m.is4 != other.is4 {
		return Network{}, false
	}
	network, ok := m.network.Intersection(other.network)
	if !ok {
		return Network{}, false
	}
	return Network{network: network, is4: m.is4}, true
}

// Intersects reports whether the two networks share at least one
// address.
//
// Networks of different families never intersect. Within a family the
// result equals the corresponding Network4 or Network6 method,
// for contiguous and non-contiguous masks alike.
func (m Network) Intersects(other Network) bool {
	// The family check must come first: without it the IPv6 universe
	// would intersect the mapped storage form of every IPv4 network.
	//
	// For two IPv4 networks the 128-bit check of the stored forms is
	// exact: mapped storage pins the top 96 address and mask bits to
	// the same values on both sides, leaving exactly the IPv4 formula
	// on the low 32 bits.
	return m.is4 == other.is4 && m.network.Intersects(other.network)
}

// IsDisjoint reports whether the two networks share no address.
//
// Networks of different families are always disjoint. Within a family
// it is the logical complement of Intersects.
func (m Network) IsDisjoint(other Network) bool {
	return !m.Intersects(other)
}

// Difference returns the networks whose union is the set difference
// m \ other, each part carrying m's address family.
//
// Same-family operands delegate to the concrete peel: exactly
// popcount(d) pairwise-disjoint parts with d the mask bits fixed by
// the intersection but free in m, most significant bit of d first,
// as documented on Network4.Difference and Network6.Difference.
// Operands of different families share no address, so the difference
// is m itself, yielded once. Masks may be non-contiguous. The
// sequence is allocation-free and re-iterable.
func (m Network) Difference(other Network) iter.Seq[Network] {
	return func(yield func(Network) bool) {
		// Operands of different families are disjoint, so the
		// difference is the whole receiver, yielded as is.
		if m.is4 != other.is4 {
			yield(m)
			return
		}
		// An IPv4 pair must unwrap before peeling.
		//
		// Running the 128-bit peel on the mapped storage would lose
		// the family of every part. The mapped-storage invariant
		// makes the low 32 stored bits the IPv4 networks, already
		// normalized, and the family dispatch stays inside this
		// closure so a range over the sequence remains a direct
		// call.
		if m.is4 {
			network := Network4{
				addr: addr4FromBits(uint32(m.network.addr.bits.lo)),
				mask: addr4FromBits(uint32(m.network.mask.bits.lo)),
			}
			otherNetwork := Network4{
				addr: addr4FromBits(uint32(other.network.addr.bits.lo)),
				mask: addr4FromBits(uint32(other.network.mask.bits.lo)),
			}
			for part := range network.Difference(otherNetwork) {
				if !yield(NetworkFrom4(part)) {
					return
				}
			}
			return
		}
		for part := range m.network.Difference(other.network) {
			if !yield(NetworkFrom6(part)) {
				return
			}
		}
	}
}

// IsAdjacent reports whether the two networks share a mask and differ
// in exactly one masked bit.
//
// Networks of different families are never adjacent. Within a family
// the result equals the corresponding Network4 or Network6
// method.
func (m Network) IsAdjacent(other Network) bool {
	// The family check must come first: without it an IPv4 network
	// could count as adjacent to the IPv6 twin of its sibling.
	//
	// For two IPv4 networks the 128-bit check of the stored forms is
	// exact: mapped storage pins the top 96 address and mask bits to
	// the same values on both sides, so the masks compare equal and
	// the address difference is exactly the IPv4 one.
	return m.is4 == other.is4 && m.network.IsAdjacent(other.network)
}

// IsAdjacentByLowestMaskBit reports whether the two networks share a
// mask and differ in exactly the lowest set bit of that mask.
//
// Networks of different families are never adjacent. Within a family
// the result equals the corresponding Network4 or Network6
// method.
func (m Network) IsAdjacentByLowestMaskBit(other Network) bool {
	// The family check must come first: without it an IPv4 network
	// could count as adjacent to the IPv6 twin of its buddy.
	//
	// For two IPv4 networks the 128-bit check of the stored forms is
	// exact: an equal non-zero IPv4 mask keeps its lowest set bit in
	// the low 32 mapped bits, and the equal all-zero IPv4 mask maps
	// to /96, whose isolated bit 32 can never equal the zero
	// difference of the two equal stored addresses.
	return m.is4 == other.is4 && m.network.IsAdjacentByLowestMaskBit(other.network)
}

// Merge returns the single network whose address set is the union of
// the two inputs, and false when no such network exists.
//
// Networks of different families never merge. Within a family the
// result equals the corresponding Network4 or Network6 method
// and keeps the family of the inputs. On ok=false the returned value
// is the zero Network.
func (m Network) Merge(other Network) (Network, bool) {
	// The family check must come first: without it the IPv6 universe
	// would absorb the mapped storage form of every IPv4 network.
	//
	// For two IPv4 networks the 128-bit merge of the stored forms is
	// exact: mapped storage pins the top 96 address and mask bits to
	// the same values on both sides, so a sibling difference and a
	// dropped mask bit land in the low 32 bits and a containment
	// result is one of the inputs — either way the result is a valid
	// mapped network.
	if m.is4 != other.is4 {
		return Network{}, false
	}
	network, ok := m.network.Merge(other.network)
	if !ok {
		return Network{}, false
	}
	return Network{network: network, is4: m.is4}, true
}

// MergeByLowestMaskBit merges two networks of the same family when
// one contains the other or when they are lowest-mask-bit siblings.
//
// Networks of different families never merge and report false.
// Within a family the result and the flag are exactly those of the
// Network4 or Network6 method, and the result keeps the
// operands' family. On ok=false the returned value is the zero
// Network.
func (m Network) MergeByLowestMaskBit(other Network) (Network, bool) {
	// The family check must come first: without it the IPv6 universe
	// would absorb the mapped storage form of every IPv4 network.
	//
	// For two IPv4 networks the 128-bit merge of the stored forms is
	// exact: mapped storage pins the top 96 address and mask bits to
	// the same values on both sides, so the lowest set bit of an
	// equal non-zero mask, the sibling test and the containment
	// probes all land in the low 32 bits, and the equal all-zero
	// IPv4 masks resolve as equal networks. Either way the result is
	// one of the inputs or their low-32 sibling union, a valid
	// mapped network.
	if m.is4 != other.is4 {
		return Network{}, false
	}
	network, ok := m.network.MergeByLowestMaskBit(other.network)
	if !ok {
		return Network{}, false
	}
	return Network{network: network, is4: m.is4}, true
}

// SupernetFor returns the smallest network containing this network
// and every network in nets.
//
// Any element of the other address family makes ok false: no network
// spans both families, so a mixed slice has no supernet and yields
// false rather than a silently narrowed answer. Within one family
// the result is exactly the Network4 or Network6 fold and
// keeps that family. An empty slice returns the network itself. On
// ok=false the returned value is the zero Network.
func (m Network) SupernetFor(nets []Network) (Network, bool) {
	// The family check rides the fold loop, so one pass both rejects
	// a foreign element and folds a same-family one.
	//
	// For a same-family slice the 128-bit fold of the stored forms is
	// exact: mapped storage pins the top 96 address and mask bits to
	// the same values on every operand, so those mask bits survive
	// every fold step, the result stays IPv4-mapped and its low 32
	// bits are exactly the IPv4 fold.
	mask := m.network.mask.bits
	for idx := range nets {
		if nets[idx].is4 != m.is4 {
			return Network{}, false
		}
		mask = nets[idx].network.supernetMask(m.network.addr, mask)
	}
	return Network{network: fromBits6(m.network.addr, addr6{mask}), is4: m.is4}, true
}

// IsContiguous reports whether the mask, in the network's own family,
// is a CIDR prefix mask: leading one bits followed only by zero bits.
//
// For an IPv4 network the answer is that of Network4.IsContiguous,
// for an IPv6 network that of Network6.IsContiguous. The stored
// mask of an IPv4 network carries 96 leading ones above the 32 IPv4
// mask bits, extending the leading run, so the 128-bit predicate of
// the stored form answers for both families without a branch. When
// the IPv4 mask is zero, the wrapped predecessor borrows one bit out
// of the pinned region and the or restores it, so the all-zero IPv4
// mask still counts as contiguous.
func (m Network) IsContiguous() bool {
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
func (m Network) PrefixLen() (int, bool) {
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
// NetworkFromPrefix.
func (m Network) Prefix() (netip.Prefix, bool) {
	if network, ok := m.IPv4(); ok {
		return network.Prefix()
	}
	return m.network.Prefix()
}

// ToContiguous returns the CIDR block whose mask is the leading run
// of one bits of this mask, keeping the address family.
//
// See Network4.ToContiguous and Network6.ToContiguous for the
// per-family contract. An IPv4 network stays an IPv4 network. The
// exact, non-widening conversion is ContiguousFrom.
func (m Network) ToContiguous() Contiguous[Network] {
	// One truncation of the stored form serves both families and
	// keeps the family flag.
	//
	// The mapped mask of an IPv4 network pins its top 96 bits as
	// ones, so the stored leading run is 96 plus the IPv4 run:
	// truncating it truncates the IPv4 mask exactly, keeps those top
	// mask bits and leaves the mapped address prefix untouched, so
	// the storage invariant survives.
	return Contiguous[Network]{network: Network{
		network: m.network.ToContiguous().Network(),
		is4:     m.is4,
	}}
}

// String returns the text form of the network, see AppendTo.
func (m Network) String() string {
	// The buffer covers the longest form of either family, so the
	// string conversion is the only allocation.
	var buffer [91]byte
	return string(m.AppendTo(buffer[:0]))
}

// AppendTo appends the text form of the network to b and returns the
// extended buffer.
//
// An IPv4 network is written in the IPv4 form ("10.0.0.0/8"), never in
// its IPv4-mapped storage form. See Network4.AppendTo and
// Network6.AppendTo for the per-family format. The output parses
// back with ParseNetwork.
func (m Network) AppendTo(b []byte) []byte {
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
func (m Network) MarshalText() ([]byte, error) {
	return m.AppendTo(make([]byte, 0, len("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"))), nil
}

// UnmarshalText implements encoding.TextUnmarshaler.
//
// The text must be accepted by ParseNetwork, which detects the
// family from the address part, so a zone suffix is rejected and
// IPv4-mapped text stays IPv6. Empty text wraps ErrEmptyInput rather
// than yielding the zero value the way it yields the invalid zero
// netip.Prefix: the zero Network is the valid network ::/0, so empty
// text would silently hide a missing field. The receiver is untouched
// on any error.
func (m *Network) UnmarshalText(text []byte) error {
	if len(text) == 0 {
		return wrapParseError("Network.UnmarshalText", "", ErrEmptyInput, nil)
	}
	network, err := ParseNetwork(string(text))
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
func (m Network) ToIPv6Mapped() Network6 {
	return m.network
}

// ToCanonical returns the network in its canonical address family.
//
// An IPv4 network is returned unchanged. An IPv6 network that is
// IPv4-mapped (address ::ffff:a.b.c.d and a mask whose top 96 bits are
// all ones, see Network6.IsIPv4MappedIPv6) collapses to the
// equivalent IPv4 network, non-contiguous masks included. Any other
// IPv6 network, including IPv4-compatible ::a.b.c.d addresses and
// mapped addresses whose mask does not pin the top 96 bits, is
// returned unchanged. The inverse of ToIPv6Mapped on mapped values.
func (m Network) ToCanonical() Network {
	if m.is4 {
		return m
	}
	// The collapse is a flag flip: a mapped IPv6 network already
	// holds the exact bits an IPv4 network is stored in.
	if m.network.IsIPv4MappedIPv6() {
		return Network{network: m.network, is4: true}
	}
	return m
}
