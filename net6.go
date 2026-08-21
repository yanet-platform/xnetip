package xnetip

import (
	"iter"
	"net/netip"
	"strconv"
	"strings"
)

// Network6 is an IPv6 network: an address and a mask of arbitrary
// shape.
//
// The mask need not be contiguous (ffff:0:ffff:: is a valid mask). The
// address is always normalized, every bit outside the mask is zero, so
// two values describing the same address set compare equal with ==. The
// zero value is ::/0, the network of every IPv6 address. Values are
// immutable and safe to copy.
type Network6 struct {
	addr addr6
	mask addr6
}

// Network6From returns the network with the given address and mask.
//
// The address is normalized by the mask:
// 2a02:6b8:c00:1:2:3:4:5/ffff:ffff:ff00:: becomes
// 2a02:6b8:c00::/ffff:ffff:ff00::. Any mask bit pattern is accepted.
// Both arguments must be Is6 addresses (an IPv4-mapped address is IPv6
// and converts as its 16-byte form, a zone is dropped silently): an Is4
// address or the invalid zero netip.Addr is rejected with
// ErrAddrFamilyMismatch.
func Network6From(addr, mask netip.Addr) (Network6, error) {
	addrKernel, addrOk := addr6FromNetip(addr)
	maskKernel, maskOk := addr6FromNetip(mask)
	if !addrOk || !maskOk {
		input := addr.String() + "/" + mask.String()
		return Network6{}, wrapParseError("Network6From", input, ErrAddrFamilyMismatch, nil)
	}
	return fromBits6(addrKernel, maskKernel), nil
}

// fromBits6 returns the normalized network of an address and mask
// kernel.
//
// It is the total internal fast path shared by every constructor: the
// address is normalized by the mask, so any kernel pair yields a valid
// network.
func fromBits6(addr, mask addr6) Network6 {
	return Network6{
		addr: addr6{addr.bits.And(mask.bits)},
		mask: mask,
	}
}

// Network6FromCIDR returns the network of addr with the top bits
// bits masked.
//
// Host bits of addr are cleared: 2001:db8::1 with 64 gives
// 2001:db8::/64, the same network netip.Prefix.Masked would report.
// The address must be Is6 (an IPv4-mapped address is IPv6 and converts
// as its 16-byte form, a zone is dropped silently) — an Is4 address or
// the invalid zero netip.Addr is rejected with ErrAddrFamilyMismatch —
// and bits must be in the range 0 through 128, otherwise
// ErrCIDROverflow is returned.
func Network6FromCIDR(addr netip.Addr, bits int) (Network6, error) {
	addrKernel, ok := addr6FromNetip(addr)
	if !ok {
		input := cidrInput(addr, bits)
		return Network6{}, wrapParseError("Network6FromCIDR", input, ErrAddrFamilyMismatch, nil)
	}
	if bits < 0 || bits > 128 {
		input := cidrInput(addr, bits)
		return Network6{}, wrapParseError("Network6FromCIDR", input, ErrCIDROverflow, nil)
	}
	return fromBits6(addrKernel, addr6{uint128MaskFromPrefix(bits)}), nil
}

// Network6FromPrefix converts a netip.Prefix into a Network6.
//
// The result is normalized: host bits of the prefix address are
// cleared, the same network netip.Prefix.Masked would report. An
// IPv4-mapped IPv6 prefix (::ffff:a.b.c.d/n) is IPv6 and is accepted,
// and a zone never appears because netip.Prefix carries none. ok is
// false when the prefix is invalid or its address is Is4 — convert
// that one through Network4FromPrefix instead. The inverse of
// Prefix.
func Network6FromPrefix(p netip.Prefix) (Network6, bool) {
	if !p.IsValid() || !p.Addr().Is6() {
		return Network6{}, false
	}
	// A valid Is6 prefix carries a length within 0 through 128, so the
	// constructor cannot fail; its error answers false, not a panic.
	network, err := Network6FromCIDR(p.Addr(), p.Bits())
	if err != nil {
		return Network6{}, false
	}
	return network, true
}

// Network6FromAddr returns the host route that contains exactly
// addr.
//
// The mask is all ones (/128), so the result is normalized by
// construction and no address bit is cleared. addr must be Is6 (an
// IPv4-mapped address is IPv6, a zone is dropped silently): an Is4
// address or the invalid zero netip.Addr is rejected with
// ErrAddrFamilyMismatch.
func Network6FromAddr(addr netip.Addr) (Network6, error) {
	addrKernel, ok := addr6FromNetip(addr)
	if !ok {
		return Network6{}, wrapParseError("Network6FromAddr", addr.String(), ErrAddrFamilyMismatch, nil)
	}
	return Network6{addr: addrKernel, mask: ipv6AllBits}, nil
}

// ipv6AllBits is the all-ones mask, the mask of a host route.
//
// Pairing an address with it keeps every address bit, so a host route
// is normalized by construction.
var ipv6AllBits = addr6FromBits(^uint64(0), ^uint64(0))

// ParseNetwork6 parses an IPv6 network in CIDR, explicit-mask or
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
func ParseNetwork6(s string) (Network6, error) {
	addrText, suffix, hasSuffix := strings.Cut(s, "/")
	addr, err := netip.ParseAddr(addrText)
	if err != nil {
		return Network6{}, wrapParseError("ParseNetwork6", s, ErrParse, err)
	}
	return parseNetwork6Parts("ParseNetwork6", s, addr, suffix, hasSuffix)
}

// parseNetwork6Parts finishes a network parse whose address part
// is already parsed.
//
// Errors carry the given parser name and echo the full input. The
// suffix is read as a strict prefix length first and as a colon-form
// mask second, so a digits-only suffix past the limit is an overflow,
// never a mask attempt. A missing suffix is a host route.
func parseNetwork6Parts(function, input string, addr netip.Addr, suffix string, hasSuffix bool) (Network6, error) {
	addrKernel, err := ipv6ParsedKernel(addr)
	if err != nil {
		return Network6{}, wrapParseError(function, input, err, nil)
	}
	if !hasSuffix {
		return Network6{addr: addrKernel, mask: ipv6AllBits}, nil
	}
	bits, isPrefixForm, ok := parsePrefixLenText(suffix, 128)
	switch {
	case ok:
		return fromBits6(addrKernel, addr6{uint128MaskFromPrefix(bits)}), nil
	case isPrefixForm:
		return Network6{}, wrapParseError(function, input, ErrCIDROverflow, nil)
	}
	mask, err := netip.ParseAddr(suffix)
	if err != nil {
		return Network6{}, wrapParseError(function, input, ErrInvalidMask, err)
	}
	maskKernel, err := ipv6ParsedKernel(mask)
	if err != nil {
		return Network6{}, wrapParseError(function, input, ErrInvalidMask, err)
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
func ipv6ParsedKernel(addr netip.Addr) (addr6, error) {
	if addr.Zone() != "" {
		return addr6{}, ErrZone
	}
	kernel, ok := addr6FromNetip(addr)
	if !ok {
		return addr6{}, ErrAddrFamilyMismatch
	}
	return kernel, nil
}

// parseText parses CIDR-block text for the generic contiguous
// wrapper, exactly as ParseContiguous6 does, its error labels included.
//
// The receiver is a zero-value dispatch token: a generic method
// cannot name a per-family function, so the constraint carries this
// route instead.
func (Network6) parseText(s string) (Network6, error) {
	block, err := ParseContiguous6(s)
	return block.Network(), err
}

// MustParseNetwork6 calls ParseNetwork6 and panics on error.
//
// It is intended for tests and package-level constants built from
// literals.
func MustParseNetwork6(s string) Network6 {
	network, err := ParseNetwork6(s)
	if err != nil {
		panic(err)
	}
	return network
}

// Addr returns the network address (already normalized by the mask) as
// an Is6 netip.Addr.
func (m Network6) Addr() netip.Addr {
	return m.addr.Netip()
}

// Mask returns the network mask as an Is6 netip.Addr.
func (m Network6) Mask() netip.Addr {
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
func (m Network6) LastAddr() netip.Addr {
	return addr6{m.addr.bits.Or(m.mask.bits.Not())}.Netip()
}

// NumHostBits returns the number of host bits, the zero bits of the
// mask.
//
// The network holds exactly 2 to the power of this value addresses,
// in any position the mask leaves free, so the count is carried
// exactly for every network including the default route, whose 2 to
// the 128 members fit no integer type. The exponent is the lossless
// form and the only count the type offers.
func (m Network6) NumHostBits() int {
	return m.mask.bits.Not().OnesCount()
}

// Addrs returns every address of the network in host-index order.
//
// The k host positions (mask bits that are zero) are filled with the
// successive values 0 through 2^k-1, least-significant host bit
// first. For a contiguous mask this is ascending numeric order from
// Addr() to LastAddr(), for a non-contiguous mask the numeric order
// differs from the iteration order. Every yielded address is an Is6
// netip.Addr, zone-free. The sequence is re-iterable, allocation-free
// and stops early when the consumer breaks. The count is exactly
// 1 << NumHostBits(), which may exceed any integer type.
func (m Network6) Addrs() iter.Seq[netip.Addr] {
	return func(yield func(netip.Addr) bool) {
		base, mask := m.addr.bits, m.mask.bits
		hostMask := mask.Not()
		last := base.Or(hostMask)
		front := base
		// The walk ends at the address with every host bit set.
		//
		// Host patterns never repeat, so that address is reached
		// exactly once, after all others, and comparing against it
		// terminates every network including the default route,
		// whose count would overflow the word.
		if hostMask.And(hostMask.AddOne()).IsZero() {
			for {
				if !yield(addr6{front}.Netip()) || front == last {
					return
				}
				front = front.AddOne()
			}
		}
		// The non-contiguous step is O(1) for any mask shape.
		//
		// Presetting the mask bits to one makes the +1 carry ripple
		// straight across them, so the increment lands in the next
		// host position however the host bits are scattered.
		for {
			if !yield(addr6{front}.Netip()) || front == last {
				return
			}
			front = front.Or(mask).AddOne().And(hostMask).Or(base)
		}
	}
}

// AddrsBackward returns every address of the network in reverse
// host-index order, starting at LastAddr().
//
// It yields exactly the addresses of Addrs in the opposite order, so
// for a contiguous mask this is descending numeric order from
// LastAddr() to Addr(). Every yielded address is an Is6 netip.Addr,
// zone-free. The sequence is re-iterable, allocation-free and stops
// early when the consumer breaks. The number of addresses is exactly
// 1 << NumHostBits().
func (m Network6) AddrsBackward() iter.Seq[netip.Addr] {
	return func(yield func(netip.Addr) bool) {
		base, mask := m.addr.bits, m.mask.bits
		hostMask := mask.Not()
		back := base.Or(hostMask)
		// The walk ends at the network address, whose host bits are
		// all zero.
		//
		// Host patterns never repeat, so that address is reached
		// exactly once, after all others, and comparing against it
		// terminates every network including the default route,
		// whose count would overflow the word.
		if hostMask.And(hostMask.AddOne()).IsZero() {
			for {
				if !yield(addr6{back}.Netip()) || back == base {
					return
				}
				back = back.SubOne()
			}
		}
		// The non-contiguous step is O(1) for any mask shape.
		//
		// With the mask bits cleared, the -1 borrow ripples straight
		// across them, so the decrement lands in the previous host
		// position however the host bits are scattered.
		for {
			if !yield(addr6{back}.Netip()) || back == base {
				return
			}
			back = back.And(hostMask).SubOne().And(hostMask).Or(base)
		}
	}
}

// Compare returns -1, 0 or +1 as m sorts before, equal to or after
// other.
//
// The order is lexicographic on (address, mask), both compared as
// unsigned 128-bit integers: the address decides first and the mask
// breaks ties, so a container sorts before the networks nested under
// the same address. This order is a documented contract: it is the
// sort Aggregate6 applies before its greedy pass and the order
// BinarySplit6 expects of its input.
func (m Network6) Compare(other Network6) int {
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
func (m Network6) Contains(other Network6) bool {
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

// containsContiguous is Contains for two CIDR networks, the
// mask-subset conjunct collapsed to one unsigned compare.
//
// With this network as `(a1, m1)` and the other as `(a2, m2)`, both
// masks leading runs of one bits, the subset test `m2&m1 == m1`
// holds exactly when `m1 <= m2`: a longer run keeps every bit of a
// shorter one, and among leading runs longer means numerically
// greater. The collapse is unsound for non-contiguous masks, so the
// caller must guarantee the precondition — the typed wrapper carries
// it in its invariant.
func (m Network6) containsContiguous(other Network6) bool {
	a1, m1 := m.addr.bits, m.mask.bits
	a2, m2 := other.addr.bits, other.mask.bits
	return a2.And(m1) == a1 && m1.Compare(m2) <= 0
}

// ContainsAddr reports whether addr is an address of this network.
//
// The test is total, the netip.Prefix.Contains rule: an address that
// is not Is6 — an Is4 address or the invalid zero netip.Addr — is
// simply not contained, and an address carrying a zone is not
// contained either. An IPv4-mapped address is IPv6 and is tested by
// its 16-byte form. The mask may be non-contiguous: membership is
// agreement with the network address on every mask bit. Equivalent to
// Contains of the host route of addr, without the construction.
func (m Network6) ContainsAddr(addr netip.Addr) bool {
	// The zone check must precede the conversion, which drops zones
	// silently.
	//
	// Relational operations mirror netip.Prefix.Contains, where a
	// zoned address is never contained. The network address is
	// normalized, so masking the argument alone decides membership.
	if addr.Zone() != "" {
		return false
	}
	member, ok := addr6FromNetip(addr)
	return ok && member.bits.And(m.mask.bits) == m.addr.bits
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
func (m Network6) Intersection(other Network6) (Network6, bool) {
	// The disjointness test compares the addresses on the doubly
	// constrained bits alone.
	//
	// With this network as `(a1, m1)` and the other as `(a2, m2)`, the
	// sets are disjoint exactly when `a1&m2 != a2&m1`: a bit set in
	// only one mask is free on the other side and cannot conflict.
	a1, m1 := m.addr.bits, m.mask.bits
	a2, m2 := other.addr.bits, other.mask.bits
	if a1.And(m2) != a2.And(m1) {
		return Network6{}, false
	}
	// The raw construction is exact, no masking AND is needed.
	//
	// Every set bit of either address lies inside its own mask and
	// thus inside the union mask, so the union address is already
	// normalized.
	return Network6{
		addr: addr6{a1.Or(a2)},
		mask: addr6{m1.Or(m2)},
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
func (m Network6) Intersects(other Network6) bool {
	_, ok := m.Intersection(other)
	return ok
}

// IsDisjoint reports whether the two networks share no address.
//
// It is the logical complement of Intersects and holds the same
// guarantees for non-contiguous masks.
func (m Network6) IsDisjoint(other Network6) bool {
	return !m.Intersects(other)
}

// Difference returns the networks whose union is the set difference
// m \ other: every address of m that is not in other.
//
// The parts are pairwise disjoint and masks may be non-contiguous.
// With d the mask bits fixed by the intersection but free in m, there
// are exactly popcount(d) parts when the two overlap, none when m is
// a subset of other, and m itself when they are disjoint — the
// minimum number of networks that can represent the difference.
// Parts are yielded from the most significant bit of d downwards,
// each mask adding one more bit of d. The sequence is allocation-free
// and re-iterable.
func (m Network6) Difference(other Network6) iter.Seq[Network6] {
	return func(yield func(Network6) bool) {
		// Disjoint operands share nothing, so the difference is the
		// whole receiver, yielded as is.
		intersected, ok := m.Intersection(other)
		if !ok {
			yield(m)
			return
		}
		// The peel flips one pending bit of the intersection address
		// per step, highest first, and fixes it into the growing mask.
		//
		// Every pending bit is fixed by the intersection but free in
		// the receiver, so each flip names the part of the receiver
		// that agrees with the overlap on the bits above and differs
		// at the flipped one: the parts are pairwise disjoint and
		// cover the difference exactly. No pending bit means the
		// receiver is a subset and nothing is yielded. The masking
		// AND normalizes each part's address.
		addr := intersected.addr.bits
		mask := m.mask.bits
		remaining := intersected.mask.bits.AndNot(mask)
		for !remaining.IsZero() {
			bit := uint128Bit(127 - remaining.LeadingZeros())
			mask = mask.Or(bit)
			part := Network6{
				addr: addr6{addr.Xor(bit).And(mask)},
				mask: addr6{mask},
			}
			if !yield(part) {
				return
			}
			remaining = remaining.Xor(bit)
		}
	}
}

// contiguousLadderPart returns one part of the CIDR difference
// ladder built over this network as the nested subtrahend.
//
// The part is the CIDR block of the given prefix length, 1 through
// 128, whose address flips this network's address at the new mask
// bit: the block that agrees with this network above that bit and
// leaves it there. The masking AND normalizes the part's address.
func (m Network6) contiguousLadderPart(bits int) Network6 {
	mask := uint128MaskFromPrefix(bits)
	bit := uint128Bit(128 - bits)
	return fromBits6(addr6{m.addr.bits.Xor(bit)}, addr6{mask})
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
func (m Network6) IsAdjacent(other Network6) bool {
	_, ok := m.adjacentBit(other)
	return ok
}

// adjacentBit returns the single bit in which the addresses of two
// same-mask networks differ.
//
// ok is false when the masks differ or the addresses differ in zero
// or more than one bit. Both addresses are normalized, so their
// difference can hold only masked bits and needs no extra masking.
func (m Network6) adjacentBit(other Network6) (uint128, bool) {
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
func (m Network6) Merge(other Network6) (Network6, bool) {
	a1, m1 := m.addr.bits, m.mask.bits
	a2, m2 := other.addr.bits, other.mask.bits
	if m1 == m2 {
		// A zero or single-bit difference merges through one formula.
		//
		// The difference is dropped from the mask and cleared from
		// the address, which yields the sibling union, or the input
		// itself unchanged when the difference is zero (a duplicate).
		diff := a1.Xor(a2)
		if !diff.ClearLowestSetBit().IsZero() {
			return Network6{}, false
		}
		mask := m1.Xor(diff)
		return Network6{
			addr: addr6{a1.And(mask)},
			mask: addr6{mask},
		}, true
	}
	// With unequal masks only containment remains.
	//
	// The common mask decides which side can be the container: the
	// container's mask must be the subset, and the contained address
	// must then match it on every container bit. Incomparable masks
	// reject without an address probe.
	common := m1.And(m2)
	if common == m2 {
		if a1.And(m2) == a2 {
			return other, true
		}
		return Network6{}, false
	}
	if common == m1 {
		if a2.And(m1) == a1 {
			return m, true
		}
		return Network6{}, false
	}
	return Network6{}, false
}

// IsAdjacentByLowestMaskBit reports whether the two networks share a
// mask and differ in exactly the lowest set bit of that mask.
//
// It is the restriction of IsAdjacent to the boundary bit between a
// block and its parent: every pair accepted here is adjacent, but
// adjacency at any higher masked bit is rejected. Merging such a pair
// never leaves the mask's structural class, so two contiguous
// networks give a contiguous parent. Identical networks are not
// adjacent, and the unspecified network /0 is never adjacent to
// anything. For a two-run non-contiguous mask only the lower run's
// boundary bit counts. Works with non-contiguous masks.
func (m Network6) IsAdjacentByLowestMaskBit(other Network6) bool {
	// The empty mask must be rejected explicitly: its isolated lowest
	// set bit is zero, and two equal addresses differ by zero too.
	a1, m1 := m.addr.bits, m.mask.bits
	a2, m2 := other.addr.bits, other.mask.bits
	return m1 == m2 && !m1.IsZero() && a1.Xor(a2) == m1.LowestSetBit()
}

// MergeByLowestMaskBit merges two networks when one contains the
// other or when they are lowest-mask-bit siblings.
//
// Exactly two disjoint cases merge and everything else reports
// false: containment returns the larger network, and a sibling pair
// sharing a mask and differing in precisely its lowest set bit
// returns the common address under that mask with the bit removed.
// Adjacency at any higher masked bit is refused even though Merge
// accepts it, so the result stays in the inputs' class — for a
// non-contiguous mask only the lowest run's boundary bit is a merge
// point. Whenever ok is true the result equals Merge's.
func (m Network6) MergeByLowestMaskBit(other Network6) (Network6, bool) {
	if m.mask == other.mask {
		if m.addr == other.addr {
			return m, true
		}
		if m.IsAdjacentByLowestMaskBit(other) {
			// The sibling result is normalized without a masking AND.
			//
			// The addresses differ only in the mask's lowest set bit,
			// which the reduced mask clears, so their AND holds no
			// bit outside that mask.
			return Network6{
				addr: addr6{m.addr.bits.And(other.addr.bits)},
				mask: addr6{m.mask.bits.ClearLowestSetBit()},
			}, true
		}
		return Network6{}, false
	}
	// With unequal masks adjacency is impossible, so containment is
	// the only remaining way to merge.
	//
	// The equal-mask branch above needed only the address compare
	// because containment degenerates to equality there.
	if m.Contains(other) {
		return m, true
	}
	if other.Contains(m) {
		return other, true
	}
	return Network6{}, false
}

// SupernetFor returns the smallest network containing this network
// and every network in nets.
//
// The mask keeps exactly the bits that every input masks and on which
// every input's address agrees with this network's address, so the
// result is the greatest mask in the bitwise-subset order that still
// covers all inputs. An empty slice returns the network itself. The
// result may be non-contiguous even when every input is a CIDR block:
// addresses differing at a bit off their mask boundary leave a hole.
// Works with non-contiguous masks.
func (m Network6) SupernetFor(nets []Network6) Network6 {
	mask := m.mask.bits
	for idx := range nets {
		mask = nets[idx].supernetMask(m.addr, mask)
	}
	return fromBits6(m.addr, addr6{mask})
}

// supernetMask folds this network into the running supernet mask of a
// receiver address.
//
// The step keeps a running bit only when this network masks it and
// its address agrees with the receiver's address on it: exactly the
// bits a common supernet of the receiver and this network may
// constrain.
func (m Network6) supernetMask(addr addr6, mask uint128) uint128 {
	return mask.And(m.mask.bits.AndNot(addr.bits.Xor(m.addr.bits)))
}

// IsContiguous reports whether the mask is a CIDR prefix mask: a run
// of leading one bits followed only by zero bits.
//
// The all-zero mask (/0) and the all-ones mask (/128) are both
// contiguous. Any mask with a one bit after a zero bit, such as
// ffff:0:ffff::, is not. The formula is the 128-bit twin of the IPv4
// one: or with the wrapped predecessor against all ones, with the
// subtraction borrowing across the 64-bit halves.
func (m Network6) IsContiguous() bool {
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
func (m Network6) IsBicontiguous() bool {
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
func (m Network6) PrefixLen() (int, bool) {
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
// and carries no zone. The inverse of Network6FromPrefix.
func (m Network6) Prefix() (netip.Prefix, bool) {
	bits, ok := m.PrefixLen()
	if !ok {
		return netip.Prefix{}, false
	}
	return netip.PrefixFrom(m.Addr(), bits), true
}

// ToContiguous returns the CIDR block whose mask is the leading run
// of one bits of this mask, with the address normalized under it.
//
// A contiguous network comes back wrapped unchanged. For a
// non-contiguous mask every one bit after the first zero bit is
// cleared, so the block is spanned by the leading run and contains
// every address of this network. The exact, non-widening conversion
// is ContiguousFrom.
func (m Network6) ToContiguous() Contiguous[Network6] {
	// A mask rebuilt from the leading-ones count is a leading run by
	// construction, so the result is wrapped without revalidation.
	mask := addr6{uint128MaskFromPrefix(m.mask.bits.LeadingOnes())}
	return Contiguous[Network6]{network: fromBits6(m.addr, mask)}
}

// String returns the text form of the network, see AppendTo.
func (m Network6) String() string {
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
// with "/128". The output parses back with ParseNetwork6.
func (m Network6) AppendTo(b []byte) []byte {
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
func (m Network6) MarshalText() ([]byte, error) {
	return m.AppendTo(make([]byte, 0, len("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"))), nil
}

// UnmarshalText implements encoding.TextUnmarshaler.
//
// The text must be accepted by ParseNetwork6, so a zone suffix is
// rejected. Empty text wraps ErrEmptyInput rather than yielding the
// zero value the way it yields the invalid zero netip.Prefix: the zero
// Network6 is the valid network ::/0, so empty text would silently
// hide a missing field. The receiver is untouched on any error.
func (m *Network6) UnmarshalText(text []byte) error {
	if len(text) == 0 {
		return wrapParseError("Network6.UnmarshalText", "", ErrEmptyInput, nil)
	}
	network, err := ParseNetwork6(string(text))
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
// IPv4 network under Network4.ToIPv6Mapped. An address with the
// ::ffff pattern under a mask that does not pin the upper bits is not
// mapped: collapsing it to IPv4 would lose addresses.
func (m Network6) IsIPv4MappedIPv6() bool {
	maskHi, maskLo := m.mask.Bits()
	return m.addr.Is4In6() && maskHi == ^uint64(0) && maskLo>>32 == 0xffffffff
}

// ToIPv4Mapped returns the IPv4 network this IPv4-mapped IPv6 network
// encodes.
//
// The result is the low 32 bits of the address and the mask, valid
// only when IsIPv4MappedIPv6 holds, otherwise ok is false. Truncation
// preserves normalization, because the upper 96 bits of a mapped
// network are fully masked. The inverse of Network4.ToIPv6Mapped.
func (m Network6) ToIPv4Mapped() (Network4, bool) {
	if !m.IsIPv4MappedIPv6() {
		return Network4{}, false
	}
	_, addrLo := m.addr.Bits()
	_, maskLo := m.mask.Bits()
	return fromBits4(addr4FromBits(uint32(addrLo)), addr4FromBits(uint32(maskLo))), true
}

// Network returns this IPv6 network as a Network.
func (m Network6) Network() Network {
	return NetworkFrom6(m)
}
