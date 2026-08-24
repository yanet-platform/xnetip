package xnetip

import (
	"iter"
	"math/bits"
	"net/netip"
)

// RangeToNetworks4 returns the minimum set of CIDR blocks covering
// the closed address interval [first, last].
//
// Blocks are yielded in ascending order and are pairwise disjoint,
// each one a typed CIDR block aligned to its own size, and no CIDR
// decomposition of the interval uses fewer blocks (at most 62). The
// function is total: the sequence is empty when first > last or either
// end fails [netip.Addr.Is4]. An IPv6 end (IPv4-mapped included) and
// the invalid zero [netip.Addr] both fail that predicate, because such
// an interval holds no IPv4 addresses. The sequence is allocation-free
// and re-iterable.
func RangeToNetworks4(first, last netip.Addr) iter.Seq[Contiguous[Network4]] {
	return func(yield func(Contiguous[Network4]) bool) {
		if !first.Is4() || !last.Is4() {
			return
		}
		firstBits := addr4From4(first.As4()).Bits()
		lastBits := addr4From4(last.As4()).Bits()
		if firstBits > lastBits {
			return
		}
		// The greedy cover splits at the highest differing bit of
		// the two ends.
		//
		// Below that boundary — the last end with its lower bits
		// cleared — the block sizes are exactly the set bits of the
		// boundary minus the start, walked lowest first, each block
		// aligned at the running cursor so all mask bits from the
		// block size upwards form its netmask, a leading run that
		// wraps as a typed block without revalidation. A zero
		// encodes the descending phase alone: the whole interval is
		// one aligned block.
		cursor := firstBits
		differing := cursor ^ lastBits
		ascending := uint32(0)
		if single := differing&(differing+1) == 0 && cursor&differing == 0; !single {
			bit := uint32(1) << (31 - bits.LeadingZeros32(differing))
			ascending = (lastBits & -bit) - cursor
		}
		for ascending != 0 {
			block := ascending & -ascending
			mask := ascending | -ascending
			if !yield(Contiguous[Network4]{network: Network4{addr: addr4FromBits(cursor), mask: addr4FromBits(mask)}}) {
				return
			}
			ascending ^= block
			cursor += block
		}
		// Past the boundary each block is the largest power of two
		// not exceeding the remaining size.
		//
		// The cursor is aligned beyond that size, and the size is
		// widened to 64 bits, which keeps the full-range case of
		// 2^32 addresses branchless. Every block address is already
		// aligned to its block and every mask is a leading run, so
		// both phases construct networks normalized by construction
		// that wrap as typed blocks without revalidation, and the
		// final block ends exactly at the interval's last address.
		for {
			size := uint64(lastBits) - uint64(cursor) + 1
			blockMax := uint32((^uint64(0) >> 1) >> bits.LeadingZeros64(size))
			if !yield(Contiguous[Network4]{network: Network4{addr: addr4FromBits(cursor), mask: addr4FromBits(^blockMax)}}) {
				return
			}
			end := cursor + blockMax
			if end == lastBits {
				return
			}
			cursor = end + 1
		}
	}
}

// RangeToNetworks6 returns the minimum set of CIDR blocks covering
// the closed address interval [first, last].
//
// Blocks are yielded in ascending order and are pairwise disjoint. Each
// is a typed CIDR block aligned to its size, and no CIDR decomposition
// uses fewer blocks (at most 254). The sequence is empty when first >
// last or either end fails [netip.Addr.Is6]. An end satisfying
// [netip.Addr.Is4] and the invalid zero [netip.Addr] both fail that
// predicate. An IPv4-mapped end is accepted, while a zone is dropped
// silently. The sequence is allocation-free and re-iterable.
func RangeToNetworks6(first, last netip.Addr) iter.Seq[Contiguous[Network6]] {
	return func(yield func(Contiguous[Network6]) bool) {
		if !first.Is6() || !last.Is6() {
			return
		}
		firstBits := addr6From16(first.As16()).bits
		lastBits := addr6From16(last.As16()).bits
		if firstBits.Compare(lastBits) > 0 {
			return
		}
		// The greedy cover splits at the highest differing bit of
		// the two ends.
		//
		// Below that boundary — the last end with its lower bits
		// cleared — the block sizes are exactly the set bits of the
		// boundary minus the start, walked lowest first, each block
		// aligned at the running cursor so all mask bits from the
		// block size upwards form its netmask, a leading run that
		// wraps as a typed block without revalidation. A zero
		// encodes the descending phase alone: the whole interval is
		// one aligned block.
		cursor := firstBits
		differing := cursor.Xor(lastBits)
		ascending := uint128{}
		if single := differing.And(differing.AddOne()).IsZero() && cursor.And(differing).IsZero(); !single {
			bit := uint128Bit(127 - differing.LeadingZeros())
			ascending = lastBits.And(bit.Neg()).Sub(cursor)
		}
		for !ascending.IsZero() {
			negated := ascending.Neg()
			block := ascending.And(negated)
			mask := ascending.Or(negated)
			if !yield(Contiguous[Network6]{network: Network6{addr: addr6{cursor}, mask: addr6{mask}}}) {
				return
			}
			ascending = ascending.Xor(block)
			cursor = cursor.Add(block)
		}
		// Past the boundary each block is the largest power of two
		// not exceeding the remaining size.
		//
		// The cursor is aligned beyond that size, and a size that
		// wraps to zero can only be the full address space, whose
		// block is everything — the word cannot widen the way the
		// 32-bit walk does. Every block address is already aligned
		// to its block and every mask is a leading run, so both
		// phases construct networks normalized by construction that
		// wrap as typed blocks without revalidation, and the final
		// block ends exactly at the interval's last address.
		allOnes := uint128FromHalves(^uint64(0), ^uint64(0))
		for {
			size := lastBits.Sub(cursor).AddOne()
			blockMax := allOnes
			if !size.IsZero() {
				blockMax = allOnes.Shr(uint(size.LeadingZeros() + 1))
			}
			if !yield(Contiguous[Network6]{network: Network6{addr: addr6{cursor}, mask: addr6{blockMax.Not()}}}) {
				return
			}
			end := cursor.Add(blockMax)
			if end == lastBits {
				return
			}
			cursor = end.AddOne()
		}
	}
}
