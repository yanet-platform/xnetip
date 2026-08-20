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
// every block is contiguous and aligned to its own size, and no CIDR
// decomposition of the interval uses fewer blocks (at most 62). The
// function is total: the sequence is empty when first > last, and
// when either end — an IPv6 end (IPv4-mapped included) or the
// invalid zero Addr — is not an Is4 netip.Addr, because such an
// interval holds no IPv4 addresses. The sequence is allocation-free
// and re-iterable.
func RangeToNetworks4(first, last netip.Addr) iter.Seq[Network4] {
	return func(yield func(Network4) bool) {
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
		// block size upwards form its netmask. A zero encodes the
		// descending phase alone: the whole interval is one aligned
		// block.
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
			if !yield(Network4{addr: addr4FromBits(cursor), mask: addr4FromBits(mask)}) {
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
		// aligned to its block, so both phases construct networks
		// normalized by construction, and the final block ends
		// exactly at the interval's last address.
		for {
			size := uint64(lastBits) - uint64(cursor) + 1
			blockMax := uint32((^uint64(0) >> 1) >> bits.LeadingZeros64(size))
			if !yield(Network4{addr: addr4FromBits(cursor), mask: addr4FromBits(^blockMax)}) {
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
