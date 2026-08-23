package xnetip

import (
	"cmp"
	"slices"
)

// Aggregate4 collapses nets in place and returns the surviving prefix.
//
// Duplicates are dropped, contained networks are absorbed and
// mergeable pairs are replaced by their merge until no pair merges:
// the address union of the result equals that of the input. The input
// order is destroyed (the slice is sorted first) and the tail beyond
// the returned prefix holds unspecified values, like slices.Compact.
// The output order is a deterministic function of the input but not
// guaranteed sorted, and for non-contiguous input the result is not
// guaranteed minimal. Works with non-contiguous masks.
func Aggregate4(nets []Network4) []Network4 {
	if len(nets) <= 1 {
		return nets
	}
	slices.SortFunc(nets, Network4.Compare)
	// Each candidate merges against the entire survivor stack, not
	// just its top: non-contiguous masks are not laminar.
	//
	// A merge partner may therefore sit below the top, and a merge
	// that changed the stack entry can expose new partners (two /24
	// siblings merge into /23 siblings), so the stack is rescanned
	// against that entry until a full pass merges nothing.
	w := 0
	for r := 1; r < len(nets); r++ {
		mergedAt := -1
		grew := false
		for k := w; k >= 0; k-- {
			if merged, ok := nets[k].Merge(nets[r]); ok {
				// An entry that absorbed the candidate unchanged
				// exposes no new merge opportunities.
				//
				// Containment and duplicates leave the entry as it
				// was, so the rescan below is skipped for them.
				grew = nets[k] != merged
				nets[k] = merged
				mergedAt = k
				break
			}
		}
		if mergedAt < 0 {
			w++
			nets[w] = nets[r]
			continue
		}
		if !grew {
			continue
		}
		k := mergedAt
		for changed := true; changed; {
			changed = false
			for j := 0; j <= w; j++ {
				if j == k {
					continue
				}
				merged, ok := nets[k].Merge(nets[j])
				if !ok {
					continue
				}
				nets[k] = merged
				copy(nets[j:w], nets[j+1:w+1])
				w--
				if j < k {
					k--
				}
				changed = true
				break
			}
		}
	}
	return nets[:w+1]
}

// AggregateContiguous aggregates CIDR blocks in place into their
// minimal cover and returns the kept prefix of nets.
//
// Duplicates are removed, contained blocks eliminated and CIDR
// buddies merged, cascading, down to the unique smallest set of
// blocks whose address union equals the input's. The result is
// sorted by Compare and every block stays contiguous. Unlike
// Aggregate4 and Aggregate6, the cover is minimal and the pass runs
// in O(N log N): sorted contiguous blocks form a laminar family, so
// each candidate can only interact with the running top. The input
// slice is reordered; only the returned prefix is meaningful.
func AggregateContiguous[T network[T]](nets []Contiguous[T]) []Contiguous[T] {
	if len(nets) <= 1 {
		return nets
	}
	slices.SortFunc(nets, Contiguous[T].Compare)
	// Sorted ascending, a candidate only ever interacts with the
	// current top — never with a deeper kept block.
	//
	// The (address, mask) order puts every container immediately
	// before its contents and makes prefix-boundary buddies adjacent,
	// while the kept blocks stay pairwise disjoint, so cascading
	// against the top alone is complete and costs O(N) after the sort.
	w := 1
	for r := 1; r < len(nets); r++ {
		current := nets[r].network
		for w > 0 {
			merged, ok := nets[w-1].network.MergeByLowestMaskBit(current)
			if !ok {
				break
			}
			current = merged
			w--
		}
		// The cascade result is contiguous and rewraps without
		// revalidation.
		//
		// Containment hands back an input unchanged, and a buddy
		// merge only clears the mask run's lowest bit, leaving the
		// leading-ones run intact.
		nets[w] = Contiguous[T]{network: current}
		w++
	}
	return nets[:w]
}

// Aggregate6 collapses nets in place and returns the surviving prefix.
//
// Duplicates are dropped, contained networks are absorbed and
// mergeable pairs are replaced by their merge until no pair merges:
// the address union of the result equals that of the input. The input
// order is destroyed (the slice is sorted first) and the tail beyond
// the returned prefix holds unspecified values, like slices.Compact.
// The output order is a deterministic function of the input but not
// guaranteed sorted, and for non-contiguous input the result is not
// guaranteed minimal. Works with non-contiguous masks.
func Aggregate6(nets []Network6) []Network6 {
	if len(nets) <= 1 {
		return nets
	}
	slices.SortFunc(nets, Network6.Compare)
	// Each candidate merges against the entire survivor stack, not
	// just its top: non-contiguous masks are not laminar.
	//
	// A merge partner may therefore sit below the top, and a merge
	// that changed the stack entry can expose new partners (two /24
	// siblings merge into /23 siblings), so the stack is rescanned
	// against that entry until a full pass merges nothing.
	w := 0
	for r := 1; r < len(nets); r++ {
		mergedAt := -1
		grew := false
		for k := w; k >= 0; k-- {
			if merged, ok := nets[k].Merge(nets[r]); ok {
				// An entry that absorbed the candidate unchanged
				// exposes no new merge opportunities.
				//
				// Containment and duplicates leave the entry as it
				// was, so the rescan below is skipped for them.
				grew = nets[k] != merged
				nets[k] = merged
				mergedAt = k
				break
			}
		}
		if mergedAt < 0 {
			w++
			nets[w] = nets[r]
			continue
		}
		if !grew {
			continue
		}
		k := mergedAt
		for changed := true; changed; {
			changed = false
			for j := 0; j <= w; j++ {
				if j == k {
					continue
				}
				merged, ok := nets[k].Merge(nets[j])
				if !ok {
					continue
				}
				nets[k] = merged
				copy(nets[j:w], nets[j+1:w+1])
				w--
				if j < k {
					k--
				}
				changed = true
				break
			}
		}
	}
	return nets[:w+1]
}

// AggregateBiContiguous6 aggregates bi-contiguous IPv6 networks in place
// into a class-closed cover of the same address union.
//
// Duplicates and containment are removed; low-half buddies and high-half
// buddies with equal canonical low sets merge. Every survivor stays in the
// class, no class-preserving pair remains, and a second call is a set no-op.
// The input is reordered; only the returned prefix is meaningful. Results
// sort by numeric (mask, address), not BiContiguous.Compare. The cover is not
// minimum: three rectangles can tile a parent with no accepted pair. For N
// inputs and S present shapes, it is O(N*S*log N) amortized plus bounded
// 65-level work, uses fixed stack state and allocates no heap memory.
func AggregateBiContiguous6(nets []BiContiguous) []BiContiguous {
	if len(nets) <= 1 {
		return nets
	}
	live := sweepBiContiguous6(nets)
	kept := removeBiContiguous6Containment(nets[:live])
	return nets[:kept]
}

// sweepBiContiguous6 canonicalizes low rows and merges equal high buddy rows
// from the most specific high prefix toward the least specific.
func sweepBiContiguous6(nets []BiContiguous) int {
	live := len(nets)
	slices.SortFunc(nets[:live], compareBiContiguous6Level)

	for highPrefix := 64; ; highPrefix-- {
		highMask := biContiguousHalfPrefixMask(highPrefix)
		blockStart := lowerBoundBiContiguous6HighMask(nets[:live], highMask)
		blockEnd := upperBoundBiContiguous6HighMask(nets[:live], highMask)

		afterLow := aggregateBiContiguous6LowRows(nets, blockStart, blockEnd)
		blockSurvivorsEnd := afterLow
		if highPrefix > 0 {
			blockSurvivorsEnd = mergeBiContiguous6HighBuddies(
				nets,
				blockStart,
				afterLow,
				highPrefix,
			)
		}
		reparented := blockSurvivorsEnd < afterLow

		if blockSurvivorsEnd < blockEnd {
			copy(nets[blockSurvivorsEnd:], nets[blockEnd:live])
			live -= blockEnd - blockSurvivorsEnd
		}
		if highPrefix == 0 {
			break
		}

		if reparented {
			newHighMask := biContiguousHalfPrefixMask(highPrefix - 1)
			previousStart := lowerBoundBiContiguous6HighMask(
				nets[:blockStart],
				newHighMask,
			)
			// Only the native next-level block and newly reparented survivors
			// can have crossed in level-major order.
			slices.SortFunc(
				nets[previousStart:blockSurvivorsEnd],
				compareBiContiguous6Level,
			)
		}
	}
	return live
}

// compareBiContiguous6Level orders by high mask, high address, low address and
// low mask, grouping one high-prefix level and each exact high row together.
func compareBiContiguous6Level(first, second BiContiguous) int {
	firstNetwork := first.network6
	secondNetwork := second.network6
	if order := cmp.Compare(
		firstNetwork.mask.bits.hi,
		secondNetwork.mask.bits.hi,
	); order != 0 {
		return order
	}
	if order := cmp.Compare(
		firstNetwork.addr.bits.hi,
		secondNetwork.addr.bits.hi,
	); order != 0 {
		return order
	}
	if order := cmp.Compare(
		firstNetwork.addr.bits.lo,
		secondNetwork.addr.bits.lo,
	); order != 0 {
		return order
	}
	return cmp.Compare(
		firstNetwork.mask.bits.lo,
		secondNetwork.mask.bits.lo,
	)
}

// lowerBoundBiContiguous6HighMask finds the first value whose high mask is at
// least the target in a level-major sorted slice.
func lowerBoundBiContiguous6HighMask(nets []BiContiguous, target uint64) int {
	lower, upper := 0, len(nets)
	for lower < upper {
		middle := int(uint(lower+upper) >> 1)
		if nets[middle].network6.mask.bits.hi < target {
			lower = middle + 1
		} else {
			upper = middle
		}
	}
	return lower
}

// upperBoundBiContiguous6HighMask finds the first value whose high mask is
// greater than the target in a level-major sorted slice.
func upperBoundBiContiguous6HighMask(nets []BiContiguous, target uint64) int {
	lower, upper := 0, len(nets)
	for lower < upper {
		middle := int(uint(lower+upper) >> 1)
		if nets[middle].network6.mask.bits.hi <= target {
			lower = middle + 1
		} else {
			upper = middle
		}
	}
	return lower
}

// aggregateBiContiguous6LowRows reduces each exact-high run to its canonical
// minimal low-half CIDR cover and compacts survivors to the block front.
func aggregateBiContiguous6LowRows(
	nets []BiContiguous,
	blockStart int,
	blockEnd int,
) int {
	write := blockStart
	for runStart := blockStart; runStart < blockEnd; {
		runHighAddr := nets[runStart].network6.addr.bits.hi
		runEnd := runStart + 1
		for runEnd < blockEnd &&
			nets[runEnd].network6.addr.bits.hi == runHighAddr {
			runEnd++
		}

		stackBase := write
		current := nets[runStart].network6
		nets[write] = BiContiguous{network6: current}
		write++
		for read := runStart + 1; read < runEnd; read++ {
			current = nets[read].network6
			for write > stackBase {
				merged, ok := nets[write-1].network6.MergeByLowestMaskBit(current)
				if !ok {
					break
				}
				current = merged
				write--
			}
			// A shared high row limits every successful boundary merge to
			// the low run, so the result keeps the wrapper proof.
			nets[write] = BiContiguous{network6: current}
			write++
		}
		runStart = runEnd
	}
	return write
}

// mergeBiContiguous6HighBuddies reparents lower high-half buddies whose
// canonical low rows equal their upper buddies and drops the upper rows.
func mergeBiContiguous6HighBuddies(
	nets []BiContiguous,
	blockStart int,
	blockEnd int,
	highPrefix int,
) int {
	buddyBit := uint64(1) << (64 - highPrefix)
	newHighMask := biContiguousHalfPrefixMask(highPrefix - 1)
	write := blockStart
	for runStart := blockStart; runStart < blockEnd; {
		lowerHighAddr := nets[runStart].network6.addr.bits.hi
		lowerEnd := runStart + 1
		for lowerEnd < blockEnd &&
			nets[lowerEnd].network6.addr.bits.hi == lowerHighAddr {
			lowerEnd++
		}

		mergedRows := false
		if lowerEnd < blockEnd && lowerHighAddr&buddyBit == 0 {
			upperHighAddr := nets[lowerEnd].network6.addr.bits.hi
			if upperHighAddr == lowerHighAddr|buddyBit {
				upperEnd := lowerEnd + 1
				for upperEnd < blockEnd &&
					nets[upperEnd].network6.addr.bits.hi == upperHighAddr {
					upperEnd++
				}
				if equalBiContiguous6LowRows(
					nets,
					runStart,
					lowerEnd,
					lowerEnd,
					upperEnd,
				) {
					for read := runStart; read < lowerEnd; read++ {
						network := nets[read].network6
						network.mask.bits.hi = newHighMask
						// The lower buddy has the cleared boundary bit, so
						// widening the high mask leaves its address normalized.
						nets[write] = BiContiguous{network6: network}
						write++
					}
					runStart = upperEnd
					mergedRows = true
				}
			}
		}
		if mergedRows {
			continue
		}
		for read := runStart; read < lowerEnd; read++ {
			nets[write] = nets[read]
			write++
		}
		runStart = lowerEnd
	}
	return write
}

// equalBiContiguous6LowRows compares canonical low rows element by element.
func equalBiContiguous6LowRows(
	nets []BiContiguous,
	firstStart int,
	firstEnd int,
	secondStart int,
	secondEnd int,
) bool {
	if firstEnd-firstStart != secondEnd-secondStart {
		return false
	}
	for offset := range firstEnd - firstStart {
		first := nets[firstStart+offset].network6
		second := nets[secondStart+offset].network6
		if first.addr.bits.lo != second.addr.bits.lo ||
			first.mask.bits.lo != second.mask.bits.lo {
			return false
		}
	}
	return true
}

// biContiguousHalfPrefixMask returns one 64-bit leading-one run for lengths
// zero through 64, including both shift boundaries.
func biContiguousHalfPrefixMask(prefix int) uint64 {
	return ^(^uint64(0) >> uint(prefix))
}

// removeBiContiguous6Containment drops strict cross-shape descendants and
// leaves the survivor prefix sorted by numeric mask and address.
func removeBiContiguous6Containment(nets []BiContiguous) int {
	if len(nets) <= 1 {
		return len(nets)
	}
	slices.SortFunc(nets, compareBiContiguous6MaskAddress)
	return probeBiContiguous6Containment(nets)
}

// compareBiContiguous6MaskAddress implements the output's numeric tuple key.
func compareBiContiguous6MaskAddress(first, second BiContiguous) int {
	if order := first.network6.mask.bits.Compare(
		second.network6.mask.bits,
	); order != 0 {
		return order
	}
	return first.network6.addr.bits.Compare(second.network6.addr.bits)
}

// probeBiContiguous6Containment searches only present strict ancestor shapes
// and compacts uncontained values without heap-backed indexes.
func probeBiContiguous6Containment(nets []BiContiguous) int {
	var lowPrefixesByHighPrefix [65]uint128
	var highPrefixesPresent uint128
	for _, block := range nets {
		highPrefix := block.HighPrefixLen()
		lowPrefix := block.LowPrefixLen()
		lowPrefixesByHighPrefix[highPrefix] = lowPrefixesByHighPrefix[highPrefix].Or(uint128Bit(lowPrefix))
		highPrefixesPresent = highPrefixesPresent.Or(uint128Bit(highPrefix))
	}

	kept := 0
	for chunkStart := 0; chunkStart < len(nets); {
		chunkMask := nets[chunkStart].network6.mask.bits
		chunkHighPrefix := nets[chunkStart].HighPrefixLen()
		chunkLowPrefix := nets[chunkStart].LowPrefixLen()
		chunkEnd := chunkStart + 1
		for chunkEnd < len(nets) && chunkEnd-chunkStart < 64 &&
			nets[chunkEnd].network6.mask.bits == chunkMask {
			chunkEnd++
		}

		chunkLength := chunkEnd - chunkStart
		allDropped := ^uint64(0)
		if chunkLength < 64 {
			allDropped = uint64(1)<<chunkLength - 1
		}
		dropped := uint64(0)
		var chunkAddresses [64]uint128
		for offset := range chunkLength {
			chunkAddresses[offset] = nets[chunkStart+offset].network6.addr.bits
		}

		eligibleHighPrefixes := highPrefixesPresent.And(
			uint128Bit(chunkHighPrefix).SubOne(),
		)
		ancestorSearchStart := 0
		for !eligibleHighPrefixes.IsZero() && dropped != allDropped {
			ancestorHighPrefix := eligibleHighPrefixes.TrailingZeros()
			eligibleHighPrefixes = eligibleHighPrefixes.ClearLowestSetBit()
			eligibleLowPrefixes := lowPrefixesByHighPrefix[ancestorHighPrefix]
			if chunkLowPrefix < 64 {
				eligibleLowPrefixes = eligibleLowPrefixes.And(
					uint128Bit(chunkLowPrefix + 1).SubOne(),
				)
			}
			for !eligibleLowPrefixes.IsZero() && dropped != allDropped {
				ancestorLowPrefix := eligibleLowPrefixes.TrailingZeros()
				eligibleLowPrefixes = eligibleLowPrefixes.ClearLowestSetBit()
				ancestorMask := uint128FromHalves(
					biContiguousHalfPrefixMask(ancestorHighPrefix),
					biContiguousHalfPrefixMask(ancestorLowPrefix),
				)

				runStart := lowerBoundBiContiguous6Mask(
					nets,
					ancestorSearchStart,
					kept,
					ancestorMask,
				)
				runEnd := upperBoundBiContiguous6Mask(
					nets,
					runStart,
					kept,
					ancestorMask,
				)
				ancestorSearchStart = runEnd
				if runStart == runEnd {
					continue
				}
				for offset := range chunkLength {
					bit := uint64(1) << offset
					if dropped&bit != 0 {
						continue
					}
					target := chunkAddresses[offset].And(ancestorMask)
					if containsBiContiguous6Address(
						nets,
						runStart,
						runEnd,
						target,
					) {
						dropped |= bit
					}
				}
			}
		}

		for read := chunkStart; read < chunkEnd; read++ {
			if dropped&(uint64(1)<<uint(read-chunkStart)) == 0 {
				nets[kept], nets[read] = nets[read], nets[kept]
				kept++
			}
		}
		chunkStart = chunkEnd
	}
	return kept
}

// lowerBoundBiContiguous6Mask finds the first numeric mask not below target in
// a bounded section of the mask-address sorted survivor prefix.
func lowerBoundBiContiguous6Mask(
	nets []BiContiguous,
	lower int,
	upper int,
	target uint128,
) int {
	for lower < upper {
		middle := int(uint(lower+upper) >> 1)
		if nets[middle].network6.mask.bits.Compare(target) < 0 {
			lower = middle + 1
		} else {
			upper = middle
		}
	}
	return lower
}

// upperBoundBiContiguous6Mask finds the first numeric mask above target in a
// bounded section of the mask-address sorted survivor prefix.
func upperBoundBiContiguous6Mask(
	nets []BiContiguous,
	lower int,
	upper int,
	target uint128,
) int {
	for lower < upper {
		middle := int(uint(lower+upper) >> 1)
		if nets[middle].network6.mask.bits.Compare(target) <= 0 {
			lower = middle + 1
		} else {
			upper = middle
		}
	}
	return lower
}

// containsBiContiguous6Address binary-searches one exact-mask run for a
// normalized ancestor address.
func containsBiContiguous6Address(
	nets []BiContiguous,
	lower int,
	upper int,
	target uint128,
) bool {
	for lower < upper {
		middle := int(uint(lower+upper) >> 1)
		order := nets[middle].network6.addr.bits.Compare(target)
		if order < 0 {
			lower = middle + 1
		} else if order > 0 {
			upper = middle
		} else {
			return true
		}
	}
	return false
}
