package xnetip

import (
	"math/bits"
	"slices"
)

// IndexRange identifies a half-open interval of slice indices.
//
// Start is inclusive and End is exclusive. A successful binary split
// returns the indices of exactly the networks its candidate contains.
type IndexRange struct {
	// Start is the first index in the selected interval.
	Start int
	// End is the first index after the selected interval.
	End int
}

// BinarySplit4 selects a narrow supernet and gathers its members in place.
//
// The projection must consistently return each element's network. Inputs
// must be sorted by [Network4.Compare] through that projection. Candidates
// are the common supernet of the full slice followed by every window of
// ceil(N/2) elements. The first candidate with the largest numeric mask wins,
// including when that mask is non-contiguous.
//
// The selected interval starts at the first contained element's original
// index and contains exactly all elements covered by the candidate, at least
// half the input. Both contained and remaining elements retain their relative
// order and payloads. Fewer than three elements or a nil projection return
// false without mutation. Search takes O(N) time, gathering O(N log N) moves
// and O(log N) stack space. No memory is allocated.
func BinarySplit4[T any](networks []T, network func(T) Network4) (Network4, IndexRange, bool) {
	if len(networks) < 3 || network == nil {
		return Network4{}, IndexRange{}, false
	}
	candidate := binarySplitCandidate4(networks, network)
	start := 0
	for start < len(networks) && !candidate.Contains(network(networks[start])) {
		start++
	}
	if start == len(networks) {
		return Network4{}, IndexRange{}, false
	}
	count := stableSplitPartition(networks[start:], func(element T) bool {
		return candidate.Contains(network(element))
	})
	return candidate, IndexRange{Start: start, End: start + count}, true
}

// binarySplitCandidate4 keeps the first widest mask among the defined windows.
func binarySplitCandidate4[T any](networks []T, network func(T) Network4) Network4 {
	length := len(networks)
	width := length/2 + length%2
	killWord := func(idx int) uint32 {
		left, right := network(networks[idx]), network(networks[idx+1])
		return ^left.mask.bits | (left.addr.bits ^ right.addr.bits)
	}
	var counters [32]int
	windowOR, fullOR := uint32(0), uint32(0)
	// A common supernet leaves a bit free if any mask leaves it free
	// or if consecutive addresses disagree on it.
	//
	// Per-bit counts preserve that exact condition as the window slides.
	for idx := range length - 1 {
		kill := killWord(idx)
		fullOR |= kill
		if idx < width-1 {
			addSplitKill4(&windowOR, &counters, kill)
		}
	}
	last := network(networks[length-1])
	first := network(networks[0])
	bestAddress, bestMask := first.addr.bits, ^fullOR&last.mask.bits
	for idx := range length - width + 1 {
		if idx > 0 {
			removeSplitKill4(&windowOR, &counters, killWord(idx-1))
			addSplitKill4(&windowOR, &counters, killWord(idx+width-2))
		}
		end := network(networks[idx+width-1])
		windowMask := ^windowOR & end.mask.bits
		if windowMask > bestMask {
			first := network(networks[idx])
			bestAddress, bestMask = first.addr.bits, windowMask
		}
	}
	return fromBits4(addr4FromBits(bestAddress), addr4FromBits(bestMask))
}

// addSplitKill4 records the newly unconstrained bits of one adjacent pair.
func addSplitKill4(windowOR *uint32, counters *[32]int, kill uint32) {
	*windowOR |= kill
	for kill != 0 {
		bit := bits.TrailingZeros32(kill)
		counters[bit]++
		kill &= kill - 1
	}
}

// removeSplitKill4 expires constraints without clearing still-referenced bits.
func removeSplitKill4(windowOR *uint32, counters *[32]int, kill uint32) {
	for kill != 0 {
		bit := bits.TrailingZeros32(kill)
		counters[bit]--
		if counters[bit] == 0 {
			*windowOR &^= uint32(1) << bit
		}
		kill &= kill - 1
	}
}

// stableSplitPartition gathers accepted elements while preserving both orders.
//
// Each half is partitioned recursively. Rotating the left rejects past
// the right accepts joins the two accepted groups without scratch memory.
func stableSplitPartition[T any](elements []T, accepted func(T) bool) int {
	switch len(elements) {
	case 0:
		return 0
	case 1:
		if accepted(elements[0]) {
			return 1
		}
		return 0
	default:
		middle := len(elements) / 2
		left := stableSplitPartition(elements[:middle], accepted)
		right := stableSplitPartition(elements[middle:], accepted)
		if left < middle && right > 0 {
			slices.Reverse(elements[left:middle])
			slices.Reverse(elements[middle : middle+right])
			slices.Reverse(elements[left : middle+right])
		}
		return left + right
	}
}

// BinarySplit6 selects a narrow supernet and gathers its members in place.
//
// The projection must consistently return each element's network. Inputs
// must be sorted by [Network6.Compare] through that projection. Candidates
// are the common supernet of the full slice followed by every window of
// ceil(N/2) elements. The first candidate with the largest numeric mask wins,
// including when that mask is non-contiguous.
//
// The selected interval starts at the first contained element's original
// index and contains exactly all elements covered by the candidate, at least
// half the input. Both contained and remaining elements retain their relative
// order and payloads. Fewer than three elements or a nil projection return
// false without mutation. Search takes O(N) time, gathering O(N log N) moves
// and O(log N) stack space. No memory is allocated.
func BinarySplit6[T any](networks []T, network func(T) Network6) (Network6, IndexRange, bool) {
	if len(networks) < 3 || network == nil {
		return Network6{}, IndexRange{}, false
	}
	candidate := binarySplitCandidate6(networks, network)
	start := 0
	for start < len(networks) && !candidate.Contains(network(networks[start])) {
		start++
	}
	if start == len(networks) {
		return Network6{}, IndexRange{}, false
	}
	count := stableSplitPartition(networks[start:], func(element T) bool {
		return candidate.Contains(network(element))
	})
	return candidate, IndexRange{Start: start, End: start + count}, true
}

// binarySplitCandidate6 keeps the first widest mask among the defined windows.
func binarySplitCandidate6[T any](networks []T, network func(T) Network6) Network6 {
	length := len(networks)
	width := length/2 + length%2
	killWord := func(idx int) uint128 {
		left, right := network(networks[idx]), network(networks[idx+1])
		return left.mask.bits.Not().Or(left.addr.bits.Xor(right.addr.bits))
	}
	var counters [128]int
	windowOR, fullOR := uint128{}, uint128{}
	// A common supernet leaves a bit free if any mask leaves it free
	// or if consecutive addresses disagree on it.
	//
	// Per-bit counts preserve that exact condition as the window slides.
	for idx := range length - 1 {
		kill := killWord(idx)
		fullOR = fullOR.Or(kill)
		if idx < width-1 {
			addSplitKill6(&windowOR, &counters, kill)
		}
	}
	last := network(networks[length-1])
	first := network(networks[0])
	bestAddress, bestMask := first.addr.bits, fullOR.Not().And(last.mask.bits)
	for idx := range length - width + 1 {
		if idx > 0 {
			removeSplitKill6(&windowOR, &counters, killWord(idx-1))
			addSplitKill6(&windowOR, &counters, killWord(idx+width-2))
		}
		end := network(networks[idx+width-1])
		windowMask := windowOR.Not().And(end.mask.bits)
		if windowMask.Compare(bestMask) > 0 {
			first := network(networks[idx])
			bestAddress, bestMask = first.addr.bits, windowMask
		}
	}
	return fromBits6(addr6{bestAddress}, addr6{bestMask})
}

// addSplitKill6 records the newly unconstrained bits of one adjacent pair.
func addSplitKill6(windowOR *uint128, counters *[128]int, kill uint128) {
	*windowOR = windowOR.Or(kill)
	for !kill.IsZero() {
		bit := kill.TrailingZeros()
		counters[bit]++
		kill = kill.ClearLowestSetBit()
	}
}

// removeSplitKill6 expires constraints without clearing still-referenced bits.
func removeSplitKill6(windowOR *uint128, counters *[128]int, kill uint128) {
	for !kill.IsZero() {
		bit := kill.TrailingZeros()
		counters[bit]--
		if counters[bit] == 0 {
			*windowOR = windowOR.AndNot(uint128Bit(bit))
		}
		kill = kill.ClearLowestSetBit()
	}
}
