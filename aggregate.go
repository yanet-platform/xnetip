package xnetip

import "slices"

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
