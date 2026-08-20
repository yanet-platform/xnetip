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
