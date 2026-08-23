package xnetip

import (
	"iter"
	"math/bits"
	"net/netip"
)

// BiContiguous is an IPv6 network whose two 64-bit mask halves are
// independently contiguous.
//
// Each half is a leading run of one bits followed by zero bits. The
// zero value wraps ::/0 and is valid. Values are immutable, comparable
// with == exactly when their wrapped networks are, and safe to copy.
// The unexported field prevents construction without validating or
// otherwise proving the mask shape.
type BiContiguous struct {
	// Distinct field identity prevents structural conversion of this
	// two-run wrapper into the stricter CIDR wrapper.
	network6 Network6
}

// halfPrefixMask returns a leading-one mask for lengths zero through 64.
func halfPrefixMask(prefix int) uint64 {
	return ^uint64(0) << (64 - prefix)
}

// ParseBiContiguous parses an IPv6 network whose two mask halves are
// independently contiguous.
//
// The grammar and ordinary parse errors are exactly ParseNetwork6's.
// A valid network whose mask has an interior hole in either 64-bit
// half instead wraps ErrNonBiContiguousMask under this function's
// name.
func ParseBiContiguous(s string) (BiContiguous, error) {
	network, err := ParseNetwork6(s)
	if err != nil {
		return BiContiguous{}, err
	}
	if !network.IsBicontiguous() {
		return BiContiguous{}, wrapParseError(
			"ParseBiContiguous",
			s,
			ErrNonBiContiguousMask,
			nil,
		)
	}
	return BiContiguous{network6: network}, nil
}

// MustParseBiContiguous calls ParseBiContiguous and panics on error.
//
// It is intended for tests and package-level constants built from
// literals.
func MustParseBiContiguous(s string) BiContiguous {
	network, err := ParseBiContiguous(s)
	if err != nil {
		panic(err)
	}
	return network
}

// BiContiguousFrom returns the normalized bi-contiguous network
// with the given IPv6 address and mask.
//
// Both arguments must be Is6 addresses. IPv4-mapped IPv6 is accepted
// and zones are dropped silently. An Is4 or invalid zero address wraps
// ErrAddrFamilyMismatch. A valid mask whose 64-bit halves are not each
// leading runs of ones wraps ErrNonBiContiguousMask. The zero wrapper is
// returned on every error.
func BiContiguousFrom(addr, mask netip.Addr) (BiContiguous, error) {
	addrKernel, addrOk := addr6FromNetip(addr)
	maskKernel, maskOk := addr6FromNetip(mask)
	if !addrOk || !maskOk {
		input := addr.String() + "/" + mask.String()
		return BiContiguous{}, wrapParseError(
			"BiContiguousFrom",
			input,
			ErrAddrFamilyMismatch,
			nil,
		)
	}

	network := fromBits6(addrKernel, maskKernel)
	wrapper, ok := BiContiguousFrom6(network)
	if !ok {
		input := addr.String() + "/" + mask.String()
		return BiContiguous{}, wrapParseError(
			"BiContiguousFrom",
			input,
			ErrNonBiContiguousMask,
			nil,
		)
	}
	return wrapper, nil
}

// BiContiguousFrom6 returns network with its bi-contiguity guarantee
// carried by the result type.
//
// ok is false when either 64-bit mask half is not a leading run of
// ones, and the zero wrapper is returned. The network is otherwise
// carried unchanged.
func BiContiguousFrom6(network Network6) (BiContiguous, bool) {
	if !network.IsBicontiguous() {
		return BiContiguous{}, false
	}
	return BiContiguous{network6: network}, true
}

// BiContiguousFromContiguous upgrades an IPv6 CIDR block to the
// broader bi-contiguous class without validation.
//
// Every global leading run is independently a leading run in both
// 64-bit halves, so the conversion is total and carries the wrapped
// network unchanged.
func BiContiguousFromContiguous(block Contiguous[Network6]) BiContiguous {
	return BiContiguous{network6: block.network}
}

// Network returns the wrapped IPv6 network.
//
// It is total: the wrapper adds only the per-half mask guarantee, and
// operations without a guarantee-bearing result are reached through
// this view.
func (m BiContiguous) Network() Network6 {
	return m.network6
}

// HighPrefixLen returns the leading-one length of the high 64-bit
// mask half.
//
// The result is total and ranges from zero through 64. The zero wrapper
// reports zero.
func (m BiContiguous) HighPrefixLen() int {
	return bits.LeadingZeros64(^m.network6.mask.bits.hi)
}

// LowPrefixLen returns the leading-one length of the low 64-bit
// mask half.
//
// The result is total and ranges from zero through 64. The zero wrapper
// reports zero.
func (m BiContiguous) LowPrefixLen() int {
	return bits.LeadingZeros64(^m.network6.mask.bits.lo)
}

// Compare returns -1, 0 or +1 as m sorts before, equal to or after
// other in the wrapped network order.
func (m BiContiguous) Compare(other BiContiguous) int {
	return m.network6.Compare(other.network6)
}

// Contains reports whether every address of other is also an address
// of m.
//
// Each mask half is a leading run of ones, so a receiver half constrains
// a subset of the other's bits exactly when its unsigned mask word is no
// greater. Checking both halves replaces the general whole-mask subset AND;
// normalized addresses still must agree on every receiver-constrained bit.
func (m BiContiguous) Contains(other BiContiguous) bool {
	receiverMask := m.network6.mask.bits
	otherMask := other.network6.mask.bits
	if receiverMask.hi <= otherMask.hi && receiverMask.lo <= otherMask.lo {
		receiverAddr := m.network6.addr.bits
		maskedOtherAddr := other.network6.addr.bits.And(receiverMask)
		if maskedOtherAddr.hi == receiverAddr.hi {
			return maskedOtherAddr.lo == receiverAddr.lo
		}
	}
	return false
}

// Intersection returns the bi-contiguous network common to m and other,
// or false when they are disjoint.
//
// The mask union takes the longer leading run independently in each
// 64-bit half, so the result stays bi-contiguous and needs no
// revalidation. On false the first result is the zero wrapper.
func (m BiContiguous) Intersection(other BiContiguous) (BiContiguous, bool) {
	intersected, ok := m.network6.Intersection(other.network6)
	if !ok {
		return BiContiguous{}, false
	}
	// The mask OR keeps a leading run in each half and therefore
	// wraps without revalidation.
	return BiContiguous{network6: intersected}, true
}

// MergeByLowestMaskBit merges containment or lowest-mask-bit siblings
// while preserving bi-contiguity.
//
// Containment returns an input unchanged. A sibling merge clears the
// low run's boundary bit when that run is nonempty, or the high run's
// boundary bit otherwise, so every successful result remains in the
// class. On false the first result is the zero wrapper.
func (m BiContiguous) MergeByLowestMaskBit(other BiContiguous) (BiContiguous, bool) {
	merged, ok := m.network6.MergeByLowestMaskBit(other.network6)
	if !ok {
		return BiContiguous{}, false
	}
	// The result is either an unchanged input or has one bottommost
	// run shortened by one bit, so it wraps without revalidation.
	return BiContiguous{network6: merged}, true
}

// Difference returns the bi-contiguous networks whose union is m
// without other.
//
// A disjoint other yields m once, while a containing other yields
// nothing. On overlap, pairwise-disjoint parts are yielded from the
// most significant pending mask bit: the high-half prefix extension
// first, then the low-half extension. The part count is the sum of
// those extension lengths. Each step lengthens one leading run, so
// every part stays bi-contiguous. The sequence is allocation-free and
// re-iterable.
func (m BiContiguous) Difference(other BiContiguous) iter.Seq[BiContiguous] {
	return func(yield func(BiContiguous) bool) {
		for part := range m.network6.Difference(other.network6) {
			// Each peeled mask advances a per-half leading run, so it
			// wraps without revalidation.
			if !yield(BiContiguous{network6: part}) {
				return
			}
		}
	}
}

// Addrs returns every address in row-major host-index order.
//
// The low half's host counter cycles fastest and carries into the high
// half after its trailing host run is exhausted. The order, membership
// and count are exactly those of the wrapped network's Addrs sequence.
// Every yielded address is an Is6 netip.Addr, zone-free. The sequence is
// re-iterable, allocation-free and stops early when the consumer breaks.
func (m BiContiguous) Addrs() iter.Seq[netip.Addr] {
	return func(yield func(netip.Addr) bool) {
		base := m.network6.addr.bits
		mask := m.network6.mask.bits
		lastHigh := ^mask.hi
		lastLow := ^mask.lo
		if lastHigh == 0 {
			for hostLow := uint64(0); ; hostLow++ {
				if !yield(addr6FromBits(base.hi, base.lo|hostLow).Netip()) ||
					hostLow == lastLow {
					return
				}
			}
		}
		if lastLow == 0 {
			for hostHigh := uint64(0); ; hostHigh++ {
				if !yield(addr6FromBits(base.hi|hostHigh, base.lo).Netip()) ||
					hostHigh == lastHigh {
					return
				}
			}
		}
		var hostHigh, hostLow uint64
		for {
			if !yield(addr6FromBits(base.hi|hostHigh, base.lo|hostLow).Netip()) {
				return
			}
			if hostLow != lastLow {
				hostLow++
				continue
			}
			if hostHigh == lastHigh {
				return
			}
			hostLow = 0
			hostHigh++
		}
	}
}

// String returns the canonical text form of the bi-contiguous network.
//
// The format is exactly the wrapped IPv6 network's: a globally contiguous
// mask uses a prefix length, while a genuine two-run mask is written as a
// compressed IPv6 address. The output parses back with ParseBiContiguous.
func (m BiContiguous) String() string {
	// The buffer covers the longest address-plus-mask form, so the string
	// conversion is the only allocation.
	var buffer [maxNetworkTextLen]byte
	return string(m.AppendTo(buffer[:0]))
}

// AppendTo appends the canonical text form to b.
//
// The format is exactly the wrapped IPv6 network's, including its choice
// between a decimal prefix length and an explicit compressed mask.
func (m BiContiguous) AppendTo(b []byte) []byte {
	return m.network6.AppendTo(b)
}

// MarshalText implements encoding.TextMarshaler.
//
// The text is the String form of the bi-contiguous network. It never fails
// and allocates only the returned slice.
func (m BiContiguous) MarshalText() ([]byte, error) {
	return m.AppendTo(make([]byte, 0, maxNetworkTextLen)), nil
}

// UnmarshalText implements encoding.TextUnmarshaler.
//
// The text must be accepted by ParseBiContiguous. Empty text wraps
// ErrEmptyInput because the zero wrapper is a valid block. The receiver is
// untouched on every error.
func (m *BiContiguous) UnmarshalText(text []byte) error {
	if len(text) == 0 {
		return wrapParseError("BiContiguous.UnmarshalText", "", ErrEmptyInput, nil)
	}
	wrapper, err := ParseBiContiguous(string(text))
	if err != nil {
		return err
	}
	*m = wrapper
	return nil
}
