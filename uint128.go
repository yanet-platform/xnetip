package xnetip

import (
	"encoding/binary"
	"math/bits"
)

// uint128 is an unsigned 128-bit integer stored as two host-order
// 64-bit halves, the same layout net/netip uses internally.
//
// It is the word type of every IPv6 bit operation in the package:
// addresses and masks are uint128 values and the algorithms written
// for IPv4 on uint32 are written for IPv6 on this type with the same
// control flow. The zero value is the number zero.
type uint128 struct {
	hi uint64
	lo uint64
}

// uint128From16 converts a big-endian 16-byte array to a uint128.
//
// The first eight bytes form the high half and the last eight the low
// half, most significant byte first — the byte layout of an IPv6
// address, so an address converts without reordering.
func uint128From16(b [16]byte) uint128 {
	return uint128{binary.BigEndian.Uint64(b[:8]), binary.BigEndian.Uint64(b[8:])}
}

// As16 converts the value back to its big-endian 16-byte form.
func (m uint128) As16() [16]byte {
	var b [16]byte
	binary.BigEndian.PutUint64(b[:8], m.hi)
	binary.BigEndian.PutUint64(b[8:], m.lo)
	return b
}

// And returns the bitwise AND of the two values.
func (m uint128) And(other uint128) uint128 {
	return uint128{m.hi & other.hi, m.lo & other.lo}
}

// Or returns the bitwise OR of the two values.
func (m uint128) Or(other uint128) uint128 {
	return uint128{m.hi | other.hi, m.lo | other.lo}
}

// Xor returns the bitwise XOR of the two values.
func (m uint128) Xor(other uint128) uint128 {
	return uint128{m.hi ^ other.hi, m.lo ^ other.lo}
}

// Not returns the bitwise complement of the value.
func (m uint128) Not() uint128 {
	return uint128{^m.hi, ^m.lo}
}

// AndNot returns the receiver with the argument's bits cleared (m &^ other).
func (m uint128) AndNot(other uint128) uint128 {
	return uint128{m.hi &^ other.hi, m.lo &^ other.lo}
}

// IsZero reports whether the value is zero.
func (m uint128) IsZero() bool {
	return m.hi|m.lo == 0
}

// IsMax reports whether every bit is set.
func (m uint128) IsMax() bool {
	return m.hi&m.lo == ^uint64(0)
}

// Compare returns -1, 0 or +1 ordering the values as unsigned integers.
//
// The high half decides and the low half breaks a tie, which is the
// numeric order of the 128-bit value and equals the lexicographic order
// of the big-endian byte form. It is the order the IPv6 network
// comparison relies on (../netip/src/net.rs:3736).
func (m uint128) Compare(other uint128) int {
	switch {
	case m.hi < other.hi || m.hi == other.hi && m.lo < other.lo:
		return -1
	case m == other:
		return 0
	default:
		return 1
	}
}

// Add returns the sum of the two values modulo 2^128.
func (m uint128) Add(other uint128) uint128 {
	lo, carry := bits.Add64(m.lo, other.lo, 0)
	hi, _ := bits.Add64(m.hi, other.hi, carry)
	return uint128{hi, lo}
}

// Sub returns the difference of the two values modulo 2^128.
func (m uint128) Sub(other uint128) uint128 {
	lo, borrow := bits.Sub64(m.lo, other.lo, 0)
	hi, _ := bits.Sub64(m.hi, other.hi, borrow)
	return uint128{hi, lo}
}

// AddOne returns the value plus one modulo 2^128.
func (m uint128) AddOne() uint128 {
	lo, carry := bits.Add64(m.lo, 1, 0)
	return uint128{m.hi + carry, lo}
}

// SubOne returns the value minus one modulo 2^128.
func (m uint128) SubOne() uint128 {
	lo, borrow := bits.Sub64(m.lo, 1, 0)
	return uint128{m.hi - borrow, lo}
}

// Neg returns the two's complement of the value, its negation modulo 2^128.
//
// A value and-ed with its negation keeps exactly its lowest set bit,
// which is how the difference peel and the range decomposition find
// their next block (../netip/src/net.rs:3918, ../netip/src/net.rs:4178).
func (m uint128) Neg() uint128 {
	return uint128{}.Sub(m)
}

// Shl returns the value shifted left by n bits, for n in 0 through 128.
//
// Bits shifted past the top are lost. A count of 64 or more moves the
// low half into the high half, a count of 128 or more yields zero, so
// the shift is total over the counts the prefix arithmetic produces (a
// mask from a prefix length of 0 or 128, a block from a leading-zero
// count), where the Rust reference guards with a checked shift.
func (m uint128) Shl(n uint) uint128 {
	switch {
	case n == 0:
		return m
	case n < 64:
		return uint128{m.hi<<n | m.lo>>(64-n), m.lo << n}
	case n < 128:
		return uint128{m.lo << (n - 64), 0}
	default:
		return uint128{}
	}
}

// Shr returns the value shifted right by n bits, for n in 0 through 128.
//
// It mirrors Shl: bits shifted past the bottom are lost, a count of 64
// or more moves the high half into the low half and a count of 128 or
// more yields zero.
func (m uint128) Shr(n uint) uint128 {
	switch {
	case n == 0:
		return m
	case n < 64:
		return uint128{m.hi >> n, m.lo>>n | m.hi<<(64-n)}
	case n < 128:
		return uint128{0, m.hi >> (n - 64)}
	default:
		return uint128{}
	}
}

// uint128FromUint64 widens a 64-bit value into the low half.
func uint128FromUint64(value uint64) uint128 {
	return uint128{0, value}
}

// uint128FromHalves assembles a value from its high and low halves.
func uint128FromHalves(hi, lo uint64) uint128 {
	return uint128{hi, lo}
}

// LeadingZeros returns the number of leading zero bits, 128 for zero.
func (m uint128) LeadingZeros() int {
	if m.hi != 0 {
		return bits.LeadingZeros64(m.hi)
	}
	return 64 + bits.LeadingZeros64(m.lo)
}

// LeadingOnes returns the length of the leading run of one bits, 128
// for the all-ones value.
func (m uint128) LeadingOnes() int {
	return m.Not().LeadingZeros()
}

// TrailingZeros returns the number of trailing zero bits, 128 for zero.
func (m uint128) TrailingZeros() int {
	if m.lo != 0 {
		return bits.TrailingZeros64(m.lo)
	}
	return 64 + bits.TrailingZeros64(m.hi)
}

// OnesCount returns the population count.
func (m uint128) OnesCount() int {
	return bits.OnesCount64(m.hi) + bits.OnesCount64(m.lo)
}

// LowestSetBit returns the value with only the lowest set bit kept
// (m & -m), zero for zero.
func (m uint128) LowestSetBit() uint128 {
	return m.And(m.Neg())
}

// ClearLowestSetBit returns m with its lowest set bit cleared
// (m & (m - 1)), zero for zero.
func (m uint128) ClearLowestSetBit() uint128 {
	return m.And(m.SubOne())
}

// IsPowerOfTwo reports whether exactly one bit is set.
func (m uint128) IsPowerOfTwo() bool {
	return !m.IsZero() && m.ClearLowestSetBit().IsZero()
}

// uint128Bit returns the value with only bit n set, for n in 0 through
// 127.
//
// Bits are numbered from the least significant one, the way a left shift
// of one counts them: bit 0 is the last bit of an IPv6 address and bit
// 127 its first. That is the opposite of the top-down numbering IPv6
// prose uses, so a caller holding a leading-zero count passes 127 minus
// that count to name the highest set bit (../netip/src/net.rs:4154).
func uint128Bit(n int) uint128 {
	return uint128{0, 1}.Shl(uint(n))
}

// uint128MaskFromPrefix returns the mask whose top bits are ones and the
// rest zero, for bits in 0 through 128.
//
// Callers validate the range: the public constructors and the parser
// reject longer prefixes with an error, this helper is only ever called
// with a length a contiguous mask can have. The mask is the complement
// of all ones shifted right by the length, so 0 yields the empty mask,
// 64 exactly the high half and 128 all ones without a special case
// (../netip/src/net.rs:68).
func uint128MaskFromPrefix(bits int) uint128 {
	return uint128{^uint64(0), ^uint64(0)}.Shr(uint(bits)).Not()
}

// IsContiguousMask reports whether the value is a run of leading ones
// followed by zeros, including all-zero and all-ones.
//
// Subtracting one flips the lowest set bit and sets every bit below it,
// so the or with the predecessor fills exactly the bits below the lowest
// one. The result is all ones only if every bit above that one was
// already set, which is the leading-run shape. Zero has no lowest set
// bit to flip, its predecessor wraps to all ones and the empty mask of
// the whole address space counts as contiguous, as it must
// (../netip/src/net.rs:2965).
func (m uint128) IsContiguousMask() bool {
	return m.Or(m.SubOne()).IsMax()
}
