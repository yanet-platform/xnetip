package xnetip

import "encoding/binary"

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

// as16 converts the value back to its big-endian 16-byte form.
func (m uint128) as16() [16]byte {
	var b [16]byte
	binary.BigEndian.PutUint64(b[:8], m.hi)
	binary.BigEndian.PutUint64(b[8:], m.lo)
	return b
}

// and returns the bitwise AND of the two values.
func (m uint128) and(other uint128) uint128 {
	return uint128{m.hi & other.hi, m.lo & other.lo}
}

// or returns the bitwise OR of the two values.
func (m uint128) or(other uint128) uint128 {
	return uint128{m.hi | other.hi, m.lo | other.lo}
}

// xor returns the bitwise XOR of the two values.
func (m uint128) xor(other uint128) uint128 {
	return uint128{m.hi ^ other.hi, m.lo ^ other.lo}
}

// not returns the bitwise complement of the value.
func (m uint128) not() uint128 {
	return uint128{^m.hi, ^m.lo}
}

// andNot returns the receiver with the argument's bits cleared (m &^ other).
func (m uint128) andNot(other uint128) uint128 {
	return uint128{m.hi &^ other.hi, m.lo &^ other.lo}
}

// isZero reports whether the value is zero.
func (m uint128) isZero() bool {
	return m.hi|m.lo == 0
}

// isMax reports whether every bit is set.
func (m uint128) isMax() bool {
	return m.hi&m.lo == ^uint64(0)
}

// compare returns -1, 0 or +1 ordering the values as unsigned integers.
//
// The high half decides and the low half breaks a tie, which is the
// numeric order of the 128-bit value and equals the lexicographic order
// of the big-endian byte form. It is the order the IPv6 network
// comparison relies on (../netip/src/net.rs:3736).
func (m uint128) compare(other uint128) int {
	switch {
	case m.hi < other.hi || m.hi == other.hi && m.lo < other.lo:
		return -1
	case m == other:
		return 0
	default:
		return 1
	}
}
