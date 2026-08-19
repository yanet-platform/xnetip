package xnetip

import (
	"bytes"
	"math/big"
	"net/netip"
	"testing"

	"github.com/stretchr/testify/require"
	"pgregory.net/rapid"
)

// uint128Max is the all-ones value, the upper end of the value space.
//
// Runtime code spells the two extremes inline, as the zero value and the
// all-ones literal, so no runtime constant exists to share here.
var uint128Max = uint128{^uint64(0), ^uint64(0)}

// verifies that the byte conversions round-trip the two extremes of the
// value space.
func Test_Uint128_From16_RoundTripsExtremes(t *testing.T) {
	cases := []struct {
		name  string
		bytes [16]byte
		value uint128
	}{
		{name: "zero", bytes: [16]byte{}, value: uint128{}},
		{name: "all ones", bytes: [16]byte(bytes.Repeat([]byte{0xff}, 16)), value: uint128Max},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.value, uint128From16(tc.bytes))
			require.Equal(t, tc.bytes, tc.value.As16())
		})
	}
}

// verifies that the first eight bytes land in the high half and the last
// eight in the low half, most significant byte first.
func Test_Uint128_From16_PlacesBytesBigEndian(t *testing.T) {
	b := [16]byte{
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
	}
	value := uint128From16(b)
	require.Equal(t, uint128{0x0102030405060708, 0x090a0b0c0d0e0f10}, value)
	require.Equal(t, b, value.As16())
}

// verifies that the bitwise operators act per bit across both halves.
//
// Two values occupying disjoint halves have an empty intersection and
// fill the word under or and xor alike.
func Test_Uint128_Bitwise_DisjointHalves(t *testing.T) {
	high := uint128{^uint64(0), 0}
	low := uint128{0, ^uint64(0)}
	require.Equal(t, uint128{}, high.And(low))
	require.Equal(t, uint128Max, high.Or(low))
	require.Equal(t, uint128Max, high.Xor(low))
}

// verifies that not maps the two extremes onto each other.
func Test_Uint128_Not_SwapsExtremes(t *testing.T) {
	require.Equal(t, uint128Max, uint128{}.Not())
	require.Equal(t, uint128{}, uint128Max.Not())
}

// verifies that and-not clears exactly the bits of its argument and
// leaves every other bit, including those of the other half, set.
func Test_Uint128_AndNot_ClearsOnlyGivenBits(t *testing.T) {
	require.Equal(t, uint128{^uint64(0), ^uint64(0) - 1}, uint128Max.AndNot(uint128{0, 1}))
}

// verifies that the zero predicate holds for the zero value only and
// sees a bit set in either half.
func Test_Uint128_IsZero_TrueOnlyOnZero(t *testing.T) {
	cases := []struct {
		name  string
		value uint128
		want  bool
	}{
		{name: "zero", value: uint128{}, want: true},
		{name: "bit set in the low half", value: uint128{0, 1}, want: false},
		{name: "bit set in the high half", value: uint128{1, 0}, want: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.want, tc.value.IsZero())
		})
	}
}

// verifies that the all-ones predicate holds for the all-ones value only
// and sees a bit cleared in either half.
func Test_Uint128_IsMax_TrueOnlyOnMax(t *testing.T) {
	cases := []struct {
		name  string
		value uint128
		want  bool
	}{
		{name: "all ones", value: uint128Max, want: true},
		{name: "bit cleared in the low half", value: uint128{^uint64(0), ^uint64(0) - 1}, want: false},
		{name: "bit cleared in the high half", value: uint128{^uint64(0) - 1, ^uint64(0)}, want: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.want, tc.value.IsMax())
		})
	}
}

// verifies that compare orders values as unsigned integers.
//
// The high half decides first, the low half only on a tie, and swapping
// the operands mirrors the sign.
func Test_Uint128_Compare_UnsignedOrder(t *testing.T) {
	cases := []struct {
		name        string
		left, right uint128
		want        int
	}{
		{name: "high half outranks a full low half", left: uint128{1, 0}, right: uint128{0, ^uint64(0)}, want: 1},
		{name: "equal values", left: uint128{5, 7}, right: uint128{5, 7}, want: 0},
		{name: "low half decides on equal high halves", left: uint128{5, 1}, right: uint128{5, 2}, want: -1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.want, tc.left.Compare(tc.right))
			require.Equal(t, -tc.want, tc.right.Compare(tc.left))
		})
	}
}

// verifies that an alternating bit pattern is inverted bit by bit and
// has no bit in common with its inverse.
//
// The alternating pattern is the shape every later non-contiguous mask
// test reduces to.
func Test_Uint128_Not_AlternatingPattern(t *testing.T) {
	pattern := uint128{0xAAAAAAAAAAAAAAAA, 0x5555555555555555}
	inverse := uint128{0x5555555555555555, 0xAAAAAAAAAAAAAAAA}
	require.Equal(t, inverse, pattern.Not())
	require.Equal(t, uint128{}, pattern.And(pattern.Not()))
}

// verifies that bits on both sides of the 64-bit half boundary combine
// under or without leaking into the other half.
//
// This is the shape of a two-run mask spanning bit 64.
func Test_Uint128_Or_BitsStraddlingHalfBoundary(t *testing.T) {
	lowest := uint128{1, 1 << 63}
	highest := uint128{1 << 63, 1}
	require.Equal(t, uint128{1<<63 | 1, 1<<63 | 1}, lowest.Or(highest))
}

// verifies that the byte form of any value is the big-endian encoding of
// its numeric value and converts back to the same value.
func Test_Uint128_From16_RoundTripsAnyValue(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		value := genUint128.Draw(t, "value")
		var want [16]byte
		bigOf(value).FillBytes(want[:])
		require.Equal(t, want, value.As16())
		require.Equal(t, value, uint128From16(value.As16()))
	})
}

// verifies that every bitwise operator agrees with the arbitrary-precision
// oracle, reduced to 128 bits.
func Test_Uint128_Bitwise_AgreesWithBigInt(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		left := genUint128.Draw(t, "left")
		right := genUint128.Draw(t, "right")
		leftBig, rightBig := bigOf(left), bigOf(right)
		require.Equal(t, uint128FromBig(new(big.Int).And(leftBig, rightBig)), left.And(right))
		require.Equal(t, uint128FromBig(new(big.Int).Or(leftBig, rightBig)), left.Or(right))
		require.Equal(t, uint128FromBig(new(big.Int).Xor(leftBig, rightBig)), left.Xor(right))
		require.Equal(t, uint128FromBig(new(big.Int).AndNot(leftBig, rightBig)), left.AndNot(right))
		require.Equal(t, uint128FromBig(new(big.Int).Not(leftBig)), left.Not())
	})
}

// verifies that compare is the numeric order of the values, which on the
// big-endian byte form is the lexicographic byte order.
func Test_Uint128_Compare_AgreesWithBytesAndBigInt(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		left := genUint128.Draw(t, "left")
		right := genUint128.Draw(t, "right")
		leftBytes, rightBytes := left.As16(), right.As16()
		require.Equal(t, bytes.Compare(leftBytes[:], rightBytes[:]), left.Compare(right))
		require.Equal(t, bigOf(left).Cmp(bigOf(right)), left.Compare(right))
	})
}

// verifies that compare is antisymmetric and that every value compares
// equal to itself.
func Test_Uint128_Compare_AntisymmetricAndReflexive(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		left := genUint128.Draw(t, "left")
		right := genUint128.Draw(t, "right")
		require.Equal(t, -right.Compare(left), left.Compare(right))
		require.Equal(t, 0, left.Compare(left))
	})
}

// verifies that the zero and all-ones predicates agree with struct
// equality against the two extremes on every shape.
func Test_Uint128_Predicates_AgreeWithStructEquality(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		value := genUint128.Draw(t, "value")
		require.Equal(t, value == uint128{}, value.IsZero())
		require.Equal(t, value == uint128Max, value.IsMax())
	})
}

// verifies that the 16-byte form is the byte layout the standard library
// address type uses, so the two can exchange bytes without reordering.
func Test_Uint128_As16_MatchesNetipByteLayout(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		value := genUint128.Draw(t, "value")
		require.Equal(t, value.As16(), netip.AddrFrom16(value.As16()).As16())
	})
}

// verifies that a chain of bitwise operations and a comparison does not
// allocate.
func Test_Uint128_Bitwise_AllocationFree(t *testing.T) {
	a := uint128{0xAAAAAAAAAAAAAAAA, 0x5555555555555555}
	b := uint128{1, 1 << 63}
	c := uint128{1 << 63, 1}
	d := uint128Max
	allocs := testing.AllocsPerRun(100, func() { compareSink = a.And(b).Or(c).Compare(d) })
	require.Zero(t, allocs, "allocations per call")
}

// genUint128 draws a 128-bit value over the shapes the IPv6 sessions
// need to see.
//
// The shapes are zero, all ones, a random value, a single set bit, a
// value confined to one half and alternating patterns of every run
// length, drawn with fixed weights rather than left to shrinking, because
// a shrunk random value is rarely the boundary one. Shared by the
// arithmetic and bit-counting sessions of the same type.
var genUint128 = rapid.Custom(func(t *rapid.T) uint128 {
	switch shape := rapid.IntRange(0, 99).Draw(t, "shape"); {
	case shape < 10:
		return uint128{}
	case shape < 20:
		return uint128Max
	case shape < 50:
		return uint128{rapid.Uint64().Draw(t, "hi"), rapid.Uint64().Draw(t, "lo")}
	case shape < 65:
		bit := rapid.IntRange(0, 127).Draw(t, "bit")
		if bit < 64 {
			return uint128{0, 1 << bit}
		}
		return uint128{1 << (bit - 64), 0}
	case shape < 75:
		return uint128{rapid.Uint64().Draw(t, "hi"), 0}
	case shape < 85:
		return uint128{0, rapid.Uint64().Draw(t, "lo")}
	default:
		run := rapid.SampledFrom([]int{1, 2, 4, 8, 16, 32, 64}).Draw(t, "run")
		value := alternatingUint128(run)
		if rapid.Bool().Draw(t, "inverted") {
			value = value.Not()
		}
		return value
	}
})

// alternatingUint128 returns the value whose bits alternate between set
// And clear in runs of the given length, set run first.
func alternatingUint128(run int) uint128 {
	var value uint128
	for bit := range 128 {
		if (bit/run)%2 != 0 {
			continue
		}
		if bit < 64 {
			value.hi |= 1 << (63 - bit)
		} else {
			value.lo |= 1 << (127 - bit)
		}
	}
	return value
}

// bigOf returns the numeric value as an arbitrary-precision integer.
//
// It is built from the halves, so it is independent of the byte
// conversions it serves as the oracle for.
func bigOf(m uint128) *big.Int {
	value := new(big.Int).SetUint64(m.hi)
	value.Lsh(value, 64)
	return value.Or(value, new(big.Int).SetUint64(m.lo))
}

// uint128FromBig reduces an oracle result modulo 2^128 into the value
// space, mapping the negative result of not and any wider one back.
func uint128FromBig(value *big.Int) uint128 {
	reduced := new(big.Int).And(value, bigOf(uint128Max))
	lo := new(big.Int).And(reduced, new(big.Int).SetUint64(^uint64(0))).Uint64()
	hi := new(big.Int).Rsh(reduced, 64).Uint64()
	return uint128{hi, lo}
}

// compareSink keeps the measured comparison alive, so the compiler cannot
// optimise the work under test away.
var compareSink int
