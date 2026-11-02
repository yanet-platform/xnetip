package xnetip

import (
	"math"
	"net/netip"
)

// AddrIterator is a resumable, double-ended cursor over a network's addresses.
//
// Next and NextBack take addresses from opposite ends of the same remaining
// range. Nth and NthBack skip without visiting intermediate addresses. Copying
// the value snapshots the cursor independently. The zero value is exhausted.
// Cursor methods allocate nothing and preserve the network's address family.
// A cursor must not be mutated concurrently.
type AddrIterator struct {
	base          uint128
	mask          uint128
	front         uint128
	back          uint128
	remainingLast uint128
	active        bool
	is4           bool
	contiguous    bool
}

// newAddrIterator stores the remaining count minus one, including a full universe.
func newAddrIterator(network Network6, is4 bool) AddrIterator {
	hostMask := network.mask.bits.Not()
	hostBits := hostMask.OnesCount()
	return AddrIterator{
		base:          network.addr.bits,
		mask:          network.mask.bits,
		front:         network.addr.bits,
		back:          network.addr.bits.Or(hostMask),
		remainingLast: uint128{}.Not().Shr(uint(128 - hostBits)),
		active:        true,
		is4:           is4,
		contiguous:    hostMask.And(hostMask.AddOne()).IsZero(),
	}
}

// Next consumes the first remaining address, or returns false on exhaustion.
//
// Exhaustion is permanent for every traversal method. A false result carries
// an invalid zero address. Stepping takes constant time for any mask shape.
func (m *AddrIterator) Next() (netip.Addr, bool) {
	if !m.active {
		return netip.Addr{}, false
	}
	address := m.front
	m.consume()
	if m.contiguous {
		m.front = m.front.AddOne()
	} else {
		m.front = m.front.Or(m.mask).AddOne().And(m.mask.Not()).Or(m.base)
	}
	return m.address(address), true
}

// consume removes one remaining item without overflowing a full-width count.
func (m *AddrIterator) consume() {
	if m.remainingLast.IsZero() {
		m.active = false
	} else {
		m.remainingLast = m.remainingLast.SubOne()
	}
}

// address presents the cursor bits in their original address family.
func (m *AddrIterator) address(bits uint128) netip.Addr {
	if m.is4 {
		return addr4FromBits(uint32(bits.lo)).Netip()
	}
	return addr6{bits}.Netip()
}

// NextBack consumes the last remaining address, or returns false on exhaustion.
//
// It shares the remaining range with Next and never yields an address already
// consumed from either end. Stepping takes constant time for any mask shape.
func (m *AddrIterator) NextBack() (netip.Addr, bool) {
	if !m.active {
		return netip.Addr{}, false
	}
	address := m.back
	m.consume()
	if m.contiguous {
		m.back = m.back.SubOne()
	} else {
		m.back = m.back.And(m.mask.Not()).SubOne().And(m.mask.Not()).Or(m.base)
	}
	return m.address(address), true
}

// Nth skips n remaining addresses from the front and consumes the next one.
//
// A zero skip is Next. Skipping past the remaining range exhausts the cursor.
// CIDR skipping takes constant time. For arbitrary masks the skip index is
// spread over host positions in logarithmic time in n, with at most 64 steps.
func (m *AddrIterator) Nth(n uint64) (netip.Addr, bool) {
	skip := uint128FromUint64(n)
	if !m.active || skip.Compare(m.remainingLast) > 0 {
		m.active = false
		return netip.Addr{}, false
	}
	if m.contiguous {
		m.front = m.front.Add(skip)
	} else {
		deposited := depositHostIndex(n, m.mask.Not())
		m.front = m.front.Or(m.mask).Add(deposited).And(m.mask.Not()).Or(m.base)
	}
	m.remainingLast = m.remainingLast.Sub(skip)
	return m.Next()
}

// depositHostIndex spreads the index bits over ascending host positions.
func depositHostIndex(index uint64, hostMask uint128) uint128 {
	deposited := uint128{}
	for index != 0 {
		lowest := hostMask.LowestSetBit()
		if index&1 != 0 {
			deposited = deposited.Or(lowest)
		}
		hostMask = hostMask.ClearLowestSetBit()
		index >>= 1
	}
	return deposited
}

// NthBack skips n remaining addresses from the back and consumes the next one.
//
// A zero skip is NextBack. Skipping past the remaining range exhausts the
// cursor. Its complexity is the same as Nth, and both ends share one count.
func (m *AddrIterator) NthBack(n uint64) (netip.Addr, bool) {
	skip := uint128FromUint64(n)
	if !m.active || skip.Compare(m.remainingLast) > 0 {
		m.active = false
		return netip.Addr{}, false
	}
	if m.contiguous {
		m.back = m.back.Sub(skip)
	} else {
		deposited := depositHostIndex(n, m.mask.Not())
		m.back = m.back.And(m.mask.Not()).Sub(deposited).And(m.mask.Not()).Or(m.base)
	}
	m.remainingLast = m.remainingLast.Sub(skip)
	return m.NextBack()
}

// SizeHint returns the number of remaining addresses when it fits uint64.
//
// The boolean reports an exact count. Otherwise the count is saturated at
// math.MaxUint64, a lower bound. An exhausted cursor returns zero and true.
// This distinguishes 2^64 or 2^128 members from wrapped zero counts.
func (m *AddrIterator) SizeHint() (uint64, bool) {
	if !m.active {
		return 0, true
	}
	if m.remainingLast.hi != 0 || m.remainingLast.lo == math.MaxUint64 {
		return math.MaxUint64, false
	}
	return m.remainingLast.lo + 1, true
}
