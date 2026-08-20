package xnetip

// IPAddr is an IPv4 or IPv6 address without a zone.
//
// The zero value is the IPv6 unspecified address ::. An IPv4 value is
// kept internally as its IPv4-mapped IPv6 form, so every operation can
// run on 128 bits, but it reports Is4 and never compares equal to the
// IPv6 address ::ffff:a.b.c.d built with IPAddrFrom6. Values are
// comparable with == and usable as map keys, and there is no invalid
// state.
type IPAddr struct {
	addr IPv6Addr
	is4  bool
}

// IPAddrFrom4 returns the IPv4 address a as an IPAddr.
func IPAddrFrom4(a IPv4Addr) IPAddr {
	return IPAddr{addr: a.ToIPv6Mapped(), is4: true}
}

// IPAddrFrom6 returns the IPv6 address a as an IPAddr.
//
// An IPv4-mapped address stays IPv6 (Is4 is false), as in net/netip
// and core::net: only IPAddrFrom4 produces IPv4 values.
func IPAddrFrom6(a IPv6Addr) IPAddr {
	return IPAddr{addr: a}
}

// Is4 reports whether the address is IPv4. It is false for an
// IPv4-mapped IPv6 address.
func (m IPAddr) Is4() bool {
	return m.is4
}

// Is6 reports whether the address is IPv6, including IPv4-mapped ones.
func (m IPAddr) Is6() bool {
	return !m.is4
}

// IPv4 returns the IPv4 address when Is4 reports true.
func (m IPAddr) IPv4() (IPv4Addr, bool) {
	if !m.is4 {
		return IPv4Addr{}, false
	}
	addr, _ := m.addr.ToIPv4Mapped()
	return addr, true
}

// IPv6 returns the IPv6 address when Is6 reports true.
//
// An IPv4 address is not an IPv6 address for this accessor: its mapped
// form is available through ToIPv6Mapped.
func (m IPAddr) IPv6() (IPv6Addr, bool) {
	if m.is4 {
		return IPv6Addr{}, false
	}
	return m.addr, true
}

// As16 returns the 16-byte form of the address. An IPv4 address is
// returned IPv4-mapped, as by netip.Addr.As16.
func (m IPAddr) As16() [16]byte {
	return m.addr.As16()
}

// BitLen returns 32 for an IPv4 address and 128 for an IPv6 address.
func (m IPAddr) BitLen() int {
	if m.is4 {
		return 32
	}
	return 128
}

// Compare returns -1, 0 or +1 as m sorts before, equal to or after
// other.
//
// Every IPv4 address orders before every IPv6 address, including the
// IPv4-mapped twin built with IPAddrFrom6 — the order of netip.Addr,
// which sorts by bit length first. Within a family the order is the
// numeric order of the address bits, as in IPv4Addr.Compare and
// IPv6Addr.Compare, and comparing the stored 128-bit forms preserves it
// because the mapped prefix above the IPv4 bits is constant. It is the
// order every sorting operation in this package uses for
// family-agnostic values.
func (m IPAddr) Compare(other IPAddr) int {
	if m.is4 != other.is4 {
		if m.is4 {
			return -1
		}
		return 1
	}
	return m.addr.Compare(other.addr)
}

// String returns the text form of the address: dotted decimal for IPv4,
// RFC 5952 for IPv6, "::ffff:a.b.c.d" for an IPv4-mapped IPv6 address.
//
// The forms are the per-family ones of IPv4Addr.String and
// IPv6Addr.String, so an IPv4 value prints without the mapping prefix
// while a mapped value kept IPv6 prints with it — the text alone
// recovers the family. It allocates once, for the result.
func (m IPAddr) String() string {
	if v4, ok := m.IPv4(); ok {
		return v4.String()
	}
	return m.addr.String()
}

// AppendTo appends the text form of the address to b and returns the
// extended buffer.
//
// It is the allocation-free path behind String and MarshalText: with
// enough capacity in b (45 bytes suffice) it performs no allocation.
func (m IPAddr) AppendTo(b []byte) []byte {
	if v4, ok := m.IPv4(); ok {
		return v4.AppendTo(b)
	}
	return m.addr.AppendTo(b)
}
