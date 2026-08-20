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
