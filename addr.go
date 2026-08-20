package xnetip

import "net/netip"

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

// IPAddrFromNetip converts a netip.Addr to an IPAddr, dropping any
// zone.
//
// An IPv4 netip.Addr becomes an IPv4 IPAddr, everything else —
// including an IPv4-mapped IPv6 address — stays IPv6, so the family
// flag follows netip's. A zone is discarded silently, as by the
// per-family conversions. The invalid zero netip.Addr converts to the
// zero IPAddr (::), a lossy mapping of an invalid input onto a valid
// value — check IsValid on the netip side first when that matters.
func IPAddrFromNetip(a netip.Addr) IPAddr {
	if v4, ok := IPv4AddrFromNetip(a); ok {
		return IPAddrFrom4(v4)
	}
	if v6, ok := IPv6AddrFromNetip(a); ok {
		return IPAddrFrom6(v6)
	}
	return IPAddr{}
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

// Netip returns the address as a zone-free netip.Addr: Is4 for IPv4
// values, Is6 otherwise.
//
// The view is always valid, a mapped value kept IPv6 comes back Is4In6
// and never unmapped, and IPAddrFromNetip restores m from it.
func (m IPAddr) Netip() netip.Addr {
	if v4, ok := m.IPv4(); ok {
		return v4.Netip()
	}
	return m.addr.Netip()
}

// ToIPv6Mapped returns the address as an IPv6 address: IPv4 becomes its
// mapped form ::ffff:a.b.c.d, IPv6 is returned unchanged.
//
// The result holds exactly the 16-byte form of the address, so the
// method is the typed counterpart of As16 and the inverse direction of
// Unmap for IPv4 values. It mirrors IPv4Addr.ToIPv6Mapped at the
// family-agnostic level, total and allocation-free.
func (m IPAddr) ToIPv6Mapped() IPv6Addr {
	return m.addr
}

// IsUnspecified reports whether the address is the unspecified address
// of its family, 0.0.0.0 or ::.
//
// The IPv4-mapped ::ffff:0.0.0.0 kept in the IPv6 family is a different
// 128-bit value and is not unspecified, as in net/netip.
func (m IPAddr) IsUnspecified() bool {
	if v4, ok := m.IPv4(); ok {
		return v4.IsUnspecified()
	}
	return m.addr.IsUnspecified()
}

// IsLoopback reports whether the address is loopback, in 127.0.0.0/8
// for IPv4 and ::1 for IPv6.
//
// An IPv4-mapped address is judged by its IPv4 part, the net/netip
// rule.
func (m IPAddr) IsLoopback() bool {
	if v4, ok := m.IPv4(); ok {
		return v4.IsLoopback()
	}
	return m.addr.IsLoopback()
}

// IsPrivate reports whether the address is private, RFC 1918 for IPv4
// and fc00::/7 (RFC 4193) for IPv6.
//
// An IPv4-mapped address is judged by its IPv4 part. A private address
// still counts as global unicast, exactly as in net/netip.
func (m IPAddr) IsPrivate() bool {
	if v4, ok := m.IPv4(); ok {
		return v4.IsPrivate()
	}
	return m.addr.IsPrivate()
}

// IsMulticast reports whether the address is multicast, in 224.0.0.0/4
// for IPv4 and ff00::/8 for IPv6.
//
// An IPv4-mapped address is judged by its IPv4 part, the net/netip
// rule.
func (m IPAddr) IsMulticast() bool {
	if v4, ok := m.IPv4(); ok {
		return v4.IsMulticast()
	}
	return m.addr.IsMulticast()
}

// IsLinkLocalUnicast reports whether the address is link-local
// unicast, in 169.254.0.0/16 for IPv4 and fe80::/10 for IPv6.
//
// An IPv4-mapped address is judged by its IPv4 part, the net/netip
// rule.
func (m IPAddr) IsLinkLocalUnicast() bool {
	if v4, ok := m.IPv4(); ok {
		return v4.IsLinkLocalUnicast()
	}
	return m.addr.IsLinkLocalUnicast()
}

// IsLinkLocalMulticast reports whether the address is link-local
// multicast, 224.0.0.0/24 for IPv4 and scope 2 for IPv6.
//
// An IPv4-mapped address is judged by its IPv4 part, the net/netip
// rule.
func (m IPAddr) IsLinkLocalMulticast() bool {
	if v4, ok := m.IPv4(); ok {
		return v4.IsLinkLocalMulticast()
	}
	return m.addr.IsLinkLocalMulticast()
}

// IsInterfaceLocalMulticast reports whether the address is an
// interface-local multicast address (scope 1 in the first group).
//
// The scope is an IPv6-only concept, so it is false for every IPv4
// address and for every IPv4-mapped address, as in net/netip.
func (m IPAddr) IsInterfaceLocalMulticast() bool {
	if m.is4 {
		return false
	}
	return m.addr.IsInterfaceLocalMulticast()
}

// IsGlobalUnicast reports whether the address is global unicast in the
// sense of net/netip and package net.
//
// It is false for the unspecified, loopback, multicast and link-local
// unicast addresses of either family, and for the IPv4 broadcast
// address 255.255.255.255. An IPv4-mapped address is judged by its IPv4
// part. Private addresses count as global unicast, exactly as in
// net/netip.
func (m IPAddr) IsGlobalUnicast() bool {
	if v4, ok := m.IPv4(); ok {
		return v4.IsGlobalUnicast()
	}
	return m.addr.IsGlobalUnicast()
}

// Is4In6 reports whether the address is an IPv6 address in the
// IPv4-mapped range ::ffff:0:0/96.
//
// It is false for an IPv4 address even though its storage is mapped:
// only a value built as IPv6 can be 4in6, as in net/netip.
func (m IPAddr) Is4In6() bool {
	return !m.is4 && m.addr.Is4In6()
}

// Unmap returns the IPv4 address embedded in an IPv4-mapped IPv6
// address, and every other address unchanged.
//
// It collapses the mapped form into the IPv4 family, so the result is
// never 4in6 and unmapping is idempotent. It is the family-agnostic
// counterpart of netip.Addr.Unmap and the exact behaviour of Rust's
// IpAddr::to_canonical.
func (m IPAddr) Unmap() IPAddr {
	if !m.Is4In6() {
		return m
	}
	v4, _ := m.addr.ToIPv4Mapped()
	return IPAddrFrom4(v4)
}

// Next returns the address one above m within its family.
//
// The second result is false at the top of the family, 255.255.255.255
// or ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff: an IPv4 increment never
// crosses into IPv6. Unlike netip.Addr.Next, the end is reported with
// the comma-ok form rather than an invalid address, because every
// IPAddr value is a real address.
func (m IPAddr) Next() (IPAddr, bool) {
	if v4, ok := m.IPv4(); ok {
		next, ok := v4.Next()
		if !ok {
			return IPAddr{}, false
		}
		return IPAddrFrom4(next), true
	}
	next, ok := m.addr.Next()
	if !ok {
		return IPAddr{}, false
	}
	return IPAddrFrom6(next), true
}

// Prev returns the address one below m within its family.
//
// The second result is false at the bottom of the family, 0.0.0.0 or
// ::. Unlike netip.Addr.Prev, the end is reported with the comma-ok
// form rather than an invalid address, because every IPAddr value is a
// real address.
func (m IPAddr) Prev() (IPAddr, bool) {
	if v4, ok := m.IPv4(); ok {
		prev, ok := v4.Prev()
		if !ok {
			return IPAddr{}, false
		}
		return IPAddrFrom4(prev), true
	}
	prev, ok := m.addr.Prev()
	if !ok {
		return IPAddr{}, false
	}
	return IPAddrFrom6(prev), true
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

// MarshalText implements encoding.TextMarshaler.
//
// The text is exactly String(): the per-family form, mapped addresses
// as "::ffff:a.b.c.d". The error is always nil, and the single
// allocation is the returned slice, sized upfront for the longest form.
// The zero value marshals as "::", not as empty text, because it is a
// real address.
func (m IPAddr) MarshalText() ([]byte, error) {
	return m.AppendTo(make([]byte, 0, len("ffff:ffff:ffff:ffff:ffff:ffff:255.255.255.255"))), nil
}

// UnmarshalText implements encoding.TextUnmarshaler.
//
// The text must be accepted by ParseIPAddr, so a zone suffix is
// rejected, and on error the receiver is left untouched. Unlike
// netip.Addr, empty text is an error rather than the zero value,
// because the zero IPAddr is the valid address :: and an absent field
// must not silently decode into it.
func (m *IPAddr) UnmarshalText(text []byte) error {
	address, err := ParseIPAddr(string(text))
	if err != nil {
		return err
	}
	*m = address
	return nil
}

// ParseIPAddr parses s as an IPv4 address ("192.0.2.1") or an IPv6
// address ("2001:db8::1"), the grammar of netip.ParseAddr minus zones.
//
// The family comes from the text: dotted decimal is IPv4 and everything
// with colons is IPv6, so an IPv4-mapped form such as "::ffff:192.0.2.1"
// stays IPv6 (Is4In6), never unmapped. Text that net/netip rejects wraps
// ErrParse together with the net/netip error that explains the
// rejection, a zone suffix ("fe80::1%eth0") wraps ErrZone alone. Every
// error names the parser and echoes s, so errors.Is works on the
// sentinels and the message identifies the input.
func ParseIPAddr(s string) (IPAddr, error) {
	addr, err := netip.ParseAddr(s)
	if err != nil {
		return IPAddr{}, wrapParseError("ParseIPAddr", s, ErrParse, err)
	}
	if addr.Zone() != "" {
		return IPAddr{}, wrapParseError("ParseIPAddr", s, ErrZone, nil)
	}
	if addr.Is4() {
		return IPAddrFrom4(IPv4AddrFrom4(addr.As4())), nil
	}
	return IPAddrFrom6(IPv6AddrFrom16(addr.As16())), nil
}

// MustParseIPAddr calls ParseIPAddr and panics on error.
//
// It is intended for tests and package-level variables with hard-coded
// text, like netip.MustParseAddr.
func MustParseIPAddr(s string) IPAddr {
	addr, err := ParseIPAddr(s)
	if err != nil {
		panic(err)
	}
	return addr
}
