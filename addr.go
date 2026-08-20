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
