package xnetip

import "net/netip"

// String returns the dotted-decimal form of the address, such as
// "192.168.0.1".
//
// The form is the one net/netip prints for an IPv4 address: four decimal
// octets without leading zeros. It allocates once, for the result.
func (m IPv4Addr) String() string {
	return netip.AddrFrom4(m.As4()).String()
}

// AppendTo appends the dotted-decimal form of the address to b and returns
// the extended buffer.
//
// It is the allocation-free path behind String and MarshalText: with
// enough capacity in b (15 bytes suffice) it performs no allocation.
func (m IPv4Addr) AppendTo(b []byte) []byte {
	return netip.AddrFrom4(m.As4()).AppendTo(b)
}
