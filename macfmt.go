package xnetip

import "fmt"

// MacHyphens renders an address as six hyphen-separated hexadecimal octets.
//
// The opaque adapter supports String, AppendTo and [fmt.Formatter]. Default
// and x formatting use lowercase letters, X uses uppercase. Width and
// precision apply to the complete text as for [MacAddr].
func MacHyphens(address MacAddr) macFormat {
	return macFormat{address: address, separator: '-'}
}

// MacDots renders an address as three dot-separated four-digit hex groups.
//
// The opaque adapter supports String, AppendTo and [fmt.Formatter]. Default
// and x formatting use lowercase letters, X uses uppercase. Width and
// precision apply to the complete text as for [MacAddr].
func MacDots(address MacAddr) macFormat {
	return macFormat{address: address, separator: '.'}
}

// macFormat carries an immutable address and its alternative text separator.
type macFormat struct {
	address   MacAddr
	separator byte
}

// String returns the adapter's lowercase address text.
func (m macFormat) String() string {
	var buffer [17]byte
	return string(m.AppendTo(buffer[:0]))
}

// AppendTo appends the adapter's lowercase address text to b.
//
// With room for 17 additional bytes the append does not allocate.
func (m macFormat) AppendTo(b []byte) []byte {
	return appendMacAddr(b, m.address, m.separator)
}

// Format implements [fmt.Formatter] with the adapter's separators.
//
// Its verbs, case and padding match [MacAddr.Format].
func (m macFormat) Format(state fmt.State, verb rune) {
	formatMacAddr(state, verb, m.address, m.separator)
}
