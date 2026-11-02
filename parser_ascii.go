package xnetip

import "bytes"

// ParseNetwork4ASCII parses a complete IPv4 network from ASCII bytes.
//
// The grammar, normalization and errors match [ParseNetwork4], including
// unsigned prefix lengths without leading zeros. Successful parsing does
// not allocate or retain the input. Errors own their input text.
func ParseNetwork4ASCII(text []byte) (Network4, error) {
	return parseNetwork4ASCII(text, "ParseNetwork4ASCII")
}

// parseNetwork4ASCII preserves the caller's diagnostic name while
// keeping the successful byte path allocation-free.
func parseNetwork4ASCII(text []byte, function string) (Network4, error) {
	if network, ok := network4ASCII(text); ok {
		return network, nil
	}
	return Network4{}, asciiParseError(text, function, ParseNetwork4)
}

// network4ASCII accepts a complete IPv4 network without constructing
// strings or errors, and normalizes every accepted address.
func network4ASCII(text []byte) (Network4, bool) {
	addressText, suffix, hasSuffix := bytes.Cut(text, []byte{'/'})
	addr, ok := address4ASCII(addressText)
	if !ok {
		return Network4{}, false
	}
	if !hasSuffix {
		return Network4{addr: addr, mask: ipv4AllBits}, true
	}
	if prefix, ok := prefixASCII(suffix, 32); ok {
		return fromBits4(addr, ipv4MaskFromPrefix(prefix)), true
	}
	mask, ok := address4ASCII(suffix)
	if !ok {
		return Network4{}, false
	}
	return fromBits4(addr, mask), true
}

// address4ASCII reads exactly four decimal octets and rejects leading
// zeros, overflows, missing separators and trailing bytes.
func address4ASCII(text []byte) (addr4, bool) {
	position := 0
	var address uint32
	for octet := range 4 {
		start := position
		value := uint32(0)
		for position < len(text) && text[position] >= '0' && text[position] <= '9' {
			value = value*10 + uint32(text[position]-'0')
			position++
			if value > 255 || position-start > 3 {
				return addr4{}, false
			}
		}
		if position == start || (position-start > 1 && text[start] == '0') {
			return addr4{}, false
		}
		address = address<<8 | value
		if octet < 3 {
			if position == len(text) || text[position] != '.' {
				return addr4{}, false
			}
			position++
		}
	}
	return addr4FromBits(address), position == len(text)
}

// prefixASCII reads a complete unsigned decimal prefix without a
// leading zero, bounded by the address family's width.
func prefixASCII(text []byte, limit int) (int, bool) {
	if len(text) == 0 || (len(text) > 1 && text[0] == '0') {
		return 0, false
	}
	value := 0
	for _, digit := range text {
		if digit < '0' || digit > '9' {
			return 0, false
		}
		value = value*10 + int(digit-'0')
		if value > limit {
			return 0, false
		}
	}
	return value, true
}

// asciiParseError owns rejected bytes before obtaining the existing
// parser's error, preserving its causes under the caller's name.
func asciiParseError[T any](text []byte, function string, parse func(string) (T, error)) error {
	input := string(text)
	_, err := parse(input)
	if err == nil {
		return wrapParseError(function, input, ErrParse, nil)
	}
	if function != "" {
		if diagnostic, ok := err.(*parseError); ok {
			diagnostic.function = function
		}
	}
	return err
}

// ParseNetwork6ASCII parses a complete IPv6 network from ASCII bytes.
//
// The grammar, normalization and errors match [ParseNetwork6]. Embedded
// IPv4 stays IPv6, zones are rejected and prefixes have no sign or leading
// zeros. Successful parsing allocates nothing and does not retain the
// input. Errors own their input text.
func ParseNetwork6ASCII(text []byte) (Network6, error) {
	return parseNetwork6ASCII(text, "ParseNetwork6ASCII")
}

// parseNetwork6ASCII preserves the caller's diagnostic name while
// keeping the successful byte path allocation-free.
func parseNetwork6ASCII(text []byte, function string) (Network6, error) {
	if network, ok := network6ASCII(text); ok {
		return network, nil
	}
	return Network6{}, asciiParseError(text, function, ParseNetwork6)
}

// network6ASCII accepts a complete IPv6 network without constructing
// strings or errors, and normalizes every accepted address.
func network6ASCII(text []byte) (Network6, bool) {
	addressText, suffix, hasSuffix := bytes.Cut(text, []byte{'/'})
	addr, ok := address6ASCII(addressText)
	if !ok {
		return Network6{}, false
	}
	if !hasSuffix {
		return Network6{addr: addr, mask: ipv6AllBits}, true
	}
	if prefix, ok := prefixASCII(suffix, 128); ok {
		return fromBits6(addr, addr6{uint128MaskFromPrefix(prefix)}), true
	}
	mask, ok := address6ASCII(suffix)
	if !ok {
		return Network6{}, false
	}
	return fromBits6(addr, mask), true
}

// address6ASCII accepts eight hex groups with at most one compressed
// zero run and an optional trailing dotted IPv4 pair of groups.
func address6ASCII(text []byte) (addr6, bool) {
	if len(text) == 0 {
		return addr6{}, false
	}
	var groups [8]uint16
	count, position, gap := 0, 0, -1
	if text[0] == ':' {
		if len(text) < 2 || text[1] != ':' {
			return addr6{}, false
		}
		gap, position = 0, 2
	}
	for position < len(text) {
		if count == len(groups) {
			return addr6{}, false
		}
		start := position
		var group uint16
		for position < len(text) {
			digit, ok := asciiHexDigit(text[position])
			if !ok {
				break
			}
			if position-start == 4 {
				return addr6{}, false
			}
			group = group<<4 | uint16(digit)
			position++
		}
		if position == start {
			return addr6{}, false
		}
		if position < len(text) && text[position] == '.' {
			embedded, ok := address4ASCII(text[start:])
			if !ok || count > 6 {
				return addr6{}, false
			}
			groups[count], groups[count+1] = uint16(embedded.Bits()>>16), uint16(embedded.Bits())
			count += 2
			break
		}
		groups[count] = group
		count++
		if position == len(text) {
			break
		}
		if text[position] != ':' {
			return addr6{}, false
		}
		position++
		if position == len(text) {
			return addr6{}, false
		}
		if text[position] == ':' {
			if gap >= 0 {
				return addr6{}, false
			}
			gap = count
			position++
		}
	}
	if gap < 0 {
		if count != len(groups) {
			return addr6{}, false
		}
	} else {
		if count == len(groups) {
			return addr6{}, false
		}
		// The compressed run represents at least one zero group, and
		// its trailing groups must end at the address's low half.
		missing := len(groups) - count
		copy(groups[gap+missing:], groups[gap:count])
		clear(groups[gap : gap+missing])
	}
	var address [16]byte
	for idx, group := range groups {
		address[idx*2], address[idx*2+1] = byte(group>>8), byte(group)
	}
	return addr6From16(address), true
}

// asciiHexDigit reads one ASCII hexadecimal digit without accepting
// non-ASCII lookalikes or locale-dependent forms.
func asciiHexDigit(character byte) (byte, bool) {
	if character >= '0' && character <= '9' {
		return character - '0', true
	}
	lower := character | 0x20
	if lower >= 'a' && lower <= 'f' {
		return lower - 'a' + 10, true
	}
	return 0, false
}

// ParseNetworkASCII parses a complete IPv4 or IPv6 network from bytes.
//
// The grammar, normalization and family rules match [ParseNetwork].
// Successful parsing allocates nothing and does not retain the input.
// Errors own their input text. Prefixes have no sign or leading zeros.
func ParseNetworkASCII(text []byte) (Network, error) {
	return parseNetworkASCII(text, "ParseNetworkASCII")
}

// parseNetworkASCII preserves the caller's diagnostic name while
// keeping the successful byte path allocation-free.
func parseNetworkASCII(text []byte, function string) (Network, error) {
	if network, ok := networkASCII(text); ok {
		return network, nil
	}
	return Network{}, asciiParseError(text, function, ParseNetwork)
}

// networkASCII selects a family from the complete address token,
// keeping IPv4-mapped input in the IPv6 family.
func networkASCII(text []byte) (Network, bool) {
	if network, ok := network4ASCII(text); ok {
		return NetworkFrom4(network), true
	}
	if network, ok := network6ASCII(text); ok {
		return NetworkFrom6(network), true
	}
	return Network{}, false
}

// ParseNextNetwork4ASCII parses the leading IPv4 network token.
//
// The maximal leading run of [0-9./+] must parse as a whole. Whitespace
// is not skipped, malformed tokens are not shortened and ':' delimits
// the token, so "1.2.3.4:80" leaves ":80". Prefixes follow the strict
// [ParseNetwork4] grammar. The successful remainder aliases the input.
// Failure returns a zero network, nil remainder and an owned error.
func ParseNextNetwork4ASCII(text []byte) (Network4, []byte, error) {
	end := networkTokenEndASCII(text, false)
	network, err := parseNetwork4ASCII(text[:end], "ParseNextNetwork4ASCII")
	if err != nil {
		return Network4{}, nil, err
	}
	return network, text[end:], nil
}

// networkTokenEndASCII finds the maximal leading network alphabet
// run, using the shared IPv6 alphabet when the family is not IPv4.
func networkTokenEndASCII(text []byte, ipv6 bool) int {
	for idx, character := range text {
		if (character >= '0' && character <= '9') || character == '.' || character == '/' || character == '+' {
			continue
		}
		if ipv6 {
			if _, ok := asciiHexDigit(character); ok || character == ':' {
				continue
			}
		}
		return idx
	}
	return len(text)
}

// ParseNextNetwork6ASCII parses the leading IPv6 network token.
//
// The maximal leading run of [0-9a-fA-F:./+] must parse as a whole.
// Whitespace is not skipped and malformed tokens are not shortened.
// Prefixes follow [ParseNetwork6]'s strict grammar. The successful
// remainder aliases the input. Failure returns a zero network, nil
// remainder and an error that owns the rejected token text.
func ParseNextNetwork6ASCII(text []byte) (Network6, []byte, error) {
	end := networkTokenEndASCII(text, true)
	network, err := parseNetwork6ASCII(text[:end], "ParseNextNetwork6ASCII")
	if err != nil {
		return Network6{}, nil, err
	}
	return network, text[end:], nil
}

// ParseNextNetworkASCII parses the leading network token in either family.
//
// The maximal leading run of [0-9a-fA-F:./+] must parse as a whole.
// Unlike [ParseNextNetwork4ASCII], "1.2.3.4:80" is an error because ':'
// stays in the shared token alphabet. Whitespace is not skipped, prefixes
// follow [ParseNetwork]'s strict grammar and the successful remainder
// aliases the input. Failure returns a zero network and nil remainder.
// Errors own the rejected token text.
func ParseNextNetworkASCII(text []byte) (Network, []byte, error) {
	end := networkTokenEndASCII(text, true)
	network, err := parseNetworkASCII(text[:end], "ParseNextNetworkASCII")
	if err != nil {
		return Network{}, nil, err
	}
	return network, text[end:], nil
}
