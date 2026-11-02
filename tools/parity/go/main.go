package main

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"net/netip"
	"os"
	"slices"
	"strconv"
	"strings"

	"github.com/yanet-platform/xnetip"
)

func address4(input string) netip.Addr {
	value, err := strconv.ParseUint(input, 16, 32)
	if err != nil {
		panic(err)
	}
	return netip.AddrFrom4([4]byte{byte(value >> 24), byte(value >> 16), byte(value >> 8), byte(value)})
}

func address6(input string) netip.Addr {
	second, err := hex.DecodeString(fmt.Sprintf("%032s", input))
	if err != nil {
		panic(err)
	}
	var first [16]byte
	copy(first[:], second)
	return netip.AddrFrom16(first)
}

func network4(first, mask string) xnetip.Network4 {
	network, err := xnetip.Network4From(address4(first), address4(mask))
	if err != nil {
		panic(err)
	}
	return network
}

func network6(first, mask string) xnetip.Network6 {
	network, err := xnetip.Network6From(address6(first), address6(mask))
	if err != nil {
		panic(err)
	}
	return network
}

func format4(network xnetip.Network4) string {
	return fmt.Sprintf("%x/%x", network.Addr().As4(), network.Mask().As4())
}

func format6(network xnetip.Network6) string {
	return fmt.Sprintf("%x/%x", network.Addr().As16(), network.Mask().As16())
}

func optional4(network xnetip.Network4, second bool) string {
	if !second {
		return "-"
	}
	return format4(network)
}

func optional6(network xnetip.Network6, second bool) string {
	if !second {
		return "-"
	}
	return format6(network)
}

func formatBools(values ...bool) string {
	var result strings.Builder
	for _, value := range values {
		if value {
			result.WriteByte('1')
		} else {
			result.WriteByte('0')
		}
	}
	return result.String()
}

func formatPrefix(p int, ok bool) string {
	if !ok {
		return "None"
	}
	return fmt.Sprintf("Some(%d)", p)
}

func writeLine(writer *bufio.Writer, line string) {
	if _, err := fmt.Fprintln(writer, line); err != nil {
		panic(err)
	}
}

func main() {
	scanner := bufio.NewScanner(os.Stdin)
	scanner.Buffer(make([]byte, 1024), 1<<20)
	writer := bufio.NewWriter(os.Stdout)
	defer func() {
		if err := writer.Flush(); err != nil {
			panic(err)
		}
	}()
	for scanner.Scan() {
		tokens := strings.Fields(scanner.Text())
		if len(tokens) == 0 {
			continue
		}
		var results []string
		switch tokens[0] {
		case "ta", "tn":
			input := decodeBytes(tokens[1])
			results = parseASCIIResults(input, tokens[0] == "tn")
			writeLine(writer, strings.Join(results, ";"))
			continue
		case "s4":
			parent := network4(tokens[1], tokens[2])
			children := []string{}
			for child := range parent.Subnets(address4(tokens[3])) {
				children = append(children, format4(child))
				if len(children) == 8 {
					break
				}
			}
			reverseChildren := []string{}
			for child := range parent.SubnetsBackward(address4(tokens[3])) {
				reverseChildren = append(reverseChildren, format4(child))
				if len(reverseChildren) == 8 {
					break
				}
			}
			prefix, err := strconv.Atoi(tokens[4])
			if err != nil {
				panic(err)
			}
			cidrs := []string{}
			for child := range parent.SubnetsWithPrefix(prefix) {
				cidrs = append(cidrs, format4(child.Network()))
				if len(cidrs) == 8 {
					break
				}
			}
			reverseCIDRs := []string{}
			for child := range parent.SubnetsWithPrefixBackward(prefix) {
				reverseCIDRs = append(reverseCIDRs, format4(child.Network()))
				if len(reverseCIDRs) == 8 {
					break
				}
			}
			results = []string{strings.Join(children, ","), strings.Join(cidrs, ","), strings.Join(reverseChildren, ","), strings.Join(reverseCIDRs, ",")}
		case "s6":
			parent := network6(tokens[1], tokens[2])
			children := []string{}
			for child := range parent.Subnets(address6(tokens[3])) {
				children = append(children, format6(child))
				if len(children) == 8 {
					break
				}
			}
			reverseChildren := []string{}
			for child := range parent.SubnetsBackward(address6(tokens[3])) {
				reverseChildren = append(reverseChildren, format6(child))
				if len(reverseChildren) == 8 {
					break
				}
			}
			prefix, err := strconv.Atoi(tokens[4])
			if err != nil {
				panic(err)
			}
			cidrs := []string{}
			for child := range parent.SubnetsWithPrefix(prefix) {
				cidrs = append(cidrs, format6(child.Network()))
				if len(cidrs) == 8 {
					break
				}
			}
			reverseCIDRs := []string{}
			for child := range parent.SubnetsWithPrefixBackward(prefix) {
				reverseCIDRs = append(reverseCIDRs, format6(child.Network()))
				if len(reverseCIDRs) == 8 {
					break
				}
			}
			results = []string{strings.Join(children, ","), strings.Join(cidrs, ","), strings.Join(reverseChildren, ","), strings.Join(reverseCIDRs, ",")}
		case "i4", "i6":
			var network xnetip.Network
			if tokens[0] == "i4" {
				network = xnetip.NetworkFrom4(network4(tokens[1], tokens[2]))
			} else {
				network = xnetip.NetworkFrom6(network6(tokens[1], tokens[2]))
			}
			cursor := network.AddrIterator()
			results = append(results, cursorSize(&cursor))
			for idx := 3; idx < len(tokens); idx += 2 {
				skip, err := strconv.ParseUint(tokens[idx+1], 16, 64)
				if err != nil {
					panic(err)
				}
				var address netip.Addr
				var ok bool
				if tokens[idx] == "f" {
					address, ok = cursor.Nth(skip)
				} else {
					address, ok = cursor.NthBack(skip)
				}
				text := "-"
				if ok {
					text = addressBits(address)
				}
				results = append(results, text+":"+cursorSize(&cursor))
			}
		case "j4":
			projected := []projected4{}
			for idx := 1; idx < len(tokens); idx += 2 {
				projected = append(projected, projected4{network: network4(tokens[idx], tokens[idx+1]), payload: (idx - 1) / 2})
			}
			slices.SortStableFunc(projected, func(first, second projected4) int { return first.network.Compare(second.network) })
			candidate, interval, ok := xnetip.BinarySplit4(projected, func(item projected4) xnetip.Network4 { return item.network })
			results = []string{optional4(candidate, ok), fmt.Sprintf("%d:%d", interval.Start, interval.End)}
			for _, item := range projected {
				results = append(results, fmt.Sprintf("%d:%s", item.payload, format4(item.network)))
			}
		case "j6":
			projected := []projected6{}
			for idx := 1; idx < len(tokens); idx += 2 {
				projected = append(projected, projected6{network: network6(tokens[idx], tokens[idx+1]), payload: (idx - 1) / 2})
			}
			slices.SortStableFunc(projected, func(first, second projected6) int { return first.network.Compare(second.network) })
			candidate, interval, ok := xnetip.BinarySplit6(projected, func(item projected6) xnetip.Network6 { return item.network })
			results = []string{optional6(candidate, ok), fmt.Sprintf("%d:%d", interval.Start, interval.End)}
			for _, item := range projected {
				results = append(results, fmt.Sprintf("%d:%s", item.payload, format6(item.network)))
			}
		case "m":
			value, err := strconv.ParseUint(tokens[1], 16, 64)
			if err != nil {
				panic(err)
			}
			address, ok := xnetip.MacAddrFromUint64(value)
			if !ok {
				writeLine(writer, "ERR")
				continue
			}
			results = []string{fmt.Sprintf("%012x", address.Uint64()), formatBools(address.IsZero(), address.IsBroadcast(), address.IsMulticast(), address.IsUnicast(), address.IsLocallyAdministered(), address.IsUniversallyAdministered()), address.String(), fmt.Sprintf("%X", address), xnetip.MacHyphens(address).String(), fmt.Sprintf("%X", xnetip.MacHyphens(address)), xnetip.MacDots(address).String(), fmt.Sprintf("%X", xnetip.MacDots(address)), fmt.Sprintf("%016x", address.ToModifiedEUI64()), addressBits(address.ToIPv6LinkLocal())}
		case "mt":
			address, err := xnetip.ParseMacAddrASCII(decodeBytes(tokens[1]))
			if err != nil {
				writeLine(writer, "ERR")
			} else {
				writeLine(writer, address.String())
			}
			continue
		case "e":
			identifier, err := strconv.ParseUint(tokens[1], 16, 64)
			if err != nil {
				panic(err)
			}
			address, ok := xnetip.MacAddrFromModifiedEUI64(identifier)
			writeLine(writer, optionalMAC(address, ok))
			continue
		case "v4":
			writeLine(writer, optionalMAC(xnetip.MacAddrFromIPv4Multicast(address4(tokens[1]))))
			continue
		case "v6":
			writeLine(writer, optionalMAC(xnetip.MacAddrFromIPv6Multicast(address6(tokens[1]))))
			continue
		case "t":
			input := decodeBytes(tokens[1])
			network, err := xnetip.ParseNetwork(string(input))
			if err != nil {
				writeLine(writer, "ERR")
			} else {
				writeLine(writer, "OK|"+network.String())
			}
			continue
		case "p4":
			first, second := network4(tokens[1], tokens[2]), network4(tokens[3], tokens[4])
			diff, reverseDiff, forward, backward := []string{}, []string{}, []string{}, []string{}
			for value := range first.Difference(second) {
				diff = append(diff, format4(value))
			}
			for value := range first.DifferenceBackward(second) {
				reverseDiff = append(reverseDiff, format4(value))
			}
			for value := range first.Addrs() {
				forward = append(forward, fmt.Sprintf("%x", value.As4()))
				if len(forward) == 8 {
					break
				}
			}
			for value := range first.AddrsBackward() {
				backward = append(backward, fmt.Sprintf("%x", value.As4()))
				if len(backward) == 8 {
					break
				}
			}
			results = []string{format4(first), format4(second), formatBools(first.Contains(second), first.Intersects(second), first.IsDisjoint(second), first.IsAdjacent(second), first.IsAdjacentByLowestMaskBit(second)), optional4(first.Intersection(second)), optional4(first.Merge(second)), optional4(first.MergeByLowestMaskBit(second)), format4(first.SupernetFor([]xnetip.Network4{second})), format4(first.ToContiguous().Network()), strconv.Itoa(first.NumHostBits()), formatPrefix(first.PrefixLen()), strings.Join(diff, ","), strings.Join(forward, ","), strings.Join(backward, ","), format6(first.ToIPv6Mapped()), first.String(), strconv.FormatBool(first.Compare(second) < 0), addressBits(first.Hostmask()), optional4(first.Supernet()), strings.Join(reverseDiff, ",")}
		case "p6":
			first, second := network6(tokens[1], tokens[2]), network6(tokens[3], tokens[4])
			diff, reverseDiff, forward, backward := []string{}, []string{}, []string{}, []string{}
			for value := range first.Difference(second) {
				diff = append(diff, format6(value))
			}
			for value := range first.DifferenceBackward(second) {
				reverseDiff = append(reverseDiff, format6(value))
			}
			for value := range first.Addrs() {
				forward = append(forward, fmt.Sprintf("%x", value.As16()))
				if len(forward) == 8 {
					break
				}
			}
			for value := range first.AddrsBackward() {
				backward = append(backward, fmt.Sprintf("%x", value.As16()))
				if len(backward) == 8 {
					break
				}
			}
			results = []string{format6(first), format6(second), formatBools(first.Contains(second), first.Intersects(second), first.IsDisjoint(second), first.IsAdjacent(second), first.IsAdjacentByLowestMaskBit(second)), optional6(first.Intersection(second)), optional6(first.Merge(second)), optional6(first.MergeByLowestMaskBit(second)), format6(first.SupernetFor([]xnetip.Network6{second})), format6(first.ToContiguous().Network()), strconv.Itoa(first.NumHostBits()), formatPrefix(first.PrefixLen()), strings.Join(diff, ","), strings.Join(forward, ","), strings.Join(backward, ","), fmt.Sprintf("%t:%t:%s", first.IsBicontiguous(), first.IsIPv4MappedIPv6(), optional4(first.ToIPv4Mapped())), first.String(), strconv.FormatBool(first.Compare(second) < 0), addressBits(first.Hostmask()), optional6(first.Supernet()), strings.Join(reverseDiff, ",")}
		case "a4":
			networks := []xnetip.Network4{}
			for idx := 1; idx < len(tokens); idx += 2 {
				networks = append(networks, network4(tokens[idx], tokens[idx+1]))
			}
			for _, network := range xnetip.Aggregate4(networks) {
				results = append(results, format4(network))
			}
			writeLine(writer, strings.Join(results, ","))
			continue
		case "a6":
			networks := []xnetip.Network6{}
			for idx := 1; idx < len(tokens); idx += 2 {
				networks = append(networks, network6(tokens[idx], tokens[idx+1]))
			}
			for _, network := range xnetip.Aggregate6(networks) {
				results = append(results, format6(network))
			}
			writeLine(writer, strings.Join(results, ","))
			continue
		case "c4":
			networks := []xnetip.Contiguous[xnetip.Network4]{}
			for idx := 1; idx < len(tokens); idx += 2 {
				network, second := xnetip.ContiguousFrom(network4(tokens[idx], tokens[idx+1]))
				if !second {
					panic("bad")
				}
				networks = append(networks, network)
			}
			for _, network := range xnetip.AggregateContiguous(networks) {
				results = append(results, format4(network.Network()))
			}
			writeLine(writer, strings.Join(results, ","))
			continue
		case "c6":
			networks := []xnetip.Contiguous[xnetip.Network6]{}
			for idx := 1; idx < len(tokens); idx += 2 {
				network, second := xnetip.ContiguousFrom(network6(tokens[idx], tokens[idx+1]))
				if !second {
					panic("bad")
				}
				networks = append(networks, network)
			}
			for _, network := range xnetip.AggregateContiguous(networks) {
				results = append(results, format6(network.Network()))
			}
			writeLine(writer, strings.Join(results, ","))
			continue
		case "b6":
			networks := []xnetip.BiContiguous{}
			for idx := 1; idx < len(tokens); idx += 2 {
				network, second := xnetip.BiContiguousFrom6(network6(tokens[idx], tokens[idx+1]))
				if !second {
					panic("bad")
				}
				networks = append(networks, network)
			}
			for _, network := range xnetip.AggregateBiContiguous6(networks) {
				results = append(results, format6(network.Network()))
			}
			writeLine(writer, strings.Join(results, ","))
			continue
		case "r4":
			for network := range xnetip.RangeToNetworks4(address4(tokens[1]), address4(tokens[2])) {
				results = append(results, format4(network.Network()))
			}
			writeLine(writer, strings.Join(results, ","))
			continue
		case "r6":
			for network := range xnetip.RangeToNetworks6(address6(tokens[1]), address6(tokens[2])) {
				results = append(results, format6(network.Network()))
			}
			writeLine(writer, strings.Join(results, ","))
			continue
		default:
			panic("unknown operation: " + tokens[0])
		}
		writeLine(writer, strings.Join(results, "|"))
	}
	if err := scanner.Err(); err != nil {
		panic(err)
	}
}

// decodeBytes preserves empty text in the whitespace-delimited protocol.
func decodeBytes(input string) []byte {
	if input == "-" {
		return nil
	}
	bytes, err := hex.DecodeString(input)
	if err != nil {
		panic(err)
	}
	return bytes
}

func addressBits(address netip.Addr) string {
	if address.Is4() {
		return fmt.Sprintf("%x", address.As4())
	}
	return fmt.Sprintf("%x", address.As16())
}

func cursorSize(cursor *xnetip.AddrIterator) string {
	size, exact := cursor.SizeHint()
	return fmt.Sprintf("%d:%t", size, exact)
}

type (
	projected4 struct {
		network xnetip.Network4
		payload int
	}
	projected6 struct {
		network xnetip.Network6
		payload int
	}
)

func optionalMAC(address xnetip.MacAddr, ok bool) string {
	if !ok {
		return "-"
	}
	return fmt.Sprintf("%012x", address.Uint64())
}

// parseASCIIResults records success and token remainders for all families.
func parseASCIIResults(input []byte, token bool) []string {
	results := []string{}
	for _, family := range []int{4, 6, 0} {
		var text string
		var rest []byte
		var err error
		switch family {
		case 4:
			var network xnetip.Network4
			if token {
				network, rest, err = xnetip.ParseNextNetwork4ASCII(input)
			} else {
				network, err = xnetip.ParseNetwork4ASCII(input)
			}
			text = network.String()
		case 6:
			var network xnetip.Network6
			if token {
				network, rest, err = xnetip.ParseNextNetwork6ASCII(input)
			} else {
				network, err = xnetip.ParseNetwork6ASCII(input)
			}
			text = network.String()
		default:
			var network xnetip.Network
			if token {
				network, rest, err = xnetip.ParseNextNetworkASCII(input)
			} else {
				network, err = xnetip.ParseNetworkASCII(input)
			}
			text = network.String()
		}
		if err != nil {
			results = append(results, "ERR")
			continue
		}
		result := "OK|" + text
		if token {
			result += "|" + hex.EncodeToString(rest)
		}
		results = append(results, result)
	}
	return results
}
