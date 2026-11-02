package main

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"net/netip"
	"os"
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
		case "t":
			input, err := hex.DecodeString(tokens[1])
			if err != nil {
				panic(err)
			}
			network, err := xnetip.ParseNetwork(string(input))
			if err != nil {
				writeLine(writer, "ERR")
			} else {
				writeLine(writer, "OK|"+network.String())
			}
			continue
		case "p4":
			first, second := network4(tokens[1], tokens[2]), network4(tokens[3], tokens[4])
			diff, forward, backward := []string{}, []string{}, []string{}
			for value := range first.Difference(second) {
				diff = append(diff, format4(value))
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
			results = []string{format4(first), format4(second), formatBools(first.Contains(second), first.Intersects(second), first.IsDisjoint(second), first.IsAdjacent(second), first.IsAdjacentByLowestMaskBit(second)), optional4(first.Intersection(second)), optional4(first.Merge(second)), optional4(first.MergeByLowestMaskBit(second)), format4(first.SupernetFor([]xnetip.Network4{second})), format4(first.ToContiguous().Network()), strconv.Itoa(first.NumHostBits()), formatPrefix(first.PrefixLen()), strings.Join(diff, ","), strings.Join(forward, ","), strings.Join(backward, ","), format6(first.ToIPv6Mapped()), first.String(), strconv.FormatBool(first.Compare(second) < 0)}
		case "p6":
			first, second := network6(tokens[1], tokens[2]), network6(tokens[3], tokens[4])
			diff, forward, backward := []string{}, []string{}, []string{}
			for value := range first.Difference(second) {
				diff = append(diff, format6(value))
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
			results = []string{format6(first), format6(second), formatBools(first.Contains(second), first.Intersects(second), first.IsDisjoint(second), first.IsAdjacent(second), first.IsAdjacentByLowestMaskBit(second)), optional6(first.Intersection(second)), optional6(first.Merge(second)), optional6(first.MergeByLowestMaskBit(second)), format6(first.SupernetFor([]xnetip.Network6{second})), format6(first.ToContiguous().Network()), strconv.Itoa(first.NumHostBits()), formatPrefix(first.PrefixLen()), strings.Join(diff, ","), strings.Join(forward, ","), strings.Join(backward, ","), fmt.Sprintf("%t:%t:%s", first.IsBicontiguous(), first.IsIPv4MappedIPv6(), optional4(first.ToIPv4Mapped())), first.String(), strconv.FormatBool(first.Compare(second) < 0)}
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
