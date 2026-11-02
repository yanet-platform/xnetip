package xnetip_test

import (
	"net/netip"
	"slices"
	"strconv"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/yanet-platform/xnetip"
	"pgregory.net/rapid"
)

// verifies that fewer than three inputs and nil projections never mutate input.
func Test_BinarySplit_InsufficientInput(t *testing.T) {
	for count := range 3 {
		networks4 := []xnetip.Network4{xnetip.MustParseNetwork4("127.0.0.1"), xnetip.MustParseNetwork4("127.0.0.2")}[:count]
		before4 := slices.Clone(networks4)
		_, selected4, ok := xnetip.BinarySplit4(networks4, func(network xnetip.Network4) xnetip.Network4 { return network })
		require.False(t, ok)
		require.Equal(t, xnetip.IndexRange{}, selected4)
		require.Equal(t, before4, networks4)
		networks6 := []xnetip.Network6{xnetip.MustParseNetwork6("::1"), xnetip.MustParseNetwork6("::2")}[:count]
		before6 := slices.Clone(networks6)
		_, selected6, ok := xnetip.BinarySplit6(networks6, func(network xnetip.Network6) xnetip.Network6 { return network })
		require.False(t, ok)
		require.Equal(t, xnetip.IndexRange{}, selected6)
		require.Equal(t, before6, networks6)
	}
	networks4 := []xnetip.Network4{{}, {}, {}}
	_, _, ok := xnetip.BinarySplit4(networks4, nil)
	require.False(t, ok)
	require.Equal(t, []xnetip.Network4{{}, {}, {}}, networks4)
	networks6 := []xnetip.Network6{{}, {}, {}}
	_, _, ok = xnetip.BinarySplit6(networks6, nil)
	require.False(t, ok)
	require.Equal(t, []xnetip.Network6{{}, {}, {}}, networks6)
}

// verifies that first maximum-mask candidates and the exact gathered blocks match.
func Test_BinarySplit_CandidateAndGather(t *testing.T) {
	cases := []struct {
		name, candidate string
		input, want     []string
		selected        xnetip.IndexRange
	}{
		{name: "three host routes", input: []string{"127.0.0.1", "127.0.0.2", "127.0.0.3"}, candidate: "127.0.0.2/31", selected: xnetip.IndexRange{Start: 1, End: 3}},
		{name: "first maximum mask wins", input: []string{"10.0.0.0/16", "10.0.0.0/16", "10.0.0.0/16", "10.1.0.0/16", "10.1.0.0/16", "10.1.0.0/16"}, candidate: "10.0.0.0/16", selected: xnetip.IndexRange{Start: 0, End: 3}},
		{name: "whole slice remains best", input: []string{"192.168.1.0/24", "192.168.1.0/24", "192.168.1.0/24"}, candidate: "192.168.1.0/24", selected: xnetip.IndexRange{Start: 0, End: 3}},
		{name: "two-run masks absorb additional input", input: []string{"10.1.0.5/255.255.0.255", "10.1.0.5/255.255.0.255", "10.1.7.5/255.255.0.255", "10.2.0.9/255.0.255.255"}, candidate: "10.1.0.5/255.255.0.255", selected: xnetip.IndexRange{Start: 0, End: 3}},
		{name: "expired counter exposes narrower mask", input: []string{"10.128.0.0/24", "10.0.0.0/24", "10.0.1.0/24", "10.0.3.0/24", "200.0.0.0/8"}, candidate: "10.0.0.0/22", selected: xnetip.IndexRange{Start: 1, End: 4}},
		{
			name:      "nonconsecutive contained networks gather stably",
			input:     []string{"10.0.0.4/32", "10.0.0.6/31", "10.0.0.12/31", "10.0.0.20/31", "10.0.0.25/32", "10.0.0.28/30", "10.0.0.56/30"},
			want:      []string{"10.0.0.4/32", "10.0.0.6/31", "10.0.0.12/31", "10.0.0.20/31", "10.0.0.28/30", "10.0.0.25/32", "10.0.0.56/30"},
			candidate: "10.0.0.4/255.255.255.228", selected: xnetip.IndexRange{Start: 0, End: 5},
		},
		{
			name:      "gather retains the rejected prefix",
			input:     []string{"10.0.0.6/255.255.255.159", "10.0.0.32/255.255.255.113", "10.0.0.64/255.255.255.64", "10.0.0.65/255.255.255.67", "10.0.0.65/255.255.255.213", "10.0.0.72/255.255.255.107", "10.0.0.97/255.255.255.97", "10.0.0.128/255.255.255.144", "10.0.0.220/255.255.255.222"},
			want:      []string{"10.0.0.6/255.255.255.159", "10.0.0.32/255.255.255.113", "10.0.0.64/255.255.255.64", "10.0.0.65/255.255.255.67", "10.0.0.65/255.255.255.213", "10.0.0.72/255.255.255.107", "10.0.0.97/255.255.255.97", "10.0.0.220/255.255.255.222", "10.0.0.128/255.255.255.144"},
			candidate: "10.0.0.64/255.255.255.64", selected: xnetip.IndexRange{Start: 2, End: 8},
		},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			var networks4 []xnetip.Network4
			var networks6 []xnetip.Network6
			for _, text := range testCase.input {
				network := xnetip.MustParseNetwork4(text)
				networks4 = append(networks4, network)
				networks6 = append(networks6, network.ToIPv6Mapped())
			}
			want4, want6 := slices.Clone(networks4), slices.Clone(networks6)
			if testCase.want != nil {
				for idx, text := range testCase.want {
					want4[idx] = xnetip.MustParseNetwork4(text)
					want6[idx] = want4[idx].ToIPv6Mapped()
				}
			}
			candidate4, selected4, ok := xnetip.BinarySplit4(networks4, func(network xnetip.Network4) xnetip.Network4 { return network })
			require.True(t, ok)
			require.Equal(t, xnetip.MustParseNetwork4(testCase.candidate), candidate4)
			require.Equal(t, testCase.selected, selected4)
			require.Equal(t, want4, networks4)
			candidate6, selected6, ok := xnetip.BinarySplit6(networks6, func(network xnetip.Network6) xnetip.Network6 { return network })
			require.True(t, ok)
			require.Equal(t, candidate4.ToIPv6Mapped(), candidate6)
			require.Equal(t, testCase.selected, selected6)
			require.Equal(t, want6, networks6)
		})
	}
}

// verifies that native IPv6 masks can select a block across both word halves.
func Test_BinarySplit6_NativeNonContiguous(t *testing.T) {
	var networks []xnetip.Network6
	for _, text := range []string{
		"2a02:6b8:c00::4510:0:0/ffff:ffff:ff00::ffff:ffff:0:0",
		"2a02:6b8:c00::4511:0:0/ffff:ffff:ff00::ffff:ffff:0:0",
		"2a02:6b8:c00::4512:0:0/ffff:ffff:ff00::ffff:ffff:0:0",
		"2a02:6b8:c00::4513:0:0/ffff:ffff:ff00::ffff:ffff:0:0",
		"2a02:6b8:c00::4514:0:0/ffff:ffff:ff00::ffff:ffff:0:0",
		"2a02:6b8:c00::4515:0:0/ffff:ffff:ff00::ffff:ffff:0:0",
		"2a02:6b8:c00::4516:0:0/ffff:ffff:ff00::ffff:ffff:0:0",
		"2a02:6b8:c00::4517:0:0/ffff:ffff:ff00::ffff:ffff:0:0",
		"2a02:6b8:c00::4518:0:0/ffff:ffff:ff00::ffff:ffff:0:0",
		"2a02:6b8:c00::4519:0:0/ffff:ffff:ff00::ffff:ffff:0:0",
		"2a02:6b8:c00::451a:0:0/ffff:ffff:ff00::ffff:ffff:0:0",
	} {
		networks = append(networks, xnetip.MustParseNetwork6(text))
	}
	candidate, selected, ok := xnetip.BinarySplit6(networks, func(network xnetip.Network6) xnetip.Network6 { return network })
	require.True(t, ok)
	require.Equal(t, xnetip.MustParseNetwork6("2a02:6b8:c00::4510:0:0/ffff:ffff:ff00:0:ffff:fff8::"), candidate)
	require.Equal(t, xnetip.IndexRange{Start: 0, End: 8}, selected)
}

// splitPayload4 carries a network and an independently preserved identity.
type splitPayload4 struct {
	network  xnetip.Network4
	identity int
}

// splitPayload6 carries a network and an independently preserved identity.
type splitPayload6 struct {
	network  xnetip.Network6
	identity int
}

// verifies that arbitrary-mask candidate search agrees with an independent oracle.
func Test_BinarySplit4_OracleAndPayloadProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		networks := rapid.SliceOfN(genNetwork4, 3, 70).Draw(t, "networks")
		slices.SortFunc(networks, xnetip.Network4.Compare)
		var payloads []splitPayload4
		for idx, network := range networks {
			payloads = append(payloads, splitPayload4{network: network, identity: idx})
		}
		before := slices.Clone(payloads)
		want := splitReference4(t, networks)
		candidate, selected, ok := xnetip.BinarySplit4(payloads, func(payload splitPayload4) xnetip.Network4 { return payload.network })
		require.True(t, ok)
		require.Equal(t, want, candidate)
		var accepted, rejected []splitPayload4
		start := -1
		for idx, payload := range before {
			if candidate.Contains(payload.network) {
				if start < 0 {
					start = idx
				}
				accepted = append(accepted, payload)
			} else {
				rejected = append(rejected, payload)
			}
		}
		require.GreaterOrEqual(t, len(accepted), (len(payloads)+1)/2)
		require.Equal(t, xnetip.IndexRange{Start: start, End: start + len(accepted)}, selected)
		expected := append(slices.Clone(rejected[:start]), accepted...)
		expected = append(expected, rejected[start:]...)
		require.Equal(t, expected, payloads)
	})
}

// splitReference4 checks every candidate through byte-wise set constraints.
func splitReference4(t require.TestingT, networks []xnetip.Network4) xnetip.Network4 {
	cover := func(window []xnetip.Network4) xnetip.Network4 {
		address := window[0].Addr().As4()
		mask := [4]byte{255, 255, 255, 255}
		for _, network := range window {
			currentAddress, currentMask := network.Addr().As4(), network.Mask().As4()
			for idx := range mask {
				mask[idx] &= currentMask[idx] & ^(address[idx] ^ currentAddress[idx])
			}
		}
		network, err := xnetip.Network4From(netip.AddrFrom4(address), netip.AddrFrom4(mask))
		require.NoError(t, err)
		return network
	}
	candidate := cover(networks)
	width := (len(networks) + 1) / 2
	for idx := 0; idx+width <= len(networks); idx++ {
		window := cover(networks[idx : idx+width])
		if window.Mask().Compare(candidate.Mask()) > 0 {
			candidate = window
		}
	}
	return candidate
}

// verifies that native IPv6 candidate search preserves stable payload groups.
func Test_BinarySplit6_OracleAndPayloadProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		networks := rapid.SliceOfN(genNetwork6, 3, 70).Draw(t, "networks")
		slices.SortFunc(networks, xnetip.Network6.Compare)
		var payloads []splitPayload6
		for idx, network := range networks {
			payloads = append(payloads, splitPayload6{network: network, identity: idx})
		}
		before := slices.Clone(payloads)
		want := splitReference6(t, networks)
		candidate, selected, ok := xnetip.BinarySplit6(payloads, func(payload splitPayload6) xnetip.Network6 { return payload.network })
		require.True(t, ok)
		require.Equal(t, want, candidate)
		var accepted, rejected []splitPayload6
		start := -1
		for idx, payload := range before {
			if candidate.Contains(payload.network) {
				if start < 0 {
					start = idx
				}
				accepted = append(accepted, payload)
			} else {
				rejected = append(rejected, payload)
			}
		}
		require.GreaterOrEqual(t, len(accepted), (len(payloads)+1)/2)
		require.Equal(t, xnetip.IndexRange{Start: start, End: start + len(accepted)}, selected)
		expected := append(slices.Clone(rejected[:start]), accepted...)
		expected = append(expected, rejected[start:]...)
		require.Equal(t, expected, payloads)
	})
}

// splitReference6 checks every candidate through byte-wise set constraints.
func splitReference6(t require.TestingT, networks []xnetip.Network6) xnetip.Network6 {
	cover := func(window []xnetip.Network6) xnetip.Network6 {
		address := window[0].Addr().As16()
		var mask [16]byte
		for idx := range mask {
			mask[idx] = 255
		}
		for _, network := range window {
			currentAddress, currentMask := network.Addr().As16(), network.Mask().As16()
			for idx := range mask {
				mask[idx] &= currentMask[idx] & ^(address[idx] ^ currentAddress[idx])
			}
		}
		network, err := xnetip.Network6From(netip.AddrFrom16(address), netip.AddrFrom16(mask))
		require.NoError(t, err)
		return network
	}
	candidate := cover(networks)
	width := (len(networks) + 1) / 2
	for idx := 0; idx+width <= len(networks); idx++ {
		window := cover(networks[idx : idx+width])
		if window.Mask().Compare(candidate.Mask()) > 0 {
			candidate = window
		}
	}
	return candidate
}

// verifies that searching and stable gathering allocate no auxiliary storage.
func Test_BinarySplit_AllocationFree(t *testing.T) {
	for _, count := range []int{3, 7, 24, 56, 256} {
		before4 := splitFixture4(count, false)
		before6 := splitFixture6(count, false)
		buffer4, buffer6 := slices.Clone(before4), slices.Clone(before6)
		requireNoAllocs(t, func() {
			copy(buffer4, before4)
			network, selected, ok := xnetip.BinarySplit4(buffer4, func(network xnetip.Network4) xnetip.Network4 { return network })
			networkSink, intSink, okSink = network, selected.End, ok
		})
		requireNoAllocs(t, func() {
			copy(buffer6, before6)
			network, selected, ok := xnetip.BinarySplit6(buffer6, func(network xnetip.Network6) xnetip.Network6 { return network })
			network6Sink, intSink, okSink = network, selected.End, ok
		})
	}
	var payloads []splitPayload4
	for idx, text := range []string{"10.0.0.4/32", "10.0.0.6/31", "10.0.0.12/31", "10.0.0.20/31", "10.0.0.25/32", "10.0.0.28/30", "10.0.0.56/30"} {
		payloads = append(payloads, splitPayload4{network: xnetip.MustParseNetwork4(text), identity: idx})
	}
	before := slices.Clone(payloads)
	requireNoAllocs(t, func() {
		copy(payloads, before)
		network, selected, ok := xnetip.BinarySplit4(payloads, func(payload splitPayload4) xnetip.Network4 { return payload.network })
		networkSink, intSink, okSink = network, selected.End, ok
	})
}

// splitFixture4 generates sorted disjoint IPv4 networks with a shared mask.
func splitFixture4(count int, nonContiguous bool) []xnetip.Network4 {
	networks := make([]xnetip.Network4, count)
	for idx := range networks {
		suffix := "/24"
		if nonContiguous {
			suffix = "/255.255.255.85"
		}
		networks[idx] = xnetip.MustParseNetwork4("10.0." + strconv.Itoa(idx) + ".0" + suffix)
	}
	return networks
}

// splitFixture6 generates sorted disjoint IPv6 networks spanning both halves.
func splitFixture6(count int, nonContiguous bool) []xnetip.Network6 {
	networks := make([]xnetip.Network6, count)
	for idx := range networks {
		suffix := "/120"
		if nonContiguous {
			suffix = "/ffff:ffff:ffff:fffe:7fff:ffff:ffff:ff55"
		}
		networks[idx] = xnetip.MustParseNetwork6("2001:db8::" + strconv.FormatInt(int64(idx*256), 16) + suffix)
	}
	return networks
}

func BenchmarkBinarySplit4(b *testing.B) {
	for _, count := range []int{3, 64, 256} {
		for _, nonContiguous := range []bool{false, true} {
			shape := "contiguous"
			if nonContiguous {
				shape = "noncontiguous"
			}
			b.Run(shape+"/"+strconv.Itoa(count), func(b *testing.B) {
				original := splitFixture4(count, nonContiguous)
				networks := slices.Clone(original)
				b.ReportAllocs()
				for b.Loop() {
					copy(networks, original)
					network, selected, ok := xnetip.BinarySplit4(networks, func(network xnetip.Network4) xnetip.Network4 { return network })
					networkSink, intSink, okSink = network, selected.End, ok
				}
			})
		}
	}
}

func BenchmarkBinarySplit6(b *testing.B) {
	for _, count := range []int{3, 64, 256} {
		for _, nonContiguous := range []bool{false, true} {
			shape := "contiguous"
			if nonContiguous {
				shape = "noncontiguous"
			}
			b.Run(shape+"/"+strconv.Itoa(count), func(b *testing.B) {
				original := splitFixture6(count, nonContiguous)
				networks := slices.Clone(original)
				b.ReportAllocs()
				for b.Loop() {
					copy(networks, original)
					network, selected, ok := xnetip.BinarySplit6(networks, func(network xnetip.Network6) xnetip.Network6 { return network })
					network6Sink, intSink, okSink = network, selected.End, ok
				}
			})
		}
	}
}
