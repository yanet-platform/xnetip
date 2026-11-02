# xnetip

[![CI](https://github.com/yanet-platform/xnetip/actions/workflows/ci.yml/badge.svg)](https://github.com/yanet-platform/xnetip/actions/workflows/ci.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/yanet-platform/xnetip.svg)](https://pkg.go.dev/github.com/yanet-platform/xnetip)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

IPv4 and IPv6 networks for Go with arbitrary subnet masks, exact set algebra,
lazy traversal and immutable EUI-48 MAC addresses. The implementation follows
Rust `netip` 0.4.0, with explicit Go API contracts described below.

```go
network := xnetip.MustParseNetwork4("10.0.0.0/255.0.255.0")

network.ContainsAddr(netip.MustParseAddr("10.7.0.9")) // true
network.ContainsAddr(netip.MustParseAddr("10.7.1.9")) // false
fmt.Println(network.LastAddr())                     // 10.255.0.255
```

## Install

```sh
go get github.com/yanet-platform/xnetip
```

Requires Go 1.24. Runtime code depends only on the standard library. The
`testify` and `rapid` dependencies in `go.mod` are used only by tests.
Examples below assume imports of `github.com/yanet-platform/xnetip`,
`net/netip`, and other standard packages as used.

## Networks and guarantees

| Type | Address family and mask |
|---|---|
| `Network4` | IPv4, any mask |
| `Network6` | IPv6, any mask |
| `Network` | Either family, preserved by set operations |
| `Contiguous[T]` | A network whose mask is one leading run of ones |
| `BiContiguous` | IPv6, one leading mask run per 64-bit half |
| `MacAddr` | Six Ethernet address octets |

Networks store normalized `(address, mask)` pairs: host bits are always
cleared. Values and guarantee wrappers are immutable, comparable map keys.
`Network4{}` is `0.0.0.0/0`; `Network6{}` and `Network{}` are `::/0`.
Wrapper zero values preserve those valid universe networks. `MacAddr{}`
is `00:00:00:00:00:00`.

`Contains`, `ContainsAddr`, `Intersection`, `Intersects`, `IsDisjoint`,
`IsAdjacent`, `Merge`, `Supernet` and `SupernetFor` work with arbitrary
masks. `Hostmask` returns the free bits. `Supernet` clears the lowest fixed
mask bit and fails on a universe network. `SupernetFor` keeps only bits fixed equally by every input, so its result
may be non-contiguous.

`Contiguous[T]` gives total `PrefixLen() int` and `Prefix() netip.Prefix`
access. Its typed intersection, parent and difference preserve the CIDR
guarantee. `BiContiguous` provides the corresponding guarantee for masks
used by site-by-subnet classifiers. Call a wrapper's `Network()` method
for operations that return a general network.

## Parsing and formatting

Parsers accept CIDR (`10.0.0.0/8`), explicit masks
(`10.0.0.0/255.0.255.0`) and bare addresses, which become host routes.
`ParseNetwork4`, `ParseNetwork6` and `ParseNetwork` accept strings.
`ParseNetwork4ASCII`, `ParseNetwork6ASCII` and `ParseNetworkASCII` parse
complete byte buffers without a string conversion or allocation on success.

The leading-token variants return the network and the unconsumed bytes:

```go
input := []byte("10.1.2.3/8 allow")
network, rest, err := xnetip.ParseNextNetworkASCII(input)
if err != nil {
	panic(err)
}
fmt.Println(network, string(rest)) // 10.0.0.0/8  allow
```

The remainder aliases the input slice. Networks retain no input, and errors
own the rejected text. Token parsers do not skip leading whitespace and
never shorten malformed tokens into valid ones. The IPv4-specific token
parser treats `:` as a delimiter: `1.2.3.4:80` leaves `:80`. The dual-family
and IPv6 parsers include `:` in the token alphabet and reject that input.

Prefix lengths contain decimal digits, with no sign and no leading zero
except `0` itself. Complete network text parsers reject zones. Errors wrap
sentinels such as `ErrCIDROverflow`, `ErrInvalidMask` and
`ErrNonContiguousMask` for use with `errors.Is`.

`String`, `AppendTo`, `MarshalText` and `UnmarshalText` use round-trippable
canonical text. Contiguous networks print as `addr/prefix`, others as
`addr/mask`. `Compact(network)` renders a host route as a bare address.
Text decoding allocates no storage on success, leaves the receiver unchanged
on failure, and rejects empty text instead of silently choosing a universe.

## Traversal and subnets

`Addrs` and `AddrsBackward` return re-iterable `iter.Seq[netip.Addr]`
streams. `Difference` yields the pairwise-disjoint networks covering the
source without the exclusion. `DifferenceBackward` yields exactly those
parts in the opposite order. All streams support early exit without
materializing their contents, including on guarantee wrappers.

For resumable address traversal, call `AddrIterator()` on a network or
wrapper. Both ends of the cursor share one remaining range:

```go
cursor := xnetip.MustParseNetwork4("192.0.2.0/29").AddrIterator()
first, _ := cursor.Next()      // 192.0.2.0
last, _ := cursor.NextBack()   // 192.0.2.7
fourth, _ := cursor.Nth(2)     // skip .1 and .2, consume .3
sixth, _ := cursor.NthBack(1)  // skip .6, consume .5
remaining, exact := cursor.SizeHint() // 1, true: only .4 remains
fmt.Println(first, last, fourth, sixth, remaining, exact)
```

`Nth` and `NthBack` take a `uint64` skip count and consume the selected
address. Skipping past the end exhausts the cursor. Copying a cursor creates
an independent snapshot; its zero value is exhausted. `SizeHint` returns
an exact `uint64` count when possible, otherwise `math.MaxUint64, false`.
`NumHostBits` gives the exact exponent of the address count even for `2^128`.

`Network4` and `Network6` also partition themselves into subnets. `Subnets`
takes an arbitrary mask that preserves every bit fixed by the parent.
Each combination of newly fixed bits appears once, in ascending address
order:

```go
for part := range (xnetip.Network4{}).Subnets(netip.MustParseAddr("0.0.0.1")) {
	fmt.Println(part)
}
// 0.0.0.0/0.0.0.1 — all even addresses
// 0.0.0.1/0.0.0.1 — all odd addresses
```

`SubnetsWithPrefix(prefix)` yields `Contiguous[Network4]` or
`Contiguous[Network6]` blocks. A non-contiguous parent can split into CIDRs
once the requested prefix covers all of its fixed bits. Both methods return
a single sequence, with no separate success flag: invalid masks, foreign
families, out-of-range prefixes or dropped parent bits yield an empty
sequence. IPv6 mask zones are dropped, as in checked constructors.
`SubnetsBackward` and `SubnetsWithPrefixBackward` reverse the corresponding
subnet sequence. These four methods belong to the concrete network types;
wrappers expose their underlying network through `Network()`.

## Collection algorithms

`Aggregate4` and `Aggregate6` collapse slices in place through duplicate
removal, containment and arbitrary-mask merges until no pair can merge.
`AggregateBiContiguous6` keeps every result bi-contiguous and continues until
no permitted class-preserving merge remains. These algorithms preserve the
exact union without promising a globally minimum cover for arbitrary masks.
`AggregateContiguous` produces the minimal CIDR cover and accepts all three
`Contiguous` instantiations.

```go
networks := []xnetip.Network4{
	xnetip.MustParseNetwork4("10.0.0.0/24"),
	xnetip.MustParseNetwork4("10.0.2.0/24"),
}
networks = xnetip.Aggregate4(networks)
fmt.Println(networks) // [10.0.0.0/255.255.253.0]
```

`RangeToNetworks4(first, last)` and `RangeToNetworks6(first, last)` lazily
produce the minimum CIDR cover of an inclusive address interval, in ascending
order. Invalid families or reversed endpoints produce an empty sequence.

`BinarySplit4` and `BinarySplit6` choose a narrow supernet covering at least
half a sorted slice, then gather exactly the elements it contains into one
block. A projection selects the network from any payload type:

```go
type Rule struct {
	Network xnetip.Network4
	Action  string
}
rules := []Rule{
	{xnetip.MustParseNetwork4("127.0.0.1"), "allow"},
	{xnetip.MustParseNetwork4("127.0.0.2"), "log"},
	{xnetip.MustParseNetwork4("127.0.0.3"), "deny"},
}
parent, selected, ok := xnetip.BinarySplit4(rules, func(rule Rule) xnetip.Network4 {
	return rule.Network
})
if ok {
	fmt.Println(parent, selected) // 127.0.0.2/31 {1 3}
	group := rules[selected.Start:selected.End]
	fmt.Println(len(group)) // 2
}
```

Inputs must be sorted by the projected network's `Compare` order. Candidates
are the full-slice supernet followed by every window of `ceil(N/2)` elements;
the first with the largest numeric mask wins. The result may be
non-contiguous. `IndexRange` is half-open and starts at the original first
contained element. Both selected and remaining elements retain their
relative order and payloads. Fewer than three elements or a nil projection
return `ok=false` without mutation. Search takes O(N) time; gathering takes
O(N log N) moves and O(log N) stack space, without scratch allocation.

## MAC addresses

`MacAddr` parses colon, hyphen and Cisco dotted forms, case-insensitively.
Default output is lowercase with colons. `MacHyphens` and `MacDots` are
formatting adapters; `%X` selects uppercase. Values support `As6`, `Uint64`,
checked integer construction, comparisons, text marshaling, and unicast,
multicast, broadcast and administration-bit predicates.

```go
mac := xnetip.MustParseMacAddr("00:11:22:33:44:55")
fmt.Println(xnetip.MacHyphens(mac)) // 00-11-22-33-44-55
fmt.Println(xnetip.MacDots(mac))    // 0011.2233.4455

identifier := mac.ToModifiedEUI64()
restored, ok := xnetip.MacAddrFromModifiedEUI64(identifier)
fmt.Println(ok && restored == mac) // true
fmt.Println(mac.ToIPv6LinkLocal()) // fe80::211:22ff:fe33:4455

group, ok := xnetip.MacAddrFromIPv4Multicast(netip.MustParseAddr("239.1.2.3"))
fmt.Println(group, ok) // 01:00:5e:01:02:03 true
```

`MacAddrFromIPv6Multicast` maps an IPv6 group to `33:33` plus its last
four octets. Multicast constructors reject invalid or foreign-family inputs.
IPv4-mapped IPv6 is not treated as native IPv4 or as an IPv6 multicast group.
`ParseMacAddrASCII` and successful MAC text decoding allocate no storage.

## Go and Rust compatibility

The address-set operations follow Rust `netip` 0.4.0, pinned in
[`tools/parity/rust-revision`](tools/parity/rust-revision). The port retains
these deliberate Go contracts:

| Area | Go contract |
|---|---|
| Prefix text | Rejects `+8` and `008`; Rust accepts them. String and ASCII parsers agree. |
| IP representation | Public inputs and outputs are `netip.Addr`; network integer `FromBits`/`ToBits` APIs are intentionally absent. |
| Address families | IPv4-mapped literals remain IPv6. Mapped conversion and canonicalization are explicit. |
| Mixed-family difference | `Network.Difference` and its reverse yield the source once. |
| Mixed-family supernet | `Network.SupernetFor` returns `ok=false`; no network spans both families. |
| Mixed-family CIDR aggregation | `AggregateContiguous[Network]` keeps both families and aggregates each independently. |
| Invalid subnet requests | Return an empty sequence instead of Rust's `None`. |
| Iteration | Go exposes `iter.Seq` streams and an address cursor, not a copy of every Rust iterator type or trait. |
| Platform guarantees | Rust has `no_std`, `const fn` and Lean proofs; Go uses the Go runtime and does not inherit those guarantees. |

Zero network values remain valid universes. An invalid zero `netip.Addr`
is still rejected by checked constructors. String parsers reject zones;
checked IPv6 constructors discard them. Different families do not contain or
intersect each other, and cannot be merged.

The [parity runner](tools/parity/README.md) compares shared deterministic
corpora against the pinned Rust source. Exact grammar exceptions are recorded
in [`contracts.json`](tools/parity/contracts.json). Language-specific error
messages are not compared. Property tests and fuzz targets additionally check
set invariants, text round trips and standard-library interoperability.

## Runtime guarantees

- Standard library only, with no unsafe, cgo or reflection in runtime code.
- Set operations, traversal and successful parsing/text decoding allocate no
  storage. `AppendTo` reuses caller capacity; `String` and `MarshalText`
  allocate their results, and errors may allocate owned diagnostics.
- IPv4 and IPv6 use matching algorithms and case analysis. Hot paths have
  `testing.AllocsPerRun` checks, with CI tests, race detection and Rust parity.

The full API is documented on
[pkg.go.dev](https://pkg.go.dev/github.com/yanet-platform/xnetip).

## License

Apache 2.0, see [LICENSE](LICENSE).
