# xnetip

[![CI](https://github.com/yanet-platform/xnetip/actions/workflows/ci.yml/badge.svg)](https://github.com/yanet-platform/xnetip/actions/workflows/ci.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/yanet-platform/xnetip.svg)](https://pkg.go.dev/github.com/yanet-platform/xnetip)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

IPv4 and IPv6 network types for Go: `(address, mask)` pairs with
first-class non-contiguous masks and full set algebra.

```go
// A mask net/netip cannot express — and every operation stays correct on it.
n := xnetip.MustParseNetwork4("10.0.0.0/255.0.255.0")

n.ContainsAddr(netip.MustParseAddr("10.7.0.9")) // true
n.ContainsAddr(netip.MustParseAddr("10.7.1.9")) // false
fmt.Println(n.LastAddr())                       // 10.255.0.255
```

## Install

```sh
go get github.com/yanet-platform/xnetip
```

Requires Go 1.24. The runtime code depends only on the standard library —
the test dependencies in `go.mod` (testify, rapid) are never pulled into
your build.

## Overview

- **Three network types.** `Network4` and `Network6` are `(address, mask)`
  pairs where the mask is any bit pattern; `Network` holds either family.
  Values are small, immutable and always normalized
  (`addr & mask == addr`); the zero values are valid networks
  (`0.0.0.0/0`, `::/0`).
- **Set algebra, correct on any mask.** `Contains`, `ContainsAddr`,
  `Intersection`, `Intersects`, `IsDisjoint`, `IsAdjacent`, `Merge`,
  `SupernetFor` and `Difference`, which carves one network out of another
  into exact, pairwise-disjoint pieces.
- **`Contiguous[T]` — CIDR guaranteed by the type.** A wrapper whose mask
  is a leading run of ones by construction: `PrefixLen() int` and
  `Prefix() netip.Prefix` become total, `Intersection` and `Difference`
  stay closed over the class, and its parsers reject non-contiguous input
  with `ErrNonContiguousMask`.
- **Collections.** `Aggregate4`/`Aggregate6` fold a slice in place using
  non-contiguous merges, `AggregateContiguous` computes a minimal CIDR
  cover, `RangeToNetworks4`/`RangeToNetworks6` turn an arbitrary address
  range into the minimal list of CIDR blocks.
- **Iteration.** `Addrs` and `AddrsBackward` as `iter.Seq[netip.Addr]`,
  `NumHostBits` for the exact address count.
- **Text.** `String`, `AppendTo`, `MarshalText`/`UnmarshalText`: a
  contiguous network prints as `addr/prefix`, a non-contiguous one as
  `addr/mask`, and both forms parse back. `Compact` renders host routes as
  a bare address. Parsing is strict: `net/netip` digit rules, no leading
  zeros in the prefix length, zones rejected.
- **`net/netip` interop.** Plain zone-free `netip.Addr` is the address
  currency of the whole API, `Contiguous` converts to and from
  `netip.Prefix`, and wherever an operation has a `net/netip` analogue it
  keeps the analogue's name and semantics.

## Why not net/netip

`net/netip` models a network as `netip.Prefix` — an address plus a prefix
length — which can only express a mask that is a run of leading ones, and
stops at membership tests. `xnetip` complements it where that is not
enough:

| | `net/netip` | `xnetip` |
|---|---|---|
| Network model | address + prefix length, contiguous masks only | `(address, mask)`, any mask |
| Notation | `10.0.0.0/8` | `10.0.0.0/8` and `10.0.0.0/255.0.255.0` |
| Set algebra | `Contains`, `Overlaps` | containment, intersection, difference, merge, adjacency, supernet |
| Slice operations | — | aggregation, range → CIDR list |
| Address iteration | `Addr.Next`/`Prev` | `iter.Seq[netip.Addr]`, both directions |

## Examples

**Address range → minimal CIDR list.**

```go
first := netip.MustParseAddr("10.0.0.1")
last := netip.MustParseAddr("10.0.0.30")
for block := range xnetip.RangeToNetworks4(first, last) {
	fmt.Println(block)
}
// 10.0.0.1/32  10.0.0.2/31  10.0.0.4/30  10.0.0.8/29
// 10.0.0.16/29 10.0.0.24/30 10.0.0.28/31 10.0.0.30/32
```

**Aggregation beyond CIDR.** Non-contiguous merges collapse networks that
no CIDR aggregator can combine — here two /25s fold into a /24, which then
merges with a non-adjacent /24 across the gap:

```go
nets := []xnetip.Network4{
	xnetip.MustParseNetwork4("10.0.0.0/24"),
	xnetip.MustParseNetwork4("10.0.1.0/25"),
	xnetip.MustParseNetwork4("10.0.4.0/25"),
	xnetip.MustParseNetwork4("10.0.4.128/25"),
}
nets = xnetip.Aggregate4(nets) // in place, no allocation
// [10.0.1.0/25 10.0.0.0/255.255.251.0]
```

**Carving a block out of another.** `Difference` yields exact,
pairwise-disjoint remainders — on CIDR blocks, the classic prefix ladder:

```go
outer := xnetip.MustParseContiguous4("10.0.0.0/16")
inner := xnetip.MustParseContiguous4("10.0.4.0/22")
for block := range outer.Difference(inner) {
	fmt.Println(block)
}
// 10.0.128.0/17 10.0.64.0/18 10.0.32.0/19
// 10.0.16.0/20  10.0.8.0/21  10.0.0.0/22
```

The full API is documented on
[pkg.go.dev](https://pkg.go.dev/github.com/yanet-platform/xnetip).

## Guarantees

- Operations do not allocate — the exceptions are `String`/`MarshalText`
  results and error construction — and hot paths are pinned by
  `testing.AllocsPerRun` tests.
- No `unsafe`, no cgo, no reflection.
- IPv4 and IPv6 take the same algorithm through every operation; behavior
  never diverges between families.
- Tested with property-based checks (differential against `net/netip`
  where an oracle exists) and fuzzed parsers.

## License

Apache 2.0, see [LICENSE](LICENSE).
