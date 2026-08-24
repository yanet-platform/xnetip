# xnetip

[![CI](https://github.com/yanet-platform/xnetip/actions/workflows/ci.yml/badge.svg)](https://github.com/yanet-platform/xnetip/actions/workflows/ci.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/yanet-platform/xnetip.svg)](https://pkg.go.dev/github.com/yanet-platform/xnetip)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

IPv4 and IPv6 network types for Go: `(addr, mask)` pairs with
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

- **Three network types**

  Use `Network4` or `Network6` when the family is known. Their method
  signatures prevent mixing IPv4 and IPv6 networks. Use `Network` when one
  value must hold either family. All three store normalized `(addr, mask)`
  pairs with arbitrary bit masks, giving each masked set a canonical
  representation.

- **Map keys**

  Network types and guarantee wrappers are immutable, comparable values.
  Use them directly as `map` keys for indexing, deduplication and map-backed
  sets without converting networks to strings.

- **Valid zero values**

  `Network4{}` represents `0.0.0.0/0`. `Network6{}` and `Network{}`
  represent `::/0`. Guarantee wrappers preserve those universe values, so
  zero-initialized fields need no constructor or validity check.

- **Set algebra on any mask**

  `Contains`, `ContainsAddr`, `Intersection`, `Intersects`, `IsDisjoint`,
  `IsAdjacent`, `Merge`, `SupernetFor` and `Difference` manipulate masked
  sets exactly. They avoid enumerating individual members or approximating
  a non-contiguous set with CIDRs.

- **CIDR guarantee**

  `Contiguous[T]` proves that the mask is a leading run of ones. Use it at
  boundaries that require CIDRs. Once constructed, `PrefixLen() int` and
  `Prefix() netip.Prefix` are total, `Intersection` and `Difference` stay
  closed over the class, and parsers reject non-contiguous input with
  `ErrNonContiguousMask`.

- **Collection algorithms**

  `Aggregate4` and `Aggregate6` fold slices in place using non-contiguous
  merges. `AggregateContiguous` computes a minimal CIDR cover.
  `RangeToNetworks4` and `RangeToNetworks6` turn an arbitrary IP range into
  the minimal list of CIDR blocks. Use them to compact network tables or
  prepare ranges for CIDR-only APIs.

- **Lazy iteration**

  `Addrs` and `AddrsBackward` stream members as `iter.Seq[netip.Addr]`, so
  callers can stop early without materializing a slice. `NumHostBits`
  carries the exact member count as its base-two exponent, even when the
  count does not fit an integer type.

- **Canonical text**

  `String`, `AppendTo`, `MarshalText` and `UnmarshalText` provide
  round-trippable forms for logs, configuration and encoding. Contiguous
  networks print as `addr/prefix`, while non-contiguous networks print as
  `addr/mask`. `Compact` renders host routes as a bare `addr`. Strict parsing
  rejects leading zeros in the prefix length and zones at the input boundary.

- **`net/netip` interop**

  Plain zone-free `netip.Addr` is the value type throughout the public API.
  `Contiguous` converts to and from `netip.Prefix`. Existing stdlib callers
  need no additional IP type, while analogue operations keep `net/netip`
  names and semantics.

## Why not net/netip

`net/netip` models a network as `netip.Prefix` — an `addr` plus a prefix
length — which can only express a mask that is a run of leading ones, and
stops at membership tests. `xnetip` complements it where that is not
enough:

| | `net/netip` | `xnetip` |
|---|---|---|
| Network model | `addr` + prefix length, contiguous masks only | `(addr, mask)`, any mask |
| Notation | `10.0.0.0/8` | `10.0.0.0/8` and `10.0.0.0/255.0.255.0` |
| Set algebra | `Contains`, `Overlaps` | containment, intersection, difference, merge, adjacency, supernet |
| Slice operations | — | aggregation, range → CIDR list |
| Addr iteration | `Addr.Next`/`Prev` | `iter.Seq[netip.Addr]`, both directions |

## Examples

**Addr range → minimal CIDR list.**

```go
first := netip.MustParseAddr("10.0.0.1")
last := netip.MustParseAddr("10.0.0.30")
for block := range xnetip.RangeToNetworks4(first, last) {
	fmt.Println(block)
}
// 10.0.0.1/32
// 10.0.0.2/31
// 10.0.0.4/30
// 10.0.0.8/29
// 10.0.0.16/29
// 10.0.0.24/30
// 10.0.0.28/31
// 10.0.0.30/32
```

**Aggregation beyond CIDR.** Two `/24` networks separated by a gap cannot
share one CIDR without including extra members. `Aggregate4` can still
represent their exact union by clearing the differing bit in the mask:

```go
nets := []xnetip.Network4{
	xnetip.MustParseNetwork4("10.0.0.0/24"),
	xnetip.MustParseNetwork4("10.0.2.0/24"),
}
nets = xnetip.Aggregate4(nets) // in place, no allocation
fmt.Println(nets)
// [10.0.0.0/255.255.253.0]
```

The result contains `10.0.0.0/24` and `10.0.2.0/24`, but not the
`10.0.1.0/24` gap.

**Exclude a network from the IPv4 universe.** `Difference` splits the
remainder into pairwise-disjoint CIDRs. Together, they cover the entire IPv4
space except `10.0.0.0/8`:

```go
universe := xnetip.MustParseContiguous4("0.0.0.0/0")
excluded := xnetip.MustParseContiguous4("10.0.0.0/8")
for block := range universe.Difference(excluded) {
	fmt.Println(block)
}
// 128.0.0.0/1
// 64.0.0.0/2
// 32.0.0.0/3
// 16.0.0.0/4
// 0.0.0.0/5
// 12.0.0.0/6
// 8.0.0.0/7
// 11.0.0.0/8
```

The full API is documented on
[pkg.go.dev](https://pkg.go.dev/github.com/yanet-platform/xnetip).

## Guarantees

- Operations do not allocate — the exceptions are `String`/`MarshalText`
  results and error construction — and hot paths are pinned by
  `testing.AllocsPerRun` tests.
- No `unsafe`, no cgo, no reflection.
- IPv4 and IPv6 take the same algorithm through every operation. Behavior
  never diverges between families.
- Tested with property-based checks (differential against `net/netip`
  where an oracle exists) and fuzzed parsers.

## License

Apache 2.0, see [LICENSE](LICENSE).
