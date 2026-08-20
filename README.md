# xnetip

IPv4 and IPv6 network types for Go with first-class support for
non-contiguous subnet masks.

`net/netip` models a network as `netip.Prefix`: an address plus a prefix
length, which can only express a mask that is a run of leading ones.
`xnetip` models a network as an `(address, mask)` pair where the mask is
any bit pattern — `10.0.0.0/255.0.255.0` is a valid network, and every
operation (containment, intersection, difference, merge, adjacency,
aggregation, iteration) stays correct on it.

## What xnetip adds over net/netip

| | `net/netip` | `xnetip` |
|---|---|---|
| Network model | `Prefix` = address + prefix length, contiguous masks only | `IPv4Network`, `IPv6Network`, `IPNetwork` = `(address, mask)`, any mask, always normalized (`addr & mask == addr`) |
| Notation | `10.0.0.0/8` | `10.0.0.0/8` and dotted masks `10.0.0.0/255.0.255.0`; the CIDR suffix is strict (digits only, no leading zeros) |
| Set algebra | `Contains`, `Overlaps` | `Contains`, `Intersection`, `Intersects`, `IsDisjoint`, `IsAdjacent`, `Merge`, `SupernetFor`, `Difference` (exact, pairwise-disjoint pieces) |
| Contiguity | implied by the type | a query: `IsContiguous`, `Prefix() (int, bool)`, `ToContiguous`, `LastAddr` |
| Collections | — | `AggregateIPv4/6` (in-place), `BinarySplitIPv4/6`, `RangeToNetworksIPv4/6` (address range → minimal CIDR list) |
| Iteration | `Addr.Next`/`Prev` | `Addrs`, `AddrsBackward` as `iter.Seq[netip.Addr]`, `NumHostBits` for the exact count |
| Addresses | `netip.Addr` with zones | plain `netip.Addr` is the address currency of the whole API — accessors, iteration and constructors speak it; zones are rejected at the parsing boundary, and contiguous networks convert to and from `netip.Prefix` |
| Ordering | `Compare` | `Compare` on every network type, IPv4 before IPv6, the sort key aggregation relies on |
| Zero value | invalid `Addr`/`Prefix` | valid networks: `0.0.0.0/0`, `::/0` |

All types are small immutable values, operations do not allocate, and the
runtime code depends only on the standard library (the test dependencies in
`go.mod`, testify and rapid, are not pulled into your build). The API is
documented in godoc: `go doc github.com/yanet-platform/xnetip`.
