# xnetip

`xnetip` is a Go port of the Rust crate [netip](https://github.com/yanet-platform/netip):
IPv4 and IPv6 network types with first-class support for non-contiguous subnet
masks — containment, intersection, difference, merge, adjacency, aggregation and
address iteration all stay correct when the mask is an arbitrary bit pattern.
The module depends only on the standard library. The API is documented in
godoc: `go doc github.com/yanet-platform/xnetip`.
