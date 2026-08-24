// Package xnetip provides IPv4 and IPv6 network types with first-class
// support for non-contiguous subnet masks.
//
// A network is an (address, mask) pair where the mask may be any bit
// pattern, not only a run of leading ones. All operations — containment,
// intersection, difference, merge, adjacency, aggregation, iteration —
// are defined on those pairs and stay correct for non-contiguous masks.
// Addresses at the API boundary are plain zone-free [netip.Addr] values,
// while all mask algebra runs on host-order integers internally.
// The package depends only on the standard library.
package xnetip
