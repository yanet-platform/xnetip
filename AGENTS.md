# AGENTS.md

Guidance for AI coding agents working on `xnetip`. Keep it under 8 KB: facts about the code, build and environment. Conventions live in `.agents/conventions/`, the work plan in `.roadmap/`.

## Project

`xnetip` (`github.com/yanet-platform/xnetip`, Go 1.24, single package, **stdlib-only runtime**, tests on `testify` + `rapid`) is a Go port of the Rust crate `netip` 0.3.9: IPv4/IPv6 network types as `(address, mask)` pairs with first-class **non-contiguous masks**, full set algebra (contains, intersection, difference, merge, adjacency, supernet), address iteration, range-to-CIDR, in-place aggregation and binary split. Reference sources: `../netip/src/{net.rs,parser.rs,fmt.rs}` (read them for semantics — the Go API mirrors them one to one), `../netip/CLAUDE.md`, `../netip/.docs/ROADMAP.md`.

Priorities: **functionality first, performance second**. Iteration 1 scope: the network core. Out of scope (backlog in `.roadmap/00-overview.md`): `Contiguous`/`BiContiguous` wrappers and their aggregations, `MacAddr`, `ParseNext*`, byte-slice parsing, hand-rolled parsers.

## Build, test, lint

```bash
go build ./... && go vet ./...
go test ./...                              # all tests (black-box package xnetip_test)
go test -run 'Test_IPv4Network_Contains' -v ./...
go test -short ./...                       # rapid checks divided by five
go test -run 'Test_X' -rapid.checks=1000 -rapid.seed=<n> ./...   # more checks (default 100), replay a failure
go test -run xxx -bench 'BenchmarkIPv4Network_Contains' -benchmem ./...
go test -run xxx -bench . -count 10 > new.txt && benchstat old.txt new.txt   # A/B, same session
go test -fuzz 'FuzzParseIPv4Network' -fuzztime 30s ./...                     # parsers only
gofumpt -l -w . ; golangci-lint run ./... ; gocommentlint                    # gate = all clean
make test | make lint | make bench          # wrappers for the above (added by session 001)
```

CI (GitHub Actions, `.github/workflows/ci.yml`) runs `go test -race`, vet, gofumpt check, golangci-lint (`modernize`, `staticcheck`, `govet`, `errcheck`, `unused`, `testifylint`) and compiles benchmarks. `gocommentlint` runs as the `pre-commit` hook (`make hooks`). `benchstat`, `gofumpt`, `golangci-lint`, `gocommentlint` are installed in `$GOPATH/bin`.

## Layout

```
uint128.go         unexported 128-bit helper {hi, lo uint64}, exported methods, unexported constructors — every IPv6 bit trick goes through it
addr4.go addr6.go addr.go        IPv4Addr{uint32}  IPv6Addr{uint128}  IPAddr{addr IPv6Addr; is4 bool}
network4.go network6.go network.go   IPv4Network  IPv6Network  IPNetwork{network IPv6Network; is4 bool}
parse.go format.go errors.go compact.go   parsing (net/netip based), String/AppendTo/MarshalText, sentinels, Compact[T]
addrs.go difference.go range.go aggregate.go binary_split.go   heavy algorithms, one file each
*_test.go          mirror of the source file, package xnetip_test; *_internal_test.go only for unexported code
testutil_test.go   requireNoAllocs + rapid generators gen<Type>, each added by the type's birth session
.roadmap/          gitignored session plan: 00-overview.md (order, status, backlog) + NNN-slug.md per pending session (deleted once done)
.agents/conventions/{go,comments,tests}.md   style rules (read the one you touch)
```

## Types and invariants

- Addresses are host-order integers, zone-free by construction (that is why `netip.Addr` is not the base type). `IPv6Addr` wraps `uint128`, `IPAddr` stores IPv4 as IPv4-mapped IPv6 plus `is4`.
- Networks are always normalized: `addr & mask == addr`. Every constructor enforces it. Zero values are valid: `IPv4Network{}` = `0.0.0.0/0`, `IPv6Network{}` = `::/0`, `IPNetwork{}` = `::/0`.
- `IPNetwork` stores IPv4 **IPv4-mapped**: addr `::ffff:a.b.c.d`, mask `ffff:ffff:ffff:ffff:ffff:ffff:M`. Invariant: `is4 ⇒ network.IsIPv4MappedIPv6()`. Every operation delegates to the 128-bit form and stays correct, `Prefix()` subtracts 96 for IPv4. Cross-family: relational ops are false, `Intersection`/`Merge` return `ok=false`, `Compare` orders IPv4 before IPv6.
- Mask semantics, contiguity, `Prefix() (int, bool)`, `ToContiguous()` (plain network), `LastAddr()`, adjacency, merge, lowest-mask-bit variants, `SupernetFor`, `Difference` (exactly popcount(m2 &^ m1) pairwise-disjoint networks), host-index iteration order — all exactly as documented in `../netip/src/net.rs`. Differences from Rust are listed in `.roadmap/00-overview.md` ("Deliberate divergences"). The CIDR suffix after `/` is strict (digits only, no leading zeros, no `+`), `%zone` in parse input is an error.
- Go idioms for Rust traits: `Option<T>` → `(T, bool)`. Parse/construct errors → `error` built from exported sentinels wrapped with `%w` and the input echoed. `Ord` → `Compare(other) int` only. `Display` → `String()` + `AppendTo([]byte) []byte` + `MarshalText`/`UnmarshalText`. Iterators → `iter.Seq` (`Addrs`, `AddrsBackward`, `NumHostBits() int`, `Difference`, `RangeToNetworksIPv4/6`). `fmt::Compact<T>` → generic `Compact[T Network]`. Free slice functions are verb-first (`AggregateIPv4`, `BinarySplitIPv6`).
- Parsing goes through `net/netip` in iteration 1: split at the first `/` ourselves (dotted masks are a supported form), `netip.ParseAddr` for the address and the mask, our own strict prefix-length rule.

## Hard constraints

- **Standard library only in runtime code.** Tests: `testing` + `github.com/stretchr/testify` (`require`/`assert`) + `pgregory.net/rapid`, nothing else (Go has no dev-dependency class, they sit in the root `go.mod`).
- **No `unsafe`, no cgo, no reflection in runtime code.**
- **Runtime code is allocation-free** except `String()`/`MarshalText` results and error construction. Hot paths carry a `testing.AllocsPerRun` test. Algorithms needing O(N) scratch memory are not implemented silently — stop and report the trade-off.
- **IPv4/IPv6 parity**: an operation has the same algorithm and case analysis in both families (word width differs, control flow does not). A tweak that helps one family goes to both or neither.
- Public API that has a `net/netip` analogue mirrors its name, signature and semantics — check the actual std source (`$(go env GOROOT)/src/net/netip/netip.go`) before naming. A deliberate divergence is documented, an accidental one is a bug.

## Session protocol (TDD, one function of one type per session)

1. Read `.roadmap/00-overview.md`, then the session file `.roadmap/NNN-slug.md` and check its dependencies are `done`. Read the referenced Rust lines fresh.
2. Tests first: write the session's test table (unit, boundary, **non-contiguous masks**, `rapid.Check` properties, differential checks against `net/netip` where an oracle exists) and watch them fail to compile or fail.
3. Implement the one function, keeping v4/v6 parity, and run `make test` until green.
4. Benchmarks only where the session file says so (algorithms, parse/format/compare) — `b.Loop()`, `b.ReportAllocs()`. Trivial delegates are waived with the reason recorded.
5. Gates: `make lint` (gofumpt, vet, golangci-lint, gocommentlint) and `make test` clean. Doc comment on every exported symbol, brief + blank + detailed shape.
6. Mark the row `done` in `.roadmap/00-overview.md`, commit, then delete the session file — a finished session leaves only its overview row and its commit.

## Commits

- Commit directly to `main`, one commit per session, only after all gates are green. Do not amend or rewrite existing commits. `gh` writes only when the task asks for them.
- Subject: `feat|fix|perf|refactor|test|docs|chore(scope): brief` — lowercase brief, no trailing period, scope = file or type (`network4`, `uint128`, `parse`). Tests and benchmarks of the change go in the same commit.
- **No AI attribution anywhere**: no `Co-Authored-By`, no "Generated with" footers, in commits or in any file.
- Never edit `../netip`.
