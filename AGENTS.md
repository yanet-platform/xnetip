# AGENTS.md

Guidance for AI coding agents working on `xnetip`. Keep it under 8 KB: facts about the code, build and environment. Conventions live in `.agents/conventions/`, the work plan in `.roadmap/`.

## Project

`xnetip` (`github.com/yanet-platform/xnetip`, Go 1.24, one package) is a
**stdlib-only runtime** port of Rust `netip` 0.3.9. It models IPv4/IPv6
networks as `(address, mask)` pairs, including non-contiguous masks, set
algebra, iteration, range-to-CIDR, aggregation and binary split. Tests use
`testify` and `rapid`. Read `../netip/src/{net.rs,parser.rs,fmt.rs}` fresh for
semantics; also see `../netip/CLAUDE.md` and `../netip/.docs/ROADMAP.md`.

Priorities: **functionality first, performance second**. Iteration 1 covers
the network core and its `Contiguous`/`BiContiguous` guarantee wrappers;
`.roadmap/00-overview.md` owns the remaining backlog.

## Build, test, lint

```bash
go build ./... && go vet ./...
go test ./...                              # all tests (black-box package xnetip_test)
go test -run 'Test_Network4_Contains' -v ./...
go test -short ./...                       # rapid checks divided by five
go test -run 'Test_X' -rapid.checks=1000 -rapid.seed=<n> ./...   # more checks (default 100), replay a failure
go test -run xxx -bench 'BenchmarkNetwork4_Contains' -benchmem ./...
go test -run xxx -bench . -count 10 > new.txt && benchstat old.txt new.txt   # A/B, same session
go test -fuzz 'FuzzParseNetwork4' -fuzztime 30s ./...                     # parsers only
gofumpt -l -w . ; golangci-lint run ./... ; gocommentlint                    # gate = all clean
make test | make lint | make bench          # wrappers for the above (added by session 001)
```

CI (GitHub Actions, `.github/workflows/ci.yml`) runs `go test -race`, vet, gofumpt check, golangci-lint (`modernize`, `staticcheck`, `govet`, `errcheck`, `unused`, `testifylint`) and compiles benchmarks. `gocommentlint` runs as the `pre-commit` hook (`make hooks`). `benchstat`, `gofumpt`, `golangci-lint`, `gocommentlint` are installed in `$GOPATH/bin`.

## Layout

```
uint128.go         unexported 128-bit helper {hi, lo uint64}, exported methods, unexported constructors — every IPv6 bit trick goes through it
addr4.go addr6.go  unexported address kernels addr4{uint32} addr6{uint128} — the public API speaks netip.Addr
net4.go net6.go net.go               Network4  Network6  Network{network Network6; is4 bool}
                   a type's whole API lives in its file (constructors, Parse*, formatters, marshalling, set algebra, Addrs, Difference)
errors.go compact.go                 sentinels, Compact (function over an unexported wrapper)
contiguous.go bicontiguous.go        Contiguous[T] CIDR wrapper + network[T] F-bound; concrete IPv6 BiContiguous wrapper
range.go aggregate.go binary_split.go   free functions over ranges and slices (RangeToNetworks*, Aggregate*, BinarySplit*), one file each
*_test.go          mirror of the source file, package xnetip_test; white-box files (package xnetip): uint128_test.go and the kernel suites addr4_test.go, addr6_test.go, errors_test.go
testutil_test.go   requireNoAllocs + rapid generators gen<Type>, each added by the type's birth session
.roadmap/          gitignored session plan: 00-overview.md (order, status, backlog) + NNN-slug.md per pending session (deleted once done)
.agents/conventions/{go,comments,tests}.md   style rules (read the one you touch)
```

## Types and invariants

- Public address inputs, views and iterators use `netip.Addr`; kernels are
  zone-free host-order integers (`addr4{uint32}`, `addr6{uint128}`). Checked
  constructors return `(T, error)`, drop zones, and reject a foreign family or
  invalid zero address with `ErrAddrFamilyMismatch`. Relations are total: a
  foreign family (4in6 against IPv4 included) is not contained, matching
  `netip.Prefix.Contains`.
- Networks are normalized (`addr & mask == addr`). Valid zero values are
  `Network4{}` = `0.0.0.0/0`, and `Network6{}`/`Network{}` = `::/0`.
- `Contiguous[T]` proves one global leading-one mask run. Concrete
  `BiContiguous` over `Network6` proves one run per 64-bit half. Their storage
  is unexported; equality and ordering match the wrapped network; zero values
  are valid universe networks.
- `Network` stores IPv4 mapped: address `::ffff:a.b.c.d`, mask
  `ffff:ffff:ffff:ffff:ffff:ffff:M`; `is4` implies
  `network.IsIPv4MappedIPv6()`. Operations delegate to 128 bits and
  `PrefixLen` subtracts 96. Cross-family relations are false,
  `Intersection`/`Merge` return `ok=false`, and `Compare` orders IPv4 first.
- Mask algebra, contiguity, `LastAddr`, adjacency, merge, supernet,
  `Difference` and iteration order mirror `../netip/src/net.rs`; deliberate
  differences are in `.roadmap/00-overview.md`. Parsing uses `net/netip` after
  our own `/` split and strict prefix-length check (digits only, no leading
  zero or `+`); dotted masks work and `%zone` is an error.
- Rust `Option<T>` becomes `(T, bool)`, errors wrap exported sentinels with
  `%w` and echo input, `Ord` becomes `Compare`, and iterators use `iter.Seq`.
  Formatting uses `String`/`AppendTo` plus text marshaling. `Compact` returns
  an unexported inferred generic wrapper. Slice functions are verb-first
  (`Aggregate4`, `BinarySplit6`).

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
- Subject: `feat|fix|perf|refactor|test|docs|chore(scope): brief` — lowercase brief, no trailing period, scope = file or type (`network4`, `uint128`, `addr6`). Tests and benchmarks of the change go in the same commit.
- **No AI attribution anywhere**: no `Co-Authored-By`, no "Generated with" footers, in commits or in any file.
- Never edit `../netip`.
