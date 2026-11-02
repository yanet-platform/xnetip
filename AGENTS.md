# AGENTS.md

Guidance for coding agents working on `xnetip`. Keep this file under 8 KB.
Style rules live in `.agents/conventions/{go,comments,tests}.md`.

## Project and reference

`github.com/yanet-platform/xnetip` is a Go 1.24 library for IPv4/IPv6
networks with arbitrary masks and immutable EUI-48 MAC addresses. Runtime
code uses only the standard library. Tests use `testify` and `rapid`.
Functionality first, performance second.

The Rust reference is `yanet-platform/netip` 0.4.0. Its exact revision is pinned
in `tools/parity/rust-revision`. Read matching Rust source fresh from `../netip`
checkout: `src/net.rs`, `src/net/{contiguous,bicontiguous}.rs`, `src/parser.rs`,
`src/fmt.rs`, `src/macaddr.rs`. Keep that checkout read-only for Go work.

## Build, test and lint

```sh
go build ./...
go vet ./...
go test ./...
go test -race ./...                         # make test, also CI
go test -short ./...                        # make test-short
go test -run 'Test_X' -rapid.checks=1000 -rapid.seed=12345 ./...
go test -fuzz FuzzParseNetwork4 -fuzztime 30s ./...
go test -run xxx -bench . -benchtime 1x ./... # make bench
python3 tools/parity/run.py --rust-source ../netip --output /tmp/xnetip-parity
```

Use Go 1.24 for CI-equivalent lint. If a newer installed toolchain is
incompatible with the pinned linter, use `GOTOOLCHAIN=go1.24.13`.
CI pins gofumpt v0.9.2 and golangci-lint v2.12.2 in
`.github/workflows/ci.yml`. Run gofumpt, vet and golangci-lint after Go changes.
`make lint` and the optional `make hooks` pre-commit hook also call
`gocommentlint`. If it is unavailable, record that limitation and review
comments against the conventions manually. Do not invent a replacement tool or claim that gate passed.

The separate parity workflow checks out the pinned Rust revision and compares
a shared deterministic corpus. Use a clean `src/` at that revision. See
`tools/parity/README.md` for replay and failure artifacts. Intentional grammar
differences are exact cases in `tools/parity/contracts.json`.
Changing the reference pin is an explicit compatibility change.

## Layout

```text
net4.go net6.go net.go       Network4, Network6 and dual-family Network
contiguous.go bicontiguous.go guarantee wrappers and their typed operations
addr_iterator.go            resumable double-ended address cursor
parser_ascii.go             complete-byte and leading-token network parsers
addr4.go addr6.go uint128.go unexported address and 128-bit arithmetic kernels
aggregate.go range.go       in-place covers and lazy range-to-CIDR decomposition
binary_split.go             generic payload projection and stable in-place split
compact.go                  opaque compact network formatting adapter
macaddr.go macfmt.go         MAC values, conversions and formatting adapters
errors.go                   sentinels and deferred owned diagnostics
*_test.go                   API tests, properties, fuzz targets and benchmarks
testutil_test.go            allocation assertion, shared generators and sinks
tools/parity/               pinned Rust/Go probes, corpus runner and contracts
.agents/conventions/        Go, comment and test style rules
```

Network methods live with their type. Tests use `package xnetip_test`;
arithmetic, address kernel and error tests use `package xnetip`.

## Invariants and deliberate port contracts

- Networks are normalized: `addr & mask == addr`. Their zero values are
  valid universes: `Network4{}` is `0.0.0.0/0`, `Network6{}` and `Network{}`
  are `::/0`. Wrapper zero values preserve the corresponding universe.
- Public IP values are `netip.Addr`, not custom integer address types.
  Network integer `FromBits`/`ToBits` APIs are intentionally absent. Kernels
  are zone-free host-order `uint32`/`uint128`. Checked constructors drop
  zones and reject invalid or foreign-family addresses. Complete parsers
  reject zones. IPv4-mapped IPv6 remains IPv6 unless explicitly converted.
- `Network` stores native IPv4 as a mapped IPv6 pair plus `is4`. Its mapped
  mask fixes the upper 96 bits. Views, order, prefix lengths and outputs
  retain the original family. `Compare` orders IPv4 before IPv6.
- Mixed-family `Contains`/`Intersects` are false and `Intersection`/`Merge`
  fail. `Network.Difference` and its reverse yield the source once for a
  foreign-family exclusion. `Network.SupernetFor` returns false for mixed
  families. `AggregateContiguous[Network]` accepts mixed families and
  aggregates each independently. Preserve these Go extensions.
- Prefix text is unsigned decimal with no leading zero except `0` itself.
  Rust also accepts `+8` and `008`; Go intentionally rejects both, following
  `net/netip.ParsePrefix`. String and ASCII entry points share this contract.
  Successful byte parsing does not retain input. Token remainders borrow
  the input slice; errors own rejected text.
- `Contiguous[T]` proves one leading mask run. `BiContiguous` proves one
  leading run per 64-bit half. Typed operations preserve those guarantees.
  General and bi-contiguous aggregation reach a merge fixpoint within their
  permitted mask class, preserving the exact union without promising a
  globally minimum arbitrary-mask cover. CIDR aggregation is minimal.
- Address streams use `iter.Seq`; `AddrIterator` provides resumable
  `Next`, `NextBack`, `Nth`, `NthBack` and a saturating `SizeHint`.
  Concrete subnet methods return a sequence directly: invalid refinements,
  prefixes or address families produce an empty re-iterable sequence.
- Rust `Option` normally becomes comma-ok, ordering becomes `Compare`,
  and formatting uses `String`, `AppendTo` and text marshaling. Formatting
  adapters are opaque values returned by functions. Binary split uses an
  explicit projection to preserve arbitrary payloads and returns a half-open
  `IndexRange`. `MacAddr{}` is the all-zero MAC, not an invalid sentinel.
- Rust's `no_std`, `const fn` and Lean proof machinery are Rust guarantees,
  not Go guarantees. Parity tests compare selected behavior; they do not
  transfer formal proofs to the Go implementation.

## Hard constraints

- Runtime dependencies: standard library only. Tests may use only `testing`,
  `testify` and `rapid` beyond the standard library. No unsafe, cgo or reflection
  in runtime code.
- Set operations, traversal and successful parsing/text decoding allocate no
  storage. `String`/`MarshalText` allocate their results, diagnostics may
  allocate, and `AppendTo` needs sufficient caller capacity. Pin new hot paths
  with `requireNoAllocs`. Never silently introduce O(N) scratch allocation.
- Keep IPv4/IPv6 algorithms and case analysis aligned. Use `uint128` for IPv6
  bit operations. Document a justified divergence rather than hiding it.
- Mirror an existing `net/netip` analogue's name and semantics when applicable.
  Check the installed standard-library source before introducing such an API.

## Change workflow

1. Read the conventions relevant to the files being changed and the matching
   reference implementation. Honor the user's scope and established contracts.
2. Write failing behavior tests first: boundary values, arbitrary masks,
   properties and independent oracles where available.
3. Keep a coherent implementation, tests and algorithm benchmarks together.
   Benchmarks use `b.Loop()` and `b.ReportAllocs()`.
4. Run relevant checks and parity for shared behavior changes. Report results
   and limitations. Docs need source/example review and `git diff --check`.
5. Use a feature branch or isolated worktree and a focused PR. Follow the
   task's authorization for pushing, creating and merging PRs. Never default
   to committing on `main`, and do not amend or rewrite existing commits.

Commit subjects use `feat|fix|perf|refactor|test|docs|chore(scope): brief`,
with a lowercase brief and no trailing period. No AI attribution, generated
footers or co-author trailers in files or commits.
