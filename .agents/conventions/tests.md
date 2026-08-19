# Test conventions

Loaded on demand by the agent writing or reviewing tests. This is the single source for what a test must say about itself and how the TDD session is structured. `go.md` defers to this file.

## Shape and naming

- **Name**: `Test_<WhatToTest>_<Case>` — CamelCase segments joined by underscores. The first segment is the unit under test (`IPv4Network_Contains`, `ParseIPv6Network`, `AggregateIPv4`), the rest is the case (`Test_IPv4Network_Contains_NonContiguousPattern`, `Test_ParseIPv4Network_RejectsLeadingZeroInPrefix`). `TestFoo` is rejected at review. Benchmarks: `Benchmark<Type>_<Method>[_<Shape>]` (`BenchmarkIPv6Network_Intersection_NonContiguous`). Fuzz: `Fuzz<Function>` (`FuzzParseIPv4Network`). Examples: `Example<Type>_<Method>`.
- **Doc comment**: each test carries a one-brief `// verifies that …` comment stating the invariant — the precondition, the action, the expected outcome — in the shape of `comments.md`, without code identifiers in prose. A detailed block only when the invariant is non-obvious (an ordering, a carry across the 64-bit half boundary, a normalization guarantee).
- **Table cases describe themselves**: each `name:` is a self-contained fragment (`"host route contains itself"`, `"family mismatch"`, `"mask 255.0.255.0 ignores second octet"`), never `"case 1"`/`"ok"`.
- **One assertion per invariant**: a table case fails for one reason and its name says which.
- **Assertions are exact and positional** when output order is deterministic (aggregation output order is a deterministic function of the input — not sorted, see sessions 116/117 — and the difference peel order is documented): compare slices element by element or with `slices.Equal`, never `slices.Contains`/"any".
- **Construct networks via string notation** in tests — `MustParseIPv4Network("10.0.0.0/255.0.255.0")` — never raw integer literals, except in tests specifically about the `*FromBits` APIs or inside generators.
- **Assertions are testify**: `require` by default (a table case stops at its first broken invariant, like `assert_eq!`), `assert` only when several independent checks on one result should all be reported. Argument order is `(t, expected, actual)`, enforced by `testifylint`. `require.Equal` for values, `require.True` for predicates, `require.ErrorIs` for sentinels, `require.NoError` for preconditions, `requireNoAllocs` for hot paths.
- **Helpers are documented** with a one-line brief stating the shape they return and the invariant they assume. Shared helpers live in `testutil_test.go`, take `require.TestingT` (never `*testing.T`) so they also run inside `rapid.Check`, and are added only when testify and rapid lack the assertion: today `requireNoAllocs`. The rapid generators `gen<Type>` live there too.
- Tests live in `package xnetip_test`. The one white-box file is `uint128_test.go` in `package xnetip`, because the word type is unexported. No name suffix marks it — the package clause does — and no further white-box file is planned: unexported kernels are tested through the public API they serve.

## What every operation session must cover (both families where the operation exists)

1. **Unit cases** ported from the Rust test module (see the session file's table and `../netip/src/net.rs` test names) — same inputs, same expected values.
2. **Boundary cases**: `/0`, `/32` or `/128`, `0.0.0.0`, `255.255.255.255`, `::`, `ffff:…:ffff`, single-bit masks, masks spanning the 64-bit half boundary for IPv6.
3. **Non-contiguous masks**: at least one alternating pattern (`170.85.170.85`, `ffff:0:ffff:0::`), one two-run mask, one pattern with a hole at the half boundary. The library's differentiator is non-contiguous support — a session without them is incomplete.
4. **Property tests** via `rapid.Check` (see below): commutativity/symmetry where it holds, self-application, normalization of every result (`addr & mask == addr`), brute-force membership checks on bounded address spaces, round trips (`Parse(String(x)) == x`), agreement with a simple oracle.
5. **Differential tests against `net/netip`** whenever std has the same operation (parsing, formatting, `Compare`, address predicates, `Prefix`-based containment for contiguous inputs).
6. **Allocation test** (`requireNoAllocs`, i.e. `testing.AllocsPerRun` == 0) for every hot-path function that is not `String`/`MarshalText`.

## Property testing with rapid

- `rapid.Check(t, func(t *rapid.T) { … })` is the `proptest!` block. Inputs come from generators: `value := genIPv4Network.Draw(t, "network")` — every `Draw` carries a label, so the shrunk counterexample reads by name. `-rapid.checks` sets the count (default 100, `-short` divides it by five, `make test-short`); a failure prints `-rapid.seed=<n>` for replay and writes `testdata/rapid/<Test>/*.fail`, which is gitignored — the shrunk case is pinned as a unit case in the session's table, never committed as a regression file.
- Generators are package-level `*rapid.Generator[T]` values built with `rapid.Custom`, named `gen<Type>` (`genIPv4Addr`, `genIPv6Addr`, `genIPAddr`, `genIPv4Network`, `genIPv6Network`, `genIPNetwork`), added to `testutil_test.go` by the session that introduces the type. They are explicit per type and per mask shape: `genIPv4Network` draws from {contiguous prefix, random mask, alternating mask, boundary masks, host route, universe} with fixed weights, `genIPv6Network` mirrors it and adds masks straddling bit 64 — shrinking does not replace boundary shapes, a shrunk random mask is rarely the interesting one. Sorted-slice generators exist for `Aggregate*`/`BinarySplit*`. Never hand-roll a PRNG in a test, `rapid` draws everything.
- Oracles are **simple and obviously correct** (brute-force bit loops, naive fixpoint appliers, per-pair definitions) — never byte-copies of the production algorithm. Prefer invariants (union preservation, idempotence, sortedness, fixpoint) over exact equality with a complex oracle.
- Go native fuzzing (`testing.F`) is used only for parsers and formatters (round trip and parity with `netip`). The seed corpus is checked in.

## Benchmarks

- Required for algorithms and for parse/format/compare, waived (with the reason written in the session file) for trivial delegates and conversions.
- `for b.Loop()`, `b.ReportAllocs()`, inputs built outside the loop, results sunk into a package-level variable. Shapes: contiguous, non-contiguous, and the Rust bench shapes from `../netip/benches/net.rs` when they exist. Compare runs with `benchstat` within one session and never read speedups into noise.
