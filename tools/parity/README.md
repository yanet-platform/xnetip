# Rust reference parity

Run from the repository root with Go, Python 3 and Rust 1.88 or newer:

```sh
python3 tools/parity/run.py --rust-source ../netip --output /tmp/parity-results
```

The reference checkout must be clean under `src/` and at the commit recorded in
`rust-revision`. CI checks out that exact commit. Updating the reference is an
explicit change to the pin and any affected contracts.

The shared deterministic corpus exercises IPv4 and IPv6 normalization, set
algebra, ordering, mapped conversion, forward and backward address iteration,
difference order, range decomposition and all three aggregation classes. Related
operands include contained networks, single-bit buddies and dense rectangles.
The bi-contiguous cases include containment that exposes a previously visited
buddy merge. Canonical parsing is checked with arbitrary masks and CIDRs.

The default seed is fixed. `--seed` selects another replayable corpus. Output
contains the seed, counts and reference revision. On failure, a nonzero exit
status fails CI and the output directory records the input and both results.
A crashed probe or missing output also fails the run.

`contracts.json` pins deliberate grammar differences to exact inputs and
outcomes. Go retains the `net/netip.ParsePrefix` rule rejecting a leading plus
or leading zero in prefix lengths, while Rust accepts them. Both must produce
the specified result for a contract case: an exception does not suppress other
failures. Error wording is language-specific and is not compared.

The two probe programs only adapt their libraries to a common line protocol.
They do not implement network algorithms or serve as independent correctness
oracles. Library property tests remain responsible for set invariants. In
particular, general and bi-contiguous aggregation preserve the union but do not
promise a globally minimum arbitrary-mask cover.
