# Comment conventions

Loaded on demand by the agent writing or reviewing any file. This is the single source for comment structure. `go.md` and `tests.md` defer to this file. `gocommentlint` enforces the shape on staged diffs.

Every comment — `//`, `/* */`, godoc, or a Markdown comment in the plan files — uses the two-part shape below. A comment that fits entirely in the brief has no detailed block, a comment that needs more always separates the two with one blank line.

```
<brief>

<detailed>
```

- **Brief**: 1–2 lines, the why or the contract, not a restatement of the code. State the invariant or the reason the code is non-obvious. If the line only paraphrases the statement beneath it, delete the comment.
- **Blank line**: exactly one, separating brief from detailed. Absent when there is no detailed block. Never two.
- **Detailed**: up to 6–8 lines, soft — the ceiling is a guideline, not a gate. Preconditions, failure modes, the correctness argument. Still prose, not a bulleted spec. If it grows past the ceiling, the comment is documenting a function that should be split.
- **One comment per block**: a single brief may stand alone, a detailed block is never written without its brief above it. Do not stack detached paragraphs under one code span. Inside a function body, at most two comment blocks per diff hunk (lint rule) — more means the function wants splitting.
- **No code identifiers in prose**: a comment states intent, invariants and contracts in domain terms. It must not name internal functions, methods, variables, fields or local symbols — that restates the code and rots on every rename. Write "the intersection address is already normalized by the mask AND", not "addr is already masked so we skip IPv4NetworkFrom".

  Exceptions. (a) A doc comment opens with its own symbol's name (godoc synopsis requirement). (b) A cross-reference to another exported symbol (`// like Merge but only at the lowest mask bit`) is allowed only when the relationship *is* the invariant. (c) Short mathematical names used as variables in dense bit code (`a1`, `m1`, `d`, `p`, `q`) may appear inside backticks **if the comment defines them** ("the intersection mask `m1 | m2`…"), because there the formula is the contract. External contract identifiers (`netip.ParsePrefix`'s grammar, a sentinel error name in an error contract) stay.
- **Self-contained**: never reference labels the reader cannot see (theorem names from plan files, PR numbers, file-and-line citations of any external source). References to the Rust reference sources (`../netip/…`) are forbidden in code comments — maintainer ruling 2026-08-20: a shipped library must read on its own, the crate is a porting aid, not documentation. State the correctness argument in place or point to the theory; the Rust line numbers stay in the session plans.
- **No comment is a substitute for a name**: if the brief is "this returns the foo", rename the symbol instead.
- **Sentences start with a capital letter** — never with a lowercase backticked identifier. Rephrase ("The expression `addr | ^mask` is…", not "`addr | ^mask` is…"). Avoid semicolons in prose: use separate sentences, commas, em-dashes or parentheses.
- **What to delete on review**: comments restating code or trivial complexity ("runs in O(1)"), ISA/compiler-behaviour claims ("the compiler inlines this", "becomes a cmov"), proofs longer than two sentences (point to the theory instead), duplicated essays between a type's doc and its methods, op-counts, and descriptions of *how* a sibling function works internally (compare against its contract and link).
- **What to keep unconditionally**: correctness justifications (why a transform is legal — "AND/XOR/NOT commute with byte order", "the borrowed bit reconstructs the source on the first peel"), anti-regression one-liners ("the back-peeled bit must NOT be folded into the running mask"), and the justification of any visible IPv4/IPv6 divergence.
- **Doc comments** follow the same shape: the brief is the synopsis `go doc` prints, the detailed block is the body. The blank line is what separates them, which `go doc` relies on. Examples belong in `Example*` test functions, not in doc comments.
