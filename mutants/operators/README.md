# Domain-specific mutation operators

Regex mutation packs run through
[universalmutator](https://github.com/agroce/universalmutator), complementing
the `cargo-mutants` gate (issue #141). `cargo-mutants` ships a fixed set of
structural operators and has no plugin API, so it never generates the
mutations that matter most for a state-commitment system. Each pack targets a
specific soundness or determinism invariant; each rules file documents its
family. The selection filter for adding rules: *"what soundness or
determinism invariant would a surviving mutant here violate?"* Generic
arithmetic/relational/logical operators are deliberately excluded — the
`cargo-mutants` gate already owns those.

| Pack | Rules | Scope | Invariant guarded |
| --- | --- | --- | --- |
| `trie` | `trie.rules` | `trie/node_utils.rs`, `trie/trie.rs`, `constant.rs`, `types.rs`, `proof/shape.rs` | Level-base and bit-width arithmetic of the two-tier trie (`STARTING_NODE_ID`, 8/24/40 splits, 256-way fanout, ceil rounding) |
| `canon` | `canon.rules` | `proof/prover.rs`, `proof/salt_witness.rs` | Canonical form: sort/dedup on the proof path must not be removable or reversible |
| `endian` | `endian.rules` | `state/ahash/convert.rs`, `state/hasher.rs`, `types.rs` | Byte-order determinism of the consensus hash and 12-byte metadata codec (see issue #127) |

## Running

```bash
pip install universalmutator

# Everything (generation + kill analysis; needs cargo + nextest):
scripts/spec_mutation.sh

# One pack, or generation only (no Rust toolchain needed):
scripts/spec_mutation.sh trie
GEN_ONLY=1 scripts/spec_mutation.sh canon endian
```

In CI: the `Spec Mutation` workflow (`workflow_dispatch`) runs the packs and
uploads `report.md` + `survivors.txt`. Expect roughly 60 mutants for all
three packs and a few hours of runtime (each mutant rebuilds `salt` and runs
the suite; killed mutants stop at the first failing test).

Mutants are generated only for production lines (everything before the first
top-level `#[cfg(test)]`), so they never land in test code.

## Triage policy

Every **survivor** is either:

1. a missing test — add a killing test (preferred), or
2. an equivalent mutant — document the justification in the rules file next
   to the rule (and consider tightening the rule's regex).

**Invalid** (non-compiling) mutants are fine in moderation; if a rule mostly
produces invalid mutants, tighten its pattern.

## Known gaps

- Multi-line `sort_unstable_by!(...)` macro invocations (e.g. in
  `trie/trie.rs`) are not matched by the line-based deletion rules.
- The `endian` pack finds nothing in `convert.rs` until the explicit
  little-endian reads land (PR #142); after that it guards them.
- Families C (field-element chunk widths), D (serialization codec config)
  and F (hash diffusion ops) from issue #141 are staged for a follow-up
  after the first survivor triage of A/B/E.
