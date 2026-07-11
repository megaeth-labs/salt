# Domain-specific mutation operators

Custom mutation-operator packs run through
[universalmutator](https://github.com/agroce/universalmutator) +
[comby](https://comby.dev), complementing the `cargo-mutants` gate (issue
#141). `cargo-mutants` ships a fixed set of structural operators and has no
plugin API, so it never generates the mutations that matter most for a
state-commitment system. Each pack targets a specific soundness or determinism
invariant. The selection filter for adding rules: *"what soundness or
determinism invariant would a surviving mutant here violate?"* Generic
arithmetic/relational/logical operators are deliberately excluded — the
`cargo-mutants` gate already owns those.

All packs are driven by `scripts/umutate.py` and scored by the **same** gate as
`cargo-mutants` (`scripts/mutation_gate.py`), via the
caught/missed/timeout/unviable results contract. Both engines live in one CI
workflow, `.github/workflows/mutation.yml`.

## Layout

Each pack is a directory `mutants/operators/<name>/` with:

- `manifest.toml` — pack config: `name`, `description`, `mode` (`comby` or
  `regex`), `targets` (source globs), optional `match` (a regex file-content
  filter), the `rules` filename, and the `test_cmd` whose non-zero exit means a
  mutant was killed.
- `<name>.rules` — the operator rules. `PATTERN ==> REPLACEMENT` per line, `#`
  for comments. In `comby` mode the pattern is a
  [comby template](https://comby.dev/docs/syntax-reference); in `regex` mode a
  Python regex.

| Pack | Scope | Invariant guarded |
| --- | --- | --- |
| `trie` | `trie/node_utils.rs`, `trie/trie.rs`, `constant.rs`, `types.rs`, `proof/shape.rs` | Level-base and bit-width arithmetic of the two-tier trie (`STARTING_NODE_ID`, 8/24/40 splits, 256-way fanout, ceil rounding) |
| `canon` | `proof/prover.rs`, `proof/salt_witness.rs` | Canonical form: sort/dedup on the proof path must not be removable or reversible |
| `endian` | `state/ahash/convert.rs`, `state/hasher.rs`, `types.rs` | Byte-order determinism of the consensus hash and 12-byte metadata codec (see issue #127) |

## Why comby

comby matches **structurally**, not textually, which removes a class of
regex-fragility bugs:

- A method/path-call template (`:[recv].to_le_bytes()`,
  `:[ty]::from_le_bytes(:[args])`) can only match a real call — never a
  substring of an identifier such as `serialize_to_le_bytes`.
- A single-word hole `:[[recv]]` matches one identifier, so a comparator or
  receiver hole cannot swallow a surrounding compound expression.

The one case comby does **not** anchor for free is a bare constant that is a
prefix of a longer one (`TRIE_WIDTH` inside `TRIE_WIDTH_BITS`): a literal
template is not word-anchored. Pin a boundary with a trailing negated-class
hole, reproduced in the replacement:

```
% TRIE_WIDTH:[b~[^A-Za-z0-9_]] ==> % (TRIE_WIDTH - 1):[b]
```

## Running

```bash
scripts/umutate_setup.sh          # installs universalmutator + comby

# Show what WOULD be mutated (no tests run, tree untouched):
python3 scripts/umutate.py plan

# Full pipeline for one pack -> gate-ready results dir:
python3 scripts/umutate.py run --packs trie --output target/umutate
python3 scripts/mutation_gate.py report --results target/umutate \
    --suppressions mutants/suppressions.toml

# Diff-scoped (the PR-gate scope: only files+lines changed vs a base):
python3 scripts/umutate.py run --diff origin/main --output target/umutate
```

Mutants inside `#[cfg(test)]` code are pruned automatically (mutating test
assertions is meaningless), as are — in `--diff` mode — mutants outside the
changed lines.

## CI

`.github/workflows/mutation.yml` runs three concerns off one file:

- **`spec-gate`** — diff-scoped, blocking, on every PR. Most PRs change no
  operator site, so it generates zero mutants and is near-instant. An
  unsuppressed survivor fails the gate and is upserted as a PR comment.
- **`spec-gate-sweep`** — nightly full sweep, sharded per pack, informational
  (surfaces survivors to triage; does not fail the workflow).
- **`orphan-suppressions`** — folds the umutate mutant universe into the
  `cargo-mutants` universe so a suppression that no longer matches any live
  mutant (either engine) is flagged.

## Triage policy

Every **survivor** is either:

1. a missing test — add a killing test (preferred), or
2. an equivalent mutant — record it in `mutants/suppressions.toml` with a
   justification (prefer a `line = <n>` pin; note that same-line twins cannot
   be pinned apart — rely on a killing test there instead).

**Unviable** (non-compiling) mutants are fine in moderation; if a rule mostly
produces unviable mutants, tighten its template.

## Known gaps

- Families C (field-element chunk widths), D (serialization codec config) and F
  (hash diffusion ops) from issue #141 are staged for a follow-up after the
  first survivor triage of A/B/E.
