# Mutation testing

Mutation testing measures whether tests detect small source-code faults. A
surviving mutant is a concrete place where the implementation can change and
the test suite still passes.

Target: production code in the `salt` crate.

## Layout

| Path | Purpose |
| --- | --- |
| `.cargo/mutants.toml` | Canonical cargo-mutants config. |
| `scripts/mutation_test.sh` | Driver for diff, full, and file-scoped runs. |
| `scripts/mutation_gate.py` | Scores results, validates suppression metadata, and enforces suppressions. |
| `mutants/suppressions.toml` | Reviewed equivalent/dead mutants. |
| `.github/workflows/mutation.yml` | PR gate, sharded scheduled/manual full runs, and suppression hygiene. |

Scheduled and manual full runs shard the mutant universe across a job matrix
(`cargo mutants --shard`) because a full crate run does not fit one hosted
runner within the job timeout.

## Local use

```bash
# Mutate only changed lines under salt/src.
scripts/mutation_test.sh diff origin/main
python3 scripts/mutation_gate.py report \
  --results target/mutants/mutants.out \
  --suppressions mutants/suppressions.toml

# Iterate on one file or subsystem.
scripts/mutation_test.sh file 'salt/src/state/**'
scripts/mutation_test.sh file 'salt/src/trie/trie.rs'

# Full crate run.
scripts/mutation_test.sh full
```

Useful environment overrides:

- `OUT_DIR`: mutation output directory, default `target/mutants`.
- `SUPPRESS`: suppression file, default `mutants/suppressions.toml`.
- `JOBS`: cargo-mutants worker count. Defaults to `nproc`, `sysctl -n hw.ncpu`,
  or `1`.
- `PYTHON`: Python executable used by the driver, default `python3`. The gate
  script needs Python 3.11+ (it uses `tomllib`).

## Gate policy

The PR gate is diff-scoped and uses "no new survivors":

- unsuppressed missed mutants fail the gate;
- unsuppressed timeouts fail the gate because they are inconclusive;
- equivalent or dead-code mutants require a reviewed suppression;
- a missing results directory fails the gate. The driver always materializes a
  result set — an explicit empty one when there is nothing to mutate — so a
  missing directory means the mutation run misfired rather than "no findings".

The score is useful, but the blocking rule is simpler: every changed-line mutant
must be killed or intentionally suppressed.

## Suppressions

Prefer tests over suppressions. Use a suppression only after manually proving a
mutant is not a real test gap.

Two supported forms:

- `kind = "line"`: mutant text from `missed.txt` or `timeout.txt`, with the
  leading `file:line:col:` locator stripped. Locator-free entries keep matching
  when unrelated edits shift line numbers. Matching is scoped to the entry's
  `file`, so identical mutant text in another module is not suppressed.
- `kind = "function"`: regex passed to cargo-mutants as `--exclude-re`.

Function suppressions are broad and can hide future behavior. Prefer `line`
unless a whole function is genuinely dead or permanently equivalent.

Every suppression must include:

- `kind = "line"` or `kind = "function"`
- `category = "equivalent"` or `category = "dead"`
- `file`
- `mutant` or `pattern`
- `justification`
- `reviewer`

The gate validates these fields before scoring. Suppression hygiene is enforced
by CI with `mutation_gate.py orphans`.
