# Code Review Guidelines

The centralized `claude-pr-review` action already applies the baseline rubric (review mindset, priority order, generic correctness/test/observability checks, the "what not to flag" list, severity scale, and previous-thread triage). This file supplements it with rules **specific to salt** or stricter than it; defer to the baseline otherwise, and let these win on conflict.

## Correctness and safety

- **Serde round-trips must be exercised.** A hand-rolled (de)serializer needs a test that actually drives it end-to-end with representative data. An assertion that is true by construction (e.g. `keys.len() == levels.len()` for any map) exercises nothing and passes even on a broken encoder.
- **No dead configuration.** A manifest/config key that is documented and set but never read is a silent no-op for operators — either honor it in code or remove it from the manifests and docs.

## Tooling and scope

- **Documented local flows must run on stock macOS bash 3.2.** The `just`/shell entry points people actually run can't assume bash ≥ 4: no `mapfile`, and always quote empty-array expansions (an unguarded `"${arr[@]}"` throws `unbound variable` under `set -u`).
