#!/usr/bin/env bash
# Mutation-testing driver for the salt crate.
#
# Subcommands:
#   diff <base-ref>   Mutate only lines changed under salt/src vs <base-ref>.
#   full              Mutate all production code in the salt crate.
#   file <glob>       Mutate files matching <glob> for local iteration.
#
# Extra arguments after the subcommand are forwarded to cargo-mutants, e.g.
# `mutation_test.sh full --shard 0/8`.
#
# A result set is always materialized at $OUT_DIR/mutants.out — including an
# explicit empty one when the requested scope contains nothing to mutate — so
# scripts/mutation_gate.py can fail closed whenever a run leaves no results.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT_DIR="${OUT_DIR:-$ROOT_DIR/target/mutants}"
SUPPRESS="${SUPPRESS:-$ROOT_DIR/mutants/suppressions.toml}"
PYTHON="${PYTHON:-python3}"
PKG="salt"

cd "$ROOT_DIR"

usage() {
    echo "usage: mutation_test.sh {diff <base-ref>|full|file <glob>} [cargo-mutants args...]" >&2
}

is_positive_int() {
    [[ "${1:-}" =~ ^[1-9][0-9]*$ ]]
}

default_jobs() {
    local jobs=""
    if command -v nproc >/dev/null 2>&1; then
        jobs="$(nproc 2>/dev/null || true)"
        if is_positive_int "$jobs"; then
            echo "$jobs"
            return
        fi
    fi

    if command -v sysctl >/dev/null 2>&1; then
        jobs="$(sysctl -n hw.ncpu 2>/dev/null || true)"
        if is_positive_int "$jobs"; then
            echo "$jobs"
            return
        fi
    fi

    echo 1
}

JOBS="${JOBS:-$(default_jobs)}"

if ! is_positive_int "$JOBS"; then
    echo "JOBS must be a positive integer, got: $JOBS" >&2
    exit 2
fi

# cargo-mutants exits without writing mutants.out at all when no mutants match
# the requested scope (for example a diff that only touches test code).
# Materialize an explicit empty result set so the gate can tell "nothing to
# mutate" apart from a run that silently produced no output.
ensure_results() {
    if [[ ! -d "$OUT_DIR/mutants.out" ]]; then
        mkdir -p "$OUT_DIR/mutants.out"
        touch "$OUT_DIR/mutants.out/caught.txt" "$OUT_DIR/mutants.out/missed.txt" \
            "$OUT_DIR/mutants.out/timeout.txt" "$OUT_DIR/mutants.out/unviable.txt"
    fi
}

run_mutants() {
    if ! command -v "$PYTHON" >/dev/null 2>&1; then
        echo "Python executable not found: $PYTHON" >&2
        exit 1
    fi

    if ! cargo mutants --version >/dev/null 2>&1; then
        echo "cargo-mutants is required. Install the version pinned in" >&2
        echo ".github/workflows/mutation.yml: cargo install cargo-mutants --version <pin> --locked" >&2
        exit 1
    fi

    local exclude_re_output
    if ! exclude_re_output="$("$PYTHON" "$ROOT_DIR/scripts/mutation_gate.py" exclude-re --suppressions "$SUPPRESS")"; then
        echo "failed to parse function suppressions from $SUPPRESS" >&2
        exit 1
    fi

    local exclude_args=()
    if [[ -n "$exclude_re_output" ]]; then
        mapfile -t exclude_args <<< "$exclude_re_output"
    fi

    rm -rf "$OUT_DIR"
    mkdir -p "$OUT_DIR"

    local rc=0
    cargo mutants \
        --package "$PKG" \
        --jobs "$JOBS" \
        --output "$OUT_DIR" \
        --no-shuffle \
        -vV \
        "${exclude_args[@]}" \
        "$@" || rc=$?

    # cargo-mutants exit codes: 0 all caught, 2 missed mutants, 3 timeouts.
    # Those are normal run outcomes; the gate script decides pass or fail.
    case "$rc" in
        0 | 2 | 3) ;;
        *) return "$rc" ;;
    esac

    ensure_results
}

cmd="${1:-}"
shift || true

case "$cmd" in
    diff)
        base="${1:?usage: mutation_test.sh diff <base-ref>}"
        diff_file="$OUT_DIR.diff"
        mkdir -p "$(dirname "$diff_file")"
        git diff --no-color "$base"...HEAD -- 'salt/src/**' > "$diff_file"
        if [[ -s "$diff_file" ]]; then
            run_mutants --in-diff "$diff_file"
        else
            echo "No changes under salt/src vs $base; recording an empty result set." >&2
            rm -rf "$OUT_DIR"
            ensure_results
        fi
        ;;
    full)
        run_mutants "$@"
        ;;
    file)
        glob="${1:?usage: mutation_test.sh file <glob>}"
        shift || true
        run_mutants -f "$glob" "$@"
        ;;
    *)
        usage
        exit 2
        ;;
esac

echo
echo "Mutation results written to $OUT_DIR/mutants.out/"
echo "Score with: $PYTHON scripts/mutation_gate.py report --results $OUT_DIR/mutants.out --suppressions mutants/suppressions.toml"
