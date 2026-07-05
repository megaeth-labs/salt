#!/usr/bin/env bash
# Mutation-testing driver for the salt crate.
#
# Subcommands:
#   diff <base-ref>   Mutate only lines changed under salt/src vs <base-ref>.
#   full              Mutate all production code in the salt crate.
#   file <glob>       Mutate files matching <glob> for local iteration.
#
# Results are written to $OUT_DIR/mutants.out. Run scripts/mutation_gate.py to
# score and gate the result.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT_DIR="${OUT_DIR:-$ROOT_DIR/target/mutants}"
SUPPRESS="${SUPPRESS:-$ROOT_DIR/mutants/suppressions.toml}"
PYTHON="${PYTHON:-python3}"
PKG="salt"

cd "$ROOT_DIR"

usage() {
    echo "usage: mutation_test.sh {diff <base-ref>|full|file <glob>}" >&2
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

if ! command -v "$PYTHON" >/dev/null 2>&1; then
    echo "Python executable not found: $PYTHON" >&2
    exit 1
fi

if ! cargo mutants --version >/dev/null 2>&1; then
    echo "cargo-mutants is required. Install with: cargo install cargo-mutants --locked" >&2
    exit 1
fi

if ! exclude_re_output="$("$PYTHON" "$ROOT_DIR/scripts/mutation_gate.py" exclude-re --suppressions "$SUPPRESS")"; then
    echo "failed to parse function suppressions from $SUPPRESS" >&2
    exit 1
fi

EXCLUDE_ARGS=()
if [[ -n "$exclude_re_output" ]]; then
    mapfile -t EXCLUDE_ARGS <<< "$exclude_re_output"
fi

run_mutants() {
    rm -rf "$OUT_DIR"
    mkdir -p "$(dirname "$OUT_DIR")"

    local rc=0
    cargo mutants \
        --package "$PKG" \
        --jobs "$JOBS" \
        --output "$OUT_DIR" \
        --no-shuffle \
        -vV \
        "${EXCLUDE_ARGS[@]}" \
        "$@" || rc=$?

    # cargo-mutants exit codes: 0 all caught, 2 missed mutants, 3 timeouts.
    # Those are normal run outcomes; the gate script decides pass or fail.
    case "$rc" in
        0 | 2 | 3) return 0 ;;
        *) return "$rc" ;;
    esac
}

cmd="${1:-}"
shift || true

case "$cmd" in
    diff)
        base="${1:?usage: mutation_test.sh diff <base-ref>}"
        diff_file="$OUT_DIR.diff"
        mkdir -p "$(dirname "$diff_file")"
        git diff --no-color "$base"...HEAD -- 'salt/src/**' > "$diff_file"
        if [[ ! -s "$diff_file" ]]; then
            echo "No changes under salt/src vs $base; nothing to mutate." >&2
            exit 0
        fi
        run_mutants --in-diff "$diff_file"
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
