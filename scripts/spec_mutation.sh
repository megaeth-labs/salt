#!/usr/bin/env bash
# Domain-specific mutation testing via universalmutator (issue #141).
#
# cargo-mutants guards generic code structure; these regex packs guard SALT
# semantics (trie arithmetic, canonicalization, endianness). See
# mutants/operators/README.md for the pack catalog and triage policy.
#
# usage: spec_mutation.sh [pack ...]          default: trie canon endian
#
# Environment overrides:
#   OUT_DIR    results directory, default target/spec-mutants
#   GEN_ONLY   1 = only generate mutants, skip the cargo analysis loop
#   CARGO_ARGS cargo package/feature selection for check + nextest
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT_DIR="${OUT_DIR:-$ROOT_DIR/target/spec-mutants}"
GEN_ONLY="${GEN_ONLY:-0}"
CARGO_ARGS="${CARGO_ARGS:--p salt --no-default-features --features parallel}"

cd "$ROOT_DIR"

# Pack -> production source files it applies to. Scoping matters: applying,
# say, the endian pack to trie code would only generate noise.
targets_for() {
    case "$1" in
        trie)
            echo "salt/src/trie/node_utils.rs salt/src/trie/trie.rs salt/src/constant.rs salt/src/types.rs salt/src/proof/shape.rs"
            ;;
        canon)
            echo "salt/src/proof/prover.rs salt/src/proof/salt_witness.rs"
            ;;
        endian)
            echo "salt/src/state/ahash/convert.rs salt/src/state/hasher.rs salt/src/types.rs"
            ;;
        *)
            echo ""
            ;;
    esac
}

if ! command -v mutate >/dev/null 2>&1; then
    echo "universalmutator is required: pip install universalmutator" >&2
    exit 1
fi

packs="${*:-trie canon endian}"

rm -rf "$OUT_DIR"
mkdir -p "$OUT_DIR/mutants"

# manifest lines: <pack>\t<source-file>\t<mutant-file>
manifest="$OUT_DIR/manifest.txt"
: > "$manifest"

for pack in $packs; do
    targets="$(targets_for "$pack")"
    if [ -z "$targets" ]; then
        echo "unknown pack: $pack (expected: trie, canon, endian)" >&2
        exit 2
    fi
    rules="$ROOT_DIR/mutants/operators/$pack.rules"

    for src in $targets; do
        # Restrict mutation to production lines: everything before the first
        # top-level #[cfg(test)]. Mutants inside test code are pure noise.
        # grep exits nonzero when a file has no test module at all.
        cutoff="$(grep -n '^#\[cfg(test)\]' "$src" | head -1 | cut -d: -f1 || true)"
        if [ -z "$cutoff" ]; then
            cutoff=$(( $(wc -l < "$src") + 1 ))
        fi
        lines_file="$OUT_DIR/prod-lines.txt"
        seq 1 $((cutoff - 1)) > "$lines_file"

        mdir="$OUT_DIR/mutants/$pack/$(basename "$src" .rs)"
        mkdir -p "$mdir"
        # mutate exits 0 when a file simply yields no mutants; a nonzero exit
        # is a real invocation error (missing file, unreadable rules/lines)
        # and must fail the run rather than produce a partial manifest.
        mutate "$src" --only "$rules" --noCheck --lines "$lines_file" \
            --mutantDir "$mdir" > /dev/null

        for m in "$mdir"/*.rs; do
            [ -e "$m" ] || continue
            printf '%s\t%s\t%s\n' "$pack" "$src" "$m" >> "$manifest"
        done
    done
done

total="$(wc -l < "$manifest")"
if [ "$total" -eq 0 ]; then
    echo "no mutants generated at all - check the rules files and targets" >&2
    exit 2
fi
echo "generated $total mutants (packs: $packs)"

if [ "$GEN_ONLY" = "1" ]; then
    echo "GEN_ONLY=1: skipping analysis; mutants are in $OUT_DIR/mutants/"
    exit 0
fi

# Restore the working tree if the analysis loop is interrupted mid-mutant.
cur_src=""
restore() {
    if [ -n "$cur_src" ] && [ -f "$OUT_DIR/.orig.rs" ]; then
        cp "$OUT_DIR/.orig.rs" "$cur_src"
    fi
}
trap restore EXIT

invalid=0
killed=0
survivors_file="$OUT_DIR/survivors.txt"
: > "$survivors_file"

i=0
while IFS="$(printf '\t')" read -r pack src mutant; do
    i=$((i + 1))
    cur_src="$src"
    cp "$src" "$OUT_DIR/.orig.rs"
    cp "$mutant" "$src"
    label="[$i/$total] $pack/$(basename "$mutant")"

    if ! cargo check $CARGO_ARGS > /dev/null 2>&1; then
        invalid=$((invalid + 1))
        echo "$label: invalid (does not compile)"
    elif ! cargo nextest run $CARGO_ARGS > /dev/null 2>&1; then
        killed=$((killed + 1))
        echo "$label: killed"
    else
        echo "$label: SURVIVED"
        {
            echo "== $pack $src ($(basename "$mutant"))"
            diff "$OUT_DIR/.orig.rs" "$src" || true
            echo
        } >> "$survivors_file"
    fi

    cp "$OUT_DIR/.orig.rs" "$src"
    cur_src=""
done < "$manifest"

survived=$((total - invalid - killed))
status="PASS"
if [ "$survived" -gt 0 ]; then
    status="$survived SURVIVORS"
fi

report="$OUT_DIR/report.md"
{
    echo "## Spec mutation - $status"
    echo
    echo "Packs: \`$packs\`"
    echo
    echo "- generated: $total"
    echo "- killed: $killed"
    echo "- invalid (did not compile): $invalid"
    echo "- survived: $survived"
    if [ -s "$survivors_file" ]; then
        echo
        echo "### Survivors"
        echo
        echo "Each survivor is a semantic fault no test noticed: add a killing"
        echo "test, or document why it is equivalent."
        echo
        echo '```diff'
        cat "$survivors_file"
        echo '```'
    fi
} > "$report"

echo
cat "$report"

if [ "$survived" -gt 0 ]; then
    exit 1
fi
