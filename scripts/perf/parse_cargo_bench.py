#!/usr/bin/env python3
"""Parse `cargo bench` output into a normalized benchmark JSON payload.

The perf workflows run `cargo bench`, capture stdout, and then feed that text
into this script. The output format is a small JSON document consumed by later
reporting steps:

- `render_pr_report.py` compares a PR run against the published main baseline.
- `render_pr_comment.py` compares a PR run against the published main baseline.
- `export_benchmark_action_json.py` emits the shape expected by
  `benchmark-action/github-action-benchmark`.

The parser supports both Criterion-style output and libtest benchmark lines.
Whenever possible we normalize times to nanoseconds and throughput to
elements/second so downstream consumers can compare values without worrying
about display units.
"""

import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

TIME_UNIT_PATTERN = r"ns|us|µs|ms"
TIME_UNIT_TO_NS = {
    "ns": 1,
    "us": 1_000,
    "µs": 1_000,
    "ms": 1_000_000,
}
IGNORED_PREFIXES = (
    "Running ",
    "Gnuplot not found",
    "Found ",
)

CRITERION_RE = re.compile(
    r"^(?P<name>.+?)\s+time:\s+\["
    rf"(?P<low>[\d,._]+)\s+(?P<low_unit>{TIME_UNIT_PATTERN})\s+"
    rf"(?P<mid>[\d,._]+)\s+(?P<mid_unit>{TIME_UNIT_PATTERN})\s+"
    rf"(?P<high>[\d,._]+)\s+(?P<high_unit>{TIME_UNIT_PATTERN})"
    r"\]$"
)
CRITERION_TIME_ONLY_RE = re.compile(
    r"^time:\s+\["
    rf"(?P<low>[\d,._]+)\s+(?P<low_unit>{TIME_UNIT_PATTERN})\s+"
    rf"(?P<mid>[\d,._]+)\s+(?P<mid_unit>{TIME_UNIT_PATTERN})\s+"
    rf"(?P<high>[\d,._]+)\s+(?P<high_unit>{TIME_UNIT_PATTERN})"
    r"\]$"
)
CRITERION_THROUGHPUT_RE = re.compile(
    r"^thrpt:\s+\["
    r"(?P<low>[\d,._]+)\s+(?P<low_unit>\S+)\s+"
    r"(?P<mid>[\d,._]+)\s+(?P<mid_unit>\S+)\s+"
    r"(?P<high>[\d,._]+)\s+(?P<high_unit>\S+)"
    r"\]$"
)
LIBTEST_RE = re.compile(
    rf"^test\s+(?P<name>\S+)\s+\.\.\.\s+bench:\s+(?P<value>[\d,._]+)\s+(?P<unit>{TIME_UNIT_PATTERN})/iter(?:\s+\(\+/-\s+[\d,._]+\))?$"
)

THROUGHPUT_UNIT_TO_ELEMS_PER_SEC = {
    "elem/s": 1.0,
    "Kelem/s": 1_000.0,
    "Melem/s": 1_000_000.0,
    "Gelem/s": 1_000_000_000.0,
}


def parse_number(raw: str) -> float:
    """Parse a benchmark number that may contain separators like `,` or `_`."""
    return float(raw.replace(",", "").replace("_", ""))


def parse_time_ns(raw_value: str, raw_unit: str) -> float:
    """Parse a benchmark time into normalized nanoseconds."""
    return parse_number(raw_value) * TIME_UNIT_TO_NS[raw_unit]


def build_time_benchmark(name: str, source: str, time_ns: float, source_unit: str) -> dict:
    """Build the normalized benchmark shape shared by Criterion and libtest."""
    return {
        "name": name.strip(),
        "time_ns": time_ns,
        "source": source,
        "source_unit": source_unit,
    }


def throughput_to_elems_per_sec(value: float, unit: str) -> float | None:
    """Convert a human-readable throughput unit into normalized elem/s."""
    scale = THROUGHPUT_UNIT_TO_ELEMS_PER_SEC.get(unit)
    if scale is None:
        return None
    return value * scale


def is_ignored_line(line: str) -> bool:
    """Return whether a line is cargo/criterion noise we can safely skip."""
    return line.startswith(IGNORED_PREFIXES) or bool(re.match(r"^\d+(\.\d+)?\s+\(", line))


def main() -> int:
    """Read a raw cargo-bench transcript and write normalized benchmark JSON."""
    if len(sys.argv) != 3:
        print("usage: parse_cargo_bench.py <input.txt> <output.json>", file=sys.stderr)
        return 1

    input_path = Path(sys.argv[1])
    output_path = Path(sys.argv[2])

    benchmarks = []
    current_benchmark_name = None
    last_criterion_benchmark = None

    for raw_line in input_path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line:
            continue

        # Criterion may emit the benchmark name on the same line as the timing
        # triple, for example `foo time: [1.0 ms 1.1 ms 1.2 ms]`.
        criterion_match = CRITERION_RE.match(line)
        if criterion_match:
            benchmarks.append(
                build_time_benchmark(
                    name=criterion_match.group("name"),
                    source="criterion",
                    time_ns=parse_time_ns(
                        criterion_match.group("mid"),
                        criterion_match.group("mid_unit"),
                    ),
                    source_unit=criterion_match.group("mid_unit"),
                )
            )
            last_criterion_benchmark = benchmarks[-1]
            current_benchmark_name = None
            continue

        # Criterion can also print the benchmark name on the previous line and
        # then emit a standalone `time: [...]` line.
        criterion_time_only_match = CRITERION_TIME_ONLY_RE.match(line)
        if criterion_time_only_match and current_benchmark_name:
            benchmarks.append(
                build_time_benchmark(
                    name=current_benchmark_name,
                    source="criterion",
                    time_ns=parse_time_ns(
                        criterion_time_only_match.group("mid"),
                        criterion_time_only_match.group("mid_unit"),
                    ),
                    source_unit=criterion_time_only_match.group("mid_unit"),
                )
            )
            last_criterion_benchmark = benchmarks[-1]
            current_benchmark_name = None
            continue

        # Throughput lines belong to the most recently parsed Criterion entry.
        criterion_throughput_match = CRITERION_THROUGHPUT_RE.match(line)
        if criterion_throughput_match and last_criterion_benchmark is not None:
            throughput_unit = criterion_throughput_match.group("mid_unit")
            throughput_value = parse_number(criterion_throughput_match.group("mid"))
            last_criterion_benchmark["throughput_value"] = throughput_value
            last_criterion_benchmark["throughput_unit"] = throughput_unit
            normalized_throughput = throughput_to_elems_per_sec(throughput_value, throughput_unit)
            if normalized_throughput is not None:
                last_criterion_benchmark["throughput_elem_per_sec"] = normalized_throughput
            continue

        # Libtest benches use a different one-line format.
        libtest_match = LIBTEST_RE.match(line)
        if libtest_match:
            benchmarks.append(
                build_time_benchmark(
                    name=libtest_match.group("name"),
                    source="libtest",
                    time_ns=parse_time_ns(
                        libtest_match.group("value"),
                        libtest_match.group("unit"),
                    ),
                    source_unit=libtest_match.group("unit"),
                )
            )
            current_benchmark_name = None
            last_criterion_benchmark = None
            continue

        if is_ignored_line(line):
            continue

        # Treat any other non-empty line as a potential Criterion benchmark name.
        current_benchmark_name = line
        last_criterion_benchmark = None

    payload = {
        "schema": 1,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "source_file": str(input_path),
        "benchmarks": benchmarks,
    }

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
