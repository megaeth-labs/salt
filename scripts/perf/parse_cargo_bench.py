#!/usr/bin/env python3

import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path


CRITERION_RE = re.compile(
    r"^(?P<name>.+?)\s+time:\s+\["
    r"(?P<low>[\d,._]+)\s+(?P<low_unit>ps|ns|us|µs|ms|s)\s+"
    r"(?P<mid>[\d,._]+)\s+(?P<mid_unit>ps|ns|us|µs|ms|s)\s+"
    r"(?P<high>[\d,._]+)\s+(?P<high_unit>ps|ns|us|µs|ms|s)"
    r"\]$"
)
CRITERION_TIME_ONLY_RE = re.compile(
    r"^time:\s+\["
    r"(?P<low>[\d,._]+)\s+(?P<low_unit>ps|ns|us|µs|ms|s)\s+"
    r"(?P<mid>[\d,._]+)\s+(?P<mid_unit>ps|ns|us|µs|ms|s)\s+"
    r"(?P<high>[\d,._]+)\s+(?P<high_unit>ps|ns|us|µs|ms|s)"
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
    r"^test\s+(?P<name>\S+)\s+\.\.\.\s+bench:\s+(?P<value>[\d,._]+)\s+(?P<unit>ns|us|µs|ms|s)/iter(?:\s+\(\+/-\s+[\d,._]+\))?$"
)

UNIT_TO_NS = {
    "ps": 0.001,
    "ns": 1.0,
    "us": 1_000.0,
    "µs": 1_000.0,
    "ms": 1_000_000.0,
    "s": 1_000_000_000.0,
}

THROUGHPUT_UNIT_TO_ELEMS_PER_SEC = {
    "elem/s": 1.0,
    "Kelem/s": 1_000.0,
    "Melem/s": 1_000_000.0,
    "Gelem/s": 1_000_000_000.0,
}


def parse_number(raw: str) -> float:
    return float(raw.replace(",", "").replace("_", ""))


def throughput_to_elems_per_sec(value: float, unit: str) -> float | None:
    scale = THROUGHPUT_UNIT_TO_ELEMS_PER_SEC.get(unit)
    if scale is None:
        return None
    return value * scale


def main() -> int:
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

        criterion_match = CRITERION_RE.match(line)
        if criterion_match:
            unit = criterion_match.group("mid_unit")
            mid = parse_number(criterion_match.group("mid"))
            benchmarks.append(
                {
                    "name": criterion_match.group("name").strip(),
                    "unit": "ns",
                    "value": mid * UNIT_TO_NS[unit],
                    "time_ns": mid * UNIT_TO_NS[unit],
                    "source": "criterion",
                    "source_unit": unit,
                }
            )
            last_criterion_benchmark = benchmarks[-1]
            current_benchmark_name = None
            continue

        criterion_time_only_match = CRITERION_TIME_ONLY_RE.match(line)
        if criterion_time_only_match and current_benchmark_name:
            unit = criterion_time_only_match.group("mid_unit")
            mid = parse_number(criterion_time_only_match.group("mid"))
            benchmarks.append(
                {
                    "name": current_benchmark_name,
                    "unit": "ns",
                    "value": mid * UNIT_TO_NS[unit],
                    "time_ns": mid * UNIT_TO_NS[unit],
                    "source": "criterion",
                    "source_unit": unit,
                }
            )
            last_criterion_benchmark = benchmarks[-1]
            current_benchmark_name = None
            continue

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

        libtest_match = LIBTEST_RE.match(line)
        if libtest_match:
            unit = libtest_match.group("unit")
            value = parse_number(libtest_match.group("value"))
            benchmarks.append(
                {
                    "name": libtest_match.group("name").strip(),
                    "unit": "ns",
                    "value": value * UNIT_TO_NS[unit],
                    "time_ns": value * UNIT_TO_NS[unit],
                    "source": "libtest",
                    "source_unit": unit,
                }
            )
            current_benchmark_name = None
            last_criterion_benchmark = None
            continue

        if line.startswith("Running "):
            continue
        if line.startswith("Gnuplot not found"):
            continue
        if line.startswith("Found "):
            continue
        if re.match(r"^\d+(\.\d+)?\s+\(", line):
            continue

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
