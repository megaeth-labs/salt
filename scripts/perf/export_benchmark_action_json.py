#!/usr/bin/env python3
"""Export normalized benchmark JSON into benchmark-action's expected format."""

import json
import sys
from pathlib import Path


def get_time_ns(benchmark: dict) -> float | None:
    """Read a benchmark's normalized time."""
    time_ns = benchmark.get("time_ns")
    return None if time_ns is None else float(time_ns)


def get_throughput(benchmark: dict) -> tuple[float, str] | None:
    """Read normalized throughput, falling back to the original unit if needed."""
    normalized = benchmark.get("throughput_elem_per_sec")
    if normalized is not None:
        return float(normalized), "elem/s"

    value = benchmark.get("throughput_value")
    unit = benchmark.get("throughput_unit")
    if value is None or not unit:
        return None
    return float(value), unit


def main() -> int:
    """Convert parsed benchmark data into a metric-specific flat JSON array."""
    if len(sys.argv) != 4:
        print(
            "usage: export_benchmark_action_json.py <input.json> <time|throughput> <output.json>",
            file=sys.stderr,
        )
        return 1

    input_path = Path(sys.argv[1])
    metric = sys.argv[2]
    output_path = Path(sys.argv[3])

    payload = json.loads(input_path.read_text(encoding="utf-8"))
    entries = []

    for benchmark in payload.get("benchmarks", []):
        if metric == "time":
            time_ns = get_time_ns(benchmark)
            if time_ns is None:
                continue
            entries.append(
                {
                    "name": benchmark["name"],
                    "unit": "ms",
                    "value": time_ns / 1_000_000,
                }
            )
            continue

        if metric == "throughput":
            throughput = get_throughput(benchmark)
            if throughput is None:
                continue
            throughput_value, throughput_unit = throughput
            entries.append(
                {
                    "name": benchmark["name"],
                    "unit": throughput_unit,
                    "value": throughput_value,
                }
            )
            continue

        print(f"unsupported metric: {metric}", file=sys.stderr)
        return 1

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(entries, indent=2) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
